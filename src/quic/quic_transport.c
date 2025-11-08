/*
    quic_transport.c -- VPN transport over QUIC implementation
    Copyright (C) 2025 tinc-vless contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "../logger.h"
#include "../xalloc.h"
#include "../splay_tree.h"
#include "../netutl.h"
#include "../names.h"
#include "../node.h"
#include "../net.h"
#include "quic_transport.h"
#include "quic.h"
#include "quic_reality.h"
#include "quic_fingerprint.h"

/* Global QUIC manager */
quic_manager_t *quic_manager = NULL;

/* Transport mode */
transport_mode_t transport_mode = TRANSPORT_UDP;

/* Local connection ID length (matches scid_len in quic_conn_new_server) */
#define LOCAL_CONN_ID_LEN 16

/* Connection ID map entry for demultiplexing */
typedef struct conn_id_entry_t {
	uint8_t conn_id[QUICHE_MAX_CONN_ID_LEN];
	size_t conn_id_len;
	quic_conn_t *conn;
} conn_id_entry_t;

/* External Reality configuration (from conf.h) */
extern bool vless_reality_enabled;
extern char *vless_reality_dest;
extern int vless_reality_dest_port;
extern char *vless_reality_server_name;
extern char *vless_reality_public_key;
extern char *vless_reality_private_key;
extern char *vless_reality_short_id;
extern char *vless_reality_fingerprint;

/* Connection comparison function for splay tree */
/* a and b are quic_conn_t pointers, compare by peer address */
static int connection_compare(const void *a, const void *b) {
	const quic_conn_t *qa = (const quic_conn_t *)a;
	const quic_conn_t *qb = (const quic_conn_t *)b;

	/* Compare by address family first */
	if(qa->peer_addr.ss_family != qb->peer_addr.ss_family) {
		return qa->peer_addr.ss_family - qb->peer_addr.ss_family;
	}

	/* Compare by IP address and port */
	if(qa->peer_addr.ss_family == AF_INET) {
		const struct sockaddr_in *sa = (const struct sockaddr_in *)&qa->peer_addr;
		const struct sockaddr_in *sb = (const struct sockaddr_in *)&qb->peer_addr;

		int addr_cmp = memcmp(&sa->sin_addr, &sb->sin_addr, sizeof(sa->sin_addr));
		if(addr_cmp != 0) {
			return addr_cmp;
		}

		return sa->sin_port - sb->sin_port;
	} else if(qa->peer_addr.ss_family == AF_INET6) {
		const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)&qa->peer_addr;
		const struct sockaddr_in6 *sb = (const struct sockaddr_in6 *)&qb->peer_addr;

		int addr_cmp = memcmp(&sa->sin6_addr, &sb->sin6_addr, sizeof(sa->sin6_addr));
		if(addr_cmp != 0) {
			return addr_cmp;
		}

		return sa->sin6_port - sb->sin6_port;
	}

	return 0;
}

/* Connection ID comparison function for splay tree */
static int conn_id_compare(const void *a, const void *b) {
	/* Handle NULL pointers - splay tree may pass sentinel nodes */
	if(!a) return b ? -1 : 0;
	if(!b) return 1;

	const conn_id_entry_t *ea = (const conn_id_entry_t *)a;
	const conn_id_entry_t *eb = (const conn_id_entry_t *)b;

	/* Compare by length first */
	if(ea->conn_id_len != eb->conn_id_len) {
		return ea->conn_id_len - eb->conn_id_len;
	}

	/* Then compare by value */
	return memcmp(ea->conn_id, eb->conn_id, ea->conn_id_len);
}

/* Register a connection ID in the demultiplexing map */
static bool register_connection_id(const uint8_t *conn_id, size_t conn_id_len, quic_conn_t *conn) {
	if(!quic_manager || !quic_manager->conn_id_map || !conn_id || conn_id_len == 0 || !conn) {
		return false;
	}

	conn_id_entry_t *entry = xzalloc(sizeof(conn_id_entry_t));
	memcpy(entry->conn_id, conn_id, conn_id_len);
	entry->conn_id_len = conn_id_len;
	entry->conn = conn;

	/* Use splay_insert correctly - pass data, not node */
	splay_insert(quic_manager->conn_id_map, entry);

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Registered connection ID (len=%zu) for demultiplexing", conn_id_len);
	return true;
}

/* Unregister a connection ID from the demultiplexing map */
static void unregister_connection_id(const uint8_t *conn_id, size_t conn_id_len) {
	if(!quic_manager || !quic_manager->conn_id_map || !conn_id || conn_id_len == 0) {
		return;
	}

	conn_id_entry_t search;
	memset(&search, 0, sizeof(search));  // Zero entire structure
	memcpy(search.conn_id, conn_id, conn_id_len);
	search.conn_id_len = conn_id_len;

	/* splay_unlink returns the node for the data */
	splay_node_t *node = splay_unlink(quic_manager->conn_id_map, &search);
	if(node) {
		free(node->data);  /* Free the conn_id_entry_t */
		free(node);        /* Free the node itself */
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Unregistered connection ID (len=%zu) from demultiplexing", conn_id_len);
	}
}

/* Lookup connection by ID */
static quic_conn_t *lookup_connection_by_id(const uint8_t *conn_id, size_t conn_id_len) {
	if(!quic_manager || !quic_manager->conn_id_map || !conn_id || conn_id_len == 0) {
		return NULL;
	}

	conn_id_entry_t search;
	memset(&search, 0, sizeof(search));  // Zero entire structure to avoid padding issues
	memcpy(search.conn_id, conn_id, conn_id_len);
	search.conn_id_len = conn_id_len;

	/* splay_search returns data pointer, not node */
	conn_id_entry_t *entry = (conn_id_entry_t *)splay_search(quic_manager->conn_id_map, &search);
	if(entry) {
		return entry->conn;
	}

	return NULL;
}

/* Initialize QUIC transport */
bool quic_transport_init(listen_socket_t *sockets, int num_sockets) {
	if(!quic_init()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize QUIC subsystem");
		return false;
	}

	if(!sockets || num_sockets <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "No listen sockets provided for QUIC");
		return false;
	}

	quic_manager = xzalloc(sizeof(quic_manager_t));

	/* Store references to tinc's listen sockets */
	quic_manager->sockets = xzalloc(num_sockets * sizeof(listen_socket_t *));
	for(int i = 0; i < num_sockets; i++) {
		quic_manager->sockets[i] = &sockets[i];
	}
	quic_manager->num_sockets = num_sockets;

	/* Create connection tree */
	quic_manager->connections = splay_alloc_tree(connection_compare, NULL);

	/* Create connection ID map for demultiplexing */
	quic_manager->conn_id_map = splay_alloc_tree(conn_id_compare, NULL);

	/* Create client configuration */
	quic_manager->client_config = quic_config_new(false);

	if(!quic_manager->client_config) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create QUIC client config");
		free(quic_manager->sockets);
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	/* Apply browser fingerprint to client config */
	const char *fingerprint = vless_reality_fingerprint ? vless_reality_fingerprint : "chrome";
	if(!quic_fingerprint_apply_name(quic_manager->client_config, fingerprint)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to apply fingerprint '%s', using defaults", fingerprint);
	}

	/* Create server configuration */
	quic_manager->server_config = quic_config_new(true);

	if(!quic_manager->server_config) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create QUIC server config");
		quic_config_free(quic_manager->client_config);
		free(quic_manager->sockets);
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	/* Apply browser fingerprint to server config as well */
	if(!quic_fingerprint_apply_name(quic_manager->server_config, fingerprint)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to apply fingerprint '%s' to server", fingerprint);
	}

	/* Load TLS certificates for server */
	char cert_path[PATH_MAX], key_path[PATH_MAX];
	snprintf(cert_path, sizeof(cert_path), "%s/quic-cert.pem", confbase);
	snprintf(key_path, sizeof(key_path), "%s/quic-key.pem", confbase);

	if(!quic_config_set_tls_cert(quic_manager->server_config, cert_path, key_path)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to load TLS certificate for QUIC server");
		logger(DEBUG_ALWAYS, LOG_ERR, "Certificate should be generated at startup by entrypoint script");
		quic_config_free(quic_manager->server_config);
		quic_config_free(quic_manager->client_config);
		free(quic_manager->sockets);
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	quic_manager->initialized = true;
	quic_manager->enabled = true;

	/* Initialize Reality configuration if enabled */
	if(vless_reality_enabled) {
		quic_manager->reality_config = reality_config_new(true);  /* Server mode */

		if(quic_manager->reality_config) {
			/* Copy configuration from global variables */
			if(vless_reality_server_name) {
				strncpy(quic_manager->reality_config->server_name, vless_reality_server_name,
				        sizeof(quic_manager->reality_config->server_name) - 1);
			}

			if(vless_reality_dest) {
				strncpy(quic_manager->reality_config->dest_domain, vless_reality_dest,
				        sizeof(quic_manager->reality_config->dest_domain) - 1);
			}

			quic_manager->reality_config->dest_port = vless_reality_dest_port;

			/* Copy public/private keys */
			if(vless_reality_public_key) {
				/* Convert hex string to bytes */
				/* TODO: Implement hex_to_bytes conversion */
			}

			if(vless_reality_private_key) {
				/* Convert hex string to bytes */
				/* TODO: Implement hex_to_bytes conversion */
			}

			/* Copy Short ID */
			if(vless_reality_short_id) {
				/* Convert hex string to bytes */
				/* TODO: Implement hex_to_bytes conversion */
				/* For now, just mark that we have one short ID */
				quic_manager->reality_config->num_short_ids = 1;
			} else {
				quic_manager->reality_config->num_short_ids = 0;
			}

			quic_manager->reality_enabled = true;
			logger(DEBUG_ALWAYS, LOG_INFO, "QUIC Reality protocol enabled");
		} else {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to create Reality configuration");
		}
	} else {
		quic_manager->reality_enabled = false;
		quic_manager->reality_config = NULL;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "QUIC transport initialized using %d shared UDP socket(s)", num_sockets);

	return true;
}

/* Cleanup QUIC transport */
void quic_transport_exit(void) {
	if(!quic_manager) {
		return;
	}

	/* Free all connections */
	if(quic_manager->connections) {
		/* TODO: Properly iterate and free connections */
		splay_delete_tree(quic_manager->connections);
	}

	/* Free connection ID map */
	if(quic_manager->conn_id_map) {
		/* Free all conn_id_entry_t structures */
		for(splay_node_t *node = quic_manager->conn_id_map->head; node; node = node->next) {
			if(node->data) {
				free(node->data);
			}
		}
		splay_delete_tree(quic_manager->conn_id_map);
	}

	/* Note: We don't close the UDP sockets - they're managed by tinc's net.c */

	/* Free socket references */
	if(quic_manager->sockets) {
		free(quic_manager->sockets);
	}

	/* Free configurations */
	if(quic_manager->client_config) {
		quic_config_free(quic_manager->client_config);
	}

	if(quic_manager->server_config) {
		quic_config_free(quic_manager->server_config);
	}

	if(quic_manager->reality_config) {
		reality_config_free(quic_manager->reality_config);
	}

	free(quic_manager);
	quic_manager = NULL;

	quic_exit();

	logger(DEBUG_ALWAYS, LOG_INFO, "QUIC transport shut down");
}

/* Get QUIC connection for a node */
quic_conn_t *quic_transport_get_connection(node_t *node) {
	if(!quic_manager || !quic_manager->connections || !node) {
		return NULL;
	}

	/* Create temporary quic_conn for searching by address */
	quic_conn_t search_key;
	memset(&search_key, 0, sizeof(search_key));

	/* Copy node's address to search key */
	if(!node->address.sa.sa_family) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Node %s has no address for connection lookup", node->name);
		return NULL;
	}

	memcpy(&search_key.peer_addr, &node->address, sizeof(struct sockaddr_storage));

	splay_node_t *sn = splay_search_node(quic_manager->connections, &search_key);

	if(!sn) {
		return NULL;
	}

	return (quic_conn_t *)sn->data;
}

/* Create QUIC connection for a node */
quic_conn_t *quic_transport_create_connection(node_t *node, bool is_client) {
	if(!quic_manager || !node) {
		return NULL;
	}

	/* Check if connection already exists */
	quic_conn_t *existing = quic_transport_get_connection(node);

	if(existing) {
		return existing;
	}

	quic_conn_t *qconn = NULL;

	if(is_client) {
		/* Create client connection */
		sockaddr_t sa;
		socklen_t sa_len;

		/* Get node's address */
		if(!node->address.sa.sa_family) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Node %s has no address for QUIC connection", node->name);
			return NULL;
		}

		memcpy(&sa, &node->address, sizeof(sa));
		sa_len = SALEN(sa.sa);

		/* Keep the peer's actual port from the node address */
		/* This will be the Port= value configured on the peer */

		/* Select appropriate socket based on address family */
		int sock_fd = -1;
		for(int i = 0; i < quic_manager->num_sockets; i++) {
			if(quic_manager->sockets[i]->sa.sa.sa_family == sa.sa.sa_family) {
				sock_fd = quic_manager->sockets[i]->udp.fd;
				logger(DEBUG_PROTOCOL, LOG_INFO, "Selected socket fd=%d for address family %d",
				       sock_fd, sa.sa.sa_family);
				break;
			}
		}

		if(sock_fd < 0) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "No suitable socket found for address family %d", sa.sa.sa_family);
			return NULL;
		}

		/* Log the destination address */
		char addr_str[INET6_ADDRSTRLEN];
		int port = 0;
		if(sa.sa.sa_family == AF_INET) {
			inet_ntop(AF_INET, &sa.in.sin_addr, addr_str, sizeof(addr_str));
			port = ntohs(sa.in.sin_port);
		} else if(sa.sa.sa_family == AF_INET6) {
			inet_ntop(AF_INET6, &sa.in6.sin6_addr, addr_str, sizeof(addr_str));
			port = ntohs(sa.in6.sin6_port);
		}
		logger(DEBUG_PROTOCOL, LOG_INFO, "Creating QUIC client connection to %s:%d using socket fd=%d",
		       addr_str, port, sock_fd);

		qconn = quic_conn_new_client(quic_manager->client_config->config, node->name,
		                              &sa.sa, sa_len, sock_fd);
	} else {
		/* Server connection will be created when receiving Initial packet */
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Server QUIC connections are created on packet reception");
		return NULL;
	}

	if(!qconn) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create QUIC connection to %s", node->name);
		return NULL;
	}

	/* Link to node */
	quic_conn_set_node(qconn, node);

	/* Add to connection tree */
	splay_insert(quic_manager->connections, qconn);

	/* Register connection IDs for demultiplexing */
	if(qconn->scid_len > 0) {
		register_connection_id(qconn->scid, qconn->scid_len, qconn);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Registered client SCID (len=%zu)", qconn->scid_len);
	}
	if(qconn->dcid_len > 0) {
		register_connection_id(qconn->dcid, qconn->dcid_len, qconn);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Registered client DCID (len=%zu)", qconn->dcid_len);
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Created QUIC %s connection to %s",
	       is_client ? "client" : "server", node->name);

	/* Send initial packet to start handshake */
	if(is_client) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Sending QUIC Initial packet to %s", node->name);
		quic_conn_send(qconn);
		logger(DEBUG_PROTOCOL, LOG_INFO, "quic_conn_send() completed for %s", node->name);
	}

	return qconn;
}

/* Remove QUIC connection */
void quic_transport_remove_connection(node_t *node) {
	if(!quic_manager || !quic_manager->connections || !node) {
		return;
	}

	/* Create temporary quic_conn for searching */
	quic_conn_t search_key;
	search_key.node = node;

	splay_node_t *sn = splay_search_node(quic_manager->connections, &search_key);

	if(!sn) {
		return;
	}

	quic_conn_t *qconn = (quic_conn_t *)sn->data;

	if(qconn) {
		/* Unregister all connection IDs before freeing */
		if(qconn->scid_len > 0) {
			unregister_connection_id(qconn->scid, qconn->scid_len);
		}
		if(qconn->dcid_len > 0) {
			unregister_connection_id(qconn->dcid, qconn->dcid_len);
		}
		quic_conn_free(qconn);
	}

	splay_delete_node(quic_manager->connections, sn);

	logger(DEBUG_PROTOCOL, LOG_INFO, "Removed QUIC connection for %s", node->name);
}

/* Send VPN packet via QUIC */
bool quic_transport_send_packet(node_t *node, vpn_packet_t *packet) {
	if(!quic_manager || !quic_manager->enabled || !node || !packet) {
		return false;
	}

	/* Get or create QUIC connection */
	quic_conn_t *qconn = quic_transport_get_connection(node);

	if(!qconn) {
		/* Create client connection */
		qconn = quic_transport_create_connection(node, true);

		if(!qconn) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create QUIC connection to %s", node->name);
			return false;
		}
	}

	/* Check if handshake is complete */
	if(!quic_conn_is_established(qconn)) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC handshake not complete for %s, buffering packet", node->name);
		/* Buffer packets until handshake completes */
		bool buffered = quic_conn_buffer_vpn_packet(qconn, DATA(packet), packet->len);

		if(!buffered) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Failed to buffer packet for %s", node->name);
		}

		/* Return true to indicate packet was handled (buffered) */
		/* This prevents immediate fallback to UDP */
		return buffered;
	}

	/* Send packet through QUIC stream */
	bool result = quic_conn_send_vpn_packet(qconn, DATA(packet), packet->len);

	if(result) {
		quic_manager->packets_sent++;
		quic_manager->bytes_sent += packet->len;
	}

	return result;
}

/* Handle incoming QUIC packet */
void quic_transport_handle_packet(const uint8_t *buf, size_t len,
                                   struct sockaddr *from, socklen_t fromlen) {
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "DEBUG: quic_transport_handle_packet() called, len=%zu", len);

	if(!quic_manager || !buf || len == 0) {
		return;
	}

	/* Parse QUIC header to get connection ID for demultiplexing */
	uint8_t type;
	uint32_t version;
	uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
	size_t scid_len = sizeof(scid);
	uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
	size_t dcid_len = sizeof(dcid);
	uint8_t token[256];
	size_t token_len = sizeof(token);

	int rc = quiche_header_info(buf, len, LOCAL_CONN_ID_LEN,
	                             &version, &type,
	                             scid, &scid_len,
	                             dcid, &dcid_len,
	                             token, &token_len);

	quic_conn_t *qconn = NULL;

	if(rc >= 0 && dcid_len > 0) {
		/* Try to find existing connection by DCID (our SCID) */
		qconn = lookup_connection_by_id(dcid, dcid_len);
	}

	/* Fallback: if CID lookup failed, try peer address lookup
	 * This handles Initial packets where client doesn't know our CID yet */
	if(!qconn && from) {
		for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
			quic_conn_t *candidate = (quic_conn_t *)n->data;
			if(candidate && candidate->peer_addr.ss_family == from->sa_family) {
				bool match = false;
				if(from->sa_family == AF_INET) {
					struct sockaddr_in *addr1 = (struct sockaddr_in *)&candidate->peer_addr;
					struct sockaddr_in *addr2 = (struct sockaddr_in *)from;
					match = (addr1->sin_port == addr2->sin_port &&
					         memcmp(&addr1->sin_addr, &addr2->sin_addr, sizeof(addr1->sin_addr)) == 0);
				} else if(from->sa_family == AF_INET6) {
					struct sockaddr_in6 *addr1 = (struct sockaddr_in6 *)&candidate->peer_addr;
					struct sockaddr_in6 *addr2 = (struct sockaddr_in6 *)from;
					match = (addr1->sin6_port == addr2->sin6_port &&
					         memcmp(&addr1->sin6_addr, &addr2->sin6_addr, sizeof(addr1->sin6_addr)) == 0);
				}
				if(match) {
					qconn = candidate;
					logger(DEBUG_PROTOCOL, LOG_DEBUG, "Found connection by peer address fallback");
					break;
				}
			}
		}
	}

	if(qconn) {
		/* Feed packet to connection */
		ssize_t done = quic_conn_recv(qconn, buf, len);

		if(done > 0) {
			quic_manager->packets_received++;
			quic_manager->bytes_received += done;

			/* Check if we need to bind server connection to node */
			if(quic_conn_is_established(qconn) && !qconn->node && qconn->peer_addr.ss_family != 0) {
				/* Server-side connection needs node binding */
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "Server connection established, attempting to bind node");

				/* Find node by peer address */
				for(splay_node_t *n = node_tree->head; n; n = n->next) {
					node_t *candidate = (node_t *)n->data;
					if(candidate && candidate->address.sa.sa_family == qconn->peer_addr.ss_family) {
						bool match = false;
						if(candidate->address.sa.sa_family == AF_INET) {
							struct sockaddr_in *addr1 = (struct sockaddr_in *)&candidate->address;
							struct sockaddr_in *addr2 = (struct sockaddr_in *)&qconn->peer_addr;
							match = (memcmp(&addr1->sin_addr, &addr2->sin_addr, sizeof(addr1->sin_addr)) == 0);
						} else if(candidate->address.sa.sa_family == AF_INET6) {
							struct sockaddr_in6 *addr1 = (struct sockaddr_in6 *)&candidate->address;
							struct sockaddr_in6 *addr2 = (struct sockaddr_in6 *)&qconn->peer_addr;
							match = (memcmp(&addr1->sin6_addr, &addr2->sin6_addr, sizeof(addr1->sin6_addr)) == 0);
						}

						if(match) {
							/* Found the node! Bind it to the connection */
							quic_conn_set_node(qconn, candidate);
							logger(DEBUG_PROTOCOL, LOG_INFO, "Bound QUIC server connection to node %s", candidate->name);
							break;
						}
					}
				}

				if(!qconn->node) {
					logger(DEBUG_PROTOCOL, LOG_WARNING, "Could not find node for server connection from %s",
					       sockaddr2hostname(&qconn->peer_addr));
				}
			}

			/* Try to read VPN packets from streams */
			uint8_t vpn_buf[4096];
			ssize_t vpn_len = quic_conn_recv_vpn_packet(qconn, vpn_buf, sizeof(vpn_buf));

			logger(DEBUG_PROTOCOL, LOG_DEBUG, "DEBUG: vpn_len = %zd", vpn_len);

			if(vpn_len > 0) {
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "DEBUG: Processing VPN packet");
				/* Create VPN packet and route it */
				vpn_packet_t vpacket;
				vpacket.offset = DEFAULT_PACKET_OFFSET;
				vpacket.priority = 0;  /* QUIC packets have normal priority */

				if((size_t)vpn_len > sizeof(vpacket.data) - vpacket.offset) {
					logger(DEBUG_PROTOCOL, LOG_WARNING, "Received oversized VPN packet (%zd bytes) via QUIC, dropping",
					       vpn_len);
					return;
				}

				vpacket.len = vpn_len;
				memcpy(DATA(&vpacket), vpn_buf, vpn_len);

				/* Get node from connection */
				node_t *node = (node_t *)qconn->node;

				if(node) {
					logger(DEBUG_PROTOCOL, LOG_DEBUG, "Received VPN packet (%zd bytes) from %s via QUIC",
					       vpn_len, node->name);

					/* Route packet through tinc */
					receive_packet(node, &vpacket);
				}
			}

			logger(DEBUG_PROTOCOL, LOG_DEBUG, "DEBUG: Before flush check");

			/* Flush buffered packets if handshake just completed */
			/* Only flush if we have a bound node (client connections have node set at creation,
			 * server connections get it when first VPN packet arrives) */
			if(quic_conn_is_established(qconn) && qconn->send_buf_count > 0 && qconn->node) {
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "DEBUG: Calling flush");
				quic_conn_flush_buffered_packets(qconn);
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "DEBUG: Flush complete");
			}

			logger(DEBUG_PROTOCOL, LOG_DEBUG, "DEBUG: Before quic_conn_send");
			/* Send any pending QUIC packets */
			quic_conn_send(qconn);
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "DEBUG: After quic_conn_send");
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "DEBUG: About to return");

			return;  // Packet processed
		}
	}

	/* No existing connection handled this packet */
	/* Check if it's a new connection (Initial packet) */

	/* Header was already parsed above for demultiplexing */
	if(rc < 0) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Failed to parse QUIC header for new connection: %d", rc);
		return;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Received QUIC packet from unknown source: type=%u version=0x%x", type, version);

	/* Create server connection for new clients
	 * Note: quiche may use different type numbering than QUIC spec
	 * So we don't filter by type here - quiche_accept will handle validation
	 */

	/* Select appropriate socket based on address family */
	int sock_fd = -1;
	for(int i = 0; i < quic_manager->num_sockets; i++) {
		if(quic_manager->sockets[i]->sa.sa.sa_family == from->sa_family) {
			sock_fd = quic_manager->sockets[i]->udp.fd;
			break;
		}
	}

	if(sock_fd < 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "No suitable socket found for incoming connection");
		return;
	}

	/* Create new server connection */
	qconn = quic_conn_new_server(quic_manager->server_config->config,
	                              scid, scid_len,  /* SCID from client becomes our DCID */
	                              dcid, dcid_len,  /* DCID from client is ODCID */
	                              from, fromlen, sock_fd);

	if(!qconn) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create server connection");
		return;
	}

	/* Node will be auto-detected when first VPN packet is received */
	/* (see automatic binding logic in packet receive handler) */

	/* Add to connection tree */
	splay_insert(quic_manager->connections, qconn);

	/* Register connection IDs for demultiplexing
	 * Register both our SCID and client's DCID (our DCID) so we can find
	 * the connection regardless of which CID is used in incoming packets */
	if(qconn->scid_len > 0) {
		register_connection_id(qconn->scid, qconn->scid_len, qconn);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Registered our SCID (len=%zu)", qconn->scid_len);
	}
	if(qconn->dcid_len > 0) {
		register_connection_id(qconn->dcid, qconn->dcid_len, qconn);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Registered client's DCID (len=%zu)", qconn->dcid_len);
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Created QUIC server connection for new client");

	/* Process the Initial packet */
	ssize_t done = quic_conn_recv(qconn, buf, len);

	if(done < 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to process Initial packet: %zd", done);
		splay_delete(quic_manager->connections, qconn);
		quic_conn_free(qconn);
		return;
	}

	quic_manager->packets_received++;
	quic_manager->bytes_received += done;

	/* Send response (Handshake packet) */
	quic_conn_send(qconn);
}

/* Event loop callback for incoming QUIC data
 * NOTE: This function is deprecated and will be removed.
 * QUIC packets are now handled via packet demultiplexing in handle_incoming_vpn_data()
 * which calls quic_transport_handle_packet() directly.
 */
void handle_incoming_quic_data(void *data, int flags) {
	logger(DEBUG_PROTOCOL, LOG_WARNING,
	       "handle_incoming_quic_data() called but should not be used with shared socket architecture");
}

/* Check if QUIC transport is enabled */
bool quic_transport_is_enabled(void) {
	bool result = quic_manager && quic_manager->enabled;
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "quic_transport_is_enabled() = %d (quic_manager=%p, enabled=%d)",
	       result, quic_manager, quic_manager ? quic_manager->enabled : -1);
	return result;
}

/* Set transport mode */
void quic_transport_set_mode(transport_mode_t mode) {
	transport_mode = mode;

	if(quic_manager) {
		quic_manager->enabled = (mode == TRANSPORT_QUIC || mode == TRANSPORT_HYBRID);
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Transport mode set to %d (%s)", mode,
	       mode == TRANSPORT_UDP ? "UDP" :
	       mode == TRANSPORT_TCP ? "TCP" :
	       mode == TRANSPORT_QUIC ? "QUIC" : "HYBRID");
}
