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
#include "../connection.h"
#include "../meta.h"
#include "../net.h"
#include "../protocol.h"
#include "quic_transport.h"
#include <quiche.h>
#include "quic.h"
#include "quic_reality.h"
#include "quic_fingerprint.h"
#include "../event.h"

/* Global QUIC manager */
quic_manager_t *quic_manager = NULL;
static timeout_t quic_timer;

/* Helper: find an existing QUIC meta connection_t without bound node
 * that matches the given qconn peer address. */
static connection_t *find_unbound_quic_meta_for_peer(const quic_conn_t *qconn) {
    if(!qconn) return NULL;
    for(list_node_t *ln = connection_list ? connection_list->head : NULL; ln; ln = ln->next) {
        connection_t *c = (connection_t *)ln->data;
        if(!c) continue;
        if(!c->status.quic_meta) continue;
        if(c->node) continue; /* only unbound */
        /* Match by peer address */
        if(sockaddrcmp_noport(&c->address, (const sockaddr_t *)&qconn->peer_addr) == 0) {
            return c;
        }
    }
    return NULL;
}

static void quic_timeout_handler(void *data) {
    (void)data;
    if(!quic_manager || !quic_manager->connections || !quic_manager->connections->head) {
        /* Reschedule conservatively */
        timeout_set(&quic_timer, &(struct timeval){0, 100000});
        return;
    }

    /* Compute minimal timeout across connections */
    uint64_t min_ns = UINT64_MAX;
    for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
        quic_conn_t *qconn = (quic_conn_t *)n->data;
        if(!qconn || !qconn->conn) continue;
        uint64_t ns = quiche_conn_timeout_as_nanos(qconn->conn);
        if(ns > 0 && ns < min_ns) {
            min_ns = ns;
        }
    }

    /* Drive timeouts now */
    for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
        quic_conn_t *qconn = (quic_conn_t *)n->data;
        if(!qconn || !qconn->conn) continue;
        quiche_conn_on_timeout(qconn->conn);
        while(true) {
            ssize_t sent = quic_conn_send(qconn);
            if(sent <= 0) break;
        }
    }

    /* Reschedule at minimal timeout (fallback 50ms) */
    if(min_ns == UINT64_MAX) {
        timeout_set(&quic_timer, &(struct timeval){0, 50000});
    } else {
        struct timeval tv = { .tv_sec = (time_t)(min_ns / 1000000000ULL), .tv_usec = (suseconds_t)((min_ns % 1000000000ULL) / 1000ULL) };
        timeout_set(&quic_timer, &tv);
    }
}

/* Forward declaration for local helper used before its definition */
static void quic_flush_meta_outbuf(connection_t *c, quic_conn_t *qconn);

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

/* Форматирует Connection ID в hex строку для логирования
 * ВАЖНО: используем кольцевой буфер из нескольких слотов, чтобы
 * одновременные вызовы в одном выражении логгера не перезаписывали
 * предыдущие результаты (static-buffer pitfall). */
static const size_t CID_STR_SLOTS = 4;
static char *format_cid(const uint8_t *cid, size_t len) {
    static char bufs[4][128];
    static unsigned idx = 0;
    char *buf = bufs[idx++ % CID_STR_SLOTS];
    if(len == 0 || len > 20 || !cid) {
        snprintf(buf, sizeof(bufs[0]), "<empty>");
        return buf;
    }
    char *p = buf;
    for(size_t i = 0; i < len && i < 20; i++) {
        p += sprintf(p, "%02x", cid[i]);
    }
    *p = '\0';
    return buf;
}

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

		/* Port doesn't matter - same IP is same peer */
	return 0;
	} else if(qa->peer_addr.ss_family == AF_INET6) {
		const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)&qa->peer_addr;
		const struct sockaddr_in6 *sb = (const struct sockaddr_in6 *)&qb->peer_addr;

		int addr_cmp = memcmp(&sa->sin6_addr, &sb->sin6_addr, sizeof(sa->sin6_addr));
		if(addr_cmp != 0) {
			return addr_cmp;
		}

		/* Port doesn't matter - same IP is same peer */
	return 0;
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

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Registered CID=%s (len=%zu) for demultiplexing",
	       format_cid(conn_id, conn_id_len), conn_id_len);
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
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "lookup_connection_by_id() called for CID=%s (len=%zu)",
	       format_cid(conn_id, conn_id_len), conn_id_len);

	if(!quic_manager || !quic_manager->conn_id_map || !conn_id || conn_id_len == 0) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "lookup_connection_by_id() - invalid parameters, returning NULL");
		return NULL;
	}

	/* Count registered CIDs for debugging */
	int cid_count = 0;
	if(quic_manager->conn_id_map) {
		for(splay_node_t *n = quic_manager->conn_id_map->head; n; n = n->next) {
			cid_count++;
		}
	}
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Total registered CIDs in map: %d", cid_count);

	conn_id_entry_t search;
	memset(&search, 0, sizeof(search));  // Zero entire structure to avoid padding issues
	memcpy(search.conn_id, conn_id, conn_id_len);
	search.conn_id_len = conn_id_len;

	/* splay_search returns data pointer, not node */
	conn_id_entry_t *entry = (conn_id_entry_t *)splay_search(quic_manager->conn_id_map, &search);
	if(entry) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "lookup_connection_by_id() - FOUND connection for CID=%s",
		       format_cid(conn_id, conn_id_len));
		return entry->conn;
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "lookup_connection_by_id() - NOT FOUND for CID=%s",
	       format_cid(conn_id, conn_id_len));
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

    /* Start periodic QUIC timeout driver */
    timeout_add(&quic_timer, quic_timeout_handler, &quic_timer, &(struct timeval){0, 10000});

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

/* Helper: Find QUIC connection by peer address only (for incoming connections)
 * Used during node binding when we don't know the node yet */
quic_conn_t *quic_find_connection_by_address(const sockaddr_t *addr) {
    if(!quic_manager || !quic_manager->connections || !addr) {
        return NULL;
    }

    /* Iterate through all live QUIC connections */
    for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
        quic_conn_t *qconn = (quic_conn_t *)n->data;
        if(!qconn) {
            continue;
        }
        /* Compare peer addresses ignoring port (we match IP only) */
        if(sockaddrcmp_noport(addr, (const sockaddr_t *)&qconn->peer_addr) == 0) {
            return qconn;
        }
    }

    return NULL;
}

/* Get QUIC connection for a node */
quic_conn_t *quic_transport_get_connection(node_t *node, const sockaddr_t *sa) {
	if(!quic_manager || !quic_manager->connections || !node) {
		return NULL;
	}

	/* Create temporary quic_conn for searching by address */
	quic_conn_t search_key;
	memset(&search_key, 0, sizeof(search_key));

	/* Use provided address if available, otherwise fall back to node->address */
	const sockaddr_t *lookup_addr = sa ? sa : &node->address;

	if(!lookup_addr->sa.sa_family) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Node %s has no valid address for connection lookup (sa_family=0)", node->name);
		return NULL;
	}

	char *addr_str = sockaddr2hostname(lookup_addr);
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Looking up QUIC connection for node %s at address %s (sa_family=%d)",
	       node->name, addr_str ? addr_str : "NULL", lookup_addr->sa.sa_family);
	free(addr_str);

	memcpy(&search_key.peer_addr, lookup_addr, sizeof(struct sockaddr_storage));

	splay_node_t *sn = splay_search_node(quic_manager->connections, &search_key);

	if(!sn) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "No QUIC connection found in splay tree for node %s", node->name);
		return NULL;
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Found existing QUIC connection for node %s", node->name);
	return (quic_conn_t *)sn->data;
}

/* Create QUIC connection for a node */
quic_conn_t *quic_transport_create_connection(node_t *node, bool is_client, const sockaddr_t *sa) {
	if(!quic_manager || !node) {
		return NULL;
	}

	/* Check if node already has a QUIC connection via connection_t */
	if(node->connection && node->connection->status.quic_meta) {
		/* Find the quic_conn_t by searching the splay tree */
		quic_conn_t *existing = quic_transport_get_connection(node, NULL);
		if(existing) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "Reusing existing QUIC connection to %s", node->name);
			return existing;
		}
		/* If lookup failed but connection_t exists, this is unexpected but continue to create new one */
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Node %s has connection_t but QUIC connection lookup failed", node->name);
	}

	quic_conn_t *qconn = NULL;

	if(is_client) {
		/* Create client connection */
		sockaddr_t sa_copy;
		socklen_t sa_len;

		/* Use provided address */
		if(!sa || !sa->sa.sa_family) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Node %s has no address for QUIC connection", node->name);
			return NULL;
		}

		memcpy(&sa_copy, sa, sizeof(sa_copy));
		sa_len = SALEN(sa_copy.sa);

		/* Keep the peer's actual port from the node address */
		/* This will be the Port= value configured on the peer */

		/* Select appropriate socket based on address family */
		int sock_fd = -1;
		for(int i = 0; i < quic_manager->num_sockets; i++) {
			if(quic_manager->sockets[i]->sa.sa.sa_family == sa_copy.sa.sa_family) {
				sock_fd = quic_manager->sockets[i]->udp.fd;
				logger(DEBUG_PROTOCOL, LOG_INFO, "Selected socket fd=%d for address family %d",
				       sock_fd, sa_copy.sa.sa_family);
				break;
			}
		}

		if(sock_fd < 0) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "No suitable socket found for address family %d", sa_copy.sa.sa_family);
			return NULL;
		}

		/* Log the destination address */
		char addr_str[INET6_ADDRSTRLEN];
		int port = 0;
		if(sa_copy.sa.sa_family == AF_INET) {
			inet_ntop(AF_INET, &sa_copy.in.sin_addr, addr_str, sizeof(addr_str));
			port = ntohs(sa_copy.in.sin_port);
		} else if(sa_copy.sa.sa_family == AF_INET6) {
			inet_ntop(AF_INET6, &sa_copy.in6.sin6_addr, addr_str, sizeof(addr_str));
			port = ntohs(sa_copy.in6.sin6_port);
		}
		logger(DEBUG_PROTOCOL, LOG_INFO, "Creating QUIC client connection to %s:%d using socket fd=%d",
		       addr_str, port, sock_fd);

		qconn = quic_conn_new_client(quic_manager->client_config->config, node->name,
		                              &sa_copy.sa, sa_len, sock_fd);
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

	/* Create connection_t for QUIC meta protocol */
	if(!node->connection) {
		connection_t *c = new_connection();
		c->name = xstrdup(node->name);
		c->outcipher = myself->connection->outcipher;
		c->outdigest = myself->connection->outdigest;
		c->outmaclength = myself->connection->outmaclength;
		c->outcompression = myself->connection->outcompression;

		/* Set address from QUIC connection */
		memcpy(&c->address, &qconn->peer_addr, sizeof(struct sockaddr_storage));
		c->hostname = sockaddr2hostname((sockaddr_t *)&qconn->peer_addr);
		c->last_ping_time = now.tv_sec;
		c->node = node;
		c->edge = NULL;

		/* Mark as QUIC meta connection */
		c->status.quic_meta = true;

		/* Add to connection list and link to node */
		connection_add(c);
		node->connection = c;

		logger(DEBUG_PROTOCOL, LOG_INFO, "Created connection_t for QUIC %s connection to %s",
		       is_client ? "outgoing" : "incoming", node->name);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Linked connection_t %p to node %s (quic_meta=%d)",
		       (void *)c, node->name, c->status.quic_meta);
	}

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
	quic_conn_t *qconn = quic_transport_get_connection(node, NULL);

	if(!qconn) {
		/* Create client connection */
		qconn = quic_transport_create_connection(node, true, &node->address);

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

    if(!quic_manager || !buf || len == 0) {
        return;
    }

    /* Trace incoming UDP for QUIC demux */
    char src[INET6_ADDRSTRLEN] = {0};
    int sport = 0;
    if(from) {
        if(from->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)from;
            inet_ntop(AF_INET, &sin->sin_addr, src, sizeof(src));
            sport = ntohs(sin->sin_port);
        } else if(from->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)from;
            inet_ntop(AF_INET6, &sin6->sin6_addr, src, sizeof(src));
            sport = ntohs(sin6->sin6_port);
        }
    }
    logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC demux: received UDP len=%zu from %s:%d", len, src[0]?src:"?", sport);

    /* Parse QUIC header to get connection ID for demultiplexing */
	uint8_t type;
	uint32_t version;
	uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
	size_t scid_len = sizeof(scid);
	uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
	size_t dcid_len = sizeof(dcid);
	uint8_t token[256];
	size_t token_len = sizeof(token);

    /* NOTE: Use a destination CID length hint of 0 to let quiche parse DCID length from packet.
     * Using a fixed LOCAL_CONN_ID_LEN can cause DCID==SCID in logs when lengths mismatch. */
    int rc = quiche_header_info(buf, len, 0,
                                 &version, &type,
                                 scid, &scid_len,
                                 dcid, &dcid_len,
                                 token, &token_len);

	/* Log parsed header information */
	if(rc >= 0) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Parsed QUIC header: type=%u version=0x%x DCID=%s (len=%zu) SCID=%s (len=%zu)",
		       type, version, format_cid(dcid, dcid_len), dcid_len,
		       format_cid(scid, scid_len), scid_len);
		/* TRACE: Log SCID value immediately after parsing */
		logger(DEBUG_PROTOCOL, LOG_INFO, "TRACE after parse: scid=%s scid_len=%zu",
		       format_cid(scid, scid_len), scid_len);
	} else {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Failed to parse QUIC header: rc=%d", rc);
	}

	quic_conn_t *qconn = NULL;

    if(rc >= 0 && dcid_len > 0) {
        /* Try to find existing connection by DCID (our SCID) */
        qconn = lookup_connection_by_id(dcid, dcid_len);

		if(qconn) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "CID lookup SUCCESS: Found connection for DCID=%s",
			       format_cid(dcid, dcid_len));
		} else {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "CID lookup FAILED: No connection found for DCID=%s, trying address fallback",
			       format_cid(dcid, dcid_len));
		}
	}

    /* Fallback: if CID lookup failed, try peer address lookup
     * IMPORTANT: do not bind incoming packets to an existing CLIENT-side connection,
     * or handshake will stall. Only consider server-side (incoming) connections here. */
    if(!qconn && from) {
        for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
            quic_conn_t *candidate = (quic_conn_t *)n->data;
            if(!candidate) {
                continue;
            }
            /* Skip client-initiated connections */
            if(candidate->is_client) {
                continue;
            }
            if(candidate->peer_addr.ss_family == from->sa_family) {
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

	/* For client connections: register peer SCID from packet header BEFORE processing packet
	 * This allows quiche to recognize the DCID in server responses during handshake */
	if(qconn && qconn->is_client && scid_len > 0) {
		/* TRACE: Log SCID value right before registration */
		logger(DEBUG_PROTOCOL, LOG_INFO, "TRACE before register: qconn=%p is_client=%d scid=%s scid_len=%zu",
		       qconn, qconn->is_client, format_cid(scid, scid_len), scid_len);

		/* Check if this peer SCID is already registered */
		quic_conn_t *existing = lookup_connection_by_id(scid, scid_len);
		if(!existing) {
			/* Register server's SCID for demultiplexing */
			register_connection_id(scid, scid_len, qconn);
			logger(DEBUG_PROTOCOL, LOG_INFO,
			       "Client: registered peer SCID=%s (len=%zu) from packet header before quic_conn_recv()",
			       format_cid(scid, scid_len), scid_len);
		} else if(existing != qconn) {
			logger(DEBUG_PROTOCOL, LOG_WARNING,
			       "Client: peer SCID=%s from packet header already registered to different connection",
			       format_cid(scid, scid_len));
		}
	}

    if(qconn) {
        /* Feed packet to connection; loop until quiche reports no more packets to send */
        ssize_t done = quic_conn_recv(qconn, buf, len);

        if(done > 0) {
            quic_manager->packets_received++;
            quic_manager->bytes_received += done;
            /* Proactively send any handshake responses/packets */
            while(true) {
                ssize_t sent = quic_conn_send(qconn);
                if(sent <= 0) break;
            }

        /* Check if we need to bind server connection to node */
			bool is_established = quic_conn_is_established(qconn);
			if(is_established && !qconn->node && qconn->peer_addr.ss_family != 0) {
				/* Server-side connection needs node binding */
				char *peer_hostname = sockaddr2hostname((sockaddr_t *)&qconn->peer_addr);
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "Server connection established from %s (family=%d), attempting to bind node",
				       peer_hostname, qconn->peer_addr.ss_family);
				free(peer_hostname);

				/* Find node by peer address */
				for(splay_node_t *n = node_tree->head; n; n = n->next) {
					node_t *candidate = (node_t *)n->data;

					/* Debug: log each candidate node */
					if(candidate) {
						char *cand_hostname = sockaddr2hostname(&candidate->address);
						logger(DEBUG_PROTOCOL, LOG_DEBUG, "  Checking node '%s': addr=%s family=%d",
						       candidate->name ? candidate->name : "NULL",
						       cand_hostname,
						       candidate->address.sa.sa_family);
						free(cand_hostname);
					}

					if(candidate && candidate->address.sa.sa_family == qconn->peer_addr.ss_family) {
						bool match = false;
						if(candidate->address.sa.sa_family == AF_INET) {
							struct sockaddr_in *addr1 = (struct sockaddr_in *)&candidate->address;
							struct sockaddr_in *addr2 = (struct sockaddr_in *)&qconn->peer_addr;

							/* Debug: print IP addresses in human readable format */
							char ip1[INET_ADDRSTRLEN], ip2[INET_ADDRSTRLEN];
							inet_ntop(AF_INET, &addr1->sin_addr, ip1, INET_ADDRSTRLEN);
							inet_ntop(AF_INET, &addr2->sin_addr, ip2, INET_ADDRSTRLEN);
							logger(DEBUG_PROTOCOL, LOG_DEBUG, "    IPv4 compare: candidate=%s peer=%s", ip1, ip2);

							match = (memcmp(&addr1->sin_addr, &addr2->sin_addr, sizeof(addr1->sin_addr)) == 0);
						} else if(candidate->address.sa.sa_family == AF_INET6) {
							struct sockaddr_in6 *addr1 = (struct sockaddr_in6 *)&candidate->address;
							struct sockaddr_in6 *addr2 = (struct sockaddr_in6 *)&qconn->peer_addr;

							/* Debug: print IP addresses in human readable format */
							char ip1[INET6_ADDRSTRLEN], ip2[INET6_ADDRSTRLEN];
							inet_ntop(AF_INET6, &addr1->sin6_addr, ip1, INET6_ADDRSTRLEN);
							inet_ntop(AF_INET6, &addr2->sin6_addr, ip2, INET6_ADDRSTRLEN);
							logger(DEBUG_PROTOCOL, LOG_DEBUG, "    IPv6 compare: candidate=%s peer=%s", ip1, ip2);

							match = (memcmp(&addr1->sin6_addr, &addr2->sin6_addr, sizeof(addr1->sin6_addr)) == 0);
						}

						if(match) {
							/* Found the node! Bind it to the connection */
							quic_conn_set_node(qconn, candidate);
							logger(DEBUG_PROTOCOL, LOG_INFO, "Bound QUIC server connection to node %s", candidate->name);

							/* Create connection_t for incoming QUIC connection if it doesn't exist */
							if(!candidate->connection) {
								connection_t *c = new_connection();
								c->name = xstrdup(candidate->name);
								c->outcipher = myself->connection->outcipher;
								c->outdigest = myself->connection->outdigest;
								c->outmaclength = myself->connection->outmaclength;
								c->outcompression = myself->connection->outcompression;

								/* Convert sockaddr_storage to sockaddr_t */
								memcpy(&c->address, &qconn->peer_addr, sizeof(struct sockaddr_storage));
								c->hostname = sockaddr2hostname((sockaddr_t *)&qconn->peer_addr);
								c->last_ping_time = now.tv_sec;
								c->node = candidate;
								c->edge = NULL;

								/* Mark as QUIC meta connection */
								c->status.quic_meta = true;

								/* Add to connection list and link to node */
								connection_add(c);
								candidate->connection = c;

								logger(DEBUG_PROTOCOL, LOG_INFO, "Created connection_t for incoming QUIC from %s", candidate->name);
							}
							break;
						}
					}
				}

				if(!qconn->node) {
                    logger(DEBUG_PROTOCOL, LOG_INFO, "Could not find node for server connection from %s - will bind via ID message",
                           sockaddr2hostname((sockaddr_t *)&qconn->peer_addr));

                    /* Hybrid binding: Create connection_t for incoming connection and keep name unset
                     * so send_id() uses our proper name toward the peer. */
                    connection_t *c = new_connection();
                    c->name = NULL;
					c->outcipher = myself->connection->outcipher;
					c->outdigest = myself->connection->outdigest;
					c->outmaclength = myself->connection->outmaclength;
					c->outcompression = myself->connection->outcompression;

					/* Convert sockaddr_storage to sockaddr_t */
					memcpy(&c->address, &qconn->peer_addr, sizeof(struct sockaddr_storage));
					c->hostname = sockaddr2hostname((sockaddr_t *)&qconn->peer_addr);
					c->last_ping_time = now.tv_sec;
					c->node = NULL;  /* Will be set when ID message arrives */
					c->edge = NULL;

					/* Mark as QUIC meta connection */
					c->status.quic_meta = true;
					c->status.sptps_disabled = true;

					/* Create metadata stream for this unbound connection */
					int64_t stream_id = quic_meta_create_stream(qconn);

					if(stream_id >= 0) {
						c->quic_stream_id = stream_id;
						logger(DEBUG_PROTOCOL, LOG_INFO, "Created QUIC meta stream %ld for unbound incoming connection from %s",
						       (long)stream_id, c->hostname);

						/* Add to connection list - will be linked to node when ID message arrives */
						connection_add(c);

                    /* Initiate metadata protocol to receive ID message */
                    c->allow_request = ID;
                    /* Do not send raw metadata before we know peer's identity */

						logger(DEBUG_PROTOCOL, LOG_INFO, "Created connection_t for unbound incoming QUIC from %s, waiting for ID message",
						       c->hostname);
					} else {
						logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create QUIC meta stream for incoming connection from %s",
						       c->hostname);
						free_connection(c);
					}
				}
			}

			/* Trigger metadata protocol for outgoing connections when handshake completes */
		if(qconn->node) {
			bool is_established = quic_conn_is_established(qconn);
			node_t *n = (node_t *)qconn->node;
			connection_t *c = n->connection;

            logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC state check for %s: established=%d, connection=%p, quic_meta=%d, quic_stream_id=%ld, outgoing=%p, initiated=%d",
                   n->name, is_established, (void*)c,
                   c ? c->status.quic_meta : -1,
                   c ? (long)c->quic_stream_id : -1L,
                   c ? (void*)c->outgoing : NULL,
                   c ? c->status.meta_protocol_initiated : -1);

            if(is_established) {
                /* For QUIC connections, we don't need c->outgoing to be set */
                /* QUIC client connections are identified by qconn->is_client */
                if(c && !c->status.meta_protocol_initiated && c->status.quic_meta) {
                    logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC handshake complete for %s, initiating metadata protocol",
                           n->name);

					/* Create or discover metadata stream NOW - after handshake, before finish_connecting()
					 * This ensures the stream is immediately usable for ID/ACK exchange */
                        if(c->quic_stream_id < 0) {
                            if(qconn->is_client) {
                                /* Try to discover server-initiated stream */
                                logger(DEBUG_PROTOCOL, LOG_INFO, "Attempting stream discovery for %s after handshake", n->name);
                                quiche_stream_iter *readable = quiche_conn_readable(qconn->conn);
                                bool discovered = false;
                                if(readable) {
                                    uint64_t stream_id;
                                    if(quiche_stream_iter_next(readable, &stream_id)) {
                                        c->quic_stream_id = stream_id;
                                        discovered = true;
                                        logger(DEBUG_PROTOCOL, LOG_INFO, "Discovered QUIC meta stream %ld from %s after handshake",
                                               (long)stream_id, n->name);
                                    }
                                    quiche_stream_iter_free(readable);
                                }
                                /* If not discovered, proactively create client stream */
                                if(!discovered) {
                                    int64_t stream_id = quic_meta_create_stream(qconn);
                                    if(stream_id >= 0) {
                                        c->quic_stream_id = stream_id;
                                        logger(DEBUG_PROTOCOL, LOG_INFO, "Created client QUIC meta stream %ld for %s after handshake",
                                               (long)stream_id, n->name);
                                    } else {
                                        logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create client QUIC meta stream for %s", n->name);
                                        return;
                                    }
                                }
                            } else {
                                /* Server: create stream if not present */
                                int64_t stream_id = quic_meta_create_stream(qconn);
                                if(stream_id >= 0) {
                                    c->quic_stream_id = stream_id;
                                    logger(DEBUG_PROTOCOL, LOG_INFO, "Created QUIC meta stream %ld for %s after handshake",
                                           (long)stream_id, n->name);
                                } else {
                                    logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create QUIC meta stream for %s after handshake",
                                           n->name);
                                    return;
                                }
                            }
                        }

                        /* Kick off metadata protocol by sending ID now on both sides */
                        c->status.meta_protocol_initiated = 1;
                        if(!send_id(c)) {
                            logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to queue ID for %s", n->name);
                        } else {
                            logger(DEBUG_PROTOCOL, LOG_INFO, "Queued ID for %s on QUIC meta stream %ld",
                                   n->name, (long)c->quic_stream_id);
                        }
                        /* Immediately flush initial ID over QUIC stream */
                        quic_conn_t *qc = quic_transport_get_connection(n, NULL);
                        if(qc) {
                            quic_flush_meta_outbuf(c, qc);
                        }
                        /* Continue with normal post-connect processing */
                        finish_connecting(c);
                    }
                }
		}

		/* Try to read VPN packets from streams */
			uint8_t vpn_buf[4096];
			ssize_t vpn_len = quic_conn_recv_vpn_packet(qconn, vpn_buf, sizeof(vpn_buf));


			if(vpn_len > 0) {
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

			/* Check for meta-connection data (control plane) */
			node_t *node = (node_t *)qconn->node;

            logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC packet processed: qconn->node=%p", (void*)node);

            if(node) {
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC node found: name=%s, connection=%p",
				       node->name ? node->name : "NULL", (void*)node->connection);

				if(node->connection) {
					connection_t *c = node->connection;
                    logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC checking connection: name=%s, quic_meta=%d, quic_stream_id=%ld, outgoing=%p",
                           c->name ? c->name : "NULL", c->status.quic_meta, (long)c->quic_stream_id, (void*)c->outgoing);

					/* If this connection has a QUIC meta stream, check for readable data */
					if(c->status.quic_meta) {
						/* Stream discovery: if stream_id not yet set, find the first readable stream */
						if(c->quic_stream_id < 0) {
							logger(DEBUG_PROTOCOL, LOG_INFO, "Attempting stream discovery for %s", c->name);
							quiche_stream_iter *readable = quiche_conn_readable(qconn->conn);
							if(readable) {
								uint64_t stream_id;
								if(quiche_stream_iter_next(readable, &stream_id)) {
									c->quic_stream_id = stream_id;
									logger(DEBUG_PROTOCOL, LOG_INFO, "Discovered QUIC meta stream %ld from %s",
									       (long)stream_id, c->name);
								} else {
									logger(DEBUG_PROTOCOL, LOG_DEBUG, "No readable streams yet for %s", c->name);
								}
								quiche_stream_iter_free(readable);
							} else {
								logger(DEBUG_PROTOCOL, LOG_DEBUG, "quiche_conn_readable returned NULL for %s", c->name);
							}
						}

						/* Now check if we have a stream and if it has readable data */
						if(c->quic_stream_id >= 0 && quic_meta_stream_readable(qconn, c->quic_stream_id)) {
							logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC meta stream %ld has readable data from %s",
							       (long)c->quic_stream_id, c->name);

							/* Call receive_meta to process metadata from QUIC stream */
							if(!receive_meta(c)) {
								logger(DEBUG_PROTOCOL, LOG_ERR, "Error processing meta data from QUIC stream %ld",
								       (long)c->quic_stream_id);
							}
						}
					}
				}
            } else {
                /* Handle unbound server-side meta connection: process readable meta
                 * so that ID can be received and node binding can proceed. */
                connection_t *uc = find_unbound_quic_meta_for_peer(qconn);
                if(uc) {
                    /* Discover stream if needed */
                    if(uc->quic_stream_id < 0) {
                        quiche_stream_iter *readable = quiche_conn_readable(qconn->conn);
                        if(readable) {
                            uint64_t sid;
                            if(quiche_stream_iter_next(readable, &sid)) {
                                uc->quic_stream_id = sid;
                                logger(DEBUG_PROTOCOL, LOG_INFO, "Discovered QUIC meta stream %ld for unbound peer",
                                       (long)sid);
                            }
                            quiche_stream_iter_free(readable);
                        }
                    }
                    if(uc->quic_stream_id >= 0 && quic_meta_stream_readable(qconn, uc->quic_stream_id)) {
                        logger(DEBUG_PROTOCOL, LOG_DEBUG, "Processing meta for unbound peer on stream %ld",
                               (long)uc->quic_stream_id);
                        receive_meta(uc);
                    }
                } else {
                    logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC packet has no associated node and no unbound meta found");
                }
            }

			/* Flush buffered packets if handshake just completed */
			/* Only flush if we have a bound node (client connections have node set at creation,
			 * server connections get it when first VPN packet arrives) */
			if(quic_conn_is_established(qconn) && qconn->send_buf_count > 0 && qconn->node) {
				quic_conn_flush_buffered_packets(qconn);
			}

            /* Send any pending QUIC packets; keep sending until QUICHE_ERR_DONE */
            while(true) {
                ssize_t sent = quic_conn_send(qconn);
                if(sent <= 0) break;
            }
            /* Drive quiche timeouts to progress handshake */
            quiche_conn_on_timeout(qconn->conn);

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

	/* Before creating new server connection, check if this is a response to existing client connection */
	/* IMPORTANT: Only route packet to client connection if DCID matches our client's SCID
	 * This prevents routing incoming Initial packets from OTHER clients to OUR client connections */
	if(scid_len > 0 && dcid_len > 0 && from) {
		/* Look for client connections that might be waiting for this response */
		for(splay_node_t *node_iter = quic_manager->connections->head; node_iter; node_iter = node_iter->next) {
			quic_conn_t *candidate = (quic_conn_t *)node_iter->data;
			if(candidate && candidate->is_client && candidate->peer_addr.ss_family == from->sa_family) {
				bool addr_match = false;
				/* Check if peer address matches (IP only, port may differ) */
				if(from->sa_family == AF_INET) {
					struct sockaddr_in *addr1 = (struct sockaddr_in *)&candidate->peer_addr;
					struct sockaddr_in *addr2 = (struct sockaddr_in *)from;
					addr_match = (memcmp(&addr1->sin_addr, &addr2->sin_addr, sizeof(addr1->sin_addr)) == 0);
				} else if(from->sa_family == AF_INET6) {
					struct sockaddr_in6 *addr1 = (struct sockaddr_in6 *)&candidate->peer_addr;
					struct sockaddr_in6 *addr2 = (struct sockaddr_in6 *)from;
					addr_match = (memcmp(&addr1->sin6_addr, &addr2->sin6_addr, sizeof(addr1->sin6_addr)) == 0);
				}

				/* Check if DCID in packet matches our client SCID */
				bool dcid_match = (candidate->scid_len == dcid_len &&
				                   memcmp(candidate->scid, dcid, dcid_len) == 0);

				logger(DEBUG_PROTOCOL, LOG_DEBUG,
				       "Client connection candidate: addr_match=%d dcid_match=%d (our_scid=%s packet_dcid=%s)",
				       addr_match, dcid_match,
				       format_cid(candidate->scid, candidate->scid_len),
				       format_cid(dcid, dcid_len));

				if(addr_match && dcid_match) {
					/* Found matching client connection - this is a response to our Initial */
					logger(DEBUG_PROTOCOL, LOG_INFO,
					       "Found existing client connection by DCID match - registering peer SCID=%s from packet header",
					       format_cid(scid, scid_len));

					/* Register peer SCID for demultiplexing */
					register_connection_id(scid, scid_len, candidate);

					/* Now route the packet to this connection */
					ssize_t done = quic_conn_recv(candidate, buf, len);
					if(done > 0) {
						quic_manager->packets_received++;
						quic_manager->bytes_received += done;
						logger(DEBUG_PROTOCOL, LOG_INFO,
						       "Successfully routed packet to existing client connection after peer SCID registration");

						/* Continue with normal packet processing */
						if(quic_conn_is_established(candidate) && candidate->send_buf_count > 0 && candidate->node) {
							quic_conn_flush_buffered_packets(candidate);
						}
						quic_conn_send(candidate);
					} else {
						logger(DEBUG_PROTOCOL, LOG_WARNING,
						       "Failed to process packet on client connection after peer SCID registration: done=%zd",
						       done);
					}
					return;  /* Packet processed, do not create new server connection */
				} else if(addr_match && !dcid_match) {
					/* Address matches but DCID doesn't - this is a NEW incoming connection from the same peer
					 * Continue to create server connection below */
					logger(DEBUG_PROTOCOL, LOG_INFO,
					       "Address matches but DCID mismatch - this is a new incoming Initial, will create server connection");
				}
			}
		}
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
    /* Important: pass client's DCID as Original DCID (odcid) to quiche_accept().
     * Using client's SCID here breaks address validation and stalls handshake. */
    qconn = quic_conn_new_server(quic_manager->server_config->config,
                                  dcid, dcid_len,  /* Track client's DCID */
                                  dcid, dcid_len,  /* ODCID for quiche_accept = client's DCID */
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
    while(true) {
        ssize_t sent = quic_conn_send(qconn);
        if(sent <= 0) break;
    }
    quiche_conn_on_timeout(qconn->conn);
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

/* ========================================================================
 * Meta-connection API (control plane over QUIC streams)
 * ======================================================================== */

/* Create a new bidirectional stream for meta-connection (control plane) */
int64_t quic_meta_create_stream(quic_conn_t *qconn) {
	if(!qconn || !qconn->conn) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "quic_meta_create_stream: invalid connection");
		return -1;
	}

	/* QUIC stream IDs:
	 * - Client-initiated bidirectional: 0, 4, 8, 12, ...
	 * - Server-initiated bidirectional: 1, 5, 9, 13, ...
	 * - Client-initiated unidirectional: 2, 6, 10, 14, ...
	 * - Server-initiated unidirectional: 3, 7, 11, 15, ...
	 */
	uint64_t stream_id = qconn->next_stream_id;

	/* Increment by 4 to get next bidirectional stream of same initiator */
	qconn->next_stream_id += 4;

	logger(DEBUG_PROTOCOL, LOG_INFO, "Created QUIC meta stream %lu for %s",
	       stream_id, qconn->is_client ? "client" : "server");

	return (int64_t)stream_id;
}

/* Send data on a QUIC meta stream */
ssize_t quic_meta_send(quic_conn_t *qconn, int64_t stream_id,
                        const uint8_t *data, size_t len) {
	if(!qconn || !qconn->conn || stream_id < 0 || !data || len == 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "quic_meta_send: invalid parameters");
		return -1;
	}

	/* Check if handshake is complete */
	if(!qconn->handshake_complete) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "quic_meta_send: handshake not complete yet, buffering %zu bytes", len);
		return -1;
	}

	/* Send data on the stream (fin=false, we keep stream open) */
	uint64_t error_code = 0;
	ssize_t sent = quiche_conn_stream_send(qconn->conn, (uint64_t)stream_id,
	                                        data, len, false, &error_code);

	if(sent < 0) {
		if(sent == QUICHE_ERR_STREAM_STOPPED) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Stream %ld stopped by peer (error: %lu)", stream_id, error_code);
		} else if(sent == QUICHE_ERR_DONE) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "Stream %ld would block", stream_id);
		} else {
			logger(DEBUG_PROTOCOL, LOG_ERR, "quiche_conn_stream_send failed: %zd (error: %lu)", sent, error_code);
		}
		return -1;
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Sent %zd bytes on QUIC meta stream %ld", sent, stream_id);

	/* Update statistics */
	qconn->bytes_sent += sent;

	return sent;
}

/* Receive data from a QUIC meta stream */
ssize_t quic_meta_recv(quic_conn_t *qconn, int64_t stream_id,
                        uint8_t *buf, size_t buf_len) {
	if(!qconn || !qconn->conn || stream_id < 0 || !buf || buf_len == 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "quic_meta_recv: invalid parameters");
		return -1;
	}

	/* Check if handshake is complete */
	if(!qconn->handshake_complete) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "quic_meta_recv: handshake not complete yet");
		return -1;
	}

	bool fin = false;
	uint64_t error_code = 0;
	ssize_t recv_len = quiche_conn_stream_recv(qconn->conn, (uint64_t)stream_id,
	                                             buf, buf_len, &fin, &error_code);

	if(recv_len < 0) {
		if(recv_len == QUICHE_ERR_DONE) {
			/* No data available right now, not an error */
			return 0;
		} else if(recv_len == QUICHE_ERR_STREAM_RESET) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Stream %ld reset by peer (error: %lu)",
			       stream_id, error_code);
		} else {
			logger(DEBUG_PROTOCOL, LOG_ERR, "quiche_conn_stream_recv failed: %zd (error: %lu)",
			       recv_len, error_code);
		}
		return -1;
	}

	if(recv_len > 0) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Received %zd bytes on QUIC meta stream %ld%s",
		       recv_len, stream_id, fin ? " (FIN)" : "");

		/* Update statistics */
		qconn->bytes_received += recv_len;
	}

	/* If stream was closed by peer, we might want to close our side too */
	if(fin) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Stream %ld closed by peer (received FIN)", stream_id);
	}

	return recv_len;
}

/* Check if a QUIC meta stream has readable data */
bool quic_meta_stream_readable(quic_conn_t *qconn, int64_t stream_id) {
	if(!qconn || !qconn->conn || stream_id < 0) {
		return false;
	}

	/* Check if handshake is complete */
	if(!qconn->handshake_complete) {
		return false;
	}

	/* Get iterator for readable streams */
	quiche_stream_iter *readable = quiche_conn_readable(qconn->conn);
	if(!readable) {
		return false;
	}

	/* Check if our stream is in the readable set */
	uint64_t s;
	bool found = false;

	while(quiche_stream_iter_next(readable, &s)) {
		if(s == (uint64_t)stream_id) {
			found = true;
			break;
		}
	}

	quiche_stream_iter_free(readable);
	return found;
}

/* Return next readable stream id, or -1 if none */
int64_t quic_meta_next_readable(quic_conn_t *qconn) {
    if(!qconn || !qconn->conn) {
        return -1;
    }
    quiche_stream_iter *readable = quiche_conn_readable(qconn->conn);
    if(!readable) {
        return -1;
    }
    uint64_t sid = 0;
    if(!quiche_stream_iter_next(readable, &sid)) {
        quiche_stream_iter_free(readable);
        return -1;
    }
    quiche_stream_iter_free(readable);
    return (int64_t)sid;
}
/* Helper: flush metadata outbuf over QUIC stream */
static void quic_flush_meta_outbuf(connection_t *c, quic_conn_t *qconn) {
    if(!c || !qconn) return;
    if(c->quic_stream_id < 0) return;
    ssize_t outlen = 0;
    if(c->outbuf.len > c->outbuf.offset) {
        logger(DEBUG_META, LOG_INFO, "QUIC meta: flushing %d bytes from outbuf via stream %ld (handshake_complete=%d)",
               c->outbuf.len - c->outbuf.offset, (long)c->quic_stream_id, qconn->handshake_complete);
        outlen = quic_meta_send(qconn, c->quic_stream_id,
                                (const uint8_t *)(c->outbuf.data + c->outbuf.offset),
                                c->outbuf.len - c->outbuf.offset);
        if(outlen > 0) {
            logger(DEBUG_META, LOG_INFO, "QUIC meta: sent %zd bytes on stream %ld, calling quic_conn_send",
                   outlen, (long)c->quic_stream_id);
            buffer_read(&c->outbuf, outlen);
            /* Actually send the QUIC packets containing stream data */
            while(true) {
                ssize_t sent = quic_conn_send(qconn);
                if(sent <= 0) break;
            }
        } else {
            logger(DEBUG_META, LOG_WARNING, "QUIC meta: quic_meta_send returned %zd for stream %ld",
                   outlen, (long)c->quic_stream_id);
        }
    }
}

/* Public helper to flush meta outbuf via QUIC for given connection's node */
void quic_transport_flush_meta(connection_t *c) {
    if(!c || !c->node) return;
    quic_conn_t *qconn = quic_transport_get_connection(c->node, NULL);
    if(!qconn) return;
    quic_flush_meta_outbuf(c, qconn);
}
