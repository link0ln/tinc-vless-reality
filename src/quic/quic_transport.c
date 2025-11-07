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
#include "../node.h"
#include "quic_transport.h"
#include "quic.h"

/* Global QUIC manager */
quic_manager_t *quic_manager = NULL;

/* Transport mode */
transport_mode_t transport_mode = TRANSPORT_UDP;

/* Connection comparison function for splay tree */
/* a and b are quic_conn_t pointers, compare their associated nodes */
static int connection_compare(const void *a, const void *b) {
	const quic_conn_t *qa = (const quic_conn_t *)a;
	const quic_conn_t *qb = (const quic_conn_t *)b;
	return (const char *)qa->node - (const char *)qb->node;
}

/* Initialize QUIC transport */
bool quic_transport_init(int port) {
	if(!quic_init()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize QUIC subsystem");
		return false;
	}

	quic_manager = xzalloc(sizeof(quic_manager_t));

	/* Create connection tree */
	quic_manager->connections = splay_alloc_tree(connection_compare, NULL);

	/* Create client configuration */
	quic_manager->client_config = quic_config_new(false);

	if(!quic_manager->client_config) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create QUIC client config");
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	/* Create server configuration */
	quic_manager->server_config = quic_config_new(true);

	if(!quic_manager->server_config) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create QUIC server config");
		quic_config_free(quic_manager->client_config);
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	/* TODO: Load TLS certificates for server */
	/* For now, we'll generate self-signed certs or use VLESS auth */

	/* Create UDP socket for QUIC */
	quic_manager->udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if(quic_manager->udp_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create UDP socket for QUIC: %s", strerror(errno));
		quic_config_free(quic_manager->client_config);
		quic_config_free(quic_manager->server_config);
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	/* Set socket to non-blocking */
	int flags = fcntl(quic_manager->udp_fd, F_GETFL, 0);
	fcntl(quic_manager->udp_fd, F_SETFL, flags | O_NONBLOCK);

	/* Bind to port */
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if(bind(quic_manager->udp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to bind QUIC UDP socket to port %d: %s", port, strerror(errno));
		close(quic_manager->udp_fd);
		quic_config_free(quic_manager->client_config);
		quic_config_free(quic_manager->server_config);
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	/* Get local address */
	quic_manager->local_addr_len = sizeof(quic_manager->local_addr);
	getsockname(quic_manager->udp_fd, (struct sockaddr *)&quic_manager->local_addr,
	            &quic_manager->local_addr_len);

	quic_manager->initialized = true;
	quic_manager->enabled = true;

	logger(DEBUG_ALWAYS, LOG_INFO, "QUIC transport initialized on port %d", port);

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

	/* Close socket */
	if(quic_manager->udp_fd >= 0) {
		close(quic_manager->udp_fd);
	}

	/* Free configurations */
	if(quic_manager->client_config) {
		quic_config_free(quic_manager->client_config);
	}

	if(quic_manager->server_config) {
		quic_config_free(quic_manager->server_config);
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

	/* Create temporary quic_conn for searching */
	quic_conn_t search_key;
	search_key.node = node;

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

		/* Use port 443 for QUIC (standard HTTPS port) */
		if(sa.sa.sa_family == AF_INET) {
			sa.in.sin_port = htons(443);
		} else if(sa.sa.sa_family == AF_INET6) {
			sa.in6.sin6_port = htons(443);
		}

		qconn = quic_conn_new_client(quic_manager->client_config->config, node->name,
		                              &sa.sa, sa_len, quic_manager->udp_fd);
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

	logger(DEBUG_PROTOCOL, LOG_INFO, "Created QUIC %s connection to %s",
	       is_client ? "client" : "server", node->name);

	/* Send initial packet to start handshake */
	if(is_client) {
		quic_conn_send(qconn);
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
		/* TODO: Buffer packets until handshake completes */
		return false;
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

	/* Try to find existing connection by address */
	/* TODO: Implement proper connection ID demultiplexing */

	/* For now, try all connections */
	splay_node_t *sn, *next;

	for(sn = quic_manager->connections->head; sn; sn = next) {
		next = sn->next;
		quic_conn_t *qconn = (quic_conn_t *)sn->data;

		if(!qconn) {
			continue;
		}

		/* Feed packet to connection */
		ssize_t done = quic_conn_recv(qconn, buf, len);

		if(done > 0) {
			quic_manager->packets_received++;
			quic_manager->bytes_received += done;

			/* Try to read VPN packets from streams */
			uint8_t vpn_buf[4096];
			ssize_t vpn_len = quic_conn_recv_vpn_packet(qconn, vpn_buf, sizeof(vpn_buf));

			if(vpn_len > 0) {
				/* Create VPN packet and route it */
				vpn_packet_t vpacket;
				memcpy(DATA(&vpacket), vpn_buf, vpn_len);
				vpacket.len = vpn_len;

				/* Get node from connection */
				node_t *node = (node_t *)qconn->node;

				if(node) {
					logger(DEBUG_PROTOCOL, LOG_DEBUG, "Received VPN packet (%zd bytes) from %s via QUIC",
					       vpn_len, node->name);

					/* Route packet through tinc */
					/* TODO: Call appropriate tinc routing function */
					// receive_packet(node, &vpacket);
				}
			}

			/* Send any pending QUIC packets */
			quic_conn_send(qconn);

			return;  // Packet processed
		}
	}

	/* No existing connection handled this packet */
	/* Check if it's a new connection (Initial packet) */
	/* TODO: Parse QUIC header and create new server connection */

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Received QUIC packet from unknown source");
}

/* Event loop callback for incoming QUIC data */
void handle_incoming_quic_data(void *data, int flags) {
	if(!quic_manager || quic_manager->udp_fd < 0) {
		return;
	}

	uint8_t buf[65536];
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);

	/* Receive UDP packet */
	ssize_t len = recvfrom(quic_manager->udp_fd, buf, sizeof(buf), 0,
	                       (struct sockaddr *)&from, &fromlen);

	if(len < 0) {
		if(errno != EAGAIN && errno != EWOULDBLOCK) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "Error receiving QUIC packet: %s", strerror(errno));
		}

		return;
	}

	if(len == 0) {
		return;
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Received %zd bytes on QUIC UDP socket", len);

	/* Handle the packet */
	quic_transport_handle_packet(buf, len, (struct sockaddr *)&from, fromlen);
}

/* Check if QUIC transport is enabled */
bool quic_transport_is_enabled(void) {
	return quic_manager && quic_manager->enabled;
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
