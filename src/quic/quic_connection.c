/*
    quic_connection.c -- QUIC Connection Management
    Copyright (C) 2025 tinc-vless contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
*/

#include "system.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "quic_internal.h"
#include "quic.h"
#include "../logger.h"
#include "../xalloc.h"
#include "../splay_tree.h"
#include "../netutl.h"
#include "../node.h"
#include "../connection.h"
#include "../net.h"

/* External references */
extern quic_manager_t *quic_manager;

/* Connection comparison function for splay tree */
/* a and b are quic_conn_t pointers, compare by peer address */
int connection_compare(const void *a, const void *b) {
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

	/* Initialize retry state */
	quic_maintenance_init_retry(qconn);

	/* Initialize keep-alive state */
	quic_maintenance_init_keepalive(qconn);

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
