/*
    quic_transport.h -- VPN transport over QUIC
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

#ifndef TINC_QUIC_TRANSPORT_H
#define TINC_QUIC_TRANSPORT_H

#include "system.h"
#include "quic.h"
#include "../splay_tree.h"
#include "../vless/reality.h"

/* Forward declarations */
struct node_t;
struct vpn_packet_t;

/* Forward declaration for listen_socket_t */
struct listen_socket_t;

/* QUIC transport manager */
typedef struct quic_manager_t {
	/* Configuration */
	quic_config_t *client_config;
	quic_config_t *server_config;
	reality_config_t *reality_config;  /* Reality protocol configuration */

	/* Connection mapping: node_t* -> quic_conn_t* */
	splay_tree_t *connections;

	/* Connection ID demultiplexing: DCID -> quic_conn_t* */
	splay_tree_t *conn_id_map;

	/* UDP sockets from tinc (shared with native protocol) */
	struct listen_socket_t **sockets;
	int num_sockets;

	/* Statistics */
	uint64_t packets_sent;
	uint64_t packets_received;
	uint64_t bytes_sent;
	uint64_t bytes_received;

	/* State */
	bool initialized;
	bool enabled;
	bool reality_enabled;
} quic_manager_t;

/* Global QUIC manager instance */
extern quic_manager_t *quic_manager;

/* Transport mode configuration */
typedef enum transport_mode_t {
	TRANSPORT_UDP = 0,     // Classic tinc UDP
	TRANSPORT_TCP,         // TCP only (VLESS + Reality)
	TRANSPORT_QUIC,        // QUIC only (this implementation)
	TRANSPORT_HYBRID       // Try QUIC, fallback to UDP
} transport_mode_t;

extern transport_mode_t transport_mode;

/* Function prototypes */

/* Initialize/cleanup QUIC transport */
extern bool quic_transport_init(struct listen_socket_t *sockets, int num_sockets);
extern void quic_transport_exit(void);

/* Connection management */
extern quic_conn_t *quic_transport_get_connection(struct node_t *node, const sockaddr_t *sa);
extern quic_conn_t *quic_find_connection_by_address(const sockaddr_t *addr);
extern quic_conn_t *quic_transport_create_connection(struct node_t *node, bool is_client, const sockaddr_t *sa);
extern void quic_transport_remove_connection(struct node_t *node);

/* VPN packet operations */
extern bool quic_transport_send_packet(struct node_t *node, struct vpn_packet_t *packet);
extern void quic_transport_handle_packet(const uint8_t *buf, size_t len,
        struct sockaddr *from, socklen_t fromlen);

/* Event loop integration */
extern void handle_incoming_quic_data(void *data, int flags);

/* Utility functions */
extern bool quic_transport_is_enabled(void);
extern void quic_transport_set_mode(transport_mode_t mode);

/* Meta-connection API (control plane over QUIC streams) */
extern int64_t quic_meta_create_stream(quic_conn_t *qconn);
extern ssize_t quic_meta_send(quic_conn_t *qconn, int64_t stream_id,
                               const uint8_t *data, size_t len);
extern ssize_t quic_meta_recv(quic_conn_t *qconn, int64_t stream_id,
                               uint8_t *buf, size_t buf_len);
extern bool quic_meta_stream_readable(quic_conn_t *qconn, int64_t stream_id);

#endif /* TINC_QUIC_TRANSPORT_H */
