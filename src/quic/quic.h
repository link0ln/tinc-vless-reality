/*
    quic.h -- QUIC protocol support for tinc
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

#ifndef TINC_QUIC_H
#define TINC_QUIC_H

#include "system.h"
#include <stdint.h>
#include <stdbool.h>
#include <quiche.h>

/* QUIC Connection States */
typedef enum quic_state_t {
	QUIC_STATE_INIT = 0,
	QUIC_STATE_HANDSHAKE,
	QUIC_STATE_ESTABLISHED,
	QUIC_STATE_DRAINING,
	QUIC_STATE_CLOSED
} quic_state_t;

/* Buffered packet during handshake */
typedef struct buffered_packet_t {
	uint8_t data[2048];
	size_t len;
	struct buffered_packet_t *next;
} buffered_packet_t;

/* QUIC Connection Context */
typedef struct quic_conn_t {
	quiche_conn *conn;              // quiche connection
	quiche_config *config;          // configuration (shared)

	/* Connection identifiers */
	uint8_t scid[20];               // source connection ID
	size_t scid_len;
	uint8_t dcid[20];               // destination connection ID
	size_t dcid_len;
	uint8_t odcid[20];              // original destination CID (server)
	size_t odcid_len;

	/* Socket and addressing */
	int sock_fd;                    // UDP socket
	struct sockaddr_storage peer_addr; // peer address
	socklen_t peer_addr_len;

	/* State */
	quic_state_t state;
	bool is_client;                 // client or server
	bool handshake_complete;        // TLS handshake done
	bool reality_enabled;           // Reality protocol active

	/* Reality context (if enabled) */
	void *reality_ctx;              // quic_reality_ctx_t *

	/* VPN packet buffering */
	uint8_t recv_buf[65536];
	size_t recv_buf_len;
	size_t recv_buf_pos;

	/* Send buffering during handshake */
	buffered_packet_t *send_buf_head;  // first buffered packet
	buffered_packet_t *send_buf_tail;  // last buffered packet
	size_t send_buf_count;             // number of buffered packets

	/* Stream management */
	uint64_t next_stream_id;        // next stream ID to use

	/* Statistics */
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t packets_sent;
	uint64_t packets_received;

	/* Connection migration support */
	bool migration_enabled;         // migration allowed for this connection
	struct timeval last_migration;  // timestamp of last migration
	int old_sock_fd;                // previous socket (draining)
	struct timeval old_fd_close_time; // when to close old_sock_fd

	/* Linked to tinc node */
	void *node;                     // node_t * (to avoid circular deps)
} quic_conn_t;

/* Global QUIC configuration */
typedef struct quic_config_t {
	quiche_config *config;

	/* QUIC parameters */
	uint64_t max_data;
	uint64_t max_stream_data_bidi_local;
	uint64_t max_stream_data_bidi_remote;
	uint64_t max_stream_data_uni;
	uint64_t max_streams_bidi;
	uint64_t max_streams_uni;
	uint64_t idle_timeout;          // milliseconds
	uint64_t max_udp_payload_size;

	/* Congestion control */
	enum {
		QUIC_CC_RENO = 0,
		QUIC_CC_CUBIC,
		QUIC_CC_BBR
	} cc_algorithm;

	/* Reality settings */
	bool reality_enabled;

	/* TLS certificates (for server) */
	char *cert_file;
	char *key_file;

	/* ALPN (Application-Layer Protocol Negotiation) */
	uint8_t *alpn;
	size_t alpn_len;
} quic_config_t;

/* Function prototypes */

/* Initialize/cleanup QUIC subsystem */
extern bool quic_init(void);
extern void quic_exit(void);

/* Configuration management */
extern quic_config_t *quic_config_new(bool is_server);
extern void quic_config_free(quic_config_t *qconf);
extern bool quic_config_set_tls_cert(quic_config_t *qconf, const char *cert_file, const char *key_file);
extern bool quic_config_set_alpn(quic_config_t *qconf, const char *alpn);
extern void quic_config_set_cc_algorithm(quic_config_t *qconf, int algorithm);

/* Connection management */
extern quic_conn_t *quic_conn_new_client(quiche_config *config, const char *server_name,
                                          struct sockaddr *addr, socklen_t addr_len, int sock_fd);
extern quic_conn_t *quic_conn_new_server(quiche_config *config, const uint8_t *dcid, size_t dcid_len,
                                          const uint8_t *odcid, size_t odcid_len,
                                          struct sockaddr *addr, socklen_t addr_len, int sock_fd);
extern void quic_conn_free(quic_conn_t *qconn);

/* QUIC packet processing */
extern ssize_t quic_conn_send(quic_conn_t *qconn);
extern ssize_t quic_conn_recv(quic_conn_t *qconn, const uint8_t *buf, size_t len);
extern bool quic_conn_is_established(quic_conn_t *qconn);
extern bool quic_conn_is_closed(quic_conn_t *qconn);

/* VPN data transfer */
extern bool quic_conn_send_vpn_packet(quic_conn_t *qconn, const void *data, size_t len);
extern ssize_t quic_conn_recv_vpn_packet(quic_conn_t *qconn, void *data, size_t max_len);
extern bool quic_conn_buffer_vpn_packet(quic_conn_t *qconn, const void *data, size_t len);
extern void quic_conn_flush_buffered_packets(quic_conn_t *qconn);

/* Stream management */
extern uint64_t quic_conn_open_stream(quic_conn_t *qconn);
extern bool quic_conn_stream_send(quic_conn_t *qconn, uint64_t stream_id, const uint8_t *data, size_t len, bool fin);
extern ssize_t quic_conn_stream_recv(quic_conn_t *qconn, uint64_t stream_id, uint8_t *data, size_t max_len, bool *fin);

/* Utility functions */
extern const char *quic_state_to_string(quic_state_t state);
extern void quic_conn_set_node(quic_conn_t *qconn, void *node);

#endif /* TINC_QUIC_H */
