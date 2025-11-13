/*
    quic_internal.h -- Internal QUIC transport definitions
    Copyright (C) 2025 tinc-vless contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#ifndef TINC_QUIC_INTERNAL_H
#define TINC_QUIC_INTERNAL_H

#include "quic_transport.h"
#include "../connection.h"
#include "../node.h"

/* Local connection ID length (matches scid_len in quic_conn_new_server) */
#define LOCAL_CONN_ID_LEN 16

/* Connection ID map entry for demultiplexing */
typedef struct conn_id_entry_t {
	uint8_t conn_id[QUICHE_MAX_CONN_ID_LEN];
	size_t conn_id_len;
	quic_conn_t *conn;
} conn_id_entry_t;

/* Forward declarations */
struct vpn_packet_t;

/* ============================================================================
 * Connection Management (quic_connection.c)
 * ============================================================================ */

extern int connection_compare(const void *a, const void *b);
extern quic_conn_t *quic_transport_get_connection(node_t *node, const sockaddr_t *sa);
extern quic_conn_t *quic_find_connection_by_address(const sockaddr_t *addr);
extern quic_conn_t *quic_transport_create_connection(node_t *node, bool is_client, const sockaddr_t *sa);
extern void quic_transport_remove_connection(node_t *node);

/* ============================================================================
 * Connection ID Demultiplexing (quic_packet.c)
 * ============================================================================ */

extern int conn_id_compare(const void *a, const void *b);
extern bool register_connection_id(const uint8_t *conn_id, size_t conn_id_len, quic_conn_t *conn);
extern void unregister_connection_id(const uint8_t *conn_id, size_t conn_id_len);
extern quic_conn_t *lookup_connection_by_id(const uint8_t *conn_id, size_t conn_id_len);

/* Packet handling */
extern void quic_transport_handle_packet(const uint8_t *buf, size_t len,
                                          struct sockaddr *from, socklen_t fromlen);
extern bool quic_transport_send_packet(node_t *node, struct vpn_packet_t *packet);

/* ============================================================================
 * Meta Protocol (quic_meta.c)
 * ============================================================================ */

extern int64_t quic_meta_create_stream(quic_conn_t *qconn);
extern ssize_t quic_meta_send(quic_conn_t *qconn, int64_t stream_id,
                               const uint8_t *data, size_t len);
extern ssize_t quic_meta_recv(quic_conn_t *qconn, int64_t stream_id,
                               uint8_t *buf, size_t buf_len);
extern bool quic_meta_stream_readable(quic_conn_t *qconn, int64_t stream_id);
extern int64_t quic_meta_next_readable(quic_conn_t *qconn);
extern void quic_transport_flush_meta(connection_t *c);

/* ============================================================================
 * Connection Migration (quic_migration.c)
 * ============================================================================ */

extern bool quic_migration_init(void);
extern void quic_migration_exit(void);

/* ============================================================================
 * Connection Maintenance (quic_maintenance.c)
 * ============================================================================ */

extern bool quic_maintenance_init(void);
extern void quic_maintenance_exit(void);
extern void quic_maintenance_update_activity(quic_conn_t *qconn);
extern void quic_maintenance_init_keepalive(quic_conn_t *qconn);
extern void quic_maintenance_init_retry(quic_conn_t *qconn);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* Format connection ID as hex string (for logging) */
static inline const char *format_cid(const uint8_t *cid, size_t len) {
	static __thread char buf[256];
	if(len == 0 || !cid) {
		return "<empty>";
	}
	char *p = buf;
	for(size_t i = 0; i < len && i < 32; i++) {
		snprintf(p, 3, "%02x", cid[i]);
		p += 2;
	}
	*p = '\0';
	return buf;
}

#endif /* TINC_QUIC_INTERNAL_H */
