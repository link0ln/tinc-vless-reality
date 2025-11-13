/*
    quic_meta.c -- QUIC Meta Protocol (Control Plane over QUIC Streams)
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

#include <string.h>
#include <quiche.h>

#include "quic_internal.h"
#include "quic.h"
#include "../logger.h"
#include "../xalloc.h"
#include "../netutl.h"
#include "../connection.h"
#include "../buffer.h"
#include "../list.h"

/* External references */
extern quic_manager_t *quic_manager;
extern list_t *connection_list;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/* Helper: find an existing QUIC meta connection_t without bound node
 * that matches the given qconn peer address. */
connection_t *find_unbound_quic_meta_for_peer(const quic_conn_t *qconn) {
	if(!qconn) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "find_unbound: qconn is NULL");
		return NULL;
	}

	char *peer_host = sockaddr2hostname((const sockaddr_t *)&qconn->peer_addr);
	logger(DEBUG_PROTOCOL, LOG_INFO, "find_unbound: looking for connection from %s (family=%d)",
	       peer_host, qconn->peer_addr.ss_family);

	int count = 0;
	for(list_node_t *ln = connection_list ? connection_list->head : NULL; ln; ln = ln->next) {
		connection_t *c = (connection_t *)ln->data;
		count++;
		if(!c) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "  [%d] c=NULL", count);
			continue;
		}
		char *c_host = c->hostname ? c->hostname : "NULL";
		logger(DEBUG_PROTOCOL, LOG_INFO, "  [%d] c->hostname=%s quic_meta=%d node=%p stream_id=%ld family=%d",
		       count, c_host, c->status.quic_meta, (void*)c->node, (long)c->quic_stream_id,
		       c->address.sa.sa_family);
		if(!c->status.quic_meta) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "    Skipping: not quic_meta");
			continue;
		}
		if(c->node) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "    Skipping: already bound");
			continue;
		}
		/* Match by peer address */
		int cmp_result = sockaddrcmp_noport(&c->address, (const sockaddr_t *)&qconn->peer_addr);
		logger(DEBUG_PROTOCOL, LOG_INFO, "    Address compare result: %d", cmp_result);
		if(cmp_result == 0) {
			logger(DEBUG_PROTOCOL, LOG_INFO, "find_unbound: FOUND match for %s", peer_host);
			free(peer_host);
			return c;
		}
	}
	logger(DEBUG_PROTOCOL, LOG_INFO, "find_unbound: NO match found for %s (checked %d connections)", peer_host, count);
	free(peer_host);
	return NULL;
}

/* Helper: flush metadata outbuf over QUIC stream */
static void quic_flush_meta_outbuf(connection_t *c, quic_conn_t *qconn) {
	logger(DEBUG_META, LOG_INFO, "quic_flush_meta_outbuf called: c=%p qconn=%p", (void *)c, (void *)qconn);

	if(!c || !qconn) {
		logger(DEBUG_META, LOG_WARNING, "quic_flush_meta_outbuf: NULL parameter (c=%p, qconn=%p)", (void *)c, (void *)qconn);
		return;
	}

	logger(DEBUG_META, LOG_INFO, "quic_flush_meta_outbuf: stream_id=%ld", (long)c->quic_stream_id);
	if(c->quic_stream_id < 0) {
		logger(DEBUG_META, LOG_WARNING, "quic_flush_meta_outbuf: invalid stream_id=%ld", (long)c->quic_stream_id);
		return;
	}

	logger(DEBUG_META, LOG_INFO, "quic_flush_meta_outbuf: outbuf len=%d offset=%d", c->outbuf.len, c->outbuf.offset);
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
	} else {
		logger(DEBUG_META, LOG_WARNING, "quic_flush_meta_outbuf: outbuf empty or already flushed (len=%d, offset=%d)",
		       c->outbuf.len, c->outbuf.offset);
	}
}

/* ============================================================================
 * Meta Protocol Stream Operations
 * ============================================================================ */

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
		logger(DEBUG_META, LOG_DEBUG, "quic_meta_stream_readable: invalid params (qconn=%p stream_id=%ld)",
		       (void*)qconn, stream_id);
		return false;
	}

	/* Check if handshake is complete */
	if(!qconn->handshake_complete) {
		logger(DEBUG_META, LOG_DEBUG, "quic_meta_stream_readable: handshake not complete for stream %ld", stream_id);
		return false;
	}

	/* Get iterator for readable streams */
	quiche_stream_iter *readable = quiche_conn_readable(qconn->conn);
	if(!readable) {
		logger(DEBUG_META, LOG_DEBUG, "quic_meta_stream_readable: quiche_conn_readable returned NULL for stream %ld", stream_id);
		return false;
	}

	/* Check if our stream is in the readable set */
	uint64_t s;
	bool found = false;
	int count = 0;

	while(quiche_stream_iter_next(readable, &s)) {
		count++;
		logger(DEBUG_META, LOG_DEBUG, "quic_meta_stream_readable: found readable stream %lu (looking for %ld)",
		       (unsigned long)s, stream_id);
		if(s == (uint64_t)stream_id) {
			found = true;
			break;
		}
	}

	quiche_stream_iter_free(readable);

	logger(DEBUG_META, LOG_INFO, "quic_meta_stream_readable: stream %ld %s (checked %d streams)",
	       stream_id, found ? "FOUND" : "NOT FOUND", count);
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

/* Public helper to flush meta outbuf via QUIC for given connection's node */
void quic_transport_flush_meta(connection_t *c) {
	if(!c || !c->node) return;
	quic_conn_t *qconn = quic_transport_get_connection(c->node, NULL);
	if(!qconn) return;
	quic_flush_meta_outbuf(c, qconn);
}
