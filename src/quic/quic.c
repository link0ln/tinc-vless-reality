/*
    quic.c -- QUIC protocol implementation for tinc
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

#include <quiche.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "quic.h"
#include "logger.h"
#include "xalloc.h"
#include "../crypto.h"
#include "utils.h"

/* Forward declaration for quiche debug callback */
static void quic_dbg_cb(const char *line, void *arg);

/* Default QUIC parameters (Chrome-like) */
#define DEFAULT_MAX_DATA 10485760ULL
#define DEFAULT_MAX_STREAM_DATA_BIDI 6291456ULL
#define DEFAULT_MAX_STREAMS_BIDI 100ULL
#define DEFAULT_MAX_STREAMS_UNI 3ULL
#define DEFAULT_IDLE_TIMEOUT 30000ULL
#define DEFAULT_MAX_UDP_PAYLOAD 1350ULL

/* Default ALPN for HTTP/3 mimicry */
static const uint8_t DEFAULT_ALPN[] = "\x02h3\x05h3-29\x05h3-28\x02h2\x08http/1.1";
static const size_t DEFAULT_ALPN_LEN = sizeof(DEFAULT_ALPN) - 1;

/* Global state */
static bool quic_initialized = false;

/* Return stable hex string for quiche connection trace id */
static const char *quic_trace_id(const quiche_conn *conn) {
    static char buf[96];
    const uint8_t *id = NULL;
    size_t len = 0;
    quiche_conn_trace_id(conn, &id, &len);
    if(!id || len == 0) {
        snprintf(buf, sizeof(buf), "-");
        return buf;
    }
    size_t maxbytes = (sizeof(buf) - 1) / 2;
    size_t n = len < maxbytes ? len : maxbytes;
    char *p = buf;
    for(size_t i = 0; i < n; i++) {
        p += sprintf(p, "%02x", id[i]);
    }
    *p = '\0';
    return buf;
}

/* Initialize QUIC subsystem */
bool quic_init(void) {
    if(quic_initialized) {
        return true;
    }

    logger(DEBUG_ALWAYS, LOG_INFO, "Initializing QUIC subsystem (quiche %s)", quiche_version());

    /* Enable quiche debug logs */
    quiche_enable_debug_logging(quic_dbg_cb, NULL);

	quic_initialized = true;
	return true;
}

/* Cleanup QUIC subsystem */
void quic_exit(void) {
	if(!quic_initialized) {
		return;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Shutting down QUIC subsystem");
	quic_initialized = false;
}

/* Create new QUIC configuration */
quic_config_t *quic_config_new(bool is_server) {
	quic_config_t *qconf = xzalloc(sizeof(quic_config_t));

    /* Create quiche config */
    qconf->config = quiche_config_new(QUICHE_PROTOCOL_VERSION);

	if(!qconf->config) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create quiche config");
		free(qconf);
		return NULL;
	}

    /* Do not verify peer certificate by default (self-signed in demos).
     * NOTE: For production, enable verification with a proper PKI. */
    quiche_config_verify_peer(qconf->config, false);

    /* Set default parameters */
	qconf->max_data = DEFAULT_MAX_DATA;
	qconf->max_stream_data_bidi_local = DEFAULT_MAX_STREAM_DATA_BIDI;
	qconf->max_stream_data_bidi_remote = DEFAULT_MAX_STREAM_DATA_BIDI;
	qconf->max_stream_data_uni = DEFAULT_MAX_STREAM_DATA_BIDI;
	qconf->max_streams_bidi = DEFAULT_MAX_STREAMS_BIDI;
	qconf->max_streams_uni = DEFAULT_MAX_STREAMS_UNI;
	qconf->idle_timeout = DEFAULT_IDLE_TIMEOUT;
	qconf->max_udp_payload_size = DEFAULT_MAX_UDP_PAYLOAD;
	qconf->cc_algorithm = QUIC_CC_CUBIC;

	/* Apply parameters to quiche config */
	quiche_config_set_initial_max_data(qconf->config, qconf->max_data);
	quiche_config_set_initial_max_stream_data_bidi_local(qconf->config, qconf->max_stream_data_bidi_local);
	quiche_config_set_initial_max_stream_data_bidi_remote(qconf->config, qconf->max_stream_data_bidi_remote);
	quiche_config_set_initial_max_stream_data_uni(qconf->config, qconf->max_stream_data_uni);
	quiche_config_set_initial_max_streams_bidi(qconf->config, qconf->max_streams_bidi);
	quiche_config_set_initial_max_streams_uni(qconf->config, qconf->max_streams_uni);
	quiche_config_set_max_idle_timeout(qconf->config, qconf->idle_timeout);
	quiche_config_set_max_recv_udp_payload_size(qconf->config, qconf->max_udp_payload_size);
	quiche_config_set_max_send_udp_payload_size(qconf->config, qconf->max_udp_payload_size);

	/* Set congestion control */
	quiche_config_set_cc_algorithm(qconf->config, QUICHE_CC_CUBIC);

	/* Disable connection migration for now (TODO: support it later) */
	quiche_config_set_disable_active_migration(qconf->config, true);

    /* Set simple ALPN for internal transport (length-prefixed as required by quiche) */
    static const uint8_t ALPN_TINC[] = "\x04tinc";
    quiche_config_set_application_protos(qconf->config, ALPN_TINC, sizeof(ALPN_TINC) - 1);
    free(qconf->alpn);
    qconf->alpn = xmalloc(sizeof(ALPN_TINC) - 1);
    memcpy(qconf->alpn, ALPN_TINC, sizeof(ALPN_TINC) - 1);
    qconf->alpn_len = sizeof(ALPN_TINC) - 1;

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Created QUIC config (%s mode)", is_server ? "server" : "client");

	return qconf;
}

/* Free QUIC configuration */
void quic_config_free(quic_config_t *qconf) {
	if(!qconf) {
		return;
	}

	if(qconf->config) {
		quiche_config_free(qconf->config);
	}

	free(qconf->cert_file);
	free(qconf->key_file);
	free(qconf->alpn);
	free(qconf);
}

/* Set TLS certificate and key (server only) */
bool quic_config_set_tls_cert(quic_config_t *qconf, const char *cert_file, const char *key_file) {
	if(!qconf || !qconf->config) {
		return false;
	}

	if(quiche_config_load_cert_chain_from_pem_file(qconf->config, cert_file) != 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to load certificate from %s", cert_file);
		return false;
	}

	if(quiche_config_load_priv_key_from_pem_file(qconf->config, key_file) != 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to load private key from %s", key_file);
		return false;
	}

	qconf->cert_file = xstrdup(cert_file);
	qconf->key_file = xstrdup(key_file);

	logger(DEBUG_PROTOCOL, LOG_INFO, "Loaded TLS certificate from %s", cert_file);

	return true;
}

/* Set ALPN */
bool quic_config_set_alpn(quic_config_t *qconf, const char *alpn) {
	if(!qconf || !qconf->config || !alpn) {
		return false;
	}

	size_t alpn_len = strlen(alpn);

	if(quiche_config_set_application_protos(qconf->config, (const uint8_t *)alpn, alpn_len) != 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to set ALPN: %s", alpn);
		return false;
	}

	free(qconf->alpn);
	qconf->alpn = xmalloc(alpn_len);
	memcpy(qconf->alpn, alpn, alpn_len);
	qconf->alpn_len = alpn_len;

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Set ALPN: %zu bytes", alpn_len);

	return true;
}

/* Set congestion control algorithm */
void quic_config_set_cc_algorithm(quic_config_t *qconf, int algorithm) {
	if(!qconf || !qconf->config) {
		return;
	}

	enum quiche_cc_algorithm cc;

	switch(algorithm) {
	case QUIC_CC_RENO:
		cc = QUICHE_CC_RENO;
		break;

	case QUIC_CC_CUBIC:
		cc = QUICHE_CC_CUBIC;
		break;

	case QUIC_CC_BBR:
		cc = QUICHE_CC_BBR;
		break;

	default:
		cc = QUICHE_CC_CUBIC;
		break;
	}

	quiche_config_set_cc_algorithm(qconf->config, cc);
	qconf->cc_algorithm = algorithm;

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Set congestion control: %d", algorithm);
}

/* Create new client QUIC connection */
quic_conn_t *quic_conn_new_client(quiche_config *config, const char *server_name,
                                   struct sockaddr *addr, socklen_t addr_len, int sock_fd) {
	quic_conn_t *qconn = xzalloc(sizeof(quic_conn_t));

	qconn->is_client = true;
	qconn->sock_fd = sock_fd;
	qconn->config = config;

	/* Generate random source connection ID */
	qconn->scid_len = 16;
	randomize(qconn->scid, qconn->scid_len);

	/* Store peer address */
	memcpy(&qconn->peer_addr, addr, addr_len);
	qconn->peer_addr_len = addr_len;

	/* Get local address from socket */
	struct sockaddr_storage local_addr;
	socklen_t local_addr_len = sizeof(local_addr);
	getsockname(sock_fd, (struct sockaddr *)&local_addr, &local_addr_len);

	/* Create quiche connection */
	qconn->conn = quiche_connect(server_name, qconn->scid, qconn->scid_len,
	                             (struct sockaddr *)&local_addr, local_addr_len,
	                             addr, addr_len, config);

	if(!qconn->conn) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create quiche client connection");
		free(qconn);
		return NULL;
	}

	qconn->state = QUIC_STATE_HANDSHAKE;
	qconn->next_stream_id = 0;  // Client-initiated bidirectional streams start at 0

    logger(DEBUG_PROTOCOL, LOG_INFO, "Created QUIC client connection to %s", server_name);

    /* Proactively send Initial flight */
    for(int i = 0; i < 4; ++i) {
        ssize_t sent = quic_conn_send(qconn);
        if(sent <= 0) break;
    }

    return qconn;
}

/* Create new server QUIC connection */
quic_conn_t *quic_conn_new_server(quiche_config *config, const uint8_t *dcid, size_t dcid_len,
                                   const uint8_t *odcid, size_t odcid_len,
                                   struct sockaddr *addr, socklen_t addr_len, int sock_fd) {
	quic_conn_t *qconn = xzalloc(sizeof(quic_conn_t));

	qconn->is_client = false;
	qconn->sock_fd = sock_fd;
	qconn->config = config;

	/* Store connection IDs */
	memcpy(qconn->dcid, dcid, dcid_len);
	qconn->dcid_len = dcid_len;
	memcpy(qconn->odcid, odcid, odcid_len);
	qconn->odcid_len = odcid_len;

	/* Generate random source connection ID */
	qconn->scid_len = 16;
	randomize(qconn->scid, qconn->scid_len);

	/* Store peer address */
	memcpy(&qconn->peer_addr, addr, addr_len);
	qconn->peer_addr_len = addr_len;

	/* Get local address from socket */
	struct sockaddr_storage local_addr;
	socklen_t local_addr_len = sizeof(local_addr);
	getsockname(sock_fd, (struct sockaddr *)&local_addr, &local_addr_len);

    /* Create quiche connection: pass client's Original DCID for address validation */
    qconn->conn = quiche_accept(qconn->scid, qconn->scid_len,
                                 odcid, odcid_len,
                                 (struct sockaddr *)&local_addr, local_addr_len,
                                 addr, addr_len, config);

	if(!qconn->conn) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create quiche server connection");
		free(qconn);
		return NULL;
	}

	qconn->state = QUIC_STATE_HANDSHAKE;
	qconn->next_stream_id = 1;  // Server-initiated bidirectional streams start at 1

	logger(DEBUG_PROTOCOL, LOG_INFO, "Accepted QUIC server connection");

	return qconn;
}

/* Free QUIC connection */
void quic_conn_free(quic_conn_t *qconn) {
	if(!qconn) {
		return;
	}

	if(qconn->conn) {
		quiche_conn_free(qconn->conn);
	}

	if(qconn->reality_ctx) {
		// TODO: free reality context
	}

	/* Free all buffered packets */
	buffered_packet_t *bp = qconn->send_buf_head;

	while(bp) {
		buffered_packet_t *next = bp->next;
		free(bp);
		bp = next;
	}

	if(qconn->send_buf_count > 0) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Dropped %zu buffered packets on connection close",
		       qconn->send_buf_count);
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Freed QUIC connection");

	free(qconn);
}

/* Send QUIC packets */
ssize_t quic_conn_send(quic_conn_t *qconn) {
	if(!qconn || !qconn->conn) {
		return -1;
	}

	uint8_t out[1350];  // MTU-safe packet size
	ssize_t total_sent = 0;
	int packet_count = 0;

	/* Send all pending QUIC packets */
    while(true) {
        quiche_send_info send_info;
        ssize_t written = quiche_conn_send(qconn->conn, out, sizeof(out), &send_info);

		if(written == QUICHE_ERR_DONE) {
			break;  // No more packets to send
		}

		if(written < 0) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "quiche_conn_send failed: %zd", written);
			return -1;
		}

        /* Log destination details */
        char dest_addr[INET6_ADDRSTRLEN];
        int dest_port = 0;
		if(send_info.to.ss_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&send_info.to;
			inet_ntop(AF_INET, &sin->sin_addr, dest_addr, sizeof(dest_addr));
			dest_port = ntohs(sin->sin_port);
		} else if(send_info.to.ss_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&send_info.to;
			inet_ntop(AF_INET6, &sin6->sin6_addr, dest_addr, sizeof(dest_addr));
			dest_port = ntohs(sin6->sin6_port);
		}

        const char *trace_id = quic_trace_id(qconn->conn);
        logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC[%s] send: %zd bytes to %s:%d via fd=%d (first=0x%02x)",
               trace_id ? trace_id : "-", written, dest_addr, dest_port, qconn->sock_fd, out[0]);

		/* Send packet via UDP socket to the address specified in send_info */
		ssize_t sent = sendto(qconn->sock_fd, out, written, 0,
		                      (struct sockaddr *)&send_info.to, send_info.to_len);

        if(sent != written) {
            logger(DEBUG_PROTOCOL, LOG_WARNING, "QUIC[%s] sendto incomplete or failed: %zd/%zd (errno=%d: %s)",
                   trace_id, sent, written, errno, strerror(errno));
        } else {
            logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC[%s] sendto OK: %zd bytes", trace_id, sent);
        }

		qconn->bytes_sent += sent;
		qconn->packets_sent++;
		total_sent += sent;
		packet_count++;
	}

    if(packet_count > 0) {
        const char *trace_id = quic_trace_id(qconn->conn);
        logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC[%s] sent %d packets, %zd bytes total",
               trace_id, packet_count, total_sent);
    }

	return total_sent;
}

/* Receive QUIC packet */
ssize_t quic_conn_recv(quic_conn_t *qconn, const uint8_t *buf, size_t len) {
	if(!qconn || !qconn->conn || !buf) {
		return -1;
	}

	/* Prepare recv_info structure */
	quiche_recv_info recv_info = {
		.from = (struct sockaddr *)&qconn->peer_addr,
		.from_len = qconn->peer_addr_len,
		.to = NULL,  // We'll fill this if needed
		.to_len = 0
	};

	/* Get local address */
	struct sockaddr_storage local_addr;
	socklen_t local_addr_len = sizeof(local_addr);
	getsockname(qconn->sock_fd, (struct sockaddr *)&local_addr, &local_addr_len);
	recv_info.to = (struct sockaddr *)&local_addr;
	recv_info.to_len = local_addr_len;

	/* Feed packet to quiche */
    const char *trace_id = quic_trace_id(qconn->conn);
    ssize_t done = quiche_conn_recv(qconn->conn, (uint8_t *)buf, len, &recv_info);

    if(done < 0) {
        logger(DEBUG_PROTOCOL, LOG_ERR, "QUIC[%s] recv failed: %zd", trace_id, done);
        return -1;
    }

	qconn->bytes_received += done;
	qconn->packets_received++;

	/* Check if handshake is complete */
    if(!qconn->handshake_complete && quiche_conn_is_established(qconn->conn)) {
        qconn->handshake_complete = true;
        qconn->state = QUIC_STATE_ESTABLISHED;
        /* Log negotiated ALPN */
        const uint8_t *alp = NULL; size_t alp_len = 0;
        quiche_conn_application_proto(qconn->conn, &alp, &alp_len);
        char alpn_buf[64] = {0};
        size_t copy = alp_len < sizeof(alpn_buf) - 1 ? alp_len : sizeof(alpn_buf) - 1;
        if(alp && copy) memcpy(alpn_buf, alp, copy);
        logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC[%s] handshake complete, ALPN='%s'", trace_id, alpn_buf);
    }

    /* Extra trace for debugging stalled handshakes */
    if(!qconn->handshake_complete) {
        bool est = quiche_conn_is_established(qconn->conn);
        logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC[%s] handshake state: established=%d bytes_received=%zd",
               trace_id, est, done);
    }

    return done;
}

/* Check if connection is established */
bool quic_conn_is_established(quic_conn_t *qconn) {
	if(!qconn || !qconn->conn) {
		return false;
	}

	return quiche_conn_is_established(qconn->conn);
}

/* Check if connection is closed */
bool quic_conn_is_closed(quic_conn_t *qconn) {
	if(!qconn || !qconn->conn) {
		return true;
	}

	return quiche_conn_is_closed(qconn->conn);
}

/* Send VPN packet */
bool quic_conn_send_vpn_packet(quic_conn_t *qconn, const void *data, size_t len) {
	if(!qconn || !qconn->conn || !data || len == 0) {
		return false;
	}

	if(!quic_conn_is_established(qconn)) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Cannot send VPN packet: connection not established");
		return false;
	}

	/* Open or reuse a stream */
	uint64_t stream_id = qconn->next_stream_id;

	/* Send data on stream */
	uint64_t error_code = 0;
	ssize_t sent = quiche_conn_stream_send(qconn->conn, stream_id, (const uint8_t *)data, len, false, &error_code);

	if(sent < 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "quiche_conn_stream_send failed: %zd (error: %lu)", sent, error_code);
		return false;
	}

	if((size_t)sent != len) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Incomplete VPN packet send: %zd/%zu", sent, len);
	}

	/* Generate QUIC packets */
	quic_conn_send(qconn);

	return true;
}

/* Receive VPN packet */
ssize_t quic_conn_recv_vpn_packet(quic_conn_t *qconn, void *data, size_t max_len) {
	if(!qconn || !qconn->conn || !data) {
		return -1;
	}

	if(!quic_conn_is_established(qconn)) {
		return 0;
	}

	/* Iterate over all readable streams */
	quiche_stream_iter *readable = quiche_conn_readable(qconn->conn);

	if(!readable) {
		return 0;
	}

	ssize_t total_read = 0;
	uint64_t stream_id = 0;

	while(quiche_stream_iter_next(readable, &stream_id)) {
		bool fin = false;
		uint64_t error_code = 0;
		ssize_t recv_len = quiche_conn_stream_recv(qconn->conn, stream_id,
		                   (uint8_t *)data, max_len, &fin, &error_code);

		if(recv_len > 0) {
			total_read = recv_len;
			break;  // Return first packet
		}
	}

	quiche_stream_iter_free(readable);

	return total_read;
}

/* Buffer VPN packet during handshake */
bool quic_conn_buffer_vpn_packet(quic_conn_t *qconn, const void *data, size_t len) {
	if(!qconn || !data || len == 0 || len > sizeof(((buffered_packet_t *)0)->data)) {
		return false;
	}

	/* Limit buffer size to prevent memory exhaustion */
	#define MAX_BUFFERED_PACKETS 100
	if(qconn->send_buf_count >= MAX_BUFFERED_PACKETS) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "QUIC send buffer full, dropping packet");
		return false;
	}

	/* Allocate new buffered packet */
	buffered_packet_t *bp = xmalloc(sizeof(buffered_packet_t));
	memcpy(bp->data, data, len);
	bp->len = len;
	bp->next = NULL;

	/* Add to tail of queue */
	if(qconn->send_buf_tail) {
		qconn->send_buf_tail->next = bp;
	} else {
		qconn->send_buf_head = bp;
	}

	qconn->send_buf_tail = bp;
	qconn->send_buf_count++;

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Buffered VPN packet (%zu bytes), queue size: %zu",
	       len, qconn->send_buf_count);

	return true;
}

/* Send all buffered packets after handshake completes */
void quic_conn_flush_buffered_packets(quic_conn_t *qconn) {
	if(!qconn || !quic_conn_is_established(qconn)) {
		return;
	}

	size_t sent = 0;
	size_t failed = 0;

	buffered_packet_t *bp = qconn->send_buf_head;

	while(bp) {
		buffered_packet_t *next = bp->next;

		if(quic_conn_send_vpn_packet(qconn, bp->data, bp->len)) {
			sent++;
		} else {
			failed++;
		}

		free(bp);
		bp = next;
	}

	qconn->send_buf_head = NULL;
	qconn->send_buf_tail = NULL;
	qconn->send_buf_count = 0;

	if(sent > 0 || failed > 0) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Flushed buffered packets: %zu sent, %zu failed",
		       sent, failed);
	}
}

/* Open new stream */
uint64_t quic_conn_open_stream(quic_conn_t *qconn) {
	if(!qconn) {
		return (uint64_t) - 1;
	}

	uint64_t stream_id = qconn->next_stream_id;
	qconn->next_stream_id += 4;  // Skip to next client/server-initiated stream

	return stream_id;
}

/* Send data on stream */
bool quic_conn_stream_send(quic_conn_t *qconn, uint64_t stream_id, const uint8_t *data, size_t len, bool fin) {
	if(!qconn || !qconn->conn || !data) {
		return false;
	}

	uint64_t error_code = 0;
	ssize_t sent = quiche_conn_stream_send(qconn->conn, stream_id, data, len, fin, &error_code);

	if(sent < 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "quiche_conn_stream_send failed: %zd (error: %lu)", sent, error_code);
		return false;
	}

	return true;
}

/* Receive data from stream */
ssize_t quic_conn_stream_recv(quic_conn_t *qconn, uint64_t stream_id, uint8_t *data, size_t max_len, bool *fin) {
	if(!qconn || !qconn->conn || !data || !fin) {
		return -1;
	}

	uint64_t error_code = 0;
	ssize_t recv_len = quiche_conn_stream_recv(qconn->conn, stream_id, data, max_len, fin, &error_code);

	if(recv_len < 0 && recv_len != QUICHE_ERR_DONE) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "quiche_conn_stream_recv failed: %zd (error: %lu)", recv_len, error_code);
		return -1;
	}

	return recv_len;
}

/* Convert QUIC state to string */
const char *quic_state_to_string(quic_state_t state) {
	switch(state) {
	case QUIC_STATE_INIT:
		return "INIT";

	case QUIC_STATE_HANDSHAKE:
		return "HANDSHAKE";

	case QUIC_STATE_ESTABLISHED:
		return "ESTABLISHED";

	case QUIC_STATE_DRAINING:
		return "DRAINING";

	case QUIC_STATE_CLOSED:
		return "CLOSED";

	default:
		return "UNKNOWN";
	}
}

/* Set node pointer */
void quic_conn_set_node(quic_conn_t *qconn, void *node) {
	if(qconn) {
		qconn->node = node;
	}
}
/* Enable quiche internal debug logging */
static void quic_dbg_cb(const char *line, void *arg) {
    (void)arg;
    logger(DEBUG_PROTOCOL, LOG_DEBUG, "quiche: %s", line);
}
