/*
    quic_reality.c -- Reality protocol implementation for QUIC
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
#include <netdb.h>
#include <string.h>

#include "../logger.h"
#include "../xalloc.h"
#include "../crypto.h"
#include "quic_reality.h"
#include "quic.h"

/* TLS handshake message types */
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01

/* TLS extension types */
#define TLS_EXT_SERVER_NAME 0x0000
#define TLS_EXT_REALITY_SHORT_ID 0xff01  /* Custom extension for Reality */

/* Create new Reality context */
quic_reality_ctx_t *quic_reality_new(reality_config_t *config) {
	if(!config) {
		return NULL;
	}

	quic_reality_ctx_t *ctx = xzalloc(sizeof(quic_reality_ctx_t));
	ctx->config = config;
	ctx->authenticated = false;
	ctx->fallback_active = false;
	ctx->fallback_fd = -1;

	return ctx;
}

/* Free Reality context */
void quic_reality_free(quic_reality_ctx_t *ctx) {
	if(!ctx) {
		return;
	}

	if(ctx->fallback_fd >= 0) {
		close(ctx->fallback_fd);
	}

	free(ctx);
}

/* Parse TLS extension from ClientHello */
static bool parse_tls_extension(const uint8_t *data, size_t len, uint16_t ext_type,
                                 uint8_t *out_data, size_t *out_len) {
	if(!data || len < 2) {
		return false;
	}

	size_t offset = 0;

	while(offset + 4 <= len) {
		/* Read extension type and length */
		uint16_t type = (data[offset] << 8) | data[offset + 1];
		uint16_t ext_len = (data[offset + 2] << 8) | data[offset + 3];
		offset += 4;

		if(offset + ext_len > len) {
			return false;  /* Malformed */
		}

		if(type == ext_type) {
			/* Found the extension */
			if(out_data && out_len) {
				size_t copy_len = ext_len < *out_len ? ext_len : *out_len;
				memcpy(out_data, data + offset, copy_len);
				*out_len = copy_len;
			}

			return true;
		}

		offset += ext_len;
	}

	return false;  /* Extension not found */
}

/* Extract SNI from TLS ClientHello */
static bool extract_sni_from_client_hello(const uint8_t *data, size_t len, char *sni_out, size_t sni_max) {
	if(!data || len < 43 || !sni_out) {  /* Minimum ClientHello size */
		return false;
	}

	/* Skip fixed ClientHello fields:
	   - Handshake Type (1 byte)
	   - Length (3 bytes)
	   - Protocol Version (2 bytes)
	   - Random (32 bytes)
	   - Session ID Length (1 byte) + Session ID
	*/

	size_t offset = 0;

	/* Handshake type */
	if(data[offset] != TLS_HANDSHAKE_CLIENT_HELLO) {
		return false;
	}

	offset += 4;  /* Skip type + length */

	if(offset + 34 > len) {
		return false;
	}

	offset += 2;  /* Protocol version */
	offset += 32;  /* Random */

	/* Session ID */
	uint8_t session_id_len = data[offset++];

	if(offset + session_id_len > len) {
		return false;
	}

	offset += session_id_len;

	/* Cipher suites */
	if(offset + 2 > len) {
		return false;
	}

	uint16_t cipher_suites_len = (data[offset] << 8) | data[offset + 1];
	offset += 2;

	if(offset + cipher_suites_len > len) {
		return false;
	}

	offset += cipher_suites_len;

	/* Compression methods */
	if(offset + 1 > len) {
		return false;
	}

	uint8_t compression_len = data[offset++];

	if(offset + compression_len > len) {
		return false;
	}

	offset += compression_len;

	/* Extensions */
	if(offset + 2 > len) {
		return false;  /* No extensions */
	}

	uint16_t extensions_len = (data[offset] << 8) | data[offset + 1];
	offset += 2;

	if(offset + extensions_len > len) {
		return false;
	}

	/* Parse SNI extension */
	uint8_t sni_data[256];
	size_t sni_data_len = sizeof(sni_data);

	if(!parse_tls_extension(data + offset, extensions_len, TLS_EXT_SERVER_NAME, sni_data, &sni_data_len)) {
		return false;  /* SNI not found */
	}

	/* SNI format: server_name_list_length (2) + name_type (1) + name_length (2) + name */
	if(sni_data_len < 5) {
		return false;
	}

	uint16_t name_len = (sni_data[3] << 8) | sni_data[4];

	if(5 + name_len > sni_data_len) {
		return false;
	}

	size_t copy_len = name_len < sni_max - 1 ? name_len : sni_max - 1;
	memcpy(sni_out, sni_data + 5, copy_len);
	sni_out[copy_len] = '\0';

	return true;
}

/* Extract SNI and Reality parameters from QUIC Initial packet */
bool quic_reality_extract_sni(quic_reality_ctx_t *ctx, const uint8_t *data, size_t len) {
	if(!ctx || !data || len == 0) {
		return false;
	}

	/* QUIC Initial packets contain CRYPTO frames with TLS ClientHello
	   For simplicity, assume the ClientHello is in the first CRYPTO frame
	   In production, we'd need to reassemble fragmented CRYPTO frames */

	/* TODO: Parse QUIC header to locate CRYPTO frame
	   For now, search for TLS ClientHello magic bytes (0x01 0x00 0x00) */

	for(size_t i = 0; i < len - 43; i++) {
		if(data[i] == TLS_HANDSHAKE_CLIENT_HELLO) {
			/* Potential ClientHello found */
			if(extract_sni_from_client_hello(data + i, len - i, ctx->client_sni, sizeof(ctx->client_sni))) {
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "Reality: Extracted SNI: %s", ctx->client_sni);

				/* Extract Short ID from custom extension (if present) */
				/* TODO: Parse Reality Short ID extension */

				return true;
			}
		}
	}

	logger(DEBUG_PROTOCOL, LOG_WARNING, "Reality: Failed to extract SNI from QUIC packet");
	return false;
}

/* Verify Reality authentication */
bool quic_reality_check_auth(quic_reality_ctx_t *ctx) {
	if(!ctx || !ctx->config) {
		return false;
	}

	/* Check if SNI matches configured server name */
	if(!ctx->config->server_name[0] || strlen(ctx->client_sni) == 0) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Reality: No server name configured or SNI empty");
		return false;
	}

	if(strcmp(ctx->client_sni, ctx->config->server_name) != 0) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Reality: SNI mismatch. Expected %s, got %s",
		       ctx->config->server_name, ctx->client_sni);
		return false;
	}

	/* Check Short ID (if configured) */
	if(ctx->config->num_short_ids > 0) {
		bool short_id_valid = false;

		for(int i = 0; i < ctx->config->num_short_ids; i++) {
			if(memcmp(ctx->client_short_id, ctx->config->short_ids[i], 8) == 0) {
				short_id_valid = true;
				break;
			}
		}

		if(!short_id_valid) {
			logger(DEBUG_PROTOCOL, LOG_INFO, "Reality: Invalid Short ID");
			return false;
		}
	}

	/* Perform X25519 key exchange */
	/* TODO: Extract client public key from TLS extension
	   For now, skip key exchange and just check SNI */

	ctx->authenticated = true;
	logger(DEBUG_PROTOCOL, LOG_INFO, "Reality: Client authenticated successfully");

	return true;
}

/* Start fallback to real destination */
bool quic_reality_start_fallback(quic_reality_ctx_t *ctx) {
	if(!ctx || !ctx->config) {
		return false;
	}

	if(ctx->fallback_active) {
		return true;  /* Already active */
	}

	/* Parse destination host and port */
	char dest_host[256];
	int dest_port = ctx->config->dest_port > 0 ? ctx->config->dest_port : 443;

	if(ctx->config->dest_domain[0]) {
		const char *colon = strchr(ctx->config->dest_domain, ':');

		if(colon) {
			size_t host_len = colon - ctx->config->dest_domain;

			if(host_len >= sizeof(dest_host)) {
				host_len = sizeof(dest_host) - 1;
			}

			memcpy(dest_host, ctx->config->dest_domain, host_len);
			dest_host[host_len] = '\0';
			dest_port = atoi(colon + 1);
		} else {
			strncpy(dest_host, ctx->config->dest_domain, sizeof(dest_host) - 1);
			dest_host[sizeof(dest_host) - 1] = '\0';
		}
	} else {
		/* Default to google.com */
		strcpy(dest_host, "www.google.com");
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Reality: Starting fallback to %s:%d", dest_host, dest_port);

	/* Resolve destination address */
	struct addrinfo hints, *result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;  /* QUIC uses UDP */
	hints.ai_protocol = IPPROTO_UDP;

	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", dest_port);

	if(getaddrinfo(dest_host, port_str, &hints, &result) != 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Reality: Failed to resolve %s: %s", dest_host, strerror(errno));
		return false;
	}

	/* Create UDP socket for fallback */
	ctx->fallback_fd = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP);

	if(ctx->fallback_fd < 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Reality: Failed to create fallback socket: %s", strerror(errno));
		freeaddrinfo(result);
		return false;
	}

	/* Store destination address */
	memcpy(&ctx->fallback_addr, result->ai_addr, result->ai_addrlen);
	ctx->fallback_addr_len = result->ai_addrlen;

	freeaddrinfo(result);

	ctx->fallback_active = true;

	logger(DEBUG_PROTOCOL, LOG_INFO, "Reality: Fallback connection established");

	return true;
}

/* Proxy data between client and real destination */
void quic_reality_proxy_data(quic_reality_ctx_t *ctx, quic_conn_t *client_conn) {
	if(!ctx || !ctx->fallback_active || ctx->fallback_fd < 0 || !client_conn) {
		return;
	}

	/* Read data from client QUIC connection */
	uint8_t buf[4096];
	ssize_t len = quic_conn_recv(client_conn, buf, sizeof(buf));

	if(len > 0) {
		/* Forward to real destination */
		ssize_t sent = sendto(ctx->fallback_fd, buf, len, 0,
		                      (struct sockaddr *)&ctx->fallback_addr, ctx->fallback_addr_len);

		if(sent < 0) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Reality: Failed to forward to destination: %s", strerror(errno));
			return;
		}

		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Reality: Forwarded %zd bytes to real destination", sent);
	}

	/* Read response from real destination */
	len = recvfrom(ctx->fallback_fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);

	if(len > 0) {
		/* Send back to client via QUIC
		   This is simplified - in production we'd need to handle QUIC streams properly */
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Reality: Received %zd bytes from real destination", len);

		/* TODO: Send data back through QUIC connection */
		/* For now, this demonstrates the fallback mechanism */
	}
}

/* Verify client connection */
bool quic_reality_verify_client(quic_reality_ctx_t *ctx, quic_conn_t *qconn) {
	if(!ctx || !qconn) {
		return false;
	}

	/* Extract Initial packet from QUIC connection
	   This is a simplified version - production code would need to:
	   1. Wait for complete Initial packet
	   2. Parse QUIC header and CRYPTO frames
	   3. Reassemble fragmented ClientHello
	*/

	/* For now, return false to trigger fallback
	   TODO: Implement proper QUIC packet inspection */

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Reality: Client verification not yet implemented, triggering fallback");

	return false;
}
