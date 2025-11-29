/*
    quic_reality.h -- Reality protocol for QUIC
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

#ifndef TINC_QUIC_REALITY_H
#define TINC_QUIC_REALITY_H

#include "system.h"
#include "quic.h"
#include "../vless/reality.h"

/* QUIC Reality Context */
typedef struct quic_reality_ctx_t {
	/* Reality configuration */
	reality_config_t *config;

	/* State */
	bool authenticated;
	bool fallback_active;

	/* Extracted from ClientHello */
	char client_sni[256];
	uint8_t client_short_id[8];
	uint8_t client_public_key[32];

	/* Shared secret and auth key */
	uint8_t shared_secret[32];
	uint8_t auth_key[32];

	/* Fallback connection (if authentication fails) */
	int fallback_fd;
	struct sockaddr_storage fallback_addr;
	socklen_t fallback_addr_len;
} quic_reality_ctx_t;

/* Function prototypes */

/* Create/destroy Reality context */
extern quic_reality_ctx_t *quic_reality_new(reality_config_t *config);
extern void quic_reality_free(quic_reality_ctx_t *ctx);

/* Verification and authentication */
extern bool quic_reality_verify_client(quic_reality_ctx_t *ctx, quic_conn_t *qconn);
extern bool quic_reality_extract_sni(quic_reality_ctx_t *ctx, const uint8_t *data, size_t len);
extern bool quic_reality_check_auth(quic_reality_ctx_t *ctx);

/* Fallback mechanism */
extern bool quic_reality_start_fallback(quic_reality_ctx_t *ctx);
extern void quic_reality_proxy_data(quic_reality_ctx_t *ctx, quic_conn_t *client_conn);

#endif /* TINC_QUIC_REALITY_H */
