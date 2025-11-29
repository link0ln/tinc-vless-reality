/*
    vless.h -- VLESS protocol support for tinc
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

#ifndef TINC_VLESS_H
#define TINC_VLESS_H

#include "system.h"
#include <stdint.h>
#include <stdbool.h>

/* VLESS Protocol Version */
#define VLESS_VERSION 0

/* VLESS Commands */
#define VLESS_CMD_TCP 0x01
#define VLESS_CMD_UDP 0x02
#define VLESS_CMD_MUX 0x03

/* VLESS Address Types */
#define VLESS_ADDR_IPV4 0x01
#define VLESS_ADDR_DOMAIN 0x02
#define VLESS_ADDR_IPV6 0x03

/* VLESS Connection States */
typedef enum vless_state_t {
	VLESS_STATE_INIT = 0,
	VLESS_STATE_HANDSHAKE,
	VLESS_STATE_REALITY_TLS,
	VLESS_STATE_AUTHENTICATED,
	VLESS_STATE_DATA_TRANSFER,
	VLESS_STATE_ERROR,
	VLESS_STATE_CLOSED
} vless_state_t;

/* UUID structure (16 bytes) */
typedef struct vless_uuid_t {
	uint8_t bytes[16];
} vless_uuid_t;

/* VLESS Request Header */
typedef struct vless_request_t {
	uint8_t version;                // Protocol version (0)
	vless_uuid_t uuid;              // User UUID
	uint8_t addon_len;              // AddOn Length (typically 0)
	uint8_t command;                // Command (TCP/UDP/MUX)
	uint16_t port;                  // Destination port
	uint8_t addr_type;              // Address type
	uint8_t addr_len;               // Address length (for domain)
	union {
		uint8_t ipv4[4];
		uint8_t ipv6[16];
		char domain[256];
	} addr;
} vless_request_t;

/* VLESS Response Header */
typedef struct vless_response_t {
	uint8_t version;                // Protocol version (0)
	uint8_t addon_len;              // AddOn Length (typically 0)
} vless_response_t;

/* VLESS Flow Control types (for XTLS) */
typedef enum vless_flow_t {
	VLESS_FLOW_NONE = 0,
	VLESS_FLOW_XTLS_RPRX_VISION,
	VLESS_FLOW_XTLS_RPRX_VISION_UDP443
} vless_flow_t;

/* VLESS Connection Context */
typedef struct vless_ctx_t {
	vless_state_t state;            // Current connection state
	vless_uuid_t local_uuid;        // Local UUID (as server)
	vless_uuid_t remote_uuid;       // Remote UUID (as client)
	bool is_client;                 // true if we initiated connection
	vless_flow_t flow;              // Flow control mode

	/* Reality protocol data */
	bool reality_enabled;           // Is Reality protocol enabled?
	void *reality_ctx;              // Reality protocol context

	/* Request/Response */
	vless_request_t request;
	vless_response_t response;

	/* Buffers */
	uint8_t *recv_buf;
	size_t recv_buf_len;
	size_t recv_buf_pos;

	uint8_t *send_buf;
	size_t send_buf_len;
	size_t send_buf_pos;

	/* Statistics */
	uint64_t bytes_sent;
	uint64_t bytes_received;
} vless_ctx_t;

/* Function prototypes */

/* Initialize VLESS subsystem */
extern void vless_init(void);
extern void vless_exit(void);

/* UUID operations */
extern bool vless_uuid_generate(vless_uuid_t *uuid);
extern bool vless_uuid_from_string(vless_uuid_t *uuid, const char *str);
extern char *vless_uuid_to_string(const vless_uuid_t *uuid);
extern bool vless_uuid_equal(const vless_uuid_t *a, const vless_uuid_t *b);

/* VLESS context management */
extern vless_ctx_t *vless_ctx_new(bool is_client);
extern void vless_ctx_free(vless_ctx_t *ctx);
extern void vless_ctx_reset(vless_ctx_t *ctx);

/* VLESS protocol operations */
extern bool vless_handshake_client(vless_ctx_t *ctx, const char *dest_addr,
                                    uint16_t dest_port, uint8_t command);
extern bool vless_handshake_server(vless_ctx_t *ctx);
extern bool vless_send_request(vless_ctx_t *ctx, int fd);
extern bool vless_recv_request(vless_ctx_t *ctx, int fd);
extern bool vless_send_response(vless_ctx_t *ctx, int fd);
extern bool vless_recv_response(vless_ctx_t *ctx, int fd);

/* Data transfer */
extern ssize_t vless_write(vless_ctx_t *ctx, int fd, const void *data, size_t len);
extern ssize_t vless_read(vless_ctx_t *ctx, int fd, void *data, size_t len);

/* Header encoding/decoding */
extern ssize_t vless_encode_request(vless_request_t *req, uint8_t *buf, size_t buf_len);
extern ssize_t vless_decode_request(const uint8_t *buf, size_t buf_len, vless_request_t *req);
extern ssize_t vless_encode_response(vless_response_t *resp, uint8_t *buf, size_t buf_len);
extern ssize_t vless_decode_response(const uint8_t *buf, size_t buf_len, vless_response_t *resp);

/* Utility functions */
extern const char *vless_state_to_string(vless_state_t state);
extern const char *vless_command_to_string(uint8_t command);
extern const char *vless_flow_to_string(vless_flow_t flow);

#endif /* TINC_VLESS_H */
