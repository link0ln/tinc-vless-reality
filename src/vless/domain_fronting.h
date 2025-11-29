/*
    domain_fronting.h -- Domain Fronting support for DPI evasion
    Copyright (C) 2025 tinc-vless contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#ifndef TINC_DOMAIN_FRONTING_H
#define TINC_DOMAIN_FRONTING_H

#include "system.h"
#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * DOMAIN FRONTING
 * ============================================================================
 * Domain fronting exploits the difference between SNI (Server Name Indication)
 * and HTTP Host header to hide the true destination behind a CDN.
 *
 * How it works:
 * 1. TLS SNI contains: innocent-domain.cdn.com (visible to DPI)
 * 2. HTTP Host header contains: actual-vpn-server.com (encrypted inside TLS)
 * 3. CDN routes request based on Host header, not SNI
 *
 * This requires:
 * - A CDN that allows different SNI and Host headers
 * - An innocent-looking domain hosted on the same CDN
 */

typedef struct domain_fronting_config_t {
	bool enabled;
	char front_domain[256];      /* Domain visible in SNI (e.g., allowed.cdn.com) */
	char real_domain[256];       /* Real destination in Host header */
	char cdn_ip[64];             /* CDN IP to connect to */
	uint16_t cdn_port;           /* CDN port (usually 443) */
} domain_fronting_config_t;

/* ============================================================================
 * HTTP/3 MASQUERADING
 * ============================================================================
 * Makes VPN traffic look like legitimate HTTP/3 (QUIC) traffic.
 * This is effective because:
 * 1. HTTP/3 traffic is encrypted and hard to analyze
 * 2. Many sites use HTTP/3, so it looks normal
 * 3. QUIC has built-in packet padding and multiplexing
 */

typedef struct http3_masq_config_t {
	bool enabled;
	char fake_host[256];         /* Fake Host header for HTTP/3 */
	char fake_path[256];         /* Fake path (e.g., /api/v1/stream) */
	char fake_user_agent[512];   /* Fake User-Agent */
	bool add_http3_frames;       /* Add fake HTTP/3 frame headers */
	bool simulate_grease;        /* Add GREASE values like browsers */
} http3_masq_config_t;

/* ============================================================================
 * WEBSOCKET ENCAPSULATION
 * ============================================================================
 * Wraps VPN traffic in WebSocket protocol.
 * Benefits:
 * 1. WebSocket is allowed on most networks
 * 2. Looks like a web application
 * 3. Can pass through HTTP proxies
 */

typedef struct websocket_config_t {
	bool enabled;
	char ws_host[256];           /* WebSocket Host header */
	char ws_path[256];           /* WebSocket upgrade path */
	char ws_origin[256];         /* WebSocket Origin header */
	char ws_protocol[64];        /* Sec-WebSocket-Protocol */
	bool use_binary_frames;      /* Use binary instead of text frames */
	bool fragment_large_packets; /* Fragment large packets into multiple frames */
	uint16_t max_frame_size;     /* Maximum WebSocket frame size */
} websocket_config_t;

/* WebSocket opcodes */
#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT         0x1
#define WS_OPCODE_BINARY       0x2
#define WS_OPCODE_CLOSE        0x8
#define WS_OPCODE_PING         0x9
#define WS_OPCODE_PONG         0xA

/* WebSocket frame structure */
typedef struct __attribute__((packed)) ws_frame_header_t {
	uint8_t opcode : 4;
	uint8_t rsv3 : 1;
	uint8_t rsv2 : 1;
	uint8_t rsv1 : 1;
	uint8_t fin : 1;
	uint8_t payload_len : 7;
	uint8_t mask : 1;
} ws_frame_header_t;

/* ============================================================================
 * COMBINED TRANSPORT CONFIG
 * ============================================================================
 */

typedef struct advanced_transport_config_t {
	domain_fronting_config_t domain_fronting;
	http3_masq_config_t http3_masq;
	websocket_config_t websocket;
} advanced_transport_config_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================
 */

/* Initialization */
extern void advanced_transport_init(void);
extern void advanced_transport_exit(void);
extern advanced_transport_config_t *advanced_transport_get_config(void);
extern bool advanced_transport_load_config(void);

/* Domain Fronting */
extern bool domain_fronting_is_enabled(void);
extern const char *domain_fronting_get_sni(void);
extern const char *domain_fronting_get_host(void);
extern bool domain_fronting_modify_sni(uint8_t *tls_data, size_t *len, size_t max_len);

/* HTTP/3 Masquerading */
extern bool http3_masq_is_enabled(void);
extern size_t http3_masq_add_headers(uint8_t *buffer, size_t data_len, size_t buffer_size);
extern size_t http3_masq_remove_headers(uint8_t *buffer, size_t total_len);
extern void http3_masq_add_grease(uint8_t *buffer, size_t *len, size_t max_len);

/* WebSocket Encapsulation */
extern bool websocket_is_enabled(void);
extern size_t websocket_create_handshake(uint8_t *buffer, size_t buffer_size);
extern bool websocket_verify_handshake(const uint8_t *buffer, size_t len);
extern size_t websocket_wrap_data(const uint8_t *data, size_t data_len,
                                   uint8_t *out_buffer, size_t out_buffer_size);
extern size_t websocket_unwrap_data(const uint8_t *frame, size_t frame_len,
                                     uint8_t *out_buffer, size_t out_buffer_size);
extern size_t websocket_create_ping(uint8_t *buffer, size_t buffer_size);
extern size_t websocket_create_pong(const uint8_t *ping_data, size_t ping_len,
                                     uint8_t *buffer, size_t buffer_size);

/* Utility */
extern void advanced_transport_log_stats(void);

#endif /* TINC_DOMAIN_FRONTING_H */
