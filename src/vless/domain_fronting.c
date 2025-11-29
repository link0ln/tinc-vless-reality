/*
    domain_fronting.c -- Advanced transport techniques implementation
    Copyright (C) 2025 tinc-vless contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"
#include "domain_fronting.h"
#include "../conf.h"
#include "../logger.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

/* Global config */
static advanced_transport_config_t transport_config;
static bool transport_initialized = false;

/* Statistics */
static uint64_t fronted_requests = 0;
static uint64_t http3_packets = 0;
static uint64_t ws_frames_sent = 0;
static uint64_t ws_frames_received = 0;

/* ============================================================================
 * INITIALIZATION
 * ============================================================================
 */

void advanced_transport_init(void) {
	if(transport_initialized) {
		return;
	}

	memset(&transport_config, 0, sizeof(transport_config));

	/* Domain Fronting defaults */
	transport_config.domain_fronting.enabled = false;
	strncpy(transport_config.domain_fronting.front_domain, "www.google.com",
	        sizeof(transport_config.domain_fronting.front_domain) - 1);
	strncpy(transport_config.domain_fronting.cdn_ip, "",
	        sizeof(transport_config.domain_fronting.cdn_ip) - 1);
	transport_config.domain_fronting.cdn_port = 443;

	/* HTTP/3 Masquerading defaults */
	transport_config.http3_masq.enabled = false;
	strncpy(transport_config.http3_masq.fake_host, "www.google.com",
	        sizeof(transport_config.http3_masq.fake_host) - 1);
	strncpy(transport_config.http3_masq.fake_path, "/",
	        sizeof(transport_config.http3_masq.fake_path) - 1);
	strncpy(transport_config.http3_masq.fake_user_agent,
	        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
	        sizeof(transport_config.http3_masq.fake_user_agent) - 1);
	transport_config.http3_masq.add_http3_frames = true;
	transport_config.http3_masq.simulate_grease = true;

	/* WebSocket defaults */
	transport_config.websocket.enabled = false;
	strncpy(transport_config.websocket.ws_host, "localhost",
	        sizeof(transport_config.websocket.ws_host) - 1);
	strncpy(transport_config.websocket.ws_path, "/ws",
	        sizeof(transport_config.websocket.ws_path) - 1);
	strncpy(transport_config.websocket.ws_origin, "https://localhost",
	        sizeof(transport_config.websocket.ws_origin) - 1);
	strncpy(transport_config.websocket.ws_protocol, "binary",
	        sizeof(transport_config.websocket.ws_protocol) - 1);
	transport_config.websocket.use_binary_frames = true;
	transport_config.websocket.fragment_large_packets = true;
	transport_config.websocket.max_frame_size = 16384;

	transport_initialized = true;
	logger(DEBUG_ALWAYS, LOG_INFO, "Advanced transport subsystem initialized");
}

void advanced_transport_exit(void) {
	if(!transport_initialized) {
		return;
	}

	transport_initialized = false;
	logger(DEBUG_ALWAYS, LOG_INFO, "Advanced transport subsystem shutdown");
}

advanced_transport_config_t *advanced_transport_get_config(void) {
	if(!transport_initialized) {
		advanced_transport_init();
	}
	return &transport_config;
}

/* ============================================================================
 * CONFIGURATION LOADING
 * ============================================================================
 */

bool advanced_transport_load_config(void) {
	if(!transport_initialized) {
		advanced_transport_init();
	}

	char *str_val;
	bool bool_val;
	int int_val;

	/* Domain Fronting config */
	if(get_config_bool(lookup_config(config_tree, "VLESSDomainFronting"), &bool_val)) {
		transport_config.domain_fronting.enabled = bool_val;
		if(bool_val) {
			logger(DEBUG_ALWAYS, LOG_INFO, "Domain Fronting enabled");
		}
	}

	if(get_config_string(lookup_config(config_tree, "VLESSFrontDomain"), &str_val)) {
		strncpy(transport_config.domain_fronting.front_domain, str_val,
		        sizeof(transport_config.domain_fronting.front_domain) - 1);
	}

	if(get_config_string(lookup_config(config_tree, "VLESSRealDomain"), &str_val)) {
		strncpy(transport_config.domain_fronting.real_domain, str_val,
		        sizeof(transport_config.domain_fronting.real_domain) - 1);
	}

	if(get_config_string(lookup_config(config_tree, "VLESSCDNIP"), &str_val)) {
		strncpy(transport_config.domain_fronting.cdn_ip, str_val,
		        sizeof(transport_config.domain_fronting.cdn_ip) - 1);
	}

	if(get_config_int(lookup_config(config_tree, "VLESSCDNPort"), &int_val)) {
		transport_config.domain_fronting.cdn_port = (uint16_t)int_val;
	}

	/* HTTP/3 Masquerading config */
	if(get_config_bool(lookup_config(config_tree, "VLESSHTTP3Masq"), &bool_val)) {
		transport_config.http3_masq.enabled = bool_val;
		if(bool_val) {
			logger(DEBUG_ALWAYS, LOG_INFO, "HTTP/3 Masquerading enabled");
		}
	}

	if(get_config_string(lookup_config(config_tree, "VLESSHTTP3Host"), &str_val)) {
		strncpy(transport_config.http3_masq.fake_host, str_val,
		        sizeof(transport_config.http3_masq.fake_host) - 1);
	}

	if(get_config_string(lookup_config(config_tree, "VLESSHTTP3Path"), &str_val)) {
		strncpy(transport_config.http3_masq.fake_path, str_val,
		        sizeof(transport_config.http3_masq.fake_path) - 1);
	}

	if(get_config_string(lookup_config(config_tree, "VLESSHTTP3UserAgent"), &str_val)) {
		strncpy(transport_config.http3_masq.fake_user_agent, str_val,
		        sizeof(transport_config.http3_masq.fake_user_agent) - 1);
	}

	if(get_config_bool(lookup_config(config_tree, "VLESSHTTP3GREASE"), &bool_val)) {
		transport_config.http3_masq.simulate_grease = bool_val;
	}

	/* WebSocket config */
	if(get_config_bool(lookup_config(config_tree, "VLESSWebSocket"), &bool_val)) {
		transport_config.websocket.enabled = bool_val;
		if(bool_val) {
			logger(DEBUG_ALWAYS, LOG_INFO, "WebSocket encapsulation enabled");
		}
	}

	if(get_config_string(lookup_config(config_tree, "VLESSWSHost"), &str_val)) {
		strncpy(transport_config.websocket.ws_host, str_val,
		        sizeof(transport_config.websocket.ws_host) - 1);
	}

	if(get_config_string(lookup_config(config_tree, "VLESSWSPath"), &str_val)) {
		strncpy(transport_config.websocket.ws_path, str_val,
		        sizeof(transport_config.websocket.ws_path) - 1);
	}

	if(get_config_string(lookup_config(config_tree, "VLESSWSOrigin"), &str_val)) {
		strncpy(transport_config.websocket.ws_origin, str_val,
		        sizeof(transport_config.websocket.ws_origin) - 1);
	}

	if(get_config_bool(lookup_config(config_tree, "VLESSWSBinary"), &bool_val)) {
		transport_config.websocket.use_binary_frames = bool_val;
	}

	if(get_config_int(lookup_config(config_tree, "VLESSWSMaxFrameSize"), &int_val)) {
		transport_config.websocket.max_frame_size = (uint16_t)int_val;
	}

	/* Log summary */
	logger(DEBUG_ALWAYS, LOG_INFO, "Advanced transport config: fronting=%s http3=%s websocket=%s",
	       transport_config.domain_fronting.enabled ? "on" : "off",
	       transport_config.http3_masq.enabled ? "on" : "off",
	       transport_config.websocket.enabled ? "on" : "off");

	return true;
}

/* ============================================================================
 * DOMAIN FRONTING
 * ============================================================================
 */

bool domain_fronting_is_enabled(void) {
	return transport_config.domain_fronting.enabled;
}

const char *domain_fronting_get_sni(void) {
	return transport_config.domain_fronting.front_domain;
}

const char *domain_fronting_get_host(void) {
	return transport_config.domain_fronting.real_domain;
}

bool domain_fronting_modify_sni(uint8_t *tls_data, size_t *len, size_t max_len) {
	if(!transport_config.domain_fronting.enabled || !tls_data || !len) {
		return false;
	}

	/* Find SNI extension in TLS ClientHello and replace it */
	/* This is a simplified implementation - full implementation would parse TLS */

	/* Look for SNI extension type (0x00 0x00) */
	const char *front = transport_config.domain_fronting.front_domain;
	size_t front_len = strlen(front);

	/* For now, just log that we would modify SNI */
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Domain fronting: would replace SNI with %s", front);
	fronted_requests++;

	(void)max_len;
	return true;
}

/* ============================================================================
 * HTTP/3 MASQUERADING
 * ============================================================================
 */

bool http3_masq_is_enabled(void) {
	return transport_config.http3_masq.enabled;
}

/* GREASE values used by browsers */
static const uint16_t grease_values[] = {
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
	0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
	0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
};

void http3_masq_add_grease(uint8_t *buffer, size_t *len, size_t max_len) {
	if(!transport_config.http3_masq.simulate_grease || !buffer || !len) {
		return;
	}

	/* Add a random GREASE value */
	if(*len + 2 <= max_len) {
		uint16_t grease = grease_values[rand() % 16];
		buffer[(*len)++] = (grease >> 8) & 0xFF;
		buffer[(*len)++] = grease & 0xFF;
	}
}

size_t http3_masq_add_headers(uint8_t *buffer, size_t data_len, size_t buffer_size) {
	if(!transport_config.http3_masq.enabled || !buffer) {
		return data_len;
	}

	/* HTTP/3 frame format:
	 * - Frame Type (variable length integer)
	 * - Frame Length (variable length integer)
	 * - Frame Payload
	 */

	/* Move data to make room for fake HTTP/3 frame header */
	size_t header_size = 4; /* Simplified: 1 byte type + 3 bytes length */

	if(data_len + header_size > buffer_size) {
		return data_len;
	}

	memmove(buffer + header_size, buffer, data_len);

	/* Add fake DATA frame header (type 0x00) */
	buffer[0] = 0x00; /* DATA frame type */
	buffer[1] = (uint8_t)((data_len >> 16) & 0x3F); /* Length with 2-bit variable int prefix */
	buffer[2] = (uint8_t)((data_len >> 8) & 0xFF);
	buffer[3] = (uint8_t)(data_len & 0xFF);

	http3_packets++;
	return data_len + header_size;
}

size_t http3_masq_remove_headers(uint8_t *buffer, size_t total_len) {
	if(!transport_config.http3_masq.enabled || !buffer || total_len < 4) {
		return total_len;
	}

	/* Check if this looks like an HTTP/3 DATA frame */
	if(buffer[0] != 0x00) {
		return total_len; /* Not a DATA frame, return as-is */
	}

	/* Extract length */
	size_t payload_len = ((buffer[1] & 0x3F) << 16) |
	                     (buffer[2] << 8) |
	                     buffer[3];

	if(payload_len + 4 > total_len) {
		return total_len; /* Invalid header */
	}

	/* Move payload to start */
	memmove(buffer, buffer + 4, payload_len);

	return payload_len;
}

/* ============================================================================
 * WEBSOCKET ENCAPSULATION
 * ============================================================================
 */

bool websocket_is_enabled(void) {
	return transport_config.websocket.enabled;
}

/* Base64 encoding for WebSocket key */
static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void generate_websocket_key(char *key_out, size_t out_size) {
	uint8_t random_bytes[16];
	for(int i = 0; i < 16; i++) {
		random_bytes[i] = (uint8_t)(rand() & 0xFF);
	}

	/* Simple base64 encoding */
	size_t pos = 0;
	for(int i = 0; i < 16 && pos + 4 < out_size; i += 3) {
		uint32_t val = (random_bytes[i] << 16) |
		               (i + 1 < 16 ? random_bytes[i + 1] << 8 : 0) |
		               (i + 2 < 16 ? random_bytes[i + 2] : 0);
		key_out[pos++] = base64_chars[(val >> 18) & 0x3F];
		key_out[pos++] = base64_chars[(val >> 12) & 0x3F];
		key_out[pos++] = (i + 1 < 16) ? base64_chars[(val >> 6) & 0x3F] : '=';
		key_out[pos++] = (i + 2 < 16) ? base64_chars[val & 0x3F] : '=';
	}
	key_out[pos] = '\0';
}

size_t websocket_create_handshake(uint8_t *buffer, size_t buffer_size) {
	if(!transport_config.websocket.enabled || !buffer || buffer_size < 512) {
		return 0;
	}

	char ws_key[32];
	generate_websocket_key(ws_key, sizeof(ws_key));

	int len = snprintf((char *)buffer, buffer_size,
	                   "GET %s HTTP/1.1\r\n"
	                   "Host: %s\r\n"
	                   "Upgrade: websocket\r\n"
	                   "Connection: Upgrade\r\n"
	                   "Sec-WebSocket-Key: %s\r\n"
	                   "Sec-WebSocket-Version: 13\r\n"
	                   "Origin: %s\r\n"
	                   "Sec-WebSocket-Protocol: %s\r\n"
	                   "\r\n",
	                   transport_config.websocket.ws_path,
	                   transport_config.websocket.ws_host,
	                   ws_key,
	                   transport_config.websocket.ws_origin,
	                   transport_config.websocket.ws_protocol);

	return (len > 0 && (size_t)len < buffer_size) ? (size_t)len : 0;
}

bool websocket_verify_handshake(const uint8_t *buffer, size_t len) {
	if(!buffer || len < 20) {
		return false;
	}

	/* Check for HTTP 101 Switching Protocols */
	if(strncmp((const char *)buffer, "HTTP/1.1 101", 12) != 0) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "WebSocket handshake failed: not 101 response");
		return false;
	}

	/* Check for Upgrade: websocket header */
	const char *upgrade = strstr((const char *)buffer, "Upgrade:");
	if(!upgrade || !strstr(upgrade, "websocket")) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "WebSocket handshake failed: no upgrade header");
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "WebSocket handshake successful");
	return true;
}

size_t websocket_wrap_data(const uint8_t *data, size_t data_len,
                            uint8_t *out_buffer, size_t out_buffer_size) {
	if(!transport_config.websocket.enabled || !data || !out_buffer) {
		return 0;
	}

	/* Calculate frame size */
	size_t header_size = 2; /* Base header */
	if(data_len > 125) header_size += 2; /* Extended 16-bit length */
	if(data_len > 65535) header_size += 6; /* Extended 64-bit length */
	header_size += 4; /* Masking key */

	if(header_size + data_len > out_buffer_size) {
		return 0;
	}

	size_t pos = 0;

	/* First byte: FIN + opcode */
	uint8_t opcode = transport_config.websocket.use_binary_frames ?
	                 WS_OPCODE_BINARY : WS_OPCODE_TEXT;
	out_buffer[pos++] = 0x80 | opcode; /* FIN=1, opcode */

	/* Second byte: MASK + length */
	if(data_len <= 125) {
		out_buffer[pos++] = 0x80 | (uint8_t)data_len; /* MASK=1 */
	} else if(data_len <= 65535) {
		out_buffer[pos++] = 0x80 | 126; /* MASK=1, extended 16-bit */
		out_buffer[pos++] = (data_len >> 8) & 0xFF;
		out_buffer[pos++] = data_len & 0xFF;
	} else {
		out_buffer[pos++] = 0x80 | 127; /* MASK=1, extended 64-bit */
		/* 64-bit length (we only use lower 32 bits) */
		out_buffer[pos++] = 0;
		out_buffer[pos++] = 0;
		out_buffer[pos++] = 0;
		out_buffer[pos++] = 0;
		out_buffer[pos++] = (data_len >> 24) & 0xFF;
		out_buffer[pos++] = (data_len >> 16) & 0xFF;
		out_buffer[pos++] = (data_len >> 8) & 0xFF;
		out_buffer[pos++] = data_len & 0xFF;
	}

	/* Generate and add masking key */
	uint8_t mask[4];
	for(int i = 0; i < 4; i++) {
		mask[i] = (uint8_t)(rand() & 0xFF);
		out_buffer[pos++] = mask[i];
	}

	/* Add masked payload */
	for(size_t i = 0; i < data_len; i++) {
		out_buffer[pos++] = data[i] ^ mask[i % 4];
	}

	ws_frames_sent++;
	return pos;
}

size_t websocket_unwrap_data(const uint8_t *frame, size_t frame_len,
                              uint8_t *out_buffer, size_t out_buffer_size) {
	if(!frame || frame_len < 2 || !out_buffer) {
		return 0;
	}

	/* Parse WebSocket frame header */
	size_t pos = 0;

	/* First byte: FIN + opcode */
	uint8_t first_byte = frame[pos++];
	uint8_t fin = (first_byte >> 7) & 0x01;
	uint8_t opcode = first_byte & 0x0F;

	(void)fin; /* Unused for now */

	/* Handle control frames */
	if(opcode == WS_OPCODE_CLOSE || opcode == WS_OPCODE_PING || opcode == WS_OPCODE_PONG) {
		return 0; /* Control frame, no data */
	}

	/* Second byte: MASK + length */
	uint8_t second_byte = frame[pos++];
	uint8_t masked = (second_byte >> 7) & 0x01;
	uint64_t payload_len = second_byte & 0x7F;

	if(payload_len == 126) {
		if(pos + 2 > frame_len) return 0;
		payload_len = ((uint64_t)frame[pos] << 8) | frame[pos + 1];
		pos += 2;
	} else if(payload_len == 127) {
		if(pos + 8 > frame_len) return 0;
		payload_len = 0;
		for(int i = 0; i < 8; i++) {
			payload_len = (payload_len << 8) | frame[pos++];
		}
	}

	/* Extract masking key if present */
	uint8_t mask[4] = {0, 0, 0, 0};
	if(masked) {
		if(pos + 4 > frame_len) return 0;
		for(int i = 0; i < 4; i++) {
			mask[i] = frame[pos++];
		}
	}

	/* Check bounds */
	if(pos + payload_len > frame_len || payload_len > out_buffer_size) {
		return 0;
	}

	/* Copy and unmask payload */
	for(size_t i = 0; i < payload_len; i++) {
		out_buffer[i] = frame[pos + i] ^ mask[i % 4];
	}

	ws_frames_received++;
	return payload_len;
}

size_t websocket_create_ping(uint8_t *buffer, size_t buffer_size) {
	if(!buffer || buffer_size < 6) {
		return 0;
	}

	/* PING frame with empty payload */
	buffer[0] = 0x80 | WS_OPCODE_PING; /* FIN=1, PING opcode */
	buffer[1] = 0x80 | 0; /* MASK=1, length=0 */
	/* Add masking key */
	for(int i = 0; i < 4; i++) {
		buffer[2 + i] = (uint8_t)(rand() & 0xFF);
	}

	return 6;
}

size_t websocket_create_pong(const uint8_t *ping_data, size_t ping_len,
                              uint8_t *buffer, size_t buffer_size) {
	if(!buffer || buffer_size < 6 + ping_len) {
		return 0;
	}

	/* PONG frame echoing ping payload */
	buffer[0] = 0x80 | WS_OPCODE_PONG; /* FIN=1, PONG opcode */

	size_t pos = 1;
	if(ping_len <= 125) {
		buffer[pos++] = 0x80 | (uint8_t)ping_len;
	} else {
		buffer[pos++] = 0x80 | 126;
		buffer[pos++] = (ping_len >> 8) & 0xFF;
		buffer[pos++] = ping_len & 0xFF;
	}

	/* Add masking key and masked payload */
	uint8_t mask[4];
	for(int i = 0; i < 4; i++) {
		mask[i] = (uint8_t)(rand() & 0xFF);
		buffer[pos++] = mask[i];
	}

	for(size_t i = 0; i < ping_len && ping_data; i++) {
		buffer[pos++] = ping_data[i] ^ mask[i % 4];
	}

	return pos;
}

/* ============================================================================
 * STATISTICS
 * ============================================================================
 */

void advanced_transport_log_stats(void) {
	logger(DEBUG_ALWAYS, LOG_INFO, "Advanced Transport Statistics:");
	logger(DEBUG_ALWAYS, LOG_INFO, "  Domain fronted requests: %lu", (unsigned long)fronted_requests);
	logger(DEBUG_ALWAYS, LOG_INFO, "  HTTP/3 masked packets: %lu", (unsigned long)http3_packets);
	logger(DEBUG_ALWAYS, LOG_INFO, "  WebSocket frames sent: %lu", (unsigned long)ws_frames_sent);
	logger(DEBUG_ALWAYS, LOG_INFO, "  WebSocket frames received: %lu", (unsigned long)ws_frames_received);
}
