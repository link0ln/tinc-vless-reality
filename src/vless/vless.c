/*
    vless.c -- VLESS protocol implementation for tinc
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
#include "vless.h"
#include "dpi_evasion.h"
#include "domain_fronting.h"
#include "multihop.h"
#include "logger.h"
#include "xalloc.h"
#include "../hosts_json.h"
#include "../invitation_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* Buffer sizes */
#define VLESS_BUFFER_SIZE 8192

/* Authorization check using hosts.json */
static bool vless_check_authorization(const vless_uuid_t *uuid) {
	if(!uuid) {
		return false;
	}

	/* Convert UUID to string for lookup */
	char uuid_str[37];
	snprintf(uuid_str, sizeof(uuid_str),
	         "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	         uuid->bytes[0], uuid->bytes[1], uuid->bytes[2], uuid->bytes[3],
	         uuid->bytes[4], uuid->bytes[5], uuid->bytes[6], uuid->bytes[7],
	         uuid->bytes[8], uuid->bytes[9], uuid->bytes[10], uuid->bytes[11],
	         uuid->bytes[12], uuid->bytes[13], uuid->bytes[14], uuid->bytes[15]);

	/* Check authorization in hosts.json database */
	if(!hosts_db_is_authorized(NULL, uuid_str)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "VLESS: Unauthorized UUID: %s", uuid_str);
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "VLESS: UUID authorized: %s", uuid_str);
	return true;
}

/* Initialize VLESS subsystem */
void vless_init(void) {
	logger(DEBUG_ALWAYS, LOG_INFO, "Initializing VLESS protocol support");

	/* Initialize DPI evasion subsystem */
	dpi_evasion_init();
	dpi_evasion_load_config();

	/* Initialize advanced transport (Domain Fronting, HTTP/3 Masq, WebSocket) */
	advanced_transport_init();
	advanced_transport_load_config();

	/* Initialize multi-hop routing */
	multihop_init();
	multihop_load_config();
}

void vless_exit(void) {
	/* Log stats before shutdown */
	dpi_evasion_log_stats();
	advanced_transport_log_stats();
	multihop_log_stats();

	/* Cleanup subsystems */
	multihop_exit();
	advanced_transport_exit();
	dpi_evasion_exit();

	logger(DEBUG_ALWAYS, LOG_INFO, "Shutting down VLESS protocol support");
}

/* UUID Operations */

bool vless_uuid_generate(vless_uuid_t *uuid) {
	if(!uuid) {
		return false;
	}

	/* Use system's random generator */
	FILE *urandom = fopen("/dev/urandom", "rb");

	if(!urandom) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to open /dev/urandom: %s", strerror(errno));
		return false;
	}

	size_t read_bytes = fread(uuid->bytes, 1, 16, urandom);
	fclose(urandom);

	if(read_bytes != 16) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to read 16 random bytes");
		return false;
	}

	/* Set UUID version 4 (random) and variant bits */
	uuid->bytes[6] = (uuid->bytes[6] & 0x0F) | 0x40; // Version 4
	uuid->bytes[8] = (uuid->bytes[8] & 0x3F) | 0x80; // Variant 10

	return true;
}

bool vless_uuid_from_string(vless_uuid_t *uuid, const char *str) {
	if(!uuid || !str) {
		return false;
	}

	/* Parse UUID string format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx */
	unsigned int parts[16];
	int matches = sscanf(str,
	                     "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	                     &parts[0], &parts[1], &parts[2], &parts[3],
	                     &parts[4], &parts[5], &parts[6], &parts[7],
	                     &parts[8], &parts[9], &parts[10], &parts[11],
	                     &parts[12], &parts[13], &parts[14], &parts[15]);

	if(matches != 16) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid UUID string format: %s", str);
		return false;
	}

	for(int i = 0; i < 16; i++) {
		uuid->bytes[i] = (uint8_t)parts[i];
	}

	return true;
}

char *vless_uuid_to_string(const vless_uuid_t *uuid) {
	if(!uuid) {
		return NULL;
	}

	char *str = xmalloc(37); // 36 chars + null terminator

	snprintf(str, 37,
	         "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	         uuid->bytes[0], uuid->bytes[1], uuid->bytes[2], uuid->bytes[3],
	         uuid->bytes[4], uuid->bytes[5], uuid->bytes[6], uuid->bytes[7],
	         uuid->bytes[8], uuid->bytes[9], uuid->bytes[10], uuid->bytes[11],
	         uuid->bytes[12], uuid->bytes[13], uuid->bytes[14], uuid->bytes[15]);

	return str;
}

bool vless_uuid_equal(const vless_uuid_t *a, const vless_uuid_t *b) {
	if(!a || !b) {
		return false;
	}

	return memcmp(a->bytes, b->bytes, 16) == 0;
}

/* VLESS Context Management */

vless_ctx_t *vless_ctx_new(bool is_client) {
	vless_ctx_t *ctx = xzalloc(sizeof(vless_ctx_t));

	ctx->state = VLESS_STATE_INIT;
	ctx->is_client = is_client;
	ctx->flow = VLESS_FLOW_NONE;
	ctx->reality_enabled = false;
	ctx->reality_ctx = NULL;

	/* Allocate buffers */
	ctx->recv_buf = xmalloc(VLESS_BUFFER_SIZE);
	ctx->recv_buf_len = VLESS_BUFFER_SIZE;
	ctx->recv_buf_pos = 0;

	ctx->send_buf = xmalloc(VLESS_BUFFER_SIZE);
	ctx->send_buf_len = VLESS_BUFFER_SIZE;
	ctx->send_buf_pos = 0;

	ctx->bytes_sent = 0;
	ctx->bytes_received = 0;

	return ctx;
}

void vless_ctx_free(vless_ctx_t *ctx) {
	if(!ctx) {
		return;
	}

	if(ctx->recv_buf) {
		free(ctx->recv_buf);
	}

	if(ctx->send_buf) {
		free(ctx->send_buf);
	}

	if(ctx->reality_ctx) {
		/* Reality context cleanup will be done in reality.c */
		free(ctx->reality_ctx);
	}

	free(ctx);
}

void vless_ctx_reset(vless_ctx_t *ctx) {
	if(!ctx) {
		return;
	}

	ctx->state = VLESS_STATE_INIT;
	ctx->recv_buf_pos = 0;
	ctx->send_buf_pos = 0;
	memset(&ctx->request, 0, sizeof(vless_request_t));
	memset(&ctx->response, 0, sizeof(vless_response_t));
}

/* Header Encoding/Decoding */

ssize_t vless_encode_request(vless_request_t *req, uint8_t *buf, size_t buf_len) {
	if(!req || !buf || buf_len < 1) {
		return -1;
	}

	size_t pos = 0;

	/* Version (1 byte) */
	if(pos + 1 > buf_len) {
		return -1;
	}

	buf[pos++] = req->version;

	/* UUID (16 bytes) */
	if(pos + 16 > buf_len) {
		return -1;
	}

	memcpy(buf + pos, req->uuid.bytes, 16);
	pos += 16;

	/* AddOn Length (1 byte) - typically 0 */
	if(pos + 1 > buf_len) {
		return -1;
	}

	buf[pos++] = req->addon_len;

	/* AddOn data - skip if addon_len is 0 */
	if(req->addon_len > 0) {
		pos += req->addon_len; // Skip addon data for now
	}

	/* Command (1 byte) */
	if(pos + 1 > buf_len) {
		return -1;
	}

	buf[pos++] = req->command;

	/* Port (2 bytes, big-endian) */
	if(pos + 2 > buf_len) {
		return -1;
	}

	buf[pos++] = (req->port >> 8) & 0xFF;
	buf[pos++] = req->port & 0xFF;

	/* Address Type (1 byte) */
	if(pos + 1 > buf_len) {
		return -1;
	}

	buf[pos++] = req->addr_type;

	/* Address */
	switch(req->addr_type) {
	case VLESS_ADDR_IPV4:
		if(pos + 4 > buf_len) {
			return -1;
		}

		memcpy(buf + pos, req->addr.ipv4, 4);
		pos += 4;
		break;

	case VLESS_ADDR_DOMAIN:
		if(pos + 1 + req->addr_len > buf_len) {
			return -1;
		}

		buf[pos++] = req->addr_len;
		memcpy(buf + pos, req->addr.domain, req->addr_len);
		pos += req->addr_len;
		break;

	case VLESS_ADDR_IPV6:
		if(pos + 16 > buf_len) {
			return -1;
		}

		memcpy(buf + pos, req->addr.ipv6, 16);
		pos += 16;
		break;

	default:
		logger(DEBUG_ALWAYS, LOG_ERR, "Unknown VLESS address type: %d", req->addr_type);
		return -1;
	}

	return pos;
}

ssize_t vless_decode_request(const uint8_t *buf, size_t buf_len, vless_request_t *req) {
	if(!buf || !req || buf_len < 1) {
		return -1;
	}

	size_t pos = 0;

	/* Version */
	if(pos + 1 > buf_len) {
		return -1;
	}

	req->version = buf[pos++];

	if(req->version != VLESS_VERSION) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unsupported VLESS version: %d", req->version);
		return -1;
	}

	/* UUID */
	if(pos + 16 > buf_len) {
		return -1;
	}

	memcpy(req->uuid.bytes, buf + pos, 16);
	pos += 16;

	/* AddOn Length */
	if(pos + 1 > buf_len) {
		return -1;
	}

	req->addon_len = buf[pos++];

	/* Skip AddOn data */
	if(pos + req->addon_len > buf_len) {
		return -1;
	}

	pos += req->addon_len;

	/* Command */
	if(pos + 1 > buf_len) {
		return -1;
	}

	req->command = buf[pos++];

	/* Port */
	if(pos + 2 > buf_len) {
		return -1;
	}

	req->port = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
	pos += 2;

	/* Address Type */
	if(pos + 1 > buf_len) {
		return -1;
	}

	req->addr_type = buf[pos++];

	/* Address */
	switch(req->addr_type) {
	case VLESS_ADDR_IPV4:
		if(pos + 4 > buf_len) {
			return -1;
		}

		memcpy(req->addr.ipv4, buf + pos, 4);
		pos += 4;
		break;

	case VLESS_ADDR_DOMAIN:
		if(pos + 1 > buf_len) {
			return -1;
		}

		req->addr_len = buf[pos++];

		if(pos + req->addr_len > buf_len) {
			return -1;
		}

		memcpy(req->addr.domain, buf + pos, req->addr_len);
		req->addr.domain[req->addr_len] = '\0'; // Null terminate
		pos += req->addr_len;
		break;

	case VLESS_ADDR_IPV6:
		if(pos + 16 > buf_len) {
			return -1;
		}

		memcpy(req->addr.ipv6, buf + pos, 16);
		pos += 16;
		break;

	default:
		logger(DEBUG_ALWAYS, LOG_ERR, "Unknown VLESS address type: %d", req->addr_type);
		return -1;
	}

	return pos;
}

ssize_t vless_encode_response(vless_response_t *resp, uint8_t *buf, size_t buf_len) {
	if(!resp || !buf || buf_len < 2) {
		return -1;
	}

	size_t pos = 0;

	/* Version */
	buf[pos++] = resp->version;

	/* AddOn Length */
	buf[pos++] = resp->addon_len;

	/* AddOn data - skip if addon_len is 0 */
	if(resp->addon_len > 0) {
		pos += resp->addon_len;
	}

	return pos;
}

ssize_t vless_decode_response(const uint8_t *buf, size_t buf_len, vless_response_t *resp) {
	if(!buf || !resp || buf_len < 2) {
		return -1;
	}

	size_t pos = 0;

	/* Version */
	resp->version = buf[pos++];

	if(resp->version != VLESS_VERSION) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unsupported VLESS response version: %d", resp->version);
		return -1;
	}

	/* AddOn Length */
	resp->addon_len = buf[pos++];

	/* Skip AddOn data */
	if(pos + resp->addon_len > buf_len) {
		return -1;
	}

	pos += resp->addon_len;

	return pos;
}

/* Protocol Operations */

bool vless_handshake_client(vless_ctx_t *ctx, const char *dest_addr,
                             uint16_t dest_port, uint8_t command) {
	if(!ctx || !dest_addr) {
		return false;
	}

	/* Initialize request */
	ctx->request.version = VLESS_VERSION;
	memcpy(&ctx->request.uuid, &ctx->remote_uuid, sizeof(vless_uuid_t));
	ctx->request.addon_len = 0;
	ctx->request.command = command;
	ctx->request.port = dest_port;

	/* Parse destination address */
	struct in_addr ipv4_addr;
	struct in6_addr ipv6_addr;

	if(inet_pton(AF_INET, dest_addr, &ipv4_addr) == 1) {
		/* IPv4 address */
		ctx->request.addr_type = VLESS_ADDR_IPV4;
		memcpy(ctx->request.addr.ipv4, &ipv4_addr, 4);
	} else if(inet_pton(AF_INET6, dest_addr, &ipv6_addr) == 1) {
		/* IPv6 address */
		ctx->request.addr_type = VLESS_ADDR_IPV6;
		memcpy(ctx->request.addr.ipv6, &ipv6_addr, 16);
	} else {
		/* Domain name */
		ctx->request.addr_type = VLESS_ADDR_DOMAIN;
		ctx->request.addr_len = strlen(dest_addr);

		if(ctx->request.addr_len > 255) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Domain name too long: %s", dest_addr);
			return false;
		}

		strncpy(ctx->request.addr.domain, dest_addr, sizeof(ctx->request.addr.domain) - 1);
		ctx->request.addr.domain[ctx->request.addr_len] = '\0';
	}

	ctx->state = VLESS_STATE_HANDSHAKE;
	return true;
}

bool vless_handshake_server(vless_ctx_t *ctx) {
	if(!ctx) {
		return false;
	}

	/* Initialize response */
	ctx->response.version = VLESS_VERSION;
	ctx->response.addon_len = 0;

	ctx->state = VLESS_STATE_HANDSHAKE;
	return true;
}

/* Utility Functions */

const char *vless_state_to_string(vless_state_t state) {
	switch(state) {
	case VLESS_STATE_INIT:
		return "INIT";

	case VLESS_STATE_HANDSHAKE:
		return "HANDSHAKE";

	case VLESS_STATE_REALITY_TLS:
		return "REALITY_TLS";

	case VLESS_STATE_AUTHENTICATED:
		return "AUTHENTICATED";

	case VLESS_STATE_DATA_TRANSFER:
		return "DATA_TRANSFER";

	case VLESS_STATE_ERROR:
		return "ERROR";

	case VLESS_STATE_CLOSED:
		return "CLOSED";

	default:
		return "UNKNOWN";
	}
}

const char *vless_command_to_string(uint8_t command) {
	switch(command) {
	case VLESS_CMD_TCP:
		return "TCP";

	case VLESS_CMD_UDP:
		return "UDP";

	case VLESS_CMD_MUX:
		return "MUX";

	default:
		return "UNKNOWN";
	}
}

const char *vless_flow_to_string(vless_flow_t flow) {
	switch(flow) {
	case VLESS_FLOW_NONE:
		return "none";

	case VLESS_FLOW_XTLS_RPRX_VISION:
		return "xtls-rprx-vision";

	case VLESS_FLOW_XTLS_RPRX_VISION_UDP443:
		return "xtls-rprx-vision-udp443";

	default:
		return "unknown";
	}
}

/* Network I/O Functions */

bool vless_send_request(vless_ctx_t *ctx, int fd) {
	if(!ctx || fd < 0) {
		return false;
	}

	/* Encode request into buffer */
	ssize_t encoded_len = vless_encode_request(&ctx->request, ctx->send_buf, ctx->send_buf_len);

	if(encoded_len < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to encode VLESS request");
		ctx->state = VLESS_STATE_ERROR;
		return false;
	}

	/* Send request */
	ssize_t sent = send(fd, ctx->send_buf, encoded_len, 0);

	if(sent < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to send VLESS request: %s", strerror(errno));
		ctx->state = VLESS_STATE_ERROR;
		return false;
	}

	if(sent != encoded_len) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Partial send of VLESS request: %zd/%zd bytes", sent, encoded_len);
		ctx->state = VLESS_STATE_ERROR;
		return false;
	}

	ctx->bytes_sent += sent;
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Sent VLESS request: %zd bytes", sent);

	return true;
}

/* Handle HTTP invitation request and return true if handled */
static int vless_handle_invitation_request(int fd, const char *data, size_t len) {
	if(!is_invitation_request(data, len)) {
		return 0; /* Not an invitation request */
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Received HTTP invitation request");

	size_t resp_len = 0;
	char *response = handle_invitation_request(data, len, &resp_len);

	if(response && resp_len > 0) {
		send(fd, response, resp_len, 0);
		free(response);
	}

	return 1; /* Invitation handled */
}

bool vless_recv_request(vless_ctx_t *ctx, int fd) {
	if(!ctx || fd < 0) {
		return false;
	}

	/* Read data from socket */
	ssize_t received = recv(fd, ctx->recv_buf + ctx->recv_buf_pos,
	                        ctx->recv_buf_len - ctx->recv_buf_pos, 0);

	if(received < 0) {
		if(errno == EAGAIN || errno == EWOULDBLOCK) {
			return false; // No data available yet
		}

		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to receive VLESS request: %s", strerror(errno));
		ctx->state = VLESS_STATE_ERROR;
		return false;
	}

	if(received == 0) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Connection closed by peer");
		ctx->state = VLESS_STATE_CLOSED;
		return false;
	}

	ctx->recv_buf_pos += received;
	ctx->bytes_received += received;

	/* Check if this is an HTTP invitation request (GET /invite/...) */
	if(vless_handle_invitation_request(fd, (const char *)ctx->recv_buf, ctx->recv_buf_pos)) {
		/* Invitation was handled, close connection */
		ctx->state = VLESS_STATE_CLOSED;
		return false;
	}

	/* Try to decode request */
	ssize_t decoded_len = vless_decode_request(ctx->recv_buf, ctx->recv_buf_pos, &ctx->request);

	if(decoded_len < 0) {
		if(ctx->recv_buf_pos >= ctx->recv_buf_len) {
			logger(DEBUG_ALWAYS, LOG_ERR, "VLESS request too large");
			ctx->state = VLESS_STATE_ERROR;
			return false;
		}

		return false; // Need more data
	}

	/* Request successfully decoded */
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Received VLESS request: %zd bytes", decoded_len);

	/* Verify UUID authorization via hosts.json */
	if(!vless_check_authorization(&ctx->request.uuid)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "VLESS: Connection rejected - unauthorized UUID");
		ctx->state = VLESS_STATE_ERROR;
		return false;
	}

	/* Remove processed data from buffer */
	if(decoded_len < (ssize_t)ctx->recv_buf_pos) {
		memmove(ctx->recv_buf, ctx->recv_buf + decoded_len, ctx->recv_buf_pos - decoded_len);
		ctx->recv_buf_pos -= decoded_len;
	} else {
		ctx->recv_buf_pos = 0;
	}

	return true;
}

bool vless_send_response(vless_ctx_t *ctx, int fd) {
	if(!ctx || fd < 0) {
		return false;
	}

	/* Encode response into buffer */
	ssize_t encoded_len = vless_encode_response(&ctx->response, ctx->send_buf, ctx->send_buf_len);

	if(encoded_len < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to encode VLESS response");
		ctx->state = VLESS_STATE_ERROR;
		return false;
	}

	/* Send response */
	ssize_t sent = send(fd, ctx->send_buf, encoded_len, 0);

	if(sent < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to send VLESS response: %s", strerror(errno));
		ctx->state = VLESS_STATE_ERROR;
		return false;
	}

	if(sent != encoded_len) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Partial send of VLESS response: %zd/%zd bytes", sent, encoded_len);
		ctx->state = VLESS_STATE_ERROR;
		return false;
	}

	ctx->bytes_sent += sent;
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Sent VLESS response: %zd bytes", sent);

	return true;
}

bool vless_recv_response(vless_ctx_t *ctx, int fd) {
	if(!ctx || fd < 0) {
		return false;
	}

	/* Read data from socket */
	ssize_t received = recv(fd, ctx->recv_buf + ctx->recv_buf_pos,
	                        ctx->recv_buf_len - ctx->recv_buf_pos, 0);

	if(received < 0) {
		if(errno == EAGAIN || errno == EWOULDBLOCK) {
			return false; // No data available yet
		}

		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to receive VLESS response: %s", strerror(errno));
		ctx->state = VLESS_STATE_ERROR;
		return false;
	}

	if(received == 0) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Connection closed by peer");
		ctx->state = VLESS_STATE_CLOSED;
		return false;
	}

	ctx->recv_buf_pos += received;
	ctx->bytes_received += received;

	/* Try to decode response */
	ssize_t decoded_len = vless_decode_response(ctx->recv_buf, ctx->recv_buf_pos, &ctx->response);

	if(decoded_len < 0) {
		if(ctx->recv_buf_pos >= ctx->recv_buf_len) {
			logger(DEBUG_ALWAYS, LOG_ERR, "VLESS response too large");
			ctx->state = VLESS_STATE_ERROR;
			return false;
		}

		return false; // Need more data
	}

	/* Response successfully decoded */
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Received VLESS response: %zd bytes", decoded_len);

	/* Remove processed data from buffer */
	if(decoded_len < (ssize_t)ctx->recv_buf_pos) {
		memmove(ctx->recv_buf, ctx->recv_buf + decoded_len, ctx->recv_buf_pos - decoded_len);
		ctx->recv_buf_pos -= decoded_len;
	} else {
		ctx->recv_buf_pos = 0;
	}

	return true;
}

/* Data transfer functions */

/* Buffer for padding operations */
#define DPI_BUFFER_SIZE 16384

ssize_t vless_write(vless_ctx_t *ctx, int fd, const void *data, size_t len) {
	if(!ctx || fd < 0 || !data || len == 0) {
		return -1;
	}

	if(ctx->state != VLESS_STATE_DATA_TRANSFER && ctx->state != VLESS_STATE_AUTHENTICATED) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot write data in state: %s", vless_state_to_string(ctx->state));
		return -1;
	}

	/* Apply DPI evasion techniques */
	dpi_evasion_config_t *dpi_cfg = dpi_evasion_get_config();
	ssize_t sent;

	/* Apply timing obfuscation before sending */
	if(dpi_cfg->timing_enabled) {
		dpi_timing_delay();
	}

	/* Apply traffic shaping */
	if(dpi_cfg->traffic_shaping_enabled) {
		dpi_shaping_pre_send(len);
	}

	/* Apply padding if enabled */
	if(dpi_cfg->padding_enabled) {
		uint8_t padded_buf[DPI_BUFFER_SIZE];
		if(len + dpi_padding_get_overhead() + 256 <= DPI_BUFFER_SIZE) {
			memcpy(padded_buf, data, len);
			size_t padded_len = dpi_padding_add(padded_buf, len, DPI_BUFFER_SIZE);
			sent = send(fd, padded_buf, padded_len, 0);
		} else {
			/* Packet too large for padding, send as-is */
			sent = send(fd, data, len, 0);
		}
	} else {
		sent = send(fd, data, len, 0);
	}

	if(sent > 0) {
		ctx->bytes_sent += sent;
	}

	return sent;
}

ssize_t vless_read(vless_ctx_t *ctx, int fd, void *data, size_t len) {
	if(!ctx || fd < 0 || !data || len == 0) {
		return -1;
	}

	if(ctx->state != VLESS_STATE_DATA_TRANSFER && ctx->state != VLESS_STATE_AUTHENTICATED) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot read data in state: %s", vless_state_to_string(ctx->state));
		return -1;
	}

	/* Read data from socket */
	ssize_t received = recv(fd, data, len, 0);

	if(received > 0) {
		ctx->bytes_received += received;

		/* Apply DPI evasion: remove padding if present */
		dpi_evasion_config_t *dpi_cfg = dpi_evasion_get_config();
		if(dpi_cfg->padding_enabled) {
			size_t actual_len = dpi_padding_remove((uint8_t *)data, received);
			if(actual_len < (size_t)received) {
				/* Padding was removed, return actual data length */
				return (ssize_t)actual_len;
			}
		}

		/* Apply traffic shaping post-receive hook */
		if(dpi_cfg->traffic_shaping_enabled) {
			dpi_shaping_post_receive(received);
		}
	}

	return received;
}
