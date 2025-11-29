/*
    reality.c -- Reality Protocol implementation for VLESS/tinc
    Copyright (C) 2025 tinc-vless contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"
#include "reality.h"
#include "logger.h"
#include "xalloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>

#include "../invitation_server.h"

/* Initialize Reality subsystem */
void reality_init(void) {
	logger(DEBUG_ALWAYS, LOG_INFO, "Initializing Reality protocol support");

	/* Initialize OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	/* Ensure we have good entropy */
	if(RAND_status() != 1) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "OpenSSL random number generator not properly seeded");
	}
}

void reality_exit(void) {
	logger(DEBUG_ALWAYS, LOG_INFO, "Shutting down Reality protocol support");
	EVP_cleanup();
	ERR_free_strings();
}

/* Configuration Management */

reality_config_t *reality_config_new(bool is_server) {
	reality_config_t *config = xzalloc(sizeof(reality_config_t));

	config->is_server = is_server;
	config->num_short_ids = 0;
	config->num_server_names = 0;
	config->dest_port = 443;
	config->fingerprint = REALITY_FP_CHROME;
	config->max_time_diff = 60; // 60 seconds

	return config;
}

void reality_config_free(reality_config_t *config) {
	if(config) {
		free(config);
	}
}

/* Key Generation */

bool reality_generate_keypair(uint8_t *private_key, uint8_t *public_key) {
	if(!private_key || !public_key) {
		return false;
	}

	/* Generate X25519 keypair */
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

	if(!pctx) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create EVP_PKEY_CTX");
		return false;
	}

	if(EVP_PKEY_keygen_init(pctx) <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize keygen");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}

	if(EVP_PKEY_keygen(pctx, &pkey) <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to generate keypair");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}

	EVP_PKEY_CTX_free(pctx);

	/* Extract public key */
	size_t pub_len = REALITY_PUBLIC_KEY_SIZE;

	if(EVP_PKEY_get_raw_public_key(pkey, public_key, &pub_len) <= 0 ||
	        pub_len != REALITY_PUBLIC_KEY_SIZE) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to extract public key");
		EVP_PKEY_free(pkey);
		return false;
	}

	/* Extract private key */
	size_t priv_len = REALITY_PRIVATE_KEY_SIZE;

	if(EVP_PKEY_get_raw_private_key(pkey, private_key, &priv_len) <= 0 ||
	        priv_len != REALITY_PRIVATE_KEY_SIZE) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to extract private key");
		EVP_PKEY_free(pkey);
		return false;
	}

	EVP_PKEY_free(pkey);

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Generated X25519 keypair for Reality");
	return true;
}

bool reality_generate_short_id(uint8_t *short_id) {
	if(!short_id) {
		return false;
	}

	if(RAND_bytes(short_id, REALITY_SHORT_ID_SIZE) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to generate ShortID");
		return false;
	}

	return true;
}

bool reality_derive_auth_key(const uint8_t *shared_secret, uint8_t *auth_key) {
	if(!shared_secret || !auth_key) {
		return false;
	}

	/* Derive AuthKey using HKDF-SHA256 */
	const char *salt = "reality-auth-key";
	const char *info = "auth";

	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

	if(!pctx) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create HKDF context");
		return false;
	}

	if(EVP_PKEY_derive_init(pctx) <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize HKDF");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}

	if(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to set HKDF hash function");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}

	if(EVP_PKEY_CTX_set1_hkdf_salt(pctx, (const unsigned char *)salt, strlen(salt)) <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to set HKDF salt");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}

	if(EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, 32) <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to set HKDF key");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}

	if(EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)info, strlen(info)) <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to set HKDF info");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}

	size_t auth_key_len = REALITY_AUTH_KEY_SIZE;

	if(EVP_PKEY_derive(pctx, auth_key, &auth_key_len) <= 0 ||
	        auth_key_len != REALITY_AUTH_KEY_SIZE) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to derive AuthKey");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}

	EVP_PKEY_CTX_free(pctx);

	return true;
}

/* Utility Functions */

void reality_bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
	for(size_t i = 0; i < len; i++) {
		sprintf(hex + (i * 2), "%02x", bytes[i]);
	}

	hex[len * 2] = '\0';
}

bool reality_hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
	if(strlen(hex) != len * 2) {
		return false;
	}

	for(size_t i = 0; i < len; i++) {
		unsigned int byte;

		if(sscanf(hex + (i * 2), "%02x", &byte) != 1) {
			return false;
		}

		bytes[i] = (uint8_t)byte;
	}

	return true;
}

char *reality_save_private_key(const uint8_t *private_key) {
	if(!private_key) {
		return NULL;
	}

	char *hex = xmalloc(REALITY_PRIVATE_KEY_SIZE * 2 + 1);
	reality_bytes_to_hex(private_key, REALITY_PRIVATE_KEY_SIZE, hex);
	return hex;
}

char *reality_save_public_key(const uint8_t *public_key) {
	if(!public_key) {
		return NULL;
	}

	char *hex = xmalloc(REALITY_PUBLIC_KEY_SIZE * 2 + 1);
	reality_bytes_to_hex(public_key, REALITY_PUBLIC_KEY_SIZE, hex);
	return hex;
}

char *reality_save_short_id(const uint8_t *short_id) {
	if(!short_id) {
		return NULL;
	}

	char *hex = xmalloc(REALITY_SHORT_ID_SIZE * 2 + 1);
	reality_bytes_to_hex(short_id, REALITY_SHORT_ID_SIZE, hex);
	return hex;
}

bool reality_load_private_key(const char *hex_str, uint8_t *private_key) {
	return reality_hex_to_bytes(hex_str, private_key, REALITY_PRIVATE_KEY_SIZE);
}

bool reality_load_public_key(const char *hex_str, uint8_t *public_key) {
	return reality_hex_to_bytes(hex_str, public_key, REALITY_PUBLIC_KEY_SIZE);
}

bool reality_load_short_id(const char *hex_str, uint8_t *short_id) {
	return reality_hex_to_bytes(hex_str, short_id, REALITY_SHORT_ID_SIZE);
}

/* Reality Context Management */

reality_ctx_t *reality_ctx_new(reality_config_t *config) {
	if(!config) {
		return NULL;
	}

	reality_ctx_t *ctx = xzalloc(sizeof(reality_ctx_t));

	ctx->config = config;
	ctx->handshake_complete = false;
	ctx->authenticated = false;
	ctx->fallback_active = false;
	ctx->fallback_fd = -1;
	ctx->bytes_encrypted = 0;
	ctx->bytes_decrypted = 0;

	/* Create SSL context */
	const SSL_METHOD *method = config->is_server ? TLS_server_method() : TLS_client_method();
	ctx->ssl_ctx = SSL_CTX_new(method);

	if(!ctx->ssl_ctx) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create SSL context");
		free(ctx);
		return NULL;
	}

	/* Set minimum TLS version to 1.3 for Reality */
	SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);

	/* Set security level */
	SSL_CTX_set_security_level(ctx->ssl_ctx, 0); // Allow self-signed certs

	return ctx;
}

void reality_ctx_free(reality_ctx_t *ctx) {
	if(!ctx) {
		return;
	}

	if(ctx->ssl) {
		SSL_free(ctx->ssl);
	}

	if(ctx->ssl_ctx) {
		SSL_CTX_free(ctx->ssl_ctx);
	}

	if(ctx->local_keypair) {
		EVP_PKEY_free(ctx->local_keypair);
	}

	if(ctx->fallback_fd >= 0) {
		close(ctx->fallback_fd);
	}

	free(ctx);
}

void reality_ctx_reset(reality_ctx_t *ctx) {
	if(!ctx) {
		return;
	}

	ctx->handshake_complete = false;
	ctx->authenticated = false;
	ctx->fallback_active = false;

	if(ctx->ssl) {
		SSL_free(ctx->ssl);
		ctx->ssl = NULL;
	}
}

/* TLS Fingerprint Configuration */

const char *reality_fingerprint_to_string(reality_fingerprint_t fp) {
	switch(fp) {
	case REALITY_FP_CHROME:
		return "chrome";

	case REALITY_FP_FIREFOX:
		return "firefox";

	case REALITY_FP_SAFARI:
		return "safari";

	case REALITY_FP_IOS:
		return "ios";

	case REALITY_FP_ANDROID:
		return "android";

	case REALITY_FP_EDGE:
		return "edge";

	case REALITY_FP_RANDOM:
		return "random";

	default:
		return "unknown";
	}
}

bool reality_setup_fingerprint(reality_ctx_t *ctx, reality_fingerprint_t fp) {
	if(!ctx || !ctx->ssl_ctx) {
		return false;
	}

	/* Configure TLS cipher suites and extensions to mimic specific browsers */
	/* This is a simplified version - full implementation would need uTLS-like capabilities */

	switch(fp) {
	case REALITY_FP_CHROME:
		/* Chrome TLS 1.3 ciphers */
		SSL_CTX_set_ciphersuites(ctx->ssl_ctx,
		                         "TLS_AES_128_GCM_SHA256:"
		                         "TLS_AES_256_GCM_SHA384:"
		                         "TLS_CHACHA20_POLY1305_SHA256");
		break;

	case REALITY_FP_FIREFOX:
		/* Firefox TLS 1.3 ciphers */
		SSL_CTX_set_ciphersuites(ctx->ssl_ctx,
		                         "TLS_AES_128_GCM_SHA256:"
		                         "TLS_CHACHA20_POLY1305_SHA256:"
		                         "TLS_AES_256_GCM_SHA384");
		break;

	case REALITY_FP_SAFARI:
	case REALITY_FP_IOS:
		/* Safari/iOS TLS 1.3 ciphers */
		SSL_CTX_set_ciphersuites(ctx->ssl_ctx,
		                         "TLS_AES_128_GCM_SHA256:"
		                         "TLS_AES_256_GCM_SHA384");
		break;

	default:
		/* Default to Chrome fingerprint */
		SSL_CTX_set_ciphersuites(ctx->ssl_ctx,
		                         "TLS_AES_128_GCM_SHA256:"
		                         "TLS_AES_256_GCM_SHA384:"
		                         "TLS_CHACHA20_POLY1305_SHA256");
		break;
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Configured Reality TLS fingerprint: %s",
	       reality_fingerprint_to_string(fp));

	return true;
}

/* Authentication Verification */

bool reality_verify_sni(reality_config_t *config, const char *sni) {
	if(!config || !sni) {
		return false;
	}

	/* If no server names configured, accept any */
	if(config->num_server_names == 0) {
		return true;
	}

	/* Check if SNI matches any configured server name */
	for(int i = 0; i < config->num_server_names; i++) {
		if(strcmp(config->server_names[i], sni) == 0) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "SNI '%s' verified successfully", sni);
			return true;
		}
	}

	logger(DEBUG_PROTOCOL, LOG_WARNING, "SNI '%s' not in whitelist", sni);
	return false;
}

bool reality_verify_short_id(reality_config_t *config, const uint8_t *short_id) {
	if(!config || !short_id) {
		return false;
	}

	/* If no ShortIDs configured, accept any */
	if(config->num_short_ids == 0) {
		return true;
	}

	/* Check if ShortID matches any configured ID */
	for(int i = 0; i < config->num_short_ids; i++) {
		if(memcmp(config->short_ids[i], short_id, REALITY_SHORT_ID_SIZE) == 0) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "ShortID verified successfully");
			return true;
		}
	}

	logger(DEBUG_PROTOCOL, LOG_WARNING, "ShortID not in whitelist");
	return false;
}

bool reality_verify_client(reality_ctx_t *ctx) {
	if(!ctx || !ctx->config || !ctx->config->is_server) {
		return false;
	}

	/* Verify SNI */
	if(!reality_verify_sni(ctx->config, ctx->client_sni)) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Client failed SNI verification");
		return false;
	}

	/* Verify ShortID */
	if(!reality_verify_short_id(ctx->config, ctx->client_short_id)) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Client failed ShortID verification");
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Client authentication successful");
	ctx->authenticated = true;
	return true;
}

/* Data Transfer */

ssize_t reality_write(reality_ctx_t *ctx, const void *data, size_t len) {
	if(!ctx || !ctx->ssl || !data || len == 0) {
		return -1;
	}

	int written = SSL_write(ctx->ssl, data, len);

	if(written > 0) {
		ctx->bytes_encrypted += written;
		return written;
	}

	int err = SSL_get_error(ctx->ssl, written);

	if(err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
		errno = EAGAIN;
		return -1;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "SSL_write error: %d", err);
	return -1;
}

ssize_t reality_read(reality_ctx_t *ctx, void *data, size_t len) {
	if(!ctx || !ctx->ssl || !data || len == 0) {
		return -1;
	}

	int read_bytes = SSL_read(ctx->ssl, data, len);

	if(read_bytes > 0) {
		ctx->bytes_decrypted += read_bytes;
		return read_bytes;
	}

	int err = SSL_get_error(ctx->ssl, read_bytes);

	if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		errno = EAGAIN;
		return -1;
	}

	if(err == SSL_ERROR_ZERO_RETURN) {
		/* Connection closed */
		return 0;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "SSL_read error: %d", err);
	return -1;
}

/* Fallback Mechanism */

bool reality_start_fallback(reality_ctx_t *ctx, int client_fd) {
	if(!ctx || !ctx->config || client_fd < 0) {
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Starting fallback to %s:%d",
	       ctx->config->dest_domain, ctx->config->dest_port);

	/* Resolve destination address */
	struct addrinfo hints, *result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", ctx->config->dest_port);

	int ret = getaddrinfo(ctx->config->dest_domain, port_str, &hints, &result);

	if(ret != 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to resolve %s: %s",
		       ctx->config->dest_domain, gai_strerror(ret));
		return false;
	}

	/* Create socket and connect to destination */
	int dest_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	if(dest_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create socket: %s", strerror(errno));
		freeaddrinfo(result);
		return false;
	}

	if(connect(dest_fd, result->ai_addr, result->ai_addrlen) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to connect to %s:%d: %s",
		       ctx->config->dest_domain, ctx->config->dest_port, strerror(errno));
		close(dest_fd);
		freeaddrinfo(result);
		return false;
	}

	freeaddrinfo(result);

	ctx->fallback_fd = dest_fd;
	ctx->fallback_active = true;

	logger(DEBUG_PROTOCOL, LOG_INFO, "Fallback connection established");

	return true;
}

bool reality_proxy_to_dest(reality_ctx_t *ctx, int client_fd) {
	if(!ctx || client_fd < 0 || ctx->fallback_fd < 0) {
		return false;
	}

	/* Simple bidirectional proxy between client and destination */
	/* This is a blocking implementation - production version should use select/poll */

	uint8_t buffer[8192];
	fd_set readfds;
	struct timeval timeout;

	while(ctx->fallback_active) {
		FD_ZERO(&readfds);
		FD_SET(client_fd, &readfds);
		FD_SET(ctx->fallback_fd, &readfds);

		timeout.tv_sec = 30;
		timeout.tv_usec = 0;

		int max_fd = (client_fd > ctx->fallback_fd) ? client_fd : ctx->fallback_fd;
		int activity = select(max_fd + 1, &readfds, NULL, NULL, &timeout);

		if(activity < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "select() failed: %s", strerror(errno));
			break;
		}

		if(activity == 0) {
			/* Timeout */
			continue;
		}

		/* Data from client to destination */
		if(FD_ISSET(client_fd, &readfds)) {
			ssize_t n = recv(client_fd, buffer, sizeof(buffer), 0);

			if(n <= 0) {
				logger(DEBUG_PROTOCOL, LOG_INFO, "Client connection closed");
				break;
			}

			ssize_t sent = send(ctx->fallback_fd, buffer, n, 0);

			if(sent != n) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Failed to forward data to destination");
				break;
			}
		}

		/* Data from destination to client */
		if(FD_ISSET(ctx->fallback_fd, &readfds)) {
			ssize_t n = recv(ctx->fallback_fd, buffer, sizeof(buffer), 0);

			if(n <= 0) {
				logger(DEBUG_PROTOCOL, LOG_INFO, "Destination connection closed");
				break;
			}

			ssize_t sent = send(client_fd, buffer, n, 0);

			if(sent != n) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Failed to forward data to client");
				break;
			}
		}
	}

	ctx->fallback_active = false;
	return true;
}

/* Reality Handshake - Client Side */

bool reality_handshake_client(reality_ctx_t *ctx, int fd) {
	if(!ctx || !ctx->config || fd < 0 || ctx->config->is_server) {
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Starting Reality client handshake");

	/* Setup TLS fingerprint */
	if(!reality_setup_fingerprint(ctx, ctx->config->fingerprint)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to setup TLS fingerprint");
		return false;
	}

	/* Create SSL connection */
	ctx->ssl = SSL_new(ctx->ssl_ctx);

	if(!ctx->ssl) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create SSL connection");
		return false;
	}

	SSL_set_fd(ctx->ssl, fd);

	/* Set SNI */
	if(strlen(ctx->config->server_name) > 0) {
		SSL_set_tlsext_host_name(ctx->ssl, ctx->config->server_name);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Set SNI: %s", ctx->config->server_name);
	}

	/* Perform TLS handshake */
	int ret = SSL_connect(ctx->ssl);

	if(ret != 1) {
		int err = SSL_get_error(ctx->ssl, ret);
		logger(DEBUG_ALWAYS, LOG_ERR, "SSL_connect failed: %d", err);

		unsigned long ssl_err;

		while((ssl_err = ERR_get_error()) != 0) {
			char err_buf[256];
			ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
			logger(DEBUG_ALWAYS, LOG_ERR, "SSL error: %s", err_buf);
		}

		return false;
	}

	ctx->handshake_complete = true;
	logger(DEBUG_PROTOCOL, LOG_INFO, "Reality client handshake completed successfully");

	/* In a full implementation, we would:
	 * 1. Extract server's Reality public key from TLS handshake
	 * 2. Perform ECDH key exchange
	 * 3. Derive authentication key
	 * 4. Send authentication data
	 */

	return true;
}

/* Reality Handshake - Server Side */

bool reality_handshake_server(reality_ctx_t *ctx, int fd) {
	if(!ctx || !ctx->config || fd < 0 || !ctx->config->is_server) {
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Starting Reality server handshake");

	/* Setup TLS fingerprint (server doesn't really need this, but for consistency) */
	reality_setup_fingerprint(ctx, REALITY_FP_CHROME);

	/* Create SSL connection */
	ctx->ssl = SSL_new(ctx->ssl_ctx);

	if(!ctx->ssl) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create SSL connection");
		return false;
	}

	SSL_set_fd(ctx->ssl, fd);

	/* Accept TLS connection */
	int ret = SSL_accept(ctx->ssl);

	if(ret != 1) {
		int err = SSL_get_error(ctx->ssl, ret);
		logger(DEBUG_PROTOCOL, LOG_WARNING, "SSL_accept failed: %d - starting fallback", err);

		/* Start fallback mechanism */
		if(reality_start_fallback(ctx, fd)) {
			reality_proxy_to_dest(ctx, fd);
		}

		return false;
	}

	/* Extract SNI from client */
	const char *sni = SSL_get_servername(ctx->ssl, TLSEXT_NAMETYPE_host_name);

	if(sni) {
		strncpy(ctx->client_sni, sni, sizeof(ctx->client_sni) - 1);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Client SNI: %s", sni);
	} else {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Client did not send SNI");
		ctx->client_sni[0] = '\0';
	}

	/* Check for HTTP invitation request before VLESS/Reality verification */
	{
		char peek_buf[128];
		int peek_len = SSL_peek(ctx->ssl, peek_buf, sizeof(peek_buf) - 1);
		if(peek_len > 0) {
			peek_buf[peek_len] = '\0';
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "Peeked data: %.50s...", peek_buf);

			if(is_invitation_request(peek_buf, peek_len)) {
				logger(DEBUG_PROTOCOL, LOG_INFO, "Detected HTTP invitation request over TLS");

				/* Read full request */
				char request[4096];
				int req_len = SSL_read(ctx->ssl, request, sizeof(request) - 1);
				if(req_len > 0) {
					request[req_len] = '\0';

					/* Handle invitation and send response */
					size_t resp_len = 0;
					char *response = handle_invitation_request(request, req_len, &resp_len);

					if(response && resp_len > 0) {
						SSL_write(ctx->ssl, response, resp_len);
						free(response);
						logger(DEBUG_PROTOCOL, LOG_INFO, "Invitation response sent");
					}
				}

				/* Gracefully close SSL connection */
				SSL_shutdown(ctx->ssl);
				return false; /* Connection handled, close it */
			}
		}
	}

	/* In a full implementation, we would:
	 * 1. Extract client's Reality parameters from TLS handshake
	 * 2. Verify ShortID
	 * 3. Perform ECDH key exchange
	 * 4. Derive and verify authentication key
	 * 5. If authentication fails, start fallback
	 */

	/* For now, we'll do a simple SNI verification */
	if(!reality_verify_client(ctx)) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Client authentication failed - starting fallback");

		/* Start fallback mechanism */
		if(reality_start_fallback(ctx, fd)) {
			reality_proxy_to_dest(ctx, fd);
		}

		return false;
	}

	ctx->handshake_complete = true;
	logger(DEBUG_PROTOCOL, LOG_INFO, "Reality server handshake completed successfully");

	return true;
}

/* Configuration Load/Save (Placeholder) */

bool reality_config_load(reality_config_t *config, const char *filename) {
	if(!config || !filename) {
		return false;
	}

	/* TODO: Implement configuration file parsing */
	logger(DEBUG_ALWAYS, LOG_WARNING, "reality_config_load not yet implemented");
	return false;
}

bool reality_config_save(reality_config_t *config, const char *filename) {
	if(!config || !filename) {
		return false;
	}

	/* TODO: Implement configuration file saving */
	logger(DEBUG_ALWAYS, LOG_WARNING, "reality_config_save not yet implemented");
	return false;
}
