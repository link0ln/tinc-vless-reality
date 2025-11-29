/*
    reality.h -- Reality Protocol support for VLESS/tinc
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

#ifndef TINC_REALITY_H
#define TINC_REALITY_H

#include "system.h"
#include <stdint.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

/* Reality Protocol Constants */
#define REALITY_PUBLIC_KEY_SIZE 32   // X25519 public key size
#define REALITY_PRIVATE_KEY_SIZE 32  // X25519 private key size
#define REALITY_SHORT_ID_SIZE 8      // ShortID size
#define REALITY_AUTH_KEY_SIZE 32     // AuthKey size
#define REALITY_MAX_SERVER_NAME 256  // Max SNI length

/* Reality TLS Fingerprint Types */
typedef enum reality_fingerprint_t {
	REALITY_FP_CHROME = 0,
	REALITY_FP_FIREFOX,
	REALITY_FP_SAFARI,
	REALITY_FP_IOS,
	REALITY_FP_ANDROID,
	REALITY_FP_EDGE,
	REALITY_FP_RANDOM
} reality_fingerprint_t;

/* Reality Configuration */
typedef struct reality_config_t {
	/* Server-side configuration */
	uint8_t private_key[REALITY_PRIVATE_KEY_SIZE];  // Server's private key
	uint8_t public_key[REALITY_PUBLIC_KEY_SIZE];    // Server's public key
	uint8_t short_ids[8][REALITY_SHORT_ID_SIZE];    // Multiple ShortIDs (max 8)
	int num_short_ids;

	/* Destination (fallback) */
	char dest_domain[REALITY_MAX_SERVER_NAME];      // Destination domain (e.g., google.com)
	uint16_t dest_port;                              // Destination port (typically 443)

	/* Server Names (SNI whitelist) */
	char server_names[16][REALITY_MAX_SERVER_NAME]; // Allowed SNI values
	int num_server_names;

	/* Client-side configuration */
	uint8_t server_public_key[REALITY_PUBLIC_KEY_SIZE]; // Server's public key (client knows)
	char server_name[REALITY_MAX_SERVER_NAME];           // SNI to send
	uint8_t short_id[REALITY_SHORT_ID_SIZE];             // ShortID to use
	reality_fingerprint_t fingerprint;                    // TLS fingerprint to use

	/* Common */
	bool is_server;                                  // Server mode or client mode?
	int max_time_diff;                               // Maximum time difference tolerance (seconds)
} reality_config_t;

/* Reality Connection Context */
typedef struct reality_ctx_t {
	reality_config_t *config;      // Configuration
	SSL_CTX *ssl_ctx;              // OpenSSL context
	SSL *ssl;                      // OpenSSL connection

	/* Key exchange data */
	EVP_PKEY *local_keypair;       // Local X25519 keypair (ephemeral)
	uint8_t remote_public_key[REALITY_PUBLIC_KEY_SIZE]; // Remote public key
	uint8_t shared_secret[32];     // Shared secret from ECDH
	uint8_t auth_key[REALITY_AUTH_KEY_SIZE]; // Derived authentication key

	/* Connection state */
	bool handshake_complete;       // TLS handshake done?
	bool authenticated;            // Reality authentication passed?
	char client_sni[REALITY_MAX_SERVER_NAME]; // SNI from client
	uint8_t client_short_id[REALITY_SHORT_ID_SIZE]; // ShortID from client

	/* Fallback connection */
	int fallback_fd;               // File descriptor for fallback connection
	bool fallback_active;          // Is fallback active?

	/* Statistics */
	uint64_t bytes_encrypted;
	uint64_t bytes_decrypted;
} reality_ctx_t;

/* Function prototypes */

/* Initialize Reality subsystem */
extern void reality_init(void);
extern void reality_exit(void);

/* Configuration management */
extern reality_config_t *reality_config_new(bool is_server);
extern void reality_config_free(reality_config_t *config);
extern bool reality_config_load(reality_config_t *config, const char *filename);
extern bool reality_config_save(reality_config_t *config, const char *filename);

/* Key generation */
extern bool reality_generate_keypair(uint8_t *private_key, uint8_t *public_key);
extern bool reality_generate_short_id(uint8_t *short_id);
extern bool reality_derive_auth_key(const uint8_t *shared_secret, uint8_t *auth_key);

/* Key operations */
extern bool reality_load_private_key(const char *hex_str, uint8_t *private_key);
extern bool reality_load_public_key(const char *hex_str, uint8_t *public_key);
extern char *reality_save_private_key(const uint8_t *private_key);
extern char *reality_save_public_key(const uint8_t *public_key);
extern char *reality_save_short_id(const uint8_t *short_id);
extern bool reality_load_short_id(const char *hex_str, uint8_t *short_id);

/* Reality context management */
extern reality_ctx_t *reality_ctx_new(reality_config_t *config);
extern void reality_ctx_free(reality_ctx_t *ctx);
extern void reality_ctx_reset(reality_ctx_t *ctx);

/* TLS fingerprint configuration */
extern bool reality_setup_fingerprint(reality_ctx_t *ctx, reality_fingerprint_t fp);
extern const char *reality_fingerprint_to_string(reality_fingerprint_t fp);

/* Reality handshake (client) */
extern bool reality_handshake_client(reality_ctx_t *ctx, int fd);

/* Reality handshake (server) */
extern bool reality_handshake_server(reality_ctx_t *ctx, int fd);

/* Authentication verification */
extern bool reality_verify_client(reality_ctx_t *ctx);

/* Fallback mechanism */
extern bool reality_start_fallback(reality_ctx_t *ctx, int client_fd);
extern bool reality_proxy_to_dest(reality_ctx_t *ctx, int client_fd);

/* Data transfer through Reality TLS */
extern ssize_t reality_write(reality_ctx_t *ctx, const void *data, size_t len);
extern ssize_t reality_read(reality_ctx_t *ctx, void *data, size_t len);

/* Utility functions */
extern bool reality_verify_sni(reality_config_t *config, const char *sni);
extern bool reality_verify_short_id(reality_config_t *config, const uint8_t *short_id);
extern void reality_bytes_to_hex(const uint8_t *bytes, size_t len, char *hex);
extern bool reality_hex_to_bytes(const char *hex, uint8_t *bytes, size_t len);

#endif /* TINC_REALITY_H */
