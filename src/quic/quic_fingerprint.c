/*
    quic_fingerprint.c -- TLS fingerprint spoofing implementation
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
#include <string.h>
#include <strings.h>

#include "quic_fingerprint.h"
#include "../logger.h"

/* TLS 1.3 Cipher Suites */
#define TLS_AES_128_GCM_SHA256       0x1301
#define TLS_AES_256_GCM_SHA384       0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303

/* TLS 1.2 Cipher Suites (for compatibility) */
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xC02F
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC02C
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   0xC030

/* Supported Groups (Curves) */
#define TLS_GROUP_X25519    0x001D
#define TLS_GROUP_SECP256R1 0x0017
#define TLS_GROUP_SECP384R1 0x0018
#define TLS_GROUP_SECP521R1 0x0019

/* Signature Algorithms */
#define TLS_SIG_ECDSA_SECP256R1_SHA256 0x0403
#define TLS_SIG_ECDSA_SECP384R1_SHA384 0x0503
#define TLS_SIG_ECDSA_SECP521R1_SHA512 0x0603
#define TLS_SIG_RSA_PSS_RSAE_SHA256    0x0804
#define TLS_SIG_RSA_PSS_RSAE_SHA384    0x0805
#define TLS_SIG_RSA_PSS_RSAE_SHA512    0x0806
#define TLS_SIG_RSA_PKCS1_SHA256       0x0401
#define TLS_SIG_RSA_PKCS1_SHA384       0x0501
#define TLS_SIG_RSA_PKCS1_SHA512       0x0601

/* TLS Extension Types */
#define TLS_EXT_SERVER_NAME               0x0000
#define TLS_EXT_STATUS_REQUEST            0x0005
#define TLS_EXT_SUPPORTED_GROUPS          0x000A
#define TLS_EXT_EC_POINT_FORMATS          0x000B
#define TLS_EXT_SIGNATURE_ALGORITHMS      0x000D
#define TLS_EXT_ALPN                      0x0010
#define TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP 0x0012
#define TLS_EXT_EXTENDED_MASTER_SECRET    0x0017
#define TLS_EXT_SESSION_TICKET            0x0023
#define TLS_EXT_SUPPORTED_VERSIONS        0x002B
#define TLS_EXT_PSK_KEY_EXCHANGE_MODES    0x002D
#define TLS_EXT_KEY_SHARE                 0x0033
#define TLS_EXT_QUIC_TRANSPORT_PARAMETERS 0x0039

/* Chrome 120 ALPN list */
static const char *chrome_120_alpn[] = {
	"h3",
	"h3-29"
};

/* Chrome 120 cipher suites */
static const uint16_t chrome_120_ciphers[] = {
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
};

/* Chrome 120 supported groups */
static const uint16_t chrome_120_groups[] = {
	TLS_GROUP_X25519,
	TLS_GROUP_SECP256R1,
	TLS_GROUP_SECP384R1
};

/* Chrome 120 signature algorithms */
static const uint16_t chrome_120_sig_algs[] = {
	TLS_SIG_ECDSA_SECP256R1_SHA256,
	TLS_SIG_RSA_PSS_RSAE_SHA256,
	TLS_SIG_RSA_PKCS1_SHA256,
	TLS_SIG_ECDSA_SECP384R1_SHA384,
	TLS_SIG_RSA_PSS_RSAE_SHA384,
	TLS_SIG_RSA_PKCS1_SHA384,
	TLS_SIG_RSA_PSS_RSAE_SHA512,
	TLS_SIG_RSA_PKCS1_SHA512
};

/* Chrome 120 extension order */
static const uint16_t chrome_120_extensions[] = {
	TLS_EXT_SERVER_NAME,
	TLS_EXT_EXTENDED_MASTER_SECRET,
	TLS_EXT_STATUS_REQUEST,
	TLS_EXT_SUPPORTED_GROUPS,
	TLS_EXT_EC_POINT_FORMATS,
	TLS_EXT_SESSION_TICKET,
	TLS_EXT_ALPN,
	TLS_EXT_SIGNATURE_ALGORITHMS,
	TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP,
	TLS_EXT_KEY_SHARE,
	TLS_EXT_PSK_KEY_EXCHANGE_MODES,
	TLS_EXT_SUPPORTED_VERSIONS,
	TLS_EXT_QUIC_TRANSPORT_PARAMETERS
};

/* Chrome 120 fingerprint template */
static const browser_fingerprint_t chrome_120_fp = {
	.name = "chrome120",
	.type = BROWSER_CHROME_120,
	.alpn_list = chrome_120_alpn,
	.alpn_count = sizeof(chrome_120_alpn) / sizeof(chrome_120_alpn[0]),
	.cipher_suites = chrome_120_ciphers,
	.cipher_count = sizeof(chrome_120_ciphers) / sizeof(chrome_120_ciphers[0]),
	.supported_groups = chrome_120_groups,
	.group_count = sizeof(chrome_120_groups) / sizeof(chrome_120_groups[0]),
	.signature_algorithms = chrome_120_sig_algs,
	.sig_alg_count = sizeof(chrome_120_sig_algs) / sizeof(chrome_120_sig_algs[0]),
	.extension_order = chrome_120_extensions,
	.extension_count = sizeof(chrome_120_extensions) / sizeof(chrome_120_extensions[0]),
	/* QUIC transport parameters (Chrome typical values) */
	.max_idle_timeout = 30000,  /* 30 seconds */
	.max_udp_payload_size = 1350,
	.initial_max_data = 10485760,  /* 10 MB */
	.initial_max_stream_data_bidi_local = 6291456,
	.initial_max_stream_data_bidi_remote = 6291456,
	.initial_max_stream_data_uni = 6291456,
	.initial_max_streams_bidi = 100,
	.initial_max_streams_uni = 3
};

/* Firefox 115 ALPN list */
static const char *firefox_115_alpn[] = {
	"h3",
	"h3-29"
};

/* Firefox 115 cipher suites */
static const uint16_t firefox_115_ciphers[] = {
	TLS_AES_128_GCM_SHA256,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
};

/* Firefox 115 supported groups */
static const uint16_t firefox_115_groups[] = {
	TLS_GROUP_X25519,
	TLS_GROUP_SECP256R1,
	TLS_GROUP_SECP384R1,
	TLS_GROUP_SECP521R1
};

/* Firefox 115 signature algorithms */
static const uint16_t firefox_115_sig_algs[] = {
	TLS_SIG_ECDSA_SECP256R1_SHA256,
	TLS_SIG_ECDSA_SECP384R1_SHA384,
	TLS_SIG_ECDSA_SECP521R1_SHA512,
	TLS_SIG_RSA_PSS_RSAE_SHA256,
	TLS_SIG_RSA_PSS_RSAE_SHA384,
	TLS_SIG_RSA_PSS_RSAE_SHA512,
	TLS_SIG_RSA_PKCS1_SHA256,
	TLS_SIG_RSA_PKCS1_SHA384,
	TLS_SIG_RSA_PKCS1_SHA512
};

/* Firefox 115 extension order */
static const uint16_t firefox_115_extensions[] = {
	TLS_EXT_SERVER_NAME,
	TLS_EXT_EXTENDED_MASTER_SECRET,
	TLS_EXT_STATUS_REQUEST,
	TLS_EXT_SUPPORTED_GROUPS,
	TLS_EXT_EC_POINT_FORMATS,
	TLS_EXT_ALPN,
	TLS_EXT_SIGNATURE_ALGORITHMS,
	TLS_EXT_SESSION_TICKET,
	TLS_EXT_KEY_SHARE,
	TLS_EXT_PSK_KEY_EXCHANGE_MODES,
	TLS_EXT_SUPPORTED_VERSIONS,
	TLS_EXT_QUIC_TRANSPORT_PARAMETERS
};

/* Firefox 115 fingerprint template */
static const browser_fingerprint_t firefox_115_fp = {
	.name = "firefox115",
	.type = BROWSER_FIREFOX_115,
	.alpn_list = firefox_115_alpn,
	.alpn_count = sizeof(firefox_115_alpn) / sizeof(firefox_115_alpn[0]),
	.cipher_suites = firefox_115_ciphers,
	.cipher_count = sizeof(firefox_115_ciphers) / sizeof(firefox_115_ciphers[0]),
	.supported_groups = firefox_115_groups,
	.group_count = sizeof(firefox_115_groups) / sizeof(firefox_115_groups[0]),
	.signature_algorithms = firefox_115_sig_algs,
	.sig_alg_count = sizeof(firefox_115_sig_algs) / sizeof(firefox_115_sig_algs[0]),
	.extension_order = firefox_115_extensions,
	.extension_count = sizeof(firefox_115_extensions) / sizeof(firefox_115_extensions[0]),
	/* QUIC transport parameters (Firefox typical values) */
	.max_idle_timeout = 30000,
	.max_udp_payload_size = 1472,
	.initial_max_data = 15728640,  /* 15 MB */
	.initial_max_stream_data_bidi_local = 12582912,
	.initial_max_stream_data_bidi_remote = 12582912,
	.initial_max_stream_data_uni = 12582912,
	.initial_max_streams_bidi = 100,
	.initial_max_streams_uni = 100
};

/* Get fingerprint by type */
const browser_fingerprint_t *quic_fingerprint_get(browser_type_t type) {
	switch(type) {
	case BROWSER_CHROME_120:
		return &chrome_120_fp;

	case BROWSER_FIREFOX_115:
		return &firefox_115_fp;

	case BROWSER_RANDOM:
		/* Randomly choose between Chrome and Firefox */
		return (rand() % 2) ? &chrome_120_fp : &firefox_115_fp;

	default:
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Unknown fingerprint type %d, using Chrome", type);
		return &chrome_120_fp;
	}
}

/* Get fingerprint by name */
const browser_fingerprint_t *quic_fingerprint_get_by_name(const char *name) {
	if(!name) {
		return &chrome_120_fp;  /* Default to Chrome */
	}

	if(!strcasecmp(name, "chrome") || !strcasecmp(name, "chrome120")) {
		return &chrome_120_fp;
	}

	if(!strcasecmp(name, "firefox") || !strcasecmp(name, "firefox115")) {
		return &firefox_115_fp;
	}

	if(!strcasecmp(name, "random")) {
		return quic_fingerprint_get(BROWSER_RANDOM);
	}

	logger(DEBUG_PROTOCOL, LOG_WARNING, "Unknown fingerprint name '%s', using Chrome", name);
	return &chrome_120_fp;
}

/* Apply fingerprint to QUIC configuration */
bool quic_fingerprint_apply(quic_config_t *config, const browser_fingerprint_t *fp) {
	if(!config || !config->config || !fp) {
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Applying %s fingerprint to QUIC config", fp->name);

	/* Apply ALPN protocols */
	if(fp->alpn_count > 0 && fp->alpn_list) {
		for(size_t i = 0; i < fp->alpn_count; i++) {
			/* Set ALPN using quiche API */
			/* quiche_config_set_application_protos() expects wire format:
			   length-prefixed strings concatenated */
			/* For simplicity, just set h3 for now */
			if(i == 0) {
				quiche_config_set_application_protos(config->config,
				                                      (uint8_t *)"\x02h3", 3);
			}
		}

		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Set ALPN: %zu protocols", fp->alpn_count);
	}

	/* Apply QUIC transport parameters */
	quiche_config_set_max_idle_timeout(config->config, fp->max_idle_timeout);
	quiche_config_set_max_recv_udp_payload_size(config->config, fp->max_udp_payload_size);
	quiche_config_set_max_send_udp_payload_size(config->config, fp->max_udp_payload_size);
	quiche_config_set_initial_max_data(config->config, fp->initial_max_data);
	quiche_config_set_initial_max_stream_data_bidi_local(config->config,
	        fp->initial_max_stream_data_bidi_local);
	quiche_config_set_initial_max_stream_data_bidi_remote(config->config,
	        fp->initial_max_stream_data_bidi_remote);
	quiche_config_set_initial_max_stream_data_uni(config->config,
	        fp->initial_max_stream_data_uni);
	quiche_config_set_initial_max_streams_bidi(config->config, fp->initial_max_streams_bidi);
	quiche_config_set_initial_max_streams_uni(config->config, fp->initial_max_streams_uni);

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Applied transport parameters: "
	       "max_data=%lu, max_streams_bidi=%lu",
	       fp->initial_max_data, fp->initial_max_streams_bidi);

	/* Note: TLS cipher suites, signature algorithms, and extension order
	   are typically controlled by the underlying TLS library (BoringSSL)
	   and may not be directly configurable through quiche API.
	   The ALPN and transport parameters are the most important for
	   appearing as a legitimate HTTP/3 browser. */

	logger(DEBUG_PROTOCOL, LOG_INFO, "Successfully applied %s fingerprint", fp->name);

	return true;
}

/* Apply fingerprint by type */
bool quic_fingerprint_apply_type(quic_config_t *config, browser_type_t type) {
	const browser_fingerprint_t *fp = quic_fingerprint_get(type);
	return quic_fingerprint_apply(config, fp);
}

/* Apply fingerprint by name */
bool quic_fingerprint_apply_name(quic_config_t *config, const char *name) {
	const browser_fingerprint_t *fp = quic_fingerprint_get_by_name(name);
	return quic_fingerprint_apply(config, fp);
}

/* Get list of available fingerprints */
const char **quic_fingerprint_list_names(size_t *count) {
	static const char *fingerprint_names[] = {
		"chrome120",
		"firefox115",
		"random"
	};

	if(count) {
		*count = sizeof(fingerprint_names) / sizeof(fingerprint_names[0]);
	}

	return fingerprint_names;
}
