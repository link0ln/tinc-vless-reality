/*
    quic_fingerprint.h -- TLS fingerprint spoofing for QUIC
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

#ifndef TINC_QUIC_FINGERPRINT_H
#define TINC_QUIC_FINGERPRINT_H

#include "system.h"
#include "quic.h"

/* Browser fingerprint types */
typedef enum browser_type_t {
	BROWSER_CHROME_120,
	BROWSER_FIREFOX_115,
	BROWSER_SAFARI_17,
	BROWSER_EDGE_120,
	BROWSER_RANDOM,
	BROWSER_CUSTOM
} browser_type_t;

/* Browser fingerprint template */
typedef struct browser_fingerprint_t {
	const char *name;
	browser_type_t type;

	/* ALPN protocols */
	const char **alpn_list;
	size_t alpn_count;

	/* TLS cipher suites (in order) */
	const uint16_t *cipher_suites;
	size_t cipher_count;

	/* Supported groups (curves) */
	const uint16_t *supported_groups;
	size_t group_count;

	/* Signature algorithms */
	const uint16_t *signature_algorithms;
	size_t sig_alg_count;

	/* TLS extension order */
	const uint16_t *extension_order;
	size_t extension_count;

	/* QUIC transport parameters */
	uint64_t max_idle_timeout;
	uint64_t max_udp_payload_size;
	uint64_t initial_max_data;
	uint64_t initial_max_stream_data_bidi_local;
	uint64_t initial_max_stream_data_bidi_remote;
	uint64_t initial_max_stream_data_uni;
	uint64_t initial_max_streams_bidi;
	uint64_t initial_max_streams_uni;
} browser_fingerprint_t;

/* Function prototypes */

/* Get predefined browser fingerprint */
extern const browser_fingerprint_t *quic_fingerprint_get(browser_type_t type);

/* Get fingerprint by name */
extern const browser_fingerprint_t *quic_fingerprint_get_by_name(const char *name);

/* Apply fingerprint to QUIC configuration */
extern bool quic_fingerprint_apply(quic_config_t *config, const browser_fingerprint_t *fp);

/* Apply fingerprint by type */
extern bool quic_fingerprint_apply_type(quic_config_t *config, browser_type_t type);

/* Apply fingerprint by name */
extern bool quic_fingerprint_apply_name(quic_config_t *config, const char *name);

/* Get list of available fingerprints */
extern const char **quic_fingerprint_list_names(size_t *count);

#endif /* TINC_QUIC_FINGERPRINT_H */
