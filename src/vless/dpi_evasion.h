/*
    dpi_evasion.h -- DPI Evasion techniques for VLESS/tinc
    Copyright (C) 2025 tinc-vless contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#ifndef TINC_DPI_EVASION_H
#define TINC_DPI_EVASION_H

#include "system.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* ============================================================================
 * 1. TIMING OBFUSCATION
 * ============================================================================
 * Adds random delays between packets to hide timing patterns that DPI can use
 * to identify VPN traffic (e.g., consistent inter-packet timing).
 */

typedef enum timing_mode_t {
	TIMING_OFF = 0,        /* No timing obfuscation */
	TIMING_RANDOM,         /* Random delay within range */
	TIMING_ADAPTIVE,       /* Adapts to traffic pattern */
	TIMING_BURST           /* Simulates bursty web traffic */
} timing_mode_t;

typedef struct timing_config_t {
	timing_mode_t mode;
	uint32_t min_delay_us;     /* Minimum delay in microseconds */
	uint32_t max_delay_us;     /* Maximum delay in microseconds */
	uint32_t burst_size;       /* Packets per burst (for BURST mode) */
	uint32_t burst_delay_us;   /* Delay between bursts */
} timing_config_t;

/* ============================================================================
 * 2. PACKET LENGTH PADDING
 * ============================================================================
 * Randomizes packet sizes to prevent DPI from identifying VPN traffic
 * based on characteristic packet length distributions.
 */

typedef enum padding_mode_t {
	PADDING_OFF = 0,       /* No padding */
	PADDING_RANDOM,        /* Random padding within range */
	PADDING_FIXED,         /* Pad to fixed size */
	PADDING_ADAPTIVE,      /* Pad based on packet type */
	PADDING_MTU            /* Pad all packets to MTU */
} padding_mode_t;

typedef struct padding_config_t {
	padding_mode_t mode;
	uint16_t min_padding;      /* Minimum padding bytes */
	uint16_t max_padding;      /* Maximum padding bytes */
	uint16_t fixed_size;       /* Target size for FIXED mode */
	bool pad_small_only;       /* Only pad small packets */
	uint16_t small_threshold;  /* Size threshold for "small" */
} padding_config_t;

/* Padding header in packet */
typedef struct __attribute__((packed)) padding_header_t {
	uint8_t magic;             /* Magic byte: 0xAD */
	uint8_t flags;             /* Bit 0: has_padding, Bit 1-7: reserved */
	uint16_t padding_len;      /* Length of padding (network order) */
	uint16_t orig_len;         /* Original payload length (network order) */
} padding_header_t;

#define PADDING_MAGIC 0xAD
#define PADDING_FLAG_HAS_PADDING 0x01

/* ============================================================================
 * 3. ACTIVE PROBING PROTECTION
 * ============================================================================
 * Protects against active probing attacks where censors replay captured
 * handshakes or send probe packets to identify VPN servers.
 */

typedef struct probing_protection_t {
	bool enabled;
	uint32_t max_time_diff;    /* Max acceptable timestamp diff (seconds) */
	uint32_t replay_window;    /* Replay detection window size */
	uint64_t *seen_nonces;     /* Circular buffer of seen nonces */
	size_t nonce_count;        /* Number of stored nonces */
	size_t nonce_capacity;     /* Capacity of nonce buffer */
	size_t nonce_index;        /* Current index in circular buffer */
} probing_protection_t;

/* ============================================================================
 * 4. TRAFFIC SHAPING
 * ============================================================================
 * Shapes traffic to mimic normal HTTPS/web browsing patterns.
 */

typedef enum traffic_pattern_t {
	PATTERN_NONE = 0,
	PATTERN_HTTP,          /* Mimic HTTP request/response pattern */
	PATTERN_VIDEO,         /* Mimic video streaming */
	PATTERN_BROWSING       /* Mimic web browsing */
} traffic_pattern_t;

typedef struct traffic_shaping_config_t {
	traffic_pattern_t pattern;
	uint32_t avg_request_size;
	uint32_t avg_response_size;
	uint32_t think_time_ms;    /* Simulated user "think time" */
} traffic_shaping_config_t;

/* ============================================================================
 * MAIN DPI EVASION CONFIG
 * ============================================================================
 */

typedef struct dpi_evasion_config_t {
	/* Feature enables */
	bool timing_enabled;
	bool padding_enabled;
	bool probing_protection_enabled;
	bool traffic_shaping_enabled;

	/* Individual configs */
	timing_config_t timing;
	padding_config_t padding;
	probing_protection_t probing;
	traffic_shaping_config_t shaping;

	/* Statistics */
	uint64_t packets_delayed;
	uint64_t packets_padded;
	uint64_t bytes_padding_added;
	uint64_t probes_blocked;
	uint64_t replays_blocked;
} dpi_evasion_config_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================
 */

/* Initialization */
extern void dpi_evasion_init(void);
extern void dpi_evasion_exit(void);
extern dpi_evasion_config_t *dpi_evasion_get_config(void);

/* Configuration loading */
extern bool dpi_evasion_load_config(void);

/* Timing obfuscation */
extern void dpi_timing_delay(void);
extern uint32_t dpi_timing_get_delay_us(void);

/* Packet padding */
extern size_t dpi_padding_add(uint8_t *buffer, size_t data_len, size_t buffer_size);
extern size_t dpi_padding_remove(uint8_t *buffer, size_t total_len);
extern size_t dpi_padding_get_overhead(void);

/* Active probing protection */
extern bool dpi_probing_verify_timestamp(uint64_t timestamp);
extern bool dpi_probing_check_replay(uint64_t nonce);
extern void dpi_probing_record_nonce(uint64_t nonce);
extern uint64_t dpi_probing_generate_nonce(void);

/* Traffic shaping */
extern void dpi_shaping_pre_send(size_t packet_size);
extern void dpi_shaping_post_receive(size_t packet_size);

/* Statistics */
extern void dpi_evasion_log_stats(void);

/* Config string parsers */
extern timing_mode_t dpi_parse_timing_mode(const char *str);
extern padding_mode_t dpi_parse_padding_mode(const char *str);
extern traffic_pattern_t dpi_parse_traffic_pattern(const char *str);

#endif /* TINC_DPI_EVASION_H */
