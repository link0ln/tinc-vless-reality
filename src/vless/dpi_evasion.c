/*
    dpi_evasion.c -- DPI Evasion techniques implementation
    Copyright (C) 2025 tinc-vless contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"
#include "dpi_evasion.h"
#include "../conf.h"
#include "../logger.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>

/* Global DPI evasion config */
static dpi_evasion_config_t dpi_config;
static bool dpi_initialized = false;

/* Random state for reproducible randomness */
static unsigned int random_seed = 0;

/* ============================================================================
 * INITIALIZATION
 * ============================================================================
 */

void dpi_evasion_init(void) {
	if(dpi_initialized) {
		return;
	}

	memset(&dpi_config, 0, sizeof(dpi_config));

	/* Initialize random seed */
	struct timeval tv;
	gettimeofday(&tv, NULL);
	random_seed = (unsigned int)(tv.tv_sec ^ tv.tv_usec ^ getpid());
	srand(random_seed);

	/* Set defaults */
	dpi_config.timing.mode = TIMING_OFF;
	dpi_config.timing.min_delay_us = 1000;    /* 1ms */
	dpi_config.timing.max_delay_us = 50000;   /* 50ms */
	dpi_config.timing.burst_size = 5;
	dpi_config.timing.burst_delay_us = 100000; /* 100ms */

	dpi_config.padding.mode = PADDING_OFF;
	dpi_config.padding.min_padding = 0;
	dpi_config.padding.max_padding = 256;
	dpi_config.padding.fixed_size = 1400;
	dpi_config.padding.pad_small_only = true;
	dpi_config.padding.small_threshold = 128;

	dpi_config.probing.enabled = false;
	dpi_config.probing.max_time_diff = 120;   /* 2 minutes */
	dpi_config.probing.replay_window = 1000;
	dpi_config.probing.seen_nonces = NULL;
	dpi_config.probing.nonce_count = 0;
	dpi_config.probing.nonce_capacity = 0;
	dpi_config.probing.nonce_index = 0;

	dpi_config.shaping.pattern = PATTERN_NONE;
	dpi_config.shaping.avg_request_size = 512;
	dpi_config.shaping.avg_response_size = 4096;
	dpi_config.shaping.think_time_ms = 1000;

	dpi_initialized = true;
	logger(DEBUG_ALWAYS, LOG_INFO, "DPI evasion subsystem initialized");
}

void dpi_evasion_exit(void) {
	if(!dpi_initialized) {
		return;
	}

	/* Free replay protection buffer */
	if(dpi_config.probing.seen_nonces) {
		free(dpi_config.probing.seen_nonces);
		dpi_config.probing.seen_nonces = NULL;
	}

	dpi_initialized = false;
	logger(DEBUG_ALWAYS, LOG_INFO, "DPI evasion subsystem shutdown");
}

dpi_evasion_config_t *dpi_evasion_get_config(void) {
	if(!dpi_initialized) {
		dpi_evasion_init();
	}
	return &dpi_config;
}

/* ============================================================================
 * CONFIGURATION LOADING
 * ============================================================================
 */

timing_mode_t dpi_parse_timing_mode(const char *str) {
	if(!str) return TIMING_OFF;
	if(!strcasecmp(str, "random")) return TIMING_RANDOM;
	if(!strcasecmp(str, "adaptive")) return TIMING_ADAPTIVE;
	if(!strcasecmp(str, "burst")) return TIMING_BURST;
	return TIMING_OFF;
}

padding_mode_t dpi_parse_padding_mode(const char *str) {
	if(!str) return PADDING_OFF;
	if(!strcasecmp(str, "random")) return PADDING_RANDOM;
	if(!strcasecmp(str, "fixed")) return PADDING_FIXED;
	if(!strcasecmp(str, "adaptive")) return PADDING_ADAPTIVE;
	if(!strcasecmp(str, "mtu")) return PADDING_MTU;
	return PADDING_OFF;
}

traffic_pattern_t dpi_parse_traffic_pattern(const char *str) {
	if(!str) return PATTERN_NONE;
	if(!strcasecmp(str, "http")) return PATTERN_HTTP;
	if(!strcasecmp(str, "video")) return PATTERN_VIDEO;
	if(!strcasecmp(str, "browsing")) return PATTERN_BROWSING;
	return PATTERN_NONE;
}

bool dpi_evasion_load_config(void) {
	if(!dpi_initialized) {
		dpi_evasion_init();
	}

	char *str_val;
	int int_val;
	bool bool_val;

	/* Timing configuration */
	if(get_config_string(lookup_config(config_tree, "VLESSTimingMode"), &str_val)) {
		dpi_config.timing.mode = dpi_parse_timing_mode(str_val);
		dpi_config.timing_enabled = (dpi_config.timing.mode != TIMING_OFF);
		logger(DEBUG_ALWAYS, LOG_INFO, "DPI timing mode: %s", str_val);
	}

	if(get_config_int(lookup_config(config_tree, "VLESSTimingMinDelay"), &int_val)) {
		dpi_config.timing.min_delay_us = (uint32_t)int_val * 1000; /* ms to us */
	}

	if(get_config_int(lookup_config(config_tree, "VLESSTimingMaxDelay"), &int_val)) {
		dpi_config.timing.max_delay_us = (uint32_t)int_val * 1000; /* ms to us */
	}

	if(get_config_int(lookup_config(config_tree, "VLESSTimingBurstSize"), &int_val)) {
		dpi_config.timing.burst_size = (uint32_t)int_val;
	}

	/* Padding configuration */
	if(get_config_string(lookup_config(config_tree, "VLESSPaddingMode"), &str_val)) {
		dpi_config.padding.mode = dpi_parse_padding_mode(str_val);
		dpi_config.padding_enabled = (dpi_config.padding.mode != PADDING_OFF);
		logger(DEBUG_ALWAYS, LOG_INFO, "DPI padding mode: %s", str_val);
	}

	if(get_config_int(lookup_config(config_tree, "VLESSPaddingMin"), &int_val)) {
		dpi_config.padding.min_padding = (uint16_t)int_val;
	}

	if(get_config_int(lookup_config(config_tree, "VLESSPaddingMax"), &int_val)) {
		dpi_config.padding.max_padding = (uint16_t)int_val;
	}

	if(get_config_int(lookup_config(config_tree, "VLESSPaddingFixedSize"), &int_val)) {
		dpi_config.padding.fixed_size = (uint16_t)int_val;
	}

	if(get_config_bool(lookup_config(config_tree, "VLESSPaddingSmallOnly"), &bool_val)) {
		dpi_config.padding.pad_small_only = bool_val;
	}

	if(get_config_int(lookup_config(config_tree, "VLESSPaddingThreshold"), &int_val)) {
		dpi_config.padding.small_threshold = (uint16_t)int_val;
	}

	/* Probing protection */
	if(get_config_bool(lookup_config(config_tree, "VLESSProbingProtection"), &bool_val)) {
		dpi_config.probing.enabled = bool_val;
		dpi_config.probing_protection_enabled = bool_val;
		if(bool_val) {
			logger(DEBUG_ALWAYS, LOG_INFO, "DPI active probing protection enabled");
		}
	}

	if(get_config_int(lookup_config(config_tree, "VLESSProbingMaxTimeDiff"), &int_val)) {
		dpi_config.probing.max_time_diff = (uint32_t)int_val;
	}

	if(get_config_int(lookup_config(config_tree, "VLESSProbingReplayWindow"), &int_val)) {
		dpi_config.probing.replay_window = (uint32_t)int_val;
	}

	/* Initialize replay buffer if probing protection enabled */
	if(dpi_config.probing.enabled && !dpi_config.probing.seen_nonces) {
		dpi_config.probing.nonce_capacity = dpi_config.probing.replay_window;
		dpi_config.probing.seen_nonces = calloc(dpi_config.probing.nonce_capacity, sizeof(uint64_t));
		if(!dpi_config.probing.seen_nonces) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to allocate nonce buffer");
		}
	}

	/* Traffic shaping */
	if(get_config_string(lookup_config(config_tree, "VLESSTrafficPattern"), &str_val)) {
		dpi_config.shaping.pattern = dpi_parse_traffic_pattern(str_val);
		dpi_config.traffic_shaping_enabled = (dpi_config.shaping.pattern != PATTERN_NONE);
		if(dpi_config.traffic_shaping_enabled) {
			logger(DEBUG_ALWAYS, LOG_INFO, "DPI traffic shaping pattern: %s", str_val);
		}
	}

	/* Log summary */
	logger(DEBUG_ALWAYS, LOG_INFO, "DPI evasion config loaded: timing=%s padding=%s probing=%s shaping=%s",
	       dpi_config.timing_enabled ? "on" : "off",
	       dpi_config.padding_enabled ? "on" : "off",
	       dpi_config.probing_protection_enabled ? "on" : "off",
	       dpi_config.traffic_shaping_enabled ? "on" : "off");

	return true;
}

/* ============================================================================
 * 1. TIMING OBFUSCATION
 * ============================================================================
 */

static uint32_t random_range(uint32_t min, uint32_t max) {
	if(min >= max) return min;
	return min + (uint32_t)(rand() % (max - min + 1));
}

uint32_t dpi_timing_get_delay_us(void) {
	if(!dpi_config.timing_enabled) {
		return 0;
	}

	switch(dpi_config.timing.mode) {
	case TIMING_RANDOM:
		return random_range(dpi_config.timing.min_delay_us,
		                    dpi_config.timing.max_delay_us);

	case TIMING_ADAPTIVE: {
		/* Adaptive: less delay for large bursts, more for small packets */
		static uint32_t packet_count = 0;
		packet_count++;
		if(packet_count % 10 == 0) {
			/* Every 10th packet, add longer delay */
			return random_range(dpi_config.timing.max_delay_us / 2,
			                    dpi_config.timing.max_delay_us);
		}
		return random_range(dpi_config.timing.min_delay_us,
		                    dpi_config.timing.min_delay_us * 2);
	}

	case TIMING_BURST: {
		/* Burst mode: send several packets quickly, then pause */
		static uint32_t burst_counter = 0;
		burst_counter++;
		if(burst_counter >= dpi_config.timing.burst_size) {
			burst_counter = 0;
			return dpi_config.timing.burst_delay_us;
		}
		return dpi_config.timing.min_delay_us;
	}

	default:
		return 0;
	}
}

void dpi_timing_delay(void) {
	uint32_t delay_us = dpi_timing_get_delay_us();
	if(delay_us > 0) {
		usleep(delay_us);
		dpi_config.packets_delayed++;
	}
}

/* ============================================================================
 * 2. PACKET LENGTH PADDING
 * ============================================================================
 */

size_t dpi_padding_get_overhead(void) {
	return sizeof(padding_header_t);
}

size_t dpi_padding_add(uint8_t *buffer, size_t data_len, size_t buffer_size) {
	if(!dpi_config.padding_enabled || !buffer) {
		return data_len;
	}

	/* Check if we should pad this packet */
	if(dpi_config.padding.pad_small_only &&
	   data_len > dpi_config.padding.small_threshold) {
		return data_len;
	}

	uint16_t padding_len = 0;

	switch(dpi_config.padding.mode) {
	case PADDING_RANDOM:
		padding_len = (uint16_t)random_range(dpi_config.padding.min_padding,
		                                     dpi_config.padding.max_padding);
		break;

	case PADDING_FIXED:
		if(data_len + sizeof(padding_header_t) < dpi_config.padding.fixed_size) {
			padding_len = dpi_config.padding.fixed_size - data_len - sizeof(padding_header_t);
		}
		break;

	case PADDING_ADAPTIVE:
		/* Pad small packets more aggressively */
		if(data_len < 64) {
			padding_len = (uint16_t)random_range(64, 256);
		} else if(data_len < 256) {
			padding_len = (uint16_t)random_range(32, 128);
		} else {
			padding_len = (uint16_t)random_range(0, 64);
		}
		break;

	case PADDING_MTU:
		/* Pad to MTU (1400 bytes typical) */
		if(data_len + sizeof(padding_header_t) < 1400) {
			padding_len = 1400 - data_len - sizeof(padding_header_t);
		}
		break;

	default:
		return data_len;
	}

	/* Check if we have space */
	size_t total_size = sizeof(padding_header_t) + data_len + padding_len;
	if(total_size > buffer_size) {
		/* Reduce padding to fit */
		padding_len = buffer_size - sizeof(padding_header_t) - data_len;
		total_size = buffer_size;
	}

	/* Move data to make room for header */
	memmove(buffer + sizeof(padding_header_t), buffer, data_len);

	/* Fill in header */
	padding_header_t *hdr = (padding_header_t *)buffer;
	hdr->magic = PADDING_MAGIC;
	hdr->flags = PADDING_FLAG_HAS_PADDING;
	hdr->padding_len = htons(padding_len);
	hdr->orig_len = htons((uint16_t)data_len);

	/* Add random padding at the end */
	uint8_t *padding_start = buffer + sizeof(padding_header_t) + data_len;
	for(uint16_t i = 0; i < padding_len; i++) {
		padding_start[i] = (uint8_t)(rand() & 0xFF);
	}

	dpi_config.packets_padded++;
	dpi_config.bytes_padding_added += padding_len + sizeof(padding_header_t);

	return total_size;
}

size_t dpi_padding_remove(uint8_t *buffer, size_t total_len) {
	if(!buffer || total_len < sizeof(padding_header_t)) {
		return total_len;
	}

	padding_header_t *hdr = (padding_header_t *)buffer;

	/* Check magic and flags */
	if(hdr->magic != PADDING_MAGIC || !(hdr->flags & PADDING_FLAG_HAS_PADDING)) {
		/* No padding header, return as-is */
		return total_len;
	}

	uint16_t orig_len = ntohs(hdr->orig_len);
	uint16_t padding_len = ntohs(hdr->padding_len);

	/* Validate lengths */
	if(sizeof(padding_header_t) + orig_len + padding_len > total_len) {
		/* Invalid header, return as-is */
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Invalid padding header in packet");
		return total_len;
	}

	/* Move original data to start of buffer */
	memmove(buffer, buffer + sizeof(padding_header_t), orig_len);

	return orig_len;
}

/* ============================================================================
 * 3. ACTIVE PROBING PROTECTION
 * ============================================================================
 */

bool dpi_probing_verify_timestamp(uint64_t timestamp) {
	if(!dpi_config.probing.enabled) {
		return true;
	}

	time_t now = time(NULL);
	int64_t diff = (int64_t)now - (int64_t)timestamp;

	if(diff < 0) diff = -diff; /* abs() */

	if((uint32_t)diff > dpi_config.probing.max_time_diff) {
		dpi_config.probes_blocked++;
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Blocked probe: timestamp too old/future (diff=%ld)", (long)diff);
		return false;
	}

	return true;
}

bool dpi_probing_check_replay(uint64_t nonce) {
	if(!dpi_config.probing.enabled || !dpi_config.probing.seen_nonces) {
		return true; /* Not a replay (protection disabled) */
	}

	/* Search for nonce in circular buffer */
	for(size_t i = 0; i < dpi_config.probing.nonce_count; i++) {
		if(dpi_config.probing.seen_nonces[i] == nonce) {
			dpi_config.replays_blocked++;
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Blocked replay attack: nonce already seen");
			return false;
		}
	}

	return true;
}

void dpi_probing_record_nonce(uint64_t nonce) {
	if(!dpi_config.probing.enabled || !dpi_config.probing.seen_nonces) {
		return;
	}

	/* Add to circular buffer */
	dpi_config.probing.seen_nonces[dpi_config.probing.nonce_index] = nonce;
	dpi_config.probing.nonce_index = (dpi_config.probing.nonce_index + 1) % dpi_config.probing.nonce_capacity;
	if(dpi_config.probing.nonce_count < dpi_config.probing.nonce_capacity) {
		dpi_config.probing.nonce_count++;
	}
}

uint64_t dpi_probing_generate_nonce(void) {
	uint64_t nonce;
	uint8_t *bytes = (uint8_t *)&nonce;
	for(size_t i = 0; i < sizeof(nonce); i++) {
		bytes[i] = (uint8_t)(rand() & 0xFF);
	}
	return nonce;
}

/* ============================================================================
 * 4. TRAFFIC SHAPING
 * ============================================================================
 */

void dpi_shaping_pre_send(size_t packet_size) {
	if(!dpi_config.traffic_shaping_enabled) {
		return;
	}

	(void)packet_size; /* Currently unused, for future use */

	switch(dpi_config.shaping.pattern) {
	case PATTERN_HTTP:
		/* HTTP pattern: occasional long delays between "pages" */
		if(rand() % 20 == 0) {
			usleep(dpi_config.shaping.think_time_ms * 1000);
		}
		break;

	case PATTERN_VIDEO:
		/* Video pattern: steady rate with occasional buffering */
		usleep(5000); /* 5ms between chunks */
		break;

	case PATTERN_BROWSING:
		/* Browsing: bursts followed by think time */
		if(rand() % 10 == 0) {
			usleep(dpi_config.shaping.think_time_ms * 1000 / 2);
		}
		break;

	default:
		break;
	}
}

void dpi_shaping_post_receive(size_t packet_size) {
	(void)packet_size;
	/* Reserved for future use */
}

/* ============================================================================
 * STATISTICS
 * ============================================================================
 */

void dpi_evasion_log_stats(void) {
	logger(DEBUG_ALWAYS, LOG_INFO, "DPI Evasion Statistics:");
	logger(DEBUG_ALWAYS, LOG_INFO, "  Packets delayed: %lu", (unsigned long)dpi_config.packets_delayed);
	logger(DEBUG_ALWAYS, LOG_INFO, "  Packets padded: %lu", (unsigned long)dpi_config.packets_padded);
	logger(DEBUG_ALWAYS, LOG_INFO, "  Padding bytes added: %lu", (unsigned long)dpi_config.bytes_padding_added);
	logger(DEBUG_ALWAYS, LOG_INFO, "  Probes blocked: %lu", (unsigned long)dpi_config.probes_blocked);
	logger(DEBUG_ALWAYS, LOG_INFO, "  Replays blocked: %lu", (unsigned long)dpi_config.replays_blocked);
}
