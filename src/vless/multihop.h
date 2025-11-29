/*
    multihop.h -- Multi-hop routing for enhanced anonymity
    Copyright (C) 2025 tinc-vless contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#ifndef TINC_VLESS_MULTIHOP_H
#define TINC_VLESS_MULTIHOP_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * Multi-hop Routing for DPI Evasion
 *
 * Routes traffic through multiple VPN nodes in a chain:
 *   Client -> Hop1 -> Hop2 -> Hop3 -> Destination
 *
 * Each hop only knows about its immediate neighbors, providing
 * traffic analysis resistance similar to Tor but simpler.
 *
 * Configuration in tinc.conf:
 *   VLESSMultiHop = yes
 *   VLESSHopCount = 2
 *   VLESSHopNodes = relay1,relay2,relay3
 *   VLESSHopSelection = random|fixed|latency
 *   VLESSHopTimeout = 30
 */

/* Maximum hops in chain (excluding entry and exit) */
#define MULTIHOP_MAX_HOPS 5

/* Maximum nodes that can be used as hops */
#define MULTIHOP_MAX_NODES 32

/* Hop selection strategies */
typedef enum multihop_selection_t {
    MULTIHOP_SELECT_FIXED = 0,      /* Use nodes in order specified */
    MULTIHOP_SELECT_RANDOM,         /* Random selection from pool */
    MULTIHOP_SELECT_LATENCY,        /* Select lowest latency nodes */
    MULTIHOP_SELECT_ROUND_ROBIN     /* Rotate through available nodes */
} multihop_selection_t;

/* State of a single hop */
typedef enum hop_state_t {
    HOP_STATE_DISCONNECTED = 0,
    HOP_STATE_CONNECTING,
    HOP_STATE_HANDSHAKING,
    HOP_STATE_READY,
    HOP_STATE_ERROR
} hop_state_t;

/* Information about a single hop node */
typedef struct hop_node_t {
    char name[64];                  /* Node name from hosts.json */
    char address[256];              /* IP address or hostname */
    uint16_t port;                  /* Port number */
    char uuid[37];                  /* VLESS UUID for this hop */
    hop_state_t state;              /* Current connection state */
    int fd;                         /* Socket file descriptor */
    uint32_t latency_ms;            /* Measured latency in ms */
    uint64_t bytes_forwarded;       /* Total bytes forwarded through this hop */
    time_t last_activity;           /* Last activity timestamp */
} hop_node_t;

/* Multi-hop circuit (chain of hops) */
typedef struct multihop_circuit_t {
    uint32_t circuit_id;            /* Unique circuit identifier */
    uint8_t hop_count;              /* Number of hops in circuit */
    hop_node_t hops[MULTIHOP_MAX_HOPS];  /* Array of hops */
    bool established;               /* Is circuit fully established? */
    time_t created_at;              /* When circuit was created */
    time_t expires_at;              /* When circuit expires (for rotation) */
    uint64_t bytes_sent;            /* Total bytes sent through circuit */
    uint64_t bytes_received;        /* Total bytes received through circuit */
} multihop_circuit_t;

/* Multi-hop configuration */
typedef struct multihop_config_t {
    bool enabled;                   /* Is multi-hop enabled? */
    uint8_t hop_count;              /* Number of hops to use */
    multihop_selection_t selection; /* Hop selection strategy */
    uint32_t timeout_sec;           /* Connection timeout per hop */
    uint32_t circuit_lifetime_sec;  /* How long before rotating circuit */
    bool strict_order;              /* Maintain strict hop order */

    /* Pool of available hop nodes */
    hop_node_t available_nodes[MULTIHOP_MAX_NODES];
    uint8_t available_count;

    /* Round-robin state */
    uint8_t rr_index;
} multihop_config_t;

/* Encapsulated packet header for multi-hop */
typedef struct __attribute__((packed)) multihop_header_t {
    uint8_t magic[2];               /* 0xMH - Multi-Hop marker */
    uint8_t version;                /* Protocol version */
    uint8_t hop_index;              /* Current hop in chain (0 = first) */
    uint8_t total_hops;             /* Total hops in circuit */
    uint32_t circuit_id;            /* Circuit identifier */
    uint16_t payload_len;           /* Payload length */
    uint8_t reserved[2];            /* Reserved for future use */
} multihop_header_t;

/* Statistics */
typedef struct multihop_stats_t {
    uint64_t circuits_created;      /* Total circuits created */
    uint64_t circuits_failed;       /* Failed circuit establishments */
    uint64_t packets_forwarded;     /* Packets forwarded through hops */
    uint64_t bytes_forwarded;       /* Total bytes forwarded */
    uint64_t hop_failures;          /* Individual hop failures */
    uint64_t circuit_rotations;     /* Number of circuit rotations */
} multihop_stats_t;

/* Initialization and cleanup */
extern void multihop_init(void);
extern void multihop_exit(void);
extern void multihop_load_config(void);

/* Get configuration */
extern multihop_config_t *multihop_get_config(void);

/* Circuit management */
extern multihop_circuit_t *multihop_create_circuit(void);
extern bool multihop_establish_circuit(multihop_circuit_t *circuit);
extern void multihop_destroy_circuit(multihop_circuit_t *circuit);
extern bool multihop_is_circuit_valid(multihop_circuit_t *circuit);
extern bool multihop_rotate_circuit(multihop_circuit_t *circuit);

/* Node management */
extern bool multihop_add_node(const char *name, const char *address,
                               uint16_t port, const char *uuid);
extern bool multihop_remove_node(const char *name);
extern hop_node_t *multihop_select_nodes(uint8_t count);
extern void multihop_update_latency(const char *name, uint32_t latency_ms);

/* Packet encapsulation */
extern size_t multihop_encapsulate(multihop_circuit_t *circuit,
                                    const uint8_t *data, size_t len,
                                    uint8_t *out, size_t out_len);
extern size_t multihop_decapsulate(const uint8_t *data, size_t len,
                                    uint8_t *out, size_t out_len,
                                    uint8_t *hop_index, uint32_t *circuit_id);

/* Forwarding for relay nodes */
extern ssize_t multihop_forward(int in_fd, int out_fd,
                                 uint8_t *buf, size_t buf_len);
extern bool multihop_is_relay_packet(const uint8_t *data, size_t len);
extern hop_node_t *multihop_get_next_hop(uint32_t circuit_id, uint8_t hop_index);

/* Statistics */
extern void multihop_log_stats(void);
extern multihop_stats_t *multihop_get_stats(void);

#endif /* TINC_VLESS_MULTIHOP_H */
