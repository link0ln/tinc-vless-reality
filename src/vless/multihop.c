/*
    multihop.c -- Multi-hop routing implementation
    Copyright (C) 2025 tinc-vless contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"
#include "multihop.h"
#include "logger.h"
#include "conf.h"
#include "names.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

/* Multi-hop magic bytes */
#define MULTIHOP_MAGIC_0 0x4D  /* 'M' */
#define MULTIHOP_MAGIC_1 0x48  /* 'H' */
#define MULTIHOP_VERSION 1

/* Header size */
#define MULTIHOP_HEADER_SIZE sizeof(multihop_header_t)

/* Global configuration */
static multihop_config_t mh_config;
static multihop_stats_t mh_stats;
static uint32_t next_circuit_id = 1;

/* Active circuits */
#define MAX_ACTIVE_CIRCUITS 16
static multihop_circuit_t *active_circuits[MAX_ACTIVE_CIRCUITS];
static int active_circuit_count = 0;

/* Initialize multi-hop subsystem */
void multihop_init(void) {
    memset(&mh_config, 0, sizeof(mh_config));
    memset(&mh_stats, 0, sizeof(mh_stats));
    memset(active_circuits, 0, sizeof(active_circuits));

    mh_config.enabled = false;
    mh_config.hop_count = 2;
    mh_config.selection = MULTIHOP_SELECT_RANDOM;
    mh_config.timeout_sec = 30;
    mh_config.circuit_lifetime_sec = 300; /* 5 minutes default */
    mh_config.strict_order = false;
    mh_config.rr_index = 0;

    srand((unsigned int)time(NULL));

    logger(DEBUG_ALWAYS, LOG_INFO, "Multi-hop routing subsystem initialized");
}

/* Cleanup multi-hop subsystem */
void multihop_exit(void) {
    /* Destroy all active circuits */
    for (int i = 0; i < MAX_ACTIVE_CIRCUITS; i++) {
        if (active_circuits[i]) {
            multihop_destroy_circuit(active_circuits[i]);
            active_circuits[i] = NULL;
        }
    }
    active_circuit_count = 0;

    logger(DEBUG_ALWAYS, LOG_INFO, "Multi-hop routing subsystem shutdown");
}

/* Parse selection strategy from string */
static multihop_selection_t parse_selection(const char *str) {
    if (!str) return MULTIHOP_SELECT_RANDOM;

    if (strcasecmp(str, "fixed") == 0) return MULTIHOP_SELECT_FIXED;
    if (strcasecmp(str, "random") == 0) return MULTIHOP_SELECT_RANDOM;
    if (strcasecmp(str, "latency") == 0) return MULTIHOP_SELECT_LATENCY;
    if (strcasecmp(str, "round-robin") == 0 || strcasecmp(str, "roundrobin") == 0)
        return MULTIHOP_SELECT_ROUND_ROBIN;

    return MULTIHOP_SELECT_RANDOM;
}

/* Load configuration from tinc.conf */
void multihop_load_config(void) {
    char *value;

    /* VLESSMultiHop = yes|no */
    if (get_config_string(lookup_config(config_tree, "VLESSMultiHop"), &value)) {
        mh_config.enabled = (strcasecmp(value, "yes") == 0 ||
                             strcasecmp(value, "true") == 0 ||
                             strcasecmp(value, "1") == 0);
        free(value);
    }

    if (!mh_config.enabled) {
        logger(DEBUG_ALWAYS, LOG_INFO, "Multi-hop routing: disabled");
        return;
    }

    /* VLESSHopCount = N (1-5) */
    int hop_count;
    if (get_config_int(lookup_config(config_tree, "VLESSHopCount"), &hop_count)) {
        if (hop_count >= 1 && hop_count <= MULTIHOP_MAX_HOPS) {
            mh_config.hop_count = (uint8_t)hop_count;
        } else {
            logger(DEBUG_ALWAYS, LOG_WARNING,
                   "VLESSHopCount out of range (1-%d), using default: 2",
                   MULTIHOP_MAX_HOPS);
        }
    }

    /* VLESSHopSelection = random|fixed|latency|round-robin */
    if (get_config_string(lookup_config(config_tree, "VLESSHopSelection"), &value)) {
        mh_config.selection = parse_selection(value);
        free(value);
    }

    /* VLESSHopTimeout = seconds */
    int timeout;
    if (get_config_int(lookup_config(config_tree, "VLESSHopTimeout"), &timeout)) {
        if (timeout > 0 && timeout <= 300) {
            mh_config.timeout_sec = (uint32_t)timeout;
        }
    }

    /* VLESSCircuitLifetime = seconds */
    int lifetime;
    if (get_config_int(lookup_config(config_tree, "VLESSCircuitLifetime"), &lifetime)) {
        if (lifetime > 0) {
            mh_config.circuit_lifetime_sec = (uint32_t)lifetime;
        }
    }

    /* VLESSHopStrictOrder = yes|no */
    if (get_config_string(lookup_config(config_tree, "VLESSHopStrictOrder"), &value)) {
        mh_config.strict_order = (strcasecmp(value, "yes") == 0);
        free(value);
    }

    /* VLESSHopNodes = node1,node2,node3 */
    if (get_config_string(lookup_config(config_tree, "VLESSHopNodes"), &value)) {
        char *token = strtok(value, ",");
        while (token && mh_config.available_count < MULTIHOP_MAX_NODES) {
            /* Trim whitespace */
            while (*token == ' ') token++;
            char *end = token + strlen(token) - 1;
            while (end > token && *end == ' ') *end-- = '\0';

            if (strlen(token) > 0) {
                strncpy(mh_config.available_nodes[mh_config.available_count].name,
                        token, sizeof(mh_config.available_nodes[0].name) - 1);
                mh_config.available_nodes[mh_config.available_count].state = HOP_STATE_DISCONNECTED;
                mh_config.available_nodes[mh_config.available_count].fd = -1;
                mh_config.available_count++;
            }
            token = strtok(NULL, ",");
        }
        free(value);
    }

    logger(DEBUG_ALWAYS, LOG_INFO,
           "Multi-hop routing: enabled, hops=%d, selection=%s, nodes=%d, timeout=%ds",
           mh_config.hop_count,
           mh_config.selection == MULTIHOP_SELECT_FIXED ? "fixed" :
           mh_config.selection == MULTIHOP_SELECT_RANDOM ? "random" :
           mh_config.selection == MULTIHOP_SELECT_LATENCY ? "latency" : "round-robin",
           mh_config.available_count,
           mh_config.timeout_sec);
}

/* Get configuration */
multihop_config_t *multihop_get_config(void) {
    return &mh_config;
}

/* Create a new circuit */
multihop_circuit_t *multihop_create_circuit(void) {
    if (!mh_config.enabled) {
        return NULL;
    }

    if (mh_config.available_count < mh_config.hop_count) {
        logger(DEBUG_ALWAYS, LOG_ERR,
               "Not enough hop nodes: have %d, need %d",
               mh_config.available_count, mh_config.hop_count);
        mh_stats.circuits_failed++;
        return NULL;
    }

    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < MAX_ACTIVE_CIRCUITS; i++) {
        if (!active_circuits[i]) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        logger(DEBUG_ALWAYS, LOG_ERR, "No free circuit slots");
        mh_stats.circuits_failed++;
        return NULL;
    }

    multihop_circuit_t *circuit = calloc(1, sizeof(multihop_circuit_t));
    if (!circuit) {
        mh_stats.circuits_failed++;
        return NULL;
    }

    circuit->circuit_id = next_circuit_id++;
    circuit->hop_count = mh_config.hop_count;
    circuit->established = false;
    circuit->created_at = time(NULL);
    circuit->expires_at = circuit->created_at + mh_config.circuit_lifetime_sec;

    /* Select hops based on strategy */
    hop_node_t *selected = multihop_select_nodes(mh_config.hop_count);
    if (!selected) {
        free(circuit);
        mh_stats.circuits_failed++;
        return NULL;
    }

    memcpy(circuit->hops, selected, mh_config.hop_count * sizeof(hop_node_t));
    free(selected);

    /* Initialize hop states */
    for (int i = 0; i < circuit->hop_count; i++) {
        circuit->hops[i].state = HOP_STATE_DISCONNECTED;
        circuit->hops[i].fd = -1;
    }

    active_circuits[slot] = circuit;
    active_circuit_count++;
    mh_stats.circuits_created++;

    logger(DEBUG_PROTOCOL, LOG_DEBUG,
           "Created circuit %u with %d hops",
           circuit->circuit_id, circuit->hop_count);

    return circuit;
}

/* Select nodes based on strategy */
hop_node_t *multihop_select_nodes(uint8_t count) {
    if (count > mh_config.available_count) {
        return NULL;
    }

    hop_node_t *selected = calloc(count, sizeof(hop_node_t));
    if (!selected) return NULL;

    switch (mh_config.selection) {
    case MULTIHOP_SELECT_FIXED:
        /* Use nodes in order */
        for (int i = 0; i < count; i++) {
            memcpy(&selected[i], &mh_config.available_nodes[i], sizeof(hop_node_t));
        }
        break;

    case MULTIHOP_SELECT_RANDOM:
        {
            /* Fisher-Yates shuffle of indices */
            int indices[MULTIHOP_MAX_NODES];
            for (int i = 0; i < mh_config.available_count; i++) {
                indices[i] = i;
            }
            for (int i = mh_config.available_count - 1; i > 0; i--) {
                int j = rand() % (i + 1);
                int tmp = indices[i];
                indices[i] = indices[j];
                indices[j] = tmp;
            }
            for (int i = 0; i < count; i++) {
                memcpy(&selected[i], &mh_config.available_nodes[indices[i]],
                       sizeof(hop_node_t));
            }
        }
        break;

    case MULTIHOP_SELECT_LATENCY:
        {
            /* Sort by latency (simple selection sort) */
            int indices[MULTIHOP_MAX_NODES];
            for (int i = 0; i < mh_config.available_count; i++) {
                indices[i] = i;
            }
            for (int i = 0; i < count; i++) {
                int min_idx = i;
                for (int j = i + 1; j < mh_config.available_count; j++) {
                    if (mh_config.available_nodes[indices[j]].latency_ms <
                        mh_config.available_nodes[indices[min_idx]].latency_ms) {
                        min_idx = j;
                    }
                }
                if (min_idx != i) {
                    int tmp = indices[i];
                    indices[i] = indices[min_idx];
                    indices[min_idx] = tmp;
                }
                memcpy(&selected[i], &mh_config.available_nodes[indices[i]],
                       sizeof(hop_node_t));
            }
        }
        break;

    case MULTIHOP_SELECT_ROUND_ROBIN:
        {
            for (int i = 0; i < count; i++) {
                int idx = (mh_config.rr_index + i) % mh_config.available_count;
                memcpy(&selected[i], &mh_config.available_nodes[idx], sizeof(hop_node_t));
            }
            mh_config.rr_index = (mh_config.rr_index + count) % mh_config.available_count;
        }
        break;
    }

    return selected;
}

/* Establish circuit by connecting to all hops */
bool multihop_establish_circuit(multihop_circuit_t *circuit) {
    if (!circuit || circuit->established) {
        return circuit ? circuit->established : false;
    }

    logger(DEBUG_PROTOCOL, LOG_DEBUG,
           "Establishing circuit %u with %d hops",
           circuit->circuit_id, circuit->hop_count);

    /* Connect to each hop in sequence */
    for (int i = 0; i < circuit->hop_count; i++) {
        hop_node_t *hop = &circuit->hops[i];

        if (strlen(hop->address) == 0) {
            logger(DEBUG_ALWAYS, LOG_ERR,
                   "Hop %d (%s) has no address configured",
                   i, hop->name);
            mh_stats.hop_failures++;
            return false;
        }

        hop->state = HOP_STATE_CONNECTING;

        /* Resolve address */
        struct addrinfo hints = {0}, *result;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%u", hop->port);

        int ret = getaddrinfo(hop->address, port_str, &hints, &result);
        if (ret != 0) {
            logger(DEBUG_ALWAYS, LOG_ERR,
                   "Failed to resolve hop %d (%s): %s",
                   i, hop->address, gai_strerror(ret));
            hop->state = HOP_STATE_ERROR;
            mh_stats.hop_failures++;
            return false;
        }

        /* Create socket */
        hop->fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (hop->fd < 0) {
            logger(DEBUG_ALWAYS, LOG_ERR,
                   "Failed to create socket for hop %d: %s",
                   i, strerror(errno));
            freeaddrinfo(result);
            hop->state = HOP_STATE_ERROR;
            mh_stats.hop_failures++;
            return false;
        }

        /* Set non-blocking for timeout */
        int flags = fcntl(hop->fd, F_GETFL, 0);
        fcntl(hop->fd, F_SETFL, flags | O_NONBLOCK);

        /* Connect with timeout */
        ret = connect(hop->fd, result->ai_addr, result->ai_addrlen);
        if (ret < 0 && errno != EINPROGRESS) {
            logger(DEBUG_ALWAYS, LOG_ERR,
                   "Failed to connect to hop %d (%s:%u): %s",
                   i, hop->address, hop->port, strerror(errno));
            close(hop->fd);
            hop->fd = -1;
            freeaddrinfo(result);
            hop->state = HOP_STATE_ERROR;
            mh_stats.hop_failures++;
            return false;
        }

        /* Wait for connection with timeout */
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(hop->fd, &write_fds);

        struct timeval tv;
        tv.tv_sec = mh_config.timeout_sec;
        tv.tv_usec = 0;

        ret = select(hop->fd + 1, NULL, &write_fds, NULL, &tv);
        if (ret <= 0) {
            logger(DEBUG_ALWAYS, LOG_ERR,
                   "Connection to hop %d (%s:%u) timed out",
                   i, hop->address, hop->port);
            close(hop->fd);
            hop->fd = -1;
            freeaddrinfo(result);
            hop->state = HOP_STATE_ERROR;
            mh_stats.hop_failures++;
            return false;
        }

        /* Check for connection error */
        int error = 0;
        socklen_t len = sizeof(error);
        getsockopt(hop->fd, SOL_SOCKET, SO_ERROR, &error, &len);
        if (error) {
            logger(DEBUG_ALWAYS, LOG_ERR,
                   "Connection to hop %d failed: %s",
                   i, strerror(error));
            close(hop->fd);
            hop->fd = -1;
            freeaddrinfo(result);
            hop->state = HOP_STATE_ERROR;
            mh_stats.hop_failures++;
            return false;
        }

        freeaddrinfo(result);

        /* Restore blocking mode */
        fcntl(hop->fd, F_SETFL, flags);

        hop->state = HOP_STATE_READY;
        hop->last_activity = time(NULL);

        logger(DEBUG_PROTOCOL, LOG_DEBUG,
               "Connected to hop %d: %s:%u",
               i, hop->address, hop->port);
    }

    circuit->established = true;
    logger(DEBUG_ALWAYS, LOG_INFO,
           "Circuit %u established with %d hops",
           circuit->circuit_id, circuit->hop_count);

    return true;
}

/* Destroy a circuit */
void multihop_destroy_circuit(multihop_circuit_t *circuit) {
    if (!circuit) return;

    /* Close all hop connections */
    for (int i = 0; i < circuit->hop_count; i++) {
        if (circuit->hops[i].fd >= 0) {
            close(circuit->hops[i].fd);
            circuit->hops[i].fd = -1;
        }
        circuit->hops[i].state = HOP_STATE_DISCONNECTED;
    }

    /* Remove from active circuits */
    for (int i = 0; i < MAX_ACTIVE_CIRCUITS; i++) {
        if (active_circuits[i] == circuit) {
            active_circuits[i] = NULL;
            active_circuit_count--;
            break;
        }
    }

    logger(DEBUG_PROTOCOL, LOG_DEBUG,
           "Destroyed circuit %u (sent: %lu, received: %lu)",
           circuit->circuit_id, circuit->bytes_sent, circuit->bytes_received);

    free(circuit);
}

/* Check if circuit is still valid */
bool multihop_is_circuit_valid(multihop_circuit_t *circuit) {
    if (!circuit || !circuit->established) {
        return false;
    }

    /* Check expiration */
    if (time(NULL) >= circuit->expires_at) {
        return false;
    }

    /* Check all hops are ready */
    for (int i = 0; i < circuit->hop_count; i++) {
        if (circuit->hops[i].state != HOP_STATE_READY ||
            circuit->hops[i].fd < 0) {
            return false;
        }
    }

    return true;
}

/* Rotate circuit (create new one, destroy old) */
bool multihop_rotate_circuit(multihop_circuit_t *circuit) {
    if (!circuit) return false;

    logger(DEBUG_ALWAYS, LOG_INFO, "Rotating circuit %u", circuit->circuit_id);

    /* Create new circuit */
    multihop_circuit_t *new_circuit = multihop_create_circuit();
    if (!new_circuit) {
        return false;
    }

    /* Establish new circuit */
    if (!multihop_establish_circuit(new_circuit)) {
        multihop_destroy_circuit(new_circuit);
        return false;
    }

    /* Destroy old circuit */
    multihop_destroy_circuit(circuit);

    mh_stats.circuit_rotations++;
    return true;
}

/* Add a node to the pool */
bool multihop_add_node(const char *name, const char *address,
                        uint16_t port, const char *uuid) {
    if (!name || !address || mh_config.available_count >= MULTIHOP_MAX_NODES) {
        return false;
    }

    hop_node_t *node = &mh_config.available_nodes[mh_config.available_count];
    strncpy(node->name, name, sizeof(node->name) - 1);
    strncpy(node->address, address, sizeof(node->address) - 1);
    node->port = port;
    if (uuid) {
        strncpy(node->uuid, uuid, sizeof(node->uuid) - 1);
    }
    node->state = HOP_STATE_DISCONNECTED;
    node->fd = -1;
    node->latency_ms = UINT32_MAX; /* Unknown latency */

    mh_config.available_count++;

    logger(DEBUG_PROTOCOL, LOG_DEBUG,
           "Added hop node: %s (%s:%u)",
           name, address, port);

    return true;
}

/* Remove a node from the pool */
bool multihop_remove_node(const char *name) {
    if (!name) return false;

    for (int i = 0; i < mh_config.available_count; i++) {
        if (strcmp(mh_config.available_nodes[i].name, name) == 0) {
            /* Shift remaining nodes */
            for (int j = i; j < mh_config.available_count - 1; j++) {
                memcpy(&mh_config.available_nodes[j],
                       &mh_config.available_nodes[j + 1],
                       sizeof(hop_node_t));
            }
            mh_config.available_count--;
            return true;
        }
    }
    return false;
}

/* Update latency for a node */
void multihop_update_latency(const char *name, uint32_t latency_ms) {
    if (!name) return;

    for (int i = 0; i < mh_config.available_count; i++) {
        if (strcmp(mh_config.available_nodes[i].name, name) == 0) {
            mh_config.available_nodes[i].latency_ms = latency_ms;
            break;
        }
    }
}

/* Encapsulate packet for multi-hop transmission */
size_t multihop_encapsulate(multihop_circuit_t *circuit,
                             const uint8_t *data, size_t len,
                             uint8_t *out, size_t out_len) {
    if (!circuit || !data || !out || len == 0) {
        return 0;
    }

    size_t total_len = MULTIHOP_HEADER_SIZE + len;
    if (total_len > out_len) {
        return 0;
    }

    /* Build header */
    multihop_header_t *hdr = (multihop_header_t *)out;
    hdr->magic[0] = MULTIHOP_MAGIC_0;
    hdr->magic[1] = MULTIHOP_MAGIC_1;
    hdr->version = MULTIHOP_VERSION;
    hdr->hop_index = 0;
    hdr->total_hops = circuit->hop_count;
    hdr->circuit_id = htonl(circuit->circuit_id);
    hdr->payload_len = htons((uint16_t)len);
    hdr->reserved[0] = 0;
    hdr->reserved[1] = 0;

    /* Copy payload */
    memcpy(out + MULTIHOP_HEADER_SIZE, data, len);

    circuit->bytes_sent += total_len;
    mh_stats.packets_forwarded++;
    mh_stats.bytes_forwarded += total_len;

    return total_len;
}

/* Decapsulate multi-hop packet */
size_t multihop_decapsulate(const uint8_t *data, size_t len,
                             uint8_t *out, size_t out_len,
                             uint8_t *hop_index, uint32_t *circuit_id) {
    if (!data || len < MULTIHOP_HEADER_SIZE || !out) {
        return 0;
    }

    multihop_header_t *hdr = (multihop_header_t *)data;

    /* Verify magic */
    if (hdr->magic[0] != MULTIHOP_MAGIC_0 || hdr->magic[1] != MULTIHOP_MAGIC_1) {
        return 0;
    }

    /* Verify version */
    if (hdr->version != MULTIHOP_VERSION) {
        return 0;
    }

    uint16_t payload_len = ntohs(hdr->payload_len);
    if (MULTIHOP_HEADER_SIZE + payload_len > len || payload_len > out_len) {
        return 0;
    }

    if (hop_index) {
        *hop_index = hdr->hop_index;
    }
    if (circuit_id) {
        *circuit_id = ntohl(hdr->circuit_id);
    }

    /* Copy payload */
    memcpy(out, data + MULTIHOP_HEADER_SIZE, payload_len);

    return payload_len;
}

/* Check if packet is a multi-hop relay packet */
bool multihop_is_relay_packet(const uint8_t *data, size_t len) {
    if (!data || len < MULTIHOP_HEADER_SIZE) {
        return false;
    }

    return (data[0] == MULTIHOP_MAGIC_0 && data[1] == MULTIHOP_MAGIC_1);
}

/* Forward packet to next hop (for relay nodes) */
ssize_t multihop_forward(int in_fd, int out_fd, uint8_t *buf, size_t buf_len) {
    if (in_fd < 0 || out_fd < 0 || !buf || buf_len < MULTIHOP_HEADER_SIZE) {
        return -1;
    }

    /* Read packet */
    ssize_t received = recv(in_fd, buf, buf_len, 0);
    if (received <= 0) {
        return received;
    }

    /* Verify it's a multi-hop packet */
    if (!multihop_is_relay_packet(buf, received)) {
        /* Not a multi-hop packet, forward as-is */
        return send(out_fd, buf, received, 0);
    }

    multihop_header_t *hdr = (multihop_header_t *)buf;

    /* Increment hop index */
    hdr->hop_index++;

    /* Forward to next hop */
    ssize_t sent = send(out_fd, buf, received, 0);

    if (sent > 0) {
        mh_stats.packets_forwarded++;
        mh_stats.bytes_forwarded += sent;
    }

    return sent;
}

/* Get next hop for a circuit */
hop_node_t *multihop_get_next_hop(uint32_t circuit_id, uint8_t hop_index) {
    for (int i = 0; i < MAX_ACTIVE_CIRCUITS; i++) {
        if (active_circuits[i] &&
            active_circuits[i]->circuit_id == circuit_id) {
            if (hop_index < active_circuits[i]->hop_count) {
                return &active_circuits[i]->hops[hop_index];
            }
            break;
        }
    }
    return NULL;
}

/* Log statistics */
void multihop_log_stats(void) {
    if (!mh_config.enabled) {
        return;
    }

    logger(DEBUG_ALWAYS, LOG_INFO,
           "Multi-hop Statistics:\n"
           "  Circuits created: %lu\n"
           "  Circuits failed: %lu\n"
           "  Packets forwarded: %lu\n"
           "  Bytes forwarded: %lu\n"
           "  Hop failures: %lu\n"
           "  Circuit rotations: %lu\n"
           "  Active circuits: %d",
           mh_stats.circuits_created,
           mh_stats.circuits_failed,
           mh_stats.packets_forwarded,
           mh_stats.bytes_forwarded,
           mh_stats.hop_failures,
           mh_stats.circuit_rotations,
           active_circuit_count);
}

/* Get statistics */
multihop_stats_t *multihop_get_stats(void) {
    return &mh_stats;
}
