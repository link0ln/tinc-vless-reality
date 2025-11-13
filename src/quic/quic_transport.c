/*
    quic_transport.c -- VPN transport over QUIC implementation (main)
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "../logger.h"
#include "../xalloc.h"
#include "../splay_tree.h"
#include "../netutl.h"
#include "../names.h"
#include "../node.h"
#include "../connection.h"
#include "../meta.h"
#include "../net.h"
#include "../protocol.h"
#include "quic_transport.h"
#include "quic_internal.h"
#include <quiche.h>
#include "quic.h"
#include "quic_reality.h"
#include "quic_fingerprint.h"
#include "../event.h"

/* Global QUIC manager */
quic_manager_t *quic_manager = NULL;
static timeout_t quic_timer;

/* External configuration variables */
extern bool quic_migration_enabled;
extern int quic_hop_interval_ms;
extern int quic_retry_max_delay_ms;
extern int quic_retry_initial_delay_ms;
extern bool quic_retry_jitter_enabled;
extern bool quic_keepalive_enabled;
extern int quic_keepalive_interval_ms;
extern bool quic_cleanup_enabled;
extern int quic_cleanup_interval_ms;
extern int quic_session_max_idle_ms;

/* External Reality configuration (from conf.h) */
extern bool vless_reality_enabled;
extern char *vless_reality_dest;
extern int vless_reality_dest_port;
extern char *vless_reality_server_name;
extern char *vless_reality_public_key;
extern char *vless_reality_private_key;
extern char *vless_reality_short_id;
extern char *vless_reality_fingerprint;

/* Transport mode */
transport_mode_t transport_mode = TRANSPORT_UDP;

/* ============================================================================
 * Timeout Handler
 * ============================================================================ */

static void quic_timeout_handler(void *data) {
	(void)data;
	if(!quic_manager || !quic_manager->connections || !quic_manager->connections->head) {
		/* Reschedule conservatively */
		timeout_set(&quic_timer, &(struct timeval){0, 100000});
		return;
	}

	/* Compute minimal timeout across connections */
	uint64_t min_ns = UINT64_MAX;
	for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
		quic_conn_t *qconn = (quic_conn_t *)n->data;
		if(!qconn || !qconn->conn) continue;
		uint64_t ns = quiche_conn_timeout_as_nanos(qconn->conn);
		if(ns > 0 && ns < min_ns) {
			min_ns = ns;
		}
	}

	/* Drive timeouts now */
	for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
		quic_conn_t *qconn = (quic_conn_t *)n->data;
		if(!qconn || !qconn->conn) continue;
		quiche_conn_on_timeout(qconn->conn);
		while(true) {
			ssize_t sent = quic_conn_send(qconn);
			if(sent <= 0) break;
		}
	}

	/* Reschedule at minimal timeout (fallback 50ms) */
	if(min_ns == UINT64_MAX) {
		timeout_set(&quic_timer, &(struct timeval){0, 50000});
	} else {
		struct timeval tv = { .tv_sec = (time_t)(min_ns / 1000000000ULL), .tv_usec = (suseconds_t)((min_ns % 1000000000ULL) / 1000ULL) };
		timeout_set(&quic_timer, &tv);
	}
}

/* ============================================================================
 * Initialization and Shutdown
 * ============================================================================ */

/* Initialize QUIC transport */
bool quic_transport_init(listen_socket_t *sockets, int num_sockets) {
	logger(DEBUG_ALWAYS, LOG_INFO, "quic_transport_init called: sockets=%p, num_sockets=%d", (void*)sockets, num_sockets);

	if(!quic_init()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize QUIC subsystem (quic_init returned false)");
		return false;
	}
	logger(DEBUG_ALWAYS, LOG_INFO, "QUIC subsystem (quiche) initialized successfully");

	if(!sockets || num_sockets <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "No listen sockets provided for QUIC (sockets=%p, num_sockets=%d)",
		       (void*)sockets, num_sockets);
		return false;
	}
	logger(DEBUG_ALWAYS, LOG_INFO, "Listen sockets validated: %d sockets available", num_sockets);

	quic_manager = xzalloc(sizeof(quic_manager_t));

	/* Store references to tinc's listen sockets */
	quic_manager->sockets = xzalloc(num_sockets * sizeof(listen_socket_t *));
	for(int i = 0; i < num_sockets; i++) {
		quic_manager->sockets[i] = &sockets[i];
	}
	quic_manager->num_sockets = num_sockets;

	/* Create connection tree */
	quic_manager->connections = splay_alloc_tree(connection_compare, NULL);

	/* Create connection ID map for demultiplexing */
	quic_manager->conn_id_map = splay_alloc_tree(conn_id_compare, NULL);

	/* Create client configuration */
	quic_manager->client_config = quic_config_new(false);

	if(!quic_manager->client_config) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create QUIC client config");
		free(quic_manager->sockets);
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	/* Apply browser fingerprint to client config */
	const char *fingerprint = vless_reality_fingerprint ? vless_reality_fingerprint : "chrome";
	if(!quic_fingerprint_apply_name(quic_manager->client_config, fingerprint)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to apply fingerprint '%s', using defaults", fingerprint);
	}

	/* Create server configuration */
	quic_manager->server_config = quic_config_new(true);

	if(!quic_manager->server_config) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create QUIC server config");
		quic_config_free(quic_manager->client_config);
		free(quic_manager->sockets);
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	/* Apply browser fingerprint to server config as well */
	if(!quic_fingerprint_apply_name(quic_manager->server_config, fingerprint)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to apply fingerprint '%s' to server", fingerprint);
	}

	/* Load TLS certificates for server */
	char cert_path[PATH_MAX], key_path[PATH_MAX];
	snprintf(cert_path, sizeof(cert_path), "%s/quic-cert.pem", confbase);
	snprintf(key_path, sizeof(key_path), "%s/quic-key.pem", confbase);

	logger(DEBUG_ALWAYS, LOG_INFO, "Loading QUIC TLS certificates: cert=%s, key=%s", cert_path, key_path);

	if(!quic_config_set_tls_cert(quic_manager->server_config, cert_path, key_path)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to load TLS certificate for QUIC server");
		logger(DEBUG_ALWAYS, LOG_ERR, "Cert path: %s", cert_path);
		logger(DEBUG_ALWAYS, LOG_ERR, "Key path: %s", key_path);
		logger(DEBUG_ALWAYS, LOG_ERR, "Certificate should be generated at startup by entrypoint script");
		quic_config_free(quic_manager->server_config);
		quic_config_free(quic_manager->client_config);
		free(quic_manager->sockets);
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "QUIC TLS certificates loaded successfully");

	quic_manager->initialized = true;
	quic_manager->enabled = true;

	/* Initialize connection migration settings */
	quic_manager->migration_enabled = quic_migration_enabled;
	quic_manager->hop_interval_ms = quic_hop_interval_ms;
	memset(&quic_manager->last_migration, 0, sizeof(quic_manager->last_migration));

	logger(DEBUG_ALWAYS, LOG_INFO, "QUIC Connection Migration: %s (interval=%ums)",
	       quic_manager->migration_enabled ? "enabled" : "disabled",
	       quic_manager->hop_interval_ms);

	/* Start periodic QUIC timeout driver */
	timeout_add(&quic_timer, quic_timeout_handler, &quic_timer, &(struct timeval){0, 10000});

	/* Initialize connection migration module */
	if(!quic_migration_init()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize QUIC migration");
		splay_delete_tree(quic_manager->connections);
		splay_delete_tree(quic_manager->conn_id_map);
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	/* Initialize connection maintenance module (retry, keep-alive, cleanup) */
	if(!quic_maintenance_init()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize QUIC maintenance");
		quic_migration_exit();
		splay_delete_tree(quic_manager->connections);
		splay_delete_tree(quic_manager->conn_id_map);
		free(quic_manager);
		quic_manager = NULL;
		return false;
	}

	/* Initialize Reality configuration if enabled */
	if(vless_reality_enabled) {
		quic_manager->reality_config = reality_config_new(true);  /* Server mode */

		if(quic_manager->reality_config) {
			/* Copy configuration from global variables */
			if(vless_reality_server_name) {
				strncpy(quic_manager->reality_config->server_name, vless_reality_server_name,
				        sizeof(quic_manager->reality_config->server_name) - 1);
			}

			if(vless_reality_dest) {
				strncpy(quic_manager->reality_config->dest_domain, vless_reality_dest,
				        sizeof(quic_manager->reality_config->dest_domain) - 1);
			}

			quic_manager->reality_config->dest_port = vless_reality_dest_port;

			/* Copy public/private keys */
			if(vless_reality_public_key) {
				/* Convert hex string to bytes */
				/* TODO: Implement hex_to_bytes conversion */
			}

			if(vless_reality_private_key) {
				/* Convert hex string to bytes */
				/* TODO: Implement hex_to_bytes conversion */
			}

			/* Copy Short ID */
			if(vless_reality_short_id) {
				/* Convert hex string to bytes */
				/* TODO: Implement hex_to_bytes conversion */
				/* For now, just mark that we have one short ID */
				quic_manager->reality_config->num_short_ids = 1;
			} else {
				quic_manager->reality_config->num_short_ids = 0;
			}

			quic_manager->reality_enabled = true;
			logger(DEBUG_ALWAYS, LOG_INFO, "QUIC Reality protocol enabled");
		} else {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to create Reality configuration");
		}
	} else {
		quic_manager->reality_enabled = false;
		quic_manager->reality_config = NULL;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "QUIC transport initialized using %d shared UDP socket(s)", num_sockets);

	return true;
}

/* Cleanup QUIC transport */
void quic_transport_exit(void) {
	if(!quic_manager) {
		return;
	}

	/* Free all connections */
	if(quic_manager->connections) {
		/* TODO: Properly iterate and free connections */
		splay_delete_tree(quic_manager->connections);
	}

	/* Free connection ID map */
	if(quic_manager->conn_id_map) {
		/* Free all conn_id_entry_t structures */
		for(splay_node_t *node = quic_manager->conn_id_map->head; node; node = node->next) {
			if(node->data) {
				free(node->data);
			}
		}
		splay_delete_tree(quic_manager->conn_id_map);
	}

	/* Note: We don't close the UDP sockets - they're managed by tinc's net.c */

	/* Free socket references */
	if(quic_manager->sockets) {
		free(quic_manager->sockets);
	}

	/* Free configurations */
	if(quic_manager->client_config) {
		quic_config_free(quic_manager->client_config);
	}

	if(quic_manager->server_config) {
		quic_config_free(quic_manager->server_config);
	}

	if(quic_manager->reality_config) {
		reality_config_free(quic_manager->reality_config);
	}

	free(quic_manager);
	quic_manager = NULL;

	quic_exit();

	logger(DEBUG_ALWAYS, LOG_INFO, "QUIC transport shut down");
}

/* ============================================================================
 * Transport Mode Management
 * ============================================================================ */

/* Event loop callback for incoming QUIC data
 * NOTE: This function is deprecated and will be removed.
 * QUIC packets are now handled via packet demultiplexing in handle_incoming_vpn_data()
 * which calls quic_transport_handle_packet() directly.
 */
void handle_incoming_quic_data(void *data, int flags) {
	logger(DEBUG_PROTOCOL, LOG_WARNING,
	       "handle_incoming_quic_data() called but should not be used with shared socket architecture");
}

/* Check if QUIC transport is enabled */
bool quic_transport_is_enabled(void) {
	bool result = quic_manager && quic_manager->enabled;
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "quic_transport_is_enabled() = %d (quic_manager=%p, enabled=%d)",
	       result, quic_manager, quic_manager ? quic_manager->enabled : -1);
	return result;
}

/* Set transport mode */
void quic_transport_set_mode(transport_mode_t mode) {
	transport_mode = mode;

	if(quic_manager) {
		quic_manager->enabled = (mode == TRANSPORT_QUIC || mode == TRANSPORT_HYBRID);
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Transport mode set to %d (%s)", mode,
	       mode == TRANSPORT_UDP ? "UDP" :
	       mode == TRANSPORT_TCP ? "TCP" :
	       mode == TRANSPORT_QUIC ? "QUIC" : "HYBRID");
}
