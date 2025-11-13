/*
    quic_maintenance.c -- QUIC Connection Maintenance (Retry, Keep-Alive, Cleanup)
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

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "quic_internal.h"
#include "quic.h"
#include "../conf.h"
#include "../event.h"
#include "../logger.h"
#include "../splay_tree.h"
#include "../utils.h"

/* Configuration */
extern bool quic_keepalive_enabled;
extern int quic_keepalive_interval_ms;
extern bool quic_cleanup_enabled;
extern int quic_cleanup_interval_ms;
extern int quic_session_max_idle_ms;
extern int quic_retry_max_delay_ms;
extern int quic_retry_initial_delay_ms;
extern bool quic_retry_jitter_enabled;

/* Timers */
static timeout_t keepalive_timer;
static timeout_t cleanup_timer;
static timeout_t retry_timer;

/* Forward declarations */
static void quic_keepalive_task(void *data);
static void quic_cleanup_task(void *data);
static void quic_retry_task(void *data);

/* ============================================================================
 * Keep-Alive Mechanism
 * ============================================================================ */

void quic_maintenance_init_keepalive(quic_conn_t *qconn) {
	if(!qconn) return;

	qconn->keepalive_enabled = quic_keepalive_enabled;

	if(qconn->keepalive_enabled) {
		struct timeval now;
		gettimeofday(&now, NULL);

		qconn->last_activity = now;

		/* Schedule first ping after keep-alive interval */
		qconn->next_ping_time.tv_sec = now.tv_sec + (quic_keepalive_interval_ms / 1000);
		qconn->next_ping_time.tv_usec = now.tv_usec + ((quic_keepalive_interval_ms % 1000) * 1000);

		/* Handle microsecond overflow */
		if(qconn->next_ping_time.tv_usec >= 1000000) {
			qconn->next_ping_time.tv_sec++;
			qconn->next_ping_time.tv_usec -= 1000000;
		}

		logger(DEBUG_PROTOCOL, LOG_DEBUG,
		       "Initialized keep-alive for connection (interval=%dms)",
		       quic_keepalive_interval_ms);
	}
}

/**
 * Update last activity timestamp when sending/receiving data
 * Resets keep-alive timer to prevent unnecessary PINGs
 */
void quic_maintenance_update_activity(quic_conn_t *qconn) {
	if(!qconn || !qconn->keepalive_enabled) return;

	struct timeval now;
	gettimeofday(&now, NULL);

	qconn->last_activity = now;

	/* Schedule next ping after keep-alive interval */
	qconn->next_ping_time.tv_sec = now.tv_sec + (quic_keepalive_interval_ms / 1000);
	qconn->next_ping_time.tv_usec = now.tv_usec + ((quic_keepalive_interval_ms % 1000) * 1000);

	/* Handle microsecond overflow */
	if(qconn->next_ping_time.tv_usec >= 1000000) {
		qconn->next_ping_time.tv_sec++;
		qconn->next_ping_time.tv_usec -= 1000000;
	}
}

/**
 * Keep-alive task: periodically sends PING frames to prevent idle timeout
 * Runs every 5 seconds to check connections that need PINGs
 */
static void quic_keepalive_task(void *data) {
	(void)data;

	if(!quic_manager || !quic_manager->connections || !quic_keepalive_enabled) {
		/* Reschedule for 5 seconds */
		timeout_set(&keepalive_timer, &(struct timeval){5, 0});
		return;
	}

	struct timeval now;
	gettimeofday(&now, NULL);

	uint32_t total = 0;
	uint32_t pinged = 0;

	/* Iterate through all connections */
	for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
		quic_conn_t *qconn = (quic_conn_t *)n->data;
		if(!qconn || !qconn->conn) continue;

		total++;

		/* Skip if keep-alive is disabled for this connection */
		if(!qconn->keepalive_enabled) continue;

		/* Skip if connection is not established */
		if(!quiche_conn_is_established(qconn->conn)) continue;

		/* Check if it's time to send PING */
		if(timercmp(&now, &qconn->next_ping_time, <)) {
			/* Not yet time to ping */
			continue;
		}

		pinged++;

		/* Send PING frame via quiche
		 * Note: quiche automatically sends PING when we call quic_conn_send()
		 * with no other data to send. We just need to trigger it. */

		/* Update activity timestamp first */
		quic_maintenance_update_activity(qconn);

		/* Trigger send to generate PING frame */
		ssize_t sent = quic_conn_send(qconn);
		if(sent > 0) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG,
			       "Sent keep-alive PING (%zd bytes) to prevent idle timeout",
			       sent);
		} else if(sent < 0) {
			logger(DEBUG_PROTOCOL, LOG_WARNING,
			       "Failed to send keep-alive PING: %zd", sent);
		}
	}

	if(pinged > 0) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG,
		       "Keep-alive cycle: %u total connections, %u sent PINGs",
		       total, pinged);
	}

	/* Reschedule for 5 seconds */
	timeout_set(&keepalive_timer, &(struct timeval){5, 0});
}

/* ============================================================================
 * Session Cleanup Task
 * ============================================================================ */

/**
 * Session cleanup task: periodically removes dead/stale connections
 * Runs every cleanup_interval_ms to check for:
 * - Closed connections that can be removed
 * - Idle connections exceeding max_idle_ms
 * - Connections with protocol errors
 */
static void quic_cleanup_task(void *data) {
	(void)data;

	if(!quic_manager || !quic_manager->connections || !quic_cleanup_enabled) {
		/* Reschedule based on config (default: 60 seconds) */
		timeout_set(&cleanup_timer,
		           &(struct timeval){quic_cleanup_interval_ms / 1000,
		                             (quic_cleanup_interval_ms % 1000) * 1000});
		return;
	}

	struct timeval now;
	gettimeofday(&now, NULL);

	uint32_t total = 0;
	uint32_t checked = 0;
	uint32_t removed = 0;

	/* List to track connections to remove (can't modify tree during iteration) */
	#define MAX_TO_REMOVE 100
	quic_conn_t *to_remove[MAX_TO_REMOVE];
	uint32_t to_remove_count = 0;

	/* Iterate through all connections */
	for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
		quic_conn_t *qconn = (quic_conn_t *)n->data;
		if(!qconn || !qconn->conn) continue;

		total++;
		checked++;

		bool should_remove = false;
		const char *reason = NULL;

		/* Check if connection is closed */
		if(quiche_conn_is_closed(qconn->conn)) {
			should_remove = true;
			reason = "connection closed";
		}
		/* Check if connection is idle for too long */
		else if(qconn->keepalive_enabled) {
			/* Calculate idle time */
			struct timeval idle_time;
			timersub(&now, &qconn->last_activity, &idle_time);
			uint64_t idle_ms = idle_time.tv_sec * 1000 + idle_time.tv_usec / 1000;

			if(idle_ms > (uint64_t)quic_session_max_idle_ms) {
				should_remove = true;
				reason = "max idle timeout exceeded";
			}
		}
		/* Check for protocol errors */
		else if(!quiche_conn_is_established(qconn->conn)) {
			/* If handshake not complete after a while, consider it stale */
			struct timeval conn_age;
			if(qconn->keepalive_enabled) {
				/* We can use last_activity as connection start time */
				timersub(&now, &qconn->last_activity, &conn_age);
				uint64_t age_ms = conn_age.tv_sec * 1000 + conn_age.tv_usec / 1000;

				/* If handshake takes longer than 30 seconds, something is wrong */
				if(age_ms > 30000) {
					should_remove = true;
					reason = "handshake timeout (>30s)";
				}
			}
		}

		if(should_remove && to_remove_count < MAX_TO_REMOVE) {
			to_remove[to_remove_count++] = qconn;

			char *peer_str = sockaddr2hostname((const sockaddr_t *)&qconn->peer_addr);
			logger(DEBUG_PROTOCOL, LOG_INFO,
			       "Marking connection to %s for removal: %s",
			       peer_str, reason);
			free(peer_str);
		}
	}

	/* Now remove marked connections */
	for(uint32_t i = 0; i < to_remove_count; i++) {
		quic_conn_t *qconn = to_remove[i];

		/* Remove from tinc node if linked */
		if(qconn->node) {
			node_t *node = (node_t *)qconn->node;

			/* Log removal */
			char *peer_str = sockaddr2hostname((const sockaddr_t *)&qconn->peer_addr);
			logger(DEBUG_PROTOCOL, LOG_INFO,
			       "Removing dead QUIC connection to %s (node=%s)",
			       peer_str, node->name ? node->name : "unknown");
			free(peer_str);

			/* Remove via transport layer (handles cleanup properly) */
			quic_transport_remove_connection(node);
			removed++;
		} else {
			/* Orphaned connection, just log and count */
			logger(DEBUG_PROTOCOL, LOG_WARNING,
			       "Found orphaned QUIC connection without node");
		}
	}

	if(removed > 0 || checked > 10) {
		logger(DEBUG_PROTOCOL, LOG_INFO,
		       "Cleanup cycle: %u total, %u checked, %u removed",
		       total, checked, removed);
	}

	/* Reschedule based on config (default: 60 seconds) */
	timeout_set(&cleanup_timer,
	           &(struct timeval){quic_cleanup_interval_ms / 1000,
	                             (quic_cleanup_interval_ms % 1000) * 1000});
}

/* ============================================================================
 * Exponential Backoff Retry Logic
 * ============================================================================ */

/**
 * Initialize retry state for a connection
 * Sets initial values for exponential backoff algorithm
 */
void quic_maintenance_init_retry(quic_conn_t *qconn) {
	if(!qconn) return;

	qconn->retry_count = 0;
	qconn->current_delay_ms = quic_retry_initial_delay_ms;
	qconn->retry_scheduled = false;
	memset(&qconn->next_retry_time, 0, sizeof(qconn->next_retry_time));

	logger(DEBUG_PROTOCOL, LOG_DEBUG,
	       "Initialized retry state for connection (initial_delay=%dms, max_delay=%dms)",
	       quic_retry_initial_delay_ms, quic_retry_max_delay_ms);
}

/**
 * Calculate next retry delay using exponential backoff with optional jitter
 * Formula: delay = min(initial * 2^retry_count, max_delay) * (1 ± jitter)
 * Jitter range: ±20% to prevent thundering herd
 */
static uint32_t calculate_retry_delay(quic_conn_t *qconn) {
	if(!qconn) return quic_retry_initial_delay_ms;

	/* Exponential backoff: initial_delay * 2^retry_count */
	uint32_t delay_ms = quic_retry_initial_delay_ms;

	/* Prevent overflow: cap at 2^20 iterations */
	uint32_t shift = (qconn->retry_count > 20) ? 20 : qconn->retry_count;

	/* Compute delay with overflow protection */
	if(shift > 0) {
		uint32_t multiplier = 1U << shift;  /* 2^retry_count */

		/* Check for overflow before multiplication */
		if(delay_ms <= (uint32_t)quic_retry_max_delay_ms / multiplier) {
			delay_ms *= multiplier;
		} else {
			delay_ms = quic_retry_max_delay_ms;
		}
	}

	/* Cap at maximum delay */
	if(delay_ms > (uint32_t)quic_retry_max_delay_ms) {
		delay_ms = quic_retry_max_delay_ms;
	}

	/* Add jitter: ±20% randomization to prevent thundering herd */
	if(quic_retry_jitter_enabled && delay_ms > 0) {
		/* Generate random value in range [0.8, 1.2] */
		/* jitter_factor = 0.8 + (rand() % 400) / 1000.0 */
		int32_t jitter_percent = (rand() % 40) - 20;  /* -20 to +20 */
		int32_t jitter_ms = (delay_ms * jitter_percent) / 100;

		/* Apply jitter with bounds checking */
		if(jitter_ms > 0 && delay_ms < UINT32_MAX - (uint32_t)jitter_ms) {
			delay_ms += jitter_ms;
		} else if(jitter_ms < 0 && delay_ms > (uint32_t)(-jitter_ms)) {
			delay_ms -= (-jitter_ms);
		}

		/* Ensure we don't go below 1ms */
		if(delay_ms < 1) delay_ms = 1;
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG,
	       "Calculated retry delay: %ums (retry_count=%u, jitter=%s)",
	       delay_ms, qconn->retry_count,
	       quic_retry_jitter_enabled ? "enabled" : "disabled");

	return delay_ms;
}

/**
 * Schedule a retry attempt for failed connection
 * Uses exponential backoff to calculate when to retry
 */
static void schedule_retry(quic_conn_t *qconn) {
	if(!qconn) return;

	/* Calculate next delay with exponential backoff */
	uint32_t delay_ms = calculate_retry_delay(qconn);
	qconn->current_delay_ms = delay_ms;

	/* Set next retry time */
	struct timeval now;
	gettimeofday(&now, NULL);

	qconn->next_retry_time.tv_sec = now.tv_sec + (delay_ms / 1000);
	qconn->next_retry_time.tv_usec = now.tv_usec + ((delay_ms % 1000) * 1000);

	/* Handle microsecond overflow */
	if(qconn->next_retry_time.tv_usec >= 1000000) {
		qconn->next_retry_time.tv_sec++;
		qconn->next_retry_time.tv_usec -= 1000000;
	}

	qconn->retry_scheduled = true;
	qconn->retry_count++;

	char *peer_str = sockaddr2hostname((const sockaddr_t *)&qconn->peer_addr);
	logger(DEBUG_PROTOCOL, LOG_INFO,
	       "Scheduled retry #%u for %s in %ums",
	       qconn->retry_count, peer_str, delay_ms);
	free(peer_str);
}

/**
 * Retry task: periodically checks connections and retries failed ones
 * Runs every 1 second to check for connections ready to retry
 */
static void quic_retry_task(void *data) {
	(void)data;

	if(!quic_manager || !quic_manager->connections) {
		/* Reschedule for 1 second */
		timeout_set(&retry_timer, &(struct timeval){1, 0});
		return;
	}

	struct timeval now;
	gettimeofday(&now, NULL);

	uint32_t total = 0;
	uint32_t retried = 0;
	uint32_t succeeded = 0;

	/* Iterate through all connections */
	for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
		quic_conn_t *qconn = (quic_conn_t *)n->data;
		if(!qconn || !qconn->conn) continue;

		total++;

		/* Skip if no retry is scheduled */
		if(!qconn->retry_scheduled) continue;

		/* Check if it's time to retry */
		if(timercmp(&now, &qconn->next_retry_time, <)) {
			/* Not yet time to retry */
			continue;
		}

		retried++;

		/* Clear retry flag before attempting */
		qconn->retry_scheduled = false;

		/* Check connection state */
		if(quiche_conn_is_established(qconn->conn)) {
			/* Connection recovered on its own */
			logger(DEBUG_PROTOCOL, LOG_INFO,
			       "Connection recovered without retry (after %u attempts)",
			       qconn->retry_count);
			quic_maintenance_init_retry(qconn);  /* Reset retry state */
			succeeded++;
			continue;
		}

		if(quiche_conn_is_closed(qconn->conn)) {
			/* Connection is dead, schedule another retry */
			char *peer_str = sockaddr2hostname((const sockaddr_t *)&qconn->peer_addr);
			logger(DEBUG_PROTOCOL, LOG_WARNING,
			       "Connection to %s still closed, scheduling retry #%u (delay=%ums)",
			       peer_str, qconn->retry_count + 1, qconn->current_delay_ms);
			free(peer_str);

			schedule_retry(qconn);

			/* Try to send any pending data to trigger reconnection */
			ssize_t sent = quic_conn_send(qconn);
			if(sent > 0) {
				logger(DEBUG_PROTOCOL, LOG_DEBUG,
				       "Sent %zd bytes during retry attempt", sent);
			}
		} else {
			/* Connection is in progress, wait for it */
			logger(DEBUG_PROTOCOL, LOG_DEBUG,
			       "Connection in progress, resetting retry state");
			quic_maintenance_init_retry(qconn);
			succeeded++;
		}
	}

	if(retried > 0 || total > 0) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG,
		       "Retry cycle: %u total connections, %u retried, %u succeeded",
		       total, retried, succeeded);
	}

	/* Reschedule for 1 second */
	timeout_set(&retry_timer, &(struct timeval){1, 0});
}

/* ============================================================================
 * Initialization and Cleanup
 * ============================================================================ */

bool quic_maintenance_init(void) {
	/* Start keep-alive timer */
	if(quic_keepalive_enabled) {
		timeout_add(&keepalive_timer, quic_keepalive_task, NULL, &(struct timeval){5, 0});
		logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC keep-alive enabled (interval=%dms)",
		       quic_keepalive_interval_ms);
	}

	/* Start cleanup timer */
	if(quic_cleanup_enabled) {
		timeout_add(&cleanup_timer, quic_cleanup_task, NULL,
		           &(struct timeval){quic_cleanup_interval_ms / 1000,
		                             (quic_cleanup_interval_ms % 1000) * 1000});
		logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC cleanup enabled (interval=%dms, max_idle=%dms)",
		       quic_cleanup_interval_ms, quic_session_max_idle_ms);
	}

	/* Start retry timer */
	timeout_add(&retry_timer, quic_retry_task, NULL, &(struct timeval){1, 0});
	logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC retry logic enabled (initial_delay=%dms, max_delay=%dms, jitter=%s)",
	       quic_retry_initial_delay_ms, quic_retry_max_delay_ms,
	       quic_retry_jitter_enabled ? "enabled" : "disabled");

	return true;
}

void quic_maintenance_exit(void) {
	timeout_del(&keepalive_timer);
	timeout_del(&cleanup_timer);
	timeout_del(&retry_timer);
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC maintenance tasks stopped");
}
