/*
    quic_migration.c -- QUIC Connection Migration
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

#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "quic_internal.h"
#include "quic.h"
#include "../conf.h"
#include "../event.h"
#include "../logger.h"
#include "../splay_tree.h"

/* Configuration */
extern bool quic_migration_enabled;
extern int quic_hop_interval_ms;

/* Migration timer */
static timeout_t migration_timer;

/* Forward declarations */
static void quic_migration_task(void *data);

/* Create a new UDP socket on a random ephemeral port */
static int create_migration_socket(int family) {
	int sock_fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	if(sock_fd < 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create migration socket: %s", strerror(errno));
		return -1;
	}

	/* Bind to ephemeral port (0 = let OS choose) */
	if(family == AF_INET) {
		struct sockaddr_in addr = {0};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = 0; /* Random port */

		if(bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to bind migration socket: %s", strerror(errno));
			close(sock_fd);
			return -1;
		}
	} else if(family == AF_INET6) {
		struct sockaddr_in6 addr = {0};
		addr.sin6_family = AF_INET6;
		addr.sin6_addr = in6addr_any;
		addr.sin6_port = 0;

		if(bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to bind IPv6 migration socket: %s", strerror(errno));
			close(sock_fd);
			return -1;
		}
	}

	/* Get assigned port for logging */
	struct sockaddr_storage local;
	socklen_t len = sizeof(local);
	if(getsockname(sock_fd, (struct sockaddr *)&local, &len) == 0) {
		int port = 0;
		if(local.ss_family == AF_INET) {
			port = ntohs(((struct sockaddr_in *)&local)->sin_port);
		} else if(local.ss_family == AF_INET6) {
			port = ntohs(((struct sockaddr_in6 *)&local)->sin6_port);
		}
		logger(DEBUG_PROTOCOL, LOG_INFO, "Created migration socket fd=%d on ephemeral port %d", sock_fd, port);
	}

	return sock_fd;
}

/* Perform connection migration for a single connection */
static bool migrate_connection(quic_conn_t *qconn) {
	if(!qconn || !qconn->migration_enabled) {
		return false;
	}

	/* Only migrate established connections */
	if(!quic_conn_is_established(qconn)) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Skipping migration for non-established connection");
		return false;
	}

	/* Determine socket family from peer address */
	int family = qconn->peer_addr.ss_family;
	if(family != AF_INET && family != AF_INET6) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Cannot migrate connection with unknown address family %d", family);
		return false;
	}

	/* Create new socket on random ephemeral port */
	int new_fd = create_migration_socket(family);
	if(new_fd < 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create new socket for migration");
		return false;
	}

	/* Save old socket for draining period */
	qconn->old_sock_fd = qconn->sock_fd;
	gettimeofday(&qconn->old_fd_close_time, NULL);
	/* Close old socket after 60 seconds (draining period) */
	qconn->old_fd_close_time.tv_sec += 60;

	/* Switch to new socket */
	int old_fd = qconn->sock_fd;
	qconn->sock_fd = new_fd;

	/* Update last migration timestamp */
	gettimeofday(&qconn->last_migration, NULL);

	/* Send packets to trigger PATH_CHALLENGE/RESPONSE */
	/* quiche will automatically send PATH_CHALLENGE when it detects address change */
	while(true) {
		ssize_t sent = quic_conn_send(qconn);
		if(sent <= 0) break;
	}

	node_t *node = (node_t *)qconn->node;
	logger(DEBUG_PROTOCOL, LOG_INFO, "Connection migrated to new socket: old_fd=%d -> new_fd=%d for node %s",
	       old_fd, new_fd, node ? node->name : "unknown");

	return true;
}

/* Close old sockets after draining period */
static void cleanup_old_sockets(void) {
	if(!quic_manager || !quic_manager->connections) {
		return;
	}

	struct timeval now;
	gettimeofday(&now, NULL);

	for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
		quic_conn_t *qconn = (quic_conn_t *)n->data;
		if(!qconn || qconn->old_sock_fd < 0) {
			continue;
		}

		/* Check if draining period expired */
		if(now.tv_sec > qconn->old_fd_close_time.tv_sec ||
		   (now.tv_sec == qconn->old_fd_close_time.tv_sec &&
		    now.tv_usec >= qconn->old_fd_close_time.tv_usec)) {

			logger(DEBUG_PROTOCOL, LOG_DEBUG, "Closing drained socket fd=%d after migration", qconn->old_sock_fd);
			close(qconn->old_sock_fd);
			qconn->old_sock_fd = -1;
		}
	}
}

/* Periodic migration task */
static void quic_migration_task(void *data) {
	(void)data;

	if(!quic_manager || !quic_manager->migration_enabled ||
	   quic_manager->hop_interval_ms == 0) {
		/* Migration disabled, reschedule check in 10s */
		timeout_set(&migration_timer, &(struct timeval){10, 0});
		return;
	}

	struct timeval now;
	gettimeofday(&now, NULL);

	/* Check if it's time for migration */
	uint64_t elapsed_ms = 0;
	if(quic_manager->last_migration.tv_sec > 0) {
		elapsed_ms = (now.tv_sec - quic_manager->last_migration.tv_sec) * 1000ULL +
		             (now.tv_usec - quic_manager->last_migration.tv_usec) / 1000ULL;
	} else {
		/* First run, initialize */
		quic_manager->last_migration = now;
		elapsed_ms = quic_manager->hop_interval_ms; /* Force migration on first check */
	}

	if(elapsed_ms >= quic_manager->hop_interval_ms) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Starting periodic connection migration (interval=%ums)",
		       quic_manager->hop_interval_ms);

		int migrated = 0;
		int failed = 0;

		/* Migrate all eligible connections */
		for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
			quic_conn_t *qconn = (quic_conn_t *)n->data;
			if(!qconn) continue;

			if(migrate_connection(qconn)) {
				migrated++;
			} else if(qconn->migration_enabled && quic_conn_is_established(qconn)) {
				/* Only count as failure if migration was expected */
				failed++;
			}
		}

		if(migrated > 0 || failed > 0) {
			logger(DEBUG_PROTOCOL, LOG_INFO, "Migration cycle completed: %d migrated, %d failed",
			       migrated, failed);
		}

		quic_manager->last_migration = now;
	}

	/* Cleanup old sockets */
	cleanup_old_sockets();

	/* Reschedule (check every 10 seconds, migrate per hop_interval_ms) */
	timeout_set(&migration_timer, &(struct timeval){10, 0});
}

/* Initialize migration subsystem */
bool quic_migration_init(void) {
	if(!quic_migration_enabled || quic_hop_interval_ms == 0) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC Connection Migration disabled");
		return true;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC Connection Migration enabled (hop interval: %d seconds)",
	       quic_hop_interval_ms / 1000);

	/* Start migration timer */
	timeout_add(&migration_timer, quic_migration_task, NULL, &(struct timeval){10, 0});
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC migration task started");

	return true;
}

/* Cleanup migration subsystem */
void quic_migration_exit(void) {
	timeout_del(&migration_timer);
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC migration task stopped");
}
