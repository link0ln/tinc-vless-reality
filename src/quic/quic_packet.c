/*
    quic_packet.c -- QUIC Packet Handling and Connection ID Demultiplexing
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <quiche.h>

#include "quic_internal.h"
#include "quic.h"
#include "../logger.h"
#include "../xalloc.h"
#include "../splay_tree.h"
#include "../netutl.h"
#include "../node.h"
#include "../connection.h"
#include "../net.h"
#include "../protocol.h"
#include "../meta.h"

/* External references */
extern quic_manager_t *quic_manager;
extern splay_tree_t *node_tree;

/* Local connection ID length (matches scid_len in quic_conn_new_server) */
#define LOCAL_CONN_ID_LEN 16

/* ============================================================================
 * Connection ID Demultiplexing
 * ============================================================================ */

/* Connection ID comparison function for splay tree */
int conn_id_compare(const void *a, const void *b) {
	/* Handle NULL pointers - splay tree may pass sentinel nodes */
	if(!a) return b ? -1 : 0;
	if(!b) return 1;

	const conn_id_entry_t *ea = (const conn_id_entry_t *)a;
	const conn_id_entry_t *eb = (const conn_id_entry_t *)b;

	/* Compare by length first */
	if(ea->conn_id_len != eb->conn_id_len) {
		return ea->conn_id_len - eb->conn_id_len;
	}

	/* Then compare by value */
	return memcmp(ea->conn_id, eb->conn_id, ea->conn_id_len);
}

/* Register a connection ID in the demultiplexing map */
bool register_connection_id(const uint8_t *conn_id, size_t conn_id_len, quic_conn_t *conn) {
	if(!quic_manager || !quic_manager->conn_id_map || !conn_id || conn_id_len == 0 || !conn) {
		return false;
	}

	conn_id_entry_t *entry = xzalloc(sizeof(conn_id_entry_t));
	memcpy(entry->conn_id, conn_id, conn_id_len);
	entry->conn_id_len = conn_id_len;
	entry->conn = conn;

	/* Use splay_insert correctly - pass data, not node */
	splay_insert(quic_manager->conn_id_map, entry);

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Registered CID=%s (len=%zu) for demultiplexing",
	       format_cid(conn_id, conn_id_len), conn_id_len);
	return true;
}

/* Unregister a connection ID from the demultiplexing map */
void unregister_connection_id(const uint8_t *conn_id, size_t conn_id_len) {
	if(!quic_manager || !quic_manager->conn_id_map || !conn_id || conn_id_len == 0) {
		return;
	}

	conn_id_entry_t search;
	memset(&search, 0, sizeof(search));  // Zero entire structure
	memcpy(search.conn_id, conn_id, conn_id_len);
	search.conn_id_len = conn_id_len;

	/* splay_unlink returns the node for the data */
	splay_node_t *node = splay_unlink(quic_manager->conn_id_map, &search);
	if(node) {
		free(node->data);  /* Free the conn_id_entry_t */
		free(node);        /* Free the node itself */
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Unregistered connection ID (len=%zu) from demultiplexing", conn_id_len);
	}
}

/* Lookup connection by ID */
quic_conn_t *lookup_connection_by_id(const uint8_t *conn_id, size_t conn_id_len) {
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "lookup_connection_by_id() called for CID=%s (len=%zu)",
	       format_cid(conn_id, conn_id_len), conn_id_len);

	if(!quic_manager || !quic_manager->conn_id_map || !conn_id || conn_id_len == 0) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "lookup_connection_by_id() - invalid parameters, returning NULL");
		return NULL;
	}

	/* Count registered CIDs for debugging */
	int cid_count = 0;
	if(quic_manager->conn_id_map) {
		for(splay_node_t *n = quic_manager->conn_id_map->head; n; n = n->next) {
			cid_count++;
		}
	}
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Total registered CIDs in map: %d", cid_count);

	conn_id_entry_t search;
	memset(&search, 0, sizeof(search));  // Zero entire structure to avoid padding issues
	memcpy(search.conn_id, conn_id, conn_id_len);
	search.conn_id_len = conn_id_len;

	/* splay_search returns data pointer, not node */
	conn_id_entry_t *entry = (conn_id_entry_t *)splay_search(quic_manager->conn_id_map, &search);
	if(entry) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "lookup_connection_by_id() - FOUND connection for CID=%s",
		       format_cid(conn_id, conn_id_len));
		return entry->conn;
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "lookup_connection_by_id() - NOT FOUND for CID=%s",
	       format_cid(conn_id, conn_id_len));
	return NULL;
}

/* ============================================================================
 * Packet Transmission
 * ============================================================================ */

/* Send VPN packet via QUIC */
bool quic_transport_send_packet(node_t *node, vpn_packet_t *packet) {
	if(!quic_manager || !quic_manager->enabled || !node || !packet) {
		return false;
	}

	/* Get or create QUIC connection */
	quic_conn_t *qconn = quic_transport_get_connection(node, NULL);

	if(!qconn) {
		/* Create client connection */
		qconn = quic_transport_create_connection(node, true, &node->address);

		if(!qconn) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create QUIC connection to %s", node->name);
			return false;
		}
	}

	/* Check if handshake is complete */
	if(!quic_conn_is_established(qconn)) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC handshake not complete for %s, buffering packet", node->name);
		/* Buffer packets until handshake completes */
		bool buffered = quic_conn_buffer_vpn_packet(qconn, DATA(packet), packet->len);

		if(!buffered) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Failed to buffer packet for %s", node->name);
		}

		/* Return true to indicate packet was handled (buffered) */
		/* This prevents immediate fallback to UDP */
		return buffered;
	}

	/* Send packet through QUIC stream */
	bool result = quic_conn_send_vpn_packet(qconn, DATA(packet), packet->len);

	if(result) {
		quic_manager->packets_sent++;
		quic_manager->bytes_sent += packet->len;
	}

	return result;
}

/* ==========================================================================
 * Packet Reception and Processing (Large function ~640 lines)
 * ========================================================================== */

/* Forward declaration for internal helper */
static void quic_flush_meta_outbuf(connection_t *c, quic_conn_t *qconn);

/* Handle incoming QUIC packet */
void quic_transport_handle_packet(const uint8_t *buf, size_t len,
                                   struct sockaddr *from, socklen_t fromlen) {

	if(!quic_manager || !buf || len == 0) {
		return;
	}

	/* Trace incoming UDP for QUIC demux */
	char src[INET6_ADDRSTRLEN] = {0};
	int sport = 0;
	if(from) {
		if(from->sa_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)from;
			inet_ntop(AF_INET, &sin->sin_addr, src, sizeof(src));
			sport = ntohs(sin->sin_port);
		} else if(from->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)from;
			inet_ntop(AF_INET6, &sin6->sin6_addr, src, sizeof(src));
			sport = ntohs(sin6->sin6_port);
		}
	}
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC demux: received UDP len=%zu from %s:%d", len, src[0]?src:"?", sport);

	/* Parse QUIC header to get connection ID for demultiplexing */
	uint8_t type;
	uint32_t version;
	uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
	size_t scid_len = sizeof(scid);
	uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
	size_t dcid_len = sizeof(dcid);
	uint8_t token[256];
	size_t token_len = sizeof(token);

	/* Detect packet type from first byte to determine DCID length hint:
	 * - Long Header (bit 7 = 1): DCID length is encoded in packet, use hint=0
	 * - Short Header (bit 7 = 0): DCID length is NOT in packet, use hint=LOCAL_CONN_ID_LEN
	 * This fixes the issue where Short Header packets were parsed with empty DCID. */
	size_t dcid_len_hint = 0;
	if(len > 0) {
		bool is_long_header = (buf[0] & 0x80) != 0;
		if(!is_long_header) {
			/* Short Header packet: need to provide expected DCID length */
			dcid_len_hint = LOCAL_CONN_ID_LEN;
		}
	}

	int rc = quiche_header_info(buf, len, dcid_len_hint,
	                             &version, &type,
	                             scid, &scid_len,
	                             dcid, &dcid_len,
	                             token, &token_len);

	/* Log parsed header information */
	if(rc >= 0) {
		const char *header_type = (dcid_len_hint == 0) ? "Long" : "Short";
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Parsed QUIC %s Header: type=%u version=0x%x DCID=%s (len=%zu) SCID=%s (len=%zu)",
		       header_type, type, version, format_cid(dcid, dcid_len), dcid_len,
		       format_cid(scid, scid_len), scid_len);
	} else {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Failed to parse QUIC header: rc=%d", rc);
	}

	quic_conn_t *qconn = NULL;

	if(rc >= 0 && dcid_len > 0) {
		/* Try to find existing connection by DCID (our SCID) */
		qconn = lookup_connection_by_id(dcid, dcid_len);

		if(qconn) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "CID lookup SUCCESS: Found connection for DCID=%s",
			       format_cid(dcid, dcid_len));
		} else {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "CID lookup FAILED: No connection found for DCID=%s, trying address fallback",
			       format_cid(dcid, dcid_len));
		}
	}

	/* Fallback: if CID lookup failed, try peer address lookup
	 * IMPORTANT: do not bind incoming packets to an existing CLIENT-side connection,
	 * or handshake will stall. Only consider server-side (incoming) connections here. */
	if(!qconn && from) {
		for(splay_node_t *n = quic_manager->connections->head; n; n = n->next) {
			quic_conn_t *candidate = (quic_conn_t *)n->data;
			if(!candidate) {
				continue;
			}
			/* Skip client-initiated connections */
			if(candidate->is_client) {
				continue;
			}
			if(candidate->peer_addr.ss_family == from->sa_family) {
				bool match = false;
				if(from->sa_family == AF_INET) {
					struct sockaddr_in *addr1 = (struct sockaddr_in *)&candidate->peer_addr;
					struct sockaddr_in *addr2 = (struct sockaddr_in *)from;
					match = (addr1->sin_port == addr2->sin_port &&
					         memcmp(&addr1->sin_addr, &addr2->sin_addr, sizeof(addr1->sin_addr)) == 0);
				} else if(from->sa_family == AF_INET6) {
					struct sockaddr_in6 *addr1 = (struct sockaddr_in6 *)&candidate->peer_addr;
					struct sockaddr_in6 *addr2 = (struct sockaddr_in6 *)from;
					match = (addr1->sin6_port == addr2->sin6_port &&
					         memcmp(&addr1->sin6_addr, &addr2->sin6_addr, sizeof(addr1->sin6_addr)) == 0);
				}
				if(match) {
					qconn = candidate;
					logger(DEBUG_PROTOCOL, LOG_DEBUG, "Found connection by peer address fallback");
					break;
				}
			}
		}
	}

	/* For client connections: register peer SCID from packet header BEFORE processing packet
	 * This allows quiche to recognize the DCID in server responses during handshake */
	if(qconn && qconn->is_client && scid_len > 0) {
		/* Check if this peer SCID is already registered */
		quic_conn_t *existing = lookup_connection_by_id(scid, scid_len);
		if(!existing) {
			/* Register server's SCID for demultiplexing */
			register_connection_id(scid, scid_len, qconn);
			logger(DEBUG_PROTOCOL, LOG_INFO,
			       "Client: registered peer SCID=%s (len=%zu) from packet header before quic_conn_recv()",
			       format_cid(scid, scid_len), scid_len);
		} else if(existing != qconn) {
			logger(DEBUG_PROTOCOL, LOG_WARNING,
			       "Client: peer SCID=%s from packet header already registered to different connection",
			       format_cid(scid, scid_len));
		}
	}

	if(qconn) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "###VERSION_CHECK### Code compiled with commit 7151b5b+ patches");
		/* Feed packet to connection; loop until quiche reports no more packets to send */
		ssize_t done = quic_conn_recv(qconn, buf, len);

		if(done > 0) {
			quic_manager->packets_received++;
			quic_manager->bytes_received += done;
			/* Proactively send any handshake responses/packets */
			while(true) {
				ssize_t sent = quic_conn_send(qconn);
				if(sent <= 0) break;
			}

			/* Check if we need to bind server connection to node */
			bool is_established = quic_conn_is_established(qconn);
			if(is_established && !qconn->node && qconn->peer_addr.ss_family != 0) {
				/* Server-side connection needs node binding */
				char *peer_hostname = sockaddr2hostname((sockaddr_t *)&qconn->peer_addr);
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "Server connection established from %s (family=%d), attempting to bind node",
				       peer_hostname, qconn->peer_addr.ss_family);
				free(peer_hostname);

				/* Find node by peer address */
				for(splay_node_t *n = node_tree->head; n; n = n->next) {
					node_t *candidate = (node_t *)n->data;

					/* Debug: log each candidate node */
					if(candidate) {
						char *cand_hostname = sockaddr2hostname(&candidate->address);
						logger(DEBUG_PROTOCOL, LOG_DEBUG, "  Checking node '%s': addr=%s family=%d",
						       candidate->name ? candidate->name : "NULL",
						       cand_hostname,
						       candidate->address.sa.sa_family);
						free(cand_hostname);
					}

					if(candidate && candidate->address.sa.sa_family == qconn->peer_addr.ss_family) {
						bool match = false;
						if(candidate->address.sa.sa_family == AF_INET) {
							struct sockaddr_in *addr1 = (struct sockaddr_in *)&candidate->address;
							struct sockaddr_in *addr2 = (struct sockaddr_in *)&qconn->peer_addr;

							/* Debug: print IP addresses in human readable format */
							char ip1[INET_ADDRSTRLEN], ip2[INET_ADDRSTRLEN];
							inet_ntop(AF_INET, &addr1->sin_addr, ip1, INET_ADDRSTRLEN);
							inet_ntop(AF_INET, &addr2->sin_addr, ip2, INET_ADDRSTRLEN);
							logger(DEBUG_PROTOCOL, LOG_DEBUG, "    IPv4 compare: candidate=%s peer=%s", ip1, ip2);

							match = (memcmp(&addr1->sin_addr, &addr2->sin_addr, sizeof(addr1->sin_addr)) == 0);
						} else if(candidate->address.sa.sa_family == AF_INET6) {
							struct sockaddr_in6 *addr1 = (struct sockaddr_in6 *)&candidate->address;
							struct sockaddr_in6 *addr2 = (struct sockaddr_in6 *)&qconn->peer_addr;

							/* Debug: print IP addresses in human readable format */
							char ip1[INET6_ADDRSTRLEN], ip2[INET6_ADDRSTRLEN];
							inet_ntop(AF_INET6, &addr1->sin6_addr, ip1, INET6_ADDRSTRLEN);
							inet_ntop(AF_INET6, &addr2->sin6_addr, ip2, INET6_ADDRSTRLEN);
							logger(DEBUG_PROTOCOL, LOG_DEBUG, "    IPv6 compare: candidate=%s peer=%s", ip1, ip2);

							match = (memcmp(&addr1->sin6_addr, &addr2->sin6_addr, sizeof(addr1->sin6_addr)) == 0);
						}

						if(match) {
							/* Found the node! Bind it to the connection */
							quic_conn_set_node(qconn, candidate);
							logger(DEBUG_PROTOCOL, LOG_INFO, "Bound QUIC server connection to node %s", candidate->name);

							/* Create connection_t for incoming QUIC connection if it doesn't exist */
							if(!candidate->connection) {
								connection_t *c = new_connection();
								c->name = xstrdup(candidate->name);
								c->outcipher = myself->connection->outcipher;
								c->outdigest = myself->connection->outdigest;
								c->outmaclength = myself->connection->outmaclength;
								c->outcompression = myself->connection->outcompression;

								/* Convert sockaddr_storage to sockaddr_t */
								memcpy(&c->address, &qconn->peer_addr, sizeof(struct sockaddr_storage));
								c->hostname = sockaddr2hostname((sockaddr_t *)&qconn->peer_addr);
								c->last_ping_time = now.tv_sec;
								c->node = candidate;
								c->edge = NULL;

								/* Mark as QUIC meta connection */
								c->status.quic_meta = true;

								/* Add to connection list and link to node */
								connection_add(c);
								candidate->connection = c;

								logger(DEBUG_PROTOCOL, LOG_INFO, "Created connection_t for incoming QUIC from %s", candidate->name);
							}
							break;
						}
					}
				}

				if(!qconn->node) {
					/* Check if an unbound connection already exists for this peer */
					connection_t *existing = find_unbound_quic_meta_for_peer(qconn);
					if(existing) {
						logger(DEBUG_PROTOCOL, LOG_DEBUG, "Unbound connection already exists for %s, skipping duplicate creation", existing->hostname);
					} else {
						logger(DEBUG_PROTOCOL, LOG_INFO, "Could not find node for server connection from %s - will bind via ID message",
						       sockaddr2hostname((sockaddr_t *)&qconn->peer_addr));

						/* Hybrid binding: Create connection_t for incoming connection and keep name unset
						 * so send_id() uses our proper name toward the peer. */
						connection_t *c = new_connection();
						c->name = NULL;
						c->outcipher = myself->connection->outcipher;
						c->outdigest = myself->connection->outdigest;
						c->outmaclength = myself->connection->outmaclength;
						c->outcompression = myself->connection->outcompression;

						/* Convert sockaddr_storage to sockaddr_t */
						memcpy(&c->address, &qconn->peer_addr, sizeof(struct sockaddr_storage));
						c->hostname = sockaddr2hostname((sockaddr_t *)&qconn->peer_addr);
						c->last_ping_time = now.tv_sec;
						c->node = NULL;  /* Will be set when ID message arrives */
						c->edge = NULL;

						/* Mark as QUIC meta connection */
						c->status.quic_meta = true;
						c->status.sptps_disabled = true;

						/* Server receives client data on client-initiated stream 0
						 * Clients always use bidirectional stream 0 for metadata */
						c->quic_stream_id = 0;  // Client stream 0

						/* Add to connection list - will be linked to node when ID message arrives */
						connection_add(c);

						/* Server waits to receive client's ID on client-initiated stream 0
						 * Server will respond with its own ID on the same stream */
						c->allow_request = ID;
						c->status.meta_protocol_initiated = 0;  // Will be set when stream is discovered

						logger(DEBUG_PROTOCOL, LOG_INFO, "Created connection_t for unbound incoming QUIC from %s, waiting for client stream and ID message",
						       c->hostname);
					}
				}
			}

			/* Trigger metadata protocol for outgoing connections when handshake completes */
			if(qconn->node) {
				bool is_established = quic_conn_is_established(qconn);
				node_t *n = (node_t *)qconn->node;
				connection_t *c = n->connection;

				logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC state check for %s: established=%d, connection=%p, quic_meta=%d, quic_stream_id=%ld, outgoing=%p, initiated=%d",
				       n->name, is_established, (void*)c,
				       c ? c->status.quic_meta : -1,
				       c ? (long)c->quic_stream_id : -1L,
				       c ? (void*)c->outgoing : NULL,
				       c ? c->status.meta_protocol_initiated : -1);

				if(is_established) {
					/* For QUIC connections, we don't need c->outgoing to be set */
					/* QUIC client connections are identified by qconn->is_client */
					if(c && !c->status.meta_protocol_initiated && c->status.quic_meta) {
						logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC handshake complete for %s, initiating metadata protocol",
						       n->name);

						/* Create or discover metadata stream NOW - after handshake, before finish_connecting()
						 * This ensures the stream is immediately usable for ID/ACK exchange */
						if(c->quic_stream_id < 0) {
							if(qconn->is_client) {
								/* Try to discover server-initiated stream */
								logger(DEBUG_PROTOCOL, LOG_INFO, "Attempting stream discovery for %s after handshake", n->name);
								quiche_stream_iter *readable = quiche_conn_readable(qconn->conn);
								bool discovered = false;
								if(readable) {
									uint64_t stream_id;
									if(quiche_stream_iter_next(readable, &stream_id)) {
										c->quic_stream_id = stream_id;
										discovered = true;
										logger(DEBUG_PROTOCOL, LOG_INFO, "Discovered QUIC meta stream %ld from %s after handshake",
										       (long)stream_id, n->name);
									}
									quiche_stream_iter_free(readable);
								}
								/* If not discovered, proactively create client stream */
								if(!discovered) {
									int64_t stream_id = quic_meta_create_stream(qconn);
									if(stream_id >= 0) {
										c->quic_stream_id = stream_id;
										logger(DEBUG_PROTOCOL, LOG_INFO, "Created client QUIC meta stream %ld for %s after handshake",
										       (long)stream_id, n->name);
									} else {
										logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create client QUIC meta stream for %s", n->name);
										return;
									}
								}
							} else {
								/* Server: create stream if not present */
								int64_t stream_id = quic_meta_create_stream(qconn);
								if(stream_id >= 0) {
									c->quic_stream_id = stream_id;
									logger(DEBUG_PROTOCOL, LOG_INFO, "Created QUIC meta stream %ld for %s after handshake",
									       (long)stream_id, n->name);
								} else {
									logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create QUIC meta stream for %s after handshake",
									       n->name);
									return;
								}
							}
						}

						/* Kick off metadata protocol */
						c->status.meta_protocol_initiated = 1;
						/* Continue with normal post-connect processing which sends ID */
						finish_connecting(c);
						/* Immediately flush ID over QUIC stream after finish_connecting sends it */
						/* Use connection address since node address may not be populated yet */
						quic_conn_t *qc = quic_transport_get_connection(n, &c->address);
						if(qc) {
							quic_flush_meta_outbuf(c, qc);
						}
					}
				}
			}

			/* Try to read VPN packets from streams */
			uint8_t vpn_buf[4096];
			ssize_t vpn_len = quic_conn_recv_vpn_packet(qconn, vpn_buf, sizeof(vpn_buf));

			if(vpn_len > 0) {
				/* Create VPN packet and route it */
				vpn_packet_t vpacket;
				vpacket.offset = DEFAULT_PACKET_OFFSET;
				vpacket.priority = 0;  /* QUIC packets have normal priority */

				if((size_t)vpn_len > sizeof(vpacket.data) - vpacket.offset) {
					logger(DEBUG_PROTOCOL, LOG_WARNING, "Received oversized VPN packet (%zd bytes) via QUIC, dropping",
					       vpn_len);
					return;
				}

				vpacket.len = vpn_len;
				memcpy(DATA(&vpacket), vpn_buf, vpn_len);

				/* Get node from connection */
				node_t *node = (node_t *)qconn->node;

				if(node) {
					logger(DEBUG_PROTOCOL, LOG_DEBUG, "Received VPN packet (%zd bytes) from %s via QUIC",
					       vpn_len, node->name);

					/* Route packet through tinc */
					receive_packet(node, &vpacket);
				}
			}

			/* Check for meta-connection data (control plane) */
			node_t *node = (node_t *)qconn->node;

			logger(DEBUG_PROTOCOL, LOG_INFO, "###META### QUIC packet processed: qconn->node=%p", (void*)node);

			if(node) {
				logger(DEBUG_PROTOCOL, LOG_INFO, "###META### node IS NOT NULL, entering if(node) block");
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC node found: name=%s, connection=%p",
				       node->name ? node->name : "NULL", (void*)node->connection);

				if(node->connection) {
					connection_t *c = node->connection;
					logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC checking connection: name=%s, quic_meta=%d, quic_stream_id=%ld, outgoing=%p",
					       c->name ? c->name : "NULL", c->status.quic_meta, (long)c->quic_stream_id, (void*)c->outgoing);

					/* If this connection has a QUIC meta stream, check for readable data */
					if(c->status.quic_meta) {
						/* Stream discovery: if stream_id not yet set, find the first readable stream */
						if(c->quic_stream_id < 0) {
							logger(DEBUG_PROTOCOL, LOG_INFO, "Attempting stream discovery for %s", c->name);
							quiche_stream_iter *readable = quiche_conn_readable(qconn->conn);
							if(readable) {
								uint64_t stream_id;
								if(quiche_stream_iter_next(readable, &stream_id)) {
									c->quic_stream_id = stream_id;
									logger(DEBUG_PROTOCOL, LOG_INFO, "Discovered QUIC meta stream %ld from %s",
									       (long)stream_id, c->name);
								} else {
									logger(DEBUG_PROTOCOL, LOG_DEBUG, "No readable streams yet for %s", c->name);
								}
								quiche_stream_iter_free(readable);
							} else {
								logger(DEBUG_PROTOCOL, LOG_DEBUG, "quiche_conn_readable returned NULL for %s", c->name);
							}
						}

						/* Now check if we have a stream and if it has readable data */
						if(c->quic_stream_id >= 0 && quic_meta_stream_readable(qconn, c->quic_stream_id)) {
							logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC meta stream %ld has readable data from %s",
							       (long)c->quic_stream_id, c->name);

							/* Call receive_meta to process metadata from QUIC stream */
							if(!receive_meta(c)) {
								logger(DEBUG_PROTOCOL, LOG_ERR, "Error processing meta data from QUIC stream %ld",
								       (long)c->quic_stream_id);
							}
						}
					}
				}
			} else {
				/* Handle unbound server-side meta connection: process readable meta
				 * so that ID can be received and node binding can proceed. */
				connection_t *uc = find_unbound_quic_meta_for_peer(qconn);
				if(uc) {
					logger(DEBUG_PROTOCOL, LOG_DEBUG, "Found unbound connection for peer: hostname=%s, quic_stream_id=%ld",
					       uc->hostname ? uc->hostname : "NULL", (long)uc->quic_stream_id);
					/* Discover stream if needed */
					if(uc->quic_stream_id < 0) {
						/* Directly assign stream 0 - clients always use bidirectional stream 0 for metadata */
						uc->quic_stream_id = 0;
						logger(DEBUG_PROTOCOL, LOG_INFO, "Assigned stream 0 to unbound peer %s (clients always use stream 0)",
						       uc->hostname ? uc->hostname : "NULL");
					} else {
						logger(DEBUG_PROTOCOL, LOG_DEBUG, "Unbound connection already has stream_id=%ld", (long)uc->quic_stream_id);
					}

					/* For unbound connections, process metadata through receive_meta()
					 * which will handle reading and parsing the ID message */
					if(uc->quic_stream_id >= 0) {
						logger(DEBUG_PROTOCOL, LOG_DEBUG, "Processing metadata for unbound connection");
						/* receive_meta() now handles unbound connections by looking up qconn by address */
						if(!receive_meta(uc)) {
							logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to process metadata from unbound connection");
						}
					}
				} else {
					logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC packet has no associated node and no unbound meta found");
				}
			}

			/* Flush buffered packets if handshake just completed */
			/* Only flush if we have a bound node (client connections have node set at creation,
			 * server connections get it when first VPN packet arrives) */
			if(quic_conn_is_established(qconn) && qconn->send_buf_count > 0 && qconn->node) {
				quic_conn_flush_buffered_packets(qconn);
			}

			/* Send any pending QUIC packets; keep sending until QUICHE_ERR_DONE */
			while(true) {
				ssize_t sent = quic_conn_send(qconn);
				if(sent <= 0) break;
			}
			/* Drive quiche timeouts to progress handshake */
			quiche_conn_on_timeout(qconn->conn);

			return;  // Packet processed
		}
	}

	/* No existing connection handled this packet */
	/* Check if it's a new connection (Initial packet) */

	/* Header was already parsed above for demultiplexing */
	if(rc < 0) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Failed to parse QUIC header for new connection: %d", rc);
		return;
	}

	/* Before creating new server connection, check if this is a response to existing client connection */
	/* IMPORTANT: Only route packet to client connection if DCID matches our client's SCID
	 * This prevents routing incoming Initial packets from OTHER clients to OUR client connections */
	if(scid_len > 0 && dcid_len > 0 && from) {
		/* Look for client connections that might be waiting for this response */
		for(splay_node_t *node_iter = quic_manager->connections->head; node_iter; node_iter = node_iter->next) {
			quic_conn_t *candidate = (quic_conn_t *)node_iter->data;
			if(candidate && candidate->is_client && candidate->peer_addr.ss_family == from->sa_family) {
				bool addr_match = false;
				/* Check if peer address matches (IP only, port may differ) */
				if(from->sa_family == AF_INET) {
					struct sockaddr_in *addr1 = (struct sockaddr_in *)&candidate->peer_addr;
					struct sockaddr_in *addr2 = (struct sockaddr_in *)from;
					addr_match = (memcmp(&addr1->sin_addr, &addr2->sin_addr, sizeof(addr1->sin_addr)) == 0);
				} else if(from->sa_family == AF_INET6) {
					struct sockaddr_in6 *addr1 = (struct sockaddr_in6 *)&candidate->peer_addr;
					struct sockaddr_in6 *addr2 = (struct sockaddr_in6 *)from;
					addr_match = (memcmp(&addr1->sin6_addr, &addr2->sin6_addr, sizeof(addr1->sin6_addr)) == 0);
				}

				/* Check if DCID in packet matches our client SCID */
				bool dcid_match = (candidate->scid_len == dcid_len &&
				                   memcmp(candidate->scid, dcid, dcid_len) == 0);

				logger(DEBUG_PROTOCOL, LOG_DEBUG,
				       "Client connection candidate: addr_match=%d dcid_match=%d (our_scid=%s packet_dcid=%s)",
				       addr_match, dcid_match,
				       format_cid(candidate->scid, candidate->scid_len),
				       format_cid(dcid, dcid_len));

				if(addr_match && dcid_match) {
					/* Found matching client connection - this is a response to our Initial */
					logger(DEBUG_PROTOCOL, LOG_INFO,
					       "Found existing client connection by DCID match - registering peer SCID=%s from packet header",
					       format_cid(scid, scid_len));

					/* Register peer SCID for demultiplexing */
					register_connection_id(scid, scid_len, candidate);

					/* Now route the packet to this connection */
					ssize_t done = quic_conn_recv(candidate, buf, len);
					if(done > 0) {
						quic_manager->packets_received++;
						quic_manager->bytes_received += done;
						logger(DEBUG_PROTOCOL, LOG_INFO,
						       "Successfully routed packet to existing client connection after peer SCID registration");

						/* Continue with normal packet processing */
						if(quic_conn_is_established(candidate) && candidate->send_buf_count > 0 && candidate->node) {
							quic_conn_flush_buffered_packets(candidate);
						}
						quic_conn_send(candidate);
					} else {
						logger(DEBUG_PROTOCOL, LOG_WARNING,
						       "Failed to process packet on client connection after peer SCID registration: done=%zd",
						       done);
					}
					return;  /* Packet processed, do not create new server connection */
				} else if(addr_match && !dcid_match) {
					/* Address matches but DCID doesn't - this is a NEW incoming connection from the same peer
					 * Continue to create server connection below */
					logger(DEBUG_PROTOCOL, LOG_INFO,
					       "Address matches but DCID mismatch - this is a new incoming Initial, will create server connection");
				}
			}
		}
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Received QUIC packet from unknown source: type=%u version=0x%x", type, version);

	/* Create server connection for new clients
	 * Note: quiche may use different type numbering than QUIC spec
	 * So we don't filter by type here - quiche_accept will handle validation
	 */

	/* Select appropriate socket based on address family */
	int sock_fd = -1;
	for(int i = 0; i < quic_manager->num_sockets; i++) {
		if(quic_manager->sockets[i]->sa.sa.sa_family == from->sa_family) {
			sock_fd = quic_manager->sockets[i]->udp.fd;
			break;
		}
	}

	if(sock_fd < 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "No suitable socket found for incoming connection");
		return;
	}

	/* Create new server connection */
	/* Important: pass client's DCID as Original DCID (odcid) to quiche_accept().
	 * Using client's SCID here breaks address validation and stalls handshake. */
	qconn = quic_conn_new_server(quic_manager->server_config->config,
	                              dcid, dcid_len,  /* Track client's DCID */
	                              dcid, dcid_len,  /* ODCID for quiche_accept = client's DCID */
	                              from, fromlen, sock_fd);

	if(!qconn) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create server connection");
		return;
	}

	/* Node will be auto-detected when first VPN packet is received */
	/* (see automatic binding logic in packet receive handler) */

	/* Add to connection tree */
	splay_insert(quic_manager->connections, qconn);

	/* Register connection IDs for demultiplexing
	 * Register both our SCID and client's DCID (our DCID) so we can find
	 * the connection regardless of which CID is used in incoming packets */
	if(qconn->scid_len > 0) {
		register_connection_id(qconn->scid, qconn->scid_len, qconn);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Registered our SCID (len=%zu)", qconn->scid_len);
	}
	if(qconn->dcid_len > 0) {
		register_connection_id(qconn->dcid, qconn->dcid_len, qconn);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Registered client's DCID (len=%zu)", qconn->dcid_len);
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Created QUIC server connection for new client");

	/* Process the Initial packet */
	ssize_t done = quic_conn_recv(qconn, buf, len);

	if(done < 0) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to process Initial packet: %zd", done);
		splay_delete(quic_manager->connections, qconn);
		quic_conn_free(qconn);
		return;
	}

	quic_manager->packets_received++;
	quic_manager->bytes_received += done;

	/* Send response (Handshake packet) */
	while(true) {
		ssize_t sent = quic_conn_send(qconn);
		if(sent <= 0) break;
	}
	quiche_conn_on_timeout(qconn->conn);
}

/* Internal helper to flush meta outbuf - forward to quic_meta.c function */
static void quic_flush_meta_outbuf(connection_t *c, quic_conn_t *qconn) {
	/* This is just a wrapper - actual implementation is in quic_meta.c
	 * via quic_transport_flush_meta() */
	quic_transport_flush_meta(c);
}
