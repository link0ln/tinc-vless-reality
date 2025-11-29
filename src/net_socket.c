/*
    net_socket.c -- Handle various kinds of sockets.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2018 Guus Sliepen <guus@tinc-vpn.org>
                  2006      Scott Lamb <slamb@slamb.org>
                  2009      Florian Forster <octo@verplant.org>

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

#include <fcntl.h>

#include "address_cache.h"
#include "conf.h"
#include "connection.h"
#include "control_common.h"
#include "list.h"
#include "logger.h"
#include "meta.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"
#include "vless/vless.h"
#include "vless/reality.h"
#include "quic/quic_transport.h"
#include "invitation_server.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

int addressfamily = AF_UNSPEC;
int maxtimeout = 900;
int seconds_till_retry = 5;
int udp_rcvbuf = 1024 * 1024;
int udp_sndbuf = 1024 * 1024;
int max_connection_burst = 10;
int fwmark;

listen_socket_t listen_socket[MAXSOCKETS];
int listen_sockets;
#ifndef HAVE_MINGW
io_t unix_socket;
#endif
list_t *outgoing_list = NULL;

/* Setup sockets */

static void configure_tcp(connection_t *c) {
	int option;

#ifdef O_NONBLOCK
	int flags = fcntl(c->socket, F_GETFL);

	if(fcntl(c->socket, F_SETFL, flags | O_NONBLOCK) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "fcntl for %s fd %d: %s", c->hostname, c->socket, strerror(errno));
	}

#elif defined(WIN32)
	unsigned long arg = 1;

	if(ioctlsocket(c->socket, FIONBIO, &arg) != 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "ioctlsocket for %s fd %d: %s", c->hostname, c->socket, sockstrerror(sockerrno));
	}

#endif

#if defined(TCP_NODELAY)
	option = 1;
	setsockopt(c->socket, IPPROTO_TCP, TCP_NODELAY, (void *)&option, sizeof(option));
#endif

#if defined(IP_TOS) && defined(IPTOS_LOWDELAY)
	option = IPTOS_LOWDELAY;
	setsockopt(c->socket, IPPROTO_IP, IP_TOS, (void *)&option, sizeof(option));
#endif

#if defined(IPV6_TCLASS) && defined(IPTOS_LOWDELAY)
	option = IPTOS_LOWDELAY;
	setsockopt(c->socket, IPPROTO_IPV6, IPV6_TCLASS, (void *)&option, sizeof(option));
#endif

#if defined(SO_MARK)

	if(fwmark) {
		setsockopt(c->socket, SOL_SOCKET, SO_MARK, (void *)&fwmark, sizeof(fwmark));
	}

#endif
}

static bool bind_to_interface(int sd) {
	char *iface;

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	struct ifreq ifr;
	int status;
#endif /* defined(SOL_SOCKET) && defined(SO_BINDTODEVICE) */

	if(!get_config_string(lookup_config(config_tree, "BindToInterface"), &iface)) {
		return true;
	}

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);
	ifr.ifr_ifrn.ifrn_name[IFNAMSIZ - 1] = 0;

	status = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr));

	if(status) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't bind to interface %s: %s", iface,
		       sockstrerror(sockerrno));
		return false;
	}

#else /* if !defined(SOL_SOCKET) || !defined(SO_BINDTODEVICE) */
	(void)sd;
	logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform", "BindToInterface");
#endif

	return true;
}

static bool bind_to_address(connection_t *c) {
	int s = -1;

	for(int i = 0; i < listen_sockets && listen_socket[i].bindto; i++) {
		if(listen_socket[i].sa.sa.sa_family != c->address.sa.sa_family) {
			continue;
		}

		if(s >= 0) {
			return false;
		}

		s = i;
	}

	if(s < 0) {
		return false;
	}

	sockaddr_t sa = listen_socket[s].sa;

	if(sa.sa.sa_family == AF_INET) {
		sa.in.sin_port = 0;
	} else if(sa.sa.sa_family == AF_INET6) {
		sa.in6.sin6_port = 0;
	}

	if(bind(c->socket, &sa.sa, SALEN(sa.sa))) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Can't bind outgoing socket: %s", sockstrerror(sockerrno));
		return false;
	}

	return true;
}

int setup_listen_socket(const sockaddr_t *sa) {
	int nfd;
	char *addrstr;
	int option;
	char *iface;

	nfd = socket(sa->sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(nfd < 0) {
		logger(DEBUG_STATUS, LOG_ERR, "Creating metasocket failed: %s", sockstrerror(sockerrno));
		return -1;
	}

#ifdef FD_CLOEXEC
	fcntl(nfd, F_SETFD, FD_CLOEXEC);
#endif

	/* Optimize TCP settings */

	option = 1;
	setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (void *)&option, sizeof(option));

#if defined(IPV6_V6ONLY)

	if(sa->sa.sa_family == AF_INET6) {
		setsockopt(nfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option));
	}

#else
#warning IPV6_V6ONLY not defined
#endif

#if defined(SO_MARK)

	if(fwmark) {
		setsockopt(nfd, SOL_SOCKET, SO_MARK, (void *)&fwmark, sizeof(fwmark));
	}

#endif

	if(get_config_string
	                (lookup_config(config_tree, "BindToInterface"), &iface)) {
#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);
		ifr.ifr_ifrn.ifrn_name[IFNAMSIZ - 1] = 0;

		if(setsockopt(nfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr))) {
			closesocket(nfd);
			logger(DEBUG_ALWAYS, LOG_ERR, "Can't bind to interface %s: %s", iface,
			       sockstrerror(sockerrno));
			return -1;
		}

#else
		logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform", "BindToInterface");
#endif
	}

	if(bind(nfd, &sa->sa, SALEN(sa->sa))) {
		closesocket(nfd);
		addrstr = sockaddr2hostname(sa);
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't bind to %s/tcp: %s", addrstr, sockstrerror(sockerrno));
		free(addrstr);
		return -1;
	}

	if(listen(nfd, 3)) {
		closesocket(nfd);
		logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "listen", sockstrerror(sockerrno));
		return -1;
	}

	return nfd;
}

int setup_vpn_in_socket(const sockaddr_t *sa) {
	int nfd;
	char *addrstr;
	int option;

	nfd = socket(sa->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

	if(nfd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Creating UDP socket failed: %s", sockstrerror(sockerrno));
		return -1;
	}

#ifdef FD_CLOEXEC
	fcntl(nfd, F_SETFD, FD_CLOEXEC);
#endif

#ifdef O_NONBLOCK
	{
		int flags = fcntl(nfd, F_GETFL);

		if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			closesocket(nfd);
			logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "fcntl",
			       strerror(errno));
			return -1;
		}
	}
#elif defined(WIN32)
	{
		unsigned long arg = 1;

		if(ioctlsocket(nfd, FIONBIO, &arg) != 0) {
			closesocket(nfd);
			logger(DEBUG_ALWAYS, LOG_ERR, "Call to `%s' failed: %s", "ioctlsocket", sockstrerror(sockerrno));
			return -1;
		}
	}
#endif

	option = 1;
	setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (void *)&option, sizeof(option));
	setsockopt(nfd, SOL_SOCKET, SO_BROADCAST, (void *)&option, sizeof(option));

	if(udp_rcvbuf && setsockopt(nfd, SOL_SOCKET, SO_RCVBUF, (void *)&udp_rcvbuf, sizeof(udp_rcvbuf))) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Can't set UDP SO_RCVBUF to %i: %s", udp_rcvbuf, sockstrerror(sockerrno));
	}

	if(udp_sndbuf && setsockopt(nfd, SOL_SOCKET, SO_SNDBUF, (void *)&udp_sndbuf, sizeof(udp_sndbuf))) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Can't set UDP SO_SNDBUF to %i: %s", udp_sndbuf, sockstrerror(sockerrno));
	}

#if defined(IPV6_V6ONLY)

	if(sa->sa.sa_family == AF_INET6) {
		setsockopt(nfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option));
	}

#endif

#if defined(IP_DONTFRAG) && !defined(IP_DONTFRAGMENT)
#define IP_DONTFRAGMENT IP_DONTFRAG
#endif

#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = IP_PMTUDISC_DO;
		setsockopt(nfd, IPPROTO_IP, IP_MTU_DISCOVER, (void *)&option, sizeof(option));
	}

#elif defined(IP_DONTFRAGMENT)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = 1;
		setsockopt(nfd, IPPROTO_IP, IP_DONTFRAGMENT, (void *)&option, sizeof(option));
	}

#endif

#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = IPV6_PMTUDISC_DO;
		setsockopt(nfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, (void *)&option, sizeof(option));
	}

#elif defined(IPV6_DONTFRAG)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = 1;
		setsockopt(nfd, IPPROTO_IPV6, IPV6_DONTFRAG, (void *)&option, sizeof(option));
	}

#endif

#if defined(SO_MARK)

	if(fwmark) {
		setsockopt(nfd, SOL_SOCKET, SO_MARK, (void *)&fwmark, sizeof(fwmark));
	}

#endif

	if(!bind_to_interface(nfd)) {
		closesocket(nfd);
		return -1;
	}

	if(bind(nfd, &sa->sa, SALEN(sa->sa))) {
		closesocket(nfd);
		addrstr = sockaddr2hostname(sa);
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't bind to %s/udp: %s", addrstr, sockstrerror(sockerrno));
		free(addrstr);
		return -1;
	}

	return nfd;
} /* int setup_vpn_in_socket */

static void retry_outgoing_handler(void *data) {
	setup_outgoing_connection(data, true);
}

void retry_outgoing(outgoing_t *outgoing) {
	outgoing->timeout += 5;

	if(outgoing->timeout > maxtimeout) {
		outgoing->timeout = maxtimeout;
	}

	timeout_add(&outgoing->ev, retry_outgoing_handler, outgoing, &(struct timeval) {
		outgoing->timeout, rand() % 100000
	});

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Trying to re-establish outgoing connection in %d seconds", outgoing->timeout);
}

/*
  Initialize VLESS context for a connection (client mode)
*/
static bool init_vless_client(connection_t *c) {
	if(!c) {
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Initializing VLESS client mode for %s", c->hostname);

	/* Create VLESS context in client mode */
	c->vless = vless_ctx_new(true); // true = client mode

	if(!c->vless) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create VLESS context");
		return false;
	}

	/* Load UUID from global configuration */
	if(vless_uuid && *vless_uuid) {
		if(!vless_uuid_from_string(&c->vless->remote_uuid, vless_uuid)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to parse VLESS UUID: %s", vless_uuid);
			vless_ctx_free(c->vless);
			c->vless = NULL;
			return false;
		}
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, "VLESS UUID not configured");
		vless_ctx_free(c->vless);
		c->vless = NULL;
		return false;
	}

	c->status.vless_enabled = 1;

	/* Check if Reality protocol is enabled for this node */
	bool reality_enabled = false;
	/* TODO: Read from node configuration */
	/* get_config_bool(lookup_config(c->config_tree, "RealityEnabled"), &reality_enabled); */

	if(reality_enabled) {
		/* Create Reality client context */
		reality_config_t *reality_config = reality_config_new(false); // false = client mode

		if(!reality_config) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create Reality configuration");
			return false;
		}

		/* TODO: Load Reality configuration from node's host file */
		/* For now, set some defaults */
		strcpy(reality_config->server_name, c->hostname);
		reality_config->fingerprint = REALITY_FP_CHROME;

		c->reality = reality_ctx_new(reality_config);

		if(!c->reality) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create Reality context");
			reality_config_free(reality_config);
			return false;
		}

		c->status.reality_enabled = 1;
	}

	return true;
}

/*
  Perform VLESS handshake on outgoing connection (client side)
*/
static bool vless_connect(connection_t *c) {
	if(!c || !c->vless) {
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Performing VLESS client handshake with %s", c->hostname);

	/* Temporarily set socket to blocking mode for handshake */
#ifdef O_NONBLOCK
	int old_flags = fcntl(c->socket, F_GETFL);
	if(old_flags & O_NONBLOCK) {
		fcntl(c->socket, F_SETFL, old_flags & ~O_NONBLOCK);
	}
#endif

	/* If Reality is enabled, do Reality TLS handshake first */
	if(c->status.reality_enabled && c->reality) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Performing Reality client handshake");

		if(!reality_handshake_client(c->reality, c->socket)) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "Reality handshake failed");
#ifdef O_NONBLOCK
			if(old_flags & O_NONBLOCK) {
				fcntl(c->socket, F_SETFL, old_flags);
			}
#endif
			return false;
		}

		c->status.reality_authenticated = 1;
		logger(DEBUG_PROTOCOL, LOG_INFO, "Reality handshake successful");
	}

	/* Prepare VLESS request */
	/* Address and port should point to the actual tinc daemon, not the Reality dest */
	const char *dest_addr = c->hostname;
	uint16_t dest_port = c->address.in.sin_port;

	if(!vless_handshake_client(c->vless, dest_addr, dest_port, VLESS_CMD_TCP)) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to prepare VLESS request");
#ifdef O_NONBLOCK
		if(old_flags & O_NONBLOCK) {
			fcntl(c->socket, F_SETFL, old_flags);
		}
#endif
		return false;
	}

	/* Send VLESS request */
	if(!vless_send_request(c->vless, c->socket)) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to send VLESS request");
#ifdef O_NONBLOCK
		if(old_flags & O_NONBLOCK) {
			fcntl(c->socket, F_SETFL, old_flags);
		}
#endif
		return false;
	}

	/* Receive VLESS response */
	if(!vless_recv_response(c->vless, c->socket)) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to receive VLESS response");
#ifdef O_NONBLOCK
		if(old_flags & O_NONBLOCK) {
			fcntl(c->socket, F_SETFL, old_flags);
		}
#endif
		return false;
	}

	/* Update connection state */
	c->vless->state = VLESS_STATE_AUTHENTICATED;
	c->status.vless_handshake_done = 1;

	logger(DEBUG_PROTOCOL, LOG_INFO, "VLESS client handshake completed successfully with %s", c->hostname);

	/* Restore non-blocking mode */
#ifdef O_NONBLOCK
	if(old_flags & O_NONBLOCK) {
		fcntl(c->socket, F_SETFL, old_flags);
	}
#endif

	return true;
}

void finish_connecting(connection_t *c) {
	logger(DEBUG_CONNECTIONS, LOG_INFO, "Connected to %s (%s)", c->name, c->hostname);

	c->last_ping_time = now.tv_sec;
	c->status.connecting = false;

	/* Check if VLESS mode is enabled (use global configuration) */
	/* Skip VLESS for QUIC connections - QUIC already provides TLS 1.3 encryption */
	if(vless_mode && !c->status.quic_meta) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "VLESS mode enabled, performing client handshake");

		/* Initialize VLESS client context */
		if(!init_vless_client(c)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize VLESS client for %s", c->hostname);
			terminate_connection(c, false);
			return;
		}

		/* Perform VLESS handshake */
		if(!vless_connect(c)) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "VLESS handshake failed for %s", c->hostname);
			terminate_connection(c, false);
			return;
		}

		logger(DEBUG_PROTOCOL, LOG_INFO, "VLESS connection established with %s", c->hostname);
	} else if(c->status.quic_meta) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC connection, skipping VLESS (already encrypted with TLS 1.3)");
	}

	send_id(c);
}

static void do_outgoing_pipe(connection_t *c, const char *command) {
#ifndef HAVE_MINGW
	int fd[2];

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not create socketpair: %s", sockstrerror(sockerrno));
		return;
	}

	if(fork()) {
		c->socket = fd[0];
		close(fd[1]);
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Using proxy %s", command);
		return;
	}

	close(0);
	close(1);
	close(fd[0]);
	dup2(fd[1], 0);
	dup2(fd[1], 1);
	close(fd[1]);

	// Other filedescriptors should be closed automatically by CLOEXEC

	char *host = NULL;
	char *port = NULL;

	sockaddr2str(&c->address, &host, &port);
	setenv("REMOTEADDRESS", host, true);
	setenv("REMOTEPORT", port, true);
	setenv("NODE", c->name, true);
	setenv("NAME", myself->name, true);

	if(netname) {
		setenv("NETNAME", netname, true);
	}

	int result = system(command);

	if(result < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not execute %s: %s", command, strerror(errno));
	} else if(result) {
		logger(DEBUG_ALWAYS, LOG_ERR, "%s exited with non-zero status %d", command, result);
	}

	exit(result);
#else
	(void)c;
	(void)command;
	logger(DEBUG_ALWAYS, LOG_ERR, "Proxy type exec not supported on this platform!");
	return;
#endif
}

static void handle_meta_write(connection_t *c) {
	if(c->outbuf.len <= c->outbuf.offset) {
		return;
	}

	ssize_t outlen;

	/* Use QUIC stream write if QUIC meta-connection is active */
	if(c->quic_stream_id >= 0 && c->status.quic_meta) {
		if(!c->node) {
			/* Node not created yet (before ACK), keep data buffered */
			logger(DEBUG_META, LOG_DEBUG, "QUIC meta-connection: node not yet created, keeping data buffered");
			return;
		}

		/* Get QUIC connection for this node */
		quic_conn_t *qconn = quic_transport_get_connection(c->node, NULL);

		if(!qconn) {
			logger(DEBUG_META, LOG_ERR, "No QUIC connection for node %s", c->node->name);
			terminate_connection(c, c->edge);
			return;
		}

		/* Try to send buffered data via QUIC stream */
		logger(DEBUG_META, LOG_DEBUG, "QUIC mode: flushing %d bytes from outbuf via stream %ld",
		       c->outbuf.len - c->outbuf.offset, (long)c->quic_stream_id);

		outlen = quic_meta_send(qconn, c->quic_stream_id,
		                        (const uint8_t *)(c->outbuf.data + c->outbuf.offset),
		                        c->outbuf.len - c->outbuf.offset);

		if(outlen < 0) {
			/* Handshake not complete or stream would block - keep data buffered */
			logger(DEBUG_META, LOG_DEBUG, "QUIC stream send would block, keeping data buffered");
			return;
		}
	} else if(c->status.vless_enabled && c->vless && c->status.vless_handshake_done) {
		/* Use VLESS write if VLESS is enabled and handshake is complete */
		logger(DEBUG_META, LOG_DEBUG, "VLESS mode: writing %d bytes through vless_write()",
		       c->outbuf.len - c->outbuf.offset);
		outlen = vless_write(c->vless, c->socket, c->outbuf.data + c->outbuf.offset,
		                     c->outbuf.len - c->outbuf.offset);
	} else {
		/* Regular TCP send */
		outlen = send(c->socket, c->outbuf.data + c->outbuf.offset, c->outbuf.len - c->outbuf.offset, 0);
	}

	if(outlen <= 0) {
		if(!sockerrno || sockerrno == EPIPE) {
			logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection closed by %s (%s)", c->name, c->hostname);
		} else if(sockwouldblock(sockerrno)) {
			logger(DEBUG_META, LOG_DEBUG, "Sending %d bytes to %s (%s) would block", c->outbuf.len - c->outbuf.offset, c->name, c->hostname);
			return;
		} else {
			logger(DEBUG_CONNECTIONS, LOG_ERR, "Could not send %d bytes of data to %s (%s): %s", c->outbuf.len - c->outbuf.offset, c->name, c->hostname, sockstrerror(sockerrno));
		}

		terminate_connection(c, c->edge);
		return;
	}

	buffer_read(&c->outbuf, outlen);

	if(!c->outbuf.len) {
		io_set(&c->io, IO_READ);
	}
}

static void handle_meta_io(void *data, int flags) {
	connection_t *c = data;

	if(c->status.connecting) {
		/*
		   The event loop does not protect against spurious events. Verify that we are actually connected
		   by issuing an empty send() call.

		   Note that the behavior of send() on potentially unconnected sockets differ between platforms:
		   +------------+-----------+-------------+-----------+
		   |   Event    |   POSIX   |    Linux    |  Windows  |
		   +------------+-----------+-------------+-----------+
		   | Spurious   | ENOTCONN  | EWOULDBLOCK | ENOTCONN  |
		   | Failed     | ENOTCONN  | (cause)     | ENOTCONN  |
		   | Successful | (success) | (success)   | (success) |
		   +------------+-----------+-------------+-----------+
		*/
		if(send(c->socket, NULL, 0, 0) != 0) {
			if(sockwouldblock(sockerrno)) {
				return;
			}

			int socket_error;

			if(!socknotconn(sockerrno)) {
				socket_error = sockerrno;
			} else {
				socklen_t len = sizeof(socket_error);
				getsockopt(c->socket, SOL_SOCKET, SO_ERROR, (void *)&socket_error, &len);
			}

			if(socket_error) {
				logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Error while connecting to %s (%s): %s", c->name, c->hostname, sockstrerror(socket_error));
				terminate_connection(c, false);
			}

			return;
		}

		c->status.connecting = false;
		finish_connecting(c);
	}

	if(flags & IO_WRITE) {
		handle_meta_write(c);
	} else {
		handle_meta_connection_data(c);
	}
}

bool do_outgoing_connection(outgoing_t *outgoing) {
	const sockaddr_t *sa;
	struct addrinfo *proxyai = NULL;
	int result;

begin:
	sa = get_recent_address(outgoing->node->address_cache);

	if(!sa) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Could not set up a meta connection to %s", outgoing->node->name);
		retry_outgoing(outgoing);
		return false;
	}

	connection_t *c = new_connection();
	c->outgoing = outgoing;
	memcpy(&c->address, sa, SALEN(sa->sa));
	c->hostname = sockaddr2hostname(&c->address);

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Trying to connect to %s (%s)", outgoing->node->name, c->hostname);

	/* QUIC mode: create QUIC connection and meta stream instead of TCP socket */
	if(transport_mode == TRANSPORT_QUIC) {
		/* Check if QUIC connection already exists in splay tree using the target address */
		quic_conn_t *qconn = quic_transport_get_connection(outgoing->node, sa);

		if(qconn) {
			/* QUIC connection already exists, reuse it */
			logger(DEBUG_CONNECTIONS, LOG_DEBUG, "QUIC connection to %s already exists, reusing", outgoing->node->name);
			free_connection(c);
			return true;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Using QUIC transport for connection to %s", outgoing->node->name);

		/* Create new QUIC connection */
		qconn = quic_transport_create_connection(outgoing->node, true, sa);

		if(!qconn) {
			logger(DEBUG_CONNECTIONS, LOG_ERR, "Failed to create QUIC connection to %s", outgoing->node->name);
			free_connection(c);
			goto begin;
		}

		/* Do NOT create metadata stream here - it must be created AFTER handshake completes
		 * Stream creation moved to quic_transport_handle_packet() when quic_conn_is_established() returns true
		 * This ensures the stream is immediately usable for sending/receiving metadata */

		/* Mark this connection as QUIC-enabled */
		c->status.quic_meta = 1;
		c->quic_stream_id = -1;  /* Will be created after handshake completes */
		c->status.sptps_disabled = 1;
		c->node = outgoing->node;

		/* Create a dummy socket for event loop compatibility (will use QUIC stream instead) */
		c->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

		if(c->socket == -1) {
			logger(DEBUG_CONNECTIONS, LOG_ERR, "Creating dummy socket failed: %s", sockstrerror(sockerrno));
			free_connection(c);
			goto begin;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection to %s created, waiting for handshake", outgoing->node->name);

		/* Skip TCP connection setup */
		goto quic_connection_ready;
	}

	if(!proxytype) {
		c->socket = socket(c->address.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
		configure_tcp(c);
	} else if(proxytype == PROXY_EXEC) {
		do_outgoing_pipe(c, proxyhost);
	} else {
		proxyai = str2addrinfo(proxyhost, proxyport, SOCK_STREAM);

		if(!proxyai) {
			free_connection(c);
			goto begin;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Using proxy at %s port %s", proxyhost, proxyport);
		c->socket = socket(proxyai->ai_family, SOCK_STREAM, IPPROTO_TCP);
		configure_tcp(c);
	}

	if(c->socket == -1) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Creating socket for %s failed: %s", c->hostname, sockstrerror(sockerrno));
		free_connection(c);
		goto begin;
	}

#ifdef FD_CLOEXEC
	fcntl(c->socket, F_SETFD, FD_CLOEXEC);
#endif

	if(proxytype != PROXY_EXEC) {
#if defined(IPV6_V6ONLY)
		int option = 1;

		if(c->address.sa.sa_family == AF_INET6) {
			setsockopt(c->socket, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option));
		}

#endif

		bind_to_interface(c->socket);
		bind_to_address(c);
	}

	/* Connect */

	if(!proxytype) {
		result = connect(c->socket, &c->address.sa, SALEN(c->address.sa));
	} else if(proxytype == PROXY_EXEC) {
		result = 0;
	} else {
		if(!proxyai) {
			abort();
		}

		result = connect(c->socket, proxyai->ai_addr, proxyai->ai_addrlen);
		freeaddrinfo(proxyai);
	}

	if(result == -1 && !sockinprogress(sockerrno)) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Could not connect to %s (%s): %s", outgoing->node->name, c->hostname, sockstrerror(sockerrno));
		free_connection(c);

		goto begin;
	}

quic_connection_ready:
	/* Now that there is a working socket, fill in the rest and register this connection. */

	c->last_ping_time = time(NULL);

	/* For QUIC, connection is already established (handshake happens separately) */
	if(transport_mode != TRANSPORT_QUIC) {
		c->status.connecting = true;
	}
	c->name = xstrdup(outgoing->node->name);
#ifndef DISABLE_LEGACY
	c->outcipher = myself->connection->outcipher;
	c->outdigest = myself->connection->outdigest;
#endif
	c->outmaclength = myself->connection->outmaclength;
	c->outcompression = myself->connection->outcompression;
	c->last_ping_time = now.tv_sec;

	connection_add(c);

	io_add(&c->io, handle_meta_io, c, c->socket, IO_READ | IO_WRITE);

	return true;
}

void setup_outgoing_connection(outgoing_t *outgoing, bool verbose) {
	(void)verbose;
	timeout_del(&outgoing->ev);

	node_t *n = outgoing->node;

	if(!n->address_cache) {
		n->address_cache = open_address_cache(n);
	}

	if(n->connection) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Already connected to %s", n->name);

		if(!n->connection->outgoing) {
			n->connection->outgoing = outgoing;
			return;
		} else {
			goto remove;
		}
	}

	do_outgoing_connection(outgoing);
	return;

remove:
	list_delete(outgoing_list, outgoing);
}

/* VLESS Protocol Helper Functions */

/*
  Initialize VLESS context for a connection (server mode)
*/
static bool init_vless_server(connection_t *c) {
	if(!c) {
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Initializing VLESS server mode for %s", c->hostname);

	/* Create VLESS context in server mode */
	c->vless = vless_ctx_new(false); // false = server mode

	if(!c->vless) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create VLESS context");
		return false;
	}

	/* Load UUID from global configuration */
	if(vless_uuid && *vless_uuid) {
		if(!vless_uuid_from_string(&c->vless->local_uuid, vless_uuid)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to parse VLESS UUID: %s", vless_uuid);
			vless_ctx_free(c->vless);
			c->vless = NULL;
			return false;
		}
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, "VLESS UUID not configured");
		vless_ctx_free(c->vless);
		c->vless = NULL;
		return false;
	}

	c->status.vless_enabled = 1;

	/* Check if Reality protocol is enabled from global configuration */
	if(vless_reality_enabled) {
		/* Create Reality context */
		reality_config_t *reality_config = reality_config_new(true); // true = server mode

		if(!reality_config) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create Reality configuration");
			return false;
		}

		/* Load Reality configuration from global settings */
		if(vless_reality_dest) {
			strncpy(reality_config->dest_domain, vless_reality_dest, sizeof(reality_config->dest_domain) - 1);
		}
		reality_config->dest_port = vless_reality_dest_port;

		if(vless_reality_server_name) {
			strncpy(reality_config->server_name, vless_reality_server_name, sizeof(reality_config->server_name) - 1);
		}

		/* Load keys */
		if(vless_reality_private_key) {
			reality_hex_to_bytes(vless_reality_private_key, reality_config->private_key, 32);
		}
		if(vless_reality_public_key) {
			reality_hex_to_bytes(vless_reality_public_key, reality_config->public_key, 32);
		}
		if(vless_reality_short_id) {
			reality_hex_to_bytes(vless_reality_short_id, reality_config->short_id, 8);
		}

		/* Set fingerprint */
		if(vless_reality_fingerprint) {
			if(strcmp(vless_reality_fingerprint, "chrome") == 0) {
				reality_config->fingerprint = REALITY_FP_CHROME;
			} else if(strcmp(vless_reality_fingerprint, "firefox") == 0) {
				reality_config->fingerprint = REALITY_FP_FIREFOX;
			} else if(strcmp(vless_reality_fingerprint, "safari") == 0) {
				reality_config->fingerprint = REALITY_FP_SAFARI;
			} else {
				reality_config->fingerprint = REALITY_FP_CHROME; // default
			}
		}

		c->reality = reality_ctx_new(reality_config);

		if(!c->reality) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create Reality context");
			reality_config_free(reality_config);
			return false;
		}

		c->status.reality_enabled = 1;
	}

	return true;
}

/*
  Handle TLS invitation request (returns true if handled, connection should be closed)
*/
static bool handle_tls_invitation(connection_t *c) {
	/* Create SSL context for accepting TLS connections */
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
	if(!ssl_ctx) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create SSL context for invitation");
		return false;
	}

	/* Use self-signed certificate - we don't verify (client doesn't verify either) */
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

	/* Try to load existing certificate or generate ephemeral one */
	char cert_path[PATH_MAX];
	char key_path[PATH_MAX];
	snprintf(cert_path, sizeof(cert_path), "%s/invitation.pem", confbase);
	snprintf(key_path, sizeof(key_path), "%s/invitation.key", confbase);

	if(SSL_CTX_use_certificate_file(ssl_ctx, cert_path, SSL_FILETYPE_PEM) != 1 ||
	   SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM) != 1) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Generating ephemeral certificate for invitation server");
		/* Generate ephemeral key pair */
		EVP_PKEY *pkey = EVP_RSA_gen(2048);
		if(!pkey) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to generate RSA key: %s", ERR_error_string(ERR_get_error(), NULL));
			SSL_CTX_free(ssl_ctx);
			return false;
		}

		X509 *x509 = X509_new();
		if(!x509) {
			EVP_PKEY_free(pkey);
			SSL_CTX_free(ssl_ctx);
			return false;
		}

		X509_set_version(x509, 2);
		ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
		X509_gmtime_adj(X509_get_notBefore(x509), 0);
		X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); /* 1 year */
		X509_set_pubkey(x509, pkey);

		X509_NAME *name = X509_get_subject_name(x509);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"tinc-vless", -1, -1, 0);
		X509_set_issuer_name(x509, name);
		X509_sign(x509, pkey, EVP_sha256());

		SSL_CTX_use_certificate(ssl_ctx, x509);
		SSL_CTX_use_PrivateKey(ssl_ctx, pkey);

		X509_free(x509);
		EVP_PKEY_free(pkey);
		logger(DEBUG_PROTOCOL, LOG_INFO, "Ephemeral certificate generated");
	}

	SSL *ssl = SSL_new(ssl_ctx);
	if(!ssl) {
		SSL_CTX_free(ssl_ctx);
		return false;
	}

	SSL_set_fd(ssl, c->socket);

	/* Set socket to blocking mode for TLS handshake */
	int flags = fcntl(c->socket, F_GETFL, 0);
	fcntl(c->socket, F_SETFL, flags & ~O_NONBLOCK);

	/* Accept TLS connection */
	int ret = SSL_accept(ssl);
	if(ret != 1) {
		int ssl_err = SSL_get_error(ssl, ret);
		unsigned long err = ERR_get_error();
		logger(DEBUG_PROTOCOL, LOG_WARNING, "SSL_accept failed for invitation from %s: ssl_err=%d, err=%lu (%s)",
		       c->hostname, ssl_err, err, ERR_error_string(err, NULL));
		fcntl(c->socket, F_SETFL, flags);  /* Restore non-blocking */
		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
		return false;
	}

	/* Restore socket flags after handshake */
	fcntl(c->socket, F_SETFL, flags);

	logger(DEBUG_PROTOCOL, LOG_INFO, "TLS connection accepted for invitation from %s", c->hostname);

	/* Read HTTP request */
	char request[4096];
	int req_len = SSL_read(ssl, request, sizeof(request) - 1);
	if(req_len <= 0) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
		return false;
	}
	request[req_len] = '\0';

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Received request: %.100s...", request);

	/* Check if it's an invitation request */
	if(is_invitation_request(request, req_len)) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Processing invitation request");

		size_t resp_len = 0;
		char *response = handle_invitation_request(request, req_len, &resp_len);

		if(response && resp_len > 0) {
			SSL_write(ssl, response, resp_len);
			free(response);
			logger(DEBUG_PROTOCOL, LOG_INFO, "Invitation response sent to %s", c->hostname);
		}
	} else {
		/* Not an invitation request - send 404 */
		const char *not_found = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
		SSL_write(ssl, not_found, strlen(not_found));
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ssl_ctx);

	return true; /* Connection handled */
}

/*
  Perform VLESS handshake on incoming connection (server side)
*/
static bool vless_accept_connection(connection_t *c) {
	if(!c || !c->vless) {
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Performing VLESS handshake with %s", c->hostname);

	/* Peek at first bytes to detect TLS ClientHello (0x16 0x03 ...) */
	unsigned char peek_buf[3];
	ssize_t peek_len = recv(c->socket, peek_buf, sizeof(peek_buf), MSG_PEEK);

	if(peek_len >= 3 && peek_buf[0] == 0x16 && peek_buf[1] == 0x03) {
		/* This is a TLS ClientHello - likely invitation request */
		logger(DEBUG_PROTOCOL, LOG_INFO, "Detected TLS ClientHello from %s - checking for invitation", c->hostname);

		if(handle_tls_invitation(c)) {
			/* Invitation was handled, connection should be closed */
			return false;
		}

		/* TLS handshake failed, fall through to VLESS */
		logger(DEBUG_PROTOCOL, LOG_WARNING, "TLS invitation handling failed, trying VLESS");
	}

	/* Receive VLESS request */
	if(!vless_recv_request(c->vless, c->socket)) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to receive VLESS request");
		return false;
	}

	/* Verify UUID */
	if(!vless_uuid_equal(&c->vless->request.uuid, &c->vless->local_uuid)) {
		char *received_uuid = vless_uuid_to_string(&c->vless->request.uuid);
		char *expected_uuid = vless_uuid_to_string(&c->vless->local_uuid);
		logger(DEBUG_PROTOCOL, LOG_WARNING, "UUID mismatch: received %s, expected %s",
		       received_uuid, expected_uuid);
		free(received_uuid);
		free(expected_uuid);
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "VLESS UUID verified successfully");

	/* Send VLESS response */
	if(!vless_handshake_server(c->vless)) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to prepare VLESS response");
		return false;
	}

	if(!vless_send_response(c->vless, c->socket)) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to send VLESS response");
		return false;
	}

	/* Update connection state */
	c->vless->state = VLESS_STATE_AUTHENTICATED;
	c->status.vless_handshake_done = 1;

	logger(DEBUG_PROTOCOL, LOG_INFO, "VLESS handshake completed successfully with %s", c->hostname);

	return true;
}

/*
  accept a new tcp connect and create a
  new connection
*/
void handle_new_meta_connection(void *data, int flags) {
	(void)flags;
	listen_socket_t *l = data;
	connection_t *c;
	sockaddr_t sa;
	int fd;
	socklen_t len = sizeof(sa);

	fd = accept(l->tcp.fd, &sa.sa, &len);

	if(fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Accepting a new connection failed: %s", sockstrerror(sockerrno));
		return;
	}

	sockaddrunmap(&sa);

	// Check if we get many connections from the same host

	static sockaddr_t prev_sa;

	if(!sockaddrcmp_noport(&sa, &prev_sa)) {
		static int samehost_burst;
		static int samehost_burst_time;

		if(now.tv_sec - samehost_burst_time > samehost_burst) {
			samehost_burst = 0;
		} else {
			samehost_burst -= now.tv_sec - samehost_burst_time;
		}

		samehost_burst_time = now.tv_sec;
		samehost_burst++;

		if(samehost_burst > max_connection_burst) {
			tarpit(fd);
			return;
		}
	}

	memcpy(&prev_sa, &sa, sizeof(sa));

	// Check if we get many connections from different hosts

	static int connection_burst;
	static int connection_burst_time;

	if(now.tv_sec - connection_burst_time > connection_burst) {
		connection_burst = 0;
	} else {
		connection_burst -= now.tv_sec - connection_burst_time;
	}

	connection_burst_time = now.tv_sec;
	connection_burst++;

	if(connection_burst >= max_connection_burst) {
		connection_burst = max_connection_burst;
		tarpit(fd);
		return;
	}

	// Accept the new connection

	c = new_connection();
	c->name = xstrdup("<unknown>");
#ifndef DISABLE_LEGACY
	c->outcipher = myself->connection->outcipher;
	c->outdigest = myself->connection->outdigest;
#endif
	c->outmaclength = myself->connection->outmaclength;
	c->outcompression = myself->connection->outcompression;

	c->address = sa;
	c->hostname = sockaddr2hostname(&sa);
	c->socket = fd;
	c->last_ping_time = now.tv_sec;

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection from %s", c->hostname);

	io_add(&c->io, handle_meta_io, c, c->socket, IO_READ);

	configure_tcp(c);

	connection_add(c);

	/* Check if VLESS mode is enabled (use global configuration) */
	if(vless_mode) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "VLESS mode enabled, performing VLESS handshake");

		/* Initialize VLESS server context */
		if(!init_vless_server(c)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize VLESS server for %s", c->hostname);
			connection_del(c);
			return;
		}

		/* Perform VLESS handshake */
		if(!vless_accept_connection(c)) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "VLESS handshake failed for %s", c->hostname);

			/* If Reality is enabled, start fallback to destination */
			if(c->status.reality_enabled && c->reality) {
				logger(DEBUG_PROTOCOL, LOG_INFO, "Starting Reality fallback for unauthorized connection from %s", c->hostname);

				if(reality_start_fallback(c->reality, c->socket)) {
					/* Start proxying - for now just log and close */
					/* TODO: Implement proper bidirectional proxy with event loop integration */
					logger(DEBUG_PROTOCOL, LOG_INFO, "Reality fallback established, starting proxy mode");

					/* For demo: send simple HTTP response */
					const char *http_response =
						"HTTP/1.1 302 Found\r\n"
						"Location: https://www.google.com/\r\n"
						"Content-Length: 0\r\n"
						"Connection: close\r\n"
						"\r\n";
					send(c->socket, http_response, strlen(http_response), 0);

					/* Close fallback connection */
					if(c->reality->fallback_fd >= 0) {
						close(c->reality->fallback_fd);
						c->reality->fallback_fd = -1;
					}
				}
			}

			connection_del(c);
			return;
		}

		logger(DEBUG_PROTOCOL, LOG_INFO, "VLESS connection established with %s", c->hostname);
	}

	c->allow_request = ID;
}

#ifndef HAVE_MINGW
/*
  accept a new UNIX socket connection
*/
void handle_new_unix_connection(void *data, int flags) {
	(void)flags;
	io_t *io = data;
	connection_t *c;
	sockaddr_t sa;
	int fd;
	socklen_t len = sizeof(sa);

	fd = accept(io->fd, &sa.sa, &len);

	if(fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Accepting a new connection failed: %s", sockstrerror(sockerrno));
		return;
	}

	sockaddrunmap(&sa);

	c = new_connection();
	c->name = xstrdup("<control>");
	c->address = sa;
	c->hostname = xstrdup("localhost port unix");
	c->socket = fd;
	c->last_ping_time = now.tv_sec;

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection from %s", c->hostname);

	io_add(&c->io, handle_meta_io, c, c->socket, IO_READ);

	connection_add(c);

	c->allow_request = ID;
}
#endif

static void free_outgoing(outgoing_t *outgoing) {
	timeout_del(&outgoing->ev);
	free(outgoing);
}

void try_outgoing_connections(void) {
	/* If there is no outgoing list yet, create one. Otherwise, mark all outgoings as deleted. */

	if(!outgoing_list) {
		outgoing_list = list_alloc((list_action_t)free_outgoing);
	} else {
		for list_each(outgoing_t, outgoing, outgoing_list) {
			outgoing->timeout = -1;
		}
	}

	/* Make sure there is one outgoing_t in the list for each ConnectTo. */

	for(config_t *cfg = lookup_config(config_tree, "ConnectTo"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		char *name;
		get_config_string(cfg, &name);

		if(!check_id(name)) {
			logger(DEBUG_ALWAYS, LOG_ERR,
			       "Invalid name for outgoing connection in %s line %d",
			       cfg->file, cfg->line);
			free(name);
			continue;
		}

		if(!strcmp(name, myself->name)) {
			free(name);
			continue;
		}

		bool found = false;

		for list_each(outgoing_t, outgoing, outgoing_list) {
			if(!strcmp(outgoing->node->name, name)) {
				found = true;
				outgoing->timeout = 0;
				break;
			}
		}

		if(!found) {
			outgoing_t *outgoing = xzalloc(sizeof(*outgoing));
			node_t *n = lookup_node(name);

			if(!n) {
				n = new_node();
				n->name = xstrdup(name);
				node_add(n);
			}

			outgoing->node = n;
			list_insert_tail(outgoing_list, outgoing);
			setup_outgoing_connection(outgoing, true);
		}
	}

	/* Terminate any connections whose outgoing_t is to be deleted. */

	for list_each(connection_t, c, connection_list) {
		if(c->outgoing && c->outgoing->timeout == -1) {
			c->outgoing = NULL;
			logger(DEBUG_CONNECTIONS, LOG_INFO, "No more outgoing connection to %s", c->name);
			terminate_connection(c, c->edge);
		}
	}

	/* Delete outgoing_ts for which there is no ConnectTo. */

	for list_each(outgoing_t, outgoing, outgoing_list)
		if(outgoing->timeout == -1) {
			list_delete_node(outgoing_list, node);
		}
}
