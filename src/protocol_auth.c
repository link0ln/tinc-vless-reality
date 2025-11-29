/*
    protocol_auth.c -- handle the meta-protocol, authentication
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2017 Guus Sliepen <guus@tinc-vpn.org>

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

#include "conf.h"
#include "connection.h"
#include "control.h"
#include "control_common.h"
#include "cipher.h"
#include "crypto.h"
#include "device.h"
#include "digest.h"
#include "ecdsa.h"
#include "edge.h"
#include "graph.h"
#include "logger.h"
#include "meta.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "prf.h"
#include "protocol.h"
#include "rsa.h"
#include "script.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"
#include "quic/quic_transport.h"

#include "stub/sha512.h"

int invitation_lifetime;
ecdsa_t *invitation_key = NULL;

static bool send_proxyrequest(connection_t *c) {
	switch(proxytype) {
	case PROXY_HTTP: {
		char *host;
		char *port;

		sockaddr2str(&c->address, &host, &port);
		send_request(c, "CONNECT %s:%s HTTP/1.1\r\n\r", host, port);
		free(host);
		free(port);
		return true;
	}

	case PROXY_SOCKS4: {
		if(c->address.sa.sa_family != AF_INET) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Cannot connect to an IPv6 host through a SOCKS 4 proxy!");
			return false;
		}

		char s4req[9 + (proxyuser ? strlen(proxyuser) : 0)];
		s4req[0] = 4;
		s4req[1] = 1;
		memcpy(s4req + 2, &c->address.in.sin_port, 2);
		memcpy(s4req + 4, &c->address.in.sin_addr, 4);

		if(proxyuser) {
			memcpy(s4req + 8, proxyuser, strlen(proxyuser));
		}

		s4req[sizeof(s4req) - 1] = 0;
		c->tcplen = 8;
		return send_meta(c, s4req, sizeof(s4req));
	}

	case PROXY_SOCKS5: {
		int len = 3 + 6 + (c->address.sa.sa_family == AF_INET ? 4 : 16);
		c->tcplen = 2;

		if(proxypass) {
			len += 3 + strlen(proxyuser) + strlen(proxypass);
		}

		char s5req[len];
		int i = 0;
		s5req[i++] = 5;
		s5req[i++] = 1;

		if(proxypass) {
			s5req[i++] = 2;
			s5req[i++] = 1;
			s5req[i++] = strlen(proxyuser);
			memcpy(s5req + i, proxyuser, strlen(proxyuser));
			i += strlen(proxyuser);
			s5req[i++] = strlen(proxypass);
			memcpy(s5req + i, proxypass, strlen(proxypass));
			i += strlen(proxypass);
			c->tcplen += 2;
		} else {
			s5req[i++] = 0;
		}

		s5req[i++] = 5;
		s5req[i++] = 1;
		s5req[i++] = 0;

		if(c->address.sa.sa_family == AF_INET) {
			s5req[i++] = 1;
			memcpy(s5req + i, &c->address.in.sin_addr, 4);
			i += 4;
			memcpy(s5req + i, &c->address.in.sin_port, 2);
			i += 2;
			c->tcplen += 10;
		} else if(c->address.sa.sa_family == AF_INET6) {
			s5req[i++] = 3;
			memcpy(s5req + i, &c->address.in6.sin6_addr, 16);
			i += 16;
			memcpy(s5req + i, &c->address.in6.sin6_port, 2);
			i += 2;
			c->tcplen += 22;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Address family %x not supported for SOCKS 5 proxies!", c->address.sa.sa_family);
			return false;
		}

		if(i > len) {
			abort();
		}

		return send_meta(c, s5req, sizeof(s5req));
	}

	case PROXY_SOCKS4A:
		logger(DEBUG_ALWAYS, LOG_ERR, "Proxy type not implemented yet");
		return false;

	case PROXY_EXEC:
		return true;

	default:
		logger(DEBUG_ALWAYS, LOG_ERR, "Unknown proxy type");
		return false;
	}
}

bool send_id(connection_t *c) {
	gettimeofday(&c->start, NULL);

	int minor = 0;

	if(experimental) {
		if(c->outgoing && !read_ecdsa_public_key(c)) {
			minor = 1;
		} else {
			minor = myself->connection->protocol_minor;
		}
	}

	if(proxytype && c->outgoing)
		if(!send_proxyrequest(c)) {
			return false;
		}

    /* If connection name is unset (incoming QUIC server-side before binding), set it to ourselves */
    if(!c->name) {
        c->name = xstrdup(myself->connection->name);
    }
    bool ok = send_request(c, "%d %s %d.%d", ID, myself->connection->name, myself->connection->protocol_major, minor);
    logger(DEBUG_PROTOCOL, LOG_INFO, "send_id: node=%s host=%s quic_meta=%d ok=%d",
           c->name ? c->name : "(nil)", c->hostname ? c->hostname : "(nil)", c->status.quic_meta, ok);
    return ok;
}

static bool finalize_invitation(connection_t *c, const char *data, uint16_t len) {
	(void)len;

	if(strchr(data, '\n')) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Received invalid key from invited node %s (%s)!\n", c->name, c->hostname);
		return false;
	}

	// Create a new host config file
	char filename[PATH_MAX];
	snprintf(filename, sizeof(filename), "%s" SLASH "hosts" SLASH "%s", confbase, c->name);

	if(!access(filename, F_OK)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Host config file for %s (%s) already exists!\n", c->name, c->hostname);
		return false;
	}

	FILE *f = fopen(filename, "w");

	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error trying to create %s: %s\n", filename, strerror(errno));
		return false;
	}

	fprintf(f, "Ed25519PublicKey = %s\n", data);
	fclose(f);

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Key successfully received from %s (%s)", c->name, c->hostname);

	// Call invitation-accepted script
	environment_t env;
	char *address, *port;

	environment_init(&env);
	environment_add(&env, "NODE=%s", c->name);
	sockaddr2str(&c->address, &address, &port);
	environment_add(&env, "REMOTEADDRESS=%s", address);
	environment_add(&env, "NAME=%s", myself->name);

	execute_script("invitation-accepted", &env);

	environment_exit(&env);

	sptps_send_record(&c->sptps, 2, data, 0);
	return true;
}

static bool receive_invitation_sptps(void *handle, uint8_t type, const void *data, uint16_t len) {
	connection_t *c = handle;

	if(type == 128) {
		return true;
	}

	if(type == 1 && c->status.invitation_used) {
		return finalize_invitation(c, data, len);
	}

	if(type != 0 || len != 18 || c->status.invitation_used) {
		return false;
	}

	// Recover the filename from the cookie and the key
	char *fingerprint = ecdsa_get_base64_public_key(invitation_key);
	char hashbuf[18 + strlen(fingerprint)];
	char cookie[64];
	memcpy(hashbuf, data, 18);
	memcpy(hashbuf + 18, fingerprint, sizeof(hashbuf) - 18);
	sha512(hashbuf, sizeof(hashbuf), cookie);
	b64encode_urlsafe(cookie, cookie, 18);
	free(fingerprint);

	char filename[PATH_MAX], usedname[PATH_MAX];
	snprintf(filename, sizeof(filename), "%s" SLASH "invitations" SLASH "%s", confbase, cookie);
	snprintf(usedname, sizeof(usedname), "%s" SLASH "invitations" SLASH "%s.used", confbase, cookie);

	// Atomically rename the invitation file
	if(rename(filename, usedname)) {
		if(errno == ENOENT) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s tried to use non-existing invitation %s\n", c->hostname, cookie);
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error trying to rename invitation %s\n", cookie);
		}

		return false;
	}

	// Check the timestamp of the invitation
	struct stat st;

	if(stat(usedname, &st)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not stat %s", usedname);
		return false;
	}

	if(st.st_mtime + invitation_lifetime < now.tv_sec) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s tried to use expired invitation %s", c->hostname, cookie);
		return false;
	}

	// Open the renamed file
	FILE *f = fopen(usedname, "r");

	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error trying to open invitation %s\n", cookie);
		return false;
	}

	// Read the new node's Name from the file
	char buf[1024] = "";
	fgets(buf, sizeof(buf), f);
	size_t buflen = strlen(buf);

	// Strip whitespace at the end
	while(buflen && strchr(" \t\r\n", buf[buflen - 1])) {
		buf[--buflen] = 0;
	}

	// Split the first line into variable and value
	len = strcspn(buf, " \t=");
	char *name = buf + len;
	name += strspn(name, " \t");

	if(*name == '=') {
		name++;
		name += strspn(name, " \t");
	}

	buf[len] = 0;

	// Check that it is a valid Name
	if(!*buf || !*name || strcasecmp(buf, "Name") || !check_id(name) || !strcmp(name, myself->name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid invitation file %s\n", cookie);
		fclose(f);
		return false;
	}

	free(c->name);
	c->name = xstrdup(name);

	// Send the node the contents of the invitation file
	rewind(f);
	size_t result;

	while((result = fread(buf, 1, sizeof(buf), f))) {
		sptps_send_record(&c->sptps, 0, buf, result);
	}

	sptps_send_record(&c->sptps, 1, buf, 0);
	fclose(f);
	unlink(usedname);

	c->status.invitation_used = true;

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Invitation %s successfully sent to %s (%s)", cookie, c->name, c->hostname);
	return true;
}

bool id_h(connection_t *c, const char *request) {
	char name[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING " %2d.%3d", name, &c->protocol_major, &c->protocol_minor) < 2) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ID", c->name,
		       c->hostname);
		return false;
	}

	/* Check if this is a control connection */

	if(name[0] == '^' && !strcmp(name + 1, controlcookie)) {
		c->status.control = true;
		c->allow_request = CONTROL;
		c->last_ping_time = now.tv_sec + 3600;

		free(c->name);
		c->name = xstrdup("<control>");

		if(!c->outgoing) {
			send_id(c);
		}

		return send_request(c, "%d %d %d", ACK, TINC_CTL_VERSION_CURRENT, getpid());
	}

	if(name[0] == '?') {
		if(!invitation_key) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got invitation from %s but we don't have an invitation key", c->hostname);
			return false;
		}

		c->ecdsa = ecdsa_set_base64_public_key(name + 1);

		if(!c->ecdsa) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got bad invitation from %s", c->hostname);
			return false;
		}

		c->status.invitation = true;
		char *mykey = ecdsa_get_base64_public_key(invitation_key);

		if(!mykey) {
			return false;
		}

		if(!c->outgoing) {
			send_id(c);
		}

		if(!send_request(c, "%d %s", ACK, mykey)) {
			return false;
		}

		free(mykey);

		c->protocol_minor = 2;

		return sptps_start(&c->sptps, c, false, false, invitation_key, c->ecdsa, "tinc invitation", 15, send_meta_sptps, receive_invitation_sptps);
	}

	/* Check if identity is a valid name */

	if(!check_id(name) || !strcmp(name, myself->name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "ID", c->name,
		       c->hostname, "invalid name");
		return false;
	}

	/* If this is an outgoing connection, make sure we are connected to the right host */

	if(c->outgoing) {
		if(strcmp(c->name, name)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s is %s instead of %s", c->hostname, name,
			       c->name);
			return false;
		}
	} else {
		free(c->name);
		c->name = xstrdup(name);
	}

	/* For incoming connections in QUIC mode, mark as QUIC-capable immediately
	 * This allows send_id() to use buffering path instead of raw metadata
	 * Stream discovery may have already happened in quic_transport.c before this function was called */
	if(!c->outgoing && transport_mode == TRANSPORT_QUIC) {
		c->status.quic_meta = 1;
		c->status.sptps_disabled = 1;
		/* Don't overwrite quic_stream_id if already discovered */
		if(c->quic_stream_id < 0) {
			c->quic_stream_id = -1;  /* Will be discovered when first data arrives */
			logger(DEBUG_PROTOCOL, LOG_INFO, "Incoming connection from %s marked for QUIC mode (stream not yet discovered)",
			       c->name);
		} else {
			logger(DEBUG_PROTOCOL, LOG_INFO, "Incoming connection from %s marked for QUIC mode (stream %ld already discovered)",
			       c->name, (long)c->quic_stream_id);
		}

		/* Hybrid node binding: bind incoming QUIC connection to node via peer address lookup
		 * This completes the hybrid approach:
		 * - Outgoing: pre-bound in quic_transport_create_connection()
		 * - Incoming: bound here when ID message is received */
		node_t *node = lookup_node(c->name);
		if(node) {
			/* Use address-only lookup for incoming connections */
			quic_conn_t *qconn = quic_find_connection_by_address(&c->address);
			if(qconn && !qconn->node) {
				qconn->node = node;
				logger(DEBUG_PROTOCOL, LOG_INFO, "Bound incoming QUIC connection from %s (%s) to node via ID message",
				       c->name, c->hostname);
			} else if(qconn && qconn->node) {
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC connection from %s already bound to node", c->name);
			} else {
				logger(DEBUG_PROTOCOL, LOG_WARNING, "No QUIC connection found for incoming connection from %s (%s)",
				       c->name, c->hostname);
			}
		} else {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Node lookup failed for %s", c->name);
		}
	}

	/* Check if version matches */

	if(c->protocol_major != myself->connection->protocol_major) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s (%s) uses incompatible version %d.%d",
		       c->name, c->hostname, c->protocol_major, c->protocol_minor);
		return false;
	}

	if(bypass_security) {
		if(!c->config_tree) {
			init_configuration(&c->config_tree);
		}

		c->allow_request = ACK;

		if(!c->outgoing) {
			send_id(c);
		}

		return send_ack(c);
	}

	if(!experimental) {
		c->protocol_minor = 0;
	}

	if(!c->config_tree) {
		init_configuration(&c->config_tree);

		if(!read_host_config(c->config_tree, c->name, false)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s had unknown identity (%s)", c->hostname, c->name);
			return false;
		}

		if(experimental) {
			read_ecdsa_public_key(c);
		}

		/* Ignore failures if no key known yet */
	}

	if(c->protocol_minor && !ecdsa_active(c->ecdsa)) {
		c->protocol_minor = 1;
	}

	/* Forbid version rollback for nodes whose Ed25519 key we know */

	if(ecdsa_active(c->ecdsa) && c->protocol_minor < 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s (%s) tries to roll back protocol version to %d.%d",
		       c->name, c->hostname, c->protocol_major, c->protocol_minor);
		return false;
	}

    c->allow_request = METAKEY;

    if(!c->outgoing) {
        /* Immediate ACK only if QUIC meta active AND stream ready */
        if(c->status.quic_meta && c->quic_stream_id >= 0) {
            c->allow_request = ACK;
            logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC meta: sending immediate ACK to %s on stream %ld", c->name, (long)c->quic_stream_id);
            if(!send_ack(c)) {
                logger(DEBUG_PROTOCOL, LOG_WARNING, "Immediate ACK failed for %s, deferring to transport", c->name);
            } else {
                extern void quic_transport_flush_meta(connection_t *c);
                quic_transport_flush_meta(c);
            }
        } else {
            /* Defer ACK until stream is ready; transport will trigger meta once handshake completes */
            logger(DEBUG_PROTOCOL, LOG_DEBUG, "Deferring ACK for %s (quic_meta=%d stream=%ld)", c->name, c->status.quic_meta, (long)c->quic_stream_id);
        }
    }

	/* Disable SPTPS when VLESS is active to avoid double encryption */
	if(c->status.vless_enabled && c->vless && disable_sptps_with_vless) {
		c->status.sptps_disabled = 1;
		c->allow_request = ACK;
		logger(DEBUG_PROTOCOL, LOG_INFO, "SPTPS disabled for VLESS connection to %s (%s)",
		       c->name, c->hostname);
		/* Server must send its ID before ACK so client can process it */
		if(!c->outgoing) {
			if(!send_id(c)) {
				return false;
			}
		}
		/* Send ACK to complete authentication handshake */
		return send_ack(c);
	}

    if(c->protocol_minor >= 2) {
        c->allow_request = ACK;
		char label[25 + strlen(myself->name) + strlen(c->name)];

		if(c->outgoing) {
			snprintf(label, sizeof(label), "tinc TCP key expansion %s %s", myself->name, c->name);
		} else {
			snprintf(label, sizeof(label), "tinc TCP key expansion %s %s", c->name, myself->name);
		}

        /* If QUIC meta is active, SPTPS не используется для метаданных */
        if(c->status.quic_meta) {
            logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC meta active: skipping SPTPS start for %s", c->name);
            return true;
        }
        return sptps_start(&c->sptps, c, c->outgoing, false, myself->connection->ecdsa, c->ecdsa, label, sizeof(label), send_meta_sptps, receive_meta_sptps);
    } else {
        return send_metakey(c);
    }
}

#ifndef DISABLE_LEGACY
bool send_metakey(connection_t *c) {
	if(!myself->connection->rsa) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Peer %s (%s) uses legacy protocol which we don't support", c->name, c->hostname);
		return false;
	}

	if(!read_rsa_public_key(c)) {
		return false;
	}

	/* We need to use a stream mode for the meta protocol. Use AES for this,
	   but try to match the key size with the one from the cipher selected
	   by Cipher.
	*/

	int keylen = cipher_keylength(myself->incipher);

	if(keylen <= 16) {
		c->outcipher = cipher_open_by_name("aes-128-cfb");
	} else if(keylen <= 24) {
		c->outcipher = cipher_open_by_name("aes-192-cfb");
	} else {
		c->outcipher = cipher_open_by_name("aes-256-cfb");
	}

	if(!c) {
		return false;
	}

	c->outbudget = cipher_budget(c->outcipher);

	if(!(c->outdigest = digest_open_by_name("sha256", -1))) {
		return false;
	}

	const size_t len = rsa_size(c->rsa);
	char key[len];
	char enckey[len];
	char hexkey[2 * len + 1];

	/* Create a random key */

	randomize(key, len);

	/* The message we send must be smaller than the modulus of the RSA key.
	   By definition, for a key of k bits, the following formula holds:

	   2^(k-1) <= modulus < 2^(k)

	   Where ^ means "to the power of", not "xor".
	   This means that to be sure, we must choose our message < 2^(k-1).
	   This can be done by setting the most significant bit to zero.
	 */

	key[0] &= 0x7F;

	if(!cipher_set_key_from_rsa(c->outcipher, key, len, true)) {
		return false;
	}

	if(debug_level >= DEBUG_SCARY_THINGS) {
		bin2hex(key, hexkey, len);
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, "Generated random meta key (unencrypted): %s", hexkey);
	}

	/* Encrypt the random data

	   We do not use one of the PKCS padding schemes here.
	   This is allowed, because we encrypt a totally random string
	   with a length equal to that of the modulus of the RSA key.
	 */

	if(!rsa_public_encrypt(c->rsa, key, len, enckey)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error during encryption of meta key for %s (%s)", c->name, c->hostname);
		return false;
	}

	/* Convert the encrypted random data to a hexadecimal formatted string */

	bin2hex(enckey, hexkey, len);

	/* Send the meta key */

	bool result = send_request(c, "%d %d %d %d %d %s", METAKEY,
	                           cipher_get_nid(c->outcipher),
	                           digest_get_nid(c->outdigest), c->outmaclength,
	                           c->outcompression, hexkey);

	c->status.encryptout = true;
	return result;
}

bool metakey_h(connection_t *c, const char *request) {
	if(!myself->connection->rsa) {
		return false;
	}

	char hexkey[MAX_STRING_SIZE];
	int cipher, digest, maclength, compression;
	const size_t len = rsa_size(myself->connection->rsa);
	char enckey[len];
	char key[len];

	if(sscanf(request, "%*d %d %d %d %d " MAX_STRING, &cipher, &digest, &maclength, &compression, hexkey) != 5) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "METAKEY", c->name, c->hostname);
		return false;
	}

	/* Convert the challenge from hexadecimal back to binary */

	size_t inlen = hex2bin(hexkey, enckey, sizeof(enckey));

	/* Check if the length of the meta key is all right */

	if(inlen != len) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong keylength");
		return false;
	}

	/* Decrypt the meta key */

	if(!rsa_private_decrypt(myself->connection->rsa, enckey, len, key)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error during decryption of meta key for %s (%s)", c->name, c->hostname);
		return false;
	}

	if(debug_level >= DEBUG_SCARY_THINGS) {
		bin2hex(key, hexkey, len);
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, "Received random meta key (unencrypted): %s", hexkey);
	}

	/* Check and lookup cipher and digest algorithms */

	if(cipher) {
		if(!(c->incipher = cipher_open_by_nid(cipher)) || !cipher_set_key_from_rsa(c->incipher, key, len, false)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error during initialisation of cipher from %s (%s)", c->name, c->hostname);
			return false;
		}
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "null cipher");
		return false;
	}

	c->inbudget = cipher_budget(c->incipher);

	if(digest) {
		if(!(c->indigest = digest_open_by_nid(digest, -1))) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error during initialisation of digest from %s (%s)", c->name, c->hostname);
			return false;
		}
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "null digest");
		return false;
	}

	c->status.decryptin = true;

	c->allow_request = CHALLENGE;

	return send_challenge(c);
}

bool send_challenge(connection_t *c) {
	const size_t len = rsa_size(c->rsa);
	char buffer[len * 2 + 1];

	c->hischallenge = xrealloc(c->hischallenge, len);

	/* Copy random data to the buffer */

	randomize(c->hischallenge, len);

	/* Convert to hex */

	bin2hex(c->hischallenge, buffer, len);

	/* Send the challenge */

	return send_request(c, "%d %s", CHALLENGE, buffer);
}

bool challenge_h(connection_t *c, const char *request) {
	if(!myself->connection->rsa) {
		return false;
	}

	char buffer[MAX_STRING_SIZE];
	const size_t len = rsa_size(myself->connection->rsa);

	if(sscanf(request, "%*d " MAX_STRING, buffer) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "CHALLENGE", c->name, c->hostname);
		return false;
	}

	/* Check if the length of the challenge is all right */

	if(strlen(buffer) != (size_t)len * 2) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge length");
		return false;
	}

	c->mychallenge = xrealloc(c->mychallenge, len);

	/* Convert the challenge from hexadecimal back to binary */

	hex2bin(buffer, c->mychallenge, len);

	/* The rest is done by send_chal_reply() */

	c->allow_request = CHAL_REPLY;

	if(c->outgoing) {
		return send_chal_reply(c);
	} else {
		return true;
	}
}

bool send_chal_reply(connection_t *c) {
	const size_t len = rsa_size(myself->connection->rsa);
	size_t digestlen = digest_length(c->indigest);
	char digest[digestlen * 2 + 1];

	/* Calculate the hash from the challenge we received */

	if(!digest_create(c->indigest, c->mychallenge, len, digest)) {
		return false;
	}

	free(c->mychallenge);
	c->mychallenge = NULL;

	/* Convert the hash to a hexadecimal formatted string */

	bin2hex(digest, digest, digestlen);

	/* Send the reply */

	return send_request(c, "%d %s", CHAL_REPLY, digest);
}

bool chal_reply_h(connection_t *c, const char *request) {
	char hishash[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING, hishash) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "CHAL_REPLY", c->name,
		       c->hostname);
		return false;
	}

	/* Convert the hash to binary format */

	size_t inlen = hex2bin(hishash, hishash, sizeof(hishash));

	/* Check if the length of the hash is all right */

	if(inlen != digest_length(c->outdigest)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge reply length");
		return false;
	}


	/* Verify the hash */

	if(!digest_verify(c->outdigest, c->hischallenge, rsa_size(c->rsa), hishash)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge reply");
		return false;
	}

	/* Identity has now been positively verified.
	   Send an acknowledgement with the rest of the information needed.
	 */

	free(c->hischallenge);
	c->hischallenge = NULL;
	c->allow_request = ACK;

	if(!c->outgoing) {
		send_chal_reply(c);
	}

	return send_ack(c);
}

static bool send_upgrade(connection_t *c) {
	/* Special case when protocol_minor is 1: the other end is Ed25519 capable,
	 * but doesn't know our key yet. So send it now. */

	char *pubkey = ecdsa_get_base64_public_key(myself->connection->ecdsa);

	if(!pubkey) {
		return false;
	}

	bool result = send_request(c, "%d %s", ACK, pubkey);
	free(pubkey);
	return result;
}
#else
bool send_metakey(connection_t *c) {
	(void)c;
	return false;
}

bool metakey_h(connection_t *c, const char *request) {
	(void)c;
	(void)request;
	return false;
}

bool send_challenge(connection_t *c) {
	(void)c;
	return false;
}

bool challenge_h(connection_t *c, const char *request) {
	(void)c;
	(void)request;
	return false;
}

bool send_chal_reply(connection_t *c) {
	(void)c;
	return false;
}

bool chal_reply_h(connection_t *c, const char *request) {
	(void)c;
	(void)request;
	return false;
}

static bool send_upgrade(connection_t *c) {
	(void)c;
	return false;
}
#endif

bool send_ack(connection_t *c) {
	if(c->protocol_minor == 1) {
		return send_upgrade(c);
	}

	/* ACK message contains rest of the information the other end needs
	   to create node_t and edge_t structures. */

	struct timeval now;
	bool choice;

	/* Estimate weight */

	gettimeofday(&now, NULL);
	c->estimated_weight = (now.tv_sec - c->start.tv_sec) * 1000 + (now.tv_usec - c->start.tv_usec) / 1000;

	/* Check some options */

	if((get_config_bool(lookup_config(c->config_tree, "IndirectData"), &choice) && choice) || myself->options & OPTION_INDIRECT) {
		c->options |= OPTION_INDIRECT;
	}

	if((get_config_bool(lookup_config(c->config_tree, "TCPOnly"), &choice) && choice) || myself->options & OPTION_TCPONLY) {
		c->options |= OPTION_TCPONLY | OPTION_INDIRECT;
	}

	if(myself->options & OPTION_PMTU_DISCOVERY && !(c->options & OPTION_TCPONLY)) {
		c->options |= OPTION_PMTU_DISCOVERY;
	}

	choice = myself->options & OPTION_CLAMP_MSS;
	get_config_bool(lookup_config(c->config_tree, "ClampMSS"), &choice);

	if(choice) {
		c->options |= OPTION_CLAMP_MSS;
	}

	if(!get_config_int(lookup_config(c->config_tree, "Weight"), &c->estimated_weight)) {
		get_config_int(lookup_config(config_tree, "Weight"), &c->estimated_weight);
	}

    bool ok = send_request(c, "%d %s %d %x", ACK, myport, c->estimated_weight, (c->options & 0xffffff) | (experimental ? (PROT_MINOR << 24) : 0));
    logger(DEBUG_PROTOCOL, LOG_INFO, "send_ack: to=%s host=%s quic_meta=%d ok=%d",
           c->name ? c->name : "(nil)", c->hostname ? c->hostname : "(nil)", c->status.quic_meta, ok);
    return ok;
}

static void send_everything(connection_t *c) {
	/* Send all known subnets and edges */

	if(disablebuggypeers) {
		static struct {
			vpn_packet_t pkt;
			char pad[MAXBUFSIZE - MAXSIZE];
		} zeropkt;

		memset(&zeropkt, 0, sizeof(zeropkt));
		zeropkt.pkt.len = MAXBUFSIZE;
		send_tcppacket(c, &zeropkt.pkt);
	}

	if(tunnelserver) {
		for splay_each(subnet_t, s, myself->subnet_tree) {
			send_add_subnet(c, s);
		}

		return;
	}

	for splay_each(node_t, n, node_tree) {
		for splay_each(subnet_t, s, n->subnet_tree) {
			send_add_subnet(c, s);
		}

		for splay_each(edge_t, e, n->edge_tree) {
			send_add_edge(c, e);
		}
	}
}

static bool upgrade_h(connection_t *c, const char *request) {
	char pubkey[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING, pubkey) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ACK", c->name, c->hostname);
		return false;
	}

	if(ecdsa_active(c->ecdsa) || read_ecdsa_public_key(c)) {
		char *knownkey = ecdsa_get_base64_public_key(c->ecdsa);
		bool different = strcmp(knownkey, pubkey);
		free(knownkey);

		if(different) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Already have an Ed25519 public key from %s (%s) which is different from the one presented now!", c->name, c->hostname);
			return false;
		}

		logger(DEBUG_ALWAYS, LOG_INFO, "Already have Ed25519 public key from %s (%s), ignoring.", c->name, c->hostname);
		c->allow_request = TERMREQ;
		return send_termreq(c);
	}

	c->ecdsa = ecdsa_set_base64_public_key(pubkey);

	if(!c->ecdsa) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Got bad Ed25519 public key from %s (%s), not upgrading.", c->name, c->hostname);
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Got Ed25519 public key from %s (%s), upgrading!", c->name, c->hostname);
	append_config_file(c->name, "Ed25519PublicKey", pubkey);
	c->allow_request = TERMREQ;

	if(c->outgoing) {
		c->outgoing->timeout = 0;
	}

	return send_termreq(c);
}

bool ack_h(connection_t *c, const char *request) {
	if(c->protocol_minor == 1) {
		return upgrade_h(c, request);
	}

	char hisport[MAX_STRING_SIZE];
	int weight, mtu;
	uint32_t options;
	node_t *n;
	bool choice;

	if(sscanf(request, "%*d " MAX_STRING " %d %x", hisport, &weight, &options) != 3) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ACK", c->name,
		       c->hostname);
		return false;
	}

	/* Check if we already have a node_t for him */

	n = lookup_node(c->name);

	if(!n) {
		n = new_node();
		n->name = xstrdup(c->name);
		node_add(n);
	} else {
		if(n->connection) {
			/* Oh dear, we already have a connection to this node. */
			logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Established a second connection with %s (%s), closing old connection", n->connection->name, n->connection->hostname);

			if(n->connection->outgoing) {
				if(c->outgoing) {
					logger(DEBUG_ALWAYS, LOG_WARNING, "Two outgoing connections to the same node!");
				} else {
					c->outgoing = n->connection->outgoing;
				}

				n->connection->outgoing = NULL;
			}

			terminate_connection(n->connection, false);
			/* Run graph algorithm to purge key and make sure up/down scripts are rerun with new IP addresses and stuff */
			graph();
		}
	}

	n->connection = c;
	c->node = n;

	/* QUIC meta-connection setup (if enabled) */
	if(!c->status.vless_enabled && (transport_mode == TRANSPORT_QUIC || transport_mode == TRANSPORT_HYBRID)) {
		/* Only create QUIC connections for outgoing (client-side) connections */
		/* Incoming connections will use the QUIC connection created by the peer */
		if(c->outgoing) {
			logger(DEBUG_PROTOCOL, LOG_INFO, "Setting up QUIC meta-connection for %s", c->name);

			/* Ensure node has address information from the connection */
			if(!n->address.sa.sa_family && c->address.sa.sa_family) {
				memcpy(&n->address, &c->address, sizeof(n->address));
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "Copied connection address to node %s", n->name);
			}

			/* Create or get QUIC connection for this node */
			quic_conn_t *qconn = quic_transport_get_connection(n, NULL);
			if(!qconn) {
				/* Create new QUIC connection (client-side only) */
				qconn = quic_transport_create_connection(n, true, &c->address);
				if(!qconn) {
					logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create QUIC connection for %s", c->name);
					if(transport_mode == TRANSPORT_QUIC) {
						/* QUIC-only mode: fail the connection */
						return false;
					}
					/* HYBRID mode: fall back to TCP */
					logger(DEBUG_PROTOCOL, LOG_WARNING, "Falling back to TCP for %s", c->name);
				}
			}

		if(qconn) {
			/* Create bidirectional meta stream */
			int64_t stream_id = quic_meta_create_stream(qconn);
			if(stream_id >= 0) {
				c->quic_stream_id = stream_id;
				c->status.quic_meta = 1;
				c->status.sptps_disabled = 1;  /* Disable SPTPS - QUIC provides encryption */
				logger(DEBUG_PROTOCOL, LOG_INFO, "QUIC meta stream %ld created for %s",
				       (long)stream_id, c->name);
			} else {
				logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to create QUIC meta stream for %s", c->name);
				if(transport_mode == TRANSPORT_QUIC) {
					return false;
				}
			}
		}
		} else {
			/* Incoming connection: discover the QUIC stream from the existing QUIC connection */
			/* Ensure node has address information from the connection */
			if(!n->address.sa.sa_family && c->address.sa.sa_family) {
				memcpy(&n->address, &c->address, sizeof(n->address));
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "Copied connection address to node %s for incoming connection", n->name);
			}

			/* Get the QUIC connection for this node (created by the peer's outgoing connection) */
			quic_conn_t *qconn = quic_transport_get_connection(n, NULL);
			if(qconn) {
				/* The peer (client) has already created a stream
				 * We'll discover it when data arrives - for now just mark this connection as QUIC-capable */
				c->quic_stream_id = -1;  /* Will be set when first stream data arrives */
				c->status.quic_meta = 1;
				c->status.sptps_disabled = 1;
				logger(DEBUG_PROTOCOL, LOG_INFO, "Incoming connection from %s will use existing QUIC connection (stream discovery deferred)",
				       c->name);
			} else {
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "No existing QUIC connection found for incoming connection from %s, using TCP", c->name);
			}
		}  /* end if(c->outgoing) */
	}

	if(!(c->options & options & OPTION_PMTU_DISCOVERY)) {
		c->options &= ~OPTION_PMTU_DISCOVERY;
		options &= ~OPTION_PMTU_DISCOVERY;
	}

	c->options |= options;

	if(get_config_int(lookup_config(c->config_tree, "PMTU"), &mtu) && mtu < n->mtu) {
		n->mtu = mtu;
	}

	if(get_config_int(lookup_config(config_tree, "PMTU"), &mtu) && mtu < n->mtu) {
		n->mtu = mtu;
	}

	if(get_config_bool(lookup_config(c->config_tree, "ClampMSS"), &choice)) {
		if(choice) {
			c->options |= OPTION_CLAMP_MSS;
		} else {
			c->options &= ~OPTION_CLAMP_MSS;
		}
	}

	/* Activate this connection */

	c->allow_request = ALL;

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection with %s (%s) activated", c->name,
	       c->hostname);

	/* Send him everything we know */

	send_everything(c);

	/* Create an edge_t for this connection */

	c->edge = new_edge();
	c->edge->from = myself;
	c->edge->to = n;
	sockaddrcpy(&c->edge->address, &c->address);
	sockaddr_setport(&c->edge->address, hisport);
	sockaddr_t local_sa;
	socklen_t local_salen = sizeof(local_sa);

	if(getsockname(c->socket, &local_sa.sa, &local_salen) < 0) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Could not get local socket address for connection with %s", c->name);
	} else {
		sockaddr_setport(&local_sa, myport);
		c->edge->local_address = local_sa;
	}

	c->edge->weight = (weight + c->estimated_weight) / 2;
	c->edge->connection = c;
	c->edge->options = c->options;

	edge_add(c->edge);

	/* Notify everyone of the new edge */

	if(tunnelserver) {
		send_add_edge(c, c->edge);
	} else {
		send_add_edge(everyone, c->edge);
	}

	/* Run MST and SSSP algorithms */

	graph();

	return true;
}
