/*
    invitation.h -- VLESS-based invitation system
    Copyright (C) 2025 Tinc VPN Project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#ifndef TINC_INVITATION_H
#define TINC_INVITATION_H

#include <stdbool.h>
#include <stdint.h>

/* Invitation token size (32 bytes = 256 bits) */
#define INVITATION_TOKEN_SIZE 32

/* Invitation validity period: 24 hours */
#define INVITATION_VALIDITY (24 * 3600)

/* Maximum number of IPs in pool (/24 = 254 hosts) */
#define MAX_IP_POOL 254

/*
 * Invitation data structure
 * Contains all information for a new node to join the VPN
 */
typedef struct invitation_data {
    char name[64];              /* Assigned node name */
    char token[64];             /* Invitation token (base64) */
    char vless_uuid[40];        /* Generated VLESS UUID */
    char vpn_address[40];       /* Allocated VPN address (e.g., "10.0.0.5/24") */
    char server_address[256];   /* Server's external address */
    uint16_t server_port;       /* Server's port (443) */
    char server_name[64];       /* Server node name (ConnectTo) */
    char reality_server[256];   /* Reality SNI (e.g., "www.google.com") */
    char reality_fingerprint[32]; /* Reality fingerprint (chrome, etc.) */
    char reality_public_key[64]; /* Reality public key (base64) */
    char reality_shortid[20];   /* Reality ShortID */
    long created;               /* Creation timestamp */
    long expires;               /* Expiration timestamp */
} invitation_data_t;

/*
 * CLI commands (used by tincctl)
 */
int cmd_invite(int argc, char *argv[]);
int cmd_join(int argc, char *argv[]);

/*
 * Create an invitation for a new node.
 *
 * @param name   Name of the node to invite
 * @param url    Output: invitation URL (caller must free)
 * @return 0 on success, negative error code on failure:
 *         -1: Invalid arguments
 *         -2: Node already exists
 *         -3: Failed to allocate VPN IP
 *         -4: Failed to create invitation file
 */
int create_invitation(const char *name, char **url);

/*
 * Validate an incoming invitation token.
 *
 * @param token       Base64-encoded invitation token
 * @param data        Output: invitation data (caller owns)
 * @return true if token is valid, false otherwise
 */
bool validate_invitation_token(const char *token, invitation_data_t *data);

/*
 * Process join request - add new node to hosts.json
 *
 * @param data        Invitation data with node info
 * @return true on success
 */
bool finalize_invitation(const invitation_data_t *data);

/*
 * Generate a random VLESS UUID
 * Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 *
 * @param uuid        Output buffer (at least 37 bytes)
 */
void generate_vless_uuid(char *uuid);

/*
 * Generate a random Reality ShortID
 * Format: 16 hex chars
 *
 * @param shortid     Output buffer (at least 17 bytes)
 */
void generate_reality_shortid(char *shortid);

/*
 * Allocate a free VPN IP address from the subnet
 *
 * @return Allocated IP with prefix (e.g., "10.0.0.5/24") or NULL
 *         Caller must free the returned string
 */
char *allocate_vpn_ip(void);

/*
 * Get my external address for invitation URL
 *
 * @return Address string or NULL (caller must free)
 */
char *get_my_address(void);

/*
 * Clean up expired invitations
 */
void cleanup_expired_invitations(void);

#endif /* TINC_INVITATION_H */
