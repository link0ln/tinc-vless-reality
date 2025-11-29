/*
    invitation.c -- VLESS-based invitation system
    Copyright (C) 2025 Tinc VPN Project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <ctype.h>

#include "invitation.h"
#include "invitation_client.h"
#include "conf.h"
#include "crypto.h"
#include "hosts_json.h"
#include "logger.h"
#include "names.h"
#include "netutl.h"
#include "utils.h"
#include "xalloc.h"

/* Forward declarations */
static char *get_invitations_dir(void);
static bool parse_vpn_address(uint32_t *network, int *prefix, char *my_ip, size_t my_ip_size);

/* Base64 URL-safe encoding table */
static const char base64url_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/*
 * Base64 URL-safe encode
 */
static char *base64url_encode(const unsigned char *data, size_t len) {
    size_t outlen = ((len + 2) / 3) * 4 + 1;
    char *out = xmalloc(outlen);
    char *p = out;

    for(size_t i = 0; i < len; i += 3) {
        unsigned int n = data[i] << 16;
        if(i + 1 < len) n |= data[i + 1] << 8;
        if(i + 2 < len) n |= data[i + 2];

        *p++ = base64url_table[(n >> 18) & 0x3f];
        *p++ = base64url_table[(n >> 12) & 0x3f];
        *p++ = (i + 1 < len) ? base64url_table[(n >> 6) & 0x3f] : '=';
        *p++ = (i + 2 < len) ? base64url_table[n & 0x3f] : '=';
    }

    *p = '\0';
    return out;
}

/*
 * Generate random bytes
 */
static void generate_random_bytes(unsigned char *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "r");
    if(f) {
        size_t read = fread(buf, 1, len, f);
        fclose(f);
        if(read == len) return;
    }
    /* Fallback to rand() if /dev/urandom not available */
    srand(time(NULL) ^ getpid());
    for(size_t i = 0; i < len; i++) {
        buf[i] = rand() & 0xFF;
    }
}

/*
 * Generate a random VLESS UUID
 * Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 */
void generate_vless_uuid(char *uuid) {
    unsigned char bytes[16];
    generate_random_bytes(bytes, 16);

    /* Set version 4 (random) */
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    /* Set variant (RFC 4122) */
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    snprintf(uuid, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5],
             bytes[6], bytes[7],
             bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

/*
 * Generate a random Reality ShortID
 * Format: 16 hex chars
 */
void generate_reality_shortid(char *shortid) {
    unsigned char bytes[8];
    generate_random_bytes(bytes, 8);

    for(int i = 0; i < 8; i++) {
        snprintf(shortid + i * 2, 3, "%02x", bytes[i]);
    }
}

/*
 * Generate random token
 */
static char *generate_token(void) {
    unsigned char token_bytes[INVITATION_TOKEN_SIZE];
    generate_random_bytes(token_bytes, sizeof(token_bytes));
    return base64url_encode(token_bytes, sizeof(token_bytes));
}

/*
 * Get hash of token for filename (first 16 chars)
 */
static char *token_to_filename(const char *token) {
    char *filename = xmalloc(17);
    strncpy(filename, token, 16);
    filename[16] = '\0';
    return filename;
}

/*
 * Get the invitations directory path
 */
static char *get_invitations_dir(void) {
    char *path = NULL;
    xasprintf(&path, "%s/invitations", confbase);
    return path;
}

/*
 * Ensure invitations directory exists
 */
static bool ensure_invitations_dir(void) {
    char *dir = get_invitations_dir();

    if(mkdir(dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create invitations directory %s: %s\n",
               dir, strerror(errno));
        free(dir);
        return false;
    }

    free(dir);
    return true;
}

/*
 * Clean up expired invitations
 */
void cleanup_expired_invitations(void) {
    char *dir = get_invitations_dir();
    DIR *d = opendir(dir);

    if(!d) {
        free(dir);
        return;
    }

    time_t now = time(NULL);
    struct dirent *ent;

    while((ent = readdir(d)) != NULL) {
        if(ent->d_name[0] == '.') continue;

        char *filepath = NULL;
        xasprintf(&filepath, "%s/%s", dir, ent->d_name);

        struct stat st;
        if(stat(filepath, &st) == 0) {
            if(now - st.st_mtime > INVITATION_VALIDITY) {
                unlink(filepath);
                fprintf(stderr, "Removed expired invitation: %s\n", ent->d_name);
            }
        }

        free(filepath);
    }

    closedir(d);
    free(dir);
}

/*
 * Convert uint32_t IP to string
 */
static void ip_to_string(uint32_t ip, char *buf, size_t size) {
    snprintf(buf, size, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
}

/*
 * Parse IP string to uint32_t
 */
static uint32_t string_to_ip(const char *str) {
    int a, b, c, d;
    if(sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        return 0;
    }
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
}

/*
 * Parse VPNAddress from tinc.conf (e.g., "10.0.0.1/24")
 */
static bool parse_vpn_address(uint32_t *network, int *prefix, char *my_ip, size_t my_ip_size) {
    char vpn_addr[64] = {0};
    char *conf_path = NULL;
    xasprintf(&conf_path, "%s/tinc.conf", confbase);

    FILE *f = fopen(conf_path, "r");
    free(conf_path);

    if(!f) {
        return false;
    }

    char line[256];
    while(fgets(line, sizeof(line), f)) {
        char *p = line;
        while(*p == ' ' || *p == '\t') p++;

        if(strncasecmp(p, "VPNAddress", 10) == 0) {
            p += 10;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            char *nl = strchr(p, '\n');
            if(nl) *nl = '\0';
            char *cr = strchr(p, '\r');
            if(cr) *cr = '\0';
            strncpy(vpn_addr, p, sizeof(vpn_addr) - 1);
            break;
        }
    }
    fclose(f);

    if(!vpn_addr[0]) {
        return false;
    }

    /* Parse IP/prefix (e.g., "10.0.0.1/24") */
    char *slash = strchr(vpn_addr, '/');
    if(!slash) {
        return false;
    }

    *slash = '\0';
    *prefix = atoi(slash + 1);

    if(my_ip && my_ip_size > 0) {
        strncpy(my_ip, vpn_addr, my_ip_size - 1);
    }

    /* Parse IP octets */
    int a, b, c, d;
    if(sscanf(vpn_addr, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        return false;
    }

    uint32_t ip = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;

    /* Calculate network address */
    uint32_t mask = *prefix ? (~0U << (32 - *prefix)) : 0;
    *network = ip & mask;

    return true;
}

/*
 * Check if IP is used in hosts.json database
 */
static bool ip_used_in_hosts(uint32_t ip) {
    char ip_str[32];
    ip_to_string(ip, ip_str, sizeof(ip_str));

    if(hosts_db) {
        const char *owner = hosts_db_find_by_vpn_address(ip_str);
        if(owner) {
            return true;
        }
    }

    return false;
}

/*
 * Check if IP is reserved in pending invitations
 */
static bool ip_used_in_invitations(uint32_t ip) {
    char *dir = get_invitations_dir();
    DIR *d = opendir(dir);

    if(!d) {
        free(dir);
        return false;
    }

    char ip_str[32];
    ip_to_string(ip, ip_str, sizeof(ip_str));

    struct dirent *ent;
    bool found = false;

    while((ent = readdir(d)) != NULL) {
        if(ent->d_name[0] == '.') continue;

        char *filepath = NULL;
        xasprintf(&filepath, "%s/%s", dir, ent->d_name);

        FILE *f = fopen(filepath, "r");
        if(f) {
            char line[256];
            while(fgets(line, sizeof(line), f)) {
                if(strncasecmp(line, "VPNAddress", 10) == 0 && strstr(line, ip_str)) {
                    found = true;
                    break;
                }
            }
            fclose(f);
        }
        free(filepath);

        if(found) break;
    }

    closedir(d);
    free(dir);
    return found;
}

/*
 * Check if IP is my own address
 */
static bool ip_is_mine(uint32_t ip, const char *my_ip) {
    return ip == string_to_ip(my_ip);
}

/*
 * Allocate a free VPN IP address from the subnet
 */
char *allocate_vpn_ip(void) {
    uint32_t network;
    int prefix;
    char my_ip[32];

    if(!parse_vpn_address(&network, &prefix, my_ip, sizeof(my_ip))) {
        fprintf(stderr, "Cannot parse VPNAddress from tinc.conf\n");
        return NULL;
    }

    /* Calculate number of hosts in subnet */
    uint32_t host_bits = 32 - prefix;
    uint32_t num_hosts = (1U << host_bits) - 2;

    if(num_hosts > MAX_IP_POOL) {
        num_hosts = MAX_IP_POOL;
    }

    /* Try each host address starting from .2 */
    for(uint32_t i = 2; i <= num_hosts + 1; i++) {
        uint32_t candidate = network | i;

        if(ip_is_mine(candidate, my_ip)) {
            continue;
        }

        if((candidate & ((1U << host_bits) - 1)) == 0 ||
           (candidate & ((1U << host_bits) - 1)) == ((1U << host_bits) - 1)) {
            continue;
        }

        if(ip_used_in_hosts(candidate)) {
            continue;
        }

        if(ip_used_in_invitations(candidate)) {
            continue;
        }

        /* Found free IP! */
        char *result = xmalloc(40);
        char ip_str[32];
        ip_to_string(candidate, ip_str, sizeof(ip_str));
        snprintf(result, 40, "%s/%d", ip_str, prefix);
        return result;
    }

    fprintf(stderr, "No free IP addresses in pool\n");
    return NULL;
}

/*
 * Check if node already exists
 */
static bool node_exists(const char *name) {
    if(hosts_db && hosts_db_find(name)) {
        return true;
    }
    return false;
}

/*
 * Get my external address for invitation URL
 */
char *get_my_address(void) {
    /* Try to read Address from hosts.json */
    if(hosts_db && myname) {
        host_entry_t *me = hosts_db_find(myname);
        if(me && me->address_count > 0) {
            return xstrdup(me->addresses[0]);
        }
    }

    /* Try to read from tinc.conf */
    char *conf_path = NULL;
    xasprintf(&conf_path, "%s/tinc.conf", confbase);

    FILE *f = fopen(conf_path, "r");
    free(conf_path);

    if(f) {
        char line[256];
        while(fgets(line, sizeof(line), f)) {
            char *p = line;
            while(*p == ' ' || *p == '\t') p++;

            if(strncasecmp(p, "Address", 7) == 0) {
                p += 7;
                while(*p == ' ' || *p == '\t' || *p == '=') p++;
                char *nl = strchr(p, '\n');
                if(nl) *nl = '\0';
                fclose(f);
                return xstrdup(p);
            }
        }
        fclose(f);
    }

    return xstrdup("127.0.0.1");
}

/*
 * Read Reality configuration from tinc.conf
 */
static bool read_reality_config(char *server, size_t server_len,
                                char *fingerprint, size_t fp_len,
                                char *public_key, size_t pk_len) {
    char *conf_path = NULL;
    xasprintf(&conf_path, "%s/tinc.conf", confbase);

    FILE *f = fopen(conf_path, "r");
    free(conf_path);

    if(!f) {
        return false;
    }

    char line[512];
    while(fgets(line, sizeof(line), f)) {
        char *p = line;
        while(*p == ' ' || *p == '\t') p++;

        char *nl = strchr(p, '\n');
        if(nl) *nl = '\0';

        if(strncasecmp(p, "RealityServerName", 17) == 0 && server) {
            p += 17;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(server, p, server_len - 1);
        } else if(strncasecmp(p, "RealityFingerprint", 18) == 0 && fingerprint) {
            p += 18;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(fingerprint, p, fp_len - 1);
        } else if(strncasecmp(p, "RealityPublicKey", 16) == 0 && public_key) {
            p += 16;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(public_key, p, pk_len - 1);
        }
    }

    fclose(f);
    return true;
}

/*
 * Create an invitation for a new node
 */
int create_invitation(const char *name, char **url) {
    if(!name || !url) {
        return -1;
    }

    *url = NULL;

    /* Check if node already exists */
    if(node_exists(name)) {
        fprintf(stderr, "Node %s already exists\n", name);
        return -2;
    }

    /* Ensure invitations directory exists */
    if(!ensure_invitations_dir()) {
        return -4;
    }

    /* Clean up old invitations */
    cleanup_expired_invitations();

    /* Generate token */
    char *token = generate_token();
    char *filename = token_to_filename(token);

    /* Generate VLESS UUID for this node */
    char vless_uuid[40];
    generate_vless_uuid(vless_uuid);

    /* Generate Reality ShortID */
    char shortid[20];
    generate_reality_shortid(shortid);

    /* Allocate VPN IP address */
    char *allocated_ip = allocate_vpn_ip();
    if(!allocated_ip) {
        free(token);
        free(filename);
        return -3;
    }

    /* Get Reality config from our tinc.conf */
    char reality_server[256] = "www.google.com";
    char reality_fingerprint[32] = "chrome";
    char reality_public_key[64] = "";
    read_reality_config(reality_server, sizeof(reality_server),
                        reality_fingerprint, sizeof(reality_fingerprint),
                        reality_public_key, sizeof(reality_public_key));

    /* Write invitation file */
    char *dir = get_invitations_dir();
    char *filepath = NULL;
    xasprintf(&filepath, "%s/%s", dir, filename);
    free(dir);

    FILE *f = fopen(filepath, "w");
    if(!f) {
        fprintf(stderr, "Failed to create invitation file: %s\n", strerror(errno));
        free(filepath);
        free(filename);
        free(token);
        free(allocated_ip);
        return -4;
    }

    time_t now = time(NULL);
    char *my_address = get_my_address();

    fprintf(f, "Name = %s\n", name);
    fprintf(f, "Token = %s\n", token);
    fprintf(f, "Created = %ld\n", (long)now);
    fprintf(f, "Expires = %ld\n", (long)(now + INVITATION_VALIDITY));
    fprintf(f, "VLESSUUID = %s\n", vless_uuid);
    fprintf(f, "VPNAddress = %s\n", allocated_ip);
    fprintf(f, "ServerName = %s\n", myname ? myname : "server");
    fprintf(f, "ServerAddress = %s\n", my_address);
    fprintf(f, "ServerPort = 443\n");
    fprintf(f, "RealityServerName = %s\n", reality_server);
    fprintf(f, "RealityFingerprint = %s\n", reality_fingerprint);
    fprintf(f, "RealityShortID = %s\n", shortid);
    if(reality_public_key[0]) {
        fprintf(f, "RealityPublicKey = %s\n", reality_public_key);
    }

    fclose(f);

    /* Add to hosts.json with authorized=true */
    host_entry_t *host = hosts_db_add(name);
    if(host) {
        char ip_only[32];
        char *slash = strchr(allocated_ip, '/');
        if(slash) {
            size_t len = slash - allocated_ip;
            if(len < sizeof(ip_only)) {
                memcpy(ip_only, allocated_ip, len);
                ip_only[len] = '\0';
                host_set_vpn_address(host, ip_only, 32);
            }
        }
        host_set_uuid(host, vless_uuid);
        host_set_authorized(host, true);
        hosts_db_save();
    }

    /* Build URL */
    xasprintf(url, "vless://%s:443/invite/%s", my_address, token);

    fprintf(stderr, "Created invitation for %s\n", name);
    fprintf(stderr, "VLESS UUID: %s\n", vless_uuid);
    fprintf(stderr, "VPN Address: %s\n", allocated_ip);
    fprintf(stderr, "URL: %s\n", *url);

    free(my_address);
    free(filepath);
    free(filename);
    free(token);
    free(allocated_ip);

    return 0;
}

/*
 * Validate an incoming invitation token
 */
bool validate_invitation_token(const char *token, invitation_data_t *data) {
    if(!token || !data) {
        return false;
    }

    memset(data, 0, sizeof(*data));

    char *filename = token_to_filename(token);
    char *dir = get_invitations_dir();
    char *filepath = NULL;
    xasprintf(&filepath, "%s/%s", dir, filename);
    free(dir);
    free(filename);

    FILE *f = fopen(filepath, "r");
    if(!f) {
        fprintf(stderr, "Invitation not found: %s\n", token);
        free(filepath);
        return false;
    }

    char line[512];
    char stored_token[64] = {0};
    long expires = 0;

    while(fgets(line, sizeof(line), f)) {
        char *p = line;
        while(*p == ' ' || *p == '\t') p++;

        char *nl = strchr(p, '\n');
        if(nl) *nl = '\0';

        if(strncasecmp(p, "Token", 5) == 0 && !strncasecmp(p, "Token ", 6)) {
            p += 5;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(stored_token, p, sizeof(stored_token) - 1);
        } else if(strncasecmp(p, "Name", 4) == 0 && (p[4] == ' ' || p[4] == '\t' || p[4] == '=')) {
            p += 4;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(data->name, p, sizeof(data->name) - 1);
        } else if(strncasecmp(p, "Expires", 7) == 0) {
            p += 7;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            expires = atol(p);
        } else if(strncasecmp(p, "VLESSUUID", 9) == 0) {
            p += 9;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(data->vless_uuid, p, sizeof(data->vless_uuid) - 1);
        } else if(strncasecmp(p, "VPNAddress", 10) == 0) {
            p += 10;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(data->vpn_address, p, sizeof(data->vpn_address) - 1);
        } else if(strncasecmp(p, "ServerName", 10) == 0) {
            p += 10;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(data->server_name, p, sizeof(data->server_name) - 1);
        } else if(strncasecmp(p, "ServerAddress", 13) == 0) {
            p += 13;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(data->server_address, p, sizeof(data->server_address) - 1);
        } else if(strncasecmp(p, "ServerPort", 10) == 0) {
            p += 10;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            data->server_port = atoi(p);
        } else if(strncasecmp(p, "RealityServerName", 17) == 0) {
            p += 17;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(data->reality_server, p, sizeof(data->reality_server) - 1);
        } else if(strncasecmp(p, "RealityFingerprint", 18) == 0) {
            p += 18;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(data->reality_fingerprint, p, sizeof(data->reality_fingerprint) - 1);
        } else if(strncasecmp(p, "RealityPublicKey", 16) == 0) {
            p += 16;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(data->reality_public_key, p, sizeof(data->reality_public_key) - 1);
        } else if(strncasecmp(p, "RealityShortID", 14) == 0) {
            p += 14;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(data->reality_shortid, p, sizeof(data->reality_shortid) - 1);
        }
    }

    fclose(f);

    /* Verify token matches */
    if(strcmp(token, stored_token) != 0) {
        fprintf(stderr, "Token mismatch for invitation\n");
        free(filepath);
        return false;
    }

    /* Check expiration */
    if(time(NULL) > expires) {
        fprintf(stderr, "Invitation has expired\n");
        unlink(filepath);
        free(filepath);
        return false;
    }

    strncpy(data->token, token, sizeof(data->token) - 1);
    data->expires = expires;

    /* Delete invitation file (one-time use) */
    unlink(filepath);
    free(filepath);

    fprintf(stderr, "Validated invitation for node: %s\n", data->name);
    return true;
}

/*
 * Finalize invitation - node is already added during create_invitation
 */
bool finalize_invitation(const invitation_data_t *data) {
    if(!data || !data->name[0]) {
        return false;
    }

    /* Node was already added to hosts.json in create_invitation */
    /* This function can be used to perform additional setup if needed */

    fprintf(stderr, "Finalized invitation for node: %s\n", data->name);
    return true;
}

/*
 * CLI command: tinc invite <name>
 */
int cmd_invite(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Usage: tinc invite <name>\n");
        return 1;
    }

    const char *name = argv[1];

    /* Validate node name */
    if(!check_id(name)) {
        fprintf(stderr, "Invalid node name: %s\n", name);
        return 1;
    }

    /* Initialize hosts database if needed */
    if(!hosts_db) {
        hosts_db_init(confbase);
    }

    char *url = NULL;
    int result = create_invitation(name, &url);

    if(result == 0 && url) {
        printf("%s\n", url);
        free(url);
        return 0;
    }

    switch(result) {
        case -1:
            fprintf(stderr, "Invalid arguments\n");
            break;
        case -2:
            fprintf(stderr, "Node %s already exists\n", name);
            break;
        case -3:
            fprintf(stderr, "Failed to allocate VPN IP address\n");
            break;
        case -4:
            fprintf(stderr, "Failed to create invitation file\n");
            break;
    }

    return 1;
}

/*
 * Parse invitation URL
 * Format: vless://host:port/invite/TOKEN
 */
static bool parse_invitation_url(const char *url, char *host, size_t host_len,
                                  uint16_t *port, char *token, size_t token_len) {
    /* Skip vless:// or https:// prefix */
    const char *p = url;
    if(strncasecmp(p, "vless://", 8) == 0) {
        p += 8;
    } else if(strncasecmp(p, "https://", 8) == 0) {
        p += 8;
    }

    /* Parse host */
    const char *colon = strchr(p, ':');
    const char *slash = strchr(p, '/');

    if(colon && (!slash || colon < slash)) {
        size_t len = colon - p;
        if(len >= host_len) len = host_len - 1;
        memcpy(host, p, len);
        host[len] = '\0';
        p = colon + 1;
        *port = atoi(p);
        p = strchr(p, '/');
    } else if(slash) {
        size_t len = slash - p;
        if(len >= host_len) len = host_len - 1;
        memcpy(host, p, len);
        host[len] = '\0';
        *port = 443;
        p = slash;
    } else {
        return false;
    }

    /* Skip /invite/ */
    if(!p || strncmp(p, "/invite/", 8) != 0) {
        return false;
    }
    p += 8;

    /* Copy token */
    strncpy(token, p, token_len - 1);
    token[token_len - 1] = '\0';

    /* Remove trailing whitespace */
    size_t len = strlen(token);
    while(len > 0 && isspace(token[len - 1])) {
        token[--len] = '\0';
    }

    return true;
}

/*
 * CLI command: tinc join <url>
 * Automatically fetches invitation from server and generates configuration
 */
int cmd_join(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Usage: tinc join <url>\n");
        return 1;
    }

    const char *url = argv[1];

    /* Use the automatic join process */
    return do_join(url, confbase ? confbase : "/etc/tinc", netname);
}
