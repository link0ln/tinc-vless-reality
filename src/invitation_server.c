/*
    invitation_server.c -- Server-side invitation handling
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
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "invitation_server.h"
#include "invitation.h"
#include "conf.h"
#include "logger.h"
#include "names.h"
#include "xalloc.h"

/* Check if incoming data looks like an HTTP GET request for invitation */
bool is_invitation_request(const char *data, size_t len) {
    if(len < 20) return false;

    /* Check for "GET /invite/" prefix */
    if(strncmp(data, "GET /invite/", 12) == 0) {
        return true;
    }

    return false;
}

/* Extract token from HTTP GET request */
static char *extract_token_from_request(const char *data) {
    /* Format: GET /invite/TOKEN HTTP/1.x */
    const char *start = data + 12;  /* Skip "GET /invite/" */
    const char *end = strchr(start, ' ');

    if(!end || end <= start) {
        return NULL;
    }

    size_t len = end - start;
    char *token = xmalloc(len + 1);
    memcpy(token, start, len);
    token[len] = '\0';

    /* Remove any query string or trailing characters */
    char *q = strchr(token, '?');
    if(q) *q = '\0';
    char *nl = strchr(token, '\n');
    if(nl) *nl = '\0';
    char *cr = strchr(token, '\r');
    if(cr) *cr = '\0';

    return token;
}

/* Get invitations directory path */
static char *get_invitations_dir(void) {
    char *path = NULL;
    xasprintf(&path, "%s/invitations", confbase);
    return path;
}

/* Read invitation file and build JSON response */
static char *build_invitation_response(const char *token) {
    /* Find invitation file */
    char filename[32];
    strncpy(filename, token, 16);
    filename[16] = '\0';

    char *dir = get_invitations_dir();
    char *filepath = NULL;
    xasprintf(&filepath, "%s/%s", dir, filename);
    free(dir);

    FILE *f = fopen(filepath, "r");
    if(!f) {
        free(filepath);
        return NULL;
    }

    /* Parse invitation file */
    char line[512];
    char name[64] = {0};
    char stored_token[128] = {0};
    char vless_uuid[64] = {0};
    char vpn_address[64] = {0};
    char server_name[64] = {0};
    char server_address[256] = {0};
    int server_port = 443;
    char reality_server[256] = {0};
    char reality_fingerprint[32] = {0};
    char reality_public_key[128] = {0};
    char reality_shortid[32] = {0};
    long expires = 0;

    while(fgets(line, sizeof(line), f)) {
        char *p = line;
        while(*p == ' ' || *p == '\t') p++;

        char *nl = strchr(p, '\n');
        if(nl) *nl = '\0';
        char *cr = strchr(p, '\r');
        if(cr) *cr = '\0';

        if(strncasecmp(p, "Name", 4) == 0 && (p[4] == ' ' || p[4] == '=' || p[4] == '\t')) {
            p += 4;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(name, p, sizeof(name) - 1);
        } else if(strncasecmp(p, "Token", 5) == 0 && (p[5] == ' ' || p[5] == '=' || p[5] == '\t')) {
            p += 5;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(stored_token, p, sizeof(stored_token) - 1);
        } else if(strncasecmp(p, "VLESSUUID", 9) == 0) {
            p += 9;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(vless_uuid, p, sizeof(vless_uuid) - 1);
        } else if(strncasecmp(p, "VPNAddress", 10) == 0) {
            p += 10;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(vpn_address, p, sizeof(vpn_address) - 1);
        } else if(strncasecmp(p, "ServerName", 10) == 0) {
            p += 10;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(server_name, p, sizeof(server_name) - 1);
        } else if(strncasecmp(p, "ServerAddress", 13) == 0) {
            p += 13;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(server_address, p, sizeof(server_address) - 1);
        } else if(strncasecmp(p, "ServerPort", 10) == 0) {
            p += 10;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            server_port = atoi(p);
        } else if(strncasecmp(p, "RealityServerName", 17) == 0) {
            p += 17;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(reality_server, p, sizeof(reality_server) - 1);
        } else if(strncasecmp(p, "RealityFingerprint", 18) == 0) {
            p += 18;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(reality_fingerprint, p, sizeof(reality_fingerprint) - 1);
        } else if(strncasecmp(p, "RealityPublicKey", 16) == 0) {
            p += 16;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(reality_public_key, p, sizeof(reality_public_key) - 1);
        } else if(strncasecmp(p, "RealityShortID", 14) == 0) {
            p += 14;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            strncpy(reality_shortid, p, sizeof(reality_shortid) - 1);
        } else if(strncasecmp(p, "Expires", 7) == 0) {
            p += 7;
            while(*p == ' ' || *p == '\t' || *p == '=') p++;
            expires = atol(p);
        }
    }

    fclose(f);

    /* Verify token */
    if(strcmp(token, stored_token) != 0) {
        free(filepath);
        return NULL;
    }

    /* Check expiration */
    if(time(NULL) > expires) {
        unlink(filepath);
        free(filepath);
        return NULL;
    }

    /* Delete invitation file (one-time use) */
    unlink(filepath);
    free(filepath);

    /* Build JSON response */
    char *json = NULL;
    xasprintf(&json,
        "{\n"
        "  \"name\": \"%s\",\n"
        "  \"vless_uuid\": \"%s\",\n"
        "  \"vpn_address\": \"%s\",\n"
        "  \"server_name\": \"%s\",\n"
        "  \"server_address\": \"%s\",\n"
        "  \"server_port\": %d,\n"
        "  \"reality_server\": \"%s\",\n"
        "  \"reality_fingerprint\": \"%s\",\n"
        "  \"reality_public_key\": \"%s\",\n"
        "  \"reality_shortid\": \"%s\",\n"
        "  \"network_name\": \"%s\"\n"
        "}",
        name, vless_uuid, vpn_address, server_name, server_address,
        server_port, reality_server, reality_fingerprint,
        reality_public_key, reality_shortid,
        netname ? netname : "vpn"
    );

    logger(DEBUG_ALWAYS, LOG_INFO, "Invitation redeemed for node: %s", name);

    return json;
}

/* Handle invitation HTTP request, return HTTP response */
char *handle_invitation_request(const char *request, size_t req_len, size_t *resp_len) {
    (void)req_len;

    char *token = extract_token_from_request(request);
    if(!token) {
        const char *error_resp =
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Invalid request";
        *resp_len = strlen(error_resp);
        return xstrdup(error_resp);
    }

    logger(DEBUG_ALWAYS, LOG_INFO, "Invitation request for token: %.16s...", token);

    char *json = build_invitation_response(token);
    free(token);

    if(!json) {
        const char *error_resp =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Invitation not found or expired";
        *resp_len = strlen(error_resp);
        return xstrdup(error_resp);
    }

    /* Build success response */
    char *response = NULL;
    size_t json_len = strlen(json);
    xasprintf(&response,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        json_len, json
    );

    free(json);
    *resp_len = strlen(response);
    return response;
}
