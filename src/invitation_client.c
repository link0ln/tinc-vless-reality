/*
    invitation_client.c -- Client-side invitation fetching via HTTPS
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <ctype.h>

#include "invitation_client.h"
#include "invitation.h"
#include "xalloc.h"

/* Parse JSON string value */
static char *json_get_string(const char *json, const char *key) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *p = strstr(json, search);
    if(!p) return NULL;

    p += strlen(search);
    while(*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;

    if(*p != '"') return NULL;
    p++;

    const char *end = strchr(p, '"');
    if(!end) return NULL;

    size_t len = end - p;
    char *result = xmalloc(len + 1);
    memcpy(result, p, len);
    result[len] = '\0';

    return result;
}

/* Parse JSON integer value */
static int json_get_int(const char *json, const char *key) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *p = strstr(json, search);
    if(!p) return 0;

    p += strlen(search);
    while(*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;

    return atoi(p);
}

/* Connect to server and fetch invitation via HTTPS */
char *fetch_invitation(const char *host, int port, const char *token) {
    int sock = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char *result = NULL;

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Create SSL context */
    ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        goto cleanup;
    }

    /* Don't verify server certificate (we use token-based auth) */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /* Resolve hostname */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int err = getaddrinfo(host, port_str, &hints, &res);
    if(err != 0) {
        fprintf(stderr, "Failed to resolve %s: %s\n", host, gai_strerror(err));
        goto cleanup;
    }

    /* Create socket and connect */
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(sock < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        freeaddrinfo(res);
        goto cleanup;
    }

    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if(connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "Failed to connect to %s:%d: %s\n", host, port, strerror(errno));
        freeaddrinfo(res);
        goto cleanup;
    }

    freeaddrinfo(res);

    /* Create SSL connection */
    ssl = SSL_new(ctx);
    if(!ssl) {
        fprintf(stderr, "Failed to create SSL object\n");
        goto cleanup;
    }

    SSL_set_fd(ssl, sock);

    /* Set SNI (Server Name Indication) */
    SSL_set_tlsext_host_name(ssl, host);

    /* Perform SSL handshake */
    if(SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL handshake failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Build HTTP request */
    char request[1024];
    snprintf(request, sizeof(request),
        "GET /invite/%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: tinc-join/1.0\r\n"
        "\r\n",
        token, host
    );

    /* Send request */
    if(SSL_write(ssl, request, strlen(request)) <= 0) {
        fprintf(stderr, "Failed to send request\n");
        goto cleanup;
    }

    /* Read response */
    char response[8192];
    size_t total = 0;

    while(total < sizeof(response) - 1) {
        int n = SSL_read(ssl, response + total, sizeof(response) - 1 - total);
        if(n <= 0) break;
        total += n;
    }
    response[total] = '\0';

    /* Check HTTP status */
    if(strncmp(response, "HTTP/1.1 200", 12) != 0 &&
       strncmp(response, "HTTP/1.0 200", 12) != 0) {
        /* Extract error message */
        const char *body = strstr(response, "\r\n\r\n");
        if(body) {
            fprintf(stderr, "Server error: %s\n", body + 4);
        } else {
            fprintf(stderr, "Server returned error status\n");
        }
        goto cleanup;
    }

    /* Find JSON body */
    const char *body = strstr(response, "\r\n\r\n");
    if(!body) {
        fprintf(stderr, "Invalid response format\n");
        goto cleanup;
    }
    body += 4;

    /* Find start of JSON (skip any chunked encoding) */
    while(*body && *body != '{') body++;

    if(*body == '{') {
        result = xstrdup(body);
    }

cleanup:
    if(ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if(sock >= 0) close(sock);
    if(ctx) SSL_CTX_free(ctx);

    return result;
}

/* Parse invitation JSON and fill data structure */
bool parse_invitation_json(const char *json, invitation_data_t *data) {
    if(!json || !data) return false;

    memset(data, 0, sizeof(*data));

    char *val;

    val = json_get_string(json, "name");
    if(val) {
        strncpy(data->name, val, sizeof(data->name) - 1);
        free(val);
    }

    val = json_get_string(json, "vless_uuid");
    if(val) {
        strncpy(data->vless_uuid, val, sizeof(data->vless_uuid) - 1);
        free(val);
    }

    val = json_get_string(json, "vpn_address");
    if(val) {
        strncpy(data->vpn_address, val, sizeof(data->vpn_address) - 1);
        free(val);
    }

    val = json_get_string(json, "server_name");
    if(val) {
        strncpy(data->server_name, val, sizeof(data->server_name) - 1);
        free(val);
    }

    val = json_get_string(json, "server_address");
    if(val) {
        strncpy(data->server_address, val, sizeof(data->server_address) - 1);
        free(val);
    }

    data->server_port = json_get_int(json, "server_port");
    if(data->server_port == 0) data->server_port = 443;

    val = json_get_string(json, "reality_server");
    if(val) {
        strncpy(data->reality_server, val, sizeof(data->reality_server) - 1);
        free(val);
    }

    val = json_get_string(json, "reality_fingerprint");
    if(val) {
        strncpy(data->reality_fingerprint, val, sizeof(data->reality_fingerprint) - 1);
        free(val);
    }

    val = json_get_string(json, "reality_public_key");
    if(val) {
        strncpy(data->reality_public_key, val, sizeof(data->reality_public_key) - 1);
        free(val);
    }

    val = json_get_string(json, "reality_shortid");
    if(val) {
        strncpy(data->reality_shortid, val, sizeof(data->reality_shortid) - 1);
        free(val);
    }

    return data->name[0] && data->vless_uuid[0];
}

/* Generate tinc.conf from invitation data */
bool generate_tinc_config(const char *confbase, const char *netname,
                          const invitation_data_t *data) {
    if(!confbase || !data || !data->name[0]) {
        return false;
    }

    /* Create config directory */
    char *dir = NULL;
    if(netname && netname[0]) {
        xasprintf(&dir, "%s/%s", confbase, netname);
    } else {
        dir = xstrdup(confbase);
    }

    if(mkdir(dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory %s: %s\n", dir, strerror(errno));
        free(dir);
        return false;
    }

    /* Create hosts directory */
    char *hosts_dir = NULL;
    xasprintf(&hosts_dir, "%s/hosts", dir);
    if(mkdir(hosts_dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Warning: Failed to create hosts directory\n");
    }
    free(hosts_dir);

    /* Write tinc.conf */
    char *conf_path = NULL;
    xasprintf(&conf_path, "%s/tinc.conf", dir);

    FILE *f = fopen(conf_path, "w");
    if(!f) {
        fprintf(stderr, "Failed to create %s: %s\n", conf_path, strerror(errno));
        free(conf_path);
        free(dir);
        return false;
    }

    fprintf(f, "# Generated by tinc join\n");
    fprintf(f, "Name = %s\n", data->name);
    fprintf(f, "ConnectTo = %s\n", data->server_name);
    fprintf(f, "\n");
    fprintf(f, "# VLESS Configuration\n");
    fprintf(f, "VLESSMode = yes\n");
    fprintf(f, "VLESSUUID = %s\n", data->vless_uuid);
    fprintf(f, "\n");
    fprintf(f, "# Reality TLS Configuration\n");
    fprintf(f, "VLESSReality = yes\n");
    if(data->reality_server[0]) {
        fprintf(f, "RealityServerName = %s\n", data->reality_server);
    }
    if(data->reality_fingerprint[0]) {
        fprintf(f, "RealityFingerprint = %s\n", data->reality_fingerprint);
    }
    if(data->reality_public_key[0]) {
        fprintf(f, "RealityPublicKey = %s\n", data->reality_public_key);
    }
    if(data->reality_shortid[0]) {
        fprintf(f, "RealityShortID = %s\n", data->reality_shortid);
    }
    fprintf(f, "\n");
    fprintf(f, "# Network Configuration\n");
    fprintf(f, "VPNAddress = %s\n", data->vpn_address);
    fprintf(f, "Device = /dev/net/tun\n");
    fprintf(f, "Mode = switch\n");

    fclose(f);
    free(conf_path);

    /* Write server host file */
    char *server_host_path = NULL;
    xasprintf(&server_host_path, "%s/hosts/%s", dir, data->server_name);

    f = fopen(server_host_path, "w");
    if(f) {
        fprintf(f, "# Server node configuration\n");
        fprintf(f, "Address = %s\n", data->server_address);
        fprintf(f, "Port = %d\n", data->server_port);
        fclose(f);
    }
    free(server_host_path);

    /* Write hosts.json */
    char *hosts_json_path = NULL;
    xasprintf(&hosts_json_path, "%s/hosts.json", dir);

    f = fopen(hosts_json_path, "w");
    if(f) {
        /* Extract IP without prefix */
        char ip_only[32];
        strncpy(ip_only, data->vpn_address, sizeof(ip_only) - 1);
        char *slash = strchr(ip_only, '/');
        if(slash) *slash = '\0';

        fprintf(f, "{\n");
        fprintf(f, "  \"%s\": {\n", data->name);
        fprintf(f, "    \"uuid\": \"%s\",\n", data->vless_uuid);
        fprintf(f, "    \"vpn_address\": \"%s\",\n", ip_only);
        fprintf(f, "    \"authorized\": true\n");
        fprintf(f, "  },\n");
        fprintf(f, "  \"%s\": {\n", data->server_name);
        fprintf(f, "    \"addresses\": [\"%s\"],\n", data->server_address);
        fprintf(f, "    \"port\": %d,\n", data->server_port);
        fprintf(f, "    \"authorized\": true\n");
        fprintf(f, "  }\n");
        fprintf(f, "}\n");
        fclose(f);
    }
    free(hosts_json_path);

    printf("Configuration generated successfully!\n");
    printf("  Config directory: %s\n", dir);
    printf("  Node name: %s\n", data->name);
    printf("  VPN address: %s\n", data->vpn_address);
    printf("  Server: %s (%s:%d)\n", data->server_name, data->server_address, data->server_port);
    printf("\n");
    printf("To start the VPN, run:\n");
    if(netname && netname[0]) {
        printf("  tincd -n %s\n", netname);
    } else {
        printf("  tincd -c %s\n", dir);
    }

    free(dir);
    return true;
}

/* Full join process: fetch invitation and generate config */
int do_join(const char *url, const char *confbase, const char *netname) {
    char host[256] = {0};
    int port = 443;
    char token[256] = {0};

    /* Parse URL: vless://host:port/invite/TOKEN */
    const char *p = url;

    /* Skip protocol prefix */
    if(strncasecmp(p, "vless://", 8) == 0) {
        p += 8;
    } else if(strncasecmp(p, "https://", 8) == 0) {
        p += 8;
    }

    /* Parse host:port */
    const char *colon = strchr(p, ':');
    const char *slash = strchr(p, '/');

    if(colon && (!slash || colon < slash)) {
        size_t len = colon - p;
        if(len >= sizeof(host)) len = sizeof(host) - 1;
        memcpy(host, p, len);
        host[len] = '\0';
        port = atoi(colon + 1);
        p = strchr(colon, '/');
    } else if(slash) {
        size_t len = slash - p;
        if(len >= sizeof(host)) len = sizeof(host) - 1;
        memcpy(host, p, len);
        host[len] = '\0';
        p = slash;
    } else {
        fprintf(stderr, "Invalid URL format\n");
        return 1;
    }

    /* Parse /invite/TOKEN */
    if(!p || strncmp(p, "/invite/", 8) != 0) {
        fprintf(stderr, "Invalid URL format: missing /invite/ path\n");
        return 1;
    }
    p += 8;

    strncpy(token, p, sizeof(token) - 1);

    /* Remove trailing whitespace */
    size_t len = strlen(token);
    while(len > 0 && isspace(token[len - 1])) {
        token[--len] = '\0';
    }

    printf("Connecting to %s:%d...\n", host, port);

    /* Fetch invitation */
    char *json = fetch_invitation(host, port, token);
    if(!json) {
        fprintf(stderr, "Failed to fetch invitation\n");
        return 1;
    }

    /* Parse invitation */
    invitation_data_t data;
    if(!parse_invitation_json(json, &data)) {
        fprintf(stderr, "Failed to parse invitation data\n");
        free(json);
        return 1;
    }
    free(json);

    printf("Received invitation for node: %s\n", data.name);

    /* Generate configuration */
    const char *base = confbase ? confbase : "/etc/tinc";
    if(!generate_tinc_config(base, netname, &data)) {
        fprintf(stderr, "Failed to generate configuration\n");
        return 1;
    }

    return 0;
}
