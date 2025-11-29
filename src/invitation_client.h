/*
    invitation_client.h -- Client-side invitation fetching via HTTPS
    Copyright (C) 2025 Tinc VPN Project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#ifndef TINC_INVITATION_CLIENT_H
#define TINC_INVITATION_CLIENT_H

#include <stdbool.h>
#include "invitation.h"

/*
 * Fetch invitation data from server via HTTPS
 * Returns JSON string (caller must free) or NULL on error
 */
char *fetch_invitation(const char *host, int port, const char *token);

/*
 * Parse invitation JSON into data structure
 */
bool parse_invitation_json(const char *json, invitation_data_t *data);

/*
 * Generate tinc configuration files from invitation data
 */
bool generate_tinc_config(const char *confbase, const char *netname,
                          const invitation_data_t *data);

/*
 * Full join process: fetch invitation and generate config
 * Returns 0 on success, non-zero on error
 */
int do_join(const char *url, const char *confbase, const char *netname);

#endif /* TINC_INVITATION_CLIENT_H */
