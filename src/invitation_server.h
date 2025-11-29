/*
    invitation_server.h -- Server-side invitation handling
    Copyright (C) 2025 Tinc VPN Project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#ifndef TINC_INVITATION_SERVER_H
#define TINC_INVITATION_SERVER_H

#include <stdbool.h>
#include <stddef.h>

/*
 * Check if incoming data looks like an HTTP invitation request
 * Returns true if data starts with "GET /invite/"
 */
bool is_invitation_request(const char *data, size_t len);

/*
 * Handle an invitation HTTP request
 * Returns HTTP response (caller must free)
 * Sets *resp_len to response length
 */
char *handle_invitation_request(const char *request, size_t req_len, size_t *resp_len);

#endif /* TINC_INVITATION_SERVER_H */
