/*
    config_template.c -- Generate default tinc.conf template
    Copyright (C) 2025 Tinc VPN Project

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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#include "config_template.h"

/*
 * Default tinc.conf template with all options documented.
 * %s placeholders will be replaced by generate_default_config():
 *   1. Node name
 *   2. Generation timestamp
 */
static const char *config_template =
"# ==============================================================================\n"
"# Tinc VLESS VPN Configuration\n"
"# ==============================================================================\n"
"# Generated: %s\n"
"# Documentation: https://www.tinc-vpn.org/documentation/\n"
"# ==============================================================================\n"
"\n"
"# ==============================================================================\n"
"# BASIC SETTINGS (Required)\n"
"# ==============================================================================\n"
"\n"
"# Name of this node (required, alphanumeric and underscores only)\n"
"Name = %s\n"
"\n"
"# Port to listen on (default: 655, using 443 for DPI evasion)\n"
"Port = 443\n"
"\n"
"# Device type: tun (IP-level) or tap (Ethernet-level)\n"
"DeviceType = tun\n"
"\n"
"# Network interface name for the VPN tunnel\n"
"Interface = tinc0\n"
"\n"
"# Operating mode: router, switch, or hub\n"
"Mode = router\n"
"\n"
"# Use TCP only (required for VLESS mode)\n"
"TCPOnly = yes\n"
"\n"
"# ==============================================================================\n"
"# VLESS PROTOCOL SETTINGS\n"
"# ==============================================================================\n"
"\n"
"# Enable VLESS protocol for DPI evasion\n"
"VLESSEnabled = yes\n"
"\n"
"# VLESS UUID for authentication (auto-generated if not set)\n"
"#VLESSUserID = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\n"
"\n"
"# Enable Reality protocol (TLS 1.3 camouflage)\n"
"VLESSRealityEnabled = yes\n"
"\n"
"# Reality destination server (must support TLS 1.3)\n"
"VLESSRealityDest = www.google.com\n"
"VLESSRealityDestPort = 443\n"
"\n"
"# Reality server name (SNI to present)\n"
"VLESSRealityServerName = www.google.com\n"
"\n"
"# Reality short ID (8 hex characters)\n"
"#VLESSRealityShortID = 12345678\n"
"\n"
"# ==============================================================================\n"
"# VPN ADDRESS CONFIGURATION\n"
"# ==============================================================================\n"
"\n"
"# VPN address for this node\n"
"# Format: IP/prefix (e.g., 10.0.0.1/24 for server, 10.0.0.x/24 for clients)\n"
"#VPNAddress = 10.0.0.1/24\n"
"\n"
"# Additional routes to add when VPN is up\n"
"#Route = 192.168.1.0/24\n"
"\n"
"# ==============================================================================\n"
"# CONNECTION SETTINGS\n"
"# ==============================================================================\n"
"\n"
"# Nodes to connect to on startup\n"
"#ConnectTo = server1\n"
"\n"
"# Automatically connect to other nodes when needed\n"
"AutoConnect = yes\n"
"\n"
"# ==============================================================================\n"
"# TIMING AND KEEPALIVE\n"
"# ==============================================================================\n"
"\n"
"# Interval between keepalive pings (seconds)\n"
"PingInterval = 10\n"
"\n"
"# Timeout before considering a node unreachable (seconds)\n"
"PingTimeout = 5\n"
"\n"
"# ==============================================================================\n"
"# MTU AND PACKET HANDLING\n"
"# ==============================================================================\n"
"\n"
"# Maximum Transmission Unit (bytes)\n"
"MTU = 1400\n"
"\n"
"# ==============================================================================\n"
"# VLESS DPI EVASION SETTINGS\n"
"# ==============================================================================\n"
"\n"
"# ----- Packet Padding -----\n"
"# Modes: off, random, fixed, adaptive, mtu\n"
"#VLESSPaddingMode = off\n"
"\n"
"# Padding size range for random/adaptive modes (bytes)\n"
"#VLESSPaddingMin = 0\n"
"#VLESSPaddingMax = 256\n"
"\n"
"# ----- Timing Obfuscation -----\n"
"# Modes: off, random, adaptive, burst\n"
"#VLESSTimingMode = off\n"
"\n"
"# Timing delay range (milliseconds)\n"
"#VLESSTimingMinDelay = 1\n"
"#VLESSTimingMaxDelay = 50\n"
"\n"
"# ----- Active Probing Protection -----\n"
"#VLESSProbingProtection = no\n"
"\n"
"# ----- Traffic Shaping -----\n"
"# Patterns: none, http, video, browsing\n"
"#VLESSTrafficPattern = none\n"
"\n"
"# ==============================================================================\n"
"# SYSTEM SETTINGS\n"
"# ==============================================================================\n"
"\n"
"# Log level (0-5, higher = more verbose)\n"
"#LogLevel = 0\n"
"\n"
"# ==============================================================================\n"
"# END OF CONFIGURATION\n"
"# ==============================================================================\n"
;

bool generate_default_config(const char *filepath, const char *node_name) {
	if(!filepath || !node_name || !node_name[0]) {
		return false;
	}

	FILE *f = fopen(filepath, "w");
	if(!f) {
		return false;
	}

	/* Get current timestamp */
	time_t now = time(NULL);
	char timestamp[64];
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

	/* Write template with substitutions */
	fprintf(f, config_template, timestamp, node_name);

	fclose(f);
	return true;
}

bool config_file_exists(const char *confbase) {
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/tinc.conf", confbase);

	struct stat st;
	return stat(path, &st) == 0;
}

bool ensure_config_dirs(const char *confbase) {
	/* Create confbase directory */
	if(mkdir(confbase, 0755) && errno != EEXIST) {
		return false;
	}

	/* Create hosts directory (legacy, may still be needed) */
	char hosts_dir[PATH_MAX];
	snprintf(hosts_dir, sizeof(hosts_dir), "%s/hosts", confbase);
	if(mkdir(hosts_dir, 0755) && errno != EEXIST) {
		return false;
	}

	/* Create cache directory (not fatal if fails) */
	char cache_dir[PATH_MAX];
	snprintf(cache_dir, sizeof(cache_dir), "%s/cache", confbase);
	mkdir(cache_dir, 0755); /* Ignore errors */

	return true;
}
