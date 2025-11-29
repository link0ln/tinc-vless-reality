#!/bin/bash
set -e

NETWORK=${TINC_NETWORK:-testvpn}
NODE=${NODE_NAME:-node1}
CONF_DIR="/etc/tinc/$NETWORK"
DEBUG_LEVEL=${TINC_DEBUG_LEVEL:-0}

echo "================================================"
echo "Starting Tinc Node: $NODE"
echo "Network: $NETWORK"
echo "Debug Level: $DEBUG_LEVEL"
echo "================================================"

# Create TUN device if not exists
if [ ! -e /dev/net/tun ]; then
    echo "Creating /dev/net/tun"
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

# Auto-generate configuration if not exists
if [ ! -f "$CONF_DIR/tinc.conf" ]; then
    echo "Auto-generating configuration for node: $NODE"
    mkdir -p "$CONF_DIR"

    # Generate VLESS UUID if not provided
    if [ -z "$VLESS_UUID" ] || [ "$VLESS_UUID" = "auto" ]; then
        VLESS_UUID=$(cat /proc/sys/kernel/random/uuid)
        echo "Generated VLESS UUID: $VLESS_UUID"
    fi

    # Generate Reality keys if not provided
    if [ -z "$REALITY_PRIVATE_KEY" ]; then
        REALITY_PRIVATE_KEY=$(openssl rand -hex 32)
        echo "Generated Reality Private Key"
    fi

    if [ -z "$REALITY_PUBLIC_KEY" ]; then
        REALITY_PUBLIC_KEY=$(openssl rand -hex 32)
        echo "Generated Reality Public Key"
    fi

    if [ -z "$REALITY_SHORT_ID" ]; then
        REALITY_SHORT_ID=$(openssl rand -hex 8)
        echo "Generated Reality Short ID: $REALITY_SHORT_ID"
    fi

    # Auto-generate VPN_IP based on node name if not provided
    if [ -z "$VPN_IP" ]; then
        # Extract node number from name (node1 -> 1, node2 -> 2, etc.)
        NODE_NUM=$(echo "$NODE" | grep -oE '[0-9]+' | head -1)
        if [ -n "$NODE_NUM" ]; then
            VPN_IP="10.0.0.$NODE_NUM/24"
            echo "Auto-generated VPN IP: $VPN_IP"
        else
            VPN_IP="10.0.0.1/24"
            echo "Using default VPN IP: $VPN_IP"
        fi
    fi

    # Default values
    PORT=${TINC_PORT:-443}
    FINGERPRINT=${REALITY_FINGERPRINT:-chrome}
    REALITY_DEST=${VLESS_REALITY_DEST:-www.google.com}
    REALITY_DEST_PORT=${VLESS_REALITY_DEST_PORT:-443}
    REALITY_SNI=${VLESS_REALITY_SNI:-$REALITY_DEST}

    # Create tinc.conf with full configuration
    cat > "$CONF_DIR/tinc.conf" << EOF
# ==============================================================================
# TINC-VLESS CONFIGURATION
# ==============================================================================
# Node: $NODE
# Auto-generated at: $(date '+%Y-%m-%d %H:%M:%S')
# ==============================================================================

# Basic node settings
Name = $NODE
Port = $PORT
DeviceType = tun
Interface = tinc0
Mode = router

# TCP only mode (required for VLESS protocol)
TCPOnly = yes

# ==============================================================================
# VLESS PROTOCOL SETTINGS
# ==============================================================================
VLESSMode = yes
VLESSUUID = $VLESS_UUID

# ==============================================================================
# REALITY TLS SETTINGS
# ==============================================================================
# Reality provides TLS fingerprinting from real websites for DPI evasion
VLESSReality = yes
VLESSRealityDest = $REALITY_DEST
VLESSRealityDestPort = $REALITY_DEST_PORT
VLESSRealityServerName = $REALITY_SNI
VLESSRealityPrivateKey = $REALITY_PRIVATE_KEY
VLESSRealityPublicKey = $REALITY_PUBLIC_KEY
VLESSRealityShortID = $REALITY_SHORT_ID
VLESSRealityFingerprint = $FINGERPRINT

# ==============================================================================
# VPN NETWORK SETTINGS
# ==============================================================================
# VPN address (replaces tinc-up/tinc-down scripts)
VPNAddress = $VPN_IP

# Keepalive settings
PingInterval = 10
PingTimeout = 5
AutoConnect = yes

# ==============================================================================
# DPI EVASION SETTINGS
# ==============================================================================
# Packet Padding - randomizes packet sizes to prevent fingerprinting
# Modes: off, random, fixed, adaptive, mtu
#VLESSPaddingMode = off
#VLESSPaddingMin = 0
#VLESSPaddingMax = 256
#VLESSPaddingFixedSize = 1400
#VLESSPaddingSmallOnly = yes
#VLESSPaddingThreshold = 128

# Timing Obfuscation - randomizes packet timing
#VLESSTimingMode = off
#VLESSTimingMinDelay = 0
#VLESSTimingMaxDelay = 100
#VLESSTimingBurstSize = 10

# Probing Protection - detects and blocks active probing attacks
#VLESSProbingProtection = off
#VLESSProbingMaxFailures = 3
#VLESSProbingBlockDuration = 300

# Traffic Shaping - normalizes traffic patterns
#VLESSTrafficShaping = off
#VLESSTrafficShapingRate = 1000000
#VLESSTrafficShapingBurst = 65536
EOF

    # Add ConnectTo entries if specified
    if [ -n "$CONNECT_TO" ]; then
        echo "" >> "$CONF_DIR/tinc.conf"
        echo "# Peer connections" >> "$CONF_DIR/tinc.conf"
        IFS=',' read -ra PEERS <<< "$CONNECT_TO"
        for peer in "${PEERS[@]}"; do
            echo "ConnectTo = $peer" >> "$CONF_DIR/tinc.conf"
        done
    fi

    echo "Created tinc.conf"

    # Create hosts.json if not exists
    if [ ! -f "$CONF_DIR/hosts.json" ]; then
        VPN_ADDR=$(echo "$VPN_IP" | cut -d'/' -f1)
        VPN_PREFIX=$(echo "$VPN_IP" | cut -d'/' -f2)
        [ -z "$VPN_PREFIX" ] && VPN_PREFIX=32
        SUBNET="$VPN_ADDR/$VPN_PREFIX"

        cat > "$CONF_DIR/hosts.json" << EOF
{
  "nodes": {
    "$NODE": {
      "addresses": [],
      "port": $PORT,
      "subnet": "$SUBNET",
      "vpn_address": "$VPN_ADDR",
      "vless_uuid": "$VLESS_UUID",
      "authorized": true
    }
  }
}
EOF
        echo "Created hosts.json"
    fi

    echo "Configuration auto-generated successfully"
    echo ""
fi

# Show configuration summary
echo "=== Tinc Configuration Summary ==="
grep -E "^(Name|Port|VPNAddress|VLESSMode|VLESSReality|ConnectTo)" "$CONF_DIR/tinc.conf" 2>/dev/null || cat "$CONF_DIR/tinc.conf"
echo "=================================="
echo ""

# Check if hosts.json exists
if [ -f "$CONF_DIR/hosts.json" ]; then
    echo "=== hosts.json ==="
    cat "$CONF_DIR/hosts.json"
    echo "=================="
    echo ""
fi

# Execute tincd
echo "Starting tincd with network: $NETWORK (debug level: $DEBUG_LEVEL)"
exec tincd -n "$NETWORK" -D -d${DEBUG_LEVEL}
