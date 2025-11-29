# TINC-VLESS: DPI-Evasion VPN with VLESS+Reality

Tinc VPN fork with VLESS protocol and Reality TLS obfuscation for DPI evasion.

## Features

- **VLESS protocol** - UUID-based authentication over TCP
- **Reality TLS** - mimics real HTTPS traffic to websites (google.com, etc.)
- **Browser fingerprinting** - Chrome/Firefox/Safari TLS fingerprints
- **Automatic node invitation** - `tinc invite` / `tinc join` workflow
- **Auto IP allocation** - server assigns VPN addresses automatically
- **DPI evasion** - packet padding, timing obfuscation, probing protection
- **Mesh networking** - nodes route traffic through each other

## Quick Start

```bash
cd docker
./build.sh

# Test connectivity
docker exec tinc-node1 ping -c 2 10.0.0.2
docker exec tinc-node2 ping -c 2 10.0.0.3  # through node1
```

## Network Topology

```
          [network_12: 172.25.1.0/24]
                    |
node2 ──────────── node1 ──────────── node3
(10.0.0.2)        (10.0.0.1)        (10.0.0.3)
                    |
          [network_13: 172.25.2.0/24]
```

Node2 and Node3 are in separate Docker networks, communicate through node1 via VPN.

## Node Invitation System

### Server: Create invitation
```bash
docker exec tinc-node1 tinc invite newnode
# Output: vless://172.25.1.10:443/invite/TOKEN...
```

### Client: Join network
```bash
tinc join vless://172.25.1.10:443/invite/TOKEN...
```

The server automatically:
- Generates VLESS UUID for the new node
- Allocates free VPN IP from subnet
- Adds node to hosts.json database
- Creates one-time invitation token

## Configuration

### Minimal tinc.conf (auto-generated on first start)
```conf
Name = node1
Port = 443
DeviceType = tun
Interface = tinc0
Mode = router
TCPOnly = yes

# VLESS Protocol
VLESSMode = yes
VLESSUUID = a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Reality TLS
VLESSReality = yes
VLESSRealityDest = www.google.com
VLESSRealityDestPort = 443
VLESSRealityServerName = www.google.com
VLESSRealityPrivateKey = <64-hex-chars>
VLESSRealityPublicKey = <64-hex-chars>
VLESSRealityShortID = <16-hex-chars>
VLESSRealityFingerprint = chrome

# VPN Address
VPNAddress = 10.0.0.1/24

# Connections
ConnectTo = node2
ConnectTo = node3
```

### DPI Evasion Options

```conf
# Packet Padding - randomizes packet sizes
VLESSPaddingMode = random          # off|random|fixed|adaptive|mtu
VLESSPaddingMin = 10
VLESSPaddingMax = 100

# Timing Obfuscation - randomizes packet timing
VLESSTimingMode = off              # off|random|burst
VLESSTimingMinDelay = 0
VLESSTimingMaxDelay = 100
VLESSTimingBurstSize = 10

# Probing Protection - blocks active probing
VLESSProbingProtection = off       # off|on
VLESSProbingMaxFailures = 3
VLESSProbingBlockDuration = 300

# Traffic Shaping - normalizes traffic patterns
VLESSTrafficShaping = off          # off|on
VLESSTrafficShapingRate = 1000000
VLESSTrafficShapingBurst = 65536
```

### Environment Variables (docker-compose)

Only two variables needed:
```yaml
environment:
  - NODE_NAME=node1
  - TINC_NETWORK=testvpn
```

Everything else is configured in tinc.conf or auto-generated.

## hosts.json Database

Node registry with VPN addresses and authentication:

```json
{
  "nodes": {
    "node1": {
      "addresses": ["172.25.1.10"],
      "port": 443,
      "subnet": "10.0.0.1/32",
      "vpn_address": "10.0.0.1",
      "vless_uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "authorized": true
    }
  }
}
```

## Key Generation

```bash
# Reality keys
openssl rand -hex 32   # Private key (keep secret)
openssl rand -hex 32   # Public key (share with peers)
openssl rand -hex 8    # Short ID

# VLESS UUID
uuidgen
# or
cat /proc/sys/kernel/random/uuid
```

## Performance

Tested on Docker network (node2 -> node1 -> node3):

| Debug Level | Throughput |
|-------------|------------|
| -d5 (verbose) | ~100 Mbps |
| -d0 (default) | ~430 Mbps |

Bottlenecks:
- TCPOnly mode (TCP-over-TCP meltdown)
- Single-threaded tincd
- VLESS+Reality overhead

## Docker Commands

```bash
# Build and start
./build.sh

# Or manually:
docker compose build
docker compose up -d

# View logs
docker logs -f tinc-node1

# Shell access
docker exec -it tinc-node1 bash

# Performance test
docker exec tinc-node3 iperf3 -s -D
docker exec tinc-node2 iperf3 -c 10.0.0.3 -t 10

# Rebuild
docker compose down && docker compose build --no-cache && docker compose up -d
```

## How Reality Works

```
Client                           Server                    Real Website
   |                               |                           |
   |------ TLS ClientHello ------->|                           |
   |       (SNI: google.com)       |                           |
   |                               |                           |
   |   [Server checks VLESS UUID]  |                           |
   |                               |                           |
   | Valid UUID:                   |                           |
   |<====== VPN Tunnel ==========>|                           |
   |                               |                           |
   | Invalid UUID:                 |                           |
   |                               |--- Forward to real ------>|
   |<----- Real google.com --------|<---- google.com ----------|
```

DPI sees: Normal HTTPS connection to google.com with valid TLS handshake.

## Project Structure

```
tinc-vless/
├── src/
│   ├── vless/
│   │   ├── vless.c/.h        # VLESS protocol
│   │   └── reality.c/.h      # Reality TLS obfuscation
│   ├── invitation.c          # Invite/join system
│   ├── invitation_server.c   # HTTP invitation handler
│   ├── invitation_client.c   # Client-side join
│   ├── hosts_json.c/.h       # Node database
│   └── config_template.c     # Auto-config generation
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── build.sh
│   ├── scripts/
│   │   └── entrypoint.sh
│   └── node{1..3}/tinc/      # Node configs
└── deps/quiche/              # TLS library (boringssl)
```

## Security

**Protects against:**
- Protocol fingerprinting (looks like HTTPS)
- Active probing (Reality fallback to real website)
- Traffic analysis (packet padding)
- Certificate inspection (uses real site's cert chain)

**Does NOT protect against:**
- Traffic correlation attacks
- Endpoint compromise
- DNS leaks (configure separately)

## License

GPL-2.0-or-later (same as Tinc VPN)
