# QUIC Connection Migration

## Overview

QUIC Connection Migration allows VPN connections to seamlessly switch between different UDP ports without disrupting the established tunnel. This is crucial for bypassing ISP throttling and QoS policies that may limit long-lived UDP flows.

## How It Works

1. **Periodic Migration**: Every `QuicHopInterval` seconds, all established QUIC connections migrate to a new random ephemeral UDP port
2. **Seamless Transition**: The old socket remains open for 60 seconds (draining period) to handle in-flight packets
3. **PATH_CHALLENGE**: QUIC's built-in path validation ensures the new path is working before switching
4. **Automatic Cleanup**: Old sockets are automatically closed after the draining period

## Benefits

- **Bypass ISP Throttling**: Many ISPs throttle long-lived UDP flows (e.g., P2P, VPN). Migration prevents detection
- **QoS Evasion**: Periodic port changes make it difficult for DPI systems to classify traffic
- **NAT Traversal**: Helps maintain connections through stateful firewalls/NAT
- **Production Ready**: Based on proven rstun implementation

## Configuration

Add the following to your `tinc.conf`:

```ini
# Enable QUIC Connection Migration
QuicMigrationEnabled = yes

# Migration interval in seconds (default: 300 = 5 minutes)
# 0 = disabled
QuicHopInterval = 300
```

### Recommended Values

| Use Case | `QuicHopInterval` | Rationale |
|----------|-------------------|-----------|
| **High Throughput VPN** | 180-300 seconds | Balance between throttling avoidance and connection stability |
| **Censored Networks** | 60-120 seconds | Frequent changes make detection harder |
| **Stable Enterprise** | 600+ seconds | Less frequent changes for stable environments |
| **Testing/Development** | 30 seconds | Quick verification that migration works |

**Warning:** Very short intervals (< 30s) may cause connection instability.

## Architecture

### Components

1. **Migration Timer** (`quic_migration_task`)
   - Runs every 10 seconds
   - Checks if `hop_interval_ms` has elapsed
   - Triggers migration for all eligible connections

2. **Per-Connection State** (`quic_conn_t`)
   ```c
   bool migration_enabled;              // Per-connection toggle
   struct timeval last_migration;       // Last migration timestamp
   int old_sock_fd;                     // Previous socket (draining)
   struct timeval old_fd_close_time;    // When to close old socket
   ```

3. **Migration Process** (`migrate_connection`)
   ```c
   1. Create new UDP socket on random ephemeral port
   2. Save old socket for draining (60s)
   3. Switch quic_conn_t to use new socket
   4. Send packets to trigger PATH_CHALLENGE
   5. Schedule old socket closure
   ```

4. **Cleanup** (`cleanup_old_sockets`)
   - Runs every 10 seconds
   - Closes old sockets after 60s draining period

### Sequence Diagram

```
Client                Migration Task         QUIC Connection           Peer
  |                         |                       |                    |
  |                         |--- Check Interval -->|                    |
  |                         |<-- Time Elapsed -----|                    |
  |                         |                       |                    |
  |                         |--- Create New Socket ------> (bind random port)
  |                         |                       |                    |
  |                         |--- Switch Socket ---->|                    |
  |                         |                       |                    |
  |                         |                    [Send PATH_CHALLENGE]-->|
  |                         |                       |<-- PATH_RESPONSE --|
  |                         |                       |                    |
  |                         |<-- Migration OK ------|                    |
  |                         |                       |                    |
  |<----------------------- VPN packets on new port ------------------->|
  |                         |                       |                    |
  |                      [60s draining period]      |                    |
  |                         |                       |                    |
  |                         |--- Close Old Socket --|                    |
```

## Testing

### 1. Basic Functionality

```bash
# Enable migration with 1 minute interval
echo "QuicMigrationEnabled = yes" >> /etc/tinc/mynetwork/tinc.conf
echo "QuicHopInterval = 60" >> /etc/tinc/mynetwork/tinc.conf

# Start tinc with debug logging
tincd -D -d5

# Watch for migration logs
tail -f /var/log/tinc/mynetwork/tinc.log | grep -i migration
```

Expected output:
```
QUIC Connection Migration enabled (hop interval: 60 seconds)
QUIC migration task started
Created migration socket fd=10 on ephemeral port 54321
Connection migrated to new socket: old_fd=7 -> new_fd=10 for node node2
Migration cycle completed: 2 migrated, 0 failed
Closing drained socket fd=7 after migration
```

### 2. Verify Port Changes

```bash
# Terminal 1: Monitor UDP traffic
watch -n 1 'netstat -an | grep UDP | grep tincd'

# Terminal 2: Continuous ping
docker exec node1 ping -i 0.2 10.0.0.2

# Expected: Source port changes every 60 seconds, no ping loss
```

### 3. Throttling Simulation

```bash
# Simulate ISP throttling on long-lived flows
iptables -A OUTPUT -p udp --sport 655 -m connbytes \
         --connbytes 10485760: --connbytes-mode bytes \
         --connbytes-dir original -j DROP

# With migration enabled, traffic should continue after port change
# Without migration, traffic would be dropped after 10MB
```

### 4. Performance Test

```bash
# Baseline without migration
QuicMigrationEnabled = no
iperf3 -c 10.0.0.2 -t 600  # 10 minutes

# With migration (60s interval)
QuicMigrationEnabled = yes
QuicHopInterval = 60
iperf3 -c 10.0.0.2 -t 600

# Compare: throughput should be similar, with brief dips during migration
```

## Troubleshooting

### Migration Fails

**Symptom:** Logs show "Failed to create new socket for migration"

**Causes:**
1. **Ephemeral port exhaustion**: System ran out of available ports
   ```bash
   # Check available ports
   cat /proc/sys/net/ipv4/ip_local_port_range

   # Increase range if needed
   echo "32768 60999" > /proc/sys/net/ipv4/ip_local_port_range
   ```

2. **Firewall blocking random ports**:
   ```bash
   # Allow outbound UDP on ephemeral ports
   iptables -A OUTPUT -p udp --sport 32768:60999 -j ACCEPT
   ```

3. **SELinux/AppArmor restrictions**:
   ```bash
   # Check denials
   ausearch -m avc -ts recent | grep tincd
   ```

### Connection Drops During Migration

**Symptom:** Ping timeouts every migration interval

**Causes:**
1. **Interval too short**: Increase `QuicHopInterval` to 120+ seconds
2. **Firewall blocks new ports**: Check firewall rules
3. **Peer doesn't support migration**: Both endpoints must have QUIC migration enabled

**Debug:**
```bash
# Enable verbose QUIC logging
export RUST_LOG=debug  # if using quiche with Rust
tincd -D -d5 --logfile=/tmp/quic-debug.log

# Look for PATH_CHALLENGE/RESPONSE frames
grep "PATH_CHALLENGE\|PATH_RESPONSE" /tmp/quic-debug.log
```

### High CPU Usage

**Symptom:** CPU spikes during migration

**Causes:**
1. **Too frequent migrations**: Increase `QuicHopInterval`
2. **Many connections**: Migration overhead grows with connection count

**Mitigation:**
```bash
# Reduce migration frequency
QuicHopInterval = 600  # 10 minutes

# Or disable for low-latency scenarios
QuicMigrationEnabled = no
```

## Performance Considerations

### Overhead

- **Memory**: ~80 bytes per connection (old socket tracking)
- **CPU**: Brief spike during migration (< 100ms)
- **Network**: 1-2 QUIC frames (PATH_CHALLENGE/RESPONSE)

### Latency Impact

| Phase | Latency Increase |
|-------|------------------|
| **Normal Operation** | 0ms (no overhead) |
| **During Migration** | 5-50ms (path validation) |
| **Post-Migration** | 0ms (seamless) |

### Throughput Impact

- **Typical**: < 1% throughput drop during migration
- **Worst Case**: 2-5% if migration occurs during high load

## Compatibility

### QUIC Library Requirements

- **quiche** >= 0.15.0 (active migration support)
- **rustls** >= 0.21.0 (if using quinn)

### Firewall Requirements

- **Outbound**: Allow UDP on ephemeral ports (32768-60999)
- **NAT**: Stateful NAT must not interfere with new 5-tuples
- **DPI**: Deep packet inspection must not block QUIC migration frames

### Peer Requirements

Both client and server must:
1. Have `QuicMigrationEnabled = yes`
2. Support QUIC connection migration (RFC 9000 §9)
3. Not have `disable_active_migration` set in quiche config

## Security Considerations

### Pros

- **Anti-Correlation**: Harder to track flows across migrations
- **Evasion**: Bypasses simple port-based blocking
- **Resilience**: Survives NAT rebindings

### Cons

- **More Ports**: Opens many ephemeral ports (defense-in-depth concern)
- **State Complexity**: Old sockets linger for 60s (resource exhaustion risk)

**Recommendation:** Use migration only when necessary (censored networks, ISP throttling).

## Future Improvements

1. **Adaptive Intervals**: Adjust `QuicHopInterval` based on detected throttling
2. **Path MTU Discovery**: Probe new path MTU during migration
3. **Multipath QUIC**: Use multiple paths simultaneously (draft-ietf-quic-multipath)
4. **Connection ID Rotation**: Rotate QUIC CIDs independently of migration

## References

- RFC 9000 §9: Connection Migration
- rstun: https://github.com/neevek/rstun
- quiche migration docs: https://docs.rs/quiche/latest/quiche/

---

**Author:** tinc-vless-reality contributors
**Last Updated:** 2025-01-11
