#!/bin/bash

cd /opt/gitrepo/vpn-experiments/tinc-vless/docker;
cat redeploy-test-logs.sh

docker compose -f docker-compose.optimized.yml build
docker compose -f docker-compose.optimized.yml up -d --force-recreate --no-deps
docker ps

# Quick connectivity checks (non-interactive exec)
docker exec tinc-node2 ping -c 3 10.0.0.1 || true
docker exec tinc-node2 ping -c 3 10.0.0.3 || true
docker exec tinc-node3 ping -c 3 10.0.0.1 || true
docker exec tinc-node1 ping -c 3 10.0.0.2 || true

# Show interface and routes for each node
echo "--- node1 ifaces/routes ---"
docker exec tinc-node1 sh -lc 'ip a show dev tinc0; ip r' || true
echo "--- node2 ifaces/routes ---"
docker exec tinc-node2 sh -lc 'ip a show dev tinc0; ip r' || true
echo "--- node3 ifaces/routes ---"
docker exec tinc-node3 sh -lc 'ip a show dev tinc0; ip r' || true

# Try to dump tinc runtime state (may not be available everywhere)
echo "--- node1 tinc dump ---"; docker exec tinc-node1 sh -lc 'tinc -n testvpn dump nodes || true; tinc -n testvpn dump connections || true'
echo "--- node2 tinc dump ---"; docker exec tinc-node2 sh -lc 'tinc -n testvpn dump nodes || true; tinc -n testvpn dump connections || true'
echo "--- node3 tinc dump ---"; docker exec tinc-node3 sh -lc 'tinc -n testvpn dump nodes || true; tinc -n testvpn dump connections || true'

# Recent logs
docker logs tinc-node1 -n 150
docker logs tinc-node2 -n 150
docker logs tinc-node3 -n 150
