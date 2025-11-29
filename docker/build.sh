#!/bin/bash
set -e

cd "$(dirname "$0")/.."

echo "=== Building tinc-vless (multistage, static binary) ==="
echo "This may take 10-15 minutes on first build..."
echo ""

cd docker

# Build with docker compose
docker compose down -v 2>/dev/null || true
docker compose build 2>&1 | tee /tmp/build.log

# Check for errors
if grep -qE "error:|Error:|fatal error" /tmp/build.log; then
    echo ""
    echo "=== BUILD ERRORS FOUND ==="
    grep -E "error:|Error:|fatal error" /tmp/build.log
    exit 1
fi

echo ""
echo "=== Build successful ==="
echo ""

# Start containers
echo "=== Starting containers ==="
docker compose up -d
sleep 3

# Show status
docker compose ps
echo ""

# Quick connectivity test
echo "=== Quick connectivity test ==="
docker exec tinc-node1 ping -c 1 10.0.0.2 2>/dev/null && echo "node1 -> node2: OK" || echo "node1 -> node2: FAIL"
docker exec tinc-node1 ping -c 1 10.0.0.3 2>/dev/null && echo "node1 -> node3: OK" || echo "node1 -> node3: FAIL"
echo ""

# Show image size
echo "=== Image size ==="
docker images | grep -E "^REPOSITORY|tinc-vless|docker-node"
