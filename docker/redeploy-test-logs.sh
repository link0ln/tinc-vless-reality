#!/bin/bash

cd /opt/gitrepo/vpn-experiments/tinc-vless/docker;
cat redeploy-test-logs.sh

docker compose -f docker-compose.optimized.yml build
docker compose -f docker-compose.optimized.yml up -d --force-recreate --no-deps
docker ps
docker exec -it tinc-node2 ping -c 3 10.0.0.1
docker exec -it tinc-node2 ping -c 3 10.0.0.3
docker exec -it tinc-node3 ping -c 3 10.0.0.1
docker exec -it tinc-node1 ping -c 3 10.0.0.2
docker logs tinc-node1 -n 100
docker logs tinc-node2 -n 100
docker logs tinc-node3 -n 100
