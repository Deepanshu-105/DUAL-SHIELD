#!/usr/bin/env bash
# Finishes the remaining Day 1 items. Run from anywhere: bash finish_day1.sh
set -e
cd ~/DUAL-SHIELD

# 1. Make the dashboard peer IP match the real container IP
PEER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' peer 2>/dev/null || true)
echo "peer container IP: ${PEER_IP:-not found}"
if [ -n "$PEER_IP" ] && [ "$PEER_IP" != "172.30.0.11" ]; then
  sed -i "s/172\.30\.0\.11/$PEER_IP/" dashboard/app/page.js
  echo "updated dashboard/app/page.js to $PEER_IP"
fi

# 2. Record the HASSH decision
mkdir -p docs
if ! grep -q "HASSH" docs/decisions.md 2>/dev/null; then
cat >> docs/decisions.md <<'EOF'
# Design decisions

## M1: fingerprinting method (Day 1)
Decision: use HASSH (SSH client fingerprinting), not JA3.
Reason: the lab's attack is SSH brute-forcing (Hydra against sshd). HASSH
fingerprints the SSH client handshake; JA3 only applies to TLS clients and
would matter only if an HTTPS target is added later.
EOF
echo "wrote docs/decisions.md"
fi

# 3. README: dashboard run instructions
if ! grep -q "## Dashboard" README.md 2>/dev/null; then
cat >> README.md <<'EOF'

## Dashboard
```
cd dashboard
npm install
npm run dev     # opens at http://localhost:3000
```

## Lab (Docker Compose)
```
docker compose up -d
docker exec -it target python3 /root/detector/ssh_parser.py
```
EOF
echo "updated README.md"
fi

# 4. docker-compose.yml (only if none exists)
if [ ! -f docker-compose.yml ] && [ ! -f network/docker-compose.yml ] && [ ! -f network/docker-compose.yaml ]; then
cat > docker-compose.yml <<'EOF'
services:
  target:
    image: ubuntu:22.04
    container_name: target
    cap_add: [NET_ADMIN]
    volumes:
      - ./detector:/root/detector
    networks:
      lab:
        ipv4_address: 172.30.0.10
    command: >
      bash -c "apt-get update &&
      DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server rsyslog ipset iptables python3 &&
      (id testuser || (useradd -m testuser && echo 'testuser:password123' | chpasswd)) &&
      echo 'auth,authpriv.* /var/log/auth.log' > /etc/rsyslog.d/50-default.conf &&
      service ssh start && rsyslogd && sleep infinity"

  peer:
    image: ubuntu:22.04
    container_name: peer
    tty: true
    stdin_open: true
    networks:
      lab:
        ipv4_address: 172.30.0.11
    command: sleep infinity

  attacker:
    image: kalilinux/kali-rolling
    container_name: attacker
    tty: true
    stdin_open: true
    networks:
      lab:
        ipv4_address: 172.30.0.12
    command: >
      bash -c "apt-get update && apt-get install -y hydra &&
      printf 'password\n123456\nadmin\nletmein\n' > /tmp/pw.txt && sleep infinity"

networks:
  lab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
EOF
echo "created docker-compose.yml"
fi

# 5. Commit and push
git add -A docs README.md dashboard/app/page.js docker-compose.yml 2>/dev/null || true
git commit -m "Day 1 wrap-up: HASSH decision, README, compose file, peer IP" || echo "nothing new to commit"
git push
echo "Done."
