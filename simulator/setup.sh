#!/bin/bash
docker network create --subnet 172.30.0.0/24 smartcity-net

docker run -dit --name target   --network smartcity-net --ip 172.30.0.10 --cap-add=NET_ADMIN ubuntu:22.04
docker run -dit --name peer     --network smartcity-net --ip 172.30.0.11 --cap-add=NET_ADMIN ubuntu:22.04
docker run -dit --name attacker --network smartcity-net --ip 172.30.0.12 --cap-add=NET_ADMIN kalilinux/kali-rolling

docker exec target   bash -c "apt update && apt install -y ipset iptables iputils-ping openssh-server rsyslog"
docker exec peer     bash -c "apt update && apt install -y ipset iptables iputils-ping"
docker exec attacker bash -c "apt update && apt install -y iputils-ping hydra"
