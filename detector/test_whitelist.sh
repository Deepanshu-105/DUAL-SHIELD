#!/usr/bin/env bash
# Whitelist test for the SSH parser. Run on the host (WSL) while the parser is running in another window.
#   bash detector/test_whitelist.sh
# It writes fake sshd "Failed password" lines into the target's auth.log:
#   - 6 failures from 172.30.0.1  (whitelisted: must NOT be blocked)
#   - 3 failures from 172.30.0.99 (control: must be blocked, otherwise the test proves nothing)

WL_IP=172.30.0.1
CTRL_IP=172.30.0.99
SET=city_blacklist

if ! docker exec target pgrep -f ssh_parser.py >/dev/null 2>&1; then
  echo "The parser is not running. In another window run:"
  echo "  docker exec -it target python3 /root/detector/ssh_parser.py"
  exit 1
fi

# start from a clean state
docker exec target ipset del $SET $WL_IP   -exist 2>/dev/null
docker exec target ipset del $SET $CTRL_IP -exist 2>/dev/null

inject() {  # inject <ip> <count>
  docker exec target bash -c "for i in \$(seq 1 $2); do
    echo \"\$(date '+%b %e %H:%M:%S') target sshd[999]: Failed password for testuser from $1 port 40000 ssh2\" >> /var/log/auth.log
  done"
}

echo "Injecting 6 failures from whitelisted $WL_IP and 3 from control $CTRL_IP ..."
inject $WL_IP 6
inject $CTRL_IP 3
sleep 1.5

fail=0
if docker exec target ipset test $SET $WL_IP >/dev/null 2>&1; then
  echo "FAIL: whitelisted $WL_IP was blocked"; fail=1
else
  echo "PASS: whitelisted $WL_IP is NOT in $SET"
fi
if docker exec target ipset test $SET $CTRL_IP >/dev/null 2>&1; then
  echo "PASS: control $CTRL_IP IS in $SET (the parser did see the log lines)"
else
  echo "FAIL: control $CTRL_IP was not blocked, so this run proves nothing"; fail=1
fi

docker exec target ipset del $SET $CTRL_IP -exist 2>/dev/null   # tidy up
echo
docker exec target ipset list $SET | sed -n '1,12p'
exit $fail
