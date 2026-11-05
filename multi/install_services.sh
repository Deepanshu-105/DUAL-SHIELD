#!/bin/bash
# Run the defenders as systemd services that restart on failure (so a crash or kill is not the end).
#   sudo multi/install_services.sh            print the unit files
#   sudo multi/install_services.sh --apply    write them to /etc/systemd/system, enable and start them
# Needs systemd (on WSL2 enable it in /etc/wsl.conf: [boot] systemd=true). Uses the same venv and folders as start_T.sh.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/blockchain/.venv/bin/python3"
unit() {  # name, description, workdir, command
cat <<UNIT
[Unit]
Description=Dual-Shield $2
After=network-online.target

[Service]
WorkingDirectory=$3
ExecStart=$4
Restart=always
RestartSec=2
EnvironmentFile=-$ROOT/multi/config.env
Environment=PYTHONPATH=$ROOT/network DEPLOY=$ROOT/deployments/localhost.json

[Install]
WantedBy=multi-user.target
UNIT
}
declare -A UNITS
UNITS[dualshield-guard]="$(unit guard 'ransomware guard (vault, kill rule, containment)' "$ROOT/ransomware" "$PY -u guard.py protect.json")"
UNITS[dualshield-selfguard]="$(unit selfguard 'self-protection (tamper and outage watch)' "$ROOT" "$PY -u multi/selfguard.py --restart --freeze-on-tamper")"
UNITS[dualshield-flood]="$(unit flood 'DDoS and port-scan detector' "$ROOT" "$PY -u detector/flood_detector.py")"
if [ "$1" != "--apply" ]; then
  for n in "${!UNITS[@]}"; do echo "# /etc/systemd/system/$n.service"; echo "${UNITS[$n]}"; echo; done
  echo "(dry run: use --apply)"; exit 0
fi
[ "$EUID" -eq 0 ] || { echo "run with sudo"; exit 1; }
for n in "${!UNITS[@]}"; do echo "${UNITS[$n]}" > "/etc/systemd/system/$n.service"; done
systemctl daemon-reload
for n in "${!UNITS[@]}"; do systemctl enable --now "$n" && echo "started $n"; done
