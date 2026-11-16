#!/bin/bash
# v13.12: encrypted backup of the whole Fabric network of D (ledgers of the orderer(s) and both peers, plus the keys), optionally copied to another machine.
#   fabric/deploy/backup_ledger.sh [--stop] [--to user@host:/path]      destination folder: $LEDGER_BACKUP_DIR (default ~/dualshield_backups)
#   --stop   stops the network for the copy and starts it again (a clean, consistent copy; without it the copy is taken while running: crash-consistent)
# The archive holds the private keys of the network, so it is encrypted (AES-256, key from a passphrase: DS_BACKUP_PASSFILE (mode 600) or typed).
# A SHA-256 file sits next to it. Restore: fabric/deploy/restore_ledger.sh FILE.enc   (network must be stopped).  Put this script in cron (daily).
FAB="$(cd "$(dirname "$0")/.." && pwd)"; NET="${NET_DIR:-$FAB/network}"
DEST="${LEDGER_BACKUP_DIR:-$HOME/dualshield_backups}"; STOP=0; TO=""
while [ $# -gt 0 ]; do case "$1" in --stop) STOP=1;; --to) TO="$2"; shift;; *) echo "unknown option $1"; exit 1;; esac; shift; done
[ -d "$NET" ] || { echo "no network folder at $NET"; exit 1; }
mkdir -p "$DEST"; chmod 700 "$DEST"
PASSARG=(); if [ -n "$DS_BACKUP_PASSFILE" ]; then
  [ "$(stat -c %a "$DS_BACKUP_PASSFILE")" -le 600 ] || { echo "DS_BACKUP_PASSFILE must be mode 600"; exit 1; }; PASSARG=(-pass "file:$DS_BACKUP_PASSFILE")
else read -rsp "backup passphrase (12+ chars): " PW; echo; [ ${#PW} -ge 12 ] || { echo "passphrase too short"; exit 1; }; export DS_BP="$PW"; PASSARG=(-pass env:DS_BP); fi
[ $STOP = 1 ] && "$FAB/deploy/network.sh" down
OUT="$DEST/dualshield_ledger_$(date +%Y%m%d_%H%M%S).tar.gz.enc"
tar -C "$NET" --exclude='*/logs' --exclude='*.pid' -czf - . 2>/dev/null | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt "${PASSARG[@]}" -out "$OUT"
RC=${PIPESTATUS[1]}
if [ $STOP = 1 ]; then "$FAB/deploy/network.sh" up >/dev/null 2>&1; fi
[ "$RC" = 0 ] || { echo "backup failed"; rm -f "$OUT"; exit 1; }
chmod 600 "$OUT"; (cd "$DEST" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")
echo "BACKUP_OK $OUT ($(du -h "$OUT" | cut -f1))"
if [ -n "$TO" ]; then scp -q "$OUT" "$OUT.sha256" "$TO" && echo "COPIED to $TO" || { echo "copy to $TO failed"; exit 1; }; fi
