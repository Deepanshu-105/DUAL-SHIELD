#!/bin/bash
# v13.12: restore a backup made by backup_ledger.sh.   fabric/deploy/restore_ledger.sh FILE.tar.gz.enc [--force]
# The network must be stopped (network.sh down). The current network folder is moved aside to network.before_restore.<time>, never deleted.
FAB="$(cd "$(dirname "$0")/.." && pwd)"; NET="${NET_DIR:-$FAB/network}"; F="$1"
[ -f "$F" ] || { echo "usage: $0 FILE.tar.gz.enc"; exit 1; }
[ -f "$F.sha256" ] && { (cd "$(dirname "$F")" && sha256sum -c "$(basename "$F").sha256" >/dev/null) || { echo "CHECKSUM MISMATCH: the backup file is damaged or changed"; exit 1; }; echo "checksum ok"; }
pgrep -f "bin/orderer|bin/peer" >/dev/null && [ "$2" != "--force" ] && { echo "the Fabric network is running: fabric/deploy/network.sh down first"; exit 1; }
PASSARG=(); if [ -n "$DS_BACKUP_PASSFILE" ]; then PASSARG=(-pass "file:$DS_BACKUP_PASSFILE"); else read -rsp "backup passphrase: " PW; echo; export DS_BP="$PW"; PASSARG=(-pass env:DS_BP); fi
TMP="$(mktemp -d)"; chmod 700 "$TMP"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 "${PASSARG[@]}" -in "$F" | tar -C "$TMP" -xzf - 2>/dev/null || { echo "wrong passphrase or damaged backup"; rm -rf "$TMP"; exit 1; }
[ -n "$(ls -A "$TMP")" ] || { echo "backup is empty"; rm -rf "$TMP"; exit 1; }
[ -d "$NET" ] && mv "$NET" "$NET.before_restore.$(date +%Y%m%d_%H%M%S)"
mv "$TMP" "$NET"; echo "RESTORE_OK into $NET (start with fabric/deploy/network.sh up)"
