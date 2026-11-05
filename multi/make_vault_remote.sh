#!/bin/bash
# Create an append-only vault remote on ANY machine you control (a laptop, a server, a NAS; not tied to one device).
#   multi/make_vault_remote.sh [/path/vault.git]          default ~/vault.git
# Then on T: set  "remote": "user@that-machine:vault.git"  in ransomware/protect.json (SSH key login recommended).
# Append-only means: no history rewrite, no branch deletion. An attacker who steals T's SSH key can still ADD
# junk branches, but cannot erase or overwrite your snapshots. For stronger guarantees use a remote the attacker's
# account cannot reach at all (separate user, separate machine, read-only backups of the repo).
P="${1:-$HOME/vault.git}"
git init -q --bare -b main "$P" || exit 1
git --git-dir "$P" config receive.denyNonFastForwards true
git --git-dir "$P" config receive.denyDeletes true
git --git-dir "$P" config receive.denyCurrentBranch refuse
echo "vault remote ready: $P  (append-only)"
echo "Recover on a new machine:  git clone -b main <remote> ransomware/data/vault   then   python3 vault.py restore ..."
echo "You also need the encryption key backup (data/vault.key)."
