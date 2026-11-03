# Recovery without ransom: vault + steps 5, 6, 7

All commands run inside `ransomware/`. First time: `bash setup_sample.sh`.

## Run the demo (2 terminals)
Terminal 1 (protection):
    python3 guard.py protect.json
Terminal 2 (attack, then recover):
    python3 mock_crypto.py --delay 0.05
    python3 vault.py status                       # frozen: true
    python3 vault.py log
    python3 vault.py restore data/restored --root sample
    python3 triage.py data/sample_copy --vault-has-snapshot
    python3 vault.py unfreeze                     # after you have restored
Self-test (no side effects):  `python3 test_guard.py`

## Step 5 - smaller data-loss window
`guard.py` commits to the vault ~2 s after the last change (debounce_s), at most
every 30 s under constant writes. Before every commit a clean gate checks the live
files against the last committed state; flagged files are held back, 3 or more
freeze the vault. Loss window = debounce, not "since the last manual snapshot".
Git history keeps older versions, so `--rev HEAD~1` is the safety net.

## Step 6 - contain the attack
When the kill rule fires (or the gate trips): vault frozen, evidence written to
`evidence/containment.json`, network quarantine chain `DS_QUAR` (loopback + `allow`
IPs only). `"contain"` in protect.json: `off`, `dry` (default, prints iptables
commands) or `apply` (needs root). Put D and P (and your SSH client) in `allow`
or you will cut your own session. Undo: `sudo python3 containment.py release --apply`.

## Step 7 - wider coverage
`protect.json` takes any number of roots, `exclude` patterns and `max_mb`.
Each root is stored as `files/<name>/`; restore one with `--root <name>`.

## Verified recovery (recover.py) and tamper checks
    python3 vault.py verify          # recompute Merkle roots, compare with the manifest committed with each snapshot
    python3 vault.py fsck            # git object integrity
    python3 recover.py sample data/sample_copy --in-place [--anchor IP]
recover.py walks the history newest to oldest, SKIPS any snapshot that fails verification, restores the first good
one into a new folder, verifies it again, optionally checks the blockchain root (--anchor), then swaps it in. The
encrypted folder is kept as `<folder>.encrypted-<time>` (evidence). Restart guard.py afterwards.

## Off-machine copy
Set `"remote"` in protect.json to a git URL or path (for example a bare repo on laptop P:
`git init --bare /srv/vault.git`, then `ssh://user@P_IP/srv/vault.git`). Every commit is pushed in the background.
Without this, ransomware that also encrypts `data/vault` on the same machine defeats the vault.

## Dashboard
The "Recovery vault (Layer 2)" panel shows vault state, last snapshot age, guard, containment, off-machine copy and the
last recovery, with Recover and Unfreeze buttons (confirm header required). In four-laptop mode D reads it from T's
signed agent (`GET /recovery`, `POST /recover`, `POST /unfreeze`). T needs `GUARD=1` in multi/config.env.

## Honest limits
- Loss window is ~debounce_s, not zero. True zero needs fanotify permission
  events / a FUSE or copy-on-write filesystem (ZFS/btrfs snapshots).
- Writer PID still comes from /proc open files + a lab fallback; fanotify would be exact.
- Whole disk / OS drive: needs a kernel-level service and an off-machine vault
  (`vault.py push` with a remote); a user-space watcher on a few folders is not that.
- The first snapshot is assumed clean. Ransomware that waits and encrypts slowly
  under 3 files per window is held by the gate (check A/B) but not by the kill rule.
