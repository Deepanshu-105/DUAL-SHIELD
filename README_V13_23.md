# DualShield v13.23 - items 3, 4, 5

## 3. Push to GitHub safely: `multi/push_to_github.sh`
`bash multi/push_to_github.sh` = check only (secret scan, tests, list of files). `bash multi/push_to_github.sh --push` = asks "yes", commits on a NEW branch
(never main, never --force), pushes it, prints the pull-request link. It refuses if `multi/config.env`, a key/pem, a TLS folder or any secret value
(passwords, TOTP, backup codes, alert tokens, private keys, Telegram bot token) is tracked or would be added, and adds the right lines to `.gitignore`.
If it says a secret file is TRACKED, the secret was in Git history: rotate it (new AGENT_SECRET_*, passwords, TOTP) - removing the file is not enough.
Tested here in a scratch repo (secret untracked -> ignored; secret in another file -> blocked; secret tracked -> blocked; push -> branch only, no config.env).
NOT tested against the real GitHub (no login in my sandbox). Needs `gh auth login` or a token on your side.

## 4. Check-A allow-list (opt-in): `apply_v13_23.py`, `ransomware/CHECK_A_ALLOWLIST.md`, `ransomware/check_a_allow_eval.py`
Default OFF: frozen results unchanged. Read the memo (table ON/OFF, trade-off) and decide as a team. Benign flags 243/243 -> about 2% on my corpus;
adaptive "keep the magic" attack on zip/gz 100% -> 95%.

## 5. Bigger held-out evaluation: `eval/heldout_round2.py`, `eval/samples_round3/`, `eval/samples_teammate/`
Honest history of the numbers (all in eval/results/):
| Set (samples, written by me) | When | SQLi | XSS | Traversal | Cmd inj. | Shells | Miners | Benign wrongly flagged |
|---|---|---|---|---|---|---|---|---|
| round 2, untuned (50/50/50/51; 26; 16; 81+40) | before any change | 64% | 92% | 78% | 57% | 85% | 88% | 0 |
| round 3, untuned (30/30/30/31; 16; 12; 47+38) | after round-2 fixes | 80% | 87% | 93% | 97% | 88% | 92% | 1 web (it BLOCKS: my own round-2 fix, fixed) |
After each fix round, those samples become development samples (their later 97-100% are NOT evidence). The numbers to quote are the untuned rows.
Independent number still missing: a teammate who has not read the rules writes `eval/samples_teammate/*.txt` (README_TEAMMATE.md, 30 minutes), runs
`python3 eval/heldout_round2.py` and sends `eval/results/ROUND2_RESULTS.md`; rows named `teammate` are then the honest estimate.
Known misses left: `curl ... | bash` (a download-and-run, not a reverse shell; flagging it would break installers), `%u2216` Unicode traversal, "filter=... or 1 eq 1" (REST filter syntax).

## Install (WSL, repo root; v13.22 first)
```
DL="/mnt/c/Users/$(cmd.exe /c "echo %USERNAME%" 2>/dev/null | tr -d '\r')/Downloads"
unzip -o "$(ls -t "$DL"/DualShield_v13_23*.zip | head -1)"
python3 apply_v13_23.py
python3 detector/test_web_guard.py; python3 detector/test_host_guard.py
bash multi/push_to_github.sh
```
