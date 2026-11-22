#!/usr/bin/env bash
# Pushes your work (v13.11 .. v13.23) to GitHub on a NEW BRANCH, after refusing anything secret.   Run from the repo root (WSL):
#   bash multi/push_to_github.sh            # check only: shows what would go, changes nothing
#   bash multi/push_to_github.sh --push     # asks "yes", then commits on a new branch and pushes it (never main, never --force)
# Then open the pull request link it prints and merge it on GitHub. Your teammates pull main afterwards.
set -u
cd "$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "not inside a git repo (cd ~/DUAL-SHIELD)"; exit 1; }
PUSH=0; [ "${1:-}" = "--push" ] && PUSH=1
REMOTE=$(git remote get-url origin 2>/dev/null) || { echo "no remote 'origin'"; exit 1; }
echo "remote: $REMOTE"
case "$REMOTE" in *Deepanshu-105/DUAL-SHIELD*) ;; *) echo "WARNING: this is not Deepanshu-105/DUAL-SHIELD. Stop here if that is wrong."; ;; esac

# 1. things that must never be committed: add them to .gitignore (idempotent)
IGN=(multi/config.env 'multi/tls/' '*.key' '*.pem' 'multi/logs/' 'multi/*.pid' '*.bak' 'node_modules/' 'dashboard/.next/' '__pycache__/' '*.pyc'
     'ransomware/data/' 'ransomware/results/*.tmp' '.env' '.env.*' '*backup*codes*' '*recovery*key*' 'vault_key*' '*.passphrase')
touch .gitignore
for p in "${IGN[@]}"; do grep -qxF "$p" .gitignore || echo "$p" >> .gitignore; done

# 2. refuse if a secret is already tracked, or would be added
KEYS='AGENT_SECRET_T|AGENT_SECRET_P|AGENT_SECRET|DASH_PASS|DASH_VIEW_PASS|DASH_OPERATOR_PASS|DASH_TOTP_SECRET|DASH_BACKUP_CODES|DASH_SESSION_KEY|SELFGUARD_KEY|CHAIN_IP_KEY|ALERT_TELEGRAM_TOKEN|ALERT_SMTP_PASS|ALERT_WEBHOOK'
bad=0
for f in $(git ls-files); do
  case "$f" in multi/config.env|*.key|*.pem|.env|multi/tls/*) echo "BLOCKED: $f is TRACKED by git (secret file). Fix: git rm --cached $f   then rotate the secrets inside it (they were public if this repo is public)"; bad=1;; esac
done
for f in $(git ls-files --others --exclude-standard; git diff --name-only); do
  [ -f "$f" ] || continue
  case "$f" in *.png|*.jpg|*.zip|*.gz|*.jar|*.pdf|*.docx|*.so|*.woff2|*.ico) continue;; esac
  if grep -IEq "(^|[^A-Za-z0-9_])($KEYS)[[:space:]]*=[[:space:]]*['\"]?[A-Za-z0-9+/=_.:-]{8,}" "$f" 2>/dev/null && [ "$f" != "multi/config.env.example" ] && [ "${f##*.}" != "example" ]; then echo "BLOCKED: a secret value inside $f"; bad=1; fi
  if grep -IEq 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}' "$f" 2>/dev/null; then echo "BLOCKED: a private key or a Telegram bot token inside $f"; bad=1; fi
done
[ $bad = 1 ] && { echo "Nothing was committed. Fix the lines above, then run again."; exit 2; }
echo "secret check: ok (no secret file tracked, no secret value in the files to be added)"

# 3. tests (skip with SKIP_TESTS=1)
if [ "${SKIP_TESTS:-0}" != 1 ] && [ -f run_all_tests.sh ]; then
  echo "running run_all_tests.sh (SKIP_TESTS=1 to skip) ..."; bash run_all_tests.sh >/tmp/ds_push_tests.out 2>&1 || { tail -15 /tmp/ds_push_tests.out; echo "tests failed: not pushing. Full output: /tmp/ds_push_tests.out"; exit 3; }
  tail -3 /tmp/ds_push_tests.out
fi

# 4. show what would go
git add -A
echo; echo "=== what will be committed ==="; git diff --cached --stat | tail -40
echo "files: $(git diff --cached --name-only | wc -l)"
if [ $PUSH = 0 ]; then git reset -q; echo; echo "CHECK ONLY: nothing committed. Run with --push to commit on a new branch and push it."; exit 0; fi
printf 'Commit these on a new branch and push it? type yes: '; read -r a; [ "$a" = yes ] || { git reset -q; echo "cancelled, nothing committed"; exit 0; }
BR="v13-security-$(date +%Y%m%d-%H%M)"
git checkout -q -b "$BR" || exit 1
git commit -q -m "DualShield v13.11-v13.23: peer trust, agent hardening, block keeper, node watch, web/host guards, dashboard events, alerts, incident report, evaluation, opt-in check-A allow-list" || { echo "nothing to commit"; exit 0; }
git push -u origin "$BR" || { echo "push failed (login? run: gh auth login, or use a token). Your commit is safe on branch $BR."; exit 4; }
REPO=$(echo "$REMOTE" | sed -E 's#(git@github.com:|https://github.com/)##; s#\.git$##')
echo; echo "PUSHED branch $BR. Open: https://github.com/$REPO/pull/new/$BR   and merge it."
