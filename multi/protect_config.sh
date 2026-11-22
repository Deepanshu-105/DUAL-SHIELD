#!/usr/bin/env bash
# Keeps the secrets of DualShield out of Git and off the disk in plain text.   multi/protect_config.sh [--check]
#  1) config.env mode 600  2) .gitignore for config.env, TLS keys, logs, sealed store  3) git pre-commit hook that REFUSES a commit
#  containing a private key, config.env/secrets.enc, or a secret value (AGENT_SECRET_*, DASH_*PASS, TOTP, backup codes, keys)
#  4) report: which secrets are still plain text in config.env (on D they should be sealed: python3 multi/secrets_vault.py seal)
# Values are never printed, only the names.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT" || exit 1
CFG=multi/config.env
KEYS='AGENT_SECRET_T|AGENT_SECRET_P|AGENT_SECRET|DASH_PASS|DASH_VIEW_PASS|DASH_OPERATOR_PASS|DASH_TOTP_SECRET|DASH_BACKUP_CODES|DASH_SESSION_KEY|SELFGUARD_KEY|CHAIN_IP_KEY|ALERT_TELEGRAM_TOKEN|ALERT_SMTP_PASS|ALERT_WEBHOOK'
rc=0
if [ "${1:-}" != "--check" ]; then
  [ -f "$CFG" ] && chmod 600 "$CFG" && echo "ok: $CFG is now mode 600"
  touch .gitignore
  for p in multi/config.env multi/secrets.enc multi/tls/ multi/logs/ '*.pem' '*.key' 'evidence/EVIDENCE_*/'; do
    grep -qxF "$p" .gitignore || { echo "$p" >> .gitignore; echo "ok: .gitignore += $p"; }
  done
  if [ -d .git ]; then
    cat > .git/hooks/pre-commit <<'HOOK'
#!/usr/bin/env bash
# DualShield: refuse to commit secrets (installed by multi/protect_config.sh)
KEYS='AGENT_SECRET_T|AGENT_SECRET_P|AGENT_SECRET|DASH_PASS|DASH_VIEW_PASS|DASH_OPERATOR_PASS|DASH_TOTP_SECRET|DASH_BACKUP_CODES|DASH_SESSION_KEY|SELFGUARD_KEY|CHAIN_IP_KEY|ALERT_TELEGRAM_TOKEN|ALERT_SMTP_PASS|ALERT_WEBHOOK'
bad=0
for f in $(git diff --cached --name-only --diff-filter=ACM); do
  case "$f" in
    *.example|*.md|*.docx) ;;
    *config.env|*secrets.enc|*.pem|*.key|*multi/tls/*) echo "BLOCKED: $f must never be committed"; bad=1; continue;;
  esac
  case "$f" in *.example|*.md|*.docx) continue;; esac
  if git diff --cached -U0 -- "$f" | grep -E '^\+' | grep -Eq -- '-----BEGIN [A-Z ]*PRIVATE KEY-----'; then echo "BLOCKED: private key inside $f"; bad=1; fi
  if git diff --cached -U0 -- "$f" | grep -E '^\+' | grep -Eq "(^|[^A-Za-z0-9_])($KEYS)[[:space:]]*=[[:space:]]*['\"]?[A-Za-z0-9+/=_.:-]{8,}"; then echo "BLOCKED: a secret value inside $f"; bad=1; fi
done
[ "$bad" = 0 ] || { echo "Commit refused. Remove the secret (use multi/config.env, which is git-ignored)."; exit 1; }
HOOK
    chmod +x .git/hooks/pre-commit; echo "ok: git pre-commit hook installed"
  else echo "note: not a git repo here, hook not installed"; fi
fi
echo "--- report (names only)"
if [ -f "$CFG" ]; then
  m=$(stat -c %a "$CFG" 2>/dev/null); [ "$m" = 600 ] || { echo "WARN: $CFG mode $m (should be 600)"; rc=1; }
  plain=$(grep -E "^[[:space:]]*(export[[:space:]]+)?($KEYS)=['\"]?[^'\" #]{4,}" "$CFG" | sed -E 's/^[[:space:]]*(export[[:space:]]+)?([A-Z_]+)=.*/\2/' | sort -u | tr '\n' ' ')
  if [ -n "$plain" ]; then
    if [ -f multi/secrets.enc ]; then echo "WARN: plain-text secrets still in $CFG although a sealed store exists: $plain-> run: python3 multi/secrets_vault.py seal"; rc=1
    else echo "INFO: plain-text secrets in $CFG: $plain"; echo "      on D: python3 multi/secrets_vault.py seal ; on T/P (they need AGENT_SECRET): keep mode 600, root only, never copy the file around"; fi
  else echo "ok: no plain-text secret values in $CFG"; fi
else echo "INFO: $CFG not found"; fi
if [ -d .git ]; then
  h=$(git log --all --oneline -- multi/config.env multi/secrets.enc 2>/dev/null | wc -l)
  [ "$h" = 0 ] && echo "ok: config.env / secrets.enc were never committed" || { echo "WARN: config.env/secrets.enc appear in $h commit(s): rotate every secret, then clean history (git filter-repo)"; rc=1; }
fi
exit $rc
