#!/usr/bin/env bash
# Collects PROOF for the report / viva into evidence/EVIDENCE_<date>/ (run on D, after the multi-VM run).   multi/collect_evidence.sh
# Best effort: every step is optional and written down as it is (ok / not available), nothing is invented.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT" || exit 1
OUT="evidence/EVIDENCE_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$OUT"
S="$OUT/EVIDENCE.md"
step() { echo "## $1" >> "$S"; echo '```' >> "$S"; shift; "$@" >> "$S" 2>&1; echo "(exit $?)" >> "$S"; echo '```' >> "$S"; echo >> "$S"; }
{ echo "# DualShield evidence"; echo "Collected: $(date -Is) on $(hostname)"; echo; } > "$S"
step "Version (git)" bash -c 'git log -5 --oneline 2>/dev/null || echo "not a git repo"; git status --short 2>/dev/null | head -20'
step "Code fingerprints (SHA-256 of the defender code)" bash -c 'sha256sum detector/*.py network/*.py multi/*.py ransomware/*.py 2>/dev/null | sha256sum; ls detector/*.py network/*.py multi/*.py ransomware/*.py 2>/dev/null | wc -l'
step "All automated tests" ./run_all_tests.sh
[ -f multi/check_D.py ] && step "Hardening report D (check_D)" python3 multi/check_D.py
[ -f multi/check_T.py ] && step "Hardening report T (check_T, meaningful when run on T)" python3 multi/check_T.py
if [ -f multi/agent_call.py ]; then
  for r in T P; do step "Signed agent: $r /health" python3 multi/agent_call.py $r GET /health; step "Signed agent: $r blocked list" python3 multi/agent_call.py $r GET /ipset; step "Signed agent: $r keeper log" python3 multi/agent_call.py $r GET "/log?name=keeper&n=20"; done
fi
[ -f network/chain_report.py ] && step "Chain parameters and recent events" bash -c 'PYTHONPATH=network python3 - <<PY
from chainlib import Chain
c=Chain(); print("params:", c.params())
ev,head=c.events(0); print("head:", head, "events:", len(ev))
for e in ev[-15:]: print(e)
PY'
[ -f ransomware/evidence/recovery_report.json ] && step "Last ransomware recovery report" cat ransomware/evidence/recovery_report.json
[ -f ransomware/evidence/watch.log ] && step "Guard / watch log (last 40 lines)" tail -40 ransomware/evidence/watch.log
[ -f multi/logs/peer_trust.out ] && step "Peer trust log (last 40 lines)" tail -40 multi/logs/peer_trust.out
echo "Evidence written to $OUT/EVIDENCE.md  (put screenshots next to it; the report can quote it line by line)"
