#!/usr/bin/env bash
# One command, all automated tests of DualShield.   ./run_all_tests.sh        (exit 1 if any FAIL)
# Tests that need a running chain (gateway on :8600) or a tool that is missing are shown as SKIP, never hidden.
cd "$(dirname "$0")" || exit 1
PASS=0; FAIL=0; SKIP=0; ROWS=""
gw_up() { (exec 3<>/dev/tcp/127.0.0.1/8600) 2>/dev/null; }
run() {  # run <name> <needs: none|chain|npm> <command...>
  local name="$1" need="$2"; shift 2
  if [ "$need" = chain ] && ! gw_up; then SKIP=$((SKIP+1)); ROWS+=$(printf '%-6s %s  (needs the chain: start multi/start_D.sh)\n' SKIP "$name"); ROWS+=$'\n'; return; fi
  if [ "$need" = npm ] && ! command -v npm >/dev/null; then SKIP=$((SKIP+1)); ROWS+=$(printf '%-6s %s  (npm not installed)\n' SKIP "$name"); ROWS+=$'\n'; return; fi
  if "$@" >/tmp/ds_test.$$ 2>&1; then PASS=$((PASS+1)); ROWS+=$(printf '%-6s %s\n' PASS "$name"); else FAIL=$((FAIL+1)); ROWS+=$(printf '%-6s %s\n' FAIL "$name"); ROWS+=$'\n'"$(tail -5 /tmp/ds_test.$$ | sed 's/^/         /')"; fi
  ROWS+=$'\n'
}
py() { local f="$1"; if [ ! -e "$f" ]; then SKIP=$((SKIP+1)); ROWS+=$(printf '%-6s %s  (file not in this version)\n' SKIP "$f"); ROWS+=$'\n'; return; fi; run "$f" none python3 "$f"; }
run "chaincode unit tests (npm test)" npm bash -c 'cd fabric/chaincode/cityshield && npm test'
for t in network/test_block_policy.py network/test_peer_trust.py network/test_watchlist.py \
         multi/test_agent_hardening.py multi/test_blockkeeper.py multi/test_v11.py multi/test_v12.py multi/test_v13_11.py \
         multi/test_registry.py multi/test_tls.py multi/test_windows_mode.py detector/test_v5.py; do
  case "$t" in network/test_watchlist.py) run "$t" chain python3 "$t";; *) py "$t";; esac
done
run "fabric/test_trust.py (real chain)" chain python3 fabric/test_trust.py
printf '%s' "$ROWS" | sed '/^$/d'
echo "------"; echo "TOTAL: $PASS pass, $FAIL fail, $SKIP skipped"
rm -f /tmp/ds_test.$$; [ "$FAIL" = 0 ]
