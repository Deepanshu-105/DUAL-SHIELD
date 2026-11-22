#!/usr/bin/env python3
"""v13.25: fixes found by checking the GitHub repo against the docs.   Run from the repo root:  python3 apply_v13_25.py
 1. AGENT_DEMO=1 (multi/agent.py + start_T.sh): lets the demo ransomware button work with PRODUCTION=1 (before: always 403 in production, so a production-mode demo could not show Layer 2).
 2. run_all_tests.sh now also runs the v13.14-v13.23 tests (web_guard, host_guard, more_attacks, flood, node_watch, alerts, agent demo flag, dashboard events/report, ransomware guard/types/vault).
 3. config.env.example lists every v13.14+ key (WEB_GUARD, HOST_GUARD, AGENT_DEMO, DS_CHECK_A_ALLOW, ALERT_*).
 4. .gitignore: duplicate lines removed.
 5. dashboard/package.json: Next.js 16.4.6 (run: cd dashboard && npm install).
 6. blockchain/README.md: marked as the legacy Hardhat prototype (it described a start procedure the project no longer uses).
 7. runs apply_v13_24.py (button style on the Attack events tab) if present.
Nothing is changed unless every anchor matches (*.bak kept)."""
import os, re, subprocess, sys
EDITS = {
 "multi/agent.py": [('DEMO_ENDPOINTS = not PRODUCTION          # /ransomware starts the mock attack and WIPES the vault (fresh=True): never in production',
                     'DEMO_ENDPOINTS = (not PRODUCTION) or os.environ.get("AGENT_DEMO", "0") == "1"   # /ransomware starts the mock attack and WIPES the vault (fresh=True): off in PRODUCTION unless AGENT_DEMO=1 (demo day only)', 'AGENT_DEMO'),
                    ('"demo endpoint is disabled (PRODUCTION=1): it would wipe the vault"', '"demo endpoint is disabled (PRODUCTION=1; set AGENT_DEMO=1 in multi/config.env for a demo): it would wipe the vault"', 'set AGENT_DEMO=1')],
 "multi/start_T.sh": [('PRODUCTION="${PRODUCTION:-0}" AGENT_ALLOW="${AGENT_ALLOW:-$AGENT_ALLOW_V}"', 'AGENT_DEMO="${AGENT_DEMO:-0}" PRODUCTION="${PRODUCTION:-0}" AGENT_ALLOW="${AGENT_ALLOW:-$AGENT_ALLOW_V}"', 'AGENT_DEMO="${AGENT_DEMO')],
 "run_all_tests.sh": [('multi/test_registry.py multi/test_tls.py multi/test_windows_mode.py detector/test_v5.py; do',
                       'multi/test_registry.py multi/test_tls.py multi/test_windows_mode.py detector/test_v5.py \\\n         detector/test_web_guard.py detector/test_host_guard.py detector/test_more_attacks.py detector/test_flood.py \\\n         multi/test_node_watch.py multi/test_alert_notify.py multi/test_agent_demo.py multi/test_win_etw.py; do', 'detector/test_web_guard.py'),
                      ('run "fabric/test_trust.py (real chain)" chain python3 fabric/test_trust.py',
                       'run "fabric/test_trust.py (real chain)" chain python3 fabric/test_trust.py\nfor t in dashboard/test_events.mjs dashboard/test_report.mjs; do [ -e "$t" ] && run "$t" none node "$t"; done\n# ransomware guard / types / vault (mock only; test_m3.py = 10 full runs is slower: run it by hand)\nfor t in test_guard.py test_types.py test_protect_vault.py; do [ -e "ransomware/$t" ] && run "ransomware/$t" none bash -c "cd ransomware && python3 setup_sample.py >/dev/null 2>&1; python3 $t"; done', 'dashboard/test_events.mjs')],
 "dashboard/package.json": [('"next": "16.4.2"', '"next": "16.4.6"', '"next": "16.4.6"')],
}
EXAMPLE_ADD = '''
# ---- v13.14 to v13.25 keys ----
#   PRODUCTION=1   TLS, strict gateway, all guards on, blocks kept (use for the evidence run)
#   AGENT_DEMO=1   with PRODUCTION=1: allow the demo ransomware button (it WIPES the vault: demo day only, remove afterwards)
#   WEB_GUARD=1    web attacks (SQLi, XSS, traversal, RCE, probes, flood, deface restore, web-shell quarantine); WEB_LOG, WEB_ROOT = web server log and folder
#   HOST_GUARD=1   reverse shells and crypto miners: kill, block, quarantine
WEB_GUARD=0
HOST_GUARD=0
AGENT_DEMO=0
#   DS_CHECK_A_ALLOW=1  fewer false positives in ransomware check A (read ransomware/CHECK_A_ALLOWLIST.md first; frozen results assume 0)
DS_CHECK_A_ALLOW=0
#   Alerts to a phone (see multi/config.env.alerts.example): ALERT_TELEGRAM_TOKEN, ALERT_TELEGRAM_CHAT, ALERT_WEBHOOK,
#   ALERT_SMTP_HOST/PORT/USER/PASS, ALERT_MAIL_TO, ALERT_MIN=high, ALERT_MAX_PER_MIN=10. Put the real values only in multi/config.env.
'''
new, bad = {}, []
for p, edits in EDITS.items():
    if not os.path.exists(p): bad.append(p + " missing (run from the repo root)"); continue
    s = o = open(p).read()
    for a, b, mark in edits:
        if mark in s: continue
        if s.count(a) != 1: bad.append("%s: anchor not found: %s" % (p, a[:60])); continue
        s = s.replace(a, b, 1)
    new[p] = (o, s)
p = "multi/config.env.example"
if os.path.exists(p):
    s = open(p).read()
    if "v13.14 to v13.25 keys" not in s: new[p] = (s, s.rstrip("\n") + "\n" + EXAMPLE_ADD)
else: bad.append(p + " missing")
p = ".gitignore"
if os.path.exists(p):
    s = open(p).read(); seen = set(); out = []
    for l in s.split("\n"):
        if l.strip() and not l.startswith("#"):
            if l in seen: continue
            seen.add(l)
        out.append(l)
    new[p] = (s, "\n".join(out))
if bad: print("NOTHING CHANGED:\n  " + "\n  ".join(bad)); sys.exit(1)
for p, (o, s) in new.items():
    if s != o: open(p + ".bak", "w").write(o); open(p, "w").write(s); print("patched", p)
    else: print("already up to date:", p)
p = "blockchain/README.md"
if os.path.exists(p):
    t = open(p).read()
    if not t.startswith("> **Legacy"):
        open(p + ".bak", "w").write(t); open(p, "w").write("> **Legacy prototype.** The current ledger is Hyperledger Fabric (see ../README_FABRIC.md, ../docs/DOCUMENTATION.md). This folder is the early Hardhat version, kept for the gas and latency numbers in REPORT_DRAFT.md. The commands below do not start the current system.\n\n" + t); print("patched", p)
if os.path.exists("apply_v13_24.py"): subprocess.call([sys.executable, "apply_v13_24.py"])
print("v13.25 applied. Now: cd dashboard && npm install && npm run build ; then bash run_all_tests.sh")
