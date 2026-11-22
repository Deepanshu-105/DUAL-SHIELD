# DualShield v13.25 - repo check: fixes and documentation
Found by checking github.com/Deepanshu-105/DUAL-SHIELD (main, 22 Nov 2026) against the docs and the tests.

| Finding | Fix |
|---|---|
| `AGENT_DEMO` did not exist: with `PRODUCTION=1` the demo ransomware button always returned 403 | `AGENT_DEMO=1` flag in agent.py + start_T.sh, test `multi/test_agent_demo.py` |
| `run_all_tests.sh` ran only 11 old tests (it missed web_guard, host_guard, node_watch, alerts, dashboard, ransomware tests) | now 25 pass + 2 skipped (need the chain) |
| `config.env.example` did not list the v13.14+ keys | added |
| Next.js still 16.4.2 | 16.4.6 (package.json + package-lock.json; `npm install` in dashboard/) |
| v13.24 button style not applied | applied by apply_v13_25.py |
| README.md contradicted itself (Hardhat steps vs "no Hardhat"), had no multi-laptop run, no web/host/alerts/report | README.md rewritten; blockchain/README.md marked legacy |
| docs/DEMO_5_LAPTOPS_3_PHONES.md had none of the v13.20+ attacks | steps 14 to 22 added |
| No single simple documentation, no changelog | docs/DOCUMENTATION.md, docs/CHANGELOG.md |
| .gitignore had duplicate lines | de-duplicated |

Install (repo root):
```
DL="/mnt/c/Users/$(cmd.exe /c "echo %USERNAME%" 2>/dev/null | tr -d '\r')/Downloads"
unzip -o "$(ls -t "$DL"/DualShield_v13_25*.zip | head -1)"    # replaces README.md and docs/DEMO_5_LAPTOPS_3_PHONES.md (Git keeps the old ones)
python3 apply_v13_25.py
(cd dashboard && npm install && npm run build)
bash run_all_tests.sh
```
Not changed: the frozen results, the guards' rules, anything on real T/P.
