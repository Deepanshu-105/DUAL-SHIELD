# DualShield v13.22 - alerts, incident report, evaluation numbers, Next.js 16.4.6

## What is new
1. **Alerts** (`multi/alert_notify.py`): Telegram / e-mail / webhook message when a guard on T or P logs a serious event (web attack, reverse shell/miner, web shell, deface restore, host change, firewall tampering, ransomware kill/type/gate, peer suspended). Only NEW events are sent (old log lines are ignored at start), `ALERT_MAX_PER_MIN` folds a flood into one "+N more" message, a failing channel does not stop the others. `start_D.sh` starts it when an ALERT_* channel is in `multi/config.env`.
2. **Incident report**: button "Incident report (print / PDF)" on the Attack events tab -> `/api/report` (needs login) -> print or save as PDF. All log text is HTML-escaped.
3. **Evaluation table** (`eval/`): `python3 eval/eval_new_attacks.py` -> `eval/results/NEW_ATTACKS_RESULTS.md` + `.csv` (dev samples and separate HELD-OUT samples).
4. **Detector fixes found by that evaluation** (web_guard.py, host_guard.py + tests): weak-SQL rule so one odd URL does not block all visitors, status-aware probe scoring (wp-login 200 is normal), name-vs-arguments miner rules (`vim xmrig`, `grep xmrig` are not miners), more shell styles (socat, openssl, telnet, awk, node), %c0%af / double-encoded traversal.
5. **Next.js 16.4.6** in `dashboard/package.json` (build tested).

## Install (WSL, from the repo root)
```
DL="/mnt/c/Users/$(cmd.exe /c "echo %USERNAME%" 2>/dev/null | tr -d '\r')/Downloads"
unzip -o "$(ls -t "$DL"/DualShield_v13_22*.zip | head -1)"
python3 apply_v13_22.py       # unzip already put the updated detector/ files, alerts, report and eval in place
cd dashboard && npm install && cd ..
```
Alerts: add the ALERT_* lines from `multi/config.env.alerts.example` to `multi/config.env`, then `python3 multi/alert_notify.py --test`.
Tests: `python3 multi/test_alert_notify.py ; node dashboard/test_report.mjs ; python3 detector/test_web_guard.py ; python3 detector/test_host_guard.py`

## Honest limits
- Alerts and report are tested with fake senders and fake logs. Not run against a real Telegram bot / real T and P.
- The evaluation is offline on text samples. Dev numbers are optimistic (rules were tuned on them); read the HELD-OUT numbers. Signature rules miss new styles.
- The package-lock.json from my sandbox is NOT shipped; run `npm install` yourself so the lock matches your machine.
