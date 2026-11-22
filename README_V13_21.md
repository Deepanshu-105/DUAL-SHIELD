# DualShield v13.21 — "Attack events" tab on the dashboard
New tab between "Layer 1 · Network" and "Consensus & Chain": what the web guard, host guard, node watch and block keeper on T and P did.
- Tiles: web attacks, host attacks, killed / blocked, restored / quarantined (retrieved), host changes, firewall tampering.
- List (newest first, filter by kind): time, node (T/P), what happened (SQLi, reverse shell, defaced file restored, web shell quarantined, new uid-0 account ...), and the actions (blocked, killed, restored, quarantined).
- Same login and roles as the rest of the dashboard (viewer can read, nothing here changes anything).
Files: dashboard/lib/events.js (parser), dashboard/app/api/events/route.js, dashboard/app/EventsPanel.jsx, apply_v13_21.py (adds the tab to AdminConsole.jsx), detector/web_guard.py (updated: one log line now carries a time stamp so the dashboard can show it).
Needs the guards from v13.16 / v13.19 / v13.20 running on T/P; without them the tab shows "No events yet".
Install: unzip; python3 apply_v13_21.py; restart D (multi/start_D.sh rebuilds the dashboard); restart T (web_guard.py changed).
Test: node dashboard/test_events.mjs (12 checks). The dashboard compiles with `next build` and /api/events is registered (checked on a copy of the repo dashboard).
Limits: network attacks stay on the Layer 1 tab and ransomware on Layer 2; events older than the last 80 log lines per source are not shown; times of lines without a date assume today.
