#!/usr/bin/env python3
"""v13.24: cosmetic fix. On the Attack events tab the 'Incident report' link and the filter buttons (All / Web attacks / ...) showed as plain browser
buttons; now they use the dashboard's own button style. Run from the repo root. Needs v13.21 and v13.22. Nothing changes if an anchor is missing."""
import sys
P = "dashboard/app/EventsPanel.jsx"
E = [('<a className="tab" href="/api/report" target="_blank" rel="noreferrer">Incident report (print / PDF)</a>', '<a className="btn" style={{ textDecoration: "none", display: "inline-block" }} href="/api/report" target="_blank" rel="noreferrer">Incident report (print / PDF)</a>'),
     ('className={"tab" + (kind === k ? " on" : "")} onClick={() => setKind(k)}', 'className={"btn" + (kind === k ? "" : " ghost")} style={{ marginRight: 6, marginTop: 10 }} onClick={() => setKind(k)}')]
try: s = open(P).read()
except OSError: sys.exit("%s not found (run from the repo root, v13.21 applied?)" % P)
if 'className={"btn" + (kind' in s: print("already up to date"); sys.exit(0)
for a, b in E:
    if s.count(a) != 1: sys.exit("NOTHING CHANGED: anchor not found: " + a[:50])
o = s
for a, b in E: s = s.replace(a, b)
open(P + ".bak", "w").write(o); open(P, "w").write(s); print("patched", P, "- rebuild the dashboard: cd dashboard && npm run build")
