#!/usr/bin/env python3
"""v13.21: adds the "Attack events" tab to the dashboard. Run from the repo root:  python3 apply_v13_21.py
Needs dashboard/app/AdminConsole.jsx; nothing is changed unless all three anchors match (a *.bak is kept)."""
import os, sys
P = "dashboard/app/AdminConsole.jsx"
EDITS = [
 ('import { useCallback, useEffect, useState } from "react";', 'import { useCallback, useEffect, useState } from "react";\nimport EventsPanel from "./EventsPanel";', "EventsPanel"),
 ('const TABS = [["overview", "Overview"], ["l1", "Layer 1 · Network"],', 'const TABS = [["overview", "Overview"], ["l1", "Layer 1 · Network"], ["events", "Attack events"],', '["events", "Attack events"]'),
 ('        {tab === "chain" && <>', '        {tab === "events" && <EventsPanel />}\n        {tab === "chain" && <>', 'tab === "events"'),
]
if not os.path.exists(P): print("%s not found (run from the repo root)" % P); sys.exit(1)
s = open(P).read(); o = s; bad = []
for a, b, mark in EDITS:
    if mark in s: continue
    if s.count(a) != 1: bad.append(a[:60]); continue
    s = s.replace(a, b, 1)
if bad: print("NOTHING CHANGED, anchor not found:\n  " + "\n  ".join(bad)); sys.exit(1)
if s != o: open(P + ".bak", "w").write(o); open(P, "w").write(s); print("patched", P)
else: print("already up to date")
for f in ("dashboard/app/EventsPanel.jsx", "dashboard/app/api/events/route.js", "dashboard/lib/events.js"):
    print(("ok " if os.path.exists(f) else "MISSING ") + f)
print("v13.21 applied. Rebuild: cd dashboard && npm run build   (start_D.sh does it). Test: node dashboard/test_events.mjs")
