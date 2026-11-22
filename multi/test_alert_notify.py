#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import alert_notify as an
bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
P = an.parse
e = P("17:40:05 WEB_ATTACK 203.0.113.5 web attack: sqli", "T", "web"); check("web attack = high, names type and address", e and e["sev"] == "high" and "sqli" in e["text"] and "203.0.113.5" in e["text"])
e = P("17:40:09 HOST_ATTACK HIGH pid=300 reverse shell (/dev/tcp) | bash -i | killed; blocked+reported 1.2.3.4", "P", "host"); check("reverse shell = critical, shows the actions", e and e["sev"] == "critical" and "killed" in e["text"] and e["node"] == "P")
e = P("17:40:08 WEB_QUARANTINED shell.php (x)", "T", "web"); check("web shell = critical", e and e["sev"] == "critical")
e = P("2026-11-21 17:40:01 NODEWATCH_ALERT MEDIUM new kernel module x", "T", "nodewatch"); check("nodewatch severity kept (medium)", e and e["sev"] == "medium")
e = P("1763740000.123456 KILL_TRIGGER distinct_files=3", "T", "watch"); check("ransomware kill (epoch prefix) = critical", e and e["sev"] == "critical")
e = P("1763740000.5 RANSOM_TYPE wiper [x]  y", "T", "watch"); check("ransomware type named", e and "wiper" in e["text"])
e = P("GATE_TRIPPED 5 suspicious files, commit skipped", "T", "watch"); check("gate tripped (no prefix)", e and e["sev"] == "high")
e = P("2026-11-21 10:00:00 TRUST Org1MSP:User1@org1.example.com -> SUSPEND (OVERRULED@1000)", "D", "trust"); check("peer suspended", e and "SUSPEND" in e["text"] and e["sev"] == "high")
check("normal lines are not alerts", P("17:40:00 WEB_GUARD on  log=x", "T", "web") is None and P("VAULT_COMMIT rev=1 3 ms", "T", "watch") is None)
check("control characters and long text are cleaned", "\x1b" not in an.clean("a\x1b[31mb\x00") and len(an.clean("x" * 1000)) == 300)
check("new_lines: sliding tail", an.new_lines(["a", "b", "c"], ["b", "c", "d", "e"]) == ["d", "e"] and an.new_lines([], ["x"]) == ["x"] and an.new_lines(["a"], ["a"]) == [])
sent = []; clock = [1000.0]
n = an.Notifier([("t", sent.append)], "high", 3, now=lambda: clock[0], log=lambda m: None)
log = {("T", "web"): ["17:40:00 WEB_GUARD on  log=x"]}
n.poll(lambda: log); check("first look at a log only sets a baseline (old events are NOT sent)", sent == [])
log[("T", "web")] = log[("T", "web")] + ["17:41:00 WEB_ATTACK 203.0.113.5 web attack: sqli"]; n.poll(lambda: log); check("a new event is sent once", len(sent) == 1)
n.poll(lambda: log); check("same log again = nothing new", len(sent) == 1)
log[("T", "web")] += ["17:42:0%d WEB_ATTACK 203.0.113.%d web attack: xss" % (i, i) for i in range(6)]; n.poll(lambda: log)
check("flood of alerts is folded into one '+N more' message (limit 3 per minute)", len(sent) == 4 and "more alerts" in sent[-1] and "+4 more" in sent[-1])
clock[0] += 120; log[("T", "host")] = []; n.poll(lambda: log); log[("T", "host")] = ["17:45:00 HOST_ATTACK HIGH pid=1 miner | c | killed"]; n.poll(lambda: log); check("after a minute alerts flow again", len(sent) == 5 and "miner" in sent[-1])
low = []; n2 = an.Notifier([("t", low.append)], "high", 10, log=lambda m: None); lg = {("T", "nodewatch"): ["2026-11-21 17:40:00 NODEWATCH on"]}; n2.poll(lambda: lg)
lg[("T", "nodewatch")] += ["2026-11-21 17:41:00 NODEWATCH_ALERT MEDIUM new kernel module x"]; n2.poll(lambda: lg); check("ALERT_MIN=high ignores medium events", low == [])
def boom(t): raise OSError("network down")
errs = []; n3 = an.Notifier([("bad", boom), ("ok", low.append)], "high", 10, log=errs.append); lg3 = {("T", "web"): []}; n3.poll(lambda: lg3); lg3[("T", "web")] = ["17:41:00 WEB_ATTACK 1.1.1.1 web attack: sqli"]; n3.poll(lambda: lg3)
check("one channel failing does not stop the others", len(low) == 1 and any("ALERT_SEND_FAILED" in x for x in errs))
check("channels are built only from what is configured", [s[0] for s in an.senders_from({"ALERT_WEBHOOK": "https://x", "ALERT_TELEGRAM_TOKEN": "t", "ALERT_TELEGRAM_CHAT": "1"})] == ["telegram", "webhook"] and an.senders_from({}) == [])
sys.exit(1 if bad else 0)
