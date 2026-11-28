#!/usr/bin/env python3
"""P's OWN independent incident report (read-only, no network calls, no chain query).
   Run ONLY on P, any time (safe during a live demo too -- it only reads local log files, never writes/changes anything else).
   Purpose: D's dashboard produces ONE incident report, from D's own view of the chain. This script produces a SECOND,
   independent report from P's own machine: what P itself saw (SSH detection if PEER_DETECT=1, peer blocks, node integrity
   alerts, host_guard kills), so the two reports can be compared side by side -- proof that P is a real second witness,
   not a laptop that only clicks "confirm".
   Usage:  python3 multi/peer_report.py            print the report
           python3 multi/peer_report.py --out FILE  also write it to FILE (markdown)
"""
import os, subprocess, sys, datetime

LOGS = [
    ("P's own SSH attack detection (PEER_DETECT=1)", "/var/log/peer_parser.out", 20),
    ("P's own block decisions (peer_block.log)", "/var/log/peer_block.log", 20),
    ("Node integrity watch (node_watch.py)", "/var/log/nodewatch.log", 20),
    ("Host guard (reverse shell / miner kills, if HOST_GUARD=1 on P)", "/var/log/host_guard.out", 20),
]


def tail(path, n):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()
        return "".join(lines[-n:]).rstrip("\n") or "(file exists, empty)"
    except OSError as e:
        return "(could not read: %s)" % e


def firewall_state():
    out = []
    try:
        r = subprocess.run(["sudo", "-n", "ipset", "list", "city_blacklist"], capture_output=True, text=True, timeout=5)
        out.append("ipset city_blacklist:\n" + (r.stdout.strip() or r.stderr.strip() or "(empty)"))
    except Exception as e:
        out.append("ipset: not available here (%s)" % e)
    return "\n\n".join(out)


def main():
    out_file = None
    if "--out" in sys.argv:
        i = sys.argv.index("--out")
        out_file = sys.argv[i + 1] if i + 1 < len(sys.argv) else None

    lines = []
    lines.append("# DualShield - Peer (P) independent incident report")
    lines.append("")
    lines.append("Generated: %s on %s" % (datetime.datetime.now().isoformat(timespec="seconds"), os.uname().nodename))
    lines.append("")
    lines.append("This report is produced ENTIRELY from P's own local logs. It does not ask D or T for anything,")
    lines.append("so it can be compared against D's dashboard / incident report as a second, independent account")
    lines.append("of the same run. A mismatch between the two is itself a useful finding, not a bug in this script.")
    lines.append("")

    any_data = False
    for title, path, n in LOGS:
        lines.append("## " + title)
        content = tail(path, n)
        if content is None:
            lines.append("_not present on this laptop (feature likely off in multi/config.env, or never triggered)_")
        else:
            any_data = True
            lines.append("```")
            lines.append(content)
            lines.append("```")
        lines.append("")

    lines.append("## Local firewall state (independent of the dashboard UI)")
    lines.append("```")
    lines.append(firewall_state())
    lines.append("```")
    lines.append("")

    if not any_data:
        lines.append("_Note: no log files had data yet -- run this after at least one attack has been sent, or with_")
        lines.append("_PEER_DETECT=1 / HOST_GUARD=1 set in multi/config.env before starting P._")

    text = "\n".join(lines)
    print(text)
    if out_file:
        with open(out_file, "w") as f:
            f.write(text + "\n")
        print("\n(written to %s)" % out_file, file=sys.stderr)


if __name__ == "__main__":
    main()
