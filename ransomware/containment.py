"""Step 6 - contain the attack once the kill rule fires (or the gate trips).

What containment does, in order (each step is independent and logged):
  1. FREEZE the vault: no further commit can overwrite the last clean snapshot.
  2. QUARANTINE the network: an iptables chain DS_QUAR (Windows: Windows Firewall default policy block in/out plus allow rules) that only allows loopback
     and an allow-list (the dashboard D and peer P), so ransomware cannot
     exfiltrate files or spread. Modes: off | dry (print only) | apply.
  3. EVIDENCE: evidence/containment.json (time, reason, flagged files, commands).

    python3 containment.py show
    python3 containment.py quarantine --allow 192.168.1.20 --allow 192.168.1.30 [--apply]
    python3 containment.py release   [--apply]      # remove the quarantine
Release does NOT unfreeze the vault: restore first, then `vault.py unfreeze`.
"""
import argparse, json, os, subprocess, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "multi"))
import shield_os            # iptables on Linux, Windows Firewall (netsh) on Windows

CHAIN = "DS_QUAR"
EVIDENCE = "evidence/containment.json"


def quarantine_commands(allow):
    return shield_os.quarantine_commands(allow)


def release_commands(allow=()):
    return shield_os.release_commands(allow)


def _run(cmds, apply):
    results = []
    for cmd in cmds:
        line = " ".join(cmd)
        if not apply:
            print("CONTAIN_DRY_RUN", line, flush=True)
            results.append({"cmd": line, "rc": None})
            continue
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
            rc, err = r.returncode, r.stderr.strip()[:120]
        except FileNotFoundError:
            rc, err = 127, "%s not installed" % cmd[0]
        print("CONTAIN_RUN rc=%s %s %s" % (rc, line, err), flush=True)
        results.append({"cmd": line, "rc": rc, "err": err})
    return results


def is_quarantined():
    return shield_os.is_quarantined()


def quarantine(allow, apply):
    if apply and is_quarantined():
        print("CONTAIN_ALREADY quarantine chain exists")
        return [{"cmd": "(already active)", "rc": 0}]
    res = _run(quarantine_commands(allow), apply)
    if apply:
        shield_os.mark_quarantine(True, allow)
    return res


def release(apply, allow=None):
    allow = shield_os.quarantine_allow_saved() if allow is None else allow
    res = _run(release_commands(allow), apply)
    if apply:
        shield_os.mark_quarantine(False)
    return res


def contain(mode, allow, reason, flagged=(), vault_mod=None):
    """Called by guard.py / detect.py. mode: off | dry | apply."""
    t = time.time()
    if vault_mod is None:
        import vault as vault_mod
    vault_mod.freeze(reason)
    # v11 product mode: CONTAIN=apply|dry|off in the environment overrides the file; CONTAIN_ALLOW="ip,ip" (D, P, the admin PC) is added
    # to the allow list; apply with an EMPTY allow list would cut this laptop off from everything (even the dashboard that
    # could release it), so it is refused and runs as dry; and quarantine releases itself after QUARANTINE_MAX_S (default 900 s,
    # 0 = never) so a false alarm cannot lock a machine out for good.
    mode = os.environ.get("CONTAIN") or mode
    allow = list(dict.fromkeys(list(allow) + [x.strip() for x in os.environ.get("CONTAIN_ALLOW", "").split(",") if x.strip()]))
    if mode == "apply" and not allow:
        print("CONTAIN_REFUSED apply needs a non-empty allow list (set CONTAIN_ALLOW=D_IP,P_IP); running as dry", flush=True)
        mode = "dry"
    net = []
    if mode in ("dry", "apply"):
        net = quarantine(allow, apply=(mode == "apply"))
        max_s = float(os.environ.get("QUARANTINE_MAX_S", "900"))
        if mode == "apply" and max_s > 0:
            import threading
            def _auto():
                if is_quarantined():
                    print("%.6f CONTAIN_AUTO_RELEASE after %.0fs" % (time.time(), max_s), flush=True)
                    release(True, allow)
            th = threading.Timer(max_s, _auto); th.daemon = True; th.start()
    ev = {"time": t, "reason": reason, "mode": mode, "allow": list(allow),
          "flagged_files": sorted(set(flagged)), "network": net,
          "next_steps": ["python3 vault.py log", "python3 vault.py restore <folder>",
                         "python3 containment.py release --apply", "python3 vault.py unfreeze"]}
    os.makedirs(os.path.dirname(EVIDENCE), exist_ok=True)
    with open(EVIDENCE, "w") as f:
        json.dump(ev, f, indent=2)
    print("%.6f CONTAINED mode=%s reason=%s" % (time.time(), mode, reason), flush=True)
    return ev


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["show", "quarantine", "release"])
    ap.add_argument("--allow", action="append", default=[])
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    if a.cmd == "show":
        print(open(EVIDENCE).read() if os.path.exists(EVIDENCE) else "no containment evidence")
    elif a.cmd == "quarantine":
        quarantine(a.allow, a.apply)
    else:
        release(a.apply)
