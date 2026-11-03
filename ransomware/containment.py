"""Step 6 - contain the attack once the kill rule fires (or the gate trips).

What containment does, in order (each step is independent and logged):
  1. FREEZE the vault: no further commit can overwrite the last clean snapshot.
  2. QUARANTINE the network: an iptables chain DS_QUAR that only allows loopback
     and an allow-list (the dashboard D and peer P), so ransomware cannot
     exfiltrate files or spread. Modes: off | dry (print only) | apply.
  3. EVIDENCE: evidence/containment.json (time, reason, flagged files, commands).

    python3 containment.py show
    python3 containment.py quarantine --allow 192.168.1.20 --allow 192.168.1.30 [--apply]
    python3 containment.py release   [--apply]      # remove the quarantine
Release does NOT unfreeze the vault: restore first, then `vault.py unfreeze`.
"""
import argparse, json, os, subprocess, sys, time

CHAIN = "DS_QUAR"
EVIDENCE = "evidence/containment.json"


def quarantine_commands(allow):
    c = [["iptables", "-N", CHAIN],
         ["iptables", "-A", CHAIN, "-i", "lo", "-j", "ACCEPT"],
         ["iptables", "-A", CHAIN, "-o", "lo", "-j", "ACCEPT"]]
    for ip in allow:
        c.append(["iptables", "-A", CHAIN, "-s", ip, "-j", "ACCEPT"])
        c.append(["iptables", "-A", CHAIN, "-d", ip, "-j", "ACCEPT"])
    c += [["iptables", "-A", CHAIN, "-j", "DROP"],
          ["iptables", "-I", "OUTPUT", "1", "-j", CHAIN],
          ["iptables", "-I", "INPUT", "1", "-j", CHAIN]]
    return c


def release_commands():
    return [["iptables", "-D", "OUTPUT", "-j", CHAIN],
            ["iptables", "-D", "INPUT", "-j", CHAIN],
            ["iptables", "-F", CHAIN],
            ["iptables", "-X", CHAIN]]


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
            rc, err = 127, "iptables not installed"
        print("CONTAIN_RUN rc=%s %s %s" % (rc, line, err), flush=True)
        results.append({"cmd": line, "rc": rc, "err": err})
    return results


def is_quarantined():
    try:
        r = subprocess.run(["iptables", "-S", CHAIN], capture_output=True, text=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def quarantine(allow, apply):
    if apply and is_quarantined():
        print("CONTAIN_ALREADY quarantine chain exists")
        return [{"cmd": "(already active)", "rc": 0}]
    return _run(quarantine_commands(allow), apply)


def release(apply):
    return _run(release_commands(), apply)


def contain(mode, allow, reason, flagged=(), vault_mod=None):
    """Called by guard.py / detect.py. mode: off | dry | apply."""
    t = time.time()
    if vault_mod is None:
        import vault as vault_mod
    vault_mod.freeze(reason)
    net = []
    if mode in ("dry", "apply"):
        net = quarantine(allow, apply=(mode == "apply"))
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
