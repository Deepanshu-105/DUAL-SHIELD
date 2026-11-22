#!/usr/bin/env python3
"""v13.16: fixes the three honest limits of v13.15 on T and P. Run from the repo root AFTER v13.15:  python3 apply_v13_16.py
Every anchor is checked first; if anything does not match NOTHING is changed (originals are kept as *.bak when it applies)."""
import os, sys
J_BLOCK = '''# ------------------------------------------------------------------ block list (Layer 1)
# v13.16: write-ahead journal of the blocks that SHOULD exist. It is written before the firewall is touched, so a crash cannot lose
# a block, and multi/blockkeeper.py compares it with the real firewall (restores what was removed behind our back = tamper).
def desired_path():
    return log_path("blocks.desired.json")


def desired_load():
    try:
        with open(desired_path()) as f:
            return set(json.load(f))
    except (OSError, ValueError):
        return set()


def desired_save(ips):
    tmp = desired_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sorted(ips), f); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, desired_path())


def _journal(ip, on):
    if IS_WIN:
        return
    try:
        d = desired_load()
        (d.add if on else d.discard)(ip)
        desired_save(d)
    except OSError:
        pass


'''
EDITS = {
 "multi/shield_os.py": [
  ("# ------------------------------------------------------------------ block list (Layer 1)\n", J_BLOCK, "desired_path"),
  ('    ip = _ip(ip)\n    if not IS_WIN:\n        _run(["ipset", "add", _set(ip), ip, "-exist"], check=True)\n        return',
   '    ip = _ip(ip)\n    if not IS_WIN:\n        _journal(ip, True)\n        _run(["ipset", "add", _set(ip), ip, "-exist"], check=True)\n        return', "_journal(ip, True)"),
  ('    ip = _ip(ip)\n    if not IS_WIN:\n        _run(["ipset", "del", _set(ip), ip, "-exist"], check=True)\n        return',
   '    ip = _ip(ip)\n    if not IS_WIN:\n        _journal(ip, False)\n        _run(["ipset", "del", _set(ip), ip, "-exist"], check=True)\n        return', "_journal(ip, False)"),
  ('    if not IS_WIN:\n        _run(["ipset", "flush", SET]); _run(["ipset", "flush", SET6])\n        return',
   '    if not IS_WIN:\n        try: desired_save(set())\n        except OSError: pass\n        _run(["ipset", "flush", SET]); _run(["ipset", "flush", SET6])\n        return', "desired_save(set())"),
 ],
 "multi/start_T.sh": [
  ('''  [ -s "$SAVE" ] && ipset restore -exist < "$SAVE" && echo "restored $(ipset list city_blacklist | grep -c '^[0-9]') blocked addresses"
  touch /var/log/parser_block.log /var/log/metrics.log
  pkill -f blocklist_save.loop 2>/dev/null
  ( exec -a blocklist_save.loop bash -c 'while true; do ipset save city_blacklist > '"$SAVE"'.tmp 2>/dev/null && mv -f '"$SAVE"'.tmp '"$SAVE"'; sleep 20; done' ) >/dev/null 2>&1 &''',
   '''  touch /var/log/parser_block.log /var/log/metrics.log
  pkill -f multi/blockkeeper.py 2>/dev/null
  "$PY" "$ROOT/multi/blockkeeper.py" --restore --once          # journal (written BEFORE every block) -> firewall: a hard crash loses nothing
  nohup "$PY" -u "$ROOT/multi/blockkeeper.py" > /var/log/blockkeeper.out 2>&1 &     # restores blocks removed behind our back, logs BLOCKKEEPER_TAMPER''', "blockkeeper.py"),
 ],
 "multi/start_P.sh": [
  ("ipset flush city_blacklist\niptables -C",
   '''if [ "${KEEP_BLOCKS:-${PRODUCTION:-0}}" = "1" ]; then
  pkill -f multi/blockkeeper.py 2>/dev/null
  "$PY" "$ROOT/multi/blockkeeper.py" --restore --once
  nohup "$PY" -u "$ROOT/multi/blockkeeper.py" > /var/log/blockkeeper.out 2>&1 &
else
  ipset flush city_blacklist
fi
iptables -C''', "blockkeeper.py"),
  ('AGENT_SECRET="$AGENT_SECRET_P" ROLE=peer',
   'PRODUCTION="${PRODUCTION:-0}" AGENT_ALLOW="${AGENT_ALLOW:-$([ "${PRODUCTION:-0}" = "1" ] && echo "$D_IP,127.0.0.1")}" AGENT_SECRET="$AGENT_SECRET_P" ROLE=peer', "AGENT_ALLOW="),
 ],
 "multi/agent.py": [
  ('    "watch": os.path.join(RDIR, "evidence", "watch.log"),', '    "watch": os.path.join(RDIR, "evidence", "watch.log"),\n    "keeper": shield_os.log_path("keeper.log"),', '"keeper"'),
  ('    print("agent role=%s port=%d root=%s" % (ROLE, PORT, ROOT), flush=True)',
   '    if PRODUCTION and not tlsutil.enabled():\n        sys.exit("PRODUCTION=1 needs TLS=1 (mutual TLS is the real identity; IP allow-lists alone are weak). Refusing to start.")\n    print("agent role=%s port=%d root=%s" % (ROLE, PORT, ROOT), flush=True)', "needs TLS=1"),
 ],
 "multi/check_T.py": [
  ('add("PASS" if os.path.exists("/var/lib/dualshield/blocklist.save") else ("WARN" if prod else "INFO"), "blocks survive a restart (saved list)", "PRODUCTION=1 or KEEP_BLOCKS=1")',
   'add("PASS" if running("multi/blockkeeper.py") else ("FAIL" if prod else "WARN"), "blockkeeper running (blocks journaled, restored after crash/flush)", "PRODUCTION=1 or KEEP_BLOCKS=1, then multi/start_T.sh")', "blockkeeper"),
 ],
}
new, bad = {}, []
for path, edits in EDITS.items():
    if not os.path.exists(path): bad.append("%s: file not found (run from the repo root; v13.15 must be installed)" % path); continue
    s = open(path).read()
    for a, b, mark in edits:
        if mark in s: continue          # already applied
        if s.count(a) != 1: bad.append("%s: anchor not found: %r" % (path, a[:60])); continue
        s = s.replace(a, b, 1)
    new[path] = s
if bad:
    print("NOTHING CHANGED:\n  " + "\n  ".join(bad)); sys.exit(1)
for path, s in new.items():
    if s != open(path).read():
        os.replace(path, path + ".bak") if False else open(path + ".bak", "w").write(open(path).read())
        open(path, "w").write(s); print("patched", path)
    else: print("already up to date", path)
print("v13.16 applied. Restart: sudo multi/start_T.sh (T), sudo multi/start_P.sh (P). Test: python3 multi/test_blockkeeper.py")
