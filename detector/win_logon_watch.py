#!/usr/bin/env python3
"""Windows failed-logon source for Layer 1 (v10). Reads the Windows event logs and writes auth.log-style lines to
%PROGRAMDATA%\\DualShield\\logs\\auth.log, which detector/ssh_parser.py (blocking, chain report) and detector/login_watch.py
(slow brute force, stolen logins) already understand. Run from an elevated prompt (reading the Security log needs it).

  Security log 4625  failed logon (RDP, SMB, network logons that carry a source address)  -> "Failed password for USER from IP"
  Security log 4624  successful remote logon (types 3 and 10)                              -> "Accepted password for USER from IP"
  OpenSSH/Operational  lines written by Windows OpenSSH Server                             -> passed through as they are

  python detector/win_logon_watch.py            # loop forever
  python detector/win_logon_watch.py --once     # one poll (tests)
Needs audit policy "Audit Logon" (success and failure), which Windows enables by default on most editions.
Limits: IPv4 only; the source address in 4625 is empty for some local or interactive logons (ignored); events appear a moment
after the attempt, so detection is a little slower than reading auth.log on Linux."""
import argparse, ipaddress, json, os, re, socket, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "multi"))
import shield_os

AUTH = os.environ.get("LOG_PATH") or shield_os.log_path("auth.log")
HOST = socket.gethostname()
PS_SEC = r"""$last=%d
$ev = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625,4624;StartTime=(Get-Date).AddMinutes(-15)} -ErrorAction SilentlyContinue | Where-Object { $_.RecordId -gt $last } | Sort-Object RecordId
@($ev | ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){ $d[$n.Name]=$n.'#text' }; [pscustomobject]@{id=$_.Id;rec=$_.RecordId;user=$d['TargetUserName'];ip=$d['IpAddress'];lt=$d['LogonType']} }) | ConvertTo-Json -Compress"""
PS_SSH = r"""$last=%d
$ev = Get-WinEvent -FilterHashtable @{LogName='OpenSSH/Operational'} -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object { $_.RecordId -gt $last } | Sort-Object RecordId
@($ev | ForEach-Object { [pscustomobject]@{rec=$_.RecordId;msg=$_.Message} }) | ConvertTo-Json -Compress"""


def _rows(text):
    text = (text or "").strip()
    if not text or text == "null":
        return []
    try:
        o = json.loads(text)
    except ValueError:
        return []
    return o if isinstance(o, list) else [o]


def _ipv4(x):
    try:
        a = ipaddress.ip_address((x or "").strip())
    except ValueError:
        return None
    return str(a) if a.version == 4 and not a.is_loopback and not a.is_unspecified else None


def lines_from_security(rows):
    out, top = [], 0
    ts = time.strftime("%b %d %H:%M:%S")
    for r in rows:
        top = max(top, int(r.get("rec") or 0))
        ip = _ipv4(r.get("ip"))
        user = (r.get("user") or "unknown").replace(" ", "_")
        if not ip:
            continue
        if int(r.get("id") or 0) == 4625:
            out.append("%s %s sshd[0]: Failed password for %s from %s port 0 ssh2" % (ts, HOST, user, ip))
        elif int(r.get("id") or 0) == 4624 and str(r.get("lt")) in ("3", "10"):
            out.append("%s %s sshd[0]: Accepted password for %s from %s port 0 ssh2" % (ts, HOST, user, ip))
    return out, top


def lines_from_ssh(rows):
    out, top = [], 0
    for r in rows:
        top = max(top, int(r.get("rec") or 0))
        m = re.search(r"((?:Failed|Accepted) \w+ for (?:invalid user )?\S+ from \d{1,3}(?:\.\d{1,3}){3}[^\n]*)", r.get("msg") or "")
        if m:
            out.append("%s %s sshd[0]: %s" % (time.strftime("%b %d %H:%M:%S"), HOST, m.group(1).strip()))
    return out, top


class Watcher:
    def __init__(self, path=AUTH):
        self.path, self.sec, self.ssh = path, None, None

    def poll(self):
        """One poll of both logs. The first poll only remembers where the logs end, so old events are never replayed."""
        n = 0
        for name, script, conv in (("sec", PS_SEC, lines_from_security), ("ssh", PS_SSH, lines_from_ssh)):
            last = getattr(self, name)
            try:
                rc, out, err = shield_os.powershell(script % (last or 0))
            except Exception as e:
                print("[WARN] powershell failed:", e, flush=True)
                continue
            if rc != 0 and not out.strip():
                print("[WARN] event log not readable (%s). Run as Administrator." % err.strip()[:120], flush=True)
                continue
            lines, top = conv(_rows(out))
            if last is None:                      # first poll: remember position, write nothing
                setattr(self, name, top)
                continue
            if top:
                setattr(self, name, max(top, last))
            if lines:
                with open(self.path, "a") as f:
                    f.write("\n".join(lines) + "\n")
                n += len(lines)
        return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--every", type=float, default=1.0)
    a = ap.parse_args()
    if not shield_os.IS_WIN and not os.environ.get("SHIELD_OS"):
        sys.exit("win_logon_watch.py is for Windows; on Linux ssh_parser.py reads /var/log/auth.log directly.")
    os.makedirs(os.path.dirname(AUTH), exist_ok=True)
    open(AUTH, "a").close()
    w = Watcher()
    print("Windows logon watch -> %s" % AUTH, flush=True)
    w.poll()                                      # baseline
    while True:
        n = w.poll()
        if n:
            print("[WINLOG] %d logon line(s) written" % n, flush=True)
        if a.once:
            return
        time.sleep(a.every)


if __name__ == "__main__":
    main()
