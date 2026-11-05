#!/usr/bin/env python3
"""Slow brute force, password spraying and stolen-credential logins (Layer 1, SSH).

ssh_parser.py catches fast guessing (3 failures in 5 s). This watcher adds what it cannot see, by
looking at a much longer window (default 10 minutes) and at SUCCESSFUL logins:

  slow-bruteforce    >= --slow-fails failures from one IP in --window seconds (patient attacker)
  password-spray     >= --spray-users different user names tried from one IP (many users, few tries each)
  distributed-guess  >= --dist-fails failures against ONE user from >= --dist-ips different IPs
  login-after-fails  a successful login from an IP that failed >= --after-fails times just before
                     (the guess worked: probably a compromised account)
  login-from-tor     a successful login from a Tor exit address
  login-unexpected   (only if --allow-ips is given) a successful login from outside the allow-list
  login-odd-hour     (only if --hours is given, e.g. 7-20) a successful login outside working hours

Reaction = same pipeline as everything else: block the IP (a blocked IP's open SSH session stops
passing traffic), log LOGIN_BLOCK, report to the chain. Opt-in (LOGIN_WATCH=1) and separate process.
  sudo python3 detector/login_watch.py --dry          # detect and print only
Limits: a login with a stolen password from an allowed IP at a normal hour looks like the real user.
"""
import argparse, collections, os, re, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flood_detector import Reactor

LOG_PATH = os.environ.get("LOG_PATH", "/var/log/auth.log")
LOGIN_LOG = "/var/log/login_block.log"
IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
FAIL = re.compile(r"Failed \S+ for (?:invalid user )?(\S+) from " + IP)
INVALID = re.compile(r"Invalid user (\S+) from " + IP)
OK = re.compile(r"Accepted \S+ for (\S+) from " + IP)


class LoginAnalyzer:
    def __init__(self, window=600, slow_fails=10, spray_users=5, dist_fails=15, dist_ips=3, after_fails=2,
                 allow_ips=(), hours=None, tor=(), whitelist=(), cooldown=600):
        self.window, self.slow_fails, self.spray_users = window, slow_fails, spray_users
        self.dist_fails, self.dist_ips, self.after_fails = dist_fails, dist_ips, after_fails
        self.allow_ips, self.hours, self.tor = set(allow_ips), hours, set(tor)
        self.whitelist, self.cooldown = set(whitelist), cooldown
        self.fails = collections.deque()          # (ts, ip, user)
        self.flagged = {}

    def _trim(self, now):
        while self.fails and now - self.fails[0][0] > self.window:
            self.fails.popleft()

    def _flag(self, out, now, kind, ip, detail):
        if ip in self.whitelist or now - self.flagged.get((kind, ip), -1e9) < self.cooldown:
            return
        self.flagged[(kind, ip)] = now
        out.append((kind, ip, detail))

    def feed(self, ts, ip, user, ok):
        out = []
        if ip in self.whitelist:
            return out
        self._trim(ts)
        if not ok:
            self.fails.append((ts, ip, user))
            mine = [f for f in self.fails if f[1] == ip]
            if len(mine) >= self.slow_fails:
                self._flag(out, ts, "slow-bruteforce", ip, "%d failures in %ds" % (len(mine), self.window))
            users = {f[2] for f in mine}
            if len(users) >= self.spray_users:
                self._flag(out, ts, "password-spray", ip, "%d different users tried" % len(users))
            same = [f for f in self.fails if f[2] == user]
            ips = {f[1] for f in same}
            if len(same) >= self.dist_fails and len(ips) >= self.dist_ips:
                for i in sorted(ips):
                    self._flag(out, ts, "distributed-guess", i, "%d failures on user %s from %d IPs" % (len(same), user, len(ips)))
            return out
        # successful login
        before = sum(1 for f in self.fails if f[1] == ip)
        if before >= self.after_fails:
            self._flag(out, ts, "login-after-fails", ip, "user %s logged in after %d failures" % (user, before))
        if ip in self.tor:
            self._flag(out, ts, "login-from-tor", ip, "user %s via Tor exit" % user)
        if self.allow_ips and ip not in self.allow_ips:
            self._flag(out, ts, "login-unexpected", ip, "user %s from outside the allow-list" % user)
        if self.hours:
            h = time.localtime(ts).tm_hour
            if not (self.hours[0] <= h < self.hours[1]):
                self._flag(out, ts, "login-odd-hour", ip, "user %s at %02d:00" % (user, h))
        return out


def parse(line):
    """auth.log line -> (ip, user, ok) or None."""
    m = OK.search(line)
    if m:
        return m.group(2), m.group(1), True
    m = FAIL.search(line) or INVALID.search(line)
    if m:
        return m.group(2), m.group(1), False
    return None


def tail(path):
    while not os.path.exists(path):
        time.sleep(1)
    with open(path) as f:
        f.seek(0, 2)
        while True:
            ln = f.readline()
            if not ln:
                time.sleep(0.05)
                continue
            yield ln


def load_tor():
    for p in ("/opt/shield/tor_exits.txt", os.path.join(os.path.dirname(os.path.abspath(__file__)), "tor_exits.txt")):
        if os.path.exists(p):
            return {x.strip() for x in open(p) if re.match(r"^\d+\.\d+\.\d+\.\d+$", x.strip())}
    return set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--window", type=int, default=600)
    ap.add_argument("--slow-fails", type=int, default=10)
    ap.add_argument("--spray-users", type=int, default=5)
    ap.add_argument("--dist-fails", type=int, default=15)
    ap.add_argument("--dist-ips", type=int, default=3)
    ap.add_argument("--after-fails", type=int, default=2)
    ap.add_argument("--allow-ips", default="")
    ap.add_argument("--hours", default="", help="working hours, e.g. 7-20")
    a = ap.parse_args()
    wl = {x.strip() for x in os.environ.get("WHITELIST_EXTRA", "").split(",") if x.strip()} | {"172.30.0.1", "172.30.0.11"}
    hours = tuple(int(x) for x in a.hours.split("-")) if a.hours else None
    an = LoginAnalyzer(a.window, a.slow_fails, a.spray_users, a.dist_fails, a.dist_ips, a.after_fails,
                       {x for x in a.allow_ips.split(",") if x}, hours, load_tor(), wl)
    rx = Reactor(a.dry, False, wl, chain=os.environ.get("NO_CHAIN") != "1", prefix="LOGIN_BLOCK", log=LOGIN_LOG, tag="LOGIN")
    print("LOGIN_WATCH on %s dry=%s window=%ds slow>=%d spray>=%d users" % (LOG_PATH, a.dry, a.window, a.slow_fails, a.spray_users), flush=True)
    for ln in tail(LOG_PATH):
        r = parse(ln)
        if r:
            for ev in an.feed(time.time(), *r):
                rx.handle(*ev)


if __name__ == "__main__":
    main()
