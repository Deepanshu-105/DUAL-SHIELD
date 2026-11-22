#!/usr/bin/env python3
"""v13.25: the demo ransomware endpoint is off in PRODUCTION unless AGENT_DEMO=1; on in the lab."""
import os, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__)); bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
def flag(**env):
    e = dict(os.environ, AGENT_SECRET="s" * 24, ROLE="target"); e.pop("PRODUCTION", None); e.pop("AGENT_DEMO", None); e.update(env)
    r = subprocess.run([sys.executable, "-c", "import agent; print(agent.DEMO_ENDPOINTS)"], capture_output=True, text=True, cwd=here, env=e)
    return r.stdout.strip()
check("lab (PRODUCTION=0): demo endpoint on", flag() == "True")
check("PRODUCTION=1: demo endpoint off", flag(PRODUCTION="1") == "False")
check("PRODUCTION=1 AGENT_DEMO=0: still off", flag(PRODUCTION="1", AGENT_DEMO="0") == "False")
check("PRODUCTION=1 AGENT_DEMO=1: on (demo day)", flag(PRODUCTION="1", AGENT_DEMO="1") == "True")
sys.exit(1 if bad else 0)
