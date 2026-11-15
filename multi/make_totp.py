#!/usr/bin/env python3
"""Turn on 2-step sign-in for the dashboard (administrator and operator).
Creates a secret, writes it into multi/config.env (mode 600) as DASH_TOTP_SECRET and shows the setup key ONCE.
Add it in an authenticator app (Google Authenticator, Microsoft Authenticator, Aegis ...): 'Enter a setup key', type = time based.
Do not screenshot or paste the key anywhere. Restart the dashboard afterwards (multi/start_D.sh).
   python3 multi/make_totp.py            create (refuses to overwrite)
   python3 multi/make_totp.py --replace  new secret (the old authenticator entry stops working)
   python3 multi/make_totp.py --off      remove 2-step sign-in"""
import base64, os, re, secrets, stat, sys, urllib.parse
CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.env")
if not os.path.exists(CFG): sys.exit("multi/config.env not found")
txt = open(CFG).read()
m = re.search(r"^DASH_TOTP_SECRET=(.*)$", txt, re.M)
cur = (m.group(1).strip() if m else "")
def save(new):
    global txt
    line = "DASH_TOTP_SECRET=" + new
    txt = re.sub(r"^DASH_TOTP_SECRET=.*$", line, txt, flags=re.M) if m else txt.rstrip("\n") + "\n" + line + "\n"
    open(CFG, "w").write(txt); os.chmod(CFG, stat.S_IRUSR | stat.S_IWUSR)
if "--off" in sys.argv: save(""); sys.exit("2-step sign-in removed. Restart the dashboard.")
if len(cur) >= 16 and "--replace" not in sys.argv: sys.exit("2-step sign-in is already on. Use --replace to create a new secret (the old authenticator entry will stop working).")
key = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
save(key)
uri = "otpauth://totp/" + urllib.parse.quote("Dual-Shield:dashboard") + "?secret=" + key + "&issuer=Dual-Shield&digits=6&period=30"
print("Setup key (shown once, type it into the authenticator app):\n\n    " + " ".join(key[i:i + 4] for i in range(0, len(key), 4)) + "\n")
print("It is saved in multi/config.env. Restart the dashboard, then sign in with password + 6-digit code.")
print("If you use a phone app that reads links: " + uri)
