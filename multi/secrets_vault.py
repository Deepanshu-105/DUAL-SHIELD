#!/usr/bin/env python3
"""Keep the passwords out of plain text on disk.  AES-256-GCM, key from a passphrase (scrypt).   Needs:  pip install cryptography
   python3 multi/secrets_vault.py seal       move DASH_PASS, DASH_OPERATOR_PASS, DASH_VIEW_PASS, DASH_SESSION_KEY, DASH_TOTP_SECRET, AGENT_SECRET_T/P,
                                             SELFGUARD_KEY, CHAIN_IP_KEY out of multi/config.env into multi/secrets.enc (config.env keeps empty KEY= lines)
   python3 multi/secrets_vault.py status     what is sealed, what is still plain text
   python3 multi/secrets_vault.py set KEY [--random]   change one sealed value (hidden prompt, or a random one that is never shown)
   python3 multi/secrets_vault.py unseal     put the values back into config.env (undo)
   python3 multi/secrets_vault.py recovery-key   make an offline RECOVERY KEY (shown once). If the passphrase is ever lost, type the recovery key (starts with RK-) at the passphrase prompt.
                                             Print it, keep it away from this machine. Run it again after you change the passphrase (re-seal).
   python3 multi/secrets_vault.py env        (used by the start scripts) prints export lines for eval; asks for the passphrase on the terminal
Passphrase: typed on the terminal, or read from the file named in DS_PASSPHRASE_FILE (mode 600, keep it on a USB stick or tmpfs, for unattended starts).
The secrets exist in clear only in the memory of the running programs, never on disk."""
import base64, getpass, hashlib, json, os, re, secrets, shlex, stat, sys
HERE = os.path.dirname(os.path.abspath(__file__))
CFG, ENC = os.path.join(HERE, "config.env"), os.path.join(HERE, "secrets.enc")
KEYS = ["DASH_PASS", "DASH_OPERATOR_PASS", "DASH_VIEW_PASS", "DASH_SESSION_KEY", "DASH_TOTP_SECRET", "AGENT_SECRET_T", "AGENT_SECRET_P", "SELFGUARD_KEY", "CHAIN_IP_KEY"]
AAD = b"dualshield-secrets-v1"
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("needs the 'cryptography' package:  pip install cryptography   (T and P already have it in blockchain/.venv)")
def die(m): print(m, file=sys.stderr); sys.exit(1)
def passphrase(confirm=False):
    f = os.environ.get("DS_PASSPHRASE_FILE")
    if f:
        if os.stat(f).st_mode & 0o077: die("DS_PASSPHRASE_FILE must not be readable by others (chmod 600)")
        return open(f).read().rstrip("\n")
    def ask(p):
        try:
            with open("/dev/tty", "r+") as tty:
                tty.write(p); tty.flush(); old = None
                try:
                    import termios; fd = tty.fileno(); old = termios.tcgetattr(fd); n = termios.tcgetattr(fd); n[3] &= ~termios.ECHO; termios.tcsetattr(fd, termios.TCSADRAIN, n)
                    v = tty.readline().rstrip("\n"); tty.write("\n")
                finally:
                    if old: termios.tcsetattr(fd, termios.TCSADRAIN, old)
                return v
        except OSError:
            return getpass.getpass(p)
    p = ask("secrets passphrase (or the recovery key RK-...): ")
    if p.startswith("RK-"): return from_recovery(p)
    if confirm:
        if len(p) < 12: die("passphrase must have at least 12 characters")
        if ask("again: ") != p: die("passphrases differ")
    return p
def from_recovery(rk):
    try:
        j = json.load(open(ENC)); r = j["rec"]
        key = base64.b32decode(rk[3:].replace("-", "").upper() + "=" * (-len(rk[3:].replace("-", "")) % 8))
        return AESGCM(key).decrypt(base64.b64decode(r["nonce"]), base64.b64decode(r["ct"]), AAD + b"-rec").decode()
    except Exception: die("wrong recovery key (or none was made: python3 multi/secrets_vault.py recovery-key)")
def derive(pw, salt): return hashlib.scrypt(pw.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=128 * 1024 * 1024, dklen=32)
def write_enc(data, pw):
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive(pw, salt)).encrypt(nonce, json.dumps(data).encode(), AAD)
    j = {"v": 1, "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()}
    try:
        old = json.load(open(ENC))
        if "rec" in old: j["rec"] = old["rec"]         # keep the recovery wrap (same passphrase)
    except Exception: pass
    open(ENC, "w").write(json.dumps(j))
    os.chmod(ENC, 0o600)
def read_enc(pw):
    if not os.path.exists(ENC): die("multi/secrets.enc does not exist (nothing sealed)")
    j = json.load(open(ENC))
    try: return json.loads(AESGCM(derive(pw, base64.b64decode(j["salt"]))).decrypt(base64.b64decode(j["nonce"]), base64.b64decode(j["ct"]), AAD))
    except Exception: die("wrong passphrase, or secrets.enc was changed")
def cfg_values():
    txt = open(CFG).read(); out = {}
    for k in KEYS:
        ms = re.findall(r"^%s=(.*)$" % k, txt, re.M)          # the shell uses the LAST assignment, so do we
        if ms and ms[-1].strip(): out[k] = ms[-1].strip().strip("'\"")
    return txt, out
def set_cfg(txt, k, v):
    line = "%s=%s" % (k, v)
    return re.sub(r"^%s=.*$" % k, lambda _: line, txt, flags=re.M) if re.search(r"^%s=" % k, txt, re.M) else txt.rstrip("\n") + "\n" + line + "\n"
def save_cfg(txt): open(CFG, "w").write(txt); os.chmod(CFG, stat.S_IRUSR | stat.S_IWUSR)
cmd = sys.argv[1] if len(sys.argv) > 1 else ""
if cmd == "seal":
    if os.path.exists(ENC): die("already sealed (multi/secrets.enc exists). Use 'set' to change a value or 'unseal' first.")
    txt, vals = cfg_values()
    if not vals: die("no secrets found in multi/config.env")
    write_enc(vals, passphrase(confirm=True))
    for k in vals: txt = set_cfg(txt, k, "")
    save_cfg(txt); print("sealed %d values into multi/secrets.enc: %s\nconfig.env now has empty lines for them. Remember the passphrase: without it the secrets cannot be recovered." % (len(vals), ", ".join(vals)))
elif cmd == "recovery-key":
    pw = passphrase(); read_enc(pw)                                  # proves the passphrase is right
    if pw.startswith("RK-"): die("type the normal passphrase, not a recovery key")
    key = os.urandom(32); nonce = os.urandom(12)
    j = json.load(open(ENC)); j["rec"] = {"nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(AESGCM(key).encrypt(nonce, pw.encode(), AAD + b"-rec")).decode()}
    open(ENC, "w").write(json.dumps(j)); os.chmod(ENC, 0o600)
    k = base64.b32encode(key).decode().rstrip("=")
    print("RECOVERY KEY (shown once; print it, keep it away from this machine; do not photograph or paste it):\n\n    RK-" + "-".join(k[i:i + 4] for i in range(0, len(k), 4)) + "\n")
elif cmd == "env":
    if not os.path.exists(ENC): sys.exit(0)
    for k, v in read_enc(passphrase()).items(): print("export %s=%s" % (k, shlex.quote(v)))
elif cmd == "status":
    txt, plain = cfg_values(); print("sealed store:", "yes (multi/secrets.enc)" if os.path.exists(ENC) else "NO")
    print("still plain text in config.env:", ", ".join(plain) if plain else "none")
elif cmd == "set":
    if len(sys.argv) < 3 or sys.argv[2] not in KEYS: die("usage: set KEY [--random]   KEY is one of: " + ", ".join(KEYS))
    if not os.path.exists(ENC): die("not sealed yet: run 'seal' first")
    pw = passphrase(); d = read_enc(pw); k = sys.argv[2]
    d[k] = secrets.token_urlsafe(32)[:32] if "--random" in sys.argv else getpass.getpass("new value for %s: " % k)
    write_enc(d, pw); print(k + " changed in multi/secrets.enc")
elif cmd == "unseal":
    pw = passphrase(); d = read_enc(pw); txt = open(CFG).read()
    for k, v in d.items(): txt = set_cfg(txt, k, v)
    save_cfg(txt); os.remove(ENC); print("values are back in multi/config.env as plain text; multi/secrets.enc removed")
else: print(__doc__)
