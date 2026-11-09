"""Say WHICH kind of ransomware attack this looks like, from what the guard can see on the protected folders.

The type comes from BEHAVIOUR, not from a malware signature, so it also works for tools and affiliates nobody has named yet.

  crypto            files encrypted in place (header overwritten, or body encrypted with the header kept = evasive)
  wiper             files deleted, truncated to zero or overwritten with filler: data destroyed, no key can bring it back
  double_extortion  encryption/wiping/ransom note AND data theft signs (archives staged, big outbound transfer)
  exfiltration      data-theft signs without file damage (doxware before the encryption phase, or plain theft)
  note_only         a ransom/scare note appeared but nothing was damaged: locker, scareware or doxware (sub-type in `why`)

A named family (WannaCry, LockBit, ...) is only a HINT from file and note names that public reports mention; affiliates
rename them, so never rely on it. Not seen by this module: boot-record / whole-disk damage, screen lockers that touch no
file, and mobile ransomware.
"""
import os, re, sys, time

ARCHIVE_EXT = (".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst")
NOTE_NAME = re.compile(r"(read[_\- ]?me|decrypt|restore|recover|how[_\- ]?to|ransom|instruction|help[_\- ]?(me|files)|@please|_readme|-readme|your[_\- ]files)", re.I)
NOTE_WORDS = ("bitcoin", "btc", "monero", "wallet", "decrypt", "ransom", "your files", "encrypted", ".onion", "tor browser",
              "payment", "pay ", "private key", "personal id", "do not rename", "do not try")
LEAK_WORDS = ("leak", "publish", "stolen", "exfiltrat", "release your data", "expose", "sell your data", "dox")
SCARE_WORDS = ("virus detected", "your computer is infected", "call support", "call microsoft", "trojan", "security alert", "malware found")
LOCK_WORDS = ("device is locked", "your device has been locked", "screen is locked", "unlock your", "locked until")

# hints only (names from public reports; they change). (regex on file name, label)
FAMILIES = [
    (r"\.(wncry|wcry|wnry)$|@please_read_me@|@wanadecryptor@", "WannaCry-like"),
    (r"ryukreadme|\.ryk$|ryuk", "Ryuk-like"),
    (r"restore-my-files|\.lockbit$|lockbit", "LockBit-like"),
    (r"\.conti$|conti", "Conti-like"),
    (r"-readme\.txt$|\.sodinokibi$|revil", "REvil-like"),
    (r"decrypt-files\.txt$|\.maze$|maze", "Maze-like"),
    (r"darkside|readme\.[a-z0-9]{8,}\.txt$", "DarkSide-like"),
]

RESPONSE = {
    "crypto": "Kill the encrypting process, block egress, freeze the vault, restore the files from the last clean vault revision (verified).",
    "wiper": "Kill the process and freeze the vault. Deleted/zeroed files are restored from the vault; there is no key to buy, so only backups help.",
    "double_extortion": "Restore the files from the vault, BUT the stolen copy cannot be recalled: treat the data as leaked, rotate credentials and tell the data owner.",
    "exfiltration": "Block egress now (containment), find what left, rotate credentials; no file restore is needed unless files were also damaged.",
    "note_only": "No files were damaged: nothing to restore. Contain, find the process that dropped the note, and treat the machine as compromised.",
}


def _family(names):
    for n in names:
        base = os.path.basename(n).lower()
        for rx, label in FAMILIES:
            if re.search(rx, base):
                return label
    return None


def _norm(s):
    return s.lower().replace("\x00", "")


def read_note(path, limit=4096):
    try:
        with open(path, "rb") as f:
            raw = f.read(limit)
        if raw.count(b"\x00") > len(raw) // 20 and raw[:2] not in (b"\xff\xfe", b"\xfe\xff"):
            return None
        return _norm(raw.decode("utf-8", "ignore"))
    except OSError:
        return None


def gather(roots, bases, max_new=300):
    """Compare live folders with the last committed state. roots: [{name,path}], bases: name -> detect baseline.
    Returns the evidence dict that verdict() reads."""
    import detect
    ev = {"enc": {}, "wiped": [], "deleted": [], "notes": [], "archives": [], "renamed": [], "total": 0}
    for r in roots:
        name, folder = r["name"], r["path"]
        base = bases.get(name, {})
        if not os.path.isdir(folder):
            continue
        live = {}
        for p, rel in detect.all_files(folder):
            if os.path.basename(rel).startswith(".~ds_"):
                continue
            live[rel] = p
        ev["total"] += len(base)
        for rel, p in live.items():
            b = base.get(rel)
            if b is None:
                continue
            if detect.is_wiped(p, b):                 # zeroed/truncated also changes the header: decide this first
                ev["wiped"].append("%s/%s" % (name, rel))
                continue
            chk, _ = detect.check_file(p, rel, base)
            if chk:
                ev["enc"]["%s/%s" % (name, rel)] = chk
        gone = [rel for rel in base if rel not in live and not os.path.basename(rel).startswith(".~ds_")]
        ev["deleted"] += ["%s/%s" % (name, g) for g in gone]
        new = [(rel, p) for rel, p in live.items() if rel not in base][:max_new]
        gone_set = set(gone)
        for rel, p in new:
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            low = rel.lower()
            if low.endswith(ARCHIVE_EXT):
                ev["archives"].append({"file": "%s/%s" % (name, rel), "size": size})
            for old in gone_set:                      # a.txt gone, a.txt.locked / a.xyz appeared = renamed by the attacker
                if rel != old and (rel.startswith(old + ".") or (os.path.splitext(rel)[0] == os.path.splitext(old)[0] and os.path.dirname(rel) == os.path.dirname(old))):
                    ev["renamed"].append((old, rel))
                    break
            if size <= 65536:
                txt = read_note(p)
                hit = 0 if txt is None else sum(w in txt for w in NOTE_WORDS)
                leak = 0 if txt is None else sum(w in txt for w in LEAK_WORDS)
                scare = 0 if txt is None else sum(w in txt for w in SCARE_WORDS)
                lock = 0 if txt is None else sum(w in txt for w in LOCK_WORDS)
                by_name = bool(NOTE_NAME.search(os.path.basename(rel)))
                # ordinary "README / how to" files must not match: a note needs several demand words, or a scare/lock/leak message with company
                ok = txt is not None and ((by_name and hit >= 2) or hit >= 3 or (scare >= 1 and (scare >= 2 or by_name or hit)) or
                                          (lock >= 1 and (by_name or hit)) or (leak >= 2 and hit >= 1))
                if ok:
                    ev["notes"].append({"file": "%s/%s" % (name, rel), "pay": hit, "leak": leak, "scare": scare, "lock": lock})
    return ev


def _ext_of_renames(renamed):
    c = {}
    for old, new in renamed:
        ext = new[len(old):] if new.startswith(old) else os.path.splitext(new)[1]
        c[ext] = c.get(ext, 0) + 1
    if not c:
        return None
    ext, n = max(c.items(), key=lambda kv: kv[1])
    return ext if n >= 2 and ext else None


def verdict(ev, exfil=None, min_files=3, delete_min=10, now=None):
    """ev from gather(); exfil: None or {"t": ..., "rate_mbps": ..., "why": ...} from ExfilWatch (recent). -> dict"""
    now = now or time.time()
    enc, wiped, deleted = ev.get("enc", {}), ev.get("wiped", []), ev.get("deleted", [])
    notes, arch, ren = ev.get("notes", []), ev.get("archives", []), ev.get("renamed", [])
    total = ev.get("total", 0)
    mass_delete = len(deleted) >= max(delete_min, -(-total // 4) if total else delete_min)
    destroyed = len(wiped) + (len(deleted) if mass_delete else 0)
    ext = _ext_of_renames(ren)
    types, mode = [], None
    # a ransomware that encrypts into a NEW file and deletes the original looks like deleted + renamed + note, not enc flags
    enc_by_copy = len(ren) >= min_files and len(deleted) >= min_files and ext is not None
    pay_note = any(n["pay"] >= 2 for n in notes)
    if len(enc) >= min_files or enc_by_copy:
        n = max(len(enc), len(ren))
        a = sum(1 for c in enc.values() if c == "A")
        mode = ("header overwritten" if a else "body encrypted, header kept (evasive)") if enc else "encrypted copy written, original deleted"
        why = ["%d files look encrypted (%s)" % (n, mode)]
        conf = "medium"
        if ext:
            why.append("%d files renamed to the same new extension %s" % (len(ren), ext)); conf = "high"
        if pay_note:
            why.append("ransom note present"); conf = "high"
        if n >= 5:
            conf = "high"
        types.append({"type": "crypto", "confidence": conf, "why": why})
    if destroyed >= min_files and not (types and types[0]["type"] == "crypto" and len(deleted) and not wiped and enc_by_copy):
        why = ["%d files destroyed (%d zeroed/truncated/overwritten, %d deleted)" % (destroyed, len(wiped), len(deleted) if mass_delete else 0)]
        conf = "high" if destroyed >= 5 else "medium"
        if pay_note:
            why.append("a ransom note is present but the files were destroyed, not encrypted: wiper posing as ransomware, or a key that does not exist")
        elif not notes:
            why.append("no ransom note: destruction without a demand")
        types.append({"type": "wiper", "confidence": conf, "why": why})
    staged = [a for a in arch if a["size"] >= 1024]
    theft = []
    if exfil:
        theft.append("outbound transfer %.1f MB/s (%s)" % (exfil.get("rate_mbps", 0), exfil.get("why", "above baseline")))
    if len(staged) >= 1 and (types or notes or exfil):
        theft.append("%d archive(s) created inside the protected folders (staging before upload)" % len(staged))
    damaged = bool(types)
    if theft and (damaged or notes):
        types.insert(0, {"type": "double_extortion", "confidence": "high" if exfil and (staged or damaged) else "medium",
                         "why": theft + ["combined with damage/ransom note: data stolen AND held hostage"]})
    elif exfil and (staged or exfil.get("rate_mbps", 0) > 0):
        types.append({"type": "exfiltration", "confidence": "high" if staged else "medium", "why": theft or ["outbound transfer above baseline"]})
    if notes and not damaged:
        n0 = notes[0]
        if any(n["leak"] >= 2 for n in notes):
            sub = "doxware / leakware (threatens to publish data)"
        elif any(n["scare"] for n in notes) and not any(n["pay"] >= 2 for n in notes):
            sub = "scareware (fake infection warning)"
        elif any(n["lock"] for n in notes):
            sub = "locker (device/screen lock message; the screen itself is not visible to Dual-Shield)"
        else:
            sub = "ransom note with no file damage yet (early stage, or locker)"
        types.append({"type": "note_only", "confidence": "medium" if n0["pay"] + n0["leak"] + n0["scare"] + n0["lock"] >= 2 else "low",
                      "why": ["%d note file(s), e.g. %s" % (len(notes), n0["file"]), sub]})
    order = {"double_extortion": 0, "crypto": 1, "wiper": 2, "exfiltration": 3, "note_only": 4}
    types.sort(key=lambda t: order[t["type"]])
    fam = _family([n["file"] for n in notes] + list(enc) + [new for _, new in ren])
    out = {"t": now, "types": types, "primary": types[0]["type"] if types else None, "mode": mode, "extension": ext,
           "family_hint": fam, "family_note": "hint from file/note names only; affiliates rename them" if fam else None,
           "counts": {"encrypted": len(enc), "wiped": len(wiped), "deleted": len(deleted), "renamed": len(ren),
                      "notes": len(notes), "archives": len(arch), "of_files": total},
           "notes": [n["file"] for n in notes][:10], "response": [RESPONSE[t["type"]] for t in types]}
    return out


class ExfilWatch:
    """Watches outbound bytes. feed(t, tx_total_bytes) -> None or {"rate_mbps","why"} once the rate has stayed far above its
    own recent normal for `sustain` seconds AND above `min_mbps`. Floor values keep a backup job or an update from alarming
    unless it is also unusual for this machine."""
    def __init__(self, min_mbps=2.0, factor=8.0, sustain=3.0, alpha=0.05):
        self.min_mbps, self.factor, self.sustain, self.alpha = min_mbps, factor, sustain, alpha
        self.last = None
        self.ewma = None
        self.hot_since = None
        self.n = 0

    def feed(self, t, tx_total):
        if self.last is None:
            self.last = (t, tx_total)
            return None
        t0, b0 = self.last
        self.last = (t, tx_total)
        dt = t - t0
        if dt <= 0 or tx_total < b0:
            return None
        rate = (tx_total - b0) / dt / 1e6                   # MB/s
        self.n += 1
        base = self.ewma if self.ewma is not None else rate
        hot = rate >= self.min_mbps and rate >= self.factor * max(base, 0.02) and self.n > 5
        if not hot:                                         # only learn "normal" from quiet samples
            self.ewma = rate if self.ewma is None else (1 - self.alpha) * self.ewma + self.alpha * rate
            self.hot_since = None
            return None
        self.hot_since = self.hot_since or t
        if t - self.hot_since >= self.sustain:
            return {"t": t, "rate_mbps": round(rate, 2), "why": "%.0fx its recent normal of %.2f MB/s" % (rate / max(base, 0.02), base)}
        return None


def tx_total():
    """Bytes sent on all non-loopback interfaces (Linux /proc/net/dev, or psutil on Windows). None if unreadable."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "multi"))
    import shield_os
    return shield_os.tx_bytes()
