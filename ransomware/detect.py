import json, os, sys, time

CHI_LIMIT = 310.46      # chi-square, df=255, p=0.01
HEAD, BLOCK = 16, 4096
SIGS = {
    ".pdf": b"%PDF", ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff",
    ".png": b"\x89PNG", ".zip": b"PK\x03\x04",
    ".docx": b"PK\x03\x04", ".xlsx": b"PK\x03\x04",
}

def chi_square_bytes(block):
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    e = len(block) / 256
    return sum((o - e) ** 2 / e for o in counts)

def read_head(path):
    with open(path, "rb") as f:
        return f.read(HEAD)

def read_block(path):
    with open(path, "rb") as f:
        return f.read(BLOCK)

def matches_extension(path, head):
    sig = SIGS.get(os.path.splitext(path)[1].lower())
    return True if sig is None else head.startswith(sig)

def all_files(folder):
    for root, _, names in os.walk(folder):
        for n in names:
            p = os.path.join(root, n)
            yield p, os.path.relpath(p, folder)

def read_block_at(path, off):
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(BLOCK)


def build_baseline(folder):
    base = {}
    for p, rel in all_files(folder):
        head = read_head(p)
        size = os.path.getsize(p)
        offs = sorted({0, max(0, (size - BLOCK) // 2), max(0, size - BLOCK)})
        blocks = []
        for off in offs:
            data = read_block_at(p, off)
            if len(data) == BLOCK:
                c = chi_square_bytes(data)
                blocks.append({"off": off, "chi2": c, "nonuniform": c > CHI_LIMIT})
        first = blocks[0] if blocks and blocks[0]["off"] == 0 else None
        base[rel] = {
            "size": size,
            "header": head.hex(),
            "chi2": first["chi2"] if first else None,
            "was_nonuniform": bool(first and first["nonuniform"]),
            "blocks": blocks,
        }
    return base


def fingerprint(path):
    """(size, header, chi-square of the sampled blocks): identifies a file that was only moved or renamed."""
    size = os.path.getsize(path)
    offs = sorted({0, max(0, (size - BLOCK) // 2), max(0, size - BLOCK)})
    chis = []
    for off in offs:
        d = read_block_at(path, off)
        if len(d) == BLOCK:
            chis.append(round(chi_square_bytes(d), 3))
    return (size, read_head(path).hex(), tuple(chis))


def base_fingerprint(b):
    if not b or b.get("size", 0) == 0:
        return None
    return (b["size"], b["header"], tuple(round(x["chi2"], 3) for x in (b.get("blocks") or [])))


# v13.23 (opt-in, DS_CHECK_A_ALLOW=1): header rewrites that normal programs do, so check A does not flag them.
#   zip family / gzip: the first bytes are the same magic number (only times, sizes and CRCs in the 16-byte header changed)
#   text files: before and after the first 16 bytes are printable text (a title line was added) and the first block still has text-like entropy.
#   Random or encrypted bytes are not printable; base64-armoured ciphertext is printable but too random (> 5.75 bits per byte).
# Trade-off (measured by ransomware/check_a_allow_eval.py): an attacker who keeps the magic number and encrypts everything after it
# is then NOT flagged by check A on zip/gz (check B is blind there anyway: those files were already random).
ZIPLIKE = {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".odt", ".ods"}
TEXTLIKE = {".txt", ".log", ".md", ".csv", ".html", ".htm", ".xml", ".json", ".py", ".c", ".h", ".conf", ".cfg", ".ini", ".sh", ".js", ".css", ".rst", ".yaml", ".yml", ".svg"}

def _printable(b):
    return len(b) > 0 and sum(1 for x in b if x in (9, 10, 13) or 32 <= x < 127) >= len(b) - 1

def _entropy(b):
    import math
    if not b: return 0.0
    n = len(b); c = [0] * 256
    for x in b: c[x] += 1
    return -sum(k / n * math.log2(k / n) for k in c if k)

def benign_header_change(path, old_head_hex, head):
    if os.environ.get("DS_CHECK_A_ALLOW") != "1":
        return False
    ext = os.path.splitext(path)[1].lower()
    old = bytes.fromhex(old_head_hex) if old_head_hex else b""
    if ext in ZIPLIKE:
        return old.startswith(b"PK\x03\x04") and head.startswith(b"PK\x03\x04")
    if ext == ".gz":
        return old.startswith(b"\x1f\x8b\x08") and head.startswith(b"\x1f\x8b\x08")
    if ext in TEXTLIKE:
        # printable before and after, AND the first block still has the entropy of text (~4-5.5 bits per byte): base64 or hex 'armoured'
        # ciphertext is printable too, but base64 sits near 6 bits, so it is not let through
        return _printable(old) and _printable(head) and _entropy(read_block(path)) <= 5.75
    return False


def check_file(path, rel, base):
    """Return (None, '') if fine, else ('A' or 'B', detail)."""
    try:
        b = base.get(rel)
        if b is None or os.path.getsize(path) == 0:
            return None, ""
        head = read_head(path)
        if (head.hex() != b["header"] or not matches_extension(path, head)) and not benign_header_change(path, b["header"], head):
            return "A", "header changed: %s -> %s" % (b["header"][:16], head.hex()[:16])
        blocks = b.get("blocks")
        if blocks is None:      # old baseline format: first block only
            blocks = [{"off": 0, "chi2": b["chi2"], "nonuniform": b["was_nonuniform"]}]
        for blk in blocks:
            if blk["nonuniform"]:
                data = read_block_at(path, blk["off"])
                if len(data) == BLOCK:
                    chi2 = chi_square_bytes(data)
                    if chi2 < CHI_LIMIT:
                        return "B", "chi2 %.0f at offset %d (was %.0f): looks uniform now" % (chi2, blk["off"], blk["chi2"])
    except FileNotFoundError:
        return None, ""
    return None, ""


def is_wiped(path, b):
    """True when a file that had content was truncated to nothing or overwritten with filler (one repeated byte).
    A destroyed file is not 'encrypted' (check B) and its header may well be intact, so it needs its own test."""
    try:
        size = os.path.getsize(path)
        if b.get("size", 0) > 0 and size == 0:
            return True
        if size >= 512 and b.get("size", 0) >= 512:
            data = read_block(path)
            top = max(data.count(bytes([x])) for x in set(data)) if data else 0
            bh = bytes.fromhex(b["header"]) if b.get("header") else b""
            was_filler = len(bh) >= 8 and len(set(bh)) == 1
            if data and top / len(data) >= 0.99 and not was_filler:
                return True
    except (OSError, ValueError):
        pass
    return False


def scan(folder, base):
    flagged, total = [], 0
    for p, rel in all_files(folder):
        total += 1
        check, detail = check_file(p, rel, base)
        if check:
            flagged.append(rel)
            print("FLAGGED [check %s] %s  %s" % (check, rel, detail))
    print("scan %s: %d of %d files flagged" % (folder, len(flagged), total))
    return flagged

def watch(folder, base, kill=False):
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    rule = None
    if kill:
        from killrule import KillRule
        rule = KillRule(folder)
    class H(FileSystemEventHandler):
        def on_modified(self, ev):
            if ev.is_directory:
                return
            rel = os.path.relpath(ev.src_path, folder)
            check, detail = check_file(ev.src_path, rel, base)
            if check:
                print("%.3f FLAGGED [check %s] %s  %s" % (time.time(), check, rel, detail), flush=True)
                if rule:
                    rule.on_flag(rel)
    obs = Observer()
    obs.schedule(H(), folder, recursive=True)
    obs.start()
    print("watching", folder, "(kill rule %s)" % ("ON" if kill else "off"), "(Ctrl+C to stop)", flush=True)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()

if __name__ == "__main__":
    mode, folder = sys.argv[1], sys.argv[2]
    if mode == "baseline":
        base = build_baseline(folder)
        json.dump(base, open("baseline.json", "w"), indent=2)
        print("baseline saved for %d files" % len(base))
    else:
        base = json.load(open("baseline.json"))
        if mode == "scan":
            scan(folder, base)
        else:
            watch(folder, base, kill="--kill" in sys.argv[3:])
