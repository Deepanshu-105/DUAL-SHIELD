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
            "header": head.hex(),
            "chi2": first["chi2"] if first else None,
            "was_nonuniform": bool(first and first["nonuniform"]),
            "blocks": blocks,
        }
    return base


def check_file(path, rel, base):
    """Return (None, '') if fine, else ('A' or 'B', detail)."""
    try:
        b = base.get(rel)
        if b is None or os.path.getsize(path) == 0:
            return None, ""
        head = read_head(path)
        if head.hex() != b["header"] or not matches_extension(path, head):
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
