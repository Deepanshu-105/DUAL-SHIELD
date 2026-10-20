"""Rollback skeleton.

The Phase 1 baseline (baseline.json / recovery/baseline_snapshot.json) only holds
header bytes and chi-square values: enough to DETECT encryption, not to UNDO it.
This module adds the missing half: a content snapshot plus a SHA-256 manifest.

    python3 rollback.py snapshot data/sample       # BEFORE the attack
    python3 rollback.py restore  data/sample_copy  # after the kill
    python3 rollback.py verify   data/sample_copy  # prints ROLLBACK_OK / ROLLBACK_FAIL

mock_crypto.py refreshes sample_copy from data/sample before encrypting, so the
pre-attack state of the protected copy is exactly data/sample.
"""
import hashlib, json, os, shutil, sys, time

STORE = "data/snapshot"                    # copy of the files (gitignored under data/)
MANIFEST = "data/snapshot_manifest.json"   # {relative path: sha256}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_folder(folder):
    out = {}
    for root, _, names in os.walk(folder):
        for n in names:
            p = os.path.join(root, n)
            out[os.path.relpath(p, folder)] = sha256(p)
    return out


def take_snapshot(folder, store=STORE, manifest=MANIFEST):
    if os.path.exists(store):
        shutil.rmtree(store)
    shutil.copytree(folder, store)
    m = hash_folder(store)                 # hash the stored copy, i.e. what we can restore
    with open(manifest, "w") as f:
        json.dump({"taken_at": time.time(), "files": m}, f, indent=1)
    print("SNAPSHOT %d files -> %s, manifest %s" % (len(m), store, manifest))
    return m


def restore(target, store=STORE):
    t0 = time.perf_counter()
    removed = copied = 0
    os.makedirs(target, exist_ok=True)
    # 1. delete anything the attacker added (encrypted copies, ransom notes ...)
    for root, dirs, names in os.walk(target, topdown=False):
        for n in names:
            p = os.path.join(root, n)
            if not os.path.exists(os.path.join(store, os.path.relpath(p, target))):
                os.remove(p); removed += 1
        for d in dirs:
            p = os.path.join(root, d)
            if not os.path.exists(os.path.join(store, os.path.relpath(p, target))):
                shutil.rmtree(p, ignore_errors=True)
    # 2. put every snapshot file back (overwrite in place; folder itself is kept,
    #    so a running watcher keeps tracking it)
    for root, _, names in os.walk(store):
        out = os.path.normpath(os.path.join(target, os.path.relpath(root, store)))
        os.makedirs(out, exist_ok=True)
        for n in names:
            shutil.copyfile(os.path.join(root, n), os.path.join(out, n)); copied += 1
    ms = (time.perf_counter() - t0) * 1000
    print("RESTORED %d files, removed %d extra, %.0f ms" % (copied, removed, ms))
    return ms


def verify(target, manifest=MANIFEST):
    want = json.load(open(manifest))["files"]
    got = hash_folder(target)
    bad = sorted(k for k in want if got.get(k) != want[k])
    extra = sorted(k for k in got if k not in want)
    ok = not bad and not extra
    if ok:
        print("ROLLBACK_OK %d of %d file hashes match the pre-attack snapshot" % (len(want), len(want)))
    else:
        print("ROLLBACK_FAIL %d of %d hashes differ, %d unexpected files: %s %s"
              % (len(bad), len(want), len(extra), bad[:5], extra[:5]))
    return ok, len(bad)


if __name__ == "__main__":
    cmd, folder = sys.argv[1], sys.argv[2]
    if cmd == "snapshot":
        take_snapshot(folder)
    elif cmd == "restore":
        restore(folder)
        sys.exit(0 if verify(folder)[0] else 1)
    elif cmd == "verify":
        sys.exit(0 if verify(folder)[0] else 1)
    else:
        sys.exit("usage: rollback.py snapshot|restore|verify FOLDER")
