"""One-command, verified recovery from the vault (no ransom, no decryptor).

    python3 recover.py sample data/sample_copy --in-place          # replace the encrypted folder
    python3 recover.py sample data/sample_copy                     # restore to data/recovered_<time>/ only
    python3 recover.py sample data/sample_copy --anchor 172.30.0.12 --in-place   # also check the chain

What it does, in order:
  1. walks the vault history newest -> oldest and takes the first commit whose Merkle roots
     verify against its own manifest (a tampered or corrupt commit is skipped, and said so);
  2. restores that commit into a NEW folder and verifies it again (file hashes, Merkle root);
  3. optional --anchor IP: compares the Merkle root with the one anchored on the blockchain;
  4. --in-place: moves the encrypted folder aside to <folder>.encrypted-<time> (kept as evidence)
     and puts the restored folder in its place; the vault stays frozen until you unfreeze it;
  5. writes evidence/recovery_report.json (the dashboard shows it).
Exit 0 on success, 1 if no verified snapshot exists, 2 if the chain check fails.
"""
import argparse, json, os, shutil, subprocess, sys, time

import snapshot, vault


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="root name in protect.json (e.g. sample)")
    ap.add_argument("folder", help="the protected folder to recover")
    ap.add_argument("--in-place", action="store_true")
    ap.add_argument("--anchor", metavar="IP")
    ap.add_argument("--max-back", type=int, default=50)
    a = ap.parse_args()
    t0 = time.perf_counter()
    report = {"t": time.time(), "root": a.root, "folder": a.folder, "skipped": [], "ok": False}

    rev = None
    for r in vault.revs(a.max_back):
        ok, why = vault.verify(r, a.root, quiet=True)
        if ok:
            rev = r
            break
        report["skipped"].append({"rev": r[:7], "why": why})
        print("RECOVER_SKIP rev=%s (%s)" % (r[:7], why), flush=True)
    if not rev:
        print("RECOVER_FAIL no verified snapshot in the last %d commits" % a.max_back)
        _save(report, t0)
        return 1

    stamp = time.strftime("%Y%m%d_%H%M%S")
    out = os.path.join("data", "recovered_" + stamp)
    if not vault.restore(out, rev, a.root):
        _save(report, t0)
        return 1
    got = snapshot.snapshot(out)
    manifest = json.loads(subprocess.run(["git", "show", "%s:.manifest.json" % rev], cwd=vault.VAULT,
                                         capture_output=True, text=True).stdout)["roots"][a.root]
    if got["root"] != manifest["merkle"]:
        print("RECOVER_FAIL restored folder does not match the manifest")
        _save(report, t0)
        return 1
    report.update(rev=rev[:7], files=got["files"], merkle=got["root"], verified_manifest=True)

    if a.anchor:
        va = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "blockchain", "scripts", "verify_anchor.py")
        py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "blockchain", ".venv", "bin", "python3")
        r = subprocess.run([py if os.path.exists(py) else sys.executable, va, a.anchor, out],
                           capture_output=True, text=True)
        print(r.stdout.strip())
        report["anchor"] = "MATCH" if r.returncode == 0 else ("MISSING" if r.returncode == 2 else "TAMPERED")
        if r.returncode != 0:
            print("RECOVER_REFUSED chain check failed (%s); restored copy left in %s" % (report["anchor"], out))
            _save(report, t0)
            return 2

    if a.in_place:
        if os.path.isdir(a.folder):
            aside = a.folder.rstrip("/") + ".encrypted-" + stamp
            os.rename(a.folder, aside)
            report["encrypted_kept_at"] = aside
        os.rename(out, a.folder)
        report["location"] = a.folder
    else:
        report["location"] = out
    report["ok"] = True
    ms = _save(report, t0)
    print("RECOVER_OK rev=%s files=%d verified=manifest%s -> %s (%.0f ms)" % (
        rev[:7], got["files"], "+chain" if a.anchor else "", report["location"], ms))
    if vault.is_frozen():
        print("Vault is still frozen. When the machine is clean: python3 vault.py unfreeze")
    return 0


def _save(report, t0):
    report["ms"] = int((time.perf_counter() - t0) * 1000)
    os.makedirs("evidence", exist_ok=True)
    with open("evidence/recovery_report.json", "w") as f:
        json.dump(report, f, indent=2)
    return report["ms"]


if __name__ == "__main__":
    sys.exit(main())
