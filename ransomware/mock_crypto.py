import argparse, os, shutil, sys, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SRC = "data/sample"
DST = "data/sample_copy"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dst", nargs="?", default=DST)
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds to pause per file while its handle is still open "
                         "(slows the attack so the kill rule can be tested)")
    args = ap.parse_args()
    dst, delay = args.dst, args.delay
    if os.path.abspath(dst) == os.path.abspath(SRC):
        sys.exit("Refusing to encrypt the originals.")
    if not os.path.basename(dst.rstrip("/")).endswith("copy"):
        sys.exit("Target folder name must end with 'copy'.")

    # Refresh the copy IN PLACE: never delete the folder itself,
    # so a running watcher keeps tracking it.
    os.makedirs(dst, exist_ok=True)
    for root, dirs, names in os.walk(SRC):
        rel = os.path.relpath(root, SRC)
        out = os.path.normpath(os.path.join(dst, rel))
        os.makedirs(out, exist_ok=True)
        for name in names:
            shutil.copyfile(os.path.join(root, name), os.path.join(out, name))

    key = os.urandom(32)
    n = 0
    for root, _, names in os.walk(dst):
        for name in names:
            p = os.path.join(root, name)
            with open(p, "rb") as f:
                data = f.read()
            nonce = os.urandom(16)
            enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
            with open(p, "wb") as f:
                f.write(nonce + enc.update(data) + enc.finalize())
                f.flush()
                if delay:
                    time.sleep(delay)   # handle still open, like a real encryptor
            n += 1
    print("encrypted %d files in %s (originals untouched)" % (n, dst))

if __name__ == "__main__":
    main()
