import os, shutil, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SRC = "data/sample"
DST = "data/sample_copy"

def main():
    dst = sys.argv[1] if len(sys.argv) > 1 else DST
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
            data = open(p, "rb").read()
            nonce = os.urandom(16)
            enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
            with open(p, "wb") as f:
                f.write(nonce + enc.update(data) + enc.finalize())
            n += 1
    print("encrypted %d files in %s (originals untouched)" % (n, dst))

main()
