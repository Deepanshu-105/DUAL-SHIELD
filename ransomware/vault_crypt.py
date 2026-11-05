"""Encryption at rest for the vault (git clean/smudge filter, AES-256-GCM).

The vault repo keeps plain files in its working folder (so the guard can compare quickly) but every FILE STORED IN
GIT, and therefore everything pushed off the machine, is encrypted. A stolen vault or a compromised remote shows
only ciphertext. Nonces are derived from key + path + content (deterministic), so an unchanged file produces the
same blob and git still deduplicates. File NAMES and sizes stay visible (limit).

Key: 32 random bytes in a key file (default data/vault.key, or VAULT_KEY_FILE), mode 0600, NEVER inside the vault
and never pushed. Back it up somewhere else: without it the vault cannot be read.

  python3 vault.py encrypt-on        # creates the key if missing, installs the filter
  (git calls)  vault_crypt.py clean <path>  /  smudge <path>
"""
import hashlib, hmac, os, sys

MAGIC = b"DSV1"
DEFAULT_KEY = "data/vault.key"


def key_path():
    return os.environ.get("VAULT_KEY_FILE", DEFAULT_KEY)


def load_key(path=None):
    p = path or key_path()
    if not os.path.exists(p):
        raise SystemExit("VAULT_KEY_MISSING %s (restore your key backup, or run: python3 vault.py encrypt-on)" % p)
    k = bytes.fromhex(open(p).read().strip())
    if len(k) != 32:
        raise SystemExit("VAULT_KEY_BAD must be 32 bytes in hex")
    return k


def make_key(path=None):
    p = path or key_path()
    if os.path.exists(p):
        return p
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(os.urandom(32).hex() + "\n")
    return p


def _sub(master, label):
    return hmac.new(master, label, hashlib.sha256).digest()


def encrypt(master, path, data):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = hmac.new(_sub(master, b"nonce"), path.encode() + b"\0" + data, hashlib.sha256).digest()[:12]
    return MAGIC + nonce + AESGCM(_sub(master, b"enc")).encrypt(nonce, data, path.encode())


def decrypt(master, path, blob):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not blob.startswith(MAGIC):
        return blob                                  # file stored before encryption was switched on
    nonce, ct = blob[4:16], blob[16:]
    return AESGCM(_sub(master, b"enc")).decrypt(nonce, ct, path.encode())


def decrypt_tree(folder, master, prefix=""):
    """Decrypt every encrypted file under `folder` in place. `prefix` = path the files had inside the repo."""
    n = 0
    for r, _, fs in os.walk(folder):
        for f in fs:
            p = os.path.join(r, f)
            blob = open(p, "rb").read()
            if blob.startswith(MAGIC):
                rel = prefix + os.path.relpath(p, folder).replace(os.sep, "/")
                open(p, "wb").write(decrypt(master, rel, blob))
                n += 1
    return n


if __name__ == "__main__":
    mode, path = sys.argv[1], sys.argv[2]
    data = sys.stdin.buffer.read()
    key = load_key()
    sys.stdout.buffer.write(encrypt(key, path, data) if mode == "clean" else decrypt(key, path, data))
