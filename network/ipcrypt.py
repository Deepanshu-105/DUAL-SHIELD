"""Privacy for what goes on the blockchain (opt-in: set CHAIN_IP_KEY on every node).

A public or shared ledger never forgets, and an IP address can be personal data. With a shared consortium key the
threat string stored on the chain is ciphertext ("enc1:..."): outsiders and chain explorers see nothing readable,
but members can decrypt. The encryption is deterministic (the same IP always gives the same string), so votes
for the same threat still add up, exactly like before. Deleting the key later makes old records unreadable
(crypto-shredding), which is the practical answer to "right to erasure" on an append-only ledger.

Without CHAIN_IP_KEY nothing changes: strings stay plain. Limits: anyone holding the key reads everything; the
deterministic form reveals which reports concern the same IP; the dashboard's browser-side tally cannot look up
encrypted IPs (it has no key, by design); keys must be shared with members out of band.
"""
import base64, hashlib, hmac, os

PREFIX = "enc1:"


def _key():
    k = os.environ.get("CHAIN_IP_KEY", "")
    return hashlib.sha256(k.encode()).digest() if k else None


def _sub(master, label):
    return hmac.new(master, label, hashlib.sha256).digest()


def enabled():
    return _key() is not None


def encode(s):
    k = _key()
    if not k or s.startswith(PREFIX):
        return s
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = hmac.new(_sub(k, b"n"), s.encode(), hashlib.sha256).digest()[:12]
    ct = AESGCM(_sub(k, b"e")).encrypt(nonce, s.encode(), b"dualshield-chain")
    return PREFIX + base64.urlsafe_b64encode(nonce + ct).decode()


def decode(s):
    """Plain strings pass through. Returns None if it is encrypted and cannot be read with our key."""
    if not s.startswith(PREFIX):
        return s
    k = _key()
    if not k:
        return None
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        raw = base64.urlsafe_b64decode(s[len(PREFIX):])
        return AESGCM(_sub(k, b"e")).decrypt(raw[:12], raw[12:], b"dualshield-chain").decode()
    except Exception:
        return None
