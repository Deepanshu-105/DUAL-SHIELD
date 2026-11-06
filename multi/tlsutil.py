"""Mutual TLS helpers for Dual-Shield (stdlib only).

Every laptop holds a certificate issued by the private CA (multi/make_tls.sh). Both sides must present one:
  - the server only talks to clients whose certificate was signed by our CA;
  - the client only talks to a server whose certificate was signed by our CA AND whose CN is the role it expects
    (hostname checking is replaced by that role check, so discovery with changing IPs still works and one node
    cannot impersonate another role).
The HMAC signatures on every request stay on top of TLS (two independent layers).

Environment: TLS=1 turns it on; TLS_DIR points to the folder with ca.crt, node.crt, node.key
(default multi/tls/node on T and P, multi/tls/dashboard on D). TLS_MIN=1.2 or 1.3 (default 1.2).
"""
import http.client, json, os, ssl

HERE = os.path.dirname(os.path.abspath(__file__))


def enabled():
    return os.environ.get("TLS", "0") == "1"


def tls_dir():
    d = os.environ.get("TLS_DIR")
    if d:
        return d
    for sub in ("node", "dashboard"):
        p = os.path.join(HERE, "tls", sub)
        if os.path.exists(os.path.join(p, "node.crt")):
            return p
    return os.path.join(HERE, "tls", "node")


def _files(d=None):
    d = d or tls_dir()
    return os.path.join(d, "ca.crt"), os.path.join(d, "node.crt"), os.path.join(d, "node.key")


def _version():
    return ssl.TLSVersion.TLSv1_3 if os.environ.get("TLS_MIN") == "1.3" else ssl.TLSVersion.TLSv1_2


def server_context(d=None, require_client=True):
    ca, crt, key = _files(d)
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = _version()
    c.load_cert_chain(crt, key)
    if require_client:
        c.load_verify_locations(ca)
        c.verify_mode = ssl.CERT_REQUIRED
    return c


def client_context(d=None, with_cert=True):
    ca, crt, key = _files(d)
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version = _version()
    c.load_verify_locations(ca)
    c.check_hostname = False            # replaced by the role (CN) check below
    c.verify_mode = ssl.CERT_REQUIRED
    if with_cert:
        c.load_cert_chain(crt, key)
    return c


def cn_of(cert):
    for rdn in (cert or {}).get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                return v
    return ""


def peer_cn(sock):
    try:
        return cn_of(sock.getpeercert())
    except (AttributeError, ValueError):
        return ""


def accept_handshake(conn, allowed_cns):
    """Server side, inside the handler thread (so a slow client cannot block the accept loop).
    Returns the client's CN, or None after closing the connection when the handshake or the role is not acceptable."""
    try:
        conn.do_handshake()
    except (ssl.SSLError, OSError):
        return None
    cn = peer_cn(conn)
    if allowed_cns and cn not in allowed_cns:
        return None
    return cn


def request(base, method, path, headers=None, body=None, expect_cn=None, timeout=5, ctx=None):
    """-> (status, raw bytes, headers). http:// works as before; https:// uses mutual TLS and checks the server's role."""
    scheme, rest = base.split("://", 1)
    host, _, port = rest.partition(":")
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, int(port or 443), timeout=timeout, context=ctx or client_context())
    else:
        conn = http.client.HTTPConnection(host, int(port or 80), timeout=timeout)
    try:
        conn.connect()
        if scheme == "https" and expect_cn and peer_cn(conn.sock) != expect_cn:
            raise ssl.SSLError("server certificate is for %r, expected %r" % (peer_cn(conn.sock), expect_cn))
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        return r.status, r.read(), r.headers
    finally:
        conn.close()
