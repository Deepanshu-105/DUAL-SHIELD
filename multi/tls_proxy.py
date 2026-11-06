#!/usr/bin/env python3
"""TLS tunnel for services that do not speak TLS themselves (the chain's JSON-RPC, the dashboard). Stdlib only.

  # on D: terminate mutual TLS in front of the chain and the dashboard
  tls_proxy.py server --listen 0.0.0.0:8546 --to 127.0.0.1:8545 --allow dualshield-target,dualshield-peer
  tls_proxy.py server --listen 0.0.0.0:3443 --to 127.0.0.1:3000 --no-client-cert      # operators use a browser: password login over TLS
  # on T and P: a local door that carries plain RPC over mutual TLS to D
  tls_proxy.py client --listen 127.0.0.1:8545 --to D_IP:8546 --expect dualshield-dashboard

So web3 code keeps using http://127.0.0.1:8545, but nothing readable crosses the network. The server side checks the
caller's certificate (private CA, role name); the client side checks that D's certificate is ours and has the dashboard role.
Note: the target service sees the proxy as its caller (127.0.0.1), so anything that relies on the caller's source address
(the registry) must speak TLS itself instead of using this tunnel.
"""
import argparse, os, socket, ssl, sys, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tlsutil


def hostport(s):
    h, _, p = s.rpartition(":")
    return h or "127.0.0.1", int(p)


def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(conn, mode, to, ctx, allow, expect):
    up = None
    try:
        if mode == "server":
            conn.settimeout(10)
            conn.do_handshake()
            if allow and tlsutil.peer_cn(conn) not in allow:
                return conn.close()
            conn.settimeout(None)
            up = socket.create_connection(to, timeout=10)
        else:
            raw = socket.create_connection(to, timeout=10)
            up = ctx.wrap_socket(raw, server_hostname=None)
            if expect and tlsutil.peer_cn(up) != expect:
                up.close()
                return conn.close()
        up.settimeout(None)
        t = threading.Thread(target=pipe, args=(up, conn), daemon=True)
        t.start()
        pipe(conn, up)
        t.join(2)
    except (OSError, ssl.SSLError):
        pass
    finally:
        for s in (conn, up):
            try:
                if s:
                    s.close()
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["server", "client"])
    ap.add_argument("--listen", required=True)
    ap.add_argument("--to", required=True)
    ap.add_argument("--allow", default="", help="server: comma list of certificate names allowed to connect")
    ap.add_argument("--expect", default="", help="client: certificate name the far side must have")
    ap.add_argument("--no-client-cert", action="store_true", help="server: do not require client certificates (browsers)")
    ap.add_argument("--tls-dir", default=None)
    a = ap.parse_args()
    lh, lp = hostport(a.listen)
    to = hostport(a.to)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((lh, lp))
    ls.listen(64)
    ctx = None
    if a.mode == "server":
        ctx = tlsutil.server_context(a.tls_dir, require_client=not a.no_client_cert)
        ls = ctx.wrap_socket(ls, server_side=True, do_handshake_on_connect=False)
    else:
        ctx = tlsutil.client_context(a.tls_dir)
    allow = {x for x in a.allow.split(",") if x}
    print("TLS_PROXY %s %s:%d -> %s:%d" % (a.mode, lh, lp, to[0], to[1]), flush=True)
    while True:
        try:
            c, _ = ls.accept()
        except OSError:
            continue
        threading.Thread(target=handle, args=(c, a.mode, to, ctx, allow, a.expect), daemon=True).start()


if __name__ == "__main__":
    main()
