#!/usr/bin/env python3
"""HASSH: fingerprint an SSH *client* from its SSH_MSG_KEXINIT packet.

Every SSH client opens with a KEXINIT packet listing the algorithms it supports.
The lists differ between clients (OpenSSH, libssh used by Hydra, PuTTY, ...), so
an MD5 of four of them identifies the client software, whatever IP it comes from.

    HASSH = md5( kex_algorithms ; encryption_c2s ; mac_c2s ; compression_c2s )

This is the SSH equivalent of the JA3 fingerprint for TLS.

Run `python3 hassh.py --selftest` to check the code without any network.
"""
import hashlib
import socket
import struct
import sys

SSH_MSG_KEXINIT = 20
ETH_P_ALL = 0x0003


# ---------------------------------------------------------------- parsing
def _name_list(buf, off):
    """Read one SSH name-list (uint32 length + comma separated text)."""
    (n,) = struct.unpack_from(">I", buf, off)
    off += 4
    if off + n > len(buf):
        raise struct.error("name-list runs past the end of the packet")
    return buf[off:off + n].decode("ascii", "replace"), off + n


def hassh_from_stream(data):
    """Return (hassh, algorithm_string), or None if `data` is not yet a full KEXINIT.

    `data` is the client's TCP byte stream: an optional 'SSH-2.0-...' banner line,
    then the first SSH binary packet (the KEXINIT).
    """
    if data.startswith(b"SSH-"):
        end = data.find(b"\n")
        if end == -1:
            return None  # banner not complete yet
        data = data[end + 1:]
    if len(data) < 22:
        return None
    (packet_len,) = struct.unpack_from(">I", data, 0)
    if packet_len > 35000 or data[5] != SSH_MSG_KEXINIT:
        return None
    if len(data) < 4 + packet_len:
        return None  # packet still arriving
    try:
        off = 22  # 4 length + 1 padding length + 1 msg type + 16 cookie
        kex, off = _name_list(data, off)
        _hostkey, off = _name_list(data, off)
        enc_c2s, off = _name_list(data, off)
        _enc_s2c, off = _name_list(data, off)
        mac_c2s, off = _name_list(data, off)
        _mac_s2c, off = _name_list(data, off)
        comp_c2s, off = _name_list(data, off)
    except struct.error:
        return None
    algs = ";".join((kex, enc_c2s, mac_c2s, comp_c2s))
    return hashlib.md5(algs.encode()).hexdigest(), algs


class FlowTable:
    """Collects the first bytes of each client connection until its KEXINIT is complete."""

    def __init__(self, max_flows=5000):
        self.buf = {}
        self.max_flows = max_flows

    def feed(self, key, payload):
        state = self.buf.get(key, b"")
        if state is None:  # this connection was already fingerprinted
            return None
        data = state + payload
        result = hassh_from_stream(data)
        if result:
            self.buf[key] = None
            return result
        if len(data) > 8192:  # not an SSH client hello; stop collecting
            self.buf[key] = None
            return None
        if len(self.buf) >= self.max_flows:
            self.buf.clear()
        self.buf[key] = data
        return None


def parse_frame(frame):
    """Ethernet + IPv4 + TCP -> (src_ip, src_port, dst_port, payload), else None."""
    if len(frame) < 14 + 20 + 20:
        return None
    if struct.unpack_from("!H", frame, 12)[0] != 0x0800:  # IPv4 only
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 6 or len(ip) < ihl + 20:  # TCP only
        return None
    total_len = struct.unpack_from("!H", ip, 2)[0]
    src = socket.inet_ntoa(ip[12:16])
    tcp = ip[ihl:]
    sport, dport = struct.unpack_from("!HH", tcp, 0)
    data_off = (tcp[12] >> 4) * 4
    payload = ip[ihl + data_off:total_len]  # total_len drops Ethernet padding
    return src, sport, dport, payload


# ---------------------------------------------------------------- capture
def sniff(callback, port=22, iface=None):
    """Watch packets going TO `port`; call callback(src_ip, hassh, algorithms) once per connection.

    Needs root (CAP_NET_RAW), which a Docker container has by default.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    if iface:
        sock.bind((iface, 0))
    flows = FlowTable()
    while True:
        frame, addr = sock.recvfrom(65535)
        if addr[2] == socket.PACKET_OUTGOING:  # only packets arriving at this host
            continue
        pkt = parse_frame(frame)
        if not pkt:
            continue
        src, sport, dport, payload = pkt
        if dport != port or not payload:
            continue
        result = flows.feed((src, sport), payload)
        if result:
            callback(src, result[0], result[1])


# ---------------------------------------------------------------- self test
def _build_kexinit(lists):
    body = bytes([SSH_MSG_KEXINIT]) + bytes(16)  # type + zero cookie
    for item in lists:
        body += struct.pack(">I", len(item)) + item.encode()
    body += b"\x00" + struct.pack(">I", 0)  # first_kex_packet_follows + reserved
    pad = 8 - ((5 + len(body)) % 8)
    if pad < 4:
        pad += 8
    return struct.pack(">IB", 1 + len(body) + pad, pad) + body + bytes(pad)


def _selftest():
    lists = [
        "curve25519-sha256,diffie-hellman-group14-sha256",  # kex
        "ssh-ed25519",                                      # host key
        "chacha20-poly1305@openssh.com,aes128-ctr",         # enc c2s
        "aes128-ctr",                                       # enc s2c
        "hmac-sha2-256",                                    # mac c2s
        "hmac-sha2-256",                                    # mac s2c
        "none,zlib@openssh.com",                            # comp c2s
        "none",                                             # comp s2c
        "", "",                                             # languages
    ]
    wire = b"SSH-2.0-TestClient_1.0\r\n" + _build_kexinit(lists)
    want_str = ("curve25519-sha256,diffie-hellman-group14-sha256;"
                "chacha20-poly1305@openssh.com,aes128-ctr;hmac-sha2-256;none,zlib@openssh.com")
    want = hashlib.md5(want_str.encode()).hexdigest()

    got = hassh_from_stream(wire)
    assert got == (want, want_str), f"parse failed: {got}"

    flows = FlowTable()  # same bytes, split into awkward pieces
    cut1, cut2 = 10, 40
    assert flows.feed(("1.2.3.4", 5000), wire[:cut1]) is None
    assert flows.feed(("1.2.3.4", 5000), wire[cut1:cut2]) is None
    assert flows.feed(("1.2.3.4", 5000), wire[cut2:]) == (want, want_str)
    assert flows.feed(("1.2.3.4", 5000), b"more") is None  # reported only once

    assert hassh_from_stream(b"GET / HTTP/1.1\r\n\r\n") is None  # not SSH

    ip = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 5, 10, 0, 0, 9])
    tcp = struct.pack("!HHIIBBHHH", 40000, 22, 0, 0, 5 << 4, 0x18, 0, 0, 0) + wire
    ip = ip[:2] + struct.pack("!H", len(ip) + len(tcp)) + ip[4:]
    frame = bytes(12) + b"\x08\x00" + ip + tcp + b"\x00\x00"  # trailing Ethernet padding
    assert parse_frame(frame) == ("10.0.0.5", 40000, 22, wire), "frame parse failed"
    print("selftest passed")
    print("  algorithms:", want_str)
    print("  hassh     :", want)


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        print("usage: python3 hassh.py --selftest")
