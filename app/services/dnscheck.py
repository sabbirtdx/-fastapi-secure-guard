"""Secure File Guard — DNS TXT verification for domain ownership.

Real lookup via dnspython. Returns None when DNS is unreachable (e.g.,
sandboxed/offline environments) so the caller can fall back to manual
approval; otherwise returns the list of TXT record strings.
"""
from __future__ import annotations

import socket
import time

TIMEOUT = 5.0


def dns_txt(name: str) -> list[str] | None:
    try:
        import dns.resolver
    except ImportError:
        return _manual_txt(name)
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=TIMEOUT)
        out = []
        for rdata in answers:
            for part in rdata.strings:
                out.append(part.decode() if isinstance(part, bytes) else str(part))
        return out
    except Exception:
        return _manual_txt(name)


def _manual_txt(name: str) -> list[str] | None:
    """Minimal DNS TXT query over UDP (fallback when dnspython is missing)."""
    import random
    import struct

    try:
        tid = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qname = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
        q = header + qname + struct.pack(">HH", 1, 1)  # type TXT, class IN
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        s.sendto(q, ("8.8.8.8", 53))
        data, _ = s.recvfrom(4096)
        s.close()
        if len(data) < 12 or struct.unpack(">H", data[:2])[0] != tid:
            return None
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return []
        # skip question section
        off = 12
        while off < len(data) and data[off] != 0:
            off += data[off] + 1
        off += 5  # null + qtype + qclass
        out = []
        for _ in range(ancount):
            # skip name (may be pointer)
            if off >= len(data):
                break
            if data[off] & 0xC0:
                off += 2
            else:
                while off < len(data) and data[off] != 0:
                    off += data[off] + 1
                off += 1
            off += 8  # type(2) + class(2) + ttl(4)
            if off + 2 > len(data):
                break
            rdlen = struct.unpack(">H", data[off:off + 2])[0]
            off += 2
            txt = data[off:off + rdlen]
            # TXT: one or more length-prefixed strings
            s = b""
            p = 0
            while p < len(txt):
                l = txt[p]
                s += txt[p + 1:p + 1 + l]
                p += 1 + l
            out.append(s.decode(errors="replace"))
            off += rdlen
        return out
    except (OSError, socket.timeout):
        return None
