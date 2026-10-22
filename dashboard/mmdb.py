"""Tiny pure-Python MaxMind DB (mmdb) reader. Read-only, enough for DB-IP Lite."""
import ipaddress, mmap, struct

class Reader:
    def __init__(self, path):
        f = open(path, "rb")
        self.buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        i = self.buf.rfind(b"\xab\xcd\xefMaxMind.com")
        self.meta, _ = self._decode(i + 14, i + 14)
        self.nodes = self.meta["node_count"]; self.rs = self.meta["record_size"]
        self.tree = self.rs * 2 // 8 * self.nodes
        self.data = self.tree + 16
        self.v4start = 0
        if self.meta["ip_version"] == 6:
            n = 0
            for _ in range(96):
                if n >= self.nodes: break
                n = self._rec(n, 0)
            self.v4start = n

    def _rec(self, node, bit):
        b = self.buf; rs = self.rs
        if rs == 24:
            o = node * 6 + bit * 3; return int.from_bytes(b[o:o+3], "big")
        if rs == 28:
            o = node * 7
            if bit == 0: return ((b[o+3] & 0xF0) << 20) | int.from_bytes(b[o:o+3], "big")
            return ((b[o+3] & 0x0F) << 24) | int.from_bytes(b[o+4:o+7], "big")
        o = node * 8 + bit * 4; return int.from_bytes(b[o:o+4], "big")

    def get(self, ip):
        a = ipaddress.ip_address(ip)
        bits = a.packed
        n = self.v4start if a.version == 4 and self.meta["ip_version"] == 6 else 0
        for i in range(len(bits) * 8):
            if n >= self.nodes: break
            n = self._rec(n, (bits[i >> 3] >> (7 - (i & 7))) & 1)
        if n <= self.nodes: return None
        off = n - self.nodes - 16 + self.data
        return self._decode(off, self.data)[0]

    def _decode(self, o, base):
        b = self.buf; c = b[o]; o += 1
        t = c >> 5
        if t == 1:
            ss = (c >> 3) & 3; v = c & 7
            if ss == 0: p = (v << 8) | b[o]; o += 1
            elif ss == 1: p = ((v << 16) | int.from_bytes(b[o:o+2], "big")) + 2048; o += 2
            elif ss == 2: p = ((v << 24) | int.from_bytes(b[o:o+3], "big")) + 526336; o += 3
            else: p = int.from_bytes(b[o:o+4], "big"); o += 4
            return self._decode(base + p, base)[0], o
        if t == 0: t = 7 + b[o]; o += 1
        size = c & 0x1F
        if size == 29: size = 29 + b[o]; o += 1
        elif size == 30: size = 285 + int.from_bytes(b[o:o+2], "big"); o += 2
        elif size == 31: size = 65821 + int.from_bytes(b[o:o+3], "big"); o += 3
        if t == 2: return b[o:o+size].decode("utf-8", "replace"), o + size
        if t == 3: return struct.unpack(">d", b[o:o+8])[0], o + 8
        if t == 4: return bytes(b[o:o+size]), o + size
        if t in (5, 6, 9, 10): return int.from_bytes(b[o:o+size], "big"), o + size
        if t == 8: return int.from_bytes(b[o:o+size].rjust(4, b"\0"), "big", signed=True), o + size
        if t == 7:
            d = {}
            for _ in range(size):
                k, o = self._decode(o, base); v, o = self._decode(o, base); d[k] = v
            return d, o
        if t == 11:
            arr = []
            for _ in range(size):
                v, o = self._decode(o, base); arr.append(v)
            return arr, o
        if t == 14: return bool(size), o
        if t == 15: return struct.unpack(">f", b[o:o+4])[0], o + 4
        return None, o + size
