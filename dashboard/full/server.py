#!/usr/bin/env python3
"""CanaryDash static archive server. Read-only, Python stdlib only, 127.0.0.1 only, makes no outbound connections.
/ = static overview + docs (dashboard/site, works without a DB); /explorer = event browser over the local SQLite built by ./setup.sh.
Usage: python3 dashboard/full/server.py [port]   (default 8802)"""
import gzip, json, os, sqlite3, sys, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
HERE = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.realpath(os.path.join(HERE, "..", "site"))
REPO = os.path.realpath(os.path.join(HERE, "..", ".."))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("CANARY_PORT", "8802"))
DB = os.path.expanduser(os.environ.get("CANARY_DB", "unpacked/canarydash-full.sqlite"))
ROOT = os.path.realpath(os.path.expanduser(os.environ.get("CANARY_FULL", "unpacked")))
INITIAL = int(os.environ.get("CANARY_INITIAL", "100000"))   # newest events sent on first page load
TEST_IPS = "32.192.139.229,3.216.253.221,44.219.165.130,98.86.143.108,172.58.210.229,100.51.208.113,100.57.124.112,54.146.63.25".split(",")
_geo = {"mtime": None, "geo": {}, "admin": [], "report": {}}

def conn():
    c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True); return c

def cached(c):
    m = os.path.getmtime(DB)
    if _geo["mtime"] != m:
        _geo["geo"] = {ip: json.loads(i) for ip, i in c.execute("SELECT ip, info FROM geo")}
        meta = dict(c.execute("SELECT k, v FROM meta WHERE k IN ('admin','report')"))
        _geo["admin"] = json.loads(meta.get("admin", "[]")); _geo["report"] = json.loads(meta.get("report", "{}")); _geo["mtime"] = m
    return _geo

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def send(self, body, ctype="application/json", code=200):
        b = body.encode() if isinstance(body, str) else body
        gz = "gzip" in (self.headers.get("Accept-Encoding") or "") and len(b) > 2048 and ctype.startswith(("application", "text"))
        if gz: b = gzip.compress(b, 5)
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Cache-Control", "no-store")
        if gz: self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}; p = u.path
        try:
            if p in ("/api/events", "/api/archive"): return self.events(p, q)
            if p == "/api/summary":
                c = conn(); era = q.get("era") or "all"
                row = c.execute("SELECT v FROM meta WHERE k=?", ("summary:" + era,)).fetchone()
                return self.send('{"summary":%s,"report":%s,"root":%s}' % (row[0] if row else "null", json.dumps(cached(c)["report"]), json.dumps(ROOT)))
            if p == "/api/report": return self.send(json.dumps(cached(conn())["report"], indent=1))
            if p == "/map.js": return self.send(open(os.path.join(HERE, "map.js"), "rb").read(), "application/javascript")
            if p in ("/explorer", "/explorer/"): return self.send(open(os.path.join(HERE, "index.html"), "rb").read(), "text/html; charset=utf-8")
            if p in ("/", "/index.html"): p = "/site/index.html"
            if p.startswith("/site/") or p.startswith("/docs/") or p == "/README.md":
                base = SITE if p.startswith("/site/") else REPO
                rel = p[len("/site/"):] if p.startswith("/site/") else p.lstrip("/")
                f = os.path.realpath(os.path.join(base, rel))
                if f.startswith(base + os.sep) and os.path.isfile(f):
                    ext = os.path.splitext(f)[1]
                    ct = {".html": "text/html; charset=utf-8", ".js": "application/javascript", ".css": "text/css", ".json": "application/json",
                          ".md": "text/markdown; charset=utf-8", ".png": "image/png", ".csv": "text/csv"}.get(ext, "application/octet-stream")
                    return self.send(open(f, "rb").read(), ct)
            return self.send('{"error":"not found"}', code=404)
        except Exception as e:
            return self.send(json.dumps({"error": str(e)}), code=500)
    def events(self, p, q):
        c = conn(); g = cached(c); arch = p == "/api/archive"
        lim = max(1, min(INITIAL if not arch else 50000, int(q.get("limit") or (10000 if arch else INITIAL))))
        if arch and q.get("before"):
            rows = c.execute("SELECT ts, raw FROM events WHERE ts <= ? ORDER BY ts DESC LIMIT ?", (int(float(q["before"])), lim)).fetchall()
        elif q.get("since"):
            rows = c.execute("SELECT ts, raw FROM events WHERE ts > ? ORDER BY ts DESC LIMIT ?", (int(float(q["since"])), lim)).fetchall()
        else:
            rows = c.execute("SELECT ts, raw FROM events ORDER BY ts DESC LIMIT ?", (lim,)).fetchall()
        tot, lo, hi = c.execute("SELECT count(*), min(ts), max(ts) FROM events").fetchone()
        out = {"events": [], "oldest_ts": rows[-1][0] if rows else None, "newest_ts": rows[0][0] if rows else None, "total": tot,
               "db_oldest_ts": lo, "db_newest_ts": hi, "limit": lim, "geo": g["geo"], "admin": g["admin"], "test_ips": TEST_IPS,
               "local_full": True, "static_archive": True}
        if arch: out["more"] = len(rows) == lim
        body = json.dumps(out, separators=(",", ":")).replace('"events":[]', '"events":[' + ",".join(r[1] for r in rows) + "]", 1)
        return self.send(body)

if __name__ == "__main__":
    print(f"CanaryDash static archive (read-only) on http://127.0.0.1:{PORT}  db={DB}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
