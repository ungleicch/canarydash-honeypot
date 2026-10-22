#!/usr/bin/env python3
"""CanaryDash: local dashboard for the OpenCanary honeypot. Python stdlib only."""
import calendar, hashlib, json, os, subprocess, threading, time
from urllib.parse import urlparse, parse_qs
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from geo import Geo

HERE = Path(__file__).resolve().parent
PORT = int(os.environ.get("CANARY_PORT", "8793"))
DATA = Path(os.environ.get("CANARY_DATA", str(Path.home() / "CanaryBackups")))
STORE = DATA / "events.jsonl"
KEY = os.path.expanduser(os.environ.get("CANARY_KEY", "~/.ssh/opencanary_key"))
HOST = os.environ.get("CANARY_HOST", "azureuser@20.98.51.91")
SOURCE_FILE = os.environ.get("CANARY_SOURCE_FILE")  # for offline testing
TEST_IPS = set(filter(None, os.environ.get("CANARY_TEST_IPS",
    "32.192.139.229,3.216.253.221,44.219.165.130,98.86.143.108,172.58.210.229,100.51.208.113,100.57.124.112,54.146.63.25").split(",")))
MAX_LOAD = int(os.environ.get("CANARY_MAX_LOAD", "50000"))

lock = threading.Lock()
GEO = None
seen, events = set(), []
state = {"last_sync": None, "last_error": None}

def ingest(line):
    line = line.strip()
    if not line.startswith("{"):
        return
    h = hashlib.sha1(line.encode()).hexdigest()
    if h in seen:
        return False
    try:
        ev = json.loads(line)
    except ValueError:
        return False
    seen.add(h)
    ev["_id"] = h
    try:
        t = (ev.get("utc_time") or ev.get("local_time") or "").replace("T", " ")[:19]
        ev["_ts"] = calendar.timegm(time.strptime(t, "%Y-%m-%d %H:%M:%S"))
    except Exception:
        ev["_ts"] = 0
    events.append(ev)
    return True

def load_store():
    DATA.mkdir(parents=True, exist_ok=True)
    if STORE.exists():
        with open(STORE) as f:
            for l in f:
                ingest(l)

CACHE = Path(os.environ.get("CANARY_CACHE", str(DATA / "poller-cache")))
CACHE_FILES = ["opencanary.log", "cowrie-canary.log"]
offsets = {}

def sync():
    """LOCAL ONLY: ingest new bytes appended to the poller-cache files.
    No network access. Fetch new data manually with ~/Developer/CanaryDash/pull_new.sh."""
    try:
        new = []
        with lock:
            for name in CACHE_FILES:
                fp = CACHE / name
                if not fp.exists():
                    continue
                size = fp.stat().st_size
                off = offsets.get(name, 0)
                if size < off:
                    off = 0
                with open(fp, "rb") as f:
                    f.seek(off)
                    chunk = f.read()
                last_nl = chunk.rfind(b"\n")
                if last_nl < 0:
                    continue
                offsets[name] = off + last_nl + 1
                for l in chunk[:last_nl].decode("utf-8", "replace").splitlines():
                    if ingest(l):
                        new.append(l.strip())
            if new:
                with open(STORE, "a") as f:
                    f.write("\n".join(new) + "\n")
            state["last_sync"] = time.time(); state["last_error"] = None
        return len(new)
    except Exception as e:
        state["last_error"] = str(e)
        return 0

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path in ("/api/events", "/api/refresh", "/api/archive"):
            if u.path == "/api/refresh":
                sync()
            arch = u.path == "/api/archive"
            try: limit = max(1, min(MAX_LOAD, int(q.get("limit") or (10000 if arch else MAX_LOAD))))
            except ValueError: limit = MAX_LOAD
            with lock:
                allv = sorted((e for e in events if int(e.get("logtype", 0)) >= 2000), key=lambda e: e["_ts"], reverse=True)
            if arch and q.get("before"):
                b = float(q["before"]); sel = [e for e in allv if e["_ts"] < b][:limit]
            elif q.get("since"):
                s0 = float(q["since"]); sel = [e for e in allv if e["_ts"] >= s0][:limit]
            else:
                sel = allv[:limit]
            ips = {e.get("src_host") for e in sel if e.get("src_host")}
            geo = {ip: GEO.lookup(ip) for ip in ips}
            out = {"events": sel, "geo": geo, "oldest_ts": sel[-1]["_ts"] if sel else None, "newest_ts": sel[0]["_ts"] if sel else None,
                   "total": len(allv), "db_oldest_ts": allv[-1]["_ts"] if allv else None, "db_newest_ts": allv[0]["_ts"] if allv else None, "limit": limit}
            if arch: out["more"] = len(sel) == limit
            else: out.update(test_ips=sorted(TEST_IPS), **state)
            return self.send(json.dumps(out))
        if self.path.startswith("/map.js"):
            return self.send((HERE / "map.js").read_bytes(), "application/javascript")
        return self.send((HERE / "index.html").read_bytes(), "text/html; charset=utf-8")

if __name__ == "__main__":
    load_store()
    GEO = Geo(DATA / "ipcache.json")
    sync()  # local cache only; no background fetching
    print(f"CanaryDash on http://127.0.0.1:{PORT}  (data: {STORE})", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
