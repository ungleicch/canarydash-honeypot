#!/usr/bin/env python3
"""CanaryDash: local dashboard for the OpenCanary honeypot. Python stdlib only."""
import hashlib, json, os, subprocess, threading, time
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
    "32.192.139.229,3.216.253.221,44.219.165.130,98.86.143.108,172.58.210.229").split(",")))
INTERVAL = 60

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
    events.append(ev)
    return True

def load_store():
    DATA.mkdir(parents=True, exist_ok=True)
    if STORE.exists():
        with open(STORE) as f:
            for l in f:
                ingest(l)

def fetch_remote():
    if SOURCE_FILE:
        return Path(SOURCE_FILE).read_text()
    cmd = ["ssh", "-i", KEY, "-p", "2222", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
           "-o", "StrictHostKeyChecking=accept-new", HOST,
           "sudo zcat -f /var/tmp/opencanary.log-*.gz 2>/dev/null; sudo cat /var/tmp/opencanary.log; sudo cat /var/tmp/cowrie-canary.log 2>/dev/null"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if r.returncode != 0 and not r.stdout:
        raise RuntimeError(r.stderr.strip()[-300:] or "ssh failed")
    return r.stdout

def sync():
    try:
        text = fetch_remote()
        new = []
        with lock:
            for l in text.splitlines():
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

def loop():
    while True:
        sync()
        time.sleep(INTERVAL)

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
        if self.path.startswith("/api/events"):
            with lock:
                evs = [e for e in events if int(e.get("logtype", 0)) >= 2000]
                ips = {e.get("src_host") for e in evs if e.get("src_host")}
            geo = {ip: GEO.lookup(ip) for ip in ips}
            body = json.dumps({"events": evs, "geo": geo, "test_ips": sorted(TEST_IPS), **state})
            return self.send(body)
        if self.path.startswith("/api/refresh"):
            n = sync()
            return self.send(json.dumps({"new": n, **state}))
        if self.path.startswith("/map.js"):
            return self.send((HERE / "map.js").read_bytes(), "application/javascript")
        return self.send((HERE / "index.html").read_bytes(), "text/html; charset=utf-8")

if __name__ == "__main__":
    load_store()
    GEO = Geo(DATA / "ipcache.json")
    threading.Thread(target=loop, daemon=True).start()
    print(f"CanaryDash on http://127.0.0.1:{PORT}  (data: {STORE})", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
