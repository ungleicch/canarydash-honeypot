#!/usr/bin/env python3
"""Builds a gzipped /api/events-shaped snapshot from local logs and uploads it to the CanaryDash Worker (KV). Cron every 2 min."""
import glob, gzip, hashlib, json, os, sys, time, datetime, urllib.request
sys.path.insert(0, "/opt/canary-tools")
import importlib.util
spec = importlib.util.spec_from_file_location("shp", "/opt/canary-tools/shipper.py")  # reuse geo() without running shipper
src = open("/opt/canary-tools/shipper.py").read().split("def parse(")[0]
ns = {}; exec(compile(src, "shipper_geo", "exec"), ns)
CFG = ns["CFG"]; geo = ns["geo"]
KEEP = None  # all events
TEST = "32.192.139.229,3.216.253.221,44.219.165.130,98.86.143.108,172.58.210.229,100.51.208.113,100.57.124.112,54.146.63.25".split(",")
def lines():
    files = sorted(glob.glob("/var/tmp/opencanary.log-*.gz")) + sorted(glob.glob("/var/tmp/cowrie-canary.log-*.gz"))
    for f in files:
        yield from gzip.open(f, "rt", errors="replace")
    for f in ("/var/tmp/opencanary.log", "/var/tmp/cowrie-canary.log"):
        if os.path.exists(f): yield from open(f, errors="replace")
evs = {}
for l in lines():
    l = l.strip()
    if not l.startswith("{"): continue
    try: e = json.loads(l)
    except ValueError: continue
    if int(e.get("logtype", 0)) < 2000: continue
    t = e.get("utc_time") or e.get("local_time")
    try: ts = int(datetime.datetime.fromisoformat(t).replace(tzinfo=datetime.timezone.utc).timestamp())
    except Exception: ts = 0
    evs[hashlib.sha1(l.encode()).hexdigest()] = (ts, e)
import re
def admin():
    out = []
    try: L = open("/var/log/honeypot-admin.log").read().splitlines()
    except OSError: return out
    for l in L:
        m = re.match(r"(\S+Z) ADMIN (.*)", l.strip())
        if not m: continue
        t = int(datetime.datetime.fromisoformat(m.group(1).replace("Z", "+00:00")).timestamp() * 1000); txt = m.group(2)
        ipm = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", txt); ip = ipm.group(0) if ipm else "-"
        lo = txt.lower()
        if "udp" in lo and "rate-limit" in lo: kind, act = "rate-limited", "Rate-limit +UDP"
        elif "rate-limit applied" in lo: kind, act = "rate-limited", "Rate-limited"
        elif "persona" in lo: kind, act = "persona", "Adaptive personas"
        elif "snapshot" in lo: kind, act = "ops", "Snapshot serving"
        else: kind, act = "ops", "Admin"
        prev = next((a for a in out if act == "Adaptive personas" and a["action"] == act), None)
        if prev:
            prev["detail"] += " (re-confirmed " + m.group(1) + ")"; continue
        out.append({"t": t, "ip": ip, "kind": kind, "action": act, "detail": txt})
    return out
allv = sorted(evs.items(), key=lambda x: x[1][0], reverse=True)
top = allv if KEEP is None else allv[:KEEP]
g = {}
for _, (ts, e) in top:
    ip = e.get("src_host")
    if ip and ip not in g:
        x = geo(ip)
        if x: g[ip] = x
out = {"events": [dict({"_id": i}, **e) for i, (ts, e) in top],
       "oldest_ts": top[-1][1][0] if top else None, "newest_ts": top[0][1][0] if top else None,
       "total": len(allv), "db_oldest_ts": allv[-1][1][0] if allv else None, "db_newest_ts": allv[0][1][0] if allv else None,
       "limit": len(top), "admin": admin(), "geo": g, "test_ips": CFG.get("test_ips", TEST), "last_sync": time.time(), "last_error": None, "snapshot": True}
body = gzip.compress(json.dumps(out, separators=(",", ":")).encode(), 6)
req = urllib.request.Request(CFG["url"] + "/snapshot", data=body, method="POST",
    headers={"Authorization": "Bearer " + CFG["token"], "Content-Type": "application/octet-stream", "User-Agent": "canary-snapshot/1"})
print(datetime.datetime.utcnow().isoformat(), len(top), len(allv), len(body), urllib.request.urlopen(req, timeout=60).read().decode())
