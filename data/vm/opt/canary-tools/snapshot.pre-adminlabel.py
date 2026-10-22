#!/usr/bin/env python3
"""Low-memory snapshot builder (v2, 2026-10-15). Streams logs, keeps raw JSON strings (not dicts),
condenses Brazil bot 191.98.239.177 dropped/portscan (logtype 5001) events into a summary in the
snapshot copy only (raw logs untouched), and streams gzip output to a temp file before upload."""
import glob, gzip, hashlib, json, os, re, sys, time, datetime, urllib.request, tempfile
src = open("/opt/canary-tools/shipper.py").read().split("def parse(")[0]
ns = {}; exec(compile(src, "shipper_geo", "exec"), ns)
CFG = ns["CFG"]; geo = ns["geo"]
TEST = "32.192.139.229,3.216.253.221,44.219.165.130,98.86.143.108,172.58.210.229,100.51.208.113,100.57.124.112,54.146.63.25".split(",")
BR = "191.98.239.177"; BR_KEEP = 25
TSRE = re.compile(r'"utc_time":\s*"([^"]+)"'); LTRE = re.compile(r'"logtype":\s*"?(\d+)'); IPRE = re.compile(r'"src_host":\s*"([^"]*)"')
PORTRE = re.compile(r'"dst_port":\s*"?(\d+)')
def lines():
    files = sorted(glob.glob("/var/tmp/opencanary.log-*.gz")) + sorted(glob.glob("/var/tmp/cowrie-canary.log-*.gz"))
    for f in files:
        with gzip.open(f, "rt", errors="replace") as fh: yield from fh
    for f in ("/var/tmp/opencanary.log", "/var/tmp/cowrie-canary.log"):
        if os.path.exists(f):
            with open(f, errors="replace") as fh: yield from fh
def ts_of(t):
    try: return int(datetime.datetime.fromisoformat(t).replace(tzinfo=datetime.timezone.utc).timestamp())
    except Exception: return 0
seen = set(); evs = []; br = []
brs = {"ip": BR, "count": 0, "first_ts": None, "last_ts": None, "ports": {}, "by_hour": {}}
for l in lines():
    l = l.strip()
    if not l.startswith("{"): continue
    m = LTRE.search(l)
    if not m or int(m.group(1)) < 2000: continue
    h = hashlib.sha1(l.encode()).digest()[:10]
    if h in seen: continue
    seen.add(h)
    t = TSRE.search(l); ts = ts_of(t.group(1)) if t else 0
    ipm = IPRE.search(l); ip = ipm.group(1) if ipm else None
    if ip == BR and m.group(1) == "5001":
        brs["count"] += 1
        brs["first_ts"] = ts if brs["first_ts"] is None else min(brs["first_ts"], ts)
        brs["last_ts"] = max(brs["last_ts"] or 0, ts)
        p = PORTRE.search(l); p = p.group(1) if p else "?"
        brs["ports"][p] = brs["ports"].get(p, 0) + 1
        hr = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:00Z")
        brs["by_hour"][hr] = brs["by_hour"].get(hr, 0) + 1
        br.append((ts, h.hex(), l)); 
        if len(br) > 4 * BR_KEEP: br.sort(reverse=True); del br[BR_KEEP:]
        continue
    evs.append((ts, h.hex(), l, ip))
del seen
br.sort(reverse=True); evs.extend((a, b, c, BR) for a, b, c in br[:BR_KEEP])
evs.sort(key=lambda x: x[0], reverse=True)
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
        if prev: prev["detail"] += " (re-confirmed " + m.group(1) + ")"; continue
        out.append({"t": t, "ip": ip, "kind": kind, "action": act, "detail": txt})
    return out
g = {}
for e in evs:
    ip = e[3]
    if ip and ip not in g:
        x = geo(ip)
        if x: g[ip] = x
total = len(evs) + brs["count"] - min(brs["count"], BR_KEEP)
meta = {"oldest_ts": evs[-1][0] if evs else None, "newest_ts": evs[0][0] if evs else None, "total": total,
        "db_oldest_ts": evs[-1][0] if evs else None, "db_newest_ts": evs[0][0] if evs else None, "limit": len(evs),
        "admin": admin(), "geo": g, "test_ips": CFG.get("test_ips", TEST), "last_sync": time.time(), "last_error": None,
        "snapshot": True, "condensed": {"br_bot_drops": brs, "note": "Brazil bot 5001 events condensed in snapshot only; raw logs untouched"}}
tmp = tempfile.NamedTemporaryFile(delete=False, dir="/var/tmp", suffix=".snap.gz"); tmp.close()
with gzip.open(tmp.name, "wt", compresslevel=6) as z:
    z.write('{"events":[')
    for i, (ts, hid, l, ip) in enumerate(evs):
        if i: z.write(",")
        z.write('{"_id":"%s",' % hid + l[1:] if l != "{}" else '{"_id":"%s"}' % hid)
    z.write("]," + json.dumps(meta, separators=(",", ":"))[1:])
n = len(evs); del evs
body = open(tmp.name, "rb").read(); os.unlink(tmp.name)
req = urllib.request.Request(CFG["url"] + "/snapshot", data=body, method="POST",
    headers={"Authorization": "Bearer " + CFG["token"], "Content-Type": "application/octet-stream", "User-Agent": "canary-snapshot/2"})
print(datetime.datetime.utcnow().isoformat(), n, total, "br_condensed=%d" % brs["count"], len(body), urllib.request.urlopen(req, timeout=60).read().decode())
