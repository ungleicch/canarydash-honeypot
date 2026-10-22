#!/usr/bin/env python3
"""Ships new OpenCanary log lines to the CanaryDash Worker. Run every minute from cron."""
import glob, gzip, hashlib, json, os, sys, urllib.request, datetime
sys.path.insert(0, "/opt/canary-tools")
import mmdb
CFG = json.load(open("/etc/canary-shipper.json"))
LOG = "/var/tmp/opencanary.log"; STATE = "/var/lib/canary-shipper/state.json"
os.makedirs(os.path.dirname(STATE), exist_ok=True)
st = json.load(open(STATE)) if os.path.exists(STATE) else {"offset": 0, "ino": None, "backfilled": False}
CLOUD_WORDS = ("amazon","aws","google","microsoft","azure","alibaba","aliyun","tencent","oracle","digitalocean","linode","akamai","vultr","choopa","hetzner","ovh","huawei","ibm","cloudflare","scaleway","upcloud")
HOSTING_WORDS = ("hosting","host","server","datacenter","data center","vps","colo","contabo","leaseweb","m247","dedicated","cdn","proxy","vpn")
HOME_WORDS = ("telecom","telekom","broadband","cable","mobile","wireless","cellular","comcast","verizon","charter","spectrum","vodafone","telefonica","chinanet","china unicom","china mobile","viettel","airtel","jio","bsnl","telmex","claro","rostelecom","singtel","optus","telstra","fiber","fibre","dsl","residential","isp")
city = mmdb.Reader("/opt/canary-tools/dbip-city-lite.mmdb"); asn = mmdb.Reader("/opt/canary-tools/dbip-asn-lite.mmdb")


def _hint(org):
    o = (org or "").lower()
    if any(w in o for w in CLOUD_WORDS): return "Cloud"
    if any(w in o for w in HOSTING_WORDS): return "Hosting"
    if any(w in o for w in HOME_WORDS): return "Home"
    return ""

def geo(ip):
    try:
        c = city.get(ip) or {}; a = asn.get(ip) or {}
    except Exception:
        return None
    org = a.get("autonomous_system_organization", "")
    return {"cc": c.get("country", {}).get("iso_code", ""), "country": c.get("country", {}).get("names", {}).get("en", "Unknown"),
            "city": c.get("city", {}).get("names", {}).get("en", ""), "lat": c.get("location", {}).get("latitude"),
            "lon": c.get("location", {}).get("longitude"), "asn": a.get("autonomous_system_number"), "org": org,
            "hint": _hint(org), "source": "DB-IP"}

def parse(lines):
    evs, g = [], {}
    for l in lines:
        l = l.strip()
        if not l.startswith("{"): continue
        try: e = json.loads(l)
        except ValueError: continue
        if int(e.get("logtype", 0)) < 2000: continue
        t = e.get("utc_time") or e.get("local_time")
        try: ts = int(datetime.datetime.fromisoformat(t).replace(tzinfo=datetime.timezone.utc).timestamp())
        except Exception: ts = 0
        evs.append({"id": hashlib.sha1(l.encode()).hexdigest(), "ts": ts, "raw": e})
        ip = e.get("src_host")
        if ip and ip not in g:
            x = geo(ip)
            if x: g[ip] = x
    return evs, g

def post(evs, g):
    for i in range(0, max(len(evs), 1), 200):
        chunk = evs[i:i+200]; ips = {e["raw"].get("src_host") for e in chunk}
        body = json.dumps({"events": chunk, "geo": {k: v for k, v in g.items() if k in ips}}).encode()
        req = urllib.request.Request(CFG["url"] + "/ingest", data=body, method="POST",
            headers={"Authorization": "Bearer " + CFG["token"], "Content-Type": "application/json", "User-Agent": "canary-shipper/1"})
        urllib.request.urlopen(req, timeout=30).read()

if not st.get("backfilled"):
    lines = []
    for f in sorted(glob.glob("/var/tmp/opencanary.log-*.gz")):
        lines += gzip.open(f, "rt", errors="replace").readlines()
    if lines:
        post(*parse(lines))
    st["backfilled"] = True
def ship(path, key):
    if not os.path.exists(path): return 0
    s = os.stat(path); o = st.get(key + "offset", 0); ino = st.get(key + "ino")
    if ino != s.st_ino or s.st_size < o:
        o = 0; st[key + "ino"] = s.st_ino
    with open(path, "rb") as f:
        f.seek(o); data = f.read(3 * 1024 * 1024)  # cap per run (low-memory fix 2026-10-15)
    end = data.rfind(b"\n") + 1
    if end:
        evs, g = parse(data[:end].decode("utf-8", "replace").splitlines())
        if evs: post(evs, g)
        st[key + "offset"] = o + end
    return end
a = ship(LOG, ""); b = ship("/var/tmp/cowrie-canary.log", "cowrie_")
json.dump(st, open(STATE, "w"))
print("shipped", a, b)
