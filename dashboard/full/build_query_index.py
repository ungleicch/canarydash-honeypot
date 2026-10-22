#!/usr/bin/env python3
"""Build unpacked/explore.sqlite: a flat, indexed, read-only query table for the Explore page.
Reads (never modifies) the ingest DB. Optional --geo-db: another CanaryDash DB whose `geo` table has DB-IP country/ASN data.
Usage: python3 dashboard/full/build_query_index.py unpacked/canarydash-full.sqlite unpacked/explore.sqlite [--geo-db path]"""
import sqlite3, json, sys, os, ipaddress, time
src, dst = sys.argv[1], sys.argv[2]
geo_db = sys.argv[sys.argv.index("--geo-db") + 1] if "--geo-db" in sys.argv else src
SVC = {2000: "ftp", 3000: "http", 3001: "http", 4000: "ssh", 4001: "ssh", 4002: "ssh", 5001: "portscan", 6001: "telnet", 8001: "mysql",
       10001: "tftp", 11001: "ntp", 12001: "vnc", 13001: "snmp", 14001: "rdp", 15001: "sip", 17001: "redis"}
t0 = time.time(); s = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
g = sqlite3.connect(f"file:{geo_db}?mode=ro", uri=True)
geo = {}
for ip, info in g.execute("select ip, info from geo"):
    i = json.loads(info); geo[ip] = (i.get("country") or "", (f"AS{i['asn']} " if i.get("asn") else "") + (i.get("org") or ""))
persona = {}
for sess, raw in s.execute("select sess, raw from events where logtype=30015"):
    p = (json.loads(raw).get("logdata") or {}).get("persona")
    if p: persona[sess] = p
tmp = dst + ".tmp"
if os.path.exists(tmp): os.remove(tmp)
d = sqlite3.connect(tmp); d.execute("PRAGMA journal_mode=OFF"); d.execute("PRAGMA synchronous=OFF")
d.execute("""CREATE TABLE ev(ts INTEGER, era TEXT, ip TEXT, ipn INTEGER, eventid TEXT, proto TEXT, port INTEGER, usr TEXT, pwd TEXT,
 sess TEXT, cmd TEXT, hash TEXT, url TEXT, country TEXT, asn TEXT, persona TEXT, rid TEXT)""")
def ipn(ip):
    try: a = ipaddress.ip_address(ip); return int(a) if a.version == 4 else None
    except ValueError: return None
batch = []; n = 0
for rid, ts, era, ip, lt, port, usr, pwd, sess, raw in s.execute("select id, ts, era, ip, logtype, port, usr, pwd, sess, raw from events where logtype >= 2000"):
    r = json.loads(raw); ld = r.get("logdata") or {}
    if era == "cowrie":
        ev = ld.get("eventid") or f"cowrie.{lt}"; proto = r.get("proto") or ld.get("protocol") or ""
        cmd = ld.get("input"); h = ld.get("shasum"); url = ld.get("url")
        usr = ld.get("username", usr); pwd = ld.get("password", pwd)
    else:
        ev = "opencanary." + SVC.get(lt, str(lt)); proto = SVC.get(lt, ""); cmd = ld.get("CMD") and (ld.get("CMD") + " " + " ".join(map(str, ld.get("ARGS") or []))).strip()
        h = None; url = ld.get("PATH"); usr = ld.get("USERNAME", usr); pwd = ld.get("PASSWORD", pwd)
    c, a = geo.get(ip, ("", ""))
    try: port = int(port)
    except (TypeError, ValueError): port = None
    batch.append((ts, era, ip, ipn(ip), ev, proto, port, usr, pwd, sess or None, cmd, h, url, c or None, a or None, persona.get(sess), rid))
    if len(batch) >= 50000: d.executemany("insert into ev values (" + ",".join("?" * 17) + ")", batch); n += len(batch); batch = []
d.executemany("insert into ev values (" + ",".join("?" * 17) + ")", batch); n += len(batch)
for col in ("ts", "ipn", "ip", "eventid", "usr", "pwd", "sess", "hash", "country", "asn", "port", "persona"):
    d.execute(f"create index ix_{col} on ev({col})")
d.execute("create index ix_era_ts on ev(era, ts)"); d.execute("create index ix_ev_ts on ev(eventid, ts)")
d.execute("analyze"); d.commit(); d.close(); os.replace(tmp, dst)
print(f"explore index: {n} rows, {len(persona)} sessions with persona, geo for {len(geo)} IPs, {time.time()-t0:.0f}s -> {dst}")
