#!/usr/bin/env python3
"""Precompute dashboard/site/stats.json from a CanaryDash SQLite DB (built by dashboard/full/ingest.py).
Read-only. Geo/ASN needs a DB built with DB-IP Lite .mmdb files present; the bundled stats.json was built that way.
Usage: python3 dashboard/build_stats.py [path/to/canarydash-full.sqlite]"""
import sqlite3, json, sys, os, collections as C, datetime as dt
from zoneinfo import ZoneInfo
PT = ZoneInfo("America/Los_Angeles")
DB = sys.argv[1] if len(sys.argv) > 1 else "unpacked/canarydash-full.sqlite"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site", "stats.json")
db = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
geo = {ip: json.loads(i) for ip, i in db.execute("select ip, info from geo")}
PERSONA_T = dt.datetime(2026, 10, 15, 7, 42, 56, tzinfo=dt.timezone.utc).timestamp() * 1000
SVC = {2000: "FTP 21", 3000: "HTTP 80", 3001: "HTTP 80", 4000: "SSH 22 (pre-Cowrie)", 4001: "SSH 22 (pre-Cowrie)", 4002: "SSH 22 (pre-Cowrie)",
       5001: "Port scan", 6001: "Telnet 23 (pre-Cowrie)", 8001: "MySQL 3306", 10001: "TFTP 69", 11001: "NTP 123", 12001: "VNC 5900",
       13001: "SNMP 161", 14001: "RDP 3389", 15001: "SIP 5060", 17001: "Redis 6379"}
hourly = C.defaultdict(C.Counter); day_sess = C.defaultdict(C.Counter); heat = C.Counter()
country = C.Counter(); asn = C.Counter(); cips = C.defaultdict(set); aips = C.defaultdict(set)
creds = C.Counter(); credip = C.defaultdict(set); chains = C.defaultdict(list); sess_ip = {}
dl_hash = C.Counter(); dl_hash_ips = C.defaultdict(set); dl_day = C.Counter(); dl_fail = 0
ip_days = C.defaultdict(set); svc = C.Counter(); svc_ips = C.defaultdict(set)
cw_ips, oc_ips = set(), set(); ba = {"before": C.Counter(), "after": C.Counter()}; persona = C.Counter()
for ts, era, ip, lt, port, usr, pwd, sess, raw in db.execute("select ts, era, ip, logtype, port, usr, pwd, sess, raw from events"):
    t = dt.datetime.fromtimestamp(ts / 1000, PT); h = t.strftime("%Y-%m-%d %H"); d = t.strftime("%Y-%m-%d")
    hourly[h][era] += 1
    if era == "cowrie":
        cw_ips.add(ip); ip_days[ip].add(d)
        w = "before" if ts < PERSONA_T else "after"
        if lt == 30001:
            r = json.loads(raw); p = r.get("proto") or "ssh"
            day_sess[d][p] += 1; heat[(t.weekday(), t.hour)] += 1; sess_ip[sess] = ip
            g = geo.get(ip, {}); country[g.get("country") or "Unknown"] += 1; cips[g.get("country") or "Unknown"].add(ip)
            a = (f"AS{g['asn']} " if g.get("asn") else "") + (g.get("org") or "Unknown"); asn[a] += 1; aips[a].add(ip)
            ba[w]["sessions"] += 1
        elif lt in (30002, 30003):
            k = f"{usr or ''} / {pwd or ''}"; creds[k] += 1; credip[k].add(ip)
        elif lt == 30004:
            r = json.loads(raw); chains[sess].append((r.get("logdata") or {}).get("input", "")); ba[w]["commands"] += 1
        elif lt == 30006:
            r = json.loads(raw); ld = r.get("logdata") or {}
            if ld.get("eventid", "").endswith("failed"): dl_fail += 1
            else:
                s = ld.get("shasum") or "?"; dl_hash[s] += 1; dl_hash_ips[s].add(ip); dl_day[d] += 1; ba[w]["downloads"] += 1
        elif lt == 30015:
            r = json.loads(raw); p = (r.get("logdata") or {}).get("persona")
            if p: persona[p] += 1
    elif lt >= 2000:
        oc_ips.add(ip); n = SVC.get(lt, f"logtype {lt}"); svc[n] += 1; svc_ips[n].add(ip)
ch = C.Counter(" ; ".join(c)[:300] for c in chains.values() if c); chip = C.defaultdict(set)
for s, c in chains.items():
    if c: chip[" ; ".join(c)[:300]].add(sess_ip.get(s))
days = sorted({d for s in ip_days.values() for d in s}); first = {}
for ip, s in ip_days.items(): first[ip] = min(s)
newrep = [{"day": d, "new": sum(1 for ip, s in ip_days.items() if d in s and first[ip] == d),
           "repeat": sum(1 for ip, s in ip_days.items() if d in s and first[ip] < d)} for d in days]
gaps = [{"from": "2026-10-14 20", "to": "2026-10-14 23", "label": "OpenCanary only (pre-Cowrie)"},
        {"from": "2026-10-15 09", "to": "2026-10-15 11", "label": "VM out-of-memory freeze"},
        {"from": "2026-10-16 10", "to": "2026-10-17 16", "label": "Cowrie outage (~30 h, cause unknown)"}]
top = lambda c, ips, n: [{"k": k, "n": v, "ips": len(ips[k])} for k, v in c.most_common(n)]
S = {"generated_from": os.path.basename(DB), "range_pt": ["2026-10-14 20:51", "2026-10-23 16:16"],
     "totals": {"events": sum(sum(c.values()) for c in hourly.values()), "cowrie_ips": len(cw_ips), "opencanary_ips": len(oc_ips),
                "sessions": sum(sum(c.values()) for c in day_sess.values()), "downloads": sum(dl_hash.values()), "unique_files": len(dl_hash), "failed_downloads": dl_fail},
     "hourly": [{"h": h, **hourly[h]} for h in sorted(hourly)], "gaps": gaps,
     "sessions_per_day": [{"day": d, **day_sess[d]} for d in sorted(day_sess)],
     "countries": top(country, cips, 15), "asns": top(asn, aips, 15), "creds": top(creds, credip, 20), "chains": top(ch, chip, 12),
     "malware_hashes": top(dl_hash, dl_hash_ips, 12), "downloads_per_day": [{"day": d, "n": dl_day[d]} for d in sorted(dl_day)],
     "persona_before_after": {k: dict(v) for k, v in ba.items()}, "persona_sessions": dict(persona),
     "heatmap": [[heat[(w, h)] for h in range(24)] for w in range(7)], "new_vs_repeat": newrep,
     "services": top(svc, svc_ips, 20), "overlap": {"cowrie_only": len(cw_ips - oc_ips), "both": len(cw_ips & oc_ips), "opencanary_only": len(oc_ips - cw_ips)}}
json.dump(S, open(OUT, "w"), separators=(",", ":")); print("wrote", OUT, os.path.getsize(OUT), "bytes")
