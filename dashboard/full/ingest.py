#!/usr/bin/env python3
"""Ingest the full local honeypot copy into SQLite for the offline CanaryDash.
Reads (never modifies) ~/CanaryBackups/full-latest/vm/... and writes canarydash-full.sqlite next to it.
Eras: 'live opencanary' (opencanary.log), 'pre-cowrie snapshot' (opencanary.log.snapshot-pre-cowrie,
deduped against the live log on utc_time+src_host+dst_port+logtype), 'cowrie' (all cowrie.json*, incl .gz,
converted to OpenCanary-style lines exactly like the VM's cowrie_conv.py). Includes the Brazil bot."""
import datetime, glob, gzip, hashlib, io, json, os, re, sqlite3, sys, tarfile, time
from collections import Counter, defaultdict
from zoneinfo import ZoneInfo
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mmdb

ROOT = os.path.expanduser(os.environ.get("CANARY_FULL", "~/CanaryBackups/full-latest"))
VM = os.path.join(ROOT, "vm")
DB = os.path.expanduser(os.environ.get("CANARY_DB", "~/CanaryBackups/canarydash-full.sqlite"))
MMDB_DIRS = [os.path.join(HERE, "..", "data"), os.path.join(HERE, "data"), os.path.join(VM, "opt/canary-tools")]
PT = ZoneInfo("America/Los_Angeles")
BR = "191.98.239.177"
ERA_LIVE, ERA_PRE, ERA_CW = "live opencanary", "pre-cowrie snapshot", "cowrie"
ERAS = [ERA_LIVE, ERA_PRE, ERA_CW]

CODES = {"cowrie.session.connect": 30001, "cowrie.login.success": 30002, "cowrie.login.failed": 30003,
         "cowrie.command.input": 30004, "cowrie.command.failed": 30005, "cowrie.session.file_download": 30006,
         "cowrie.session.file_download.failed": 30006, "cowrie.session.file_upload": 30007,
         "cowrie.client.version": 30008, "cowrie.client.kex": 30009, "cowrie.session.closed": 30010,
         "cowrie.direct-tcpip.request": 30011, "cowrie.direct-tcpip.data": 30011, "cowrie.client.size": 30012,
         "cowrie.log.closed": 30013, "cowrie.client.fingerprint": 30014, "cowrie.session.params": 30015,
         "cowrie.client.var": 30016}
SKIP = {"src_ip", "src_port", "dst_ip", "dst_port", "timestamp", "sensor", "eventid", "session", "message"}
SLIM = {"kexAlgs", "keyAlgs", "encCS", "macCS", "compCS", "langCS"}  # big kex lists dropped from the served copy only
proto = {}

def conv(e):
    ev = e.get("eventid", ""); t = e.get("timestamp", "")
    try: t = datetime.datetime.fromisoformat(t.replace("Z", "+00:00")).astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    except Exception: pass
    sid = e.get("session", "")
    if ev == "cowrie.session.connect": proto[sid] = e.get("protocol", "ssh")
    d = {k: v for k, v in e.items() if k not in SKIP and k not in SLIM}
    d["eventid"] = ev; d["message"] = e.get("message", "")
    return {"logtype": CODES.get(ev, 30099), "node_id": "cowrie", "source": "cowrie", "session": sid,
            "proto": e.get("protocol") or proto.get(sid) or ("telnet" if e.get("dst_port") == 23 else "ssh"),
            "src_host": e.get("src_ip", ""), "src_port": e.get("src_port", -1), "dst_host": e.get("dst_ip", ""),
            "dst_port": e.get("dst_port", -1), "utc_time": t, "local_time": t, "logdata": d}

def ts_ms(t):
    try: return int(datetime.datetime.fromisoformat(str(t).replace(" ", "T")[:26]).replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
    except Exception: return 0

def opener(p):
    return gzip.open(p, "rt", errors="replace") if p.endswith(".gz") else open(p, errors="replace")

def main():
    t0 = time.time()
    if not os.path.isdir(VM): sys.exit(f"no data at {VM}; run pull.sh first")
    tmp = DB + ".tmp"
    if os.path.exists(tmp): os.remove(tmp)
    db = sqlite3.connect(tmp); db.execute("PRAGMA journal_mode=OFF"); db.execute("PRAGMA synchronous=OFF")
    db.executescript("""CREATE TABLE events(id TEXT PRIMARY KEY, ts INTEGER, era TEXT, ip TEXT, logtype INTEGER, port INTEGER,
        usr TEXT, pwd TEXT, sess TEXT, raw TEXT);
        CREATE TABLE geo(ip TEXT PRIMARY KEY, info TEXT); CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);""")
    rep = {"files": {}, "ingested_at": time.time()}
    rows = []
    def flush():
        db.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?)", rows); rows.clear()
    def add(era, ev, hid):
        ev = {"_id": hid, "_era": era, **ev}
        d = ev.get("logdata") or {}
        cw = ev.get("node_id") == "cowrie"
        u = d.get("username") if cw else d.get("USERNAME")
        p = d.get("password") if cw else d.get("PASSWORD")
        if not cw and p is None and str(ev.get("logtype")) == "17001" and d.get("CMD") == "AUTH": p = d.get("ARGS")
        try: port = int(ev.get("dst_port"))
        except Exception: port = -1
        rows.append((hid, ts_ms(ev.get("utc_time") or ev.get("local_time")), era, ev.get("src_host") or "", int(ev.get("logtype", 0)), port,
                     None if u is None else str(u), None if p is None else str(p), ev.get("session") or "", json.dumps(ev, separators=(",", ":"))))
        if len(rows) >= 20000: flush()

    # --- OpenCanary: pre-cowrie snapshot keys first, then the live log, then snapshot-only lines ---
    # A live-log event whose (utc_time, src_host, dst_port, logtype) is also in the snapshot is stored ONCE and labelled
    # 'pre-cowrie snapshot' (it belongs to that era); snapshot lines missing from the live log are added with the same label.
    def oc_lines(path):
        with opener(path) as f:
            for l in f:
                l = l.strip()
                if not l.startswith("{"): yield l, None; continue
                try: yield l, json.loads(l)
                except ValueError: yield l, None
    key = lambda ev: (ev.get("utc_time"), ev.get("src_host"), str(ev.get("dst_port")), int(ev.get("logtype", 0) or 0))
    pre_path = os.path.join(VM, "var/tmp/opencanary.log.snapshot-pre-cowrie"); live_path = os.path.join(VM, "var/tmp/opencanary.log")
    prekeys = {}
    pst = Counter(lines=0, non_json=0, below2000=0, dup_exact=0)
    if os.path.exists(pre_path):
        for l, ev in oc_lines(pre_path):
            pst["lines"] += 1
            if ev is None: pst["non_json"] += 1; continue
            if int(ev.get("logtype", 0) or 0) < 2000: pst["below2000"] += 1; continue
            k = key(ev)
            if k in prekeys: pst["dup_exact"] += 1; continue
            prekeys[k] = (l, ev)
    st = Counter(lines=0, non_json=0, below2000=0, cowrie_node_lt30000=0, dup_exact=0, stored=0, labelled_pre_cowrie=0)
    seen = set(); matched = set()
    if os.path.exists(live_path):
        for l, ev in oc_lines(live_path):
            st["lines"] += 1
            if ev is None: st["non_json"] += 1; continue
            lt = int(ev.get("logtype", 0) or 0)
            if lt < 2000: st["below2000"] += 1; continue
            if ev.get("node_id") == "cowrie" and lt < 30000: st["cowrie_node_lt30000"] += 1; continue
            h = hashlib.sha1(l.encode()).hexdigest()[:20]
            if h in seen: st["dup_exact"] += 1; continue
            seen.add(h); k = key(ev)
            if k in prekeys and k not in matched:
                matched.add(k); add(ERA_PRE, ev, h); st["labelled_pre_cowrie"] += 1
            else: add(ERA_LIVE, ev, h)
            st["stored"] += 1
    rep["files"]["var/tmp/opencanary.log"] = dict(st)
    only = 0
    for k, (l, ev) in prekeys.items():
        if k in matched: continue
        h = hashlib.sha1(l.encode()).hexdigest()[:20]
        if h in seen: continue
        add(ERA_PRE, ev, h); only += 1
    pst.update(events=len(prekeys), overlap_live=len(matched), snapshot_only_added=only)
    rep["files"]["var/tmp/opencanary.log.snapshot-pre-cowrie"] = dict(pst)
    prekeys = seen = matched = None

    # --- Cowrie: every cowrie.json* (oldest first, live file last) ---
    cdir = os.path.join(VM, "opt/cowrie/cowrie/var/log/cowrie")
    files = sorted(f for f in glob.glob(os.path.join(cdir, "cowrie.json.*")) if not f.endswith(".uploaded"))
    if os.path.exists(os.path.join(cdir, "cowrie.json")): files.append(os.path.join(cdir, "cowrie.json"))
    seen = set()
    for path in files:
        st = Counter(lines=0, bad=0, dup_exact=0, stored=0)
        with opener(path) as f:
            for l in f:
                st["lines"] += 1; l = l.strip()
                if not l: continue
                try: e = json.loads(l)
                except ValueError: st["bad"] += 1; continue
                h = hashlib.sha1(l.encode()).hexdigest()[:20]
                if h in seen: st["dup_exact"] += 1; continue
                seen.add(h); add(ERA_CW, conv(e), h); st["stored"] += 1
        rep["files"][os.path.relpath(path, VM)] = dict(st)
    seen = None; flush()
    db.execute("CREATE INDEX ev_ts ON events(ts)"); db.commit()

    # --- Geo (offline DB-IP Lite only) ---
    readers = {}
    for k in ("city", "asn"):
        for d in MMDB_DIRS:
            p = os.path.join(d, f"dbip-{k}-lite.mmdb")
            if os.path.exists(p): readers[k] = mmdb.Reader(p); break
    CLOUD = ("amazon", "aws", "google", "microsoft", "azure", "alibaba", "aliyun", "tencent", "oracle", "digitalocean", "linode",
             "akamai", "vultr", "choopa", "hetzner", "ovh", "huawei", "ibm", "cloudflare", "scaleway", "upcloud")
    HOST = ("hosting", "host", "server", "datacenter", "data center", "vps", "colo", "contabo", "leaseweb", "m247", "dedicated", "cdn", "proxy", "vpn")
    HOME = ("telecom", "telekom", "broadband", "cable", "mobile", "wireless", "cellular", "comcast", "verizon", "charter", "spectrum",
            "vodafone", "telefonica", "chinanet", "china unicom", "china mobile", "viettel", "airtel", "jio", "bsnl", "telmex", "claro",
            "rostelecom", "singtel", "optus", "telstra", "fiber", "fibre", "dsl", "residential", "isp")
    G = {}
    for (ip,) in db.execute("SELECT DISTINCT ip FROM events WHERE ip != ''"):
        out = {"cc": "", "country": "", "city": "", "asn": None, "org": "", "hint": "", "source": "DB-IP Lite (offline)"}
        try:
            if "city" in readers:
                d = readers["city"].get(ip) or {}
                out["cc"] = d.get("country", {}).get("iso_code", ""); out["country"] = d.get("country", {}).get("names", {}).get("en", "")
                out["city"] = d.get("city", {}).get("names", {}).get("en", "")
            if "asn" in readers:
                d = readers["asn"].get(ip) or {}
                out["asn"] = d.get("autonomous_system_number"); out["org"] = d.get("autonomous_system_organization", "")
        except Exception: pass
        o = (out["org"] or "").lower()
        out["hint"] = "Cloud" if any(w in o for w in CLOUD) else "Hosting" if any(w in o for w in HOST) else "Home" if any(w in o for w in HOME) else ""
        G[ip] = out
    db.executemany("INSERT INTO geo VALUES (?,?)", [(k, json.dumps(v)) for k, v in G.items()])

    # --- Admin markers (same parsing as the VM snapshot) ---
    admin = []
    try:
        for l in open(os.path.join(VM, "var/log/honeypot-admin.log"), errors="replace"):
            m = re.match(r"(\S+Z) ADMIN (.*)", l.strip())
            if not m: continue
            t = int(datetime.datetime.fromisoformat(m.group(1).replace("Z", "+00:00")).timestamp() * 1000); txt = m.group(2)
            ipm = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", txt); lo = txt.lower()
            if "rate-limit" in lo: kind, act = "rate-limited", "Rate-limited"
            elif "persona" in lo: kind, act = "persona", "Adaptive personas"
            else: kind, act = "ops", "Admin"
            if act == "Adaptive personas" and any(a["action"] == act for a in admin): continue
            admin.append({"t": t, "ip": ipm.group(0) if ipm else "-", "kind": kind, "action": act, "detail": txt})
    except OSError: pass

    # --- Malware types from the tar.gz (headers + first bytes only, nothing written to disk) ---
    mal = {}
    tpath = os.path.join(ROOT, "malware/downloads_DO_NOT_RUN.tar.gz")
    if os.path.exists(tpath):
        ARCH = {3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86-64", 183: "ARM64", 2: "SPARC", 42: "SuperH", 0x5A: "?"}
        try:
            with tarfile.open(tpath, "r:gz") as tf:
                for m in tf:
                    if not m.isfile(): continue
                    name = os.path.basename(m.name)
                    if not re.fullmatch(r"[0-9a-f]{64}", name): continue
                    f = tf.extractfile(m); b = f.read(4096)
                    if b[:4] == b"\x7fELF":
                        big = b[5] == 2; mach = int.from_bytes(b[18:20], "big" if big else "little")
                        typ = f"ELF {'64' if b[4]==2 else '32'}-bit {ARCH.get(mach, 'machine '+str(mach))}{' BE' if big else ''}"
                        if b"UPX!" in b: typ += " (UPX packed)"
                    elif b[:2] == b"#!" or b"wget" in b[:400] or b"curl" in b[:400]: typ = "shell script"
                    elif m.size <= 1: typ = "empty"
                    else: typ = "data/text"
                    mal[name] = {"type": typ, "size": m.size}
        except Exception as e: rep["malware_error"] = str(e)
    db.execute("INSERT INTO meta VALUES ('malware', ?)", (json.dumps(mal),))

    # --- Precomputed summaries per era (+ all) ---
    def summary(era):
        w, a = ("WHERE era=?", (era,)) if era else ("", ())
        q = lambda s, *x: db.execute(s, a + x).fetchall()
        aw = (w + " AND " if w else "WHERE ")
        tot, lo, hi, nip = q(f"SELECT count(*), min(ts), max(ts), count(DISTINCT ip) FROM events {w}")[0]
        def geoname(ip): g = G.get(ip, {}); return {"cc": g.get("cc", ""), "country": g.get("country", "") or "Unknown", "org": g.get("org", "")}
        top_ips = [{"ip": ip, "n": n, **geoname(ip)} for ip, n in q(f"SELECT ip, count(*) n FROM events {w} GROUP BY ip ORDER BY n DESC LIMIT 25")]
        cty_ev, cty_ip = Counter(), Counter()
        for ip, n in q(f"SELECT ip, count(*) FROM events {w} GROUP BY ip"):
            c = (G.get(ip, {}).get("country") or "Unknown"); cty_ev[c] += n; cty_ip[c] += 1
        ccmap = {g.get("country"): g.get("cc") for g in G.values()}
        days = Counter(); eradays = defaultdict(Counter)
        for ts, e, n in q(f"SELECT ts/3600000, era, count(*) FROM events {w} GROUP BY 1, 2"):
            d = datetime.datetime.fromtimestamp(ts * 3600, PT).strftime("%Y-%m-%d"); days[d] += n; eradays[d][e] += n
        hours = Counter()
        for ts, n in q(f"SELECT ts/3600000, count(*) FROM events {aw} ts >= ? GROUP BY 1", (hi or 0) - 72 * 3600000):
            hours[ts * 3600000] += n
        creds = q(f"SELECT usr, pwd, count(*) n FROM events {aw} (usr IS NOT NULL OR pwd IS NOT NULL) AND logtype NOT IN (30002) GROUP BY usr, pwd ORDER BY n DESC LIMIT 25")
        login_attempts = q(f"SELECT count(*) FROM events {aw} (usr IS NOT NULL OR pwd IS NOT NULL)")[0][0]
        cw_ok = q(f"SELECT count(*) FROM events {aw} logtype=30002")[0][0]; cw_fail = q(f"SELECT count(*) FROM events {aw} logtype=30003")[0][0]
        ok_creds = q(f"SELECT usr, pwd, count(*) n FROM events {aw} logtype=30002 GROUP BY usr, pwd ORDER BY n DESC LIMIT 15")
        users = q(f"SELECT usr, count(*) n FROM events {aw} usr IS NOT NULL AND usr != '' GROUP BY usr ORDER BY n DESC LIMIT 15")
        pwds = q(f"SELECT pwd, count(*) n FROM events {aw} pwd IS NOT NULL AND pwd != '' GROUP BY pwd ORDER BY n DESC LIMIT 15")
        cmds = Counter(); 
        for (r,) in q(f"SELECT json_extract(raw,'$.logdata.input') FROM events {aw} logtype IN (30004,30005)"): cmds[r or ""] += 1
        dl = {}; dln = 0; urls = Counter(); dlsrc = Counter()
        for r, ip, ts in q(f"SELECT raw, ip, ts FROM events {aw} logtype IN (30006,30007)"):
            d = json.loads(r).get("logdata", {}); dln += 1
            u = d.get("url") or d.get("filename") or d.get("destfile") or ""
            if u: urls[u] += 1
            m = re.match(r"https?://([^/]+)", u or "")
            if m: dlsrc[m.group(1)] += 1
            s = d.get("shasum")
            if s:
                x = dl.setdefault(s, {"sha256": s, "n": 0, "first": ts, "last": ts, "url": u, "ips": set(), "size": d.get("size")})
                x["n"] += 1; x["first"] = min(x["first"], ts); x["last"] = max(x["last"], ts); x["ips"].add(ip)
        for x in dl.values():
            x["ips"] = len(x["ips"]); x.update(mal.get(x["sha256"], {"type": "not in downloads folder"}))
            if x.get("size") is None and x["sha256"] in mal: x["size"] = mal[x["sha256"]]["size"]
        sess = q(f"SELECT count(DISTINCT sess) FROM events {aw} sess != ''")[0][0]
        return {"era": era or "all", "total": tot, "first_ts": lo, "last_ts": hi, "unique_ips": nip, "cowrie_sessions": sess,
                "by_era": dict(q(f"SELECT era, count(*) FROM events {w} GROUP BY era")),
                "by_logtype": q(f"SELECT logtype, count(*) n FROM events {w} GROUP BY logtype ORDER BY n DESC"),
                "by_port": q(f"SELECT port, count(*) n FROM events {w} GROUP BY port ORDER BY n DESC LIMIT 20"),
                "top_ips": top_ips, "brazil_bot": q(f"SELECT count(*) FROM events {aw} ip=?", BR)[0][0],
                "countries_by_events": [[c, ccmap.get(c, ""), n] for c, n in cty_ev.most_common(20)],
                "countries_by_ips": [[c, ccmap.get(c, ""), n] for c, n in cty_ip.most_common(20)], "n_countries": len(cty_ip),
                "days": sorted(days.items()), "era_days": {d: dict(v) for d, v in sorted(eradays.items())}, "hours": sorted(hours.items()),
                "login_attempts": login_attempts, "cowrie_login_ok": cw_ok, "cowrie_login_failed": cw_fail,
                "top_creds": creds, "ok_creds": ok_creds, "top_users": users, "top_passwords": pwds,
                "commands_total": sum(cmds.values()), "commands_unique": len(cmds), "top_commands": cmds.most_common(30),
                "downloads_total": dln, "malware": sorted(dl.values(), key=lambda x: -x["n"]), "top_urls": urls.most_common(15),
                "download_hosts": dlsrc.most_common(15)}
    for era in [None] + ERAS:
        db.execute("INSERT INTO meta VALUES (?, ?)", ("summary:" + (era or "all"), json.dumps(summary(era))))
    rep["seconds"] = round(time.time() - t0, 1)
    rep["stored"] = dict(db.execute("SELECT era, count(*) FROM events GROUP BY era").fetchall())
    rep["overlap_pre_vs_live"] = rep["files"].get("var/tmp/opencanary.log.snapshot-pre-cowrie", {}).get("overlap_live")
    db.execute("INSERT INTO meta VALUES ('admin', ?)", (json.dumps(admin),))
    db.execute("INSERT INTO meta VALUES ('report', ?)", (json.dumps(rep),))
    db.commit(); db.close(); os.replace(tmp, DB)
    print(json.dumps(rep, indent=1))

if __name__ == "__main__": main()
