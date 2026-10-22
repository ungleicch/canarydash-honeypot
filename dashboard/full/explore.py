"""Read-only query API for the Explore page. Whitelisted fields/ops, parameterized SQL only, time and row caps.
Runs against unpacked/explore.sqlite (built by build_query_index.py). Local only; not a live feed."""
import sqlite3, json, time, ipaddress, csv, io, os
EXPLORE_DB = os.path.expanduser(os.environ.get("CANARY_EXPLORE_DB") or os.path.join(os.path.dirname(os.path.expanduser(os.environ.get("CANARY_DB", "unpacked/canarydash-full.sqlite"))), "explore.sqlite"))
TZ_MS = 7 * 3600 * 1000          # whole dataset is in PDT (UTC-7); DST ended after the data range
TIMEOUT_S = 15; MAX_PAGE = 500; MAX_CSV = 200000; MAX_GROUPS = 2000
EQ = {"era": "era", "proto": "proto", "eventid": "eventid", "port": "port", "usr": "usr", "pwd": "pwd", "sess": "sess",
      "country": "country", "persona": "persona", "hash": "hash"}
LIKE = {"cmd": "cmd", "hash_like": "hash", "url": "url", "asn": "asn", "usr_like": "usr", "pwd_like": "pwd"}
COLS = ["ts", "era", "ip", "eventid", "proto", "port", "usr", "pwd", "sess", "cmd", "hash", "url", "country", "asn", "persona"]
GROUP = {"minute": f"((ts-{TZ_MS})/60000)*60000+{TZ_MS}", "hour": f"((ts-{TZ_MS})/3600000)*3600000+{TZ_MS}", "day": f"((ts-{TZ_MS})/86400000)*86400000+{TZ_MS}",
         "hourofday": f"((ts-{TZ_MS})/3600000)%24", "weekday": f"(((ts-{TZ_MS})/86400000)+3)%7",   # 0=Mon (1970-01-01 was Thu)
         "ip": "ip", "country": "country", "asn": "asn", "port": "port", "usr": "usr", "pwd": "pwd", "cmd": "cmd", "hash": "hash",
         "eventid": "eventid", "era": "era", "proto": "proto", "persona": "persona", "sess": "sess", "url": "url"}
TIMEX = {"minute", "hour", "day", "hourofday", "weekday"}
METRIC = {"events": "COUNT(*)", "ips": "COUNT(DISTINCT ip)", "sessions": "COUNT(DISTINCT sess)",
          "downloads": "SUM(eventid='cowrie.session.file_download')"}

class QErr(Exception): pass

def conn():
    if not os.path.exists(EXPLORE_DB): raise QErr("explore.sqlite not found; run ./setup.sh")
    c = sqlite3.connect(f"file:{EXPLORE_DB}?mode=ro", uri=True, check_same_thread=False)
    dl = time.time() + TIMEOUT_S
    c.set_progress_handler(lambda: 1 if time.time() > dl else 0, 20000)
    return c

def _list(v):
    if v is None or v == "": return []
    if isinstance(v, list): return [str(x).strip() for x in v if str(x).strip() != ""]
    return [x.strip() for x in str(v).replace("\n", ",").split(",") if x.strip()]

def where(f):
    """f: {field: value(s), ..., "not": [fields to exclude], "from": ms, "to": ms}. All conditions AND-combined."""
    if not isinstance(f, dict): raise QErr("filters must be an object")
    neg = set(f.get("not") or []); parts, args = [], []
    def add(field, sql, a):
        if field in neg: parts.append(f"NOT COALESCE({sql},0)")
        else: parts.append(sql)
        args.extend(a)
    if f.get("from") not in (None, ""): parts.append("ts >= ?"); args.append(int(f["from"]))
    if f.get("to") not in (None, ""): parts.append("ts < ?"); args.append(int(f["to"]))
    for k, col in EQ.items():
        vals = _list(f.get(k))
        if not vals: continue
        if k == "port":
            try: vals = [int(v) for v in vals]
            except ValueError: raise QErr("port must be numeric")
        if k in ("usr", "pwd"): vals = ["" if v == "(empty)" else v for v in vals]
        add(k, f"{col} IN ({','.join('?' * len(vals))})", vals)
    for k, col in LIKE.items():
        v = f.get(k)
        if v in (None, ""): continue
        v = str(v).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        add(k, f"{col} LIKE ? ESCAPE '\\'", [f"%{v}%"])
    ips = _list(f.get("ip"))
    if ips:
        sub, a = [], []
        for x in ips:
            try:
                if "/" in x:
                    n = ipaddress.ip_network(x, strict=False)
                    if n.version != 4: raise QErr("CIDR filters support IPv4 only")
                    sub.append("ipn BETWEEN ? AND ?"); a += [int(n.network_address), int(n.broadcast_address)]
                else:
                    ipaddress.ip_address(x); sub.append("ip = ?"); a.append(x)
            except ValueError: raise QErr(f"bad IP/CIDR: {x}")
        add("ip", "(" + " OR ".join(sub) + ")", a)
    return (" WHERE " + " AND ".join(parts)) if parts else "", args

def run(c, sql, args):
    t = time.time()
    try: rows = c.execute(sql, args).fetchall()
    except sqlite3.OperationalError as e:
        if "interrupt" in str(e): raise QErr(f"query exceeded {TIMEOUT_S}s; narrow the filters")
        raise QErr(str(e))
    return rows, round((time.time() - t) * 1000)

def count(f):
    w, a = where(f); c = conn()
    rows, ms = run(c, f"SELECT COUNT(*), COUNT(DISTINCT ip), MIN(ts), MAX(ts) FROM ev{w}", a)
    n, ips, lo, hi = rows[0]
    return {"count": n, "ips": ips, "first_ts": lo, "last_ts": hi, "ms": ms}

def rows(f, sort="ts", direction="desc", page=0, size=100):
    if sort not in COLS: raise QErr("bad sort field")
    d = "ASC" if direction == "asc" else "DESC"; size = max(1, min(MAX_PAGE, int(size))); page = max(0, int(page))
    w, a = where(f); c = conn()
    r, ms = run(c, f"SELECT {','.join(COLS)} FROM ev{w} ORDER BY {sort} {d} LIMIT ? OFFSET ?", a + [size, page * size])
    return {"cols": COLS, "rows": r, "page": page, "size": size, "ms": ms}

def to_csv(f, sort="ts", direction="asc"):
    if sort not in COLS: raise QErr("bad sort field")
    w, a = where(f); c = conn(); d = "ASC" if direction == "asc" else "DESC"
    r, _ = run(c, f"SELECT {','.join(COLS)} FROM ev{w} ORDER BY {sort} {d} LIMIT ?", a + [MAX_CSV])
    b = io.StringIO(); wr = csv.writer(b); wr.writerow(COLS); wr.writerows(r); return b.getvalue()

def agg(f, x="hour", y="events", split="", top=20):
    if x not in GROUP or y not in METRIC or (split and split not in GROUP): raise QErr("bad x/y/split")
    top = max(1, min(200, int(top or 20))); w, a = where(f); c = conn(); gx = GROUP[x]; m = METRIC[y]
    order = "ORDER BY gx" if x in TIMEX else "ORDER BY v DESC"
    lim = MAX_GROUPS if x in TIMEX else top
    if x not in TIMEX: w2 = (w + " AND " if w else " WHERE ") + f"{gx} IS NOT NULL"
    else: w2 = w
    if not split:
        r, ms = run(c, f"SELECT {gx} AS gx, {m} AS v FROM ev{w2} GROUP BY gx {order} LIMIT ?", a + [lim])
        return {"x": x, "y": y, "series": [{"name": y, "points": r}], "ms": ms}
    gs = GROUP[split]; ws = (w2 + " AND " if w2 else " WHERE ") + f"{gs} IS NOT NULL"
    nser = min(top, 12) if x not in TIMEX or split not in TIMEX else 24
    tops, ms1 = run(c, f"SELECT {gs} AS s, {m} AS v FROM ev{ws} GROUP BY s ORDER BY v DESC LIMIT ?", a + [nser])
    names = [t[0] for t in tops]
    if not names: return {"x": x, "y": y, "series": [], "ms": ms1}
    r, ms2 = run(c, f"SELECT {gx} AS gx, {gs} AS s, {m} AS v FROM ev{ws} AND {gs} IN ({','.join('?' * len(names))}) GROUP BY gx, s",
                 a + names)
    by = {n: [] for n in names}
    for gxv, s, v in r: by[s].append((gxv, v))
    if x not in TIMEX:   # keep top-N x categories by total
        tot = {}
        for pts in by.values():
            for k, v in pts: tot[k] = tot.get(k, 0) + (v or 0)
        keep = set(sorted(tot, key=lambda k: -tot[k])[:top]); by = {n: [p for p in pts if p[0] in keep] for n, pts in by.items()}
    return {"x": x, "y": y, "split": split, "series": [{"name": n, "points": sorted(by[n], key=lambda p: (p[0] is None, p[0]))} for n in names], "ms": ms1 + ms2}

def meta():
    c = conn(); out = {}
    for col in ("era", "eventid", "proto", "persona"):
        out[col] = [r[0] for r in c.execute(f"SELECT {col}, COUNT(*) n FROM ev WHERE {col} IS NOT NULL GROUP BY 1 ORDER BY n DESC")]
    out["country"] = [r[0] for r in c.execute("SELECT country, COUNT(*) n FROM ev WHERE country IS NOT NULL GROUP BY 1 ORDER BY n DESC LIMIT 300")]
    out["port"] = [r[0] for r in c.execute("SELECT port, COUNT(*) n FROM ev WHERE port IS NOT NULL GROUP BY 1 ORDER BY n DESC LIMIT 60")]
    out["range"] = list(c.execute("SELECT MIN(ts), MAX(ts), COUNT(*) FROM ev").fetchone())
    return out

def handle(p, q):
    """Returns (body, content_type). p like /api/x/count; q = query dict with 'f' JSON."""
    f = json.loads(q.get("f") or "{}")
    if p == "/api/x/meta": return json.dumps(meta()), "application/json"
    if p == "/api/x/count": return json.dumps(count(f)), "application/json"
    if p == "/api/x/rows": return json.dumps(rows(f, q.get("sort", "ts"), q.get("dir", "desc"), q.get("page", 0), q.get("size", 100))), "application/json"
    if p == "/api/x/agg": return json.dumps(agg(f, q.get("x", "hour"), q.get("y", "events"), q.get("split", ""), q.get("top", 20))), "application/json"
    if p == "/api/x/csv": return to_csv(f, q.get("sort", "ts"), q.get("dir", "asc")), "text/csv; charset=utf-8"
    raise QErr("unknown endpoint")
