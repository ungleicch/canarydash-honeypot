#!/usr/bin/env python3
"""Converts new Cowrie JSON events into OpenCanary-style lines appended to /var/tmp/cowrie-canary.log.
Cowrie logs are never modified. Run before shipper.py (cron)."""
import glob, json, os, datetime
SRC = "/opt/cowrie/cowrie/var/log/cowrie/cowrie.json"
OUT = "/var/tmp/cowrie-canary.log"
STATE = "/var/lib/canary-shipper/cowrie_state.json"
CODES = {"cowrie.session.connect": 30001, "cowrie.login.success": 30002, "cowrie.login.failed": 30003,
         "cowrie.command.input": 30004, "cowrie.command.failed": 30005, "cowrie.session.file_download": 30006,
         "cowrie.session.file_download.failed": 30006, "cowrie.session.file_upload": 30007,
         "cowrie.client.version": 30008, "cowrie.client.kex": 30009, "cowrie.session.closed": 30010,
         "cowrie.direct-tcpip.request": 30011, "cowrie.direct-tcpip.data": 30011, "cowrie.client.size": 30012,
         "cowrie.log.closed": 30013, "cowrie.client.fingerprint": 30014, "cowrie.session.params": 30015,
         "cowrie.client.var": 30016}
SKIP = {"src_ip", "src_port", "dst_ip", "dst_port", "timestamp", "sensor", "eventid", "session", "message"}
os.makedirs(os.path.dirname(STATE), exist_ok=True)
st = json.load(open(STATE)) if os.path.exists(STATE) else {"ino": None, "offset": 0}
proto = {}
def conv(l):
    try: e = json.loads(l)
    except ValueError: return None
    ev = e.get("eventid", "")
    t = e.get("timestamp", "")
    try: t = datetime.datetime.fromisoformat(t.replace("Z", "+00:00")).astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    except Exception: pass
    sid = e.get("session", "")
    if ev == "cowrie.session.connect": proto[sid] = e.get("protocol", "ssh")
    d = {k: v for k, v in e.items() if k not in SKIP}
    d["eventid"] = ev; d["message"] = e.get("message", "")
    return {"logtype": CODES.get(ev, 30099), "node_id": "cowrie", "source": "cowrie", "session": sid,
            "proto": e.get("protocol") or proto.get(sid) or ("telnet" if e.get("dst_port") == 23 else "ssh"),
            "src_host": e.get("src_ip", ""), "src_port": e.get("src_port", -1), "dst_host": e.get("dst_ip", ""),
            "dst_port": e.get("dst_port", -1), "utc_time": t, "local_time": t, "logdata": d}
def read(path, off):
    with open(path, "rb") as f:
        f.seek(off); data = f.read()
    end = data.rfind(b"\n") + 1
    return data[:end].decode("utf-8", "replace").splitlines(), off + end
lines = []
if not os.path.exists(SRC): raise SystemExit(0)
s = os.stat(SRC)
if st["ino"] and st["ino"] != s.st_ino:  # rotated: finish the old file
    for f in glob.glob(SRC + ".*"):
        if os.stat(f).st_ino == st["ino"]:
            ls, _ = read(f, st["offset"]); lines += ls
    st["offset"] = 0
if s.st_size < st["offset"]: st["offset"] = 0
st["ino"] = s.st_ino
ls, st["offset"] = read(SRC, st["offset"]); lines += ls
out = [json.dumps(c, sort_keys=True) for c in map(conv, lines) if c]
if out:
    with open(OUT, "a") as f: f.write("\n".join(out) + "\n")
json.dump(st, open(STATE, "w"))
print("converted", len(out))
