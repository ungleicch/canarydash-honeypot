"""IP enrichment: offline DB-IP Lite (city + ASN) with an ip-api.com batch fallback and a persistent cache."""
import datetime, gzip, ipaddress, json, os, shutil, threading, time, urllib.request
from pathlib import Path
import mmdb

HERE = Path(__file__).resolve().parent
DBDIR = HERE / "data"
DBS = {"city": DBDIR / "dbip-city-lite.mmdb", "asn": DBDIR / "dbip-asn-lite.mmdb"}
CLOUD_WORDS = ("amazon", "aws", "google", "microsoft", "azure", "alibaba", "aliyun", "tencent", "oracle",
               "digitalocean", "linode", "akamai", "vultr", "choopa", "hetzner", "ovh", "huawei", "ibm",
               "cloudflare", "scaleway", "upcloud")
HOSTING_WORDS = ("hosting", "host", "server", "datacenter", "data center", "vps", "colo", "contabo",
                 "leaseweb", "m247", "dedicated", "cdn", "proxy", "vpn")
HOME_WORDS = ("telecom", "telekom", "broadband", "cable", "mobile", "wireless", "cellular", "comcast",
              "verizon", "charter", "spectrum", "vodafone", "telefonica", "chinanet", "china unicom",
              "china mobile", "viettel", "airtel", "jio", "bsnl", "telmex", "claro", "rostelecom",
              "singtel", "optus", "telstra", "fiber", "fibre", "dsl", "residential", "isp")

class Geo:
    def __init__(self, cache_path):
        self.cache_path = Path(cache_path)
        self.cache = {}
        if self.cache_path.exists():
            try: self.cache = json.loads(self.cache_path.read_text())
            except ValueError: self.cache = {}
        self.readers = {}
        self.lock = threading.Lock()
        self.pending = set()
        self._open()
        threading.Thread(target=self._monthly, daemon=True).start()
        threading.Thread(target=self._ipapi_worker, daemon=True).start()

    def _open(self):
        r = {}
        for k, p in DBS.items():
            if p.exists():
                try: r[k] = mmdb.Reader(str(p))
                except Exception: pass
        self.readers = r

    # monthly refresh of the DB-IP files
    def _download(self):
        DBDIR.mkdir(exist_ok=True)
        today = datetime.date.today()
        months = [today.strftime("%Y-%m"), (today.replace(day=1) - datetime.timedelta(days=1)).strftime("%Y-%m")]
        for k, p in DBS.items():
            for m in months:
                url = f"https://download.db-ip.com/free/dbip-{k}-lite-{m}.mmdb.gz"
                try:
                    tmp = p.with_suffix(".tmp")
                    with urllib.request.urlopen(url, timeout=120) as resp, gzip.GzipFile(fileobj=resp) as gz, open(tmp, "wb") as out:
                        shutil.copyfileobj(gz, out)
                    os.replace(tmp, p); break
                except Exception:
                    continue
        with self.lock:
            self._open()

    def _monthly(self):
        while True:
            old = [p for p in DBS.values() if not p.exists() or time.time() - p.stat().st_mtime > 30 * 86400]
            if old: self._download()
            time.sleep(86400)

    def _ipapi_worker(self):
        # ip-api.com batch: free, no key, max 15 batch requests/min. Used for hosting/proxy hints and as fallback.
        while True:
            time.sleep(5)
            with self.lock:
                batch = list(self.pending)[:100]
            if not batch: continue
            try:
                req = urllib.request.Request("http://ip-api.com/batch?fields=status,query,countryCode,country,city,as,org,isp,proxy,hosting",
                                             data=json.dumps(batch).encode(), headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    res = json.load(r)
                with self.lock:
                    for x in res:
                        ip = x.get("query"); self.pending.discard(ip)
                        if x.get("status") == "success":
                            self.cache[ip] = {"t": time.time(), **{k: x.get(k) for k in ("countryCode", "country", "city", "as", "org", "isp", "proxy", "hosting")}}
                        else:
                            self.cache[ip] = {"t": time.time(), "fail": True}
                    self.cache_path.write_text(json.dumps(self.cache))
            except Exception:
                time.sleep(30)

    def lookup(self, ip):
        try: a = ipaddress.ip_address(ip)
        except ValueError: return None
        if a.is_private or a.is_loopback: return {"cc": "", "country": "Private network", "city": "", "asn": None, "org": "", "hint": ""}
        out = {"cc": "", "country": "", "city": "", "asn": None, "org": "", "hint": "", "source": ""}
        with self.lock:
            r = self.readers; c = self.cache.get(ip)
            if c is None: self.pending.add(ip)
        if "city" in r:
            d = r["city"].get(ip) or {}
            out["cc"] = d.get("country", {}).get("iso_code", "")
            out["country"] = d.get("country", {}).get("names", {}).get("en", "")
            out["city"] = d.get("city", {}).get("names", {}).get("en", "")
            out["source"] = "DB-IP"
        if "asn" in r:
            d = r["asn"].get(ip) or {}
            out["asn"] = d.get("autonomous_system_number"); out["org"] = d.get("autonomous_system_organization", "")
        if c and not c.get("fail"):
            if not out["cc"]:
                out.update(cc=c.get("countryCode") or "", country=c.get("country") or "", city=c.get("city") or "", source="ip-api")
            if not out["asn"] and c.get("as"):
                parts = c["as"].split(" ", 1); out["asn"] = int(parts[0][2:]) if parts[0][2:].isdigit() else None
                out["org"] = c.get("org") or c.get("isp") or (parts[1] if len(parts) > 1 else "")
            hints = [h for h, k in (("VPN or proxy", "proxy"), ("Hosting", "hosting")) if c.get(k)]
            out["hint"] = ", ".join(hints)
        if not out["hint"]:
            o = (out["org"] or "").lower()
            if any(w in o for w in CLOUD_WORDS): out["hint"] = "Cloud"
            elif any(w in o for w in HOSTING_WORDS): out["hint"] = "Hosting"
            elif any(w in o for w in HOME_WORDS): out["hint"] = "Home"
        # Prefer explicit Cloud/Hosting/Home labels; map older "Hosting"/"VPN or proxy" hints
        if out["hint"] in ("Likely hosting", "Hosting", "VPN or proxy"):
            o = (out["org"] or "").lower()
            if any(w in o for w in CLOUD_WORDS): out["hint"] = "Cloud"
            elif "VPN" in out["hint"] or "proxy" in out["hint"].lower(): out["hint"] = "Hosting"
            else: out["hint"] = "Hosting"
        return out
