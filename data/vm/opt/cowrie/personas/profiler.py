#!/usr/bin/env python3
"""Profile Cowrie src_ips into persona tags. Writes ip_profiles.json."""
from __future__ import annotations

import json
import os
import tempfile
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path("/opt/cowrie/personas")
PROFILES = ROOT / "ip_profiles.json"
PERSONAS = ROOT / "personas.json"
COWRIE_LOG = Path("/opt/cowrie/cowrie/var/log/cowrie/cowrie.json")
MAX_IPS = 5000
LOOKBACK_BYTES = 8_000_000  # last ~8MB of log

IOT_CREDS = {
    "888888", "12345", "antslq", "juantech", "hg2x0", "xc3511", "vizxv",
    "admin", "default", "pass", "password", "7ujMko0vizxv", "7ujMko0admin",
    "smcadmin", "klv123", "klv1234", "jvbzd", "hi3518", "ikwb", "dreambox",
    "realtek", "00000000", "1111111", "54321", "zsun1188", "service",
    "firetide", "beardropper", "guest", "support", "user", "root",
}
IOT_USERS = {"root", "admin", "support", "user", "guest", "default", "ubnt", "supervisor"}


def load_profiles():
    if PROFILES.exists():
        try:
            return json.loads(PROFILES.read_text())
        except Exception:
            pass
    return {"updated": None, "ips": {}}


def score_events(events):
    score = {"iot": 0, "mips": 0, "miner": 0, "server": 0}
    evidence = []
    for e in events:
        eid = e.get("eventid", "")
        inp = (e.get("input") or "")
        low = inp.lower()
        user = (e.get("username") or "").lower()
        pw = (e.get("password") or "")

        if eid == "cowrie.login.success":
            if user in IOT_USERS and (pw in IOT_CREDS or user == pw):
                score["iot"] += 3
                evidence.append(f"cred:{user}:{pw[:12]}")
            elif user in ("ubuntu", "deploy", "www-data", "postgres", "mysql"):
                score["server"] += 2
                evidence.append(f"server-user:{user}")

        if eid != "cowrie.command.input":
            continue

        if "busybox" in low:
            score["iot"] += 4
            evidence.append("busybox")
        if "hostname pboc" in low or low.rstrip().endswith("pboc"):
            score["iot"] += 5
            evidence.append("PBOC")
        if "/.b" in low or " .b" in low or low.endswith(".b") or "echo >" in low and ".b" in low:
            score["iot"] += 3
            evidence.append(".b")
        if "sh .k" in low or low.strip() == "sh .k" or "/.k" in low:
            score["iot"] += 3
            evidence.append(".k")
        if "/.f" in low or " .f" in low:
            score["iot"] += 2
            evidence.append(".f")
        for tok in ("enable", "system", "shell", "linuxshell", "sh_enable"):
            if low.strip() == tok or low.startswith(tok + " "):
                score["iot"] += 2
                evidence.append(tok)
                break
        if "mips" in low:
            score["mips"] += 4
            evidence.append("mips-str")
        if any(x in low for x in ("hi3518", "armv7", "armv6", "/lib/ld-uclibc", "buildroot")):
            score["iot"] += 3
            evidence.append("arm-str")
        if any(x in low for x in ("xmrig", "minerd", "cpuminer", "nvidia-smi", "cuda", "stratum+tcp", "monero", "xmr-stak")):
            score["miner"] += 5
            evidence.append("miner")
        if any(x in low for x in ("apt-get", "systemctl", "docker", "kubectl", "nginx", "apache2")):
            score["server"] += 2
            evidence.append("linux-admin")
        if "uname" in low and ("-m" in low or "-a" in low):
            score["iot"] += 1  # weak; both check this
    return score, evidence[:20]


def pick_persona(score, evidence):
    # Explicit MIPS beats generic IoT
    if score["mips"] >= 3 and score["mips"] >= score["iot"] - 2:
        return "iot-mips"
    if score["miner"] >= 5 and score["miner"] > score["iot"]:
        return "miner"
    if score["iot"] >= 4:
        return "iot-arm"
    if score["server"] >= 3 and score["iot"] == 0:
        return "linux-server"
    return "linux-server"


def read_recent_events():
    if not COWRIE_LOG.exists():
        return []
    size = COWRIE_LOG.stat().st_size
    events = []
    with COWRIE_LOG.open("rb") as f:
        if size > LOOKBACK_BYTES:
            f.seek(size - LOOKBACK_BYTES)
            f.readline()  # skip partial
        for line in f:
            try:
                events.append(json.loads(line))
            except Exception:
                continue
    return events


def main():
    data = load_profiles()
    ips = data.setdefault("ips", {})
    by_ip = defaultdict(list)
    for e in read_recent_events():
        ip = e.get("src_ip")
        if not ip or ip.startswith("127.") or ip == "::1":
            continue
        eid = e.get("eventid", "")
        if eid in (
            "cowrie.command.input",
            "cowrie.login.success",
            "cowrie.login.failed",
            "cowrie.session.file_download",
            "cowrie.session.connect",
        ):
            by_ip[ip].append(e)

    changed = []
    for ip, evs in by_ip.items():
        score, evidence = score_events(evs)
        persona = pick_persona(score, evidence)
        prev = ips.get(ip, {})
        # Don't downgrade a strong IoT tag to server on a quiet window
        if prev.get("persona", "").startswith("iot") and persona == "linux-server":
            if prev.get("score", {}).get("iot", 0) >= 8:
                persona = prev["persona"]
                evidence = list(dict.fromkeys((prev.get("evidence") or []) + evidence))[:20]
        entry = {
            "persona": persona,
            "score": score,
            "evidence": evidence,
            "events_seen": len(evs),
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if prev.get("persona") != persona or not prev:
            changed.append((ip, prev.get("persona"), persona))
        # Preserve pinned flag
        if prev.get("pinned"):
            entry["persona"] = prev["persona"]
            entry["pinned"] = True
            entry["evidence"] = list(dict.fromkeys((prev.get("evidence") or []) + evidence))[:20]
        ips[ip] = entry

    # Cap map size: keep pinned + highest iot scores
    if len(ips) > MAX_IPS:
        items = sorted(
            ips.items(),
            key=lambda kv: (
                1 if kv[1].get("pinned") else 0,
                kv[1].get("score", {}).get("iot", 0) + kv[1].get("score", {}).get("miner", 0),
                kv[1].get("updated") or "",
            ),
            reverse=True,
        )
        ips = dict(items[:MAX_IPS])
        data["ips"] = ips

    data["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    data["persona_count"] = {}
    for e in ips.values():
        p = e.get("persona", "linux-server")
        data["persona_count"][p] = data["persona_count"].get(p, 0) + 1

    fd, tmp = tempfile.mkstemp(dir=str(ROOT), prefix=".ip_profiles.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, PROFILES)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise

    if changed:
        print(f"profiler: {len(changed)} persona changes; totals={data['persona_count']}")
    else:
        print(f"profiler: no changes; totals={data['persona_count']}")


if __name__ == "__main__":
    main()
