# Admin notes: setup, architecture, decisions, timeline

All times are Pacific (PT) unless marked Z (UTC). Secrets, account names, emails and subscription IDs have been removed.

## Architecture
- **Honeypot VM**: a small Azure VM (Azure for Students credit, no pay-as-you-go) with public IP 20.98.51.91 and private IP 10.0.0.4, which appears as `dst_ip` in the Cowrie logs. The real admin SSH runs on a non-standard port that only accepts keys.
- **OpenCanary** (`/etc/opencanaryd/opencanary.conf`) runs the low-interaction services: FTP, HTTP, Telnet/SSH banners, port-scan detection and others. It logs to `/var/tmp/opencanary.log`.
- **Cowrie** (`/opt/cowrie/cowrie`) runs the medium-interaction SSH (22) and Telnet (23) honeypot. It logs JSON to `var/log/cowrie/cowrie.json*`, stores session recordings in `var/lib/cowrie/tty/`, and captures payloads in `downloads/` (not in this repo).
  - The fake filesystem (`etc/honeyfs`) was made more convincing by `canary-tools/improve_honeyfs.py`, which added bait pages and files.
  - **Adaptive personas** (`/opt/cowrie/personas`): each attacking IP gets a fake device (iot-arm, iot-mips, linux-server or miner) based on its earlier behavior. A profiler re-scores IPs every 5 minutes.
- **`canary-tools/cowrie_conv.py`** converts Cowrie events into OpenCanary format and writes them to `/var/tmp/cowrie-canary.log`, so one pipeline can read both.
- **Cloud pipeline (retired as a primary path)**: `shipper.py` sent batches to a Cloudflare Worker backed by D1 on the free tier. `snapshot.py` posted a gzipped snapshot of the newest 20k events to the Worker, which stored it in KV. `upload_*.sh` and `blob_put.sh` archived rotated logs to Azure Blob using the VM's managed identity, with a lifecycle rule moving them to the Cool tier after 7 days and no deletes.
- **Local CanaryDash** (`dashboard/`): a Python standard-library dashboard on the owner's Mac.
  - The live version (not in this repo) polled the VM over SSH at first, then switched to manual incremental pulls.
  - This repo contains only a static, read-only version (`dashboard/site` and `dashboard/full`).
  - `dashboard/full/` is the offline full-dataset version. `ingest.py` builds SQLite from a full copy, and `server.py` serves it.
  - IP enrichment uses DB-IP Lite databases plus a cached ip-api.com lookup (`data/ipcache.json`).
- **Backups**: a daily `rsync` to the Mac (`data/backup-logs/`), plus manual full copies, which is what this repo is built from.

## Operational components (described here, not included)
This archive deliberately contains **no runnable operational code**. On the live system the following existed:
- **Shipper** (`shipper.py`, several revisions): ran from cron on the VM. It read new log lines and posted them in batches to a Cloudflare Worker, which stored them in D1. It kept a saved file position, and soft-exited on free-tier limit errors so the backlog could be sent later.
- **Snapshot builder** (`snapshot.py`): ran from cron every 2 minutes. It streamed the newest 20,000 events plus geo data, gzipped them, and posted them to the Worker's KV store for the cloud dashboard.
- **Blob uploaders** (`upload_cowrie.sh`, `upload_rotated.sh`, `blob_put.sh`): archived rotated logs to Azure Blob Storage using the VM's managed identity, and wrote empty `.uploaded` marker files.
- **Log converter** (`cowrie_conv.py`): wrote `cowrie-canary.log` (see the glossary).
- **Cowrie watchdog** (`cowrie_watchdog.sh`): ran from cron. It restarted Cowrie when the log was idle or memory went above about 300 MB.
- **Persona profiler** (`personas/profiler.py`): ran from cron every 5 minutes. Its logic is summarized below.
- **honeyfs builder** (`improve_honeyfs.py`): a one-time script that wrote the fake filesystem files that *are* included.
- **Cloudflare Worker, D1 and KV**: a password-protected web dashboard and archive.
- **Mac-side tools**: a poller (later disabled), manual incremental pull and refresh scripts, a daily rsync backup job, and restart scripts.
- **Cron and systemd units** for the above, plus iptables rules for the rate limit.

Cowrie and OpenCanary configs are kept only as reference text (`*.reference.txt`).

## Operating rules
- **No hack-back.** Attackers are only observed, never attacked, scanned back or contacted. Captured malware is never run.
- **Keep all data.** Raw logs are never wiped or truncated, and dedup and condensing happen only in derived copies. Cloud rows are never deleted without the owner's OK.
- **Free tiers and student credit only.** Never upgrade Cloudflare and never use real money, so hitting a limit means degrading gracefully.
- **The honeypot runs 24/7.** The owner's machines never pull data automatically; pulls are manual and incremental.

## Config decisions
- A single Brazilian bot (191.98.239.177) flooded about 3,200 events. Instead of blocking it, it was soft rate-limited with iptables hashlimit (6 new TCP and 6 UDP connections per hour, burst 3) and pinned to the iot-arm persona.
- Cowrie's download size cap is 10 MB.
- The snapshot copy condenses that bot's dropped/port-scan events (logtype 5001) into a count. The raw logs are untouched.
- Cron jobs are memory-capped (flock, systemd MemoryMax=200M, nice), and sshd is protected from the OOM killer.
- A Cowrie watchdog restarts Cowrie when its log is idle for more than about 30 minutes, or pre-emptively when its memory goes above about 300 MB.

## Timeline
| When (PT) | Change |
|---|---|
| 2026-10-14 ~20:51 | OpenCanary logging begins. The earliest events are in the pre-Cowrie snapshot. |
| 2026-10-14 ~23:00 | Cowrie installed on 22/23. The OpenCanary log was snapshotted first (`opencanary.log.snapshot-pre-cowrie`). |
| 2026-10-15 00:19–00:24 | Rate limit applied to 191.98.239.177 (TCP, then UDP). |
| 2026-10-15 00:42–00:48 | Adaptive personas enabled. |
| 2026-10-15 00:59 | Cloudflare D1 free daily read limit exceeded, so the web dashboard switched to serving KV snapshots and archiving to D1 paused until the reset. |
| 2026-10-15 ~10:00–11:06 | VM froze from OOM caused by overlapping snapshot/shipper cron jobs. It was restarted, and memory limits and low-memory streaming were added. |
| 2026-10-15 11:15 | Shipper capped at 3 MB of backlog per run. |
| 2026-10-15 17:15–17:18 | After the D1 reset, the Worker threw error 1101 on large batches, so the chunk size went from 200 to 25. The D1 free daily write limit was then hit too, so the shipper soft-exits and the backlog is queued. |
| 2026-10-16 ~10:20 → 2026-10-17 ~16:00 | Cowrie produced no events (see the data-gaps doc). |
| 2026-10-17 ~18:25 | First entry in the Cowrie watchdog log (idle-log restarts). |
| 2026-10-15 → 2026-10-18 13:54 | The old Mac CanaryDash poller kept re-downloading the full logs (about 387 GB of egress, which pushed the Azure budget alert past $20). It was killed, and pulls became manual and incremental. |
| 2026-10-19 | Pre-emptive memory restarts added to the watchdog. Restarts climbed to 119 on 10-20, 222 on 10-22 and 461 on 10-23 (UTC days). |
| 2026-10-23 16:16 | Services stopped and final full copy taken; last event in this dataset. The Azure VM and storage and the hosted dashboard were then removed. |

## Adaptive personas (in detail)
**Terms.** A *honeypot* is a computer put on the internet only to be attacked, so the attacks can be recorded. *OpenCanary* is a honeypot that imitates many network services (FTP, web, databases and so on) and logs each attempt. *Cowrie* imitates an SSH/Telnet login and a Linux shell, and it records the attacker's commands and downloaded files. A *persona* is the fake identity the fake shell shows: its hostname, CPU type, kernel version, BusyBox banner and certain files.

**What it is.** Normally Cowrie shows every visitor the same fake machine. With adaptive personas, each attacking IP address gets the fake machine that best matches what it seems to be looking for. That IP then keeps the same persona across its later sessions.

**When it was enabled.** 2026-10-15 at 00:42 PT, per `data/vm/var/log/honeypot-admin.log`. A second log line at 00:48 PT records the same change again.

**Personas** (from `data/vm/opt/cowrie/personas/personas.json`):
| id | Hostname | Looks like | Arch / kernel | Shell / BusyBox |
|---|---|---|---|---|
| iot-arm | IPC-HI3518 | Hi3518 ARM IP camera or DVR | armv7l, Linux 3.4.35 | /bin/sh, BusyBox v1.22.1 |
| iot-mips | Router-MIPS | MIPS home router | mips, Linux 2.6.36 | /bin/sh, BusyBox v1.19.4 |
| linux-server (default) | web-prod-02 | Ubuntu 22.04 web server | x86_64, 5.15.0-122 | /bin/bash |
| miner | gpu-node-07 | x86_64 host that looks GPU-capable | x86_64, 5.15.0-105 | /bin/bash |

The IoT and miner personas also add overlay files under `personas/honeyfs/<id>/` (`etc/`, `proc/`, for example a fake `/proc/cpuinfo`).

**How IPs get tagged** (by the profiler script, which ran every 5 minutes from cron and is not included in this repo):
1. It reads recent Cowrie connect, login, command and download events and groups them by source IP.
2. It scores each IP with keyword rules. Signals of a Mirai-style IoT bot are BusyBox, `enable`/`system`/`shell`, typical IoT default passwords and IoT usernames. MIPS strings point to a MIPS router. Miner signals are xmrig, nvidia-smi, `stratum+tcp` and monero. Admin-like commands count toward the server persona.
3. It picks a persona. A MIPS score of 3 or more wins first, then a miner score of 5 or more, then an IoT score of 4 or more gives iot-arm. Anything else gets linux-server.
4. An IP already tagged as IoT with an IoT score of 8 or more is not moved back to linux-server during a quiet period. A `pinned: true` entry is never changed.
5. The results go in `personas/ip_profiles.json`, along with the evidence for each choice. The map size is capped, keeping pinned entries and the highest IoT/miner scores. The copy in this repo has 1,010 IPs: 666 linux-server and 344 iot-arm. One IP is pinned: 191.98.239.177, set to iot-arm.

**What changes for the attacker.** Commands like `uname`, `busybox`, `hostname` and `cat /proc/cpuinfo` return the persona's values. On 2026-10-15 a check of an iot-arm session returned `uname -m` = armv7l, an ARM cpuinfo, BusyBox v1.22.1 and hostname IPC-HI3518. Each session logs a `cowrie.session.params` event with `persona=<id>` (and `arch`).
The Cowrie source patches that apply the persona (`persona_loader.py` and changes to `shell/realm.py`, `shell/server.py`, `commands/uname.py`, `commands/busybox.py` and `shell/protocol.py`) are **not included in this repo**. They are described here only.

**Why.** IoT botnets usually check the CPU architecture before downloading a payload built for it. A plain x86 web server makes many of them give up, while a matching fake device makes them download their malware, which gets captured (capped at 10 MB and never run).

**Effect on the data.** Counts are deduplicated Cowrie events. Personas were enabled about 45 minutes after Cowrie started, so the "before" window is short, and traffic kept changing over the week. This is a correlation, not proof of cause.
| | Before (to 10-15 00:42 PT) | After |
|---|---|---|
| Sessions (`session.connect`) | 286 | 233,474 |
| Commands | 11,987 | 1,946,724 |
| File downloads (`session.file_download`) | **0** | **106,944** |
| `session.params` events by persona | (none) | iot-arm 201,001; linux-server 3,929 |

From 10-15 00:42 PT on, the fake system an attacker sees depends on its IP. So read commands and outputs together with that session's `persona` field.
