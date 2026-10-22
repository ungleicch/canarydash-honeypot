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
  - `dashboard/` was the live-cache version. It polled over SSH at first, then switched to manual incremental pulls.
  - `dashboard/full/` is the offline full-dataset version. `ingest.py` builds SQLite from a full copy, and `server.py` serves it.
  - IP enrichment uses DB-IP Lite databases plus a cached ip-api.com lookup (`data/ipcache.json`).
- **Backups**: a daily `rsync` to the Mac (`data/backup-logs/`), plus manual full copies, which is what this repo is built from.

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
| 2026-10-19 | Pre-emptive memory restarts added to the watchdog. Restarts climbed to about 40–120 per day from 10-20 on. |
| 2026-10-21 20:37 | Last event in this dataset (full copy taken 20:39). |
