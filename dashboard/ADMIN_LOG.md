2026-10-15 00:19 PT: Rate-limited 191.98.239.177 (6 new conns/hour, burst 3) on VM via iptables; reboot-persistent via /etc/cron.d/softblock-br. Only this IP affected.
2026-10-15 00:24 PT: Extended rate limit on 191.98.239.177 to UDP (6/hour, burst 3).
2026-10-15 00:42 PT: Adaptive per-IP Cowrie personas live (iot-arm / iot-mips / linux-server / miner). Profiler every 5m at /opt/cowrie/personas/. 191.98.239.177 pinned iot-arm (Hi3518 BusyBox). Rate limit on that IP UNCHANGED. Verified: uname -m=armv7l, ARM cpuinfo, BusyBox v1.22.1, hostname IPC-HI3518.
2026-10-15 00:48 PDT: Enabled adaptive per-IP Cowrie personas (iot-arm, iot-mips, linux-server, miner). 191.98.239.177 pinned to iot-arm. Profiler every 5 min. Brazil rate limit unchanged.

## 2026-10-15 12:59 AM PT — Dashboard switched to snapshot serving
- Why: Cloudflare D1 free daily row-read limit exceeded (resets 5 PM PT); every D1 query returned 500.
- What: VM script `/opt/canary-tools/snapshot.py` (cron every 2 min, `/etc/cron.d/canary-snapshot`) builds the newest 20,000 events + geo from local logs, gzips (~1.2 MB) and POSTs to `/snapshot`; Worker stores it in KV namespace SNAP and serves `/api/events` + `/api/refresh` from it. Archive paused (`SNAPSHOT_ONLY=1`) until reset. Login lockout falls back to KV when D1 errors.
- Worker version: 607a6f35-085a-4f44-858e-60fb3eb36c77. Backups: `src/worker.pre-snapshot.js`, `wrangler.pre-snapshot.toml`.
- No data deleted; shipper keeps its position so the D1 backlog fills after the reset.
2026-10-15T18:12:10Z ADMIN VM froze from OOM (overlapping snapshot.py/shipper.py cron runs); restarted ~11:06 AM PT (2026-10-15 11:12 PT)
2026-10-15T18:12:10Z ADMIN Memory fix: snapshot.py v2 low-memory streaming (backup snapshot.pre-lowmem.py); flock + systemd MemoryMax=200M + nice on snapshot/shipper crons; sshd OOMScoreAdjust=-900 (2026-10-15 11:12 PT)
2026-10-15T18:12:10Z ADMIN Persona profiler cron fixed: logs to /var/log/cowrie-personas/profiler.log (cowrie-writable), flock added; manual run OK (2026-10-15 11:12 PT)
2026-10-15T18:12:10Z ADMIN Snapshot copy condenses 191.98.239.177 dropped/portscan events (logtype 5001) into a summary count; raw logs untouched (2026-10-15 11:12 PT)
2026-10-15T18:12:10Z ADMIN Azure blob lifecycle: canary-logs Cool tier after 7 days (no deletes) on <storage-account> (2026-10-15 11:12 PT)
2026-10-15T18:15:52Z ADMIN Shipper capped to 3MB of backlog per run to stop memory blowups (backup shipper.pre-lowmem.py) (2026-10-15 11:15 PT)
