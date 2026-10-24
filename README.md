# CanaryDash honeypot dataset + dashboard

Raw, **unredacted** logs from a university-class honeypot (a machine put online only to be attacked and recorded) (Azure VM running OpenCanary, then Cowrie SSH/Telnet), with the local CanaryDash dashboard used to explore them.
Data covers **2026-10-14 20:51 PDT → 2026-10-23 16:16 PDT**.

> The logs contain attacker IPs, credentials, commands, malware download URLs, SHA-256 hashes and filenames, and SSH public keys that attackers tried to plant. They also show the honeypot VM's own public IP (20.98.51.91). Do not run anything you find in here.

## Data sources (`data/`)
| Source | Path |
|---|---|
| Pre-Cowrie snapshot (OpenCanary only, before Cowrie went in) | `data/vm/var/tmp/opencanary.log.snapshot-pre-cowrie` |
| Live OpenCanary log | `data/vm/var/tmp/opencanary.log.gz` |
| Cowrie JSON logs (native, daily rotated) | `data/vm/opt/cowrie/cowrie/var/log/cowrie/cowrie.json*` |
| Cowrie events converted to OpenCanary format | `data/vm/var/tmp/cowrie-canary.log.gz.part00`, `.part01` (split, gzipped) |
| Cowrie TTY session recordings | `data/vm/opt/cowrie/cowrie/var/lib/cowrie/tty/` |
| Cowrie config, fake filesystem (honeyfs), adaptive personas | `data/vm/opt/cowrie/cowrie/etc/`, `data/vm/opt/cowrie/personas/` |
| OpenCanary/Cowrie config (reference text only), watchdog and admin logs | `data/vm/etc/`, `data/vm/opt/cowrie/cowrie/etc/*.reference.txt`, `data/vm/var/log/` |
| Captured malware listing (names, sizes, hashes; no binaries) | `data/downloads_listing.txt` |
| Backup run logs, IP geo cache, VM vs local byte counts | `data/backup-logs/`, `data/ipcache.json`, `data/*_COUNTS.txt` |

Files over 20 MB were gzipped (`data/GZIPPED_FOR_REPO.txt`), and anything still over 95 MB was split into 90 MB `.partNN` chunks to fit GitHub's limit. To rejoin a split file, run `cat file.gz.part* | gunzip > file`.

## Static archive: no live components
This repository is a **static, read-only, offline snapshot**. It doesn't connect to the honeypot, any cloud service or any remote URL. It has no refresh or pull features and no auto-reload, and there's no hosted version.

## View the dashboard locally
Requires Python 3 (standard library only).
```bash
python3 dashboard/full/server.py 8802      # port optional, default 8802
# open http://127.0.0.1:8802
```
- `/` shows the overview charts (precomputed in `dashboard/site/stats.json`) and all the docs, and needs no setup.
- `/#explore` is **Explore & query**, a query builder over the full dataset that runs on your own machine. It has:
  - filters for source, PT time range, IP/CIDR, protocol, event type, port, username, password, command, malware hash, URL, country, ASN, persona and session, each with an option to exclude matches;
  - an instant count of matching entries;
  - a chart builder (line, area, bar, stacked bar, pie, heatmap, scatter);
  - a sortable, paginated table with CSV export;
  - nine example queries.

  Every chart (Explore and the overview pages) has **PNG** and **Copy** buttons. They export the chart at 2x resolution on the current theme's background, with the title, active filters, PT time range and a footer.
  The current query is stored in the URL, so a link reopens the same view. It needs `./setup.sh`, which builds the indexed `unpacked/explore.sqlite`. The query endpoints (`/api/x/*`) are read-only, accept only whitelisted fields and fixed parameterized SQL, and stop any query after 15 s. This is **local querying of a static archive, not a live feed**.
- `/explorer` is an event-by-event browser. It needs the local SQLite index: run `./setup.sh` once, which unpacks the logs into `./unpacked` and builds the index.
- The chart and markdown libraries are vendored in `dashboard/site/vendor`, so there are no CDN requests.
- To regenerate the stats, run `python3 dashboard/build_stats.py unpacked/canarydash-full.sqlite`. Country and ASN charts need DB-IP Lite `.mmdb` files during ingest (not included).

## Excluded
- **Malware samples**: Cowrie `downloads/` and the `downloads_DO_NOT_RUN.tar.gz` archive. They are live MIPS/ARM/x86 malware, and GitHub doesn't allow them. Their hashes and URLs are still in the logs and in `downloads_listing.txt`.
- **Operational code**: shippers, uploaders, the watchdog, the profiler, poll/pull/refresh scripts, cron jobs and the cloud worker. They're described in prose in `docs/ADMIN_NOTES.md`.
- **Owner secrets**: the shipper config (`/etc/canary-shipper.json`, never copied), SSH keys, `.env` files, and the dashboard's online password file.
- **Derived or duplicate data**: `canarydash-full.sqlite` (3.7 GB, rebuilt by `setup.sh`), `daily/` backup snapshots (copies of the same logs), and `events.jsonl`/`poller-cache` (copies of the live logs).
- **DB-IP `.mmdb` geo databases**: the 127 MB file is over the size limit. They're free from db-ip.com (the Lite city/ASN versions).

## What "adaptive personas" means
Starting 2026-10-15 00:42 PT, the SSH/Telnet honeypot (Cowrie) shows each attacking IP address its own fake system. That can be an ARM camera, a MIPS router, an Ubuntu web server or a GPU miner, chosen every 5 minutes from what the IP did before. The same IP keeps seeing the same fake system. Bots that only infect matching hardware then go ahead and download their malware, so it can be captured. Every Cowrie session records its persona in a `cowrie.session.params` event. Details are in `docs/ADMIN_NOTES.md`.

## Docs
- `docs/TOP10_FINDINGS.md`: the ten most notable findings.
- `docs/GLOSSARY.md`: every custom term, tag, field and log message explained.
- `docs/ADMIN_NOTES.md`: architecture, config decisions, operating rules and timeline.
- `docs/DATA_GAPS_AND_ISSUES.md`: known gaps and anomalies, checked against the data. Hourly counts are in `docs/events_per_hour_pt.csv` and charted in `docs/events_per_hour_pt.png`.
