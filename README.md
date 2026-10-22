# CanaryDash honeypot dataset + dashboard

Raw, **unredacted** logs from a class honeypot (Azure VM running OpenCanary, then Cowrie SSH/Telnet), with the local CanaryDash dashboard used to explore them.
Data covers **2026-10-15 03:51 PDT → 2026-10-21 20:37 PDT**.

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
| OpenCanary config, VM tooling scripts, watchdog/admin logs | `data/vm/etc/`, `data/vm/opt/canary-tools/`, `data/vm/var/log/` |
| Captured malware listing (names, sizes, hashes; no binaries) | `data/downloads_listing.txt` |
| Backup run logs, IP geo cache, VM vs local byte counts | `data/backup-logs/`, `data/ipcache.json`, `data/*_COUNTS.txt` |

Files over 20 MB were gzipped (`data/GZIPPED_FOR_REPO.txt`), and anything still over 95 MB was split into 90 MB `.partNN` chunks to fit GitHub's limit. To rejoin a split file, run `cat file.gz.part* | gunzip > file`.

## Run the dashboard locally
Requires Python 3 (standard library only).
```bash
./setup.sh      # rebuilds ./unpacked/vm and builds the SQLite index (takes a few minutes)
CANARY_FULL=$PWD/unpacked CANARY_DB=$PWD/unpacked/canarydash-full.sqlite CANARY_PORT=8790 python3 dashboard/full/server.py
# open http://127.0.0.1:8790
```
`dashboard/full/` is the offline full-dataset view. `dashboard/` (top level) is the live-cache version, which pulls from the VM over SSH and won't work without the VM.

## Excluded
- **Malware samples**: Cowrie `downloads/` and the `downloads_DO_NOT_RUN.tar.gz` archive. They are live MIPS/ARM/x86 malware, and GitHub doesn't allow them. Their hashes and URLs are still in the logs and in `downloads_listing.txt`.
- **Owner secrets**: the shipper config (`/etc/canary-shipper.json`, never copied), SSH keys, `.env` files, and the dashboard's online password file.
- **Derived or duplicate data**: `canarydash-full.sqlite` (3.7 GB, rebuilt by `setup.sh`), `daily/` backup snapshots (copies of the same logs), and `events.jsonl`/`poller-cache` (copies of the live logs).
- **DB-IP `.mmdb` geo databases**: the 127 MB file is over the size limit. They're free from db-ip.com (the Lite city/ASN versions).
