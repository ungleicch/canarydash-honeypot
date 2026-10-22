# Glossary: terms, tags, fields and messages in this repo

This page explains everything specific to this setup that a newcomer might run into in the data or the dashboard. All times are Pacific (PT). Anything not confirmed from the code or logs is marked **unverified**.

## Basics
| Term | Meaning |
|---|---|
| Honeypot | A machine put online only to be attacked, so the attacks can be recorded. Any connection to it is suspicious by definition. |
| OpenCanary | A honeypot that imitates many services and logs each connection or login attempt as one JSON line with a numeric `logtype`. |
| Cowrie | An SSH/Telnet honeypot with a fake Linux shell. It logs JSON events with an `eventid` such as `cowrie.command.input`. |
| VM | The single Azure virtual machine running both honeypots. Its public IP is 20.98.51.91 and its private IP is 10.0.0.4, which shows up as `dst_ip`. |
| CanaryDash | The owner's local web dashboard, in `dashboard/`. |

## Data source labels (`era` in the dashboard, set by `dashboard/full/ingest.py`)
| Label | Meaning | Since |
|---|---|---|
| `pre-cowrie snapshot` | OpenCanary events from before Cowrie was installed, taken from `opencanary.log.snapshot-pre-cowrie`. Ports 22 and 23 were still OpenCanary banners then. | 10-14 20:51 → ~23:00 |
| `live opencanary` | Everything else from the live `opencanary.log` | the whole range |
| `cowrie` | Events from Cowrie's own `cowrie.json*` logs | 10-14 ~23:00 → |

## OpenCanary logtypes seen in this data (port taken from the events)
`1001` startup/status message (not attack traffic; marks a restart) · `2000` FTP login (21) · `3000`/`3001` HTTP request or login (80) · `4000`–`4002` SSH connection, version or login (22, OpenCanary era only) · `5001` port scan / dropped packet (from firewall logs) · `6001` Telnet login (23, OpenCanary era) · `8001` MySQL login (3306) · `10001` TFTP (69) · `11001` NTP (123) · `12001` VNC (5900) · `13001` SNMP (161) · `14001` RDP (3389) · `15001` SIP (5060) · `17001` Redis (6379).

## Custom (non-stock) items
| Item | Plain meaning | Introduced | How it affects reading the data |
|---|---|---|---|
| `cowrie-canary.log` and logtypes **30001–30016, 30099** | `canary-tools/cowrie_conv.py` copies Cowrie events into OpenCanary format with made-up logtypes: 30001 connect, 30002 login ok, 30003 login failed, 30004 command, 30005 command failed, 30006 download (including failed), 30007 upload, 30008 client version, 30009 key exchange, 30010 closed, 30011 TCP forwarding, 30012 terminal size, 30013 log closed, 30014 fingerprint, 30015 session params, 30016 client env, 30099 other. These events carry `node_id: "cowrie"`. | With Cowrie, ~10-14 23:00 | They duplicate `cowrie.json*`, so don't add both. The dashboard ignores `node_id=cowrie` lines with logtype < 30000 (`cowrie_node_lt30000`). |
| Adaptive personas / `persona`, `arch` fields | A fake identity for each attacker IP. See ADMIN_NOTES. | 10-15 00:42 | Shell outputs depend on the persona. |
| `ip_profiles.json` `score`, `evidence`, `pinned` | The profiler's per-IP scores, the keywords it matched, and a manual lock on the choice | 10-15 00:42 | Explains why an IP got a given persona. |
| honeyfs | Cowrie's fake filesystem (`cowrie/etc/honeyfs`). It was expanded by `improve_honeyfs.py` to look like a small Ubuntu web server named `web-prod-02`. | **unverified** date (10-14/15) | Files that attackers `cat` are fake. |
| Bait pages | Fake website files in honeyfs, such as `var/www/html/index.html` and an `admin/index.php` login form, for attackers who browse the filesystem | same as honeyfs | They're fake content, not real exposure. The form isn't served over HTTP by Cowrie (**unverified**). |
| `downloads_DO_NOT_RUN` / `downloads_listing.txt` | Cowrie's captured attacker payloads, named by SHA-256. The files are excluded here and only listed. Downloads are capped at 10 MB (`download_limit_size`). | 10-14 | Hashes appear in `cowrie.session.file_download` events (`shasum`, `url`, `outfile`). |
| tty / session recordings | Cowrie's replayable terminal recordings (`var/lib/cowrie/tty/`), linked from events by the `ttylog` field. They can be replayed with Cowrie's `playlog`. | 10-14 | They show exactly what the attacker saw. |
| HASSH (`hassh`, `hasshAlgorithms` in `cowrie.client.kex`) | A fingerprint of the SSH client's encryption settings, which identifies the client software. 15,768 events have one. JA4 (`cowrie.direct-tcpip.ja4`) is a similar fingerprint for TLS. | stock Cowrie | Use it to group bots that run the same software. |
| Memory watchdog restarts (`cowrie_watchdog.log`) | A cron job restarts Cowrie when its log has been idle for more than about 30 minutes (`log idle`) or its memory goes above about 300 MB (`preemptive mem=...`). | idle checks 10-17 18:25; memory checks around 10-19 | Each restart cuts live sessions short. See DATA_GAPS. |
| `ADMIN ...` lines (`honeypot-admin.log`) | A changelog the operator wrote on the VM. The dashboard shows these as markers. | 10-15 | They're notes, not attacks. |
| Soft rate limit / "Brazil bot" | iptables limits 191.98.239.177 to 6 new TCP and 6 UDP connections per hour | 10-15 00:19 / 00:24 | That IP's volume is artificially low after this. |
| Condensed port-scan summary | Snapshot and dashboard copies replace that IP's logtype-5001 events with a count | 10-15 11:12 | Raw logs have every event, and dashboard counts are lower. |
| Cloud / Hosting / Home hint (`hint`) | A guess from the IP's network name (ASN): known cloud brands → Cloud, words like "hosting" → Hosting, ISP or telecom words → Home | dashboard | It's a keyword guess, not verified. |
| Test IPs (`test`) | The operator's own test connections, which can be hidden with "hide test" | dashboard | Exclude them from analysis. |
| Archive view / raised cap | The dashboard loads the newest 100,000 events first (`CANARY_INITIAL`). "Archive" pages back in batches of up to 50,000 (`/api/archive`). | dashboard | The first view doesn't show everything. Page back through the archive or query SQLite directly. |
| Cloudflare snapshot / KV | A cloud dashboard (not in this repo) showed a gzipped "newest 20k events" snapshot posted every 2 minutes by `snapshot.py` | 10-15 00:59 | It only affected the cloud view. |
| D1 queue / backfill | `shipper.py` sent events to a Cloudflare D1 database. After free-tier read and write limits were hit, it soft-exits and resumes from its saved position later. | 10-15 / 10-16 | Cloud copies lag behind, and the raw logs here are complete. |
| `.uploaded` files | Empty markers meaning that rotated log was archived to cloud storage | 10-15 → | No data in them. |
| `.DATE` vs `.DATE.1.gz` | The same rotated day stored both uncompressed and compressed | 10-16, 10-18, 10-19, 10-21 | Dedup before counting. |
| Incremental refresh / pull | Copying only the bytes added since the last pull from the VM, started by hand | 10-18 13:54 | Explains how this copy was made. |
| `VM_COUNTS.txt` / `LOCAL_COUNTS.txt` | Bytes, lines and path for each file on the VM vs this copy | at copy time | Live files can differ slightly (rsync code 24). |
| `.bak*`, `.pre-*` files | Earlier versions of scripts kept before each change | various | Useful history, not active code. |
