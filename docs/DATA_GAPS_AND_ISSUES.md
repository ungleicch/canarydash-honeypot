# Data gaps, drops and anomalies

All times are PT. The empirical numbers come from `events_per_hour_pt.csv` and `events_per_hour_pt.png`, computed over the whole range (2026-10-14 20:00 → 2026-10-23 16:00 PT, 212 hours).
An hour is "low" when it has under 10% of that source's median. The medians are 1,894 events/hour for OpenCanary and 14,567 for Cowrie. Cowrie counts are deduplicated across the live log, the rotated logs and the compressed copies.

## Known issues
| # | PT range | Issue | Cause | Impact on data |
|---|---|---|---|---|
| 1 | 10-14 20:51 → ~23:00 | OpenCanary-only period | Cowrie wasn't installed yet | There are no Cowrie sessions. SSH and Telnet appear only as OpenCanary banner hits (2,309 events in `opencanary.log.snapshot-pre-cowrie`). The 20:00 hour is partial and mostly startup messages. |
| 2 | 10-15 01:00 → 05:00 | Low Cowrie volume (479–1,200/h) | The first hours after the Cowrie launch, plus the 00:19 rate limit on the dominant Brazil bot | This is real reduced traffic, not lost data. |
| 3 | 10-15 ~09:00 → 11:06 | VM OOM freeze: 0 events in the 10:00 hour for both sources, and the 09:00 hour was low | Overlapping `snapshot.py`/`shipper.py` cron jobs ran out of memory | Events from about 1 hour are lost on both OpenCanary and Cowrie. |
| 4 | from 10-15 00:59 | D1 read limit, then the write limit (10-15 17:18) | Cloudflare D1 free-tier limits | The web dashboard showed KV snapshots of the newest 20k events, and the D1 archive lags with a queued backfill. **The raw VM logs (this repo) are unaffected.** |
| 5 | 10-16 ~10:20 → 10-17 ~16:00 | **Cowrie outage of about 30 hours**: 0 Cowrie events from 11:00 on 10-16 through 15:00 on 10-17 | Not logged. The native log ends at 10:20, and the converted `cowrie-canary.log` also stops at that time. There is no record of a crash. A hang or crash under memory pressure is likely, but the cause is **unknown**. The idle watchdog first appears afterwards (10-17 18:25). | Cowrie data for that window is lost. OpenCanary kept logging, but its 07:00, 11:00 and 14:00 hours on 10-16 were low (28, 93 and 140 events), cause **unknown**. |
| 6 | 10-17 → 10-23 | Cowrie watchdog restarts (892 logged: 12 on 10-18, 17 on 10-19, 119 on 10-20, 61 on 10-21, 222 on 10-22 and 461 on 10-23 UTC). 23 were for an idle log and 869 were pre-emptive because memory was above about 300 MB. | Cowrie's memory growth on a small VM | Each restart drops the live sessions and costs a few seconds to a minute of downtime. Expect truncated sessions and missing `session.closed` events. No hour drops below the threshold. |
| 7 | 10-15 → 10-18 13:54 | Old CanaryDash poller re-downloaded everything (about 387 GB of Azure egress) | A bug in the polling design | No data loss. It caused the Azure budget alert, and pulls became manual and incremental. |
| 8 | various | Mac offline | The laptop was asleep or away | The daily backups are missing or late on those days, so the `daily/` snapshots are uneven. The VM kept logging, so the full copy in this repo is complete. |
| 9 | each rotation | rsync code 24 ("vanished files") during the full copy, and code 23 in the daily backups | Cowrie rotated or compressed a log mid-copy (24). The 23s come from `Permission denied` on some capture files in `downloads/`. | No log data lost. The newest live files can differ slightly from `VM_COUNTS.txt`. |
| 10 | 10-18, 10-19 (and 10-16, 10-21) | Duplicate rotated Cowrie logs | Each day exists both as `cowrie.json.DATE` and as `cowrie.json.DATE.1.gz` | Without dedup, events get double-counted. 1,064,868 duplicate Cowrie events were removed in this analysis by (session, eventid, timestamp), leaving 4,407,232 unique events. The dashboard ingest also dedups. |
| 11 | entire range | `cowrie-canary.log` duplicates Cowrie | It's a converted copy of the same events, made by `cowrie_conv.py` | Don't add it to the `cowrie.json*` totals. |
| 12 | 10-15 on | Condensed Brazil port-scan events | These are snapshot and dashboard copies only | The raw logs are complete. Dashboard counts for 191.98.239.177 are lower than the raw counts. |

## Unexplained
- Low OpenCanary hours on 10-16 at 07:00, 11:00 and 14:00: **unknown**. There's no restart or startup message in those hours.
- The root cause of the 30-hour Cowrie outage on 10-16/10-17: **unknown**, and no journald logs are in the data.

## Not available in the data
There are no journald or syslog files and no VM boot records. OpenCanary startup messages (logtypes 1000–1002) mark its restarts, which happened at 10-14 20:00, 23:00, 10-15 00:00, 11:00 and 10-21 23:00.


**Cowrie hangs 10-17 17:53 → 10-19 09:00 PT (shaded on the hourly chart):** the sharp single-hour dips in the Cowrie line are honeypot-side. `/var/log/cowrie_watchdog.log` shows 21 "log idle" restarts in this window, each after ~1,760–2,075 s (~30 min) of a silent Cowrie log (e.g. 10-19 03:11→03:45, 05:27→06:00, 08:29→09:00 PT). In those minutes every attacker IP drops to zero at once, so it is a logging/service hang, not attacker behaviour. Events during the hangs were not recorded.

**Final partial hour:** the services were stopped at 2026-10-23 16:16 PT, so the 16:00 hour is omitted from the hourly charts (its events are still counted in all totals).
