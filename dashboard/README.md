# CanaryDash

A local dashboard for the OpenCanary honeypot (20.98.51.91). It uses only the Python standard library, runs only on this Mac, and uses no Azure credit.

- URL: http://127.0.0.1:8793
- Data: every 60 seconds it pulls `/var/tmp/opencanary.log` plus the rotated `.gz` logs over SSH (`~/.ssh/opencanary_key`, port 2222). New events are appended without duplicates to `~/CanaryBackups/events.jsonl`, which keeps your own copy long term.
- The Refresh button pulls right away. OpenCanary's own startup messages are hidden. My test IPs are tagged "test" and can be hidden.

## Start, stop, restart
    screen -dmS canarydash python3 ~/Developer/CanaryDash/server.py   # start
    screen -r canarydash                                                # look at it (Ctrl A then D to leave)
    screen -S canarydash -X quit                                        # stop
    ~/Developer/CanaryDash/restart.sh                                   # restart

It doesn't start on its own after a reboot. Run restart.sh again.
Settings via env vars: CANARY_PORT, CANARY_DATA, CANARY_HOST, CANARY_KEY, CANARY_TEST_IPS.

## IP enrichment
- Offline lookups use DB-IP Lite City and ASN (CC BY 4.0) in `data/`, read by the pure-Python `mmdb.py`. They're redownloaded automatically when older than 30 days.
- ip-api.com batch fallback (adds hosting and VPN hints), cached in `~/CanaryBackups/ipcache.json`. If ip-api can't be reached, a "Likely hosting" hint is guessed from the network name instead.
- Click any IP to see its details. There are charts of country and service over time, with tooltips on hover.
