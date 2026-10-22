# CanaryDash, local full dataset (offline)

http://127.0.0.1:8790  (screen session `canarydash-full`; the older OpenCanary-only dashboard stays on :8793)

- Data copy: `~/CanaryBackups/full-latest` (symlink to `full-<YYYYMMDD-HHMM>`). `vm/` mirrors the VM paths exactly.
  Malware is only inside `malware/downloads_DO_NOT_RUN.tar.gz`. Never extract or run it.
- Database: `~/CanaryBackups/canarydash-full.sqlite`, rebuilt from scratch by `ingest.py` (about 30 s).
- Every event has a source/era: `live opencanary`, `pre-cowrie snapshot`, `cowrie`. Pre-cowrie snapshot lines that are also
  in opencanary.log (same utc_time+src_host+dst_port+logtype) are stored once, labelled `pre-cowrie snapshot`.
  The overlap count is shown in the Full dataset card and in `/api/report`.
- All events are included, including the Brazil bot 191.98.239.177 that the online shipper skips.
- Countries/ASNs: offline DB-IP Lite (`../data/*.mmdb`), no web lookups.

Commands
    ./refresh.sh        # pull from the VM (read-only) + re-ingest; the page picks it up on its next refresh
    ./refresh.sh --new  # same, but first make a new dated copy folder
    ./start.sh          # (re)start the server
    screen -r canarydash-full   # look at it (Ctrl-A then D to leave)

The "Full dataset" card at the top is computed over every stored event. The interactive views below load the newest
100,000 events first (CANARY_INITIAL); "Load everything" at the bottom pulls the rest into those charts.
