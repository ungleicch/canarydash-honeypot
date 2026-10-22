#!/bin/bash
# One command: pull fresh data from the VM (read-only) and rebuild the local dashboard database.
#   ./refresh.sh          update ~/CanaryBackups/full-latest in place, then re-ingest
#   ./refresh.sh --new    make a new dated copy ~/CanaryBackups/full-<YYYYMMDD-HHMM> first

set -u
cd "$(dirname "$0")"
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
./pull.sh "${1:-}" || echo "WARN: pull had problems, ingesting what is there"
python3 ingest.py | tail -25
curl -s -o /dev/null -w "dashboard http %{http_code}\n" http://127.0.0.1:${CANARY_PORT:-8790}/ || true
