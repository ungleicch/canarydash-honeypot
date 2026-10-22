#!/bin/bash
# MANUAL ONLY. Fetches only NEW bytes of the honeypot logs into ~/CanaryBackups/poller-cache/.
# Do not schedule (launchd/cron/screen). The 8793 dashboard picks up the data on page refresh.
set -euo pipefail
KEY="$HOME/.ssh/opencanary_key"; HOST="azureuser@20.98.51.91"
CACHE="$HOME/CanaryBackups/poller-cache"; mkdir -p "$CACHE"
SSH=(ssh -i "$KEY" -p 2222 -o BatchMode=yes -o ConnectTimeout=15 "$HOST")
for name in opencanary.log cowrie-canary.log; do
  local_f="$CACHE/$name"; touch "$local_f"
  lsize=$(stat -f %z "$local_f")
  rsize=$("${SSH[@]}" "sudo stat -c %s /var/tmp/$name 2>/dev/null || echo 0")
  if [ "$rsize" -lt "$lsize" ]; then
    echo "[$name] remote shrank ($rsize < $lsize): rotated/truncated, starting new cache file"
    mv "$local_f" "$local_f.rotated-$(date +%Y%m%d-%H%M%S)"; : > "$local_f"; lsize=0
  fi
  if [ "$rsize" -gt "$lsize" ]; then
    n=$((rsize - lsize))
    "${SSH[@]}" "sudo tail -c +$((lsize+1)) /var/tmp/$name | head -c $n | gzip -c" | gunzip -c >> "$local_f"
    echo "[$name] +$n bytes (gzip on the wire)"
  else
    echo "[$name] no new data"
  fi
done
curl -s -o /dev/null "http://127.0.0.1:8793/api/refresh" && echo "dashboard reloaded from cache" || true
