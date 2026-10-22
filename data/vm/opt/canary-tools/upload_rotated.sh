#!/bin/bash
# upload every rotated daily log not yet uploaded, as canary-logs/YYYY/MM/DD/opencanary.log.gz
for f in /var/tmp/opencanary.log-*.gz; do
  [ -e "$f" ] || continue; [ -e "$f.uploaded" ] && continue
  d=$(basename "$f" | sed -E 's/opencanary\.log-([0-9]{4})([0-9]{2})([0-9]{2})\.gz/\1\/\2\/\3/')
  /opt/canary-tools/blob_put.sh "$f" "$d/opencanary.log.gz" && touch "$f.uploaded"
done
