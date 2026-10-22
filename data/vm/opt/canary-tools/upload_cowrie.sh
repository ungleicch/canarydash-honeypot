#!/bin/bash
# Daily: archive rotated Cowrie JSON logs + session recordings (tty) + captured downloads to blob.
# Local: keep ~30d of rotated JSON; prune empty 1-byte redir_* probes after they have been archived.
set -e
L=/opt/cowrie/cowrie/var/log/cowrie
V=/opt/cowrie/cowrie/var/lib/cowrie
for f in $L/cowrie.json.20*; do
  case "$f" in *.gz|*.uploaded) continue;; esac
  [ -e "$f" ] || continue
  [ -e "$f.uploaded" ] && continue
  d=$(basename "$f" | sed -E 's/cowrie\.json\.([0-9]{4})-([0-9]{2})-([0-9]{2})/\1\/\2\/\3/')
  gzip -c "$f" > /tmp/cj.gz && /opt/canary-tools/blob_put.sh /tmp/cj.gz "cowrie/$d/cowrie.json.gz" && touch "$f.uploaded"
done
day=$(date -u +%Y/%m/%d)
if tar czf /tmp/cowrie-artifacts.tgz -C "$V" tty downloads 2>/dev/null; then
  /opt/canary-tools/blob_put.sh /tmp/cowrie-artifacts.tgz "cowrie/$day/artifacts.tgz"
  # Safe prune: empty shell-redir probes only (1 byte), older than 2 days, already in today's/prior archives
  find "$V/downloads" -type f -name 'redir_*' -size 1c -mtime +2 -delete 2>/dev/null || true
fi
# Drop local rotated JSON older than 30 days once uploaded/compressed
find "$L" -type f \( -name 'cowrie.json.20*' -o -name 'cowrie.json.20*.gz' \) -mtime +30 -delete 2>/dev/null || true
find "$L" -type f -name 'cowrie.json.20*.uploaded' -mtime +30 -delete 2>/dev/null || true
rm -f /tmp/cj.gz /tmp/cowrie-artifacts.tgz
