#!/bin/sh
# Restart Cowrie if its log has gone silent for 3+ min, or pre-emptively when
# its cgroup nears the memory cap (memory throttling = the cause of the hangs).
LOG=/opt/cowrie/cowrie/var/log/cowrie/cowrie.json
OUT=/var/log/cowrie_watchdog.log
CG=/sys/fs/cgroup/system.slice/cowrie.service
now=$(date +%s); m=$(stat -c %Y "$LOG" 2>/dev/null || echo 0)
age=$((now-m))
mem=$(cat $CG/memory.current 2>/dev/null || echo 0)
swp=$(cat $CG/memory.swap.current 2>/dev/null || echo 0)
memMB=$((mem/1048576)); swpMB=$((swp/1048576))
if [ "$age" -gt 180 ] || ! systemctl is-active -q cowrie; then
  echo "$(date -u +%FT%TZ) restart: log idle ${age}s mem=${memMB}M swap=${swpMB}M" >> $OUT
  systemctl restart cowrie
elif [ "$memMB" -gt 300 ] || [ "$swpMB" -gt 110 ]; then
  echo "$(date -u +%FT%TZ) restart: preemptive mem=${memMB}M swap=${swpMB}M" >> $OUT
  systemctl restart cowrie
fi
