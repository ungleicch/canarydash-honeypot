#!/bin/bash
# Read-only pull of the full honeypot dataset from the VM into ~/CanaryBackups/full-latest (-> full-<ts>).
# Never deletes anything on the VM. Malware is stored only inside a tar.gz.
set -u
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
KEY="$HOME/.ssh/opencanary_key"; H=azureuser@20.98.51.91
SSHO="-i $KEY -p 2222 -o BatchMode=yes -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new"
B="$HOME/CanaryBackups"
if [ "${1:-}" = "--new" ] || [ ! -e "$B/full-latest" ]; then
  D="$B/full-$(date +%Y%m%d-%H%M)"; mkdir -p "$D"
  [ -d "$B/full-latest/" ] && rsync -a "$B/full-latest/" "$D/"   # seed from previous copy
  ln -sfn "$(basename "$D")" "$B/full-latest"
fi
D="$B/full-latest/"; cd "$D" || exit 1
mkdir -p vm malware
PATHS="/var/tmp/opencanary.log /var/tmp/opencanary.log.snapshot-pre-cowrie /var/tmp/cowrie-canary.log /opt/cowrie/cowrie/var/log/cowrie /opt/cowrie/cowrie/var/lib/cowrie/tty /opt/cowrie/personas /opt/cowrie/cowrie/etc /etc/opencanaryd/opencanary.conf /opt/canary-tools /var/log/honeypot-admin.log /var/log/cowrie_watchdog.log"
SRC=""; for p in $PATHS; do SRC="$SRC $H:$p"; done
rsync -az --partial --relative --ignore-missing-args --rsync-path="sudo nice -n 19 ionice -c3 rsync" -e "ssh $SSHO" $SRC vm/
RC=$?
# malware: streamed tar.gz, never extracted on the Mac
T=malware/downloads_DO_NOT_RUN.tar.gz; [ -f $T ] && chmod 600 $T
ssh $SSHO $H "sudo nice -n 19 ionice -c3 tar czf - -C /opt/cowrie/cowrie/var/lib/cowrie downloads 2>/dev/null" > $T.tmp; TRC=$?
# GNU tar exit 1 = "file changed as we read it" (Cowrie prunes 1-byte redir_ stubs); archive is still valid
if [ $TRC -le 1 ] && gzip -t $T.tmp 2>/dev/null; then rm -f $T; mv $T.tmp $T; chmod 400 $T; else echo "ERROR: malware tar failed rc=$TRC"; fi
tar tzvf $T > malware/downloads_listing.txt 2>/dev/null
# VM-side reference counts for verification
ssh $SSHO $H 'cd /; for f in /var/tmp/opencanary.log /var/tmp/opencanary.log.snapshot-pre-cowrie /var/tmp/cowrie-canary.log /opt/cowrie/cowrie/var/log/cowrie/cowrie.json*; do [ -f "$f" ] || continue; case $f in *.gz) n=$(sudo zcat "$f"|wc -l);; *) n=$(sudo wc -l <"$f");; esac; echo "$(sudo stat -c %s "$f") $n $f"; done' > VM_COUNTS.txt
( for f in $(awk '{print $3}' VM_COUNTS.txt); do l="vm$f"; [ -f "$l" ] || continue; case $l in *.gz) n=$(zcat <"$l"|wc -l);; *) n=$(wc -l <"$l");; esac; echo "$(stat -f %z "$l") $(echo $n) $f"; done ) > LOCAL_COUNTS.txt
cat > README.txt <<R
Full copy of Tom's class honeypot (opencanary VM 20.98.51.91). Refreshed $(date '+%F %H:%M %Z'), rsync exit $RC.
vm/       exact paths from the VM (OpenCanary log, pre-cowrie snapshot, all Cowrie JSON logs incl. .gz, tty recordings, canary-tools, configs)
malware/downloads_DO_NOT_RUN.tar.gz   LIVE MIPS/ARM MALWARE captured by Cowrie. Do NOT extract or run. listing in downloads_listing.txt
VM_COUNTS.txt / LOCAL_COUNTS.txt      bytes, lines, path on the VM vs this copy (live logs keep growing, so the newest file can differ slightly)
R
echo "pull done rc=$RC -> $(readlink "$B/full-latest")"
