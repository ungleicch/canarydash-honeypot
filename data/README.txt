Full copy of a class honeypot (OpenCanary + Cowrie VM, public IP 20.98.51.91), copied 2026-10-21 20:39 PDT. Copy tool reported 'some files vanished' (rsync code 24) because live logs rotated mid-copy.
vm/       exact paths from the VM (OpenCanary log, pre-cowrie snapshot, all Cowrie JSON logs incl. .gz, tty recordings, canary-tools, configs)
malware/downloads_DO_NOT_RUN.tar.gz   LIVE MIPS/ARM MALWARE captured by Cowrie. Do NOT extract or run. listing in downloads_listing.txt
VM_COUNTS.txt / LOCAL_COUNTS.txt      bytes, lines, path on the VM vs this copy (live logs keep growing, so the newest file can differ slightly)
