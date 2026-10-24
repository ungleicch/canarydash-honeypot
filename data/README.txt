Full copy of a class honeypot (OpenCanary + Cowrie VM). Originally copied 2026-10-21 20:39 PDT; final update 2026-10-23 after the honeypot was shut down (services stopped 16:16 PDT, VM deallocated). Last event 2026-10-23 16:16 PDT. Earlier copy tool reported rsync code 24 (vanished files) because live logs rotated mid-copy.
vm/       exact paths from the VM (OpenCanary log, pre-cowrie snapshot, all Cowrie JSON logs incl. .gz, tty recordings, canary-tools, configs)
malware/downloads_DO_NOT_RUN.tar.gz   LIVE MIPS/ARM MALWARE captured by Cowrie. Do NOT extract or run. listing in downloads_listing.txt
VM_COUNTS.txt / LOCAL_COUNTS.txt      bytes, lines, path on the VM vs this copy (live logs keep growing, so the newest file can differ slightly)
