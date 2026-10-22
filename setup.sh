#!/bin/bash
# Rebuilds the original (uncompressed) VM tree into ./unpacked/vm and builds the dashboard DB.
set -e; cd "$(dirname "$0")"
rm -rf unpacked; mkdir -p unpacked; cp -R data/vm unpacked/vm
cd unpacked/vm
for f in $(find . -name '*.part00'); do b="${f%.part00}"; cat "$b".part* > "$b"; rm "$b".part*; done
while read -r p; do [ -f "$p.gz" ] && gunzip "$p.gz"; done < ../../data/GZIPPED_FOR_REPO.txt
cd ../..
CANARY_FULL="$PWD/unpacked" CANARY_DB="$PWD/unpacked/canarydash-full.sqlite" python3 dashboard/full/ingest.py
echo "Run: CANARY_FULL=\$PWD/unpacked CANARY_DB=\$PWD/unpacked/canarydash-full.sqlite CANARY_PORT=8790 python3 dashboard/full/server.py"
