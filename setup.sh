#!/bin/bash
# Downloads the prebuilt dashboard databases from the Hugging Face dataset
#   https://huggingface.co/datasets/hznd67/canarydash-honeypot
# verifies their sha256, decompresses them into ./unpacked and starts the local dashboard.
# Nothing is rebuilt from the logs. Needs: curl (or the `hf` CLI), zstd, shasum/sha256sum, python3.
set -euo pipefail; cd "$(dirname "$0")"
REPO="hznd67/canarydash-honeypot"
BASE="https://huggingface.co/datasets/$REPO/resolve/main"
FILES="canarydash-full.sqlite.zst explore.sqlite.zst SHA256SUMS"
PORT="${1:-8802}"
command -v zstd >/dev/null || { echo "zstd is required (brew install zstd / apt install zstd)"; exit 1; }
if command -v sha256sum >/dev/null; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
mkdir -p unpacked/download
cd unpacked/download
for f in $FILES; do
  if [ -f "$f" ] && [ "$f" != SHA256SUMS ] && grep " $f\$" SHA256SUMS 2>/dev/null | $SHA -c --status 2>/dev/null; then echo "have $f"; continue; fi
  echo "downloading $f"
  curl -fL --retry 3 -C - -o "$f" "$BASE/$f"
done
echo "verifying sha256"; grep '\.zst$' SHA256SUMS | $SHA -c -
for z in canarydash-full.sqlite.zst explore.sqlite.zst; do
  out="../${z%.zst}"; echo "decompressing $z"; zstd -d --long=27 -f "$z" -o "$out"
done
cd ..; grep -v '\.zst$' download/SHA256SUMS | $SHA -c -
cd ..
echo "Done. Starting http://127.0.0.1:$PORT  (Ctrl-C to stop)"
exec env CANARY_DB="$PWD/unpacked/canarydash-full.sqlite" CANARY_FULL="$PWD/unpacked" python3 dashboard/full/server.py "$PORT"
