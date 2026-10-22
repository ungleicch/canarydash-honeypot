#!/bin/bash
# usage: blob_put.sh <file> <blobpath>
set -e
SA=<storage-account>
TOK=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -sf -X PUT -T "$1" -H "Authorization: Bearer $TOK" -H "x-ms-version: 2021-08-06" -H "x-ms-blob-type: BlockBlob" "https://$SA.blob.core.windows.net/canary-logs/$2" && echo "uploaded $2"
