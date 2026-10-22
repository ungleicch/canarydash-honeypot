#!/bin/bash
# (Re)start the offline dashboard in a detached screen session 'canarydash-full' on http://127.0.0.1:8790
cd "$(dirname "$0")"
screen -S canarydash-full -X quit 2>/dev/null
pid=$(lsof -tiTCP:${CANARY_PORT:-8790} -sTCP:LISTEN); [ -n "$pid" ] && kill $pid
sleep 1
screen -dmS canarydash-full bash -c "cd '$PWD' && exec /opt/homebrew/bin/python3 server.py > server.log 2>&1"
echo "CanaryDash (local full dataset): http://127.0.0.1:${CANARY_PORT:-8790}"
