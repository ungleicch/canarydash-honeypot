#!/bin/bash
screen -S canarydash -X quit 2>/dev/null
pid=$(lsof -tiTCP:8793 -sTCP:LISTEN); [ -n "$pid" ] && kill $pid
sleep 1
screen -dmS canarydash bash -c 'cd "$HOME/Developer/CanaryDash" && exec /opt/homebrew/bin/python3 server.py > .server.log 2>&1'
echo "CanaryDash: http://127.0.0.1:8793"
