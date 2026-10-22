#!/bin/bash
curl -sf http://127.0.0.1/ >/dev/null || systemctl reload nginx
