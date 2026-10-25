#!/usr/bin/env bash
# Sends the same injection payloads to the vulnerable and the secure endpoint
# so the difference can be compared side by side. Start the server first:
#   npm start
set -u
BASE="${BASE:-http://127.0.0.1:3000}"

PAYLOADS=(
  "ping 127.0.0.1; whoami"
  "ping 127.0.0.1 && cat ../private/secrets.txt"
  "ping 127.0.0.1 | id"
  'echo $(whoami)'
  'echo `uname -a`'
  "ls ..; cat /etc/passwd"
)

send() {
  local mode="$1" payload="$2"
  # Build the JSON body with node so quotes/backticks are escaped correctly
  local body
  body=$(node -e 'process.stdout.write(JSON.stringify({command: process.argv[1]}))' "$payload")
  curl -s -X POST "$BASE/api/$mode/run" -H 'Content-Type: application/json' -d "$body"
  echo
}

for p in "${PAYLOADS[@]}"; do
  echo "=================================================================="
  echo "PAYLOAD: $p"
  echo "------------------------- VULNERABLE -----------------------------"
  send vulnerable "$p" | head -c 1200
  echo
  echo "--------------------------- SECURE -------------------------------"
  send secure "$p"
done
