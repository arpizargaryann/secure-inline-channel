#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $EUID -ne 0 ]]; then echo 'Run: sudo bash scripts/run_demo.sh'; exit 1; fi
PY="$(pwd)/.venv/bin/python"
timeout 20s ip netns exec pc2 "$PY" scripts/demo_tcp.py server > runtime/pc2.log 2>&1 & SERVER_PID=$!
sleep 0.5
set +e
ip netns exec pc1 "$PY" scripts/demo_tcp.py client
RESULT=$?
set -e
wait "$SERVER_PID" || true
cat runtime/pc2.log
printf '\nDevice1 log:\n'; tail -n 15 runtime/d1.log
printf '\nDevice2 log:\n'; tail -n 15 runtime/d2.log
exit "$RESULT"
