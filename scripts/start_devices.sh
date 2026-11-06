#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $EUID -ne 0 ]]; then echo 'Run: sudo -E bash scripts/start_devices.sh'; exit 1; fi
PY="$(pwd)/.venv/bin/python"
[[ -x $PY ]] || { echo 'Create .venv and install requirements first'; exit 1; }
: "${INLINE_PSK:?Set INLINE_PSK to a hex-encoded 32-byte secret (see README)}"
mkdir -p runtime
# Control traffic on d1wan <-> d2wan uses ordinary TCP/47000 only for handshake.
ip netns exec d2 env INLINE_PSK="$INLINE_PSK" "$PY" -m secure_inline.device \
  --role d2 --lan d2lan --wan d2wan --peer 10.10.2.1 --next-lan 10.10.3.2 \
  > runtime/d2.log 2>&1 & echo $! > runtime/d2.pid
sleep 1
ip netns exec d1 env INLINE_PSK="$INLINE_PSK" "$PY" -m secure_inline.device \
  --role d1 --lan d1lan --wan d1wan --peer 10.10.2.2 --next-lan 10.10.1.2 \
  > runtime/d1.log 2>&1 & echo $! > runtime/d1.pid
for i in $(seq 1 40); do
  if grep -q '\[ready\]' runtime/d1.log 2>/dev/null && grep -q '\[ready\]' runtime/d2.log 2>/dev/null; then
    echo 'Both devices ready; logs: runtime/d1.log, runtime/d2.log'; exit 0
  fi
  if ! kill -0 "$(cat runtime/d1.pid)" 2>/dev/null || ! kill -0 "$(cat runtime/d2.pid)" 2>/dev/null; then
    echo 'Device exited; see logs:'; cat runtime/d1.log runtime/d2.log; exit 1
  fi
  sleep 0.25
done
echo 'Handshake timeout; see runtime/*.log'; exit 1
