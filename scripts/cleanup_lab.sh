#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $EUID -ne 0 ]]; then echo 'Run: sudo bash scripts/cleanup_lab.sh'; exit 1; fi
if [[ -d runtime ]]; then
 for file in runtime/d1.pid runtime/d2.pid; do
   if [[ -f "$file" ]]; then kill "$(cat "$file")" 2>/dev/null || true; fi
 done
fi
for ns in pc1 d1 d2 pc2; do ip netns del "$ns" 2>/dev/null || true; done
echo 'Removed lab network namespaces.'
