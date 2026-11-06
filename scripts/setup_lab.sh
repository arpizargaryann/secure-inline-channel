#!/usr/bin/env bash
set -euo pipefail
# Run once on a disposable Linux VM. Requires root, iproute2.
if [[ $EUID -ne 0 ]]; then echo 'Run: sudo bash scripts/setup_lab.sh'; exit 1; fi
for ns in pc1 d1 d2 pc2; do
  if ip netns list | grep -q "^${ns} "; then echo "Namespace $ns exists; run cleanup_lab.sh first"; exit 1; fi
done
for ns in pc1 d1 d2 pc2; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add p1 type veth peer name d1lan
ip link add d1wan type veth peer name d2wan
ip link add d2lan type veth peer name p2
ip link set p1 netns pc1; ip link set d1lan netns d1
ip link set d1wan netns d1; ip link set d2wan netns d2
ip link set d2lan netns d2; ip link set p2 netns pc2
ip -n pc1 addr add 10.10.1.2/24 dev p1
ip -n d1 addr add 10.10.1.1/24 dev d1lan
ip -n d1 addr add 10.10.2.1/24 dev d1wan
ip -n d2 addr add 10.10.2.2/24 dev d2wan
ip -n d2 addr add 10.10.3.1/24 dev d2lan
ip -n pc2 addr add 10.10.3.2/24 dev p2
for pair in 'pc1 p1' 'd1 d1lan' 'd1 d1wan' 'd2 d2wan' 'd2 d2lan' 'pc2 p2'; do
  read -r ns dev <<< "$pair"
  ip -n "$ns" link set "$dev" up
done
ip -n pc1 route add default via 10.10.1.1
ip -n pc2 route add default via 10.10.3.1
# Linux IPv4 forwarding deliberately OFF on devices: only our process forwards.
for ns in d1 d2; do ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=0; done
# Disable offloads for predictable observable packet lengths/checksums (best effort).
if command -v ethtool >/dev/null; then
  for pair in 'pc1 p1' 'd1 d1lan' 'd1 d1wan' 'd2 d2wan' 'd2 d2lan' 'pc2 p2'; do
    read -r ns dev <<< "$pair"
    ip netns exec "$ns" ethtool -K "$dev" tx off rx off tso off gso off gro off 2>/dev/null || true
  done
fi
printf 'Created: PC1 (10.10.1.2) -> Device1 (10.10.1.1 / 10.10.2.1) -> Device2 (10.10.2.2 / 10.10.3.1) -> PC2 (10.10.3.2)\n'
