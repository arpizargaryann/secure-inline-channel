"""Raw Ethernet forwarding on two Linux interfaces (root required)."""
from __future__ import annotations
import argparse
import os
import sys
from scapy.all import IP, TCP, Ether, get_if_hwaddr, getmacbyip, sendp, sniff
from .crypto import CONTROL_PORT, handshake_client, handshake_server
from .packets import convert


def run():
    parser = argparse.ArgumentParser(description='Secure inline IPv4/TCP payload device')
    parser.add_argument('--role', choices=['d1', 'd2'], required=True)
    parser.add_argument('--lan', required=True, help='interface toward local PC')
    parser.add_argument('--wan', required=True, help='interface toward other device')
    parser.add_argument('--pc1', default='10.10.1.2')
    parser.add_argument('--pc2', default='10.10.3.2')
    parser.add_argument('--peer', required=True, help='peer device WAN IPv4')
    parser.add_argument('--next-lan', required=True, help='local host IPv4 for next hop ARP')
    parser.add_argument('--tcp-port', type=int, default=8080)
    args = parser.parse_args()

    psk_hex = os.environ.get('INLINE_PSK', '')
    if len(psk_hex) < 64:
        sys.exit('Set INLINE_PSK to at least 32 random bytes encoded as hex')
    try:
        psk = bytes.fromhex(psk_hex)
    except ValueError:
        sys.exit('INLINE_PSK must be hexadecimal')

    states = (handshake_client(args.peer, psk) if args.role == 'd1'
              else handshake_server(args.peer, psk))
    print('[handshake] X25519 + PSK authentication complete; AES-256-GCM keys derived', flush=True)

    local_macs = {iface: get_if_hwaddr(iface).lower() for iface in (args.lan, args.wan)}
    # In the demo, lan next hop is the PC, and wan next hop is the peer device.
    forwarding = {
        args.lan: (args.wan, args.peer),
        args.wan: (args.lan, args.next_lan),
    }
    mac_cache = {}

    def on_packet(frame):
        incoming = getattr(frame, 'sniffed_on', None)
        if incoming not in forwarding or Ether not in frame or IP not in frame or TCP not in frame:
            return
        if frame[Ether].src.lower() == local_macs[incoming]:
            return  # ignore our own transmitted frames (PACKET_OUTGOING)
        ip = frame[IP]
        tcp = ip[TCP]
        if tcp.sport == CONTROL_PORT or tcp.dport == CONTROL_PORT:
            return  # handshake TCP is handled by the Linux kernel
        if tcp.sport != args.tcp_port and tcp.dport != args.tcp_port:
            return  # only the selected TCP service is processed
        if (ip.src, ip.dst) == (args.pc1, args.pc2):
            direction = 'pc1_to_pc2'
            do_encrypt = args.role == 'd1'
        elif (ip.src, ip.dst) == (args.pc2, args.pc1):
            direction = 'pc2_to_pc1'
            do_encrypt = args.role == 'd2'
        else:
            return
        try:
            output = convert(ip, states[direction], encrypt=do_encrypt)
            out_iface, next_hop = forwarding[incoming]
            if next_hop not in mac_cache:
                mac_cache[next_hop] = getmacbyip(next_hop)
            destination_mac = mac_cache[next_hop]
            if not destination_mac:
                raise RuntimeError(f'Could not resolve ARP for {next_hop}')
            # Ensure the encrypted IP packet fits the interface MTU.
            # In this lab, application sends small TCP segments.
            if len(bytes(output)) > 1500:
                raise ValueError('Packet exceeds lab MTU after adding GCM tag')
            sendp(Ether(src=local_macs[out_iface], dst=destination_mac) / output,
                  iface=out_iface, verbose=False)
            if bytes(tcp.payload):
                print(f'[{args.role}] {"ENC" if do_encrypt else "DEC"} '
                      f'{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} '
                      f'{len(bytes(tcp.payload))} -> {len(bytes(output[TCP].payload))} bytes',
                      flush=True)
        except Exception as exc:
            print(f'[{args.role}] dropped packet: {exc}', file=sys.stderr, flush=True)

    print(f'[ready] {args.role}: {args.lan} <-> {args.wan}, TCP port {args.tcp_port}', flush=True)
    sniff(iface=[args.lan, args.wan], filter='ip and tcp', prn=on_packet, store=False)


if __name__ == '__main__':
    run()
