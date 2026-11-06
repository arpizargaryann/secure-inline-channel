"""Encrypt/decrypt *only* TCP data; preserve every other TCP/IP field."""
import struct
from scapy.all import IP, TCP, raw


def aad_for(ip: IP) -> bytes:
    tcp = ip[TCP]
    # Authenticate stable TCP stream identifiers/header fields. IP TTL,
    # lengths, checksums are omitted because the encrypted payload is longer.
    return (bytes(map(int, ip.src.split('.'))) + bytes(map(int, ip.dst.split('.')))
            + struct.pack('!HHIIBH', tcp.sport, tcp.dport, tcp.seq, tcp.ack,
                          int(tcp.flags), tcp.window))


def convert(packet: IP, state, encrypt: bool) -> IP:
    if IP not in packet or TCP not in packet:
        raise ValueError('Expected IPv4/TCP')
    ip = IP(raw(packet[IP]))  # fresh copy, leaving original untouched
    tcp = ip[TCP]
    original = bytes(tcp.payload)
    if not original:
        return ip  # preserve TCP SYN/ACK/FIN/empty segments unchanged
    if ip.frag != 0 or (int(ip.flags) & 1):
        raise ValueError('IPv4 fragmentation is not supported')
    if not encrypt and len(original) < 16:
        raise ValueError('Encrypted TCP payload has no 16-byte authentication tag')
    associated_data = aad_for(ip)
    updated = state.encrypt(original, associated_data) if encrypt else state.decrypt(original, associated_data)
    tcp.remove_payload()
    tcp.add_payload(updated)
    # Important: deleting these fields makes Scapy recompute all checksums and lengths.
    for field in ('len', 'chksum'):
        if field in ip.fields:
            del ip.fields[field]
    if 'chksum' in tcp.fields:
        del tcp.fields['chksum']
    result = IP(raw(ip))
    # TCP options, IP options, sequence numbers, ports and flags stay intact.
    return result
