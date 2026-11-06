import os
import pytest
from secure_inline.crypto import CipherState, session_keys


def test_directional_keys_and_unique_nonces():
    psk = os.urandom(32)
    x = session_keys(os.urandom(32), psk, os.urandom(32), os.urandom(16), os.urandom(32), os.urandom(16))
    assert x['pc1_to_pc2'].key != x['pc2_to_pc1'].key
    assert x['pc1_to_pc2'].nonce(0) != x['pc1_to_pc2'].nonce(1)
    a = x['pc1_to_pc2']
    b = CipherState(a.key, a.prefix)
    ciphertext1 = a.encrypt(b'hello', b'header')
    ciphertext2 = a.encrypt(b'hello', b'header')
    assert ciphertext1 != ciphertext2
    assert len(ciphertext1) == len(b'hello') + 16
    assert b.decrypt(ciphertext2, b'header') == b'hello'  # packet 0 skipped
    assert b.decrypt(ciphertext1, b'header') == b'hello'  # out of order
    with pytest.raises(ValueError):
        b.decrypt(ciphertext1, b'header')  # replay
    with pytest.raises(ValueError):
        b.decrypt(ciphertext2[:-1] + b'X', b'header')  # corrupted tag


def test_packet_round_trip():
    from scapy.all import IP, TCP, raw
    from secure_inline.packets import convert
    key, prefix = os.urandom(32), os.urandom(4)
    tx, rx = CipherState(key, prefix), CipherState(key, prefix)
    original = IP(src='10.10.1.2', dst='10.10.3.2', ttl=64, id=12) / TCP(
        sport=42310, dport=8080, flags='PA', seq=1000, ack=500, options=[('NOP', None)]) / b'hello inline channel'
    original = IP(raw(original))
    encrypted = convert(original, tx, encrypt=True)
    assert len(bytes(encrypted[TCP].payload)) == len(bytes(original[TCP].payload)) + 16
    assert encrypted[TCP].seq == original[TCP].seq
    assert encrypted[TCP].options == original[TCP].options
    assert encrypted[IP].src == original[IP].src
    decrypted = convert(encrypted, rx, encrypt=False)
    assert raw(decrypted) == raw(original)
