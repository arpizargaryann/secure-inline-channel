"""Authenticated key agreement and per-packet AEAD with no on-wire nonce field."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import struct
from dataclasses import dataclass
from typing import Dict

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

CONTROL_PORT = 47000
WINDOW = 256  # bounded recovery from modest loss / reordering
LABEL = b"secure-inline-v1"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def mac(psk: bytes, *parts: bytes) -> str:
    return b64(hmac.digest(psk, LABEL + b"|" + b"|".join(parts), "sha256"))


def expect_mac(actual: str, psk: bytes, *parts: bytes) -> None:
    if not hmac.compare_digest(unb64(actual), unb64(mac(psk, *parts))):
        raise ValueError("Handshake authentication failed (PSK mismatch or tampering)")


def public_bytes(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def send_json(stream, obj: dict) -> None:
    stream.write((json.dumps(obj, separators=(",", ":")) + "\n").encode())
    stream.flush()


def recv_json(stream) -> dict:
    line = stream.readline(4096)
    if not line or not line.endswith(b"\n"):
        raise ConnectionError("Missing/invalid handshake message")
    return json.loads(line)


@dataclass
class CipherState:
    key: bytes
    prefix: bytes
    next_send: int = 0
    highest_seen: int = -1
    used: set[int] | None = None

    def __post_init__(self):
        if self.used is None:
            self.used = set()
        if len(self.prefix) != 4:
            raise ValueError("AES-GCM nonce prefix must have 4 bytes")
        self.aead = AESGCM(self.key)

    def nonce(self, counter: int) -> bytes:
        return self.prefix + struct.pack("!Q", counter)

    def encrypt(self, plaintext: bytes, aad: bytes) -> bytes:
        if self.next_send >= 2**64:
            raise OverflowError("Nonce space exhausted: new handshake required")
        result = self.aead.encrypt(self.nonce(self.next_send), plaintext, aad)
        self.next_send += 1  # never reuse a nonce, even for TCP retransmissions
        return result  # ciphertext || 16-byte GCM tag; no custom header

    def decrypt(self, protected: bytes, aad: bytes) -> bytes:
        # No nonce is placed on the wire. Try candidate counters and validate
        # via the GCM authentication tag. This is intentionally lab-scale.
        assert self.used is not None
        start = max(0, self.highest_seen - WINDOW + 1)
        stop = self.highest_seen + WINDOW + 1
        for i in range(start, stop):
            if i in self.used:
                continue
            try:
                plaintext = self.aead.decrypt(self.nonce(i), protected, aad)
            except Exception:
                continue
            self.used.add(i)
            self.highest_seen = max(self.highest_seen, i)
            cutoff = self.highest_seen - WINDOW + 1
            self.used = {n for n in self.used if n >= cutoff}
            return plaintext
        raise ValueError("Authentication failed, replay, or packet beyond nonce window")


def session_keys(shared: bytes, psk: bytes, p1: bytes, n1: bytes, p2: bytes, n2: bytes) -> Dict[str, CipherState]:
    # Derive independent keys and nonce prefixes for each TCP direction.
    transcript = LABEL + p1 + n1 + p2 + n2
    material = HKDF(
        algorithm=hashes.SHA256(), length=72,
        salt=hashlib.sha256(psk + transcript).digest(),
        info=b"inline-tcp-directional-aes-gcm-v1",
    ).derive(shared)
    return {
        "pc1_to_pc2": CipherState(material[0:32], material[64:68]),
        "pc2_to_pc1": CipherState(material[32:64], material[68:72]),
    }


def handshake_client(peer_ip: str, psk: bytes, port: int = CONTROL_PORT) -> Dict[str, CipherState]:
    private = X25519PrivateKey.generate()
    p1, n1 = public_bytes(private), os.urandom(16)
    with socket.create_connection((peer_ip, port), timeout=15) as sock:
        sock.settimeout(15)
        with sock.makefile("rwb") as stream:
            send_json(stream, {"type": "hello", "pub": b64(p1), "nonce": b64(n1),
                               "mac": mac(psk, b"hello", p1, n1)})
            response = recv_json(stream)
            if response.get("type") != "reply":
                raise ValueError("Expected authenticated handshake reply")
            p2, n2 = unb64(response["pub"]), unb64(response["nonce"])
            expect_mac(response["mac"], psk, b"reply", p1, n1, p2, n2)
            send_json(stream, {"type": "finish", "mac": mac(psk, b"finish", p1, n1, p2, n2)})
            ack = recv_json(stream)
            if ack.get("type") != "ok":
                raise ValueError("Peer did not confirm handshake")
    shared = private.exchange(X25519PublicKey.from_public_bytes(p2))
    return session_keys(shared, psk, p1, n1, p2, n2)


def handshake_server(bind_ip: str, psk: bytes, port: int = CONTROL_PORT) -> Dict[str, CipherState]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind_ip, port))
        listener.listen(1)
        print(f"[handshake] Listening on {bind_ip}:{port}", flush=True)
        conn, addr = listener.accept()
        with conn:
            conn.settimeout(15)
            with conn.makefile("rwb") as stream:
                hello = recv_json(stream)
                if hello.get("type") != "hello":
                    raise ValueError("Expected handshake hello")
                p1, n1 = unb64(hello["pub"]), unb64(hello["nonce"])
                expect_mac(hello["mac"], psk, b"hello", p1, n1)
                private = X25519PrivateKey.generate()
                p2, n2 = public_bytes(private), os.urandom(16)
                send_json(stream, {"type": "reply", "pub": b64(p2), "nonce": b64(n2),
                                   "mac": mac(psk, b"reply", p1, n1, p2, n2)})
                finished = recv_json(stream)
                if finished.get("type") != "finish":
                    raise ValueError("Missing final handshake message")
                expect_mac(finished["mac"], psk, b"finish", p1, n1, p2, n2)
                send_json(stream, {"type": "ok"})
        print(f"[handshake] Authenticated Device1 at {addr[0]}", flush=True)
    shared = private.exchange(X25519PublicKey.from_public_bytes(p1))
    return session_keys(shared, psk, p1, n1, p2, n2)
