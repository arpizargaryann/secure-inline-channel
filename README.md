# Secure Inline TCP Payload Channel (Linux Prototype)

Educational Python/Linux prototype implementing:

```text
PC1 (10.10.1.2) -- Device1 (10.10.1.1 / 10.10.2.1)
                              |
                         protected TCP
                              |
                  Device2 (10.10.2.2 / 10.10.3.1) -- PC2 (10.10.3.2)
```

## What it demonstrates

1. A separate **authenticated X25519 Diffie–Hellman** handshake over TCP port **47000** between the two devices. A pre-shared secret (PSK) authenticates handshake messages using HMAC-SHA256. HKDF-SHA256 derives independent AES-256-GCM keys and nonce prefixes for each data direction. *Unauthenticated DH alone would be vulnerable to man-in-the-middle attacks.*
2. Inline raw Ethernet forwarding using Scapy. No IP routing in the Linux kernel of the devices; selected TCP/IPv4 packets are read from one interface and directly emitted from the other.
3. For TCP port **8080**, **TCP payload only** is encrypted with **AES-256-GCM**; the **16-byte GCM tag** is appended to the encrypted TCP payload. There is **no UDP encapsulation or custom per-packet protocol header**. IPv4 and TCP addresses, ports, sequence/ack numbers, flags, options, etc. remain the same. The IPv4 length and IPv4/TCP checksums are recalculated.
4. Receiver checks the authentication tag *before* delivering plaintext, removes the tag and restores the original IP packet size/checksums. Reverse-direction traffic works similarly.
5. Each encrypted packet gets a unique **96-bit AES-GCM nonce**: a fresh derived 32-bit direction-specific prefix + monotonically increasing 64-bit per-session counter. Sender advances on *every* encryption, including TCP retransmissions. Counters reset only after a new authenticated handshake derives new keys/prefixes.

### Important engineering limitation: no explicit nonce or sequence field

Since no per-packet metadata is allowed, the receiver cannot simply read the sender's nonce counter. The receiver searches a **bounded 256-counter sliding window** of candidates and accepts **only** the counter that passes AES-GCM authentication. It remembers accepted counters to reject replay; it tolerates *limited* loss/reordering. This is computationally expensive and cannot support arbitrary reordering, indefinite packet loss, production-scale traffic or device restart mid-session. Larger MTUs, IPv4 fragmentation and general-purpose TCP forwarding aren't implemented. The lab sends short messages only. This is a **prototype, not a production VPN**. The control handshake uses a dedicated TCP connection and does not encapsulate protected application traffic.

## Requirements

- Ubuntu 22.04 / 24.04 (native Linux or an Ubuntu VM with admin/root access); Linux kernel with network namespaces, veth, raw packet sockets.
- `sudo apt update && sudo apt install -y python3 python3-venv python3-pip iproute2 iputils-ping tcpdump ethtool git`
- Python 3.10+

> Windows users: prefer an Ubuntu VM. WSL2 may not provide the required network capabilities depending on its configuration. GitHub Desktop or Git for Windows can still be used for the upload.

## 1. Install

```bash
cd secure-inline-channel
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
```

## 2. Create topology (use Ubuntu terminal)

```bash
sudo bash scripts/setup_lab.sh
```

Topology:

```text
pc1:p1 (10.10.1.2/24) <-> d1:d1lan (10.10.1.1/24)
d1:d1wan (10.10.2.1/24) <-> d2:d2wan (10.10.2.2/24)
d2:d2lan (10.10.3.1/24) <-> pc2:p2 (10.10.3.2/24)
```

## 3. Start devices / handshake

In the **same terminal**, from the project root:

```bash
export INLINE_PSK="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
sudo -E bash scripts/start_devices.sh
```

The devices share this demo PSK through the launcher; real deployment needs secure pre-provisioning. Never commit PSKs. Expected: `Both devices ready`. Check:

```bash
cat runtime/d1.log
cat runtime/d2.log
```

Each log should show an authenticated Diffie–Hellman handshake and `[ready]`.

## 4. Run TCP message test

```bash
sudo bash scripts/run_demo.sh
```

Expected text resembles:

```text
[PC1] RESPONSE: ACK: secure channel working
[PC2] RECEIVED: Hello from PC1 - AES-GCM protected between devices!
[d1] ENC ... 53 -> 69 bytes
[d2] DEC ... 69 -> 53 bytes
[d2] ENC ... 27 -> 43 bytes
[d1] DEC ... 43 -> 27 bytes
```

The precise byte counts depend on the sent strings. Observe protected payload between the devices with:

```bash
sudo ip netns exec d1 tcpdump -ni d1wan -X 'tcp port 8080'
```

Compare with plaintext on PC1-side interface:

```bash
sudo ip netns exec d1 tcpdump -ni d1lan -X 'tcp port 8080'
```

Run these tcpdump commands in **separate terminals while** running `run_demo.sh`. The control handshake is separate TCP port 47000, not inside the protected application packet.

## 5. Cleanup

```bash
sudo bash scripts/cleanup_lab.sh
```

## Security and scope

- Works for preselected IPv4/TCP traffic (`10.10.1.2 <-> 10.10.3.2`, TCP/8080).
- No UDP tunnel; no custom header on protected data. Only the GCM tag changes the TCP payload length on the inter-device link.
- AAD binds the encrypted data to source/destination IPs, TCP ports, TCP sequence and acknowledgment numbers, flags and window. It does not cover every TCP/IP field; an attacker can tamper with unauthenticated header fields. This is an explicit prototype limitation.
- The receiver discards packets with wrong authentication tags or reused counters.
- The device does not forward unsupported traffic, fragmented packets, or packets that would exceed 1500-byte IP MTU.
- The forwarded encrypted payload is larger by 16 bytes. Since it is decrypted before PC2, end hosts see original TCP lengths and sequence space; inter-device MTU still must accommodate the tag.
- Requires Linux root permissions and isolated test network. Avoid using this in real production network infrastructure.
- No persistent replay protection or key recovery across process restarts; restart **both** devices and perform a fresh handshake together.

## Files

```text
secure_inline/crypto.py    # X25519+PSK authentication, HKDF, nonce and AES-GCM
secure_inline/packets.py   # TCP payload conversion, integrity AAD, checksums
secure_inline/device.py    # Ethernet sniff, filter, forward
scripts/setup_lab.sh       # Four Linux namespaces / three veth links
scripts/start_devices.sh   # D2 server then D1 client
scripts/demo_tcp.py        # PC1 client and PC2 echo service
scripts/run_demo.sh        # Runs application test and displays logs
scripts/cleanup_lab.sh     # Stops devices, removes namespaces
tests/test_crypto.py       # Cryptographic and packet round-trip tests
```

## Suggested oral defense

**What is the topology?** Two host namespaces and two inline device namespaces connected by three virtual Ethernet pairs.

**Why DH?** To derive a common secret without transmitting the final AES key. We use X25519 (modern elliptic-curve Diffie–Hellman), HMAC-PSK for authentication, and HKDF for traffic keys.

**Why AES-GCM?** It encrypts the data and provides a tag to detect tampering. The receiver releases plaintext only after successful tag verification.

**What changes in each packet?** TCP data becomes ciphertext+16-byte tag. We keep original IP/TCP addresses, ports, flags, numbers and options, but update length/checksums. There is no extra protocol header.

**How is nonce uniqueness guaranteed?** Per-direction key/prefix and strictly incrementing 64-bit counter, one increment per encrypted packet, even retransmissions. A fresh DH session produces new keys. Receiver tries expected counter candidates because nonce metadata is forbidden.

**What are the limits?** Searching nonce candidates is slow; bounded loss/reordering, small MTU-safe payloads, and this is a teaching prototype, not a production security product.
