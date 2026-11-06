"""TCP receiver on PC2 or TCP sender on PC1; small chunks avoid MTU issues."""
import argparse
import socket

p = argparse.ArgumentParser()
p.add_argument('mode', choices=['server', 'client'])
a = p.parse_args()
if a.mode == 'server':
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('10.10.3.2', 8080))
        server.listen(1)
        print('[PC2] Listening on 10.10.3.2:8080', flush=True)
        conn, _ = server.accept()
        with conn:
            data = conn.recv(512)
            print('[PC2] RECEIVED:', data.decode(), flush=True)
            conn.sendall(b'ACK: secure channel working')
else:
    with socket.create_connection(('10.10.3.2', 8080), timeout=15) as conn:
        conn.sendall(b'Hello from PC1 - AES-GCM protected between devices!')
        print('[PC1] RESPONSE:', conn.recv(512).decode(), flush=True)
