#!/usr/bin/env python3
import socket, sys, datetime

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
out = f"exfil_{datetime.datetime.now():%Y%m%d_%H%M%S}.bin"

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port))
srv.listen(1)
print(f"Listening on :{port}")

conn, addr = srv.accept()
print(f"Connection from {addr}")

data = b""
while True:
    chunk = conn.recv(65536)
    if not chunk:
        break
    data += chunk

conn.close()
srv.close()

with open(out, "wb") as f:
    f.write(data)

print(f"Received: {len(data)} bytes -> {out}")

if len(data) > 100:
    print("\nText preview:")
    import subprocess
    subprocess.run(["strings", out], stdout=subprocess.PIPE)
    result = subprocess.run(["strings", out], capture_output=True, text=True)
    for line in result.stdout.split("\n")[:20]:
        print(f"  {line}")
