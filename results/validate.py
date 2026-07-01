#!/usr/bin/env python3
"""Non-interactive validation — automated deploy + test + report.

Usage:  python3 validate.py [--type ransomware|infostealer|keylogger]
                             [--timeout 60] [--exe path/to/exe]
                             [--no-overlay] [--no-restore]

Replaces the interactive SSH session in deploy_and_test.py with:
  1. Create disk overlay snapshot
  2. Upload exe + create type-specific canary files
  3. Execute exe on VM (non-interactive)
  4. Wait for execution to settle
  5. Run type-specific validation checks
  6. Collect EDR/Defender alerts
  7. Print PASS/FAIL with detailed output
  8. Restore clean VM state

Exit code: 0 = all checks passed, 1 = some checks failed, 2 = error
"""
import argparse
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

SCRIPT_DIR  = Path(__file__).parent
EXE         = SCRIPT_DIR / "malware_source.exe"
SSH_PORT    = 10022
VM_USER     = 'vmuser'
VM_PASS     = 'vmuser123'
REMOTE_EXE  = r"C:\Users\vmuser\malware_test.exe"
QMP_SOCK    = '/tmp/vm_provision/vm-windows-11.qmp'
COW_DISK    = '/tmp/vm_provision/base_windows-11.cow.qcow2'
OVERLAY     = '/tmp/vm_provision/base_windows-11.overlay.qcow2'
TPM_SOCK    = '/tmp/vm_provision/vm-windows-11-tpm.sock'
TPM_STATE   = '/tmp/vm_provision/vm-windows-11-tpm'
C2_PORT     = 9001

_SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]


# ---------------------------------------------------------------------------
# Helpers (same as deploy_and_test.py)
# ---------------------------------------------------------------------------

def _qmp_command(command, arguments=None):
    import socket as _sock, json as _json
    s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
    s.settimeout(10)
    s.connect(QMP_SOCK)
    s.recv(4096)
    s.sendall(b'{"execute":"qmp_capabilities"}\n')
    s.recv(4096)
    payload = {"execute": command}
    if arguments:
        payload["arguments"] = arguments
    s.sendall(_json.dumps(payload).encode() + b"\n")
    time.sleep(1)
    data = s.recv(8192).decode()
    s.close()
    return data


def _ssh_cmd(cmd, timeout=15):
    ret = subprocess.run(
        ["sshpass", f"-p{VM_PASS}", "ssh", "-p", str(SSH_PORT), *_SSH_OPTS,
         f"{VM_USER}@localhost", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    return ret.stdout.strip()


def _scp(local_path, remote_path):
    ret = subprocess.run(
        ["sshpass", f"-p{VM_PASS}", "scp", "-P", str(SSH_PORT), *_SSH_OPTS,
         str(local_path), f"{VM_USER}@localhost:{remote_path}"],
        capture_output=True,
    )
    return ret.returncode == 0


def create_overlay():
    if os.path.exists(OVERLAY):
        os.remove(OVERLAY)
    try:
        result = _qmp_command("blockdev-snapshot-sync", {
            "device": "ide0-hd0",
            "snapshot-file": OVERLAY,
            "format": "qcow2",
        })
        if '"return"' in result:
            return True
        return False
    except Exception:
        return False


def restore_clean_state():
    subprocess.run(
        ["sshpass", f"-p{VM_PASS}", "ssh", "-p", str(SSH_PORT), *_SSH_OPTS,
         f"{VM_USER}@localhost", "shutdown /s /t 0"],
        capture_output=True,
    )
    for _ in range(30):
        ret = subprocess.run(["pgrep", "-f", f"qemu-system.*{QMP_SOCK}"], capture_output=True)
        if ret.returncode != 0:
            break
        time.sleep(1)
    else:
        subprocess.run(["pkill", "-f", f"qemu-system.*{QMP_SOCK}"], capture_output=True)
        time.sleep(2)

    if os.path.exists(OVERLAY):
        os.remove(OVERLAY)
    for f in [QMP_SOCK, TPM_SOCK]:
        if os.path.exists(f):
            os.remove(f)

    subprocess.run(["pkill", "-f", "swtpm"], capture_output=True)
    time.sleep(1)
    subprocess.Popen(
        ["swtpm", "socket", "--tpmstate", f"dir={TPM_STATE}",
         "--ctrl", f"type=unixio,path={TPM_SOCK}", "--tpm2"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    qemu_cmd = [
        "qemu-system-x86_64", "-enable-kvm",
        "-name", "vm-windows-11",
        "-m", "8192", "-cpu", "host", "-smp", "cores=4",
        "-machine", "q35,accel=kvm",
        "-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
        "-drive", f"if=pflash,format=raw,file=/tmp/vm_provision/OVMF_VARS_4M.fd",
        "-drive", f"if=ide,index=0,file={COW_DISK},format=qcow2,cache=none",
        "-chardev", f"socket,id=chrtpm,path={TPM_SOCK}",
        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
        "-device", "tpm-tis,tpmdev=tpm0",
        "-qmp", f"unix:{QMP_SOCK},server,nowait",
        "-netdev", "user,id=net0,hostfwd=tcp::10022-:22",
        "-device", "e1000,netdev=net0,romfile=",
        "-vga", "std", "-vnc", "127.0.0.1:1",
        "-serial", "file:/tmp/vm.log",
    ]
    subprocess.Popen(qemu_cmd, stdout=open("/tmp/vm_output.log", "w"),
                     stderr=subprocess.STDOUT, start_new_session=True)

    subprocess.run(
        ["ssh-keygen", "-f", os.path.expanduser("~/.ssh/known_hosts"),
         "-R", f"[localhost]:{SSH_PORT}"],
        capture_output=True,
    )

    for i in range(60):
        try:
            ret = subprocess.run(
                ["sshpass", f"-p{VM_PASS}", "ssh", "-p", str(SSH_PORT), *_SSH_OPTS,
                 "-o", "ConnectTimeout=5", f"{VM_USER}@localhost", "echo ready"],
                capture_output=True, text=True, timeout=10,
            )
            if ret.returncode == 0 and "ready" in ret.stdout:
                return True
        except subprocess.TimeoutExpired:
            pass
        time.sleep(5)
    return False


# ---------------------------------------------------------------------------
# Canary creation (same logic as deploy_and_test.py)
# ---------------------------------------------------------------------------

def _create_ransomware_canaries():
    _ssh_cmd(r'cmd /c "mkdir "C:\Users\vmuser\Documents\canary_files" 2>NUL"')
    canaries = {
        "canary_doc.txt": "This is a canary document for verification.",
        "canary_sheet.xlsx": "This is a canary spreadsheet for verification.",
        "canary_photo.jpg": "This is a canary image for verification.",
    }
    hashes = {}
    for name, content in canaries.items():
        _ssh_cmd(f'cmd /c "echo {content} > "C:\\Users\\vmuser\\Documents\\canary_files\\{name}""')
        h = _ssh_cmd(f'certutil -hashfile "C:\\Users\\vmuser\\Documents\\canary_files\\{name}" SHA256 2>NUL')
        hashes[name] = h
    for user_dir in ["Desktop", "Downloads", "Documents"]:
        _ssh_cmd(f'cmd /c "echo test content > "C:\\Users\\vmuser\\{user_dir}\\root_canary.txt""')
    return hashes


def _create_keylogger_canaries():
    _ssh_cmd(r'cmd /c "mkdir "C:\Users\vmuser\Documents\keylog_test" 2>NUL"')
    _ssh_cmd(r'echo CANARY_KEYLOG_MARKER > "C:\Users\vmuser\Documents\keylog_test\pre_marker.txt"')


def _create_infostealer_canaries():
    cmds = [
        r'cmd /c "mkdir "C:\Users\vmuser\Documents\credentials" 2>NUL"',
        r'echo username=admin > "C:\Users\vmuser\Documents\credentials\passwords.txt"',
        r'echo password=SuperSecret123! >> "C:\Users\vmuser\Documents\credentials\passwords.txt"',
        r'echo api_key=AKIA_FAKE_KEY_FOR_TESTING >> "C:\Users\vmuser\Documents\credentials\passwords.txt"',
        r'cmd /c "mkdir "C:\Users\vmuser\AppData\Local\Google\Chrome\User Data\Default" 2>NUL"',
        r'echo CANARY_BROWSER_DATA > "C:\Users\vmuser\AppData\Local\Google\Chrome\User Data\Default\Login Data"',
        r'cmd /c "mkdir "C:\Users\vmuser\AppData\Roaming\Mozilla\Firefox\Profiles\test.default" 2>NUL"',
        r'echo CANARY_FF_DATA > "C:\Users\vmuser\AppData\Roaming\Mozilla\Firefox\Profiles\test.default\logins.json"',
        r'echo CANARY_WALLET_DATA > "C:\Users\vmuser\Documents\credentials\wallet.dat"',
    ]
    for cmd in cmds:
        _ssh_cmd(cmd)


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def execute_exe(timeout=30):
    _ssh_cmd(f'cmd /c "start /B "" "{REMOTE_EXE}""', timeout=10)
    time.sleep(timeout)
    tasklist = _ssh_cmd("tasklist /FI \"IMAGENAME eq malware_test.exe\" /FO CSV /NH", timeout=10)
    alive = "malware_test.exe" in tasklist
    return alive, tasklist


# ---------------------------------------------------------------------------
# C2 listener (for infostealer/keylogger)
# ---------------------------------------------------------------------------

class C2Listener:
    def __init__(self, port=C2_PORT):
        self.port = port
        self.data = b""
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()

    def _listen(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(5)
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
                conn.settimeout(5.0)
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    self.data += chunk
                conn.close()
            except socket.timeout:
                continue
            except Exception:
                break
        srv.close()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)


# ---------------------------------------------------------------------------
# Validation checks
# ---------------------------------------------------------------------------

def check_ransomware(pre_hashes):
    evidence = []
    passed = False
    for name, pre_hash in pre_hashes.items():
        post = _ssh_cmd(f'certutil -hashfile "C:\\Users\\vmuser\\Documents\\canary_files\\{name}" SHA256 2>NUL')
        if post != pre_hash:
            evidence.append(f"MODIFIED: {name}")
            passed = True
        else:
            evidence.append(f"UNCHANGED: {name}")

    # Check for encrypted extensions
    listing = _ssh_cmd(r'dir /B "C:\Users\vmuser\Documents\canary_files\" 2>NUL')
    for ext in (".encrypted", ".locked", ".enc", ".crypt"):
        if ext in listing:
            evidence.append(f"ENCRYPTED_EXT: {ext} found")
            passed = True

    # Check for ransom note
    notes = _ssh_cmd(r'dir /B /S "C:\Users\vmuser\Documents\*readme*" "C:\Users\vmuser\Documents\*ransom*" "C:\Users\vmuser\Documents\*decrypt*" 2>NUL')
    if notes:
        evidence.append(f"RANSOM_NOTE: {notes.splitlines()[0]}")
        passed = True

    return passed, evidence


def check_keylogger(c2_listener):
    evidence = []
    passed = False

    # Check for log files
    logs = _ssh_cmd(r'dir /B /S "C:\Users\vmuser\*.log" "C:\Users\vmuser\*keylog*" 2>NUL')
    if logs:
        evidence.append(f"LOG_FILE: {logs.splitlines()[0]}")
        passed = True

    # Check C2 data
    if c2_listener and len(c2_listener.data) > 0:
        evidence.append(f"C2_DATA: {len(c2_listener.data)} bytes received")
        passed = True

    # Check network connections
    netstat = _ssh_cmd(r'netstat -an | findstr "9001"', timeout=10)
    if "ESTABLISHED" in netstat:
        evidence.append("NET_CONN: connection to C2 port established")
        passed = True

    return passed, evidence


def check_infostealer(c2_listener):
    evidence = []
    passed = False

    # Check if credentials were accessed
    cred_check = _ssh_cmd(r'dir /B "C:\Users\vmuser\Documents\credentials\" 2>NUL')
    if cred_check:
        evidence.append(f"CRED_DIR: files present ({cred_check.count(chr(10))+1} files)")

    # Check C2 data
    if c2_listener and len(c2_listener.data) > 0:
        evidence.append(f"C2_DATA: {len(c2_listener.data)} bytes exfiltrated")
        passed = True

    # Check for collection files
    collection = _ssh_cmd(r'dir /B /S "C:\Users\vmuser\AppData\Local\Temp\*.txt" "C:\Users\vmuser\AppData\Local\Temp\*.zip" 2>NUL')
    if collection:
        evidence.append(f"COLLECTION: {collection.splitlines()[0]}")
        passed = True

    # Check network
    netstat = _ssh_cmd(r'netstat -an | findstr "9001"', timeout=10)
    if "ESTABLISHED" in netstat or "TIME_WAIT" in netstat:
        evidence.append("NET_CONN: C2 communication detected")
        passed = True

    return passed, evidence


def check_defender_alerts():
    query = (
        r'powershell -NoProfile -Command "'
        r'Get-WinEvent -LogName Microsoft-Windows-Windows-Defender/Operational '
        r'-MaxEvents 20 -ErrorAction SilentlyContinue | '
        r'Where-Object { $_.Id -in 1116,1117,1006,1007 } | '
        r'Select-Object -ExpandProperty Message"'
    )
    output = _ssh_cmd(query, timeout=30)
    alerts = [l for l in output.splitlines() if l.strip()] if output else []
    return len(alerts), alerts


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    passed: bool
    malware_type: str
    execution_alive: bool
    functional_checks_passed: bool
    functional_evidence: list = field(default_factory=list)
    defender_alert_count: int = 0
    defender_messages: list = field(default_factory=list)
    elapsed_sec: float = 0.0


# ---------------------------------------------------------------------------
# Main validation orchestrator
# ---------------------------------------------------------------------------

def run_validation(malware_type="ransomware", timeout=60, exe_path=None,
                   use_overlay=True, do_restore=True):
    start_time = time.time()
    exe = Path(exe_path) if exe_path else EXE

    if not exe.exists():
        print(f"ERROR: {exe} not found")
        return ValidationResult(passed=False, malware_type=malware_type,
                                execution_alive=False, functional_checks_passed=False,
                                functional_evidence=["EXE not found"])

    # 1. Overlay
    if use_overlay:
        print("[*] Creating disk overlay...")
        if not create_overlay():
            print("[!] Overlay creation failed — continuing without protection")

    # 2. Upload
    print(f"[*] Uploading {exe.name}...")
    if not _scp(exe, REMOTE_EXE):
        return ValidationResult(passed=False, malware_type=malware_type,
                                execution_alive=False, functional_checks_passed=False,
                                functional_evidence=["Upload failed"])

    # 3. Canaries
    print(f"[*] Creating {malware_type} canary files...")
    pre_hashes = {}
    c2 = None
    if malware_type == "ransomware":
        pre_hashes = _create_ransomware_canaries()
    elif malware_type == "keylogger":
        _create_keylogger_canaries()
        c2 = C2Listener()
        c2.start()
    elif malware_type == "infostealer":
        _create_infostealer_canaries()
        c2 = C2Listener()
        c2.start()

    # 4. Execute
    print(f"[*] Executing malware (waiting {timeout}s)...")
    alive, tasklist = execute_exe(timeout)

    # 5. Validation checks
    print("[*] Running validation checks...")
    if malware_type == "ransomware":
        func_passed, evidence = check_ransomware(pre_hashes)
    elif malware_type == "keylogger":
        func_passed, evidence = check_keylogger(c2)
    elif malware_type == "infostealer":
        func_passed, evidence = check_infostealer(c2)
    else:
        func_passed = alive
        evidence = [f"Process alive: {alive}"]

    # 6. Defender alerts
    print("[*] Checking Defender alerts...")
    alert_count, alert_msgs = check_defender_alerts()

    # 7. Stop C2
    if c2:
        c2.stop()

    elapsed = time.time() - start_time

    result = ValidationResult(
        passed=func_passed and alert_count == 0,
        malware_type=malware_type,
        execution_alive=alive,
        functional_checks_passed=func_passed,
        functional_evidence=evidence,
        defender_alert_count=alert_count,
        defender_messages=alert_msgs,
        elapsed_sec=elapsed,
    )

    # 8. Restore
    if do_restore and use_overlay:
        print("[*] Restoring clean VM state...")
        restore_clean_state()

    return result


def print_report(result):
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

    verdict = f"{GREEN}PASS{RESET}" if result.passed else f"{RED}FAIL{RESET}"
    print(f"\n{'='*60}")
    print(f"{BOLD}VALIDATION RESULT: {verdict}{RESET}")
    print(f"{'='*60}")
    print(f"  Malware type:      {result.malware_type}")
    print(f"  Process alive:     {'yes' if result.execution_alive else 'no'}")
    print(f"  Functional goal:   {'MET' if result.functional_checks_passed else 'NOT MET'}")
    print(f"  Defender alerts:   {result.defender_alert_count}")
    print(f"  Elapsed:           {result.elapsed_sec:.1f}s")

    if result.functional_evidence:
        print(f"\n  {BOLD}Evidence:{RESET}")
        for e in result.functional_evidence:
            color = GREEN if any(k in e for k in ("MODIFIED", "C2_DATA", "NET_CONN", "LOG_FILE", "COLLECTION", "RANSOM_NOTE", "ENCRYPTED_EXT")) else YELLOW
            print(f"    {color}> {e}{RESET}")

    if result.defender_messages:
        print(f"\n  {BOLD}Defender Alerts:{RESET}")
        for msg in result.defender_messages[:5]:
            print(f"    {RED}! {msg[:120]}{RESET}")

    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Non-interactive malware validation")
    parser.add_argument("--type", default=None, help="Malware type: ransomware, infostealer, keylogger")
    parser.add_argument("--timeout", type=int, default=60, help="Execution wait time in seconds")
    parser.add_argument("--exe", default=None, help="Path to exe to test")
    parser.add_argument("--no-overlay", action="store_true", help="Skip overlay creation")
    parser.add_argument("--no-restore", action="store_true", help="Skip VM restore after test")
    args = parser.parse_args()

    # Auto-detect malware type from spec.yaml if not specified
    malware_type = args.type
    if not malware_type:
        spec_path = SCRIPT_DIR.parent / "spec.yaml"
        if spec_path.exists():
            for line in spec_path.read_text().splitlines():
                if line.strip().startswith("malware_type:"):
                    mt = line.split(":", 1)[1].strip().lower()
                    if any(k in mt for k in ("ransom", "encrypt", "locker")):
                        malware_type = "ransomware"
                    elif any(k in mt for k in ("keylog", "keystroke")):
                        malware_type = "keylogger"
                    elif any(k in mt for k in ("info steal", "infostealer", "credential", "password")):
                        malware_type = "infostealer"
                    break
        if not malware_type:
            malware_type = "ransomware"

    result = run_validation(
        malware_type=malware_type,
        timeout=args.timeout,
        exe_path=args.exe,
        use_overlay=not args.no_overlay,
        do_restore=not args.no_restore,
    )
    print_report(result)
    sys.exit(0 if result.passed else 1)
