"""Tier 3 VM integration tests — requires running Windows 11 QEMU VM."""

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

SSH_BASE = [
    "sshpass", "-pvmuser123", "ssh", "-p", "10022",
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    "vmuser@localhost",
]


def _ssh(cmd, timeout=15):
    ret = subprocess.run(SSH_BASE + [cmd], capture_output=True, text=True, timeout=timeout)
    return ret.stdout.strip().replace("\r", "")


def _create_ransomware_canaries():
    cmds = [
        r'mkdir "C:\Users\vmuser\Documents\canary_files" 2>NUL',
        r'echo This is a canary document for verification. > "C:\Users\vmuser\Documents\canary_files\canary_doc.txt"',
        r'echo This is a canary spreadsheet for verification. > "C:\Users\vmuser\Documents\canary_files\canary_sheet.xlsx"',
        r'echo This is a canary image for verification. > "C:\Users\vmuser\Documents\canary_files\canary_photo.jpg"',
    ]
    for c in cmds:
        _ssh(c)
    hashes = {}
    for name in ("canary_doc.txt", "canary_sheet.xlsx", "canary_photo.jpg"):
        out = _ssh(rf'certutil -hashfile "C:\Users\vmuser\Documents\canary_files\{name}" MD5 2>NUL')
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if len(lines) >= 2:
            hashes[name] = lines[1].replace(" ", "").lower()
    return hashes


def _create_infostealer_canaries():
    cmds = [
        r'mkdir "C:\Users\vmuser\Documents\credentials" 2>NUL',
        r'echo admin:SuperSecret123 > "C:\Users\vmuser\Documents\credentials\passwords.txt"',
        r'echo aws_access_key_id=AKIAIOSFODNN7EXAMPLE > "C:\Users\vmuser\Documents\credentials\aws_creds.txt"',
    ]
    for c in cmds:
        _ssh(c)


def check_defender_alerts():
    out = _ssh(
        'powershell -Command "Get-MpThreatDetection | Select-Object -Last 5 | Format-List"',
        timeout=20,
    )
    msgs = [l.strip() for l in out.splitlines() if l.strip()]
    count = out.count("ThreatID")
    return count, msgs


# ---------------------------------------------------------------------------
# Basic connectivity
# ---------------------------------------------------------------------------

@pytest.mark.vm
def test_vm_ssh_echo(vm_ssh_ready):
    result = vm_ssh_ready.ssh_cmd("echo ready")
    assert "ready" in result


@pytest.mark.vm
def test_vm_windows_version(vm_ssh_ready):
    result = vm_ssh_ready.ssh_cmd("ver")
    assert "Windows" in result or "10.0" in result


@pytest.mark.vm
def test_vm_scp_upload_download(vm_ssh_ready, tmp_path):
    test_file = tmp_path / "test_upload.txt"
    test_file.write_text("hello from test")
    remote = r"C:\Users\vmuser\test_upload.txt"

    assert vm_ssh_ready.scp(test_file, remote)
    content = vm_ssh_ready.ssh_cmd(f'type "{remote}"')
    assert "hello from test" in content

    # Clean up
    vm_ssh_ready.ssh_cmd(f'del "{remote}" 2>NUL')


# ---------------------------------------------------------------------------
# Canary creation
# ---------------------------------------------------------------------------

@pytest.mark.vm
def test_vm_canary_creation_ransomware(vm_ssh_ready):
    hashes = _create_ransomware_canaries()
    assert len(hashes) >= 3

    # Verify canaries exist
    listing = vm_ssh_ready.ssh_cmd(r'dir /B "C:\Users\vmuser\Documents\canary_files\"')
    assert "canary_doc.txt" in listing

    # Clean up
    vm_ssh_ready.ssh_cmd(r'cmd /c "rd /S /Q "C:\Users\vmuser\Documents\canary_files""')


@pytest.mark.vm
def test_vm_canary_creation_infostealer(vm_ssh_ready):
    _create_infostealer_canaries()

    # Verify credential files exist
    creds = vm_ssh_ready.ssh_cmd(r'type "C:\Users\vmuser\Documents\credentials\passwords.txt"')
    assert "admin" in creds or "SuperSecret" in creds

    # Clean up
    vm_ssh_ready.ssh_cmd(r'cmd /c "rd /S /Q "C:\Users\vmuser\Documents\credentials""')


# ---------------------------------------------------------------------------
# Defender query
# ---------------------------------------------------------------------------

@pytest.mark.vm
def test_vm_defender_query(vm_ssh_ready):
    count, msgs = check_defender_alerts()
    # Should not error — count may be 0 or more
    assert isinstance(count, int)
    assert isinstance(msgs, list)


# ---------------------------------------------------------------------------
# Upload and execute a benign exe
# ---------------------------------------------------------------------------

@pytest.mark.vm
def test_vm_upload_and_execute(vm_ssh_ready, mingw_available, tmp_path):
    source = (
        '#include <windows.h>\n'
        '#include <stdio.h>\n'
        'int main() {\n'
        '    HANDLE hFile = CreateFileA("C:\\\\Users\\\\vmuser\\\\test_output.txt",\n'
        '        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n'
        '    if (hFile != INVALID_HANDLE_VALUE) {\n'
        '        const char *msg = "test_passed";\n'
        '        DWORD written;\n'
        '        WriteFile(hFile, msg, 11, &written, NULL);\n'
        '        CloseHandle(hFile);\n'
        '    }\n'
        '    return 0;\n'
        '}\n'
    )
    src = tmp_path / "benign.c"
    exe = tmp_path / "benign.exe"
    src.write_text(source)

    ret = subprocess.run(
        ["x86_64-w64-mingw32-gcc", "-O2", "-s", "-static",
         str(src), "-o", str(exe)],
        capture_output=True, text=True,
    )
    assert ret.returncode == 0, f"Compilation failed: {ret.stderr}"

    remote_exe = r"C:\Users\vmuser\benign_test.exe"
    assert vm_ssh_ready.scp(exe, remote_exe)

    # Execute
    vm_ssh_ready.ssh_cmd(f'"{remote_exe}"')

    import time
    time.sleep(2)

    # Check output
    output = vm_ssh_ready.ssh_cmd(r'type "C:\Users\vmuser\test_output.txt"')
    assert "test_passed" in output

    # Clean up
    vm_ssh_ready.ssh_cmd(f'del "{remote_exe}" 2>NUL')
    vm_ssh_ready.ssh_cmd(r'del "C:\Users\vmuser\test_output.txt" 2>NUL')
