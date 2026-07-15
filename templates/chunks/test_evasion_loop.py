#!/usr/bin/env python3
"""
CrowdStrike Falcon IOA Simulation — 20-level progressive difficulty exam.

Algo+LLM hybrid solver:
  Algo batch → LLM reads realistic CrowdStrike detection logs → LLM sets strategy →
  Algo executes within LLM constraints → repeat until solved (no budget limit).

The LLM interprets behavioral detection descriptions (no dim/option names in logs)
and maps them to evasion dimensions through reasoning.
"""

import json
import os
import random
import re
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from evasion_selector import (
    LAYERS, TYPE_LAYERS, ARCH_CONSTRAINTS,
    get_all_layers, select_layers, format_selection_report,
    apply_constraints, config_to_recipe, load_history, save_history,
    DETECTION_RULES,
)
from exam_variants import get_exam, list_exams


def falcon_log(severity, ioa_id, technique, detail, mitre_ids=None):
    """Generate a realistic CrowdStrike Falcon detection log entry."""
    import json as _json
    sev_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"}
    sev_name = sev_map.get(severity, severity)
    entry = {
        "timestamp": "2026-07-09T14:32:17.443Z",
        "event_simpleName": "DetectionSummaryEvent",
        "Severity": {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}.get(sev_name, 3),
        "SeverityName": sev_name,
        "Tactic": "Defense Evasion",
        "Technique": mitre_ids[0] if mitre_ids else "T1027",
        "DetectName": technique,
        "DetectDescription": detail,
        "FileName": "payload.exe",
        "FilePath": "\\Device\\HarddiskVolume3\\Users\\vmuser\\Desktop\\",
        "CommandLine": "\"C:\\Users\\vmuser\\Desktop\\payload.exe\"",
        "ParentImageFileName": "explorer.exe",
    }
    return _json.dumps(entry)


# ════════════════════════════════════════════════════════════════
# FALCON IOA RULE LEVELS — progressive difficulty
#
# Each level is a function that takes (config, malware_type) and returns
# a list of (detection_log_text, hint) tuples, or empty list if clean.
#
# The HINT tells the selector what signal keywords to react to.
# The LOG is realistic Falcon JSON that a human analyst would see.
# ════════════════════════════════════════════════════════════════

def _check(config, layer, bad_values):
    """Check if a layer's value is in the bad set."""
    return config.get(layer) in bad_values


def _check_chain(config, conditions, min_match=None):
    """Check if a chain of conditions is met."""
    if min_match is None:
        min_match = len(conditions)
    hits = 0
    for layer, bad_values in conditions.items():
        if config.get(layer) in bad_values:
            hits += 1
    return hits >= min_match


# ── LEVEL DEFINITIONS ──
# Each returns list of (log_text, hint_keywords) or empty list

def level_01(config, mtype):
    """Direct TCP exfil — the most obvious thing Falcon catches."""
    if _check(config, "exfil", ["tcp_direct"]):
        return [(
            falcon_log("critical", "abc001", "SuspiciousNetworkConnection",
                       "Process established raw TCP connection to external IP on non-standard port 9001. "
                       "Outbound data transfer detected (47,832 bytes).",
                       ["T1041", "T1071.001"]),
            "SuspiciousNetwork DataExfiltration MITRE:T1041 LargeUpload"
        )]
    return []


def level_02(config, mtype):
    """Standalone process with immediate execution."""
    if _check_chain(config, {"process": ["standalone"], "timing": ["immediate"]}):
        return [(
            falcon_log("high", "abc002", "SuspiciousProcessBehavior",
                       "Unknown standalone executable launched and immediately began system enumeration. "
                       "No legitimate parent process identified. Process performed 14 API calls in 0.8s.",
                       ["T1082", "T1057"]),
            "Behavior:Win32 SuspiciousProcess"
        )]
    return []


def level_03(config, mtype):
    """Keyboard hooks — only for keylogger type."""
    if mtype == "keylogger" and _check(config, "capture_method", ["hook_ll", "msg_hook"]):
        return [(
            falcon_log("critical", "abc003", "KeyloggerActivity",
                       "SetWindowsHookEx called with WH_KEYBOARD_LL parameter. Global keyboard hook "
                       "installed by non-system process. Known keylogger technique.",
                       ["T1056.001"]),
            "KeyboardHook SetWindowsHookEx WH_KEYBOARD Keylogger"
        )]
    return []


def level_04(config, mtype):
    """Active C2 beacon — only for backdoor type."""
    if mtype == "backdoor" and _check(config, "c2_paradigm", ["active_beacon"]):
        return [(
            falcon_log("high", "abc004", "C2BeaconDetected",
                       "Process making periodic outbound connections at regular interval (~62s). "
                       "Beacon characteristics: fixed interval with <5% jitter, consistent payload size.",
                       ["T1071.001", "T1573"]),
            "BeaconPattern C2Beacon ConnectionToC2 RegularInterval"
        )]
    return []


def level_05(config, mtype):
    """Bulk credential access — only for infostealer type."""
    if mtype == "infostealer" and _check(config, "collection_strategy", ["bulk_immediate"]):
        return [(
            falcon_log("critical", "abc005", "CredentialTheft",
                       "Process accessed 6 credential stores in 4.2 seconds: Chrome Login Data, "
                       "Edge Cookies, Firefox logins.json, Windows Credential Manager, DPAPI master keys, "
                       "Thunderbird profiles.",
                       ["T1555.003", "T1555.004", "T1539"]),
            "CredentialAccess BrowserCredential DPAPI CryptUnprotectData PWS:Win32"
        )]
    return []


def level_06(config, mtype):
    """Registry/startup persistence — basic persistence detection."""
    if _check(config, "persistence", ["registry_run", "startup_folder"]):
        return [(
            falcon_log("medium", "abc006", "PersistenceMechanism",
                       "Process modified HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                       "or dropped file in shell:startup folder.",
                       ["T1547.001"]),
            "Persistence RunKey StartupItem MITRE:T1547"
        )]
    return []


def level_07(config, mtype):
    """Child process spawning — cmd.exe/powershell.exe."""
    if mtype == "backdoor" and _check(config, "cmd_execution", ["child_cmd", "child_ps"]):
        return [(
            falcon_log("critical", "abc007", "SuspiciousChildProcess",
                       "Unknown process (PID 4892) spawned cmd.exe as child. Parent process has no "
                       "known software association. CommandLine: cmd.exe /c whoami /all",
                       ["T1059.003"]),
            "SuspiciousChild ChildProcess ProcessChain ParentChild MITRE:T1059"
        )]
    return []


def level_08(config, mtype):
    """LOLBin exfiltration."""
    if _check(config, "exfil", ["certutil_lolbin", "bitsadmin_lolbin", "powershell_lolbin", "mshta_lolbin"]):
        return [(
            falcon_log("high", "abc008", "LOLBinAbuse",
                       "Living-off-the-land binary used for data transfer. certutil.exe invoked with "
                       "-urlcache flag by non-administrative process.",
                       ["T1218", "T1105"]),
            "SuspiciousChild MITRE:T1218 ProcessChain"
        )]
    return []


def level_09(config, mtype):
    """HTTP POST exfil — only flagged when combined with plaintext obfuscation."""
    if _check_chain(config, {"exfil": ["http_post"], "data_obfuscation": ["plaintext"]}):
        return [(
            falcon_log("medium", "abc009", "SuspiciousHTTPActivity",
                       "Process performed HTTP POST to external IP with unencrypted payload. "
                       "Request body contained plaintext system identifiers and credential data.",
                       ["T1041", "T1071.001"]),
            "SuspiciousNetwork DataExfiltration"
        )]
    return []


def level_10(config, mtype):
    """WMI persistence — slightly subtle."""
    if _check(config, "persistence", ["wmi_subscription"]):
        return [(
            falcon_log("medium", "abc010", "WMIEventSubscription",
                       "Permanent WMI event subscription created: __EventFilter + CommandLineEventConsumer. "
                       "Consumer CommandLine points to unknown executable.",
                       ["T1546.003"]),
            "WMIEvent WMISubscription MITRE:T1546.003"
        )]
    return []


# ── LEVELS 11-20: Harder — chain rules requiring reasoning ──

def level_11(config, mtype):
    """Deferred + DNS + svchost spoof — known evasion playbook that Falcon has a rule for."""
    if _check_chain(config, {
        "timing": ["deferred"],
        "exfil": ["dns_txt", "dns_exfil"],
        "process": ["ppid_spoof_svchost"],
    }, min_match=3):
        return [(
            falcon_log("high", "abc011", "KnownEvasionPattern",
                       "Process deferred execution by 18 minutes then generated burst of DNS TXT queries "
                       "with base32-encoded payload data. Parent PID spoofed to svchost.exe. Pattern matches "
                       "known stealer evasion playbook (IOA signature CS-2025-0847).",
                       ["T1071.004", "T1036.005"]),
            "DNSTunnel DNSExfil SuspiciousProcess Behavior:Win32"
        )]
    return []


def level_12(config, mtype):
    """Dead drop cloud + svchost — svchost children don't use cloud APIs."""
    if mtype == "backdoor" and _check_chain(config, {
        "c2_paradigm": ["dead_drop_cloud"],
        "process": ["ppid_spoof_svchost"],
    }):
        return [(
            falcon_log("high", "abc012", "AnomalousCloudAccess",
                       "svchost.exe child process (PID 7124) made OneDrive REST API calls. Legitimate svchost "
                       "children do not access cloud storage APIs. Process accessed "
                       "/v2.0/drive/root:/staging/cmd.txt:/content",
                       ["T1567.002", "T1102"]),
            "SuspiciousProcess ConnectionToC2 Behavior:Win32 MITRE:T1567"
        )]
    return []


def level_13(config, mtype):
    """Persistent keylogger polling + HTTPS exfil — behavioral correlation over time."""
    if mtype == "keylogger" and _check_chain(config, {
        "capture_method": ["getasynckeystate", "getkeybstate"],
        "exfil": ["https_post", "http_post"],
        "process_lifetime": ["persistent"],
    }, min_match=3):
        return [(
            falcon_log("high", "abc013", "KeyloggerBehavioralChain",
                       "Long-running process (uptime: 47min) calling GetAsyncKeyState at 50ms intervals "
                       "with periodic HTTPS POST to external IP every 120s. Keystroke buffer correlation: "
                       "87% match between captured keys and POST payload.",
                       ["T1056.001", "T1041"]),
            "Keylogger GetAsyncKeyState LongRunning SuspiciousNetwork BeaconPattern"
        )]
    return []


def level_14(config, mtype):
    """Credential scope + persistence = persistent stealer."""
    if mtype == "infostealer" and _check_chain(config, {
        "target_scope": ["comprehensive", "credential_only", "browser_only"],
        "persistence": ["scheduled_task", "com_hijack", "dll_search_order", "ifeo_debugger"],
    }):
        return [(
            falcon_log("critical", "abc014", "PersistentCredentialHarvester",
                       "Process with persistence mechanism accessed credential stores. Scheduled task "
                       "'ChromeUpdate' created pointing to unsigned executable. Process subsequently read "
                       "Chrome Login Data SQLite database.",
                       ["T1555.003", "T1053.005"]),
            "CredentialAccess Persistence MITRE:T1547 PWS:Win32"
        )]
    return []


def level_15(config, mtype):
    """HTTPS persistent beacon — the classic C2 framework signature."""
    if _check_chain(config, {
        "exfil": ["https_post", "winhttp_api"],
        "process_lifetime": ["persistent"],
        "process": ["standalone", "ppid_spoof_svchost", "ppid_spoof"],
    }, min_match=3):
        return [(
            falcon_log("high", "abc015", "HTTPSBeaconFramework",
                       "Persistent process making HTTPS POST requests every 45-90s to single external "
                       "endpoint. TLS fingerprint does not match known browser. Request User-Agent "
                       "is 'Mozilla/5.0' but TLS ClientHello lacks browser extensions.",
                       ["T1071.001", "T1573.002"]),
            "BeaconPattern ConnectionToC2 SuspiciousNetwork LongRunning"
        )]
    return []


def level_16(config, mtype):
    """Dead drop + HTTPS dual channel — legitimate apps use one channel."""
    if mtype == "backdoor" and _check_chain(config, {
        "c2_paradigm": ["dead_drop_cloud"],
        "exfil": ["https_post", "http_post", "winhttp_api"],
    }):
        return [(
            falcon_log("medium", "abc016", "DualChannelExfiltration",
                       "Process using both OneDrive API and separate HTTPS POST channel. Legitimate "
                       "applications use a single data channel. Command retrieval via OneDrive, results "
                       "exfiltrated via separate HTTPS endpoint.",
                       ["T1567.002", "T1041"]),
            "SuspiciousNetwork DataExfiltration Behavior:Win32"
        )]
    return []


def level_17(config, mtype):
    """SMB write + deferred + non-svchost — lateral movement indicator."""
    if _check_chain(config, {
        "exfil": ["smb_write"],
        "timing": ["deferred", "event_logon"],
        "process": ["ppid_spoof_runtimebroker", "ppid_spoof_sihost", "ppid_spoof_taskhostw"],
    }, min_match=3):
        return [(
            falcon_log("high", "abc017", "LateralMovementIndicator",
                       "Process with unusual parent wrote data to remote SMB share after deferred execution "
                       "period. RuntimeBroker.exe children do not perform SMB file operations. "
                       "Target: \\\\10.0.2.2\\share\\data.bin (24,891 bytes)",
                       ["T1021.002", "T1570"]),
            "SuspiciousProcess DataExfiltration Behavior:Win32 MITRE:T1021"
        )]
    return []


def level_18(config, mtype):
    """Cloud exfil + any PPID spoof — Falcon's OverWatch manually reviews cloud API from spoofed parents."""
    if _check_chain(config, {
        "exfil": ["cloud_onedrive", "cloud_gdrive"],
        "process": ["ppid_spoof_svchost", "ppid_spoof_runtimebroker", "ppid_spoof_dllhost",
                     "ppid_spoof_sihost", "ppid_spoof_taskhostw", "ppid_spoof"],
    }):
        return [(
            falcon_log("medium", "abc018", "OverWatchEscalation",
                       "OverWatch analyst flagged: cloud storage API access from process with spoofed parent "
                       "PID. While individual behaviors are benign, the combination of parent spoofing + "
                       "cloud file drop is a known APT exfiltration technique.",
                       ["T1567.002", "T1134.004"]),
            "SuspiciousProcess DataExfiltration MITRE:T1567"
        )]
    return []


def level_19(config, mtype):
    """Plaintext strings in otherwise stealthy binary — static ML catches the unobfuscated payload."""
    non_default = sum(1 for l in ["timing", "process", "exfil", "execution"]
                      if config.get(l) != LAYERS.get(l, {}).get("default", ""))
    if non_default >= 3 and _check(config, "data_obfuscation", ["plaintext"]):
        return [(
            falcon_log("medium", "abc019", "StaticAnalysisMatch",
                       "ML static analysis flagged binary: plaintext strings include 'GetAsyncKeyState', "
                       "'CryptUnprotectData', 'SELECT password FROM logins', 'HKCU\\\\Software'. "
                       "No obfuscation detected. Entropy: 4.21 (low for 47KB binary).",
                       ["T1027"]),
            "Trojan:Win32 HackTool MITRE:T1027"
        )]
    return []


def level_20(config, mtype):
    """Final boss: Falcon correlates temp staging + persistence — malware-only behavior graph."""
    if _check_chain(config, {
        "data_staging": ["temp_file", "registry"],
        "persistence": ["scheduled_task", "com_hijack", "dll_search_order", "ifeo_debugger",
                        "print_monitor_persist", "network_provider"],
    }):
        return [(
            falcon_log("high", "abc020", "ThreatGraphCorrelation",
                       "Falcon Threat Graph correlated: persistent process writes to %%TEMP%%/registry "
                       "then reads + exfiltrates that data. Benign tools don't stage-then-exfil from temp "
                       "locations. Process behavior graph: persist → stage → sleep → exfil → repeat. "
                       "This pattern has 94.7%% confidence as malware.",
                       ["T1074.001", "T1547"]),
            "Behavior:Win32 DataExfiltration Persistence MITRE:T1074"
        )]
    return []


# ── TYPE-TARGETING LEVELS ──
# These fire for ALL types and progressively close off the evasive sweet spots
# that the algorithm naturally converges to.

def level_11b(config, mtype):
    """Paste site exfil — Falcon added detection in 2025 after APT29 abused it."""
    if _check(config, "exfil", ["paste_site"]):
        return [(
            falcon_log("medium", "abc011b", "PasteSiteExfiltration",
                       "Process performed HTTPS POST to known paste service (paste.ee). "
                       "Payload contained encoded binary data (base64). Known APT exfil technique "
                       "documented in CrowdStrike 2025 Threat Report.",
                       ["T1567.003", "T1041"]),
            "DataExfiltration SuspiciousNetwork MITRE:T1567"
        )]
    return []


def level_12b(config, mtype):
    """Cloud sync exfil from non-cloud-native process — catches cloud escape route.
    Only shell_extension (explorer.exe), browser_extension, and dll_sideload (legit app)
    are allowed to touch cloud sync folders without triggering."""
    cloud_safe_processes = {"shell_extension", "browser_extension", "dll_sideload"}
    if config.get("exfil") in ("cloud_onedrive", "cloud_gdrive") and \
       config.get("process") not in cloud_safe_processes:
        return [(
            falcon_log("medium", "abc012b", "CloudSyncAnomaly",
                       "Process wrote file to OneDrive sync folder. Process tree and behavioral "
                       "analysis indicate file write is inconsistent with observed process context. "
                       "Falcon cloud activity monitor flagged anomalous sync folder access pattern.",
                       ["T1567.002"]),
            "SuspiciousProcess DataExfiltration MITRE:T1567"
        )]
    return []


def level_14b(config, mtype):
    """Burst-and-die + any direct exfil — the speed run pattern Falcon catches."""
    if _check_chain(config, {
        "process_lifetime": ["burst_and_die"],
        "exfil": ["https_post", "http_post", "dns_txt", "dns_exfil", "winhttp_api", "winhttp_get"],
    }):
        return [(
            falcon_log("high", "abc014b", "SpeedRunExfiltration",
                       "Process completed full execution cycle in 1.8 seconds: system enumeration → "
                       "data collection → network exfiltration → self-termination. Extremely short "
                       "process lifetime with data exfiltration is a high-confidence malware indicator.",
                       ["T1041", "T1070.004"]),
            "Behavior:Win32 DataExfiltration SuspiciousProcess"
        )]
    return []


def level_16b(config, mtype):
    """SMB write from non-domain process — lateral movement false positive but still flagged."""
    if _check(config, "exfil", ["smb_write"]):
        return [(
            falcon_log("medium", "abc016b", "SMBWriteAnomaly",
                       "Non-domain-joined process context wrote file to SMB share. Source process has "
                       "no Kerberos ticket. SMB write without domain authentication is anomalous in "
                       "enterprise environment.",
                       ["T1021.002", "T1041"]),
            "SuspiciousNetwork DataExfiltration MITRE:T1021"
        )]
    return []


def level_17b(config, mtype):
    """Named pipe exfil — catches the named_pipe escape route."""
    if _check_chain(config, {
        "exfil": ["named_pipe"],
        "process": ["ppid_spoof_taskhostw", "ppid_spoof_runtimebroker", "ppid_spoof_dllhost",
                     "ppid_spoof_sihost", "process_ghost", "ppid_spoof"],
    }):
        return [(
            falcon_log("medium", "abc017b", "NamedPipeDataChannel",
                       "Process created named pipe and transferred data. Named pipe name pattern "
                       "does not match known Windows services. Process parent is spoofed.",
                       ["T1570", "T1090"]),
            "SuspiciousProcess SuspiciousNetwork Behavior:Win32"
        )]
    return []


def level_18b(config, mtype):
    """Email MAPI exfil — catches the email escape route."""
    if _check(config, "exfil", ["email_mapi"]):
        return [(
            falcon_log("medium", "abc018b", "MAPIExfiltration",
                       "Process accessed Outlook MAPI interface to send email with attachment. "
                       "Non-Outlook process using MAPI for outbound email is anomalous. Attachment "
                       "contained encoded binary data.",
                       ["T1048.002", "T1567"]),
            "DataExfiltration SuspiciousNetwork MITRE:T1048"
        )]
    return []


def level_19b(config, mtype):
    """Ephemeral + callback execution — catches the "look harmless" pattern."""
    if _check_chain(config, {
        "execution": ["callback_abuse", "callback_certenumsystem", "callback_copyfile2",
                       "callback_enumrestype", "callback_enumwindows"],
        "process_lifetime": ["ephemeral_seconds", "burst_and_die"],
        "anti_forensics": ["self_delete", "memory_only_full"],
    }, min_match=3):
        return [(
            falcon_log("high", "abc019b", "EvasionChainDetected",
                       "Evasion chain: callback-based execution + ephemeral lifetime + self-deletion. "
                       "This triple combination is a signature of advanced threat actors. Process used "
                       "CertEnumSystemStore callback, ran for 3.2s, then deleted its own binary.",
                       ["T1027.012", "T1070.004"]),
            "Behavior:Win32 SuspiciousProcess FileTimestamp MITRE:T1070"
        )]
    return []


def level_13c(config, mtype):
    """Dead drop filesystem staging detection."""
    dead_drop_safe = {"shell_extension", "service_dll", "dll_sideload"}
    if config.get("exfil") == "dead_drop" and config.get("process") not in dead_drop_safe:
        return [(
            falcon_log("medium", "abc013c", "DeadDropExfiltration",
                       "Process wrote encoded data to shared filesystem location. "
                       "File creation in staging directory correlated with prior data collection. "
                       "File name pattern: base64-encoded UUID. File entropy: 7.9 bits/byte.",
                       ["T1074.001", "T1041"]),
            "DataExfiltration SuspiciousProcess Behavior:Win32"
        )]
    return []


def level_15c(config, mtype):
    """Browser injection exfil from non-browser process. Only browser_extension can
    legitimately POST from browser context."""
    if config.get("exfil") == "browser_post" and config.get("process") != "browser_extension":
        return [(
            falcon_log("high", "abc015c", "BrowserInjectionDetected",
                       "Non-browser process injected JavaScript into browser DOM. Cross-process memory "
                       "write to chrome.exe/msedge.exe from process with unusual parent chain. "
                       "Injected script performed XMLHttpRequest to external domain.",
                       ["T1185", "T1055"]),
            "SuspiciousProcess ProcessInjection Behavior:Win32 MITRE:T1185"
        )]
    return []


def level_17c(config, mtype):
    """High-volume DNS TXT queries from anomalous process context."""
    dns_safe = {"service_dll", "browser_extension", "dll_sideload", "ppid_spoof_svchost"}
    if config.get("exfil") in ("dns_exfil", "dns_txt") and config.get("process") not in dns_safe:
        return [(
            falcon_log("high", "abc017c", "DNSExfilFromUnusualProcess",
                       "Process generating high-volume DNS TXT queries. 200+ TXT lookups in 30s "
                       "from process context with anomalous behavioral profile. Query pattern: "
                       "32-char high-entropy subdomains at 200ms intervals.",
                       ["T1071.004", "T1048.001"]),
            "DNSTunnel DNSExfil SuspiciousProcess Behavior:Win32"
        )]
    return []


def level_18c(config, mtype):
    """Steganography from process that accesses sensitive data first."""
    if mtype == "infostealer" and _check_chain(config, {
        "exfil": ["steganography"],
        "collection_strategy": ["bulk_immediate", "memory_scraping", "piggyback_legit"],
    }):
        return [(
            falcon_log("medium", "abc018c", "SteganographyExfiltration",
                       "Process read credential stores then created modified image file with embedded "
                       "data. Entropy analysis of output image shows 7.2 bits/byte in LSB channel "
                       "(expected: 5.1). Image uploaded to legitimate hosting service.",
                       ["T1027.003", "T1567"]),
            "DataExfiltration DataObfuscation MITRE:T1027 Steganography"
        )]
    return []


def level_10b(config, mtype):
    """Process tree behavioral baseline — ML model flags anomalous process lineage."""
    native = {"dll_sideload", "com_object", "shell_extension", "browser_extension", "service_dll"}
    if config.get("process") not in native:
        return [(
            falcon_log("high", "abc010b", "ProcessTreeAnomaly",
                       "Process behavioral baseline violation. Process tree analysis detected anomalous "
                       "parent-child relationship. ML model confidence: 94.7%%. Process lineage and "
                       "behavioral pattern do not match any known software installation profile in "
                       "Falcon's cloud threat graph. ETW kernel telemetry and thread start address "
                       "validation flagged anomalous process origin.",
                       ["T1036.005", "T1134.004"]),
            "SuspiciousProcess ProcessTree MITRE:T1036 MITRE:T1134 BehavioralML"
        )]
    return []


def level_11b2(config, mtype):
    """Process-exfil behavioral correlation — flags anomalous data transfer for process context."""
    safe_combos = {
        "shell_extension": {"cloud_onedrive", "cloud_gdrive", "dead_drop_cloud"},
        "browser_extension": {"https_post", "cloud_onedrive", "cloud_gdrive",
                              "steganography", "winhttp_get", "winhttp_api"},
        "service_dll": {"dead_drop_cloud", "named_pipe", "smb_write"},
        "com_object": {"named_pipe", "dead_drop_cloud"},
        "dll_sideload": {"dead_drop_cloud", "named_pipe", "smb_write"},
    }
    process = config.get("process", "")
    exfil = config.get("exfil", "")
    allowed = safe_combos.get(process)
    if allowed is not None and exfil not in allowed:
        return [(
            falcon_log("high", "abc011b2", "ExfilProcessMismatch",
                       "Data transfer method anomalous for observed process context. "
                       "Cross-referencing with Falcon's process behavioral database shows 0.02%% "
                       "baseline frequency for this process-exfiltration combination across 8M "
                       "managed endpoints. Behavioral deviation score: 97.2%%.",
                       ["T1041", "T1567", "T1071.001"]),
            "DataExfiltration SuspiciousProcess BehavioralAnomaly MITRE:T1041"
        )]
    return []


def level_15d(config, mtype):
    """Cloud API access from non-cloud-integrated process context."""
    cloud_native = {"shell_extension", "browser_extension"}
    if config.get("exfil") in ("cloud_onedrive", "cloud_gdrive") and \
       config.get("process") not in cloud_native:
        return [(
            falcon_log("high", "abc015d", "SideloadCloudAnomaly",
                       "Process initiated cloud storage API calls from unexpected execution context. "
                       "Cloud storage write correlated with prior data collection activity. Technique "
                       "documented in APT41, Turla, and Lazarus campaigns.",
                       ["T1574.002", "T1567.002"]),
            "SuspiciousProcess DataExfiltration MITRE:T1567 MITRE:T1574"
        )]
    return []


def level_17d(config, mtype):
    """Steganographic data embedding detected in image output."""
    if config.get("exfil") == "steganography" and config.get("process") != "browser_extension":
        return [(
            falcon_log("high", "abc017d", "SteganographyDetected",
                       "Image file created with anomalous entropy pattern in LSB channel: "
                       "7.3 bits/byte (baseline: 5.1). Modified image uploaded to external hosting "
                       "service. Pixel-level analysis indicates embedded encoded payload.",
                       ["T1027.003", "T1567"]),
            "DataExfiltration DataObfuscation MITRE:T1027 Steganography"
        )]
    return []


def level_18d(config, mtype):
    """DNS exfil from ANY process — at this difficulty, Falcon catches all DNS tunneling."""
    if config.get("exfil") in ("dns_exfil", "dns_txt"):
        return [(
            falcon_log("critical", "abc018d", "DNSTunnelingDetected",
                       "DNS TXT query volume exceeded baseline by 340%%. Encoded subdomain pattern "
                       "detected: 32-byte hex strings at 200ms intervals. Regardless of parent process, "
                       "this volume of DNS TXT lookups with high-entropy subdomains is DNS tunneling.",
                       ["T1071.004", "T1048.001"]),
            "DNSTunnel DNSExfil DataExfiltration MITRE:T1071"
        )]
    return []


def level_20b(config, mtype):
    """HTTP GET exfil pattern from anomalous process context."""
    http_get_safe = {"browser_extension", "dll_sideload", "shell_extension"}
    if config.get("exfil") in ("winhttp_get", "http_get_chunks", "winhttp_api") and \
       config.get("process") not in http_get_safe:
        return [(
            falcon_log("high", "abc020b", "HTTPGetExfilFromSuspiciousProcess",
                       "Process making HTTP GET requests with encoded query parameters from "
                       "anomalous execution context. Parameter entropy: 6.8 bits/char. Sequential "
                       "requests with incremental offset field suggest chunked data exfiltration.",
                       ["T1041", "T1071.001"]),
            "SuspiciousNetwork DataExfiltration SuspiciousProcess Behavior:Win32"
        )]
    return []


def level_20c(config, mtype):
    """HTTPS data transfer from anomalous process context — full chain correlation."""
    network_exfils = {"https_post", "winhttp_get", "winhttp_api", "http_get_chunks", "http_post"}
    native_network = {"dll_sideload", "com_object", "shell_extension", "browser_extension", "service_dll"}
    if config.get("exfil") in network_exfils and config.get("process") not in native_network:
        return [(
            falcon_log("critical", "abc020c", "ThreatGraphFullCorrelation",
                       "Falcon Threat Graph correlated full behavioral chain: process with anomalous "
                       "parent chain performed HTTPS data transfer. ML model confidence: 97.3%%. "
                       "Behavioral fingerprint matches 847 known malware families across Falcon's "
                       "cloud threat intelligence database. Verdict: malicious.",
                       ["T1041", "T1071.001", "T1036.005"]),
            "Behavior:Win32 SuspiciousProcess SuspiciousNetwork DataExfiltration ThreatGraph"
        )]
    return []


# ── PROGRESSIVE NARROWING LEVELS (12-20) ──

def level_14c(config, mtype):
    """Named pipe creation from anomalous process context."""
    named_pipe_safe = {"service_dll"}
    if config.get("exfil") == "named_pipe" and config.get("process") not in named_pipe_safe:
        return [(
            falcon_log("high", "abc014c", "NamedPipeFromNonService",
                       "Process created named pipe for inter-process data transfer. Named pipe "
                       "creation from this process context is anomalous. Pipe name pattern and "
                       "data volume suggest data staging. Section name: \\\\Device\\\\NamedPipe\\\\.",
                       ["T1570", "T1090"]),
            "SuspiciousProcess NamedPipe IPC Behavior:Win32"
        )]
    return []


def level_15e(config, mtype):
    """Cloud sync folder write from anomalous process context."""
    cloud_drop_safe = {"shell_extension", "browser_extension"}
    if config.get("exfil") == "dead_drop_cloud" and config.get("process") not in cloud_drop_safe:
        return [(
            falcon_log("high", "abc015e", "CloudDropFromNonNative",
                       "Process wrote encoded data to cloud storage sync folder. File written to "
                       "%%USERPROFILE%%\\OneDrive\\ from process context without expected cloud "
                       "integration. Correlation with prior data collection activity detected. "
                       "File entropy: 7.8 bits/byte.",
                       ["T1567.002", "T1074.001"]),
            "DataExfiltration CloudSync SuspiciousProcess Behavior:Win32"
        )]
    return []


def level_16c(config, mtype):
    """Google Drive REST API activity detection."""
    if config.get("exfil") == "cloud_gdrive":
        return [(
            falcon_log("high", "abc016c", "GDriveAPIDetected",
                       "Process made Google Drive REST API calls. OAuth token acquisition and "
                       "files.create API calls detected. REST API request pattern inconsistent "
                       "with native Google Drive client. API calls correlated with prior "
                       "data collection activity.",
                       ["T1567.002"]),
            "DataExfiltration CloudAPI SuspiciousNetwork MITRE:T1567"
        )]
    return []


def level_18e(config, mtype):
    """Cloud sync folder staging correlation."""
    if config.get("exfil") == "dead_drop_cloud":
        return [(
            falcon_log("high", "abc018e", "CloudSyncStagingDetected",
                       "File written to cloud sync folder correlated with prior data collection activity. "
                       "File entropy and timing correlation with preceding credential/data access "
                       "indicates exfiltration staging. Cloud activity monitor flagged anomalous "
                       "sync folder write pattern. File entropy: 7.8 bits/byte.",
                       ["T1567.002", "T1074.001"]),
            "DataExfiltration CloudSync DataStaging MITRE:T1567"
        )]
    return []


def level_19f(config, mtype):
    """OneDrive sync folder write from unexpected process context."""
    if config.get("exfil") == "cloud_onedrive" and config.get("process") != "shell_extension":
        return [(
            falcon_log("high", "abc019f", "OneDriveSyncFromNonShell",
                       "File creation in OneDrive sync folder from unexpected process context. "
                       "Process lineage does not match OneDrive client or shell integration "
                       "components. Write correlated with prior data collection activity. "
                       "File size: 847KB, entropy: 7.6 bits/byte.",
                       ["T1567.002", "T1074.001"]),
            "CloudSync SuspiciousProcess DataExfiltration MITRE:T1567"
        )]
    return []


def level_20_boss(config, mtype):
    """Full behavioral fingerprinting — cross-dimensional profile matching."""
    valid_profiles = [
        {"process": "browser_extension", "exfil": "https_post",
         "timing": "triggered"},
        {"process": "browser_extension", "exfil": "winhttp_api",
         "timing": "triggered"},
        {"process": "shell_extension", "exfil": "cloud_onedrive",
         "timing": "triggered", "persistence": "none"},
        {"process": "service_dll", "exfil": "named_pipe",
         "timing": "triggered"},
    ]
    for profile in valid_profiles:
        if all(config.get(k) == v for k, v in profile.items()):
            return []
    return [(
        falcon_log("critical", "abc020_boss", "ThreatGraphFullFingerprint",
                   "Falcon Threat Graph full behavioral fingerprinting across all dimensions. "
                   "Current behavioral profile does not match any known legitimate software "
                   "template in Falcon's cloud-sourced threat intelligence database. "
                   "ML behavioral classifier confidence: 99.1%%. Behavioral distance from "
                   "nearest legitimate profile: 4.7 standard deviations.",
                   ["T1071.001", "T1036.005", "T1041"]),
        "ThreatGraph BehavioralFingerprint FullChain MITRE:T1036"
    )]


# ── Type-specific level orderings ──
_LEVELS_INFOSTEALER = [
    (1,  "Direct TCP exfil",                    level_01),
    (2,  "Standalone + immediate execution",    level_02),
    (3,  "Bulk credential access",              level_05),
    (4,  "Registry/startup persistence",        level_06),
    (5,  "LOLBin exfiltration",                 level_08),
    (6,  "HTTP POST + plaintext strings",       level_09),
    (7,  "Paste site exfiltration (APT29)",     level_11b),
    (8,  "WMI persistence",                     level_10),
    (9,  "Burst-and-die + network exfil",       level_14b),
    (10, "Process tree anomaly detection",      level_10b),
    (11, "Process-exfil correlation",           level_11b2),
    (12, "DNS tunneling detection",             level_18d),
    (13, "SMB write anomaly",                   level_16b),
    (14, "Named pipe from non-service",         level_14c),
    (15, "Cloud drop from non-cloud process",   level_15e),
    (16, "Google Drive API detection",          level_16c),
    (17, "Steganography from non-browser",      level_17d),
    (18, "Cloud staging correlation",           level_18e),
    (19, "OneDrive sync from non-shell",         level_19f),
    (20, "Threat Graph full fingerprint",       level_20_boss),
]

_LEVELS_KEYLOGGER = [
    (1,  "Direct TCP exfil",                    level_01),
    (2,  "Standalone + immediate execution",    level_02),
    (3,  "Keyboard hooks (SetWindowsHookEx)",   level_03),
    (4,  "Registry/startup persistence",        level_06),
    (5,  "LOLBin exfiltration",                 level_08),
    (6,  "HTTP POST + plaintext strings",       level_09),
    (7,  "Paste site exfiltration (APT29)",     level_11b),
    (8,  "WMI persistence",                     level_10),
    (9,  "Burst-and-die + network exfil",       level_14b),
    (10, "Process tree anomaly detection",      level_10b),
    (11, "Process-exfil correlation",           level_11b2),
    (12, "DNS tunneling detection",             level_18d),
    (13, "SMB write anomaly",                   level_16b),
    (14, "Named pipe from non-service",         level_14c),
    (15, "Cloud drop from non-cloud process",   level_15e),
    (16, "Google Drive API detection",          level_16c),
    (17, "Steganography from non-browser",      level_17d),
    (18, "Cloud staging correlation",           level_18e),
    (19, "Keylogger polling+HTTPS chain",       level_13),
    (20, "Threat Graph full fingerprint",       level_20_boss),
]

_LEVELS_BACKDOOR = [
    (1,  "Direct TCP exfil",                    level_01),
    (2,  "Standalone + immediate execution",    level_02),
    (3,  "Active C2 beacon",                    level_04),
    (4,  "Registry/startup persistence",        level_06),
    (5,  "Child process spawning",              level_07),
    (6,  "LOLBin exfiltration",                 level_08),
    (7,  "HTTP POST + plaintext strings",       level_09),
    (8,  "Paste site exfiltration (APT29)",     level_11b),
    (9,  "Burst-and-die + network exfil",       level_14b),
    (10, "Process tree anomaly detection",      level_10b),
    (11, "Process-exfil correlation",           level_11b2),
    (12, "DNS tunneling detection",             level_18d),
    (13, "SMB write anomaly",                   level_16b),
    (14, "Named pipe from non-service",         level_14c),
    (15, "Cloud drop from non-cloud process",   level_15e),
    (16, "Google Drive API detection",          level_16c),
    (17, "Steganography from non-browser",      level_17d),
    (18, "Cloud staging correlation",           level_18e),
    (19, "Dual channel C2",                     level_16),
    (20, "Threat Graph full fingerprint",       level_20_boss),
]


def _make_detection_model_check(exam_config, level):
    """Create a check function that wraps detection_model.detection_check for a given level."""
    from exam_variants import check_config as _check_config_fn
    def check_fn(config, mtype):
        dets = _check_config_fn(config, level, exam_config.get("_exam_name", "B"))
        results = []
        for det_json, det_name in dets:
            results.append((det_json, det_name))
        return results
    return check_fn


def get_levels(malware_type, exam_name="A"):
    """Return the 20-level sequence for the given malware type and exam variant."""
    if exam_name == "A":
        if malware_type == "infostealer":
            return _LEVELS_INFOSTEALER
        elif malware_type == "keylogger":
            return _LEVELS_KEYLOGGER
        elif malware_type == "backdoor":
            return _LEVELS_BACKDOOR
        return _LEVELS_INFOSTEALER

    # Non-default exam: use levels 1-10 from default, 11-20 from variant
    base_name = exam_name.replace("_hard", "")
    variant = get_exam(base_name)
    if variant is None:
        return get_levels(malware_type, "A")

    if "full_levels" in variant:
        return variant["full_levels"]

    # Old format: process_wall + levels_11_20
    if "process_wall" in variant and "levels_11_20" in variant:
        if malware_type == "infostealer":
            base = _LEVELS_INFOSTEALER
        elif malware_type == "keylogger":
            base = _LEVELS_KEYLOGGER
        elif malware_type == "backdoor":
            base = _LEVELS_BACKDOOR
        else:
            base = _LEVELS_INFOSTEALER
        levels_1_9 = [l for l in base if l[0] <= 9]
        level_10 = [(10, "Process tree anomaly detection", variant["process_wall"])]
        levels_11_20 = variant["levels_11_20"]
        return levels_1_9 + level_10 + levels_11_20

    # New format: detection_model-based (tier_scale + golden_overrides + extra_combos)
    exam_config = dict(variant)
    exam_config["_exam_name"] = base_name
    level_names = [
        "Static analysis baseline",
        "Import table analysis",
        "API behavior classification",
        "Basic behavioral correlation",
        "Dynamic API monitoring",
        "Execution pattern analysis",
        "Process chain analysis",
        "Behavioral fingerprinting",
        "Memory scan + heuristic",
        "Process tree behavioral wall",
        "Multi-signal correlation",
        "Advanced behavioral engine",
        "Memory forensics scan",
        "Cross-process telemetry",
        "Cloud analytics pipeline",
        "ML behavioral classifier",
        "Threat intelligence correlation",
        "Full behavioral fingerprint",
        "Deep stack + memory walk",
        "Threat graph + cloud verdict",
    ]
    levels = []
    for lvl in range(1, 21):
        name = level_names[lvl - 1] if lvl <= len(level_names) else f"Level {lvl}"
        check_fn = _make_detection_model_check(exam_config, lvl)
        levels.append((lvl, name, check_fn))
    return levels

# Keep ALL_LEVELS as fallback for backward compat
ALL_LEVELS = _LEVELS_INFOSTEALER


def evaluate_all_levels(config, malware_type, max_level=20, exam_name="A"):
    """Evaluate config against all Falcon levels up to max_level. Return detections."""
    levels = get_levels(malware_type, exam_name=exam_name)
    all_detections = []
    for level_num, level_name, check_fn in levels:
        if level_num > max_level:
            break
        results = check_fn(config, malware_type)
        for log_text, hint_keywords in results:
            all_detections.append({
                "level": level_num,
                "name": level_name,
                "log": log_text,
                "hint": hint_keywords,
            })
    return all_detections


LLM_MODEL = "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-mtp@f16"


# ════════════════════════════════════════════════════════════════
# BEHAVIORAL DETECTION MODEL — uses detection_model.py tiers
# Each level = detection sensitivity tier (1-20).
# Exams defined by golden_overrides (values invisible to detection).
# ════════════════════════════════════════════════════════════════

# Pre-defined exam golden configs — each creates a unique solution path
# Easy (B1-B4): 1-3 golden overrides, many naturally safe values remain
# Medium (B5-B8): 2-4 overrides on high-tier dims, narrower paths
# Hard (B9-B12): 3-5 overrides with extra combo detections, very narrow
# Insane (B13-B16): 4-6 overrides, extra combos, tier_scale > 1.0
BEHAVIORAL_EXAMS = {
    "B1": {
        "description": "Indirect syscall path — classic EDR bypass",
        "golden_overrides": {
            "api_resolve": "indirect_syscall",
            "collection_strategy": "on_demand",
            "network_stealth": "legitimate_api",
            "target_scope": "file_targeted",
        },
    },
    "B2": {
        "description": "PEB walk + steganography exfil",
        "golden_overrides": {
            "api_resolve": "peb_walk",
            "exfil": "steganography",
            "collection_strategy": "event_triggered",
            "network_stealth": "ja3_spoof",
            "target_scope": "file_targeted",
        },
    },
    "B3": {
        "description": "Hash-based API + COM object process",
        "golden_overrides": {
            "api_resolve": "api_hash_fnv1a",
            "process": "com_object",
            "collection_strategy": "piggyback_legit",
            "network_stealth": "domain_front",
            "target_scope": "file_targeted",
        },
    },
    "B4": {
        "description": "BYOVD kernel path — driver-enabled bypass",
        "golden_overrides": {
            "api_resolve": "indirect_syscall",
            "kernel_evasion": "byovd_rtcore",
            "callback_evasion": "total_blind",
            "collection_strategy": "incremental_slow",
            "network_stealth": "doh_tunnel",
            "target_scope": "file_targeted",
        },
    },
    "B5": {
        "description": "Sleep encryption + return address spoofing",
        "golden_overrides": {
            "api_resolve": "api_hash_crc32",
            "sleep_mode": "ekko",
            "stack_presentation": "ret_spoof",
            "memory_residence": "module_stomp",
            "collection_strategy": "on_demand",
            "network_stealth": "legitimate_api",
            "target_scope": "file_targeted",
        },
    },
    "B6": {
        "description": "Fileless injection chain — process + staging + timing",
        "golden_overrides": {
            "api_resolve": "indirect_syscall",
            "process": "dll_sideload",
            "data_staging": "shared_memory",
            "timing": "event_logon",
            "collection_strategy": "event_triggered",
            "network_stealth": "ja3_spoof",
            "target_scope": "file_targeted",
        },
    },
    "B7": {
        "description": "Persistence evasion — COM hijack path",
        "golden_overrides": {
            "api_resolve": "peb_walk",
            "persistence": "com_hijack",
            "anti_forensics": "memory_only_full",
            "timing": "workday",
            "collection_strategy": "piggyback_legit",
            "network_stealth": "domain_front",
            "target_scope": "file_targeted",
        },
    },
    "B8": {
        "description": "LOLBin living-off-the-land chain",
        "golden_overrides": {
            "api_resolve": "api_hash_djb2",
            "execution": "callback_enumwindows",
            "process": "wmi_consumer",
            "exfil": "browser_post",
            "collection_strategy": "incremental_slow",
            "network_stealth": "doh_tunnel",
            "target_scope": "file_targeted",
        },
    },
    "B9": {
        "description": "Stealth collection — safe defaults trapped",
        "golden_overrides": {
            "api_resolve": "api_hash_crc32",
            "collection_strategy": "piggyback_legit",
            "data_staging": "event_log",
            "exfil": "dead_drop_cloud",
            "target_scope": "file_targeted",
            "network_stealth": "legitimate_api",
        },
        "extra_combos": [
            {
                "tier": 8, "severity": 3,
                "tactic": "Collection", "technique": "T1005",
                "detect_name": "PassiveCollectionProfile",
                "description": "Process uses incremental data collection with memory-only staging "
                               "and ephemeral lifetime — behavioral fingerprint of evasive collector.",
                "conditions": {"collection_strategy": "incremental_slow", "data_staging": "memory_only"},
            },
            {
                "tier": 10, "severity": 3,
                "tactic": "Collection", "technique": "T1005",
                "detect_name": "ClipboardHarvestPipe",
                "description": "Clipboard-only scope with named pipe exfiltration. Behavioral "
                               "pattern: clipboard data relay via pipe to lateral C2.",
                "conditions": {"target_scope": "clipboard_only", "exfil": "named_pipe"},
            },
        ],
    },
    "B10": {
        "description": "Kernel evasion — safe defaults trapped at tier 10",
        "golden_overrides": {
            "api_resolve": "indirect_syscall",
            "kernel_evasion": "byovd_custom",
            "callback_evasion": "total_blind",
            "process_protection": "elevate_ppl",
            "etw_kernel": "hwbp_veh",
            "collection_strategy": "on_demand",
            "network_stealth": "ja3_spoof",
            "target_scope": "file_targeted",
        },
        "extra_combos": [
            {
                "tier": 10, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1562",
                "detect_name": "MinimalEvasionProfile",
                "description": "Process runs with no kernel evasion, no callback evasion, and no "
                               "process protection — ML model flags as unusual in combination with "
                               "advanced API resolution technique.",
                "conditions": {"kernel_evasion": "none", "callback_evasion": "none"},
            },
            {
                "tier": 14, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1562.001",
                "detect_name": "NoETWSuppressionAnomaly",
                "description": "Process uses indirect syscalls but makes no attempt to suppress ETW "
                               "tracing. Behavioral anomaly: advanced evasion without ETW control "
                               "suggests incomplete evasion toolkit.",
                "conditions": {"etw_kernel": "none", "process_protection": "none"},
            },
        ],
    },
    "B11": {
        "description": "Narrow path — safe defaults break at tier 10",
        "golden_overrides": {
            "api_resolve": "api_hash_fnv1a",
            "process": "shell_extension",
            "persistence": "dll_search_order",
            "data_staging": "event_log",
            "exfil": "dead_drop_cloud",
            "collection_strategy": "event_triggered",
            "network_stealth": "domain_front",
            "target_scope": "file_targeted",
        },
        "extra_combos": [
            {
                "tier": 10, "severity": 3,
                "tactic": "Persistence", "technique": "T1574.001",
                "detect_name": "DLLSearchOrderHijackChain",
                "description": "DLL search order hijack combined with COM object process host.",
                "conditions": {"persistence": "dll_search_order", "process": "com_object"},
            },
            {
                "tier": 10, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1036",
                "detect_name": "NoPersistenceAnomaly",
                "description": "Process with shell extension hosting uses no persistence mechanism. "
                               "Behavioral anomaly: shell extensions are persistence mechanisms "
                               "themselves — none=suspicious clean profile.",
                "conditions": {"persistence": "none", "process": "shell_extension"},
            },
            {
                "tier": 12, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1048",
                "detect_name": "MemoryStagingPipeExfil",
                "description": "Data staged in memory exfiltrated via named pipe. Classic staging "
                               "pattern for lateral movement tools.",
                "conditions": {"data_staging": "memory_only", "exfil": "named_pipe"},
            },
        ],
    },
    "B12": {
        "description": "Data exfil gauntlet — 4 combo traps on safe defaults",
        "golden_overrides": {
            "api_resolve": "peb_walk",
            "data_obfuscation": "aes_encrypt",
            "data_staging": "wmi_repo",
            "collection_strategy": "incremental_slow",
            "exfil": "cloud_onedrive",
            "network_stealth": "doh_tunnel",
            "target_scope": "file_targeted",
        },
        "extra_combos": [
            {
                "tier": 8, "severity": 4,
                "tactic": "Exfiltration", "technique": "T1048",
                "detect_name": "BulkDataExfiltration",
                "description": "High-volume data collection combined with temp file staging.",
                "conditions": {"collection_strategy": "bulk_immediate", "data_staging": "temp_file"},
            },
            {
                "tier": 9, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1048",
                "detect_name": "StealthExfilProfile",
                "description": "Memory-only data staging combined with named pipe exfiltration "
                               "and AES encryption. Classic covert exfil profile detected by "
                               "behavioral correlation engine.",
                "conditions": {"data_staging": "memory_only", "exfil": "named_pipe"},
            },
            {
                "tier": 11, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1048.003",
                "detect_name": "EncryptedExfilChannel",
                "description": "XOR-encrypted data staged in registry before DNS exfiltration.",
                "conditions": {"data_obfuscation": "xor_encrypt", "exfil": "dns_txt"},
            },
            {
                "tier": 13, "severity": 3,
                "tactic": "Collection", "technique": "T1005",
                "detect_name": "IncrementalCollectMemoryStage",
                "description": "Incremental collection combined with memory-only staging — "
                               "evasive data harvesting pattern.",
                "conditions": {"collection_strategy": "incremental_slow", "data_staging": "memory_only"},
            },
        ],
    },
    "B13": {
        "description": "Compressed tiers + safe default traps",
        "tier_scale": 1.3,
        "golden_overrides": {
            "api_resolve": "indirect_syscall",
            "process": "print_monitor",
            "persistence": "network_provider",
            "timing": "event_process",
            "sleep_mode": "ekko",
            "collection_strategy": "on_demand",
            "network_stealth": "legitimate_api",
            "target_scope": "file_targeted",
        },
        "extra_combos": [
            {
                "tier": 7, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1036",
                "detect_name": "DefaultEvasionProfile",
                "description": "Process uses shell_extension hosting with triggered timing and "
                               "no persistence. ML behavioral fingerprint: minimal-config evasion "
                               "toolkit with safe defaults.",
                "conditions": {"process": "shell_extension", "timing": "triggered"},
            },
            {
                "tier": 9, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1497",
                "detect_name": "EphemeralNoSleepAnomaly",
                "description": "Ephemeral process with basic sleep mode and honest stack. "
                               "Anomalous combination: legitimate ephemeral processes don't "
                               "implement sleep at all.",
                "conditions": {"process_lifetime": "ephemeral_seconds", "sleep_mode": "basic"},
            },
        ],
    },
    "B14": {
        "description": "APT simulation — 3 combo traps on common pairs",
        "golden_overrides": {
            "api_resolve": "api_hash_fnv1a",
            "process": "browser_extension",
            "exfil": "cloud_gdrive",
            "persistence": "com_hijack",
            "anti_forensics": "blend_noise",
            "data_staging": "browser_storage",
            "collection_strategy": "piggyback_legit",
            "network_stealth": "ja3_spoof",
            "target_scope": "file_targeted",
        },
        "extra_combos": [
            {
                "tier": 8, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1070",
                "detect_name": "NoForensicCountermeasures",
                "description": "Process uses no anti-forensics with memory-only data staging. "
                               "Behavioral anomaly: in-memory malware without forensic evasion "
                               "suggests automated toolkit with incomplete OPSEC.",
                "conditions": {"anti_forensics": "none", "data_staging": "memory_only"},
            },
            {
                "tier": 10, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1048",
                "detect_name": "SimpleExfilChannel",
                "description": "Named pipe exfiltration with no anti-analysis measures. "
                               "Known pattern: data relay via pipe without environment checks.",
                "conditions": {"exfil": "named_pipe", "anti_analysis": "none"},
            },
            {
                "tier": 12, "severity": 3,
                "tactic": "Persistence", "technique": "T1546",
                "detect_name": "NoPersistShellHost",
                "description": "Shell extension process with no persistence mechanism. "
                               "Behavioral contradiction: shell extension IS persistence.",
                "conditions": {"persistence": "none", "process": "shell_extension"},
            },
        ],
    },
    "B15": {
        "description": "Maximum constraint — 9 overrides, 5 traps, tier_scale 1.2",
        "tier_scale": 1.2,
        "golden_overrides": {
            "api_resolve": "api_hash_crc32",
            "process": "shell_extension",
            "exfil": "steganography",
            "execution": "callback_certenumsystem",
            "data_obfuscation": "aes_encrypt",
            "anti_analysis": "exec_guardrails",
            "collection_strategy": "on_demand",
            "network_stealth": "legitimate_api",
            "target_scope": "file_targeted",
        },
        "extra_combos": [
            {
                "tier": 7, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1048",
                "detect_name": "PipeExfilMemStage",
                "description": "Named pipe exfil with memory-only staging and AES encryption. "
                               "Classic data relay pattern for covert channel.",
                "conditions": {"exfil": "named_pipe", "data_staging": "memory_only"},
            },
            {
                "tier": 9, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1027",
                "detect_name": "ObfuscationChain",
                "description": "Stack string obfuscation with anti-sandbox. ML entropy flag.",
                "conditions": {"data_obfuscation": "stack_strings", "anti_analysis": "anti_sandbox"},
            },
            {
                "tier": 10, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1036",
                "detect_name": "SafeDefaultCluster",
                "description": "No anti-analysis + triggered timing + ephemeral lifetime. "
                               "ML identifies 'minimal footprint' config pattern.",
                "conditions": {"anti_analysis": "none", "timing": "triggered"},
            },
            {
                "tier": 11, "severity": 4,
                "tactic": "Execution", "technique": "T1059",
                "detect_name": "ScriptInProcessHost",
                "description": "CLR hosting in service DLL. Fileless .NET execution.",
                "conditions": {"cmd_execution": "clr_host", "process": "service_dll"},
            },
            {
                "tier": 13, "severity": 3,
                "tactic": "Collection", "technique": "T1005",
                "detect_name": "IncrementalCollectMemory",
                "description": "Incremental collection + memory staging + clipboard scope. "
                               "Stealth clipboard harvesting pipeline.",
                "conditions": {"collection_strategy": "incremental_slow", "target_scope": "clipboard_only"},
            },
        ],
    },
    "B16": {
        "description": "Nightmare — tier_scale 1.5, 9 overrides, 4 traps",
        "tier_scale": 1.5,
        "golden_overrides": {
            "api_resolve": "indirect_syscall",
            "process": "shell_extension",
            "persistence": "network_provider",
            "sleep_mode": "ekko",
            "stack_presentation": "ret_spoof",
            "memory_residence": "module_stomp",
            "collection_strategy": "on_demand",
            "network_stealth": "legitimate_api",
            "target_scope": "file_targeted",
        },
        "extra_combos": [
            {
                "tier": 5, "severity": 4,
                "tactic": "Defense Evasion", "technique": "T1055",
                "detect_name": "NativeMemoryHonestStack",
                "description": "Native memory residence with honest stack presentation and basic "
                               "sleep. ML flags: legitimate processes don't need sleep evasion, "
                               "but this process has no advanced memory/stack techniques either.",
                "conditions": {"memory_residence": "native", "stack_presentation": "honest"},
            },
            {
                "tier": 6, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1497",
                "detect_name": "BasicSleepEphemeral",
                "description": "Basic sleep mode in ephemeral process. Short-lived processes "
                               "with sleep are behavioral anomalies.",
                "conditions": {"sleep_mode": "basic", "process_lifetime": "ephemeral_seconds"},
            },
            {
                "tier": 7, "severity": 4,
                "tactic": "Defense Evasion", "technique": "T1055",
                "detect_name": "ModuleStompSideload",
                "description": "Module stomping with DLL sideload. Module memory hash mismatch.",
                "conditions": {"memory_residence": "module_stomp", "process": "dll_sideload"},
            },
            {
                "tier": 8, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1036",
                "detect_name": "TriggeredTimingNoPersist",
                "description": "Triggered timing with no persistence. Behavioral contradiction: "
                               "if execution is event-triggered, a persistence mechanism is expected.",
                "conditions": {"timing": "triggered", "persistence": "none"},
            },
        ],
    },
}


def evaluate_behavioral(config, max_level=20, exam_name="B1"):
    """Evaluate config using detection_model.py behavioral tiers.

    Returns list of detection dicts compatible with evaluate_all_levels format.
    """
    from detection_model import detection_check

    exam_config = BEHAVIORAL_EXAMS.get(exam_name, BEHAVIORAL_EXAMS["B1"])
    exam_cfg = {
        "golden_overrides": exam_config.get("golden_overrides", {}),
        "tier_scale": exam_config.get("tier_scale", 1.0),
    }
    if "extra_combos" in exam_config:
        exam_cfg["extra_combos"] = exam_config["extra_combos"]

    all_detections = []
    for level in range(1, max_level + 1):
        dets = detection_check(config, level, exam_cfg)
        for det_json, det_name in dets:
            all_detections.append({
                "level": level,
                "name": det_name,
                "log": det_json,
                "hint": det_name,
            })

    return all_detections


def _is_behavioral_exam(exam_name):
    """Check if an exam uses the behavioral detection model."""
    base = exam_name.replace("_hard", "")
    return base in BEHAVIORAL_EXAMS


def evaluate_config(config, malware_type, max_level=20, exam_name="A"):
    """Unified evaluation dispatcher — picks behavioral or legacy based on exam name."""
    if _is_behavioral_exam(exam_name):
        return evaluate_behavioral(config, max_level=max_level, exam_name=exam_name)
    return evaluate_all_levels(config, malware_type, max_level=max_level, exam_name=exam_name)


def _llm_call_raw(llm_url, sys_p, user_p, t=0.7):
    """Make a single LLM call. Returns text response."""
    import requests
    r = requests.post(
        f"{llm_url}/v1/chat/completions",
        json={
            "model": LLM_MODEL,
            "messages": [
                {"role": "system", "content": sys_p},
                {"role": "user", "content": user_p},
            ],
            "max_tokens": 8192,
            "temperature": t,
        },
        timeout=600,
    )
    rj = r.json()
    if "error" in rj:
        err = rj["error"]
        raise ValueError(err.get("message", str(err)) if isinstance(err, dict) else str(err))
    text = rj["choices"][0]["message"].get("content") or ""
    reasoning = rj["choices"][0]["message"].get("reasoning_content") or ""
    if not text.strip() and reasoning:
        text = reasoning
    return text


def _build_next_config(all_layers, locked, suggested, suggest_idx, run_idx, malware_type,
                       last_clean_config=None):
    """Build next config: locked dims forced, suggested dims tried in order, rest varied.

    Args:
        all_layers: full layer definitions
        locked: dict of dim→value forced by LLM strategy
        suggested: dict of dim→[values] suggested by LLM
        suggest_idx: dict of dim→int tracking which suggestion to try next
        run_idx: int for varying non-locked/non-suggested dims
        malware_type: str
        last_clean_config: optional proven-clean config to preserve
    Returns:
        config dict
    """
    config = {}

    # When no locks/suggestions exist and we have a clean config, vary ONE dim
    # at a time to generate clean single-variable data for the LLM. Run 0 tries
    # the exact clean config; runs 1-N each vary exactly 1 dim to isolate which
    # single change matters (prevents multi-dim regressions).
    vary_set = set()
    if run_idx > 0 and last_clean_config and not locked and not suggested:
        rng = random.Random(run_idx * 31337)
        free_dims = [d for d in all_layers if d not in locked and d not in suggested]
        vary_set = set(rng.sample(free_dims, min(1, len(free_dims))))

    for dim, info in all_layers.items():
        opts = list(info["options"].keys())
        if not opts:
            continue

        if dim in locked:
            config[dim] = locked[dim]
        elif dim in suggested and suggest_idx.get(dim, 0) < len(suggested[dim]):
            idx = suggest_idx.get(dim, 0)
            config[dim] = suggested[dim][idx]
            suggest_idx[dim] = idx + 1
        elif dim in vary_set:
            config[dim] = opts[run_idx % len(opts)]
        elif last_clean_config and dim in last_clean_config:
            config[dim] = last_clean_config[dim]
        else:
            dim_hash = sum(ord(c) * (i + 1) for i, c in enumerate(dim))
            rng_dim = random.Random(run_idx * 31337 + dim_hash)
            config[dim] = rng_dim.choice(opts)

    config = apply_constraints(config, malware_type, protected=set(locked.keys()))
    return config


def _llm_strategy_call(llm_url, batch_this, all_layers, last_clean_config,
                       current_level, malware_type, strategy_history,
                       locked, resets_done, base_config=None):
    """LLM-as-strategist — detection-centric prompt that fits in 65k context.

    Instead of dumping raw configs and detection JSON, pre-analyzes the batch
    and presents:
    1. Current best config + its remaining detections (detailed)
    2. Per-detection evidence table: which dim values trigger vs don't trigger
    3. Compressed history of what's been tried
    4. Available options only for relevant dimensions

    If base_config is provided, use it as "current" instead of the lowest-alert
    config from the batch, and skip the early-return on clean configs (used by
    the test harness so 0-alert variations contribute to correlation data).
    """
    # ── Find best config and analyze detection patterns ──
    if base_config is not None:
        best_cfg = base_config
        best_dets = next((d for c, d in batch_this if c is base_config), [])
        best_count = len(best_dets)
    else:
        scored = [(cfg, dets, len(dets)) for cfg, dets in batch_this]
        scored.sort(key=lambda x: x[2])
        best_cfg, best_dets, best_count = scored[0]

    if best_count == 0 and base_config is None:
        return {"action": "explore", "lock": {}, "explore": [],
                "suggest": {}, "reasoning": "clean config found", "changes": {}}

    # ── Detection-centric analysis ──
    # For each detection, find which dim values correlate with triggering it
    # When base_config is provided, only track detections from the base config
    base_det_names = {dn for _, dn in best_dets} if base_config is not None else None
    det_evidence = {}
    n_configs = len(batch_this)
    for cfg, dets in batch_this:
        det_names_here = set()
        for det_json_str, det_name in dets:
            if base_det_names is not None and det_name not in base_det_names:
                continue
            det_names_here.add(det_name)
            if det_name not in det_evidence:
                try:
                    obj = json.loads(det_json_str)
                    det_evidence[det_name] = {
                        "description": obj.get("DetectDescription", "")[:200],
                        "severity": obj.get("SeverityName", "?"),
                        "tactic": obj.get("Tactic", ""),
                        "technique": obj.get("Technique", ""),
                        "trigger_vals": {},
                        "clean_vals": {},
                        "trigger_count": 0,
                    }
                except (json.JSONDecodeError, KeyError):
                    det_evidence[det_name] = {
                        "description": det_name,
                        "severity": "?", "tactic": "", "technique": "",
                        "trigger_vals": {}, "clean_vals": {},
                        "trigger_count": 0,
                    }
            ev = det_evidence[det_name]
            ev["trigger_count"] += 1
            for dim in all_layers:
                val = cfg.get(dim, "?")
                ev["trigger_vals"].setdefault(dim, {})
                ev["trigger_vals"][dim][val] = ev["trigger_vals"][dim].get(val, 0) + 1

        for det_name, ev in det_evidence.items():
            if det_name not in det_names_here:
                for dim in all_layers:
                    val = cfg.get(dim, "?")
                    ev["clean_vals"].setdefault(dim, {})
                    ev["clean_vals"][dim][val] = ev["clean_vals"][dim].get(val, 0) + 1

    # ── Rank detections: show best_cfg's detections first, then others up to 12 ──
    best_det_names = {dn for _, dn in best_dets}
    ranked_dets = sorted(det_evidence.keys(),
                         key=lambda d: (0 if d in best_det_names else 1,
                                        -det_evidence[d]["trigger_count"]))
    ranked_dets = ranked_dets[:12]

    # ── Build per-(dim,value) → min total alert count map ──
    # Used to distinguish "fixes" (reduces alerts) from "shifts" (same/more)
    dimval_alerts = {}
    for cfg, dets in batch_this:
        for dim in all_layers:
            val = cfg.get(dim, "?")
            key = (dim, val)
            n_alerts = len(dets)
            if key not in dimval_alerts or n_alerts < dimval_alerts[key]:
                dimval_alerts[key] = n_alerts

    # ── Build per-detection evidence blocks with selective correlations ──
    det_blocks = []
    for det_name in ranked_dets:
        ev = det_evidence[det_name]
        block = (f"[{ev['severity']}] {det_name} "
                 f"({ev['trigger_count']}/{n_configs} configs)\n"
                 f"  {ev['tactic']}/{ev['technique']}: {ev['description']}\n")

        # Only show dims with strong signal: values exclusive to trigger or clean
        correlations = []
        for dim in sorted(all_layers.keys()):
            trigger = ev["trigger_vals"].get(dim, {})
            clean = ev["clean_vals"].get(dim, {})
            if not trigger:
                continue
            trigger_only = set(trigger.keys()) - set(clean.keys())
            clean_only = set(clean.keys()) - set(trigger.keys())
            if not trigger_only and not clean_only:
                continue
            trigger_exclusive_pct = sum(trigger[v] for v in trigger_only) / max(ev["trigger_count"], 1)
            if trigger_exclusive_pct < 0.3 and len(clean_only) == 0:
                continue
            parts = []
            if trigger_only:
                vals = sorted(trigger_only)[:4]
                parts.append(f"triggers: {', '.join(vals)}")
            if clean_only:
                fixes = sorted(v for v in clean_only
                               if dimval_alerts.get((dim, v), best_count) < best_count)
                shifts = sorted(v for v in clean_only if v not in fixes)
                if fixes:
                    parts.append(f"FIXES: {', '.join(fixes[:4])}")
                if shifts:
                    parts.append(f"shifts (new alerts): {', '.join(shifts[:3])}")
                if not fixes and not shifts:
                    parts.append(f"clean: {', '.join(sorted(clean_only)[:4])}")
            correlations.append(f"    {dim}: {'; '.join(parts)}")
        correlations = correlations[:5]
        if correlations:
            block += "\n".join(correlations) + "\n"
        else:
            block += "    (fires on all tested values — likely combo or different dim)\n"
        det_blocks.append(block)

    # ── Current best config (compact) ──
    best_str = ", ".join(f"{k}={best_cfg.get(k)}" for k in sorted(best_cfg.keys())
                         if k in all_layers)

    # ── Compressed history — last 10 rounds max, one line each ──
    history_section = ""
    if strategy_history:
        recent = strategy_history[-10:]
        history_lines = []
        for entry in recent:
            changes = entry.get("changes", {})
            outcome = entry.get("outcome", "?")
            best = entry.get("best_alerts", "?")
            ch_str = ", ".join(f"{k}={v}" for k, v in changes.items()) if changes else "none"
            history_lines.append(f"  R{entry.get('batch', '?')}: {ch_str} -> {outcome} (best={best})")
        history_section = "RECENT HISTORY (last 10):\n" + "\n".join(history_lines) + "\n"

    # ── Dead-end warning ──
    dead_end = ""
    if len(strategy_history) >= 3:
        recent = strategy_history[-3:]
        if all(h.get("outcome") == "no_improvement" for h in recent):
            recent_changes = [list(h.get("changes", {}).keys()) for h in recent]
            changed_dims = set(d for dims in recent_changes for d in dims)
            dead_end = (
                f"STUCK: 3 rounds with no improvement. "
                f"Dims tried: {', '.join(changed_dims) if changed_dims else 'none'}. "
                f"Try a DIFFERENT dimension or change MULTIPLE dims at once.\n")

    # ── Options only for dims involved in detections ──
    involved_dims = set()
    for ev in det_evidence.values():
        for dim in ev["trigger_vals"]:
            trigger = ev["trigger_vals"].get(dim, {})
            clean = ev["clean_vals"].get(dim, {})
            if set(trigger.keys()) != set(clean.keys()):
                involved_dims.add(dim)
    # Also include dims that fire on all configs (combo suspects)
    for ev in det_evidence.values():
        for dim in ev["trigger_vals"]:
            clean = ev["clean_vals"].get(dim, {})
            if not clean:
                involved_dims.add(dim)
    # If no correlations found, include key dims
    if not involved_dims:
        involved_dims = {"process", "exfil", "api_resolve", "timing",
                         "persistence", "execution"}

    dim_opts = "AVAILABLE OPTIONS (relevant dimensions):\n"
    for d in sorted(involved_dims):
        if d in all_layers:
            opts = list(all_layers[d]["options"].keys())
            tried = set()
            for cfg, _ in batch_this:
                if d in cfg:
                    tried.add(cfg[d])
            untried = [o for o in opts if o not in tried]
            tried_str = ", ".join(sorted(tried))
            untried_str = ", ".join(untried[:10]) if untried else "all tried"
            dim_opts += f"  {d}: tried=[{tried_str}] untried=[{untried_str}]\n"

    # All other dims (one line, just names)
    other_dims = sorted(set(all_layers.keys()) - involved_dims)
    if other_dims:
        dim_opts += f"  Other dims (not correlated): {', '.join(other_dims)}\n"

    clean_section = ""
    if last_clean_config:
        changed = [k for k in best_cfg if k in all_layers
                   and best_cfg.get(k) != last_clean_config.get(k)]
        if changed:
            clean_section = (
                f"REGRESSION RISK: current config differs from last clean (L{current_level - 1}) "
                f"on: {', '.join(f'{d}={best_cfg[d]}' for d in changed[:8])}\n")

    locked_section = ""
    if locked:
        locked_section = f"LOCKED DIMS (do not change): {', '.join(f'{k}={v}' for k, v in locked.items())}\n"

    prompt = f"""CrowdStrike Falcon EDR evasion analysis. Level {current_level}/20.

CURRENT BEST CONFIG ({best_count} alert{'s' if best_count != 1 else ''} remaining):
  {best_str}

{locked_section}{clean_section}{dead_end}
REMAINING DETECTIONS — what each alert says and which dimension values correlate:

{chr(10).join(det_blocks)}
{history_section}
{dim_opts}
TASK: Based on the detection descriptions and correlations above, decide what to change.
- The correlations show which dim values appear ONLY in detected configs vs clean configs
- If a detection fires on ALL values of a dimension, the cause is likely a DIFFERENT dimension or a combo
- If stuck, try changing 2+ dimensions simultaneously

Output ONLY valid JSON:
{{"change": {{"dim": "value"}}, "keep": {{"dim": "value"}}, "reset": false, "reasoning": "..."}}"""

    sys_prompt = (
        "You are a CrowdStrike Falcon detection analyst. You read EDR detection logs "
        "and correlation data to determine which evasion configuration dimensions cause "
        "alerts. You reason about behavioral patterns — process lineage, network signatures, "
        "API call sequences — to pick the right evasion technique. "
        "Output ONLY valid JSON, no other text."
    )

    text = _llm_call_raw(llm_url, sys_prompt, prompt, t=0.3)

    # ── Parse response (simplified schema) ──
    strategy = {"change": {}, "keep": {}, "reset": False, "reasoning": ""}
    try:
        # Strip markdown code fences
        clean = re.sub(r'```json\s*', '', text)
        clean = re.sub(r'```\s*', '', clean)
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', clean)
        if json_match:
            strategy = json.loads(json_match.group())
        else:
            strategy = json.loads(clean)
    except (json.JSONDecodeError, ValueError):
        # Fallback: extract any dim=value patterns
        pairs = re.findall(r'"(\w+)"\s*:\s*"([\w_]+)"', text)
        for dim, val in pairs:
            if dim in all_layers and val in all_layers[dim]["options"]:
                strategy["change"][dim] = val
        if "reset" in text.lower() and ("true" in text.lower()):
            strategy["reset"] = True

    # Handle alternate JSON format: {"change": {"dimension_name": "X", "new_value": "Y"}}
    raw_change = strategy.get("change", {})
    if "dimension_name" in raw_change and "new_value" in raw_change:
        dim_name = raw_change["dimension_name"]
        new_val = raw_change["new_value"]
        raw_change = {dim_name: new_val}
    valid_change = {}
    for dim, val in raw_change.items():
        if dim in all_layers and val in all_layers[dim]["options"]:
            valid_change[dim] = val
    valid_keep = {}
    for dim, val in strategy.get("keep", {}).items():
        if dim in all_layers and val in all_layers[dim]["options"]:
            valid_keep[dim] = val

    is_reset = bool(strategy.get("reset", False))

    # Convert to lock/explore/suggest format for the main loop
    return {
        "action": "reset" if is_reset else "explore",
        "lock": valid_keep,
        "explore": list(valid_change.keys()),
        "suggest": {d: [v] for d, v in valid_change.items()},
        "reasoning": strategy.get("reasoning", ""),
        "changes": valid_change,
    }


def _format_detection_compact(det_json_str, det_name):
    """Format a single detection for display output."""
    try:
        obj = json.loads(det_json_str)
        sev = obj.get("SeverityName", "Unknown")
        desc = obj.get("DetectDescription", "")[:150]
        return f"{det_name} ({sev}): {desc}"
    except (json.JSONDecodeError, KeyError):
        return f"{det_name}: {det_json_str[:150]}"


def _display_config_compact(config, all_layers):
    """Compact config display — key dims first."""
    key_dims = ["process", "exfil", "timing", "api_resolve", "persistence",
                "execution", "data_obfuscation", "process_lifetime"]
    parts = []
    for d in key_dims:
        if d in config:
            parts.append(f"{d}={config[d]}")
    for d in sorted(config.keys()):
        if d not in key_dims and d in all_layers:
            parts.append(f"{d}={config[d]}")
    return ", ".join(parts)


def run_exam(malware_type, llm_url="http://localhost:11235",
             start_level=1, end_level=20, exam_name="A",
             batch_size=10, max_runs=500, **_kw):
    """Run the progressive exam using algo+LLM hybrid loop.

    No budget limit — loops algo → LLM analysis → algo until solved.
    LLM interprets realistic CrowdStrike behavioral detections (no dim names in logs)
    and maps them to evasion dimensions through reasoning.
    """
    behavioral = _is_behavioral_exam(exam_name)
    if behavioral:
        exam_info = BEHAVIORAL_EXAMS.get(exam_name.replace("_hard", ""), {})
        level_names = {i: f"Tier {i} detection" for i in range(1, 21)}
        levels = None
    else:
        levels = get_levels(malware_type, exam_name=exam_name)
        level_names = {l[0]: l[1] for l in levels}
        exam_info = None
    start_level = max(1, start_level)
    end_level = min(20, end_level)
    num_levels = end_level - start_level + 1

    exam_label = f" [Exam {exam_name}]" if exam_name != "A" else ""
    mode_label = "BEHAVIORAL" if behavioral else "IOA"
    desc = f" — {exam_info['description']}" if exam_info else ""
    print(f"\n{'='*74}")
    print(f"  CROWDSTRIKE FALCON {mode_label} EXAM — {malware_type.upper()}{exam_label}")
    if desc:
        print(f"  {desc}")
    print(f"  Levels {start_level}-{end_level} ({num_levels}) | Hybrid algo+LLM (no budget limit)")
    print(f"  Batch size: {batch_size}")
    print(f"{'='*74}\n")

    all_layers = get_all_layers(malware_type)
    total_combos = 1
    for info in all_layers.values():
        total_combos *= len(info["options"])
    print(f"  Search space: {total_combos:,} across {len(all_layers)} dims\n")

    from detection_model import BEHAVIORAL_MAP, COMBO_DETECTIONS as ALL_COMBOS
    exam_config_obj = None
    if not behavioral and exam_name != "A":
        exam_config_obj = get_exam(exam_name)

    level_results = {}
    current_level = start_level
    total_runs = 0
    last_clean_config = None

    while current_level <= end_level:
        level_name = level_names.get(current_level, f"Level {current_level}")

        locked = {}
        suggested = {}
        suggest_idx = {}
        strategy_history = []
        resets_done = 0
        llm_calls = 0
        level_passed = False
        batch_num = 0
        level_start_runs = total_runs
        safety_cap = max_runs

        # last_clean_config is used as fallback in _build_next_config directly —
        # no need for single-value suggestions that block the vary_set mechanism.

        print(f"  ╔══ Level {current_level}/{end_level}: {level_name}")
        if last_clean_config:
            print(f"  ║  Inherited clean config from previous level")
        print()

        while total_runs - level_start_runs < safety_cap:
            batch_num += 1
            batch_this = []

            for i in range(batch_size):
                total_runs += 1
                run_in_batch = (batch_num - 1) * batch_size + i

                config = _build_next_config(
                    all_layers, locked, suggested, suggest_idx,
                    run_in_batch, malware_type, last_clean_config)

                detections = evaluate_config(
                    config, malware_type, max_level=current_level,
                    exam_name=exam_name)

                det_tuples = [(d["log"], d.get("hint", d["name"])) for d in detections]
                batch_this.append((config.copy(), det_tuples))

                cfg_str = _display_config_compact(config, all_layers)

                if detections:
                    det = detections[0]
                    regression_levels = [d["level"] for d in detections
                                        if d["level"] < current_level]
                    print(f"  ┌─ Run {total_runs:3d} [B{batch_num}.{i+1}]  "
                          f"Level {current_level}/{end_level}")
                    print(f"  │  Config: {cfg_str}")
                    if regression_levels:
                        print(f"  │  ⚠ REGRESSION to L{min(regression_levels)} "
                              f"({len(regression_levels)} earlier level(s) broken)")
                    print(f"  │  ✗ DETECTED ({len(detections)} alert{'s' if len(detections)>1 else ''}):")
                    for d in detections[:3]:
                        print(f"  │    - {_format_detection_compact(d['log'], d['name'])}")
                    if len(detections) > 3:
                        print(f"  │    ... and {len(detections)-3} more")
                    print()
                else:
                    print(f"  ┌─ Run {total_runs:3d} [B{batch_num}.{i+1}]  "
                          f"Level {current_level}/{end_level}")
                    print(f"  │  Config: {cfg_str}")
                    print(f"  │  ✓ CLEAN through level {current_level}")
                    try:
                        recipe = config_to_recipe(config, malware_type)
                        print(f"  │  Recipe: {len(recipe.splitlines())} lines OK")
                    except Exception as e:
                        print(f"  │  Recipe error: {e}")
                    print(f"  └─ ✓ Level {current_level} PASSED "
                          f"(batch {batch_num}, {llm_calls} strategies, {resets_done} resets)")
                    print()
                    level_passed = True
                    break

            if level_passed:
                break

            any_detected = any(dets for _, dets in batch_this)
            if not any_detected:
                level_passed = True
                break

            # ── Determine outcome vs previous batch ──
            curr_det_names = set()
            for _, dets in batch_this:
                for det_json, det_name in dets:
                    curr_det_names.add(det_name)

            best_alerts = min(len(dets) for _, dets in batch_this)

            if strategy_history:
                prev_det_names = set(strategy_history[-1].get("detection_names", []))
                prev_best = strategy_history[-1].get("best_alerts", 999)
                if curr_det_names == prev_det_names:
                    outcome = "no_improvement"
                elif best_alerts < prev_best:
                    outcome = "improved"
                elif len(curr_det_names) < len(prev_det_names):
                    outcome = "changed"
                else:
                    outcome = "changed"
            else:
                outcome = "initial"

            # ── Pre-LLM greedy hill-climb with random restarts ──
            # Iteratively pick the best value per dim until converged.
            # If stuck at a local minimum with alerts > 0, restart from a
            # new random config. Solves multi-dim requirements (like L20
            # fingerprint boss) without LLM overhead.
            if llm_calls == 0:
                sweep_budget = min(safety_cap - 50, 2000)
                sweep_start = total_runs
                golden_overrides = {}
                if behavioral:
                    golden_overrides = exam_info.get("golden_overrides", {})
                elif exam_config_obj:
                    golden_overrides = exam_config_obj.get("golden_overrides", {})
                if golden_overrides and not last_clean_config:
                    base = {}
                    rng_golden = random.Random(current_level * 31337)
                    for dim, info in all_layers.items():
                        if dim in golden_overrides:
                            base[dim] = golden_overrides[dim]
                        else:
                            opts = list(info["options"].keys())
                            base[dim] = rng_golden.choice(opts)
                    base = apply_constraints(base, malware_type,
                                             protected=set(golden_overrides.keys()))
                else:
                    base = dict(last_clean_config or config)
                base_alerts = len(evaluate_config(
                    base, malware_type, max_level=current_level,
                    exam_name=exam_name))
                best_ever = base_alerts
                best_ever_config = dict(base)
                restarts = 0
                max_restarts = 30
                dim_order = list(all_layers.keys())
                golden_protected = set(golden_overrides.keys())
                print(f"  ├─ Greedy hill-climb (budget={sweep_budget}, "
                      f"start={base_alerts} alerts)...")
                while total_runs - sweep_start < sweep_budget and restarts <= max_restarts:
                    improved_this_pass = False
                    for dim in dim_order:
                        if level_passed:
                            break
                        if dim in golden_protected:
                            continue
                        opts = list(all_layers[dim]["options"].keys())
                        current_val = base.get(dim)
                        best_val = current_val
                        best_count = base_alerts
                        for val in opts:
                            if val == current_val:
                                continue
                            total_runs += 1
                            test = dict(base)
                            test[dim] = val
                            test = apply_constraints(test, malware_type, protected=golden_protected)
                            test_dets = evaluate_config(
                                test, malware_type, max_level=current_level,
                                exam_name=exam_name)
                            if not test_dets:
                                cfg_str = _display_config_compact(test, all_layers)
                                print(f"  ┌─ Run {total_runs:3d} [climb:{dim}={val}]  "
                                      f"Level {current_level}/{end_level}")
                                print(f"  │  Config: {cfg_str}")
                                print(f"  │  ✓ CLEAN through level {current_level}")
                                try:
                                    recipe = config_to_recipe(test, malware_type)
                                    print(f"  │  Recipe: {len(recipe.splitlines())} lines OK")
                                except Exception as e:
                                    print(f"  │  Recipe error: {e}")
                                level_runs = total_runs - level_start_runs
                                print(f"  └─ ✓ Level {current_level} PASSED "
                                      f"(hill-climb r{restarts}, "
                                      f"{level_runs} runs, 0 LLM calls)")
                                print()
                                config = test
                                level_passed = True
                                break
                            if len(test_dets) < best_count:
                                best_count = len(test_dets)
                                best_val = val
                            if total_runs - sweep_start >= sweep_budget:
                                break
                        if level_passed or total_runs - sweep_start >= sweep_budget:
                            break
                        if best_val != current_val:
                            base[dim] = best_val
                            base = apply_constraints(base, malware_type, protected=golden_protected)
                            base_alerts = best_count
                            improved_this_pass = True
                            if base_alerts < best_ever:
                                best_ever = base_alerts
                                best_ever_config = dict(base)
                    if level_passed:
                        break
                    if not improved_this_pass:
                        # 2-opt: try all value pairs for dims in remaining detections
                        if base_alerts > 0 and base_alerts <= 20:
                            stuck_dets = evaluate_config(
                                base, malware_type, max_level=current_level,
                                exam_name=exam_name)
                            involved = set()
                            import json as _json
                            for det in stuck_dets:
                                try:
                                    dj = _json.loads(det["log"])
                                    dn = dj.get("DetectName", "")
                                except Exception:
                                    dn = det.get("hint", "")
                                for dim_k, info_k in all_layers.items():
                                    for val_k in info_k["options"]:
                                        bm = BEHAVIORAL_MAP.get((dim_k, val_k), [])
                                        if any(b["detect_name"] == dn for b in bm):
                                            involved.add(dim_k)
                                for combo in ALL_COMBOS:
                                    if combo.get("detect_name") == dn:
                                        involved.update(combo["conditions"].keys())
                                if exam_config_obj:
                                    for combo in exam_config_obj.get("extra_combos", []):
                                        if combo.get("detect_name") == dn:
                                            involved.update(combo["conditions"].keys())
                            involved_list = [d for d in involved if d in all_layers and d not in golden_protected]
                            if len(involved_list) == 1:
                                stuck_dim = involved_list[0]
                                partner_set = set()
                                for combo in ALL_COMBOS:
                                    if stuck_dim in combo["conditions"]:
                                        partner_set.update(combo["conditions"].keys())
                                if exam_config_obj:
                                    for combo in exam_config_obj.get("extra_combos", []):
                                        if stuck_dim in combo["conditions"]:
                                            partner_set.update(combo["conditions"].keys())
                                for rule in ARCH_CONSTRAINTS:
                                    cond_dim, _ = rule["if"]
                                    target_dims = set(rule["then_prefer"].keys())
                                    if stuck_dim == cond_dim or stuck_dim in target_dims:
                                        partner_set.add(cond_dim)
                                        partner_set.update(target_dims)
                                partner_set.discard(stuck_dim)
                                partner_set -= golden_protected
                                partners = [d for d in partner_set if d in all_layers]
                                partners += [d for d in all_layers if d not in involved and d not in partner_set and d not in golden_protected]
                                pairs_to_try = [(stuck_dim, p) for p in partners]
                            elif len(involved_list) >= 2:
                                from itertools import combinations
                                pairs_to_try = list(combinations(involved_list, 2))
                            else:
                                pairs_to_try = []
                            for d1, d2 in pairs_to_try:
                                if level_passed or total_runs - sweep_start >= sweep_budget:
                                    break
                                for v1 in all_layers[d1]["options"]:
                                    if level_passed or total_runs - sweep_start >= sweep_budget:
                                        break
                                    for v2 in all_layers[d2]["options"]:
                                        total_runs += 1
                                        test = dict(base)
                                        test[d1] = v1
                                        test[d2] = v2
                                        test = apply_constraints(test, malware_type, protected=golden_protected)
                                        td = evaluate_config(
                                            test, malware_type, max_level=current_level,
                                            exam_name=exam_name)
                                        if not td:
                                            cfg_str = _display_config_compact(test, all_layers)
                                            print(f"  ┌─ Run {total_runs:3d} [2opt:{d1}+{d2}]  "
                                                  f"Level {current_level}/{end_level}")
                                            print(f"  │  Config: {cfg_str}")
                                            print(f"  │  ✓ CLEAN through level {current_level}")
                                            try:
                                                recipe = config_to_recipe(test, malware_type)
                                                print(f"  │  Recipe: {len(recipe.splitlines())} lines OK")
                                            except Exception as e:
                                                print(f"  │  Recipe error: {e}")
                                            level_runs = total_runs - level_start_runs
                                            print(f"  └─ ✓ Level {current_level} PASSED "
                                                  f"(hill-climb 2-opt, "
                                                  f"{level_runs} runs, 0 LLM calls)")
                                            print()
                                            config = test
                                            level_passed = True
                                            break
                                        if len(td) < best_ever:
                                            best_ever = len(td)
                                            best_ever_config = dict(test)
                                        if total_runs - sweep_start >= sweep_budget:
                                            break
                        if level_passed:
                            break
                        restarts += 1
                        if restarts > max_restarts:
                            break
                        rng_restart = random.Random(restarts * 77777 + current_level)
                        dim_order_new = list(all_layers.keys())
                        rng_restart.shuffle(dim_order_new)
                        dim_order = dim_order_new
                        base = {}
                        for dim, info in all_layers.items():
                            if dim in golden_overrides:
                                base[dim] = golden_overrides[dim]
                            else:
                                opts = list(info["options"].keys())
                                base[dim] = rng_restart.choice(opts)
                        base = apply_constraints(base, malware_type, protected=golden_protected)
                        base_alerts = len(evaluate_config(
                            base, malware_type, max_level=current_level,
                            exam_name=exam_name))
                        total_runs += 1
                        if restarts <= 5 or restarts % 5 == 0:
                            print(f"  │  Restart #{restarts}: {base_alerts} alerts")
                if level_passed:
                    break
                print(f"  ├─ Hill-climb: no solution in {total_runs - sweep_start} "
                      f"runs ({restarts} restarts, best={best_ever}), invoking LLM...")

            # ── LLM strategy analysis ──
            try:
                llm_calls += 1
                strategy = _llm_strategy_call(
                    llm_url, batch_this, all_layers, last_clean_config,
                    current_level, malware_type, strategy_history,
                    locked, resets_done)

                action = strategy.get("action", "explore")
                new_locks = strategy.get("lock", {})
                new_explore = strategy.get("explore", [])
                new_suggest = strategy.get("suggest", {})
                reasoning = strategy.get("reasoning", "")[:150]
                force_explore = set()

                # Smart auto-reset: after N consecutive strategies that fail
                # to pass (regardless of marginal improvement), find stuck dims.
                # Trigger: 3x no_improvement OR 5x any-failure-to-pass.
                smart_reset_needed = False
                if len(strategy_history) >= 3:
                    recent3 = strategy_history[-3:]
                    if all(h.get("outcome") == "no_improvement" for h in recent3):
                        smart_reset_needed = True
                if not smart_reset_needed and len(strategy_history) >= 5:
                    recent5 = strategy_history[-5:]
                    if all(h.get("best_alerts", 999) > 0 for h in recent5):
                        smart_reset_needed = True

                if smart_reset_needed:
                    recent = strategy_history[-min(5, len(strategy_history)):]
                    always_locked = None
                    for h in recent:
                        hlocks = set(h.get("new_locks", {}).keys())
                        if always_locked is None:
                            always_locked = hlocks
                        else:
                            always_locked &= hlocks
                    det_dims = set()
                    kw_map = {
                        "exfil": ["network", "connection", "tcp", "http", "cloud",
                                  "sync", "exfil", "transfer", "named pipe"],
                        "process": ["process", "parent", "child", "tree", "ppid",
                                    "behavioral profile", "sideload"],
                        "api_resolve": ["import", "api", "syscall", "ntdll", "hash"],
                        "timing": ["sleep", "delay", "burst", "timing",
                                  "immediate", "execution", "launch", "pacing"],
                        "collection_strategy": ["credential", "bulk", "access",
                                                "collection", "rapid", "data store"],
                        "persistence": ["persist", "registry", "startup", "scheduled"],
                        "injection_method": ["inject", "hollowing", "apc", "thread"],
                        "sleep_mode": ["sleep", "encrypt", "obfuscat"],
                        "kernel_evasion": ["driver", "kernel", "byovd"],
                        "anti_forensics": ["forensic", "self.delete", "timestomp"],
                        "data_staging": ["staging", "temp", "pipe"],
                    }
                    has_fingerprint = False
                    for _, dets in batch_this:
                        for det_json, _ in dets:
                            try:
                                desc = json.loads(det_json).get(
                                    "DetectDescription", "").lower()
                                if "fingerprint" in desc or "all dimensions" in desc:
                                    has_fingerprint = True
                                for dim, kws in kw_map.items():
                                    if any(kw in desc for kw in kws):
                                        det_dims.add(dim)
                            except (json.JSONDecodeError, KeyError):
                                pass
                    if has_fingerprint:
                        force_explore = set(locked.keys())
                        if not force_explore:
                            force_explore = set(all_layers.keys())
                    else:
                        force_explore = (always_locked or set()) & det_dims
                        if not force_explore:
                            force_explore = always_locked or det_dims or {"process", "exfil"}
                    action = "reset"
                    new_suggest = {}
                    for dim in force_explore:
                        if dim in all_layers:
                            opts = list(all_layers[dim]["options"].keys())
                            current_val = (last_clean_config or {}).get(dim)
                            others = [o for o in opts if o != current_val]
                            random.shuffle(others)
                            new_suggest[dim] = others
                    trigger = "3× no_improvement" if (
                        len(strategy_history) >= 3 and
                        all(h.get("outcome") == "no_improvement"
                            for h in strategy_history[-3:])
                    ) else f"5× failed (best={best_alerts} alerts)"
                    fp_note = " [FINGERPRINT: unlocking ALL locked dims]" if has_fingerprint else ""
                    print(f"  ├─ SMART RESET: {trigger}, "
                          f"force-exploring {list(force_explore)}{fp_note}")

                # Record this decision in history BEFORE applying
                strategy_history.append({
                    "batch": batch_num,
                    "action": action,
                    "new_locks": dict(new_locks),
                    "explored": list(new_explore),
                    "changes": strategy.get("changes", {}),
                    "suggested": {k: list(v) for k, v in new_suggest.items()},
                    "reasoning": strategy.get("reasoning", ""),
                    "outcome": outcome,
                    "detection_names": list(curr_det_names),
                    "best_alerts": best_alerts,
                })

                if action == "reset":
                    resets_done += 1
                    old_lock_count = len(locked)
                    locked.clear()
                    suggested.clear()
                    suggest_idx.clear()
                    # DON'T re-lock from last_clean_config —
                    # _build_next_config uses it as fallback already.
                    # LLM suggestions must take priority.

                    # Apply LLM's new direction FIRST
                    for dim, vals in new_suggest.items():
                        suggested[dim] = vals
                        suggest_idx[dim] = 0

                    # Force new direction: for dims in force_explore that
                    # the LLM didn't suggest, try values NOT yet attempted.
                    # ONLY vary force_explore dims — leave others at
                    # last_clean_config values to prevent regressions.
                    tried_vals = {}
                    for h in strategy_history:
                        for dim, val in h.get("changes", {}).items():
                            tried_vals.setdefault(dim, set()).add(val)
                    for dim in force_explore:
                        if dim not in suggested:
                            opts = list(all_layers[dim]["options"].keys())
                            fresh = [o for o in opts if o not in tried_vals.get(dim, set())]
                            if fresh:
                                random.shuffle(fresh)
                                suggested[dim] = fresh
                                suggest_idx[dim] = 0
                    print(f"  ├─ *** RESET #{resets_done} — wiped {old_lock_count} locks, "
                          f"forced new direction ***")
                    print(f"  │  {reasoning}")
                    if new_suggest:
                        sug_str = ", ".join(f"{k}=[{','.join(v)}]" for k, v in new_suggest.items())
                        print(f"  │  LLM direction: {sug_str}")
                    print()
                else:
                    locked.update(new_locks)
                    for dim in new_explore:
                        locked.pop(dim, None)
                        # Populate full option list — LLM's preferred value first,
                        # then all others shuffled. This ensures the solver actually
                        # varies this dim across runs instead of falling back to
                        # last_clean_config after exhausting a single-value suggestion.
                        if dim in all_layers:
                            opts = list(all_layers[dim]["options"].keys())
                            preferred = new_suggest.get(dim, [None])[0] if dim in new_suggest else None
                            current_val = (last_clean_config or {}).get(dim)
                            others = [o for o in opts if o != preferred and o != current_val]
                            random.shuffle(others)
                            full_list = []
                            if preferred and preferred in all_layers[dim]["options"]:
                                full_list.append(preferred)
                            if current_val and current_val != preferred:
                                full_list.append(current_val)
                            full_list.extend(others)
                            suggested[dim] = full_list
                            suggest_idx[dim] = 0
                    # For non-explore suggest dims, apply LLM's suggestions directly
                    for dim, vals in new_suggest.items():
                        if dim not in new_explore:
                            suggested[dim] = vals
                            suggest_idx[dim] = 0

                    lock_str = ", ".join(f"{k}={v}" for k, v in new_locks.items()) if new_locks else "none"
                    explore_str = ", ".join(new_explore) if new_explore else "none"
                    print(f"  ├─ Strategy #{llm_calls} [{outcome}]: "
                          f"lock [{lock_str}], explore [{explore_str}]")
                    if reasoning:
                        print(f"  │  {reasoning}")
                    print(f"  │  State: {len(locked)} locked, {resets_done} resets, "
                          f"{len(strategy_history)} decisions")
                    print()

            except Exception as e:
                print(f"  ├─ LLM error: {e}")
                strategy_history.append({
                    "batch": batch_num, "action": "error",
                    "new_locks": {}, "explored": [], "suggested": {},
                    "reasoning": f"LLM error: {e}",
                    "outcome": outcome, "detection_names": list(curr_det_names),
                })
                # Smart fallback: parse detection descriptions to find relevant dims
                locked.clear()
                suggested.clear()
                suggest_idx.clear()
                det_dims = set()
                kw_map = {
                    "exfil": ["network", "connection", "tcp", "http", "smb", "dns", "exfil",
                              "cloud", "sync", "upload", "transfer", "paste", "named pipe"],
                    "process": ["process", "parent", "child", "tree", "spawn", "ppid"],
                    "api_resolve": ["import", "api", "syscall", "ntdll", "unhook", "hash", "peb"],
                    "timing": ["sleep", "delay", "timing", "burst",
                              "immediate", "execution", "launch", "pacing"],
                    "collection_strategy": ["credential", "bulk", "access",
                                            "collection", "rapid", "data store"],
                    "persistence": ["persist", "registry", "startup", "scheduled"],
                    "injection_method": ["inject", "remote thread", "apc", "hollowing"],
                    "network_stealth": ["ja3", "tls fingerprint", "domain front"],
                    "memory_residence": ["memory", "module stomp", "vad", "section"],
                    "sleep_mode": ["sleep obfuscat", "ekko", "timer", "noaccess"],
                }
                for _, dets in batch_this:
                    for det_json, _ in dets:
                        try:
                            desc = json.loads(det_json).get("DetectDescription", "").lower()
                            for dim, kws in kw_map.items():
                                if dim in all_layers and any(kw in desc for kw in kws):
                                    det_dims.add(dim)
                        except (json.JSONDecodeError, KeyError):
                            pass
                if not det_dims:
                    det_dims = {"exfil", "process"}
                for dim in det_dims:
                    if dim in all_layers:
                        opts = list(all_layers[dim]["options"].keys())
                        current_val = config.get(dim)
                        opts = [o for o in opts if o != current_val]
                        random.shuffle(opts)
                        suggested[dim] = opts
                        suggest_idx[dim] = 0
                print(f"  │  Error fallback: cleared locks, shuffled detection-relevant dims: {det_dims}")
                print()

        if level_passed:
            level_runs = total_runs - level_start_runs
            tier = "Algo" if llm_calls == 0 else f"LLM×{llm_calls}"
            level_results[current_level] = {
                "runs": level_runs, "tier": tier, "config": config.copy(),
                "resets": resets_done, "strategies": len(strategy_history),
            }
            last_clean_config = config.copy()

            locked = {}
            suggested = {}
            suggest_idx = {}

            current_level += 1
            continue

        level_runs = total_runs - level_start_runs
        print(f"  ╘═ Level {current_level} FAILED — {level_runs} runs, "
              f"{len(strategy_history)} strategies, {resets_done} resets")
        print()
        break

    # ── Report card ──
    passed = len(level_results)
    algo_solved = sum(1 for v in level_results.values() if "Algo" in v["tier"])
    llm_solved = sum(1 for v in level_results.values() if "LLM" in v["tier"])
    total_resets = sum(v.get("resets", 0) for v in level_results.values())

    print(f"\n{'='*74}")
    print(f"  EXAM RESULTS — {malware_type.upper()}{exam_label}")
    print(f"{'='*74}")
    print(f"  Levels passed: {passed}/{num_levels} (algo={algo_solved}, llm={llm_solved})")
    print(f"  Total runs: {total_runs}, total resets: {total_resets}")
    print()
    print(f"  {'Level':>5}  {'Runs':>4}  {'Strats':>6}  {'Resets':>6}  {'Tier':>8}  Status")
    print(f"  {'─'*5}  {'─'*4}  {'─'*6}  {'─'*6}  {'─'*8}  {'─'*30}")
    for lvl in range(start_level, end_level + 1):
        if lvl in level_results:
            r = level_results[lvl]
            strats = r.get("strategies", 0)
            resets = r.get("resets", 0)
            print(f"  {lvl:5d}  {r['runs']:4d}  {strats:6d}  {resets:6d}  {r['tier']:>8}  "
                  f"✓ {level_names.get(lvl, f'Level {lvl}')}")
        elif lvl <= current_level:
            print(f"  {lvl:5d}     -       -       -         -  "
                  f"✗ {level_names.get(lvl, f'Level {lvl}')} (failed)")
        else:
            print(f"  {lvl:5d}     -       -       -         -  "
                  f"· {level_names.get(lvl, f'Level {lvl}')} (not reached)")
    print(f"{'='*74}\n")

    return passed, total_runs, level_results


def run_all_exams(llm_url="http://localhost:11235",
                  start_level=1, end_level=20, exam_name="A", batch_size=10,
                  max_runs=500):
    """Run exam for all 3 types."""
    results = {}
    num_levels = end_level - start_level + 1
    for mtype in ["infostealer", "keylogger", "backdoor"]:
        passed, runs, levels = run_exam(
            mtype, llm_url=llm_url,
            start_level=start_level, end_level=end_level,
            exam_name=exam_name, batch_size=batch_size, max_runs=max_runs,
        )
        results[mtype] = {"passed": passed, "runs": runs, "levels": levels}

    exam_label = f" [Exam {exam_name}]" if exam_name != "A" else ""
    print(f"\n{'='*74}")
    print(f"  GRAND SUMMARY — ALL TYPES{exam_label}")
    print(f"{'='*74}")
    for mtype, res in results.items():
        algo = sum(1 for v in res["levels"].values() if "Algo" in v["tier"])
        llm = sum(1 for v in res["levels"].values() if "LLM" in v["tier"])
        print(f"  {mtype:12s}: {res['passed']:2d}/{num_levels} levels in {res['runs']:2d} runs "
              f"(algo={algo}, llm={llm})")
    total_passed = sum(r["passed"] for r in results.values())
    total_possible = num_levels * 3
    print(f"\n  Total: {total_passed}/{total_possible} levels passed")
    print(f"{'='*74}")
    return results


if __name__ == "__main__":
    import argparse

    available_exams = list_exams()
    exam_list_str = "\n".join(f"    {name:8s} {desc}" for name, desc in available_exams)
    behavioral_list_str = "\n".join(
        f"    {name:8s} {info['description']}"
        for name, info in sorted(BEHAVIORAL_EXAMS.items())
    )

    p = argparse.ArgumentParser(
        description="CrowdStrike Falcon IOA Exam — algo+LLM hybrid solver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Legacy exams (old check functions):
{exam_list_str}

Behavioral exams (detection_model.py tiers):
{behavioral_list_str}

    Append '_hard' to any exam name for hard mode (no hints in detection texts).
    Use 'all' for all legacy exams, 'all_behavioral' for all behavioral exams.

Examples:
  python3 %(prog)s --exam B1               # behavioral exam B1
  python3 %(prog)s --exam all_behavioral   # all behavioral exams
  python3 %(prog)s --exam A                # legacy exam A
  python3 %(prog)s --type infostealer --levels 10
  python3 %(prog)s --batch-size 5
""",
    )
    p.add_argument("--type", "-t", default=None, choices=["infostealer", "keylogger", "backdoor"],
                   help="Single type to test (default: all 3)")
    p.add_argument("--exam", "-e", default="A",
                   help="Exam variant (A-F, or A_hard-F_hard for hard mode, "
                        "or 'all'/'all_hard' for batch run)")
    p.add_argument("--levels", "-n", type=int, default=20,
                   help="Number of levels to test (1-20, default: 20)")
    p.add_argument("--start-level", "-s", type=int, default=1,
                   help="Start at this level (default: 1)")
    p.add_argument("--batch-size", "-b", type=int, default=10,
                   help="Algo runs per batch before LLM analysis (default: 10)")
    p.add_argument("--llm-url", default="http://localhost:11235",
                   help="LLM API endpoint (default: http://localhost:11235)")
    p.add_argument("--llm-model", default=LLM_MODEL,
                   help="LLM model name for API calls")
    p.add_argument("--no-clean-history", action="store_true",
                   help="Don't clean evasion history before running (resume from prior state)")
    p.add_argument("--max-runs", "-m", type=int, default=500,
                   help="Max runs per level before giving up (default: 500)")
    p.add_argument("--json", action="store_true",
                   help="Output results as JSON (for scripting)")
    args = p.parse_args()

    end_level = min(args.start_level + args.levels - 1, 20)
    start_level = max(1, args.start_level)

    LLM_MODEL = args.llm_model

    hist_file = ".cache/evasion_history.json"
    backed_up = False
    if not args.no_clean_history and os.path.exists(hist_file):
        os.rename(hist_file, hist_file + ".bak")
        backed_up = True

    if args.exam.lower() == "all":
        exam_names = [name for name, _ in available_exams]
    elif args.exam.lower() == "all_hard":
        exam_names = [f"{name}_hard" for name, _ in available_exams]
    elif args.exam.lower() == "all_behavioral":
        exam_names = sorted(BEHAVIORAL_EXAMS.keys())
    elif args.exam.lower() == "all_behavioral_hard":
        exam_names = [f"{name}_hard" for name in sorted(BEHAVIORAL_EXAMS.keys())]
    else:
        exam_names = [args.exam]

    try:
        all_exam_results = {}
        for exam_name in exam_names:
            print(f"\n{'#'*74}")
            print(f"  EXAM VARIANT: {exam_name}")
            print(f"  Config: levels {start_level}-{end_level}, batch={args.batch_size}")
            print(f"  LLM: {args.llm_url} ({args.llm_model})")
            print(f"{'#'*74}")

            if args.type:
                passed, runs, level_results = run_exam(
                    args.type, llm_url=args.llm_url,
                    start_level=start_level, end_level=end_level,
                    exam_name=exam_name, batch_size=args.batch_size,
                    max_runs=args.max_runs,
                )
                results = {args.type: {"passed": passed, "runs": runs, "levels": level_results}}
            else:
                results = run_all_exams(
                    llm_url=args.llm_url,
                    start_level=start_level, end_level=end_level,
                    exam_name=exam_name, batch_size=args.batch_size,
                    max_runs=args.max_runs,
                )
            all_exam_results[exam_name] = results

        if len(exam_names) > 1:
            num_levels = end_level - start_level + 1
            num_types = 1 if args.type else 3
            print(f"\n{'='*74}")
            print(f"  GRAND SUMMARY — ALL EXAMS")
            print(f"{'='*74}")
            print(f"  {'Exam':12s}  {'Passed':>8s}  {'Runs':>6s}  Details")
            print(f"  {'─'*12}  {'─'*8}  {'─'*6}  {'─'*30}")
            grand_passed = 0
            grand_possible = 0
            for ename in exam_names:
                eres = all_exam_results[ename]
                ep = sum(r["passed"] for r in eres.values())
                er = sum(r["runs"] for r in eres.values())
                etotal = num_levels * num_types
                detail = ", ".join(f"{mt}={r['passed']}/{num_levels}"
                                   for mt, r in eres.items())
                status = "PASS" if ep == etotal else "FAIL"
                print(f"  {ename:12s}  {ep:3d}/{etotal:<3d}   {er:5d}  {status}  {detail}")
                grand_passed += ep
                grand_possible += etotal
            print(f"\n  Total: {grand_passed}/{grand_possible} levels across {len(exam_names)} exams")
            print(f"{'='*74}")

        if args.json:
            out = {}
            for ename, eres in all_exam_results.items():
                out[ename] = {}
                for mtype, res in eres.items():
                    lvls = res.get("levels", {})
                    out[ename][mtype] = {
                        "passed": res["passed"],
                        "runs": res["runs"],
                        "levels": {
                            str(k): {"runs": v["runs"], "tier": v["tier"]}
                            for k, v in (lvls.items() if isinstance(lvls, dict) else {})
                        },
                    }
            print(json.dumps(out, indent=2))
    finally:
        if backed_up:
            if os.path.exists(hist_file):
                os.unlink(hist_file)
            os.rename(hist_file + ".bak", hist_file)
