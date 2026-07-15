# Architectural Layers — All Malware Types Combined Synthesis

## Answer to: Are these layers independent like the current 12, or do they change everything?

They are HIERARCHICAL, not combinatorial. Architecture sits above implementation and constrains it.

Example cascade for infostealer:
- Architecture: "DLL sideloaded into OneDrive.exe + cloud sync exfil"
  - api_resolve: IRRELEVANT — you're inside a trusted process
  - sleep_mode: IRRELEVANT — OneDrive's own lifecycle controls timing  
  - exfil method: CONSTRAINED — must use OneDrive sync folder, not raw TCP
  - persistence: FREE — OneDrive auto-starts
  - process identity: FIXED — you ARE OneDrive

The framework needs TWO-TIER selection: pick architecture first, then pick compatible implementation layers.

## Complete Layer Catalog Across All Types

### UNIVERSAL LAYERS (apply to all 3 types)

| # | Layer | Options Count | Description |
|---|---|---|---|
| U1 | Execution Model | 14 | What process hosts the malware (standalone exe, DLL sideload, COM object, service DLL, browser extension, shellcode, WMI consumer, etc.) |
| U2 | Process Ancestry | 8 | What process tree the EDR sees (user click, schtasks, WMI spawn, COM activation, service start, logon trigger, PPID-spoofed, orphaned) |
| U3 | Exfiltration Paradigm | 15 | How data fundamentally leaves (direct socket, cloud API, legitimate app sync, DNS, email/MAPI, social media, dead drop, browser POST, steganography, USB, Bluetooth, print queue) |
| U4 | Process Lifetime | 6 | How long the process exists (seconds, staged multi-short, minutes, persistent, burst-and-die, process chain) |
| U5 | Privilege Architecture | 6 | Elevation strategy (user-only, token impersonation, UAC bypass, exploit, abuse existing, split-privilege) |
| U6 | Anti-Forensics Architecture | 7 | Structural cleanup approach (none, self-delete, timestomp, memory-only, LOLBin cleanup, process ghosting, MFT wipe) |
| U7 | Security Product Interaction | 7 | How it relates to EDR (ignore, blind ETW, unhook usermode, detect-and-adapt, coexist below thresholds, abuse exclusions, timestop) |
| U8 | Data Staging | 11 | Where data lives before exfil (memory, temp file, registry, ADS, WMI repo, event log, cert store, shared memory, steganography, browser storage, cloud note) |

### INFOSTEALER-SPECIFIC LAYERS

| # | Layer | Options Count | Description |
|---|---|---|---|
| I1 | Collection Strategy | 10 | When/how data is gathered (bulk immediate, incremental slow, piggyback legitimate, on-demand, event-triggered, opportunistic, memory scraping, clipboard watch, API hooking, ETW consumer) |
| I2 | Target Selectivity | 8 | What data to collect (comprehensive, browser-only, credential-only, file-targeted, clipboard-only, session tokens, network creds, environment recon) |
| I3 | Multi-Stage Architecture | 4 | Structural composition (monolithic, loader+payload, stager chain, split collector/exfiltrator) |

### BACKDOOR-SPECIFIC LAYERS

| # | Layer | Options Count | Description |
|---|---|---|---|
| B1 | C2 Paradigm | 18 | How implant receives commands (active beacon, long-poll, passive listener, dead-drop cloud, DNS C2, email C2, social media, steganography, blockchain, WMI event, named pipe, scheduled task, registry, event log, DoH, WebSocket, serverless, P2P mesh) |
| B2 | Command Execution Model | 11 | How received commands execute (in-process, spawn child, inject into existing, LOLBin proxy, WMI execution, COM execution, task scheduler, service creation, DCOM, thread pool abuse, callback abuse) |
| B3 | Operational Tempo | 8 | When active (always, business hours, human-mimicking, burst-dormant, triggered-only, random schedule, seasonal, once-and-done) |
| B4 | Multi-Stage Architecture | 8 | Structural composition (monolithic, loader+payload, stager chain, modular plugin, reflective DLL, BOF-based, script modules, split-function) |
| B5 | Persistence Architecture | 9 | How persistence relates to execution (binary restart, loader fetches fresh, fileless, LOLBin chain, supply chain, firmware, user-assisted, shadow service, boot execute) |
| B6 | Data Return Channel | 7 | How results return (same channel, separate channel, dead drop, steganographic, DNS chunks, email, delayed batch) |
| B7 | Network Identity | 14 | What traffic looks like on wire (custom TCP, HTTP custom, HTTPS domain-fronted, HTTPS legitimate service, DNS tunnel, ICMP, SMB pipe, RDP channel, SSH tunnel, Tor, proxy chain, VPN piggyback, IoT protocols, mail protocol) |
| B8 | Lateral Movement | 5 | Spread behavior (local only, spread on command, auto-spread, relay/pivot, P2P mesh) |

### KEYLOGGER-SPECIFIC LAYERS

| # | Layer | Options Count | Description |
|---|---|---|---|
| K1 | Capture Method | 19 | How keystrokes are intercepted (SetWindowsHookEx WH_KEYBOARD_LL, WH_KEYBOARD, GetAsyncKeyState, GetKeyboardState, Raw Input, DirectInput, UI Automation, MSAA, Text Services Framework, IME replacement, WH_GETMESSAGE, WH_JOURNALRECORD, clipboard monitor, screen OCR, browser injection, memory scanning, debug API, window subclass, named pipe sniff) |
| K2 | Session Binding | 7 | How it accesses interactive desktop (Session 1 native, cross-session hook, WTS token, user context launch, winlogon attach, RDP intercept, console session) |
| K3 | Operational Tempo | 7 | When actively capturing (continuous, business hours, foreground app-based, URL/site-specific, burst capture, event-triggered, human-paced random) |
| K4 | Target Selectivity | 7 | What to capture (all keystrokes, window-filtered, URL-filtered, password-field-only, credential patterns, app-specific, session-type adaptive) |
| K5 | Context Enrichment | 7 | Additional data alongside keys (keys only, +window title, +URL, +screenshot, +clipboard, +mouse, full session record) |
| K6 | Exfiltration Timing | 9 | When data leaves (realtime stream, periodic batch, threshold-based, user idle, piggyback activity, on-disconnect, daily dump, accumulate local only, on-trigger from C2) |
| K7 | Anti-Detection Architecture | 5 | Structural split (monolithic, split capture/exfil, legitimate IPC bridge, volunteer process hosting, proxy through legitimate app data store) |

## TOTAL LAYER COUNT

| Category | Layers | Total Options |
|---|---|---|
| Universal | 8 | 74 |
| Infostealer-specific | 3 | 22 |
| Backdoor-specific | 8 | 80 |
| Keylogger-specific | 7 | 61 |
| **TOTAL** | **26** | **237** |

## Combinatorial Space (with hierarchy constraints)

Not all combinations are valid — architecture constrains implementation. But even with constraints:

- **Infostealer**: 8 universal + 3 specific = 11 architectural layers
- **Backdoor**: 8 universal + 8 specific = 16 architectural layers  
- **Keylogger**: 8 universal + 7 specific = 15 architectural layers

Conservative estimate (only ~30% of cross-layer combinations are compatible):
- Infostealer: ~10^8 valid architectural combinations × 358M implementation combinations
- Backdoor: ~10^12 valid combinations × 358M implementation
- Keylogger: ~10^10 valid combinations × 358M implementation

This is a fundamentally different search space than the current 358M implementation-only combinations.
