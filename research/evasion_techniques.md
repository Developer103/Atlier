# Evasion & Obfuscation Techniques

## Source-Level Transforms (`evasion_passes.py`)

Nine regex-based passes that mutate assembled C source. Each produces a unique variant per build.

### 1. `_sanitize_includes()`

**Levels:** all (light, heavy, max)

Fixes hallucinated/incorrect headers from LLM output. Deduplicates, corrects misspellings (e.g. `winsocket.h` -> `winsock2.h`), strips POSIX-only headers (`unistd.h`, `pthread.h`), enforces correct ordering (`winsock2.h` before `windows.h`).

### 2. `_mutate_source()`

**Levels:** all (light, heavy, max)

Polymorphic mutation — three transforms in one pass:

- **Variable renaming**: Finds local variable declarations (`int`, `DWORD`, `BOOL`, `HANDLE`, etc.) and renames them to random 5-char names (`_xabcd`). Protects reserved names (`argc`, `argv`, `hProcess`, etc.). Typically renames ~29 variables.
- **Junk code injection**: Inserts dead code blocks before `if`, `for`, `while`, and `return` statements with 15% probability. Blocks call real Windows APIs (`GetTickCount()`, `GetCurrentProcessId()`) so they look like real code to static analysis. Typically inserts ~15-21 blocks.
- **Integer literal mutation**: Splits integer constants into addition expressions (`4096` -> `(4090 + 6)`). Skips array sizes, hex literals, and small values (0, 1).

### 3. `_encrypt_string_literals()`

**Levels:** all (light, heavy, max) — always runs last

Replaces plaintext string literals with XOR-encrypted byte arrays. Generates a random 16-byte key per build. At runtime, `_xd_init()` decrypts all strings in-place on first call (injected at entry point).

Skips: format strings with `%` specifiers, strings <= 3 chars, preprocessor lines, array initializers, implicit string concatenation, and common separators (`\n`, `\t`, `, `).

Typically encrypts 50-60 literals. Array initializers (browser name tables, path arrays) remain plaintext — these require the LLM rewrite pass to restructure.

### 4. `_obfuscate_api_calls()`

**Levels:** heavy, max

Replaces static imports of suspicious Windows APIs with dynamic `LoadLibrary` + `GetProcAddress` resolution at runtime. Generates a typedef + function pointer for each API, resolved via `_api_init()` on first call.

Covers 22 APIs across 5 DLLs:

| DLL | APIs |
|---|---|
| kernel32.dll | CreateToolhelp32Snapshot, Process32First/Next, Module32First/Next, OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, IsDebuggerPresent, CheckRemoteDebuggerPresent |
| advapi32.dll | RegOpenKeyExA, RegSetValueExA, RegCreateKeyExA, CryptAcquireContextA, CryptGenRandom, CryptEncrypt, CryptCreateHash, CryptDeriveKey |
| iphlpapi.dll | GetExtendedTcpTable |
| mpr.dll | WNetOpenEnumA, WNetEnumResourceA |
| wininet.dll | InternetOpenA, InternetOpenUrlA |

This removes these API names from the binary's Import Address Table (IAT), defeating static signature scanners that flag on import combinations.

### 5. `_inject_anti_debug()`

**Levels:** heavy, max

Injects `_chk_dbg()` at the entry point. Three detection methods:

1. `IsDebuggerPresent()` — process debug flag
2. `CheckRemoteDebuggerPresent()` — remote debugger attachment
3. **Timing check** — `QueryPerformanceCounter` delta over a volatile loop. If delta exceeds one second (single-stepping), returns detected.

On detection: returns 0 silently (no crash, no message — looks like normal termination).

### 6. `_inject_seh_in_main()`

**Levels:** heavy, max

Structured Exception Handler wrapper. Moves the entire `main()` body into `_worker_thread()` (DWORD WINAPI signature). New `main()`:

1. Sets `_crash_filter` as unhandled exception filter (calls `ExitThread(1)` — thread dies, process survives)
2. Sets error mode to suppress crash dialogs
3. Creates thread running `_worker_thread`, waits 30s
4. `Sleep(5000)` after thread completes (cleanup window)

Effect: crashes in payload code kill the thread, not the process. No crash dialog appears. Strips `(void)argc; (void)argv;` from moved body to avoid undeclared-variable errors.

### 7. `_inject_amsi_etw_bypass()`

**Levels:** used by Framework 0 (LLM pipeline), not by chunk obfuscation

In-memory patches at runtime:

- **AMSI bypass**: Patches `AmsiScanBuffer` to return `E_INVALIDARG` (0x80070057) — all AMSI scans pass without inspection
- **ETW bypass**: Patches `EtwEventWrite` entry point with `0xC3` (ret) — all ETW telemetry silently dropped

Both use `VirtualProtect` to make the target memory writable before patching.

Note: triggers Defender Tamper Protection on recent Windows 11 builds. Disabled for compiled C payloads (irrelevant — AMSI scans scripts, not native binaries).

### 8. `_ensure_exfil_substance()`

**Levels:** used by Framework 0 only

Detects when LLM-generated code has `send()` calls but no real data collection. Scores the code on 6 substance indicators (GetComputerName, GetUserName, ReadFile, FindFirstFile, CreateToolhelp32Snapshot, substantial send). If score < 3, injects a `_collect_sysinfo()` function that collects hostname, username, PID, process list, and file listings.

Not used by chunk pipeline (chunks always have real collector implementations).

### 9. `_inject_process_injection()`

**Levels:** used by Framework 0 only

Injects `_inject_payload()` — a process injection stub targeting `explorer.exe`:

1. Enumerates processes via `CreateToolhelp32Snapshot`
2. Opens explorer.exe with `PROCESS_ALL_ACCESS`
3. Allocates RWX memory with `VirtualAllocEx`
4. Writes a small shellcode stub
5. Creates remote thread to execute

Skips if `VirtualAllocEx` or `CreateRemoteThread` already present.

---

## LLM-Powered Obfuscation (`obfuscate.py`)

**Level:** max only

After all regex passes complete, the assembled source is sent to the local LLM (Qwen3-35B or configured endpoint) for semantic rewriting. The LLM is prompted to:

1. **Rename all static functions** to generic names (`init_module_N`, `process_data_N`, `handle_event_N`) and update all callers/declarations
2. **Reorder function definitions** randomly (main stays last)
3. **Replace readable section markers** (`"=== SYSTEM INFO ==="`) with computed/obfuscated equivalents
4. **Split large functions** (>40 lines) into 2-3 smaller functions with opaque names
5. **Add 3-5 realistic dead code paths** — code referencing real variables and APIs, guarded by always-false conditions (`if (GetTickCount() == 0)`, `if (sizeof(void*) > 16)`)
6. Preserve all `#include`, `#define`, `typedef`, and Windows API callback signatures

### Compile-Verify Loop

LLM rewrites break compilation ~30% of the time. After each rewrite:

1. Compile-test with `x86_64-w64-mingw32-gcc -fsyntax-only`
2. If failed, send the error back to the LLM with the broken source for a fix
3. Maximum 3 attempts
4. If all attempts fail, falls back to the regex-obfuscated source (no LLM changes applied)

### Conflict Avoidance

Before applying passes, checks for chunk guard sentinels in the assembled source:

| Sentinel | Meaning | Skipped Pass |
|---|---|---|
| `CHUNK_ANTI_DEBUG` | Chunk already has anti-debug | `_inject_anti_debug()` |
| `CHUNK_API_HASH` | Chunk has hash-based API resolution | `_obfuscate_api_calls()` |
| `CHUNK_STRING_ENCRYPT` | Chunk encrypts its own strings | `_encrypt_string_literals()` |

---

## Chunk Layer Options

44 chunk files across 8 layer categories. The assembler picks one option per layer (from a recipe YAML or the adaptive selector) and stitches them into a single .c file.

### api_resolve (2 chunks)

How Windows APIs are resolved at runtime.

| Chunk | Risk | Description |
|---|---|---|
| `api_hash_djb2.c` | low | DJB2 hash-based resolution — no plaintext API name strings in binary |
| `peb_walk.c` | vlow | Manual PEB (Process Environment Block) walking — no `LoadLibrary` in IAT at all |

Default: `direct_import` (no chunk — normal static imports)

### arch (7 chunks)

How collector code executes.

| Chunk | Risk | Description |
|---|---|---|
| `sequential.c` | high | Direct calls in `main()` — straightforward, easily profiled |
| `threaded.c` | medium | Each collector in its own thread via `CreateThread` |
| `staged.c` | low | Staged execution with random jitter (1-5s) between operations |
| `fiber.c` | low | Fiber-based cooperative scheduling via `ConvertThreadToFiber`/`SwitchToFiber` |
| `callback_abuse.c` | vlow | Uses `EnumWindows`/timer callbacks as execution vehicle — looks like GUI enumeration |
| `apc_self.c` | vlow | `QueueUserAPC` to own thread — execution via APC queue, unusual control flow |
| `service.c` | high | Windows service binary — requires admin, suspicious for non-service exe |

### collectors (14 chunks)

Data collection modules — each gathers one category of information.

| Chunk | What it Collects |
|---|---|
| `system_info.c` | Hostname, username, OS version, hardware, IP addresses |
| `processes.c` | Running process list via `CreateToolhelp32Snapshot` |
| `env_vars.c` | Environment variables (`PATH`, `USERPROFILE`, tokens, etc.) |
| `wifi_passwords.c` | Saved WiFi profiles + plaintext passwords via `netsh` |
| `browser_chromium.c` | Chromium browser data (Login Data, History, Cookies, Credit Cards, Autofill) for Chrome, Edge, Brave, Opera, Vivaldi, Yandex |
| `discord_tokens.c` | Discord/DiscordPTB/DiscordCanary local storage tokens |
| `ssh_keys.c` | `~/.ssh/` directory contents (id_rsa, id_ed25519, known_hosts, config) |
| `cloud_creds.c` | AWS credentials, Azure tokens, GCP service account keys |
| `crypto_wallets.c` | Wallet files from Electrum, Exodus, Atomic, Jaxx, MetaMask |
| `screenshot.c` | Desktop screenshot via `BitBlt` (BMP format). Detects blank screens (no desktop session) and skips |
| `keylogger.c` | Low-level keyboard hook via `SetWindowsHookEx` (WH_KEYBOARD_LL) |
| `clipboard.c` | Clipboard contents via `OpenClipboard`/`GetClipboardData` |
| `ftp_credentials.c` | FileZilla, WinSCP saved sessions |
| `installed_software.c` | Installed programs from registry `Uninstall` keys |
| `telegram_session.c` | Telegram Desktop `tdata` session directory |

### core (3 chunks)

Utility functions used by collectors.

| Chunk | Purpose |
|---|---|
| `emit_buffer.c` | Shared output buffer — collectors append data with section markers |
| `file_ops.c` | File read/write helpers |
| `run_cmd.c` | Shell command execution via `CreateProcess` with captured output |

### evasion (10 chunks)

Anti-analysis and obfuscation modules selected per-build.

| Chunk | Risk | Description |
|---|---|---|
| `anti_debug.c` | medium | `IsDebuggerPresent` + timing checks (same logic as `_inject_anti_debug` pass) |
| `anti_vm.c` | low | CPUID leaf detection + registry checks for VMware/VirtualBox/Hyper-V artifacts |
| `anti_sandbox.c` | low | Mouse movement tracking, screen resolution check, uptime check, process count threshold |
| `deferred_exec.c` | low | Sleep 5-30 minutes before starting (sandbox timeout evasion) |
| `triggered_exec.c` | vlow | Wait for user mouse/keyboard activity before starting |
| `sleep_jitter.c` | medium | Random delays (1-5s) between operations |
| `string_encrypt.h` | medium | XOR string encryption header (compile-time encrypted, runtime decrypted) |
| `stack_strings.h` | low | Build strings character-by-character on the stack — no `.rdata` section strings |
| `aes_encrypt.c` | vlow | AES-128-CBC string encryption with runtime decryption |
| `api_hash.c` | low | Generic API hashing resolver (DJB2-based) |

### exfil (3 chunks)

Data exfiltration methods.

| Chunk | Risk | Description |
|---|---|---|
| `tcp_direct.c` | high | Raw TCP socket to C2 — fast, reliable, easily detected as anomalous traffic |
| `http_post.c` | medium | HTTP POST request — blends with normal web traffic |
| `dns_exfil.c` | vlow | DNS TXT record queries — extremely stealthy, slow, limited bandwidth |

### persist (3 chunks)

Post-reboot persistence mechanisms.

| Chunk | Risk | Description |
|---|---|---|
| `registry_run.c` | medium | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` key |
| `scheduled_task.c` | medium | Windows Task Scheduler via `schtasks` command |
| `startup_folder.c` | medium | Shortcut in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` |

### process (1 chunk)

Binary structure and process lineage.

| Chunk | Risk | Description |
|---|---|---|
| `ppid_spoof.c` | low | Spoofed parent process — creates child under `explorer.exe` PID to look legitimate |

Additional options defined in the selector but without dedicated chunks: `dll_sideload` (proxy DLL loaded by signed MS binary), `process_hollow` (hollowed legitimate process).

---

## Hybrid Evasion Loop (`evasion_selector.py`)

Automated adaptive loop that deploys, checks detection, re-selects layers, and repeats. Three escalation tiers.

### Tier 1: Algorithmic (runs 1-5)

Rule-based selection from detection signal keywords. 11 detection rules map AV/EDR output strings to layer changes:

| Signal Keywords | Detection Type | Layer Changes |
|---|---|---|
| `Trojan:Win32`, `TrojanSpy` | Static signature | api_resolve -> hash/peb, data_obfuscation -> stack/aes |
| `Behavior:Win32` | Behavioral | timing -> deferred/triggered, execution -> callback/fiber, process -> ppid/dll |
| `HackTool` | Known tool | data_obfuscation -> aes, api_resolve -> indirect_syscall |
| `PWS:Win32`, `Stealer` | Credential access | timing -> triggered, exfil -> dns/http, process -> dll/hollow |
| `Persistence`, `RunKey` | Persistence flagged | persistence -> scheduled_task/none |
| `Keylogger`, `Spy:Win32` | Keylogger detection | api_resolve -> peb/syscall, execution -> callback, anti_analysis -> sandbox/full |
| `SuspiciousProcess` | Process lineage | process -> dll_sideload/hollow |
| `ConnectionToC2`, `Beacon` | Network behavior | exfil -> dns, timing -> workday/triggered |
| `AMSI` | Content scan | data_obfuscation -> aes/stack |
| `SandboxDetected` | Anti-analysis detected | anti_analysis -> debug/none, timing -> triggered |
| `Exploit:`, `CVE-` | Exploit pattern | data_obfuscation -> stack, execution -> apc/callback |

History tracking: avoids repeating layer combinations that were previously detected. Without feedback, progressively escalates evasion each run.

### Tier 2: Local LLM (runs 6-8)

Sends a structured prompt to the local LLM (default Qwen3-35B at localhost:1234) containing:

- All available layer options with risk ratings
- Current auto-selected configuration
- Detection feedback text
- Any compile errors

The LLM outputs `CHANGE layer option REASON: ...` or `CONFIRM` lines. Parsed changes override the algorithmic selection.

Falls back to algorithmic selection if the LLM is unreachable or returns unparseable output.

### Tier 3: Cloud LLM (runs 9-10)

Escalates to cloud LLM for deep architectural analysis. Additionally selects the lowest-risk (`vlow`) option for every layer that hasn't been caught before — maximum evasion.

### AV/EDR Support

Configurable detection commands per AV type:

| AV Type | Detection Command |
|---|---|
| Defender | `Get-MpThreatDetection \| Select-Object -Last 3 \| Format-List` |
| CrowdStrike | `Get-EventLog -LogName Application -Source CsFalcon* -Newest 5` |
| SentinelOne | `Get-EventLog -LogName Application -Source SentinelOne* -Newest 5` |
| Carbon Black | `Get-EventLog -LogName Application -Source Cb* -Newest 5` |
| Custom | User-specified PowerShell command |

---

## Obfuscation Levels

| Level | Passes Applied | Use Case |
|---|---|---|
| **none** | No transforms | Debugging, testing raw chunk output |
| **light** | sanitize_includes, mutate_source (vars + junk + int split), encrypt_string_literals | Quick builds, low-priority targets |
| **heavy** | All of light + inject_seh_in_main, inject_anti_debug, obfuscate_api_calls | Default. Good balance of evasion vs compile reliability |
| **max** | All of heavy + LLM rewrite (function rename, control flow restructure, dead code) | Maximum evasion. Requires local LLM running. ~30% compile failure rate mitigated by retry loop |

### Binary Size Impact (infostealer_full recipe)

| Level | Source Size | Binary Size |
|---|---|---|
| none | 28,861 chars | 282,091 bytes |
| light | 40,378 chars | 289,433 bytes |
| heavy | 44,795 chars | 293,107 bytes |
| max | varies (LLM-dependent) | varies |

---

## Recipes

Pre-configured layer selections in `templates/chunks/recipes/`:

| Recipe | Description |
|---|---|
| `infostealer_full.yaml` | All 14 collectors, TCP exfil, sequential execution |
| `infostealer_staged.yaml` | Staged execution with jitter between collectors |
| `infostealer_edr_v1.yaml` | EDR-evasive: hash API resolution, callback execution, anti-debug |
| `infostealer_edr_v2.yaml` | Maximum EDR evasion: PEB walk, APC execution, DNS exfil |
| `keylogger.yaml` | Keylogger + clipboard collectors |
| `keylogger_stealth.yaml` | Stealth keylogger with anti-sandbox, deferred exec |

## Total Combinations

8 layers x variable options per layer = **216,000** possible layer combinations (before obfuscation-level variations).
