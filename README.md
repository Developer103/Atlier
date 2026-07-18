# Malware Generation Framework

Deterministic, chunk-assembled polymorphic malware generation with autonomous EDR evasion. Produces unique, evasion-hardened binaries from declarative YAML recipes — validated against CrowdStrike Falcon and Windows Defender on live Windows 11 VMs.

**Proven results:** 207,827 bytes exfiltrated through CrowdStrike Falcon + Windows Defender with zero detections. Binary survived on disk post-execution.

---

## Quick Start

```bash
# Assemble + compile from recipe (< 5 seconds)
python3 templates/chunks/assembler.py templates/chunks/recipes/infostealer_full.yaml \
    -o output/source.c --compile --randomize \
    --var C2_IP=10.0.2.2 --var C2_PORT=9001

# CLI wrapper
python -m malware_gen_framework chunk --recipe infostealer_full --compile --randomize --obfuscate light

# Hermes autonomous campaign (scan → build → deploy → detect → mutate → retry)
python -m hermes --edr crowdstrike --malware-type infostealer

# Web portal
python -m malware_gen_framework portal --port 7070 --host 0.0.0.0
```

### Prerequisites

| Dependency | Purpose |
|---|---|
| `x86_64-w64-mingw32-gcc` | Cross-compilation for Windows PE/DLL |
| Python 3.12+ | `flask`, `asyncssh`, `pyyaml`, `httpx` |
| QEMU/KVM + OVMF | Windows 11 VM with TPM 2.0 |
| Local LLM (optional) | Hermes agent reasoning (port 11235) |

---

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │           Hermes AI Orchestrator             │
                    │  (23 tools, autonomous campaigns, LLM)      │
                    └──────────────┬──────────────────────────────┘
                                   │ scan → strategy → build →
                                   │ deploy → detect → mutate
                                   ▼
┌──────────────┐   ┌──────────────────────────────┐   ┌──────────────┐
│ Recipe YAML  │──▶│     Chunk Assembler          │──▶│  Obfuscation │
│ (294 recipes)│   │ - dependency resolution      │   │  - light     │
│              │   │ - template variable subst    │   │  - heavy     │
│ Variant      │   │ - resource injection         │   │  - max (LLM) │
│ Groups (50)  │   │ - Rich header injection      │   └──────┬───────┘
│ --randomize  │   │ - PE timestamp stomping      │          │
└──────────────┘   └──────────────────────────────┘          ▼
                                                    ┌──────────────┐
                                                    │   Compile    │
                                                    │   (MinGW)    │
                                                    └──────┬───────┘
                                                           │
                    ┌──────────────────────────────────────┘
                    ▼
           ┌──────────────┐    ┌─────────────────────────┐
           │  Deploy to   │───▶│  Validate:              │
           │  Windows VM  │    │  - CrowdStrike Falcon   │
           │  (SSH/SCP)   │    │  - Windows Defender     │
           └──────────────┘    │  - C2 data received?    │
                               │  - Binary survived?     │
                               └─────────────────────────┘
```

---

## Framework at a Glance

| Metric | Value |
|---|---|
| Total code chunks | 409 across PE, JScript, VBScript, Batch |
| PE chunks | 255 (evasion: 110, collectors: 42, arch: 26, exfil: 22, commands: 13, process: 9, api_resolve: 7, persist: 7, c2: 5, core: 5, AD: 9) |
| JScript chunks | 81 |
| VBScript chunks | 43 |
| Batch chunks | 30 |
| Recipes | 294 |
| Variant groups | 50 (197 interchangeable chunks) |
| Behavioral variant groups | 45 — each swap changes runtime behavior EDRs observe |
| Static variant groups | 2 — change binary signature only (PE metadata, IAT) |
| Behavioral variants per recipe | ~5.9M (typical 9-group recipe) to ~2.5B (12-group recipe) |
| Output formats | PE (EXE), DLL, JScript, VBScript, Batch, CPL |
| Build time | < 5 seconds (assemble + compile) |
| Hermes agent tools | 23 |
| Codebase | 42K lines Python + 25K lines C templates |

---

## Chunk System

The core innovation. Pre-written, pre-tested C code fragments assembled into complete malware by declarative YAML recipes.

### Categories

| Category | Count | Purpose |
|---|---|---|
| `evasion/` | 110 | ETW bypass, syscall gates, sleep obfuscation, stack spoofing, anti-debug, anti-sandbox, PPID spoof, unhooking, etc. |
| `collectors/` | 42 | System info, processes, browser data, credentials, screenshots, cloud creds, crypto wallets, SSH keys |
| `arch/` | 26 | Execution architecture: sequential, threaded, fiber, callback, APC, staged, backdoor |
| `exfil/` | 22 | TCP, HTTP, HTTPS, DNS, LOLBin pipes, named pipe |
| `commands/` | 13 | Backdoor command handlers (sysinfo, processes, fileread, exec, screenshot, registry, etc.) |
| `process/` | 9 | PPID spoof (6 parents), process ghosting, masquerade |
| `api_resolve/` | 7 | DJB2, FNV-1a, CRC32, ROR13, PEB walk, indirect import, API set redirect |
| `persist/` | 7 | Registry Run, schtask, startup folder, COM hijack, service, WMI event |
| `ad_collectors/` | 6 | AD reconnaissance: users, groups, computers, OUs, GPOs, SPNs |
| `c2/` | 5 | TCP beacon (TLV), WinHTTP beacon, DNS C2, dead drop, named pipe |
| `core/` | 5 | Shared utilities: emit_buffer, run_cmd, file_ops |
| `ad/` | 3 | AD infrastructure: LDAP bind, SID resolve, JSON builder |

### Variant Groups & Behavioral Variants

50 groups of interchangeable chunks in `variants.yaml`. When `--randomize` is passed, the assembler randomly selects one member from each group. Same recipe → behaviorally different binary every build.

**45 behavioral groups** — each swap changes what EDRs observe at runtime (different syscall methods, different sleep mechanisms, different process trees, different API call patterns):

| Category | Groups | Key examples |
|---|---|---|
| **Evasion (25 groups)** | syscall_gate (10), sleep_obfuscation (8), stack_spoofing (7), api_resolution (7), anti_sandbox (7), arch_execution (7), injection_threadless (7), persistence (7), etw_bypass (6), anti_debug (6), ppid_spoof (6), arch_callback (6), env_keying (4), memory_evasion (4), control_flow (4), uac_bypass (4), execution_timing (3), net_transport (3), process_evasion (3), net_evasion (3), amsi_bypass (2), injection_callback (2), self_cleanup (2), injection_thread (4) | Swapping `hells_gate` ↔ `tartarus_gate` changes the syscall invocation mechanism; swapping `sleep_ekko` ↔ `sleep_foliage` changes the ROP chain used during encrypted sleep |
| **Functional (16 groups)** | system_info (4), keylogger_hook (4), exfil_http_lolbin (5), processes (3), exfil_tcp (3), exfil_http_api (3), exfil_dns (3), cmd_sysinfo (2), cmd_processes (2), cmd_netinfo (2), screenshot (2), env_vars (2), clipboard (2), netinfo (2), active_windows (2), exfil_file (2) | Swapping `exfil/curl_lolbin` ↔ `exfil/bitsadmin_lolbin` changes the child process EDR sees; swapping `collectors/system_info` ↔ `collectors/system_info_lolbin` changes API calls vs process spawns |
| **JScript evasion (4 groups)** | js_delivery (5), js_anti_analysis (4), js_execution_timing (4), js_string_protection (2) | Swapping `wsf_wrapper` ↔ `hta_wrapper` changes the delivery container and execution engine |

**2 static groups** — change binary signature without altering runtime behavior: `pe_metadata` (6: entropy pad, rich header, timestomp, checksum, debug dir, code cave), `iat_manipulation` (3: IAT pad, resource spoof, section merge).

**Combinatorial scale**: A typical PE infostealer recipe touching 9 variant groups yields **~5.9 million** unique behavioral variants. A heavier backdoor recipe touching 12 groups yields **~2.5 billion**. Each `--randomize` build is a detection-distinct binary.

### Recipe Format

```yaml
name: infostealer_cs_pe_proven
core:
  - core/emit_buffer
  - core/run_cmd
collectors:
  - collectors/system_info
  - collectors/processes
  - collectors/browser_chromium
exfil: exfil/tcp_direct
arch: arch/sequential
api_resolve: api_resolve/api_hash_ror13
resources: true
evasion:
  - evasion/etw_patch
  - evasion/sleep_ekko
  - evasion/stack_spoof
  - evasion/anti_sandbox
vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
```

---

## Evasion System

110 evasion chunks mapped to CrowdStrike Falcon's 6 detection layers:

| CS Layer | Our Countermeasures | Status |
|---|---|---|
| **Static ML** | Resources + manifest, Rich header injection, entropy padding, timestamp stomping, IAT padding, section merge | PROVEN |
| **Userland hooks** | 10 syscall gates (indirect, hells_gate, tartarus, syswhispers3...), 5 unhook methods, AMSI bypass | PROVEN |
| **Kernel callbacks** | Process masquerade, herpaderp, phantom DLL, 6 PPID spoof variants | PARTIAL |
| **Behavioral IOAs** | 8 sleep obfuscation, 7 stack spoof, 6 ETW bypass, 6 anti-debug, 7 anti-sandbox, 3 exec timing | PROVEN |
| **Cloud ML** | API resolution (required), resources + manifest (required), multi-format output | PROVEN |
| **Memory scanning** | Header stomp, module stomp, sleep encryption | THEORETICAL |

### Obfuscation Levels

| Level | Transforms |
|---|---|
| `none` | Passthrough |
| `light` | Variable renaming, junk code blocks, control-flow junk, string encryption |
| `heavy` | Light + SEH wrapper, anti-debug injection, API call obfuscation |
| `max` | Heavy + LLM-powered rewrite (function renaming, dead code, control flow) |

If obfuscation breaks compilation, the assembler automatically retries without it. When targeting an EDR, randomization and obfuscation are force-enabled.

---

## Hermes AI Orchestrator

Autonomous malware campaign agent built on the Hermes agent framework. Runs continuous scan → build → deploy → detect → mutate → retry loops without human intervention.

### Tools (23)

| Tool | Purpose |
|---|---|
| `scan_target` | Fingerprint OS, EDR products, LOLBins |
| `get_strategy` | Get recommended format + evasion for target EDR |
| `query_knowledge` | Check proven recipes and failed patterns |
| `list_recipes` / `list_chunks` | Browse available recipes and chunks |
| `assemble` | Build from recipe (auto-randomize + obfuscate for EDR) |
| `create_recipe` / `mutate_recipe` | Create new or modify existing recipes |
| `deploy_to_vm` | SCP to target, detect quarantine, auto-feed detection logs |
| `execute_on_vm` | Run binary on target |
| `start_c2_listener` | Start TCP/HTTP C2 listener |
| `check_c2_data` | Check exfiltrated data |
| `analyze_results` | Full post-execution analysis |
| `analyze_detection` | Classify detection type + recommend countermeasures |
| `list_edr_events` | Read EDR event logs |
| `sweep_matrix` | Test multiple evasion combos in batch |
| `cleanup_vm` | Kill processes, delete binaries, remove persistence |
| `read_file` | Read any framework file |
| `write_experimental_code` | LLM-generated experimental chunks |
| `compile_experimental` | Compile experimental code |
| `save_innovation_report` | Record novel findings |

### Campaign Flow

```
1. scan_target      → OS, EDR, LOLBins
2. query_knowledge  → proven recipes, failed patterns
3. get_strategy     → recommended format + evasion
4. assemble         → randomized + obfuscated binary
5. deploy_to_vm     → SCP, quarantine check, detection log feed
6. execute + C2     → start listener, run binary, capture data
7. analyze_results  → binary alive? C2 data? detections?
8. mutate + retry   → swap evasion chunks, rebuild, re-deploy
```

Auto-forces `randomize=true` and `obfuscation≥light` for EDR targets. If obfuscation breaks compilation, auto-falls back to unobfuscated (still randomized).

---

## Malware Types

### Infostealer
System info, processes, browser data (Chromium), Discord tokens, screenshots, cloud credentials, crypto wallets, SSH keys. 42 collector chunks, each independently swappable.

### Backdoor
Bidirectional C2 with TLV protocol. TCP beacon or WinHTTP beacon. 13 command handlers (sysinfo, processes, filelist, fileread, filewrite, screenshot, registry, netinfo, exec, exec_powershell). Reconnect with jitter. Supports hostname-based C2 (ngrok compatible).

### Keylogger
GetAsyncKeyState polling, clipboard monitoring, active window tracking. Multiple exfil options. Self-test validates full capture pipeline.

### AD Recon
LDAP-based Active Directory reconnaissance. Users, groups, computers, OUs, GPOs, SPNs. Works against Samba 4 AD and Windows AD.

---

## VM Infrastructure

- **QEMU/KVM** with OVMF/UEFI + TPM 2.0 (`swtpm`)
- **Windows 11 Pro** with CrowdStrike Falcon + Windows Defender
- **Snapshots**: `blockdev-snapshot-sync` overlays for fast resets (never `savevm`/`loadvm`)
- **Access**: SSH (port 10022), RDP (port 13389), user `vmuser`
- **Gold snapshot**: `crowdstrike` — clean state with Falcon + Defender + RDP ready

```bash
# Snapshot management
./scripts/vm_snapshot.sh save <name>
./scripts/vm_snapshot.sh restore <name>
./scripts/vm_snapshot.sh list
```

---

## Output

Results packaged in `results/chunk_<type>_<timestamp>/`:

```
results/chunk_infostealer_20260715_221129/
├── payload.exe       # Compiled binary
├── source.c          # Obfuscated C source
├── recipe.yaml       # Recipe used
├── resource.o        # PE resources (version info + manifest)
├── resource.rc       # Resource script
├── deploy.sh         # Deployment + validation script
├── c2_server.py      # Interactive C2 server
├── c2_listener.sh    # Simple netcat listener
├── parse_exfil.py    # Parse exfil blob into sections
└── exfil_*.bin       # Captured C2 data
```

---

## CLI Reference

```bash
# Assemble from recipe
python -m malware_gen_framework chunk --recipe <name> --compile [options]

Options:
  --randomize           Swap chunks via variant groups (forced for EDR targets)
  --obfuscate LEVEL     none | light | heavy | max (default: light)
  --compiler COMPILER   mingw | zig (default: mingw)
  --var KEY=VALUE       Override template variables (C2_IP, C2_PORT, etc.)

# Hermes autonomous campaign
python -m hermes --edr crowdstrike --malware-type infostealer

# Web portal
python -m malware_gen_framework portal --port 7070 --host 0.0.0.0
```

---

## Key Files

| File | Purpose |
|---|---|
| `templates/chunks/assembler.py` | Core assembler — recipe parsing, dependency resolution, compilation |
| `templates/chunks/obfuscate.py` | Post-assembly obfuscation (4 levels) |
| `templates/chunks/variants.yaml` | Variant group definitions (50 groups, 197 chunks) |
| `evasion_passes.py` | Source-level evasion transforms |
| `cli.py` | CLI entry point |
| `hermes/tools.py` | Hermes tool implementations (23 tools) |
| `hermes/prompts.py` | Hermes system prompt + tool schemas |
| `hermes/hermes_agent_bridge.py` | Bridge to Hermes agent framework |
| `hermes/strategy.py` | EDR-specific strategy trees |
| `hermes/config.py` | Framework configuration |
| `knowledge.md` | Operational knowledge base |
| `portal/app.py` | Web portal (Flask + WebSocket) |
| `scripts/vm_snapshot.sh` | VM snapshot management |

---

## Documentation

| Document | Description |
|---|---|
| `docs/framework_architecture_en.md` | Detailed architecture (English) |
| `docs/framework_architecture_ja.md` | Detailed architecture (Japanese) |
| `docs/crowdstrike_falcon_evasion_research.md` | CrowdStrike Falcon evasion research |
| `docs/malgen_skill_documentation.md` | Full framework guide |
| `knowledge.md` | Operational lessons and proven techniques |
