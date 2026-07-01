# Malware Generation Framework

An automated end-to-end system that generates, compiles, deploys, and verifies malware against live Windows/Linux VMs with real EDR products. Uses local LLMs (via LM Studio) and/or cloud LLMs (via Fugu/Sakana) to produce working C/Go source code, cross-compiles with MinGW, uploads to a QEMU/KVM VM, executes, and checks EDR/AV detection — feeding specific detection feedback back into each subsequent attempt.

Implements the closed-loop evasion approach from Adam Chester's SpecterOps "Day Shift" research: generate malware, get caught, learn *exactly what caught it*, adapt, and retry.

---

## Quick Start

```bash
# Generate malware source only (no VM needed)
python -m malware_gen_framework generate --spec spec.yaml --output results

# Full pipeline: generate + provision VM + verify + iterate
python -m malware_gen_framework run --spec spec.yaml --output results --loop

# Reuse existing VM
python -m malware_gen_framework run --spec spec.yaml --output results \
    --use-existing-vm --vm-port 10022 --loop

# Web dashboard
python -m malware_gen_framework portal
```

### Prerequisites

| Dependency | Purpose |
|---|---|
| [LM Studio](https://lmstudio.ai/) | Local LLM server (port 1234) |
| `x86_64-w64-mingw32-gcc` | Cross-compilation for Windows targets |
| QEMU/KVM + OVMF | VM provisioning (verification mode) |
| `swtpm` | TPM 2.0 emulation for Windows 11 |
| ChromaDB databases | Technique/exploit/CTI corpus (see Databases) |
| Python 3.12+ | `asyncssh`, `chromadb`, `pydantic`, `jinja2`, `flask` |

---

## Architecture

```
                              spec.yaml
                                  |
                                  v
  +-----------------------------------------------------------------+
  |                         CLI (cli.py)                             |
  |  generate | provision | verify | run | analyze | portal | clean  |
  +-----------------------------------------------------------------+
                                  |
                                  v
  +-----------------------------------------------------------------+
  |                      Pipeline (pipeline.py)                      |
  |                                                                  |
  |  Stage 0        Stage 1         Stage 2          Stage 3         |
  |  Parse Spec --> Generate --> Provision VM --> Verify + Loop      |
  |                    |                             |               |
  |              Pre-loop compile              Detection feedback    |
  |              check (3 attempts)            loop (up to N iter)   |
  +-----------------------------------------------------------------+
         |              |                |                |
         v              v                v                v
  +------------+  +-----------+  +-------------+  +--------------+
  | Generation |  | Provision |  |  Verifier   |  |    Loop      |
  |   Engine   |  |   Engine  |  |             |  |  Controller  |
  |            |  |           |  | - Compile   |  |              |
  | - DB query |  | - QEMU/KVM|  | - Deploy    |  | - Failure    |
  | - Context  |  | - OVMF    |  | - Execute   |  |   classify   |
  | - Plan     |  | - TPM 2.0 |  | - Pre-scan  |  | - Analyze    |
  | - Chunk gen|  | - SSH     |  | - EDR check |  | - Patch or   |
  | - Assembly |  | - Snapshot|  | - Behavior  |  |   rewrite    |
  | - Evasion  |  | - Overlay |  |   validate  |  | - Backoff    |
  +------------+  +-----------+  +-------------+  +--------------+
       |    |                          |
       v    v                          v
  +------+ +------+          +-----------------+
  |Local | |Cloud |          | Binary Analyzer |
  | LLM  | | LLM  |          | (pre-deploy)    |
  +------+ +------+          +-----------------+
```

---

## Pipeline Stages

### Stage 0: Parse Target Spec

Reads `spec.yaml` into a `TargetEnvironmentSpec`. For connection-back malware (infostealer, keylogger, RAT), C2 address and port are auto-injected.

### Stage 1: Generate Malware

The core of the framework. Follows a multi-step process:

```
spec.yaml --> DB Queries (3 ChromaDB collections in parallel)
                |
                v
          Context Build (rank techniques by EDR match, OS, severity)
                |
                v
          Selection (evasion techniques, CVE exploits, compiler flags)
                |
                v
          LLM Planning (structured component plan, reviewed up to N cycles)
                |
                v
          Chunk Generation (each function in a separate LLM call)
                |
                v
          Assembly (topological sort, forward declarations, globals)
                |
                v
          Smooth Pass (fix cross-chunk call-site mismatches)
                |
                v
          Main Wiring (verify main() calls all dependencies)
                |
                v
          Evasion Passes (string encryption, API obfuscation, anti-debug, ...)
                |
                v
          Pre-loop Compile Check (cross-compile, deterministic fix, up to 3 attempts)
```

### Stage 1b: Behavioral Validation Plan

Before verification, the LLM generates a `ValidationPlan` — 3-5 commands to run on the VM after execution to verify the malware did its job (e.g., "check if exfil data was sent", "verify registry key was created").

### Stage 2: Provision VM

Provisions a QEMU/KVM VM or reuses an existing one. Windows 11 via OVMF/UEFI with TPM 2.0, Linux via cloud-init. Uses `blockdev-snapshot-sync` overlays for fast resets.

### Stage 3: Verify + Loop

Compiles, deploys to VM, executes, checks EDR detections, runs behavioral validation. On failure, analyzes *what specifically was detected* and feeds that into the next generation.

---

## Detection Feedback Loop

The key differentiator from naive generate-and-pray approaches. When EDR detects the malware, the framework captures **specific detection details** — not just "detected" vs "not detected":

```
Iteration 1: Generate ransomware
     |
     v
Defender detects: "Trojan:Win32/Wacatac.B!ml" (Category: Trojan, Severity: Severe)
     |
     v
Failure Analysis receives: "Defender flagged heuristic ML model match on
  CryptEncrypt + file enumeration pattern. Rule: Wacatac.B!ml"
     |
     v
Iteration 2: LLM adapts — indirect syscalls, different encryption API,
  randomized file access pattern
     |
     v
Defender: no detection
```

### What Gets Captured

| Detection Method | Data Extracted |
|---|---|
| Windows Defender (Get-WinEvent) | Threat name, category, severity, process path |
| MpCmdRun.exe pre-scan | Immediate threat verdict before execution |
| REST API EDRs (Wazuh, Velociraptor) | Rule description, alert JSON |
| Elasticsearch EDRs (Elastic) | Signal rule description, matched fields |
| Log file EDRs (OpenEDR) | Raw JSON event entries |
| SSH command EDRs | Raw command output |

### Pre-Deployment Analysis

Before uploading to the VM, `binary_analyzer.py` checks the compiled PE:

- **Import table** — flags suspicious APIs (VirtualAllocEx, CreateRemoteThread, etc.)
- **String analysis** — detects suspicious plaintext strings
- **Entropy analysis** — flags high-entropy sections (packed/encrypted)
- **YARA pre-check** — runs community YARA rules against binary

If the risk score exceeds the threshold, the binary is blocked from VM deployment and findings feed back through the detection loop — saving a full VM iteration.

---

## Evasion Pipeline

After code generation, before compilation, the source passes through a chain of evasion transforms:

| Pass | What It Does |
|---|---|
| `_sanitize_includes` | Fix hallucinated headers (`win.h`->`windows.h`, `iprtrapi.h`->`iprtrmib.h`), enforce ordering (`winsock2.h` before `windows.h`), remove Linux-only headers |
| `_encrypt_string_literals` | Replace string constants with XOR-encrypted byte arrays + runtime decryption |
| `_obfuscate_api_calls` | Replace direct Win32 API calls with `GetProcAddress` + function pointers via `_xd_init()` |
| `_inject_amsi_etw_bypass` | Patch `AmsiScanBuffer` and `EtwEventWrite` in memory at startup |
| `_inject_anti_debug` | `IsDebuggerPresent` + `CheckRemoteDebuggerPresent` checks |
| `_inject_seh_in_main` | Wrap `main()` in `__try/__except` structured exception handler |
| `_inject_process_injection` | Process hollowing / injection scaffolding |
| `_ensure_exfil_substance` | Verify exfiltration functions actually collect and send data |
| `_mutate_source` | Variable/function name randomization |

All passes are idempotent. AMSI/ETW and anti-debug are applied before API obfuscation so their API names get obfuscated too.

---

## Deterministic Compile Fixes

LLMs consistently produce the same categories of broken C code. Rather than burning LLM calls on fixes, `code_analysis.py` applies ~100 deterministic corrections before compilation:

| Category | Examples |
|---|---|
| **Hallucinated headers** | `win.h`->`windows.h`, `iprtrapi.h`->`iprtrmib.h` |
| **Hallucinated APIs** | `close_socket`->`closesocket`, `FindCloseA`->`FindClose` |
| **Wrong API suffix** | `Process32FirstA`->`Process32First` (no A/W variant exists) |
| **Wide->ANSI** | `FindFirstFileW`->`FindFirstFileA`, `wcslen`->`strlen` |
| **Type mismatches** | `HANDLE`->`HCRYPTPROV` for crypto variables, `bool`->`BOOL` |
| **Python/Rust leaks** | `none`->`NULL`, `None`->`NULL` |
| **Hallucinated _p\<API\>** | De-obfuscate `_pCreateFile` back to `CreateFile` when no typedef exists |
| **Missing constants** | `HKCU`->`HKEY_CURRENT_USER`, `CSIDL_DOWNLOADS`->`CSIDL_PROFILE` |
| **Brace imbalance** | Remove stray `}` at file scope |
| **LLM prose in code** | Strip leaked reasoning text, numbered lists, markdown |
| **Compiler suggestions** | Parse gcc's "did you mean X?" and auto-rename |
| **Undefined functions** | Remove calls to functions with no definition |
| **Duplicate definitions** | Keep first occurrence, remove subsequent |
| **Placeholder bodies** | `{ ... }` -> `{ return 0; }` |
| **sprintf/snprintf** | Fix `sprintf(buf, size, fmt)` -> `snprintf(buf, size, fmt)` |

These fixes resolve ~70% of compile errors without any LLM call.

---

## Iteration State

The framework tracks persistent state across retry iterations via `iteration_state.py`:

```json
{
  "total_attempts": 3,
  "detection_history": [
    {"edr": "defender", "rule": "Trojan:Win32/Wacatac.B!ml", "category": "Trojan"}
  ],
  "techniques_tried": [
    {"name": "xor_string_encrypt", "iteration": 1, "result": "detected"},
    {"name": "api_obfuscation", "iteration": 2, "result": "undetected"}
  ],
  "evasion_strategies_exhausted": ["basic_xor"],
  "successful_evasions": ["api_obfuscation", "amsi_bypass"],
  "precheck_failures": ["high_entropy_section_0"],
  "notes_for_next_iteration": "Defender ML model flags CryptEncrypt pattern"
}
```

This state is injected into the LLM prompt so each iteration builds on everything learned — not just the most recent failure.

---

## Chunk Generation

Instead of generating entire malware in one LLM call, each function is generated independently:

1. **Topological sort** — components ordered by dependency graph
2. **Per-chunk prompt** — exact signature, dependencies, evasion techniques, globals
3. **Cloud + local fallback** — cloud LLM first (if `cloud-run` mode), local on refusal
4. **Per-chunk syntax check** — MinGW `-fsyntax-only` after each chunk
5. **Retry loop** — up to 6 attempts per chunk with error feedback
6. **Substance check** — verify the function actually does something (not a stub)
7. **Golden chunk cache** — successful chunks cached across iterations

### Adaptive Thinking Disable (Qwen3)

After 3 consecutive garbage chunks, switches to no-think mode (`enable_thinking: false`). Also forced on last-resort retries and main rewire attempts.

---

## VM Provisioning

### Windows 11

```
Windows ISO -> autounattend.xml -> FAT12 ISO -> QEMU boot
                                                    |
                                                    v
                                            Unattended install (~13 min):
                                            - Bypass TPM/SecureBoot checks
                                            - Create vmuser / vmuser123
                                            - Install & start OpenSSH
                                            - Disable Windows Defender
                                                    |
                                                    v
                                            SSH ready -> clean-state snapshot
```

### Linux

Cloud-init on Ubuntu/Debian cloud images. ~2 minutes.

### Snapshot Management

Uses `blockdev-snapshot-sync` (QMP) to create qcow2 overlays. Each iteration discards the overlay and creates a new one. Never uses `savevm`/`loadvm` (crashes pflash).

Per-EDR overlays allow testing the same binary against multiple EDR products without reinstalling.

---

## EDR Support

### Supported EDRs

| EDR | Detection Method | Setup |
|---|---|---|
| **Windows Defender** | Get-WinEvent + MpCmdRun pre-scan | Built into Windows 11 |
| **OpenEDR** | Local `events.json` log file | Agent on VM, no server needed |
| **Wazuh** | REST API (`/alerts`) | Manager on host + agent on VM |
| **Velociraptor** | REST API (artifact results) | Server on host + client on VM |
| **Elastic** | Elasticsearch query (`/alerts/_search`) | Stack on host + agent on VM |

### Detection-Aware Evasion Selection

When retry iterations have detection history, `evasion_selector.py` adapts technique ranking:
- Boost techniques targeting the specific detection categories seen
- Demote techniques associated with detected patterns
- Query ChromaDB with actual detection rule names

### Defender Rule Extraction

`edr_rule_extractor.py` runs `MpCmdRun.exe -Scan` for immediate verdicts before waiting for real-time alerts. Gives exact threat name in seconds vs. minutes.

---

## Compilation

| Target | Compiler | Key Flags |
|---|---|---|
| Windows (C) | `x86_64-w64-mingw32-gcc` | `-O2 -s -static -m64` + 16 Win32 libs |
| Windows (Go) | `GOOS=windows GOARCH=amd64 go build` | `-ldflags='-s -w'` |
| Linux (C) | `gcc` on VM | standard flags |

Win32 libraries: `-lws2_32 -ladvapi32 -lole32 -loleaut32 -luuid -lgdi32 -luser32 -lshell32 -lshlwapi -lwininet -lpsapi -lcrypt32 -lcomdlg32 -lnetapi32 -lmpr -liphlpapi`

---

## Configuration

### spec.yaml

```yaml
os_platform: windows              # linux | windows
os_version: windows-11            # ubuntu-24.04 | windows-11
malware_type: ransomware          # ransomware | infostealer | keylogger | rat | ...
source_language: c                # c | go
output_format: exe                # exe | dll | shellcode

c2_address: "10.0.2.2"           # QEMU host IP (user-mode networking)
c2_port: 9001                    # Exfil listener port

edrs:                             # EDR products on target VM
  - defender
  - wazuh

admin_rights: true
installed_compilers:
  - mingw-w64

custom_gates:                     # Extra evasion requirements
  - no console window
  - must bypass AMSI
  - process hollowing preferred
```

### CLI Commands

| Command | Description |
|---|---|
| `generate` | Generate malware source code (no VM needed) |
| `provision` | Provision a new VM |
| `verify` | Verify existing source against VM |
| `run` | Full pipeline: generate + provision + verify + loop |
| `analyze` | Analyze existing source for issues |
| `portal` | Launch web dashboard (port 7070) |
| `clean` | Clean output directory |

### Key Flags

| Flag | Description |
|---|---|
| `--loop` | Enable verify-regenerate iteration loop |
| `--max-iters N` | Max loop iterations (default: 5) |
| `--mode cloud-run` | Use cloud LLM for chunk generation |
| `--cloud-provider fugu` | Cloud provider: `fugu` or `openrouter` |
| `--use-existing-vm` | Connect to already-running VM |
| `--vm-port PORT` | SSH port for VM (implies --use-existing-vm) |
| `--boot-existing` | Boot existing disk without reinstalling |
| `--resume` | Resume from checkpoint |
| `--debug` | Colored step-by-step debug output |
| `--plan-review-cycles N` | Max plan review iterations (default: 10) |
| `--llm-url URL` | Override local LLM endpoint |
| `--llm-model NAME` | Override LLM model name |

---

## Web Portal

`python -m malware_gen_framework portal` launches a Flask dashboard on port 7070:

- Live pipeline status and iteration progress
- Generated source code viewer
- Compilation output and error logs
- Detection results and alert details
- C2 listener management and received data
- Pipeline report viewer

---

## Module Reference

### Core Pipeline

| Module | Purpose |
|---|---|
| `cli.py` | CLI entry point, argument parsing, subcommand dispatch |
| `pipeline.py` | End-to-end orchestrator tying all stages together |
| `loop_controller.py` | Iteration loop with backoff, failure classification, stuck detection |
| `checkpoint.py` | Checkpoint/resume for crash recovery |

### Generation

| Module | Purpose |
|---|---|
| `generation_engine.py` | Planning, chunk gen, smooth pass, compile-fix, LLM routing |
| `llm_client.py` | Local LLM (LM Studio) and cloud LLM (Fugu/OpenRouter) clients |
| `code_processor.py` | Source assembly, fixup, compile-check commands |
| `code_analysis.py` | ~100 deterministic compile fixes, function parsing, call-site validation |
| `prompt_templates.py` | Jinja2 templates for all LLM prompts |

### Evasion & Analysis

| Module | Purpose |
|---|---|
| `evasion_passes.py` | String encryption, API obfuscation, AMSI/ETW bypass, anti-debug |
| `evasion_selector.py` | Detection-aware evasion technique ranking |
| `binary_analyzer.py` | PE import table, string, entropy, YARA pre-deployment analysis |
| `iteration_state.py` | Persistent iteration state across retry cycles |
| `edr_rule_extractor.py` | Defender MpCmdRun.exe rule/signature extraction |

### Knowledge Base

| Module | Purpose |
|---|---|
| `db_query_engine.py` | ChromaDB queries across 3 databases (malware, PoC, CTI) |
| `context_builder.py` | Ranks and deduplicates DB results into prompt-ready context |
| `exploit_selector.py` | Picks CVE exploits matching target OS/patch level |
| `compiler_selector.py` | Generates compiler-specific build instructions |
| `db_models.py` | Data models for MalwareTechnique, PoC, CTIFinding |

### VM & Verification

| Module | Purpose |
|---|---|
| `provision_engine.py` | QEMU/KVM VM lifecycle, SSH, QMP snapshots |
| `verifier.py` | Cross-compile, deploy, execute, EDR check, behavioral validation |
| `config_models.py` | VMProvisionConfig, EDR configs, overlay paths |
| `target_spec.py` | TargetEnvironmentSpec data model (Pydantic v2) |
| `spec_parser.py` | YAML/JSON spec file parser |
| `windows_provisioner.py` | autounattend.xml generation, FAT12 ISO creation |
| `linux_provisioner.py` | cloud-init YAML generation, ISO creation |
| `image_sources.py` | OS image/ISO download and caching |

### Portal & Utilities

| Module | Purpose |
|---|---|
| `portal/app.py` | Flask web dashboard |
| `portal/c2_listener.py` | C2 callback listener for connection-back malware |
| `debug_logger.py` | Colored step-by-step debug output |

---

## Databases

Three ChromaDB vector databases (external to this repo):

| Database | Collection | Contains |
|---|---|---|
| `malware_corpus/data/chroma` | `malware_techniques` | Evasion/injection/persistence techniques with EDR detection ratings |
| `malware_corpus/data/poc_chroma` | `poc_exploits` | CVE PoC exploit code with full source |
| `hermes_qwen_cti/data/chroma` | `cti_intel` | CTI intelligence reports (threat data) |

Queries are purpose-specific: per-EDR evasion queries, OS-specific technique queries, CVE-targeted lookups, CTI cross-references. Results cached per target-spec hash.

---

## Output Files

| File | Contents |
|---|---|
| `malware_source.c` | Final generated source code |
| `malware_test.exe` | Compiled binary (if compilation succeeded) |
| `pipeline_report.txt` | Run summary: iterations, detection results, timings |
| `iteration_state.json` | Persistent state for resume/analysis |
| `checkpoint.json` | Resume state (if run was interrupted) |
| `binary_analysis.json` | Pre-deployment PE analysis results |

---

## Test Suite

39 end-to-end tests covering the full pipeline:

```bash
# Run all tests
python -m pytest tests/test_pipeline_e2e.py -v

# Run fast tests only (no LLM needed, <1 sec each)
python -m pytest tests/test_pipeline_e2e.py -v -k "spec_ or cli_clean or db_ or context_ or edr_config or c2_"

# Run a specific generation test (requires LLM, ~15-40 min)
python -m pytest tests/test_pipeline_e2e.py::test_generate_ransomware -v

# Run VM tests (requires running QEMU VM)
python -m pytest tests/test_pipeline_e2e.py -v -k "vm or full_pipeline or cli_run"
```

| Category | Tests | Requirements |
|---|---|---|
| Spec parsing & CLI | 6 | None |
| Database & context | 3 | ChromaDB |
| C2 listener | 3 | None |
| Code generation (per malware type) | 6 | LLM |
| Generation features (plan, report, evasion, etc.) | 13 | LLM |
| Cross-language (Go, Rust, Linux) | 3 | LLM + Go/Rust compiler |
| VM verification | 4 | LLM + QEMU VM |
| CLI integration | 1 | LLM |

---

## LLM Integration

### Local LLM (LM Studio)

Default mode. Connects to LM Studio's OpenAI-compatible API at `http://localhost:1234`.

- Auto-loads model if nothing is loaded
- Supports `chat_template_kwargs` for Qwen3 thinking control
- Retries with exponential backoff (3 attempts, 600s timeout)
- Strips `<think>...</think>` blocks

### Cloud LLM (Fugu / Sakana)

In `cloud-run` mode, only chunk generation goes to the cloud. All orchestration stays local.

- Sanitizes prompts to avoid guardrail triggers
- Falls back to local on refusal/quota/auth errors
- Permanently disables on 401/402/403/429
- Supports Fugu (api.sakana.ai) and OpenRouter
