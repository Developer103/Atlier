# Malware Generation Framework

A modular pipeline that takes a target environment specification and produces undetectable malware, verified against EDR/AV in an ephemeral VM. The framework queries three pre-populated databases (malware techniques corpus, PoC exploits, CTI intelligence), assembles ranked context for an LLM, generates C/C++ source code, compiles it inside a virtual machine, and iteratively retries until the binary escapes detection or max iterations are reached.

## Architecture Overview

The framework is organised into six phases:

```
┌───────────────────────────────────────────────────────────────┐
│                       CLI Entry Point                         │
│  python -m malware_gen_framework <command> --spec target.yaml │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 0: Parse & Validate Target Spec                        │
│  spec_parser.py + target_spec.py                               │
│  YAML/JSON → Pydantic TargetEnvironmentSpec                   │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 1: Database Query & Context Assembly                   │
│  db_query_engine.py → context_builder.py → prompt_templates.py│
│  Malware corpus + PoC DB + CTI KB → ranked context block      │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 2: LLM Generation                                      │
│  generation_engine.py                                          │
│  Context + prompt templates → C/C++ malware source code       │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 3: VM Provisioning (optional)                          │
│  provision_engine.py + linux_provisioner.py +                 │
│  windows_provisioner.py + image_sources.py                    │
│  QEMU VM with COW disk, cloud-init/autounattend, SSH bridge   │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 4: Verification                                        │
│  verifier.py                                                   │
│  Compile + execute on VM → query EDR logs → behaviour checks  │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 5: Retry Loop (optional)                               │
│  loop_controller.py                                            │
│  Detect failure mode → regenerate variant with new seed → retry│
└───────────────────────────────────────────────────────────────┘
```

## Usage

### CLI Subcommands

| Command | Description |
|---------|-------------|
| `generate` | Generate malware source code from a target spec (no VM needed) |
| `verify` | Verify already-generated source against a running VM |
| `run` | Full pipeline: generate → provision → verify → retry loop |
| `analyze` | Query DBs and show context without generating code |

```bash
# Generate only (fastest, no VM required)
python -m malware_gen_framework generate --spec target.yaml --output ./results

# Full end-to-end with retry loop
python -m malware_gen_framework run \
    --spec target.yaml \
    --output ./results \
    --max-iters 5 \
    --loop

# Analyze without generation
python -m malware_gen_framework analyze --spec target.yaml
```

### Programmatic API

```python
import asyncio
from malware_gen_framework.pipeline import MalwarePipeline

async def main():
    pipeline = MalwarePipeline(
        generate=True,
        provision_vm=False,  # set True for full VM verification
        verify=False,
        retry_loop=False,
    )
    result = await pipeline.run(spec_path="target.yaml", output_dir="./results")
    print(result.print_summary())

asyncio.run(main())
```

## Target Specification

Every phase after spec parsing consumes a `TargetEnvironmentSpec` (defined in `target_spec.py`). It is a Pydantic model that accepts YAML or JSON input:

```yaml
os_platform: linux          # "linux" or "windows"
os_version: ubuntu-24.04    # e.g. windows-11, debian-bookworm
edrs:                         # EDR products installed on target
  - crowdstrike
  - sentinel_one
antivirus: null               # AV product name if any
patch_level: "latest"         # OS patch level context
installed_compilers:          # available build tools
  - gcc
  - mingw-w64
common_tools:                 # commonly installed utilities
  - python3
  - powershell
sandbox_detectors:            # known sandbox detectors in environment
  - vmware
  - virtualbox
custom_gates:                 # custom evasion requirements (free-form)
  - no_console_window
  - sleep_before_main
```

The parser (`spec_parser.py`) normalises fields — EDR names are lowercased with spaces replaced by underscores, compiler lists are normalised to lowercase, etc.

## Module Reference

### Phase 0: Spec Parsing

| File | Purpose |
|------|---------|
| `target_spec.py` | Core Pydantic model for the target environment. Defines enums (`OSPlatform`, `LinuxDistro`, `WindowsVersion`) and constants (`KNOWN_EDRS`, `KNOWN_COMPILER_TOOLS`). Includes validators that normalise EDR names, compiler lists, and sandbox detectors to lowercase snake_case. |
| `spec_parser.py` | Loads YAML/JSON spec files and returns a validated `TargetEnvironmentSpec`. Handles the conversion from raw file format to Pydantic model with all field normalisation applied. Also includes `spec_to_yaml()` for serialising specs back to YAML. |

### Phase 1: Database Query & Context Assembly

| File | Purpose |
|------|---------|
| `db_models.py` | Dataclass definitions for structured query results: `MalwareTechnique`, `PoC`, `CTIFinding`, and `QueryResult`. These represent the output schema from each database. All fields have safe defaults in `__post_init__`. |
| `db_query_engine.py` | Subprocess wrappers that invoke the external query scripts (`query_malware.py`, `query_poc.py`) against the three databases (malware corpus, PoC DB, CTI knowledge base). Parses JSON output into `MalwareTechnique`/`PoC`/`CTIFinding` dataclasses. Supports parallel execution via `query_all()`. |
| `context_builder.py` | Takes raw query results + target spec and produces a single ranked context block. Deduplicates by ID/CVE across sources. Ranks techniques using a scoring formula: base score from detection rating (lower = easier to evade), +3.0 boost for EDR-matched techniques, +2.0 for high-value categories (evasion/persistence/lateral_movement). Ranks PoCs by severity and exploit type (+5.0 bonus for RCE/PRIVESC). Produces a `ContextBlock` dataclass with a SHA256 hash for change detection across retry iterations. |
| `prompt_templates.py` | Jinja2 template manager holding the LLM prompt templates. `GENERATE_MALWARE_TEMPLATE` renders the context block (techniques, PoCs, CTI findings) into structured markdown sections that get injected into the generation prompt alongside compiler instructions. |

### Phase 1.5: Selectors

| File | Purpose |
|------|---------|
| `evasion_selector.py` | Queries the malware corpus for EDR-specific evasion techniques. Given a list of target EDRs, returns ranked evasion strategies with concrete API call sequences and parameter tweaks that have historically evaded those products. Deduplicates by ID across EDR queries. |
| `exploit_selector.py` | Queries the PoC DB for exploits relevant to the target OS and CVEs. Builds search terms from the spec (e.g., "ubuntu" → ["linux", "2024"]), filters PoCs by OS, deduplicates by CVE ID. Ranks by severity weight (critical=4.0 down to low=1.0) plus exploit-type bonus (RCE=3.0, PRIVESC=2.5), with a version proximity bonus for 2024+ CVEs (+0.5). Generates adaptation notes per PoC (input vector matching, compiler selection, patch level verification). |
| `compiler_selector.py` | Validates installed compilers and generates concrete build commands. Detects source code features (threading headers → `-lpthread`, Windows API → `-lws2_32 -ladvapi32`, OpenSSL → `-lcrypto`) and appends appropriate flags. Produces language-specific build instructions for gcc, clang, mingw-w64, rustc, and go with optimisation/stripping guidance. |

### Phase 2: Generation Engine

| File | Purpose |
|------|---------|
| `generation_engine.py` | Core generation orchestrator. Contains the `SubprocessLLMClient` class that invokes local LLMs via Ollama (`http://localhost:11434`) or GGUF model files from `~/.llm_vault/models`. The `GenerationEngine.generate()` method loads the context block, renders it into a prompt using Jinja2 templates from `prompt_templates.py`, and sends it to the LLM. Supports variant generation with seed strings for retry iterations — each call appends previous failure context (detection score, alerts) as an instruction to avoid repeating mistakes. The engine tracks context hashes to detect when regeneration produces identical output. |

### Phase 3: VM Provisioning

| File | Purpose |
|------|---------|
| `config_models.py` | Pydantic models for VM configuration. Defines `TargetOS` enum (Windows 10/11, Ubuntu 24.04/22.04, Debian Bookworm), `VMProvisionConfig` with resource specs (CPU cores, RAM, disk GB), network config (SSH port forwarding defaults to host:10022→vm:22), and EDR configuration. Computes internal paths for base images, COW snapshots, and QMP sockets based on the OS type. |
| `provision_engine.py` | Orchestrates the full VM provisioning pipeline in six steps: (1) ensure base OS image via `image_sources`, (2) create a copy-on-write QCOW2 snapshot from the base disk using `qemu-img create -b`, (3) generate an auto-provisioning ISO (cloud-init for Linux, autounattend for Windows), (4) build and start a QEMU VM with KVM acceleration, guest agent, virtio-net, and host port forwarding, (5) wait for SSH readiness on the forwarded port (up to 5 minutes), (6) return an active `VMInstance` object. Handles graceful shutdown via QMP powerdown command or SSH fallback, plus force kill after timeout. Uses asyncssh for all VM communication. |
| `linux_provisioner.py` | Generates cloud-init NoCloud configuration for Linux VMs. Produces user-data YAML with ssh_authorized_keys (optional), password authentication, sudo access, and runcmd scripts to enable/start SSH service and disable screen blanking. Packages the YAML into a bootable ISO using genisoimage with the cidata volume ID that cloud-init recognises. |
| `windows_provisioner.py` | Generates autounattend.xml for unattended Windows installation. Covers disk partitioning (EFI 100MB → MSR 16MB → primary), image selection (Windows 11 Pro key), OOBE bypass, auto-logon, user creation with admin group membership, and FirstLogonCommands that disable password expiry and install/enable OpenSSH Server with firewall rules. Packages into a bootable ISO as AUTOUNATTEND.XML. |
| `image_sources.py` | Handles OS image downloads. For Linux: downloads Ubuntu cloud images from canonical URLs (noble/jammy server cloudimg). For Windows: tries the quickget CLI first, falls back to downloading the official Microsoft evaluation ISO and VirtIO driver ISO via aiohttp async HTTP. Verifies file existence before re-downloading. |

### Phase 4: Verification

| File | Purpose |
|------|---------|
| `verifier.py` | Runs generated malware inside the provisioned VM through a six-step verification pipeline: (1) write source code to `/tmp/malware_src.c` on the VM via SSH heredoc, (2) compile using auto-detected or spec-provided compiler command (defaults to `x86_64-w64-mingw32-gcc -O2 -s` for Windows targets), (3) execute in background and capture exit code, (4) query EDR logs (`/var/log/syslog` on Linux, Get-WinEvent on Windows) for matching process entries, (5) run behaviour checks — binary executability test, network activity via `ss`, splash window detection via xwininfo/WMI, (6) sandbox detection by checking CPU count (<2 cores) and RAM (<1000MB). Returns a `VerificationResult` with detection score (NONE/LOW/MEDIUM/HIGH), alert records, behaviour check results, and compilation output. Also provides `verify_standalone()` for smoke testing without a VM — compiles locally using gcc if available. |

### Phase 5: Retry Loop

| File | Purpose |
|------|---------|
| `loop_controller.py` | Manages the verify→regenerate retry loop with intelligent backoff and failure classification. Tracks iteration history via `IterationRecord` objects containing source code hash, context hash, detection score, alerts count, and build time. Classifies failures into modes: COMPILATION_FAILED, EXECUTION_CRASHED, DETECTED (high severity or >3 alerts), SANDBOX_DETECTED, CONTEXT_STUCK (same context hash across iterations), LLM_GENERATION_EMPTY, UNKNOWN. Implements exponential backoff between regeneration attempts (`backoff_base * 2^(iteration-1)`, capped at `backoff_max`). Detects stuck loops when the same context hash repeats `stick_threshold` times consecutively — forces a new variant with a different seed. Continues until an undetected binary is produced, max iterations reached, or all techniques are exhausted (exhaustive mode). Returns a `LoopResult` summarising all iterations and identifying the best outcome. |

### Phase 6: Pipeline & CLI

| File | Purpose |
|------|---------|
| `pipeline.py` | End-to-end orchestrator (`MalwarePipeline`) that chains phases together. Each phase is independently toggleable — users can generate code only (no VM), or run the full pipeline with verification and retry loop. The `run()` method executes stages sequentially: parse spec → generate code → provision VM (optional) → verify in VM (optional) → retry loop (optional). Assembles a `PipelineResult` container with all outputs, writes source code to disk, generates a human-readable report (`pipeline_report.txt`). |
| `cli.py` | Command-line interface using argparse. Four subcommands: `generate` (code only), `verify` (source + VM verification), `run` (full pipeline), `analyze` (query DBs and display context). The `--debug` flag activates the real-time debug logger for step-by-step tracing; `--verbose` enables Python stdlib logging at DEBUG level. |

### Supporting Modules

| File | Purpose |
|------|---------|
| `__init__.py` | Package initialisation — exports all public classes, functions, and models from every phase so users can import directly (e.g., `from malware_gen_framework import MalwarePipeline`). Organised by phase comments. |
| `debug_logger.py` | Coloured stdout debug logger with structured output. Provides methods for phase markers (`phase()`), step traces (`step()`), success/failure/warning/info messages, dictionary and list dumps, code snippets, and iteration summaries. All output is ANSI-coloured when enabled via the `--debug` flag. Gates all output on `self.enabled` — setting it to False suppresses everything for clean production runs. |

## Database Integration

The framework queries three external databases via subprocess calls:

1. **Malware Technique Corpus** (`/home/kei/llm_vault/malware_corpus/`): Contains evasion techniques with EDR-specific detection ratings. Queried by `db_query_engine.query_malware_by_edr()`.
2. **PoC Exploit Database** (`poc-chroma/` in the same directory): Contains proof-of-concept exploits indexed by CVE, OS, and exploit type. Queried by `query_poc_by_cve()`.
3. **CTI Knowledge Base** (`/home/kei/llm_vault/hermes_qwen_cti/data/`): Contains threat intelligence findings with severity ratings, threat actors, and indicators. Queried via the RAG pipeline script.

## Configuration Constants

| Constant | Default Value | Location |
|----------|---------------|----------|
| SSH host port | 10022 | `NetworkConfig.port_fwd_ssh` |
| VM credentials | vmuser / vmuser123 | `linux_provisioner.py`, `windows_provisioner.py` |
| Max loop iterations | 5 | LoopController default |
| Min loop iterations | 1 | LoopController default |
| EDR match boost | +3.0 score | `_EDR_MATCH_BOOST` in context_builder.py |
| Severity scores | critical=10, high=7, medium=4, low=2 | `_SEVERITY_SCORES` |
| Exploit type bonus | RCE=+5.0, PRIVESC=+5.0 | `_rank_pocs()` in context_builder.py |

## Dependencies

- Python 3.12+
- pydantic (models and validation)
- aiohttp (async OS image downloading)
- asyncssh (SSH communication with VMs)
- PyYAML (cloud-init YAML generation)
- Jinja2 (prompt template rendering)
- qemu-system-x86_64 (VM virtualisation, KVM acceleration)
- genisoimage (ISO creation for cloud-init/autounattend)
- Ollama or local GGUF models (LLM inference)

## Key Design Decisions

- **Subprocess-based DB queries** instead of direct Python drivers — maintains compatibility with external query scripts and avoids driver dependencies.
- **Inline Jinja2 templates** in `prompt_templates.py` rather than external `.j2` files for portability.
- **Deterministic context scoring** using fixed weight constants (EDR boost, severity scores) so the same input always produces the same ranked output — critical for detecting when retries produce identical contexts.
- **Copy-on-write disk snapshots** mean each VM iteration starts from a clean state without needing full re-provisioning.
- **Context hash comparison** (`ContextBlock.context_hash`) detects when the LLM generates variants that are contextually identical, triggering forced regeneration with new seeds.
