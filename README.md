# Malware Generation Framework

A modular pipeline that takes a target environment specification and produces tailored malware source code, then optionally verifies it inside an ephemeral QEMU VM and retries until the binary evades EDR/AV detection or max iterations are reached.

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────┐
│                       CLI Entry Point                         │
│  python -m malware_gen_framework <command> --spec target.yaml │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 0: Parse & Validate Target Spec                        │
│  spec_parser.py + target_spec.py                              │
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
│  generation_engine.py                                         │
│  Context + prompt templates → malware source code             │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 3: VM Provisioning (run/verify only)                   │
│  provision_engine.py + linux_provisioner.py +                 │
│  windows_provisioner.py + image_sources.py                    │
│  QEMU VM with COW disk, cloud-init/autounattend, SSH bridge   │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 4: Verification                                        │
│  verifier.py                                                  │
│  Compile + execute on VM → query EDR logs → behaviour checks  │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 5: Retry Loop (run/verify only)                        │
│  loop_controller.py                                           │
│  Classify failure → regenerate variant → retry until clean    │
└───────────────────────────────────────────────────────────────┘
```

## Usage

### CLI Subcommands

| Command | Phases | Description |
|---------|--------|-------------|
| `generate` | 0–2 | Generate malware source code from a spec. No VM required. |
| `verify` | 0, 3–5 | Test an existing source file against a freshly provisioned VM. |
| `run` | 0–5 | Full pipeline: generate → provision VM → verify → retry loop. |
| `analyze` | 0–1 | Query DBs and display ranked context without generating code. |

```bash
# Generate only (fastest — no VM, no EDR check)
python -m malware_gen_framework generate --spec target.yaml --output ./results

# Full end-to-end pipeline with retry loop
python -m malware_gen_framework run \
    --spec target.yaml \
    --output ./results \
    --max-iters 5 \
    --loop

# Test an already-generated source file in a VM
python -m malware_gen_framework verify \
    --spec target.yaml \
    --source ./results/malware_source.c \
    --os linux \
    --loop

# Inspect what the LLM would be given without generating
python -m malware_gen_framework analyze --spec target.yaml
```

### Programmatic API

```python
import asyncio
from malware_gen_framework.pipeline import MalwarePipeline

async def main():
    pipeline = MalwarePipeline(
        generate=True,
        provision_vm=True,
        verify=True,
        retry_loop=True,
        max_iterations=5,
    )
    result = await pipeline.run(spec_path="target.yaml", output_dir="./results")
    print(result.print_summary())

asyncio.run(main())
```

## Target Specification

Every phase consumes a `TargetEnvironmentSpec` (defined in `target_spec.py`). Supply it as a YAML or JSON file.

```yaml
os_platform: linux          # "linux" or "windows"
os_version: ubuntu-24.04    # ubuntu-24.04 | ubuntu-22.04 | debian-bookworm
                            # windows-11 | windows-10

# Freeform description of malware behaviour — the LLM reads this
# and decides payload format, runtime actions, and which DB results matter.
malware_type: info stealer  # e.g. "ransomware", "backdoor", "keylogger"

edrs:                       # EDR products installed on the target
  - crowdstrike
  - sentinel_one
antivirus: null
patch_level: "latest"

installed_compilers:        # available build tools on the target
  - gcc
  - mingw-w64
common_tools:
  - python3

domain_joined: false
admin_rights: true

sandbox_detectors:          # VM/sandbox checks present in the environment
  - vmware
custom_gates:               # freeform evasion requirements injected into the prompt
  - no console window
  - sleep before main
```

The parser (`spec_parser.py`) auto-completes missing fields: if `os_platform` is omitted it is inferred from `os_version` (e.g. `ubuntu-*` → `linux`), EDR names are normalised to lowercase snake_case, and compiler lists default to `["gcc", "python3"]` on Linux or `["gcc", "mingw-w64", "python3"]` on Windows.

## Phase Details

### Phase 0 — Spec Parsing (`spec_parser.py`, `target_spec.py`)

Reads the YAML/JSON file into a validated Pydantic `TargetEnvironmentSpec`. Fills in gaps and normalises all string fields. The resulting object is passed unchanged through every subsequent phase.

### Phase 1 — Database Query & Context Assembly

#### `db_query_engine.py`
Calls three external query scripts via subprocess and parses their JSON output:

| Script | Database location | Returns |
|--------|------------------|---------|
| `query_malware.py` | `/home/kei/llm_vault/malware_corpus/` | `MalwareTechnique` objects — evasion techniques with per-EDR detection ratings |
| `query_poc.py` | `/home/kei/llm_vault/malware_corpus/` | `PoC` objects — CVE exploits indexed by OS, severity, and type |
| `query_rag.py` | `/home/kei/llm_vault/hermes_qwen_cti/` | `CTIFinding` objects — threat intelligence with severity and related CVEs |

All three are queried with `"{os_platform} {os_version}"` as the search term via `query_all()`.

#### `context_builder.py`
Deduplicates and ranks the raw results:
- **Techniques** — scored by detection rating (lower = easier to evade), +3.0 boost if the technique was tested against a target EDR, +2.0 for high-value categories (evasion, persistence, lateral movement).
- **PoCs** — scored by severity (critical=10, high=7, medium=4, low=2) plus +5.0 for RCE or PRIVESC exploit types.
- Produces a `ContextBlock` containing ranked lists and a `context_hash` (SHA-256 of ranked IDs) used later for stuck-detection in the retry loop.

#### `evasion_selector.py` / `exploit_selector.py`
Additional per-EDR and per-OS filtering on top of the main query. Results are merged back into the context for prompt injection.

#### `prompt_templates.py`
Jinja2 template manager. The `GENERATE_MALWARE_TEMPLATE` renders the ranked techniques, PoCs, CTI findings, compiler instructions, and malware type description into structured markdown that forms the LLM prompt.

### Phase 2 — LLM Generation (`generation_engine.py`)

`GenerationEngine.generate()` runs six steps:

1. Query all three databases (`DBQueryEngine.query_all`)
2. Build ranked context (`ContextBuilder.build_context`)
3. Select evasions + exploits per EDR / OS version
4. If compilers are listed in the spec, call the LLM with a short compiler-focused sub-prompt to generate build instructions
5. Render the full generation prompt via Jinja2
6. Call the LLM and return the source code

**LLM client (`SubprocessLLMClient`):**
- **Primary:** local GGUF model via `llama-cli` — looks for `.gguf` files in `~/.llm_vault/models/`
- **Fallback:** LM Studio OpenAI-compatible HTTP API at `http://localhost:1234` (default model: `qwen3.6-35b-a3b-uncensored-hauhaucs-aggressiv`)
- Retries up to 3 times with a doubling token limit if the response appears truncated
- Validates output completeness by checking balanced braces, parentheses, and brackets

The LLM is instructed to return raw source code only (no markdown wrappers), with build instructions as inline comments at the top. The source is written to `output_dir/malware_source.c`.

**Variant generation (`generate_variant`):** Used by the retry loop. Calls `generate()` for a full re-generation, then appends a variant seed comment to the output and re-calls the LLM, producing a different code path.

### Phase 3 — VM Provisioning (`provision_engine.py`)

Only runs for `run` and `verify`. If no `VMProvisionConfig` is supplied, the pipeline auto-builds one from the target spec (e.g. `os_version: ubuntu-24.04` → `TargetOS.UBUNTU_24_04`).

`ProvisionEngine.provision()` runs six steps:

1. **`compute_paths()`** — resolves paths for base image, COW snapshot, and QMP socket under `/tmp/vm_provision/`
2. **Download base image** (`image_sources.py`):
   - Linux: Ubuntu cloud images (pre-built `.img`) from Canonical CDN
   - Windows: tries `quickget` CLI first, falls back to downloading the Microsoft evaluation ISO + VirtIO driver ISO
3. **COW snapshot** — `qemu-img create -f qcow2 -b <base_img>` so each run starts from a clean state without re-downloading
4. **Auto-provisioning ISO**:
   - Linux: cloud-init NoCloud ISO (`linux_provisioner.py`) — sets up `vmuser`, enables SSH, allows passwordless sudo
   - Windows: autounattend.xml ISO (`windows_provisioner.py`) — handles disk partitioning, OOBE bypass, TPM bypass, user creation, OpenSSH Server installation
5. **Start QEMU** — `qemu-system-x86_64` with KVM, UEFI (OVMF), virtio networking, SSH forwarded from host port 10022 → VM port 22
6. **Wait for SSH** — polls until port 10022 accepts connections (up to 5 minutes), then returns a live `VMInstance`

VM credentials: `vmuser` / `vmuser123`, SSH port 10022.

### Phase 4 — Verification (`verifier.py`)

`Verifier.verify()` runs inside the provisioned VM via `asyncssh`:

1. Write source to `/tmp/malware_src.c` via SSH heredoc
2. Compile — uses compiler instructions from Phase 2, or falls back to:
   - Linux: `gcc -O2 -Wall /tmp/malware_src.c -o /tmp/malware_bin`
   - Windows: `x86_64-w64-mingw32-gcc -O2 -s /tmp/malware_src.c -o /tmp/malware_bin -lws2_32 -ladvapi32`
3. Execute the binary in background, capture exit code
4. Query EDR logs: `/var/log/syslog` and `/var/log/audit/audit.log` on Linux; `Get-WinEvent` on Windows
5. Behaviour checks: binary executability, network connections (`ss`), window creation (`xwininfo` on Linux)
6. Sandbox check: flags the VM if CPU count < 2 or RAM < 1000 MB

Returns a `VerificationResult` with:
- `detection_score`: `NONE` / `LOW` / `MEDIUM` / `HIGH`
- `alerts`: list of `AlertRecord` objects (EDR name, type, severity, process path)
- `behaviour_checks`: dict of check results
- `compilation_output`, `execution_output`, `execution_exit_code`

### Phase 5 — Retry Loop (`loop_controller.py`)

`LoopController.run_loop()` manages the verify → regenerate cycle:

- Uses the initially generated source as iteration 1
- On `detection_score == "none"`: stops immediately (success)
- On any other result: classifies the failure mode:
  - `COMPILATION_FAILED` — source didn't compile
  - `EXECUTION_CRASHED` — binary exited non-zero
  - `DETECTED` — EDR fired (high score or >3 alerts)
  - `UNKNOWN` — something else went wrong
- Applies exponential backoff between attempts: `1.0s × 2^(iteration−1)`, capped at 30s
- Calls `generate_variant()` with seed `"iter_N"` to get a different code path
- Stuck detection: if `context_hash` is identical for 2 consecutive iterations, logs a warning
- Continues until undetected or `max_iterations` reached

Returns `LoopResult` with the full iteration history and the best result across all attempts.

## Output Files

Written to `--output` dir (default: `./results/`):

| File | Contents |
|------|----------|
| `malware_source.c` | Final generated malware source code |
| `pipeline_report.txt` | Target summary, generation stats, VM status, loop iteration history |

## Module Reference

| File | Phase | Purpose |
|------|-------|---------|
| `target_spec.py` | 0 | Pydantic model for target environment. Defines `OSPlatform`, `LinuxDistro`, `WindowsVersion` enums and field validators. |
| `spec_parser.py` | 0 | Loads YAML/JSON into `TargetEnvironmentSpec`. Handles auto-completion and normalisation. |
| `db_models.py` | 1 | Dataclasses: `MalwareTechnique`, `PoC`, `CTIFinding`, `QueryResult`. |
| `db_query_engine.py` | 1 | Subprocess wrappers for the three external query scripts. |
| `context_builder.py` | 1 | Deduplicates, scores, and ranks query results into a `ContextBlock`. |
| `evasion_selector.py` | 1 | Per-EDR technique filtering and deduplication. |
| `exploit_selector.py` | 1 | Per-OS PoC filtering, scoring, and adaptation notes. |
| `compiler_selector.py` | 1 | Compiler flag detection from source headers (available but not called in the main pipeline — compiler instructions are generated via LLM sub-prompt instead). |
| `prompt_templates.py` | 2 | Jinja2 templates: `GENERATE_MALWARE_TEMPLATE` and `BUILD_COMPILER_TEMPLATE`. |
| `generation_engine.py` | 2 | Core generation orchestrator. `SubprocessLLMClient` for llama-cli / LM Studio. |
| `image_sources.py` | 3 | OS image download: Ubuntu cloud images, Windows eval ISO + VirtIO drivers. |
| `linux_provisioner.py` | 3 | cloud-init NoCloud ISO generation. |
| `windows_provisioner.py` | 3 | autounattend.xml ISO generation. |
| `config_models.py` | 3 | `TargetOS` enum, `VMProvisionConfig`, `VMResourceSpec`, `NetworkConfig`. |
| `provision_engine.py` | 3 | QEMU lifecycle: `QEMUProcess`, `VMInstance`, `ProvisionEngine`. |
| `verifier.py` | 4 | Compile → execute → EDR check → behaviour check inside the VM. |
| `loop_controller.py` | 5 | Retry loop with failure classification, exponential backoff, stuck detection. |
| `pipeline.py` | all | `MalwarePipeline` — chains all phases. `PipelineResult` output container. |
| `cli.py` | all | `argparse` CLI with `generate`, `verify`, `run`, `analyze` subcommands. |
| `debug_logger.py` | all | ANSI-coloured step-by-step trace logger, activated by `--debug`. |

## Configuration Constants

| Constant | Default | Location |
|----------|---------|----------|
| VM SSH host port | 10022 | `NetworkConfig.port_fwd_ssh` |
| VM CPU cores | 4 | `VMResourceSpec.CPU_cores` |
| VM RAM | 8 GB | `VMResourceSpec.RAM_GB` |
| VM credentials | vmuser / vmuser123 | `provision_engine.py` |
| Max loop iterations | 5 | `LoopController` default |
| Backoff base | 1.0s | `LoopController.backoff_base` |
| Backoff cap | 30s | `LoopController.backoff_max` |
| Stuck threshold | 2 iterations | `LoopController.stick_threshold` |
| EDR match score boost | +3.0 | `ContextBuilder._EDR_MATCH_BOOST` |
| LLM HTTP endpoint | http://localhost:1234 | `SubprocessLLMClient.llm_api_url` |
| LLM model name | qwen3.6-35b-a3b-uncensored-hauhaucs-aggressiv | `SubprocessLLMClient.llm_model_name` |

## Dependencies

- **Python 3.12+**
- `pydantic` — spec model and validation
- `aiohttp` — async OS image downloading
- `asyncssh` — SSH communication with the VM
- `PyYAML` — cloud-init YAML generation and spec file parsing
- `Jinja2` — LLM prompt template rendering
- `qemu-system-x86_64` + KVM — VM virtualisation
- `genisoimage` — ISO creation for cloud-init / autounattend
- `llama-cli` (optional) — local GGUF model inference
- LM Studio (optional, fallback) — OpenAI-compatible HTTP inference at `localhost:1234`

## Key Design Decisions

- **Subprocess DB queries** — the three database scripts are external tools with their own dependencies; calling them via subprocess avoids importing those dependencies into the framework.
- **COW disk snapshots** — each VM starts from a clean image snapshot without re-downloading or re-installing, keeping provisioning fast on retries.
- **Context hash for stuck detection** — `ContextBlock.context_hash` is a SHA-256 of all ranked technique/PoC IDs and scores. If the hash is identical across consecutive retry iterations, the DB results haven't changed and regenerating with the same context is unlikely to produce a meaningfully different binary.
- **Inline Jinja2 templates** — kept in `prompt_templates.py` rather than external `.j2` files so the package is self-contained with no template path resolution.
- **LLM completeness validation** — the client checks balanced braces, parentheses, and brackets before accepting output, retrying with a doubled token limit if the response appears truncated mid-block.
