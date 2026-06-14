# Test Steps + Next Steps

## Test Steps (Execute in Order)

### Step 1 — Check QEMU/KVM Availability
```
qemu-system-x86_64 --version
kvm-ok               # or: lsmod | grep kvm
```

### Step 2 — Compile Check
```
cd /home/kei/llm_vault/malware_gen_framework
python3 -m py_compile config_models.py image_sources.py linux_provisioner.py windows_provisioner.py provision_engine.py __init__.py
```

### Step 3 — Import Check
```
cd /home/kei/llm_vault/malware_gen_framework
python3 -c "from malware_gen_framework import ProvisionEngine, VMProvisionConfig, TargetOS; print('imports ok')"
```

### Step 4 — Test Config Models
```python
python3 -c "
from malware_gen_framework.config_models import VMProvisionConfig, TargetOS
cfg = VMProvisionConfig(
    os_type=TargetOS.LINUX,
    os_version='24.04',
    cpu=2,
    ram_gb=4,
    vm_name='test-vm'
)
print(cfg.vm_name, cfg.base_img, cfg.cow_img)
"
```

### Step 5 — Test Provisioners (Unit)
```
mkdir -p /tmp/test-iso-test /tmp/test-iso-test-win
```
```python
python3 -c "
from malware_gen_framework.linux_provisioner import CloudInitProvisioner
p = CloudInitProvisioner()
iso_path = p.create_nocloud_iso(target_dir='/tmp/test-iso-test')
print('linux iso created:', iso_path)

from malware_gen_framework.windows_provisioner import WindowsProvisioner
wp = WindowsProvisioner()
iso_path = wp.create_unattended_iso(target_dir='/tmp/test-iso-test-win')
print('windows iso created:', iso_path)
"
```

### Step 6 — Dry-Run ProvisionEngine Command Builder
```python
python3 -c "
from malware_gen_framework.provision_engine import ProvisionEngine, TargetOS
from malware_gen_framework.config_models import VMProvisionConfig
cfg = VMProvisionConfig(os_type=TargetOS.LINUX, os_version='24.04', cpu=2, ram_gb=4, vm_name='dryrun')
engine = ProvisionEngine(cfg)
print('VM name:', engine.vm_name)
print('Image:', engine.image_path)
print('QMP socket:', engine.qmp_socket_path)
print('SSH port:', engine.ssh_port)
"
```

---

## What Is Built (Phase 3)

| Module | Status | Description |
|---|---|---|
| `config_models.py` | DONE | Pydantic models for OS, resources, network, EDR, provision config |
| `image_sources.py` | DONE | Async cloud image downloader (Ubuntu + Windows via quickget/aiohttp) |
| `linux_provisioner.py` | DONE | cloud-init user-data YAML + NoCloud ISO generation |
| `windows_provisioner.py` | DONE | autounattend.xml generation + virtual floppy ISO |
| `provision_engine.py` | DONE | QEMU lifecycle, QMP monitoring, COW snapshots, SSH bridge |
| `__init__.py` | DONE | Package exports |

---

## What Is Left To Build (If Tests Pass)

### Phase 1 — DB Integration Layer (~5 files)
1. **`db_query_engine.py`**
   - Wrapper that queries all 3 databases from within the framework
   - Methods: `query_malware_by_edr()`, `query_poc_by_cve()`, `query_findings_recent()`
   - Uses subprocess to call existing query scripts (`/home/kei/llm_vault/malware_corpus/query_malware.py`, `query_poc.py`, hermes_qwen_cti `query_rag.py`)
2. **`db_models.py`**
   - Dataclasses for structured query results (technique, poc, finding schemas)
   - Validation and parsing of subprocess output
3. **`context_builder.py`**
   - Takes query results + target spec → constructs prompt context block
   - Merge, rank, and deduplicate results from all 3 DBs
4. **`prompt_templates.py`**
   - Jinja2 or string templates for generating the LLM prompt
   - Injection of target env, techniques, CVEs, findings

### Phase 2 — Target Environment Spec Parser (~2 files)
5. **`target_spec.py`**
   - `TargetEnvironmentSpec` dataclass / Pydantic model (complete target spec schema)
   - Fields: os_type, os_version, edrs, antivirus, patch_level, installed_compilers, common_tools, network_config, domain_joined, admin_rights, sandbox_detectors, custom_gates
6. **`spec_parser.py`**
   - YAML/JSON/CLI input parser
   - Validation + auto-completion of missing fields

### Phase 4 — Malware Generation Engine (~3 files)
7. **`generation_engine.py`**
   - Core class that takes enriched context + target spec → generates malware
   - Manages LLM prompt construction via prompt_templates
   - Calls local LLM (llama.cpp / ollama) with context injection
8. **`evasion_selector.py`**
   - Sub-engine that queries malware_corpus for EDR-specific techniques
   - Ranked technique selection based on target EDR list
9. **`exploit_selector.py`**
   - Sub-engine that queries PoC DB for target CVEs
   - Highest-quality PoC selection and adaptation guidance
10. **`compiler_selector.py`**
    - Validates installed_compilers from target spec
    - Generates compiler-specific build instructions

### Phase 5 — Verification Pipeline (~2 files)
11. **`verifier.py`**
    - Runs generated malware in the provisioned VM via SSH bridge
    - Compiles, executes, queries EDR/AV for alerts
    - Returns VerificationResult (detection_score, alerts, behavior_check)
12. **`loop_controller.py`**
    - Phase 5b retry loop with backoff, failure classification, stuck detection
    - `max_iterations`, `min_iterations`, `exhaustive_mode`, `stick_threshold`
    - Iteration history tracking and context hash comparison

### Phase 6 — CLI and Pipeline Integration (~2 files)
13. **`cli.py`** (or `__main__.py`)
    - CLI with subcommands: `generate`, `verify`, `generate-and-verify`, `analyze`
    - Arguments: `--spec`, `--db-engine`, `--output`, `--variants`, `--max-iters`, `--exhaustive`, `--track-history`
14. **`pipeline.py`**
    - Full end-to-end orchestrator: spec → DB query → generation → VM provision → verify → loop → output

### Testing Infrastructure (1 file)
15. **`tests/test_framework.py`**
    - Unit tests for config, provisioners, parsers
    - Integration test for full pipeline (requires live VM)

---

## Total Remaining Files: ~15

All within `/home/kei/llm_vault/malware_gen_framework/`. No code changes outside this directory.
