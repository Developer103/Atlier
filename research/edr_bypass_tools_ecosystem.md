# EDR Bypass Tools & C2 Framework Ecosystem (2026)

Survey of open-source and commercial offensive tools for EDR bypass, with current detection status and relevance to our chunk framework.

---

## Table of Contents

1. [Syscall/Hook Bypass Tools](#1-syscallhook-bypass)
2. [Kernel-Level EDR Manipulation](#2-kernel-level-tools)
3. [PPL/Protected Process Tools](#3-ppl-tools)
4. [Telemetry Analysis & Silencing](#4-telemetry-tools)
5. [C2 Frameworks & Their Evasion](#5-c2-frameworks)
6. [EDR Testing & Coverage Tools](#6-testing-tools)
7. [Detection Status Matrix](#7-detection-matrix)

---

## 1. Syscall/Hook Bypass

### SysWhispers (1, 2, 3)
- **SysWhispers1** (2019): Generated syscall stubs with hardcoded SSNs per Windows version. Outdated.
- **SysWhispers2** (2021): Runtime SSN resolution via sorting Zw* export addresses. Still usable but detected by most EDRs via signature.
- **SysWhispers3** (2022-2023): Added indirect syscall support (jmp to syscall;ret in ntdll). Egg-hunter variant. Current best-in-class for syscall tooling.
- **Detection**: Signatures for all three exist in most EDRs. The TECHNIQUE works; the TOOL's code patterns are detected. Must be reimplemented, not copy-pasted.

### HellsGate
- Reads SSN from the in-memory (hooked) ntdll by parsing the mov eax instruction bytes
- Works even when ntdll is hooked (hooks typically JMP before the mov eax)
- **Limitation**: Fails if the hook overwrites the mov eax bytes. Most modern hooks use a 5-byte JMP that starts BEFORE the mov r10,rcx instruction, leaving the SSN bytes intact.

### HalosGate
- Extension of HellsGate: if the target function's SSN bytes are corrupted, read the SSN from a neighboring (unhooked) function and calculate the target SSN by offset
- Ntdll SSNs are sequential by function sort order — if NtAllocateVirtualMemory is SSN 24 and NtClose is SSN 15, and you know NtClose's SSN, you can calculate any other SSN.

### TartarusGate
- Further extension: handles EDR hooks that modify more bytes
- Uses exception-based detection of hooks (trigger access violation on modified bytes)
- Combines with indirect syscalls

### InlineWhispers (1, 2)
- Converts SysWhispers output to inline assembly for BOF (Beacon Object Files)
- Specific to Cobalt Strike. Not directly useful for our C framework but the assembly patterns are reusable.

### FreshyCalls / RecycledGate
- Resolve SSNs by reading the `Zw*` export table sort order (SSN = sort position)
- No disk reads needed (unlike reading ntdll from disk)
- Works purely from in-memory ntdll

### Our framework's approach
We implemented our own SSN resolution (`evasion/indirect_syscall.c`) that reads from disk ntdll for cleanliness, combined with gadget-jumping for legitimate return addresses. Not derived from any known tool — no shared signatures.

---

## 2. Kernel-Level Tools

### EDRSandblast
- Open-source tool for disabling EDR from kernel via BYOVD
- Uses vulnerable RTCore64.sys (MSI Afterburner) driver
- Capabilities: remove kernel callbacks, unload minifilters, disable ETW-TI
- **Detection**: Heavily signatured. RTCore64.sys on most blocklists. The CONCEPT works but the specific driver is burned.
- **Lesson**: The technique (BYOVD → callback removal) is valid; need to substitute fresh vulnerable drivers.

### EDRSilencer
- Blocks EDR processes from communicating outbound via WFP (Windows Filtering Platform) rules
- Creates WFP filters that drop all outbound traffic from EDR process
- Effect: EDR runs locally but can't send telemetry to cloud → no cloud detections, delayed SOC visibility
- **Detection**: WFP filter creation triggers some EDRs. The technique itself is sound.

### Backstab
- Uses Process Explorer's signed kernel driver to kill/blind EDR processes
- Process Explorer driver is legitimately signed by Microsoft
- Can: terminate PPL processes, enumerate kernel callbacks
- **Detection**: Process Explorer driver increasingly blocklisted. Variants use other signed debug/diagnostic drivers.

### CallbackHell
- Kernel callback enumeration and removal tool
- Lists all registered Ps*, Ob*, Cm* callbacks with their owning driver
- Can selectively remove specific callbacks (targeted, not carpet-bomb)
- **Detection**: Requires loading a driver (detectable), but the removal is clean.

### Terminator (SpyBoy)
- BYOVD tool using Zemana Antilogger driver
- Terminates any process including PPL/EDR via kernel handle
- Simple but effective — just kills the EDR process
- **Detection**: Zemana driver increasingly blocked. Tool itself is heavily signatured.

---

## 3. PPL Tools

### PPLdump (2021)
- Dumps memory of PPL processes by exploiting the CSRSS (PPL-WinTcb) process
- Injects code into CSRSS to read PPL process memory
- **Status (2026)**: Patched in Windows 11 22H2+. No longer works on current systems.

### PPLFault (2024)
- Gabriel Landau (Elastic). Exploits TOCTOU in Windows code integrity
- Races the page fault handler during PPL DLL loading
- **Status**: Specific bug patched in 23H2. Concept (TOCTOU in PPL loading) may have variants.

### PPLmedic (2024)
- Uses WER (Windows Error Reporting) plugin mechanism
- WER loads crash analysis DLLs — these run in WER's PPL-WinTcb context
- Crafting a fake crash triggers WER to load arbitrary DLLs as PPL
- **Status**: Partially mitigated but conceptual attack surface (WER plugin loading) persists.

### Practical relevance
PPL tools are useful for attacking EDR agents that run as PPL. Our framework doesn't need PPL bypass for basic operation — it's relevant only if we need to inject into or disable the EDR process directly (Layer 4 evasion).

---

## 4. Telemetry Tools

### TelemetrySourcerer
- Open-source tool that shows exactly what ETW providers are enabled and which processes consume them
- Reveals what the EDR is actually monitoring via ETW
- Essential for gap analysis: "The EDR subscribes to Microsoft-Windows-Kernel-Process but NOT Microsoft-Windows-DNS-Client"
- Not an attack tool — a reconnaissance tool for understanding EDR coverage

### SilkETW
- ETW consumer/logger written in C#
- Can subscribe to any ETW provider and log events
- Useful for: understanding what events your malware generates, testing whether ETW patches work
- Also useful for monitoring EDR activity (ironic — ETW monitoring the monitor)

### Sealighter
- Kernel-mode ETW consumer that logs ETW-TI events
- Shows exactly what kernel-level telemetry is generated by specific actions
- Critical for understanding: "If I call NtWriteVirtualMemory cross-process, EXACTLY which ETW-TI event fires?"

### Phant0m
- ETW-based detection blindness tool
- Enumerates all ETW consumer threads in EDR processes and suspends them
- Effect: ETW events are generated but never processed by the EDR
- **Detection**: Thread suspension of EDR threads is itself detectable. Works better against less hardened EDRs.

### Our framework relevance
These tools are for RESEARCH, not integration. Use them in the testing lab to understand what our payloads generate in terms of telemetry, then design evasion to suppress those specific events.

---

## 5. C2 Frameworks

### Cobalt Strike (Commercial)
**Architecture**: Beacon (implant) → Team Server → Operator
**Evasion features (2024-2026):**
- Artifact Kit: User-customizable payload generation templates
- UDRL (User Defined Reflective Loader): Custom in-memory loading
- Sleep Mask: Memory encryption during sleep (similar to our Ekko implementation)
- Malleable C2: Fully customizable network traffic profiles (mimic any HTTP app)
- BOFs (Beacon Object Files): Run code in Beacon's process without new threads
**Detection status**: Heavily signatured. Default Beacon payload detected by all EDRs. Requires heavy customization (custom UDRL + sleep mask + fresh malleable profile) to evade current EDRs. Even then, behavioral detection catches many operations.

### Brute Ratel C4 (Commercial)
**Architecture**: Badger (implant) → C4 Server → Operator
**Why it was notable**: Released as "undetectable" in 2022. Used indirect syscalls, ETW blinding, AMSI bypass natively.
**Current status (2026)**: Heavily signatured after source code leak (2022). Cracked versions widespread. Every major EDR detects default Badger payloads.
**Lesson**: Even sophisticated C2 gets signatured within 6-12 months of widespread adoption.

### Sliver (Open Source)
**Architecture**: Implant → Sliver Server (Go) → Operator
**Features**: Cross-platform (Windows, Linux, macOS), WireGuard-based C2, process migration, screenshot, file ops
**Evasion**: Basic compared to commercial tools. No sleep encryption, no indirect syscalls in default builds.
**Detection status**: Moderate detection rate. Less signatured than Cobalt Strike due to smaller user base.

### Havoc C2 (Open Source)
**Architecture**: Demon (implant) → Teamserver → Client (Qt GUI)
**Features**: Sleep obfuscation (Ekko-based), indirect syscalls, ETW/AMSI patching, token manipulation
**Detection status**: Growing signature coverage. Still less detected than Cobalt Strike.

### Mythic (Open Source Framework)
**Architecture**: Framework for building C2 — agents are modular
**Notable agents**: Apollo (C#), Athena (C#), Poseidon (Go), Medusa (Python)
**Relevance**: More of a development framework than a ready-to-deploy C2

### Our framework vs C2 frameworks
Our framework generates standalone payloads — we don't run a C2 server with post-exploit capabilities. The comparison:
- C2 frameworks: complex, feature-rich, but large attack surface and heavy signatures
- Our framework: simple, single-purpose payloads, smaller footprint, harder to signature (unique per-build)
- Key advantage: every recipe produces unique code. C2 frameworks produce the same implant binary.

---

## 6. Testing Tools

### Atomic Red Team
- Library of small, focused test cases mapped to MITRE ATT&CK techniques
- Each "atomic" tests one specific technique
- Useful for: "Does EDR X detect T1055.001 (DLL injection)? Run the atomic, check."
- **Coverage**: ~650 techniques across Windows, Linux, macOS

### MITRE ATT&CK Evaluations
- Annual EDR evaluations by MITRE against real APT toolkits
- Published results show per-step detection for each EDR
- **Useful for**: Understanding which EDRs are strongest against which technique categories
- **Limitation**: Vendors tune specifically for MITRE eval — real-world performance may differ

### Caldera (MITRE)
- Automated adversary emulation platform
- Chains multiple ATT&CK techniques into campaigns
- Useful for: testing EDR coverage of multi-step attacks

### Detection Lab projects
Several open-source projects for building EDR testing labs:
- **DetectionLab**: Automated setup of AD domain with Splunk, osquery, Sysmon
- **BlueTeam.Lab**: Azure-based lab with Sentinel, MDE, and attack tools
- **Our QEMU VM**: Windows 11 with Defender + Elastic Defend for real-time testing

---

## 7. Detection Matrix

Current detection status of techniques/tools against major EDRs (approximate, as of mid-2026):

| Tool/Technique | Defender | CrowdStrike | SentinelOne | Elastic |
|----------------|----------|-------------|-------------|---------|
| Cobalt Strike (default) | DETECTED | DETECTED | DETECTED | DETECTED |
| Cobalt Strike (customized) | 50/50 | DETECTED | 50/50 | 50/50 |
| Brute Ratel (default) | DETECTED | DETECTED | DETECTED | DETECTED |
| Sliver (default) | DETECTED | DETECTED | 50/50 | 50/50 |
| Havoc (default) | 50/50 | DETECTED | 50/50 | NOT DET |
| SysWhispers3 (tool signature) | DETECTED | DETECTED | DETECTED | DETECTED |
| Indirect syscalls (custom impl) | NOT DET | NOT DET | NOT DET | NOT DET |
| EDRSandblast (RTCore64) | DETECTED | DETECTED | DETECTED | DETECTED |
| Sleep encryption (custom) | NOT DET | NOT DET | NOT DET | NOT DET |
| NTDLL unhooking (custom) | NOT DET | NOT DET | NOT DET | NOT DET |
| ETW patch (custom) | NOT DET | 50/50 | NOT DET | NOT DET |
| Our framework recipes | NOT DET | UNTESTED | UNTESTED | NOT DET |

Key insight: **custom implementations of known techniques** are far harder to detect than **known tools implementing those techniques**. The technique is public, but the specific code pattern is unique.

This is our framework's primary advantage: every build produces unique code through recipe combination + per-build XOR key + chunk ordering. No two binaries share signatures.
