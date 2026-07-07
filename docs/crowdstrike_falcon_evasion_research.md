# CrowdStrike Falcon: Evasion & Kill Techniques

Research compiled for the malware generation framework. Covers both evasion (operating undetected while Falcon runs) and kill (disabling Falcon entirely).

---

## Part 1: Evasion Techniques

### 1.1 Falcon Architecture Overview

Falcon operates at two layers:
- **Kernel driver** (`csagent.sys`): Located at `C:\WINDOWS\system32\drivers\CrowdStrike\csagent.sys`. Registers kernel callbacks for process creation, image loading, registry, and network events. This is the primary telemetry source and cannot be bypassed from userland.
- **User-mode agent** (`CSFalconService`): Handles policy enforcement, cloud communication, and IOA (Indicator of Attack) correlation. Stopping this blocks remote incident response but does NOT stop kernel-level monitoring.

Falcon's detection stack:
1. Static analysis (entropy measurement, PE structure, import table analysis)
2. Userland API hooking (NT function inline hooks with SSN scrambling)
3. Kernel callbacks (process/thread/image/registry notifications)
4. Behavioral IOAs (correlated patterns across events)
5. Cloud-based ML (file reputation, behavioral models)
6. Memory scanning (Intel TDT AMS integration for in-memory artifact detection)

### 1.2 Userland Hook Bypass

**How Falcon hooks work:**
- Falcon replaces `mov eax, <SSN>` in NT functions with a `jmp` to Falcon's DLL
- SSNs (System Service Numbers) are scrambled — functions are reordered so hardcoded SSNs fail
- Hook chain: `jmp` → series of `push rcx` → indirect jump to Falcon DLL → XOR-based obfuscation → loop adding `0x45` per pushed register → final jump to `r10 + 0x28`

**Bypass: Indirect Syscalls**
- Skip hooked ntdll stubs entirely; execute `syscall` instruction from a legitimate ntdll code region
- SysWhispers3-generated code is detected by Falcon — use custom implementations
- Retrieve SSNs dynamically: parse ntdll export table, sort by RVA to recover original SSN order despite scrambling

**Bypass: In-Memory Unhooking Without VirtualProtect**
- Falcon's hook chain ends at a writable heap address
- Calculate the final heap target using the same XOR + loop logic Falcon uses
- Overwrite that heap address with the relocated clean syscall stub address
- No `VirtualProtect`/`NtAllocateVirtualMemory` calls needed (both are hooked)
- Implementation: `FindHook()` → `FindRelocatedStub()` → `PatchHeapAddr()`

**Bypass: Fresh NTDLL Copy**
- Map a second copy of ntdll.dll from disk into the process
- Copy the clean `.text` section over the hooked one
- Falcon detects some variants of this — use `NtCreateSection` + `NtMapViewOfSection` with SEC_IMAGE

**Important caveat:** Modern Falcon versions (2024+) are moving away from userland hooking toward pure kernel callbacks. Userland bypass alone is increasingly insufficient.

### 1.3 Entropy-Based Evasion

Falcon measures entropy to flag encrypted/compressed payloads during static analysis.

**Technique: Embed low-entropy data**
- Append ~7,500 English dictionary words as a string array in the binary
- Compression ratio changes from 37.8% → 98.9% (appears non-random)
- Alternative: concatenate a large image file onto the payload post-compilation
- Use natural-language variable/function names instead of random identifiers

### 1.4 Sleep Obfuscation (Ekko/Zilean)

Encrypts beacon memory during sleep to evade periodic memory scans.

**Ekko implementation (ROP chain via timer queues):**
1. `CreateTimerQueue()` + 9 `CreateTimerQueueTimer()` callbacks at 100ms intervals
2. Callback sequence:
   - `VirtualProtect()` → PAGE_READWRITE
   - `SystemFunction032()` → RC4 encrypt payload (16-byte key)
   - `GetThreadContext()` → backup main thread context
   - `SetThreadContext()` → spoof call stack
   - `Sleep()` → actual sleep period (use Sleep, not WaitForSingleObject to avoid detection)
   - `SystemFunction032()` → RC4 decrypt
   - `SetThreadContext()` → restore original context
   - `VirtualProtect()` → PAGE_EXECUTE_READ
   - `SetEvent()` → resume main thread

**Key APIs:** `SystemFunction032` (cryptsp.dll, undocumented RC4), `NtContinue`, `RtlCaptureContext`

**Anti-detection:** Replace `WaitForSingleObject()` with `Sleep()` to change thread wait state from `Wait:UserRequest` to `Wait:DelayExecution`, defeating Hunt-Sleeping-Beacons scanners.

### 1.5 Process-Level Evasion

**Embedded VM technique (confirmed bypass):**
- Run QEMU emulating Tinycore Linux inside the target — no admin privileges needed
- The VM has no Falcon sensor, creating an unmonitored compute environment on the LAN
- Execute attacks from inside the VM; Falcon has zero visibility
- "It worked beautifully" — most complete bypass documented

**Network tunneling:**
- SOCKS5 proxy via OpenSSH + NCAT dual connections
- Execute payloads on unmonitored remote machines; only network artifacts visible to Falcon
- Successfully performed Pass-The-Hash undetected

### 1.6 Return Address Spoofing

Falcon inspects call stacks to detect suspicious API call origins. Spoof the return address to point to a legitimate code location (e.g., inside kernel32.dll or ntdll.dll) before making sensitive API calls.

### 1.7 DLL Side-Loading

Use a legitimate signed executable that insecurely loads a DLL:
- **MpCmdRun.exe** (Defender CLI) + fake `MpClient.dll` → Cobalt Strike beacon injection
- **ecls.exe** (ESET scanner) + fake `version.dll` → TCESB payload (CVE-2024-11859)
- The signed parent process inherits trust from Falcon's perspective

---

## Part 2: Kill/Disable Techniques

### 2.1 BYOVD (Bring Your Own Vulnerable Driver)

Load a signed-but-vulnerable kernel driver to gain ring-0 access and terminate Falcon.

**Known vulnerable drivers:**
| Driver | Source | CVE | Capability |
|--------|--------|-----|------------|
| `RTCore64.sys` | MSI Afterburner | CVE-2019-16098 | Arbitrary kernel memory R/W |
| `aswArPot.sys` | Avast Anti-Rootkit | — | Process termination |
| `PROCEXP.SYS` | Process Explorer | — | Used by Backstab/AuKill tools |
| `TrueSight.sys` | Anti-rootkit v2.0.2 | — | 2,500+ variants by RansomHub |
| `Zemana drivers` | Zemana Anti-Malware | — | Used by Terminator tool |
| `PoisonX.sys` | Unknown/0-day (2026) | — | Specifically kills CrowdStrike PPL |

**PoisonX.sys details (2026 0-day):**
- Device: `\\.\{F8284233-48F4-4680-ADDD-F8284233}`
- IOCTL: `0x22E010`
- Accepts PID as null-terminated ASCII string
- Calls `ZwTerminateProcess` from kernel mode, bypassing PPL protection
- 0/71 VirusTotal detections, valid Microsoft Hardware Compatibility signature

**Attack chain:**
1. Drop vulnerable .sys file + loader
2. `sc.exe create` / `sc.exe start` to load driver
3. Send IOCTL with CrowdStrike process PID
4. `ZwTerminateProcess` bypasses PPL (Protected Process Light) from kernel mode

**Falcon defense:** BYOVD protection feature blocks known vulnerable drivers. CrowdStrike detected/blocked 6 simultaneous BYOVD attempts in a Sept 2024 intrusion. However, 0-day signed drivers (like PoisonX) bypass this.

**Tools:**
- **Terminator** (Spyboy): $300-$3000, uses Zemana driver, sold on Russian forums
- **Backstab**: Uses procexp.sys to kill antimalware-protected processes
- **AuKill**: Uses PROCEXP.SYS

### 2.2 ABYSSWORKER EDR-Killer Driver

- File: `smuol.sys`, imitates legitimate CrowdStrike driver name
- Samples found 2024-08 through 2025-02
- Searches and removes ALL registered kernel notification callbacks:
  - `PsSetCreateProcessNotifyRoutine` callbacks
  - `PsSetCreateThreadNotifyRoutine` callbacks
  - `PsSetLoadImageNotifyRoutine` callbacks
  - MiniFilter driver callbacks
  - Optionally removes devices belonging to specific modules

### 2.3 Safe Mode Boot Attack

Most EDR agents (including Falcon) are inactive in Safe Mode.

**Method:**
1. Install malicious service configured to run in Safe Mode
2. Set registry Run key for payload
3. Force reboot into Safe Mode: `bcdedit /set {default} safeboot network`
4. Payload executes without EDR monitoring
5. Reboot back to normal: `bcdedit /deletevalue {default} safeboot`

Used by Snatch and AvosLocker ransomware families.

### 2.4 Registry-Based Disable (from Safe Mode)

Boot into Safe Mode, then disable Falcon services:

```
# Set service start type to DISABLED (4)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSAgent" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSFalconService" /v Start /t REG_DWORD /d 4 /f

# Delete CrowdStrike registry keys
reg delete "HKLM\System\CrowdStrike" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\CSAgent\Sim" /f
```

Reboot normally — Falcon will not start.

### 2.5 Maintenance Token Extraction

Falcon v5.10+ requires a maintenance token for uninstall/tamper operations. The token is machine-specific and generated from the CrowdStrike console.

**Bypass approaches:**
- Boot Safe Mode → services don't load → registry modifications bypass token requirement
- If you have CrowdStrike console access, generate the token directly
- Some environments have Sensor Tamper Protection disabled — check before attempting

### 2.6 Kernel Callback Removal (Driver-Level)

With kernel code execution (via BYOVD or custom driver):
- Enumerate callback arrays: `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `PspLoadImageNotifyRoutine`
- Find entries belonging to `csagent.sys` by checking the callback function's module range
- Zero out or replace the callback entry
- Falcon continues running but receives no telemetry — effectively blind

### 2.7 Channel File Manipulation (July 2024 Outage)

**Root cause:** Channel File 291 defined 21 IPC template parameters, but the Content Interpreter only supplied 20 input values. When a non-wildcard matching criterion was used for the 21st field, an out-of-bounds read crashed `csagent.sys` → BSOD.

**Not exploitable** for privilege escalation or RCE per CrowdStrike's analysis. The OOB read cannot be controlled to achieve arbitrary code execution. Channel files are now validated and protected against external modification — Falcon raises detection alerts on any unauthorized channel file changes.

### 2.8 CrowdStrike Falcon CVEs

| CVE | Year | Type | Impact |
|-----|------|------|--------|
| CVE-2025-42701 | 2025 | Race condition | Arbitrary file deletion |
| CVE-2025-42706 | 2025 | Logic error | Arbitrary file deletion |
| (unnamed) | 2023 | Logic flaw | Suspend Falcon processes (patched) |

CVE-2025-42701 and CVE-2025-42706 affect Falcon Sensor for Windows v7.28 and earlier. Both allow attackers with existing code execution to delete arbitrary files, potentially destabilizing the sensor. Fixed in hotfixes for v7.24-7.28.

---

## Part 3: Implementation Priority for Framework

### Tier 1 — Most actionable for chunk templates

1. **Entropy padding** — embed dictionary strings to lower payload entropy (simple, high ROI)
2. **Indirect syscalls with custom SSN resolution** — parse ntdll exports, sort by RVA to defeat SSN scrambling
3. **Sleep obfuscation (Ekko)** — encrypt memory during sleep with RC4 via `SystemFunction032`
4. **Return address spoofing** — spoof call stack before sensitive API calls
5. **DLL side-loading** — use trusted signed executable as loader

### Tier 2 — Requires more infrastructure

6. **In-memory unhooking via heap patching** — reverse Falcon's XOR chain, patch writable heap
7. **BYOVD for kill** — requires dropping and loading a vulnerable driver (noisy, but effective)
8. **Kernel callback removal** — requires kernel execution first

### Tier 3 — Operational techniques (not code-level)

9. **Embedded QEMU VM** — unmonitored compute on the LAN
10. **Safe Mode boot** — disable Falcon via registry, reboot
11. **Network tunneling** — SOCKS5 proxy to execute off-endpoint
