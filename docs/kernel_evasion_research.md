# Kernel-Level EDR Evasion: Deep Dive Research

Companion to `crowdstrike_falcon_evasion_research.md`. Focused exclusively on Ring-0 techniques for blinding, disabling, or killing EDR kernel-mode telemetry. This document covers techniques that go beyond userland evasion into the kernel driver layer where CrowdStrike Falcon (csagent.sys) and other EDRs collect their most critical telemetry.

---

## 1. EDR Kernel Architecture — What We're Fighting

Modern EDRs (CrowdStrike, SentinelOne, MDE, Cortex XDR) register into 6 kernel notification families. Understanding exactly what each one monitors is essential to knowing what must be blinded.

### 1.1 Kernel Callback Families

| Callback Registration API | What It Monitors | EDR Use Case |
|---------------------------|------------------|--------------|
| `PsSetCreateProcessNotifyRoutineEx` | Process creation/termination | Parent PID (immune to spoofing), image path, command line, creator thread |
| `PsSetCreateThreadNotifyRoutineEx` | Thread creation/termination | Detects remote thread injection (source PID != target PID) |
| `PsSetLoadImageNotifyRoutine` | DLL/driver/image loading | Catches reflective DLL loading, module stomping, driver loads |
| `ObRegisterCallbacks` | Object handle operations (pre-op) | Strips PROCESS_VM_READ/WRITE/OPERATION from handles to protected processes (lsass, csagent) |
| `CmRegisterCallbackEx` | Registry operations (pre/post) | Monitors persistence keys, HKLM\SYSTEM\CurrentControlSet\Services modifications |
| `FltRegisterFilter` (Minifilter) | File I/O operations | File writes, reads, renames, deletes — detects payload drops, ransomware encryption |

**Key insight**: `PsSetCreateProcessNotifyRoutineEx` provides parent PID that is **immune to PPID spoofing** — the kernel resolves the actual creator, not the spoofed parent. This is why PPID spoofing alone doesn't evade kernel-level detection.

### 1.2 ETW-TI (Threat Intelligence Provider)

The `Microsoft-Windows-Threat-Intelligence` ETW provider (GUID: `f4e1897c-bb5d-5668-f1d8-040f4d8dd344`) is a kernel-mode provider that fires events for security-sensitive operations:

- `NtAllocateVirtualMemory` (cross-process)
- `NtWriteVirtualMemory` (cross-process)
- `NtMapViewOfSection` (injection via sections)
- `NtSetContextThread` / `NtQueueApcThread` (thread hijacking)
- `VirtualProtect` toggling executable permissions

**Critical property**: ETW-TI events fire after kernel operation completion, meaning **usermode ntdll patching is ineffective** against TI provider emission. Only kernel-mode manipulation can silence these events.

**Access control**: Only PPL-Antimalware (`PsProtectedSignerAntimalware`) processes can consume ETW-TI events. The enforcement is in `EtwpCheckNotificationAccess` which checks `EPROCESS->Protection`.

### 1.3 Minifilter Driver Stack

Minifilters register at specific altitudes (numeric priority):
- **320,000–329,999**: Typical EDR altitude range
- **Higher altitude = closer to user**, lower = closer to filesystem
- Pre-operation callbacks: can block/modify I/O before filesystem processes it
- Post-operation callbacks: observational only (after filesystem completion)

CrowdStrike csagent.sys registers as a file system filter driver. It receives notifications on:
- Named pipe creation (lateral movement detection)
- File writes to sensitive paths (payload drops)
- Process image file operations (hollowing, ghosting detection)

---

## 2. BYOVD (Bring Your Own Vulnerable Driver)

The most reliable path to Ring-0 access. Load a legitimately signed but vulnerable kernel driver, exploit it to gain arbitrary kernel read/write, then use that to disable EDR callbacks.

### 2.1 Attack Flow

```
1. Drop vulnerable .sys + loader executable
2. sc create <name> binPath= <path> type= kernel
3. sc start <name>
4. Send crafted IOCTL → driver executes kernel R/W primitive
5. Use R/W to:
   a. Remove kernel callbacks (Section 3)
   b. Modify EPROCESS protection (Section 4)
   c. Terminate protected processes (Section 5)
   d. Disable ETW-TI (Section 6)
```

### 2.2 Driver Arsenal (Current as of 2026)

| Driver | Source | Capability | Windows Version | Notes |
|--------|--------|-----------|-----------------|-------|
| `RTCore64.sys` | MSI Afterburner | Arbitrary kernel R/W via IOCTL | All | CVE-2019-16098, widely blocklisted |
| `dbutil_2_3.sys` | Dell BIOS Update | Arbitrary kernel R/W | Win7+ | Used by RealBlindingEDR |
| `echo_driver.sys` | Unknown | Arbitrary kernel R/W | Win10+ | Used by RealBlindingEDR |
| `wnBio.sys` | Unknown | Arbitrary kernel R/W | Win6.3+ | Used by RealBlindingEDR |
| `PROCEXP.SYS` | SysInternals Process Explorer | Process termination | All | Used by Backstab, AuKill |
| `TrueSight.sys` v2.0.2 | Anti-rootkit | Process termination | All | 2,500+ hash variants, pre-2015 signed |
| `PoisonX.sys` | Unknown 0-day (2026) | Kills CrowdStrike PPL via `ZwTerminateProcess` | All | Valid MS WHQL signature, 0/71 VT |
| Zemana drivers | Zemana Anti-Malware | Process termination | All | Used by Terminator ($300-3000) |
| EnCase forensic driver | Guidance Software | Process termination, revoked cert | All | Used in SonicWall intrusion 2026 |

### 2.3 Evasion of Driver Blocklist

Microsoft's Vulnerable Driver Blocklist (enabled via HVCI/Memory Integrity) blocks known hashes.

**Bypass techniques:**
- **Hash mutation**: Modify non-functional bytes (version info, padding, resources) to change hash while preserving valid Authenticode signature. RansomHub/EDRKillShifter generated 2,500+ TrueSight variants this way.
- **Pre-2015 drivers**: Microsoft blocklist only covers drivers signed after July 2015 by default. Older drivers with valid cross-signatures are not blocklisted.
- **0-day drivers**: Newly discovered vulnerable drivers (like PoisonX) aren't in any blocklist yet.
- **Driver DLL side-loading**: Load the driver from a trusted path or via a trusted loader process.

### 2.4 GentleKiller (2026 State of the Art)

GentleKiller is the most sophisticated EDR-killer suite as of mid-2026, used by the Gentlemen RaaS group:

- **8+ driver variants** abusing different vulnerable drivers
- **Targets 400+ processes** across 48 security vendors (including CrowdStrike, SentinelOne, MDE)
- **Modular architecture**: Combines in-house tools with leaked/adapted tools (HexKiller, ThrottleBlood, HavocKiller)
- **Binary protection**: Enigma/Themida packing, mimics security vendor file metadata
- **Rapid weaponization**: Incorporates new BYOVD PoCs within days of public disclosure
- **478 confirmed victims** across 70+ countries as of June 2026

---

## 3. Kernel Callback Removal (Blinding)

Once Ring-0 access is achieved (via BYOVD), the most effective approach is to **remove EDR callbacks** rather than killing the process. The EDR continues running but receives no telemetry — "blinded."

### 3.1 Process Notification Callback Removal

**Target**: `PspCreateProcessNotifyRoutine` (kernel-internal array)

**Implementation**:
1. Find `PsSetCreateProcessNotifyRoutine` export in ntoskrnl.exe
2. Disassemble forward from the export to find the `lea` instruction referencing the callback array
3. The array is an `EX_CALLBACK_ROUTINE_BLOCK` array (max 64 entries)
4. Each entry contains: `Function` pointer and `Context` pointer
5. Resolve each callback's owning module by checking if `Function` falls within any loaded driver's address range
6. If module is `csagent.sys` (or other EDR driver), zero out the entry

**RealBlindingEDR approach**: Uses vulnerable drivers (echo_driver.sys, dbutil_2_3.sys) for arbitrary kernel R/W. Enumerates all callback arrays, identifies EDR entries by module range, zeros them out.

### 3.2 Thread Notification Callback Removal

**Target**: `PspCreateThreadNotifyRoutine`

Same technique as process callbacks. Removing these prevents detection of:
- Remote thread injection
- Thread context manipulation (SetThreadContext)
- APC injection detection

### 3.3 Image Load Callback Removal

**Target**: `PspLoadImageNotifyRoutine`

Removing these prevents detection of:
- Reflective DLL loading
- Module stomping
- Driver loading events
- DLL side-loading anomalies

**Important**: There is no `PsRemoveLoadImageNotifyRoutine` API — the kernel provides no legitimate way to unregister image load callbacks. This means EDR drivers cannot be cleanly unloaded without leaving dangling callbacks, which rootkits exploit.

### 3.4 Object Handle Callback Removal

**Target**: `ObRegisterCallbacks` entries in `CallbackListHead`

Removing ObRegisterCallbacks eliminates:
- Handle protection on EDR processes (allows regular `TerminateProcess`)
- Handle protection on lsass.exe (allows credential dumping)
- Handle stripping for PROCESS_VM_READ/WRITE operations

**After removal**: Standard admin-level `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess` works against EDR processes that were previously protected.

### 3.5 Registry Callback Removal

**Target**: `CmRegisterCallbackEx` registration

Removing these enables:
- Undetected persistence via registry Run keys, services, scheduled tasks
- Modification of EDR configuration keys
- Permanent EDR disable via service Start=4

### 3.6 Minifilter Callback Removal/Unlinking

**Target**: FltMgr filter registration

**Callback Unlinking** (2026 state of the art, replaces older patching):
- Microsoft's Kernel Control Flow Guard (kCFG) now protects indirect function calls
- Old approach (patching callback function pointers) triggers kCFG violation → BSOD
- New approach: Unlink the minifilter's registration entry from FltMgr's internal list
- The filter remains loaded but never receives I/O callbacks
- No kCFG violation because no function pointers are modified

**Altitude Takeover** (alternative approach):
- Register a dummy minifilter at the same altitude as the EDR before it loads
- FltMgr enforces unique altitudes → EDR's minifilter fails to register on next boot
- Requires reboot, so useful for persistence not immediate evasion

### 3.7 Combined "Total Blind" Approach

Tools like RealBlindingEDR remove ALL six callback types simultaneously. After execution:
- EDR process is still running (no tampering alerts to SOC)
- EDR reports "healthy" status to management console
- But receives ZERO telemetry about system activity
- Any subsequent malware activity is invisible to the EDR

This is the most dangerous state for defenders because the EDR appears operational.

---

## 4. DKOM (Direct Kernel Object Manipulation)

DKOM modifies kernel data structures directly to hide processes, manipulate tokens, or alter security attributes without hooking or patching code.

### 4.1 Process Hiding via ActiveProcessLinks

**Target**: `EPROCESS->ActiveProcessLinks` (doubly-linked list)

```
EPROCESS_A.Flink → EPROCESS_B.Flink → EPROCESS_C.Flink → ...
EPROCESS_A.Blink ← EPROCESS_B.Blink ← EPROCESS_C.Blink ← ...

To hide process B:
  EPROCESS_A.Flink = EPROCESS_C
  EPROCESS_C.Blink = EPROCESS_A
  EPROCESS_B.Flink = EPROCESS_B  (self-referential to avoid crashes)
  EPROCESS_B.Blink = EPROCESS_B
```

**Effect**: Process B disappears from:
- Task Manager
- Process Explorer
- `NtQuerySystemInformation(SystemProcessInformation)`
- EDR process enumeration

**But still runs**: The scheduler uses a different data structure (KTHREAD ready queues), so the process continues executing normally.

**Detection**: Cross-reference process list with scheduler thread list, or enumerate via `PspCidTable` (handle table).

### 4.2 Token Manipulation

**Target**: `EPROCESS->Token`

- Copy the Token pointer from a SYSTEM process (e.g., `System` PID 4) to the malware's EPROCESS
- Instant privilege escalation without calling `AdjustTokenPrivileges` (which is monitored)
- Can also modify `TokenPrivileges` bitmap directly to enable SeDebugPrivilege

### 4.3 Protection Level Manipulation

**Target**: `EPROCESS->Protection` (PS_PROTECTION structure)

```c
typedef struct _PS_PROTECTION {
    UCHAR Type : 3;      // PsProtectedTypeNone=0, Protected=1, ProtectedLight=2
    UCHAR Audit : 1;
    UCHAR Signer : 4;    // PsProtectedSignerNone=0, ..., Antimalware=3, ...
} PS_PROTECTION;
```

**Attack**: Set malware process to `PsProtectedSignerAntimalware-Light` (PPL-AM)
- Process becomes immune to termination/injection by non-PPL processes
- Can subscribe to ETW-TI events (normally restricted to PPL-AM)
- EDR cannot inspect or terminate the process via standard APIs

**Defense bypass**: Set `EPROCESS->Protection.Type = 0` on the EDR process to strip its PPL protection, then terminate it with standard `TerminateProcess`.

### 4.4 ETW Provider DKOM

**Target**: ETW registration entries (`_ETW_REG_ENTRY` structures)

IBM X-Force research (2024) documented DKOM attacks that:
- Locate the ETW registration entry for Microsoft-Windows-Threat-Intelligence
- Modify the `GuidEntry->ProviderEnableInfo` to disable the provider
- Or unlink the registration from the provider's callback list
- Result: ETW-TI events stop firing without patching any code

**PatchGuard consideration**: PatchGuard monitors some kernel code pages but its checks are periodic (minutes apart) and do not comprehensively cover ETW structures. DKOM modifications to ETW data structures are less likely to trigger PatchGuard than code patches.

---

## 5. PPL (Protected Process Light) Bypass

CrowdStrike Falcon runs as PPL-Antimalware, which prevents:
- `OpenProcess` with PROCESS_TERMINATE by non-PPL processes
- Memory reads/writes via `ReadProcessMemory`/`WriteProcessMemory`
- DLL injection, thread injection, APC injection
- Handle duplication with elevated access rights

### 5.1 BYOVD-Based PPL Bypass

Vulnerable kernel drivers call `ZwTerminateProcess`/`ZwOpenProcess` from kernel mode, which bypasses ALL PPL checks:
- PPL is enforced in `PsOpenProcess`/`PsTerminateProcess` by checking the caller's protection level
- Kernel-mode callers (Ring-0) bypass these checks entirely
- PoisonX.sys (2026 0-day) specifically targets this vector against CrowdStrike

### 5.2 EPROCESS Protection Patching

With kernel R/W (via BYOVD):
1. Find the EDR process EPROCESS structure
2. Set `EPROCESS->Protection.Type = 0` (PsProtectedTypeNone)
3. Now standard `OpenProcess(PROCESS_TERMINATE) + TerminateProcess` works
4. Or: `OpenProcess(PROCESS_ALL_ACCESS)` → inject, read memory, etc.

### 5.3 Handle Table Manipulation

Alternative to patching EPROCESS:
1. Find an existing handle to the EDR process in the System process handle table
2. Elevate the handle's granted access rights via DKOM on the handle table entry
3. Duplicate the handle to the attacker process
4. Use the elevated handle to terminate/inject

### 5.4 Process Explorer Driver Trick

Process Explorer's driver (PROCEXP.SYS) is Microsoft-signed and can:
- Open handles to PPL processes from kernel mode
- Terminate PPL processes
- Used by Backstab and AuKill tools
- Not blocklisted on many systems because it's a legitimate Microsoft tool

---

## 6. ETW Bypass at Kernel Level

### 6.1 ETW-TI Provider Disable

**Approach 1**: DKOM on provider structures (see Section 4.4)

**Approach 2**: Patch `EtwWrite` in ntoskrnl.exe to `ret` early
- Disables ALL ETW events system-wide
- PatchGuard will eventually detect and BSOD (minutes to hours)
- Viable for short-lived operations (exfiltrate → exit before PatchGuard check)

**Approach 3**: SecurityTrace flag consumption
- `EtwEventWriteEx` with `SecurityTrace` flag accesses a subset of TI events WITHOUT requiring PPL
- Does not disable ETW-TI, but allows non-PPL processes to consume the events
- Useful for understanding what the EDR sees, not for blinding it

### 6.2 Hardware Breakpoint ETW Bypass

For userland ETW consumers (not TI provider):
1. Set hardware breakpoint on `EtwEventWrite` entry point in ntdll
2. VEH catches the breakpoint, modifies return value to indicate "not enabled"
3. No byte patching (bypasses integrity checks)
4. Works for AMSI bypass via same mechanism on `AmsiScanBuffer`

### 6.3 ETW Session Manipulation

With kernel R/W:
1. Enumerate ETW sessions via `EtwpSessionDemuxInfo`
2. Find the session subscribed to TI provider events
3. Remove the EDR's consumer from the session's consumer list
4. TI events still fire but nobody receives them

---

## 7. Sleep Obfuscation — Kernel Interaction Points

While sleep obfuscation itself is userland, EDR kernel drivers detect it via specific kernel events.

### 7.1 Detection Points and Bypasses

| EDR Detection | Technique | Kernel Bypass |
|---------------|-----------|---------------|
| VirtualProtect toggle frequency | Ekko changes RWX↔RX↔RW per sleep cycle | Remove `Microsoft-Windows-Threat-Intelligence` subscription (Section 6) |
| Suspicious timer queue callbacks | Ekko uses `CreateTimerQueueTimer` | Use custom timer implementation via NtSetTimer2 |
| Stack frame analysis during sleep | Thread's stack shows NtWaitForSingleObject→RtlpTpTimerCallback | SilentMoonwalk stack spoofing |
| Memory scan during sleep | Encrypted memory pages still have identifiable metadata | Foliage/FOLIAGE APC chains + memory permission reset |

### 7.2 DreamWalkers (State of the Art)

Combines:
- Ekko-style sleep encryption
- Dynamic stack spoofing (synthetic frames)
- Ghost-mapped module loading (no backing file)
- All in a single integrated implementation

---

## 8. Advanced Evasion Techniques

### 8.1 Transacted NTFS (Process Doppelganging)

1. Create NTFS transaction
2. Write malicious PE to file within transaction
3. Create section from the transacted file
4. Rollback transaction (file disappears from disk)
5. Create process from the section (mapped memory remains)

**Kernel detection**: Image load callback fires, but the file path is transacted (may appear legitimate).

### 8.2 Process Ghosting

1. Create a file, mark it for deletion (pending delete state)
2. Write malicious PE to the file
3. Create section from the pending-delete file
4. Close file handle (file is deleted)
5. Create process from the section

**Kernel detection**: Image load callback fires with a path to a deleted file. Some EDRs detect this anomaly.

### 8.3 Module Stomping

1. Load a legitimate, signed DLL (e.g., `amsi.dll`, `dbghelp.dll`)
2. Overwrite its `.text` section with shellcode
3. Execute from within the legitimate module's memory range

**Kernel detection**: Image load callback shows legitimate DLL. Memory protection changes (W→X) may trigger ETW-TI events.

### 8.4 Ghost-Mapped Modules

Load modules without any backing file by:
1. `NtCreateSection` with `SEC_COMMIT` (not `SEC_IMAGE`)
2. `NtMapViewOfSection` to desired address
3. Manual PE loading (relocations, imports)

**No image load callback fires** because it's not an image section. The module exists only in memory with no disk backing.

---

## 9. Framework Implementation Strategy

### 9.1 New Dimensions to Add

Based on this research, the following kernel-level evasion dimensions should be added to the framework:

#### Dimension: `kernel_evasion` (Ring-0 technique)
| Option | Risk | Description |
|--------|------|-------------|
| `none` | L | No kernel-level evasion (userland only) |
| `byovd_rtcore` | H | RTCore64.sys — widely known, often blocklisted |
| `byovd_dbutil` | H | dbutil_2_3.sys — Dell driver, less blocklisted |
| `byovd_procexp` | M | PROCEXP.SYS — Microsoft-signed, PPL termination only |
| `byovd_custom` | H | Template for newly discovered vulnerable drivers |

#### Dimension: `callback_evasion` (What to blind)
| Option | Risk | Description |
|--------|------|-------------|
| `none` | L | No callback manipulation |
| `process_callbacks` | H | Remove PsSetCreateProcessNotifyRoutine entries |
| `thread_callbacks` | H | Remove PsSetCreateThreadNotifyRoutine entries |
| `image_callbacks` | H | Remove PsSetLoadImageNotifyRoutine entries |
| `object_callbacks` | H | Remove ObRegisterCallbacks entries |
| `minifilter_unlink` | H | Unlink minifilter from FltMgr list |
| `total_blind` | H | Remove ALL callback types (RealBlindingEDR approach) |

#### Dimension: `process_protection` (DKOM/PPL manipulation)
| Option | Risk | Description |
|--------|------|-------------|
| `none` | L | Standard process, no DKOM |
| `hide_process` | H | DKOM ActiveProcessLinks unlinking |
| `elevate_ppl` | H | Set EPROCESS->Protection to PPL-AM |
| `strip_edr_ppl` | H | Remove EDR's PPL protection before termination |
| `token_steal` | H | Copy SYSTEM token via EPROCESS->Token DKOM |

#### Dimension: `etw_kernel` (Kernel-level ETW manipulation)
| Option | Risk | Description |
|--------|------|-------------|
| `none` | L | No kernel ETW manipulation (use userland patching) |
| `dkom_provider` | H | DKOM on ETW-TI provider registration |
| `session_unlink` | H | Remove EDR consumer from ETW session |
| `hwbp_veh` | M | Hardware breakpoint + VEH for ETW bypass |

### 9.2 Implementation Constraints

1. **All kernel techniques require admin/SYSTEM**: The framework should check `whoami /priv` or `IsUserAnAdmin()` before attempting kernel-level evasion
2. **HVCI blocks kernel code modifications**: On HVCI-enabled systems, vulnerable drivers cannot modify kernel .text (W^X enforcement). DKOM on data structures still works.
3. **PatchGuard timing**: Kernel code patches survive 5-30 minutes before PatchGuard check. Data structure DKOM may survive longer but is not guaranteed.
4. **Driver blocklist**: The framework should check HVCI status and attempt blocklist bypass (hash mutation) before loading vulnerable drivers.
5. **Driver signing**: All loaded drivers must have valid Authenticode signatures. Custom drivers are not viable without a stolen/leaked code-signing certificate.

### 9.3 Implementation Priority

**Phase 1** (High ROI, lower complexity):
- `kernel_evasion` dimension with BYOVD options
- PROCEXP.SYS approach (Microsoft-signed, simple IOCTL)
- Basic PPL termination of EDR process

**Phase 2** (Full blind approach):
- `callback_evasion` dimension
- Enumerate and remove specific callback types
- Focus on process + image load callbacks first (highest EDR value)

**Phase 3** (Advanced stealth):
- `process_protection` DKOM options
- Process hiding, token manipulation
- ETW-TI DKOM disable

### 9.4 Template Integration

Each kernel evasion option should generate a C code chunk that:
1. Drops the embedded vulnerable driver to a temp path
2. Creates and starts the driver service
3. Sends IOCTLs to gain kernel R/W
4. Performs the specified evasion (callback removal, PPL strip, etc.)
5. Cleans up: stops service, deletes driver file, removes service registry key
6. Proceeds with main payload (now undetected)

The driver binary should be XOR-encrypted and embedded as a resource or stack string array to avoid static signature detection.

---

## 10. Real-World Validation

### 10.1 Proven Against CrowdStrike

| Technique | Group/Tool | Year | Result |
|-----------|-----------|------|--------|
| BYOVD + process kill | Scattered Spider (6 drivers) | 2024 | Detected by Falcon BYOVD protection |
| BYOVD + callback removal | ABYSSWORKER (smuol.sys) | 2024-25 | Successful blind |
| BYOVD + process kill | PoisonX 0-day | 2026 | Successful kill, 0 VT detections |
| BYOVD + total blind | GentleKiller suite | 2026 | 478 victims, successful against Falcon |
| Network tunneling (no kernel) | Komodo Security pentest | 2023 | CrowdStrike saw nothing (endpoint-only) |
| Embedded QEMU VM | Komodo Security pentest | 2023 | Complete invisibility |
| Safe Mode boot | Snatch/AvosLocker | 2019-23 | Falcon inactive in Safe Mode |

### 10.2 What CrowdStrike Detects

- Known vulnerable driver hashes (BYOVD protection feature)
- Suspicious `sc create` + `sc start` for .sys files
- Anomalous IOCTL patterns to loaded drivers
- Mass process termination events targeting security services
- Kernel callback array modification (via integrity monitoring)
- ETW session manipulation (via TI provider self-monitoring)

### 10.3 What CrowdStrike Doesn't Detect

- 0-day vulnerable drivers not in blocklist
- Hash-mutated variants of known drivers
- DKOM on data structures (vs. code patches)
- Network-layer attacks from unmonitored endpoints
- Operations during Safe Mode (Falcon inactive)
- Ghost-mapped modules (no image load callback fires)

---

## Sources

- [Bypassing CrowdStrike Falcon and MDE](https://ericesquivel.github.io/posts/bypass) — 8-technique methodology
- [EDR Tradecraft: Internals, Research, and Bypass](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/) — Comprehensive callback architecture
- [RealBlindingEDR](https://github.com/myzxcg/RealBlindingEDR) — Open-source 6-callback removal tool
- [PoisonX 0-Day BYOVD](https://threatlabsnews.xcitium.com/blog/reverse-engineering-a-0-day-poisonx-byovd-driver-bypasses-crowdstrike-edr/) — CrowdStrike-specific kill
- [GentleKiller EDR Suite](https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/) — 2026 state of the art
- [Endpoint Security Evasion 2020-2025](https://windshock.github.io/en/post/2025-05-28-endpoint-security-evasion-techniques-20202025/) — Evolution timeline
- [Minifilter Callback Unlinking](https://medium.com/@s12deff/silencing-edr-file-telemetry-minifilter-callback-unlinking-fe215b009d72) — kCFG-safe approach
- [BYOVD in 2026](https://www.threatintelreport.com/2026/02/21/articles/byovd-in-2026-the-signed-driver-loophole-powering-edr-bypass-at-scale/) — Scale analysis
- [CrowdStrike Kernel Access Architecture](https://www.crowdstrike.com/en-us/blog/tech-analysis-kernel-access-security-architecture/) — Official architecture
- [Scattered Spider BYOVD](https://www.crowdstrike.com/en-us/blog/scattered-spider-attempts-to-avoid-detection-with-bring-your-own-vulnerable-driver-tactic/) — CrowdStrike detection case study
- [CrowdStrike Enterprise Bypass](https://www.komodosec.com/post/bypassing-crowdstrike) — Network-layer and VM evasion
- [Sleep Obfuscation](https://binarydefense.com/resources/blog/understanding-sleep-obfuscation) — Ekko/Foliage/DreamWalkers
- [SilentMoonwalk Stack Spoofing](https://klezvirus.github.io/posts/Stackmoonwalk/) — Dynamic call stack spoofer
- [Indirect Syscalls](https://redops.at/en/blog/indirect-syscalls-and-dynamic-ssn-retrieval-via-apis) — SSN resolution techniques
- [DKOM Attacks on ETW Providers](https://www.ibm.com/think/x-force/direct-kernel-object-manipulation-attacks-etw-providers) — IBM X-Force research
- [PPL Bypass Techniques](https://medium.com/@s12deff/windows-ppl-protected-processes-light-e158332aedca) — Protection level manipulation
