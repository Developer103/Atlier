# Kernel vs Usermode Evasion: A Comparative Analysis

Deep analysis of the two primary evasion battlegrounds, their respective capabilities, limitations, and the trajectory of the arms race.

---

## Table of Contents

1. [Usermode Evasion Taxonomy](#1-usermode-evasion-taxonomy)
2. [Kernel Evasion Taxonomy](#2-kernel-evasion-taxonomy)
3. [What Each Level Can and Cannot Hide](#3-detection-asymmetry)
4. [Getting to Ring 0 in 2025-2026](#4-ring-0-access)
5. [VBS and HVCI Impact](#5-vbs-and-hvci)
6. [The Arms Race Timeline](#6-arms-race-timeline)
7. [Longevity Analysis](#7-longevity-analysis)
8. [Recommended Strategy](#8-recommended-strategy)

---

## 1. Usermode Evasion Taxonomy

All usermode evasion operates within the fundamental constraint: **the kernel sees every syscall**. Usermode evasion blinds the monitoring layer between your code and the kernel, but not the kernel itself.

### Category A: Hook Bypass
Bypassing inline hooks placed by EDR DLLs in ntdll.dll.

| Technique | Mechanism | What it defeats |
|-----------|-----------|-----------------|
| NTDLL unhooking | Remap clean ntdll from disk | All usermode inline hooks |
| Indirect syscalls | Call syscall instruction directly | Usermode hooks (but not kernel callbacks) |
| Direct syscalls | Syscall stub in your binary | Same as indirect but easier to detect (no ntdll return address) |
| Manual mapping | Load your own ntdll copy | All hooks on the process's ntdll |
| Syscall via HellsGate | Read SSN from hooked ntdll | Hooks that don't modify the SSN bytes |

**What remains detectable after perfect hook bypass:**
- Kernel callbacks still fire (process/thread/image notifications)
- ETW-TI still logs cross-process operations
- Minifilter still intercepts file I/O
- WFP still sees network connections
- Memory scanners can still find suspicious allocations

### Category B: Telemetry Blinding
Preventing events from being logged.

| Technique | Target | Scope |
|-----------|--------|-------|
| ETW patch (usermode) | EtwEventWrite in ntdll | Blinds usermode ETW consumers only |
| ETW provider disabling | Specific ETW providers | Targeted provider only |
| AMSI patch | AmsiScanBuffer | Script-based detection only |
| HW breakpoint ETW | EtwEventWrite via DR0 | Same as ETW patch, patchless |

**Fundamental limit:** Usermode ETW patching does NOT affect kernel ETW providers (ETW-TI). The kernel has its own event generation path that never touches ntdll.

### Category C: Execution Primitive Abuse
Using unexpected code paths to execute.

| Technique | Mechanism | EDR visibility |
|-----------|-----------|----------------|
| Callback abuse (EnumFonts, etc.) | Legitimate API calls your function | Low — function appears as callback parameter |
| Fiber execution | ConvertThreadToFiber + CreateFiber | Low — fiber switching has minimal telemetry |
| APC abuse | NtQueueApcThread | Medium — some EDRs monitor APC queuing |
| Thread pool abuse (Pool Party) | Thread pool work items | Low — thread pool is kernel-managed |

### Category D: Memory Evasion
Hiding malicious code in memory from scanners.

| Technique | Mechanism | Effectiveness |
|-----------|-----------|---------------|
| Sleep encryption (Ekko) | Encrypt image during sleep | High — scanner sees only ciphertext |
| Header stomping | Overwrite MZ/PE headers | Medium — defeats header-based scanning |
| No-RWX allocation | W→X, never WX simultaneously | Medium — defeats RWX heuristic |
| Stack-based shellcode | Execute from stack, not heap | Medium — unusual but detectable |

### Category E: Identity/Trust Abuse
Making the malware appear legitimate.

| Technique | Mechanism | Requirements |
|-----------|-----------|--------------|
| DLL sideloading | Legitimate exe loads malicious DLL | Vulnerable signed binary |
| Masquerading | Match legitimate process names/paths | None |
| PPID spoofing | Fake parent process | Admin |
| Timestomping | Modify file timestamps | File system access |

---

## 2. Kernel Evasion Taxonomy

Kernel evasion requires Ring 0 access (BYOVD, zero-day, or loading a driver). Once achieved, the attacker can:

### Category F: Callback Manipulation
| Technique | Impact | PatchGuard risk |
|-----------|--------|-----------------|
| Callback removal | Kill all kernel notifications | HIGH — PatchGuard monitors callback arrays |
| Callback tampering | Modify callback behavior | HIGH |
| ObCallback removal | Allow handle access to EDR | HIGH |

### Category G: Driver/Minifilter Manipulation
| Technique | Impact | PatchGuard risk |
|-----------|--------|-----------------|
| Minifilter unloading | Kill file I/O monitoring | MEDIUM — depends on how it's done |
| Filter altitude manipulation | Reorder minifilter processing | LOW |
| IRP hijacking | Modify I/O requests before EDR sees them | MEDIUM |

### Category H: Kernel Telemetry Disabling
| Technique | Impact | PatchGuard risk |
|-----------|--------|-----------------|
| ETW-TI disabling | Kill kernel ETW events | LOW — not monitored by PatchGuard |
| WFP callout removal | Kill network monitoring | MEDIUM |
| Kernel ETW provider patching | Selective event suppression | LOW |

### Category I: Object Manipulation
| Technique | Impact | PatchGuard risk |
|-----------|--------|-----------------|
| DKOM process hiding | Hide from process enumeration | HIGH |
| Token manipulation | Privilege escalation | MEDIUM |
| Handle table modification | Access restricted objects | MEDIUM |

---

## 3. Detection Asymmetry

### What kernel-level detection sees that usermode cannot:
1. **Actual syscall arguments** — even if usermode hooks are bypassed, the kernel function receives the real parameters
2. **Cross-process operations** — kernel callbacks fire regardless of how the syscall was invoked
3. **File system operations** — minifilter sees every IRP, no usermode bypass possible (without kernel access)
4. **Network operations** — WFP operates at the kernel/NDIS level
5. **Driver loading** — PsSetLoadImageNotifyRoutine fires for all image loads including drivers
6. **Memory operations** — VAD (Virtual Address Descriptor) tracking in the kernel

### What usermode detection sees that kernel cannot:
1. **Application-level context** — what the user was doing when the operation occurred
2. **Script content** — AMSI sees PowerShell/VBScript content before execution
3. **API call sequences** — behavioral patterns across multiple API calls
4. **Thread execution context** — which thread, from which module, with what stack
5. **String content in memory** — usermode scanners can read process memory and look for indicators

### The gap
The kernel sees THAT something happened (process created, memory allocated, file written) but not always WHY or WHAT in full context. Usermode sees the full context but can be bypassed by the attacker. This creates a permanent detection gap — neither layer alone can see everything.

---

## 4. Ring 0 Access in 2025-2026

### BYOVD (primary method)
600+ vulnerable signed drivers cataloged in LOLDrivers. Key drivers still usable in 2025:
- **Not on Microsoft's blocklist**: Dozens of lesser-known OEM drivers
- **WHQL-signed**: Some Intel/AMD utility drivers with memory write IOCTLs
- **Legitimate tools**: Process Hacker, PCHunter drivers (signed, legitimately privileged)

### Zero-day driver vulnerabilities
New kernel-mode vulnerabilities are regularly discovered:
- ~50-100 Windows kernel CVEs per year (2023-2025 average)
- Third-party driver vulnerabilities discovered at higher rate
- Average patch latency: 30-90 days (longer for third-party drivers)

### Windows Defender Application Control (WDAC)
WDAC driver policies can block known vulnerable drivers. But:
- Requires explicit enterprise configuration (not default)
- Allowlist-based = maintenance burden
- Drivers signed after cutoff date are allowed by default

### Attestation signing (post-2023)
Microsoft's attestation signing for kernel drivers was intended to reduce BYOVD risk. Reality:
- Some malicious drivers have been attestation-signed (submission review is imperfect)
- Legacy cross-signed drivers still work on most systems
- EV certificate requirement was dropped in some signing pathways

---

## 5. VBS and HVCI

### Virtualization-Based Security (VBS)
VBS uses the hypervisor to create isolated memory regions (VTL 1) that even the kernel (VTL 0) cannot access. Used for:
- Credential Guard (protect LSASS secrets)
- HVCI (code integrity enforcement)
- Kernel CFG (Control Flow Guard)

### HVCI Impact on Kernel Evasion
HVCI prevents:
- Loading unsigned drivers (kills most BYOVD)
- Modifying executable kernel memory (kills kernel code patching)
- Allocating executable kernel memory without valid signatures

HVCI does NOT prevent:
- Modifying kernel DATA structures (DKOM, callback pointer overwrite)
- Reading kernel memory
- IOCTLs to legitimately loaded drivers
- Exploiting bugs in already-loaded, signed drivers

### Current HVCI adoption (2025-2026)
- Enabled by default on new Windows 11 devices (since 22H2)
- Enterprise adoption: ~40-50% of managed Windows 11 endpoints
- Legacy Windows 10: rarely enabled
- Can be disabled by admin (but Defender flags it)

### Does VBS break the bypass cycle?
**Partially.** VBS significantly raises the bar for kernel-level attacks by eliminating trivial BYOVD and kernel patching. However:
- HVCI-compatible BYOVD still possible (exploit data corruption bugs in signed drivers, not code execution)
- Hypervisor escapes (rare but documented — VMWare, Hyper-V CVEs)
- Firmware-level attacks bypass VBS entirely
- The attacker can disable VBS if they control boot (Secure Boot bypass, BitLocker key recovery)

**Verdict:** VBS adds a significant layer but doesn't close the loop. It's the most impactful single defense advancement in the 2020-2026 period.

---

## 6. Arms Race Timeline

### 2018-2020: Usermode Hook Era
- **Offense**: Unhooking ntdll, direct syscalls (SysWhispers)
- **Defense**: Usermode inline hooks on ntdll, basic ETW monitoring
- **State**: Relatively easy to evade. Most EDRs relied on usermode hooks as primary detection.

### 2020-2022: Kernel Callback Era
- **Offense**: Indirect syscalls, callback-based execution, sleep obfuscation
- **Defense**: Kernel callbacks deployed widely, ETW-TI provider activated, memory scanning improved
- **State**: Usermode-only evasion no longer sufficient against top-tier EDRs. Need combination of hook bypass + memory evasion + behavioral mimicry.

### 2022-2024: VBS/HVCI Deployment
- **Offense**: BYOVD for kernel access, Pool Party injection, Phantom DLL hollowing
- **Defense**: HVCI blocks unsigned drivers, VBS protects kernel integrity, cloud-based ML detection
- **State**: Kernel attacks getting harder. BYOVD still works but driver supply narrowing. Usermode evasion combinations still effective against most EDRs.

### 2024-2026: Current State
- **Offense**: PPL abuse (PPLFault), ETW-TI disabling via BYOVD, AI/ML evasion, telemetry flooding, COM abuse
- **Defense**: Vulnerable driver blocklist growing, PPL hardening, behavioral ML improvement, kernel ETW-TI
- **State**: Arms race is at the usermode/kernel boundary. Attackers who can get Ring 0 access can still disable most detection. Usermode-only evasion requires stacking 4-6 techniques.

### 2026+ Prediction
- **Hardware security**: ARM64 Windows (Copilot+ PCs) with hardware-enforced security features
- **AI detection**: Large behavioral models running on dedicated silicon
- **Kernel lockdown**: Progressive restrictions on kernel code loading
- **The permanent gap**: Application-level semantic understanding will remain hard for automated detection. Social engineering, living-off-the-land, and supply chain attacks will dominate.

---

## 7. Longevity Analysis

### Techniques that will remain effective 3+ years:
1. **Sleep encryption** (Ekko-style) — no practical kernel-level counter without VBS memory introspection
2. **Behavioral mimicry** — fundamental ML problem, can't be fully solved
3. **LOLBin abuse** — operational tools can't be blocked
4. **COM/DCOM abuse** — massive, underexplored surface
5. **String encryption / API hashing** — basic but effective signature evasion

### Techniques on borrowed time (1-2 years):
1. **BYOVD with well-known drivers** — blocklist growing, HVCI adoption increasing
2. **PPL abuse via known bugs** — specific vulns get patched
3. **Usermode ETW patching** — EDRs moving to kernel-level ETW
4. **Simple hook bypass (unhooking only)** — EDRs adding kernel-level cross-referencing

### Already diminishing:
1. **Direct syscalls** (without call stack spoofing) — trivially detected by stack analysis
2. **Process hollowing** — heavily signatured by all major EDRs
3. **Classic reflective loading** — memory scanning catches basic variants
4. **Simple DLL injection** (CreateRemoteThread + LoadLibrary) — universally detected

---

## 8. Recommended Strategy

### For our framework's longevity:

**Layer 1 (Always apply):**
- String encryption (XOR per-build key)
- API resolution via hash (minimize IAT)
- Behavioral pacing (delays between operations)
- No-RWX memory (W→X transitions)

**Layer 2 (Apply for EDR environments):**
- ETW patching (usermode — cheap, effective)
- NTDLL unhooking (removes all usermode hooks)
- Sleep encryption (Ekko — defeats memory scans)
- Call stack spoofing (defeats stack analysis)

**Layer 3 (Apply for hardened targets):**
- Indirect syscalls (defeats hook + stack analysis)
- HW breakpoint ETW (patchless, harder to detect)
- Temporal spacing (operations spread over hours)
- COM-based execution (execution from trusted processes)

**Layer 4 (Nuclear — requires admin/kernel):**
- BYOVD → callback removal
- ETW-TI disabling
- Minifilter unloading
- PPL injection

**Principle:** Stack techniques from Layer 1 upward. Most targets fall at Layer 2. Only invest in Layer 3-4 for hardened targets with mature SOCs. Each layer adds diminishing returns but also diminishing detection risk.
