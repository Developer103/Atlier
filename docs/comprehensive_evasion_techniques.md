# Comprehensive Evasion Techniques — Gap Analysis & New Dimension Proposals

Everything real attackers and red teams use in 2024-2026 that we either don't model at all or model incompletely.
Organized by: what we have → what's missing → concrete proposals.

---

## LEGEND

- **HAVE** = dimension/option exists in evasion_selector.py
- **PARTIAL** = dimension exists but missing important options
- **MISSING** = not modeled at all, needs new dimension or new options

---

## 1. NTDLL/API UNHOOKING (MISSING — new options for `api_resolve`)

EDRs hook ntdll.dll functions in userland. Attackers un-hook before making sensitive calls.

### What We Have
- `api_resolve` dim covers API resolution: direct_import, loadlibrary, hash resolvers, peb_walk, indirect_syscall

### What's Missing — NTDLL Unhooking Variants
These run BEFORE any API call and restore a clean ntdll.dll, making all subsequent calls invisible to userland hooks.

| Technique | How It Works | Detection Risk | Implementable in C? |
|-----------|-------------|----------------|---------------------|
| **Disk remap** | Read ntdll.dll from disk, overwrite .text section in memory | Medium — touches disk | Yes, ~50 lines |
| **KnownDLLs remap** | NtOpenSection(\KnownDlls\ntdll.dll), map clean copy | Low — no disk I/O | Yes, ~30 lines |
| **Suspend-remap** | Create suspended process, copy its pristine ntdll .text | Low — suspended proc is clean before EDR hooks | Yes, ~60 lines |
| **Perun's Fart** | Map ntdll from suspended process using NtReadVirtualMemory | Low — avoids NtMapViewOfSection monitoring | Yes, ~50 lines |
| **HookChain** | Rebuild IAT with syscall stubs extracted from clean ntdll copy | VLow — no patching, just new table | Yes, ~80 lines |
| **Lazy unhooking** | Only unhook specific functions as needed (not entire DLL) | VLow — minimal memory changes | Yes, ~20 lines |

### Proposal
Add to `api_resolve`:
```
"ntdll_disk_remap":    {"risk": "medium", "desc": "Remap ntdll.dll from disk — restores clean copy, defeats userland hooks"}
"ntdll_knowndlls":     {"risk": "low",    "desc": "Map clean ntdll from \\KnownDlls — no disk I/O, patchless"}
"ntdll_suspend_remap": {"risk": "vlow",   "desc": "Clean ntdll from suspended child process — EDR hasn't hooked it yet"}
"hookchain":           {"risk": "vlow",   "desc": "HookChain: rebuild syscall stubs from clean ntdll — no patching needed"}
```

---

## 2. SYSCALL TECHNIQUES (PARTIAL — expand `api_resolve`)

### What We Have
- `indirect_syscall` — single option covering all syscall approaches

### What's Missing — Specific Syscall Variants
Each has different detection signatures and CrowdStrike handles them differently.

| Technique | How It Works | Status vs CrowdStrike | In C? |
|-----------|-------------|----------------------|-------|
| **SysWhispers 1** | Hardcoded SSNs per OS version | Detected — static SSN table is signaturable | Yes |
| **SysWhispers 2** | Runtime SSN resolution via EAT sorting | Partially detected — EAT walk pattern | Yes |
| **SysWhispers 3** | Indirect syscalls through ntdll jump stubs | Better — return addr in ntdll | Yes |
| **SysWhispers 4** | Combines sleep encryption + indirect syscalls | Current best — layered evasion | Yes |
| **Hell's Gate** | Read SSN from ntdll function prologue at runtime | Medium — mov eax,SSN pattern | Yes |
| **Halo's Gate** | Hell's Gate + fallback: walk neighbors if hooked | Low — handles hooked stubs | Yes |
| **Tartarus Gate** | Halo's Gate + deep neighbor walk + hook-length awareness | VLow — handles complex hooks | Yes |
| **FreshyCalls** | Sort Zw* exports by address to get SSN order | Low — pure arithmetic approach | Yes |
| **RecycledGate** | Reuse existing ntdll syscall;ret gadget | VLow — legitimate return address | Yes |
| **VEH-based** | Hardware breakpoint on ntdll stub, VEH redirects to syscall | VLow — no code patching at all | Yes |

### Proposal
Expand `api_resolve` with:
```
"syscall_indirect":    {"risk": "vlow",   "desc": "SysWhispers3-style indirect syscalls — ret addr points into ntdll"}
"syscall_hells_gate":  {"risk": "low",    "desc": "Hell's Gate runtime SSN resolution from ntdll prologue"}
"syscall_halos_gate":  {"risk": "vlow",   "desc": "Halo's Gate — Hell's Gate with neighbor walk for hooked stubs"}
"syscall_recycled":    {"risk": "vlow",   "desc": "RecycledGate — reuse existing ntdll syscall;ret gadgets"}
"syscall_veh":         {"risk": "vlow",   "desc": "VEH + hardware breakpoint on ntdll — zero code modification"}
```

---

## 3. SLEEP OBFUSCATION (PARTIAL — expand `sleep_mode`)

### What We Have
- basic, jitter, encrypt, ekko

### What's Missing — Advanced Sleep Variants
These are critical for persistent implants that sit idle 95% of the time.

| Technique | How It Works | Key Difference from Ekko | In C? |
|-----------|-------------|--------------------------|-------|
| **Zilean** | Waitable Timer + NtContinue chaining, similar to Ekko | Uses WaitableTimer instead of TimerQueue — different API footprint | Yes |
| **Foliage** | APC-based, queues APC chain directly | No timer objects — APC only, harder to detect | Yes |
| **Gargoyle** | ROP chain on top of legitimate DLL, PAGE_NOACCESS while sleeping | Sleep in non-executable memory — defeats memory scan | Yes |
| **DeathSleep** | Unmap own image entirely during sleep, remap on wake | Process appears completely empty to scanner | Yes |
| **Cronos** | Thread pool callbacks for sleep/wake cycle | Uses Windows thread pool — blends with system behavior | Yes |
| **AceLdr** | Combines sleep obfuscation + position-independent shellcode | Shellcode-native sleep encryption | Yes |

### Proposal
Add to `sleep_mode`:
```
"zilean":      {"risk": "vlow",   "desc": "Zilean WaitableTimer + NtContinue chain — different API surface from Ekko"}
"foliage":     {"risk": "vlow",   "desc": "Foliage APC-based sleep — no timer objects, pure APC chain"}
"gargoyle":    {"risk": "vlow",   "desc": "Gargoyle ROP + PAGE_NOACCESS — code non-executable during sleep"}
"death_sleep": {"risk": "vlow",   "desc": "DeathSleep — unmap entire image during sleep, invisible to memory scan"}
```

---

## 4. PROCESS INJECTION TECHNIQUES (MISSING — new dimension `injection_method`)

### What We Have
- `process` dim covers process identity (hollowing, ghosting, spoofing) but NOT injection into running processes
- `execution` dim covers execution vehicle (callbacks, fibers, APC)

### Gap
No dimension for HOW code gets into another process. Process hollowing is listed under `process` as an identity choice, but the broader injection taxonomy is missing.

| Technique | How It Works | Detection Profile | In C? |
|-----------|-------------|-------------------|-------|
| **Classic VirtualAllocEx + WriteProcessMemory** | Alloc RWX in target, write shellcode, CreateRemoteThread | High — every step is monitored | Yes |
| **APC injection (EarlyBird)** | Queue APC to thread in CREATE_SUSPENDED state before it runs | Medium — APC to suspended thread is flagged | Yes |
| **Threadless injection** | No CreateRemoteThread — abuse existing thread's execution flow | VLow — no thread creation event | Yes |
| **Module stomping** | Load legit DLL in target, overwrite .text with payload | VLow — memory backed by real DLL | Yes (have this in memory_residence) |
| **Process Doppelgänging** | NTFS transaction + NtCreateProcessEx — file never on disk | VLow — transactional NTFS, no disk artifact | Yes |
| **Process Herpaderping** | Modify file AFTER process creation but before EDR scans | VLow — EDR sees wrong file content | Yes |
| **Process Ghosting** | Delete file before image mapping completes | VLow — file gone before EDR can read | Yes (have as process_ghost) |
| **Phantom DLL Hollowing** | Map phantom (non-existent) DLL section, inject there | VLow — memory appears mapped from "legitimate" source | Yes |
| **Transacted Hollowing** | Combine transactions + hollowing — rollback hides written content | VLow — NTFS transaction + process creation | Yes |
| **KernelCallbackTable hijack** | Overwrite PEB->KernelCallbackTable entry to redirect execution | VLow — no new thread, no APC, triggered by window msg | Yes |
| **NtQueueApcThreadEx2** | Newer APC variant, special flags for immediate execution | Low — newer API, less monitored | Yes |

### Proposal — New Dimension
```python
"injection_method": {
    "description": "How code enters target process — only applies when process != standalone",
    "options": {
        "none":              {"risk": "low",    "desc": "No injection — run in own process"},
        "classic_remote":    {"risk": "high",   "desc": "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"},
        "earlybird_apc":     {"risk": "medium", "desc": "EarlyBird APC to suspended thread — code runs before EDR hooks"},
        "threadless":        {"risk": "vlow",   "desc": "Threadless injection — hijack existing thread execution flow"},
        "doppelganging":     {"risk": "vlow",   "desc": "Process Doppelgänging — NTFS transaction, no disk artifact"},
        "herpaderping":      {"risk": "vlow",   "desc": "Process Herpaderping — modify file after creation, before scan"},
        "phantom_dll":       {"risk": "vlow",   "desc": "Phantom DLL Hollowing — inject into phantom-mapped DLL section"},
        "kcb_hijack":        {"risk": "vlow",   "desc": "KernelCallbackTable hijack — triggered by window message, no thread"},
    },
    "default": "none",
}
```

---

## 5. CALL STACK MANIPULATION (PARTIAL — expand `stack_presentation`)

### What We Have
- honest, ret_spoof

### What's Missing
CrowdStrike and Elastic now walk the entire call stack, not just return addresses.

| Technique | How It Works | Vs CrowdStrike | In C? |
|-----------|-------------|----------------|-------|
| **Static frame spoofing** | Build fake RBP/RSP chain with return addrs in legit DLLs | Better — fools simple stack walk | Yes |
| **Dynamic timer spoofing** | Use timer callbacks, spoof stack dynamically per-call | Best — Cobalt Strike 4.10+ uses this | Yes |
| **Call gadget injection** | Insert legitimate module into call chain via gadget | VLow — breaks pattern matching | Yes |
| **Stack pivot** | Switch to entirely different stack before sensitive call | VLow — call originates from "clean" stack | Yes |
| **Synthetic frames** | Create believable multi-frame call chain matching known paths | VLow — passes deep walk validation | Yes |
| **SilentMoonwalk** | Manipulate unwinding info to hide true origin | VLow — abuses exception handling metadata | Yes |

### Proposal
Add to `stack_presentation`:
```
"full_frame_spoof":    {"risk": "vlow",   "desc": "Full stack frame chain spoofing — multiple fake frames in legit DLLs"}
"dynamic_timer_spoof": {"risk": "vlow",   "desc": "Timer-based dynamic spoofing — stack changes per callback cycle"}
"silent_moonwalk":     {"risk": "vlow",   "desc": "SilentMoonwalk — abuse unwind info to hide call origin"}
```

---

## 6. ETW MANIPULATION (PARTIAL — expand `etw_method` and `etw_kernel`)

### What We Have
- etw_method: patch, hwbp_etw, hwbp_both, none
- etw_kernel: none, dkom_provider, session_unlink, hwbp_veh

### What's Missing

| Technique | Layer | How It Works | In C? |
|-----------|-------|-------------|-------|
| **ETW Provider GUID removal** | Kernel | Remove specific provider GUID from _ETW_REG_ENTRY | Yes |
| **ETW consumer disconnect** | Kernel | NtTraceControl to disconnect specific consumer | Yes |
| **ETW buffer manipulation** | Kernel | Corrupt ETW buffer pool so events are lost | Yes |
| **Userland NtTraceEvent patch** | User | Patch NtTraceEvent instead of EtwEventWrite | Yes |
| **ETW provider disable via registry** | User | Disable provider via HKLM Autologger entries | Yes |
| **Threat Intelligence ETW blind** | Kernel | Specifically target Microsoft-Windows-Threat-Intelligence provider | Yes |

### Proposal
Add to `etw_method`:
```
"nttraceevent_patch": {"risk": "low",    "desc": "Patch NtTraceEvent — lower-level than EtwEventWrite, fewer hooks"}
"registry_disable":   {"risk": "medium", "desc": "Disable ETW providers via Autologger registry keys — persistent"}
```
Add to `etw_kernel`:
```
"ti_provider_blind":  {"risk": "high",   "desc": "DKOM on Microsoft-Windows-Threat-Intelligence provider specifically"}
"buffer_corrupt":     {"risk": "high",   "desc": "Corrupt ETW kernel buffer pool — events generated but lost in transit"}
```

---

## 7. CREDENTIAL & TOKEN MANIPULATION (MISSING — relevant for infostealers)

### What We Have
- `target_scope` has credential_only, session_tokens
- No modeling of HOW credentials are accessed

### What's Missing — Credential Access Methods
CrowdStrike specifically monitors lsass.exe access patterns.

| Technique | How It Works | Detection Risk |
|-----------|-------------|----------------|
| **LSASS direct read** | OpenProcess + MiniDumpWriteDump on lsass | High — signature detection |
| **LSASS handle duplication** | Duplicate existing handle to lsass (from another process) | Medium |
| **SSP injection** | Load custom Security Support Provider DLL into lsass | Low — legitimate SSP mechanism |
| **DPAPI offline** | CryptUnprotectData on credential files without touching lsass | VLow — reads files, not processes |
| **Token impersonation** | Steal tokens via NtDuplicateToken — no credential extraction | Low |
| **Kerberos ticket extraction** | Read tickets from LSASS memory or krbtgt hash | Medium |
| **Registry SAM dump** | Copy SAM/SECURITY/SYSTEM hives — offline hash extraction | Medium |
| **Volume Shadow Copy abuse** | Access SAM via VSS snapshot — no live registry access | Low |
| **Browser credential store** | SQLite + DPAPI for Chrome, profiles for Firefox | VLow — file access only |
| **RDP credential harvest** | Hook RDP client or parse .rdp files for saved creds | VLow |

### Proposal — New Dimension (infostealer type-specific)
```python
"credential_access": {
    "description": "How credentials are extracted — shapes lsass/DPAPI behavioral signals",
    "options": {
        "file_only":       {"risk": "vlow",   "desc": "Only read credential files (browser DBs, .rdp) — no process access"},
        "dpapi_offline":   {"risk": "low",    "desc": "DPAPI CryptUnprotectData on files — no lsass touch"},
        "handle_dup":      {"risk": "medium", "desc": "Duplicate existing lsass handle — no direct OpenProcess"},
        "ssp_inject":      {"risk": "low",    "desc": "Load custom SSP into lsass — legitimate security provider mechanism"},
        "token_impersonate":{"risk": "low",   "desc": "Token theft via NtDuplicateToken — no credential extraction needed"},
        "vss_shadow":      {"risk": "low",    "desc": "Read SAM from Volume Shadow Copy — no live registry access"},
    },
    "default": "file_only",
}
```

---

## 8. MEMORY PROTECTION & ALLOCATION (MISSING — new dimension)

### What We Have
- `memory_residence`: native, module_stomp

### What's Missing
HOW memory is allocated matters as much as WHERE code lives. CrowdStrike flags VirtualAlloc(RWX) patterns.

| Technique | How It Works | Detection Risk |
|-----------|-------------|----------------|
| **RWX allocation** | VirtualAlloc with PAGE_EXECUTE_READWRITE | High — monitored |
| **RW → RX flip** | Alloc as RW, write, then VirtualProtect to RX | Medium — protection change tracked |
| **Mapped section** | NtCreateSection + NtMapViewOfSection | Low — looks like file mapping |
| **Existing RX reuse** | Find existing RX region in loaded DLL, overwrite | VLow — no new allocation |
| **Heap execution** | Execute from heap via VEH trick or APC | Low — unusual but no RWX alloc |
| **CFG bypass alloc** | Use allocations that bypass Control Flow Guard | VLow — needed for call target validation |

### Proposal
Expand `memory_residence` with:
```
"mapped_section":    {"risk": "low",    "desc": "NtCreateSection + NtMapViewOfSection — looks like legitimate file mapping"}
"rw_rx_flip":        {"risk": "medium", "desc": "Alloc RW, write payload, VirtualProtect to RX — no simultaneous RWX"}
"existing_rx_reuse": {"risk": "vlow",   "desc": "Overwrite existing RX region in loaded DLL — zero new allocations"}
```

---

## 9. NETWORK EVASION (PARTIAL — expand exfil-adjacent concerns)

### What We Have
- Extensive `exfil` dim (22 options) — good coverage
- `c2_paradigm` for backdoors (12 options) — good coverage

### What's Missing — Network-Level Evasion

| Technique | How It Works | Currently Modeled? |
|-----------|-------------|-------------------|
| **Domain fronting** | SNI mismatch — CDN routes to C2 | YES (c2_paradigm: domain_front) |
| **DNS over HTTPS (DoH)** | DNS queries inside HTTPS — invisible to DNS monitors | NO |
| **Encrypted DNS exfil** | Data in DoH/DoT queries to custom resolver | NO |
| **JA3/JA4 fingerprint spoofing** | Mimic browser TLS fingerprint | NO |
| **HTTP/2 multiplexing** | C2 traffic interleaved with legitimate HTTP/2 streams | NO |
| **Traffic shaping** | Match bandwidth/timing to legitimate app pattern | NO |
| **Certificate pinning abuse** | Use pinned certs from legit apps for C2 | NO |
| **Protocol tunneling** | C2 inside legitimate protocol (ICMP, WebRTC, QUIC) | PARTIAL (DNS only) |

### Proposal — New Dimension
```python
"network_stealth": {
    "description": "Network-level traffic camouflage beyond exfil method choice",
    "options": {
        "none":              {"risk": "medium", "desc": "No network stealth — raw connections"},
        "ja3_spoof":         {"risk": "low",    "desc": "JA3/JA4 TLS fingerprint mimicking legitimate browser"},
        "doh_tunnel":        {"risk": "vlow",   "desc": "DNS-over-HTTPS tunneling — invisible to DNS monitoring"},
        "traffic_shaping":   {"risk": "vlow",   "desc": "Shape bandwidth/timing to match legitimate application patterns"},
        "protocol_tunnel":   {"risk": "vlow",   "desc": "Tunnel inside ICMP/WebRTC/QUIC — non-standard channel"},
    },
    "default": "none",
}
```

---

## 10. DELIVERY & INITIAL ACCESS (MISSING — pre-execution gate)

### What We Have
- Nothing — framework starts at execution time

### What's Missing
SmartScreen/MOTW bypass is a **prerequisite** for execution. See `docs/smartscreen_evasion_research.md` for details.

### Proposal — New Dimensions (from smartscreen research)
```python
"motw_bypass": {
    "description": "How Mark of the Web is removed/avoided before execution",
    "options": {
        "none":            {"risk": "high",   "desc": "File has MOTW — SmartScreen will inspect"},
        "zone_id_delete":  {"risk": "medium", "desc": "Delete Zone.Identifier ADS after landing — requires prior execution"},
        "container_vhd":   {"risk": "low",    "desc": "Deliver inside VHD — inner files have no MOTW on mount"},
        "container_img":   {"risk": "low",    "desc": "Deliver inside IMG — same as VHD, less commonly blocked"},
        "encrypted_zip":   {"risk": "low",    "desc": "Encrypted ZIP — 7-Zip/WinRAR don't propagate MOTW on extract"},
        "html_smuggle":    {"risk": "vlow",   "desc": "HTML smuggling — JS constructs binary client-side, never downloaded"},
    },
    "default": "none",
}
```

---

## 11. BEHAVIORAL MIMICRY (MISSING — new dimension)

### What We Have
- Some implicit mimicry via `process` (browser_extension, service_dll, etc.)
- No explicit behavioral pattern matching

### What's Missing
CrowdStrike's behavioral engine correlates PATTERNS of API calls, not individual calls. Looking like a specific legitimate application defeats pattern matching.

| Technique | How It Works | In C? |
|-----------|-------------|-------|
| **Noise generation** | Mix malicious calls with benign API patterns | Yes |
| **Legitimate API interleaving** | Call CreateFile/ReadFile on real files between sensitive ops | Yes |
| **Process behavior cloning** | Mimic exact API call pattern of a known benign process | Yes |
| **Timing normalization** | Match API call cadence to human interaction speed | Yes |
| **Window/GUI spoofing** | Create invisible windows with legitimate class names | Yes |
| **Registry noise** | Read/write legitimate registry paths between real operations | Yes |

### Proposal — New Dimension
```python
"behavioral_mimicry": {
    "description": "Behavioral pattern camouflage — make API call patterns match legitimate software",
    "options": {
        "none":             {"risk": "medium", "desc": "No mimicry — raw malicious API pattern"},
        "noise_injection":  {"risk": "low",    "desc": "Interleave benign API calls between sensitive operations"},
        "app_clone":        {"risk": "vlow",   "desc": "Clone exact API pattern of specific legitimate app (e.g. Chrome update)"},
        "timing_match":     {"risk": "vlow",   "desc": "Normalize API call timing to match human-speed interaction"},
    },
    "default": "none",
}
```

---

## 12. VIRTUALIZATION / HYPERVISOR-LEVEL (MISSING — advanced)

### What We Have
- Nothing at this level

### What's Missing
Some EDRs (CrowdStrike included) are moving to hypervisor-based monitoring. Advanced attackers respond.

| Technique | How It Works | Feasibility |
|-----------|-------------|-------------|
| **Blue Pill style** | Install thin hypervisor below OS — intercept EDR's VMX calls | Complex, requires vuln driver |
| **EPT manipulation** | Modify Extended Page Tables to hide memory regions | Requires hypervisor access |
| **VMCS manipulation** | Modify VM Control Structure to alter CPU behavior | Requires hypervisor access |
| **Time manipulation** | Modify TSC reads to defeat timing-based detection | Moderate — RDTSC interception |

### Proposal
**Skip for now** — these require kernel access beyond BYOVD and are mainly theoretical for userland malware. Our kernel evasion dims (BYOVD, callback removal) cover the practical kernel-level attacks. Hypervisor evasion is an arms race that's not practical for generated C malware.

---

## 13. SAFE MODE / RECOVERY ABUSE (MISSING)

### What We Have
- Nothing

### What's Missing
Multiple ransomware families reboot into Safe Mode where EDR drivers don't load.

| Technique | How It Works | In C? |
|-----------|-------------|-------|
| **Safe Mode boot** | bcdedit /set safeboot minimal, reboot — most EDR won't start | Yes |
| **Safe Mode networking** | bcdedit /set safeboot network — EDR off but network available | Yes |
| **WinRE abuse** | Boot into Windows Recovery — full disk access, no EDR | Yes |
| **DSE bypass** | Disable Driver Signature Enforcement — load unsigned rootkit | Yes (needs vuln driver) |

### Proposal
**Don't add as dimension** — this is a tactical technique specific to ransomware scenarios and requires reboot which breaks most infostealer/keylogger/backdoor use cases. Document in knowledge.md as awareness item.

---

## 14. EVASION CHAINING / STRUCTURAL DEPENDENCIES (OBSERVATION)

### Current Gap
Our dimensions are treated as independent layers. In reality, many techniques are synergistic:

| Combo | Why It's Better Together |
|-------|------------------------|
| BYOVD + callback removal + DKOM | Full kernel blindness chain |
| Indirect syscall + NTDLL unhook | Belt and suspenders for API hiding |
| Sleep encryption + module stomp | Memory looks clean AND image-backed |
| Threadless injection + ret spoof | No thread event AND clean stack |
| Domain front + JA3 spoof | Network looks legitimate at every layer |
| EarlyBird APC + process ghost | Inject before hooks + no file on disk |

### Current Status
We have `ARCH_CONSTRAINTS` in evasion_selector.py that handles some of this (kernel_evasion=none blocks callback_evasion, etc.) but it's "must be in" constraints, not "synergy bonuses."

### Proposal
Add **synergy rules** to detection_model.py — when certain combos are present, reduce detection probability beyond what individual dims would suggest. This is how real CrowdStrike works: it detects patterns, so breaking multiple patterns simultaneously is multiplicatively better.

---

## SUMMARY — All Proposals Ranked by Impact

### NEW DIMENSIONS (add to evasion_selector.py)
| Priority | Dimension | Options | Impact |
|----------|-----------|---------|--------|
| **P0** | `injection_method` | 8 options | Fills biggest gap — process injection is core to most payloads |
| **P0** | `network_stealth` | 5 options | JA3 spoofing and DoH are current frontline techniques |
| **P1** | `behavioral_mimicry` | 4 options | Defeats CrowdStrike's strongest detection engine |
| **P1** | `credential_access` (infostealer) | 6 options | How creds are grabbed is heavily monitored |
| **P2** | `motw_bypass` | 6 options | Pre-execution gate, from smartscreen research |

### EXPANDED OPTIONS (add to existing dims)
| Priority | Dimension | New Options | Impact |
|----------|-----------|-------------|--------|
| **P0** | `api_resolve` | +4 unhooking variants, +5 syscall variants | Most impactful — defeats EDR's primary hook-based detection |
| **P0** | `sleep_mode` | +4 variants (zilean, foliage, gargoyle, death_sleep) | Critical for persistent implants |
| **P1** | `stack_presentation` | +3 variants (full frame, dynamic timer, silent moonwalk) | CrowdStrike now does deep stack walking |
| **P1** | `memory_residence` | +3 variants (mapped section, rw_rx_flip, rx_reuse) | Memory allocation is monitored |
| **P2** | `etw_method` | +2 options | Minor — current coverage is decent |
| **P2** | `etw_kernel` | +2 options | Minor — current coverage is decent |

### STRUCTURAL IMPROVEMENTS
| Priority | Change | Impact |
|----------|--------|--------|
| **P1** | Synergy rules in detection_model.py | Models real-world combo effectiveness |
| **P2** | Kernel dim structural treatment | BYOVD enables other kernel dims (partially done via constraints) |

### TOTAL NEW SEARCH SPACE
Current: 21 dims, ~38.5 quadrillion combinations
After proposals: 26 dims, ~67,000 quadrillion combinations (estimating conservatively)

The expanded search space makes the algo+LLM hybrid solver even more important — brute force becomes completely infeasible.

---

## WHAT REAL ATTACKERS DO THAT WE ALREADY MODEL WELL

Credit where due — our framework covers these better than most:

1. **Process identity diversity** — 16 options including COM, WMI, shell extension, print monitor, LSA plugin (excellent)
2. **Exfiltration variety** — 22 options covering LOLBins, cloud, steganography, named pipes (excellent)
3. **Persistence mechanisms** — 12 options including COM hijack, IFEO, network provider (very good)
4. **Anti-analysis** — 8 options including geofence, exec guardrails, canary-aware (very good)
5. **Callback execution vehicles** — 6 callback variants in execution dim (good)
6. **Kernel evasion** — BYOVD, callback removal, DKOM, ETW kernel (good foundation)
7. **C2 paradigms** — 12 options for backdoors (excellent)

## WHAT WE'RE WORST AT (BIGGEST GAPS)

1. **NTDLL unhooking** — THE most common EDR bypass technique, we don't model it at all
2. **Process injection taxonomy** — we conflate identity with injection method
3. **Network fingerprinting** — JA3/JA4 spoofing is standard and we ignore it
4. **Behavioral mimicry** — CrowdStrike's strongest engine, we have zero counter-modeling
5. **Memory allocation stealth** — only 2 options when there should be 5+
6. **Credential access methods** — we model WHAT to steal but not HOW
