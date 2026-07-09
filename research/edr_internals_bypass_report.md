# EDR Internals & Bypass Research Report

Source: https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/

## Summary

Comprehensive 4-part article covering EDR architecture (kernel callbacks, ETW,
minifilters, WFP, inline hooks), detection techniques (VAD scanning, memory
heuristics, parent-child lineage), bypass/evasion methods (syscalls, sleep
obfuscation, call-stack spoofing, AMSI bypass, BYOVD), and an 8-phase research
methodology for reverse-engineering specific EDR products.

Key takeaway: **user-mode bypass is "solved tradecraft"** — the hard problem is
kernel-mode telemetry (ETW-TI, kernel callbacks, minifilters) which persists
regardless of what you do in userspace.

---

## What Our Framework Already Has

| Technique | Our Implementation | Status |
|---|---|---|
| API hashing (DJB2) | `api_resolve/api_hash_djb2.c` | Working, validated |
| PEB walk (no LoadLibrary) | `api_resolve/peb_walk.c` | Working, validated |
| Indirect syscalls | `evasion/indirect_syscall.c` | Working, validated |
| PPID spoofing (6 targets) | `process/ppid_spoof_*.c` | Working, 6 variants |
| ETW patching | `evasion/etw_patch.c` | Working, validated |
| NTDLL unhooking | `evasion/unhook_ntdll.c` | Working, validated |
| Anti-debug | `evasion/anti_debug.c` | Working, validated |
| Anti-VM | `evasion/anti_vm.c` | Working (kills payload in QEMU) |
| Anti-sandbox | `evasion/anti_sandbox.c` | Working, validated |
| Sleep jitter/encrypt | `evasion/sleep_jitter.c`, `evasion/sleep_encrypt.c` | Working |
| Header stomping | `evasion/header_stomp.c` | Working, validated |
| String encryption (XOR/AES) | Obfuscation pass | Working |
| LOLBin exfil (6 methods) | `exfil/certutil_lolbin.c`, etc. | Working, 6 variants |
| Callback-based execution | 5 callback arch chunks | Working, 5 variants |
| Behavioral pacing | `evasion/behavioral_pacing.c` | Working |

We already cover the fundamentals well. The article confirms our approach is sound.

---

## Implementable Techniques (New)

### Priority 1: High-Value, Directly Implementable

#### 1. FNV-1a API Hashing (new hash variant)

We have DJB2 and CRC32. The article provides a complete FNV-1a implementation.
Adding this as a third hash algorithm makes the API resolution layer more
diverse — EDR rules targeting DJB2 hash constants won't match FNV-1a.

**Implementation**: New chunk `api_resolve/api_hash_fnv1a.c`
**Effort**: Low — article provides complete C code
**Value**: One more option in the api_resolve layer; different hash constants in
binary means different static signatures

#### 2. Patchless AMSI Bypass via Hardware Breakpoints

Our current `evasion/etw_patch.c` patches `EtwEventWrite` in memory. The article
describes a patchless alternative using hardware breakpoints + VEH that leaves
`amsi.dll` binary completely unmodified. This is significantly stealthier because
memory-integrity scanners that hash `.text` against on-disk file won't detect it.

**Implementation**: New chunk `evasion/amsi_hwbp.c`
**Effort**: Medium — article provides complete C code (VEH handler + DR0/DR7 setup)
**Value**: Defeats memory-integrity-based AMSI bypass detection. Our current
approach modifies bytes in memory which modern EDRs specifically scan for.

Key detail from article: use `NtContinue` instead of `SetThreadContext` to install
debug registers — `SetThreadContext` with `CONTEXT_DEBUG_REGISTERS` produces an
`EtwTiLogSetContextThread` event, while `NtContinue` does not.

#### 3. Module Stomping

Load a legitimate signed DLL, overwrite its `.text` section with our payload code,
restore `PAGE_EXECUTE_READ`. The executable region appears image-backed (defeating
the "unbacked executable private commit" detection heuristic that catches our
current `VirtualAlloc` + shellcode patterns).

**Implementation**: New chunk `evasion/module_stomp.c`
**Effort**: Medium — requires finding a suitable legitimate DLL, VirtualProtect
sequence, and careful size management
**Value**: Defeats VAD-based memory scanning (MEM_IMAGE vs MEM_PRIVATE detection).
Article explicitly calls out "unbacked executable private commit" as high-signal
detection indicator.

#### 4. Control-Flow Obfuscation (Junk Code Insertion)

The article describes inserting bogus conditional branches that are always/never
taken, disrupting linear disassembly. We can implement this as a source-level
transform in our obfuscation pass.

**Implementation**: Enhancement to obfuscation pass in evasion_selector.py
**Effort**: Low-medium — insert `if (volatile_zero) { __asm__("int3"); }` style
blocks between function calls
**Value**: Defeats pattern-matching disassemblers and some ML classifiers that
analyze control-flow graphs

#### 5. Section Name Randomization

PE section names (`.text`, `.data`, `.rdata`) are default giveaways. Renaming them
to random strings defeats YARA rules matching on section names.

**Implementation**: Post-compile PE manipulation or MinGW linker script
**Effort**: Low — `objcopy --rename-section .text=.qx0a` or linker `-Wl,--section-rename`
**Value**: Defeats section-name-based YARA rules; per-build randomization means
each binary has unique section fingerprint

### Priority 2: Valuable but More Complex

#### 6. Sleep Obfuscation (Ekko-style)

For persistent payloads (backdoor, keylogger), encrypt the entire implant memory
during sleep intervals. The article describes Ekko (timer queue + ROP via
NtContinue): encrypt memory → set PAGE_NOACCESS → sleep → decrypt → restore
PAGE_EXECUTE_READ.

**Implementation**: New chunk `evasion/sleep_obfuscate_ekko.c`
**Effort**: High — requires timer queue creation, CONTEXT manipulation,
NtContinue ROP chain. The article provides the mechanism but not complete
compilable code.
**Value**: Very high for persistent payloads. Memory scans during sleep see
encrypted, non-executable bytes. Currently our sleep_encrypt.c does basic XOR
of buffers, not full Ekko-style ROP-based memory encryption.
**Detection note**: Detectable via ETW-TI VirtualProtect frequency analysis and
CFG enforcement. But significantly harder than detecting current approach.

#### 7. Call Stack Spoofing

When our payload calls sensitive APIs, the return address on the stack points into
our (unbacked, private) memory region. EDR kernel callbacks walk the stack and
flag this. Stack spoofing fabricates frames that point into legitimate DLLs.

**Implementation**: New chunk `evasion/stack_spoof.c`
**Effort**: High — requires either synthetic frame construction (VulcanRaven
approach) or desynchronized unwinding (SilentMoonwalk). Both need careful x64
unwind-info management.
**Value**: High — defeats kernel callback stack-walk analysis. Currently our
payloads have "honest" stacks that point directly into private memory.
**Detection note**: SilentMoonwalk specifically targeted by recent EDR signatures.
Synthetic frame approach simpler but less robust.

#### 8. Process Ghosting

Create file → write payload → mark for deletion → create section from pending-
delete file → create process from section. When EDR's image-load callback fires,
the originating file no longer exists at any path.

**Implementation**: New chunk `process/process_ghost.c`
**Effort**: High — requires `NtCreateSection`, `NtCreateProcessEx`, `NtCreateThreadEx`
with careful handle management
**Value**: Defeats all signature-based static scanners that read the on-disk file.
EDR sees the process but can't find the binary to scan.

#### 9. WFP Awareness (Network Evasion)

The article explains how EDR uses WFP callout filters to inspect network traffic.
Our exfil chunks could be made WFP-aware — detecting if WFP filters are present
and routing traffic through less-monitored layers.

**Implementation**: Enhancement to exfil chunks — check for WFP filters before
choosing exfil method
**Effort**: Medium — `FwpmFilterEnum` to detect active filters
**Value**: Medium — helps choose between TCP (heavily monitored) vs DNS (less
monitored via WFP) at runtime

### Priority 3: Research-Grade, Not Directly Implementable Yet

#### 10. BYOVD (Bring Your Own Vulnerable Driver)

Load a signed-but-vulnerable driver to get kernel write access, then zero out
EDR callback registrations, modify EPROCESS protection level, etc. The nuclear
option — completely silences the EDR.

**Status**: Not implementable as a chunk because:
- Requires a specific vulnerable driver binary (signed .sys file)
- Microsoft's vulnerable-driver blocklist blocks known drivers
- HVCI (enabled by default on Win 11 22H2+) prevents kernel memory modification
- Our framework targets user-mode evasion, not kernel exploitation

**Use case**: Research/documentation only. Worth knowing about for understanding
what advanced threat actors do, but not practical for our chunk framework.

#### 11. ETW-TI Consumer Without PPL

The article mentions a 2026 technique using `EtwEnumerateProcessRegGuids` to
consume TI events without PPL elevation. This is more of a detection tool than
an evasion technique — useful for building better detection rules, not for
evading them.

#### 12. Phantom DLL Hollowing

Variant of module stomping using NTFS transaction rollback. Creates section
from transacted file view, rolls back transaction. Very stealthy but requires
Transactional NTFS which is deprecated and monitored.

---

## What the Article Confirms About Our Approach

### 1. Our PPID Spoofing Is Sound but Limited

The article notes that EDR's process-creation kernel callback receives the
**true parent PID** from the kernel, not the spoofed one. PPID spoofing fools
user-mode tools (Process Explorer, tasklist) but NOT kernel callbacks.

However, the article also confirms PPID spoofing still has value: it affects
process-lineage detection rules that fire on parent-child relationships as seen
in Sysmon events (which reflect the spoofed parent for some event types).

### 2. Our Callback-Based Execution Is a Good Pattern

The article lists `APC injection` and `callback abuse` as techniques that avoid
`CreateRemoteThread` and therefore bypass the thread-creation kernel callback.
Our 5 callback variants (EnumWindows, CertEnumSystemStore, CopyFile2,
EnumResourceTypes, CreateTimerQueueTimer) execute code without creating new
threads or processes — confirmed as sound approach.

### 3. Our LOLBin Exfil Has a Blindspot

The article emphasizes that LOLBin execution is detected via parent-child process
relationships: `our_payload.exe → certutil.exe` is anomalous. Our framework
already accounts for this (LOLBin exfil is rated "medium" risk), but the article
provides the specific detection mechanism — **Sysmon EID 1 with parent process
matching**. Our evasion selector correctly deprioritizes LOLBin methods when
Sysmon is enabled.

### 4. String Encryption Is Table Stakes

The article treats string encryption as baseline ("compile-time string and code
encryption" in the static evasion section). Our XOR/AES string encryption is
the minimum viable approach. The article's recommendation: encrypt at build time,
decrypt into stack buffer, zero after use. Our obfuscation pass does exactly this.

### 5. Direct Syscalls Bypass User-Mode Hooks Only

The article explicitly states: "Direct and indirect syscalls evade user-mode hook
inspection only; kernel-mode notification callbacks, ETW-TI emissions, and memory
scanning remain operational." This validates our layered approach — indirect
syscalls alone aren't enough, you need behavioral evasion (timing, pacing,
callback execution) too.

---

## Recommended Implementation Order

1. **FNV-1a API hashing** — trivial, instant diversity gain
2. **Section name randomization** — trivial post-compile step
3. **Control-flow junk insertion** — low effort, defeats pattern matchers
4. **Patchless AMSI bypass (hardware breakpoints)** — medium effort, high stealth
5. **Module stomping** — medium effort, defeats VAD scanning
6. **Ekko sleep obfuscation** — high effort, critical for persistent payloads
7. **Call stack spoofing** — high effort, defeats kernel stack walks

Items 1-3 could be implemented in a few hours and immediately increase diversity.
Items 4-5 are medium-effort but provide significant evasion improvements against
memory-scanning EDRs. Items 6-7 are research-grade and would take dedicated effort.

---

## Implementation Status (Updated 2026-07-08)

### Implemented

| # | Technique | Chunk/Feature | Status |
|---|---|---|---|
| 1 | FNV-1a API hashing | `api_resolve/api_hash_fnv1a.c` | Created, compile-tested, registered in LAYERS |
| 2 | Patchless AMSI bypass (hwbp) | `evasion/amsi_hwbp.c` | Created, registered as `etw_method: hwbp_both` |
| 3 | Module stomping | `evasion/module_stomp.c` | Created, registered as `memory_residence: module_stomp` |
| 4 | Ekko sleep obfuscation | `evasion/sleep_ekko.c` | Created, registered as `sleep_mode: ekko` |
| 5 | Section name randomization | `assembler.py:randomize_section_names()` | Auto-applied to every compiled binary |
| 6 | Call stack spoofing | `evasion/ret_spoof.c` (pre-existing) | Wired into LAYERS as `stack_presentation: ret_spoof` |
| 7 | HW breakpoint ETW bypass | `evasion/hw_bp_etw.c` (pre-existing) | Wired into LAYERS as `etw_method: hwbp_etw` |

| 8 | Control-flow junk insertion | `evasion_passes.py:_inject_control_flow_junk()` | Opaque predicates + dead API branches, wired into obfuscation pipeline |
| 9 | Process ghosting | `process/process_ghost.c` | Created, registered as `process: process_ghost` in LAYERS + 4 strategy archetypes |

### Impact on Framework

- **Evasion layers**: 8 → 12 (added etw_method, memory_residence, stack_presentation, sleep_mode)
- **Base combinations**: 4,320,000 → 358,400,000 (83x increase)
- **Process layer**: 9 → 10 options (added process_ghost)
- **Tier 1 selection**: Replaced linear escalation with 5 strategy archetypes per type
- **Post-compile transforms**: Added section name randomization (per-build unique PE sections)
- **Obfuscation pipeline**: Added control-flow junk insertion (opaque predicates + dead API calls)
- **All 20 strategy archetypes compile clean** (5 per type × 4 types)
