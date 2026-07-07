# EDR Bypass Research Library — Summary

**Total: 12 documents, ~7,700 lines of research**
**Research period: June-July 2026**

---

## Document Index

### Core Reference Documents

| Document | Lines | Description |
|----------|-------|-------------|
| [edr_bypass_research.md](edr_bypass_research.md) | 1,931 | **Primary reference.** 20 specific bypass techniques with C implementations: ETW patching (3 methods), NTDLL unhooking, indirect syscalls, Ekko/FOLIAGE/DeathSleep sleep obfuscation, call stack spoofing, LACUNA Chain, module stomping, HW BP evasion, Pool Party, thread hijacking, callback/fiber execution, process ghosting, AMSI bypass, EDR preloading, Dirty Vanity, threadless injection, PE metadata stripping, Elastic Defend gadget bypass. Each technique has working C code, detection risk rating, and implementation notes. |
| [edr_architecture_deep_dive.md](edr_architecture_deep_dive.md) | 1,989 | **How EDRs actually work.** Exhaustive coverage of every EDR layer: kernel callbacks (Ps/Ob/Cm/minifilter), ETW consumers (which providers, which events), usermode hooks (trampoline/IAT/EAT), minifilter architecture (altitude numbers, IRP interception), network filtering (WFP, NDIS), memory scanning (triggers, algorithms, timing), telemetry pipeline (kernel→usermode→cloud latency), protected processes (PP/PPL levels), and behavioral detection engines. |
| [edr_fundamental_limits.md](edr_fundamental_limits.md) | 743 | **Why bypasses will always exist.** Formal analysis of 11 fundamental EDR limitations: TOCTOU gaps, performance constraints, usermode trust boundary, LOLBin overlap, encrypted traffic blindness, cloud dependency, kernel/usermode detection asymmetry, AI/ML limits, VBS/HVCI partial mitigation, and the infinite cat-and-mouse cycle. Concludes with a formal argument that EDR bypasses are theoretically unlimited. |

### Technique & Strategy Documents

| Document | Lines | Description |
|----------|-------|-------------|
| [cutting_edge_evasion_2024_2026.md](cutting_edge_evasion_2024_2026.md) | 467 | **New techniques not in the primary reference.** 13 topics: BYOVD (LOLDrivers, driver exploitation), DKOM (process hiding), ETW-TI kernel provider attacks, PPL abuse (PPLFault, PPLmedic), kernel callback removal, AI/ML model evasion (adversarial ML), Defender exclusion abuse, WSL2/container blind spots, COM/DCOM execution primitives, telemetry flooding, certificate/trust abuse, reflective DLL evolution, Windows 11 24H2 new API abuse. |
| [kernel_vs_usermode_evasion.md](kernel_vs_usermode_evasion.md) | 288 | **Comparative analysis.** Full taxonomy of usermode evasion (5 categories: hook bypass, telemetry blinding, execution primitive abuse, memory evasion, identity/trust) vs kernel evasion (4 categories: callback manipulation, driver/minifilter, kernel telemetry, object manipulation). Detection asymmetry analysis. Arms race timeline 2018→2026+. Longevity ratings for each technique. 4-layer recommended evasion strategy for our framework. |
| [reverse_engineering_edrs.md](reverse_engineering_edrs.md) | 867 | **How to find NEW bypasses.** Methodology for reverse engineering EDR products: static analysis (Ghidra/IDA on .sys drivers and usermode DLLs), dynamic analysis (WinDbg, Frida, API Monitor), gap analysis techniques, IOCTL fuzzing, timing analysis. Open source tool survey (EDRSandblast, SysWhispers3, HellsGate/HalosGate/TartarusGate, PPLdump/Fault/medic, TelemetrySourcerer, SilkETW, Sealighter). Lab setup guide. Case studies of CrowdStrike, SentinelOne, Elastic, MDE internals. |
| [edr_detection_gaps_2026.md](edr_detection_gaps_2026.md) | 316 | **Actionable blind spots.** Under-monitored Windows APIs (newer Nt variants, undocumented syscalls), file system blind spots (TxF, ADS, junction abuse), process trust gaps (which processes get reduced scrutiny), temporal blind spots (boot window, sleep/wake, EDR update gaps), network protocol gaps (DoH, QUIC, cloud service tunneling), memory scanning limitations (timing, triggers, algorithm limits), EDR self-protection weaknesses, configuration-based gaps. Testing methodology for building a detection coverage matrix. |
| [edr_bypass_tools_ecosystem.md](edr_bypass_tools_ecosystem.md) | 233 | **Tool survey.** Syscall tools (SysWhispers 1-3, HellsGate, HalosGate, TartarusGate, FreshyCalls). Kernel tools (EDRSandblast, EDRSilencer, Backstab, CallbackHell, Terminator). PPL tools. Telemetry tools. C2 frameworks (Cobalt Strike, Brute Ratel, Sliver, Havoc, Mythic) with current detection status. Testing frameworks (Atomic Red Team, Caldera). Detection matrix: custom implementations vs known tools. |

### Supplementary Documents (Pre-existing)

| Document | Lines | Description |
|----------|-------|-------------|
| [evasion_techniques.md](evasion_techniques.md) | 347 | Earlier evasion technique notes — partially superseded by edr_bypass_research.md |
| [falcon_bypass_analysis.md](falcon_bypass_analysis.md) | 107 | CrowdStrike Falcon-specific bypass analysis |
| [specterops_analysis.md](specterops_analysis.md) | 222 | SpecterOps offensive research analysis |
| [edr_testing_plan.md](edr_testing_plan.md) | 231 | Testing plan for EDR evasion validation |

---

## Key Findings from This Research Period

### 1. EDR bypasses are fundamentally unlimited
Every detection mechanism is software running on the same system as the attacker. Software has bugs, new features create new attack surface, and the attacker only needs to succeed once while the defender must be correct every time. This is not a temporary gap — it's structural. (See: `edr_fundamental_limits.md`)

### 2. Custom implementations beat known tools every time
The detection matrix shows: known tools (EDRSandblast, SysWhispers, Cobalt Strike) are heavily detected. The same TECHNIQUES reimplemented in custom code are largely undetected. Our framework's advantage: unique code per-build, no shared signatures with any public tool. (See: `edr_bypass_tools_ecosystem.md`)

### 3. Usermode evasion is sufficient for most targets
Full kernel-level evasion (BYOVD, callback removal) is powerful but risky (driver loading is detectable, PatchGuard crashes). Stacking 4-6 usermode techniques (ETW patch + NTDLL unhook + sleep encryption + behavioral pacing + string encryption + indirect syscalls) defeats most EDRs without kernel access. Our framework already implements all of these. (See: `kernel_vs_usermode_evasion.md`)

### 4. The biggest gap is "what EDRs DON'T monitor"
Under-monitored APIs (newer Nt variants, COM objects), temporal blind spots (boot/update windows), and network protocol gaps (DoH, cloud service tunneling) are more reliably exploitable than trying to bypass what EDRs DO monitor. (See: `edr_detection_gaps_2026.md`)

### 5. Finding new bypasses is systematic, not creative
Reverse engineering EDR products follows a repeatable methodology: enumerate what's monitored, compare against the full API surface, identify gaps, test assumptions. The gap between "what Windows offers" and "what EDRs monitor" is vast and growing with each Windows update. (See: `reverse_engineering_edrs.md`)

### 6. VBS/HVCI is the most impactful defense advancement
Virtualization-based security significantly limits kernel-level attacks but doesn't eliminate them (BYOVD data corruption, firmware attacks). Adoption is growing but incomplete (~40-50% of enterprise Win11). Usermode evasion techniques are unaffected by VBS/HVCI. (See: `kernel_vs_usermode_evasion.md` § 5)

### 7. AI/ML detection is fundamentally brittle against adaptive adversaries
EDR ML models are trained on historical malware. Feature manipulation, temporal spacing, and behavioral mimicry can shift classification. The false-positive pressure limits how aggressive ML models can be. (See: `cutting_edge_evasion_2024_2026.md` § 6)

---

## Recommended Next Steps for the Framework

Based on this research:

1. **Already implemented (Layer 1-2):** String encryption, ETW patch, NTDLL unhook, sleep encryption (Ekko), indirect syscalls, behavioral pacing, HW BP ETW — all working and VM-tested

2. **Should implement next:**
   - Call stack spoofing (defeats EDR stack analysis on suspicious API calls)
   - COM-based execution primitives (execute from trusted process context)
   - Cloud service C2 channels (Graph API, DoH — harder to block)
   - Header stomping post-load (defeat memory scanners looking for PE headers)

3. **Research needed:**
   - Set up EDR testing lab with CrowdStrike/SentinelOne trial licenses
   - Build detection coverage matrix for all 37 recipes against each EDR
   - Reverse engineer Elastic Defend's specific hook list and callback registrations
   - Identify Windows 11 24H2 new APIs not yet covered by EDR rules
