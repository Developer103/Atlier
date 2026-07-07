# CrowdStrike Falcon Bypass Analysis

## TL;DR
Current framework (both F1 and F2) would get caught by Falcon within seconds. But the framework ARCHITECTURE is exactly right — it just needs new chunks designed for behavioral EDR evasion, not just signature evasion.

## Why Falcon is fundamentally harder than Defender

Defender = signature + cloud ML. Falcon adds three layers:

### 1. Kernel-mode ESP (Event Stream Processing)
- Runs IN THE KERNEL, correlates 1000+ event types in real-time
- Process creation, DLL loads, file I/O, registry access — ALL visible regardless of userland tricks
- Can't be blinded by patching ntdll or AMSI — kernel callbacks fire independently

### 2. Behavioral IOAs (Indicators of Attack)
- Tool/malware-agnostic — doesn't care WHAT binary, cares WHAT IT DOES
- Correlates event CHAINS: "Process A -> GetAsyncKeyState loop -> writes temp file -> spawns cmd.exe -> cmd runs curl -> curl connects to external IP" = textbook keylogger IOA
- LOLBin diversity (9 exfil methods) is irrelevant if the BEHAVIOR CHAIN is the same

### 3. Intel PT (Hardware-level tracing)
- CPU control-flow tracing at hardware level
- 32KB per-thread trace buffers — reconstructs exact execution flow
- Not relevant for keylogger specifically but blocks future escalation paths

## What our current framework WOULD trigger

| Our Technique | Falcon Detection Layer | Verdict |
|---|---|---|
| GetAsyncKeyState polling loop | Behavioral IOA — known keylogger pattern | CAUGHT |
| LOLBin exfil (curl/certutil/etc) | Behavioral IOA — LOLBin abuse is tracked TTP | CAUGHT |
| Child process spawning (cmd /c curl) | Kernel callbacks + ESP chain correlation | CAUGHT |
| Clean 3-DLL IAT | IOC layer only — Falcon barely cares about static PE | Irrelevant |
| Sleep/pacing evasion | Behavioral pacing — delays don't change the chain | Weak |
| Anti-debug/anti-sandbox | Known evasion technique — actually raises suspicion | Counterproductive |
| DNS exfil | ETW monitors all network connections | CAUGHT |
| Direct API (tcp/winhttp) | ETW + kernel callbacks see socket creation | CAUGHT |

## What COULD work against Falcon

Key insight: Falcon detects BEHAVIOR CHAINS, not individual actions. Break the chain or make it look legitimate.

### Tier 1 — Chain-breaking techniques (new chunks needed)

1. **Process injection into legitimate process** — instead of spawning curl.exe, inject into existing browser/svchost that already has network connections. Exfil traffic from trusted process breaks parent->child->network chain.

2. **Input capture without GetAsyncKeyState** — Raw Input API (RegisterRawInputDevices), DirectInput, UI Automation accessibility APIs. Look like legitimate application behavior, not keylogger IOAs.

3. **Exfil without child processes** — in-process networking combined with process injection = no suspicious parent-child relationships. Or abuse existing sync services (OneDrive/Dropbox folder drop -> auto-upload).

4. **Staged execution** — binary does NOTHING suspicious for first 10+ minutes (just decoy work). Then starts slow keylogging with data accumulating locally. Exfil only after hours via single burst. Falcon ESP has correlation windows — long delays may break temporal chain.

### Tier 2 — Advanced (significant new capabilities needed)

5. **Direct syscalls** — skip ntdll, invoke syscall instructions directly. Kernel callbacks still fire but user-mode hooks in sensor's injected DLL are bypassed.

6. **Unhook Falcon's user-mode DLL** — Falcon injects DLL via kernel callbacks. Remapping clean copies or patching hooks. Risky — PPL self-protection makes this hard.

7. **LOL scripts with AMSI bypass** — PowerShell keylogging with AMSI bypass? Risky because Falcon uses hardened ETW + AMSI.

8. **Legitimate software masquerade** — valid cert, legitimate filename, match behavior of known application.

## Framework utility against Falcon

### Framework 1 (chunk system) — Partially useful
- Assembler architecture is perfect — just needs NEW chunk categories
- Current chunks are Defender-grade. Against Falcon, they're starting point not solution
- Need: process injection chunks, alternative input capture chunks, in-process networking, chain-breaking arch chunks
- 339M combination space would grow massively
- LLM-driven selection MORE valuable — Falcon has more detection vectors to navigate

### Framework 2 (LLM pipeline) — More useful for Falcon
- LLM generates novel behavioral patterns not matching known IOAs
- Can produce code mimicking legitimate application behavior
- Better at adapting to behavioral detection — LLM reasons about what looks "normal"
- Weakness: LLM needs falcon_structure.md as context to understand IOA patterns

## Proposed plan

### Phase 1: New chunk categories for Framework 1
- `injection/` — process hollowing, APC injection, DLL injection, thread hijacking
- `capture/` — RawInput, DirectInput, UI Automation (alternatives to GetAsyncKeyState)
- `exfil_stealth/` — OneDrive/Dropbox drop, DNS-over-HTTPS, HTTPS with browser User-Agent
- `chain_break/` — temporal separation, process migration, legitimate-process abuse

### Phase 2: Falcon-aware LLM loop
- Feed falcon_structure.md into LLM context for Framework 2 generation
- Detection feedback from Falcon includes IOA names mapping to architecture doc
- LLM reasons: "IOA X detected chain A->B->C, break link B->C"

### Phase 3: Validation
- Need Falcon test environment (hard — no free trials)
- Alternative: published detection research to predict which techniques survive
- Test against other behavioral EDRs (Elastic, SentinelOne) as proxies

## Bottom line
Current keylogger recipes = caught by Falcon within seconds. Framework ARCHITECTURE (chunk system + LLM selection loop) = exactly right approach. Needs chunks designed for behavioral EDR evasion, not just signature evasion. The 339M search space targeting Defender needs to become a search space targeting behavior chains.

## How the 339M combinations work
NOT brute force. LLM-driven intelligent selection:
1. First run: LLM picks recipe based on target env (available binaries, OS, EDR)
2. If caught: detection details (ThreatID, rule name) fed back to LLM
3. LLM analyzes WHY caught (static sig? behavioral IOA? hash?) and picks DIFFERENT chunk combination
4. Repeat until evasion succeeds

The LLM also handles obfuscation:
- Framework 1: rule-based evasion passes (string encrypt, control flow, junk) via evasion_passes.py, PLUS LLM can rewrite functions with novel obfuscation when rule-based fails
- Framework 2: LLM generates code with obfuscation baked in — reasons about what looks suspicious vs normal
