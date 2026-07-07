# Chunk Framework vs Malgen Skill: Strategic Analysis

## The Question

Why maintain a deterministic chunk assembler when malgen skill (Claude) can write
adaptive, novel malware code? Won't the LLM always be smarter?

## Short Answer

They solve different problems. The chunk framework is a breadth tool (systematic,
fast, cheap). Malgen skill is a depth tool (creative, adaptive, expensive). Neither
replaces the other. The real value emerges from the loop between them.

## Detailed Comparison

### Chunk Framework (Framework 1)

**What it is:** Recipe YAML -> assembler.py -> single .c file -> obfuscate -> compile.
Pre-written, hand-verified C chunks wired together deterministically.

**Strengths:**
- **Speed:** Binary in ~5 seconds. No LLM call. No network latency.
- **Cost:** Zero marginal cost per build. Test 50 variants for free.
- **Reproducibility:** Same recipe -> identical binary, every time. Critical for
  A/B testing evasion. Change one layer, hold everything else constant, measure
  the effect. This is impossible with LLM generation.
- **Compile reliability:** 49/50 recipes compile clean (98%). LLM-generated C
  fails to compile ~30% of the time due to type mismatches, missing headers,
  MinGW-specific issues.
- **Combinatorial coverage:** 8 evasion layers x 3-6 options each = thousands of
  unique combinations. The evasion selector can systematically sweep this matrix.
  Malgen skill would need thousands of expensive API calls.
- **Operational speed:** Real engagement, need a binary now. Upload recipe, get
  .exe in 10 seconds, deploy. Not "wait 3 minutes for Claude to reason."

**Weaknesses:**
- Limited to existing chunks. Can't invent techniques.
- Evasion selector is algorithmic (Tier 1) or local-LLM-guided (Tier 2), not
  deeply creative.
- Novel EDR signatures that bypass all existing chunks = dead end.
- No architectural reasoning about WHY a detection fires.

### Malgen Skill (Framework 2)

**What it is:** Claude reads the detection signal, reasons about it, writes
evasion-hardened C code from scratch. Full creative freedom.

**Strengths:**
- **No ceiling:** Can invent techniques that don't exist in any corpus.
- **Adaptive reasoning:** "Falcon caught this because of the LDAP query sequence
  after schtasks execution. If I interleave legitimate API calls between LDAP
  calls and use a different execution trigger..." -- this kind of causal reasoning
  is beyond what the chunk selector can do.
- **Novel technique discovery:** Can combine ideas from the malware corpus
  (23,000+ technique docs, 30,000+ PoC exploits) in ways no human pre-encoded.
- **Architecture-level changes:** Can fundamentally restructure payload flow,
  not just swap modules.

**Weaknesses:**
- **Slow:** 2-5 minutes per generation attempt.
- **Expensive:** API tokens per attempt. 50 attempts = significant cost.
- **Non-deterministic:** Same prompt -> different code. Can't isolate variables.
  Did it pass because of the new technique or because the LLM happened to
  structure the code differently?
- **Compilation failures:** ~30% of generated C code doesn't compile under MinGW.
  Missing headers, MSVC-isms, wrong casts, using GNU extensions.
- **Regression risk:** Each new generation might lose a working technique from
  the previous iteration.

## The Flywheel Model

The real architecture isn't "pick one." It's a feedback loop:

```
    Chunk Framework                    Malgen Skill
    (breadth, speed)                   (depth, creativity)
         |                                  |
         |  1. Map detection landscape      |
         |     fast and cheap               |
         |                                  |
         +----------> detection signal ---->+
                                            |
                       2. Reason about WHY  |
                          detection fires,  |
                          invent novel      |
                          bypass            |
                                            |
         +<-------- new technique <---------+
         |
         |  3. Encode as new chunk
         |     (hand-verify, add to matrix)
         |
         |  4. Now the framework includes
         |     this technique in ALL future
         |     combinatorial sweeps, forever.
         |     Zero additional cost.
         |
         +----------> (repeat) ----------->+
```

Each cycle makes the chunk framework more capable without making it slower or
more expensive. The malgen skill focuses its expensive reasoning on the frontier
-- the detection signals that existing chunks can't handle.

## When to Use Each

### Use chunk framework when:
- **First pass on a target:** Rapid iteration to find what works. 50 combos in
  10 minutes establishes a baseline.
- **Known EDR:** Defender, Wazuh, CrowdStrike patterns already have chunks that
  handle them. No need to reinvent.
- **Batch testing:** Systematic evasion matrix sweep. Which layers get caught,
  which don't.
- **Operational deployment:** Need a binary NOW. Recipe -> compile -> deploy in
  seconds.
- **Regression testing:** After updating chunks, verify all 50 recipes still pass.
  Automated, deterministic.
- **Training signal:** Generate detection/evasion data that feeds into malgen
  skill prompts. "These 5 approaches got caught by Sigma rule X, these 3
  didn't. Here's why."

### Use malgen skill when:
- **Chunk framework hits a wall:** All combinations detected. Need novel approach.
- **Unknown EDR behavior:** New detection engine, need creative probing.
- **Post-detection analysis:** "CrowdStrike blocked the payload at the memory
  scan stage. The behavioral pacing wasn't enough -- need sleep obfuscation
  with memory encryption." This causal chain requires reasoning.
- **Pushing the ceiling:** Research-grade evasion. Techniques not in any public
  corpus.
- **Complex multi-stage payloads:** Staged execution, process injection chains,
  reflective loading -- where architectural decisions matter more than
  individual chunks.

### Use both together when:
- **Target has layered detection:** Chunk framework handles Defender+Sysmon
  baseline. Malgen skill handles the CrowdStrike Falcon cloud ML layer that
  the chunks can't model.
- **Engagement with iteration time:** Day 1: chunk framework maps the surface.
  Day 2: malgen skill attacks the gaps. Day 3: encode wins as chunks.
- **Building the corpus:** Every malgen skill success should become a chunk.
  Every chunk failure should become a malgen skill prompt.

## Concrete Example

**Scenario:** Keylogger detected by CrowdStrike Falcon (cloud ML behavioral).

**Chunk framework alone:** Tries all 12 keylogger recipes. 8 get caught. 4 pass.
Identifies that `GetAsyncKeyState` + `LOLBin exfil` + `behavioral_pacing` is the
winning combination. Total time: 20 minutes. Cost: $0.

**Malgen skill alone:** Writes evasion-hardened keylogger. First attempt: compile
error. Second attempt: detected. Third attempt: passes but used a technique the
framework already had (wasted $). Fourth attempt: novel technique (callback-based
key capture via `SetWindowsHookEx` with `WH_CALLWNDPROC` instead of
`WH_KEYBOARD_LL`). Total time: 15 minutes. Cost: ~$2 in API tokens.

**Both together:** Chunk framework identifies the winning base in 20 minutes.
Malgen skill is told: "This base works. Now make it better -- Falcon's cloud ML
might catch the `GetAsyncKeyState` polling pattern in production. Find an
alternative capture method." Malgen skill focuses on the ONE hard problem instead
of reinventing everything. Finds the `WH_CALLWNDPROC` approach in one attempt.
New chunk created: `collectors/keylogger_callwnd.c`. Framework now has 13
keylogger recipes. Total time: 25 minutes. Cost: ~$0.50.

## The "Always Adapt" Argument

> "Malgen skill is always gonna adapt, it's smarter, it has potential to find
> new techniques whereas the framework doesn't."

This is true but incomplete:

1. **Adaptation has a cost.** Every adaptation attempt costs time and money.
   The chunk framework's "non-adaptive" approach is actually adaptive -- it
   adapts by recombination, which is free. The evasion selector's 50-run loop
   explores more of the solution space than 5 malgen skill attempts, for less
   cost.

2. **Discovery without retention is waste.** If malgen skill finds a novel
   technique but it's not encoded as a chunk, you lose it. Next session,
   Claude might not rediscover it. The chunk framework IS the retention layer.

3. **Smartness doesn't scale.** Malgen skill is smarter per-attempt, but you
   can't run 50 of them in parallel (cost, LLM contention). The chunk framework
   can test 50 variants in the time malgen skill tests 1.

4. **Reproducibility matters for security testing.** "Did the payload change
   because we improved evasion, or because the LLM generated different code?"
   With chunks, you know exactly what changed. With malgen skill, you're
   reasoning about a black box generating a black box.

## Recombination Defeats Patch Cycles

This is arguably the chunk framework's most important property.

When an EDR vendor "patches" a technique, they don't block the underlying
primitive. They can't — `GetAsyncKeyState`, `SetWindowsHookEx`, `CreateFileA`,
`send()` are all legitimate APIs used by millions of programs. What they block
is a *behavioral signature*: a specific combination of indicators observed
together.

Example detection rule (modeled after real CrowdStrike Falcon logic):
```
IF process_parent == "schtasks.exe"
AND api_call_sequence CONTAINS "GetAsyncKeyState" at >50Hz
AND network_connection TO non-standard port
AND no_valid_signature
THEN flag as "Keylogger/Behavioral"
```

This rule catches ONE combination. The chunk framework has that `GetAsyncKeyState`
polling as a chunk, and when this combination gets caught, the evasion selector
automatically recombines it:

- Same keylogger chunk + different trigger (callback abuse instead of schtasks)
- Same keylogger chunk + different exfil (HTTP POST to port 443 instead of raw TCP)
- Same keylogger chunk + behavioral pacing (polling at 10Hz instead of 50Hz)
- Same keylogger chunk + all three changes at once

The "patched" technique is alive again. The detection rule fires on the old
signature and misses the new combination. The vendor now has to write another
rule for THIS combination. They patch that, the framework recombines again.

This is asymmetric warfare in the defender's worst direction:

- **Vendor cost per patch:** analyst time to write + test + deploy a rule
- **Framework cost per recombination:** zero (already in the matrix)
- **Combinations that need patching:** grows multiplicatively with each new chunk
- **Combinations the framework can test:** all of them, in minutes

This is exactly how real-world malware families operate. Emotet's core DLL
injection has been "patched" a dozen times. Each time they tweak one surrounding
element — different parent process, different timing, different C2 protocol — and
the core technique sails through. QakBot, IcedID, and BumbleBee all reuse the
same injection primitives with different behavioral wrappers.

The chunk framework codifies this pattern. Every "dead" technique stays in the
matrix because it's only dead in one specific context. Recombination resurrects
it automatically.

**Malgen skill can't do this efficiently.** It would have to independently reason:
"Wait, that old technique might work if I change the surrounding context." It
might. It might not. It has no systematic way to test every combination. The
chunk framework tests all of them as a side effect of its normal operation.

**The flywheel effect compounds:** Every new chunk added to the framework doesn't
just add one new capability. It multiplies the number of untested combinations
across ALL existing chunks. Adding one exfil method creates N new combinations
with every existing collector, architecture, and evasion layer. The defender's
patch burden grows geometrically while the framework's cost stays constant.

## Bottom Line

The chunk framework is not a worse version of malgen skill. It's a different
tool for a different job. Together they form a complete system:

- **Chunk framework:** systematic, fast, cheap, reproducible, stores knowledge,
  defeats patch cycles through recombination
- **Malgen skill:** creative, adaptive, expensive, novel, discovers knowledge,
  pushes past ceilings the framework can't reach

Kill either one and you lose something irreplaceable. The framework without
malgen skill has a ceiling. Malgen skill without the framework has no memory.

## Telemetry-Aware Composition

The chunk framework's evasion selector currently picks combinations based on
risk scores (per-layer detection probability). This works but treats each layer
independently. The telemetry dependency map (`templates/chunks/telemetry_map.py`)
adds a deeper model: **target the telemetry sources, not the detection rules**.

### The Model

EDR detections are built on telemetry providers:

| Telemetry Source | What it sees | Suppressible? |
|---|---|---|
| ETW Threat Intelligence | Memory alloc, thread injection, image loads | Yes (etw_patch, hw_bp_etw) |
| Usermode Hooks (ntdll) | Syscall stubs — NtAllocateVirtualMemory etc. | Yes (unhook_ntdll, indirect_syscall) |
| Sysmon Process Create | Process creation, parent PID, cmd line | No (kernel driver) |
| Sysmon Network | Outbound connections | No (kernel driver) |
| ETW Process Provider | Process start/stop | Yes (etw_patch) |
| Kernel Callbacks | PsSetCreateProcessNotifyRoutine | No (kernel-level) |
| Filesystem Minifilter | File I/O at kernel level | No (kernel driver) |

### Why This Matters

A single evasion chunk can blind multiple detection rules simultaneously.
`etw_patch` doesn't just evade one Sigma rule — it suppresses the entire ETW-TI
provider, which means every detection rule built on ETW-TI events goes dark:
process hollowing, APC injection, fiber execution, DLL sideloading. One chunk,
four technique categories invisible.

Conversely, some telemetry sources can't be suppressed from usermode (Sysmon
kernel driver, minifilter, kernel callbacks). Techniques observed only by these
sources need behavioral camouflage (timing, process choice, PPID spoofing)
rather than telemetry suppression.

### Composition Strategy

The optimal combination targets shared telemetry roots:

1. **Suppress what you can:** `etw_patch` + `unhook_ntdll` = ETW-TI + AMSI +
   usermode hooks + ETW Process all go dark. 4 telemetry sources suppressed.
2. **Choose techniques that benefit:** `process_hollow` (observed by ETW-TI +
   usermode hooks, now both blind) becomes invisible. `callback_certenumsystem`
   (observed by Sysmon process create, unsuppressible) still needs behavioral
   camouflage.
3. **Camouflage what remains:** For techniques visible through unsuppressible
   kernel-level telemetry, use PPID spoofing (svchost parent = noise),
   behavioral pacing (human-like timing), and benign-looking exfil
   (HTTPS POST to /api/v1/telemetry).

### Scoring

`telemetry_map.score_combination()` returns a float from 0.0 (fully blind) to
1.0 (fully observed). The evasion selector can use this to prefer combinations
that minimize remaining telemetry coverage:

```
# No evasion, basic techniques: 1.00 (fully visible)
score_combination([], ["sequential", "tcp_direct", "standalone"])

# ETW + unhook, same techniques: 0.75 (25% reduction)
score_combination(["etw_patch", "unhook_ntdll"], ["sequential", "tcp_direct", "standalone"])

# Full evasion, stealth techniques: varies by combination
score_combination(["etw_patch", "unhook_ntdll", "indirect_syscall"],
                  ["callback_certenumsystem", "https_post", "ppid_spoof_runtimebroker"])
```

### Integration Path

The next step is wiring `score_combination()` into the evasion selector's Tier 1
(algorithmic) logic. Instead of randomly sampling layer combinations, it would:

1. Generate candidate combinations
2. Score each with `score_combination()`
3. Prefer combinations with lower telemetry coverage scores
4. Still respect risk ordering (don't jump to the stealthiest combination first —
   start minimal and escalate)

This makes the framework's recombination *targeted* rather than random — it
doesn't just try different combinations, it tries combinations that attack the
EDR's observability architecture.
