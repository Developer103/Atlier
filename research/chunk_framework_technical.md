# Chunk Framework: How It Works and Why It Beats Malgen Skill

## What the Framework Actually Does

The chunk framework generates unique, undetectable Windows malware by
assembling pre-written C modules into complete binaries. It's a mix-and-match
system with 8 independent evasion layers, where each layer has 5-16 options
that can be freely combined.

### The Assembly Process

```
Recipe YAML  →  assembler.py  →  single .c file  →  obfuscation  →  compile  →  deploy  →  test
```

1. **Recipe** defines which chunks to include: collectors, exfil method,
   execution architecture, evasion techniques, persistence
2. **Assembler** reads each chunk file, extracts headers/libs from metadata
   comments, concatenates the bodies, wires placeholder substitutions
   (`{{COLLECTOR_CALLS}}`, `{{COMMAND_DISPATCH}}`)
3. **Obfuscation** applies string encryption (XOR/AES), API name mangling,
   and identifier randomization to the assembled source
4. **Compilation** via MinGW cross-compiler: `-mwindows` (no console window),
   `-static` (no DLL deps), `-s -Wl,--strip-all` (no symbols)
5. **Deploy** to Windows 11 VM via SSH + schtasks
6. **Test** against full detection stack: Defender + Wazuh + Sysmon + 3,009
   Sigma rules (via Chainsaw)

### The 8 Evasion Layers

Each layer controls one dimension of the binary's behavioral signature:

| Layer | Options | What It Controls |
|---|---|---|
| **api_resolve** (6) | direct_import, loadlibrary, api_hash_djb2, api_hash_crc32, peb_walk, indirect_syscall | How Windows APIs appear in the binary. Direct imports leave names in the PE import table. Hash resolution hides them. Indirect syscalls bypass usermode hooks entirely. |
| **execution** (10) | sequential, threaded, staged, fiber, callback_abuse, callback_enumwindows, callback_certenumsystem, callback_copyfile2, callback_enumrestype, apc_self | How collector/command code gets executed. Sequential = direct calls. Callbacks use legitimate Windows APIs (EnumWindows, CopyFile2, CertEnumSystemStore) as execution vehicles — the malicious code runs as a "callback" to a benign-looking API call. |
| **process** (9) | standalone, ppid_spoof (explorer, svchost, RuntimeBroker, sihost, taskhostw, dllhost), dll_sideload, process_hollow | What the binary looks like in process listings. PPID spoofing makes it appear as a child of a trusted process. Each parent target has different risk — svchost spawns child processes normally; RuntimeBroker rarely does. |
| **timing** (5) | immediate, staged_jitter, deferred, triggered, workday | When operations run. Deferred sleeps 5-30 min to evade sandboxes (most sandboxes timeout in 2 min). Triggered waits for mouse movement (proves human at keyboard). Workday only runs during business hours. |
| **data_obfuscation** (4) | plaintext, xor_encrypt, stack_strings, aes_encrypt | How strings appear in the binary. Plaintext = visible in `strings` output. Stack strings build char-by-char at runtime. AES encrypts with a key derived from binary metadata. |
| **anti_analysis** (5) | none, anti_debug, anti_vm, anti_sandbox, full | Checks for analyst/sandbox environments. Debug = IsDebuggerPresent + timing. VM = CPUID + registry checks. Sandbox = mouse, resolution, uptime, process count. |
| **exfil** (16) | tcp_direct, http_post, https_post, winhttp_get, winhttp_api, dns_exfil, dns_txt, smb_write, http_get_chunks, named_pipe, certutil_lolbin, bitsadmin_lolbin, powershell_lolbin, cscript_lolbin, mshta_lolbin, curl_lolbin | How data leaves the target. TCP = raw socket. HTTPS = blends with web traffic on 443. DNS = encodes data in TXT queries. LOLBins use legitimate Windows tools (certutil, powershell, curl.exe) as proxies. |
| **persistence** (5) | none, registry_run, scheduled_task, startup_folder, service | How the payload survives reboots. Registry Run key, schtask, Startup folder shortcut, or Windows service. |

### Combination Space

The base evasion layer space is **4,320,000** (6 × 10 × 9 × 5 × 4 × 5 × 16 × 5).

But the total variant space is much larger because each malware type adds its
own multiplier:

| Type | Type-Specific Variation | Total Unique Variants |
|---|---|---|
| **Infostealer** | 20 collectors, 6 with LOLBin/API dual variants, each independently on/off | **~51.6 trillion** |
| **Backdoor** | 2 C2 transports × 9 command handlers (4 with LOLBin/API variants), each on/off | **~22.4 billion** |
| **AD Recon** | 6 collector modules, any non-empty subset | **~272 million** |
| **Keylogger** | 2 capture methods (polling vs hook) | **~8.6 million** |

### Within-Technique Variation

Beyond mixing different technique categories, the framework varies within
individual techniques. This is the difference between "use PPID spoofing"
and "spoof as a child of RuntimeBroker.exe specifically":

**PPID spoofing** — 6 parent process targets:
- `explorer.exe` — default user shell, common parent
- `svchost.exe` — service host, spawns child processes routinely
- `RuntimeBroker.exe` — rarely spawns children (low suspicion in process trees)
- `sihost.exe` — Shell Infrastructure Host, always running
- `taskhostw.exe` — Task Host Window, generic task runner
- `dllhost.exe` — COM Surrogate, frequently spawned for COM objects

Each target has a different behavioral signature. EDR rules that catch "suspicious
child of svchost.exe" don't fire when the parent is RuntimeBroker.exe.

**Callback execution** — 5 different APIs:
- `CreateTimerQueueTimer` — timer callbacks (the original)
- `EnumWindows` — window enumeration callback
- `CertEnumSystemStore` — certificate store enumeration
- `CopyFile2` — file copy progress callback
- `EnumResourceTypes` — resource enumeration callback

Each API generates different telemetry. CertEnumSystemStore looks like certificate
management. CopyFile2 looks like a file operation. The malicious code that runs is
identical; only the vehicle changes.

**Exfiltration** — 16 methods:
- 6 LOLBin exfil methods (certutil, bitsadmin, powershell, cscript, mshta, curl)
- 5 direct network methods (TCP, HTTP POST, HTTPS, WinHTTP GET, DNS)
- 3 alternative channels (SMB write, named pipe, HTTP GET chunks)
- 2 DNS variants (standard DNS TXT, base32 DNS TXT)

---

## The Evasion Selector: Hybrid 3-Tier Loop

The selector doesn't just try random combinations. It operates in three
escalating tiers:

### Tier 1: Algorithmic (runs 1-5)

Zero LLM cost. Rules-based selection:
- Start with minimum-risk baseline
- If detection occurs, parse the detection signal
- Map detection to specific layer change (e.g., "Sigma fired on schtasks
  process creation" → avoid `scheduled_task` persistence, try `startup_folder`)
- Track history to never repeat a caught combination
- Progressively increase evasion from known-good layers

### Tier 2: Local LLM (runs 6-8)

Local model (Qwen3-35B) receives:
- Full detection history from Tier 1
- Available layer options with risk scores
- Which combinations have been tried
- Specific detection rules that fired

The LLM reasons about WHY detection happened and picks creative combinations
that the algorithmic tier wouldn't reach.

### Tier 3: Cloud LLM (runs 9-10)

Cloud model (Claude/Fugu) for novel approaches when local exhausts options.
Full architectural reasoning about detection mechanisms.

---

## Why Turning Everything On Is Worse

A common misconception: "more evasion = more evasive." In practice, stacking
every technique makes detection MORE likely:

1. **Larger binary = more static analysis surface.** ML classifiers score on the
   totality of the binary. More obfuscation code, more API calls, more suspicious
   patterns all ADD to the suspicion score. A 50KB binary with 3 targeted layers
   is less suspicious than a 120KB binary with 10 layers.

2. **Anti-analysis checks are themselves signatures.** `IsDebuggerPresent`,
   CPUID timing checks, registry VM queries — these ARE detection indicators.
   CrowdStrike has Sigma rules specifically for "process called
   IsDebuggerPresent AND NtQueryInformationProcess." Adding anti-VM on a
   physical desktop target just gives a free detection for zero benefit.

3. **LOLBin exfil spawns child processes.** Using `certutil -encode` or
   `powershell Invoke-WebRequest` spawns a child process, generating a
   Sysmon Process Create event (Event ID 1) with the parent-child chain.
   Two child spawns might pass. Eight in 30 seconds is a detection signal.

4. **Conflicting techniques waste complexity.** API hashing resolves APIs
   via hash at runtime. Indirect syscalls bypass resolved APIs and go straight
   to the kernel. Using both pays the complexity cost of both but only one
   actually runs.

5. **Timing layers stack into dysfunction.** `deferred` (5-30 min sleep) +
   `staged_jitter` (random inter-op delays) + `workday` (business hours only)
   = a payload that might not execute for hours, massively increasing the
   detection window before any useful work happens.

The optimal approach is **minimum viable evasion** — just enough to bypass the
specific detection layers on the target, no more.

---

## Definite Advantages Over Malgen Skill

### 1. Recombination Defeats Patch Cycles (The Killer Feature)

When an EDR vendor patches a technique, they don't block the underlying API
(they can't — `GetAsyncKeyState`, `CreateFileA`, `send()` are used by millions
of legitimate programs). They block a **behavioral signature**: a specific
combination of indicators observed together.

Example real-world detection rule:
```
IF process_parent == "schtasks.exe"
AND api_call_sequence CONTAINS "GetAsyncKeyState" at >50Hz
AND network_connection TO non-standard port
AND no_valid_signature
THEN flag as "Keylogger/Behavioral"
```

This catches ONE combination. The chunk framework recombines automatically:
- Same keylogger + different trigger (callback_enumwindows instead of schtasks)
- Same keylogger + different exfil (HTTPS POST to port 443 instead of raw TCP)
- Same keylogger + different parent (RuntimeBroker instead of schtasks)

The "patched" technique is alive again. The vendor writes another rule. The
framework recombines again.

**Cost asymmetry:**
- Vendor: analyst time to write + test + deploy each rule
- Framework: zero (already in the matrix)
- Combinations needing rules: grows geometrically with each new chunk
- Combinations the framework tests: all of them, automatically

Malgen skill can't do this efficiently. It would need to independently reason
"maybe this old technique works in a different context" — and systematically
test every permutation costs thousands of LLM calls.

### 2. Speed: 5 Seconds vs 5 Minutes

| Operation | Chunk Framework | Malgen Skill |
|---|---|---|
| Generate source | ~0.5s (assemble) | 2-5 min (LLM generation) |
| Obfuscate | ~0.3s (string encrypt) | included in LLM output |
| Compile | ~1s (MinGW) | ~1s (MinGW) |
| Total per variant | **~2 seconds** | **2-5 minutes** |
| 50 variants | **~100 seconds** | **2-4 hours** |

### 3. Cost: $0 vs $0.50+ Per Attempt

Chunk assembly is pure computation. No LLM calls, no API tokens. Testing 1,000
variants costs the same as testing 1. Malgen skill costs ~$0.50 per generation
attempt (cloud LLM tokens).

### 4. Reproducibility: Identical vs Non-Deterministic

Same recipe → identical binary, every time. Critical for A/B testing evasion:
change one layer, hold everything else constant, measure the effect.

Malgen skill: same prompt → different code. "Did it pass because of better
evasion or because the LLM happened to generate code differently?"

### 5. Compile Reliability: 98% vs ~70%

53/54 recipes compile clean (the one exception is a DLL sideload recipe that
needs `DllMain` instead of `WinMain`). LLM-generated C fails to compile ~30%
of the time due to type mismatches, hallucinated headers, MSVC-isms.

### 6. Knowledge Retention

Every technique that works gets encoded as a chunk and stays in the matrix
forever. With malgen skill, a technique might work in one session and not be
rediscovered in the next.

### 7. Combinatorial Testing at Scale

The evasion selector's hybrid loop can test 50 variants in 10 minutes, mapping
which layers get caught and which don't. This produces training data for
targeted evasion improvement. Malgen skill would need 50 separate LLM calls
($25+) to cover the same space.

---

## What Malgen Skill Does Better

Malgen skill has genuine advantages that the chunk framework can't replicate:

1. **Novel technique discovery.** Can invent techniques that don't exist in
   any corpus or chunk library.
2. **Architectural reasoning.** Can fundamentally restructure payload flow,
   not just swap modules.
3. **Causal analysis.** "CrowdStrike caught this because the LDAP query
   sequence after schtasks execution matches a known APT pattern. If I
   interleave legitimate API calls..." — this causal chain requires reasoning.
4. **No ceiling.** Chunk framework is bounded by existing chunks. Malgen skill
   is bounded only by the LLM's capability.

---

## The Flywheel: How They Work Together

```
    Chunk Framework                    Malgen Skill
    (breadth, speed, $0)               (depth, creativity, $$)
         |                                  |
         |  1. Map detection landscape      |
         |     50 variants in 10 min        |
         |                                  |
         +----------> detection gaps ------>+
                                            |
                       2. Reason about WHY  |
                          detections fire,  |
                          invent novel      |
                          bypass            |
                                            |
         +<-------- new technique <---------+
         |
         |  3. Encode discovery as new chunk
         |     (hand-verify, add to matrix)
         |
         |  4. New chunk multiplies ALL
         |     future combinations.
         |     Zero additional cost.
         |
         +----------> (repeat) ----------->+
```

Each cycle makes the chunk framework more capable without making it slower or
more expensive. The malgen skill focuses its expensive reasoning on the frontier
— the detections that existing chunks can't handle.

**Discovery without retention is waste.** If malgen skill finds a novel technique
but it's not encoded as a chunk, you lose it. The chunk framework IS the
retention layer.

---

## Current State (July 2026)

- **123 chunk files** across 14 categories
- **54 recipes** (8 infostealer, 17 backdoor, 16 keylogger, 3 AD recon)
- **8 evasion layers** with 51 total options
- **3,009 Sigma rules** for behavioral detection scoring
- **All 3 malware types validated**: 0 Defender, 0 Wazuh, 0 Sigma medium+
- **Infostealer**: 54,940 bytes exfiltrated (system info, processes, browser,
  screenshots, credentials, cloud creds, crypto wallets, SSH keys)
- **Keylogger**: 156 bytes (keystroke capture with self-test validation)
- **Backdoor**: 12 bytes (heartbeat + command execution via TLV protocol)
