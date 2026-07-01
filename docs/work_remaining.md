# Work Remaining

## Category 1: Make It Fully Work — STATUS

| # | Issue | Status |
|---|-------|--------|
| 1 | `print_summary` picks worst iteration | Already correct — uses `min()` |
| 2 | Missing `functional_failed` key | Already present in all return paths |
| 3 | CloudLLMClient missing `_strip_thinking` | Already calls it (line 445) |
| 4 | Monolithic fallback skips post-processing | **FIXED** — added full post-processing chain |
| 5 | Linux behavioral verification | Deferred — Windows-only workflow |
| 6 | Rust/Go prompts C-specific | Deferred — C-only workflow |
| 7 | Hardcoded SSH credentials | **FIXED** — uses instance variables |
| 8 | DB path error handling | **FIXED** — path existence check with actionable message |
| 9 | Checkpoint missing chunk cache | **FIXED** — serialized into CheckpointState |
| 10 | Host execution safety | **FIXED** — removed host binary execution |
| 11 | Detection score classification gap | **FIXED** — "low" now classified as DETECTED |
| 12 | Smooth pass using plan sigs | Correct — grafting ensures plan sigs match generated code |
| 13 | VirtIO ISO in boot-only | Deferred — both paths use IDE consistently |

## Category 2: Make It Better — PRIORITIZED

Ranked by: evasion impact (primary), effort, and dependencies.

### Tier 1: Highest Impact — DONE
All three implemented as post-processing passes in generation_engine.py.

**P1. String encryption/obfuscation** — **DONE**
- `_encrypt_string_literals()`: XOR with random 16-byte key, runtime `_xd_init()` decryptor

**P2. IAT obfuscation / dynamic API resolution** — **DONE**
- `_obfuscate_api_calls()`: 24 suspicious APIs resolved via GetProcAddress at runtime

**P3. AMSI/ETW bypass generation** — **DONE**
- `_inject_amsi_etw_bypass()`: patches AmsiScanBuffer + EtwEventWrite at runtime

### Tier 2: High Impact — DONE

**P4. Anti-debugging techniques** — **DONE**
- `_inject_anti_debug()`: IsDebuggerPresent + CheckRemoteDebuggerPresent + timing checks
- Anti-debug APIs added to IAT obfuscation list

**P5. Polymorphic/metamorphic mutation** — **DONE**
- `_mutate_source()`: variable renaming, dead code injection, integer literal mutation
- Each compilation produces unique binary hash

**P6. Process injection primitives** (was #5)
- Impact: MEDIUM-HIGH — enables in-memory execution, but increases detection surface if done poorly
- Effort: High — multiple injection techniques, each needs correct implementation
- Benefits from anti-debugging (P4) to survive analysis

### Tier 2.5: Reliability & Substance — DONE

**P6a. Compile-fix function targeting** — **DONE**
- `_extract_erroring_functions()` now uses a loose regex scan before falling back to "closest function"
- Catches malformed signatures like `BOOL init_buffer(int min {` that `_extract_c_functions` misses
- GCC "In function 'X'" messages parsed authoritatively — malformed functions recovered via regex
- Works alongside existing GCC "In function" recovery

**P6b. Behavioral substance — two layers** — **DONE**
- **Chunk-level** (`_validate_chunk_substance()`): catches stubs at generation time before assembly
  - Rejects chunks with <5 code lines, missing return statements, self-recursion, comment-heavy output
  - Checks API coverage: if responsibility mentions specific Win32 APIs, verifies they appear in code
  - Triggers up to 2 retries with specific error feedback on failure
  - Failed chunks excluded from golden chunk cache
- **Post-assembly** (`_ensure_exfil_substance()`): scores 6 behavioral indicators; if <3, injects `_collect_sysinfo()` helper
  - Collects hostname, username, PID, process list, Desktop/Documents file listing
  - Injected before mutation/obfuscation so the data collection gets encrypted and IAT-obfuscated

### Tier 3: Operational Improvements — IN PROGRESS

**P7. Parallel chunk generation** (was #2)
- Impact: Speed — could cut generation time by 3-5x for independent chunks
- Effort: Medium — dependency graph analysis, async batch generation
- Only matters once single-threaded generation is reliable (it nearly is now)

**P8. Split the monolith** (was #1)
- Impact: Code quality — makes debugging/testing practical, enables parallel development
- Effort: High — 4600+ lines to decompose into 5-6 modules
- Should happen when the engine is stable and feature-complete

**P9. Orphan VM cleanup** — **DONE**
- `cleanup_orphan_vms()`: kills stale QEMU processes by name prefix
- ProvisionEngine registers atexit handler to kill tracked VMs on crash

**P10. DB query disk caching** — **DONE**
- QueryResult serialized to `.cache/db_queries/{cache_key}.json`
- Survives process restarts, saves 10-30s on repeated runs with same spec

### Tier 4: Future Capabilities — Need External Setup
Require VM/infrastructure changes or aren't relevant to current workflow.

**P11. EDR testing beyond Defender** (was #3) — **PLANNED**
- Full plan written: `docs/edr_testing_plan.md`
- Free options: Wazuh, Elastic Security, OpenEDR, Velociraptor, WHIDS
- Architecture: EDRConfig dataclass, per-EDR VM overlays, detection check per API
- Recommended start: Wazuh (fully free, REST API, Docker server)

**P12. DLL/shellcode output format** (was #7)
- Impact: Medium — delivery format diversity, but needs different compilation and testing
- Effort: Medium — MinGW DLL compilation, PIC shellcode extraction
- Not urgent for current exe-based workflow

**P13. PoC deduplication improvement** (was #12)
- Impact: Low — marginal context quality improvement
- Effort: Low

**P14. Test coverage** (was #13)
- Impact: Quality — important long-term but not blocking
- Effort: High — integration tests need real LLM + VM

**P15. Language-specific technique ranking** (was #8)
- Impact: Low — only matters when Rust/Go are supported
- Deferred until multi-language support

**P16. Rust/Go templates** (was #9)
- Impact: Low — not needed for current C workflow
- Deferred until multi-language support
