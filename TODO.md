# TODO

## Completed
- [x] Fix generated ransomware exe — worker thread was hollow, fixed encrypt_file_content (XOR+writeback), change_file_extension (MoveFileA), generate_ransom_key (CryptGenRandom), wired up _worker_thread
- [x] Validate cloud LLM mode (Fugu/Sakana AI) — works, graceful fallback on quota exhaustion
- [x] Multi-language generation (Rust, Go) via `code_processor.py` — compile checks, plan prompts, verifier dispatch
- [x] Behavioral verifiers for keylogger + infostealer types — canary setup, post-execution checks, C2 config
- [x] blockdev-snapshot-sync overlay approach replaces broken savevm/loadvm
- [x] deploy_and_test.py malware-type-aware canary creation

## In Progress
- [ ] Checkpoint/resume (crash recovery for long runs)
- [ ] End-to-end validation: infostealer + keylogger generation and VM verification

## Planned
- [ ] Linux target path testing/validation
- [ ] EDR bypass testing (CrowdStrike, SentinelOne — not just Defender)
- [ ] Exploit integration (CVE PoCs for priv esc, EDR kill, worm propagation)
- [ ] Evasion improvements (polymorphic code, packing, anti-debug, AMSI bypass)
- [ ] Multi-stage payloads (dropper → loader → final payload)
- [ ] Vulnerability prioritization during generation

## Future
- [ ] Language expansion (Nim, Zig, PowerShell, .NET)
- [ ] Cloud target support (AWS, Azure, GCP VMs)
- [ ] Performance optimization (parallel chunk gen, better caching)
- [ ] Portal UI improvements
