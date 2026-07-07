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

## Planned — New Evasion Chunks (from CrowdStrike Falcon research)
- [ ] **Heap unhook (Falcon-specific)** — follow Falcon's inline hook `jmp` chain, decode XOR+0x45 to find writable heap target, overwrite with clean stub. Avoids VirtualProtect. Needs Falcon installed on VM to test. (~3-4h)
- [ ] **BYOVD loader** — drop vulnerable signed driver (RTCore64.sys etc), `sc create`/`sc start`, IOCTL to kill EDR PID. Requires admin + driver binary embedded as byte array. Falcon's BYOVD protection blocks known drivers — need unknown/0-day. (~3-4h)
- [ ] **Kernel callback removal** — enumerate PspCreateProcessNotifyRoutine, find csagent.sys entries by module range, zero them. Requires kernel execution via BYOVD first. Windows-build-specific offsets. (~4-5h)
- [ ] **Safe Mode boot attack** — `bcdedit /set safeboot network`, install service for Safe Mode, set Run key, reboot. Falcon inactive in Safe Mode. Needs admin + reboot-aware test infrastructure. (~2h)
- [ ] **Port DLL sideload to more host binaries** — version.def done, add profapi.def (computerdefaults.exe UAC bypass) and MpClient.def (MpCmdRun.exe Defender CLI)

## Planned — General
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
