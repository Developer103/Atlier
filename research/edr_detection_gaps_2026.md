# EDR Detection Gaps & Blind Spots (2026)

Specific, actionable gaps in modern EDR detection coverage. Not theoretical — these are gaps exploitable by compiled C payloads on Windows 11 with Defender + Elastic Defend.

---

## Table of Contents

1. [Under-Monitored Windows APIs](#1-under-monitored-apis)
2. [File System Blind Spots](#2-file-system-blind-spots)
3. [Process Trust Gaps](#3-process-trust-gaps)
4. [Temporal Blind Spots](#4-temporal-blind-spots)
5. [Network Protocol Gaps](#5-network-protocol-gaps)
6. [Memory Scanning Limitations](#6-memory-scanning-limits)
7. [EDR Self-Protection Weaknesses](#7-edr-self-protection)
8. [Configuration-Based Gaps](#8-configuration-gaps)
9. [Testing Methodology](#9-testing-methodology)

---

## 1. Under-Monitored APIs

### APIs rarely hooked by EDRs (as of 2025-2026)

**File operations:**
- `NtCreateMailslotFile` — rarely monitored, can be used for local IPC
- `NtCreateNamedPipeFile` — less scrutiny than TCP/IP for local C2
- `NtNotifyChangeDirectoryFile` — directory change notifications, benign-looking
- `NtQueryDirectoryFileEx` — newer variant of directory enumeration
- `NtLockFile` / `NtUnlockFile` — file locking used for IPC signaling

**Memory operations:**
- `NtMapViewOfSectionEx` — newer API, some EDRs only hook `NtMapViewOfSection`
- `NtAllocateVirtualMemoryEx` — extended variant, may bypass hooks on the base version
- `NtManagePartition` — memory partition operations
- `NtCreateEnclave` — SGX enclave creation

**Process/Thread operations:**
- `NtCreateUserProcess` — newer than `NtCreateProcessEx`, some EDRs only hook the older variant
- `NtCreateWorkerFactory` — thread pool worker creation
- `NtAlertThread` / `NtAlertResumeThread` — thread signaling

**Registry:**
- `NtRenameKey` — registry key rename (some EDRs only monitor Create/Set/Delete)
- `NtSaveKeyEx` / `NtRestoreKey` — registry hive save/restore
- `NtLoadKey2` / `NtLoadKeyEx` — loading registry hives

### Win32 API alternatives
Many Win32 APIs have multiple paths to the same Nt function. EDRs may hook one path but not others:
- `CreateFileA` vs `CreateFile2` (newer Win8+ variant)
- `VirtualAlloc` vs `VirtualAlloc2` (Win10+ extended)
- `CreateProcessA` vs `CreateProcessWithLogonW` vs `CreateProcessWithTokenW`

### Undocumented syscalls
Windows has ~460+ syscalls (ntoskrnl) and ~1200+ (win32u). New syscalls are added with each Windows version. EDRs can't hook what they don't know about. Windows 11 24H2 added several new syscalls that may not have EDR coverage.

---

## 2. File System Blind Spots

### Paths with reduced scrutiny
- `C:\Windows\Temp\` — high-volume temp directory, often excluded or rate-limited by EDR scanning
- `C:\ProgramData\Microsoft\` — Microsoft subdirectories often whitelisted
- `%LOCALAPPDATA%\Temp\` — per-user temp, heavy legitimate traffic
- `C:\Windows\System32\spool\drivers\` — print spooler directory, historically less monitored
- ADS (Alternate Data Streams) — `file.txt:hidden.exe` — some EDRs check, many don't thoroughly

### File system features that confuse EDRs
- **Transactional NTFS (TxF)**: Create files in a transaction, use them, roll back — file never existed
- **Named pipes as file paths**: `\\.\pipe\name` can be used for IPC that bypasses file monitoring
- **Junction points / symlinks**: Creating junctions from monitored to unmonitored paths
- **Opportunistic locks**: File locking behavior that may interfere with EDR file scanning
- **File ID-based access**: Opening files by ID instead of path — bypasses path-based rules

### NTFS metadata abuse
- `$MFT` direct parsing: Read MFT records directly instead of using FindFirst/FindNext
- `$UsnJrnl`: Change journal gives file history without opening files
- `$Secure`: Security descriptor streams

---

## 3. Process Trust Gaps

### Processes that receive reduced EDR scrutiny
EDRs must balance detection vs performance/stability. These processes typically get lighter monitoring:

**System processes:**
- `svchost.exe` — hundreds of instances, high-volume activity, heavy scrutiny is expensive
- `explorer.exe` — constant file/registry operations from normal user activity
- `RuntimeBroker.exe` — UWP broker, high activity

**Developer tools:**
- `devenv.exe` (Visual Studio) — file I/O patterns overlap with malware
- `code.exe` (VS Code) — similarly high file activity
- `node.exe` — scripts, network connections, file I/O

**IT management tools:**
- `powershell.exe` (with `-NoProfile`) — blocked by many EDRs but allowed in many enterprises
- `SCCM/MECM` client — enterprise deployment tools with elevated privileges
- Remote management (WinRM, RDP) — trusted admin activity

### PPID spoofing effectiveness
Spoofing the parent PID to appear as a child of a trusted process. EDRs check parent-child relationships:
- `explorer.exe` → `notepad.exe`: Normal
- `cmd.exe` → `powershell.exe` → unknown.exe: Suspicious
- `services.exe` → `svchost.exe` → unknown.exe: Looks like a service, reduced scrutiny

### Process argument spoofing
Create process with benign arguments, then modify the PEB command line after creation:
```c
// Create process suspended with legitimate arguments
CreateProcessA(NULL, "notepad.exe C:\\Users\\readme.txt", ...
    CREATE_SUSPENDED, ...);

// Modify PEB->ProcessParameters->CommandLine in remote process
// to show benign args in Process Explorer / EDR logs

// Resume thread — process runs with real (malicious) behavior
// but logs show benign command line
```

---

## 4. Temporal Blind Spots

### Boot/startup window
During system boot, EDR agents take 15-60 seconds to fully initialize. Services scheduled for early boot may execute before EDR monitoring is complete.

**Exploitable window:**
- `SERVICE_BOOT_START` (driver) and `SERVICE_SYSTEM_START` (service) execute before most EDR agents
- Kernel callbacks are registered by the EDR driver during its initialization — there's a gap
- Persistence mechanisms that execute during early boot (BootExecute, Session Manager)

### Sleep/wake transition
When the system sleeps and wakes:
- Some EDR monitoring threads may have timing issues during wake
- ETW sessions may lose events during sleep transitions
- Minifilter may miss operations during power state changes

### User login transition
Session 0 (services) → Session 1 (interactive desktop) transition:
- Some EDR components start per-session; there's a gap during user login
- Multiple concurrent user sessions can confuse session-scoped monitoring

### EDR update window
When the EDR agent updates itself:
- Old agent stops → gap → new agent starts
- During the gap, monitoring may be reduced or absent
- Some EDRs do rolling updates to minimize gaps, but the gap still exists

### Day/night detection quality
Cloud-based ML models and analyst responsiveness vary:
- Automated detection quality is consistent
- But many "detections" are actually alerts that require analyst triage
- SOC staffing is typically lighter during off-hours (nights, weekends)
- Executing during low-SOC-coverage periods increases the window before human response

---

## 5. Network Protocol Gaps

### DNS-based C2
- Traditional DNS queries: visible to EDR network monitoring
- DNS-over-HTTPS (DoH): encrypted, goes to 1.1.1.1 or 8.8.8.8 — looks like regular HTTPS
- DNS-over-TLS (DoT): encrypted, port 853 — less common, may be blocked
- Many EDRs can't inspect DoH content — they see an HTTPS connection to a DNS provider

### Legitimate cloud service tunneling
Using legitimate cloud services as C2 channels:
- **Azure/AWS API calls**: EDR sees HTTPS to `*.amazonaws.com` — can't distinguish malicious from legitimate cloud API usage
- **Office 365 Graph API**: C2 via Outlook email drafts or OneDrive files
- **Google Docs/Sheets**: Read/write to shared documents as C2 channel
- **Slack/Teams webhooks**: POST to webhook URLs for exfiltration
- **GitHub/GitLab**: Use issues, comments, or file contents for C2

EDRs cannot block traffic to `login.microsoftonline.com` or `graph.microsoft.com` without breaking business operations.

### QUIC/HTTP3
QUIC runs over UDP with encryption built-in. Some EDRs:
- Don't inspect UDP traffic as thoroughly as TCP
- Can't parse QUIC protocol internals
- May not even recognize QUIC connections as HTTP

### Certificate pinning bypass by EDR
Some EDRs attempt TLS inspection. If the malware validates certificates (pin to specific CAs), it detects and refuses EDR MITM inspection, potentially alerting the operator.

---

## 6. Memory Scanning Limits

### When scans trigger
Memory scanning is expensive. EDRs only scan on specific triggers:
- `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` (RWX)
- `VirtualProtect` changing to executable
- `NtMapViewOfSection` with execute permission
- Thread creation pointing to unbacked memory
- Periodic timer-based scans (every 30-300 seconds depending on EDR)

### What scans miss
- **Non-executable code**: Code in RW pages that's later changed to RX (if the protection change isn't caught)
- **Stack-based code**: Executable stack (if enabled) with code pushed to stack
- **Encrypted payloads**: Sleep encryption makes memory scans find only ciphertext
- **Fragmented payloads**: Code spread across multiple small allocations, assembled via control flow
- **JIT code**: Process writes code, marks executable, executes — same pattern as legitimate JIT compilers

### Scan algorithm limits
- **Signature-based**: Only catches known patterns. Change 1 byte and the signature breaks.
- **YARA rules**: More flexible but still pattern-matching. Rule quality varies.
- **ML-based**: Feature extraction from memory regions. Evasion via feature manipulation (see cutting_edge doc).
- **Heuristic**: "This looks suspicious" — high false-positive rate limits aggressiveness.

### Timing exploitation
Between scan triggers, memory is unmonitored. If you can:
1. Allocate as RW (no scan)
2. Write code (no scan — it's RW, not executable)
3. Change to RX (scan triggers, but code is encrypted/obfuscated)
4. Decrypt in-place just before execution
5. Re-encrypt after execution

Step 4-5 happen between scan intervals. If the scan interval is 60 seconds, you have 60 seconds of cleartext execution time.

---

## 7. EDR Self-Protection

### Protected Process Light (PPL) gaps
EDR agents run as PPL-Antimalware to prevent termination. But:
- The EDR's SERVICE can be stopped if the attacker modifies the service configuration before the agent starts
- PPL doesn't protect against kernel-level attacks (BYOVD)
- PPL can be removed from a process via kernel EPROCESS manipulation

### Tamper detection blind spots
EDRs detect tampering with their own files, registry keys, and services. But:
- New files can be placed alongside EDR files (DLL sideloading into EDR process paths)
- Environment variables that affect EDR DLL loading
- Symbolic link manipulation in the EDR's installation directory

### EDR crash exploitation
If the EDR agent crashes:
- Some EDRs auto-restart (watchdog service)
- There's a window between crash and restart (typically 5-30 seconds)
- Repeated crashes may trigger a "safe mode" with reduced monitoring
- Certain EDRs have known crash bugs triggered by specific inputs (malformed ETW events, unusual file paths, extreme-length strings)

---

## 8. Configuration Gaps

### Default vs hardened EDR configurations
Most EDRs ship with moderate default settings. Hardened configuration requires manual tuning:

**Commonly disabled by default:**
- Credential theft protection (LSASS protection beyond PPL)
- Network traffic inspection
- Script block logging (beyond AMSI)
- USB device monitoring
- Cloud sandbox detonation for unknown binaries

**Often weakened for performance:**
- Full file scan on open (changed to on-close or periodic)
- Real-time memory scanning frequency
- Depth of process tree analysis

### Enterprise misconfigurations
Common enterprise configuration mistakes:
- Broad exclusion paths (entire development directories excluded)
- Exclusion by process name instead of path (any process named `devenv.exe` excluded)
- Disabled tamper protection for remote management compatibility
- Alert-only mode instead of block mode for behavioral detections
- Disabled cloud protection due to data sovereignty concerns

---

## 9. Testing Methodology

### Building a detection coverage matrix

**Setup:**
1. Windows 11 VM with target EDR (Defender, Elastic Defend, CrowdStrike, etc.)
2. Procmon + API Monitor for baseline activity monitoring
3. ETW session logging all relevant providers
4. Network capture (Wireshark) for all VM traffic

**Testing process:**
```
For each technique:
  1. Execute technique in VM
  2. Wait 5 minutes for cloud-based detection
  3. Check EDR console for alerts
  4. Check local event logs
  5. Record: detected (Y/N), severity, response action
  6. If detected: what specific indicator triggered it?
  7. If not detected: why? (gap in hooks, timing, trust?)
```

**Coverage score calculation:**
```
Coverage = (techniques_detected / techniques_tested) × 100
Per-category: injection_coverage, persistence_coverage, evasion_coverage, etc.
```

### Automated testing tools
- **Atomic Red Team**: Pre-built test cases mapped to MITRE ATT&CK
- **Caldera**: Automated adversary emulation
- **Infection Monkey**: Automated breach and attack simulation
- **Our framework**: `python3 -m atelier chunk --recipe <name> --compile --test` for each recipe

### Iterative gap discovery
1. Run all recipes against EDR
2. Note which pass (not detected) and which fail (detected)
3. For detected recipes: identify the detection trigger
4. Modify the detected chunk to avoid the specific trigger
5. Re-test
6. Document the specific detection boundary (what's detected vs what's not)

This produces a precise map of the EDR's detection capabilities for your specific payload patterns.
