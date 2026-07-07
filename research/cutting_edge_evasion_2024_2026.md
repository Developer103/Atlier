# Cutting-Edge EDR Evasion Techniques (2024-2026)

Techniques discovered or significantly evolved in the 2024-2026 period. Excludes the 20 techniques already documented in `edr_bypass_research.md`.

---

## Table of Contents

1. [BYOVD (Bring Your Own Vulnerable Driver)](#1-byovd)
2. [Direct Kernel Object Manipulation (DKOM)](#2-dkom)
3. [ETW-TI Provider Attacks](#3-etw-ti-provider-attacks)
4. [PPL Abuse (PPLFault, PPLmedic)](#4-ppl-abuse)
5. [Kernel Callback Removal](#5-kernel-callback-removal)
6. [AI/ML Model Evasion](#6-aiml-model-evasion)
7. [Defender Exclusion Abuse](#7-defender-exclusion-abuse)
8. [WSL/Container Blind Spots](#8-wslcontainer-blind-spots)
9. [COM/DCOM Execution Primitives](#9-comdcom-execution-primitives)
10. [Telemetry Flooding](#10-telemetry-flooding)
11. [Certificate & Trust Abuse](#11-certificate--trust-abuse)
12. [Reflective DLL Loading Evolution](#12-reflective-dll-loading-evolution)
13. [Windows 11 24H2 New API Abuse](#13-windows-11-24h2-new-api-abuse)

---

## 1. BYOVD

**Bring Your Own Vulnerable Driver** — load a signed, vulnerable kernel driver to disable EDR from Ring 0.

### Why it works
Windows driver signing enforcement only verifies the digital signature is valid — it doesn't check whether the driver has known vulnerabilities. Attackers load a legitimately signed driver with a known arbitrary-write or code-execution vulnerability, then exploit it to:
- Remove EDR kernel callbacks
- Unload EDR minifilter drivers
- Kill EDR protected processes
- Disable PatchGuard monitoring

### The LOLDrivers Project
The LOLDrivers project (loldrivers.io) catalogs 600+ vulnerable signed drivers as of 2026. Categories:
- **Arbitrary read/write**: RTCore64.sys (MSI Afterburner), DBUtil_2_3.sys (Dell), ene.sys (ENE Technology)
- **Code execution**: gdrv.sys (GIGABYTE), aswArPot.sys (Avast — ironic)
- **Process termination**: Zemana antilogger driver, Capcom.sys
- **Memory mapping**: Intel NAL driver, AMD Ryzen Master driver

### Implementation pattern
```c
// 1. Drop vulnerable driver to disk (embedded or downloaded)
// 2. Create a service and load the driver
SC_HANDLE hSvc = CreateServiceA(hSCM, "vuln_drv", "vuln_drv",
    SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
    SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
    "C:\\Windows\\Temp\\vuln.sys", NULL, NULL, NULL, NULL, NULL);
StartServiceA(hSvc, 0, NULL);

// 3. Open device handle
HANDLE hDev = CreateFileA("\\\\.\\VulnDriver", GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING, 0, NULL);

// 4. Send IOCTL to exploit the vulnerability
// (varies per driver — arbitrary write to kernel memory)
DeviceIoControl(hDev, IOCTL_WRITE_MEMORY, &input, sizeof(input),
    &output, sizeof(output), &bytes, NULL);

// 5. Use arbitrary write to zero out EDR callback registrations
//    or overwrite EDR driver code with RET instructions
```

### Current detection status (2026)
- **Microsoft**: Vulnerable Driver Blocklist (WDBL) blocks ~300 known drivers. Updated quarterly via Windows Update. Attackers use less-known drivers not yet on the list.
- **CrowdStrike**: Detects known BYOVD patterns (service creation + known driver hashes). Bypassable with novel/renamed drivers.
- **Limitation**: New vulnerable drivers are discovered faster than blocklists update. The supply is essentially infinite — any signed driver with a memory write IOCTL is a candidate.

### Post-HVCI considerations
HVCI (Hypervisor-enforced Code Integrity) prevents loading drivers not signed by Microsoft or WHQL. This significantly narrows BYOVD options — only WHQL-signed or MS-signed drivers work. However:
- HVCI adoption is still incomplete (~40% of enterprise Windows 11 as of 2025)
- Some WHQL-signed drivers are vulnerable (Dell, Intel utilities)
- Attestation-signed drivers may still have vulnerabilities

---

## 2. DKOM

**Direct Kernel Object Manipulation** — modify kernel data structures to hide processes, threads, or modules from EDR visibility.

### Process hiding via EPROCESS unlinking
Every process in Windows has an `EPROCESS` structure in kernel memory. These are linked in a doubly-linked list via `ActiveProcessLinks`. Unlinking a process from this list hides it from:
- `NtQuerySystemInformation(SystemProcessInformation)` — which Task Manager, Process Explorer, and most EDRs use
- Kernel callback notifications (the process still runs, but new callbacks won't fire for it)

```c
// Conceptual — requires kernel-mode execution (via BYOVD or driver)
// Find target EPROCESS
PEPROCESS target = NULL;
PsLookupProcessByProcessId((HANDLE)targetPid, &target);

// ActiveProcessLinks offset varies by Windows version
// Win11 22H2: 0x448, Win11 23H2: 0x448
PLIST_ENTRY links = (PLIST_ENTRY)((BYTE*)target + 0x448);

// Unlink from list
links->Flink->Blink = links->Blink;
links->Blink->Flink = links->Flink;

// Process is now invisible to enumeration but still scheduled by the kernel
```

### Thread hiding
Similar technique on `ETHREAD.ThreadListEntry` — hides individual threads from enumeration. Useful for hiding injected threads in legitimate processes.

### Post-PatchGuard
KPP (PatchGuard) periodically verifies kernel structures haven't been tampered with. DKOM modifications to the process list trigger a BSOD when PatchGuard detects them. Bypass approaches:
- **Timing**: Relink before PatchGuard checks (PatchGuard runs every 5-10 minutes, timing varies)
- **PatchGuard bypass**: Disable PatchGuard itself (very difficult post-2023, requires finding the PatchGuard context structure)
- **Alternative hiding**: Instead of unlinking, modify process attributes (name, PID) to look benign

### Detection difficulty
- DKOM is fundamentally hard to detect from usermode — the kernel's own enumeration APIs return the tampered view
- Kernel-level detection requires comparing the process list with the scheduler's thread queues or handle table enumeration
- Memory forensics tools (Volatility) can detect DKOM by walking multiple kernel structures and finding inconsistencies

---

## 3. ETW-TI Provider Attacks

The **ETW Threat Intelligence** provider (`Microsoft-Windows-Threat-Intelligence`) is a special kernel-level ETW provider that feeds directly into Defender and EDRs. Unlike usermode ETW (which can be patched in ntdll), ETW-TI operates in the kernel and requires kernel-level access to disable.

### What ETW-TI provides
- `THREATINT_ALLOCVM_REMOTE` — cross-process memory allocation
- `THREATINT_PROTECTVM_REMOTE` — cross-process memory protection changes
- `THREATINT_MAPVIEW_REMOTE` — cross-process section mapping
- `THREATINT_QUEUEAPC_REMOTE` — cross-process APC queuing
- `THREATINT_SETCTX_REMOTE` — cross-process context setting (SetThreadContext)
- `THREATINT_WRITEVM_REMOTE` — cross-process memory writing
- `THREATINT_SUSPEND_RESUME` — process suspend/resume

These events are critical for detecting process injection. Patching usermode ETW (EtwEventWrite) does NOT affect ETW-TI — it's a separate kernel pathway.

### Disabling ETW-TI from kernel
Requires kernel-mode access (via BYOVD or driver):
```c
// The EtwThreatIntProviderGuid registration in the kernel has a
// ProviderEnableInfo structure. Zeroing the IsEnabled field stops events.
//
// Finding the provider:
// 1. Locate nt!EtwpRegistrationListHead (kernel global)
// 2. Walk the registration list looking for GUID
//    {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
// 3. Zero the EnableInfo.IsEnabled field
//
// Alternatively: patch the ETW-TI provider's TraceHandle to 0
// This disconnects it from the trace session without unregistering
```

### Detection
- EDR can detect driver loading (kernel callback PsSetLoadImageNotifyRoutine)
- EDR can periodically verify ETW-TI is still enabled (query the provider status)
- But if the attacker has kernel access, they can also patch the verification code

### Practical status
ETW-TI disabling is a nuclear option — it kills ALL ETW-TI telemetry, not just specific events. Combined with BYOVD, this creates a window where process injection becomes invisible to EDR kernel telemetry. Several offensive frameworks (Backstab, Terminator) implement this.

---

## 4. PPL Abuse

**Protected Process Light (PPL)** is Windows' mechanism for protecting critical processes from tampering. EDR agents often run as PPL to prevent attackers from terminating or injecting into them.

### PPL hierarchy
Protection levels (highest to lowest):
- `PsProtectedSignerWinTcb` (WinTcb-Light) — csrss.exe, services.exe
- `PsProtectedSignerWindows` (Windows-Light) — smss.exe  
- `PsProtectedSignerAntimalware` (Antimalware-Light) — MsMpEng.exe, EDR agents
- `PsProtectedSignerLsa` (Lsa-Light) — lsass.exe (when RunAsPPL enabled)
- `PsProtectedSignerApp` (App-Light) — UWP apps

### PPLFault (2024)
Gabriel Landau's PPLFault exploits a TOCTOU in the Windows code integrity verification for PPL processes. The attack:
1. Create a legitimate PPL process with a known DLL dependency
2. Race the page fault handler: when the PPL process faults in a DLL page, replace the file on disk between the signature check and the page read
3. The corrupted page loads into the PPL process with arbitrary code

**Status (2026)**: Partially patched in Windows 11 23H2+. The specific TOCTOU was fixed, but variants may exist.

### PPLmedic
Uses the Windows Error Reporting (WER) service — which runs as PPL-WinTcb (highest) — to load arbitrary DLLs into PPL processes. WER has a plugin mechanism that loads DLLs for crash analysis. By crafting a fake crash report, the attacker triggers WER to load a malicious DLL into a PPL process.

### Practical impact
If an attacker can inject into an EDR's PPL process, they can:
- Disable the EDR from within its own process
- Read EDR's internal detection rules
- Modify EDR telemetry before it's sent to the cloud
- Use the EDR's own signed certificate for trust abuse

---

## 5. Kernel Callback Removal

Removing EDR's kernel callbacks disables its telemetry at the source. Unlike usermode hooks, kernel callbacks can't be trivially patched from Ring 3.

### CallbackHell / Backstab approach
From Ring 0 (via BYOVD):
```c
// The kernel maintains arrays of registered callbacks:
//   PspCreateProcessNotifyRoutine[] — process creation
//   PspCreateThreadNotifyRoutine[] — thread creation
//   PspLoadImageNotifyRoutine[] — image loading

// Each entry is an EX_CALLBACK_ROUTINE_BLOCK:
// struct EX_CALLBACK_ROUTINE_BLOCK {
//     EX_RUNDOWN_REF RundownProtect;
//     PEX_CALLBACK_FUNCTION Function;   // the callback function pointer
//     PVOID Context;
// };

// To remove: find the array, locate the EDR's callback by matching
// the function address to the EDR driver's address range,
// then zero the entry or replace it with a no-op.
```

### Finding callback arrays
The callback arrays aren't exported symbols. Locating them requires:
- **Pattern scanning**: Search for known instruction patterns near `PsSetCreateProcessNotifyRoutine`
- **Relative offset**: The `PsSetCreateProcessNotifyRoutine` function references the array at a known offset from its entry point
- **Version-specific offsets**: Maintain a table of offsets per Windows build number

### ObRegisterCallbacks removal
`ObRegisterCallbacks` registers callbacks for object access (handle creation/duplication). EDRs use this to protect their processes from being opened with `PROCESS_TERMINATE` or `PROCESS_VM_WRITE` access. Removing these callbacks allows terminating the EDR process.

### Detection
- PatchGuard monitors the callback arrays — modifications trigger BSOD
- EDRs can periodically verify their callbacks are still registered
- The act of loading a driver to do the removal is itself detectable (PsSetLoadImageNotifyRoutine fires BEFORE the callback removal code runs)

---

## 6. AI/ML Model Evasion

Modern EDRs use machine learning for both static (file-level) and behavioral (runtime) detection. These models have inherent weaknesses.

### Static ML evasion
EDR static ML models analyze PE features: section entropy, import table, string patterns, header anomalies. Evasion approaches:
- **Feature manipulation**: Add legitimate-looking imports, strings, resources to shift feature vectors toward benign classification
- **Adversarial appending**: Append bytes from known-good binaries to shift model features
- **Section padding**: Reduce section entropy by padding with structured data
- **Import table grooming**: Include imports for legitimate APIs (COM, OLE, Shell32) to dilute suspicious import ratios

### Behavioral ML evasion
Behavioral models analyze sequences of API calls, file/registry modifications, and network activity. Evasion:
- **Temporal spacing**: Spread malicious operations over minutes/hours instead of milliseconds
- **Interleaving benign activity**: Mix benign API calls between malicious ones
- **Mimicking legitimate software**: If the ML model was trained on installer behavior, make the malware look like an installer
- **Feature boundary abuse**: ML models have decision boundaries. Small changes in timing, ordering, or volume can flip the classification.

### Concept drift
ML models degrade over time as the distribution of malware changes. EDR vendors retrain periodically, but there's always a lag. New malware families may be initially undetected until enough samples are collected for retraining.

### Adversarial ML research (academic)
- **EvadeML** (2017): Demonstrated automated evasion of ML-based AV
- **MalGAN** (2017-2019): GAN-based malware generation to evade ML detectors
- **AIMED** (2023): Automated feature manipulation for evasion
- **PE-GPT** (2024-2025): Using LLMs to understand and manipulate PE features
- The academic consensus: purely ML-based detection is fundamentally brittle against adaptive adversaries

### Practical status
- CrowdStrike's static ML catches ~70-80% of novel malware (per independent testing)
- Behavioral ML adds another 10-15%
- The remaining 5-20% gap is where evasive malware lives
- Adding a few hundred bytes of legitimate-looking PE resources can reduce static ML detection by 30-50% for some models

---

## 7. Defender Exclusion Abuse

Windows Defender allows path, process, and extension exclusions. These can be programmatically discovered and abused.

### Discovering existing exclusions
```powershell
# Requires local admin (or SYSTEM)
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension
# Registry: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
```

### Common enterprise exclusions
Many enterprises exclude:
- `C:\Program Files\<LOB Application>\` — line-of-business apps
- `C:\inetpub\` — IIS web servers
- `*.log`, `*.bak` — performance optimization
- SQL Server data directories
- Development directories (`C:\src\`, `C:\dev\`)

### Exploitation
1. Enumerate exclusions (requires admin, but if you have admin you're already past the hard part)
2. Drop payload in an excluded path
3. Defender won't scan it — static detection bypassed entirely
4. Name payload with an excluded extension

### Creating exclusions
With admin access:
```powershell
Add-MpPreference -ExclusionPath "C:\Windows\Temp\legit"
# Defender won't scan anything in this path
```
This is logged in event log (Event ID 5007) and some EDRs alert on exclusion changes. But the window between adding the exclusion and the EDR alerting may be enough.

### Tamper Protection
Defender Tamper Protection (enabled by default on Windows 11) prevents modifying Defender settings through PowerShell, registry, or group policy. Bypassing requires:
- Disabling Tamper Protection through the Defender portal (cloud admin)
- Kernel-level attack (BYOVD) to modify Defender's memory directly
- Exploiting a Defender vulnerability

---

## 8. WSL/Container Blind Spots

### WSL2 (Windows Subsystem for Linux)
WSL2 runs a real Linux kernel in a Hyper-V lightweight utility VM. EDR coverage of WSL2 is incomplete:

**What EDRs typically DON'T see in WSL2:**
- Linux process creation/execution within the VM
- File operations on the Linux filesystem (ext4 in a VHDX)
- Network traffic originating from the WSL2 VM (NAT'd through the host)
- Linux syscalls (EDR hooks Windows syscalls, not Linux ones)

**What EDRs CAN see:**
- The WSL2 VM itself (wsl.exe, wslhost.exe process creation)
- File access to Windows filesystem from WSL2 (via /mnt/c/)
- Network traffic at the Windows firewall/WFP layer

**Exploitation:**
- Run malware tooling (C2 frameworks, lateral movement tools) entirely within WSL2
- Access Windows filesystem from WSL2 for data exfiltration
- Use WSL2's Linux networking stack for C2 (some EDRs can't inspect this)

### Windows Containers (Docker on Windows)
Windows Server containers share the host kernel but have process isolation. Hyper-V containers have stronger isolation. EDR coverage varies:
- Process-isolated containers: EDR typically has visibility (shared kernel)
- Hyper-V isolated containers: Similar blind spots to WSL2

---

## 9. COM/DCOM Execution Primitives

COM (Component Object Model) objects can be instantiated to execute code in unexpected ways. Many COM objects are under-monitored by EDRs.

### COM-based execution
```c
// ShellWindows COM object — get an Explorer.exe window and execute
IShellWindows *sw = NULL;
CoCreateInstance(&CLSID_ShellWindows, NULL, CLSCTX_LOCAL_SERVER,
    &IID_IShellWindows, (void**)&sw);
// Navigate to a folder, then use ShellExecute via the COM interface
// Execution appears to come from explorer.exe, not the malware process

// MMC20.Application — execute commands via MMC snap-in
// ShellBrowserWindow — similar to ShellWindows
// Excel.Application, Word.Application — macro execution via COM
```

### DCOM lateral movement
DCOM extends COM across the network. Abusable objects for remote execution:
- `MMC20.Application` — `ExecuteShellCommand()`
- `ShellWindows` + `ShellBrowserWindow`
- `Outlook.Application` — create and send emails
- `ExcelApplication` — DDEInitiate for command execution

**EDR coverage:** Most EDRs detect well-known DCOM abuse patterns (MMC20, ShellWindows) but may miss less common COM objects. The COM object surface is massive — thousands of registered objects, most unexplored from an offensive perspective.

### COM hijacking for persistence
Replace a legitimate COM object's DLL path in the registry with a malicious DLL. When any application instantiates that COM object, the malicious DLL loads:
```
HKCU\Software\Classes\CLSID\{GUID}\InProcServer32 → malicious.dll
```
This persists across reboots and executes in the context of whatever process loads the COM object — often a trusted, signed application.

---

## 10. Telemetry Flooding

Overwhelm the EDR's telemetry pipeline with high-volume benign events, causing:
- Event drops due to buffer overflow
- Delayed processing (malicious events queued behind benign flood)
- Increased false positives (analyst fatigue in SOC)

### Techniques
- **Rapid file operations**: Create/delete thousands of temporary files per second. Minifilter callbacks fire for each, consuming EDR processing budget.
- **Process creation spam**: Rapidly create and terminate legitimate processes (cmd.exe /c echo). Each triggers PsSetCreateProcessNotifyRoutine.
- **ETW event storm**: Generate massive volumes of ETW events from legitimate providers, competing for the same trace buffers.
- **Network connection churn**: Open and close thousands of TCP connections to legitimate endpoints.

### Practical effectiveness
- CrowdStrike: Has event rate limiting. Past ~10,000 events/sec, starts sampling instead of processing all. Malicious events during sampling window may be missed.
- Defender: Cloud submission queue has depth limits. Flooding can delay cloud-based detections.
- Elastic: Ingest pipeline has documented throughput limits. Event loss during saturation is possible.

### Detection
EDRs can detect telemetry flooding as an anomaly itself. But the detection of the flooding vs the detection of the actual malicious activity are separate systems — and the flooding may delay the latter enough to matter.

---

## 11. Certificate & Trust Abuse

### Stolen/purchased code signing certificates
- Code signing certificates from compromised CAs or purchased on the dark market
- Signed malware gets significantly reduced scrutiny from EDRs
- SmartScreen reputation: signed binaries accumulate trust faster

### Catalog file abuse
Windows catalog files (.cat) can be used to sign files retroactively. If an attacker can add an entry to a catalog file trusted by the system, arbitrary files become "signed."

### Timestamping server abuse
Authenticode timestamps make signatures valid even after certificate expiration. Historical technique: use a compromised certificate before revocation, timestamp the signature, and it remains valid forever.

### 2024-2025 examples
- Multiple documented cases of legitimate certificate theft (Nvidia leak 2022, continuing abuse through 2025)
- Chinese APT groups maintaining collections of valid EV certificates
- Attestation-signed drivers via Microsoft's WHQL process (some malicious drivers slipped through)

---

## 12. Reflective DLL Loading Evolution

### Classic reflective loading
Load a DLL from memory without touching disk (no `LoadLibrary` call). The DLL parses its own PE headers, resolves imports, and fixes relocations in memory. No file system artifacts.

### 2024-2026 improvements
- **Header stomping**: After loading, overwrite the PE headers in memory with random data. Memory scanners looking for MZ/PE signatures in RWX regions won't find them.
- **Section remapping**: Map each section into separate, non-contiguous memory regions. Defeats scanners looking for contiguous PE layout.
- **Phantom loading**: Create a legitimate file-backed section (from a real DLL on disk), then overwrite the mapped view with malicious code. The section appears file-backed and signed.
- **No-RWX loading**: Allocate as RW, write code, then change to RX. Never have RWX at any point. Some EDRs specifically alert on RWX allocations.

### Transacted Hollowing variant
Use TxF (Transactional NTFS) to create a file in a transaction, map it into memory, then roll back the transaction. The file never existed on disk, but the section mapping persists.

---

## 13. Windows 11 24H2 New API Abuse

Windows 11 24H2 introduced new APIs and features that may not be fully covered by EDR rules written for earlier versions.

### Potential blind spots
- **New scheduled task COM interfaces**: Updated task scheduler API surface
- **Recall/AI features**: Copilot integration creates new processes and services that might be whitelisted
- **Dev Home / Dev Drive**: Developer-focused features with reduced security friction
- **Passkey infrastructure**: New credential provider DLLs that load in sensitive contexts
- **New Windows Update delivery optimization**: P2P update mechanism changes
- **Smart App Control evolution**: New trust policies that interact with EDR differently

### General principle
Every major Windows update adds new attack surface. EDR detection rules are written reactively — there's always a window between feature release and detection rule deployment. This window can be months for less obvious features.

---

## Summary

| Technique | Requires | EDR Impact | Longevity |
|-----------|----------|------------|-----------|
| BYOVD | Admin + driver | Kernel-level EDR kill | Years (infinite driver supply) |
| DKOM | Ring 0 | Process hiding | Years (but PatchGuard risk) |
| ETW-TI disable | Ring 0 | Blind injection detection | Years |
| PPL abuse | Specific vulns | EDR process injection | Patches kill specific vulns |
| Callback removal | Ring 0 | Kill all EDR telemetry | Years (but PatchGuard) |
| AI/ML evasion | None | Bypass ML detection | Indefinite (fundamental) |
| Exclusion abuse | Admin | Bypass static scanning | Years (common misconfig) |
| WSL2 blind spots | WSL installed | Hide Linux-side activity | Until EDR adds WSL coverage |
| COM/DCOM abuse | Varies | Unexpected execution context | Years (huge COM surface) |
| Telemetry flooding | None | Delay/drop events | Until EDR adds rate analysis |
| Certificate abuse | Certificate | Trust bypass | Until revocation |
| Reflective DLL evolution | Admin/inject | Memory evasion | Evolving |
| New API abuse | None | Detection gap window | Months per Windows update |
