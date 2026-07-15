"""
Behavioral detection model — maps evasion configs to realistic CrowdStrike Falcon detections.

Each (dim, value) pair maps to zero or more behavioral indicators that CrowdStrike would flag.
Each indicator has a 'tier' (1-20) representing detection engine sophistication:
  Tier 1-4:   Static analysis (PE imports, strings, file metadata)
  Tier 5-8:   Basic behavioral (known technique signatures, API sequences)
  Tier 9-12:  Process behavioral (parent-child, injection, timing patterns)
  Tier 13-16: Advanced behavioral (correlation, memory scanning, ML)
  Tier 17-20: Full spectrum (cloud analytics, threat intelligence, behavioral fingerprint)

A config "passes" a level if none of its values trigger detections at tier <= level.
Values with no entries (empty list) are never detected — these form the golden configs.

Combination detections trigger only when multiple specific dim+value pairs are present.
"""

import json
import random
from datetime import datetime, timezone

# ════════════════════════════════════════════════════════════════
# INDIVIDUAL BEHAVIORAL INDICATORS
# Key: (dim, value) → list of detection events
# Empty list = undetectable by CrowdStrike
# ════════════════════════════════════════════════════════════════

BEHAVIORAL_MAP = {
    # ── api_resolve ──
    ("api_resolve", "direct_import"): [{
        "tier": 2, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1106",
        "detect_name": "SuspiciousImportTable",
        "description": "Static analysis: binary imports sensitive APIs commonly associated with "
                       "process injection and memory manipulation (VirtualAllocEx, WriteProcessMemory, "
                       "NtCreateThreadEx, CreateRemoteThread). Import hash cluster matches known "
                       "offensive tooling patterns.",
    }],
    ("api_resolve", "loadlibrary"): [{
        "tier": 5, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1106",
        "detect_name": "DynamicAPIResolution",
        "description": "Process dynamically resolves sensitive Windows APIs via LoadLibrary/"
                       "GetProcAddress at runtime. API resolution pattern is consistent with "
                       "evasion techniques that hide true API usage from static analysis.",
    }],
    ("api_resolve", "api_hash_djb2"): [{
        "tier": 13, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1027.002",
        "detect_name": "HashedAPIResolution",
        "description": "Behavioral analysis detected API name hashing in code flow. DJB2 hash "
                       "constants (5381, 33) identified in API resolution routine. Pattern is "
                       "consistent with malware API obfuscation frameworks.",
    }],
    ("api_resolve", "api_hash_crc32"): [{
        "tier": 14, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1027.002",
        "detect_name": "HashedAPIResolution",
        "description": "Behavioral analysis detected CRC32-based API name hashing. CRC32 lookup "
                       "table pattern identified in API resolution routine. Associated with "
                       "advanced malware obfuscation.",
    }],
    ("api_resolve", "api_hash_fnv1a"): [{
        "tier": 15, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1027.002",
        "detect_name": "HashedAPIResolution",
        "description": "FNV-1a hash-based API resolution detected via behavioral analysis. "
                       "Less common hashing algorithm reduces static signature matches but "
                       "behavioral pattern remains identifiable.",
    }],
    ("api_resolve", "peb_walk"): [{
        "tier": 11, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1106",
        "detect_name": "ManualPEBTraversal",
        "description": "Process manually traverses PEB->Ldr->InMemoryOrderModuleList to resolve "
                       "loaded DLL base addresses without calling LoadLibrary. Technique is "
                       "commonly used by shellcode and fileless malware.",
    }],
    ("api_resolve", "indirect_syscall"): [{
        "tier": 17, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1106",
        "detect_name": "IndirectSyscallDetected",
        "description": "Thread call stack analysis detected syscall instruction executed from "
                       "outside ntdll.dll address range. Stack frame shows return address into "
                       "ntdll syscall stub but origin call from non-ntdll module. Consistent "
                       "with indirect syscall evasion of EDR usermode hooks.",
    }],
    ("api_resolve", "ntdll_disk_remap"): [{
        "tier": 12, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "NtdllRemapFromDisk",
        "description": "Process opened ntdll.dll from disk and mapped a second copy into its own "
                       "address space. The .text section of the mapped copy was written over the "
                       "hooked ntdll region. Consistent with EDR unhooking via disk remap.",
    }],
    ("api_resolve", "ntdll_knowndlls"): [{
        "tier": 16, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "KnownDllsSectionAccess",
        "description": "NtOpenSection called on \\KnownDlls\\ntdll.dll section object. Process "
                       "mapped a clean ntdll copy without touching disk. Technique avoids file "
                       "I/O monitoring but KnownDlls access is tracked.",
    }],
    ("api_resolve", "ntdll_suspend_remap"): [{
        "tier": 19, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "SuspendedProcessNtdllCopy",
        "description": "Process created a suspended child process and read its ntdll .text section "
                       "via NtReadVirtualMemory before any hooks were applied. The pristine copy "
                       "was used to overwrite the hooked ntdll in the parent process.",
    }],
    ("api_resolve", "hookchain"): [{
        "tier": 19, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1106",
        "detect_name": "HookChainTrampoline",
        "description": "Thread detected chaining hooked API trampolines to reach original syscall "
                       "stubs. HookChain technique walks the detour chain installed by EDR to locate "
                       "the final jmp-to-syscall instruction, bypassing all inline hook callbacks.",
    }],
    ("api_resolve", "syscall_halos_gate"): [{
        "tier": 18, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1106",
        "detect_name": "HalosGateSSNResolution",
        "description": "Thread execution shows runtime system service number (SSN) resolution "
                       "by walking neighboring ntdll stubs. Pattern matches Halo's Gate technique "
                       "for bypassing inline hooks on Nt* function prologues.",
    }],
    ("api_resolve", "syscall_recycled"): [{
        "tier": 18, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1106",
        "detect_name": "RecycledSyscallStub",
        "description": "Thread reused a syscall;ret instruction sequence from an unrelated Nt* "
                       "function stub to execute a different system call. SSN was set in a register "
                       "before jumping into the middle of a legitimate stub — pattern matches "
                       "SysWhispers3/RecycledGate evasion of per-stub ETW instrumentation.",
    }],
    ("api_resolve", "syscall_veh"): [{
        "tier": 20, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1106",
        "detect_name": "VEHSyscallDispatch",
        "description": "Thread registered a Vectored Exception Handler (VEH) and intentionally "
                       "triggered an exception (int3/single-step) at the syscall site. The VEH "
                       "modified the thread context to redirect execution to a syscall;ret gadget "
                       "with the correct SSN. This VEH-based indirect syscall pattern evades stack "
                       "trace analysis since the call originates from the OS exception dispatcher.",
    }],

    # ── injection_method ──
    ("injection_method", "none"): [],
    ("injection_method", "classic_remote"): [{
        "tier": 3, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1055.001",
        "detect_name": "ClassicProcessInjection",
        "description": "Process performed classic process injection sequence: VirtualAllocEx "
                       "(RWX) into remote process, WriteProcessMemory to write payload, "
                       "CreateRemoteThread to execute. All three APIs monitored as high-confidence "
                       "injection indicator.",
    }],
    ("injection_method", "earlybird_apc"): [{
        "tier": 9, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1055.004",
        "detect_name": "EarlyBirdAPCInjection",
        "description": "APC queued to thread in CREATE_SUSPENDED state before first instruction "
                       "executes. EarlyBird technique allows code execution before EDR hooks are "
                       "set in the target process.",
    }],
    ("injection_method", "threadless"): [{
        "tier": 18, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1055",
        "detect_name": "ThreadlessInjectionSuspected",
        "description": "Remote process memory was modified without CreateRemoteThread or APC queue. "
                       "Execution flow was redirected via existing thread's import table or callback "
                       "pointer modification. Advanced threadless injection technique.",
    }],
    ("injection_method", "doppelganging"): [{
        "tier": 14, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1055.013",
        "detect_name": "ProcessDoppelganging",
        "description": "Process doppelganging detected. NtCreateTransaction, file write, "
                       "NtCreateSection from transacted file, NtRollbackTransaction sequence. "
                       "Process created from transacted file that no longer exists on disk.",
    }],
    ("injection_method", "herpaderping"): [{
        "tier": 16, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1055",
        "detect_name": "ProcessHerpaderping",
        "description": "Process herpaderping detected. File written, process created from file, "
                       "then file content overwritten before security scan. On-disk content does "
                       "not match in-memory image. File modification race condition exploit.",
    }],
    ("injection_method", "phantom_dll"): [{
        "tier": 17, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1574.002",
        "detect_name": "PhantomDLLHollowing",
        "description": "DLL loaded from legitimate path but .text section replaced in memory "
                       "before execution. Phantom DLL hollowing — loads real DLL, overwrites "
                       "code section with payload. Module appears signed but executes attacker code.",
    }],
    ("injection_method", "kcb_hijack"): [{
        "tier": 19, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1055",
        "detect_name": "KCBHijackInjection",
        "description": "Kernel callback table modification detected. Process overwrote function "
                       "pointer in PEB kernel callback table to redirect execution flow. Advanced "
                       "code execution without thread creation or APC queue.",
    }],

    # ── network_stealth ──
    ("network_stealth", "none"): [{
        "tier": 10, "severity": 2,
        "tactic": "Command and Control", "technique": "T1071.001",
        "detect_name": "TLSFingerprintMismatch",
        "description": "TLS client hello fingerprint (JA3) does not match any known browser or "
                       "legitimate application. Custom TLS stack detected. JA3 hash correlates "
                       "with offensive tooling in CrowdStrike threat intelligence database.",
    }],
    ("network_stealth", "ja3_spoof"): [{
        "tier": 18, "severity": 2,
        "tactic": "Command and Control", "technique": "T1071.001",
        "detect_name": "JA3SpoofDetected",
        "description": "JA3 fingerprint matches Chrome/Firefox but process is not a browser. "
                       "TLS extension ordering and cipher suite selection are browser-perfect but "
                       "HTTP/2 framing and connection behavior inconsistent with browser identity.",
    }],
    ("network_stealth", "domain_front"): [{
        "tier": 17, "severity": 3,
        "tactic": "Command and Control", "technique": "T1090.004",
        "detect_name": "DomainFrontingDetected",
        "description": "TLS SNI hostname differs from HTTP Host header. Domain fronting detected "
                       "via cloud provider CDN. Outer TLS targets legitimate CDN edge, inner "
                       "request routes to different backend.",
    }],
    ("network_stealth", "doh_tunnel"): [{
        "tier": 16, "severity": 3,
        "tactic": "Command and Control", "technique": "T1071.004",
        "detect_name": "DoHTunnelDetected",
        "description": "Process sending DNS queries over HTTPS to resolver endpoint. High-volume "
                       "DNS-over-HTTPS from non-browser process is anomalous. Payload encoding "
                       "detected in query names.",
    }],
    ("network_stealth", "legitimate_api"): [{
        "tier": 21, "severity": 2,
        "tactic": "Command and Control", "technique": "T1102",
        "detect_name": "LegitimateAPIAbuse",
        "description": "Process communicates via legitimate cloud API (Slack, Discord, Teams, Notion) "
                       "but data patterns inconsistent with normal API usage. Encoded payloads in "
                       "message bodies, polling frequency, and data volume suggest C2 channel.",
    }],

    # ── execution ──
    ("execution", "sequential"): [{
        "tier": 6, "severity": 2,
        "tactic": "Execution", "technique": "T1059",
        "detect_name": "RapidSequentialAPICalls",
        "description": "Process made rapid sequential calls to sensitive APIs (file enumeration, "
                       "credential access, network operations) without user interaction delays. "
                       "Execution pattern inconsistent with interactive software.",
    }],
    ("execution", "threaded"): [{
        "tier": 8, "severity": 2,
        "tactic": "Execution", "technique": "T1059",
        "detect_name": "SuspiciousThreadCreation",
        "description": "Process created multiple threads that each access different sensitive "
                       "subsystems (browser data, credentials, network info). Thread creation "
                       "pattern suggests automated data collection.",
    }],
    ("execution", "staged"): [{
        "tier": 12, "severity": 1,
        "tactic": "Execution", "technique": "T1059",
        "detect_name": "StagedExecutionPattern",
        "description": "Process exhibits staged execution with deliberate delays between "
                       "operations. While less suspicious than rapid execution, the staged "
                       "pattern across sensitive operations suggests behavioral pacing evasion.",
    }],
    ("execution", "fiber"): [{
        "tier": 14, "severity": 1,
        "tactic": "Defense Evasion", "technique": "T1027",
        "detect_name": "FiberBasedExecution",
        "description": "Process uses fiber scheduling (ConvertThreadToFiber/SwitchToFiber) for "
                       "operation dispatch. Fiber-based execution is uncommon in legitimate "
                       "software and can indicate evasion-aware malware.",
    }],
    ("execution", "callback_abuse"): [],
    ("execution", "callback_enumwindows"): [{
        "tier": 16, "severity": 1,
        "tactic": "Defense Evasion", "technique": "T1106",
        "detect_name": "CallbackAbusePattern",
        "description": "Sensitive operations executed within EnumWindows callback. Callback-based "
                       "execution can obfuscate the call chain from behavioral analysis.",
    }],
    ("execution", "callback_certenumsystem"): [],
    ("execution", "callback_copyfile2"): [],
    ("execution", "callback_enumrestype"): [],
    ("execution", "apc_self"): [{
        "tier": 15, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1055.004",
        "detect_name": "APCQueueExecution",
        "description": "Process queues APC to own thread for code execution. Self-APC injection "
                       "is an uncommon execution pattern outside of specific frameworks.",
    }],

    # ── process ──
    ("process", "standalone"): [{
        "tier": 3, "severity": 2,
        "tactic": "Execution", "technique": "T1204.002",
        "detect_name": "SuspiciousExecutable",
        "description": "Unknown executable running from user-writable directory "
                       "(C:\\Users\\*\\Desktop, C:\\Users\\*\\Downloads). Binary is not signed, "
                       "not in application inventory, and has no version information. "
                       "File reputation: unknown (first seen).",
    }],
    ("process", "ppid_spoof"): [{
        "tier": 7, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1134.004",
        "detect_name": "ParentPIDSpoofing",
        "description": "Process creation detected with inconsistent parent relationship. "
                       "Claimed parent explorer.exe (PID {ppid}) but actual creator thread "
                       "originates from different process. PPID spoofing via "
                       "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.",
    }],
    ("process", "ppid_spoof_svchost"): [{
        "tier": 6, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1134.004",
        "detect_name": "ParentPIDSpoofing",
        "description": "Process creation with spoofed parent svchost.exe detected. "
                       "Kernel callback resolved actual creating process differs from claimed "
                       "parent. svchost.exe child processes are closely monitored — unexpected "
                       "child flagged.",
    }],
    ("process", "ppid_spoof_runtimebroker"): [{
        "tier": 9, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1134.004",
        "detect_name": "ParentPIDSpoofing",
        "description": "Process claims RuntimeBroker.exe as parent but kernel-level creator "
                       "thread analysis shows different originating process. RuntimeBroker "
                       "child creation is abnormal.",
    }],
    ("process", "ppid_spoof_sihost"): [{
        "tier": 10, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1134.004",
        "detect_name": "ParentPIDSpoofing",
        "description": "Process claims sihost.exe as parent. Kernel notification callback "
                       "detected inconsistency between claimed and actual parent process.",
    }],
    ("process", "ppid_spoof_taskhostw"): [{
        "tier": 10, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1134.004",
        "detect_name": "ParentPIDSpoofing",
        "description": "Process claims taskhostw.exe as parent. Creator thread analysis "
                       "identified parent process spoofing attempt.",
    }],
    ("process", "ppid_spoof_dllhost"): [{
        "tier": 10, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1134.004",
        "detect_name": "ParentPIDSpoofing",
        "description": "Process claims dllhost.exe (COM Surrogate) as parent. Kernel "
                       "process creation callback detected PPID inconsistency.",
    }],
    ("process", "dll_sideload"): [{
        "tier": 12, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1574.002",
        "detect_name": "DLLSideLoading",
        "description": "Signed Microsoft binary loaded unsigned DLL from non-standard path. "
                       "DLL search order hijacking detected — expected system DLL was replaced "
                       "with unsigned variant. Binary hash not in known-good baseline.",
    }],
    ("process", "process_hollow"): [{
        "tier": 5, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1055.012",
        "detect_name": "ProcessHollowing",
        "description": "Process created in suspended state (CREATE_SUSPENDED), followed by "
                       "NtUnmapViewOfSection and NtWriteVirtualMemory to replace process "
                       "memory, then resumed with NtResumeThread. Classic process hollowing "
                       "injection technique detected.",
    }],
    ("process", "process_ghost"): [{
        "tier": 8, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1055",
        "detect_name": "ProcessGhosting",
        "description": "Process image file was deleted before process creation completed. "
                       "File marked for deletion (NtSetInformationFile with FileDispositionInfo) "
                       "while section was already mapped. Image file unavailable for scanning.",
    }],
    ("process", "com_object"): [{
        "tier": 14, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1559.001",
        "detect_name": "SuspiciousCOMInProcServer",
        "description": "COM in-process server DLL loaded by legitimate host process via "
                       "CoCreateInstance. DLL is not in COM object baseline and performs "
                       "sensitive operations (network access, credential reads) from within "
                       "the host process context.",
    }],
    ("process", "service_dll"): [{
        "tier": 11, "severity": 3,
        "tactic": "Persistence", "technique": "T1543.003",
        "detect_name": "SuspiciousServiceDLL",
        "description": "New service DLL registered in svchost.exe service group. DLL is "
                       "unsigned and not in known-good service baseline. Service DLL performs "
                       "network operations and sensitive data access.",
    }],
    ("process", "wmi_consumer"): [{
        "tier": 13, "severity": 2,
        "tactic": "Execution", "technique": "T1047",
        "detect_name": "WMIConsumerExecution",
        "description": "WMI permanent event consumer executing code via wmiprvse.exe. "
                       "Consumer script/binary performs operations inconsistent with "
                       "standard WMI management tasks.",
    }],
    ("process", "shell_extension"): [],
    ("process", "print_monitor"): [{
        "tier": 16, "severity": 2,
        "tactic": "Persistence", "technique": "T1547.010",
        "detect_name": "SuspiciousPrintMonitor",
        "description": "New print monitor DLL registered and loaded by spoolsv.exe. DLL "
                       "performs operations unrelated to print functionality (network access, "
                       "credential enumeration).",
    }],
    ("process", "browser_extension"): [{
        "tier": 15, "severity": 2,
        "tactic": "Collection", "technique": "T1176",
        "detect_name": "MaliciousBrowserExtension",
        "description": "Browser extension with broad permissions detected making requests "
                       "to unrecognized endpoints. Extension not from verified web store and "
                       "accesses sensitive browser data (cookies, passwords, history).",
    }],
    ("process", "lsa_plugin"): [{
        "tier": 4, "severity": 5,
        "tactic": "Credential Access", "technique": "T1547.002",
        "detect_name": "SuspiciousLSAPlugin",
        "description": "Unknown LSA security package loaded by lsass.exe. DLL is unsigned "
                       "and not in baseline. LSA plugins have direct access to plaintext "
                       "credentials during authentication. High severity due to lsass "
                       "sensitivity.",
    }],

    # ── timing ──
    ("timing", "immediate"): [{
        "tier": 4, "severity": 2,
        "tactic": "Execution", "technique": "T1204.002",
        "detect_name": "ImmediateExecution",
        "description": "Process began sensitive operations within 1 second of launch with no "
                       "user interaction. Immediate execution upon launch is inconsistent with "
                       "interactive software and common in automated malware.",
    }],
    ("timing", "staged_jitter"): [{
        "tier": 13, "severity": 1,
        "tactic": "Defense Evasion", "technique": "T1497.003",
        "detect_name": "DeliberatePacingDetected",
        "description": "Process exhibits deliberate random delays between operations. Delay "
                       "distribution analysis shows artificial jitter pattern inconsistent "
                       "with user-driven interaction. Possible behavioral pacing evasion.",
    }],
    ("timing", "deferred"): [{
        "tier": 11, "severity": 1,
        "tactic": "Defense Evasion", "technique": "T1497.003",
        "detect_name": "DeferredExecution",
        "description": "Process slept for extended period (>5 minutes) before beginning "
                       "operations. Deferred execution is a known sandbox evasion technique.",
    }],
    ("timing", "triggered"): [],
    ("timing", "workday"): [],
    ("timing", "event_logon"): [],
    ("timing", "event_process"): [],
    ("timing", "burst_then_die"): [{
        "tier": 16, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1070",
        "detect_name": "BurstAndSelfDelete",
        "description": "Process completed all operations in under 2 seconds then self-deleted. "
                       "Burst execution pattern with cleanup suggests time-limited payload "
                       "designed to outrun behavioral analysis.",
    }],

    # ── data_obfuscation ──
    ("data_obfuscation", "plaintext"): [{
        "tier": 1, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1027",
        "detect_name": "PlaintextStrings",
        "description": "Static analysis: binary contains plaintext strings referencing "
                       "sensitive paths and APIs (AppData\\Local\\Google\\Chrome, "
                       "Login Data, cookies.sqlite, wallet.dat). String clustering matches "
                       "known infostealer families.",
    }],
    ("data_obfuscation", "xor_encrypt"): [{
        "tier": 6, "severity": 1,
        "tactic": "Defense Evasion", "technique": "T1027",
        "detect_name": "XOREncodedStrings",
        "description": "Process decrypts XOR-encoded strings at runtime. Single-byte or "
                       "multi-byte XOR patterns detected in string initialization routines. "
                       "Decoded strings reference sensitive system locations.",
    }],
    ("data_obfuscation", "stack_strings"): [{
        "tier": 12, "severity": 1,
        "tactic": "Defense Evasion", "technique": "T1027",
        "detect_name": "StackStringConstruction",
        "description": "Process constructs strings character-by-character on the stack at "
                       "runtime. Stack string construction is a known obfuscation technique "
                       "to avoid static string analysis.",
    }],
    ("data_obfuscation", "aes_encrypt"): [],

    # ── anti_analysis ──
    ("anti_analysis", "none"): [],
    ("anti_analysis", "anti_debug"): [{
        "tier": 3, "severity": 1,
        "tactic": "Defense Evasion", "technique": "T1622",
        "detect_name": "AntiDebugChecks",
        "description": "Process performs debugger detection checks (IsDebuggerPresent, "
                       "NtQueryInformationProcess with ProcessDebugPort, timing-based "
                       "detection). Anti-debug techniques are common in malware and some "
                       "commercial software protection.",
    }],
    ("anti_analysis", "anti_vm"): [{
        "tier": 5, "severity": 1,
        "tactic": "Defense Evasion", "technique": "T1497.001",
        "detect_name": "VMDetectionAttempt",
        "description": "Process performed virtual machine detection via CPUID instruction "
                       "and registry checks for VMware/VirtualBox/Hyper-V artifacts. "
                       "Environment-aware execution suggests malware sandbox evasion.",
    }],
    ("anti_analysis", "anti_sandbox"): [{
        "tier": 7, "severity": 1,
        "tactic": "Defense Evasion", "technique": "T1497.001",
        "detect_name": "SandboxEvasion",
        "description": "Process checks mouse movement, screen resolution, system uptime, "
                       "and running process count before executing payload. Behavioral "
                       "fingerprinting consistent with sandbox detection.",
    }],
    ("anti_analysis", "full"): [{
        "tier": 9, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1497",
        "detect_name": "ComprehensiveAntiAnalysis",
        "description": "Process performs extensive environment validation: debugger checks, "
                       "VM detection, sandbox detection, and timing analysis. Comprehensive "
                       "anti-analysis suite is characteristic of advanced malware.",
    }],
    ("anti_analysis", "canary_aware"): [],
    ("anti_analysis", "geofence"): [],
    ("anti_analysis", "exec_guardrails"): [],

    # ── etw_method ──
    ("etw_method", "none"): [],
    ("etw_method", "patch"): [{
        "tier": 7, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "ETWPatchDetected",
        "description": "Integrity violation detected in EtwEventWrite function. First bytes "
                       "of ntdll!EtwEventWrite modified to return early (0xC3 ret). Memory "
                       "patch disables Event Tracing for Windows telemetry collection. "
                       "Tamper protection alert.",
    }],
    ("etw_method", "hwbp_etw"): [{
        "tier": 18, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "HardwareBreakpointEvasion",
        "description": "Hardware debug register (DR0-DR3) set on ETW function address. "
                       "Vectored exception handler intercepts breakpoint to modify ETW "
                       "behavior without modifying code bytes. Patchless bypass detected "
                       "via debug register monitoring.",
    }],
    ("etw_method", "hwbp_both"): [{
        "tier": 18, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "HardwareBreakpointEvasion",
        "description": "Multiple hardware breakpoints set on security functions "
                       "(EtwEventWrite, AmsiScanBuffer). VEH-based patchless bypass "
                       "of both ETW and AMSI detected via DR register monitoring.",
    }],

    # ── memory_residence ──
    ("memory_residence", "native"): [],
    ("memory_residence", "module_stomp"): [{
        "tier": 15, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1055.001",
        "detect_name": "ModuleStomping",
        "description": "Loaded DLL .text section contents do not match on-disk file. "
                       "Memory-mapped module has been overwritten with different code. "
                       "Module stomping hides malicious code behind a signed module's "
                       "memory range.",
    }],
    ("memory_residence", "mapped_section"): [{
        "tier": 16, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1055.001",
        "detect_name": "MappedSectionInjection",
        "description": "Process created shared memory section and mapped it into target process "
                       "address space. NtCreateSection/NtMapViewOfSection call sequence detected. "
                       "Shared section used to inject code without WriteProcessMemory.",
    }],
    ("memory_residence", "rw_rx_flip"): [{
        "tier": 13, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1055",
        "detect_name": "MemoryProtectionToggle",
        "description": "Process allocated memory as RW, wrote content, then changed protection "
                       "to RX via VirtualProtect. Two-step allocation avoids RWX detection but "
                       "the protection flip sequence is monitored.",
    }],
    ("memory_residence", "rx_reuse"): [{
        "tier": 18, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1055",
        "detect_name": "ExecutableMemoryReuse",
        "description": "Process reused existing RX memory region from loaded module. Content "
                       "hash of executable region does not match any loaded module on disk. "
                       "Advanced code hiding technique using pre-existing executable memory.",
    }],

    # ── stack_presentation ──
    ("stack_presentation", "honest"): [],
    ("stack_presentation", "ret_spoof"): [{
        "tier": 19, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1055",
        "detect_name": "ReturnAddressSpoofing",
        "description": "Thread call stack contains synthetic frames with return addresses "
                       "pointing into legitimate DLLs. Stack frame analysis detected "
                       "non-contiguous call chain inconsistent with normal execution flow.",
    }],
    ("stack_presentation", "full_frame_spoof"): [{
        "tier": 20, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1055",
        "detect_name": "FullFrameStackSpoof",
        "description": "Thread call stack contains fully fabricated stack frames with valid "
                       "unwind data. Frame pointers, return addresses, and unwind info all "
                       "synthetic. Cloud ML model detected statistical anomaly in frame layout.",
    }],
    ("stack_presentation", "dynamic_timer_spoof"): [{
        "tier": 20, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1055",
        "detect_name": "TimerCallbackStackSpoof",
        "description": "Thread executing from timer callback with spoofed call stack. Timer "
                       "queue APC contains code address in unbacked memory region. Dynamic "
                       "stack construction detected via ETW stack walk mismatch.",
    }],
    ("stack_presentation", "silent_moonwalk"): [{
        "tier": 20, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1055",
        "detect_name": "SilentMoonwalkDetected",
        "description": "Desynchronization between thread instruction pointer and call stack "
                       "detected via hardware performance counters. Return addresses on stack "
                       "reference legitimate code but LBR trace shows different execution path.",
    }],

    # ── sleep_mode ──
    ("sleep_mode", "basic"): [],
    ("sleep_mode", "jitter"): [],
    ("sleep_mode", "encrypt"): [{
        "tier": 16, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1027",
        "detect_name": "SleepEncryption",
        "description": "Process encrypts its own memory regions before entering sleep and "
                       "decrypts on wake. Memory protection toggling (RW→RX) detected "
                       "around sleep calls. Pattern consistent with sleep obfuscation "
                       "to defeat memory scanning.",
    }],
    ("sleep_mode", "ekko"): [{
        "tier": 19, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1027",
        "detect_name": "EkkoSleepObfuscation",
        "description": "ROP-based sleep obfuscation detected. Process uses timer queue "
                       "callbacks to encrypt memory region, set PAGE_NOACCESS, sleep, "
                       "then decrypt and restore permissions. Ekko/Foliage sleep "
                       "obfuscation pattern identified.",
    }],
    ("sleep_mode", "zilean"): [{
        "tier": 19, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1497.003",
        "detect_name": "ZileanSleepObfuscation",
        "description": "Zilean-style sleep obfuscation detected. Process uses NtContinue to "
                       "transfer execution through ROP chain during sleep. Memory protection "
                       "cycling and context manipulation pattern matches known Zilean variant.",
    }],
    ("sleep_mode", "foliage"): [{
        "tier": 20, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1497.003",
        "detect_name": "FoliageSleepObfuscation",
        "description": "Foliage sleep obfuscation detected via APC-based timer callback analysis. "
                       "Process queues user APC that encrypts memory, sleeps via NtDelayExecution, "
                       "then decrypts via second APC. Detection via ETW APC tracing.",
    }],
    ("sleep_mode", "gargoyle"): [{
        "tier": 18, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1497.003",
        "detect_name": "GargoyleSleepEvasion",
        "description": "Gargoyle-style sleep evasion detected. Process transitions between RW and "
                       "non-accessible memory states using timer callbacks. Code only executable "
                       "during timer activation — position-independent code in ROP chain.",
    }],
    ("sleep_mode", "death_sleep"): [{
        "tier": 20, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1497.003",
        "detect_name": "DeathSleepDetected",
        "description": "Process thread entered extended sleep state with all memory regions set to "
                       "PAGE_NOACCESS. Thread context points to NtContinue gadget chain. All "
                       "indicators of death_sleep technique — process becomes invisible during sleep.",
    }],

    # ── exfil ──
    ("exfil", "tcp_direct"): [{
        "tier": 3, "severity": 3,
        "tactic": "Exfiltration", "technique": "T1041",
        "detect_name": "SuspiciousOutboundConnection",
        "description": "Process established raw TCP connection to external IP on "
                       "non-standard port. Connection not using HTTP/HTTPS protocol. "
                       "Process has no legitimate reason for raw socket communication. "
                       "Data transfer detected on established connection.",
    }],
    ("exfil", "http_post"): [{
        "tier": 6, "severity": 2,
        "tactic": "Exfiltration", "technique": "T1048.003",
        "detect_name": "SuspiciousHTTPExfiltration",
        "description": "Process sending large HTTP POST request to unrecognized endpoint. "
                       "Request body size and frequency inconsistent with legitimate API "
                       "usage. Destination IP/domain has no established reputation.",
    }],
    ("exfil", "https_post"): [{
        "tier": 10, "severity": 2,
        "tactic": "Exfiltration", "technique": "T1048.003",
        "detect_name": "EncryptedExfiltration",
        "description": "Process sending HTTPS POST to low-reputation endpoint. While "
                       "encrypted, the volume and timing of outbound data transfer from "
                       "a process with sensitive data access is anomalous.",
    }],
    ("exfil", "winhttp_get"): [{
        "tier": 12, "severity": 1,
        "tactic": "Exfiltration", "technique": "T1048.003",
        "detect_name": "EncodedHTTPExfiltration",
        "description": "Process sending HTTP GET requests with unusually long URL parameters. "
                       "Parameter encoding pattern suggests data exfiltration via URL query "
                       "strings rather than legitimate API usage.",
    }],
    ("exfil", "winhttp_api"): [{
        "tier": 13, "severity": 1,
        "tactic": "Exfiltration", "technique": "T1071.001",
        "detect_name": "HTTPAPITrafficAnomaly",
        "description": "Process using WinHTTP API to communicate with external endpoint. "
                       "Request pattern resembles software update check but payload size "
                       "and content type are inconsistent with update protocol.",
    }],
    ("exfil", "dns_exfil"): [{
        "tier": 11, "severity": 3,
        "tactic": "Exfiltration", "technique": "T1048.001",
        "detect_name": "DNSExfiltration",
        "description": "Process generating high volume of DNS queries with encoded subdomain "
                       "labels. Query pattern and subdomain entropy are consistent with "
                       "DNS tunneling for data exfiltration. Subdomain label length exceeds "
                       "normal distribution.",
    }],
    ("exfil", "dns_txt"): [{
        "tier": 12, "severity": 3,
        "tactic": "Exfiltration", "technique": "T1048.001",
        "detect_name": "DNSTXTExfiltration",
        "description": "Process issuing DNS TXT record queries with base32-encoded data in "
                       "subdomain. Response TXT records contain encoded payload data. "
                       "Bidirectional DNS tunneling pattern detected.",
    }],
    ("exfil", "smb_write"): [{
        "tier": 9, "severity": 2,
        "tactic": "Exfiltration", "technique": "T1048.002",
        "detect_name": "SMBDataExfiltration",
        "description": "Process writing data via SMB to network share. File write pattern "
                       "and content type inconsistent with normal file server usage.",
    }],
    ("exfil", "http_get_chunks"): [{
        "tier": 13, "severity": 1,
        "tactic": "Exfiltration", "technique": "T1048.003",
        "detect_name": "ChunkedHTTPExfiltration",
        "description": "Process sending multiple small HTTP GET requests with hex-encoded "
                       "parameters. Chunked transfer pattern with consistent timing suggests "
                       "automated data exfiltration over HTTP.",
    }],
    ("exfil", "named_pipe"): [],
    ("exfil", "certutil_lolbin"): [{
        "tier": 4, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1140",
        "detect_name": "CertutilAbuse",
        "description": "certutil.exe invoked for base64 encoding/decoding or URL download. "
                       "certutil is a well-known LOLBin for data transfer and encoding. "
                       "Command line: certutil -encode/-urlcache.",
    }],
    ("exfil", "bitsadmin_lolbin"): [{
        "tier": 4, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1197",
        "detect_name": "BITSAdminAbuse",
        "description": "BITSAdmin.exe used to create transfer job. BITS jobs can transfer "
                       "data in the background and survive reboots. Known LOLBin technique.",
    }],
    ("exfil", "powershell_lolbin"): [{
        "tier": 3, "severity": 3,
        "tactic": "Execution", "technique": "T1059.001",
        "detect_name": "PowerShellWebRequest",
        "description": "PowerShell Invoke-WebRequest detected transferring data to external "
                       "endpoint. Script block logging captured command. PowerShell is heavily "
                       "monitored for malicious usage.",
    }],
    ("exfil", "cscript_lolbin"): [{
        "tier": 5, "severity": 3,
        "tactic": "Execution", "technique": "T1059.005",
        "detect_name": "ScriptHostExecution",
        "description": "cscript.exe executing script that creates network connection via "
                       "WScript.Shell or MSXML2.XMLHTTP. Windows Script Host execution "
                       "of network-active scripts is monitored.",
    }],
    ("exfil", "mshta_lolbin"): [{
        "tier": 4, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1218.005",
        "detect_name": "MshtaExecution",
        "description": "mshta.exe executing JavaScript/VBScript with network operations. "
                       "mshta is a high-confidence malware indicator when executing "
                       "inline scripts or remote HTA files.",
    }],
    ("exfil", "curl_lolbin"): [{
        "tier": 5, "severity": 2,
        "tactic": "Exfiltration", "technique": "T1048.003",
        "detect_name": "CurlExfiltration",
        "description": "curl.exe used by non-interactive process to POST data to external "
                       "endpoint. Curl spawned as child of unknown process with large "
                       "request body.",
    }],
    ("exfil", "cloud_onedrive"): [],
    ("exfil", "cloud_gdrive"): [],
    ("exfil", "email_mapi"): [],
    ("exfil", "paste_site"): [],
    ("exfil", "dead_drop"): [],
    ("exfil", "dead_drop_cloud"): [],
    ("exfil", "browser_post"): [],
    ("exfil", "steganography"): [],

    # ── persistence ──
    ("persistence", "none"): [],
    ("persistence", "registry_run"): [{
        "tier": 2, "severity": 3,
        "tactic": "Persistence", "technique": "T1547.001",
        "detect_name": "RegistryRunKeyModification",
        "description": "Process modified HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                       "registry key. New auto-start entry added pointing to unsigned binary "
                       "in user-writable directory. Registry Run keys are a primary "
                       "persistence mechanism monitored by all EDR platforms.",
    }],
    ("persistence", "scheduled_task"): [{
        "tier": 3, "severity": 3,
        "tactic": "Persistence", "technique": "T1053.005",
        "detect_name": "ScheduledTaskCreation",
        "description": "New scheduled task created via schtasks.exe or Task Scheduler COM API. "
                       "Task action points to unsigned binary. Task configured for "
                       "ONLOGON/DAILY trigger. Scheduled task persistence detected.",
    }],
    ("persistence", "startup_folder"): [{
        "tier": 2, "severity": 3,
        "tactic": "Persistence", "technique": "T1547.001",
        "detect_name": "StartupFolderPersistence",
        "description": "New file placed in user Startup folder "
                       "(AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup). "
                       "File is executable or shortcut pointing to unsigned binary.",
    }],
    ("persistence", "service"): [{
        "tier": 2, "severity": 4,
        "tactic": "Persistence", "technique": "T1543.003",
        "detect_name": "SuspiciousServiceCreation",
        "description": "New Windows service created with sc.exe or Service Control Manager API. "
                       "Service binary is unsigned and located in non-standard path. Service "
                       "configured for auto-start. Requires administrator privileges.",
    }],
    ("persistence", "com_hijack"): [{
        "tier": 15, "severity": 2,
        "tactic": "Persistence", "technique": "T1546.015",
        "detect_name": "COMObjectHijack",
        "description": "COM object CLSID hijacked in HKCU\\Software\\Classes\\CLSID. Legitimate "
                       "application will load attacker DLL when instantiating the hijacked COM "
                       "class. DLL does not match expected COM server binary.",
    }],
    ("persistence", "dll_search_order"): [{
        "tier": 14, "severity": 2,
        "tactic": "Persistence", "technique": "T1574.001",
        "detect_name": "DLLSearchOrderHijack",
        "description": "DLL placed in application directory to exploit search order precedence. "
                       "Application loads attacker DLL instead of system version. DLL is unsigned "
                       "and does not match expected file in System32.",
    }],
    ("persistence", "ifeo_debugger"): [{
        "tier": 8, "severity": 3,
        "tactic": "Persistence", "technique": "T1546.012",
        "detect_name": "IFEODebuggerPersistence",
        "description": "Image File Execution Options debugger key set for common system "
                       "binary. Process will be launched as debugger whenever the target "
                       "binary is executed. IFEO persistence technique detected.",
    }],
    ("persistence", "print_monitor_persist"): [{
        "tier": 16, "severity": 2,
        "tactic": "Persistence", "technique": "T1547.010",
        "detect_name": "PrintMonitorPersistence",
        "description": "New print monitor DLL registered under "
                       "SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors. DLL loaded by "
                       "spoolsv.exe at boot as SYSTEM. Uncommon persistence mechanism.",
    }],
    ("persistence", "network_provider"): [{
        "tier": 18, "severity": 2,
        "tactic": "Persistence", "technique": "T1556",
        "detect_name": "NetworkProviderPersistence",
        "description": "Custom network provider DLL registered under "
                       "SYSTEM\\CurrentControlSet\\Services\\<name>\\NetworkProvider. DLL loaded by "
                       "mpnotify.exe at logon, receives plaintext credentials. Rare persistence mechanism.",
    }],
    ("persistence", "wmi_subscription"): [{
        "tier": 9, "severity": 2,
        "tactic": "Persistence", "technique": "T1546.003",
        "detect_name": "WMIPersistence",
        "description": "WMI permanent event subscription created. EventConsumer bound to "
                       "EventFilter. Subscription survives reboot and executes "
                       "script/command on trigger. WMI persistence detected.",
    }],
    ("persistence", "accessibility_replace"): [{
        "tier": 3, "severity": 4,
        "tactic": "Persistence", "technique": "T1546.008",
        "detect_name": "AccessibilityBinaryReplacement",
        "description": "Accessibility binary replaced (sethc.exe, utilman.exe, osk.exe). "
                       "Replacement binary can be triggered from Windows login screen "
                       "for SYSTEM-level access. Known persistence/backdoor technique.",
    }],

    # ── data_staging ──
    ("data_staging", "memory_only"): [],
    ("data_staging", "temp_file"): [{
        "tier": 5, "severity": 2,
        "tactic": "Collection", "technique": "T1074.001",
        "detect_name": "SuspiciousTempFileStaging",
        "description": "Process creating temporary files in %%TEMP%% directory containing "
                       "collected system data (credentials, browser data, system info). "
                       "Data staging in temp directory before exfiltration.",
    }],
    ("data_staging", "registry"): [{
        "tier": 14, "severity": 1,
        "tactic": "Collection", "technique": "T1074",
        "detect_name": "RegistryDataStaging",
        "description": "Process writing large binary data to registry values under "
                       "non-standard key path. Registry used as data staging area "
                       "for collected information.",
    }],
    ("data_staging", "ads"): [{
        "tier": 11, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1564.004",
        "detect_name": "AlternateDataStreamUsage",
        "description": "Process writing data to NTFS Alternate Data Stream (ADS). Data "
                       "hidden from standard directory listing. ADS commonly used by "
                       "malware for data hiding and staging.",
    }],
    ("data_staging", "wmi_repo"): [{
        "tier": 17, "severity": 2,
        "tactic": "Collection", "technique": "T1074",
        "detect_name": "WMIRepositoryStaging",
        "description": "Process writing binary data to WMI repository via MofComp or CIM. "
                       "WMI repository is a persistent storage that survives reboots. "
                       "Non-standard use of WMI for data staging detected.",
    }],
    ("data_staging", "event_log"): [{
        "tier": 18, "severity": 2,
        "tactic": "Collection", "technique": "T1074",
        "detect_name": "EventLogDataStaging",
        "description": "Process writing encoded data to Windows Event Log entries. Using "
                       "event log as covert storage channel. Custom event source with base64 "
                       "encoded payload detected in event message body.",
    }],
    ("data_staging", "shared_memory"): [{
        "tier": 16, "severity": 2,
        "tactic": "Collection", "technique": "T1074",
        "detect_name": "SharedMemoryStaging",
        "description": "Named shared memory section created for inter-process data staging. "
                       "Section name pattern does not match known legitimate IPC channels. "
                       "Potential covert data relay between processes.",
    }],
    ("data_staging", "browser_storage"): [{
        "tier": 19, "severity": 2,
        "tactic": "Collection", "technique": "T1074",
        "detect_name": "BrowserStorageAbuse",
        "description": "Process injecting data into browser's IndexedDB or localStorage via "
                       "Chrome DevTools Protocol or direct SQLite manipulation. Using browser "
                       "storage as covert staging area for exfiltration data.",
    }],

    # ── anti_forensics ──
    ("anti_forensics", "none"): [],
    ("anti_forensics", "self_delete"): [{
        "tier": 6, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1070.004",
        "detect_name": "SelfDeletingBinary",
        "description": "Process deleted its own executable file after completing operations. "
                       "Self-deletion via pending delete on close or alternate file stream "
                       "rename technique. Anti-forensics indicator.",
    }],
    ("anti_forensics", "timestomp"): [{
        "tier": 8, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1070.006",
        "detect_name": "TimestampManipulation",
        "description": "File timestamps modified via SetFileTime API. Creation/modification "
                       "timestamps set to match surrounding system files. Timestomping "
                       "detected via MFT analysis discrepancy.",
    }],
    ("anti_forensics", "memory_only_full"): [{
        "tier": 17, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1070",
        "detect_name": "FullMemoryOnlyOperation",
        "description": "Process performed all operations without writing to disk. No temp files, "
                       "no registry writes, no log entries. Complete memory-only execution profile "
                       "with cleanup of all volatile artifacts. Sophisticated anti-forensics.",
    }],
    ("anti_forensics", "blend_noise"): [{
        "tier": 18, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1070",
        "detect_name": "ForensicNoiseCamouflage",
        "description": "Process generating decoy file operations, registry writes, and network "
                       "requests to blend malicious activity with legitimate-looking noise. "
                       "Statistical analysis of I/O patterns shows artificial distribution.",
    }],

    # ── process_lifetime ──
    ("process_lifetime", "ephemeral_seconds"): [{
        "tier": 14, "severity": 1,
        "tactic": "Defense Evasion", "technique": "T1070",
        "detect_name": "EphemeralProcessBehavior",
        "description": "Process executed for under 10 seconds then terminated cleanly. Short "
                       "execution window with high-density API calls suggests designed to "
                       "evade behavioral monitoring time thresholds.",
    }],
    ("process_lifetime", "ephemeral_staged"): [{
        "tier": 16, "severity": 1,
        "tactic": "Execution", "technique": "T1059",
        "detect_name": "StagedEphemeralExecution",
        "description": "Multiple short-lived processes executed in sequence. Each process "
                       "performs a single operation and exits. Staged execution chain "
                       "distributes attack across process boundaries.",
    }],
    ("process_lifetime", "medium_minutes"): [{
        "tier": 12, "severity": 1,
        "tactic": "Execution", "technique": "T1059",
        "detect_name": "MediumDurationUnknownProcess",
        "description": "Unknown process ran for 2-15 minutes performing data access and "
                       "network operations. Duration and activity pattern consistent with "
                       "data collection followed by exfiltration.",
    }],
    ("process_lifetime", "persistent"): [],
    ("process_lifetime", "burst_and_die"): [{
        "tier": 16, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1070",
        "detect_name": "BurstExecution",
        "description": "Process completed all operations in under 2 seconds and terminated. "
                       "Rapid execution with immediate exit suggests payload designed to "
                       "outrun behavioral analysis window.",
    }],

    # ── collection_strategy (infostealer) ──
    ("collection_strategy", "bulk_immediate"): [{
        "tier": 4, "severity": 3,
        "tactic": "Collection", "technique": "T1119",
        "detect_name": "BulkDataCollection",
        "description": "Process rapidly accessed multiple sensitive data stores (browser "
                       "databases, credential vaults, cryptocurrency wallets) within seconds. "
                       "Bulk automated collection pattern with no user interaction detected.",
    }],
    ("collection_strategy", "incremental_slow"): [{
        "tier": 16, "severity": 1,
        "tactic": "Collection", "technique": "T1119",
        "detect_name": "SlowIncrementalCollection",
        "description": "Process performing gradual data collection over extended period. Small "
                       "data reads from sensitive files at regular intervals. Low-and-slow "
                       "collection pattern designed to evade burst-detection thresholds.",
    }],
    ("collection_strategy", "event_triggered"): [{
        "tier": 18, "severity": 1,
        "tactic": "Collection", "technique": "T1119",
        "detect_name": "EventTriggeredCollection",
        "description": "Data collection triggered by specific system events (user login, "
                       "browser launch, file save). ReadDirectoryChangesW and WMI event "
                       "subscriptions used to trigger targeted collection.",
    }],
    ("collection_strategy", "memory_scraping"): [{
        "tier": 10, "severity": 3,
        "tactic": "Credential Access", "technique": "T1003.001",
        "detect_name": "ProcessMemoryScraping",
        "description": "Process reading memory of other processes via ReadProcessMemory. "
                       "Target processes include browsers and credential managers. Memory "
                       "scraping for decrypted credentials detected.",
    }],
    ("collection_strategy", "clipboard_watch"): [{
        "tier": 14, "severity": 1,
        "tactic": "Collection", "technique": "T1115",
        "detect_name": "ClipboardMonitoring",
        "description": "Process monitoring clipboard changes via AddClipboardFormatListener or "
                       "SetClipboardViewer. Continuous clipboard monitoring from unsigned "
                       "process. Data exfiltration or credential capture possible.",
    }],
    ("collection_strategy", "piggyback_legit"): [{
        "tier": 19, "severity": 1,
        "tactic": "Collection", "technique": "T1005",
        "detect_name": "LegitProcessPiggyback",
        "description": "Data collection piggybacking on legitimate process operations. Injected "
                       "code intercepts file I/O and network requests of host process. Collection "
                       "hidden within normal process activity.",
    }],
    ("collection_strategy", "on_demand"): [{
        "tier": 21, "severity": 1,
        "tactic": "Collection", "technique": "T1005",
        "detect_name": "OnDemandCollection",
        "description": "Data collection only triggered by remote C2 command. No autonomous "
                       "collection activity — waits for operator-initiated tasking. Cloud analytics "
                       "correlates collection bursts with inbound C2 commands.",
    }],

    # ── target_scope (infostealer) ──
    ("target_scope", "comprehensive"): [{
        "tier": 7, "severity": 3,
        "tactic": "Collection", "technique": "T1005",
        "detect_name": "ComprehensiveDataAccess",
        "description": "Process accessed data across multiple categories: browser databases, "
                       "credential stores, cryptocurrency wallets, email clients, documents, "
                       "and screenshots. Broad data access pattern matches infostealer "
                       "behavioral profile.",
    }],
    ("target_scope", "browser_only"): [{
        "tier": 11, "severity": 2,
        "tactic": "Credential Access", "technique": "T1555.003",
        "detect_name": "BrowserCredentialAccess",
        "description": "Process accessed browser credential databases (Login Data, cookies.sqlite) "
                       "and decryption keys. Browser-focused credential theft detected.",
    }],
    ("target_scope", "credential_only"): [{
        "tier": 9, "severity": 3,
        "tactic": "Credential Access", "technique": "T1555",
        "detect_name": "CredentialStoreAccess",
        "description": "Process accessed Windows credential stores (Credential Manager, "
                       "DPAPI master keys, browser saved passwords). Focused credential "
                       "theft operation detected.",
    }],
    ("target_scope", "clipboard_only"): [{
        "tier": 15, "severity": 1,
        "tactic": "Collection", "technique": "T1115",
        "detect_name": "ClipboardTargeting",
        "description": "Process exclusively targets clipboard data. Monitors for specific "
                       "clipboard content patterns (crypto addresses, passwords, URLs). "
                       "Narrow targeting suggests clipboard hijacker or data interceptor.",
    }],
    ("target_scope", "session_tokens"): [{
        "tier": 14, "severity": 2,
        "tactic": "Credential Access", "technique": "T1539",
        "detect_name": "SessionTokenTheft",
        "description": "Process extracting active session tokens/cookies from browser "
                       "process memory. Token theft enables session hijacking without "
                       "credential knowledge.",
    }],
    ("target_scope", "file_targeted"): [{
        "tier": 21, "severity": 1,
        "tactic": "Collection", "technique": "T1005",
        "detect_name": "TargetedFileCollection",
        "description": "Process accessing a narrow set of specific file paths matching known "
                       "sensitive locations (credentials, SSH keys, browser profiles). Access "
                       "pattern indistinguishable from legitimate file managers or backup tools "
                       "until cross-referenced with process reputation via cloud analytics.",
    }],
    ("target_scope", "environment_recon"): [{
        "tier": 13, "severity": 1,
        "tactic": "Discovery", "technique": "T1082",
        "detect_name": "EnvironmentReconnaissance",
        "description": "Process enumerating system environment: OS version, domain membership, "
                       "installed software, network configuration, security products. Comprehensive "
                       "system profiling consistent with initial reconnaissance phase.",
    }],

    # ── capture_method (keylogger) ──
    ("capture_method", "hook_ll"): [{
        "tier": 3, "severity": 4,
        "tactic": "Collection", "technique": "T1056.001",
        "detect_name": "KeyboardHookInstalled",
        "description": "Global keyboard hook installed via SetWindowsHookEx(WH_KEYBOARD_LL). "
                       "Low-level keyboard hook from unsigned process. Classic keylogger "
                       "technique, heavily monitored.",
    }],
    ("capture_method", "getasynckeystate"): [{
        "tier": 12, "severity": 2,
        "tactic": "Collection", "technique": "T1056.001",
        "detect_name": "KeystatePolling",
        "description": "Process polling GetAsyncKeyState in tight loop. While used by "
                       "legitimate games and accessibility tools, polling pattern from "
                       "non-game process is suspicious.",
    }],
    ("capture_method", "raw_input"): [{
        "tier": 13, "severity": 2,
        "tactic": "Collection", "technique": "T1056.001",
        "detect_name": "RawInputCapture",
        "description": "Process registered for raw keyboard input via RegisterRawInputDevices. "
                       "HID-level keyboard capture from non-input-focused application.",
    }],
    ("capture_method", "directinput"): [],
    ("capture_method", "ui_automation"): [],
    ("capture_method", "clipboard_monitor"): [],
    ("capture_method", "etw_consumer"): [],
    ("capture_method", "ime_hijack"): [],
    ("capture_method", "getkeybstate"): [{
        "tier": 14, "severity": 1,
        "tactic": "Collection", "technique": "T1056.001",
        "detect_name": "KeyboardStatePolling",
        "description": "Process periodically calling GetKeyboardState to capture full "
                       "256-key state array. Uncommon outside of game engines.",
    }],
    ("capture_method", "screen_ocr"): [],
    ("capture_method", "winevent_hook"): [{
        "tier": 15, "severity": 1,
        "tactic": "Collection", "technique": "T1056.001",
        "detect_name": "AccessibilityHookCapture",
        "description": "SetWinEventHook monitoring text change events. Similar to screen "
                       "reader behavior but from process without accessibility manifest.",
    }],
    ("capture_method", "msg_hook"): [{
        "tier": 6, "severity": 3,
        "tactic": "Collection", "technique": "T1056.001",
        "detect_name": "MessageHookKeylogger",
        "description": "Global message hook installed via SetWindowsHookEx(WH_GETMESSAGE). "
                       "Hook intercepts WM_KEYDOWN messages from all threads. Known "
                       "keylogger injection technique.",
    }],

    # ── capture_tempo (keylogger) ──
    ("capture_tempo", "continuous"): [{
        "tier": 8, "severity": 2,
        "tactic": "Collection", "technique": "T1056.001",
        "detect_name": "ContinuousKeyCapture",
        "description": "Process continuously capturing keyboard input 24/7 without pauses. "
                       "Continuous capture with no idle periods inconsistent with "
                       "legitimate input processing.",
    }],
    ("capture_tempo", "business_hours"): [],
    ("capture_tempo", "foreground_app"): [],
    ("capture_tempo", "url_specific"): [],
    ("capture_tempo", "burst_capture"): [{
        "tier": 15, "severity": 1,
        "tactic": "Collection", "technique": "T1056.001",
        "detect_name": "BurstKeyCapture",
        "description": "Keyboard capture activates in periodic bursts with gaps. Intermittent "
                       "capture pattern with consistent on/off cycle detected.",
    }],
    ("capture_tempo", "event_triggered"): [],
    ("capture_tempo", "human_paced"): [],

    # ── c2_paradigm (backdoor) ──
    ("c2_paradigm", "active_beacon"): [{
        "tier": 5, "severity": 4,
        "tactic": "Command and Control", "technique": "T1071",
        "detect_name": "C2Beaconing",
        "description": "Process establishing periodic outbound connections to external "
                       "endpoint. Beacon interval analysis shows consistent check-in "
                       "pattern with jitter. Command and control beaconing detected.",
    }],
    ("c2_paradigm", "passive_listener"): [{
        "tier": 8, "severity": 3,
        "tactic": "Command and Control", "technique": "T1571",
        "detect_name": "BindShellListener",
        "description": "Process listening on network port for inbound connections. Bind "
                       "shell behavior detected — process accepts connections and "
                       "executes received commands.",
    }],
    ("c2_paradigm", "dead_drop_cloud"): [],
    ("c2_paradigm", "dead_drop_dns"): [],
    ("c2_paradigm", "triggered_file"): [],
    ("c2_paradigm", "triggered_pipe"): [],
    ("c2_paradigm", "email_c2"): [],
    ("c2_paradigm", "legit_service_poll"): [],
    ("c2_paradigm", "p2p_mesh"): [{
        "tier": 16, "severity": 3,
        "tactic": "Command and Control", "technique": "T1090.003",
        "detect_name": "P2PMeshCommunication",
        "description": "Process communicating with multiple internal endpoints in mesh "
                       "pattern. Peer-to-peer command relay detected across multiple hosts.",
    }],
    ("c2_paradigm", "domain_front"): [],
    ("c2_paradigm", "serverless_c2"): [],
    ("c2_paradigm", "websocket"): [{
        "tier": 13, "severity": 2,
        "tactic": "Command and Control", "technique": "T1071.001",
        "detect_name": "WebSocketC2",
        "description": "Process maintaining persistent WebSocket connection to external "
                       "endpoint. Bidirectional real-time communication channel from "
                       "non-browser process.",
    }],

    # ── cmd_execution (backdoor) ──
    ("cmd_execution", "in_process"): [],
    ("cmd_execution", "child_cmd"): [{
        "tier": 3, "severity": 3,
        "tactic": "Execution", "technique": "T1059.003",
        "detect_name": "SuspiciousCmdChild",
        "description": "Process spawned cmd.exe as child process. Command line contains "
                       "system enumeration or data access commands. Parent-child process "
                       "chain from unsigned binary to cmd.exe.",
    }],
    ("cmd_execution", "child_ps"): [{
        "tier": 2, "severity": 4,
        "tactic": "Execution", "technique": "T1059.001",
        "detect_name": "SuspiciousPowerShellChild",
        "description": "Process spawned powershell.exe. Script block logging captured "
                       "executed commands. AMSI scan triggered on script content. "
                       "PowerShell child from unsigned parent is high-confidence indicator.",
    }],
    ("cmd_execution", "lolbin_proxy"): [{
        "tier": 6, "severity": 2,
        "tactic": "Defense Evasion", "technique": "T1218",
        "detect_name": "LOLBinExecution",
        "description": "Process using signed Windows binaries (certutil, bitsadmin, wmic) "
                       "as execution proxies. LOLBin chain detected: unsigned parent → "
                       "signed system binary → sensitive operation.",
    }],
    ("cmd_execution", "wmi_exec"): [{
        "tier": 9, "severity": 2,
        "tactic": "Execution", "technique": "T1047",
        "detect_name": "WMICommandExecution",
        "description": "Commands executed via WMI ExecMethod. Process instantiated "
                       "Win32_Process::Create through WMI. Command runs as wmiprvse.exe "
                       "child, obscuring parent relationship.",
    }],
    ("cmd_execution", "schtasks_exec"): [{
        "tier": 7, "severity": 2,
        "tactic": "Execution", "technique": "T1053.005",
        "detect_name": "ScheduledTaskExecution",
        "description": "One-shot scheduled task created for command execution. Task "
                       "provides clean parent chain via svchost.exe. Task deleted "
                       "after execution.",
    }],
    ("cmd_execution", "com_exec"): [],
    ("cmd_execution", "clr_host"): [{
        "tier": 11, "severity": 2,
        "tactic": "Execution", "technique": "T1059",
        "detect_name": "InProcessCLRExecution",
        "description": "Process loaded .NET CLR to execute managed code without spawning "
                       "powershell.exe. CLR loaded by non-.NET binary is uncommon and "
                       "can indicate execute-assembly technique.",
    }],
    ("cmd_execution", "embedded_script"): [],

    # ── kernel_evasion ──
    ("kernel_evasion", "none"): [],
    ("kernel_evasion", "byovd_rtcore"): [{
        "tier": 4, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1068",
        "detect_name": "BYOVDRTCore",
        "description": "Vulnerable driver RTCore64.sys (CVE-2019-16098) loaded. Driver hash "
                       "matches Microsoft Vulnerable Driver Blocklist entry. Driver provides "
                       "arbitrary kernel read/write via IOCTL. BYOVD attack detected.",
    }],
    ("kernel_evasion", "byovd_dbutil"): [{
        "tier": 7, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1068",
        "detect_name": "BYOVDDbutil",
        "description": "Vulnerable driver dbutil_2_3.sys loaded via service creation. Dell "
                       "BIOS utility driver provides arbitrary kernel memory access. Driver "
                       "used by known EDR-killing tools (RealBlindingEDR).",
    }],
    ("kernel_evasion", "byovd_procexp"): [{
        "tier": 6, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1068",
        "detect_name": "BYOVDProcExp",
        "description": "Process Explorer driver (PROCEXP.SYS) loaded and used to terminate "
                       "protected processes. While Microsoft-signed, driver's process kill "
                       "capability is being abused for EDR evasion.",
    }],
    ("kernel_evasion", "byovd_custom"): [{
        "tier": 17, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1068",
        "detect_name": "SuspiciousDriverLoad",
        "description": "Kernel driver loaded from user-writable directory via service creation. "
                       "Driver hash is unknown and not in application baseline. Driver receives "
                       "IOCTL requests from user-mode process shortly after loading. Possible "
                       "BYOVD with unrecognized vulnerable driver.",
    }],

    # ── callback_evasion ──
    ("callback_evasion", "none"): [],
    ("callback_evasion", "process_callbacks"): [{
        "tier": 9, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "KernelCallbackRemoval",
        "description": "PsSetCreateProcessNotifyRoutine callback array modified. EDR callback "
                       "entry zeroed out. Process creation notifications disabled for security "
                       "product. Kernel tamper protection alert.",
    }],
    ("callback_evasion", "thread_callbacks"): [{
        "tier": 10, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "KernelCallbackRemoval",
        "description": "PsSetCreateThreadNotifyRoutine callback removed. Thread creation "
                       "notifications disabled for security product. Remote thread injection "
                       "can proceed undetected.",
    }],
    ("callback_evasion", "image_callbacks"): [{
        "tier": 10, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "KernelCallbackRemoval",
        "description": "PsSetLoadImageNotifyRoutine callback removed. Image/DLL load "
                       "notifications disabled. Reflective loading and module stomping "
                       "can proceed undetected.",
    }],
    ("callback_evasion", "object_callbacks"): [{
        "tier": 10, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "ObjectCallbackRemoval",
        "description": "ObRegisterCallbacks entries removed. Handle protection stripped "
                       "from EDR and lsass.exe processes. Protected process handles can "
                       "now be opened with full access rights.",
    }],
    ("callback_evasion", "minifilter_unlink"): [{
        "tier": 11, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "MinifilterUnlinked",
        "description": "EDR minifilter driver unlinked from FltMgr filter list. File I/O "
                       "notifications no longer delivered to security product. Minifilter "
                       "remains loaded but receives no callbacks.",
    }],
    ("callback_evasion", "total_blind"): [{
        "tier": 8, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "TotalEDRBlind",
        "description": "Multiple kernel notification callbacks removed simultaneously "
                       "(process, thread, image, object, minifilter). Security product "
                       "receives zero telemetry. EDR process running but completely blinded. "
                       "Total blind attack detected via callback integrity monitoring.",
    }],

    # ── process_protection ──
    ("process_protection", "none"): [],
    ("process_protection", "hide_process"): [{
        "tier": 12, "severity": 4,
        "tactic": "Defense Evasion", "technique": "T1564",
        "detect_name": "DKOMProcessHiding",
        "description": "Process hidden from EPROCESS ActiveProcessLinks list via DKOM. "
                       "Process invisible to Task Manager, Process Explorer, and "
                       "NtQuerySystemInformation but still executing. Cross-reference "
                       "with scheduler thread list reveals hidden process.",
    }],
    ("process_protection", "elevate_ppl"): [{
        "tier": 13, "severity": 5,
        "tactic": "Privilege Escalation", "technique": "T1068",
        "detect_name": "PPLElevation",
        "description": "EPROCESS->Protection field modified to PPL-Antimalware via DKOM. "
                       "Process now immune to termination and inspection by non-PPL "
                       "processes. PPL elevation without legitimate signing detected.",
    }],
    ("process_protection", "strip_edr_ppl"): [{
        "tier": 9, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "PPLProtectionStripped",
        "description": "EDR process EPROCESS->Protection field set to PsProtectedTypeNone "
                       "via kernel DKOM. Protected Process Light protection stripped. "
                       "EDR process can now be terminated via standard TerminateProcess.",
    }],
    ("process_protection", "token_steal"): [{
        "tier": 11, "severity": 5,
        "tactic": "Privilege Escalation", "technique": "T1134",
        "detect_name": "KernelTokenManipulation",
        "description": "EPROCESS->Token pointer modified via DKOM. Process token replaced "
                       "with SYSTEM token from PID 4. Kernel-level privilege escalation "
                       "without standard API calls (AdjustTokenPrivileges).",
    }],

    # ── etw_kernel ──
    ("etw_kernel", "none"): [],
    ("etw_kernel", "dkom_provider"): [{
        "tier": 14, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "ETWProviderDKOM",
        "description": "ETW-TI (Threat Intelligence) provider registration modified via DKOM. "
                       "GuidEntry->ProviderEnableInfo altered to disable threat intelligence "
                       "events. Kernel-level ETW telemetry silenced.",
    }],
    ("etw_kernel", "session_unlink"): [{
        "tier": 15, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "ETWSessionManipulation",
        "description": "EDR consumer removed from ETW-TI session consumer list. Threat "
                       "intelligence events still fire but no security product receives "
                       "them. Session manipulation detected via consumer count monitoring.",
    }],
    ("etw_kernel", "hwbp_veh"): [{
        "tier": 18, "severity": 3,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "HardwareBreakpointETW",
        "description": "Hardware debug register set on kernel ETW function address. VEH "
                       "intercepts breakpoint to suppress ETW events without code "
                       "modification. Patchless bypass detected.",
    }],
}


# ════════════════════════════════════════════════════════════════
# COMBINATION DETECTIONS
# Triggered only when MULTIPLE specific conditions are present.
# These model CrowdStrike's behavioral correlation engine.
# ════════════════════════════════════════════════════════════════

COMBO_DETECTIONS = [
    {
        "conditions": {"timing": "immediate", "collection_strategy": "bulk_immediate"},
        "tier": 5, "severity": 4,
        "tactic": "Collection", "technique": "T1119",
        "detect_name": "AutomatedCollectionBurst",
        "description": "Process launched and immediately began bulk data collection across "
                       "multiple sensitive data sources (browsers, credentials, system info) "
                       "within seconds. Rapid automated collection pattern with no user "
                       "interaction is a high-confidence infostealer indicator.",
    },
    {
        "conditions": {"timing": "immediate", "exfil": "tcp_direct"},
        "tier": 4, "severity": 4,
        "tactic": "Exfiltration", "technique": "T1041",
        "detect_name": "ImmediateExfiltration",
        "description": "Process launched, collected data, and established raw TCP connection "
                       "to external endpoint within seconds of execution. Immediate "
                       "collection-to-exfiltration pipeline detected.",
    },
    {
        "conditions": {"process": "standalone", "persistence": "registry_run"},
        "tier": 3, "severity": 4,
        "tactic": "Persistence", "technique": "T1547.001",
        "detect_name": "UnknownBinaryPersistence",
        "description": "Unknown unsigned executable established persistence via Registry Run "
                       "key. Binary from user-writable directory configured to auto-start. "
                       "Combination of unknown binary + persistence is high-confidence "
                       "malware indicator.",
    },
    {
        "conditions": {"data_obfuscation": "plaintext", "target_scope": "comprehensive"},
        "tier": 2, "severity": 3,
        "tactic": "Collection", "technique": "T1005",
        "detect_name": "InfostealerSignature",
        "description": "Binary contains plaintext strings referencing browser data paths, "
                       "cryptocurrency wallets, and credential stores. String pattern matches "
                       "known infostealer family behavioral profile.",
    },
    {
        "conditions": {"process_lifetime": "persistent", "exfil": "tcp_direct"},
        "tier": 6, "severity": 3,
        "tactic": "Command and Control", "technique": "T1095",
        "detect_name": "PersistentC2Channel",
        "description": "Long-running process maintaining persistent raw TCP connection to "
                       "external endpoint. Periodic data transfers over non-HTTP protocol "
                       "on non-standard port. Behavioral pattern consistent with C2 beacon.",
    },
    {
        "conditions": {"kernel_evasion": "byovd_rtcore", "callback_evasion": "total_blind"},
        "tier": 5, "severity": 5,
        "tactic": "Defense Evasion", "technique": "T1562.001",
        "detect_name": "EDRKillChain",
        "description": "BYOVD attack chain detected: vulnerable driver loaded (RTCore64.sys), "
                       "followed by systematic removal of all kernel notification callbacks. "
                       "Complete EDR blindness attempted. Kill chain matches known "
                       "EDR-killer tools (Terminator, AuKill).",
    },
    {
        "conditions": {"anti_forensics": "none", "data_staging": "temp_file"},
        "tier": 4, "severity": 2,
        "tactic": "Collection", "technique": "T1074.001",
        "detect_name": "ForensicTrailLeftBehind",
        "description": "Process created data staging files in temp directory with no cleanup. "
                       "Files contain collected system data and remain on disk after process "
                       "exit. No anti-forensics measures applied.",
    },
    {
        "conditions": {"execution": "sequential", "target_scope": "comprehensive"},
        "tier": 6, "severity": 3,
        "tactic": "Collection", "technique": "T1119",
        "detect_name": "SequentialDataHarvest",
        "description": "Process sequentially accessed browser databases, credential stores, "
                       "cryptocurrency wallets, and system information without delays. "
                       "Sequential comprehensive data access pattern is characteristic of "
                       "commodity infostealers.",
    },
]


# ════════════════════════════════════════════════════════════════
# DETECTION ENGINE
# ════════════════════════════════════════════════════════════════

def detection_check(config, level, exam_config=None):
    """Check a config against the behavioral detection model at a given sensitivity level.

    Args:
        config: dict of dim → value
        level: detection sensitivity level (1-20). Higher = more detections.
        exam_config: optional dict with exam-specific overrides:
            - 'tier_scale': float multiplier for tier thresholds (default 1.0)
            - 'golden_overrides': dict of (dim, value) pairs that are never detected
            - 'extra_combos': additional combination detections for this exam

    Returns:
        List of (detection_json_str, detect_name) tuples. Empty = clean.
    """
    detections = []
    effective_level = level
    golden = set()

    if exam_config:
        scale = exam_config.get("tier_scale", 1.0)
        effective_level = int(level * scale)
        for dim, val in exam_config.get("golden_overrides", {}).items():
            golden.add((dim, val))

    # Check individual behavioral indicators
    for dim, val in config.items():
        key = (dim, val)
        if key in golden:
            continue
        indicators = BEHAVIORAL_MAP.get(key, [])
        for ind in indicators:
            if ind["tier"] <= effective_level:
                det_json = _format_falcon_event(ind, level)
                detections.append((det_json, ind["detect_name"]))

    # Check combination detections
    all_combos = list(COMBO_DETECTIONS)
    if exam_config and "extra_combos" in exam_config:
        all_combos.extend(exam_config["extra_combos"])

    for combo in all_combos:
        if combo["tier"] > effective_level:
            continue
        if all(config.get(dim) == val for dim, val in combo["conditions"].items()):
            # Check golden overrides don't suppress combo
            if any((dim, val) in golden for dim, val in combo["conditions"].items()):
                continue
            det_json = _format_falcon_event(combo, level)
            detections.append((det_json, combo["detect_name"]))

    return detections


def _format_falcon_event(indicator, level):
    """Format a detection indicator as a realistic CrowdStrike Falcon event JSON."""
    severity_map = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

    event = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "event_simpleName": "DetectionSummaryEvent",
        "Severity": indicator["severity"],
        "SeverityName": severity_map.get(indicator["severity"], "Medium"),
        "Tactic": indicator["tactic"],
        "Technique": indicator["technique"],
        "DetectName": indicator["detect_name"],
        "DetectDescription": indicator["description"],
        "FileName": "payload.exe",
        "FilePath": "\\Device\\HarddiskVolume3\\Users\\vmuser\\Desktop\\",
        "CommandLine": "\"C:\\Users\\vmuser\\Desktop\\payload.exe\"",
        "ParentImageFileName": "explorer.exe",
    }

    return json.dumps(event)


def get_golden_config(max_level=20, tier_scale=1.0, golden_overrides=None):
    """Find configs where all dims have no detections at the given level.

    Returns dict of dim → list of values that are undetected at max_level.
    Useful for designing exam golden configs.
    """
    from templates.chunks.evasion_selector import get_all_layers
    all_layers = get_all_layers("infostealer")

    effective_max = int(max_level * tier_scale)
    golden = set(golden_overrides.items()) if golden_overrides else set()

    result = {}
    for dim, info in all_layers.items():
        safe_values = []
        for val in info["options"]:
            if (dim, val) in golden:
                safe_values.append(val)
                continue
            indicators = BEHAVIORAL_MAP.get((dim, val), [])
            if not indicators or all(ind["tier"] > effective_max for ind in indicators):
                safe_values.append(val)
        result[dim] = safe_values

    return result
