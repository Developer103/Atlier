"""
Exam variant definitions using the behavioral detection model.

Each exam is a config dict consumed by detection_model.detection_check():
  - tier_scale: multiplier for detection sensitivity ramp (higher = harder)
  - golden_overrides: {dim: value} pairs that bypass all detection in this exam
  - extra_combos: additional combination detections specific to this exam
  - description: human-readable exam name

The solver calls:
    exam = get_exam(name)
    detections = detection_check(config, level, exam)

If detections is empty, the config passes that level.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))


# ════════════════════════════════════════════════════════════════
# EASY EXAMS (B-E): tier_scale 0.50-0.55
# Wide solution space. Algo can solve without LLM.
# ════════════════════════════════════════════════════════════════

EXAMS = {
    "B": {
        "description": "Static Analysis Gauntlet",
        "tier_scale": 0.50,
        "golden_overrides": {},
        "extra_combos": [],
    },
    "C": {
        "description": "Behavioral Pacing Challenge",
        "tier_scale": 0.55,
        "golden_overrides": {},
        "extra_combos": [
            {
                "conditions": {"timing": "triggered", "exfil": "named_pipe"},
                "tier": 8, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1048",
                "detect_name": "SuspiciousTimingExfil",
                "description": "Process remained dormant until trigger event, then immediately "
                               "wrote data to named pipe. Trigger-and-exfil pattern is consistent "
                               "with staged data theft.",
            },
        ],
    },
    "D": {
        "description": "Collection Stealth Course",
        "tier_scale": 0.50,
        "golden_overrides": {},
        "extra_combos": [
            {
                "conditions": {"data_staging": "memory_only", "target_scope": "comprehensive"},
                "tier": 7, "severity": 3,
                "tactic": "Collection", "technique": "T1005",
                "detect_name": "InMemoryBulkCollection",
                "description": "Process collected comprehensive data (browsers, credentials, wallets) "
                               "entirely in memory with no disk staging. In-memory bulk collection "
                               "is characteristic of advanced infostealers.",
            },
            {
                "conditions": {"persistence": "none", "process_lifetime": "persistent"},
                "tier": 6, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1070",
                "detect_name": "PersistentNoPersistence",
                "description": "Long-running process with no persistence mechanism. Process appears "
                               "to rely on continuous execution rather than surviving reboots, "
                               "inconsistent with legitimate background services.",
            },
        ],
    },
    "E": {
        "description": "Defense Evasion Drill",
        "tier_scale": 0.55,
        "golden_overrides": {},
        "extra_combos": [
            {
                "conditions": {"anti_analysis": "none", "etw_method": "none"},
                "tier": 8, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1027",
                "detect_name": "NoEvasionBaseline",
                "description": "Process performs sensitive operations with no anti-analysis or "
                               "ETW evasion. Absence of evasion techniques from an unsigned "
                               "binary accessing sensitive data is itself anomalous in "
                               "Falcon's ML model.",
            },
            {
                "conditions": {"sleep_mode": "basic", "process_lifetime": "persistent"},
                "tier": 7, "severity": 2,
                "tactic": "Command and Control", "technique": "T1573",
                "detect_name": "BasicSleepPersistent",
                "description": "Long-running process using basic Sleep() calls with no jitter. "
                               "Predictable sleep pattern from persistent process is consistent "
                               "with basic implant beaconing.",
            },
            {
                "conditions": {"execution": "callback_abuse", "process": "shell_extension"},
                "tier": 9, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1106",
                "detect_name": "ShellExtensionCallback",
                "description": "Shell extension DLL using callback-based execution. Unusual "
                               "pattern — legitimate shell extensions use standard COM "
                               "interfaces, not Windows API callbacks for primary execution.",
            },
        ],
    },

    # ════════════════════════════════════════════════════════════════
    # MEDIUM EXAMS (F-I): tier_scale 0.65-0.75
    # Golden overrides create specific answer paths. LLM helpful.
    # ════════════════════════════════════════════════════════════════

    "F": {
        "description": "Process Injection Maze",
        "tier_scale": 0.65,
        "golden_overrides": {
            "api_resolve": "loadlibrary",
        },
        "extra_combos": [
            {
                "conditions": {"process": "shell_extension", "persistence": "dll_search_order"},
                "tier": 10, "severity": 3,
                "tactic": "Persistence", "technique": "T1574.001",
                "detect_name": "ShellDLLHijack",
                "description": "Shell extension DLL combined with DLL search order hijacking. "
                               "Dual DLL abuse pattern creates persistent presence through "
                               "Explorer process. Known APT technique.",
            },
        ],
    },
    "G": {
        "description": "Network Exfil Laboratory",
        "tier_scale": 0.70,
        "golden_overrides": {
            "api_resolve": "peb_walk",
        },
        "extra_combos": [
            {
                "conditions": {"exfil": "cloud_onedrive", "data_staging": "memory_only"},
                "tier": 10, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1567.002",
                "detect_name": "CloudExfilNoStaging",
                "description": "Process uploading data to OneDrive directly from memory buffers. "
                               "Memory-only collection with immediate cloud upload is consistent "
                               "with advanced stealer behavior.",
            },
            {
                "conditions": {"timing": "workday", "target_scope": "comprehensive"},
                "tier": 11, "severity": 2,
                "tactic": "Collection", "technique": "T1005",
                "detect_name": "WorkdayDataHarvest",
                "description": "Process performs comprehensive data access during business hours. "
                               "Business-hour collection of all sensitive data categories matches "
                               "insider threat or stealer behavioral profile.",
            },
        ],
    },
    "H": {
        "description": "Persistence Stronghold",
        "tier_scale": 0.70,
        "golden_overrides": {
            "api_resolve": "api_hash_djb2",
            "process": "ppid_spoof",
        },
        "extra_combos": [
            {
                "conditions": {"persistence": "com_hijack", "execution": "callback_abuse"},
                "tier": 11, "severity": 3,
                "tactic": "Persistence", "technique": "T1546.015",
                "detect_name": "COMHijackCallbackChain",
                "description": "COM object hijack loading DLL that uses callback-based execution. "
                               "COM persistence combined with callback execution obfuscation is "
                               "consistent with advanced persistent threats.",
            },
            {
                "conditions": {"anti_forensics": "blend_noise", "data_obfuscation": "aes_encrypt"},
                "tier": 12, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1027",
                "detect_name": "EncryptedBlendPattern",
                "description": "Process generates fake filesystem and network noise while encrypting "
                               "all sensitive data. Blending combined with AES encryption indicates "
                               "high-sophistication evasion-aware malware.",
            },
        ],
    },
    "I": {
        "description": "Memory Residence Challenge",
        "tier_scale": 0.75,
        "golden_overrides": {
            "api_resolve": "api_hash_djb2",
        },
        "extra_combos": [
            {
                "conditions": {"memory_residence": "native", "process": "shell_extension"},
                "tier": 12, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1055",
                "detect_name": "NativeShellExtension",
                "description": "Shell extension DLL running native code in Explorer process space. "
                               "Native memory residence in shell extension avoids module stomping "
                               "detection but behavioral analysis flagged unusual shell extension "
                               "API access patterns.",
            },
            {
                "conditions": {"sleep_mode": "jitter", "exfil": "cloud_gdrive"},
                "tier": 11, "severity": 2,
                "tactic": "Command and Control", "technique": "T1071.001",
                "detect_name": "JitteredCloudAccess",
                "description": "Process accessing Google Drive API with jittered timing. Cloud "
                               "API access with artificial timing variation flagged by anomaly "
                               "detection.",
            },
            {
                "conditions": {"timing": "event_logon", "persistence": "none"},
                "tier": 10, "severity": 2,
                "tactic": "Execution", "technique": "T1204",
                "detect_name": "LogonTriggeredNoPersist",
                "description": "Process activates on user logon but has no persistence mechanism. "
                               "Logon-triggered execution without persistence suggests the binary "
                               "is being launched by an external persistence mechanism.",
            },
        ],
    },

    # ════════════════════════════════════════════════════════════════
    # HARD EXAMS (J-M): tier_scale 0.85-0.90
    # Tight golden paths. LLM essential for upper levels.
    # ════════════════════════════════════════════════════════════════

    "J": {
        "description": "EDR Evasion Fortress",
        "tier_scale": 0.85,
        "golden_overrides": {
            "api_resolve": "api_hash_crc32",
            "process": "dll_sideload",
        },
        "extra_combos": [
            {
                "conditions": {"exfil": "cloud_onedrive", "persistence": "com_hijack"},
                "tier": 13, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1567.002",
                "detect_name": "CloudPersistenceChain",
                "description": "COM hijack persistence combined with OneDrive exfiltration. "
                               "Process loads via COM object then exfils to legitimate cloud "
                               "service. Behavioral correlation flagged dual-stage evasion chain.",
            },
            {
                "conditions": {"timing": "triggered", "target_scope": "credential_only"},
                "tier": 14, "severity": 3,
                "tactic": "Credential Access", "technique": "T1555",
                "detect_name": "TriggeredCredentialTheft",
                "description": "Process waits for trigger event then specifically targets credential "
                               "stores. Trigger-based credential access is consistent with targeted "
                               "credential theft operations.",
            },
        ],
    },
    "K": {
        "description": "Syscall Evasion Grid",
        "tier_scale": 0.85,
        "golden_overrides": {
            "api_resolve": "api_hash_fnv1a",
            "persistence": "wmi_subscription",
        },
        "extra_combos": [
            {
                "conditions": {"process": "shell_extension", "exfil": "steganography"},
                "tier": 14, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1001.002",
                "detect_name": "StegShellExtension",
                "description": "Shell extension DLL embedding data in images. Steganographic "
                               "exfiltration from Explorer shell extension is a known APT "
                               "persistence+exfil technique.",
            },
            {
                "conditions": {"data_staging": "event_log", "anti_forensics": "none"},
                "tier": 13, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1070.001",
                "detect_name": "EventLogStagingNoCleanup",
                "description": "Data staged in Windows Event Log entries without forensic "
                               "cleanup. Event log data storage without anti-forensics leaves "
                               "recoverable trail.",
            },
            {
                "conditions": {"execution": "callback_certenumsystem", "timing": "workday"},
                "tier": 15, "severity": 2,
                "tactic": "Execution", "technique": "T1106",
                "detect_name": "CertEnumWorkday",
                "description": "CertEnumSystemStore callback execution during business hours. "
                               "Certificate enumeration callback with workday timing matches "
                               "targeted exfiltration profile.",
            },
        ],
    },
    "L": {
        "description": "Correlation Engine Gauntlet",
        "tier_scale": 0.85,
        "golden_overrides": {
            "api_resolve": "peb_walk",
            "execution": "staged",
        },
        "extra_combos": [
            {
                "conditions": {"process": "shell_extension", "data_staging": "shared_memory"},
                "tier": 14, "severity": 3,
                "tactic": "Collection", "technique": "T1074",
                "detect_name": "SharedMemShellExtension",
                "description": "Shell extension using shared memory sections for data staging. "
                               "Shared memory from Explorer shell extension can enable "
                               "cross-process data collection.",
            },
            {
                "conditions": {"exfil": "dead_drop_cloud", "timing": "event_logon"},
                "tier": 13, "severity": 2,
                "tactic": "Exfiltration", "technique": "T1567",
                "detect_name": "LogonDeadDrop",
                "description": "Dead drop cloud check triggered by user logon event. Logon-timed "
                               "dead drop access matches C2 polling pattern.",
            },
            {
                "conditions": {"anti_analysis": "canary_aware", "sleep_mode": "jitter"},
                "tier": 14, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1497",
                "detect_name": "CanaryJitterCorrelation",
                "description": "Process checks for canary tokens while using jittered sleep. "
                               "Combination of canary awareness and timing evasion indicates "
                               "adversary-aware malware targeting honeypots.",
            },
        ],
    },
    "M": {
        "description": "Threat Intelligence Labyrinth",
        "tier_scale": 0.90,
        "golden_overrides": {
            "api_resolve": "api_hash_djb2",
            "exfil": "dns_txt",
        },
        "extra_combos": [
            {
                "conditions": {"process": "shell_extension", "persistence": "dll_search_order"},
                "tier": 14, "severity": 3,
                "tactic": "Persistence", "technique": "T1574.001",
                "detect_name": "ShellDLLSearchHijack",
                "description": "Shell extension combined with DLL search order hijacking for "
                               "persistence. Dual DLL manipulation in Explorer context detected.",
            },
            {
                "conditions": {"timing": "triggered", "collection_strategy": "on_demand"},
                "tier": 15, "severity": 2,
                "tactic": "Collection", "technique": "T1119",
                "detect_name": "TriggeredOnDemand",
                "description": "On-demand data collection activated by trigger. Trigger-based "
                               "selective collection indicates targeted operation with specific "
                               "data objectives.",
            },
            {
                "conditions": {"data_staging": "browser_storage", "target_scope": "browser_only"},
                "tier": 15, "severity": 3,
                "tactic": "Collection", "technique": "T1185",
                "detect_name": "BrowserDoubleAbuse",
                "description": "Process targeting browser data AND staging stolen data in "
                               "browser local storage. Browser as both target and staging "
                               "mechanism flagged by behavioral correlation.",
            },
            {
                "conditions": {"anti_forensics": "memory_only_full", "data_obfuscation": "aes_encrypt"},
                "tier": 16, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1027",
                "detect_name": "FullMemoryEncrypted",
                "description": "Full memory-only operation with AES encryption. Entire operation "
                               "in encrypted memory with no disk artifacts. Advanced evasion "
                               "technique targeting forensic analysis.",
            },
        ],
    },

    # ════════════════════════════════════════════════════════════════
    # ULTRA-HARD EXAMS (N-P): tier_scale 0.95
    # Very tight constraints. LLM essential throughout.
    # ════════════════════════════════════════════════════════════════

    "N": {
        "description": "Threat Intelligence Nightmare",
        "tier_scale": 0.95,
        "golden_overrides": {
            "api_resolve": "indirect_syscall",
            "process": "com_object",
            "exfil": "https_post",
        },
        "extra_combos": [
            {
                "conditions": {"timing": "triggered", "persistence": "com_hijack"},
                "tier": 16, "severity": 3,
                "tactic": "Persistence", "technique": "T1546.015",
                "detect_name": "TriggeredCOMHijack",
                "description": "Trigger-based activation combined with COM hijack persistence. "
                               "Event-driven COM object loading matches advanced persistent "
                               "threat behavior.",
            },
            {
                "conditions": {"execution": "callback_abuse", "data_staging": "wmi_repo"},
                "tier": 16, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1047",
                "detect_name": "CallbackWMIStaging",
                "description": "Callback-based execution staging data in WMI repository. "
                               "WMI data staging combined with callback execution chain "
                               "matches known APT framework behavior.",
            },
            {
                "conditions": {"anti_forensics": "blend_noise", "sleep_mode": "jitter"},
                "tier": 17, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1027",
                "detect_name": "BlendJitterCorrelation",
                "description": "Filesystem noise generation combined with jittered sleep. "
                               "Blending pattern with artificial timing variation detected "
                               "by behavioral correlation engine.",
            },
        ],
    },
    "O": {
        "description": "ML Evasion Challenge",
        "tier_scale": 0.95,
        "golden_overrides": {
            "api_resolve": "api_hash_crc32",
            "process": "dll_sideload",
            "sleep_mode": "encrypt",
        },
        "extra_combos": [
            {
                "conditions": {"execution": "callback_certenumsystem", "exfil": "cloud_gdrive"},
                "tier": 16, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1567.002",
                "detect_name": "CertCallbackGDrive",
                "description": "CertEnumSystemStore callback exfiltrating to Google Drive. "
                               "Certificate API callback combined with cloud exfil is an "
                               "uncommon but documented APT technique.",
            },
            {
                "conditions": {"persistence": "network_provider", "data_staging": "shared_memory"},
                "tier": 17, "severity": 3,
                "tactic": "Persistence", "technique": "T1556",
                "detect_name": "NetworkProviderDataLeak",
                "description": "Network provider DLL staging data in shared memory sections. "
                               "Network authentication interceptor with cross-process data "
                               "staging pattern detected.",
            },
            {
                "conditions": {"timing": "event_process", "anti_analysis": "exec_guardrails"},
                "tier": 16, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1480",
                "detect_name": "ProcessGuardrailCombo",
                "description": "Process-triggered execution with execution guardrails. "
                               "Target-aware activation combined with environment validation "
                               "matches targeted implant profile.",
            },
            {
                "conditions": {"data_staging": "event_log", "exfil": "dead_drop"},
                "tier": 16, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1048",
                "detect_name": "EventLogDeadDrop",
                "description": "Data staged in event logs then retrieved via dead drop. "
                               "Multi-stage staging+exfil chain detected by behavioral "
                               "correlation engine.",
            },
        ],
    },
    "P": {
        "description": "Full Spectrum Defense",
        "tier_scale": 0.95,
        "golden_overrides": {
            "api_resolve": "api_hash_fnv1a",
            "execution": "fiber",
            "data_staging": "registry",
        },
        "extra_combos": [
            {
                "conditions": {"process": "shell_extension", "exfil": "named_pipe"},
                "tier": 16, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1048",
                "detect_name": "ShellExtPipeExfil",
                "description": "Shell extension DLL using named pipe for data exfiltration. "
                               "Named pipe communication from Explorer shell extension to "
                               "external process detected.",
            },
            {
                "conditions": {"timing": "workday", "collection_strategy": "incremental_slow"},
                "tier": 17, "severity": 2,
                "tactic": "Collection", "technique": "T1119",
                "detect_name": "SlowWorkdayCollection",
                "description": "Incremental data collection during business hours over multiple "
                               "days. Slow-drip collection pattern blends with normal activity "
                               "but behavioral analysis detected consistent access to sensitive "
                               "data stores.",
            },
            {
                "conditions": {"persistence": "dll_search_order", "memory_residence": "native"},
                "tier": 17, "severity": 2,
                "tactic": "Persistence", "technique": "T1574.001",
                "detect_name": "DLLHijackNativeResident",
                "description": "DLL search order hijack loading native-resident payload. "
                               "Non-stomped DLL in hijack position running native code "
                               "detected via DLL integrity monitoring.",
            },
            {
                "conditions": {"anti_analysis": "geofence", "target_scope": "file_targeted"},
                "tier": 16, "severity": 3,
                "tactic": "Collection", "technique": "T1005",
                "detect_name": "GeofencedTargetedExfil",
                "description": "Geofenced process targeting specific files. Location-aware "
                               "targeted file access indicates nation-state level targeting.",
            },
        ],
    },

    # ════════════════════════════════════════════════════════════════
    # INSANE EXAMS (Q-U): tier_scale 1.0
    # Only naturally-safe values + golden overrides survive.
    # Extra combos block obvious safe combinations.
    # The LLM must discover the narrow path from detection patterns.
    # ════════════════════════════════════════════════════════════════

    "Q": {
        "description": "Syscall Shadow Fortress",
        "tier_scale": 1.0,
        "golden_overrides": {
            "api_resolve": "api_hash_crc32",
            "etw_method": "patch",
            "process_lifetime": "persistent",
        },
        "extra_combos": [
            {
                "conditions": {"process": "shell_extension", "persistence": "com_hijack"},
                "tier": 5, "severity": 3,
                "tactic": "Persistence", "technique": "T1546.015",
                "detect_name": "ShellExtCOMHijack",
                "description": "Shell extension persistence combined with COM object hijacking. "
                               "Dual persistence mechanisms in Explorer context detected by "
                               "behavioral correlation.",
            },
            {
                "conditions": {"exfil": "cloud_onedrive", "data_staging": "memory_only"},
                "tier": 6, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1567.002",
                "detect_name": "MemoryToCloud",
                "description": "In-memory data staged directly to OneDrive upload. Memory-only "
                               "collection with immediate cloud exfil matches advanced stealer.",
            },
            {
                "conditions": {"timing": "workday", "collection_strategy": "on_demand"},
                "tier": 8, "severity": 2,
                "tactic": "Collection", "technique": "T1119",
                "detect_name": "WorkdayOnDemand",
                "description": "On-demand collection during business hours. Selective timed "
                               "collection matches targeted exfiltration behavioral profile.",
            },
            {
                "conditions": {"anti_analysis": "exec_guardrails", "target_scope": "clipboard_only"},
                "tier": 7, "severity": 2,
                "tactic": "Collection", "technique": "T1115",
                "detect_name": "GuardrailedClipboard",
                "description": "Execution guardrails protecting clipboard-only collection. "
                               "Environment validation combined with clipboard monitoring "
                               "indicates targeted clipboard theft operation.",
            },
            {
                "conditions": {"data_staging": "shared_memory", "exfil": "steganography"},
                "tier": 9, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1001.002",
                "detect_name": "SharedMemSteg",
                "description": "Data staged in shared memory sections then exfiltrated via "
                               "steganography. Multi-stage covert exfil chain detected.",
            },
        ],
    },
    "R": {
        "description": "COM Object Stealth Grid",
        "tier_scale": 1.0,
        "golden_overrides": {
            "api_resolve": "api_hash_djb2",
            "persistence": "wmi_subscription",
            "data_obfuscation": "xor_encrypt",
        },
        "extra_combos": [
            {
                "conditions": {"process": "shell_extension", "exfil": "dead_drop_cloud"},
                "tier": 5, "severity": 3,
                "tactic": "Command and Control", "technique": "T1102",
                "detect_name": "ShellExtDeadDrop",
                "description": "Shell extension DLL checking cloud dead drop. Explorer shell "
                               "extension polling legitimate cloud service for commands "
                               "matches known APT C2 pattern.",
            },
            {
                "conditions": {"timing": "event_logon", "data_staging": "event_log"},
                "tier": 6, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1070.001",
                "detect_name": "LogonEventLogStaging",
                "description": "Logon-triggered process staging data in event logs. Event log "
                               "used as both trigger source and data storage.",
            },
            {
                "conditions": {"execution": "callback_copyfile2", "exfil": "named_pipe"},
                "tier": 7, "severity": 2,
                "tactic": "Exfiltration", "technique": "T1048",
                "detect_name": "CopyFileCallbackPipe",
                "description": "CopyFile2 callback used to intercept file data into named pipe. "
                               "File copy callback combined with pipe-based exfiltration is "
                               "consistent with file interception malware.",
            },
            {
                "conditions": {"anti_analysis": "canary_aware", "anti_forensics": "memory_only_full"},
                "tier": 8, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1497",
                "detect_name": "CanaryMemoryOnly",
                "description": "Canary-aware process operating entirely in memory. Canary "
                               "detection combined with full memory-only operation indicates "
                               "sophisticated threat actor aware of deception technology.",
            },
            {
                "conditions": {"sleep_mode": "basic", "collection_strategy": "incremental_slow"},
                "tier": 6, "severity": 2,
                "tactic": "Collection", "technique": "T1119",
                "detect_name": "BasicSleepSlowCollect",
                "description": "Basic sleep pattern combined with incremental slow collection. "
                               "Consistent sleep timing with periodic data access flagged by "
                               "behavioral anomaly detection.",
            },
        ],
    },
    "S": {
        "description": "Fileless Phantom",
        "tier_scale": 1.0,
        "golden_overrides": {
            "api_resolve": "peb_walk",
            "execution": "staged",
            "data_staging": "registry",
            "exfil": "smb_write",
        },
        "extra_combos": [
            {
                "conditions": {"process": "shell_extension", "timing": "event_process"},
                "tier": 5, "severity": 3,
                "tactic": "Execution", "technique": "T1106",
                "detect_name": "ShellExtProcessWatch",
                "description": "Shell extension monitoring process creation events. Explorer "
                               "extension watching for specific processes indicates conditional "
                               "payload activation.",
            },
            {
                "conditions": {"persistence": "dll_search_order", "anti_forensics": "blend_noise"},
                "tier": 6, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1574.001",
                "detect_name": "DLLHijackBlend",
                "description": "DLL search order hijack combined with filesystem noise blending. "
                               "Hijacked DLL generating decoy file activity to mask real "
                               "operations.",
            },
            {
                "conditions": {"anti_analysis": "geofence", "collection_strategy": "piggyback_legit"},
                "tier": 7, "severity": 3,
                "tactic": "Collection", "technique": "T1005",
                "detect_name": "GeofencedPiggyback",
                "description": "Geofenced process piggybacking on legitimate application data "
                               "access. Location-restricted data theft using legitimate app "
                               "as proxy.",
            },
            {
                "conditions": {"sleep_mode": "jitter", "target_scope": "file_targeted"},
                "tier": 8, "severity": 2,
                "tactic": "Collection", "technique": "T1005",
                "detect_name": "JitteredFileAccess",
                "description": "Jittered timing with targeted file access. Artificial delay "
                               "between specific file reads flagged by behavioral analysis.",
            },
            {
                "conditions": {"data_staging": "wmi_repo", "exfil": "cloud_gdrive"},
                "tier": 6, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1567.002",
                "detect_name": "WMIRepoCloudExfil",
                "description": "WMI repository data staging with Google Drive exfiltration. "
                               "WMI used as intermediate store before cloud upload.",
            },
            {
                "conditions": {"memory_residence": "native", "anti_forensics": "memory_only_full"},
                "tier": 7, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1055",
                "detect_name": "NativeMemoryOnlyOps",
                "description": "Native memory resident code with zero disk footprint. Full "
                               "memory-only operation from native code flagged by advanced "
                               "memory analysis.",
            },
        ],
    },
    "T": {
        "description": "Shell Extension Maze",
        "tier_scale": 1.0,
        "golden_overrides": {
            "api_resolve": "api_hash_fnv1a",
            "process": "com_object",
            "timing": "staged_jitter",
        },
        "extra_combos": [
            {
                "conditions": {"execution": "callback_abuse", "exfil": "steganography"},
                "tier": 5, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1001.002",
                "detect_name": "CallbackSteg",
                "description": "Callback-based execution combined with steganographic exfil. "
                               "Obfuscated execution chain with covert exfiltration detected.",
            },
            {
                "conditions": {"persistence": "network_provider", "data_staging": "browser_storage"},
                "tier": 6, "severity": 3,
                "tactic": "Credential Access", "technique": "T1556",
                "detect_name": "NetProviderBrowserStage",
                "description": "Network provider credential interceptor staging data in browser "
                               "local storage. Authentication interception with browser-based "
                               "staging chain.",
            },
            {
                "conditions": {"anti_analysis": "canary_aware", "exfil": "cloud_onedrive"},
                "tier": 7, "severity": 2,
                "tactic": "Exfiltration", "technique": "T1567.002",
                "detect_name": "CanaryCloudExfil",
                "description": "Canary-aware process exfiltrating to OneDrive. Honeypot evasion "
                               "combined with legitimate cloud service for data theft.",
            },
            {
                "conditions": {"data_staging": "shared_memory", "collection_strategy": "memory_scraping"},
                "tier": 8, "severity": 3,
                "tactic": "Credential Access", "technique": "T1003.001",
                "detect_name": "SharedMemScraping",
                "description": "Memory scraping collected data staged in shared memory sections. "
                               "Cross-process memory theft pipeline detected.",
            },
            {
                "conditions": {"sleep_mode": "basic", "anti_forensics": "none"},
                "tier": 5, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1027",
                "detect_name": "NoEvasionProfile",
                "description": "Process with no sleep obfuscation and no anti-forensics. "
                               "Complete absence of evasion from unsigned binary performing "
                               "sensitive operations is a red flag in ML models.",
            },
            {
                "conditions": {"exfil": "email_mapi", "target_scope": "environment_recon"},
                "tier": 7, "severity": 2,
                "tactic": "Discovery", "technique": "T1082",
                "detect_name": "ReconEmailExfil",
                "description": "Environment reconnaissance data exfiltrated via MAPI email. "
                               "System enumeration with email-based exfiltration matches "
                               "initial recon stage of targeted attack.",
            },
        ],
    },
    "U": {
        "description": "Hollow Injection Gauntlet",
        "tier_scale": 1.0,
        "golden_overrides": {
            "api_resolve": "indirect_syscall",
            "process": "process_hollow",
            "sleep_mode": "ekko",
            "stack_presentation": "ret_spoof",
        },
        "extra_combos": [
            {
                "conditions": {"execution": "callback_abuse", "persistence": "dll_search_order"},
                "tier": 5, "severity": 3,
                "tactic": "Persistence", "technique": "T1574.001",
                "detect_name": "CallbackDLLHijack",
                "description": "Callback-based execution from DLL search order hijacked position. "
                               "DLL hijack loading callback-abusing payload.",
            },
            {
                "conditions": {"exfil": "cloud_gdrive", "data_staging": "memory_only"},
                "tier": 6, "severity": 3,
                "tactic": "Exfiltration", "technique": "T1567.002",
                "detect_name": "MemoryGDriveExfil",
                "description": "In-memory data staged directly to Google Drive. Memory-only "
                               "collection bypassing disk staging with cloud upload.",
            },
            {
                "conditions": {"timing": "triggered", "anti_analysis": "geofence"},
                "tier": 7, "severity": 3,
                "tactic": "Defense Evasion", "technique": "T1480.001",
                "detect_name": "GeofencedTriggered",
                "description": "Geofenced trigger-based execution. Location validation before "
                               "triggered activation indicates nation-state targeting.",
            },
            {
                "conditions": {"anti_forensics": "blend_noise", "data_obfuscation": "aes_encrypt"},
                "tier": 8, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1027",
                "detect_name": "BlendEncryptCombo",
                "description": "Noise blending with AES-encrypted operations. Filesystem noise "
                               "generation combined with encrypted sensitive operations "
                               "detected by behavioral analysis.",
            },
            {
                "conditions": {"collection_strategy": "event_triggered", "target_scope": "session_tokens"},
                "tier": 7, "severity": 3,
                "tactic": "Credential Access", "technique": "T1539",
                "detect_name": "EventTokenTheft",
                "description": "Event-triggered session token collection. Targeted token theft "
                               "activated by specific application events.",
            },
            {
                "conditions": {"persistence": "com_hijack", "exfil": "dead_drop"},
                "tier": 6, "severity": 3,
                "tactic": "Command and Control", "technique": "T1102",
                "detect_name": "COMDeadDrop",
                "description": "COM hijack persistence with dead drop command channel. COM-loaded "
                               "DLL polling dead drop for instructions and uploading stolen data.",
            },
            {
                "conditions": {"data_staging": "event_log", "process_lifetime": "medium_minutes"},
                "tier": 8, "severity": 2,
                "tactic": "Defense Evasion", "technique": "T1070.001",
                "detect_name": "EventLogMediumLife",
                "description": "Medium-duration process staging data in event logs. Timed "
                               "operation writing to event log then terminating after data "
                               "collection completes.",
            },
        ],
    },
}


# ════════════════════════════════════════════════════════════════
# EXPANDED DIMENSION EXAMS (V-Z): Test new api_resolve, injection,
# network_stealth, sleep_mode, and memory_residence options
# ════════════════════════════════════════════════════════════════

EXAMS["V"] = {
    "description": "NTDLL Unhooking Gauntlet — forces advanced API resolution",
    "tier_scale": 0.70,
    "golden_overrides": {
        "api_resolve": "hookchain",
    },
    "extra_combos": [
        {
            "conditions": {"api_resolve": "ntdll_disk_remap", "anti_forensics": "none"},
            "tier": 5, "severity": 3,
            "tactic": "Defense Evasion", "technique": "T1562.001",
            "detect_name": "DiskRemapNoCleanup",
            "description": "Disk-based ntdll remap without forensic cleanup. Open handle to "
                           "ntdll.dll on disk combined with no anti-forensics leaves clear "
                           "evidence of EDR unhooking attempt.",
        },
        {
            "conditions": {"api_resolve": "indirect_syscall", "stack_presentation": "honest"},
            "tier": 6, "severity": 3,
            "tactic": "Defense Evasion", "technique": "T1106",
            "detect_name": "SyscallHonestStack",
            "description": "Indirect syscall with honest call stack. Syscall return address points "
                           "into ntdll but call origin outside ntdll is visible in unmasked stack.",
        },
    ],
}

EXAMS["W"] = {
    "description": "Process Injection Maze — forces advanced injection methods",
    "tier_scale": 0.65,
    "golden_overrides": {
        "injection_method": "threadless",
        "process": "dll_sideload",
    },
    "extra_combos": [
        {
            "conditions": {"injection_method": "classic_remote", "process": "standalone"},
            "tier": 3, "severity": 5,
            "tactic": "Defense Evasion", "technique": "T1055.001",
            "detect_name": "ClassicInjectionStandalone",
            "description": "Classic remote thread injection from standalone process. Highest-confidence "
                           "injection indicator — textbook VirtualAllocEx+WriteProcessMemory chain.",
        },
        {
            "conditions": {"injection_method": "earlybird_apc", "timing": "immediate"},
            "tier": 4, "severity": 4,
            "tactic": "Defense Evasion", "technique": "T1055.004",
            "detect_name": "EarlyBirdImmediate",
            "description": "EarlyBird APC injection with immediate timing. CREATE_SUSPENDED → APC queue "
                           "→ resume within milliseconds is a classic loader pattern.",
        },
    ],
}

EXAMS["X"] = {
    "description": "Network Stealth Challenge — forces JA3/domain fronting evasion",
    "tier_scale": 0.60,
    "golden_overrides": {
        "network_stealth": "ja3_spoof",
        "exfil": "https_post",
    },
    "extra_combos": [
        {
            "conditions": {"network_stealth": "none", "exfil": "https_post"},
            "tier": 4, "severity": 3,
            "tactic": "Command and Control", "technique": "T1071.001",
            "detect_name": "RawTLSFingerprint",
            "description": "HTTPS exfiltration with default TLS fingerprint. JA3 hash does not match "
                           "any known browser. Trivially fingerprintable at the network layer.",
        },
        {
            "conditions": {"network_stealth": "doh_tunnel", "process": "standalone"},
            "tier": 5, "severity": 3,
            "tactic": "Command and Control", "technique": "T1071.004",
            "detect_name": "DoHFromStandalone",
            "description": "DNS-over-HTTPS tunnel from standalone process. Non-browser process "
                           "sending encrypted DNS queries is highly anomalous. Browser context required.",
        },
    ],
}

EXAMS["Y"] = {
    "description": "Sleep Obfuscation Gauntlet — forces advanced sleep techniques",
    "tier_scale": 0.65,
    "golden_overrides": {
        "sleep_mode": "gargoyle",
        "memory_residence": "mapped_section",
    },
    "extra_combos": [
        {
            "conditions": {"sleep_mode": "encrypt", "memory_residence": "native"},
            "tier": 4, "severity": 3,
            "tactic": "Defense Evasion", "technique": "T1027",
            "detect_name": "BasicEncryptNativeMemory",
            "description": "XOR sleep encryption with native memory residence. Memory protection "
                           "toggling on the process's own .text section is easily detected by "
                           "integrity monitoring. Advanced sleep technique required.",
        },
        {
            "conditions": {"sleep_mode": "basic", "process_lifetime": "persistent"},
            "tier": 3, "severity": 4,
            "tactic": "Defense Evasion", "technique": "T1497.003",
            "detect_name": "PersistentPlainSleep",
            "description": "Persistent process using plain Sleep(). Long-lived process with "
                           "unobfuscated memory during idle is trivially scanned. Memory scanner "
                           "found payload signature during sleep interval.",
        },
    ],
}

EXAMS["Z"] = {
    "description": "Full Spectrum — all new dimensions active, insane difficulty",
    "tier_scale": 0.85,
    "golden_overrides": {
        "api_resolve": "syscall_veh",
        "injection_method": "kcb_hijack",
        "network_stealth": "legitimate_api",
        "sleep_mode": "death_sleep",
        "memory_residence": "rx_reuse",
        "stack_presentation": "silent_moonwalk",
    },
    "extra_combos": [
        {
            "conditions": {"network_stealth": "none", "api_resolve": "direct_import"},
            "tier": 2, "severity": 5,
            "tactic": "Defense Evasion", "technique": "T1106",
            "detect_name": "ZeroEvasionProfile",
            "description": "No network stealth combined with direct API imports. Baseline detection "
                           "profile — no evasion techniques applied at all.",
        },
        {
            "conditions": {"injection_method": "none", "process": "standalone"},
            "tier": 3, "severity": 4,
            "tactic": "Execution", "technique": "T1059",
            "detect_name": "StandaloneNoInjection",
            "description": "Standalone process with no injection technique. Direct execution "
                           "without process context change is the simplest detection target.",
        },
        {
            "conditions": {"sleep_mode": "basic", "memory_residence": "native"},
            "tier": 3, "severity": 4,
            "tactic": "Defense Evasion", "technique": "T1027",
            "detect_name": "NativeBasicSleep",
            "description": "Native memory with basic sleep — fully scannable at all times. "
                           "Memory scanner identified payload in idle process memory.",
        },
    ],
}


# ════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════

_cache = {}


def get_exam(name):
    """Get exam config by name. Returns dict for detection_check, or None for default."""
    if name is None or name == "A":
        return None
    exam = EXAMS.get(name)
    if exam is None:
        raise ValueError(
            f"Unknown exam: {name}. Available: A, {', '.join(sorted(EXAMS.keys()))}"
        )
    return exam


def check_config(config, level, exam_name="A"):
    """Check a config against an exam at a given level. Returns detections list."""
    from detection_model import detection_check
    exam = get_exam(exam_name)
    return detection_check(config, level, exam)


def list_exams():
    """List all available exam names and descriptions."""
    exams = [("A", "Default (raw detection model, no golden overrides)")]
    for name in sorted(EXAMS.keys()):
        exams.append((name, EXAMS[name]["description"]))
    return exams
