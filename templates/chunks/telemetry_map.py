"""
Telemetry dependency map — connects evasion chunks to detection telemetry sources.

Key insight: EDR detections depend on telemetry sources. Suppress the telemetry
source and all detections built on it go blind. Composition should target shared
telemetry roots, not individual detection rules.

Usage:
    from telemetry_map import get_blind_spots, recommend_evasion_for, score_combination
"""

TELEMETRY_SOURCES = {
    "etw_ti": {
        "name": "ETW Threat Intelligence",
        "desc": "Kernel ETW provider — memory allocation, thread injection, image loads",
        "suppressed_by": ["etw_patch", "hw_bp_etw"],
        "observes": [
            "process_hollow", "apc_self", "fiber",
            "dll_sideload",
        ],
    },
    "usermode_hooks": {
        "name": "ntdll.dll Usermode Hooks",
        "desc": "EDR inline hooks on NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.",
        "suppressed_by": ["unhook_ntdll", "indirect_syscall"],
        "observes": [
            "direct_import", "loadlibrary",
            "ppid_spoof", "ppid_spoof_svchost", "ppid_spoof_runtimebroker",
            "ppid_spoof_sihost", "ppid_spoof_taskhostw", "ppid_spoof_dllhost",
            "process_hollow",
        ],
    },
    "sysmon_process_create": {
        "name": "Sysmon Event ID 1 — Process Create",
        "desc": "Logs process creation with parent PID, command line, hashes",
        "suppressed_by": [],  # kernel driver, can't suppress from usermode
        "observes": [
            "sequential", "threaded", "staged", "fiber",
            "callback_abuse", "callback_enumwindows", "callback_certenumsystem",
            "callback_copyfile2", "callback_enumrestype", "apc_self",
            "ppid_spoof", "ppid_spoof_svchost", "ppid_spoof_runtimebroker",
            "ppid_spoof_sihost", "ppid_spoof_taskhostw", "ppid_spoof_dllhost",
            "standalone",
            "certutil_lolbin", "bitsadmin_lolbin", "powershell_lolbin",
            "cscript_lolbin", "mshta_lolbin",
        ],
    },
    "sysmon_network": {
        "name": "Sysmon Event ID 3 — Network Connection",
        "desc": "Logs outbound TCP/UDP connections with destination IP/port",
        "suppressed_by": [],
        "observes": [
            "tcp_direct", "http_post", "https_post",
            "winhttp_get", "winhttp_api", "http_get_chunks",
            "dns_exfil", "dns_txt", "curl_lolbin",
        ],
    },
    "sysmon_file_create": {
        "name": "Sysmon Event ID 11 — File Create",
        "desc": "Logs file creation events",
        "suppressed_by": [],
        "observes": [
            "smb_write", "startup_folder", "self_delete",
        ],
    },
    "sysmon_registry": {
        "name": "Sysmon Event ID 12/13 — Registry",
        "desc": "Logs registry key/value creation and modification",
        "suppressed_by": [],
        "observes": [
            "registry_run", "anti_vm",
        ],
    },
    "sysmon_dns": {
        "name": "Sysmon Event ID 22 — DNS Query",
        "desc": "Logs DNS queries with query name",
        "suppressed_by": [],
        "observes": [
            "dns_exfil", "dns_txt",
        ],
    },
    "amsi": {
        "name": "Antimalware Scan Interface",
        "desc": "Scans script content, .NET assemblies, memory buffers",
        "suppressed_by": ["etw_patch"],  # AMSI uses ETW for some logging
        "observes": [
            "plaintext",  # plaintext strings in memory are AMSI-scannable
        ],
    },
    "kernel_callbacks": {
        "name": "Kernel Process/Thread Callbacks",
        "desc": "PsSetCreateProcessNotifyRoutine, PsSetCreateThreadNotifyRoutine",
        "suppressed_by": [],  # kernel-level, not suppressible from usermode
        "observes": [
            "ppid_spoof", "ppid_spoof_svchost", "ppid_spoof_runtimebroker",
            "ppid_spoof_sihost", "ppid_spoof_taskhostw", "ppid_spoof_dllhost",
            "process_hollow", "threaded", "apc_self",
        ],
    },
    "minifilter": {
        "name": "Filesystem Minifilter Driver",
        "desc": "EDR filesystem filter — intercepts file I/O at kernel level",
        "suppressed_by": [],
        "observes": [
            "smb_write", "startup_folder", "self_delete",
        ],
    },
    "etw_process": {
        "name": "ETW Process Provider",
        "desc": "Microsoft-Windows-Kernel-Process ETW — process start/stop events",
        "suppressed_by": ["etw_patch"],
        "observes": [
            "sequential", "threaded", "staged",
            "ppid_spoof", "ppid_spoof_svchost",
        ],
    },
}


def get_blind_spots(active_evasion):
    """Given active evasion chunks, return suppressed telemetry and invisible techniques.

    Args:
        active_evasion: list of evasion chunk names (e.g. ["etw_patch", "unhook_ntdll"])

    Returns:
        dict: {
            "suppressed": ["etw_ti", "usermode_hooks", ...],
            "invisible": ["process_hollow", "apc_self", ...],  # techniques no longer observed
            "still_observed_by": {"tcp_direct": ["sysmon_network"]}  # remaining coverage
        }
    """
    active = set(active_evasion)
    suppressed = set()
    for src_key, src in TELEMETRY_SOURCES.items():
        if active & set(src["suppressed_by"]):
            suppressed.add(src_key)

    all_observed = {}
    for src_key, src in TELEMETRY_SOURCES.items():
        for tech in src["observes"]:
            if tech not in all_observed:
                all_observed[tech] = set()
            all_observed[tech].add(src_key)

    invisible = set()
    still_observed = {}
    for tech, sources in all_observed.items():
        remaining = sources - suppressed
        if not remaining:
            invisible.add(tech)
        else:
            still_observed[tech] = sorted(remaining)

    return {
        "suppressed": sorted(suppressed),
        "invisible": sorted(invisible),
        "still_observed_by": still_observed,
    }


def recommend_evasion_for(technique):
    """Recommend evasion chunks that suppress telemetry observing this technique.

    Args:
        technique: technique chunk name (e.g. "process_hollow")

    Returns:
        list of dicts: [{"evasion": "etw_patch", "suppresses": "etw_ti", "also_blinds": [...]}]
    """
    observers = set()
    for src_key, src in TELEMETRY_SOURCES.items():
        if technique in src["observes"]:
            observers.add(src_key)

    if not observers:
        return []

    recommendations = []
    for src_key in observers:
        src = TELEMETRY_SOURCES[src_key]
        for evasion in src["suppressed_by"]:
            also_blinds = [t for t in src["observes"] if t != technique]
            recommendations.append({
                "evasion": evasion,
                "suppresses": src_key,
                "also_blinds": also_blinds,
            })

    return recommendations


def score_combination(evasion_list, technique_list):
    """Score how much telemetry coverage remains for a given combination.

    Args:
        evasion_list: active evasion chunks
        technique_list: technique chunks being used

    Returns:
        float: 0.0 = fully blind (best for attacker), 1.0 = fully observed (worst)
    """
    blind = get_blind_spots(evasion_list)
    suppressed = set(blind["suppressed"])

    total_observations = 0
    active_observations = 0
    for tech in technique_list:
        for src_key, src in TELEMETRY_SOURCES.items():
            if tech in src["observes"]:
                total_observations += 1
                if src_key not in suppressed:
                    active_observations += 1

    if total_observations == 0:
        return 0.0
    return active_observations / total_observations


if __name__ == "__main__":
    print("=== ETW patch + unhook_ntdll blind spots ===")
    result = get_blind_spots(["etw_patch", "unhook_ntdll"])
    print(f"Suppressed: {result['suppressed']}")
    print(f"Invisible techniques: {result['invisible']}")
    print()

    print("=== Recommendations for process_hollow ===")
    for rec in recommend_evasion_for("process_hollow"):
        print(f"  {rec['evasion']} suppresses {rec['suppresses']}, also blinds: {rec['also_blinds'][:3]}")
    print()

    print("=== Score: no evasion, basic techniques ===")
    s1 = score_combination([], ["sequential", "tcp_direct", "standalone"])
    print(f"  Score: {s1:.2f} (1.0 = fully observed)")

    print("=== Score: etw_patch + unhook, same techniques ===")
    s2 = score_combination(["etw_patch", "unhook_ntdll"], ["sequential", "tcp_direct", "standalone"])
    print(f"  Score: {s2:.2f}")

    print("=== Score: full evasion, stealth techniques ===")
    s3 = score_combination(
        ["etw_patch", "unhook_ntdll", "indirect_syscall"],
        ["callback_certenumsystem", "https_post", "ppid_spoof_runtimebroker"]
    )
    print(f"  Score: {s3:.2f}")
