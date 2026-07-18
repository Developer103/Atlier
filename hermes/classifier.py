"""Failure classifier — deterministic fast-path for known failure patterns."""

import re
from dataclasses import dataclass
from enum import Enum


class FailureType(Enum):
    SUCCESS = "SUCCESS"
    PE_QUARANTINED = "PE_QUARANTINED"
    AMSI_BLOCKED = "AMSI_BLOCKED"
    PROCESS_BLOCKED = "PROCESS_BLOCKED"
    BEHAVIORAL = "BEHAVIORAL"
    PARTIAL_COLLECT = "PARTIAL_COLLECT"
    BUILD_ERROR = "BUILD_ERROR"
    NO_C2 = "NO_C2"
    TIMEOUT = "TIMEOUT"
    EXFIL_BLOCKED = "EXFIL_BLOCKED"
    SCRIPT_ERROR = "SCRIPT_ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass
class FailureResult:
    failure_type: FailureType
    detail: str
    suggested_action: str


def classify_failure(
    binary_exists: bool,
    c2_bytes: int,
    defender_detections: list[str],
    cs_detections: list[str],
    exit_code: int | None,
    stderr: str,
    stdout: str,
    format_type: str = "c",
    is_backdoor: bool = False,
    backdoor_beacons: int = 0,
    backdoor_results: int = 0,
) -> FailureResult:
    if is_backdoor and backdoor_beacons > 0:
        if backdoor_results >= 2 and binary_exists \
                and not defender_detections and not cs_detections:
            return FailureResult(
                FailureType.SUCCESS,
                f"Backdoor operational: {backdoor_beacons} beacons, {backdoor_results} command results",
                "none",
            )
        if backdoor_results == 0 and binary_exists:
            return FailureResult(
                FailureType.PARTIAL_COLLECT,
                f"Backdoor beaconed ({backdoor_beacons}x) but returned no command results — TLV encoding mismatch or command handlers broken",
                "check_command_handler_implementation",
            )

    if c2_bytes > 100 and binary_exists and not defender_detections and not cs_detections:
        return FailureResult(FailureType.SUCCESS, "All checks passed", "none")

    if is_backdoor and c2_bytes == 0 and backdoor_beacons == 0 and binary_exists:
        return FailureResult(
            FailureType.NO_C2,
            "Backdoor never beaconed — check C2 protocol (must be backdoor, not tcp/http) and connectivity",
            "check_c2_protocol_and_connectivity",
        )

    if stderr and ("error:" in stderr.lower() or "undefined reference" in stderr.lower()):
        return FailureResult(
            FailureType.BUILD_ERROR,
            _extract_build_error(stderr),
            "fix_compilation",
        )

    if not binary_exists and defender_detections:
        threat_id = _extract_threat_id(defender_detections)
        return FailureResult(
            FailureType.PE_QUARANTINED,
            f"Defender quarantined binary (threat: {threat_id})",
            "change_binary_signature",
        )

    if not binary_exists and cs_detections:
        return FailureResult(
            FailureType.PE_QUARANTINED,
            "CrowdStrike quarantined binary",
            "switch_to_script_format",
        )

    combined = (stdout + stderr).lower()
    if "amsi" in combined or "malicious content" in combined:
        return FailureResult(
            FailureType.AMSI_BLOCKED,
            "AMSI detected malicious content",
            "avoid_powershell_or_obfuscate",
        )

    if "process was blocked" in combined or "malicious behavior" in combined:
        return FailureResult(
            FailureType.PROCESS_BLOCKED,
            "EDR blocked process execution",
            "change_execution_pattern",
        )

    if c2_bytes == 0 and binary_exists:
        if exit_code is not None and exit_code != 0:
            return FailureResult(
                FailureType.SCRIPT_ERROR if format_type == "jscript" else FailureType.NO_C2,
                f"Process exited with code {exit_code}, no C2 data",
                "debug_runtime_error",
            )
        return FailureResult(
            FailureType.NO_C2,
            "Binary exists but no C2 data received",
            "check_c2_connectivity",
        )

    if c2_bytes > 0 and not binary_exists:
        return FailureResult(
            FailureType.BEHAVIORAL,
            "Data exfiltrated but binary removed post-execution",
            "change_runtime_behavior",
        )

    if c2_bytes > 0 and c2_bytes < 1000:
        return FailureResult(
            FailureType.PARTIAL_COLLECT,
            f"Only {c2_bytes} bytes collected (process likely killed)",
            "add_delays_and_reorder_collectors",
        )

    if c2_bytes > 0 and (defender_detections or cs_detections):
        return FailureResult(
            FailureType.BEHAVIORAL,
            "Data collected but post-execution detection triggered",
            "change_runtime_behavior",
        )

    return FailureResult(
        FailureType.UNKNOWN,
        f"Unclassified: binary={'exists' if binary_exists else 'gone'}, c2={c2_bytes}B",
        "manual_investigation",
    )


def _extract_threat_id(detections: list[str]) -> str:
    for d in detections:
        match = re.search(r"(Trojan|HackTool|Behavior)[\w:.!/]+", d)
        if match:
            return match.group(0)
    return "unknown"


def _extract_build_error(stderr: str) -> str:
    for line in stderr.split("\n"):
        if "error:" in line.lower():
            return line.strip()[:200]
    return stderr[:200]
