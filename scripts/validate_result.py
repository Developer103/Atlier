#!/usr/bin/env python3
"""Standalone validation — verifies pipeline output independently.

Usage:
    python3 scripts/validate_result.py [--output-dir results] [--type ransomware]
                                        [--timeout 60] [--no-restore]

Reads spec.yaml and malware_source.exe from the output directory,
deploys to VM, creates canaries, executes, and checks functional goal.
Returns exit code 0 if PASS, 1 if FAIL, 2 if error.

This script is the GROUND TRUTH for validating pipeline claims of SUCCESS.
If the pipeline says SUCCESS but this script says FAIL, that's a false positive.
"""
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PROJ_DIR = SCRIPT_DIR.parent

sys.path.insert(0, str(PROJ_DIR / "results"))
from validate import run_validation, print_report

import argparse


def detect_malware_type(output_dir: Path) -> str:
    """Auto-detect malware type from spec.yaml in output dir or project root."""
    for spec_path in [output_dir / "spec.yaml", PROJ_DIR / "spec.yaml"]:
        if spec_path.exists():
            for line in spec_path.read_text().splitlines():
                if line.strip().startswith("malware_type:"):
                    mt = line.split(":", 1)[1].strip().strip("'\"").lower()
                    if any(k in mt for k in ("ransom", "encrypt", "locker")):
                        return "ransomware"
                    if any(k in mt for k in ("keylog", "keystroke")):
                        return "keylogger"
                    if any(k in mt for k in ("info steal", "infostealer", "credential", "password")):
                        return "infostealer"
                    return mt
    return "ransomware"


def main():
    parser = argparse.ArgumentParser(description="Validate pipeline output independently")
    parser.add_argument("--output-dir", default="results", help="Pipeline output directory")
    parser.add_argument("--type", default=None, help="Override malware type")
    parser.add_argument("--timeout", type=int, default=60, help="Execution wait seconds")
    parser.add_argument("--no-restore", action="store_true", help="Skip VM restore")
    parser.add_argument("--no-overlay", action="store_true", help="Skip overlay creation")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    exe_path = output_dir / "malware_source.exe"

    if not exe_path.exists():
        print(f"ERROR: {exe_path} not found — did the pipeline compile successfully?")
        sys.exit(2)

    malware_type = args.type or detect_malware_type(output_dir)
    print(f"[*] Validating {malware_type} from {output_dir}")

    result = run_validation(
        malware_type=malware_type,
        timeout=args.timeout,
        exe_path=str(exe_path),
        use_overlay=not args.no_overlay,
        do_restore=not args.no_restore,
    )
    print_report(result)

    if result.passed:
        print("GROUND TRUTH: PASS — malware accomplished its functional goal")
    else:
        reasons = []
        if not result.functional_checks_passed:
            reasons.append("functional goal NOT met")
        if result.defender_alert_count > 0:
            reasons.append(f"{result.defender_alert_count} Defender alert(s)")
        print(f"GROUND TRUTH: FAIL — {', '.join(reasons)}")

    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()
