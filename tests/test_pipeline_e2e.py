"""Tier 4 E2E tests — exercise the actual framework pipeline with real LLM + VM.

These tests call the framework end-to-end: spec parsing → LLM code generation →
evasion passes → MinGW cross-compilation → VM deployment → verification.

They are SLOW (minutes per test due to LLM generation) and require:
  - LM Studio running at localhost:1234
  - Windows 11 QEMU VM reachable at localhost:10022

Run with: python3 tests/run_all.py e2e
Or:       pytest tests/test_pipeline_e2e.py -v --timeout=900
"""

import asyncio
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

def _llm_available():
    try:
        import urllib.request
        req = urllib.request.Request("http://localhost:1234/v1/models")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _vm_available():
    try:
        ret = subprocess.run(
            ["sshpass", "-pvmuser123", "ssh", "-p", "10022",
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=5", "vmuser@localhost", "echo ready"],
            capture_output=True, text=True, timeout=10,
        )
        return ret.returncode == 0 and "ready" in ret.stdout
    except Exception:
        return False


requires_llm = pytest.mark.skipif(not _llm_available(), reason="LLM not running at localhost:1234")
requires_vm = pytest.mark.skipif(not _vm_available(), reason="VM not reachable at localhost:10022")
requires_mingw = pytest.mark.skipif(
    not subprocess.run(["which", "x86_64-w64-mingw32-gcc"], capture_output=True).returncode == 0,
    reason="MinGW cross-compiler not installed",
)
requires_rustc = pytest.mark.skipif(
    not subprocess.run(["which", "rustc"], capture_output=True).returncode == 0,
    reason="rustc not installed",
)
requires_go = pytest.mark.skipif(
    not subprocess.run(["which", "go"], capture_output=True).returncode == 0,
    reason="go not installed",
)
requires_gcc = pytest.mark.skipif(
    not subprocess.run(["which", "gcc"], capture_output=True).returncode == 0,
    reason="gcc not installed",
)


def _write_spec(path, malware_type="ransomware", output_format="exe",
                os_platform="windows", os_version=None, source_language="c"):
    """Write a minimal test spec YAML."""
    if os_version is None:
        os_version = "windows-11" if os_platform == "windows" else "ubuntu-24.04"
    _edrs = "defender" if os_platform == "windows" else "none"
    _compilers = "mingw-w64" if source_language == "c" and os_platform == "windows" else "gcc"
    Path(path).write_text(
        f"os_platform: {os_platform}\n"
        f"os_version: {os_version}\n"
        f"malware_type: {malware_type}\n"
        f"source_language: {source_language}\n"
        f"output_format: {output_format}\n"
        f"c2_address: '10.0.2.2'\n"
        f"c2_port: 9001\n"
        f"edrs:\n"
        f"  - {_edrs}\n"
        f"installed_compilers:\n"
        f"  - {_compilers}\n"
        f"admin_rights: true\n"
        f"custom_gates:\n"
        f"  - no console window\n"
    )
    return str(path)


def _compile_source(source_text, tmpdir, extra_flags=None):
    """Cross-compile C source with MinGW. Returns (success, stderr, exe_path)."""
    src = Path(tmpdir) / "test.c"
    exe = Path(tmpdir) / "test.exe"
    src.write_text(source_text)
    cmd = [
        "x86_64-w64-mingw32-gcc", "-O2", "-s", "-static",
        str(src), "-o", str(exe),
        "-lws2_32", "-ladvapi32", "-liphlpapi", "-lcrypt32",
        "-lole32", "-lshell32", "-lshlwapi", "-lmpr", "-lwininet",
    ]
    if extra_flags:
        cmd.extend(extra_flags)
    ret = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return ret.returncode == 0, ret.stderr, str(exe)


# ---------------------------------------------------------------------------
# E2E Tests: Generate-only (LLM required, no VM)
# ---------------------------------------------------------------------------

@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_ransomware():
    """Generate ransomware source from spec, verify it compiles."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None, "Generation returned no result"
        source = result.generation_result.source_code
        assert source is not None, "Generated source is None"
        assert len(source) > 200, f"Generated source too short ({len(source)} chars)"

        src_file = output_dir / "malware_source.c"
        assert src_file.exists(), "Source file not written to output dir"

        assert "main" in source, "No main function in generated source"
        assert "#include" in source, "No #include directives"

        ok, stderr, _ = _compile_source(source, tmpdir)
        assert ok, f"Generated ransomware source failed to compile:\n{stderr[:2000]}"


@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_infostealer():
    """Generate infostealer source from spec, verify it compiles and has C2 code."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="info stealer")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None, "Generation returned no result"
        source = result.generation_result.source_code
        assert source is not None, "Generated source is None"
        assert len(source) > 200, f"Generated source too short ({len(source)} chars)"

        ok, stderr, _ = _compile_source(source, tmpdir)
        assert ok, f"Generated infostealer source failed to compile:\n{stderr[:2000]}"

        # Infostealer should have network exfiltration code
        has_network = any(kw in source for kw in ("WSAStartup", "connect", "send", "socket", "WSASocket"))
        assert has_network, "Infostealer source has no network/socket code"


@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_keylogger():
    """Generate keylogger source from spec, verify structure and hook-related code.

    Keylogger is the hardest type for local LLMs — compilation is checked but
    not required to pass (the compile-fix loop handles that in real runs).
    """
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="keylogger")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=True,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None, "Generation returned no result"
        source = result.generation_result.source_code
        if result.loop_result and result.loop_result.final_source:
            source = result.loop_result.final_source
        assert source is not None, "Generated source is None"
        assert len(source) > 200, f"Generated source too short ({len(source)} chars)"

        hook_markers = ["SetWindowsHookEx", "WH_KEYBOARD", "CallNextHookEx",
                        "GetAsyncKeyState", "keyboard", "hook", "key"]
        found = [m for m in hook_markers if m.lower() in source.lower()]
        assert len(found) >= 2, (
            f"Keylogger source missing hook-related code. "
            f"Found only: {found}"
        )

        ok, stderr, _ = _compile_source(source, tmpdir)
        assert ok, (
            f"Keylogger source failed to compile: {stderr[:500]}"
        )


@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_dll_output():
    """Generate DLL-format output, verify it compiles as a shared library."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware", output_format="dll")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None, "Generation returned no result"
        source = result.generation_result.source_code
        assert source is not None, "Generated source is None"

        ok, stderr, _ = _compile_source(source, tmpdir, extra_flags=["-shared"])
        assert ok, f"Generated DLL source failed to compile:\n{stderr[:2000]}"


@pytest.mark.e2e
@requires_llm
def test_generate_produces_plan():
    """Verify that generation produces a MalwarePlan with components."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None
        plan = result.generation_result.plan
        assert plan is not None, "No plan produced — generation should create a MalwarePlan"
        assert len(plan.components) > 0, "Plan has no components"
        assert plan.language in ("c", "rust", "go"), f"Unexpected plan language: {plan.language}"


@pytest.mark.e2e
@requires_llm
def test_generate_writes_report():
    """Verify that the pipeline writes a pipeline_report.txt."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        report = output_dir / "pipeline_report.txt"
        assert report.exists(), "pipeline_report.txt not written"
        content = report.read_text()
        assert "MALWARE GENERATION PIPELINE REPORT" in content
        assert "windows" in content.lower()


# ---------------------------------------------------------------------------
# E2E Tests: Generate + Local compile loop (LLM required, no VM)
# ---------------------------------------------------------------------------

@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_with_compile_loop():
    """Generate + local compile-fix loop. Tests the auto-fix-on-compile-error path."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=True, retry_loop=True,
            max_iterations=3, use_existing_vm=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None, "No generation result"
        assert result.loop_result is not None, "No loop result — compile loop didn't run"
        assert result.loop_result.total_iterations >= 1, "Loop ran 0 iterations"

        source = (output_dir / "malware_source.c").read_text()
        assert len(source) > 200, "Final source is too short"


# ---------------------------------------------------------------------------
# E2E Tests: VM verification (requires both LLM + VM)
# ---------------------------------------------------------------------------

@pytest.mark.e2e
@requires_llm
@requires_vm
@requires_mingw
def test_verify_existing_source_in_vm():
    """Verify existing malware_source.c in the VM without re-generating."""
    src_file = PROJECT_ROOT / "results" / "malware_source.c"
    if not src_file.exists():
        pytest.skip("results/malware_source.c not found")

    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="info stealer")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=False, provision_vm=False, verify=True, retry_loop=False,
            use_existing_vm=True, existing_vm_port=10022,
            existing_vm_user="vmuser", existing_vm_pass="vmuser123",
        )
        result = asyncio.run(pipeline.run(
            spec_path=spec_path, output_dir=str(output_dir),
            source_file=str(src_file),
        ))

        assert result.loop_result is not None, "No verification result"
        assert result.loop_result.total_iterations >= 1, "Verification didn't run"

        # Check that the iteration produced a meaningful detection score
        last = result.loop_result.iterations[-1]
        assert last.detection_score in ("none", "low", "medium", "high"), \
            f"Unexpected detection score: {last.detection_score}"


@pytest.mark.e2e
@requires_llm
@requires_vm
@requires_mingw
def test_full_pipeline_generate_and_verify():
    """Full pipeline: generate ransomware → compile → deploy to VM → verify."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=True, retry_loop=True,
            max_iterations=2, use_existing_vm=True,
            existing_vm_port=10022, existing_vm_user="vmuser",
            existing_vm_pass="vmuser123",
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None, "No generation result"
        assert result.generation_result.source_code is not None, "No source code generated"
        assert result.loop_result is not None, "No loop result — verify+loop didn't run"
        assert result.loop_result.total_iterations >= 1, "Loop ran 0 iterations"

        report = output_dir / "pipeline_report.txt"
        assert report.exists(), "No pipeline report written"


@pytest.mark.e2e
@requires_llm
@requires_vm
@requires_mingw
def test_full_pipeline_infostealer_with_verify():
    """Full pipeline for infostealer: generate → deploy → verify C2 exfiltration."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="info stealer")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=True, retry_loop=True,
            max_iterations=2, use_existing_vm=True,
            existing_vm_port=10022, existing_vm_user="vmuser",
            existing_vm_pass="vmuser123",
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None, "No generation result"
        assert result.loop_result is not None, "No loop result"

        source = result.generation_result.source_code
        has_network = any(kw in source for kw in ("WSAStartup", "connect", "send", "socket"))
        assert has_network, "Infostealer source missing network code"


# ---------------------------------------------------------------------------
# E2E Tests: CLI interface
# ---------------------------------------------------------------------------

@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_cli_generate_command():
    """Invoke the CLI 'generate' subcommand via subprocess."""
    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"

        ret = subprocess.run(
            [sys.executable, "-m", "malware_gen_framework", "generate",
             "--spec", spec_path, "--output", str(output_dir)],
            capture_output=True, text=True, timeout=2400,
            cwd=str(PROJECT_ROOT.parent),
        )

        assert ret.returncode == 0, f"CLI generate failed (exit {ret.returncode}):\n{ret.stderr[:2000]}"
        assert (output_dir / "malware_source.c").exists(), "CLI didn't produce source file"
        source = (output_dir / "malware_source.c").read_text()
        assert len(source) > 200, f"CLI produced too-short source ({len(source)} chars)"


@pytest.mark.e2e
@requires_llm
@requires_vm
@requires_mingw
def test_cli_run_command():
    """Invoke the CLI 'run' subcommand with existing VM."""
    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"

        ret = subprocess.run(
            [sys.executable, "-m", "malware_gen_framework", "run",
             "--spec", spec_path, "--output", str(output_dir),
             "--use-existing-vm", "--vm-port", "10022",
             "--loop", "--max-iters", "2"],
            capture_output=True, text=True, timeout=3600,
            cwd=str(PROJECT_ROOT.parent),
        )

        assert ret.returncode == 0, f"CLI run failed (exit {ret.returncode}):\n{ret.stderr[:2000]}"
        assert (output_dir / "malware_source.c").exists(), "CLI didn't produce source file"
        assert (output_dir / "pipeline_report.txt").exists(), "CLI didn't produce report"


# ---------------------------------------------------------------------------
# E2E Tests: Checkpoint resume
# ---------------------------------------------------------------------------

@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_checkpoint_save_and_resume():
    """Generate with 1 iteration, verify checkpoint is saved, then resume."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        # First run — 1 iteration with compile loop to create checkpoint
        pipeline1 = MalwarePipeline(
            generate=True, provision_vm=False, verify=True, retry_loop=True,
            max_iterations=1, use_existing_vm=False,
            plan_review_cycles=2,
        )
        result1 = asyncio.run(pipeline1.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result1.generation_result is not None, "First run produced no generation result"

        checkpoint = output_dir / "checkpoint.json"
        if not checkpoint.exists():
            # Pipeline succeeded on first try — no checkpoint needed.
            # Verify source was generated (success is a valid outcome).
            source = result1.generation_result.source_code
            assert source and len(source) > 200, (
                "No checkpoint AND no valid source — something went wrong"
            )
            return

        # Second run — resume from checkpoint
        pipeline2 = MalwarePipeline(
            generate=True, provision_vm=False, verify=True, retry_loop=True,
            max_iterations=2, use_existing_vm=False,
            resume=True, plan_review_cycles=2,
        )
        result2 = asyncio.run(pipeline2.run(spec_path=spec_path, output_dir=str(output_dir)))
        assert result2.loop_result is not None, "Resume run produced no loop result"


# ---------------------------------------------------------------------------
# E2E Tests: Evasion quality checks
# ---------------------------------------------------------------------------

@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generated_source_has_evasion():
    """Generated source should include evasion passes (string encryption, IAT obfuscation)."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        source = result.generation_result.source_code
        assert source is not None

        # Check for string encryption evidence (XOR key array)
        has_xor = "_xk" in source or "xor_key" in source or "XOR" in source.upper()

        # Check for IAT obfuscation (GetProcAddress/LoadLibraryA patterns)
        has_iat = "GetProcAddress" in source or "LoadLibrary" in source

        # Check for anti-debug
        has_antidebug = "IsDebuggerPresent" in source or "NtQueryInformationProcess" in source

        evasion_count = sum([has_xor, has_iat, has_antidebug])
        assert evasion_count >= 1, (
            f"No evasion techniques found in generated source. "
            f"Expected at least string encryption, IAT obfuscation, or anti-debug. "
            f"Source length: {len(source)} chars"
        )


@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generated_source_no_guardrail_refusal():
    """LLM should not produce a guardrail refusal as the source code."""
    from malware_gen_framework.pipeline import MalwarePipeline
    from malware_gen_framework.code_analysis import _is_guardrail_refusal

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        source = result.generation_result.source_code
        assert source is not None, "No source generated"
        assert not _is_guardrail_refusal(source), (
            f"Generated source is a guardrail refusal: {source[:200]}"
        )


# ---------------------------------------------------------------------------
# E2E Tests: Spec parsing and configuration (no LLM needed)
# ---------------------------------------------------------------------------

@pytest.mark.e2e
def test_spec_parsing_valid():
    """Parse a valid spec through the pipeline's spec loader."""
    from malware_gen_framework.spec_parser import parse_target_spec

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        spec = parse_target_spec(spec_path=spec_path)

        assert spec.os_platform.value == "windows"
        assert "windows" in spec.os_version.lower()
        assert spec.malware_type == "ransomware"
        assert "defender" in spec.edrs


@pytest.mark.e2e
def test_spec_edr_normalization():
    """EDR aliases should be normalized in parsed spec."""
    from malware_gen_framework.spec_parser import parse_target_spec

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_file = Path(tmpdir) / "spec.yaml"
        spec_file.write_text(
            "os_platform: windows\n"
            "os_version: windows-11\n"
            "malware_type: ransomware\n"
            "source_language: c\n"
            "edrs:\n"
            "  - cs\n"
            "  - s1\n"
            "  - defender\n"
        )
        spec = parse_target_spec(spec_path=str(spec_file))
        assert "crowdstrike" in spec.edrs, f"Expected 'crowdstrike' alias, got {spec.edrs}"
        assert "sentinel_one" in spec.edrs, f"Expected 'sentinel_one' alias, got {spec.edrs}"


@pytest.mark.e2e
def test_spec_behavior_auto_injection():
    """Pipeline should auto-inject behavior spec for known malware types."""
    from malware_gen_framework.spec_parser import parse_target_spec
    from malware_gen_framework.pipeline import _generate_behavior_spec

    bspec = _generate_behavior_spec("info stealer", "10.0.2.2", 9001)
    assert "INFOSTEALER" in bspec
    assert "10.0.2.2" in bspec
    assert "9001" in bspec

    bspec_ransom = _generate_behavior_spec("ransomware", "10.0.2.2", 9001)
    assert "RANSOMWARE" in bspec_ransom
    assert "encrypt" in bspec_ransom.lower()

    bspec_keylog = _generate_behavior_spec("keylogger", "10.0.2.2", 9001)
    assert "KEYLOGGER" in bspec_keylog
    assert "hook" in bspec_keylog.lower()


@pytest.mark.e2e
def test_spec_invalid_malware_type_cli():
    """CLI should reject a spec with no malware_type set."""
    with tempfile.TemporaryDirectory() as tmpdir:
        spec_file = Path(tmpdir) / "spec.yaml"
        spec_file.write_text(
            "os_platform: windows\n"
            "os_version: windows-11\n"
            "source_language: c\n"
        )
        ret = subprocess.run(
            [sys.executable, "-m", "malware_gen_framework", "generate",
             "--spec", str(spec_file), "--output", str(tmpdir)],
            capture_output=True, text=True, timeout=30,
            cwd=str(PROJECT_ROOT.parent),
        )
        assert ret.returncode != 0, "CLI should reject spec without malware_type"


@pytest.mark.e2e
def test_spec_missing_file_cli():
    """CLI should fail cleanly when spec file doesn't exist."""
    ret = subprocess.run(
        [sys.executable, "-m", "malware_gen_framework", "generate",
         "--spec", "/nonexistent/spec.yaml", "--output", "/tmp/test_out"],
        capture_output=True, text=True, timeout=30,
        cwd=str(PROJECT_ROOT.parent),
    )
    assert ret.returncode != 0, "CLI should fail when spec file missing"


@pytest.mark.e2e
def test_cli_clean_command():
    """CLI clean command should run without error."""
    ret = subprocess.run(
        [sys.executable, "-m", "malware_gen_framework", "clean"],
        capture_output=True, text=True, timeout=30,
        cwd=str(PROJECT_ROOT.parent),
    )
    assert ret.returncode == 0, f"CLI clean failed: {ret.stderr}"


# ---------------------------------------------------------------------------
# E2E Tests: DB query engine (no LLM, but requires ChromaDB)
# ---------------------------------------------------------------------------

@pytest.mark.e2e
def test_db_query_returns_results():
    """DBQueryEngine should return results for a Windows target query."""
    from malware_gen_framework.spec_parser import parse_target_spec

    try:
        from malware_gen_framework.db_query_engine import DBQueryEngine
        db = DBQueryEngine()
    except Exception as e:
        pytest.skip(f"ChromaDB not available: {e}")

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        spec = parse_target_spec(spec_path=spec_path)
        result = asyncio.run(db.query_unified(spec))
        total = len(result.malware_techniques) + len(result.all_pocs) + len(result.cti_findings)
        assert total > 0, "DB queries returned zero results for Windows target"


@pytest.mark.e2e
def test_context_building_produces_techniques():
    """ContextBuilder should produce ranked techniques from DB results."""
    try:
        from malware_gen_framework.db_query_engine import DBQueryEngine
        from malware_gen_framework.context_builder import ContextBuilder
        from malware_gen_framework.spec_parser import parse_target_spec
    except Exception as e:
        pytest.skip(f"Required modules not available: {e}")

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        spec = parse_target_spec(spec_path=spec_path)

        try:
            db = DBQueryEngine()
            query_result = asyncio.run(db.query_unified(spec))
        except Exception:
            pytest.skip("ChromaDB not available")

        cb = ContextBuilder()
        context = cb.build_context(query_result, spec)
        assert context.target_summary, "Context has no target summary"
        assert len(context.techniques) > 0 or len(context.pocs) > 0, \
            "Context produced no techniques or PoCs"


@pytest.mark.e2e
def test_edr_config_resolution():
    """Pipeline EDR config resolver should return configs for all builtin EDRs."""
    from malware_gen_framework.pipeline import _resolve_edr_configs

    configs = _resolve_edr_configs(["defender"])
    assert len(configs) >= 1
    assert any(c.name == "defender" for c in configs)

    all_configs = _resolve_edr_configs([])
    assert len(all_configs) >= 3, f"Expected 3+ builtin EDRs, got {len(all_configs)}"

    unknown_configs = _resolve_edr_configs(["crowdstrike_pro_ultra_v9"])
    assert len(unknown_configs) >= 3, "Unknown EDR should fall back to all available"


# ---------------------------------------------------------------------------
# E2E Tests: Additional LLM generation tests
# ---------------------------------------------------------------------------

@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_rat():
    """Generate RAT/backdoor source, verify it compiles and has C2 code."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_file = Path(tmpdir) / "spec.yaml"
        spec_file.write_text(
            "os_platform: windows\n"
            "os_version: windows-11\n"
            "malware_type: backdoor\n"
            "source_language: c\n"
            "output_format: exe\n"
            "c2_address: '10.0.2.2'\n"
            "c2_port: 9001\n"
            "edrs:\n"
            "  - defender\n"
            "installed_compilers:\n"
            "  - mingw-w64\n"
            "admin_rights: true\n"
        )
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=str(spec_file), output_dir=str(output_dir)))

        assert result.generation_result is not None
        source = result.generation_result.source_code
        assert source is not None
        assert len(source) > 200

        ok, stderr, _ = _compile_source(source, tmpdir)
        assert ok, f"Generated backdoor source failed to compile:\n{stderr[:2000]}"

        has_network = any(kw in source for kw in ("WSAStartup", "connect", "send", "socket", "recv"))
        assert has_network, "Backdoor source has no network code"


@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_with_behavior_override():
    """Generate with explicit behavior_spec override, verify key markers present."""
    from malware_gen_framework.pipeline import MalwarePipeline

    custom_behavior = (
        "Create a simple file dropper: drop a .txt file to C:\\Users\\vmuser\\Desktop "
        "containing 'payload_delivered', then connect to 10.0.2.2:9001 and send "
        "'status:complete'. Use CreateFileA for file operations and WSAStartup/connect/send for network."
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="info stealer")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=True,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(
            spec_path=spec_path, output_dir=str(output_dir),
            behavior_spec=custom_behavior,
        ))

        assert result.generation_result is not None
        source = result.generation_result.source_code
        if result.loop_result and result.loop_result.final_source:
            source = result.loop_result.final_source
        assert source is not None
        assert len(source) > 200

        behavior_markers = [
            "CreateFile", "WSAStartup", "connect", "send",
            "Desktop", "payload", "status", "10.0.2.2",
        ]
        found = [m for m in behavior_markers if m.lower() in source.lower()]
        assert len(found) >= 3, (
            f"Behavior override not reflected in source — only {len(found)}/8 "
            f"markers found: {found}"
        )

        ok, stderr, _ = _compile_source(source, tmpdir)
        assert ok, (
            f"Behavior-override source failed to compile: {stderr[:500]}"
        )


@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_multiple_edrs():
    """Generate with multiple EDRs in spec, verify evasion techniques present."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_file = Path(tmpdir) / "spec.yaml"
        spec_file.write_text(
            "os_platform: windows\n"
            "os_version: windows-11\n"
            "malware_type: ransomware\n"
            "source_language: c\n"
            "output_format: exe\n"
            "edrs:\n"
            "  - defender\n"
            "  - elastic\n"
            "  - wazuh\n"
            "installed_compilers:\n"
            "  - mingw-w64\n"
            "admin_rights: true\n"
        )
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=str(spec_file), output_dir=str(output_dir)))

        assert result.generation_result is not None
        source = result.generation_result.source_code
        assert source is not None

        ok, stderr, _ = _compile_source(source, tmpdir)
        assert ok, f"Multi-EDR source failed to compile:\n{stderr[:2000]}"


@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_custom_gates():
    """Generate with custom gates in spec, verify source compiles."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_file = Path(tmpdir) / "spec.yaml"
        spec_file.write_text(
            "os_platform: windows\n"
            "os_version: windows-11\n"
            "malware_type: ransomware\n"
            "source_language: c\n"
            "output_format: exe\n"
            "edrs:\n"
            "  - defender\n"
            "installed_compilers:\n"
            "  - mingw-w64\n"
            "admin_rights: true\n"
            "custom_gates:\n"
            "  - no console window\n"
            "  - must bypass AMSI\n"
            "  - process hollowing preferred\n"
        )
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=str(spec_file), output_dir=str(output_dir)))

        assert result.generation_result is not None
        source = result.generation_result.source_code
        assert source is not None
        assert len(source) > 200

        ok, stderr, _ = _compile_source(source, tmpdir)
        assert ok, f"Custom-gates source failed to compile:\n{stderr[:2000]}"


@pytest.mark.e2e
@requires_llm
def test_pipeline_result_fields():
    """Verify PipelineResult has all expected fields populated after generation."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.target_spec is not None, "target_spec not set"
        assert result.output_dir == str(output_dir), "output_dir mismatch"
        assert result.generation_result is not None, "generation_result not set"
        assert result.generation_result.source_code is not None
        assert result.generation_result.prompt_length > 0, "prompt_length should be positive"
        assert result.generation_result.context_hash, "context_hash should be non-empty"
        assert result.generation_result.plan is not None, "plan should be set"
        assert len(result.generation_result.plan.components) > 0, "plan should have components"

        summary = result.print_summary()
        assert "windows" in summary.lower()
        assert "chars" in summary.lower()


@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_evasion_chain_on_generated_source():
    """Apply full evasion chain to generated source and verify it still compiles."""
    from malware_gen_framework.pipeline import MalwarePipeline
    from malware_gen_framework.evasion_passes import (
        _encrypt_string_literals,
        _mutate_source,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        source = result.generation_result.source_code
        assert source is not None

        # The pipeline already applies evasion passes, but verify the source
        # can survive an additional mutation round (polymorphic stability)
        mutated = _mutate_source(source)
        assert mutated != source, "Mutation should change the source"
        assert len(mutated) > 100, "Mutated source too short"

        ok, stderr, _ = _compile_source(mutated, tmpdir)
        assert ok, f"Mutated source failed to compile:\n{stderr[:2000]}"


@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_report_content():
    """Verify pipeline report contains expected sections."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="info stealer")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        report_file = output_dir / "pipeline_report.txt"
        assert report_file.exists(), "No report written"
        report = report_file.read_text()

        assert "MALWARE GENERATION PIPELINE REPORT" in report
        assert "windows" in report.lower()
        assert "Generation:" in report
        assert "Source code length:" in report
        assert "C2 Listener" in report, "Infostealer report should mention C2"
        assert "10.0.2.2" in report, "Report should mention C2 address"


@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_plan_component_coverage():
    """Generated plan should have components covering key malware functions."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(Path(tmpdir) / "spec.yaml", malware_type="ransomware")
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=False,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        plan = result.generation_result.plan
        assert plan is not None
        assert plan.language == "c"
        assert len(plan.components) >= 3, \
            f"Expected 3+ plan components for ransomware, got {len(plan.components)}"

        comp_names = [c.name.lower() for c in plan.components]
        comp_text = " ".join(comp_names)
        has_main = any("main" in n for n in comp_names)
        assert has_main, f"Plan should include a main component. Got: {comp_names}"


# ---------------------------------------------------------------------------
# E2E Tests: Shellcode output format
# ---------------------------------------------------------------------------

@pytest.mark.e2e
@requires_llm
@requires_mingw
def test_generate_shellcode_output():
    """Generate shellcode-format output, verify .bin file produced."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(
            Path(tmpdir) / "spec.yaml",
            malware_type="ransomware",
            output_format="shellcode",
        )
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=True,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None, "Generation returned no result"
        source = result.generation_result.source_code
        if result.loop_result and result.loop_result.final_source:
            source = result.loop_result.final_source
        assert source is not None, "Generated source is None"
        assert len(source) > 200, f"Source too short ({len(source)} chars)"

        src_file = Path(tmpdir) / "sc_test.c"
        src_file.write_text(source)
        obj_file = Path(tmpdir) / "sc_test.obj"
        bin_file = Path(tmpdir) / "sc_test.bin"

        compile_ret = subprocess.run(
            ["x86_64-w64-mingw32-gcc", "-O2", "-m64", "-c",
             "-fPIC", "-fno-stack-protector",
             str(src_file), "-o", str(obj_file)],
            capture_output=True, text=True, timeout=60,
        )
        assert compile_ret.returncode == 0, (
            f"Shellcode source failed to compile as position-independent code: "
            f"{compile_ret.stderr[:500]}"
        )

        objcopy = "x86_64-w64-mingw32-objcopy"
        extract_ret = subprocess.run(
            [objcopy, "-O", "binary", "-j", ".text", str(obj_file), str(bin_file)],
            capture_output=True, text=True, timeout=30,
        )
        assert extract_ret.returncode == 0, \
            f"objcopy .text extraction failed: {extract_ret.stderr[:500]}"
        assert bin_file.exists(), "Shellcode .bin file not created"
        assert bin_file.stat().st_size > 0, "Shellcode .bin file is empty"


# ---------------------------------------------------------------------------
# E2E Tests: Linux target
# ---------------------------------------------------------------------------

@pytest.mark.e2e
@requires_llm
@requires_gcc
def test_generate_linux_ransomware():
    """Generate ransomware for Linux, compile with native gcc."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(
            Path(tmpdir) / "spec.yaml",
            malware_type="ransomware",
            os_platform="linux",
            source_language="c",
        )
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=True,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None, "Generation returned no result"
        source = result.generation_result.source_code
        if result.loop_result and result.loop_result.final_source:
            source = result.loop_result.final_source
        assert source is not None, "Generated source is None"
        assert len(source) > 200, f"Source too short ({len(source)} chars)"

        linux_markers = ["opendir", "readdir", "fopen", "fwrite", "stat", "dirent",
                         "unistd", "fcntl", "stdlib", "stdio"]
        found = [m for m in linux_markers if m.lower() in source.lower()]
        assert len(found) >= 2, (
            f"Linux ransomware should use POSIX APIs — only {len(found)}/10 "
            f"markers found: {found}"
        )

        windows_apis = [w for w in ["windows.h", "CreateFile", "WinMain", "HMODULE"]
                        if w in source]
        assert not windows_apis, (
            f"Linux ransomware contains Windows APIs — framework generated "
            f"Windows code for a Linux target: {windows_apis}"
        )

        src_file = Path(tmpdir) / "linux_test.c"
        src_file.write_text(source)
        out_file = Path(tmpdir) / "linux_test"
        ret = subprocess.run(
            ["gcc", "-O2", "-o", str(out_file), str(src_file),
             "-lcrypto", "-lpthread", "-lssl"],
            capture_output=True, text=True, timeout=60,
        )
        if ret.returncode != 0:
            ret = subprocess.run(
                ["gcc", "-O2", "-o", str(out_file), str(src_file), "-lpthread"],
                capture_output=True, text=True, timeout=60,
            )
        assert ret.returncode == 0, (
            f"Linux ransomware source failed to compile with gcc: "
            f"{ret.stderr[:500]}"
        )
        assert Path(out_file).exists(), "Compiled Linux binary not created"
        assert Path(out_file).stat().st_size > 0, "Compiled Linux binary is empty"


# ---------------------------------------------------------------------------
# E2E Tests: Rust generation
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="Rust support dropped — local LLM can't produce valid Rust consistently")
@pytest.mark.e2e
@requires_llm
@requires_rustc
def test_generate_rust_ransomware():
    """Generate ransomware in Rust, verify it produces valid Rust source."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(
            Path(tmpdir) / "spec.yaml",
            malware_type="ransomware",
            source_language="rust",
        )
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=True,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None, "Generation returned no result"
        source = result.generation_result.source_code
        if result.loop_result and result.loop_result.final_source:
            source = result.loop_result.final_source
        assert source is not None, "Generated source is None"
        assert len(source) > 100, f"Source too short ({len(source)} chars)"

        rust_markers = ["fn ", "use ", "let ", "mut ", "impl ", "struct ",
                        "String", "Vec", "Result", "pub "]
        found = [m for m in rust_markers if m in source]
        assert len(found) >= 3, (
            f"Rust source should contain Rust syntax — only {len(found)}/10 "
            f"markers found: {found}"
        )

        src_file = Path(tmpdir) / "rust_test.rs"
        src_file.write_text(source)
        out_file = Path(tmpdir) / "rust_test.exe"
        ret = subprocess.run(
            ["rustc", "--target", "x86_64-pc-windows-gnu",
             "--crate-type", "bin",
             "-C", "opt-level=2", "-C", "strip=symbols",
             str(src_file), "-o", str(out_file)],
            capture_output=True, text=True, timeout=120,
        )
        assert ret.returncode == 0, (
            f"Rust ransomware source failed to compile with rustc: "
            f"{ret.stderr[:500]}"
        )


# ---------------------------------------------------------------------------
# E2E Tests: Go generation
# ---------------------------------------------------------------------------

@pytest.mark.e2e
@requires_llm
@requires_go
def test_generate_go_ransomware():
    """Generate ransomware in Go, verify it produces valid Go source."""
    from malware_gen_framework.pipeline import MalwarePipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        spec_path = _write_spec(
            Path(tmpdir) / "spec.yaml",
            malware_type="ransomware",
            source_language="go",
        )
        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        pipeline = MalwarePipeline(
            generate=True, provision_vm=False, verify=False, retry_loop=True,
            plan_review_cycles=2,
        )
        result = asyncio.run(pipeline.run(spec_path=spec_path, output_dir=str(output_dir)))

        assert result.generation_result is not None, "Generation returned no result"
        source = result.generation_result.source_code
        if result.loop_result and result.loop_result.final_source:
            source = result.loop_result.final_source
        assert source is not None, "Generated source is None"
        assert len(source) > 100, f"Source too short ({len(source)} chars)"

        go_markers = ["package ", "func ", "import ", "fmt.", "os.",
                      "if ", "for ", "return ", "var ", "defer "]
        found = [m for m in go_markers if m in source]
        assert len(found) >= 3, (
            f"Go source should contain Go syntax — only {len(found)}/10 "
            f"markers found: {found}"
        )

        src_file = Path(tmpdir) / "main.go"
        src_file.write_text(source)
        subprocess.run(["go", "mod", "init", "test"], capture_output=True, cwd=tmpdir)
        out_file = Path(tmpdir) / "go_test.exe"
        ret = subprocess.run(
            ["go", "build", "-ldflags=-s -w", "-o", str(out_file), "."],
            capture_output=True, text=True, timeout=120, cwd=tmpdir,
            env={**subprocess.os.environ, "GOOS": "windows", "GOARCH": "amd64",
                 "CGO_ENABLED": "0"},
        )
        assert ret.returncode == 0, (
            f"Go ransomware source failed to compile: "
            f"{ret.stderr[:500]}"
        )


# ---------------------------------------------------------------------------
# E2E Tests: C2 Listener
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_c2_listener_start_stop():
    """C2 listener starts on a free port and stops cleanly."""
    from portal.c2_listener import C2Listener

    async def _run():
        listener = C2Listener()
        started = await listener.start(port=19876, host="127.0.0.1")
        assert started, "C2 listener failed to start"
        assert listener.running, "Listener not marked as running"

        status = listener.status()
        assert status["running"] is True
        assert status["port"] == 19876
        assert status["total_connections"] == 0

        await listener.stop()
        assert not listener.running, "Listener still running after stop"

    asyncio.run(_run())


@pytest.mark.integration
def test_c2_listener_receives_data():
    """C2 listener receives TCP data and saves it to disk."""
    import socket
    from portal.c2_listener import C2Listener

    async def _run():
        listener = C2Listener()
        started = await listener.start(port=19877, host="127.0.0.1")
        assert started

        test_data = b"EXFIL_DATA_credential_dump_test_payload_1234567890"

        def _send():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", 19877))
            s.sendall(test_data)
            s.close()

        await asyncio.to_thread(_send)
        await asyncio.sleep(1)

        status = listener.status()
        assert status["total_connections"] >= 1, "No connections recorded"
        assert status["total_bytes"] >= len(test_data), \
            f"Expected >= {len(test_data)} bytes, got {status['total_bytes']}"

        conns = status["connections"]
        assert len(conns) >= 1
        assert conns[0]["bytes_received"] >= len(test_data)
        assert conns[0]["data_file"], "No data file recorded"

        from pathlib import Path as _P
        data_path = _P(__file__).parent.parent / "results" / conns[0]["data_file"]
        assert data_path.exists(), f"Data file not found: {data_path}"
        saved = data_path.read_bytes()
        assert test_data in saved, "Saved data doesn't contain sent payload"

        data_path.unlink(missing_ok=True)
        await listener.stop()

    asyncio.run(_run())


@pytest.mark.integration
def test_c2_listener_multiple_connections():
    """C2 listener handles multiple concurrent connections."""
    import socket
    from portal.c2_listener import C2Listener

    async def _run():
        listener = C2Listener()
        started = await listener.start(port=19878, host="127.0.0.1")
        assert started

        def _send(msg: bytes):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", 19878))
            s.sendall(msg)
            s.close()

        payloads = [b"CONN_1_data", b"CONN_2_data", b"CONN_3_data"]
        for p in payloads:
            await asyncio.to_thread(_send, p)
            await asyncio.sleep(0.3)

        await asyncio.sleep(1)

        status = listener.status()
        assert status["total_connections"] >= 3, \
            f"Expected 3+ connections, got {status['total_connections']}"
        total_sent = sum(len(p) for p in payloads)
        assert status["total_bytes"] >= total_sent, \
            f"Expected >= {total_sent} bytes, got {status['total_bytes']}"

        for conn in status["connections"]:
            from pathlib import Path as _P
            f = _P(__file__).parent.parent / "results" / conn["data_file"]
            f.unlink(missing_ok=True)

        await listener.stop()

    asyncio.run(_run())
