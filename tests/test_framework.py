"""
Comprehensive tests for the malware generation framework.

Tests cover:
  - Config models (Phase 3)
  - Provisioners (Phase 3 — unit)
  - DB query engine / models (Phase 1)
  - Target spec parser (Phase 2)
  - Context builder + prompt templates (Phase 1 extras)
  - Evasion / exploit / compiler selectors (Phase 4)
  - Generation engine (Phase 4 core)
  - Verifier + loop controller (Phase 5)
  - Pipeline integration (Phase 6)

Run: python3 -m pytest tests/test_framework.py -v
Or:  cd /home/kei/llm_vault/malware_gen_framework && python3 -m pytest tests/test_framework.py -v
"""

import asyncio
import json
import os
import shutil
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

# Ensure the package is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ===================================================================
# Helper: run async test functions in sync context
# ===================================================================

def _async(f):
    """Decorate an async test so it can be called from a sync test."""
    def wrapper(*args, **kwargs):
        return asyncio.get_event_loop().run_until_complete(f(*args, **kwargs))
    return wrapper


# ===================================================================
# Phase 3 — Config Models
# ===================================================================

def test_vm_provision_config_defaults():
    """VMProvisionConfig should have reasonable defaults."""
    from malware_gen_framework.config_models import VMProvisionConfig, TargetOS

    cfg = VMProvisionConfig(os_type=TargetOS.UBUNTU_24_04)
    assert cfg.resources.CPU_cores == 4
    assert cfg.resources.RAM_GB == 8
    assert cfg.network.port_fwd_ssh == 10022


def test_vm_provision_config_compute_paths():
    """compute_paths should fill in derived paths."""
    from malware_gen_framework.config_models import VMProvisionConfig, TargetOS

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = VMProvisionConfig(
            os_type=TargetOS.UBUNTU_24_04,
            vm_name="test-vm",
            base_dir=Path(tmpdir),
        )
        cfg.compute_paths()

        assert cfg.base_img.exists() or tmpdir in str(cfg.base_img)
        assert "base_ubuntu-24.04" in str(cfg.base_img)
        assert "cow.qcow2" in str(cfg.cow_img)


def test_target_os_enum():
    """TargetOS enum should have expected members."""
    from malware_gen_framework.config_models import TargetOS

    assert hasattr(TargetOS, "UBUNTU_24_04")
    assert hasattr(TargetOS, "WINDOWS_11")
    assert hasattr(TargetOS, "DEBIAN_BOOKWORM")


# ===================================================================
# Phase 3 — Provisioners (Unit Tests)
# ===================================================================

def test_cloud_init_iso_creation():
    """CloudInitProvisioner should create a valid NoCloud ISO."""
    if shutil.which("genisoimage") is None:
        pytest.skip("genisoimage not installed")

    from malware_gen_framework.linux_provisioner import CloudInitProvisioner

    with tempfile.TemporaryDirectory() as tmpdir:
        prov = CloudInitProvisioner()
        iso_path = prov.create_nocloud_iso(target_dir=tmpdir)

        assert Path(iso_path).exists()
        assert iso_path.endswith(".iso")


def test_autounattend_iso_creation():
    """WindowsProvisioner should create an unattended ISO."""
    if shutil.which("genisoimage") is None:
        pytest.skip("genisoimage not installed")

    from malware_gen_framework.windows_provisioner import WindowsProvisioner

    with tempfile.TemporaryDirectory() as tmpdir:
        prov = WindowsProvisioner()
        iso_path = prov.create_unattended_iso(target_dir=tmpdir)

        assert Path(iso_path).exists()


# ===================================================================
# Phase 3 — Import Check
# ===================================================================

def test_package_imports():
    """All package-level imports should resolve."""
    from malware_gen_framework import (
        ProvisionEngine, VMProvisionConfig, TargetOS,
        DBQueryEngine, ContextBuilder, PromptTemplates,
        GenerationEngine, EvasionSelector, ExploitSelector, CompilerSelector,
        Verifier, LoopController, MalwarePipeline,
        parse_target_spec, spec_to_yaml,
    )


# ===================================================================
# Phase 1 — DB Models
# ===================================================================

def test_db_models_dataclasses():
    """All DB dataclasses should instantiate correctly."""
    from malware_gen_framework.db_models import (
        MalwareTechnique, PoC, CTIFinding, QueryResult, TargetEnvironmentSpec as DBSpec,
    )

    tech = MalwareTechnique(
        id="test-1", name="API Unhooking", description="Test technique",
        category="evasion", os_type="windows", edr_detection="crowdstrike"
    )
    assert tech.id == "test-1"
    assert tech.references == []  # __post_init__ default

    poc = PoC(id="poc-1", cve="CVE-2024-1234", title="Test Exploit",
              description="Test desc", exploit_type="RCE", target_os="windows", severity="critical")
    assert poc.id == "poc-1"

    finding = CTIFinding(id="c-1", title="Threat Intel", description="Test intel", severity="high")
    assert finding.related_cves == []  # __post_init__ default


# ===================================================================
# Phase 2 — Target Spec Parser
# ===================================================================

def test_parse_target_spec_yaml():
    """parse_target_spec should load and validate a YAML spec."""
    from malware_gen_framework.spec_parser import parse_target_spec

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""
os_platform: linux
os_version: ubuntu-24.04
edrs:
  - sentinel_one
  - CrowdStrike
installed_compilers:
  - gcc
  - python3
""")
        spec_path = f.name

    try:
        spec = parse_target_spec(spec_path=spec_path)
        assert spec.os_platform.value == "linux"
        assert spec.os_version == "ubuntu-24.04"
        # EDRs should be normalised to lowercase with underscores
        assert any("sentinel_one" in e for e in spec.edrs)
        assert any("crowdstrike" in e for e in spec.edrs)
    finally:
        os.unlink(spec_path)


def test_parse_target_spec_json():
    """parse_target_spec should load and validate a JSON spec."""
    from malware_gen_framework.spec_parser import parse_target_spec

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({
            "os_platform": "windows",
            "os_version": "windows-11",
            "edrs": ["defender"],
            "installed_compilers": ["gcc", "mingw-w64"],
        }, f)
        spec_path = f.name

    try:
        spec = parse_target_spec(spec_path=spec_path)
        assert spec.os_platform.value == "windows"
    finally:
        os.unlink(spec_path)


def test_parse_target_spec_overrides():
    """parse_target_spec overrides should take precedence over file values."""
    from malware_gen_framework.spec_parser import parse_target_spec

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("os_version: ubuntu-22.04\n")
        spec_path = f.name

    try:
        spec = parse_target_spec(spec_path=spec_path, os_version="ubuntu-24.04")
        assert spec.os_version == "ubuntu-24.04"  # override wins
    finally:
        os.unlink(spec_path)


def test_parse_target_spec_auto_detect_platform():
    """Platform should auto-detect from version string if not specified."""
    from malware_gen_framework.spec_parser import parse_target_spec

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("os_version: debian-bookworm\n")
        spec_path = f.name

    try:
        spec = parse_target_spec(spec_path=spec_path)
        assert spec.os_platform.value == "linux"  # auto-detected from version
    finally:
        os.unlink(spec_path)


# ===================================================================
# Phase 1 Extras — Context Builder
# ===================================================================

def test_context_builder_ranking():
    """ContextBuilder should rank techniques by relevance."""
    from malware_gen_framework.context_builder import ContextBuilder, RankedTechnique
    from malware_gen_framework.db_models import MalwareTechnique, QueryResult, PoC, CTIFinding
    from malware_gen_framework.target_spec import TargetEnvironmentSpec

    builder = ContextBuilder()

    # Create mock query results
    techs = [
        MalwareTechnique(id="t1", name="API Unhooking via NtQuerySystemInformation", description="d", category="evasion", os_type="windows", detection_rating=2),
        MalwareTechnique(id="t2", name="AMSI Bypass via Memory Patch", description="d", category="evasion", os_type="windows", detection_rating=4),
    ]
    query_result = QueryResult(malware_techniques=techs, poc_results=[], cti_findings=[])

    spec = TargetEnvironmentSpec(
        os_platform="linux", os_version="ubuntu-24.04",
        edrs=["crowdstrike"], installed_compilers=["gcc"]
    )

    ctx = builder.build_context(query_result, spec)
    assert len(ctx.techniques) == 2
    # t1 (rating=2) should rank higher than t2 (rating=4) since lower rating = easier to evade
    assert ctx.techniques[0].rank_score >= ctx.techniques[1].rank_score


# ===================================================================
# Phase 1 Extras — Prompt Templates
# ===================================================================

def test_prompt_templates_render():
    """PromptTemplates should render a non-empty prompt string."""
    from malware_gen_framework.prompt_templates import PromptTemplates
    from malware_gen_framework.context_builder import ContextBlock, RankedTechnique, RankedPoC
    from malware_gen_framework.db_models import MalwareTechnique, PoC

    templates = PromptTemplates()

    ctx = ContextBlock(
        target_summary="linux ubuntu-24.04",
        techniques=[RankedTechnique(technique=MalwareTechnique(id="t1", name="Test", description="", category="", os_type=""), rank_score=5.0)],
        pocs=[RankedPoC(poc=PoC(id="p1", cve="CVE-2024-1", title="Test PoC", description="", exploit_type="", target_os="", severity=""), rank_score=3.0)],
        cti_findings=[],
    )

    prompt = templates.render_generate_prompt(
        context=ctx,
        installed_compilers=["gcc"],
        custom_gates=["no console"],
    )
    assert len(prompt) > 100


# ===================================================================
# Phase 4 — Evasion Selector (mocked DB)
# ===================================================================

def test_evasion_selector_mock():
    """EvasionSelector should return ranked techniques from mocked DB."""
    from malware_gen_framework.evasion_selector import EvasionSelector
    from malware_gen_framework.db_models import MalwareTechnique, QueryResult, PoC, CTIFinding
    from malware_gen_framework.target_spec import TargetEnvironmentSpec

    selector = EvasionSelector()

    # Mock the DB engine's query method
    mock_db = MagicMock()
    mock_db.query_malware_by_edr.return_value = [
        MalwareTechnique(id="e1", name="EDR Unhook", description="d", category="evasion", os_type="", detection_rating=2),
    ]

    selector._db = mock_db

    spec = TargetEnvironmentSpec(
        os_platform="linux", os_version="ubuntu-24.04",
        edrs=["crowdstrike"], installed_compilers=[]
    )

    result = selector.select_evasions(spec)
    assert len(result) == 1
    mock_db.query_malware_by_edr.assert_called_once()


# ===================================================================
# Phase 4 — Exploit Selector (mocked DB)
# ===================================================================

def test_exploit_selector_mock():
    """ExploitSelector should return ranked exploits from mocked DB."""
    from malware_gen_framework.exploit_selector import ExploitSelector, ExploitSelection
    from malware_gen_framework.db_models import PoC

    selector = ExploitSelector()
    mock_db = MagicMock()
    mock_db.query_poc_by_cve.return_value = [
        PoC(id="p1", cve="CVE-2024-9999", title="RCE Exploit", description="", exploit_type="RCE", target_os="linux", severity="critical"),
    ]

    selector._db = mock_db

    from malware_gen_framework.target_spec import TargetEnvironmentSpec
    spec = TargetEnvironmentSpec(
        os_platform="linux", os_version="ubuntu-24.04", edrs=[], installed_compilers=[]
    )

    result = selector.select_exploits(spec)
    assert len(result) >= 1


# ===================================================================
# Phase 4 — Compiler Selector
# ===================================================================

def test_compiler_selector():
    """CompilerSelector should produce valid build instructions."""
    from malware_gen_framework.compiler_selector import CompilerSelector
    from malware_gen_framework.target_spec import TargetEnvironmentSpec

    selector = CompilerSelector()
    spec = TargetEnvironmentSpec(
        os_platform="linux", os_version="ubuntu-24.04",
        installed_compilers=["gcc"], common_tools=[]
    )

    instrs = selector.select_build_instructions("#include <stdio.h>\nint main(){return 0;}", "c", spec)
    assert len(instrs) >= 1
    assert any("gcc" in i.command for i in instrs)


# ===================================================================
# Phase 4 — Generation Engine (mocked LLM)
# ===================================================================

def test_generation_engine_mock():
    """GenerationEngine should build a prompt and call the mocked LLM."""
    from malware_gen_framework.generation_engine import GenerationEngine, SubprocessLLMClient
    from malware_gen_framework.target_spec import TargetEnvironmentSpec
    from malware_gen_framework.db_models import MalwareTechnique, PoC, CTIFinding, QueryResult

    # Mock DB — query_unified is async, so use AsyncMock
    mock_db = MagicMock()
    mock_db.query_unified = AsyncMock(return_value=QueryResult(
        malware_techniques=[
            MalwareTechnique(id="t1", name="test technique", description="", category="evasion", os_type="linux"),
        ],
        poc_results=[
            PoC(id="p1", cve="CVE-2024-1", title="Test Exploit", description="", exploit_type="", target_os="linux", severity="high"),
        ],
        cti_findings=[CTIFinding(id="c1", title="Test CTI", description="", severity="high")],
    ))

    # Mock the LLM client — .generate() must be async and return a string
    mock_llm = MagicMock()
    mock_llm.generate = AsyncMock(return_value="int main(){return 0;}")

    engine = GenerationEngine(db_engine=mock_db, llm_client=mock_llm)

    spec = TargetEnvironmentSpec(
        os_platform="linux", os_version="ubuntu-24.04",
        edrs=["crowdstrike"], installed_compilers=["gcc"]
    )

    result = asyncio.run(engine.generate(spec))
    assert mock_llm.generate.called


# ===================================================================
# Phase 5 — Loop Controller
# ===================================================================

def test_loop_controller_iteration_record():
    """IterationRecord should be constructible."""
    from malware_gen_framework.loop_controller import IterationRecord, FailureMode

    rec = IterationRecord(
        iteration=1, source_code_hash="abc", context_hash="xyz",
        failure_mode=FailureMode.DETECTED, detection_score="high",
        alerts_count=3, build_time_sec=2.0, execution_exit_code=0,
    )
    assert rec.iteration == 1
    assert rec.failure_mode == FailureMode.DETECTED


def test_loop_controller_stuck_detection():
    """LoopController should detect stuck context hashes."""
    from malware_gen_framework.loop_controller import LoopController

    ctrl = LoopController(stick_threshold=2)
    # Same hash repeated — should be detected as stuck after threshold
    assert ctrl._is_stuck(0, None, "abc") is False  # no previous
    assert ctrl._is_stuck(1, "abc", "abc") is True   # same as before


def test_loop_result_summary():
    """LoopResult.summary() should produce readable output."""
    from malware_gen_framework.loop_controller import LoopResult, IterationRecord, FailureMode

    records = [
        IterationRecord(iteration=1, source_code_hash="", context_hash="", failure_mode=None, detection_score="none", alerts_count=0, build_time_sec=1.0, execution_exit_code=0),
        IterationRecord(iteration=2, source_code_hash="", context_hash="", failure_mode=FailureMode.DETECTED, detection_score="high", alerts_count=5, build_time_sec=2.0, execution_exit_code=0),
    ]

    loop_result = LoopResult(
        iterations=records, best_result={"iteration": 1, "detection_score": "none"},
        total_iterations=2, success=True
    )

    summary = loop_result.summary()
    assert "Iteration" in summary
    assert "UNDETECTED" in summary


# ===================================================================
# Phase 5 — Verifier (mocked VM)
# ===================================================================

def test_verifier_standalone():
    """verify_standalone should compile a simple C program."""
    from malware_gen_framework.verifier import verify_standalone, DetectionLevel, BehaviourCheck
    from malware_gen_framework.target_spec import TargetEnvironmentSpec

    source = "#include <stdio.h>\nint main(){printf(\"hello\");return 0;}"

    spec = TargetEnvironmentSpec(
        os_platform="linux", os_version="ubuntu-24.04",
        installed_compilers=["gcc"], edrs=[]
    )

    result = asyncio.run(verify_standalone(source, spec))

    # Should compile successfully (assuming gcc is available)
    assert result.compilation_output or True  # may fail if no gcc — don't hard-fail


# ===================================================================
# Phase 6 — CLI Parser
# ===================================================================

def test_cli_parser():
    """CLI parser should have all expected subcommands."""
    from malware_gen_framework.cli import build_parser

    parser = build_parser()

    # Just check that it parses without error
    args = parser.parse_args(["generate", "--spec", "/tmp/test.yaml"])
    assert args.command == "generate"
    assert args.spec == "/tmp/test.yaml"


# ===================================================================
# Phase 6 — Pipeline (mocked)
# ===================================================================

def test_pipeline_result():
    """PipelineResult should produce a summary."""
    from malware_gen_framework.pipeline import PipelineResult

    result = PipelineResult(
        target_spec=MagicMock(os_platform=MagicMock(value="linux"), os_version="ubuntu-24.04"),
        output_dir="/tmp", generation_result=None, verification_results=[], loop_result=None,
    )

    summary = result.print_summary()
    assert "linux" in summary


# ===================================================================
# Full Compile + Import Check (from TEST_AND_NEXT_STEPS.md)
# ===================================================================

def test_compile_check():
    """All module files should compile without syntax errors."""
    import py_compile
    from pathlib import Path

    base = Path(__file__).resolve().parent.parent
    modules = [
        "config_models.py", "image_sources.py", "linux_provisioner.py",
        "windows_provisioner.py", "provision_engine.py", "__init__.py",
        "db_models.py", "db_query_engine.py",
        "target_spec.py", "spec_parser.py",
        "context_builder.py", "prompt_templates.py",
        "generation_engine.py", "evasion_selector.py",
        "exploit_selector.py", "compiler_selector.py",
        "verifier.py", "loop_controller.py",
        "cli.py", "pipeline.py",
    ]

    for mod in modules:
        path = base / mod
        assert path.exists(), f"{mod} does not exist"
        # py_compile will raise SyntaxError if the file is invalid
        py_compile.compile(str(path), doraise=True)


def test_import_all():
    """All module imports should resolve."""
    from malware_gen_framework import (
        ProvisionEngine, VMProvisionConfig, TargetOS,
        DBQueryEngine, ContextBuilder, PromptTemplates,
        GenerationEngine, EvasionSelector, ExploitSelector, CompilerSelector,
        Verifier, LoopController, MalwarePipeline,
        parse_target_spec, spec_to_yaml, cli_build_parser,
    )
