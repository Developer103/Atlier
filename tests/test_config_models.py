"""Tier 1 unit tests for config_models.py, target_spec.py, spec_parser.py, checkpoint.py, code_processor.py, llm_client.py."""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ---------------------------------------------------------------------------
# EDRConfig / BUILTIN_EDRS
# ---------------------------------------------------------------------------

def test_builtin_edrs_all_present():
    from atelier.config_models import BUILTIN_EDRS
    expected = {"defender", "wazuh", "elastic", "openedr", "velociraptor"}
    assert set(BUILTIN_EDRS.keys()) == expected


def test_get_edr_config_known():
    from atelier.config_models import get_edr_config
    cfg = get_edr_config("defender")
    assert cfg.name == "defender"
    assert "Get-WinEvent" in cfg.alert_query


def test_get_edr_config_unknown():
    from atelier.config_models import get_edr_config
    cfg = get_edr_config("totally_unknown")
    assert cfg.name == "totally_unknown"
    assert cfg.detection_method == "ssh_command"


def test_edr_config_defaults():
    from atelier.config_models import EDRConfig
    cfg = EDRConfig(name="test")
    assert cfg.detection_method == "ssh_command"
    assert cfg.alert_query == ""
    assert cfg.api_auth == {}


def test_wazuh_has_rest_api():
    from atelier.config_models import BUILTIN_EDRS
    assert BUILTIN_EDRS["wazuh"].detection_method == "rest_api"


def test_elastic_has_elasticsearch():
    from atelier.config_models import BUILTIN_EDRS
    assert BUILTIN_EDRS["elastic"].detection_method == "elasticsearch"


def test_openedr_has_log_file():
    from atelier.config_models import BUILTIN_EDRS
    assert BUILTIN_EDRS["openedr"].detection_method == "log_file"


# ---------------------------------------------------------------------------
# TargetEnvironmentSpec — output_format normalization
# ---------------------------------------------------------------------------

def test_output_format_exe():
    from atelier.target_spec import TargetEnvironmentSpec
    spec = TargetEnvironmentSpec(os_platform="windows", os_version="windows-11", output_format="exe")
    assert spec.output_format == "exe"


def test_output_format_dll():
    from atelier.target_spec import TargetEnvironmentSpec
    spec = TargetEnvironmentSpec(os_platform="windows", os_version="windows-11", output_format="DLL")
    assert spec.output_format == "dll"


def test_output_format_sc_to_shellcode():
    from atelier.target_spec import TargetEnvironmentSpec
    spec = TargetEnvironmentSpec(os_platform="windows", os_version="windows-11", output_format="sc")
    assert spec.output_format == "shellcode"


def test_output_format_bin_to_shellcode():
    from atelier.target_spec import TargetEnvironmentSpec
    spec = TargetEnvironmentSpec(os_platform="windows", os_version="windows-11", output_format="bin")
    assert spec.output_format == "shellcode"


def test_output_format_invalid_defaults_exe():
    from atelier.target_spec import TargetEnvironmentSpec
    spec = TargetEnvironmentSpec(os_platform="windows", os_version="windows-11", output_format="junk")
    assert spec.output_format == "exe"


# ---------------------------------------------------------------------------
# TargetEnvironmentSpec — os_details
# ---------------------------------------------------------------------------

def test_os_details_default_empty():
    from atelier.target_spec import TargetEnvironmentSpec
    spec = TargetEnvironmentSpec(os_platform="windows", os_version="windows-11")
    assert spec.os_details == ""


def test_os_details_set():
    from atelier.target_spec import TargetEnvironmentSpec
    spec = TargetEnvironmentSpec(os_platform="windows", os_version="windows-11", os_details="25H2")
    assert spec.os_details == "25H2"


# ---------------------------------------------------------------------------
# TargetEnvironmentSpec — EDR normalization
# ---------------------------------------------------------------------------

def test_edrs_normalized_lowercase():
    from atelier.target_spec import TargetEnvironmentSpec
    spec = TargetEnvironmentSpec(os_platform="windows", os_version="windows-11", edrs=["CrowdStrike", "Sentinel One"])
    assert "crowdstrike" in spec.edrs
    assert "sentinel_one" in spec.edrs


# ---------------------------------------------------------------------------
# TargetEnvironmentSpec — C2 config
# ---------------------------------------------------------------------------

def test_c2_defaults():
    from atelier.target_spec import TargetEnvironmentSpec
    spec = TargetEnvironmentSpec(os_platform="windows", os_version="windows-11")
    assert spec.c2_address == "10.0.2.2"
    assert spec.c2_port == 9001


# ---------------------------------------------------------------------------
# spec_parser — edge cases
# ---------------------------------------------------------------------------

def test_parse_spec_from_yaml(tmp_spec_yaml):
    from atelier.spec_parser import parse_target_spec
    spec = parse_target_spec(spec_path=tmp_spec_yaml)
    assert spec.os_platform.value == "windows"
    assert spec.os_version == "windows-11"
    assert "defender" in spec.edrs


def test_parse_spec_overrides(tmp_spec_yaml):
    from atelier.spec_parser import parse_target_spec
    spec = parse_target_spec(spec_path=tmp_spec_yaml, os_version="windows-10")
    assert spec.os_version == "windows-10"


def test_parse_spec_auto_detect_platform():
    from atelier.spec_parser import parse_target_spec
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("os_version: windows-11\nmalware_type: ransomware\n")
        spec_path = f.name
    try:
        spec = parse_target_spec(spec_path=spec_path)
        assert spec.os_platform.value == "windows"
    finally:
        os.unlink(spec_path)


def test_parse_spec_json():
    from atelier.spec_parser import parse_target_spec
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({
            "os_platform": "linux",
            "os_version": "ubuntu-24.04",
            "edrs": ["wazuh"],
            "installed_compilers": ["gcc"],
            "malware_type": "backdoor",
        }, f)
        spec_path = f.name
    try:
        spec = parse_target_spec(spec_path=spec_path)
        assert spec.os_platform.value == "linux"
    finally:
        os.unlink(spec_path)


# ---------------------------------------------------------------------------
# Checkpoint — round-trip
# ---------------------------------------------------------------------------

def test_checkpoint_save_load():
    from atelier.checkpoint import CheckpointManager, CheckpointState
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = CheckpointManager(Path(tmpdir))
        state = CheckpointState(
            spec_path="/tmp/spec.yaml",
            output_dir="/tmp/results",
            created_at="2026-06-28T00:00:00",
            run_mode="run",
            llm_url="http://localhost:11235",
            llm_model="qwen",
            max_iterations=5,
            completed_iterations=2,
            iteration_history=[{"iter": 1, "status": "ok"}],
            failure_history=["compile error"],
            current_source="int main() {}",
        )
        mgr.save(state)
        loaded = mgr.load()
        assert loaded.spec_path == state.spec_path
        assert loaded.completed_iterations == 2
        assert loaded.current_source == state.current_source
        assert loaded.iteration_history == state.iteration_history


def test_checkpoint_clear():
    from atelier.checkpoint import CheckpointManager, CheckpointState
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = CheckpointManager(Path(tmpdir))
        state = CheckpointState(
            spec_path="x", output_dir="x", created_at="x", run_mode="x",
            llm_url="x", llm_model="x", max_iterations=1, completed_iterations=0,
        )
        mgr.save(state)
        assert mgr.has_checkpoint()
        mgr.clear()
        assert not mgr.has_checkpoint()


def test_checkpoint_has_none():
    from atelier.checkpoint import CheckpointManager
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = CheckpointManager(Path(tmpdir))
        assert not mgr.has_checkpoint()


# ---------------------------------------------------------------------------
# code_processor — filename/extension helpers
# ---------------------------------------------------------------------------

def test_source_extension():
    from atelier.code_processor import source_extension
    assert source_extension("c") == ".c"
    assert source_extension("rust") == ".rs"
    assert source_extension("go") == ".go"
    assert source_extension("unknown") == ".c"


def test_source_filename():
    from atelier.code_processor import source_filename
    assert source_filename("c") == "malware_source.c"
    assert source_filename("rust") == "malware_source.rs"


def test_output_filename():
    from atelier.code_processor import output_filename
    assert output_filename("exe") == "malware_source.exe"
    assert output_filename("dll") == "malware_source.dll"
    assert output_filename("shellcode") == "malware_source.bin"


# ---------------------------------------------------------------------------
# llm_client — _strip_thinking
# ---------------------------------------------------------------------------

def test_strip_thinking():
    from atelier.llm_client import _strip_thinking
    assert _strip_thinking("<think>reasoning here</think>code output") == "code output"


def test_strip_thinking_empty():
    from atelier.llm_client import _strip_thinking
    assert _strip_thinking("") == ""


def test_strip_thinking_no_tags():
    from atelier.llm_client import _strip_thinking
    assert _strip_thinking("plain text") == "plain text"


def test_strip_thinking_multiline():
    from atelier.llm_client import _strip_thinking
    text = "<think>\nline1\nline2\n</think>\nresult"
    assert _strip_thinking(text) == "result"


# ---------------------------------------------------------------------------
# llm_client — _llm_label
# ---------------------------------------------------------------------------

def test_llm_label():
    from atelier.llm_client import _llm_label
    assert _llm_label("http://localhost:11235") == "Blackwell"
    assert _llm_label("http://localhost:11234") == "Blackwell-alt"
    assert _llm_label("http://localhost:1234") == "local"
    assert "9999" in _llm_label("http://localhost:9999") or "LLM" in _llm_label("http://localhost:9999")


# ---------------------------------------------------------------------------
# loop_controller — FailureMode
# ---------------------------------------------------------------------------

def test_failure_mode_enum():
    from atelier.loop_controller import FailureMode
    assert FailureMode.DETECTED is not None
    assert FailureMode.COMPILATION_FAILED is not None
    assert FailureMode.EXECUTION_CRASHED is not None


# ---------------------------------------------------------------------------
# verifier — ValidationCheck negate field
# ---------------------------------------------------------------------------

def test_validation_check_negate():
    from atelier.verifier import ValidationCheck
    check = ValidationCheck(description="no console", command="echo test", success_pattern="error", negate=True)
    assert check.negate is True
    assert check.description == "no console"
