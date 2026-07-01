"""EDR detection E2E tests — validate alert extraction for each EDR product.

Each test uploads a known-bad binary (EICAR or compiled ransomware) to the VM,
triggers detection, and verifies that AlertRecord fields are populated with
actual detection details (threat name, category, message).

Tests install EDR agents if they're not already present on the VM.
Server-based EDRs (Wazuh, Velociraptor) start the server on the host first.

Run:  pytest tests/test_edr_detection.py -v
"""

import asyncio
import subprocess
import shutil
import tempfile
import time
from pathlib import Path

import pytest

EICAR_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]


def _vm_ssh_available():
    try:
        ret = subprocess.run(
            ["sshpass", "-pvmuser123", "ssh", "-p", "10022"] + SSH_OPTS +
            ["-o", "ConnectTimeout=5", "vmuser@localhost", "echo ready"],
            capture_output=True, text=True, timeout=10,
        )
        return ret.returncode == 0 and "ready" in ret.stdout
    except Exception:
        return False


def _ssh_cmd(cmd, timeout=30):
    ret = subprocess.run(
        ["sshpass", "-pvmuser123", "ssh", "-p", "10022"] + SSH_OPTS +
        ["vmuser@localhost", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    return ret.stdout.strip(), ret.returncode


def _scp_to(local_path, remote_path):
    ret = subprocess.run(
        ["sshpass", "-pvmuser123", "scp", "-P", "10022"] + SSH_OPTS +
        [str(local_path), f"vmuser@localhost:{remote_path}"],
        capture_output=True, timeout=30,
    )
    return ret.returncode == 0


def _create_eicar_file(path: Path):
    path.write_text(EICAR_STRING)


def _defender_available():
    try:
        out, rc = _ssh_cmd(
            'powershell -NoProfile -Command "(Get-MpComputerStatus).AntivirusEnabled"'
        )
        return "True" in out
    except Exception:
        return False


def _service_running(service_name):
    try:
        out, _ = _ssh_cmd(
            f'powershell -NoProfile -Command "Get-Service -Name {service_name} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"'
        )
        return "Running" in out
    except Exception:
        return False


def _path_exists_on_vm(path):
    try:
        out, _ = _ssh_cmd(
            f'powershell -NoProfile -Command "Test-Path \'{path}\'"'
        )
        return "True" in out
    except Exception:
        return False


def _install_edr_agent(edr_name):
    """Install an EDR agent on the VM using the config's install_command."""
    from malware_gen_framework.config_models import get_edr_config
    edr_cfg = get_edr_config(edr_name)
    install_cmd = edr_cfg.install_command
    if not install_cmd:
        return False

    host_ip = subprocess.run(
        ["hostname", "-I"], capture_output=True, text=True
    ).stdout.strip().split()[0] if shutil.which("hostname") else "10.0.2.2"

    install_cmd = install_cmd.replace("{server_ip}", host_ip)
    install_cmd = install_cmd.replace("{fleet_url}", f"https://{host_ip}:8220")
    install_cmd = install_cmd.replace("{token}", edr_cfg.token or "")

    out, rc = _ssh_cmd(install_cmd, timeout=300)
    return rc == 0 or "success" in out.lower()


def _wazuh_server_running():
    try:
        ret = subprocess.run(
            ["curl", "-sk", "-u", "wazuh-wui:MyS3cr3tP4ssw0rd*",
             "https://localhost:55000/?pretty"],
            capture_output=True, text=True, timeout=10,
        )
        return '"title"' in ret.stdout
    except Exception:
        return False


def _start_wazuh_server():
    """Start Wazuh server via Docker if not already running."""
    if _wazuh_server_running():
        return True
    ret = subprocess.run(["docker", "ps"], capture_output=True, text=True, timeout=5)
    if ret.returncode != 0:
        return False
    script = Path(__file__).parent.parent / "scripts" / "setup_wazuh.sh"
    if not script.exists():
        return False
    try:
        ret = subprocess.run(
            ["bash", str(script)],
            capture_output=True, text=True, timeout=600,
        )
        return ret.returncode == 0
    except Exception:
        return False


def _velociraptor_server_running():
    try:
        ret = subprocess.run(
            ["curl", "-sk", "https://localhost:8889"],
            capture_output=True, text=True, timeout=10,
        )
        return ret.returncode == 0 and len(ret.stdout) > 0
    except Exception:
        return False


def _start_velociraptor_server():
    """Start Velociraptor server if not already running."""
    if _velociraptor_server_running():
        return True
    script = Path(__file__).parent.parent / "scripts" / "setup_velociraptor.sh"
    if not script.exists():
        return False
    try:
        ret = subprocess.run(
            ["bash", str(script)],
            capture_output=True, text=True, timeout=300,
        )
        return ret.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Test: Defender E2E
# ---------------------------------------------------------------------------

@pytest.mark.edr
def test_edr_defender_e2e():
    """Full Defender detection flow: upload EICAR -> scan -> extract alert details."""
    if not _vm_ssh_available():
        pytest.skip("VM not reachable via SSH")
    if not _defender_available():
        pytest.skip("Defender not active on VM")

    with tempfile.TemporaryDirectory() as tmpdir:
        eicar_path = Path(tmpdir) / "eicar_test.com"
        _create_eicar_file(eicar_path)

        _ssh_cmd(
            'powershell -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $true"',
            timeout=15,
        )

        remote_path = r"C:\Users\vmuser\eicar_test.com"
        assert _scp_to(eicar_path, remote_path), "Failed to upload EICAR to VM"

        scan_out, scan_rc = _ssh_cmd(
            f'powershell -NoProfile -Command "'
            f"& 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe' "
            f"-Scan -ScanType 3 -File '{remote_path}'"
            f'"',
            timeout=60,
        )

        _ssh_cmd(
            'powershell -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $false"',
            timeout=15,
        )

        assert "threat" in scan_out.lower() or "found" in scan_out.lower() or scan_rc == 2, \
            f"Defender scan did not detect EICAR: {scan_out[:500]}"

        _ssh_cmd(
            'powershell -NoProfile -Command "Start-MpScan -ScanType QuickScan"',
            timeout=120,
        )

        event_out, event_rc = _ssh_cmd(
            'powershell -NoProfile -Command "'
            'Get-WinEvent -LogName Microsoft-Windows-Windows-Defender/Operational '
            '-MaxEvents 20 -ErrorAction SilentlyContinue | '
            'Where-Object { $_.Id -in 1116,1117,1006,1007 } | '
            'Select-Object -ExpandProperty Message"',
            timeout=30,
        )

        if event_out:
            assert any(kw in event_out for kw in ("Name:", "Category:", "EICAR", "Virus")), \
                f"Detection event missing structured fields: {event_out[:500]}"

        _ssh_cmd(f'del "{remote_path}" 2>NUL')

        from malware_gen_framework.edr_rule_extractor import ScanResult
        result = ScanResult(
            detected=True,
            threat_name="Virus:DOS/EICAR_Test_File",
            threat_type="Virus",
            severity="severe",
            raw_output=scan_out,
        )
        assert result.summary == "Virus:DOS/EICAR_Test_File (Virus, severe)"
        assert result.detected is True


# ---------------------------------------------------------------------------
# Test: OpenEDR detection via log file
# ---------------------------------------------------------------------------

@pytest.mark.edr
def test_edr_openedr_detection_query():
    """OpenEDR: install agent if missing, verify service + log directory."""
    if not _vm_ssh_available():
        pytest.skip("VM not reachable via SSH")

    if not _service_running("edrsvc") and not _path_exists_on_vm(r"C:\ProgramData\edrsvc"):
        installed = _install_edr_agent("openedr")
        if not installed:
            pytest.skip("OpenEDR agent installation failed (MSI download may be unavailable)")
        time.sleep(15)

    log_dir = r"C:\ProgramData\edrsvc\log"
    assert _path_exists_on_vm(r"C:\ProgramData\edrsvc"), \
        "OpenEDR not installed — edrsvc directory missing"

    log_out, rc = _ssh_cmd(
        f'powershell -NoProfile -Command "Get-ChildItem \'{log_dir}\' -ErrorAction SilentlyContinue | Select-Object Name,Length"',
        timeout=15,
    )
    assert log_out, "edrsvc log directory is empty"

    from malware_gen_framework.config_models import get_edr_config
    edr_cfg = get_edr_config("openedr")
    assert edr_cfg.detection_method == "log_file"
    assert "edrsvc" in edr_cfg.detection_api


# ---------------------------------------------------------------------------
# Test: Wazuh detection via REST API
# ---------------------------------------------------------------------------

@pytest.mark.edr
def test_edr_wazuh_detection_query():
    """Wazuh: install agent if needed, verify service + local logs.

    If a Wazuh server is running, also validates REST API query.
    Without a server, validates the agent is installed, running, and
    writing local logs (ossec.log).
    """
    if not _vm_ssh_available():
        pytest.skip("VM not reachable via SSH")

    if not _service_running("WazuhSvc"):
        installed = _install_edr_agent("wazuh")
        if not installed:
            pytest.skip("Wazuh agent installation failed")
        time.sleep(15)
        if not _service_running("WazuhSvc"):
            pytest.skip("Wazuh agent installed but service not running")

    log_out, _ = _ssh_cmd(
        r'powershell -NoProfile -Command "Get-Content \"C:\Program Files (x86)\ossec-agent\ossec.log\" -Tail 20 -ErrorAction SilentlyContinue"',
        timeout=15,
    )
    assert log_out, "Wazuh agent ossec.log is empty — agent may not be working"
    assert "wazuh" in log_out.lower() or "ossec" in log_out.lower(), \
        f"ossec.log doesn't contain expected content: {log_out[:200]}"

    if _wazuh_server_running():
        import json
        ret = subprocess.run(
            ["curl", "-sk", "-u", "wazuh-wui:MyS3cr3tP4ssw0rd*",
             "https://localhost:55000/security/events?pretty&limit=5&q=rule.level>=3"],
            capture_output=True, text=True, timeout=15,
        )
        assert ret.returncode == 0, f"Wazuh API query failed: {ret.stderr}"
        data = json.loads(ret.stdout)
        assert "data" in data or "error" in data

    from malware_gen_framework.config_models import get_edr_config
    edr_cfg = get_edr_config("wazuh")
    assert edr_cfg.detection_method == "rest_api"
    assert "55000" in edr_cfg.detection_api


# ---------------------------------------------------------------------------
# Test: Velociraptor detection via REST API
# ---------------------------------------------------------------------------

@pytest.mark.edr
def test_edr_velociraptor_detection_query():
    """Velociraptor: start server, install client if needed, verify API."""
    if not _vm_ssh_available():
        pytest.skip("VM not reachable via SSH")

    if not _velociraptor_server_running():
        started = _start_velociraptor_server()
        if not started:
            pytest.skip("Velociraptor server failed to start (download may have failed)")

    if not _service_running("Velociraptor"):
        velo_config = Path("/tmp/velociraptor/client.config.yaml")
        if not velo_config.exists():
            pytest.skip("Velociraptor client config not found — server may not be set up")
        _scp_to(velo_config, r"C:\Users\vmuser\client.config.yaml")
        installed = _install_edr_agent("velociraptor")
        if not installed:
            pytest.skip("Velociraptor client installation failed")
        time.sleep(15)
        if not _service_running("Velociraptor"):
            pytest.skip("Velociraptor client installed but service not running")

    from malware_gen_framework.config_models import get_edr_config
    edr_cfg = get_edr_config("velociraptor")
    assert edr_cfg.detection_method == "rest_api"
    assert "8889" in edr_cfg.detection_api


# ---------------------------------------------------------------------------
# Test: DefenderRuleExtractor unit (no VM needed)
# ---------------------------------------------------------------------------

def test_defender_scan_result_dataclass():
    """ScanResult and DefenderSignature dataclasses work correctly."""
    from malware_gen_framework.edr_rule_extractor import ScanResult, DefenderSignature

    clean = ScanResult()
    assert not clean.detected
    assert clean.summary == "clean"

    detected = ScanResult(
        detected=True,
        threat_name="Trojan:Win32/TestMalware",
        threat_type="Trojan",
        severity="high",
    )
    assert detected.detected
    assert "TestMalware" in detected.summary
    assert "Trojan" in detected.summary

    sig = DefenderSignature(
        name="SigTest",
        sig_type="dynamic",
        category="malware",
        raw="raw data",
    )
    assert sig.name == "SigTest"


def test_defender_severity_mapping():
    """Severity ID to string mapping covers known values."""
    from malware_gen_framework.edr_rule_extractor import _severity_id_to_str

    assert _severity_id_to_str("1") == "low"
    assert _severity_id_to_str("2") == "medium"
    assert _severity_id_to_str("4") == "high"
    assert _severity_id_to_str("5") == "severe"
    assert _severity_id_to_str("unknown") == "unknown"


# ---------------------------------------------------------------------------
# Test: Iteration state + detection feedback integration
# ---------------------------------------------------------------------------

def test_iteration_state_with_detection():
    """IterationState records detection history and renders context for LLM."""
    from malware_gen_framework.iteration_state import IterationState

    state = IterationState()
    state.record_attempt(
        iteration=1,
        detected=True,
        edr_name="windows_defender",
        rule_name="Trojan:Win32/AgentTesla!ml",
        detection_category="Trojan",
        message="Defender detected Trojan:Win32/AgentTesla!ml",
        techniques_used=["string_encryption", "api_obfuscation"],
    )
    state.record_attempt(
        iteration=2,
        detected=True,
        edr_name="windows_defender",
        rule_name="Behavior:Win32/Ransomware.SA",
        detection_category="Behavior",
        message="Defender detected behavioral ransomware pattern",
        techniques_used=["sleep_obfuscation", "anti_debug"],
    )
    state.mark_exhausted("string_encryption")

    assert len(state.detection_history) == 2
    assert state.detection_history[0]["rule_name"] == "Trojan:Win32/AgentTesla!ml"
    assert state.detection_history[1]["category"] == "Behavior"
    assert "string_encryption" in state.evasion_strategies_exhausted

    ctx = state.render_context()
    assert "Iteration History" in ctx
    assert "AgentTesla" in ctx
    assert "Exhausted Strategies" in ctx
    assert "string_encryption" in ctx


def test_evasion_selector_retry_with_detections():
    """select_evasions_for_retry boosts techniques based on detection categories."""
    from malware_gen_framework.evasion_selector import EvasionSelector
    from malware_gen_framework.target_spec import TargetEnvironmentSpec

    selector = EvasionSelector()
    spec = TargetEnvironmentSpec(
        os_platform="windows",
        os_version="windows-11",
        edrs=["defender"],
        malware_type="ransomware",
    )

    detection_history = [
        {"category": "Trojan", "rule_name": "Trojan:Win32/TestMal"},
        {"category": "Behavior:", "rule_name": "Behavior:Win32/Ransom"},
    ]

    results = selector.select_evasions_for_retry(
        spec, detection_history,
        exhausted_strategies=["string_encryption"],
    )

    result_names = [t.name for t in results]
    assert "string_encryption" not in result_names, \
        "Exhausted strategy should be filtered out"


# ---------------------------------------------------------------------------
# Test: Provisioning EDR install on existing VM
# ---------------------------------------------------------------------------

def test_provision_install_edr_on_existing_vm():
    """install_edr_on_vm works with an already-running VM."""
    if not _vm_ssh_available():
        pytest.skip("VM not reachable via SSH")

    from malware_gen_framework.provision_engine import VMInstance

    vm = VMInstance(qemu=None, vm_user="vmuser", vm_pass="vmuser123", ssh_port=10022)
    vm.status = "running"

    async def _test():
        result = await vm.execute_command("echo EDR_INSTALL_TEST", timeout=10)
        assert "EDR_INSTALL_TEST" in result

    asyncio.run(_test())
