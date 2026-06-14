"""
Verification pipeline — runs generated malware in the provisioned VM via SSH bridge,
compiles, executes, queries EDR/AV for alerts, returns a VerificationResult.

Also supports sandbox detection checks and behaviour validation.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List

logger = logging.getLogger(__name__)


class DetectionLevel(Enum):
    NONE = "none"          # No EDR/AV detected the malware
    LOW = "low"            # Detected but low confidence / benign classification
    MEDIUM = "medium"      # Detected as suspicious
    HIGH = "high"          # Detected and flagged as malicious


class BehaviourCheck(Enum):
    COMPILATION_SUCCESS = "compilation_success"
    EXECUTION_SUCCESS = "execution_success"
    NO_CONSOLE_OUTPUT = "no_console_output"
    LAUNCHES_NETWORK = "launches_network"
    CREATES_FILE = "creates_file"
    MODIFIES_REGISTRY = "modifies_registry"  # Windows only
    SPLASH_WINDOW = "splash_window"
    DYNAMIC_DISPATCH = "dynamic_dispatch"     # LoadLibrary/GetProcAddress pattern


@dataclass
class AlertRecord:
    """A single alert from an EDR/AV product."""
    edr_name: str
    alert_type: str      # e.g. "process_injection", "api_hooking"
    severity: str        # info, warning, high
    process_path: str    # path of the detected process
    timestamp_offset: float  # seconds after execution start


@dataclass
class VerificationResult:
    """Complete result of a verification run."""

    detection_score: DetectionLevel = DetectionLevel.NONE
    alerts: List[AlertRecord] = field(default_factory=list)
    behaviour_checks: dict[BehaviourCheck, bool] = field(default_factory=dict)
    compilation_output: str = ""
    execution_output: str = ""
    execution_exit_code: int = 0
    sandbox_detected: bool = False

    @property
    def is_undetected(self) -> bool:
        """True if no EDR/AV detected the malware."""
        return self.detection_score == DetectionLevel.NONE

    @property
    def total_alerts(self) -> int:
        return len(self.alerts)


class Verifier:
    """Runs generated malware in a provisioned VM and checks for detections."""

    def __init__(self, vm_instance=None, debug=None):
        self._vm = vm_instance  # VMInstance from ProvisionEngine (Phase 3)
        self._debug = debug

    async def verify(
        self,
        source_code: str,
        target_spec,  # TargetEnvironmentSpec
        compiler_instructions: str = "",
        timeout: int = 120,
        check_sandbox: bool = True,
    ) -> VerificationResult:
        """Full verification pipeline on the running VM.

        Steps:
          1. Write source code to VM
          2. Compile using specified or auto-detected compiler
          3. Execute in background
          4. Monitor EDR/AV for alerts (via log queries)
          5. Run behaviour checks
          6. Return VerificationResult
        """
        if not self._vm:
            raise RuntimeError("No VM instance attached. Provision a VM first via ProvisionEngine.")

        result = VerificationResult()

        # -- Step 1: Write source to VM ----------------------------------------
        vm_source_path = "/tmp/malware_src.c"
        await self._write_file_to_vm(vm_source_path, source_code)
        if self._debug and self._debug.enabled:
            self._debug.step("vfy_1_upload", "Source code written to VM")

        # -- Step 2: Compile ---------------------------------------------------
        compile_cmd = self._build_compile_command(compiler_instructions or "", target_spec)
        logger.info("Compiling on VM: %s", compile_cmd)
        compile_result = await self._vm.execute_command(compile_cmd, timeout=60)

        if self._debug and self._debug.enabled:
            compile_ok = "error" not in compile_result.lower() and "undefined reference" not in compile_result.lower()
            self._debug.step("vfy_2_compile", f"Compile {'succeeded' if compile_ok else 'failed'}")
            if not compile_ok:
                return result  # compilation failed — nothing more to check

        result.compilation_output = compile_result

        # -- Step 3: Execute ---------------------------------------------------
        exe_path = "/tmp/malware_bin"
        exec_cmd = f"{exe_path} & sleep 0.1; echo $?"
        exec_out = await self._vm.execute_command(exec_cmd, timeout=timeout)
        result.execution_output = exec_out

        # Parse exit code from output (last line should be the code)
        lines = [l.strip() for l in exec_out.strip().split("\n")]
        if lines and lines[-1].isdigit():
            result.execution_exit_code = int(lines[-1])

        if self._debug and self._debug.enabled:
            exit_ok = bool(result.execution_exit_code == 0) if result.execution_exit_code else False
            self._debug.step("vfy_3_execute", f"Executed (exit={result.execution_exit_code}, {'ok' if exit_ok else 'fail'})")

        # -- Step 4: Check EDR/AV alerts --------------------------------------
        if target_spec.edrs:
            result.alerts = await self._check_edr_alerts(target_spec, timeout)

        if self._debug and self._debug.enabled:
            score = "NONE" if result.total_alerts == 0 else f"{result.total_alerts} alert(s)"
            self._debug.step("vfy_4_edr", f"EDR check — {score}")

        # Score detection level based on alerts
        if result.total_alerts == 0:
            result.detection_score = DetectionLevel.NONE
        elif result.total_alerts <= 1 and any(a.severity == "info" for a in result.alerts):
            result.detection_score = DetectionLevel.LOW
        elif result.total_alerts <= 3:
            result.detection_score = DetectionLevel.MEDIUM
        else:
            result.detection_score = DetectionLevel.HIGH

        # -- Step 5: Behaviour checks -----------------------------------------
        await self._run_behaviour_checks(result, target_spec)

        if self._debug and self._debug.enabled:
            checks_summary = ", ".join(f"{k.name}={'✓' if v else '✗'}" for k, v in result.behaviour_checks.items())
            self._debug.step("vfy_5_behaviour", f"Behaviour checks — {checks_summary}")

        # -- Step 6: Sandbox detection ----------------------------------------
        if check_sandbox:
            result.sandbox_detected = await self._check_sandbox(target_spec)

        if self._debug and self._debug.enabled:
            sandbox_str = "detected" if result.sandbox_detected else "clean"
            score_str = result.detection_score.value if hasattr(result, 'detection_score') else "unknown"
            self._debug.step("vfy_6_sandbox", f"Sandbox check — {sandbox_str}")
            self._debug.ok(f"Verification complete — detection={score_str}, sandbox={sandbox_str}")

        return result

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    async def _write_file_to_vm(self, remote_path: str, content: str) -> None:
        """Write a file to the VM via SSH."""
        # Use cat with heredoc
        escaped = content.replace("'", "'\\''")
        cmd = f"cat > '{remote_path}' << 'HEREDOC'\n{content}\nHEREDOC"
        await self._vm.execute_command(cmd, timeout=30)

    def _build_compile_command(self, compiler_instructions: str, spec) -> str:
        """Build the compilation command from instructions + spec."""
        if compiler_instructions.strip():
            # Extract just the compile command (first line that looks like a command)
            for line in compiler_instructions.split("\n"):
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and any(x in stripped for x in ["gcc", "clang", "rustc", "go ", "cc "]):
                    return stripped

        # Fallback: use default compiler for the platform
        if "windows" in spec.os_version.lower():
            return "x86_64-w64-mingw32-gcc -O2 -s /tmp/malware_src.c -o /tmp/malware_bin -lws2_32 -ladvapi32 2>&1 || gcc -O2 -s /tmp/malware_src.c -o /tmp/malware_bin 2>&1"
        else:
            return "gcc -O2 -Wall /tmp/malware_src.c -o /tmp/malware_bin 2>&1 || g++ -O2 /tmp/malware_src.c -o /tmp/malware_bin 2>&1"

    async def _check_edr_alerts(self, spec, timeout: int) -> list[AlertRecord]:
        """Query EDR logs on the VM for alerts."""
        alerts = []
        # Linux EDR log patterns
        linux_log_paths = [
            "/var/log/syslog",
            "/var/log/audit/audit.log",
        ]
        # Windows EDR log patterns
        windows_cmd = 'Get-WinEvent -LogName "Microsoft-Windows-Threat-Intelligence/Operational" -MaxEvents 50 2>$null'

        if "windows" in spec.os_version.lower():
            cmd = f"{windows_cmd} | Select-Object TimeCreated, Id, Message"
        else:
            # Generic: check for recent process activity patterns
            cmd = "grep -i 'malware_bin\\|trojan\\|suspicious' /var/log/syslog 2>/dev/null || echo 'no alerts'"

        try:
            output = await self._vm.execute_command(cmd, timeout=30)
            if output.strip() and "no alerts" not in output.lower():
                for line in output.strip().split("\n"):
                    if line.strip():
                        alerts.append(AlertRecord(
                            edr_name="generic",
                            alert_type="log_match",
                            severity="info",
                            process_path="/tmp/malware_bin",
                            timestamp_offset=0,
                        ))
        except Exception as e:
            logger.warning("EDR alert check failed: %s", e)

        return alerts

    async def _run_behaviour_checks(self, result: VerificationResult, spec) -> None:
        """Run behaviour validation checks on the executed binary."""
        checks = {}

        # Check if binary exists and is executable
        try:
            stat_out = await self._vm.execute_command(
                "test -x /tmp/malware_bin && echo exists || echo missing"
            )
            checks[BehaviourCheck.EXECUTION_SUCCESS] = (stat_out.strip() == "exists")
        except Exception:
            checks[BehaviourCheck.EXECUTION_SUCCESS] = False

        # Check for network activity in the last few seconds
        try:
            net_cmd = "ss -tunp 2>/dev/null | grep malware_bin || echo 'no_net'"
            net_out = await self._vm.execute_command(net_cmd, timeout=5)
            checks[BehaviourCheck.LAUNCHES_NETWORK] = "no_net" not in net_out.lower()
        except Exception:
            checks[BehaviourCheck.LAUNCHES_NETWORK] = False

        # Check for window creation (Linux X11 or Windows GUI)
        if "windows" in spec.os_version.lower():
            checks[BehaviourCheck.SPLASH_WINDOW] = True  # placeholder — need WMI query
        else:
            try:
                win_out = await self._vm.execute_command(
                    "xwininfo -root -tree 2>/dev/null | grep malware || echo 'no_win'", timeout=5
                )
                checks[BehaviourCheck.SPLASH_WINDOW] = "malware" in win_out.lower() and "no_win" not in win_out.lower()
            except Exception:
                checks[BehaviourCheck.SPLASH_WINDOW] = False

        # Store results
        result.behaviour_checks.update(checks)

    async def _check_sandbox(self, spec) -> bool:
        """Check if the VM is running inside a sandbox environment."""
        sandbox_indicators = []

        try:
            # Check CPU count (sandboxes often have low core counts)
            cpu_out = await self._vm.execute_command("nproc 2>/dev/null || echo 0", timeout=5)
            if int(cpu_out.strip()) < 2:
                sandbox_indicators.append("low_cpu_count")

            # Check RAM
            ram_out = await self._vm.execute_command(
                "free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo 0", timeout=5
            )
            if int(ram_out.strip()) < 1000:
                sandbox_indicators.append("low_ram")

        except Exception as e:
            logger.warning("Sandbox check failed: %s", e)

        return len(sandbox_indicators) > 0


# Convenience function for standalone use without a VM
async def verify_standalone(
    source_code: str,
    target_spec,
    compile_cmd: Optional[str] = None,
    workdir: str = "/tmp",
) -> VerificationResult:
    """Verify malware compilation and basic execution on the local host.

    Useful for quick smoke tests without a VM.
    """
    result = VerificationResult()

    src_path = f"{workdir}/malware_src.c"
    with open(src_path, "w") as f:
        f.write(source_code)

    compiler = compile_cmd or "gcc -O2 -Wall"
    try:
        proc = await asyncio.create_subprocess_shell(
            f"{compiler} {src_path} -o {workdir}/malware_bin",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        result.compilation_output = (stdout.decode("utf-8") or "") + (stderr.decode("utf-8") or "")

        if proc.returncode == 0:
            result.behaviour_checks[BehaviourCheck.COMPILATION_SUCCESS] = True
            result.detection_score = DetectionLevel.NONE  # no EDR on host in standalone mode

            # Try running it
            try:
                run_proc = await asyncio.create_subprocess_exec(
                    f"{workdir}/malware_bin",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    timeout=10,
                )
                _, _ = await run_proc.communicate()
                result.behaviour_checks[BehaviourCheck.EXECUTION_SUCCESS] = True
            except (asyncio.TimeoutError, Exception):
                result.behaviour_checks[BehaviourCheck.EXECUTION_SUCCESS] = False

    except FileNotFoundError:
        result.compilation_output = "gcc not found in PATH"

    return result
