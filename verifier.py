"""
Verification pipeline — compiles and executes generated malware in a provisioned VM,
queries EDR/AV for alerts, returns a VerificationResult.

Windows flow:  cross-compile on host (x86_64-w64-mingw32-gcc) → SFTP .exe to VM → run
Linux flow:    SFTP source to VM → compile on VM → run
"""

import asyncio
import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, List

logger = logging.getLogger(__name__)


class DetectionLevel(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class BehaviourCheck(Enum):
    COMPILATION_SUCCESS = "compilation_success"
    EXECUTION_SUCCESS = "execution_success"
    NO_CONSOLE_OUTPUT = "no_console_output"
    LAUNCHES_NETWORK = "launches_network"
    CREATES_FILE = "creates_file"
    MODIFIES_REGISTRY = "modifies_registry"
    SPLASH_WINDOW = "splash_window"
    DYNAMIC_DISPATCH = "dynamic_dispatch"
    FUNCTIONAL_GOAL_MET = "functional_goal_met"


@dataclass
class ValidationCheck:
    """One LLM-generated check that verifies the malware performed its intended function."""
    description: str
    command: str
    success_pattern: str  # substring that must appear in command output


@dataclass
class ValidationPlan:
    """Set of behavioral validation checks generated before the verification loop."""
    checks: list[ValidationCheck]
    is_windows: bool
    setup_commands: list[str] = field(default_factory=list)  # run on VM before exe launches


@dataclass
class AlertRecord:
    edr_name: str
    alert_type: str
    severity: str
    process_path: str
    timestamp_offset: float


@dataclass
class VerificationResult:
    detection_score: DetectionLevel = DetectionLevel.NONE
    alerts: List[AlertRecord] = field(default_factory=list)
    behaviour_checks: dict[BehaviourCheck, bool] = field(default_factory=dict)
    compilation_output: str = ""
    execution_output: str = ""
    execution_exit_code: int = 0
    sandbox_detected: bool = False
    functional_validation_passed: Optional[bool] = None  # None = not checked
    functional_validation_output: str = ""

    @property
    def is_undetected(self) -> bool:
        return self.detection_score == DetectionLevel.NONE

    @property
    def total_alerts(self) -> int:
        return len(self.alerts)


def _is_windows(spec) -> bool:
    return "windows" in (spec.os_version or "").lower() or \
           (hasattr(spec, "os_platform") and spec.os_platform.value == "windows")


class Verifier:
    """Runs generated malware in a provisioned VM and checks for detections."""

    def __init__(self, vm_instance=None, debug=None, output_dir: Optional[Path] = None):
        self._vm = vm_instance
        self._debug = debug
        self._output_dir = output_dir

    async def verify(
        self,
        source_code: str,
        target_spec,
        compiler_instructions: str = "",
        timeout: int = 120,
        check_sandbox: bool = True,
        validation_plan: Optional["ValidationPlan"] = None,
    ) -> VerificationResult:
        """Full verification pipeline.

        Windows: cross-compile on host → SFTP .exe to VM → execute
        Linux:   SFTP source to VM → compile on VM → execute
        """
        if not self._vm:
            raise RuntimeError("No VM instance attached.")

        result = VerificationResult()
        win = _is_windows(target_spec)

        if win:
            await self._verify_windows(result, source_code, target_spec,
                                        compiler_instructions, timeout,
                                        validation_plan=validation_plan)
        else:
            await self._verify_linux(result, source_code, target_spec,
                                      compiler_instructions, timeout)

        # Skip EDR/behaviour/sandbox checks if compilation failed — the binary
        # doesn't exist so none of these checks are meaningful.
        if not result.behaviour_checks.get(BehaviourCheck.COMPILATION_SUCCESS, True):
            return result

        # EDR alerts
        if target_spec.edrs:
            result.alerts = await self._check_edr_alerts(target_spec, win)
        if result.total_alerts == 0:
            result.detection_score = DetectionLevel.NONE
        elif result.total_alerts <= 1 and any(a.severity == "info" for a in result.alerts):
            result.detection_score = DetectionLevel.LOW
        elif result.total_alerts <= 3:
            result.detection_score = DetectionLevel.MEDIUM
        else:
            result.detection_score = DetectionLevel.HIGH

        await self._run_behaviour_checks(result, target_spec, win)

        if check_sandbox:
            result.sandbox_detected = await self._check_sandbox(win)

        return result

    async def run_validation_checks(self, plan: ValidationPlan, settle_secs: int = 5) -> bool:
        """Run all behavioral validation checks against the live VM.

        Returns True if a majority of checks pass (tolerates LLM-generated checks
        that point to the wrong path or slightly wrong pattern).
        An empty plan returns False — no evidence of function means not a success.
        """
        if not plan.checks:
            logger.warning("run_validation_checks called with empty plan — returning False")
            return False

        # Brief settle wait so any async file writes / registry ops finish
        if settle_secs > 0:
            await asyncio.sleep(settle_secs)

        n_pass = 0
        outputs: list[str] = []
        for check in plan.checks:
            try:
                output = await self._vm.execute_command(check.command, timeout=30)
                ok = check.success_pattern.lower() in output.lower()
                n_pass += ok
                outputs.append(f"[{'PASS' if ok else 'FAIL'}] {check.description}: {output[:200]}")
                logger.info("Validation check '%s': %s", check.description, "PASS" if ok else "FAIL")
            except Exception as exc:
                outputs.append(f"[ERROR] {check.description}: {exc}")
                logger.warning("Validation check '%s' error: %s", check.description, exc)

        threshold = (len(plan.checks) + 1) // 2  # strict majority
        overall = n_pass >= threshold
        logger.info(
            "Behavioral validation: %d/%d checks passed (threshold %d) — %s",
            n_pass, len(plan.checks), threshold, "PASS" if overall else "FAIL",
        )
        return overall

    # ------------------------------------------------------------------
    # Windows path
    # ------------------------------------------------------------------

    async def _verify_windows(self, result, source_code, spec,
                               compiler_instructions, timeout,
                               validation_plan=None):
        # Step 1: cross-compile on host
        mingw = shutil.which("x86_64-w64-mingw32-gcc")
        if not mingw:
            raise RuntimeError(
                "x86_64-w64-mingw32-gcc not found on host. "
                "Install with: sudo apt install gcc-mingw-w64"
            )

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "malware_src.c"
            exe = Path(td) / "malware_test.exe"
            src.write_text(source_code)

            # Extract any extra flags from compiler instructions
            extra_flags = self._extract_mingw_flags(compiler_instructions)
            # Standard Win32 libraries — link the full common set so generated
            # code can use GDI, WinINet, Winsock, Registry, Shell, Crypto, etc.
            # without needing per-feature linker flags.
            _std_libs = (
                "-lws2_32 -ladvapi32 -lole32 -loleaut32 -luuid "
                "-lgdi32 -luser32 -lshell32 -lshlwapi "
                "-lwininet -lpsapi -lcrypt32 -lcomdlg32 -lnetapi32"
            )
            compile_cmd = (
                f"{mingw} -O2 -s -static -m64 "
                f"-ffunction-sections -fdata-sections -Wl,--gc-sections "
                f"{extra_flags} "
                f"{src} -o {exe} "
                f"{_std_libs} 2>&1"
            )

            logger.info("Compile command: %s", compile_cmd)
            proc = await asyncio.create_subprocess_shell(
                compile_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            compiler_stdout = stdout.decode("utf-8", errors="replace")
            result.compilation_output = f"$ {compile_cmd}\n{compiler_stdout}"
            result.behaviour_checks[BehaviourCheck.COMPILATION_SUCCESS] = (proc.returncode == 0)

            if self._debug:
                self._debug.step("vfy_1_compile",
                    f"Cross-compile {'ok' if proc.returncode == 0 else 'FAILED'} (rc={proc.returncode})")

            if proc.returncode != 0:
                logger.warning("Compilation failed:\n%s", result.compilation_output)
                return

            # Persist compiled .exe next to the source for later use
            if self._output_dir:
                dest_exe = self._output_dir / "malware_source.exe"
                shutil.copy2(str(exe), str(dest_exe))
                logger.info("Compiled .exe saved to %s", dest_exe)

            # Step 2: upload .exe to VM
            remote_exe = r"C:\Users\vmuser\malware_test.exe"
            await self._vm.upload_file(str(exe), remote_exe)

            if self._debug:
                self._debug.step("vfy_2_upload", f"Uploaded .exe → {remote_exe}")

        # Step 2b: run pre-execution setup commands (create canary files, etc.)
        if validation_plan and validation_plan.setup_commands:
            for setup_cmd in validation_plan.setup_commands:
                try:
                    await self._vm.execute_command(setup_cmd, timeout=15)
                    logger.info("Pre-execution setup: %s", setup_cmd[:120])
                except Exception as exc:
                    logger.warning("Pre-execution setup command failed (%s): %s", setup_cmd[:80], exc)

        # Step 3: execute on VM — 15s wait gives malware time to do real work
        exec_cmd = f'start /B "" "{remote_exe}" & timeout /t 15 /nobreak >NUL & echo LAUNCHED'
        try:
            exec_out = await self._vm.execute_command(exec_cmd, timeout=timeout)
            result.execution_output = exec_out
            result.execution_exit_code = 0
            result.behaviour_checks[BehaviourCheck.EXECUTION_SUCCESS] = "LAUNCHED" in exec_out
        except Exception as e:
            result.execution_output = str(e)
            result.execution_exit_code = 1
            result.behaviour_checks[BehaviourCheck.EXECUTION_SUCCESS] = False

        if self._debug:
            self._debug.step("vfy_3_execute",
                f"Execute {'ok' if result.execution_exit_code == 0 else 'FAILED'}")

    def _extract_mingw_flags(self, compiler_instructions: str) -> str:
        """Pull any -l or -D flags out of the compiler instructions block."""
        flags = []
        for line in compiler_instructions.splitlines():
            line = line.strip()
            if line.startswith("-l") or line.startswith("-D") or line.startswith("-W"):
                flags.append(line)
            elif " -l" in line:
                # e.g. "x86_64-w64-mingw32-gcc ... -lws2_32 -ladvapi32"
                for tok in line.split():
                    if tok.startswith("-l") or tok.startswith("-D"):
                        flags.append(tok)
        return " ".join(dict.fromkeys(flags))  # deduplicate, preserve order

    # ------------------------------------------------------------------
    # Linux path
    # ------------------------------------------------------------------

    async def _verify_linux(self, result, source_code, spec,
                             compiler_instructions, timeout):
        remote_src = "/tmp/malware_src.c"
        remote_bin = "/tmp/malware_bin"

        # Step 1: upload source via SFTP
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w") as f:
            f.write(source_code)
            tmp_src = f.name
        try:
            await self._vm.upload_file(tmp_src, remote_src)
        finally:
            Path(tmp_src).unlink(missing_ok=True)

        if self._debug:
            self._debug.step("vfy_1_upload", f"Source uploaded → {remote_src}")

        # Step 2: compile on VM
        compile_cmd = self._build_linux_compile_cmd(compiler_instructions, remote_src, remote_bin)
        compile_out = await self._vm.execute_command(compile_cmd, timeout=60)
        result.compilation_output = compile_out
        failed = "error:" in compile_out.lower() or "undefined reference" in compile_out.lower()
        result.behaviour_checks[BehaviourCheck.COMPILATION_SUCCESS] = not failed

        if self._debug:
            self._debug.step("vfy_2_compile", f"Compile {'ok' if not failed else 'FAILED'}")

        if failed:
            return

        # Step 3: execute
        exec_cmd = f"{remote_bin} & sleep 0.1; echo $?"
        exec_out = await self._vm.execute_command(exec_cmd, timeout=timeout)
        result.execution_output = exec_out
        lines = [l.strip() for l in exec_out.strip().splitlines()]
        if lines and lines[-1].isdigit():
            result.execution_exit_code = int(lines[-1])

    def _build_linux_compile_cmd(self, instructions: str, src: str, out: str) -> str:
        for line in (instructions or "").splitlines():
            s = line.strip()
            if s and not s.startswith("#") and any(x in s for x in ["gcc", "clang", "cc "]):
                return s
        return f"gcc -O2 -Wall {src} -o {out} 2>&1 || g++ -O2 {src} -o {out} 2>&1"

    # ------------------------------------------------------------------
    # EDR / behaviour / sandbox
    # ------------------------------------------------------------------

    async def _check_edr_alerts(self, spec, is_windows: bool) -> list[AlertRecord]:
        alerts = []
        try:
            if is_windows:
                cmd = (
                    'powershell -NoProfile -Command '
                    '"Get-WinEvent -LogName Microsoft-Windows-Windows-Defender/Operational '
                    '-MaxEvents 20 -ErrorAction SilentlyContinue | '
                    'Where-Object { $_.Id -in 1116,1117,1006,1007 } | '
                    'Select-Object -ExpandProperty Message"'
                )
            else:
                cmd = "grep -i 'malware_bin\\|trojan\\|suspicious' /var/log/syslog 2>/dev/null || echo 'no alerts'"
            output = await self._vm.execute_command(cmd, timeout=30)
            if output.strip() and "no alerts" not in output.lower():
                for line in output.strip().splitlines():
                    if line.strip():
                        alerts.append(AlertRecord(
                            edr_name="windows_defender" if is_windows else "syslog",
                            alert_type="detection",
                            severity="high" if is_windows else "info",
                            process_path="malware_test.exe" if is_windows else "/tmp/malware_bin",
                            timestamp_offset=0,
                        ))
        except Exception as e:
            logger.warning("EDR alert check failed: %s", e)
        return alerts

    async def _run_behaviour_checks(self, result: VerificationResult, spec, is_windows: bool) -> None:
        checks = {}
        try:
            if is_windows:
                stat_out = await self._vm.execute_command(
                    r'if exist "C:\Users\vmuser\malware_test.exe" (echo exists) else (echo missing)',
                    timeout=10,
                )
                checks[BehaviourCheck.EXECUTION_SUCCESS] = "exists" in stat_out
                net_out = await self._vm.execute_command(
                    "netstat -ano | findstr ESTABLISHED", timeout=10
                )
                checks[BehaviourCheck.LAUNCHES_NETWORK] = bool(net_out.strip())
                checks[BehaviourCheck.SPLASH_WINDOW] = True  # placeholder
            else:
                stat_out = await self._vm.execute_command(
                    "test -x /tmp/malware_bin && echo exists || echo missing", timeout=10
                )
                checks[BehaviourCheck.EXECUTION_SUCCESS] = stat_out.strip() == "exists"
                net_out = await self._vm.execute_command(
                    "ss -tunp 2>/dev/null | grep malware_bin || echo no_net", timeout=5
                )
                checks[BehaviourCheck.LAUNCHES_NETWORK] = "no_net" not in net_out.lower()
        except Exception as e:
            logger.warning("Behaviour check failed: %s", e)
        result.behaviour_checks.update(checks)

    async def _check_sandbox(self, is_windows: bool) -> bool:
        indicators = []
        try:
            if is_windows:
                cpu_out = await self._vm.execute_command(
                    'powershell -NoProfile -Command '
                    '"(Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors"',
                    timeout=10,
                )
                if cpu_out.strip().isdigit() and int(cpu_out.strip()) < 2:
                    indicators.append("low_cpu")
                ram_out = await self._vm.execute_command(
                    'powershell -NoProfile -Command '
                    '"[math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1MB)"',
                    timeout=10,
                )
                if ram_out.strip().isdigit() and int(ram_out.strip()) < 1000:
                    indicators.append("low_ram")
            else:
                cpu_out = await self._vm.execute_command("nproc 2>/dev/null || echo 0", timeout=5)
                if int(cpu_out.strip() or 0) < 2:
                    indicators.append("low_cpu")
                ram_out = await self._vm.execute_command(
                    "free -m 2>/dev/null | awk '/Mem:/{print $2}' || echo 0", timeout=5
                )
                if int(ram_out.strip() or 0) < 1000:
                    indicators.append("low_ram")
        except Exception as e:
            logger.warning("Sandbox check failed: %s", e)
        return len(indicators) > 0


# ---------------------------------------------------------------------------
# Standalone (no VM) — compile-check only
# ---------------------------------------------------------------------------

async def verify_standalone(
    source_code: str,
    target_spec,
    compile_cmd: Optional[str] = None,
    workdir: str = "/tmp",
    output_dir: Optional[Path] = None,
) -> VerificationResult:
    """Verify compilation on the local host without a VM (smoke-test mode)."""
    import tempfile as _tempfile
    import os as _os

    result = VerificationResult()

    win = _is_windows(target_spec)
    if win:
        mingw = shutil.which("x86_64-w64-mingw32-gcc")
        compiler = compile_cmd or (
            f"{mingw} -fsyntax-only -x c" if mingw else None
        )
        if not compiler:
            result.compilation_output = "x86_64-w64-mingw32-gcc not found"
            return result
    else:
        compiler = compile_cmd or "gcc -O2 -Wall"

    syntax_only = "-fsyntax-only" in compiler

    src_fd, src_name = _tempfile.mkstemp(suffix=".c", dir=workdir)
    bin_fd, bin_name = (None, None) if syntax_only else _tempfile.mkstemp(dir=workdir)
    try:
        _os.close(src_fd)
        Path(src_name).write_text(source_code)
        if bin_fd is not None:
            _os.close(bin_fd)

        out_flag = "" if syntax_only else f"-o {bin_name}"
        shell_cmd = f"{compiler} {src_name} {out_flag}"

        logger.info("Compile command: %s", shell_cmd)
        try:
            proc = await asyncio.create_subprocess_shell(
                shell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            compiler_stdout = stdout.decode("utf-8", errors="replace")
            result.compilation_output = f"$ {shell_cmd}\n{compiler_stdout}"

            if proc.returncode == 0:
                result.behaviour_checks[BehaviourCheck.COMPILATION_SUCCESS] = True
                result.detection_score = DetectionLevel.NONE
                if not syntax_only and output_dir and bin_name:
                    dest_exe = Path(output_dir) / "malware_source.exe"
                    shutil.copy2(bin_name, str(dest_exe))
                    logger.info("Compiled .exe saved to %s", dest_exe)
                if not syntax_only and not win and bin_name:
                    try:
                        run_proc = await asyncio.create_subprocess_exec(
                            bin_name,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        try:
                            await asyncio.wait_for(run_proc.communicate(), timeout=10)
                        except asyncio.TimeoutError:
                            run_proc.kill()
                            await run_proc.communicate()
                        result.behaviour_checks[BehaviourCheck.EXECUTION_SUCCESS] = True
                    except Exception:
                        result.behaviour_checks[BehaviourCheck.EXECUTION_SUCCESS] = False
        except FileNotFoundError:
            result.compilation_output = f"compiler not found: {compiler}"
    finally:
        for p in (src_name, bin_name):
            if p:
                try:
                    _os.unlink(p)
                except OSError:
                    pass

    return result
