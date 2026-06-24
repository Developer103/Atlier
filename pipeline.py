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

from .config_models import VMProvisionConfig, TargetOS
from .spec_parser import parse_target_spec
from .target_spec import TargetEnvironmentSpec, OSPlatform
from .db_query_engine import DBQueryEngine
from .generation_engine import GenerationEngine, GenerationResult, ErrorAnalyzer, FailureAnalysis, MalwarePlan
from .verifier import Verifier, VerificationResult, BehaviourCheck
from .loop_controller import LoopController, LoopResult
from .debug_logger import DebugLogger

logger = logging.getLogger(__name__)


class PipelineError(Exception):
    """Raised when a pipeline stage fails."""
    pass


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
        run_mode: str = "local-run",  # "local-run" | "cloud-run"
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

        if generate and not db_engine:
            logger.info("DB engine auto-initialised for generation stage")
            db_engine = DBQueryEngine()

        # Stages that are always enabled
        self.engine = (
            GenerationEngine(db_engine=db_engine, debug=debug, run_mode=run_mode)
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
        **spec_overrides: Any,
    ) -> "PipelineResult":
        """Execute the full pipeline.

        Parameters set which stages run:
            spec_path: Path to YAML/JSON target spec file
            output_dir: Where to write generated code and results
            vm_config: VMProvisionConfig for the provision stage
            **spec_overrides: Override fields from the spec file
        """
        output = Path(output_dir) if output_dir else None
        if output:
            output.mkdir(parents=True, exist_ok=True)

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
            logger.info("Target spec loaded: %s (%s)", target_spec.os_platform.value, target_spec.os_version)
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
                    (output / "malware_source.c").write_text(gen_result.source_code)
                    logger.info("Source written to %s", output / "malware_source.c")

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
                from .verifier import ValidationPlan
                _validation_plan = await self.engine.generate_validation_plan(target_spec)
                if _validation_plan.checks:
                    logger.info(
                        "Behavioral validation plan ready — %d checks",
                        len(_validation_plan.checks),
                    )
                else:
                    logger.info("Behavioral validation plan: no checks generated (skipping functional validation)")
                    _validation_plan = None
            except Exception as e:
                logger.warning("Validation plan generation failed (%s) — functional validation disabled", e)
                _validation_plan = None

        # -- Stage 2: Provision VM (optional) --------------------------------
        vm_instance = None
        if self._use_existing_vm:
            from .provision_engine import VMInstance
            vm_instance = VMInstance(
                qemu=None,
                vm_user=self._existing_vm_user,
                vm_pass=self._existing_vm_pass,
                ssh_port=self._existing_vm_port,
            )
            vm_instance.status = "running"
            result.vm_status = "running"
            result.ssh_port = self._existing_vm_port
            logger.info("Using pre-existing VM at localhost:%d (user=%s)", self._existing_vm_port, self._existing_vm_user)

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

        if not self._use_existing_vm and self._provision_vm and vm_config:
            logger.info("Provisioning VM...")
            try:
                from .provision_engine import ProvisionEngine
                engine = ProvisionEngine()
                vm_instance = await engine.provision(vm_config, background=True)
                result.vm_status = "running"
                result.ssh_port = vm_instance.ssh_port if vm_instance else None
                if self._debug and self._debug.enabled:
                    self._debug.ok("VM provisioned")
                    if result.ssh_port:
                        self._debug.step("vm_info", f"SSH port: {result.ssh_port}")
                # Save a clean-state snapshot so each loop iteration starts fresh.
                # loadvm restores disk+RAM+CPU atomically — works even after ransomware
                # or other destructive payloads since qcow2 discards all writes since savevm.
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
        _state: dict = {
            "last_analysis": None,          # FailureAnalysis | None
            "last_source":   None,          # str | None — source that was verified and failed
            "last_plan":     _initial_plan, # MalwarePlan | None — seeded from initial generation
            "fixed_source":  None,          # str | None — directly compiler-fixed source (skip re-gen)
        }
        _error_analyzer = ErrorAnalyzer()

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

                if analysis and last_src and not analysis.full_rewrite_needed and analysis.problem_functions:
                    # Patch mode: only rewrite the functions flagged by failure analysis
                    patched = await self.engine.patch_source(last_src, analysis, spec, plan=last_plan)
                    return patched or gen_source
                elif analysis:
                    # Full rewrite informed by the failure analysis
                    vresult = await self.engine.generate_variant(
                        spec, variant_seed=variant_seed,
                        error_context=analysis.patch_instructions or analysis.summary,
                    )
                    _state["last_plan"] = vresult.plan
                    return vresult.source_code or gen_source
                else:
                    vresult = await self.engine.generate_variant(spec, variant_seed=variant_seed)
                    _state["last_plan"] = vresult.plan
                    return vresult.source_code or gen_source
            return ""

        if self._verify and gen_source and vm_instance is not None:
            verifier = Verifier(vm_instance=vm_instance, debug=self._debug)
            if self._debug and self._debug.enabled:
                self._debug.phase("VERIFY+LOOP")
                self._debug.step("verifier_init", "Verifier created (VM=running)")

            async def _verify_fn(src_code: str) -> dict[str, Any]:
                try:
                    vresult = await verifier.verify(
                        source_code=src_code,
                        target_spec=target_spec,
                        timeout=60,
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
                    _func_validation_output = ""
                    if (
                        vresult.is_undetected
                        and _compile_ok
                        and _exec_ok
                        and _validation_plan is not None
                    ):
                        try:
                            _func_passed = await verifier.run_validation_checks(_validation_plan)
                            result_dict["functional_failed"] = not _func_passed
                            vresult.functional_validation_passed = _func_passed
                            if not _func_passed:
                                logger.warning(
                                    "Behavioral validation FAILED — malware ran but produced no observable effect"
                                )
                                if self._debug and self._debug.enabled:
                                    self._debug.fail("Behavioral validation: FAIL (malware did nothing)")
                            else:
                                logger.info("Behavioral validation: PASS")
                                if self._debug and self._debug.enabled:
                                    self._debug.ok("Behavioral validation: PASS")
                        except Exception as fve:
                            logger.warning("Behavioral validation error: %s", fve)

                    _is_failure = (
                        result_dict["compilation_failed"]
                        or result_dict["execution_crashed"]
                        or result_dict["detection_score"] not in ("none", "error")
                        or result_dict["functional_failed"]
                    )
                    if _error_analyzer.available and _is_failure:
                        if result_dict["compilation_failed"] and vresult.compilation_output:
                            # Direct compile-fix: Fugu first → local LLM → produce complete fixed source.
                            # If it works the next _generate_fn call returns the fixed source immediately
                            # without another generation round-trip.
                            fixed = await _error_analyzer.fix_compile_error(
                                src_code, vresult.compilation_output,
                            )
                            if fixed:
                                _state["fixed_source"] = fixed
                                logger.info("Compile error auto-fixed (%d chars)", len(fixed))
                            else:
                                # fix_compile_error failed — fall back to failure analysis
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
                            fa = await _error_analyzer.analyze_failure(
                                source_code=src_code,
                                failure_mode=failure_mode,
                                detection_score=result_dict["detection_score"],
                                error_output="",
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

            loop_result = await self.loop_ctrl.run_loop(
                generate_fn=_generate_fn,
                verify_fn=_verify_fn,
                target_spec=target_spec,
                initial_source=gen_source,
                reset_fn=_reset_vm if _snapshot_tag else None,
            )
            result.loop_result = loop_result
            if self._debug and self._debug.enabled:
                status = "SUCCESS" if loop_result.success else f"FAILED ({loop_result.total_iterations} iterations)"
                self._debug.ok(f"Verify+Loop complete — {status}")

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
            # Windows C uses Win32 headers that plain gcc on Linux can't find, so
            # prefer MinGW cross-compiler; fall back to structural-only check.
            if _is_win_target:
                if _shutil.which("x86_64-w64-mingw32-gcc"):
                    _local_compile_cmd = "x86_64-w64-mingw32-gcc -fsyntax-only -x c"
                    _syntax_only_mode = "cross-compile"
                else:
                    _local_compile_cmd = None  # structural check only
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
                            "context_hash": "",
                            "is_undetected": compile_ok,
                        }
                    vresult = await verify_standalone(
                        src_code, target_spec, compile_cmd=_local_compile_cmd
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
                        "context_hash": "",
                        "is_undetected": compile_ok,
                    }
                    if not compile_ok and vresult.compilation_output and _error_analyzer.available:
                        fixed = await _error_analyzer.fix_compile_error(
                            src_code, vresult.compilation_output,
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
            )
            result.loop_result = loop_result
            if self._debug and self._debug.enabled:
                status = "SUCCESS" if loop_result.success else f"FAILED ({loop_result.total_iterations} iterations)"
                self._debug.ok(f"Local-loop complete — {status}")

        # -- Stage 4: Write final report -------------------------------------
        if output and result.generation_result:
            (output / "pipeline_report.txt").write_text(self._build_report(result))
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
            best = max(self.loop_result.iterations, key=lambda r: (0 if r.detection_score == "none" else 1))
            lines.append(f"Best iteration: #{best.iteration} — {best.detection_score}")

        return "\n".join(lines)
