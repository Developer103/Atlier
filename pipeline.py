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
from .generation_engine import GenerationEngine, GenerationResult
from .verifier import Verifier, VerificationResult
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
    ):
        self._generate = generate
        self._provision_vm = provision_vm
        self._verify = verify
        self._retry_loop = retry_loop
        self._debug = debug

        if generate and not db_engine:
            logger.info("DB engine auto-initialised for generation stage")
            db_engine = DBQueryEngine()

        # Stages that are always enabled
        self.engine = GenerationEngine(db_engine=db_engine, debug=debug) if generate else None

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
            except Exception as e:
                raise PipelineError(f"Generation failed: {e}") from e

        # -- Stage 2: Provision VM (optional) --------------------------------
        vm_instance = None
        if self._provision_vm and vm_config is None:
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

        if self._provision_vm and vm_config:
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
            except Exception as e:
                logger.warning("VM provisioning failed (continuing without VM): %s", e)
                result.vm_status = "failed"

        # -- Stage 3: Verify + Loop (optional) -------------------------------
        if self._verify and gen_source:
            verifier = Verifier(vm_instance=vm_instance, debug=self._debug)
            if self._debug and self._debug.enabled:
                self._debug.phase("VERIFY+LOOP")
                self._debug.step("verifier_init", f"Verifier created (VM={'running' if vm_instance else 'none'})")

            async def _verify_fn(src_code: str) -> dict[str, Any]:
                try:
                    vresult = await verifier.verify(
                        source_code=src_code,
                        target_spec=target_spec,
                        timeout=60 if vm_instance else 120,
                    )
                    return {
                        "detection_score": vresult.detection_score.value,
                        "alerts_count": len(vresult.alerts),
                        "compilation_failed": not vresult.behaviour_checks.get("compilation_success", False)
                            and not vresult.compilation_output.strip().startswith("/")
                            and "error" in vresult.compilation_output.lower(),
                        "execution_crashed": vresult.execution_exit_code != 0,
                        "context_hash": "",  # would need to be threaded through
                        "is_undetected": vresult.is_undetected,
                    }
                except Exception as e:
                    logger.error("Verification error: %s", e)
                    if self._debug and self._debug.enabled:
                        self._debug.fail(f"Verify error: {e}")
                    return {"detection_score": "error", "alerts_count": -1}

            async def _generate_fn(spec, variant_seed="default"):
                if self.engine and gen_source is not None:
                    vresult = await self.engine.generate_variant(spec, variant_seed=variant_seed)
                    return vresult.source_code or gen_source
                return ""  # no generation engine — will use existing source

            loop_result = await self.loop_ctrl.run_loop(
                generate_fn=_generate_fn,
                verify_fn=_verify_fn,
                target_spec=target_spec,
                initial_source=gen_source,
            )
            result.loop_result = loop_result
            if self._debug and self._debug.enabled:
                status = "SUCCESS" if loop_result.success else f"FAILED ({loop_result.total_iterations} iterations)"
                self._debug.ok(f"Verify+Loop complete — {status}")

        # -- Stage 4: Write final report -------------------------------------
        if output and result.generation_result:
            (output / "pipeline_report.txt").write_text(self._build_report(result))
            if self._debug and self._debug.enabled:
                self._debug.ok(f"Report written to {output}/pipeline_report.txt")

        if self._debug and self._debug.enabled:
            self._debug.end()

        return result

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
