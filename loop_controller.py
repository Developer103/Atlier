"""
Loop controller — retry loop with exponential backoff, failure classification,
and stuck detection for the verification pipeline (Phase 5b).

Manages iteration history, context hash comparison, and determines when to stop
or continue generating new malware variants.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Callable, Awaitable

from .debug_logger import DebugLogger as _DebugLogger

logger = logging.getLogger(__name__)


class FailureMode(Enum):
    """Classification of why a verification iteration failed."""
    COMPILATION_FAILED = "compilation_failed"       # Source didn't compile
    EXECUTION_CRASHED = "execution_crashed"         # Malware crashed on execution
    DETECTED = "detected"                           # EDR/AV flagged the binary
    SANDBOX_DETECTED = "sandbox_detected"           # VM is running in a sandbox
    CONTEXT_STUCK = "context_stuck"                 # Same context hash across iterations
    LLM_GENERATION_EMPTY = "llm_empty"              # LLM returned empty/nothing useful
    UNKNOWN = "unknown"


@dataclass
class IterationRecord:
    """Record of a single verification iteration."""
    iteration: int
    source_code_hash: str
    context_hash: str
    failure_mode: Optional[FailureMode]
    detection_score: str  # from VerificationResult.detection_score.name
    alerts_count: int
    build_time_sec: float
    execution_exit_code: int


class LoopController:
    """Manages the verify → regenerate retry loop.

    Implements:
      - Exponential backoff between regeneration attempts
      - Failure classification to guide next attempt strategy
      - Stuck detection via context hash comparison
      - Max iteration enforcement with early stopping conditions
    """

    def __init__(
        self,
        max_iterations: int = 5,
        min_iterations: int = 1,
        exhaustive_mode: bool = False,
        stick_threshold: int = 2,
        backoff_base: float = 1.0,
        backoff_max: float = 30.0,
        debug: Optional[_DebugLogger] = None,
    ):
        self.max_iterations = max_iterations
        self.min_iterations = min_iterations
        self.exhaustive_mode = exhaustive_mode  # keep going until all techniques exhausted
        self.stick_threshold = stick_threshold   # consecutive same-context-hash triggers stuck
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self._debug = debug

    async def run_loop(
        self,
        generate_fn: Callable[..., Awaitable],  # generates malware (source_code)
        verify_fn: Callable[[str], Awaitable],   # verifies source code, returns result dict
        target_spec,                             # TargetEnvironmentSpec
        initial_source: Optional[str] = None,
    ):
        """Run the full verification loop.

        Parameters:
            generate_fn: Async function that takes a context/seed → returns generated source code string
            verify_fn: Async function that takes source code → returns dict with detection info
            target_spec: Target environment specification
            initial_source: Pre-generated source to use as first attempt (from GenerationEngine)

        Returns:
            LoopResult with all iteration records and final verdict.
        """
        history: List[IterationRecord] = []
        prev_context_hash: Optional[str] = None
        consecutive_same_hash = 0

        # -- Initial generation if provided ------------------------------------
        source_code = initial_source or await generate_fn(target_spec)

        if self._debug and self._debug.enabled:
            self._debug.phase("LOOP")
            self._debug.step("init", f"Starting loop — max {self.max_iterations} iterations, min {self.min_iterations}")

        for iteration in range(1, self.max_iterations + 1):
            iter_start = time.time()

            if self._debug and self._debug.enabled:
                self._debug.step(f"iter_{iteration}", f"Running verification #{iteration}/{self.max_iterations}...")

            # -- Verify --------------------------------------------------------
            try:
                result = await verify_fn(source_code)
            except Exception as e:
                logger.error("Verification error at iteration %d: %s", iteration, e)
                record = IterationRecord(
                    iteration=iteration,
                    source_code_hash="",
                    context_hash="",
                    failure_mode=FailureMode.UNKNOWN,
                    detection_score="error",
                    alerts_count=-1,
                    build_time_sec=0.0,
                    execution_exit_code=-1,
                )
                history.append(record)
                continue

            # -- Classify failure mode ---------------------------------------
            failure_mode = self._classify_failure(result)

            if self._debug and self._debug.enabled:
                self._debug.dump_dict("iteration_result", {
                    "detection_score": result.get("detection_score"),
                    "alerts_count": result.get("alerts_count"),
                    "compilation_failed": result.get("compilation_failed"),
                    "execution_crashed": result.get("execution_crashed"),
                    "is_undetected": result.get("is_undetected"),
                })
                if failure_mode:
                    self._debug.step("classification", f"Failure mode: {failure_mode.value}")

            record = IterationRecord(
                iteration=iteration,
                source_code_hash=_hash(source_code[:200]),
                context_hash=result.get("context_hash", ""),
                failure_mode=failure_mode,
                detection_score=result.get("detection_score", "unknown"),
                alerts_count=result.get("alerts_count", -1),
                build_time_sec=0.0,
                execution_exit_code=result.get("execution_exit_code", -1),
            )
            history.append(record)

            # -- Check stopping conditions -----------------------------------
            if record.detection_score == "none":
                logger.info("Iteration %d: UNDETECTED! Stopping.", iteration)
                if self._debug and self._debug.enabled:
                    self._debug.ok(f"Iteration {iteration} — undetected (SUCCESS)")
                    self._debug.step("stop", f"Stopping loop at iteration {iteration}")
                break  # success — no need for more iterations

            if self._is_stuck(consecutive_same_hash, prev_context_hash, record.context_hash):
                consecutive_same_hash += 1
                if self._debug and self._debug.enabled:
                    self._debug.step("stuck_check", f"Context hash unchanged (count={consecutive_same_hash})")
                if consecutive_same_hash >= self.stick_threshold:
                    logger.warning(
                        "Stuck at iteration %d (same context hash %d times). "
                        "Forcing new variant with different seed.",
                        iteration, consecutive_same_hash
                    )

            # -- Backoff before next generation ------------------------------
            if iteration < self.max_iterations and not result.get("is_undetected"):
                backoff = min(
                    self.backoff_base * (2 ** (iteration - 1)),
                    self.backoff_max,
                )
                logger.info("Backing off %.1fs before next generation attempt...", backoff)
                if self._debug and self._debug.enabled:
                    self._debug.step("backoff", f"Sleeping {backoff:.1f}s before retry")
                    self._debug.step("generate_next", f"Calling generate_fn for iteration {iteration + 1}")
                await asyncio.sleep(backoff)

            # -- Generate next variant ---------------------------------------
            source_code = await generate_fn(target_spec, variant_seed=f"iter_{iteration}")

            # Update context hash tracking
            if record.context_hash == prev_context_hash:
                consecutive_same_hash += 1
            else:
                consecutive_same_hash = 0
            prev_context_hash = record.context_hash

        success = any(r.detection_score == "none" for r in history)

        if self._debug and self._debug.enabled:
            self._debug.ok(f"Loop complete — {len(history)} iterations, success={success}")
            for r in history:
                status = "✓ UNDETECTED" if r.detection_score == "none" else f"detected({r.detection_score})"
                fail_note = f" [{r.failure_mode.value}]" if r.failure_mode else ""
                self._debug.step(f"iter_{r.iteration}_done", f"{status}{fail_note}")

        return LoopResult(
            iterations=history,
            best_result=self._find_best(history),
            total_iterations=len(history),
            success=success,
        )

    # ------------------------------------------------------------------
    # classification helpers
    # ------------------------------------------------------------------

    def _classify_failure(self, result: dict) -> Optional[FailureMode]:
        """Classify why this iteration didn't succeed."""
        if result.get("compilation_failed"):
            return FailureMode.COMPILATION_FAILED
        if result.get("execution_crashed"):
            return FailureMode.EXECUTION_CRASHED

        score = result.get("detection_score", "")
        alerts = result.get("alerts_count", 0)

        if score == "none" and alerts == 0:
            return None  # success, no failure
        if score in ("high",):
            return FailureMode.DETECTED
        if alerts > 3:
            return FailureMode.DETECTED
        return FailureMode.UNKNOWN

    @staticmethod
    def _is_stuck(consecutive_count: int, prev_hash: Optional[str], curr_hash: str) -> bool:
        """Check if the context has been stuck (same hash)."""
        if not prev_hash or not curr_hash:
            return False
        return prev_hash == curr_hash

    @staticmethod
    def _find_best(records: List[IterationRecord]) -> Optional[dict]:
        """Find the best iteration result."""
        best = None
        for r in records:
            if best is None or LoopController._better(r, best):
                best = r
        if best is None:
            return None
        return {
            "iteration": best.iteration,
            "detection_score": best.detection_score,
            "alerts_count": best.alerts_count,
            "failure_mode": best.failure_mode.value if best.failure_mode else None,
        }

    @staticmethod
    def _better(current: IterationRecord, existing: IterationRecord) -> bool:
        """Compare two records — does current beat existing?"""
        score_order = {"none": 0, "low": 1, "medium": 2, "high": 3}
        cur_score = score_order.get(current.detection_score, 99)
        ex_score = score_order.get(existing.detection_score, 99)

        if cur_score != ex_score:
            return cur_score < ex_score  # lower detection score is better
        return current.alerts_count < existing.alerts_count


@dataclass
class LoopResult:
    """Final result of the verification loop."""
    iterations: List[IterationRecord]
    best_result: Optional[dict]
    total_iterations: int
    success: bool

    def summary(self) -> str:
        """Human-readable summary string."""
        lines = [
            f"=== Verification Loop Summary ===",
            f"Total iterations: {self.total_iterations}",
            f"Success (undetected): {'YES' if self.success else 'NO'}",
        ]
        if self.best_result:
            lines.append(f"Best result — iteration {self.best_result['iteration']}: "
                         f"detection={self.best_result['detection_score']}, "
                         f"alerts={self.best_result.get('alerts_count', 'N/A')}, "
                         f"failure_mode={self.best_result.get('failure_mode', 'N/A')}")

        lines.append("\nIteration details:")
        for r in self.iterations:
            status = "✓ UNDETECTED" if r.detection_score == "none" else \
                     f"detected({r.detection_score})" if r.alerts_count >= 0 else "?"
            fail_note = f" [{r.failure_mode.value}]" if r.failure_mode else ""
            lines.append(f"  Iter {r.iteration}: {status}{fail_note}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# utility
# ---------------------------------------------------------------------------

def _hash(text: str, length: int = 12) -> str:
    """Quick hash for context comparison."""
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()[:length]
