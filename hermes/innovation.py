"""Innovation engine — experimental evasion technique discovery.

When the normal template-based approach exhausts its options (100+ consecutive
failures), innovation mode engages: Hermes analyzes all failures holistically,
hypothesizes a new technique the framework doesn't have, generates experimental
code in a sandboxed directory, and tests it. Results go into a report for human
review — successful innovations can be promoted into the template library.

The innovation engine NEVER modifies the existing template library. All
experimental code lives in results/innovations/.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class InnovationEngine:

    def __init__(self, threshold: int = 100, base_dir: str | None = None):
        self.threshold = threshold
        self.consecutive_failures = 0
        self.total_attempts = 0
        self.in_innovation_mode = False
        self.base_dir = Path(base_dir or
                             Path(__file__).parent.parent / "results" / "innovations")
        self.past_innovations: list[dict] = []
        self.current_scratch: Path | None = None
        self._failure_log: list[dict] = []
        self._load_history()

    def _history_path(self) -> Path:
        return self.base_dir / "innovation_history.json"

    def _load_history(self):
        hp = self._history_path()
        if hp.exists():
            try:
                data = json.loads(hp.read_text())
                self.past_innovations = data.get("innovations", [])
            except Exception:
                self.past_innovations = []

    def _save_history(self):
        self.base_dir.mkdir(parents=True, exist_ok=True)
        data = {"innovations": self.past_innovations}
        self._history_path().write_text(json.dumps(data, indent=2))

    def record_attempt(self, failure_info: dict | None = None,
                       success: bool = False) -> bool:
        """Record an attempt result. Returns True if innovation mode should trigger."""
        self.total_attempts += 1
        if success:
            self.consecutive_failures = 0
            self._failure_log.clear()
            return False
        self.consecutive_failures += 1
        if failure_info:
            self._failure_log.append(failure_info)
            if len(self._failure_log) > 200:
                self._failure_log = self._failure_log[-150:]
        return (self.consecutive_failures >= self.threshold
                and not self.in_innovation_mode)

    def enter(self) -> Path:
        """Enter innovation mode. Returns the scratch directory."""
        self.in_innovation_mode = True
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        scratch = self.base_dir / f"experiment_{ts}"
        scratch.mkdir(parents=True, exist_ok=True)
        self.current_scratch = scratch
        logger.info("Entering innovation mode: %s (after %d failures)",
                     scratch, self.consecutive_failures)
        return scratch

    def exit(self, success: bool, report: dict):
        """Exit innovation mode and save results."""
        self.in_innovation_mode = False
        record = {
            "timestamp": datetime.now().isoformat(),
            "dir": str(self.current_scratch),
            "success": success,
            "consecutive_failures_at_trigger": self.consecutive_failures,
            "report": report,
        }
        self.past_innovations.append(record)
        self._save_history()
        self.consecutive_failures = 0
        self._failure_log.clear()
        self.current_scratch = None
        logger.info("Exited innovation mode: %s", "SUCCESS" if success else "FAILED")

    def get_failure_analysis(self) -> str:
        """Summarize all recent failures for the LLM."""
        if not self._failure_log:
            return "No failures logged."

        detection_counts: dict[str, int] = {}
        recipes_tried: set[str] = set()
        formats_tried: set[str] = set()
        evasion_tried: set[str] = set()

        for f in self._failure_log:
            reason = f.get("reason", "unknown")
            detection_counts[reason] = detection_counts.get(reason, 0) + 1
            if f.get("recipe"):
                recipes_tried.add(f["recipe"])
            if f.get("format"):
                formats_tried.add(f["format"])
            for e in f.get("evasion", []):
                evasion_tried.add(e)

        lines = [
            f"## Failure Analysis ({len(self._failure_log)} failures)",
            "",
            f"Detection patterns:",
        ]
        for reason, count in sorted(detection_counts.items(),
                                     key=lambda x: -x[1]):
            lines.append(f"  - {reason}: {count}x")

        lines.append(f"\nRecipes tried ({len(recipes_tried)}):")
        for r in sorted(recipes_tried):
            lines.append(f"  - {r}")

        lines.append(f"\nFormats tried: {', '.join(sorted(formats_tried)) or 'none logged'}")
        lines.append(f"\nEvasion chunks tried ({len(evasion_tried)}):")
        for e in sorted(evasion_tried):
            lines.append(f"  - {e}")

        return "\n".join(lines)

    def get_past_innovations_summary(self) -> str:
        """Summary of past innovation attempts."""
        if not self.past_innovations:
            return "No prior innovation attempts."
        lines = ["Past innovation attempts:"]
        for i, inn in enumerate(self.past_innovations, 1):
            status = "SUCCESS" if inn["success"] else "FAILED"
            technique = inn["report"].get("technique", "unknown")
            lines.append(f"  {i}. [{status}] {inn['timestamp']}: {technique}")
            if inn["report"].get("notes"):
                lines.append(f"     Notes: {inn['report']['notes'][:200]}")
        return "\n".join(lines)

    def build_innovation_prompt(self) -> str:
        """Build the injection prompt for innovation mode."""
        analysis = self.get_failure_analysis()
        past = self.get_past_innovations_summary()

        return f"""\
## INNOVATION MODE ACTIVATED

You have failed {self.consecutive_failures} consecutive times using the existing template library. The current templates and chunk combinations are exhausted against this target's EDR.

Your task: **hypothesize and implement a NEW evasion technique** that doesn't exist in the template library. Think creatively — what approach hasn't been tried? What assumption about the EDR can be exploited?

{analysis}

{past}

## Rules for Innovation Mode

1. Write experimental C code using write_experimental_code — this saves to a sandboxed directory, NOT the template library.
2. Compile with compile_experimental.
3. Deploy and test normally (deploy_to_vm, start_c2_listener, analyze_results).
4. When done (success or failure), call save_innovation_report with what you tried, why, and whether it worked.
5. DO NOT modify any files in templates/chunks/ — innovation is sandboxed.
6. If your innovation FAILS, that's OK. Call save_innovation_report anyway, then return to normal template-based operation.
7. Try to understand WHY your technique works or fails, not just whether it does.
8. If previous innovations failed, try a DIFFERENT direction — don't repeat what's been tried.

## Ideas to Consider
- Novel API call patterns that look like legitimate software
- Different binary structures (custom sections, unusual entry points)
- Execution flow that mimics known-good software patterns
- Network traffic that looks like legitimate services
- Timing patterns that evade behavioral analysis
- Resource configurations that match trusted software profiles
"""
