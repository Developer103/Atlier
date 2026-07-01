"""Persistent iteration state — structured context across retry iterations.

Replaces the simple failure_history list with rich state that persists as JSON
and renders as markdown for LLM consumption.
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class IterationState:
    total_attempts: int = 0
    detection_history: list[dict] = field(default_factory=list)
    techniques_tried: list[dict] = field(default_factory=list)
    evasion_strategies_exhausted: list[str] = field(default_factory=list)
    successful_evasions: list[str] = field(default_factory=list)
    precheck_failures: list[str] = field(default_factory=list)
    notes_for_next_iteration: str = ""

    def record_attempt(
        self,
        iteration: int,
        detected: bool = False,
        edr_name: str = "",
        rule_name: str = "",
        detection_category: str = "",
        message: str = "",
        techniques_used: Optional[list[str]] = None,
        compile_failed: bool = False,
        precheck_blocked: bool = False,
    ) -> None:
        self.total_attempts = max(self.total_attempts, iteration)

        if detected and (rule_name or message):
            self.detection_history.append({
                "iteration": iteration,
                "edr": edr_name,
                "rule_name": rule_name,
                "category": detection_category,
                "message": message[:500],
            })

        if techniques_used:
            self.techniques_tried.append({
                "iteration": iteration,
                "techniques": techniques_used,
                "result": "detected" if detected else "compiled" if not compile_failed else "compile_fail",
            })

        if precheck_blocked:
            self.precheck_failures.append(f"iter_{iteration}: {message[:200]}")

    def mark_exhausted(self, strategy: str) -> None:
        if strategy not in self.evasion_strategies_exhausted:
            self.evasion_strategies_exhausted.append(strategy)

    def mark_successful(self, technique: str) -> None:
        if technique not in self.successful_evasions:
            self.successful_evasions.append(technique)

    def save(self, output_dir: Path) -> None:
        path = output_dir / "iteration_state.json"
        try:
            path.write_text(json.dumps(asdict(self), indent=2))
        except Exception as e:
            logger.warning("Failed to save iteration state: %s", e)

    @classmethod
    def load(cls, output_dir: Path) -> "IterationState":
        path = output_dir / "iteration_state.json"
        if path.exists():
            try:
                data = json.loads(path.read_text())
                return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
            except Exception as e:
                logger.warning("Failed to load iteration state: %s", e)
        return cls()

    def render_context(self) -> str:
        """Render as markdown for injection into LLM prompts."""
        if not self.detection_history and not self.techniques_tried:
            return ""

        lines = ["## Iteration History"]

        if self.detection_history:
            lines.append(f"\n### Detections ({len(self.detection_history)} total)")
            for d in self.detection_history[-5:]:
                lines.append(
                    f"- **Iter {d['iteration']}** [{d['edr']}]: "
                    f"{d['rule_name'] or 'unnamed'} ({d['category'] or 'uncategorized'})"
                )
                if d.get("message"):
                    lines.append(f"  > {d['message'][:200]}")

        if self.evasion_strategies_exhausted:
            lines.append(f"\n### Exhausted Strategies (do NOT retry)")
            for s in self.evasion_strategies_exhausted:
                lines.append(f"- {s}")

        if self.successful_evasions:
            lines.append(f"\n### Working Techniques (keep using)")
            for s in self.successful_evasions:
                lines.append(f"- {s}")

        if self.techniques_tried:
            lines.append(f"\n### Techniques Tried ({len(self.techniques_tried)} attempts)")
            for t in self.techniques_tried[-5:]:
                techs = ", ".join(t.get("techniques", []))
                lines.append(f"- Iter {t['iteration']}: [{t['result']}] {techs}")

        if self.notes_for_next_iteration:
            lines.append(f"\n### Notes\n{self.notes_for_next_iteration}")

        return "\n".join(lines)
