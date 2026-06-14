"""
Real-time debug logger for the malware generation pipeline.

Provides structured, colour-coded stdout output that streams each step as it runs,
making it easy to spot errors at any stage without waiting for a final report.

Usage:
    # Programmatic — call from within any module:
    from .debug_logger import DebugLogger
    debug = DebugLogger()
    debug.step("P1", "DB queries complete — 3 techniques, 2 PoCs found")

    # CLI — use --debug flag which creates a global instance injected into the pipeline.
"""

import sys
import time
from dataclasses import dataclass, field
from typing import Optional


# ANSI colour codes
_C = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "cyan": "\033[96m",
    "white": "\033[97m",
}


def _c(text: str, colour: str = "") -> str:
    """Wrap text in ANSI colours."""
    prefix = _C[colour] if colour else ""
    return f"{prefix}{text}{_C['reset']}"


@dataclass
class DebugLogger:
    """Streams structured debug output to stdout for the full pipeline.

    Attributes:
        enabled: Set True to start printing, False to suppress all output.
        step_times: Internal clock used to measure elapsed time per phase.
    """

    enabled: bool = False
    _step_start: Optional[float] = None
    _phase: str = ""

    def __post_init__(self) -> None:
        if self.enabled:
            self._start_banner()

    # ------------------------------------------------------------------
    # Public API — call these from pipeline modules
    # ------------------------------------------------------------------

    def phase(self, name: str) -> None:
        """Start a new pipeline phase."""
        self._phase = name
        self._step_start = time.monotonic()
        print(_c(f"\n{'='*60}", "cyan"))
        print(_c(f"  PHASE {name}: {name.upper()}", "bold cyan"))
        print(_c(f"{'='*60}", "cyan"))

    def step(self, label: str, detail: str = "") -> None:
        """Log a sub-step within the current phase."""
        if self._step_start is not None:
            elapsed = time.monotonic() - self._step_start
            timer = _c(f"[{elapsed:.2f}s]", "dim")
        else:
            timer = ""

        prefix = f"  [{self._phase}] {label}"
        if detail:
            print(_c(prefix, "cyan"), timer)
            # Print details indented with dim colour
            for line in str(detail).split("\n"):
                print(f"      {_c(line.strip(), 'dim')}")
        else:
            print(_c(prefix + f" {timer}", "dim"))

    def ok(self, message: str) -> None:
        """Print a success marker."""
        print("  ", _c("[OK]", "green"), _c(message, "white"))

    def fail(self, message: str) -> None:
        """Print an error marker and traceback hint."""
        print("  ", _c("[FAIL]", "red"), _c(message, "white"))

    def warn(self, message: str) -> None:
        """Print a warning marker."""
        print("  ", _c("[WARN]", "yellow"), _c(message, "dim"))

    def info(self, message: str) -> None:
        """Print informational output (always shown when debug enabled)."""
        print(f"      {_c(message.strip(), 'white')}")

    def dump_dict(self, title: str, data: dict) -> None:
        """Pretty-print a dictionary in a structured format."""
        if not isinstance(data, dict):
            return
        print(f"\n  --- {title} ---")
        for k, v in data.items():
            val_str = _c(str(v), "dim")
            # Truncate long values
            if len(val_str) > 120:
                val_str = val_str[:117] + "..."
            print(f"      {_c(k+':', 'cyan')} {val_str}")

    def dump_list(self, title: str, items: list) -> None:
        """Pretty-print a numbered list."""
        if not isinstance(items, list):
            return
        print(f"\n  --- {title} ({len(items)} items) ---")
        for i, item in enumerate(items[:10], 1):  # cap at 10 to avoid flooding
            line = f"      {_c(i, 'yellow')}. "
            if isinstance(item, dict):
                pairs = ", ".join(f"{k}={_c(str(v), 'dim')}" for k, v in item.items())
                print(_c(line + pairs))
            elif isinstance(item, str):
                line += _c(item.strip()[:100], "dim") if len(str(item)) > 100 else _c(item.strip(), "dim")
                print(line)
            else:
                print(line + _c(str(item), "dim"))
        if len(items) > 10:
            print(f"      {_c(f'... and {len(items)-10} more', 'dim')}")

    def dump_code(self, title: str, code: str) -> None:
        """Pretty-print a block of source code."""
        if not isinstance(code, str):
            return
        print(f"\n  --- {title} ({len(code)} chars) ---")
        preview = code[:500]
        if len(code) > 500:
            print(f"      {_c('// truncated — full output in source file', 'dim')}")
        for line in preview.split("\n"):
            print(f"      |_ {line}")

    def summary(self, messages: list[str]) -> None:
        """Print a final phase summary."""
        if self._step_start is not None:
            elapsed = time.monotonic() - self._step_start
            print(_c(f"\n  PHASE {self._phase} complete — {elapsed:.2f}s total", "green"))

    def loop_iteration(self, iteration: int, detection_score: str, source_len: int) -> None:
        """Print a single retry-loop iteration status."""
        marker = _c("[UNDETECTED]", "green") if detection_score == "none" else _c("[DETECTED]", "red")
        print(f"\n  {_c(f'--- ITERATION #{iteration} ---', 'bold white')}")
        print(f"      Detection: {marker}")
        print(f"      Source length: {source_len} chars")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _start_banner(self) -> None:
        """Print the debug header banner."""
        print(_c("\n" + "=" * 60, "cyan"))
        print(_c("  MALWARE GEN FRAMEWORK — DEBUG MODE", "bold cyan"))
        print(_c("=" * 60 + "\n", "cyan"))
