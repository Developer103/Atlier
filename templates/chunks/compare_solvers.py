#!/usr/bin/env python3
"""
Compare algo-only vs hybrid LLM+algo solvers side-by-side.

Runs sequentially (local LLM can't handle concurrent requests).
Shows live updating progress dashboard and final comparison.
"""

import argparse
import io
import json
import os
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(__file__))
from exam_variants import list_exams


# ════════════════════════════════════════════════════════════════
# LIVE PROGRESS DISPLAY
# ════════════════════════════════════════════════════════════════

class ProgressTracker:
    """Thread-safe progress tracker for a solver run."""
    def __init__(self, name, num_levels, start_level):
        self.name = name
        self.num_levels = num_levels
        self.start_level = start_level
        self.current_level = start_level
        self.runs = 0
        self.passed = 0
        self.failed = False
        self.failed_at = None
        self.done = False
        self.elapsed = 0.0
        self.level_runs = {}   # level → runs to solve
        self.level_status = {} # level → "pass"|"fail"|"working"
        self.lock = threading.Lock()

    def update(self, level, runs, status):
        with self.lock:
            self.current_level = level
            self.runs = runs
            if status == "pass":
                self.level_status[level] = "pass"
                self.level_runs[level] = runs
                self.passed += 1
            elif status == "fail":
                self.level_status[level] = "fail"
                self.failed = True
                self.failed_at = level
            else:
                self.level_status[level] = "working"

    def finish(self, elapsed):
        with self.lock:
            self.done = True
            self.elapsed = elapsed


def _render_dashboard(algo, hybrid, num_levels, start_level, end_level):
    """Render a compact visual comparison dashboard."""
    lines = []
    lines.append("")
    lines.append("╔══════════════════════════════════════════════════════════════════════════╗")
    lines.append("║  SOLVER COMPARISON — LIVE PROGRESS                                     ║")
    lines.append("╠═══════════════════════════════╦══════════════════════════════════════════╣")
    lines.append("║  ALGO-ONLY (no LLM)           ║  HYBRID (algo + LLM)                   ║")
    lines.append("╠═══════════════════════════════╬══════════════════════════════════════════╣")

    for lvl in range(start_level, end_level + 1):
        a_status = algo.level_status.get(lvl, "")
        h_status = hybrid.level_status.get(lvl, "")

        if a_status == "pass":
            a_runs = algo.level_runs.get(lvl, 0)
            a_str = f"✓ L{lvl:2d} ({a_runs:3d} runs)"
        elif a_status == "fail":
            a_str = f"✗ L{lvl:2d} FAILED"
        elif a_status == "working":
            a_str = f"⟳ L{lvl:2d} ({algo.runs:3d} runs...)"
        elif algo.done:
            a_str = f"· L{lvl:2d} (not reached)"
        else:
            a_str = f"  L{lvl:2d}"

        if h_status == "pass":
            h_runs = hybrid.level_runs.get(lvl, 0)
            h_str = f"✓ L{lvl:2d} ({h_runs:3d} runs)"
        elif h_status == "fail":
            h_str = f"✗ L{lvl:2d} FAILED"
        elif h_status == "working":
            h_str = f"⟳ L{lvl:2d} ({hybrid.runs:3d} runs...)"
        elif hybrid.done:
            h_str = f"· L{lvl:2d} (not reached)"
        else:
            h_str = f"  L{lvl:2d}"

        lines.append(f"║  {a_str:<28s}║  {h_str:<39s}║")

    lines.append("╠═══════════════════════════════╬══════════════════════════════════════════╣")

    a_summary = f"{algo.passed}/{num_levels} | {algo.runs} runs | {algo.elapsed:.0f}s"
    h_summary = f"{hybrid.passed}/{num_levels} | {hybrid.runs} runs | {hybrid.elapsed:.0f}s"
    if algo.done:
        a_label = "DONE"
    else:
        a_label = "RUNNING"
    if hybrid.done:
        h_label = "DONE"
    else:
        h_label = "RUNNING"

    lines.append(f"║  {a_label}: {a_summary:<22s}║  {h_label}: {h_summary:<33s}║")
    lines.append("╚═══════════════════════════════╩══════════════════════════════════════════╝")
    return "\n".join(lines)


def _capture_run_with_progress(solver_fn, tracker, malware_type,
                                start_level, end_level, exam_name, **kwargs):
    """Run a solver, parsing output to update progress tracker."""
    import re

    class ProgressWriter:
        def __init__(self, tracker, stream):
            self.tracker = tracker
            self.stream = stream
            self.buf = io.StringIO()

        def write(self, s):
            self.buf.write(s)
            self.stream.write(s)
            self.stream.flush()

            # Parse progress from output
            for line in s.split("\n"):
                # Match "Level X PASSED"
                m = re.search(r'Level\s+(\d+)\s+PASSED', line)
                if m:
                    lvl = int(m.group(1))
                    self.tracker.update(lvl, self.tracker.runs, "pass")

                # Match "Run NNN"
                m = re.search(r'Run\s+(\d+)', line)
                if m:
                    self.tracker.runs = int(m.group(1))

                # Match "Level X/Y"
                m = re.search(r'Level\s+(\d+)/(\d+)', line)
                if m:
                    lvl = int(m.group(1))
                    if lvl != self.tracker.current_level:
                        self.tracker.update(lvl, self.tracker.runs, "working")

                # Match "FAILED"
                m = re.search(r'Level\s+(\d+)\s+FAILED', line)
                if m:
                    lvl = int(m.group(1))
                    self.tracker.update(lvl, self.tracker.runs, "fail")

        def flush(self):
            self.buf.flush()
            self.stream.flush()

    t0 = time.time()
    old_stdout = sys.stdout
    writer = ProgressWriter(tracker, old_stdout)
    sys.stdout = writer

    try:
        passed, total_runs, level_results = solver_fn(
            malware_type, start_level=start_level, end_level=end_level,
            exam_name=exam_name, **kwargs)
    except Exception as e:
        passed, total_runs, level_results = 0, 0, {}
        print(f"\n  *** SOLVER ERROR: {e} ***\n")
    finally:
        sys.stdout = old_stdout

    elapsed = time.time() - t0
    tracker.runs = total_runs
    tracker.passed = passed
    tracker.finish(elapsed)
    return passed, total_runs, level_results, elapsed


def main():
    available_exams = list_exams()

    p = argparse.ArgumentParser(
        description="Compare algo-only vs hybrid LLM+algo exam solvers")
    p.add_argument("--type", "-t", default="infostealer",
                   choices=["infostealer", "keylogger", "backdoor"])
    p.add_argument("--exam", "-e", default="A")
    p.add_argument("--levels", "-n", type=int, default=20)
    p.add_argument("--start-level", "-s", type=int, default=1)
    p.add_argument("--batch-size", "-b", type=int, default=10,
                   help="Batch size for hybrid solver (default: 10)")
    p.add_argument("--llm-url", default="http://localhost:11235")
    p.add_argument("--algo-only", action="store_true",
                   help="Only run the algo solver (skip hybrid)")
    p.add_argument("--hybrid-only", action="store_true",
                   help="Only run the hybrid solver (skip algo)")
    args = p.parse_args()

    end_level = min(args.start_level + args.levels - 1, 20)
    start_level = max(1, args.start_level)
    num_levels = end_level - start_level + 1

    print(f"\n{'#'*74}")
    print(f"  SOLVER COMPARISON — {args.type.upper()} [Exam {args.exam}]")
    print(f"  Levels {start_level}-{end_level} ({num_levels})")
    print(f"{'#'*74}\n")

    algo_tracker = ProgressTracker("Algo", num_levels, start_level)
    hybrid_tracker = ProgressTracker("Hybrid", num_levels, start_level)

    algo_result = None
    hybrid_result = None

    # ── Run algo solver first (fast, no LLM) ──
    if not args.hybrid_only:
        print(f"{'='*74}")
        print(f"  ALGO-ONLY SOLVER")
        print(f"{'='*74}\n")

        from test_evasion_loop_algo import run_exam as run_algo
        a_passed, a_runs, a_levels, a_time = _capture_run_with_progress(
            run_algo, algo_tracker, args.type, start_level, end_level, args.exam)
        algo_result = {"passed": a_passed, "total_runs": a_runs,
                        "levels": a_levels, "elapsed": a_time}

        print(f"\n  Algo finished: {a_passed}/{num_levels} levels, "
              f"{a_runs} runs, {a_time:.1f}s\n")
    else:
        algo_tracker.finish(0)

    # ── Run hybrid solver (slow, uses LLM) ──
    if not args.algo_only:
        print(f"{'='*74}")
        print(f"  HYBRID LLM+ALGO SOLVER")
        print(f"{'='*74}\n")

        from test_evasion_loop import run_exam as run_hybrid
        h_passed, h_runs, h_levels, h_time = _capture_run_with_progress(
            run_hybrid, hybrid_tracker, args.type, start_level, end_level, args.exam,
            llm_url=args.llm_url, batch_size=args.batch_size)
        hybrid_result = {"passed": h_passed, "total_runs": h_runs,
                          "levels": h_levels, "elapsed": h_time}

        print(f"\n  Hybrid finished: {h_passed}/{num_levels} levels, "
              f"{h_runs} runs, {h_time:.1f}s\n")
    else:
        hybrid_tracker.finish(0)

    # ── Final comparison dashboard ──
    if algo_result and hybrid_result:
        dashboard = _render_dashboard(
            algo_tracker, hybrid_tracker, num_levels, start_level, end_level)
        print(dashboard)

        from test_evasion_loop import get_levels, _is_behavioral_exam, BEHAVIORAL_EXAMS
        if _is_behavioral_exam(args.exam):
            level_names = {i: f"Tier {i} detection" for i in range(1, 21)}
        else:
            levels = get_levels(args.type, exam_name=args.exam)
            level_names = {l[0]: l[1] for l in levels}

        print(f"\n  {'Level':>5}  {'Algo':>8}  {'Hybrid':>8}  {'Winner':>8}  Level Name")
        print(f"  {'─'*5}  {'─'*8}  {'─'*8}  {'─'*8}  {'─'*30}")

        algo_wins = 0
        hybrid_wins = 0
        ties = 0
        algo_only_pass = 0
        hybrid_only_pass = 0

        for lvl in range(start_level, end_level + 1):
            a = algo_result["levels"].get(lvl)
            h = hybrid_result["levels"].get(lvl)
            a_runs = a["runs"] if a else "FAIL"
            h_runs = h["runs"] if h else "FAIL"

            if a and h:
                if a["runs"] < h["runs"]:
                    winner = "Algo"
                    algo_wins += 1
                elif h["runs"] < a["runs"]:
                    winner = "Hybrid"
                    hybrid_wins += 1
                else:
                    winner = "Tie"
                    ties += 1
            elif a:
                winner = "Algo!"
                algo_only_pass += 1
            elif h:
                winner = "Hybrid!"
                hybrid_only_pass += 1
            else:
                winner = "Both fail"

            a_str = f"{a_runs:>4}" if isinstance(a_runs, int) else f"{a_runs:>8}"
            h_str = f"{h_runs:>4}" if isinstance(h_runs, int) else f"{h_runs:>8}"

            print(f"  {lvl:5d}  {a_str:>8}  {h_str:>8}  {winner:>8}  {level_names.get(lvl, f'Level {lvl}')}")

        print(f"\n  ╔════════════════════════════════════════╗")
        print(f"  ║  FINAL SCORE                           ║")
        print(f"  ╠════════════════════════════════════════╣")
        print(f"  ║  Algo-only:  {algo_result['passed']:2d}/{num_levels} levels, "
              f"{algo_result['total_runs']:4d} runs, {algo_result['elapsed']:6.1f}s ║")
        print(f"  ║  Hybrid:     {hybrid_result['passed']:2d}/{num_levels} levels, "
              f"{hybrid_result['total_runs']:4d} runs, {hybrid_result['elapsed']:6.1f}s ║")
        print(f"  ╠════════════════════════════════════════╣")
        print(f"  ║  Algo wins:    {algo_wins:2d}                      ║")
        print(f"  ║  Hybrid wins:  {hybrid_wins:2d}                      ║")
        print(f"  ║  Ties:         {ties:2d}                      ║")
        if algo_only_pass:
            print(f"  ║  Algo-only solves:  {algo_only_pass:2d}                 ║")
        if hybrid_only_pass:
            print(f"  ║  Hybrid-only solves: {hybrid_only_pass:2d}                ║")
        print(f"  ╚════════════════════════════════════════╝")

        if algo_result['total_runs'] > 0 and hybrid_result['total_runs'] > 0:
            ratio = hybrid_result['total_runs'] / max(algo_result['total_runs'], 1)
            print(f"\n  Hybrid uses {ratio:.1f}x {'more' if ratio > 1 else 'fewer'} runs")
        if algo_result['elapsed'] > 0 and hybrid_result['elapsed'] > 0:
            time_ratio = hybrid_result['elapsed'] / max(algo_result['elapsed'], 0.01)
            print(f"  Hybrid takes {time_ratio:.1f}x {'longer' if time_ratio > 1 else 'shorter'}")

        # Verdict
        print()
        if algo_result['passed'] > hybrid_result['passed']:
            print("  VERDICT: Algo-only solver wins — solves more levels with fewer runs.")
        elif hybrid_result['passed'] > algo_result['passed']:
            print("  VERDICT: Hybrid solver wins — LLM reasoning helps on harder levels.")
        elif algo_result['total_runs'] < hybrid_result['total_runs']:
            print("  VERDICT: Tie on levels — Algo wins on efficiency (fewer runs).")
        else:
            print("  VERDICT: Dead heat.")

    elif algo_result:
        print(f"\n  Algo-only: {algo_result['passed']}/{num_levels} levels, "
              f"{algo_result['total_runs']} runs, {algo_result['elapsed']:.1f}s")
    elif hybrid_result:
        print(f"\n  Hybrid: {hybrid_result['passed']}/{num_levels} levels, "
              f"{hybrid_result['total_runs']} runs, {hybrid_result['elapsed']:.1f}s")

    print(f"\n{'='*74}\n")


if __name__ == "__main__":
    main()
