#!/usr/bin/env python3
"""
Pure algorithmic solver for CrowdStrike Falcon IOA exams — no LLM.

Smart deterministic search:
  1. Parse detection hints to guess which dim is relevant
  2. Sweep that dim's values (low-risk first)
  3. If single-dim exhausted, try 2-dim combos
  4. If still stuck, try 3-dim combos
  5. Backtrack if a change breaks a previously-solved level
  6. Dead-end prevention: track explored dims, force new directions
"""

import json
import os
import sys
import time
from itertools import product

sys.path.insert(0, os.path.dirname(__file__))
from evasion_selector import (
    LAYERS, TYPE_LAYERS, ARCH_CONSTRAINTS,
    get_all_layers, select_layers,
    apply_constraints, config_to_recipe,
)
from exam_variants import get_exam, list_exams
from test_evasion_loop import (
    get_levels, evaluate_all_levels, evaluate_config,
    _format_detection_compact, _display_config_compact,
    _is_behavioral_exam, BEHAVIORAL_EXAMS,
)


# ════════════════════════════════════════════════════════════════
# DETECTION → DIMENSION MAPPING (keyword heuristics)
# ════════════════════════════════════════════════════════════════

DET_DIM_KEYWORDS = {
    "exfil": [
        "network", "connection", "tcp", "http", "smb", "dns", "exfil",
        "post", "beacon", "upload", "transfer", "outbound", "tunnel",
        "paste", "cloud", "dropbox", "named pipe", "mapi", "email",
        "winhttp", "data channel",
    ],
    "process": [
        "process", "parent", "child", "tree", "spawn", "ppid", "svchost",
        "explorer", "dllhost", "sihost", "runtimebroker", "taskhostw",
        "ghost", "hollowing", "sideload", "service_dll", "shell extension",
    ],
    "api_resolve": [
        "import", "api", "loadlibrary", "getprocaddress", "hash",
        "peb", "syscall", "ntdll", "resolution", "iat", "djb2",
        "crc32", "fnv1a", "unhook", "hookchain", "ssn", "gate",
        "knowndlls", "suspend", "remap",
    ],
    "persistence": [
        "persist", "registry", "startup", "scheduled", "task", "run key",
        "com hijack", "ifeo", "debugger", "dll search", "autorun",
        "wmi", "subscription",
    ],
    "timing": [
        "sleep", "delay", "timing", "deferred", "burst", "immediate",
        "jitter", "human", "triggered",
    ],
    "process_lifetime": [
        "long-running", "uptime", "persistent", "ephemeral", "lifetime",
        "duration",
    ],
    "data_staging": [
        "staging", "temp file", "memory_only", "named pipe",
    ],
    "data_obfuscation": [
        "encrypt", "obfuscat", "plaintext", "xor", "string", "aes",
        "steganograph",
    ],
    "collection_strategy": [
        "collection", "bulk", "harvest", "incremental", "scraping",
        "piggyback",
    ],
    "target_scope": [
        "scope", "credential", "browser", "comprehensive", "financial",
    ],
    "execution": [
        "thread", "callback", "fiber", "sequential", "staged",
        "apc", "enumwindows",
    ],
    "anti_analysis": [
        "debug", "sandbox", "anti-vm", "analysis", "emulat",
    ],
    "anti_forensics": [
        "forensic", "self-delet", "timestomp", "log clear",
    ],
    "memory_residence": [
        "memory", "module stomp", "reflective", "phantom", "vad",
        "section", "rwx", "allocation", "virtual",
    ],
    "sleep_mode": [
        "sleep obfuscat", "ekko", "zilean", "foliage", "gargoyle",
        "death_sleep", "timer", "noaccess",
    ],
    "stack_presentation": [
        "stack", "spoof", "call stack", "return address", "frame",
        "unwind", "moonwalk",
    ],
    "injection_method": [
        "inject", "remote thread", "apc", "hollowing", "threadless",
        "doppel", "herpad", "phantom", "callback table",
    ],
    "network_stealth": [
        "ja3", "ja4", "tls fingerprint", "domain front",
        "dns-over-https", "doh",
    ],
    "kernel_evasion": [
        "driver", "byovd", "kernel", "ring-0", "vulnerable driver",
    ],
    "callback_evasion": [
        "callback", "minifilter", "object callback", "image load",
    ],
    "etw_kernel": [
        "etw", "trace", "provider", "session",
    ],
    "etw_method": [
        "etw", "patch", "hardware breakpoint", "hwbp",
    ],
    "process_protection": [
        "ppl", "protection", "elevat", "edr", "hide process",
    ],
}


def _guess_dims_from_detection(det, all_layers):
    """Guess which dims are relevant based on detection hint keywords and description."""
    hint = det.get("hint", "").lower()
    try:
        log_obj = json.loads(det["log"])
        desc = log_obj.get("DetectDescription", log_obj.get("description", "")).lower()
    except (json.JSONDecodeError, KeyError):
        desc = det["log"][:500].lower()

    text = f"{hint} {desc}"
    scores = {}
    for dim, keywords in DET_DIM_KEYWORDS.items():
        if dim not in all_layers:
            continue
        score = sum(1 for kw in keywords if kw in text)
        if score > 0:
            scores[dim] = score

    # Sort by score descending
    ranked = sorted(scores.keys(), key=lambda d: scores[d], reverse=True)
    return ranked


def _sort_options_by_risk(dim_info):
    """Sort options low-risk first for deterministic sweep."""
    risk_order = {"vlow": 0, "low": 1, "medium": 2, "high": 3}
    opts = list(dim_info["options"].items())
    opts.sort(key=lambda x: risk_order.get(x[1].get("risk", "medium"), 2))
    return [name for name, _ in opts]


def _build_config(all_layers, overrides, malware_type, last_clean=None):
    """Build a config with specific overrides applied."""
    config = {}
    for dim, info in all_layers.items():
        if dim in overrides:
            config[dim] = overrides[dim]
        elif last_clean and dim in last_clean:
            config[dim] = last_clean[dim]
        else:
            # Default: pick lowest-risk option
            opts = _sort_options_by_risk(info)
            config[dim] = opts[0] if opts else list(info["options"].keys())[0]
    config = apply_constraints(config, malware_type, protected=set(overrides.keys()))
    return config


def run_exam(malware_type, start_level=1, end_level=20, exam_name="A",
             batch_size=10, max_runs=500, **_kw):
    """Run exam with pure algorithmic solver.

    Strategy per level:
    Phase 1: Single-dim sweep on guessed dims (ordered by detection relevance)
    Phase 2: 2-dim combos on top guessed dims
    Phase 3: 3-dim combos (limited)
    Dead-end: track fully-explored dims, skip them on retry
    """
    behavioral = _is_behavioral_exam(exam_name)
    if behavioral:
        exam_info = BEHAVIORAL_EXAMS.get(exam_name.replace("_hard", ""), {})
        level_names = {i: f"Tier {i} detection" for i in range(1, 21)}
        levels = None
    else:
        levels = get_levels(malware_type, exam_name=exam_name)
        level_names = {l[0]: l[1] for l in levels}
        exam_info = None
    start_level = max(1, start_level)
    end_level = min(20, end_level)
    num_levels = end_level - start_level + 1
    safety_cap = max_runs

    exam_label = f" [Exam {exam_name}]" if exam_name != "A" else ""
    mode_label = "BEHAVIORAL" if behavioral else "IOA"
    desc = f" — {exam_info['description']}" if exam_info else ""
    print(f"\n{'='*74}")
    print(f"  CROWDSTRIKE FALCON {mode_label} EXAM — {malware_type.upper()}{exam_label}")
    if desc:
        print(f"  {desc}")
    print(f"  Levels {start_level}-{end_level} ({num_levels}) | Algo-only solver (no LLM)")
    print(f"{'='*74}\n")

    all_layers = get_all_layers(malware_type)
    total_combos = 1
    for info in all_layers.values():
        total_combos *= len(info["options"])
    print(f"  Search space: {total_combos:,} across {len(all_layers)} dims\n")

    level_results = {}
    current_level = start_level
    total_runs = 0
    last_clean_config = None

    while current_level <= end_level:
        level_name = level_names.get(current_level, f"Level {current_level}")
        level_passed = False
        level_start_runs = total_runs
        phase = 1  # 1=single-dim, 2=two-dim, 3=three-dim

        # Per-level tracking
        explored_dims = set()  # dims where we tried ALL values
        tried_configs = set()  # fingerprints of configs we already evaluated
        dim_tried_vals = {}    # dim → set of values tried at this level
        best_det_count = 999   # fewest detections seen (for progress tracking)
        best_config = None

        # Start from last clean or lowest-risk defaults
        base_overrides = {}
        if last_clean_config:
            base_overrides = dict(last_clean_config)

        print(f"  ╔══ Level {current_level}/{end_level}: {level_name}")

        while total_runs - level_start_runs < safety_cap:

            # ════════════════════════════════
            #  PHASE 1: Single-dim sweep
            # ════════════════════════════════
            if phase == 1:
                # Get current config and evaluate to find what's detected
                config = _build_config(all_layers, base_overrides, malware_type, last_clean_config)
                detections = evaluate_config(
                    config, malware_type, max_level=current_level, exam_name=exam_name)

                if not detections:
                    level_passed = True
                    break

                # Guess which dims are relevant
                guessed = _guess_dims_from_detection(detections[0], all_layers)
                # Also try all dims not yet explored
                all_dim_order = guessed + [d for d in all_layers if d not in guessed and d not in explored_dims]

                found_improvement = False
                for dim in all_dim_order:
                    if dim in explored_dims:
                        continue

                    opts = _sort_options_by_risk(all_layers[dim])
                    current_val = base_overrides.get(dim, config.get(dim))
                    dim_tried_vals.setdefault(dim, set())

                    tried_all = True
                    for val in opts:
                        if val == current_val:
                            continue
                        if val in dim_tried_vals[dim]:
                            continue

                        total_runs += 1
                        dim_tried_vals[dim].add(val)
                        test_overrides = dict(base_overrides)
                        test_overrides[dim] = val
                        test_config = _build_config(all_layers, test_overrides, malware_type, last_clean_config)

                        fp = tuple(sorted(test_config.items()))
                        if fp in tried_configs:
                            continue
                        tried_configs.add(fp)

                        test_dets = evaluate_config(
                            test_config, malware_type, max_level=current_level, exam_name=exam_name)

                        cfg_str = _display_config_compact(test_config, all_layers)

                        if not test_dets:
                            print(f"  ┌─ Run {total_runs:3d} [P1:{dim}={val}]  "
                                  f"Level {current_level}/{end_level}")
                            print(f"  │  Config: {cfg_str}")
                            print(f"  │  ✓ CLEAN through level {current_level}")
                            try:
                                recipe = config_to_recipe(test_config, malware_type)
                                print(f"  │  Recipe: {len(recipe.splitlines())} lines OK")
                            except Exception as e:
                                print(f"  │  Recipe error: {e}")
                            level_runs = total_runs - level_start_runs
                            print(f"  └─ ✓ Level {current_level} PASSED "
                                  f"(phase 1, {level_runs} runs)")
                            print()
                            config = test_config
                            level_passed = True
                            break

                        det = test_dets[0]
                        n_dets = len(test_dets)

                        # Check for regression
                        if det["level"] < current_level and last_clean_config:
                            # This change broke a previous level — skip it
                            print(f"  ┌─ Run {total_runs:3d} [P1:{dim}={val}]  "
                                  f"Level {current_level}/{end_level}")
                            print(f"  │  ✗ REGRESSION to L{det['level']} — skipping")
                            print()
                            continue

                        if n_dets < best_det_count:
                            best_det_count = n_dets
                            best_config = test_config.copy()
                            base_overrides[dim] = val
                            found_improvement = True
                            print(f"  ┌─ Run {total_runs:3d} [P1:{dim}={val}]  "
                                  f"Level {current_level}/{end_level}")
                            print(f"  │  ↓ {n_dets} det(s) — improvement! Locking {dim}={val}")
                            print()
                            break  # Re-evaluate from top with new base
                        else:
                            print(f"  ┌─ Run {total_runs:3d} [P1:{dim}={val}]  "
                                  f"Level {current_level}/{end_level}")
                            print(f"  │  ✗ {_format_detection_compact(det['log'], det['name'])}")
                            print()

                        tried_all = False

                    if level_passed:
                        break

                    # If we tried all values for this dim, mark it explored
                    remaining = [v for v in opts if v not in dim_tried_vals.get(dim, set())
                                 and v != current_val]
                    if not remaining:
                        explored_dims.add(dim)

                    if found_improvement:
                        break  # Go back to re-evaluate with updated base

                if level_passed:
                    break

                if not found_improvement:
                    # All single-dim sweeps exhausted for current detection
                    phase = 2
                    print(f"  ├─ Phase 1 exhausted ({len(explored_dims)} dims explored), "
                          f"trying 2-dim combos...")
                    print()

            # ════════════════════════════════
            #  PHASE 2: Two-dim combos
            # ════════════════════════════════
            elif phase == 2:
                config = _build_config(all_layers, base_overrides, malware_type, last_clean_config)
                detections = evaluate_config(
                    config, malware_type, max_level=current_level, exam_name=exam_name)
                if not detections:
                    level_passed = True
                    break

                guessed = _guess_dims_from_detection(detections[0], all_layers)
                # Try pairs: each guessed dim paired with every other dim
                candidate_dims = guessed[:6] + [d for d in all_layers if d not in guessed][:4]
                candidate_dims = [d for d in candidate_dims if d in all_layers]

                found_combo = False
                for d1, d2 in [(a, b) for a in candidate_dims for b in candidate_dims if a < b]:
                    opts1 = _sort_options_by_risk(all_layers[d1])[:4]
                    opts2 = _sort_options_by_risk(all_layers[d2])[:4]

                    for v1, v2 in product(opts1, opts2):
                        total_runs += 1
                        if total_runs - level_start_runs >= safety_cap:
                            break

                        test_overrides = dict(base_overrides)
                        test_overrides[d1] = v1
                        test_overrides[d2] = v2
                        test_config = _build_config(
                            all_layers, test_overrides, malware_type, last_clean_config)

                        fp = tuple(sorted(test_config.items()))
                        if fp in tried_configs:
                            continue
                        tried_configs.add(fp)

                        test_dets = evaluate_config(
                            test_config, malware_type, max_level=current_level, exam_name=exam_name)

                        if not test_dets:
                            cfg_str = _display_config_compact(test_config, all_layers)
                            level_runs = total_runs - level_start_runs
                            print(f"  ┌─ Run {total_runs:3d} [P2:{d1}+{d2}]  "
                                  f"Level {current_level}/{end_level}")
                            print(f"  │  Config: {cfg_str}")
                            print(f"  │  ✓ CLEAN through level {current_level}")
                            try:
                                recipe = config_to_recipe(test_config, malware_type)
                                print(f"  │  Recipe: {len(recipe.splitlines())} lines OK")
                            except Exception as e:
                                print(f"  │  Recipe error: {e}")
                            print(f"  └─ ✓ Level {current_level} PASSED "
                                  f"(phase 2, {level_runs} runs, combo {d1}+{d2})")
                            print()
                            config = test_config
                            base_overrides[d1] = v1
                            base_overrides[d2] = v2
                            level_passed = True
                            found_combo = True
                            break

                        n_dets = len(test_dets)
                        det = test_dets[0]
                        if det["level"] < current_level:
                            continue  # regression

                        if n_dets < best_det_count:
                            best_det_count = n_dets
                            base_overrides[d1] = v1
                            base_overrides[d2] = v2
                            found_combo = True
                            print(f"  ┌─ Run {total_runs:3d} [P2:{d1}+{d2}]  "
                                  f"↓ {n_dets} det(s) — improvement")
                            print()
                            break

                    if level_passed or found_combo:
                        break
                    if total_runs - level_start_runs >= safety_cap:
                        break

                if level_passed:
                    break

                if found_combo and not level_passed:
                    # Got improvement, go back to phase 1 with updated base
                    phase = 1
                    explored_dims.clear()
                    continue

                phase = 3
                print(f"  ├─ Phase 2 exhausted, trying 3-dim combos...")
                print()

            # ════════════════════════════════
            #  PHASE 3: Three-dim combos (limited)
            # ════════════════════════════════
            elif phase == 3:
                config = _build_config(all_layers, base_overrides, malware_type, last_clean_config)
                detections = evaluate_config(
                    config, malware_type, max_level=current_level, exam_name=exam_name)
                if not detections:
                    level_passed = True
                    break

                guessed = _guess_dims_from_detection(detections[0], all_layers)
                candidate_dims = (guessed[:4] +
                                  [d for d in all_layers if d not in guessed])[:8]
                candidate_dims = [d for d in candidate_dims if d in all_layers]

                for d1, d2, d3 in [(a, b, c) for a in candidate_dims
                                    for b in candidate_dims if b > a
                                    for c in candidate_dims if c > b]:
                    opts1 = _sort_options_by_risk(all_layers[d1])[:3]
                    opts2 = _sort_options_by_risk(all_layers[d2])[:3]
                    opts3 = _sort_options_by_risk(all_layers[d3])[:3]

                    for v1, v2, v3 in product(opts1, opts2, opts3):
                        total_runs += 1
                        if total_runs - level_start_runs >= safety_cap:
                            break

                        test_overrides = dict(base_overrides)
                        test_overrides[d1] = v1
                        test_overrides[d2] = v2
                        test_overrides[d3] = v3
                        test_config = _build_config(
                            all_layers, test_overrides, malware_type, last_clean_config)

                        fp = tuple(sorted(test_config.items()))
                        if fp in tried_configs:
                            continue
                        tried_configs.add(fp)

                        test_dets = evaluate_config(
                            test_config, malware_type, max_level=current_level, exam_name=exam_name)

                        if not test_dets:
                            cfg_str = _display_config_compact(test_config, all_layers)
                            level_runs = total_runs - level_start_runs
                            print(f"  ┌─ Run {total_runs:3d} [P3:{d1}+{d2}+{d3}]  "
                                  f"Level {current_level}/{end_level}")
                            print(f"  │  Config: {cfg_str}")
                            print(f"  │  ✓ CLEAN through level {current_level}")
                            try:
                                recipe = config_to_recipe(test_config, malware_type)
                                print(f"  │  Recipe: {len(recipe.splitlines())} lines OK")
                            except Exception as e:
                                print(f"  │  Recipe error: {e}")
                            print(f"  └─ ✓ Level {current_level} PASSED "
                                  f"(phase 3, {level_runs} runs)")
                            print()
                            config = test_config
                            level_passed = True
                            break

                    if level_passed:
                        break
                    if total_runs - level_start_runs >= safety_cap:
                        break

                if level_passed:
                    break

                # All phases exhausted
                break

        if level_passed:
            level_runs = total_runs - level_start_runs
            level_results[current_level] = {
                "runs": level_runs, "tier": f"P{phase}",
                "config": config.copy(),
            }
            last_clean_config = config.copy()
            current_level += 1
            continue

        level_runs = total_runs - level_start_runs
        print(f"  ╘═ Level {current_level} FAILED — {level_runs} runs across all phases")
        print()
        break

    # ── Report card ──
    passed = len(level_results)

    print(f"\n{'='*74}")
    print(f"  EXAM RESULTS — {malware_type.upper()}{exam_label} [ALGO-ONLY]")
    print(f"{'='*74}")
    print(f"  Levels passed: {passed}/{num_levels}")
    print(f"  Total runs: {total_runs}")
    print()
    print(f"  {'Level':>5}  {'Runs':>4}  {'Phase':>6}  Status")
    print(f"  {'─'*5}  {'─'*4}  {'─'*6}  {'─'*30}")
    for lvl in range(start_level, end_level + 1):
        if lvl in level_results:
            r = level_results[lvl]
            print(f"  {lvl:5d}  {r['runs']:4d}  {r['tier']:>6}  ✓ {level_names.get(lvl, f'Level {lvl}')}")
        elif lvl <= current_level:
            print(f"  {lvl:5d}     -       -  ✗ {level_names.get(lvl, f'Level {lvl}')} (failed)")
        else:
            print(f"  {lvl:5d}     -       -  · {level_names.get(lvl, f'Level {lvl}')} (not reached)")
    print(f"{'='*74}\n")

    return passed, total_runs, level_results


def run_all_exams(start_level=1, end_level=20, exam_name="A", batch_size=10,
                  max_runs=500):
    """Run exam for all 3 types."""
    results = {}
    num_levels = end_level - start_level + 1
    for mtype in ["infostealer", "keylogger", "backdoor"]:
        passed, runs, levels = run_exam(
            mtype, start_level=start_level, end_level=end_level,
            exam_name=exam_name, batch_size=batch_size, max_runs=max_runs,
        )
        results[mtype] = {"passed": passed, "runs": runs, "levels": levels}

    exam_label = f" [Exam {exam_name}]" if exam_name != "A" else ""
    print(f"\n{'='*74}")
    print(f"  GRAND SUMMARY — ALL TYPES{exam_label} [ALGO-ONLY]")
    print(f"{'='*74}")
    for mtype, res in results.items():
        print(f"  {mtype:12s}: {res['passed']:2d}/{num_levels} levels in {res['runs']:2d} runs")
    total_passed = sum(r["passed"] for r in results.values())
    total_possible = num_levels * 3
    print(f"\n  Total: {total_passed}/{total_possible} levels passed")
    print(f"{'='*74}")
    return results


if __name__ == "__main__":
    import argparse

    available_exams = list_exams()
    exam_list_str = "\n".join(f"    {name:8s} {desc}" for name, desc in available_exams)
    behavioral_list_str = "\n".join(
        f"    {name:8s} {info['description']}"
        for name, info in sorted(BEHAVIORAL_EXAMS.items())
    )

    p = argparse.ArgumentParser(
        description="CrowdStrike Falcon IOA Exam — pure algorithmic solver (no LLM)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Legacy exams:
{exam_list_str}

Behavioral exams (detection_model.py tiers):
{behavioral_list_str}

Examples:
  python3 %(prog)s --exam B1              # behavioral exam B1
  python3 %(prog)s --exam all_behavioral  # all behavioral exams
  python3 %(prog)s --exam A               # legacy exam A
""",
    )
    p.add_argument("--type", "-t", default=None,
                   choices=["infostealer", "keylogger", "backdoor"])
    p.add_argument("--exam", "-e", default="A")
    p.add_argument("--levels", "-n", type=int, default=20)
    p.add_argument("--start-level", "-s", type=int, default=1)
    p.add_argument("--max-runs", "-m", type=int, default=500,
                   help="Max runs per level before giving up (default: 500)")
    args = p.parse_args()

    end_level = min(args.start_level + args.levels - 1, 20)
    start_level = max(1, args.start_level)

    if args.exam.lower() == "all":
        exam_names = [name for name, _ in available_exams]
    elif args.exam.lower() == "all_hard":
        exam_names = [f"{name}_hard" for name, _ in available_exams]
    elif args.exam.lower() == "all_behavioral":
        exam_names = sorted(BEHAVIORAL_EXAMS.keys())
    elif args.exam.lower() == "all_behavioral_hard":
        exam_names = [f"{name}_hard" for name in sorted(BEHAVIORAL_EXAMS.keys())]
    else:
        exam_names = [args.exam]

    for exam_name in exam_names:
        print(f"\n{'#'*74}")
        print(f"  EXAM VARIANT: {exam_name} [ALGO-ONLY]")
        print(f"{'#'*74}")

        if args.type:
            run_exam(args.type, start_level=start_level, end_level=end_level,
                     exam_name=exam_name, max_runs=args.max_runs)
        else:
            run_all_exams(start_level=start_level, end_level=end_level,
                          exam_name=exam_name, max_runs=args.max_runs)
