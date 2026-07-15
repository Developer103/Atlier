#!/usr/bin/env python3
"""LLM reasoning test harness — does the model pick the right evasion dimensions?

Generates thousands of problems from the detection model, computes ground truth
by brute-force evaluation, then scores the LLM's suggestions.

Usage:
    python3 test_llm_reasoning.py --generate              # build problem set (fast, no LLM)
    python3 test_llm_reasoning.py --test [--batch N]       # run LLM on problems (slow)
    python3 test_llm_reasoning.py --report                 # summarize results
    python3 test_llm_reasoning.py --test --id 42           # test single problem
    python3 test_llm_reasoning.py --test --category combo  # test one category
"""
import argparse
import json
import os
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

from detection_model import detection_check
from evasion_selector import get_all_layers, apply_constraints
from exam_variants import get_exam, list_exams

PROBLEMS_FILE = "llm_reasoning_problems.jsonl"
RESULTS_FILE = "llm_reasoning_results.jsonl"


# ═══════════════════════════════════════════════════════════════════
#  Ground truth: brute-force what the optimal dim change is
# ═══════════════════════════════════════════════════════════════════

def compute_ground_truth(config, all_layers, malware_type, level, exam_name,
                         locked=None):
    """For each dimension, find the value that reduces alerts the most.

    Returns:
        current_alerts: int
        best_single: {dim: (best_val, new_alert_count, reduction)}
        best_pair: ((dim1, val1, dim2, val2), new_alert_count, reduction) or None
    """
    locked = locked or {}
    exam = get_exam(exam_name)

    current_dets = detection_check(config, level, exam)
    current_alerts = len(current_dets)

    if current_alerts == 0:
        return current_alerts, {}, None

    # Single-dim sweep
    best_single = {}
    for dim, info in all_layers.items():
        if dim in locked:
            continue
        original_val = config.get(dim)
        best_val = original_val
        best_count = current_alerts

        for val in info["options"]:
            if val == original_val:
                continue
            test_cfg = dict(config)
            test_cfg[dim] = val
            test_cfg = apply_constraints(test_cfg, malware_type,
                                         protected=set(locked.keys()))
            if test_cfg[dim] != val:
                continue
            count = len(detection_check(test_cfg, level, exam))
            if count < best_count:
                best_count = count
                best_val = val

        if best_val != original_val:
            reduction = current_alerts - best_count
            best_single[dim] = (best_val, best_count, reduction)

    # Best pair (2-opt) — only check dims that individually help or are in top detections
    best_pair = None
    candidate_dims = [d for d in best_single if best_single[d][2] > 0]
    # Also add dims that are stuck (no single improvement) but appear in detections
    det_dims = set()
    for det in current_dets:
        try:
            desc = json.loads(det[0]).get("DetectDescription", "").lower()
        except (json.JSONDecodeError, KeyError):
            desc = ""
        kw_map = {
            "process": ["process", "parent", "child", "ppid", "sideload"],
            "exfil": ["exfil", "network", "connection", "tcp", "http"],
            "persistence": ["persist", "registry", "startup", "scheduled"],
            "api_resolve": ["import", "api", "syscall", "ntdll", "hash"],
            "timing": ["sleep", "delay", "timing", "burst", "immediate"],
        }
        for dim, kws in kw_map.items():
            if any(kw in desc for kw in kws):
                det_dims.add(dim)
    candidate_dims = list(set(candidate_dims) | det_dims)

    if len(candidate_dims) >= 2 and current_alerts > 1:
        best_pair_count = current_alerts
        for i, d1 in enumerate(candidate_dims[:8]):
            if d1 in locked or d1 not in all_layers:
                continue
            for d2 in candidate_dims[i+1:8]:
                if d2 in locked or d2 not in all_layers:
                    continue
                for v1 in list(all_layers[d1]["options"])[:6]:
                    for v2 in list(all_layers[d2]["options"])[:6]:
                        test_cfg = dict(config)
                        test_cfg[d1] = v1
                        test_cfg[d2] = v2
                        test_cfg = apply_constraints(test_cfg, malware_type,
                                                     protected=set(locked.keys()))
                        if test_cfg[d1] != v1 or test_cfg[d2] != v2:
                            continue
                        count = len(detection_check(test_cfg, level, exam))
                        if count < best_pair_count:
                            best_pair_count = count
                            best_pair = ((d1, v1, d2, v2),
                                         best_pair_count,
                                         current_alerts - best_pair_count)

    return current_alerts, best_single, best_pair


# ═══════════════════════════════════════════════════════════════════
#  Problem generation
# ═══════════════════════════════════════════════════════════════════

def gen_random_config(all_layers, malware_type, rng):
    cfg = {}
    for dim, info in all_layers.items():
        opts = list(info["options"].keys())
        cfg[dim] = rng.choice(opts)
    return apply_constraints(cfg, malware_type)


MALWARE_TYPES = ["infostealer", "keylogger", "backdoor"]
EXAM_LEVELS = [5, 8, 10, 12, 14, 16, 18, 20]


def generate_exam_problems(all_layers_cache, rng):
    problems = []
    exam_names = [name for name, _ in list_exams()]
    for exam_name in exam_names:
        exam = get_exam(exam_name)
        golden = exam.get("golden_overrides", {}) if exam else {}
        for malware_type in MALWARE_TYPES:
            all_layers = all_layers_cache[malware_type]
            for level in EXAM_LEVELS:
                for seed in range(25):
                    cfg_rng = random.Random(
                        hash((exam_name, malware_type, level, seed)) & 0xFFFFFFFF)
                    cfg = gen_random_config(all_layers, malware_type, cfg_rng)
                    for dim, val in golden.items():
                        if dim in cfg:
                            cfg[dim] = val
                    dets = detection_check(cfg, level, exam)
                    if len(dets) == 0:
                        continue
                    problems.append({
                        "exam": exam_name, "type": malware_type,
                        "level": level, "seed": seed, "config": cfg,
                        "alert_count": len(dets), "locked": golden,
                        "category": "exam",
                    })
    return problems


def generate_combo_problems(all_layers_cache, rng):
    problems = []
    from detection_model import COMBO_DETECTIONS
    for malware_type in MALWARE_TYPES:
        all_layers = all_layers_cache[malware_type]
        for ci, combo in enumerate(COMBO_DETECTIONS):
            if combo["tier"] > 20:
                continue
            for seed in range(15):
                cfg_rng = random.Random(
                    hash(("combo", ci, malware_type, seed)) & 0xFFFFFFFF)
                cfg = gen_random_config(all_layers, malware_type, cfg_rng)
                for dim, val in combo["conditions"].items():
                    if dim in all_layers and val in all_layers[dim]["options"]:
                        cfg[dim] = val
                cfg = apply_constraints(cfg, malware_type,
                                        protected=set(combo["conditions"].keys()))
                level = max(combo["tier"], 15)
                dets = detection_check(cfg, level, get_exam("A"))
                if len(dets) == 0:
                    continue
                problems.append({
                    "exam": "A", "type": malware_type, "level": level,
                    "seed": seed, "config": cfg, "alert_count": len(dets),
                    "locked": {}, "category": "combo",
                    "combo_name": combo["detect_name"],
                    "combo_dims": dict(combo["conditions"]),
                })
    return problems


def generate_locked_problems(all_layers_cache, rng):
    problems = []
    exams_with_golden = []
    for name, desc in list_exams():
        exam = get_exam(name)
        if exam and exam.get("golden_overrides"):
            exams_with_golden.append((name, exam))
    for exam_name, exam in exams_with_golden:
        golden = exam["golden_overrides"]
        for malware_type in MALWARE_TYPES:
            all_layers = all_layers_cache[malware_type]
            for seed in range(25):
                cfg_rng = random.Random(
                    hash(("locked", exam_name, malware_type, seed)) & 0xFFFFFFFF)
                cfg = gen_random_config(all_layers, malware_type, cfg_rng)
                for dim, val in golden.items():
                    if dim in cfg:
                        cfg[dim] = val
                dets = detection_check(cfg, 20, exam)
                if len(dets) == 0:
                    continue
                problems.append({
                    "exam": exam_name, "type": malware_type, "level": 20,
                    "seed": seed, "config": cfg, "alert_count": len(dets),
                    "locked": golden, "category": "locked",
                })
    return problems


def generate_history_problems(all_layers_cache, rng):
    problems = []
    for malware_type in MALWARE_TYPES:
        all_layers = all_layers_cache[malware_type]
        for seed in range(50):
            cfg_rng = random.Random(
                hash(("history", malware_type, seed)) & 0xFFFFFFFF)
            cfg = gen_random_config(all_layers, malware_type, cfg_rng)
            dets = detection_check(cfg, 20, get_exam("A"))
            if len(dets) < 2:
                continue
            history = []
            tried_dims = cfg_rng.sample(
                [d for d in all_layers if d not in ["process", "exfil"]],
                min(4, len(all_layers) - 2))
            for hi, dim in enumerate(tried_dims):
                vals = cfg_rng.sample(list(all_layers[dim]["options"].keys()),
                                      min(2, len(all_layers[dim]["options"])))
                history.append({
                    "batch": hi + 1,
                    "changes": {dim: vals[0]},
                    "outcome": "no_improvement",
                    "best_alerts": len(dets),
                    "detection_names": [d[1] for d in dets[:2]],
                    "reasoning": f"Changed {dim} but detection persists",
                    "new_locks": {},
                })
            problems.append({
                "exam": "A", "type": malware_type, "level": 20,
                "seed": seed, "config": cfg, "alert_count": len(dets),
                "locked": {}, "category": "history",
                "strategy_history": history,
            })
    return problems


def generate_minimal_problems(all_layers_cache, rng):
    problems = []
    for malware_type in MALWARE_TYPES:
        all_layers = all_layers_cache[malware_type]
        for seed in range(400):
            cfg_rng = random.Random(
                hash(("minimal", malware_type, seed)) & 0xFFFFFFFF)
            cfg = gen_random_config(all_layers, malware_type, cfg_rng)
            for level in range(5, 21):
                dets = detection_check(cfg, level, get_exam("A"))
                if 1 <= len(dets) <= 2:
                    problems.append({
                        "exam": "A", "type": malware_type, "level": level,
                        "seed": seed, "config": cfg, "alert_count": len(dets),
                        "locked": {}, "category": "minimal",
                    })
                    break
    return problems


def generate_adversarial_problems(all_layers_cache, rng):
    problems = []
    exam_names = [name for name, _ in list_exams()]
    for malware_type in MALWARE_TYPES:
        all_layers = all_layers_cache[malware_type]
        for exam_name in exam_names:
            exam = get_exam(exam_name)
            if not exam:
                continue
            golden = exam.get("golden_overrides", {})
            for seed in range(25):
                cfg_rng = random.Random(
                    hash(("adversarial", exam_name, malware_type, seed)) & 0xFFFFFFFF)
                cfg = gen_random_config(all_layers, malware_type, cfg_rng)
                for dim, val in golden.items():
                    if dim in cfg:
                        cfg[dim] = val
                dets = detection_check(cfg, 20, exam)
                if len(dets) < 3:
                    continue
                _, best_single, best_pair = compute_ground_truth(
                    cfg, all_layers, malware_type, 20, exam_name, golden)
                single_can_solve = any(v[1] == 0 for v in best_single.values())
                pair_can_solve = best_pair and best_pair[1] == 0
                if not single_can_solve and pair_can_solve:
                    problems.append({
                        "exam": exam_name, "type": malware_type, "level": 20,
                        "seed": seed, "config": cfg, "alert_count": len(dets),
                        "locked": golden, "category": "adversarial",
                        "needs_pair": True,
                    })
                elif not single_can_solve and not pair_can_solve:
                    best_reduction = 0
                    if best_single:
                        best_reduction = max(v[2] for v in best_single.values())
                    if best_pair and best_pair[2] > best_reduction:
                        best_reduction = best_pair[2]
                    if best_reduction > 0:
                        problems.append({
                            "exam": exam_name, "type": malware_type, "level": 20,
                            "seed": seed, "config": cfg, "alert_count": len(dets),
                            "locked": golden, "category": "adversarial",
                            "needs_pair": False,
                            "best_possible_reduction": best_reduction,
                        })
    return problems


def generate_nightmare_cascade(all_layers_cache, rng):
    """Configs where the obvious single-dim fix introduces NEW detections."""
    problems = []
    exam_names = [name for name, _ in list_exams()]
    for malware_type in MALWARE_TYPES:
        all_layers = all_layers_cache[malware_type]
        for exam_name in exam_names:
            exam = get_exam(exam_name)
            if not exam:
                continue
            golden = exam.get("golden_overrides", {})
            for seed in range(20):
                cfg_rng = random.Random(
                    hash(("cascade", exam_name, malware_type, seed)) & 0xFFFFFFFF)
                cfg = gen_random_config(all_layers, malware_type, cfg_rng)
                for dim, val in golden.items():
                    if dim in cfg:
                        cfg[dim] = val
                for level in [18, 19, 20]:
                    dets = detection_check(cfg, level, exam)
                    if len(dets) < 3:
                        continue
                    current_names = {d[1] for d in dets}
                    found_cascade = False
                    for dim in all_layers:
                        if dim in golden:
                            continue
                        orig = cfg.get(dim)
                        for val in all_layers[dim]["options"]:
                            if val == orig:
                                continue
                            test = dict(cfg)
                            test[dim] = val
                            test = apply_constraints(test, malware_type,
                                                     protected=set(golden.keys()))
                            if test[dim] != val:
                                continue
                            new_dets = detection_check(test, level, exam)
                            new_names = {d[1] for d in new_dets}
                            added = new_names - current_names
                            removed = current_names - new_names
                            if len(added) >= 2 and len(removed) >= 1:
                                found_cascade = True
                                break
                        if found_cascade:
                            break
                    if found_cascade:
                        problems.append({
                            "exam": exam_name, "type": malware_type,
                            "level": level, "seed": seed, "config": cfg,
                            "alert_count": len(dets), "locked": golden,
                            "category": "nightmare_cascade",
                        })
                        break
    return problems


def generate_nightmare_multilocked(all_layers_cache, rng):
    """Heavy lock constraints: 5-8 locked dims at L20."""
    problems = []
    exams_with_golden = []
    for name, desc in list_exams():
        exam = get_exam(name)
        if exam and exam.get("golden_overrides"):
            exams_with_golden.append((name, exam))
    for exam_name, exam in exams_with_golden:
        golden = dict(exam["golden_overrides"])
        for malware_type in MALWARE_TYPES:
            all_layers = all_layers_cache[malware_type]
            unlockable = [d for d in all_layers if d not in golden]
            for seed in range(20):
                cfg_rng = random.Random(
                    hash(("multilocked", exam_name, malware_type, seed)) & 0xFFFFFFFF)
                cfg = gen_random_config(all_layers, malware_type, cfg_rng)
                for dim, val in golden.items():
                    if dim in cfg:
                        cfg[dim] = val
                extra_lock_count = min(
                    cfg_rng.randint(3, 6),
                    len(unlockable) - 3)
                if extra_lock_count <= 0:
                    continue
                extra_locked = cfg_rng.sample(unlockable, extra_lock_count)
                full_locked = dict(golden)
                for dim in extra_locked:
                    full_locked[dim] = cfg[dim]
                dets = detection_check(cfg, 20, exam)
                if len(dets) < 3:
                    continue
                free_dims = [d for d in all_layers if d not in full_locked]
                has_fix = False
                for dim in free_dims:
                    orig = cfg.get(dim)
                    for val in all_layers[dim]["options"]:
                        if val == orig:
                            continue
                        test = dict(cfg)
                        test[dim] = val
                        test = apply_constraints(test, malware_type,
                                                 protected=set(full_locked.keys()))
                        if test[dim] != val:
                            continue
                        if len(detection_check(test, 20, exam)) < len(dets):
                            has_fix = True
                            break
                    if has_fix:
                        break
                if not has_fix:
                    continue
                problems.append({
                    "exam": exam_name, "type": malware_type, "level": 20,
                    "seed": seed, "config": cfg, "alert_count": len(dets),
                    "locked": full_locked, "category": "nightmare_multilocked",
                })
    return problems


def generate_nightmare_history_trap(all_layers_cache, rng):
    """History includes the correct dim tried with wrong values."""
    problems = []
    for malware_type in MALWARE_TYPES:
        all_layers = all_layers_cache[malware_type]
        for seed in range(60):
            cfg_rng = random.Random(
                hash(("history_trap", malware_type, seed)) & 0xFFFFFFFF)
            cfg = gen_random_config(all_layers, malware_type, cfg_rng)
            dets = detection_check(cfg, 20, get_exam("A"))
            if len(dets) < 3:
                continue
            _, best_single, _ = compute_ground_truth(
                cfg, all_layers, malware_type, 20, "A", {})
            if not best_single:
                continue
            fix_dim = max(best_single, key=lambda d: best_single[d][2])
            fix_val = best_single[fix_dim][0]
            non_fix_vals = [v for v in all_layers[fix_dim]["options"]
                           if v != fix_val and v != cfg.get(fix_dim)]
            if len(non_fix_vals) < 2:
                continue
            wrong_dims = [d for d in all_layers
                          if d != fix_dim and d not in ["process", "exfil"]]
            history = []
            trap_vals = cfg_rng.sample(non_fix_vals, min(2, len(non_fix_vals)))
            for hi, wv in enumerate(trap_vals):
                history.append({
                    "batch": hi + 1,
                    "changes": {fix_dim: wv},
                    "outcome": "no_improvement",
                    "best_alerts": len(dets),
                    "detection_names": [d[1] for d in dets[:2]],
                    "reasoning": f"Changed {fix_dim}={wv} but detection persists",
                    "new_locks": {},
                })
            extra_wrong = cfg_rng.sample(wrong_dims,
                                         min(cfg_rng.randint(4, 8), len(wrong_dims)))
            for hi, dim in enumerate(extra_wrong):
                vals = list(all_layers[dim]["options"].keys())
                history.append({
                    "batch": len(history) + 1,
                    "changes": {dim: cfg_rng.choice(vals)},
                    "outcome": "no_improvement",
                    "best_alerts": len(dets),
                    "detection_names": [d[1] for d in dets[:2]],
                    "reasoning": f"Changed {dim} but no improvement",
                    "new_locks": {},
                })
            cfg_rng.shuffle(history)
            for hi, h in enumerate(history):
                h["batch"] = hi + 1
            problems.append({
                "exam": "A", "type": malware_type, "level": 20,
                "seed": seed, "config": cfg, "alert_count": len(dets),
                "locked": {}, "category": "nightmare_history_trap",
                "strategy_history": history,
            })
    return problems


def generate_nightmare_contradictory(all_layers_cache, rng):
    """Two detections where fixing one worsens the other."""
    problems = []
    exam_names = [name for name, _ in list_exams()]
    for malware_type in MALWARE_TYPES:
        all_layers = all_layers_cache[malware_type]
        for exam_name in exam_names:
            exam = get_exam(exam_name)
            if not exam:
                continue
            golden = exam.get("golden_overrides", {})
            for seed in range(15):
                cfg_rng = random.Random(
                    hash(("contradict", exam_name, malware_type, seed)) & 0xFFFFFFFF)
                cfg = gen_random_config(all_layers, malware_type, cfg_rng)
                for dim, val in golden.items():
                    if dim in cfg:
                        cfg[dim] = val
                for level in [18, 19, 20]:
                    dets = detection_check(cfg, level, exam)
                    if len(dets) < 4:
                        continue
                    det_names = [d[1] for d in dets]
                    found = False
                    for dim in all_layers:
                        if dim in golden:
                            continue
                        orig = cfg.get(dim)
                        for val in all_layers[dim]["options"]:
                            if val == orig:
                                continue
                            test = dict(cfg)
                            test[dim] = val
                            test = apply_constraints(test, malware_type,
                                                     protected=set(golden.keys()))
                            if test[dim] != val:
                                continue
                            new_dets = detection_check(test, level, exam)
                            new_names = [d[1] for d in new_dets]
                            removed = set(det_names) - set(new_names)
                            added = set(new_names) - set(det_names)
                            if len(removed) >= 1 and len(added) >= 1:
                                found = True
                                break
                        if found:
                            break
                    if found:
                        problems.append({
                            "exam": exam_name, "type": malware_type,
                            "level": level, "seed": seed, "config": cfg,
                            "alert_count": len(dets), "locked": golden,
                            "category": "nightmare_contradictory",
                        })
                        break
    return problems


ALL_CATEGORIES = [
    "exam", "combo", "locked", "history", "minimal", "adversarial",
    "nightmare_cascade", "nightmare_multilocked",
    "nightmare_history_trap", "nightmare_contradictory",
]


def classify_difficulty(prob):
    gt = prob["ground_truth"]
    alerts = gt["alerts"]
    best_single = gt["best_single"]
    best_pair = gt["best_pair"]
    locked = prob.get("locked", {})
    history = prob.get("strategy_history", [])
    category = prob.get("category", "")

    single_full_fix = any(
        v["new_alerts"] == 0 for v in best_single.values()) if best_single else False
    best_single_red = max(
        (v["reduction"] for v in best_single.values()), default=0
    ) if best_single else 0
    reduction_pct = best_single_red / alerts if alerts > 0 else 0

    # Nightmare: dedicated generators, adversarial pair-only, or extreme
    if category.startswith("nightmare"):
        return "nightmare"
    if category == "adversarial" and prob.get("needs_pair") and not single_full_fix:
        return "nightmare"
    if alerts >= 8 and best_single_red <= 1 and len(locked) >= 3:
        return "nightmare"
    if alerts >= 10 and reduction_pct < 0.2:
        return "nightmare"

    # Normal: low alerts OR strong single-dim reduction
    if alerts <= 3 and best_single_red >= 1:
        return "normal"
    if single_full_fix:
        return "normal"
    if reduction_pct >= 0.5 and alerts <= 6:
        return "normal"
    if alerts <= 2:
        return "normal"

    # Hard: everything in between
    return "hard"


def generate_all_problems():
    rng = random.Random(2026)

    print("Loading layers...")
    all_layers_cache = {}
    for t in MALWARE_TYPES:
        all_layers_cache[t] = get_all_layers(t)

    all_problems = []
    categories = {}

    generators = [
        ("exam", lambda: generate_exam_problems(all_layers_cache, rng)),
        ("combo", lambda: generate_combo_problems(all_layers_cache, rng)),
        ("locked", lambda: generate_locked_problems(all_layers_cache, rng)),
        ("history", lambda: generate_history_problems(all_layers_cache, rng)),
        ("minimal", lambda: generate_minimal_problems(all_layers_cache, rng)),
        ("adversarial", lambda: generate_adversarial_problems(all_layers_cache, rng)),
        ("nightmare_cascade", lambda: generate_nightmare_cascade(all_layers_cache, rng)),
        ("nightmare_multilocked", lambda: generate_nightmare_multilocked(all_layers_cache, rng)),
        ("nightmare_history_trap", lambda: generate_nightmare_history_trap(all_layers_cache, rng)),
        ("nightmare_contradictory", lambda: generate_nightmare_contradictory(all_layers_cache, rng)),
    ]

    for cat_name, gen_fn in generators:
        print(f"Generating {cat_name}...")
        probs = gen_fn()
        all_problems.extend(probs)
        categories[cat_name] = len(probs)
        print(f"  {cat_name}: {categories[cat_name]}")

    print(f"\nComputing ground truth for {len(all_problems)} problems...")
    t0 = time.time()
    for i, prob in enumerate(all_problems):
        if (i + 1) % 500 == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed
            eta = (len(all_problems) - i - 1) / rate
            print(f"  {i+1}/{len(all_problems)} ({rate:.0f}/s, ETA {eta:.0f}s)")

        malware_type = prob["type"]
        all_layers = all_layers_cache[malware_type]
        alerts, best_single, best_pair = compute_ground_truth(
            prob["config"], all_layers, malware_type,
            prob["level"], prob["exam"], prob.get("locked", {}))

        prob["ground_truth"] = {
            "alerts": alerts,
            "best_single": {
                dim: {"value": val, "new_alerts": cnt, "reduction": red}
                for dim, (val, cnt, red) in best_single.items()
            },
            "best_pair": None,
        }
        if best_pair:
            (d1, v1, d2, v2), cnt, red = best_pair
            prob["ground_truth"]["best_pair"] = {
                "dims": {d1: v1, d2: v2},
                "new_alerts": cnt,
                "reduction": red,
            }

        prob["difficulty"] = classify_difficulty(prob)
        prob["id"] = i

    elapsed = time.time() - t0
    print(f"  Done in {elapsed:.1f}s")

    valid = [p for p in all_problems
             if p["ground_truth"]["alerts"] > 0
             and (p["ground_truth"]["best_single"] or p["ground_truth"]["best_pair"])]

    print(f"\nFiltered: {len(all_problems)} -> {len(valid)} valid problems "
          f"({len(all_problems) - len(valid)} had no improvable config)")

    for i, p in enumerate(valid):
        p["id"] = i

    with open(PROBLEMS_FILE, "w") as f:
        for p in valid:
            f.write(json.dumps(p) + "\n")

    print(f"\nWrote {len(valid)} problems to {PROBLEMS_FILE}")
    print(f"\nBreakdown:")
    for cat in ALL_CATEGORIES:
        cat_probs = [p for p in valid if p["category"] == cat]
        if not cat_probs:
            continue
        by_diff = defaultdict(int)
        for p in cat_probs:
            by_diff[p["difficulty"]] += 1
        diff_str = ", ".join(f"{d}={c}" for d, c in sorted(by_diff.items()))
        print(f"  {cat:25s}: {len(cat_probs):5d}  ({diff_str})")

    by_diff_all = defaultdict(int)
    for p in valid:
        by_diff_all[p["difficulty"]] += 1
    diff_str = ", ".join(f"{d}={c}" for d, c in sorted(by_diff_all.items()))
    print(f"  {'TOTAL':25s}: {len(valid):5d}  ({diff_str})")


# ═══════════════════════════════════════════════════════════════════
#  LLM testing
# ═══════════════════════════════════════════════════════════════════

def build_prompt_for_problem(prob, all_layers):
    """Build the detection-centric prompt for a problem, same format as the solver.

    Creates a batch with ALL value variations per unlocked dimension so the
    correlation analysis always includes the fix value. ~167 configs total,
    but the prompt stays compact (bounded by 12 detections × 5 correlations).
    """
    config = prob["config"]
    level = prob["level"]
    exam = get_exam(prob["exam"])
    locked = prob.get("locked", {})
    history = prob.get("strategy_history", [])

    dets = detection_check(config, level, exam)
    batch = [(config, dets)]

    unlocked_dims = [d for d in all_layers if d not in locked]

    for dim in unlocked_dims:
        for val in all_layers[dim]["options"]:
            if val == config.get(dim):
                continue
            var = dict(config)
            var[dim] = val
            var = apply_constraints(var, prob["type"],
                                    protected=set(locked.keys()))
            if var[dim] != val:
                continue
            var_dets = detection_check(var, level, exam)
            batch.append((var, var_dets))

    return batch, history


def score_result(result, prob, all_layers):
    """Score an LLM result against ground truth.

    Returns:
        score: float 0-1
        grade: str (perfect/good/partial/neutral/bad/invalid)
        detail: str
    """
    gt = prob["ground_truth"]
    changes = result.get("changes", {})
    locked = prob.get("locked", {})

    if not changes:
        return 0.0, "invalid", "no changes suggested"

    # Check for locked dim violations
    for dim in changes:
        if dim in locked:
            return 0.0, "bad", f"changed locked dim {dim}"

    # Check validity
    for dim, val in changes.items():
        if dim not in all_layers:
            return 0.0, "invalid", f"unknown dim {dim}"
        if val not in all_layers[dim]["options"]:
            return 0.0, "invalid", f"unknown value {dim}={val}"

    # Apply the changes and evaluate
    test_cfg = dict(prob["config"])
    for dim, val in changes.items():
        test_cfg[dim] = val
    test_cfg = apply_constraints(test_cfg, prob["type"],
                                 protected=set(locked.keys()))

    exam = get_exam(prob["exam"])
    new_dets = detection_check(test_cfg, prob["level"], exam)
    new_alerts = len(new_dets)
    old_alerts = gt["alerts"]

    if new_alerts == 0:
        return 1.0, "perfect", f"{old_alerts}→0 alerts"

    if new_alerts < old_alerts:
        # Good — reduced alerts. Score by how close to optimal.
        best_possible = 0
        if gt["best_single"]:
            best_possible = max(best_possible,
                                max(v["reduction"] for v in gt["best_single"].values()))
        if gt["best_pair"]:
            best_possible = max(best_possible, gt["best_pair"]["reduction"])
        if best_possible == 0:
            best_possible = 1

        actual_reduction = old_alerts - new_alerts
        ratio = actual_reduction / best_possible
        if ratio >= 0.9:
            return ratio, "good", f"{old_alerts}→{new_alerts} ({actual_reduction}/{best_possible} reduction)"
        else:
            return ratio * 0.7, "partial", f"{old_alerts}→{new_alerts} ({actual_reduction}/{best_possible} reduction)"

    if new_alerts == old_alerts:
        return 0.1, "neutral", f"no change ({old_alerts} alerts)"

    return 0.0, "bad", f"increased {old_alerts}→{new_alerts}"


def test_problems(llm_url, batch_size=None, problem_id=None, category=None,
                  difficulty=None):
    """Run LLM on problems and score results."""
    from test_evasion_loop import _llm_strategy_call

    if not os.path.exists(PROBLEMS_FILE):
        print(f"No problems file. Run --generate first.")
        return

    # Load problems
    problems = []
    with open(PROBLEMS_FILE) as f:
        for line in f:
            problems.append(json.loads(line))
    print(f"Loaded {len(problems)} problems")

    # Load existing results
    done_ids = set()
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE) as f:
            for line in f:
                try:
                    r = json.loads(line)
                    done_ids.add(r["id"])
                except (json.JSONDecodeError, KeyError):
                    pass
        print(f"Already completed: {len(done_ids)}")

    # Filter
    if problem_id is not None:
        problems = [p for p in problems if p["id"] == problem_id]
    if category:
        problems = [p for p in problems if p["category"] == category]
    if difficulty:
        problems = [p for p in problems if p["difficulty"] == difficulty]

    # Skip already done
    remaining = [p for p in problems if p["id"] not in done_ids]
    if batch_size:
        remaining = remaining[:batch_size]

    if not remaining:
        print("No problems to test. Run --report to see results.")
        return

    print(f"Testing {len(remaining)} problems "
          f"(filtered from {len(problems)}, {len(done_ids)} already done)")

    # Load layers
    all_layers_cache = {}
    for t in ["infostealer", "keylogger", "backdoor"]:
        all_layers_cache[t] = get_all_layers(t)

    # ── Run ──
    results_f = open(RESULTS_FILE, "a")
    stats = defaultdict(int)
    total_time = 0

    for i, prob in enumerate(remaining):
        pid = prob["id"]
        cat = prob["category"]
        diff = prob["difficulty"]
        alerts = prob["ground_truth"]["alerts"]
        all_layers = all_layers_cache[prob["type"]]

        print(f"\n{'─'*70}")
        print(f"Problem {pid} [{cat}/{diff}] "
              f"Exam {prob['exam']} {prob['type']} L{prob['level']} "
              f"({alerts} alerts)")

        batch, history = build_prompt_for_problem(prob, all_layers)
        locked = prob.get("locked", {})

        t0 = time.time()
        try:
            result = _llm_strategy_call(
                llm_url, batch, all_layers, None,
                prob["level"], prob["type"], history, locked, 0,
                base_config=prob["config"])
            elapsed = time.time() - t0
            total_time += elapsed

            score, grade, detail = score_result(result, prob, all_layers)
            stats[grade] += 1

            print(f"  LLM response ({elapsed:.1f}s): {result['changes']}")
            print(f"  Score: {score:.2f} ({grade}) — {detail}")
            print(f"  Reasoning: {result.get('reasoning', '')[:200]}")

            # Show ground truth comparison
            gt = prob["ground_truth"]
            if gt["best_single"]:
                top_single = max(gt["best_single"].items(),
                                 key=lambda x: x[1]["reduction"])
                print(f"  Ground truth (best single): {top_single[0]}={top_single[1]['value']} "
                      f"({top_single[1]['reduction']} reduction)")
            if gt["best_pair"]:
                bp = gt["best_pair"]
                print(f"  Ground truth (best pair): {bp['dims']} "
                      f"({bp['reduction']} reduction)")

            record = {
                "id": pid,
                "category": cat,
                "difficulty": diff,
                "exam": prob["exam"],
                "type": prob["type"],
                "level": prob["level"],
                "alerts": alerts,
                "changes": result["changes"],
                "lock": result.get("lock", {}),
                "reasoning": result.get("reasoning", ""),
                "score": score,
                "grade": grade,
                "detail": detail,
                "elapsed": round(elapsed, 1),
            }

        except Exception as e:
            elapsed = time.time() - t0
            total_time += elapsed
            stats["error"] += 1
            print(f"  ERROR ({elapsed:.1f}s): {e}")
            record = {
                "id": pid,
                "category": cat,
                "difficulty": diff,
                "exam": prob["exam"],
                "type": prob["type"],
                "level": prob["level"],
                "alerts": alerts,
                "error": str(e),
                "score": 0.0,
                "grade": "error",
                "elapsed": round(elapsed, 1),
            }

        results_f.write(json.dumps(record) + "\n")
        results_f.flush()

        # Running stats
        tested = i + 1
        avg_time = total_time / tested
        remaining_count = len(remaining) - tested
        eta = remaining_count * avg_time
        pct_good = (stats.get("perfect", 0) + stats.get("good", 0)) / tested * 100

        print(f"  Progress: {tested}/{len(remaining)} | "
              f"Avg {avg_time:.0f}s | ETA {eta/60:.0f}m | "
              f"Pass rate: {pct_good:.0f}%")

    results_f.close()

    print(f"\n{'═'*70}")
    print(f"BATCH COMPLETE: {len(remaining)} problems in {total_time:.0f}s")
    print(f"  Avg time per problem: {total_time/max(len(remaining),1):.1f}s")
    for grade in ["perfect", "good", "partial", "neutral", "bad", "invalid", "error"]:
        if stats[grade] > 0:
            print(f"  {grade:10s}: {stats[grade]:4d} ({stats[grade]/len(remaining)*100:.0f}%)")


# ═══════════════════════════════════════════════════════════════════
#  Reporting
# ═══════════════════════════════════════════════════════════════════

def report():
    """Summarize test results."""
    if not os.path.exists(RESULTS_FILE):
        print("No results file. Run --test first.")
        return

    results = []
    with open(RESULTS_FILE) as f:
        for line in f:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    if not results:
        print("No results found.")
        return

    total = len(results)
    print(f"{'═'*70}")
    print(f"LLM REASONING TEST RESULTS — {total} problems")
    print(f"{'═'*70}\n")

    # Overall grades
    grades = defaultdict(int)
    for r in results:
        grades[r["grade"]] += 1

    pass_count = grades.get("perfect", 0) + grades.get("good", 0)
    partial_count = grades.get("partial", 0)
    fail_count = grades.get("neutral", 0) + grades.get("bad", 0) + grades.get("invalid", 0)
    error_count = grades.get("error", 0)

    print(f"OVERALL:")
    print(f"  Pass (perfect+good): {pass_count:4d} / {total} ({pass_count/total*100:.1f}%)")
    print(f"  Partial:             {partial_count:4d} / {total} ({partial_count/total*100:.1f}%)")
    print(f"  Fail:                {fail_count:4d} / {total} ({fail_count/total*100:.1f}%)")
    print(f"  Error:               {error_count:4d} / {total} ({error_count/total*100:.1f}%)")
    print(f"  Avg score:           {sum(r['score'] for r in results)/total:.3f}")

    avg_time = sum(r.get("elapsed", 0) for r in results) / total
    print(f"  Avg time:            {avg_time:.1f}s")

    # By category
    print(f"\nBY CATEGORY:")
    print(f"  {'Category':15s} {'Total':>5s} {'Pass':>5s} {'Rate':>6s} {'Avg Score':>9s}")
    print(f"  {'─'*45}")
    for cat in ALL_CATEGORIES:
        cat_results = [r for r in results if r["category"] == cat]
        if not cat_results:
            continue
        cat_pass = len([r for r in cat_results if r["grade"] in ("perfect", "good")])
        cat_score = sum(r["score"] for r in cat_results) / len(cat_results)
        print(f"  {cat:15s} {len(cat_results):5d} {cat_pass:5d} "
              f"{cat_pass/len(cat_results)*100:5.1f}% {cat_score:9.3f}")

    # By difficulty
    print(f"\nBY DIFFICULTY:")
    print(f"  {'Difficulty':15s} {'Total':>5s} {'Pass':>5s} {'Rate':>6s} {'Avg Score':>9s}")
    print(f"  {'─'*45}")
    for diff in ["normal", "hard", "nightmare"]:
        diff_results = [r for r in results if r["difficulty"] == diff]
        if not diff_results:
            continue
        diff_pass = len([r for r in diff_results if r["grade"] in ("perfect", "good")])
        diff_score = sum(r["score"] for r in diff_results) / len(diff_results)
        print(f"  {diff:15s} {len(diff_results):5d} {diff_pass:5d} "
              f"{diff_pass/len(diff_results)*100:5.1f}% {diff_score:9.3f}")

    # By exam (top/bottom 5)
    print(f"\nBY EXAM (top and bottom by pass rate, min 5 results):")
    exam_stats = {}
    for r in results:
        exam = r["exam"]
        exam_stats.setdefault(exam, {"total": 0, "pass": 0, "scores": []})
        exam_stats[exam]["total"] += 1
        if r["grade"] in ("perfect", "good"):
            exam_stats[exam]["pass"] += 1
        exam_stats[exam]["scores"].append(r["score"])

    exam_ranked = [(name, s["pass"]/s["total"], s)
                   for name, s in exam_stats.items()
                   if s["total"] >= 5]
    exam_ranked.sort(key=lambda x: -x[1])

    if exam_ranked:
        print(f"  {'Exam':>6s} {'Total':>5s} {'Pass':>5s} {'Rate':>6s} {'Avg':>6s}")
        print(f"  {'─'*35}")
        for name, rate, s in exam_ranked[:5]:
            avg = sum(s["scores"]) / len(s["scores"])
            print(f"  {name:>6s} {s['total']:5d} {s['pass']:5d} {rate*100:5.1f}% {avg:6.3f}")
        if len(exam_ranked) > 10:
            print(f"  {'...':>6s}")
        for name, rate, s in exam_ranked[-5:]:
            avg = sum(s["scores"]) / len(s["scores"])
            print(f"  {name:>6s} {s['total']:5d} {s['pass']:5d} {rate*100:5.1f}% {avg:6.3f}")

    # Failure analysis
    failures = [r for r in results if r["grade"] in ("bad", "neutral", "invalid")]
    if failures:
        print(f"\nFAILURE ANALYSIS ({len(failures)} failures):")
        reason_counts = defaultdict(int)
        for r in failures:
            reason_counts[r["detail"]] += 1
        for reason, count in sorted(reason_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {count:4d}x  {reason}")

    # Grade distribution
    print(f"\nGRADE DISTRIBUTION:")
    for grade in ["perfect", "good", "partial", "neutral", "bad", "invalid", "error"]:
        count = grades.get(grade, 0)
        bar = "█" * (count * 40 // max(total, 1))
        print(f"  {grade:10s} {count:4d} {bar} {count/total*100:.1f}%")

    print()


# ═══════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="LLM reasoning test harness")
    parser.add_argument("--generate", action="store_true",
                        help="Generate problem set (fast, no LLM)")
    parser.add_argument("--test", action="store_true",
                        help="Run LLM on problems")
    parser.add_argument("--report", action="store_true",
                        help="Summarize results")
    parser.add_argument("--batch", type=int, default=None,
                        help="Number of problems to test")
    parser.add_argument("--id", type=int, default=None,
                        help="Test single problem by ID")
    parser.add_argument("--category", type=str, default=None,
                        choices=ALL_CATEGORIES,
                        help="Test only one category")
    parser.add_argument("--difficulty", type=str, default=None,
                        choices=["normal", "hard", "nightmare"],
                        help="Test only one difficulty")
    parser.add_argument("--llm-url", type=str,
                        default="http://localhost:11235",
                        help="LLM API endpoint")
    parser.add_argument("--reset", action="store_true",
                        help="Delete existing results and start fresh")

    args = parser.parse_args()

    if args.reset and os.path.exists(RESULTS_FILE):
        os.remove(RESULTS_FILE)
        print(f"Deleted {RESULTS_FILE}")

    if args.generate:
        generate_all_problems()
    elif args.test:
        test_problems(args.llm_url, batch_size=args.batch,
                      problem_id=args.id, category=args.category,
                      difficulty=args.difficulty)
    elif args.report:
        report()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
