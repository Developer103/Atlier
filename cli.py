"""
CLI entry point for the malware generation framework.

Subcommands:
  generate     — Generate malware source code from a target spec (no VM needed)
  verify       — Verify already-generated source against a running VM
  run          — Full pipeline: generate → provision → verify → loop
  analyze      — Run DB queries and show context without generation

Usage:
  python -m malware_gen_framework generate --spec target.yaml --output ./results
  python -m malware_gen_framework run --spec target.yaml --max-iterations 5
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from .target_spec import OSPlatform, TargetEnvironmentSpec
from .pipeline import MalwarePipeline, PipelineResult
from .config_models import VMProvisionConfig, TargetOS
from .debug_logger import DebugLogger


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

async def cmd_generate(args) -> int:
    """Generate malware source code from a target spec."""
    debug = DebugLogger(enabled=getattr(args, "debug", False))
    pipeline = MalwarePipeline(
        generate=True, provision_vm=False, verify=False, retry_loop=False, debug=debug,
    )

    overrides = {}
    if getattr(args, "malware_type", None):
        overrides["malware_type"] = args.malware_type

    result = await pipeline.run(
        spec_path=args.spec,
        output_dir=args.output,
        **overrides,
    )

    print(result.print_summary())
    return 0


async def cmd_verify(args) -> int:
    """Verify already-generated source against a provisioned VM."""
    debug = DebugLogger(enabled=getattr(args, "debug", False))

    pipeline = MalwarePipeline(
        generate=False,
        provision_vm=True,
        verify=True,
        retry_loop=bool(getattr(args, "loop", False)),
        max_iterations=getattr(args, "max_iters", 5),
        debug=debug,
    )

    source_path = Path(args.source or "/tmp/malware_source.c")
    if not source_path.exists():
        print(f"Error: source file not found: {source_path}")
        return 1

    result = await pipeline.run(
        spec_path=args.spec,
        output_dir=getattr(args, "output", None),
    )

    print(result.print_summary())
    if result.loop_result:
        print("\n" + result.loop_result.summary())

    return 0


async def cmd_run(args) -> int:
    """Full pipeline: spec → generate → provision → verify → loop."""
    debug = DebugLogger(enabled=getattr(args, "debug", False))
    pipeline = MalwarePipeline(
        generate=True,
        provision_vm=True,
        verify=True,
        retry_loop=args.loop or args.exhaustive,
        max_iterations=getattr(args, "max_iters", 5),
        min_iterations=getattr(args, "min_iters", 1),
        exhaustive_mode=bool(getattr(args, "exhaustive", False)),
        debug=debug,
    )

    overrides = {}
    if getattr(args, "malware_type", None):
        overrides["malware_type"] = args.malware_type

    result = await pipeline.run(
        spec_path=args.spec,
        output_dir=args.output,
        **overrides,
    )

    print(result.print_summary())
    if result.loop_result:
        print("\n" + result.loop_result.summary())

    return 0


async def cmd_analyze(args) -> int:
    """Run DB queries and show the context without generating code."""
    debug = DebugLogger(enabled=getattr(args, "debug", False))
    from .spec_parser import parse_target_spec
    from .db_query_engine import DBQueryEngine
    from .context_builder import ContextBuilder

    overrides = {}
    if getattr(args, "malware_type", None):
        overrides["malware_type"] = args.malware_type

    target_spec = parse_target_spec(spec_path=args.spec, **overrides)
    db = DBQueryEngine()
    cb = ContextBuilder()

    query_result = db.query_all(
        f"{target_spec.os_platform.value} {target_spec.os_version}",
        n_results=getattr(args, "db_n", 10),
    )

    context = cb.build_context(query_result, target_spec)

    print(f"Target: {context.target_summary}")
    print(f"\nRanked techniques ({len(context.techniques)}):")
    for t in context.techniques:
        print(f"  [{t.rank_score:.1f}] {t.technique.name} (det={t.technique.detection_rating})")

    print(f"\nRanked PoCs ({len(context.pocs)}):")
    for p in context.pocs:
        print(f"  [{p.rank_score:.1f}] {p.poc.title} ({p.poc.cve})")

    return 0


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="malware_gen_framework",
        description="Malware-on-demand framework — generate undetectable malware for target environments",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--debug", action="store_true", help="Real-time pipeline debugging mode (step-by-step trace)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # -- generate -----------------------------------------------------------
    gen_parser = subparsers.add_parser("generate", help="Generate malware source code")
    gen_parser.add_argument("--spec", required=True, help="Path to target spec (YAML/JSON)")
    gen_parser.add_argument("--output", "-o", help="Output directory for generated files")
    gen_parser.add_argument(
        "--malware-type",
        default=None,
        help="Freeform description of malware behaviour (e.g. \"info stealer\", \"ransomware\"); overrides spec.yaml if set",
    )

    # -- verify -------------------------------------------------------------
    ver_parser = subparsers.add_parser("verify", help="Verify malware in a VM")
    ver_parser.add_argument("--spec", required=True, help="Path to target spec")
    ver_parser.add_argument("--source", "-s", help="Path to source code file (default: /tmp/malware_source.c)")
    ver_parser.add_argument("--os", choices=["linux", "windows"], default="linux")
    ver_parser.add_argument("--loop", action="store_true", help="Enable retry loop after first verification")

    # -- run ----------------------------------------------------------------
    run_parser = subparsers.add_parser("run", help="Full pipeline: generate → provision → verify → loop")
    run_parser.add_argument("--spec", required=True, help="Path to target spec (YAML/JSON)")
    run_parser.add_argument("--output", "-o", help="Output directory")
    run_parser.add_argument(
        "--malware-type",
        default=None,
        help="Freeform description of malware behaviour (e.g. \"info stealer\", \"ransomware\"); overrides spec.yaml if set",
    )
    run_parser.add_argument("--max-iters", type=int, default=5)
    run_parser.add_argument("--min-iters", type=int, default=1)
    run_parser.add_argument("--exhaustive", action="store_true", help="Run until all techniques exhausted")
    run_parser.add_argument("--loop", action="store_true", help="Enable retry loop")

    # -- analyze ------------------------------------------------------------
    ana_parser = subparsers.add_parser("analyze", help="Query DBs and show context without generating code")
    ana_parser.add_argument("--spec", required=True, help="Path to target spec")
    ana_parser.add_argument("--db-n", type=int, default=10, help="Number of results per DB query")
    ana_parser.add_argument(
        "--malware-type",
        default=None,
        help="Freeform description of malware behaviour (e.g. \"info stealer\", \"ransomware\"); overrides spec.yaml if set",
    )

    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    _setup_logging(args.verbose)

    command_map = {
        "generate": cmd_generate,
        "verify": cmd_verify,
        "run": cmd_run,
        "analyze": cmd_analyze,
    }

    handler = command_map.get(args.command)
    if not handler:
        parser.print_help()
        sys.exit(1)

    try:
        exit_code = asyncio.run(handler(args))
        sys.exit(exit_code or 0)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except Exception as e:
        logging.error("Pipeline error: %s", e, exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
