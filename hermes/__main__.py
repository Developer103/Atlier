"""CLI entry point for Hermes orchestrator.

Usage:
    python -m hermes --target-edr crowdstrike --malware-type infostealer
    python -m hermes --mode validate --target-edr crowdstrike
    python -m hermes --mode evade --target-edr crowdstrike --recipes infostealer_full,keylogger
"""

import argparse
import asyncio
import json
import logging
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Hermes — AI-driven malware campaign orchestrator"
    )
    parser.add_argument("--mode", default="campaign",
                        choices=["campaign", "validate", "evade"],
                        help="Mode: campaign (default), validate (test proven recipes), evade (mutate until evasion)")
    parser.add_argument("--target-edr", default="none",
                        choices=["crowdstrike", "defender", "elastic", "none"],
                        help="Target EDR (default: none)")
    parser.add_argument("--target-os", default="windows11",
                        help="Target OS (default: windows11)")
    parser.add_argument("--malware-type", default="infostealer",
                        choices=["infostealer", "keylogger", "backdoor"],
                        help="Malware type (default: infostealer)")
    parser.add_argument("--format", default="auto",
                        choices=["auto", "pe", "c", "jscript", "vbscript", "batch"],
                        help="Force output format (default: auto)")
    parser.add_argument("--max-rounds", type=int, default=50,
                        help="Maximum rounds (default: 50)")
    parser.add_argument("--blind", action="store_true",
                        help="Blind mode: strip all prior knowledge and proven recipes")
    parser.add_argument("--variants", type=int, default=1,
                        help="Number of randomized variants to build per recipe (1-10)")
    parser.add_argument("--llm-model", default=None,
                        help="LLM model name override")
    parser.add_argument("--innovation-threshold", type=int, default=100,
                        help="Consecutive failures before innovation mode (default: 100)")
    parser.add_argument("--recipes", default=None,
                        help="Comma-separated recipe names (for validate/evade modes)")
    parser.add_argument("--network", default="nat",
                        help="Network config (default: nat)")
    parser.add_argument("--llm-url", default=None,
                        help="LLM API URL override")
    parser.add_argument("--engine", default="agent",
                        choices=["agent", "legacy"],
                        help="Engine: agent (Hermes agent framework, default) or legacy (hand-rolled loop)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose logging")
    parser.add_argument("--json-output", action="store_true",
                        help="Output result as JSON")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    recipe_list = [r.strip() for r in args.recipes.split(",") if r.strip()] if args.recipes else None

    if args.mode == "evade" and not recipe_list:
        print("ERROR: --recipes required for evade mode", file=sys.stderr)
        sys.exit(1)

    target_spec = {
        "os": args.target_os,
        "edr": args.target_edr,
        "malware_type": args.malware_type,
        "network": args.network,
    }
    if args.format != "auto":
        target_spec["preferred_format"] = args.format

    config_overrides = {
        "max_rounds": args.max_rounds,
        "innovation_threshold": args.innovation_threshold,
    }
    if args.llm_url:
        config_overrides["llm_url"] = args.llm_url
    if args.llm_model:
        config_overrides["llm_model"] = args.llm_model
    if args.blind:
        config_overrides["blind_mode"] = True
    if args.variants > 1:
        config_overrides["variant_count"] = args.variants

    def on_progress(event_type, data):
        if event_type == "round_start":
            print(f"\n{'='*60}")
            print(f"Round {data['round']}/{data['max_rounds']}")
            print(f"{'='*60}")
        elif event_type == "reasoning":
            print(f"\nHermes: {data['text'][:500]}")
        elif event_type == "tool_call":
            print(f"\n  -> {data['name']}({json.dumps(data.get('args', {}))[:80]})")
        elif event_type == "tool_result":
            preview = data["result"][:200]
            print(f"  <- {preview}")
        elif event_type == "package_created":
            print(f"\n  Package: {data['path']}")
            print(f"  Deploy:  cd {data['path']} && ./deploy.sh")
        elif event_type == "campaign_success":
            print(f"\n{'='*60}")
            print(f"Campaign SUCCESS in round {data['round']}")
            print(f"{'='*60}")
        elif event_type == "session_complete":
            print(f"\n{'='*60}")
            print(f"Session complete: {data['status']} in {data['rounds']} rounds")
            print(f"{'='*60}")
        elif event_type == "validation_start":
            print(f"\n{'='*60}")
            print(f"Validation: testing {data['total']} proven recipes")
            print(f"{'='*60}")
        elif event_type == "validation_progress":
            print(f"\n[{data['current']}/{data['total']}] {data['recipe']} ({data['format']})")
        elif event_type == "validation_complete":
            print(f"\n{'='*60}")
            print(f"Validation complete: {data['still_pass']}/{data['total_tested']} still pass, "
                  f"{data['newly_failed']} newly failed")
            print(f"{'='*60}")

    if args.engine == "agent" and args.mode == "campaign":
        from .hermes_agent_bridge import launch_campaign
        result = launch_campaign(
            target_spec,
            config_overrides,
            max_rounds=args.max_rounds,
            on_progress=on_progress,
        )
    else:
        from .orchestrator import Hermes
        hermes = Hermes(target_spec, config_overrides)
        hermes.on_progress(on_progress)

        if args.mode == "validate":
            result = asyncio.run(hermes.run_validation(recipe_list))
        elif args.mode == "evade":
            result = asyncio.run(hermes.run_evade(recipe_list, max_rounds=args.max_rounds))
        else:
            result = asyncio.run(hermes.run())

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        if args.mode == "validate":
            s = result.get("summary", {})
            print(f"\nValidation: {s.get('still_pass', 0)}/{s.get('total_tested', 0)} still pass")
            if result.get("detected"):
                print("\nNewly detected recipes:")
                for d in result["detected"]:
                    print(f"  - {d['recipe']}: {d['verdict']}")
            if result.get("still_working"):
                print(f"\nStill working: {', '.join(result['still_working'])}")
        else:
            print(f"\nResult: {result.get('status', 'unknown')}")
            if result.get("error"):
                print(f"Error: {result['error']}")


if __name__ == "__main__":
    main()
