"""Bridge between malware campaign tools and the Hermes agent framework.

Registers all malware campaign tools with Hermes agent's ToolRegistry so
the full AIAgent conversation loop (compaction, empty-response recovery,
context management) handles the LLM interaction instead of our hand-rolled
orchestrator loop.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

from .config import get_config
from .prompts import (
    SYSTEM_PROMPT, SYSTEM_PROMPT_BLIND, OPERATIONAL_KNOWLEDGE,
    TOOL_DEFINITIONS, INNOVATION_TOOL_DEFINITIONS,
)
from .tools import ToolExecutor

logger = logging.getLogger(__name__)

TOOLSET_NAME = "malware_campaign"

# Map tool names to ToolExecutor method names
_TOOL_METHOD_MAP = {
    "scan_target": "tool_scan_target",
    "list_edr_events": "tool_list_edr_events",
    "list_recipes": "tool_list_recipes",
    "recipe_status": "tool_recipe_status",
    "list_chunks": "tool_list_chunks",
    "get_strategy": "tool_get_strategy",
    "query_corpus": "tool_query_corpus",
    "query_knowledge": "tool_query_knowledge",
    "sweep_matrix": "tool_sweep_matrix",
    "analyze_detection": "tool_analyze_detection",
    "assemble": "tool_assemble",
    "create_recipe": "tool_create_recipe",
    "mutate_recipe": "tool_mutate_recipe",
    "deploy_to_vm": "tool_deploy_to_vm",
    "read_file": "tool_read_file",
    "start_c2_listener": "tool_start_c2_listener",
    "execute_on_vm": "tool_execute_on_vm",
    "check_c2_data": "tool_check_c2_data",
    "analyze_results": "tool_analyze_results",
    "cleanup_vm": "tool_cleanup_vm",
    "write_experimental_code": "tool_write_experimental_code",
    "compile_experimental": "tool_compile_experimental",
    "save_innovation_report": "tool_save_innovation_report",
}


_shared_loop = None
_shared_loop_thread = None


def _get_shared_loop():
    """Get a persistent background event loop for running async tool handlers."""
    global _shared_loop, _shared_loop_thread
    if _shared_loop is None or _shared_loop.is_closed():
        import threading
        _shared_loop = asyncio.new_event_loop()
        _shared_loop_thread = threading.Thread(
            target=_shared_loop.run_forever, daemon=True
        )
        _shared_loop_thread.start()
    return _shared_loop


def _make_handler(tool_executor: ToolExecutor, tool_name: str):
    """Create a sync handler wrapper that routes through execute() for epoch tracking."""

    def handler(args, **kw):
        try:
            asyncio.get_running_loop()
            loop = _get_shared_loop()
            future = asyncio.run_coroutine_threadsafe(
                tool_executor.execute(tool_name, args), loop)
            return future.result(timeout=300)
        except RuntimeError:
            return asyncio.run(tool_executor.execute(tool_name, args))

    return handler


def register_tools(tool_executor: ToolExecutor):
    """Register all malware campaign tools with Hermes agent's ToolRegistry."""
    hermes_agent_path = Path.home() / ".hermes" / "hermes-agent"
    if str(hermes_agent_path) not in sys.path:
        sys.path.insert(0, str(hermes_agent_path))

    from tools.registry import registry

    all_defs = TOOL_DEFINITIONS + INNOVATION_TOOL_DEFINITIONS
    for tool_def in all_defs:
        fn_def = tool_def.get("function", tool_def)
        name = fn_def["name"]

        method_name = _TOOL_METHOD_MAP.get(name)
        if not method_name or not hasattr(tool_executor, method_name):
            logger.warning("No handler for tool %s (method %s) — skipping", name, method_name)
            continue

        schema = {
            "name": name,
            "description": fn_def.get("description", ""),
            "parameters": fn_def.get("parameters", {"type": "object", "properties": {}}),
        }

        registry.register(
            name=name,
            toolset=TOOLSET_NAME,
            schema=schema,
            handler=_make_handler(tool_executor, name),
            is_async=False,
            emoji="",
            override=True,
        )

    logger.info("Registered %d malware campaign tools with Hermes agent", len(_TOOL_METHOD_MAP))


def build_system_prompt_for_agent(target: dict, knowledge_md: str = "",
                                  config: dict | None = None) -> str:
    """Build the full system prompt including operational knowledge."""
    blind_mode = (config or {}).get("blind_mode", False)
    if blind_mode:
        parts = [SYSTEM_PROMPT_BLIND]
    else:
        parts = [SYSTEM_PROMPT]
        parts.append(OPERATIONAL_KNOWLEDGE)

        if knowledge_md:
            lines = knowledge_md.split("\n")
            summary_lines = []
            for line in lines[:200]:
                if line.startswith("##") or line.startswith("- ") or "REQUIRED" in line.upper() or "PROVEN" in line.upper():
                    summary_lines.append(line)
            if summary_lines:
                parts.append(
                    "\n## Knowledge Summary (use query_knowledge tool for full details)\n"
                    + "\n".join(summary_lines[:50])
                )

    edr = target.get("edr", "none")
    malware_type = target.get("malware_type", "infostealer")
    preferred_format = target.get("preferred_format", "")
    variant_count = (config or {}).get("variant_count", 1)
    mission = (
        f"\n## Current Mission\n"
        f"- Target EDR: {edr}\n"
        f"- Malware type: {malware_type}\n"
        f"- Target OS: {target.get('os', 'windows11')}\n"
        f"- Network: {target.get('network', 'nat')}\n"
    )
    if not blind_mode:
        mission += "- Use query_knowledge tool for detailed evasion strategies and proven recipes\n"
    if preferred_format and preferred_format != "auto":
        mission += (
            f"- **REQUIRED format: {preferred_format}** — the user explicitly selected this format. "
            f"Use {preferred_format} recipes ONLY. Do NOT switch to another format.\n"
        )
    if variant_count > 1:
        mission += (
            f"- Variant count: {variant_count} — when calling assemble, pass count={variant_count} "
            f"to build {variant_count} randomized variants. Deploy and test each one.\n"
        )
    parts.append(mission)

    if blind_mode:
        from hermes.prompts import BLIND_TYPE_HINTS, BLIND_FORMAT_HINTS
        type_hint = BLIND_TYPE_HINTS.get(malware_type, "")
        if type_hint:
            parts.append(type_hint)
        fmt_hint = BLIND_FORMAT_HINTS.get(preferred_format, "")
        if fmt_hint:
            parts.append(fmt_hint)

    # Add quick reference for valid chunk names
    from hermes.prompts import _load_quick_reference
    quick_ref = _load_quick_reference()
    if quick_ref:
        parts.append(f"## Quick Reference (valid chunk names)\n{quick_ref}")

    # Add custom instructions from user
    custom_instructions = (config or {}).get("custom_instructions", "")
    if custom_instructions:
        parts.append(f"## User Custom Instructions\n{custom_instructions}")

    return "\n\n".join(parts)


def _detect_context_length(config: dict) -> int:
    """Detect the actual model context length from lms CLI or config."""
    import subprocess
    try:
        out = subprocess.run(
            ["lms", "ps"], capture_output=True, text=True, timeout=5,
        ).stdout
        for line in out.splitlines():
            if config["llm_model"] in line or (
                "IDLE" in line or "PROCESSING" in line
            ):
                parts = line.split()
                for i, p in enumerate(parts):
                    if p.isdigit() and int(p) >= 1024 and i > 2:
                        ctx = int(p)
                        logger.info("Detected context length from lms ps: %d", ctx)
                        return ctx
    except Exception:
        pass
    ctx = config.get("llm_context_tokens", 65000)
    logger.info("Using config context length: %d", ctx)
    return ctx


def _ensure_hermes_path():
    hermes_agent_path = Path.home() / ".hermes" / "hermes-agent"
    if str(hermes_agent_path) not in sys.path:
        sys.path.insert(0, str(hermes_agent_path))


def _build_initial_message(target_spec: dict) -> str:
    return (
        f"Begin campaign against {target_spec.get('edr', 'none')} EDR.\n"
        f"- Malware type: {target_spec['malware_type']}\n"
        f"- Target OS: {target_spec.get('os', 'windows11')}\n"
        f"- Network: {target_spec.get('network', 'nat')}\n\n"
        f"Start with reconnaissance, then plan and execute. "
        f"Use your tools to accomplish the mission."
    )


def make_agent(target_spec: dict, config_overrides: dict | None = None,
               max_rounds: int = 999999, event_callback=None):
    """Create an AIAgent wired with malware campaign tools.

    Returns (agent, tool_executor, config) tuple. The agent is ready for
    run_conversation() or can be used by the web UI with callbacks.
    The returned config has resolved llm_url and llm_model (auto-selected
    from the running server, not the stale default).
    """
    _ensure_hermes_path()
    from run_agent import AIAgent

    config = get_config(config_overrides)
    logger.info("make_agent config_overrides=%s → llm_url=%s, llm_model=%s",
                config_overrides, config["llm_url"], config["llm_model"])
    config["edr"] = target_spec.get("edr", "none")
    config["_target_malware_type"] = target_spec.get("malware_type", "")
    config["_target_format"] = target_spec.get("preferred_format", "")

    import httpx

    preferred_model = config["llm_model"]

    knowledge_md = ""
    knowledge_path = Path(__file__).parent.parent / "knowledge.md"
    if knowledge_path.exists():
        knowledge_md = knowledge_path.read_text(errors="replace")
    probe_prompt = build_system_prompt_for_agent(target_spec, knowledge_md)

    def _probe_server(url):
        """Probe an LLM server: check availability. Does NOT send completions
        (LM Studio reloads models with default n_ctx on any request)."""
        try:
            resp = httpx.get(f"{url}/v1/models", timeout=2)
            if resp.status_code != 200:
                return None, None
            available = [m["id"] for m in resp.json().get("data", [])
                         if "embed" not in m.get("id", "").lower()]
            if not available:
                return None, None
            model = preferred_model if preferred_model in available else available[0]
            return resp, model
        except Exception:
            return None, None

    llm_url = config["llm_url"].rstrip("/")
    seen = set()
    for candidate in [llm_url] + [f"http://localhost:{p}" for p in (11235, 1234, 8080, 30000)]:
        candidate = candidate.rstrip("/")
        if candidate in seen:
            continue
        seen.add(candidate)
        resp, viable_model = _probe_server(candidate)
        if resp is None:
            continue
        if candidate != llm_url:
            logger.info("LLM fallback: %s -> %s", llm_url, candidate)
        config["llm_url"] = candidate
        if viable_model and viable_model != config["llm_model"]:
            config["llm_model"] = viable_model
            logger.info("Model auto-selected: %s", viable_model)
        break

    tool_executor = ToolExecutor(config)
    register_tools(tool_executor)

    knowledge_md = ""
    knowledge_path = Path(__file__).parent.parent / "knowledge.md"
    if knowledge_path.exists():
        knowledge_md = knowledge_path.read_text(errors="replace")

    system_prompt = build_system_prompt_for_agent(target_spec, knowledge_md, config)

    llm_url = config["llm_url"].rstrip("/")
    if not llm_url.endswith("/v1"):
        llm_url += "/v1"

    kwargs = dict(
        base_url=llm_url,
        api_key=config.get("llm_api_key", "no-key-required"),
        model=config["llm_model"],
        max_iterations=999999,
        max_tokens=config.get("llm_max_tokens", 4096),
        enabled_toolsets=[TOOLSET_NAME],
        ephemeral_system_prompt=system_prompt,
        quiet_mode=False,
    )
    # Track state for early success detection
    _agent_state = {"streamed_text": [], "success_emitted": False, "current_round": 1}

    if event_callback:
        def _on_tool_progress(event_type, name, preview, args, **kw):
            if event_type == "tool.started":
                event_callback("tool_call", {"name": name, "args": args or {}})
            elif event_type == "tool.completed":
                result = kw.get("result", "")
                event_callback("tool_result", {"name": name, "result": str(result)[:500]})

        def _on_stream_delta(delta):
            event_callback("text", {"content": delta})
            # Accumulate streamed text to detect success in real-time
            _agent_state["streamed_text"].append(delta)
            if not _agent_state["success_emitted"]:
                full_text = "".join(_agent_state["streamed_text"]).lower()
                if "campaign success" in full_text or "mission complete" in full_text:
                    _agent_state["success_emitted"] = True
                    logger.info("Campaign SUCCESS detected in stream (early) at round %d",
                                _agent_state["current_round"])
                    event_callback("campaign_success", {"round": _agent_state["current_round"]})

        kwargs["tool_progress_callback"] = _on_tool_progress
        kwargs["stream_delta_callback"] = _on_stream_delta
        kwargs["status_callback"] = lambda kind, data=None: event_callback(
            "status", {"kind": kind, "data": data}
        )
    else:
        _agent_state = None

    agent = AIAgent(**kwargs)
    ctx = _detect_context_length(config)
    config["_detected_context_length"] = ctx
    agent._config_context_length = ctx
    # Report aux context as 65K to bypass Hermes's 64K minimum check.
    # The actual compressor threshold (set below) controls when compression
    # fires, and the summarization request itself is small enough for 40K.
    agent._aux_compression_context_length_config = max(ctx, 65000)
    threshold_pct = 0.65
    threshold_tokens = int(ctx * threshold_pct)
    if hasattr(agent, 'context_compressor'):
        agent.context_compressor.context_length = ctx
        agent.context_compressor.threshold_percent = threshold_pct
        agent.context_compressor.threshold_tokens = threshold_tokens
        # Disable the tail anchor for agent mode.  Hermes injects synthetic
        # role="user" messages during agent loops (continuation prompts, empty
        # recovery nudges).  The compressor's _ensure_last_user_message_in_tail
        # anchors to these, pulling the tail cut all the way back and leaving
        # 0 turns to summarize.  In agent mode the initial task is already in
        # the protected head — there is no "latest user question" to preserve.
        agent.context_compressor._ensure_last_user_message_in_tail = (
            lambda messages, cut_idx, head_end: cut_idx
        )
    logger.info("Context length set to %d (compress at %d%% = %d tokens)",
                ctx, int(threshold_pct * 100), threshold_tokens)
    return agent, tool_executor, config, _agent_state


_NUDGE = (
    "You returned text without calling any tools. You MUST call a tool to proceed. "
    "Pick ONE: scan_target, list_chunks, create_recipe, assemble."
)


def _preflight_context_check(config: dict, system_prompt: str) -> str | None:
    """Verify the LLM server has enough context for our system prompt.

    Returns None on success, error message string on failure.
    Uses arithmetic check against detected context length instead of sending
    a test POST (which can crash the model under LM Studio).
    """
    import httpx

    llm_url = config["llm_url"].rstrip("/")
    if not llm_url.endswith("/v1"):
        llm_url += "/v1"

    try:
        resp = httpx.get(f"{llm_url}/models", timeout=3)
        if resp.status_code != 200:
            return f"Cannot reach LLM server at {llm_url} (status {resp.status_code})"
    except httpx.ConnectError:
        return f"Cannot connect to LLM server at {llm_url}. Is it running?"
    except Exception as e:
        return f"LLM preflight check failed: {e}"

    tool_overhead_tokens = 9000
    prompt_tokens = len(system_prompt) // 3
    total_needed = prompt_tokens + tool_overhead_tokens

    ctx = config.get("_detected_context_length", 40000)

    if ctx < 8192:
        return (
            f"LLM context window too small (n_ctx={ctx}). "
            f"The model appears to have reloaded with default settings. "
            f"Reload the model with at least 32K context in LM Studio."
        )

    if total_needed > ctx * 0.85:
        return (
            f"LLM context window may be too small. System prompt needs "
            f"~{prompt_tokens:,} tokens + ~{tool_overhead_tokens:,} tool overhead "
            f"= ~{total_needed:,} tokens, but context is only {ctx:,}. "
            f"Need at least {int(total_needed / 0.85):,} context tokens."
        )

    return None


def launch_campaign(target_spec: dict, config_overrides: dict | None = None,
                    max_rounds: int = 999999, on_progress=None):
    """Launch a malware campaign using the Hermes agent framework.

    The agent runs continuously (max_iterations=999999 per turn). The outer loop
    only re-invokes if the agent stops with a text response instead of tools.
    No artificial round limit — runs until success, stall, or explicit stop.
    """
    agent, tool_executor, config, _agent_state = make_agent(
        target_spec, config_overrides, max_rounds, event_callback=on_progress,
    )

    knowledge_md = ""
    knowledge_path = Path(__file__).parent.parent / "knowledge.md"
    if knowledge_path.exists():
        knowledge_md = knowledge_path.read_text(errors="replace")
    system_prompt = build_system_prompt_for_agent(target_spec, knowledge_md, config)
    preflight_err = _preflight_context_check(config, system_prompt)
    if preflight_err:
        logger.error("Preflight failed: %s", preflight_err)
        if on_progress:
            on_progress("error", {"content": preflight_err})
        return {"status": "error", "round": 0, "response": preflight_err}

    msg = _build_initial_message(target_spec)
    consecutive_text_only = 0
    consecutive_empty = 0

    for turn in range(1, max_rounds + 1):
        logger.info("Campaign turn %d", turn)
        if _agent_state:
            _agent_state["current_round"] = turn
            _agent_state["streamed_text"] = []  # Reset for each turn
        if on_progress:
            on_progress("status", {"kind": "turn", "turn": turn})

        response = agent.run_conversation(msg)
        resp_text = ""
        if isinstance(response, dict):
            resp_text = response.get("final_response", "") or ""
        elif isinstance(response, str):
            resp_text = response

        lower = resp_text.lower()
        if "campaign success" in lower or "mission complete" in lower:
            logger.info("Campaign SUCCESS detected")
            if on_progress:
                on_progress("campaign_success", {"round": turn})
            tool_executor.package_success()
            return {"status": "success", "round": turn, "response": resp_text}

        if not resp_text or len(resp_text) < 10:
            consecutive_empty += 1
            if consecutive_empty >= 5:
                prompt_tokens = len(system_prompt) // 3
                err = (
                    f"LLM returned {consecutive_empty} consecutive empty responses. "
                    f"System prompt is ~{prompt_tokens:,} tokens. "
                    f"Check that the LLM model context window (n_ctx) is large enough "
                    f"and the model is still loaded."
                )
                logger.error(err)
                if on_progress:
                    on_progress("error", {"content": err})
                return {"status": "error", "round": turn, "response": err}
            msg = "Continue."
        elif len(resp_text) > 50:
            consecutive_empty = 0
            consecutive_text_only += 1
            if consecutive_text_only >= 5:
                return {"status": "stalled", "round": turn, "response": resp_text}
            msg = _NUDGE
        else:
            consecutive_empty = 0
            consecutive_text_only = 0
            msg = "Continue."

    return {"status": "max_turns", "round": max_rounds, "response": resp_text}
