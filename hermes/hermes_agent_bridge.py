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
    SYSTEM_PROMPT, OPERATIONAL_KNOWLEDGE,
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
    "list_chunks": "tool_list_chunks",
    "get_strategy": "tool_get_strategy",
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


def _make_handler(tool_executor: ToolExecutor, method_name: str):
    """Create a sync handler wrapper for an async ToolExecutor method."""
    async_method = getattr(tool_executor, method_name)

    def handler(args, **kw):
        try:
            asyncio.get_running_loop()
            loop = _get_shared_loop()
            future = asyncio.run_coroutine_threadsafe(async_method(**args), loop)
            return future.result(timeout=300)
        except RuntimeError:
            return asyncio.run(async_method(**args))

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
            handler=_make_handler(tool_executor, method_name),
            is_async=False,
            emoji="",
            override=True,
        )

    logger.info("Registered %d malware campaign tools with Hermes agent", len(_TOOL_METHOD_MAP))


def build_system_prompt_for_agent(target: dict, knowledge_md: str = "") -> str:
    """Build the full system prompt including operational knowledge."""
    parts = [SYSTEM_PROMPT, OPERATIONAL_KNOWLEDGE]

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
    parts.append(
        f"\n## Current Mission\n"
        f"- Target EDR: {edr}\n"
        f"- Malware type: {malware_type}\n"
        f"- Target OS: {target.get('os', 'windows11')}\n"
        f"- Network: {target.get('network', 'nat')}\n"
        f"- Use query_knowledge tool for detailed evasion strategies and proven recipes\n"
    )
    return "\n\n".join(parts)


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
               max_rounds: int = 50, event_callback=None):
    """Create an AIAgent wired with malware campaign tools.

    Returns (agent, tool_executor) tuple. The agent is ready for
    run_conversation() or can be used by the web UI with callbacks.
    """
    _ensure_hermes_path()
    from run_agent import AIAgent

    config = get_config(config_overrides)
    config["edr"] = target_spec.get("edr", "none")
    config["_target_malware_type"] = target_spec.get("malware_type", "")

    import httpx

    preferred_model = config["llm_model"]

    def _probe_server(url):
        """Probe an LLM server: check availability and sufficient context for our model."""
        try:
            resp = httpx.get(f"{url}/v1/models", timeout=2)
            if resp.status_code != 200:
                return None, None, None
            available = [m["id"] for m in resp.json().get("data", [])
                         if "embed" not in m.get("id", "").lower()]
            if not available:
                return None, None, None
            test_model = preferred_model if preferred_model in available else available[0]
            padding = "x " * 20000
            test_resp = httpx.post(
                f"{url}/v1/chat/completions",
                json={"model": test_model,
                      "messages": [{"role": "system", "content": padding},
                                   {"role": "user", "content": "test"}],
                      "max_tokens": 1, "stream": False},
                timeout=30,
            )
            if test_resp.status_code == 200:
                return resp, None, test_model
            err_data = test_resp.json().get("error", {})
            err = err_data.get("message", "") if isinstance(err_data, dict) else str(err_data)
            if "n_ctx" in err or "n_keep" in err or "context" in err.lower():
                logger.warning("Server %s model %s context too small: %s", url, test_model, err[:120])
                return resp, "context_too_small", None
            return resp, None, test_model
        except Exception:
            return None, None, None

    llm_url = config["llm_url"].rstrip("/")
    models_resp = None
    seen = set()
    for candidate in [llm_url] + [f"http://localhost:{p}" for p in (11235, 1234, 8080, 30000)]:
        candidate = candidate.rstrip("/")
        if candidate in seen:
            continue
        seen.add(candidate)
        resp, issue, viable_model = _probe_server(candidate)
        if resp is None:
            continue
        if issue == "context_too_small":
            continue
        models_resp = resp
        if candidate != llm_url:
            logger.info("LLM fallback: %s -> %s", llm_url, candidate)
        config["llm_url"] = candidate
        if viable_model and viable_model != config["llm_model"]:
            config["llm_model"] = viable_model
            logger.info("Model auto-selected: %s", viable_model)
        break

    if models_resp:
        try:
            available = [m["id"] for m in models_resp.json().get("data", [])
                         if "embed" not in m["id"].lower()]
            if available and config["llm_model"] not in available:
                config["llm_model"] = available[0]
                logger.info("Model auto-selected: %s", config["llm_model"])
        except Exception:
            pass

    tool_executor = ToolExecutor(config)
    register_tools(tool_executor)

    knowledge_md = ""
    knowledge_path = Path(__file__).parent.parent / "knowledge.md"
    if knowledge_path.exists():
        knowledge_md = knowledge_path.read_text(errors="replace")

    system_prompt = build_system_prompt_for_agent(target_spec, knowledge_md)

    llm_url = config["llm_url"].rstrip("/")
    if not llm_url.endswith("/v1"):
        llm_url += "/v1"

    kwargs = dict(
        base_url=llm_url,
        api_key=config.get("llm_api_key", "no-key-required"),
        model=config["llm_model"],
        max_iterations=9999,
        max_tokens=config.get("llm_max_tokens", 4096),
        enabled_toolsets=[TOOLSET_NAME],
        ephemeral_system_prompt=system_prompt,
        quiet_mode=False,
    )
    if event_callback:
        def _on_tool_progress(event_type, name, preview, args, **kw):
            if event_type == "tool.started":
                event_callback("tool_call", {"name": name, "args": args or {}})
            elif event_type == "tool.completed":
                result = kw.get("result", "")
                event_callback("tool_result", {"name": name, "result": str(result)[:500]})
        kwargs["tool_progress_callback"] = _on_tool_progress
        kwargs["stream_delta_callback"] = lambda delta: event_callback(
            "text", {"content": delta}
        )
        kwargs["status_callback"] = lambda kind, data=None: event_callback(
            "status", {"kind": kind, "data": data}
        )

    agent = AIAgent(**kwargs)
    agent._config_context_length = 131072
    agent._aux_compression_context_length_config = 131072
    return agent, tool_executor


_NUDGE = (
    "You returned text without calling any tools. You MUST call a tool to proceed. "
    "Pick ONE: scan_target, list_recipes, assemble, query_knowledge."
)


def launch_campaign(target_spec: dict, config_overrides: dict | None = None,
                    max_rounds: int = 50, on_progress=None):
    """Launch a malware campaign using the Hermes agent framework.

    The agent runs continuously (max_iterations=200 per turn). The outer loop
    only re-invokes if the agent stops with a text response instead of tools.
    """
    agent, tool_executor = make_agent(
        target_spec, config_overrides, max_rounds, event_callback=on_progress,
    )

    msg = _build_initial_message(target_spec)
    consecutive_text_only = 0

    for turn in range(1, max_rounds + 1):
        logger.info("Campaign turn %d", turn)

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

        if resp_text and len(resp_text) > 50:
            consecutive_text_only += 1
            if consecutive_text_only >= 3:
                return {"status": "stalled", "round": turn, "response": resp_text}
            msg = _NUDGE
        else:
            consecutive_text_only = 0
            msg = "Continue."

    return {"status": "max_turns", "round": max_rounds, "response": resp_text}
