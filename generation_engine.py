"""
Generation engine — core class that takes enriched context + target spec → generates malware.

Orchestrates:
  1. Evasion selection (evasion_selector)
  2. Exploit selection (exploit_selector)
  3. Compiler instruction generation (compiler_selector)
  4. LLM prompt construction (prompt_templates)
  5. LLM invocation via subprocess (llama.cpp / ollama / remote API)

The engine is designed to work with any local or remote LLM endpoint through
the ``llm_client`` interface. A default subprocess-based client ships with
the module for llama.cpp compatibility.
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Callable, Awaitable

from .db_query_engine import DBQueryEngine
from .db_models import QueryResult
from .context_builder import ContextBuilder
from .evasion_selector import EvasionSelector
from .exploit_selector import ExploitSelector
from .compiler_selector import CompilerSelector
from .prompt_templates import PromptTemplates
from .debug_logger import DebugLogger as _DebugLogger
from .target_spec import TargetEnvironmentSpec

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default LLM client (subprocess-based llama.cpp)
# ---------------------------------------------------------------------------

class SubprocessLLMClient:
    """Default LLM client — invokes llama.cpp via subprocess."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        llm_api_url: str = "http://localhost:1234",
        llm_model_name: str = "qwen3.6-35b-a3b-uncensored-hauhaucs-aggressiv",
        max_tokens: int = 16384,
        temperature: float = 0.7,
    ):
        self.model_path = model_path or self._find_model()
        self.llm_api_url = llm_api_url.rstrip("/")
        self.llm_model_name = llm_model_name
        self.max_tokens = max_tokens
        self.temperature = temperature

    def _find_model(self) -> str:
        """Look for a GGUF model in common locations."""
        home = Path.home()
        search_paths = [
            Path(home) / ".llm_vault" / "models",
            Path.home() / "Downloads" / "models",
            Path("/home/kei/.llm_vault/models"),
        ]
        for sp in search_paths:
            if sp.exists():
                ggufs = list(sp.glob("*.gguf"))
                if ggufs:
                    return str(ggufs[0])
        # Default fallback — user will need to set model_path explicitly
        logger.warning("No GGUF model found; set model_path explicitly")
        return ""

    async def generate(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """Run llama.cpp with the given prompt and return generated text."""
        effective_max = max_tokens if max_tokens is not None else self.max_tokens
        
        if self.model_path:
            # Use llama.cpp CLI for local inference
            cmd = [
                "llama-cli",
                "-m", self.model_path,
                "-p", prompt,
                "-n", str(effective_max),
                "--temp", str(self.temperature),
                "-ngl", "99",  # offload all layers to GPU if available
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode != 0:
                    logger.error("llama-cli failed (rc=%d): %s", proc.returncode, stderr.decode(errors="replace"))
                    return ""

                # Extract generated text — llama-cli outputs after the prompt
                output = stdout.decode("utf-8", errors="replace")
                return self._extract_generation(output)
            except FileNotFoundError:
                logger.warning("llama-cli not found in PATH; trying HTTP LLM fallback")

        # HTTP LLM fallback (LM Studio / OpenAI-compatible API)
        return await self._http_generate(prompt, max_tokens=effective_max)

    async def _http_generate(self, prompt: str, *, max_tokens: int | None = None) -> str:
        """Call LM Studio via its OpenAI-compatible /v1/chat/completions endpoint."""
        import urllib.request
        import time as _time

        url = f"{self.llm_api_url}/v1/chat/completions"
        max_attempts = 3
        current_max_tokens = max_tokens if max_tokens is not None else self.max_tokens

        for attempt in range(max_attempts):
            if attempt > 0:
                logger.info("Retrying LLM generation (attempt %d, tokens=%d)...", attempt + 1, current_max_tokens)
                _time.sleep(min(attempt * 5, 15))

            payload = json.dumps({
                "model": self.llm_model_name,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": current_max_tokens,
                "temperature": self.temperature,
                "stream": False,
            }).encode()

            req = urllib.request.Request(
                url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=600) as resp:
                    raw = resp.read().decode('utf-8', errors='replace')
                    result = json.loads(raw)
                    content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                    if not content or len(content.strip()) < 50:
                        logger.warning(
                            "LM Studio returned empty/short response (%d chars). ",
                            len(content),
                        )
                        current_max_tokens = min(current_max_tokens * 2, 32768)
                        continue

                    # Check if the code looks complete
                    if self._is_code_complete(content):
                        return content.strip()

                    logger.warning(
                        "LM Studio returned potentially truncated output (%d chars). "
                        "Retrying with higher token limit...",
                        len(content),
                    )
                    current_max_tokens = min(current_max_tokens * 2, 32768)
                    # Keep trying — last iteration just returns what we got
            except urllib.error.HTTPError as e:
                if 500 <= e.code < 600 and attempt < max_attempts - 1:
                    continue  # server error, retry
                logger.warning("LM Studio HTTP error (%s): %s", url, e)
                return content.strip()
            except Exception as e:
                if "timed out" in str(e).lower() or "connection" in str(e).lower():
                    continue  # timeout/connection, retry
                logger.warning("LM Studio request error (%s): %s", url, e)

        logger.error("LM Studio generation failed after retries (%s)", url)
        return content.strip() if 'content' in locals() else ""

    @staticmethod
    def _extract_generation(output: str) -> str:
        """Extract generated text from llama-cli output."""
        # llama-cli outputs the prompt + generation interleaved.
        # Best effort: return everything after the first newline that looks like continuation
        lines = output.split("\n")
        for i, line in enumerate(lines):
            if "llama" not in line.lower() and "loading" not in line.lower():
                return "\n".join(lines[i:])
        return output

    @staticmethod
    def _is_code_complete(code: str) -> bool:
        """Check if generated source code looks complete (not cut off mid-block)."""
        stripped = code.strip()
        if len(stripped) < 200:
            return False

        # Check for obvious truncation patterns in C/C++ code
        open_braces = stripped.count('{')
        close_braces = stripped.count('}')
        open_parens = stripped.count('(')
        close_parens = stripped.count(')')
        open_brackets = stripped.count('[')
        close_brackets = stripped.count(']')

        # Unbalanced brackets usually means truncated output
        if abs(open_braces - close_braces) > 3:
            return False
        if abs(open_parens - close_parens) > 5:
            return False
        if abs(open_brackets - close_brackets) > 2:
            return False

        # Check for incomplete array initialization (common shellcode pattern)
        if '[] = {' in stripped and not stripped.rstrip().endswith('};'):
            # Could be legitimate — only flag if also unbalanced brackets
            if open_braces != close_braces:
                return False

        # Check that the code ends with a plausible terminator (not mid-statement)
        last_chars = stripped[-10:].rstrip()
        bad_endings = ['{', '(', '[', ',', '=', '+', '-', '*', '/', '<', '>']
        if any(last_char in bad_endings for last_char in [last_chars[-1]]):
            return False

        # Check that code contains expected structure markers (at least some function definitions)
        has_func = bool(
            stripped and
            ('{' in stripped or 'def ' in stripped or 'function' in stripped.lower() or '(' in stripped)
        )
        if not has_func:
            return False

        return True


# ---------------------------------------------------------------------------
# GenerationEngine — main orchestrator
# ---------------------------------------------------------------------------

class GenerationResult:
    """Result of a malware generation run."""

    def __init__(self, source_code: str = "", build_instructions: str = "",
                 context_hash: str = "", prompt_length: int = 0):
        self.source_code = source_code
        self.build_instructions = build_instructions
        self.context_hash = context_hash
        self.prompt_length = prompt_length

    @property
    def success(self) -> bool:
        return len(self.source_code.strip()) > 50


class GenerationEngine:
    """Core engine that orchestrates DB queries, selection, and LLM generation."""

    def __init__(
        self,
        db_engine: Optional[DBQueryEngine] = None,
        llm_client: Optional[object] = None,
        max_tokens: int = 32768,
        temperature: float = 0.7,
        debug: Optional[_DebugLogger] = None,
    ):
        self._db = db_engine or DBQueryEngine()
        self._llm_client = llm_client or SubprocessLLMClient(max_tokens=max_tokens, temperature=temperature)
        self._debug = debug

        # Sub-engines
        self.context_builder = ContextBuilder()
        self.prompt_templates = PromptTemplates()
        self.evasion_selector = EvasionSelector(self._db)
        self.exploit_selector = ExploitSelector(self._db)
        self.compiler_selector = CompilerSelector()

    async def generate(
        self,
        target_spec: TargetEnvironmentSpec,
        max_tokens: Optional[int] = None,
    ) -> GenerationResult:
        """Run the full generation pipeline.

        Steps:
          1. Query all 3 DBs for relevant techniques/exploits/findings
          2. Build ranked context block
          3. Select evasion techniques + exploits
          4. Generate compiler instructions (if compilers available)
          5. Render full prompt via templates
          6. Call LLM to generate malware source code
        """

        # -- Step 1: DB queries ------------------------------------------------
        query_result = self._db.query_all(
            f"{target_spec.os_platform.value} {target_spec.os_version}",
            n_results=10,
        )
        if self._debug and self._debug.enabled:
            self._debug.phase("GEN")
            self._debug.step("step_1_db_query", "Querying DBs for evasion/exploits/CTI...")
            self._debug.dump_dict("db_results", {
                "malware_techniques": len(query_result.malware_techniques) if query_result else 0,
                "poc_results": len(query_result.poc_results) if query_result else 0,
                "cti_findings": len(query_result.cti_findings) if query_result else 0,
            })

        # -- Step 2: Build context -------------------------------------------
        context = self.context_builder.build_context(
            query_result=query_result,
            target_spec=target_spec,
            max_techniques=15,
            max_pocs=10,
            max_cti=5,
        )
        if self._debug and self._debug.enabled:
            self._debug.step("step_2_context", f"Context built — {len(context.evasion_techniques)} techniques, {len(context.poc_findings)} PoCs")

        # -- Step 3: Evasion & exploit selection (for context enrichment) ----
        evasions = self.evasion_selector.select_evasions(target_spec, max_techniques=8)
        exploits = self.exploit_selector.select_exploits(target_spec, max_results=6)

        if self._debug and self._debug.enabled:
            self._debug.dump_dict("selections", {
                "evasions_selected": len(evasions),
                "exploits_selected": len(exploits),
            })

        # -- Step 4: Compiler instructions -----------------------------------
        compiler_instructions = ""
        if target_spec.installed_compilers:
            # Generate a mini-prompt for the LLM to produce build guidance
            compiler_prompt = self.prompt_templates.render_compiler_prompt(
                compilers=target_spec.installed_compilers,
                os_version=target_spec.os_version,
                os_platform=target_spec.os_platform.value,
                source_code="(will be filled during generation)",
            )
            comp_output = await self._llm_client.generate(compiler_prompt)
            compiler_instructions = comp_output.strip()

        if self._debug and self._debug.enabled:
            self._debug.step("step_4_compiler", f"Compiler instructions generated ({len(compiler_instructions)} chars)")

        # Update context with compiler info
        context.compiler_instructions = compiler_instructions or "(no compilers detected — LLM will infer build steps)"

        # -- Step 5: Render full prompt --------------------------------------
        max_tok = max_tokens or self._llm_client.max_tokens if hasattr(self._llm_client, 'max_tokens') else 8192
        malware_type = getattr(target_spec, "malware_type", "exe")
        prompt = self.prompt_templates.render_generate_prompt(
            context=context,
            installed_compilers=target_spec.installed_compilers,
            custom_gates=target_spec.custom_gates,
            malware_type=malware_type,
        )

        # -- Step 6: Call LLM ------------------------------------------------
        if self._debug and self._debug.enabled:
            self._debug.dump_dict("prompt_info", {
                "prompt_length": len(prompt),
                "max_tokens": max_tok,
            })
            self._debug.step("step_5_prompt_rendered", f"Prompt rendered ({len(prompt)} chars)")

        logger.info("Generating malware (prompt length: %d chars)...", len(prompt))
        if self._debug and self._debug.enabled:
            self._debug.step("step_6_llm_call", "Calling LLM client...")

        source_code = await self._llm_client.generate(prompt)

        if self._debug and self._debug.enabled:
            self._debug.ok(f"Generation complete — {len(source_code.strip())} chars of source code, hash={context.context_hash}")

        return GenerationResult(
            source_code=source_code.strip(),
            build_instructions=context.compiler_instructions,
            context_hash=context.context_hash,
            prompt_length=len(prompt),
        )

    async def generate_variant(
        self,
        target_spec: TargetEnvironmentSpec,
        variant_seed: str = "default",
        max_tokens: Optional[int] = None,
    ) -> GenerationResult:
        """Generate a different malware variant by modifying the prompt seed.

        Useful for generating multiple variants to test detection rates.
        """
        if self._debug and self._debug.enabled:
            self._debug.step(f"variant_{variant_seed}", f"Generating variant with seed '{variant_seed}'...")

        # Modify context hash by appending seed for variation
        base_result = await self.generate(target_spec, max_tokens)

        if not base_result.success:
            return base_result  # propagate failure

        # Append variant-specific instructions to the prompt and regenerate
        variant_prompt = f"{base_result.source_code}\n\n/* VARIANT SEED: {variant_seed} */\n"

        logger.info("Generating variant '%s'...", variant_seed)
        source_code = await self._llm_client.generate(variant_prompt)

        return GenerationResult(
            source_code=source_code.strip() or base_result.source_code,
            build_instructions=base_result.build_instructions,
            context_hash=f"{base_result.context_hash}_v{variant_seed}",
            prompt_length=len(variant_prompt),
        )
