"""LLM client implementations — subprocess-based (llama.cpp) and cloud (OpenAI-compatible)."""

import asyncio
import json
import logging
import os
import re
import time as _time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ContextTooLongError(Exception):
    """Raised when the prompt exceeds the model's context window."""


def _strip_thinking(text: str) -> str:
    """Remove <think>...</think> blocks from an LLM response."""
    if not text:
        return text
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _extract_code_from_reasoning(reasoning: str) -> str:
    """Extract the last fenced code block from reasoning_content.

    When LM Studio ignores chat_template_kwargs and routes everything through
    reasoning_content, the model often drafts a "Final Output" code block near
    the end of its reasoning.  We grab the *last* fenced block (most likely the
    polished answer rather than an intermediate draft).
    """
    if not reasoning:
        return ""
    blocks = re.findall(r"```[\w]*\n(.*?)```", reasoning, re.DOTALL)
    if not blocks:
        return ""
    candidate = blocks[-1].strip()
    if len(candidate) < 30:
        return ""
    return candidate


# ---------------------------------------------------------------------------
# Default LLM client (subprocess-based llama.cpp)
# ---------------------------------------------------------------------------

_LLM_SERVER_LABELS: dict[str, str] = {
    "1234": "local",
    "11234": "Blackwell",
    "11235": "T",
}


def _llm_label(url: str) -> str:
    """Return a friendly label for an LLM server URL based on port."""
    try:
        port = url.rstrip("/").split(":")[-1].split("/")[0]
        return _LLM_SERVER_LABELS.get(port, f"LLM@{port}")
    except Exception:
        return "local LLM"


class SubprocessLLMClient:
    """Default LLM client — invokes llama.cpp via subprocess."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        llm_api_url: str = "http://localhost:1234",
        llm_model_name: str = "qwen3.6-35b-a3b-uncensored-hauhaucs-aggressiv",
        max_tokens: int = 8192,
        temperature: float = 0.7,
    ):
        self.model_path = model_path or self._find_model()
        self.llm_api_url = llm_api_url.rstrip("/")
        self.llm_model_name = llm_model_name
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._model_load_checked = False
        self.label = _llm_label(self.llm_api_url)

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

    async def generate(self, prompt: str, max_tokens: Optional[int] = None, prefix: str = "", disable_thinking: bool = False) -> str:
        """Run llama.cpp with the given prompt and return generated text.

        prefix: optional assistant-role prefill string (forces the model to
        continue from that text rather than generating a preamble). Useful
        for structured-output prompts where thinking preamble wastes tokens.
        disable_thinking: when True, sends chat_template_kwargs to disable
        extended thinking in Qwen3 models. Use as fallback when thinking
        mode produces too much prose mixed with code.
        """
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
        return await self._http_generate(prompt, max_tokens=effective_max, prefix=prefix, disable_thinking=disable_thinking)

    async def _ensure_model_loaded(self) -> None:
        """Load the model in LM Studio if nothing is currently loaded (runs once per client)."""
        if self._model_load_checked:
            return
        self._model_load_checked = True

        models_url = f"{self.llm_api_url}/v1/models"

        def _loaded():
            try:
                with urllib.request.urlopen(models_url, timeout=5) as r:
                    return json.loads(r.read()).get("data", [])
            except Exception:
                return None

        current = _loaded()
        if current is None or current:
            return

        load_url = f"{self.llm_api_url}/api/v0/models/load"
        payload = json.dumps({"identifier": self.llm_model_name}).encode()
        req = urllib.request.Request(
            load_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
            logger.info("LM Studio: loading '%s'…", self.llm_model_name)
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                logger.warning("LM Studio load request returned HTTP %d — continuing", exc.code)
            return
        except Exception as exc:
            logger.warning("LM Studio load request failed (%s) — continuing", exc)
            return

        deadline = _time.monotonic() + 120
        while _time.monotonic() < deadline:
            await asyncio.sleep(3)
            if _loaded():
                logger.info("LM Studio: model ready.")
                return
        logger.warning("LM Studio: model did not become ready within 120s")

    async def _http_generate(self, prompt: str, *, max_tokens: int | None = None, prefix: str = "", disable_thinking: bool = False) -> str:
        """Call LM Studio via its OpenAI-compatible /v1/chat/completions endpoint.

        prefix: when provided, appended as an assistant-role message before the
        completion request. llama.cpp/LM Studio will continue from that text,
        skipping any preamble the model would otherwise generate. The prefix is
        prepended to the returned content so the caller receives the full output.
        disable_thinking: when True, adds chat_template_kwargs to suppress
        Qwen3 extended thinking mode.
        """
        await self._ensure_model_loaded()

        url = f"{self.llm_api_url}/v1/chat/completions"
        logger.debug("LLM endpoint: %s", url)
        max_attempts = 3
        effective_tokens = max_tokens if max_tokens is not None else self.max_tokens
        content = ""

        for attempt in range(max_attempts):
            if attempt > 0:
                logger.info("Retrying LLM generation (attempt %d)...", attempt + 1)
                await asyncio.sleep(min(attempt * 5, 15))

            messages = [
                {"role": "user", "content": prompt},
            ]
            if prefix:
                messages.append({"role": "assistant", "content": prefix})

            body: dict = {
                "model": self.llm_model_name,
                "messages": messages,
                "max_tokens": effective_tokens,
                "temperature": self.temperature,
                "stream": False,
                "chat_template_kwargs": {"enable_thinking": False},
            }

            payload = json.dumps(body).encode()

            req = urllib.request.Request(
                url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=600) as resp:
                    raw = resp.read().decode('utf-8', errors='replace')
                    result = json.loads(raw)
                    msg = result.get("choices", [{}])[0].get("message", {})
                    content = msg.get("content", "") or ""
                    # Strip <think>...</think> blocks that Qwen3 includes when
                    # thinking mode is active (content field, not reasoning_content).
                    content = _strip_thinking(content)
                    if not content:
                        rc = msg.get("reasoning_content", "") or ""
                        if "</think>" in rc:
                            content = rc.split("</think>", 1)[-1].strip()
                        elif rc.strip():
                            content = _strip_thinking(rc.strip())
                        if content:
                            logger.debug("Extracted response from reasoning_content (%d chars)", len(content))
                    if not content or len(content.strip()) < 50:
                        rc = msg.get("reasoning_content", "") or ""
                        _rc_len = len(rc)
                        _fr = result.get("choices", [{}])[0].get("finish_reason", "")
                        # Last resort: extract fenced code blocks from reasoning
                        if _rc_len > 200:
                            code_from_rc = _extract_code_from_reasoning(rc)
                            if code_from_rc:
                                logger.info(
                                    "Extracted code block from reasoning_content "
                                    "(%d chars from %d reasoning chars)",
                                    len(code_from_rc), _rc_len)
                                content = code_from_rc
                        if not content or len(content.strip()) < 50:
                            if _rc_len > 500 and not disable_thinking:
                                logger.warning(
                                    "Thinking consumed all tokens (%d reasoning chars, finish=%s) — "
                                    "retrying with thinking disabled", _rc_len, _fr)
                                body["chat_template_kwargs"] = {"enable_thinking": False}
                                disable_thinking = True
                                continue
                            logger.warning("LM Studio returned empty/short response (%d chars) — retrying", len(content))
                            continue
                    # Prepend the assistant prefill so the caller sees the full output
                    if prefix:
                        content = prefix + content
                    return content.strip()
            except urllib.error.HTTPError as e:
                if 400 <= e.code < 500:
                    try:
                        body = e.read().decode("utf-8", errors="replace")
                    except Exception:
                        body = "(could not read response body)"
                    if "n_keep" in body and "n_ctx" in body:
                        raise ContextTooLongError(body[:200])
                    logger.error(
                        "LM Studio rejected the request (HTTP %d). "
                        "Check that the model name is correct and LM Studio is running.\n"
                        "Response: %s",
                        e.code, body[:500],
                    )
                    return content.strip()
                if 500 <= e.code < 600 and attempt < max_attempts - 1:
                    continue
                logger.warning("LM Studio HTTP error (%s): %s", url, e)
                return content.strip()
            except Exception as e:
                if "timed out" in str(e).lower() or "connection" in str(e).lower():
                    continue
                logger.warning("LM Studio request error (%s): %s", url, e)

        logger.error("LM Studio generation failed after retries (%s)", url)
        return content.strip()

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
# Cloud LLM client (OpenAI-compatible — default when FUGU_API_KEY is set)
# ---------------------------------------------------------------------------

_CLOUD_PROVIDER_PRESETS: dict[str, dict] = {
    "fugu": {
        "api_url": "https://api.sakana.ai/v1",
        "api_key_env": "FUGU_API_KEY",
        "model_env": "FUGU_MODEL",
        "default_model": "fugu",
    },
    "openrouter": {
        "api_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "model_env": "OPENROUTER_MODEL",
        "default_model": "deepseek/deepseek-r1-0528",
    },
}


class CloudLLMClient:
    """Cloud LLM client — calls any OpenAI-compatible API.

    Use CloudLLMClient.for_provider('fugu'|'openrouter', model='') to create
    a pre-configured instance.  Direct construction is also supported for
    custom endpoints.

    Once a fatal quota/auth error is seen (HTTP 401/402/403/429), the client
    permanently disables itself for the rest of the process so no further
    network calls are made and local-LLM fallback takes over immediately.
    """

    # HTTP codes that mean "quota exhausted / no access" — not worth retrying
    _FATAL_CODES: frozenset[int] = frozenset({401, 402, 403, 429})

    def __init__(
        self,
        api_url: str = "",
        api_key: str = "",
        model: str = "",
        max_tokens: int = 32768,
        temperature: float = 0.7,
    ):
        self.api_url = (api_url or os.environ.get("FUGU_API_URL", "https://api.sakana.ai/v1")).rstrip("/")
        self.api_key = api_key or os.environ.get("FUGU_API_KEY", "")
        self.model = model or os.environ.get("FUGU_MODEL", "fugu")
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._disabled = False  # set permanently on quota/auth failure

    @classmethod
    def for_provider(cls, provider: str, model: str = "") -> "CloudLLMClient":
        """Create a client configured for the named provider ('fugu' or 'openrouter')."""
        preset = _CLOUD_PROVIDER_PRESETS.get(provider) or _CLOUD_PROVIDER_PRESETS["fugu"]
        api_key = os.environ.get(preset["api_key_env"], "")
        resolved_model = model or os.environ.get(preset["model_env"], preset["default_model"])
        client = cls(api_url=preset["api_url"], api_key=api_key, model=resolved_model)
        if not api_key:
            client._disabled = True
            logger.warning(
                "cloud-run: %s is not set — chunk generation will fall back to local LLM. "
                "Set %s=<key> to enable %s.",
                preset["api_key_env"], preset["api_key_env"], provider,
            )
        else:
            logger.info(
                "cloud-run: chunk generation → %s / %s (fallback: local LLM)",
                provider, resolved_model,
            )
        return client

    async def generate(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """Call the cloud LLM and return generated text."""
        if self._disabled:
            return ""

        url = f"{self.api_url}/chat/completions"
        effective_tokens = max_tokens if max_tokens is not None else self.max_tokens

        payload = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": effective_tokens,
            "temperature": self.temperature,
            "stream": False,
        }).encode()

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode("utf-8", errors="replace"))
                content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                return _strip_thinking(content.strip())
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            if "n_keep" in body and "n_ctx" in body:
                raise ContextTooLongError(body[:200])
            if exc.code in self._FATAL_CODES:
                self._disabled = True
                logger.warning(
                    "Cloud LLM HTTP %d — quota/auth error, disabling cloud for this run "
                    "(falling back to local LLM permanently): %s",
                    exc.code, body[:200],
                )
            else:
                logger.error("Cloud LLM HTTP %d: %s", exc.code, body[:300])
            return ""
        except Exception as exc:
            logger.error("Cloud LLM request failed: %s", exc)
            return ""
