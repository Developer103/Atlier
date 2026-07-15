"""Hermes LLM client — async httpx wrapper for local Qwen with OpenAI-format tool calling."""

import asyncio
import json
import logging
import re

import httpx

logger = logging.getLogger(__name__)

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def _strip_thinking(text: str) -> str:
    if not text:
        return text
    return _THINK_RE.sub("", text).strip()


def _dedup_response(text: str, min_block_len: int = 80, max_repeats: int = 2) -> str:
    """Detect and truncate degenerate repetition in LLM output.

    Local LLMs sometimes enter infinite loops repeating the same paragraph.
    This detects blocks of text that appear 3+ times and truncates to the
    first occurrence, returning cleaned text.
    """
    if not text or len(text) < min_block_len * 3:
        return text

    sentences = re.split(r'(?<=[.!?\n])\s+', text)
    if len(sentences) < 6:
        return text

    # Check for repeated sentence blocks (sliding window of 2-4 sentences)
    for window in range(4, 1, -1):
        if len(sentences) < window * 3:
            continue
        for start in range(len(sentences) - window * 2):
            block = " ".join(sentences[start:start + window])
            if len(block) < min_block_len:
                continue
            rest = " ".join(sentences[start + window:])
            count = rest.count(block)
            if count >= max_repeats:
                # Found degenerate repetition — keep first occurrence + truncation notice
                truncated = " ".join(sentences[:start + window])
                logger.warning(
                    "Detected degenerate repetition: block of %d chars repeated %d+ times. "
                    "Truncating from %d to %d chars.",
                    len(block), count + 1, len(text), len(truncated),
                )
                return truncated

    # Also check for exact paragraph repetition (split on double newline)
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    if len(paragraphs) >= 4:
        seen = {}
        cutoff = None
        for i, p in enumerate(paragraphs):
            if len(p) < min_block_len:
                continue
            if p in seen and i - seen[p] <= 3:
                # Same paragraph repeated within 3 paragraphs — degenerate
                cutoff = seen[p] + 1
                break
            seen[p] = i
        if cutoff is not None:
            truncated = "\n\n".join(paragraphs[:cutoff])
            logger.warning(
                "Detected repeated paragraphs. Truncating from %d to %d paragraphs.",
                len(paragraphs), cutoff,
            )
            return truncated

    return text


def _sanitize_tool_call(tc: dict) -> dict:
    fn = tc.get("function", {})
    name = fn.get("name", "")
    raw_args = fn.get("arguments", "{}")
    if isinstance(raw_args, dict):
        raw_args = json.dumps(raw_args)
    elif not isinstance(raw_args, str):
        raw_args = str(raw_args)
    try:
        json.loads(raw_args)
    except (json.JSONDecodeError, TypeError):
        raw_args = "{}"
        logger.warning("Malformed tool_call arguments for %s — replaced with {}", name)
    return {
        "id": tc.get("id", f"call_{name}"),
        "type": "function",
        "function": {"name": name, "arguments": raw_args},
    }


class HermesLLM:
    def __init__(
        self,
        base_url: str = "http://localhost:11235",
        model: str = "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-mtp",
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._lock = asyncio.Lock()
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=15.0))

    async def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
    ) -> tuple[str, list[dict]]:
        """Send a chat completion request. One request at a time (local model).

        Returns (text_content, tool_calls) where tool_calls is a list of
        {"id": str, "function": {"name": str, "arguments": str}} dicts.
        """
        async with self._lock:
            return await self._chat_inner(messages, tools)

    async def _chat_inner(
        self,
        messages: list[dict],
        tools: list[dict] | None,
    ) -> tuple[str, list[dict]]:
        base = self.base_url.rstrip("/")
        if base.endswith("/v1"):
            url = f"{base}/chat/completions"
        else:
            url = f"{base}/v1/chat/completions"

        body: dict = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "stream": False,
            "chat_template_kwargs": {"enable_thinking": False},
            "options": {"num_ctx": 65536},
        }
        if tools:
            body["tools"] = [
                {"type": "function", "function": t} if "type" not in t else t
                for t in tools
            ]

        last_err: Exception | None = None
        for attempt in range(3):
            if attempt > 0:
                wait = min(attempt * 5, 15)
                logger.info("LLM retry %d/%d in %ds", attempt + 1, 3, wait)
                await asyncio.sleep(wait)
            try:
                resp = await self._client.post(url, json=body)
                resp.raise_for_status()
                data = resp.json()
                return self._parse_response(data)
            except httpx.TimeoutException as exc:
                last_err = exc
                logger.warning("LLM request timed out (attempt %d): %s", attempt + 1, exc)
            except httpx.HTTPStatusError as exc:
                last_err = exc
                status = exc.response.status_code
                resp_text = exc.response.text[:500]
                if 400 <= status < 500:
                    logger.error("LLM HTTP %d (non-retryable): %s", status, resp_text)
                    return "", []
                logger.warning("LLM HTTP %d (attempt %d): %s", status, attempt + 1, resp_text)
            except (httpx.ConnectError, httpx.ReadError, OSError) as exc:
                last_err = exc
                logger.warning("LLM connection error (attempt %d): %s", attempt + 1, exc)

        logger.error("LLM failed after 3 attempts: %s", last_err)
        return "", []

    def _parse_response(self, data: dict) -> tuple[str, list[dict]]:
        choices = data.get("choices", [])
        if not choices:
            logger.warning("LLM returned no choices: %s", json.dumps(data)[:300])
            return "", []

        msg = choices[0].get("message", {})

        content = msg.get("content") or ""
        content = _strip_thinking(content)

        if not content:
            rc = msg.get("reasoning_content") or ""
            if rc:
                after_think = rc.split("</think>", 1)[-1].strip() if "</think>" in rc else ""
                if after_think:
                    content = after_think
                else:
                    content = _strip_thinking(rc)

        content = _dedup_response(content)

        raw_calls = msg.get("tool_calls") or []
        tool_calls = [_sanitize_tool_call(tc) for tc in raw_calls]

        return content, tool_calls

    async def close(self):
        await self._client.aclose()
