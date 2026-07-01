# Agent Escalation Layer -- Design Proposal

**Date:** 2026-06-27
**Author:** Developer103
**Status:** Draft / RFC


## 1. Problem Statement

The malware generation framework uses a deterministic pipeline that progresses
through fixed stages (plan, chunk-gen, assembly, smooth, wire, compile, deploy).
Each stage has built-in retry loops, but those loops are *blind*: they feed
errors back to the LLM as text and hope for a corrected output. The LLM has no
ability to inspect its environment, read headers, run experiments, or
iteratively narrow down a fix.

### Specific Failure Modes

**Failure Mode 1: Chunk generation exhausts retries**
Location: `generation_engine.py` line ~4148-4205 (`_generate_chunks`)

The pipeline retries each chunk up to 6 times (`_CHUNK_RETRIES = 6`). On each
retry it feeds the syntax error back to the LLM. But the LLM cannot:
- Read the MinGW header files to see the actual function signatures
- Check what typedefs are available in `windows.h` vs `winhttp.h`
- Grep the codebase for how similar functions were implemented before
- Run the compiler itself to test incremental fixes

After 2 identical errors, it bails early (line 4186-4194). After 3 consecutive
garbage chunks, it disables thinking mode (line 4212-4218). Neither of these is
a *fix* -- they are surrender strategies.

**Failure Mode 2: Compile-fix loop cannot resolve errors**
Location: `generation_engine.py` line ~3087-3206 (`ErrorAnalyzer.fix_compile_error`)

The compile-fix loop has two phases: deterministic regex-based fixes, then LLM
fix. The LLM phase extracts erroring functions, sends them with the error text,
and asks for a corrected version. When both cloud and local LLMs return nothing
(line 3150) or the output cannot be spliced back (line 3183), it returns `None`
and the pipeline proceeds with broken code.

The LLM is asked to fix code without being able to:
- Read `x86_64-w64-mingw32-gcc` header paths to see actual declarations
- Check which MinGW libraries are available (`-lws2_32`, `-lwinhttp`, etc.)
- Run a test compilation to see if a proposed fix actually works
- Examine the linking order or the full compiler invocation

**Failure Mode 3: Main wiring cannot converge**
Location: `generation_engine.py` line ~4321-4444 (`_validate_main_wiring`)

After 3 rewire attempts (`_MAX_REWIRE_RETRIES = 3`), the pipeline gives up and
proceeds with a broken `main()` (line 4443). The LLM sees the missing calls but
has no way to inspect the function signatures, check dependencies, or
iteratively test its fixes.

**Failure Mode 4: Pipeline compile-fix streak**
Location: `pipeline.py` line ~656-676

When 2+ consecutive compile-fix attempts fail within the VM verification loop,
the pipeline escalates to a full rewrite analysis -- but using the *same LLM*
with the *same limitations*. This is escalation without capability gain.

### Root Cause

All failure modes share the same root cause: **the LLM operates as a
text-in/text-out function with no tool access**. It cannot inspect the build
environment, run experiments, or iteratively refine its approach. An agent with
tool access (file reading, compilation, header inspection, source modification)
could handle these cases where blind text generation fails.


## 2. Pattern 1: Local Hermes Agent

### 2.1 Overview

[Hermes](https://huggingface.co/NousResearch) is a function-calling/tool-use
fine-tuned model family from NousResearch. Unlike Qwen3 (which the framework
currently uses as a text generator), Hermes is specifically trained to emit
structured tool calls and process tool results in a multi-turn ReAct loop.

### 2.2 Architecture

```
                         CURRENT PIPELINE
                    ========================
                    |                      |
  [DB Query] --> [Context] --> [Plan] --> [Chunk Gen] --+--> [Assembly]
                                              |         |
                                         6 retries      |
                                         (text-only)    |
                                              |         |
                                          FAIL (>6)     |
                                              |         v
                                              |    [Smooth Pass]
                                              |         |
                                              v         v
                                    +------------------+--+
                                    |  ESCALATION GATE    |
                                    |  (new module)       |
                                    +----------+----------+
                                               |
                              +----------------+----------------+
                              |                                 |
                              v                                 v
                    +---------+---------+            +----------+----------+
                    | HERMES AGENT LOOP |            | (Pattern 2 fallback)|
                    |                   |            +---------------------+
                    | Tools:            |
                    |  - read_file      |
                    |  - write_file     |
                    |  - compile        |
                    |  - grep_source    |
                    |  - read_headers   |
                    |  - read_errors    |
                    |                   |
                    | ReAct loop:       |
                    |  Think -> Act ->  |
                    |  Observe -> ...   |
                    |  (max 15 turns)   |
                    +-------------------+
                              |
                         Fixed source
                              |
                              v
                    [Resume pipeline at
                     next stage]
```

### 2.3 Model Selection

| Model                    | Size (Q4) | VRAM   | Context | Tool Quality | Recommendation |
|--------------------------|-----------|--------|---------|--------------|----------------|
| Hermes-3-Llama-3.1-8B   | ~5 GB     | 6 GB   | 128K    | Good         | Dev/testing    |
| Hermes-4.3-36B           | ~20 GB    | 24 GB  | 128K    | Excellent    | Production     |

Hermes-4.3-36B is the recommended production model. It has hybrid thinking
mode (`<think></think>` tags), built-in JSON self-repair for malformed tool
calls, and significantly stronger reasoning than the 8B variant.

For development, Hermes-3-8B is sufficient and can run alongside Qwen3 on a
single GPU.

### 2.4 Tool-Calling Format

Hermes uses ChatML with XML tags for tool calling. Tools are defined in the
system prompt inside `<tools></tools>` tags. The model emits calls inside
`<tool_call></tool_call>` tags, and results are fed back inside
`<tool_response></tool_response>` tags.

**System prompt structure:**
```
<|im_start|>system
You are a compile-fix agent for a Windows malware generation framework.
You have access to tools for reading files, compiling code, and inspecting
the MinGW cross-compilation environment.

<tools>
[
  {
    "type": "function",
    "function": {
      "name": "read_file",
      "description": "Read a file from disk. Use for source code, headers, etc.",
      "parameters": {
        "type": "object",
        "properties": {
          "path": {"type": "string", "description": "Absolute file path"}
        },
        "required": ["path"]
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "compile",
      "description": "Cross-compile C source with MinGW. Returns compiler output.",
      "parameters": {
        "type": "object",
        "properties": {
          "source_path": {"type": "string"},
          "extra_flags": {"type": "string", "description": "Additional gcc flags"}
        },
        "required": ["source_path"]
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "modify_source",
      "description": "Replace a section of source code",
      "parameters": {
        "type": "object",
        "properties": {
          "file_path": {"type": "string"},
          "old_text": {"type": "string"},
          "new_text": {"type": "string"}
        },
        "required": ["file_path", "old_text", "new_text"]
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "grep_headers",
      "description": "Search MinGW headers for a symbol or type definition",
      "parameters": {
        "type": "object",
        "properties": {
          "pattern": {"type": "string", "description": "grep pattern"},
          "header_dir": {"type": "string", "description": "Header subdirectory (e.g. 'winhttp')"}
        },
        "required": ["pattern"]
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "list_mingw_libs",
      "description": "List available MinGW import libraries",
      "parameters": {
        "type": "object",
        "properties": {},
        "required": []
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "write_file",
      "description": "Write content to a file (for test compilations)",
      "parameters": {
        "type": "object",
        "properties": {
          "path": {"type": "string"},
          "content": {"type": "string"}
        },
        "required": ["path", "content"]
      }
    }
  }
]
</tools>

When you need to use a tool, emit a tool_call block. When you have enough
information, respond with the fixed source code directly.
<|im_end|>
```

**Model emits:**
```
<tool_call>
{"name": "grep_headers", "arguments": {"pattern": "WinHttpOpen", "header_dir": "winhttp"}}
</tool_call>
```

**Tool result fed back as:**
```
<|im_start|>tool
<tool_response>
{"name": "grep_headers", "content": "WINHTTPAPI HINTERNET WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);"}
</tool_response>
<|im_end|>
```

### 2.5 Agent Loop Implementation

The agent loop follows the ReAct pattern: the model reasons about the problem,
calls tools to gather information or test fixes, observes the results, and
repeats until the problem is solved or the turn limit is reached.

**Using LM Studio's Python SDK (recommended -- already in use for Qwen3):**

```python
import lmstudio as lms
import subprocess
import os
import re

# ---- Tool implementations ----

MINGW_PREFIX = "/usr/x86_64-w64-mingw32"
MINGW_INCLUDE = f"{MINGW_PREFIX}/include"
MINGW_LIB = f"{MINGW_PREFIX}/lib"

def read_file(path: str) -> str:
    """Read a file and return its contents."""
    try:
        with open(path, "r") as f:
            return f.read()[:16000]  # Cap at 16K chars
    except Exception as e:
        return f"Error: {e}"

def write_file(path: str, content: str) -> str:
    """Write content to a file."""
    try:
        with open(path, "w") as f:
            f.write(content)
        return f"Written {len(content)} bytes to {path}"
    except Exception as e:
        return f"Error: {e}"

def compile_source(source_path: str, extra_flags: str = "") -> str:
    """Cross-compile C source with MinGW and return compiler output."""
    cmd = f"x86_64-w64-mingw32-gcc {source_path} -o /tmp/test.exe {extra_flags}"
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        return "Compilation successful."
    return result.stderr[:8000]  # Cap error output

def modify_source(file_path: str, old_text: str, new_text: str) -> str:
    """Replace a section of source code."""
    try:
        with open(file_path, "r") as f:
            content = f.read()
        if old_text not in content:
            return "Error: old_text not found in file"
        content = content.replace(old_text, new_text, 1)
        with open(file_path, "w") as f:
            f.write(content)
        return "Replacement successful."
    except Exception as e:
        return f"Error: {e}"

def grep_headers(pattern: str, header_dir: str = "") -> str:
    """Search MinGW headers for a symbol or type definition."""
    search_path = os.path.join(MINGW_INCLUDE, header_dir) if header_dir else MINGW_INCLUDE
    result = subprocess.run(
        ["grep", "-r", "-n", "--include=*.h", pattern, search_path],
        capture_output=True, text=True, timeout=10
    )
    lines = result.stdout.strip().split("\n")[:20]  # Max 20 matches
    return "\n".join(lines) if lines[0] else "No matches found."

def list_mingw_libs() -> str:
    """List available MinGW import libraries."""
    result = subprocess.run(
        ["ls", MINGW_LIB],
        capture_output=True, text=True
    )
    libs = [f for f in result.stdout.split() if f.endswith(".a")]
    return "\n".join(libs[:50])


# ---- Agent loop ----

def run_hermes_agent(source_path: str, errors: str, plan: dict,
                     max_turns: int = 15) -> str | None:
    """
    Run the Hermes agent loop to fix compilation errors.

    Returns the fixed source code, or None if the agent cannot fix it.
    """
    model = lms.llm("hermes-3-llama-3.1-8b")  # or hermes-4.3-36b

    prompt = (
        f"Fix the compilation errors in {source_path}.\n\n"
        f"Compiler errors:\n```\n{errors}\n```\n\n"
        f"The source is a Windows malware component. It must cross-compile "
        f"with x86_64-w64-mingw32-gcc. Use the tools to inspect headers, "
        f"test fixes, and verify compilation.\n\n"
        f"Function plan:\n{plan}\n\n"
        f"Start by reading the source file, then systematically fix each error. "
        f"After each fix, recompile to check progress."
    )

    tools = [read_file, write_file, compile_source, modify_source,
             grep_headers, list_mingw_libs]

    result = model.act(
        prompt,
        tools,
        on_message=lambda msg: _log_agent_turn(msg),
        max_iterations=max_turns,
    )

    # Read the (hopefully fixed) source
    if os.path.exists(source_path):
        with open(source_path, "r") as f:
            return f.read()
    return None
```

**Alternative: OpenAI-compatible API (manual loop):**

For more control over the agent loop, or if LM Studio's `.act()` API is not
available, implement the loop manually against the `/v1/chat/completions`
endpoint:

```python
from openai import OpenAI
import json
import re

client = OpenAI(base_url="http://localhost:1234/v1", api_key="lm-studio")

TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "compile_source",
            "description": "Cross-compile C source with MinGW",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_path": {"type": "string"},
                    "extra_flags": {"type": "string"}
                },
                "required": ["source_path"]
            }
        }
    },
    # ... other tools ...
]

TOOL_DISPATCH = {
    "read_file": read_file,
    "write_file": write_file,
    "compile_source": compile_source,
    "modify_source": modify_source,
    "grep_headers": grep_headers,
    "list_mingw_libs": list_mingw_libs,
}

def hermes_agent_loop(messages: list, max_turns: int = 15) -> str:
    """Run a manual ReAct loop with Hermes via OpenAI-compat API."""

    for turn in range(max_turns):
        response = client.chat.completions.create(
            model="hermes-3-llama-3.1-8b",
            messages=messages,
            tools=TOOLS_SCHEMA,
            temperature=0.3,
        )

        choice = response.choices[0]
        messages.append(choice.message)

        # If no tool calls, the agent is done
        if choice.finish_reason != "tool_calls" or not choice.message.tool_calls:
            return choice.message.content

        # Execute each tool call
        for tc in choice.message.tool_calls:
            fn = TOOL_DISPATCH.get(tc.function.name)
            if fn is None:
                result = f"Unknown tool: {tc.function.name}"
            else:
                args = json.loads(tc.function.arguments)
                result = fn(**args)

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": str(result),
            })

    return messages[-1].get("content", "Agent loop exhausted.")
```

### 2.6 Integration Points

The Hermes agent should be invoked at these specific points in the existing
pipeline:

| Trigger Point                         | File                    | Line  | Condition                                  |
|---------------------------------------|-------------------------|-------|--------------------------------------------|
| Chunk retries exhausted               | `generation_engine.py`  | 4202  | `retries >= _CHUNK_RETRIES` and errors remain |
| Compile-fix LLM returns None          | `generation_engine.py`  | 3150  | Both cloud and local LLMs return nothing   |
| Compile-fix output unspliceable       | `generation_engine.py`  | 3183  | LLM output cannot be matched to source     |
| Main wiring exhausted                 | `generation_engine.py`  | 4443  | 3 rewire attempts failed                   |
| Pre-loop compile fails                | `pipeline.py`           | 459   | 3 pre-loop fix attempts failed             |
| Compile-fix streak in VM loop         | `pipeline.py`           | 676   | 2+ consecutive compile-fix failures        |

### 2.7 Pros and Cons

**Pros:**
- Zero cost per invocation (runs locally)
- Low latency (no network round-trip for API calls)
- Full control over the model, quantization, context window
- Can run alongside Qwen3 in LM Studio (model auto-load)
- Privacy: all data stays on the local machine
- The LM Studio OpenAI-compat API means minimal new code

**Cons:**
- Reasoning quality limited by model size (8B-36B vs 200B+ cloud models)
- VRAM contention: running Hermes alongside Qwen3 requires enough VRAM for
  both, or model-swap latency (~10-30s per swap)
- Smaller models (8B) may emit malformed tool-call JSON, especially with
  complex arguments
- No built-in web search or documentation lookup
- Requires downloading and configuring an additional model
- 36B model needs 24GB+ VRAM at Q4; 8B is weaker at multi-step reasoning

### 2.8 Example: Compile-Fix Scenario

**Current behavior** (fails): The source uses `WinHttpOpen` with wrong
argument types. The compiler emits `error: incompatible type for argument 1 of
'WinHttpOpen'`. The LLM receives this error text and guesses a fix -- but
guesses wrong because it does not know the actual signature. After 5 iterations
of wrong guesses, the pipeline gives up.

**With Hermes agent:**

```
Turn 1: Agent reads source file, sees WinHttpOpen call
Turn 2: Agent calls grep_headers("WinHttpOpen", "winhttp.h")
         -> Sees: HINTERNET WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD)
Turn 3: Agent calls modify_source() to fix the argument types
         (char* -> LPCWSTR, int -> DWORD)
Turn 4: Agent calls compile_source() to verify
         -> New error: undefined reference to `__imp_WinHttpOpen`
Turn 5: Agent calls list_mingw_libs()
         -> Sees libwinhttp.a is available
Turn 6: Agent calls compile_source(extra_flags="-lwinhttp")
         -> Compilation successful
Turn 7: Agent responds with the fix summary and notes -lwinhttp is needed
```

Total: 7 turns, ~30 seconds, zero cost. The deterministic pipeline would
have failed after 5 blind LLM retries.


## 3. Pattern 2: Claude Code Escalation

### 3.1 Overview

Claude Code is Anthropic's agentic coding tool. It has built-in tool use (file
reading, editing, shell commands, web search) and strong reasoning capabilities.
The framework can invoke it programmatically when the local pipeline and/or
Hermes agent cannot resolve an issue.

### 3.2 Architecture

```
                         CURRENT PIPELINE
                    ========================

  [Chunk Gen / Compile-Fix / Main Wiring]
              |
         FAIL (retries exhausted)
              |
              v
    +-------------------+
    | ESCALATION GATE   |
    | (agent_escalation |
    |  module)          |
    +---------+---------+
              |
              |  (if Hermes failed or skipped)
              v
    +----------------------------+
    | CLAUDE CODE INVOCATION     |
    |                            |
    |  Subprocess / SDK call:    |
    |  - Source file path        |
    |  - Compiler errors         |
    |  - Function plan (JSON)    |
    |  - MinGW header paths      |
    |  - Link flags              |
    |                            |
    |  Claude Code gets:         |
    |  - Read (filesystem)       |
    |  - Edit (source files)     |
    |  - Bash (compiler, grep)   |
    |  - Full reasoning          |
    |                            |
    |  Constraints:              |
    |  - max-turns: 20           |
    |  - max-budget: $2.00       |
    |  - permission: acceptEdits |
    |  - --bare (no hooks/MCP)   |
    +----------------------------+
              |
         Fixed source
         (read back from disk)
              |
              v
    [Resume pipeline at
     next stage]
```

### 3.3 Programmatic Invocation

There are two approaches: the CLI (`claude -p`) and the Python SDK
(`claude-agent-sdk`).

#### 3.3.1 CLI Invocation (`claude -p`)

The `claude` CLI supports a non-interactive print mode (`-p` / `--print`) that
takes a prompt, runs the agent loop, and exits. Key flags:

| Flag                     | Purpose                                         |
|--------------------------|-------------------------------------------------|
| `-p "prompt"`            | Non-interactive mode; single prompt in, output out |
| `--output-format json`   | Returns `{result, session_id, total_cost_usd, usage}` |
| `--max-turns N`          | Limit agent loop depth (default: unlimited)     |
| `--allowedTools "..."`   | Auto-approve specific tools without prompts     |
| `--model sonnet`         | Model selection (sonnet, opus, haiku)            |
| `--permission-mode X`    | `acceptEdits` auto-accepts file writes           |
| `--max-budget-usd N`    | Hard cost cap per invocation                     |
| `--bare`                 | Skip hooks/skills/MCP for faster startup         |
| `--cwd /path`            | Set working directory                            |
| `--json-schema '{...}'`  | Get structured output conforming to a schema     |

Stdin piping is supported (up to 10 MB).

**Implementation:**

```python
import subprocess
import json
import tempfile
import shutil

def escalate_to_claude_cli(source_path: str, errors: str,
                           plan: dict, link_flags: str = "") -> str | None:
    """
    Escalate a compile-fix to Claude Code via CLI.

    Writes the source to a temp working directory, invokes Claude Code,
    and reads back the fixed source.

    Returns fixed source code, or None on failure.
    """
    # Create isolated working directory
    work_dir = tempfile.mkdtemp(prefix="escalation_")
    work_source = os.path.join(work_dir, "malware_source.c")
    shutil.copy2(source_path, work_source)

    prompt = (
        f"Fix the compilation errors in {work_source}.\n\n"
        f"This is a Windows executable that must cross-compile with:\n"
        f"  x86_64-w64-mingw32-gcc {work_source} -o out.exe "
        f"-lws2_32 -lwinhttp -ladvapi32 {link_flags}\n\n"
        f"Compiler errors:\n```\n{errors}\n```\n\n"
        f"Function plan:\n```json\n{json.dumps(plan, indent=2)}\n```\n\n"
        f"MinGW headers are at: /usr/x86_64-w64-mingw32/include/\n"
        f"MinGW libs are at: /usr/x86_64-w64-mingw32/lib/\n\n"
        f"Fix every error. After each fix, recompile to verify. "
        f"Do not stop until compilation succeeds or you have exhausted "
        f"all reasonable approaches.\n\n"
        f"When done, the fixed source must be at {work_source}."
    )

    allowed_tools = ",".join([
        "Read",
        "Edit",
        "Bash(x86_64-w64-mingw32-gcc *)",
        "Bash(grep *)",
        "Bash(find *)",
        "Bash(ls *)",
    ])

    try:
        result = subprocess.run(
            [
                "claude", "-p", prompt,
                "--bare",
                "--output-format", "json",
                "--allowedTools", allowed_tools,
                "--max-turns", "20",
                "--max-budget-usd", "2.00",
                "--model", "sonnet",
                "--permission-mode", "acceptEdits",
                "--cwd", work_dir,
            ],
            capture_output=True, text=True,
            timeout=300,  # 5 minute timeout
        )

        if result.returncode != 0:
            logger.error(f"Claude Code exited {result.returncode}: {result.stderr}")
            return None

        output = json.loads(result.stdout)
        cost = output.get("total_cost_usd", 0)
        logger.info(f"Claude Code escalation cost: ${cost:.4f}")

        # Read back the (hopefully fixed) source
        if os.path.exists(work_source):
            with open(work_source, "r") as f:
                fixed = f.read()
            shutil.copy2(work_source, source_path)  # Copy back
            return fixed

    except subprocess.TimeoutExpired:
        logger.error("Claude Code escalation timed out (5 min)")
    except Exception as e:
        logger.error(f"Claude Code escalation failed: {e}")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    return None
```

#### 3.3.2 Python SDK (`claude-agent-sdk`)

The `claude-agent-sdk` package provides an async Python API that wraps the
Claude Code binary. It supports streaming results, multi-turn sessions, custom
MCP tools, and structured output.

**Installation:** `pip install claude-agent-sdk` (Python 3.10+)

**Implementation:**

```python
import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage

async def escalate_to_claude_sdk(source_path: str, errors: str,
                                  plan: dict, link_flags: str = "") -> tuple[str | None, float]:
    """
    Escalate a compile-fix to Claude Code via Python SDK.

    Returns (fixed_source, cost_usd) or (None, cost_usd).
    """
    work_dir = os.path.dirname(source_path)

    options = ClaudeAgentOptions(
        allowed_tools=[
            "Read", "Edit",
            "Bash(x86_64-w64-mingw32-gcc *)",
            "Bash(grep *)",
            "Bash(find *)",
            "Bash(ls *)",
        ],
        permission_mode="acceptEdits",
        max_turns=20,
        max_budget_usd=2.00,
        model="sonnet",
        cwd=work_dir,
        system_prompt={
            "type": "preset",
            "preset": "claude_code",
            "append": (
                "You are fixing MinGW cross-compilation errors for a "
                "Windows executable. The target compiler is "
                "x86_64-w64-mingw32-gcc. Headers are at "
                "/usr/x86_64-w64-mingw32/include/. "
                "After each fix, recompile to verify progress."
            ),
        },
    )

    prompt = (
        f"Fix the compilation errors in {source_path}.\n\n"
        f"Compile command: x86_64-w64-mingw32-gcc {source_path} "
        f"-o out.exe -lws2_32 -lwinhttp -ladvapi32 {link_flags}\n\n"
        f"Errors:\n```\n{errors}\n```\n\n"
        f"Plan:\n```json\n{json.dumps(plan, indent=2)}\n```"
    )

    cost = 0.0
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, ResultMessage):
            cost = message.total_cost_usd
            logger.info(
                f"Claude Code: {message.num_turns} turns, ${cost:.4f}"
            )

    # Read back fixed source
    if os.path.exists(source_path):
        with open(source_path, "r") as f:
            return f.read(), cost

    return None, cost


# Sync wrapper for use in the synchronous pipeline
def escalate_to_claude(source_path: str, errors: str,
                       plan: dict, link_flags: str = "") -> str | None:
    """Synchronous wrapper for Claude Code escalation."""
    fixed, cost = asyncio.run(
        escalate_to_claude_sdk(source_path, errors, plan, link_flags)
    )
    return fixed
```

#### 3.3.3 Custom MCP Tools (Advanced)

For tighter integration, the framework can expose custom tools to Claude Code
via an in-process MCP server. This lets Claude Code use framework-specific
capabilities (e.g., querying ChromaDB for similar code, running the verifier):

```python
from claude_agent_sdk import tool, create_sdk_mcp_server

@tool("query_chromadb", "Search the malware technique database",
      {"query": str, "n_results": int})
async def query_chromadb(args):
    results = chroma_collection.query(
        query_texts=[args["query"]], n_results=args.get("n_results", 5)
    )
    return {"content": [{"type": "text", "text": json.dumps(results)}]}

@tool("verify_compile", "Compile and report detailed diagnostics",
      {"source_path": str, "flags": str})
async def verify_compile(args):
    # Full pipeline compilation with detailed error extraction
    result = verifier.verify_standalone(args["source_path"], args.get("flags", ""))
    return {"content": [{"type": "text", "text": json.dumps(result)}]}

framework_tools = create_sdk_mcp_server(
    "malware-framework", "1.0.0",
    tools=[query_chromadb, verify_compile]
)

options = ClaudeAgentOptions(
    mcp_servers={"framework": framework_tools},
    allowed_tools=[
        "Read", "Edit", "Bash(x86_64-w64-mingw32-gcc *)",
        "mcp__framework__query_chromadb",
        "mcp__framework__verify_compile",
    ],
    # ... other options ...
)
```

### 3.4 Context to Pass

Each escalation should include:

| Context Item               | Size (approx) | Purpose                                    |
|----------------------------|---------------|--------------------------------------------|
| Source file path            | trivial       | Claude reads the file directly              |
| Compiler errors (full)     | 500-2K tokens | The errors to fix                          |
| Function plan (JSON)       | 200-500 tokens| What each function should do               |
| Compile command             | 50 tokens     | Exact gcc invocation with flags            |
| MinGW header/lib paths     | 50 tokens     | Where to find headers                      |
| Previous fix attempts      | 500-1K tokens | What was already tried (avoid repeating)   |
| Link flags                 | 50 tokens     | `-lws2_32 -lwinhttp` etc.                  |

**Total input context per escalation:** ~1.5-4K tokens (excluding source
file, which Claude reads via tool).

### 3.5 Cost Analysis

**Pricing (June 2026):**

| Model       | Input/MTok | Output/MTok | Cache Hit/MTok |
|-------------|-----------|-------------|----------------|
| Sonnet 4.6  | $3.00     | $15.00      | $0.30          |
| Opus 4.6    | $5.00     | $25.00      | $0.50          |
| Haiku 4.5   | $1.00     | $5.00       | $0.10          |

**Estimated cost per escalation (Sonnet, compile-fix):**

```
Input tokens per turn:
  System prompt + tools:  ~1,500
  Source file:            ~2,000  (500 lines)
  Compiler errors:          ~500
  Conversation history:   ~1,000  (grows per turn)
  ---------------------------------
  Average per turn:       ~5,000

Output tokens per turn:   ~2,000  (reasoning + tool calls + edits)

Typical escalation:  8-12 turns

Total input:   ~60K tokens  x $3/MTok  = $0.18
Total output:  ~20K tokens  x $15/MTok = $0.30
                                         ------
Estimated cost per escalation:            $0.48

With prompt caching (~70% hit rate):      ~$0.35
```

**Expected frequency:** Based on current failure rates, escalation would
trigger 1-3 times per pipeline run. At $0.35-0.48 per escalation, the cost
per pipeline run is approximately **$0.35-$1.44**.

**Comparison with current approach:** A failed pipeline run that restarts from
scratch (outer loop iteration) costs ~15-30 minutes of compute time and local
LLM inference. If Claude Code escalation prevents even one restart, it pays
for itself in time savings.

### 3.6 Pros and Cons

**Pros:**
- Dramatically stronger reasoning than any local model (Sonnet/Opus vs 8B-36B)
- Built-in tool use -- no custom agent loop code needed
- Can read files, edit, run bash commands, search the web
- `--bare` mode starts fast (~2s)
- Cost cap via `--max-budget-usd` prevents runaway spending
- Python SDK provides clean async API with streaming
- Can use structured output (`--json-schema`) for machine-readable results
- Session continuation (`--resume`) for multi-stage fixes

**Cons:**
- Cost per escalation ($0.35-0.50 with Sonnet)
- Requires internet connectivity
- Latency: network round-trips add 2-5s per turn
- External dependency on Anthropic API availability
- Source code is sent to Anthropic's servers (privacy consideration)
- Requires `claude` CLI or `claude-agent-sdk` installed and authenticated
- Cannot run in fully air-gapped environments

### 3.7 Example: Compile-Fix Scenario

Same scenario as Pattern 1: `WinHttpOpen` called with wrong argument types.

**Claude Code invocation:**
```bash
claude -p "Fix compile errors in /tmp/work/malware_source.c. \
  Compile with: x86_64-w64-mingw32-gcc malware_source.c -o out.exe -lwinhttp -lws2_32 \
  Errors: error: incompatible type for argument 1 of 'WinHttpOpen' \
  MinGW headers: /usr/x86_64-w64-mingw32/include/" \
  --bare --output-format json --max-turns 20 \
  --allowedTools "Read,Edit,Bash(x86_64-w64-mingw32-gcc *),Bash(grep *)" \
  --max-budget-usd 2.00 --model sonnet \
  --permission-mode acceptEdits --cwd /tmp/work
```

**What Claude Code does internally:**

```
Turn 1: Read malware_source.c -- see the WinHttpOpen call
Turn 2: Bash: grep -rn "WinHttpOpen" /usr/x86_64-w64-mingw32/include/winhttp.h
         -> HINTERNET WINAPI WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD)
Turn 3: Identifies the mismatch (char* vs LPCWSTR, int vs DWORD)
         Also notices missing L"" wide string prefix on the user agent
Turn 4: Edit malware_source.c -- fix argument types + add wide string literals
Turn 5: Bash: x86_64-w64-mingw32-gcc malware_source.c -o out.exe -lwinhttp -lws2_32
         -> New error: undefined reference to 'WinHttpSendRequest'
Turn 6: Bash: grep -rn "WinHttpSendRequest" /usr/x86_64-w64-mingw32/include/winhttp.h
         -> Finds the signature, notices additional missing parameters
Turn 7: Edit malware_source.c -- fix WinHttpSendRequest call
Turn 8: Bash: recompile -> success
Turn 9: Returns summary of all fixes made
```

Total: 9 turns, ~45 seconds, ~$0.40. The key difference from Pattern 1 is that
Claude's stronger reasoning means it is more likely to identify *all* related
issues in a single pass (e.g., noticing the wide string literal issue in Turn 3
without needing to fail and retry).


## 4. Comparison Table

| Dimension              | Pattern 1: Hermes Agent         | Pattern 2: Claude Code            |
|------------------------|---------------------------------|-----------------------------------|
| **Cost**               | Free (local inference)          | ~$0.35-0.50/escalation            |
| **Latency per turn**   | 1-5s (local GPU)                | 3-8s (network + inference)        |
| **Reasoning quality**  | Good (8B) / Very good (36B)     | Excellent (Sonnet) / Best (Opus)  |
| **Tool-use quality**   | Good (trained for it)           | Excellent (native capability)     |
| **Setup complexity**   | Medium (download model, config) | Low (CLI already installed)       |
| **Code complexity**    | High (custom agent loop)        | Low (subprocess or SDK call)      |
| **Privacy**            | Full (all local)                | Source sent to Anthropic          |
| **Internet required**  | No                              | Yes                               |
| **VRAM impact**        | +5-20 GB alongside Qwen3        | None (runs externally)            |
| **Reliability**        | May fail on complex errors      | Very high success rate            |
| **Max context**        | 128K tokens                     | 200K tokens                       |
| **Web search**         | No                              | Yes (can look up docs)            |
| **Cost cap**           | N/A (free)                      | `--max-budget-usd` flag           |
| **Parallel execution** | Needs separate LM Studio port   | Independent process               |
| **Air-gap compatible** | Yes                             | No                                |


## 5. Recommended Hybrid Approach

The two patterns are complementary. Use both in a tiered escalation strategy:

```
Pipeline Stage Fails
        |
        v
  [Deterministic Fixes]     <-- existing regex/heuristic fixes
        |
   still broken?
        |
        v
  [Current LLM Fix]         <-- existing Qwen3/Fugu text-only fix
        |
   still broken?
        |
        v
  [Tier 1: Hermes Agent]    <-- local, free, fast
        |                       Tool-use loop, 15 turns max
   still broken?                ~30 seconds
        |
        v
  [Tier 2: Claude Code]     <-- cloud, paid, powerful
        |                       Full agent, 20 turns max
   still broken?                ~2 minutes, ~$0.40
        |
        v
  [Tier 3: Claude Opus]     <-- cloud, expensive, deepest reasoning
        |                       20 turns, $2 budget
   still broken?                For the hardest cases
        |
        v
  [Record failure, skip     <-- existing behavior
   to next iteration]
```

**Decision logic:**

```python
class EscalationTier(Enum):
    HERMES_LOCAL = "hermes_local"
    CLAUDE_SONNET = "claude_sonnet"
    CLAUDE_OPUS = "claude_opus"

class EscalationGate:
    """Decides when and how to escalate."""

    def __init__(self, config: dict):
        self.enable_hermes = config.get("enable_hermes", True)
        self.enable_claude = config.get("enable_claude", True)
        self.claude_budget_per_run = config.get("claude_budget_per_run", 5.00)
        self.claude_spent = 0.0

    def should_escalate(self, failure_type: str, attempts: int,
                        error_text: str) -> EscalationTier | None:
        """Determine escalation tier based on failure context."""

        # Don't escalate trivial errors (missing semicolons, etc.)
        if self._is_trivial_error(error_text):
            return None

        # Tier 1: Hermes (if enabled and available)
        if self.enable_hermes:
            return EscalationTier.HERMES_LOCAL

        # Tier 2: Claude Sonnet (if budget allows)
        if (self.enable_claude and
                self.claude_spent < self.claude_budget_per_run * 0.7):
            return EscalationTier.CLAUDE_SONNET

        # Tier 3: Claude Opus (for the hardest cases, if budget allows)
        if (self.enable_claude and
                self.claude_spent < self.claude_budget_per_run):
            return EscalationTier.CLAUDE_OPUS

        return None  # Budget exhausted, fall back to existing behavior

    def escalate(self, tier: EscalationTier, source_path: str,
                 errors: str, plan: dict) -> str | None:
        """Execute the escalation."""

        if tier == EscalationTier.HERMES_LOCAL:
            return run_hermes_agent(source_path, errors, plan)

        elif tier == EscalationTier.CLAUDE_SONNET:
            fixed, cost = asyncio.run(
                escalate_to_claude_sdk(source_path, errors, plan)
            )
            self.claude_spent += cost
            return fixed

        elif tier == EscalationTier.CLAUDE_OPUS:
            fixed, cost = asyncio.run(
                escalate_to_claude_sdk(
                    source_path, errors, plan,
                    model_override="opus",
                    budget_override=2.00
                )
            )
            self.claude_spent += cost
            return fixed

        return None
```

**When does Tier 1 fail and Tier 2 kick in?**

- Complex multi-file dependency errors that require reasoning chains beyond
  8B/36B model capacity
- Errors involving uncommon Windows API patterns not well-represented in
  Hermes' training data
- Situations requiring web search (e.g., looking up undocumented MinGW
  behavior)
- Cases where the 128K context window is insufficient


## 6. Implementation Plan

### Phase 1: Escalation Hooks (1-2 days)

**Goal:** Add the detection layer -- identify *when* to escalate, without
implementing the agents yet.

**Tasks:**
1. Create `agent_escalation.py` module with `EscalationGate` class
2. Add `EscalationTier` enum and configuration dataclass
3. Insert hooks at the 6 trigger points identified in Section 2.6
4. Add logging/metrics: track escalation triggers, frequency, error types
5. Wire configuration into `pipeline.py` (enable/disable, budget caps)
6. Test with `escalate()` returning `None` (hooks fire but do nothing)

**Files to modify:**
- `generation_engine.py` -- 4 hook insertions (chunk retry, compile-fix x2, main wiring)
- `pipeline.py` -- 2 hook insertions (pre-loop compile, VM loop streak)
- New: `agent_escalation.py` -- escalation gate, tier enum, config

**Estimated effort:** 1-2 days

### Phase 2: Hermes Agent (2-3 days)

**Goal:** Implement Tier 1 local escalation.

**Tasks:**
1. Download and configure Hermes model in LM Studio
   - Hermes-3-8B for development, Hermes-4.3-36B for production
2. Implement tool functions (read_file, compile, grep_headers, modify_source,
   write_file, list_mingw_libs)
3. Implement agent loop using LM Studio's `.act()` API or manual OpenAI-compat
   loop
4. Add sandboxing: write-protect non-source files, cap tool execution time
5. Integrate with `EscalationGate.escalate()`
6. Test against historical failures (replay saved error logs)
7. Add metrics: success rate, turns used, time per escalation

**Files to modify:**
- `agent_escalation.py` -- add `HermesAgent` class, tool implementations
- LM Studio config -- add Hermes model

**Estimated effort:** 2-3 days

### Phase 3: Claude Code Integration (1-2 days)

**Goal:** Implement Tier 2/3 cloud escalation.

**Tasks:**
1. Install `claude-agent-sdk` (or verify `claude` CLI is available)
2. Implement `escalate_to_claude_sdk()` with proper error handling
3. Add cost tracking and budget enforcement
4. Configure allowed tools and permission mode
5. Implement Opus fallback (Tier 3) with higher budget
6. Test against the same historical failures
7. Add cost reporting to pipeline output

**Files to modify:**
- `agent_escalation.py` -- add `ClaudeEscalation` class
- `requirements.txt` or `pyproject.toml` -- add `claude-agent-sdk`
- Pipeline report output -- add escalation cost summary

**Estimated effort:** 1-2 days

### Phase 4: Tuning and Hardening (2-3 days)

**Goal:** Optimize the hybrid system based on real-world runs.

**Tasks:**
1. Run 10+ full pipeline iterations, collect escalation metrics
2. Tune trigger thresholds (when to escalate vs retry)
3. Tune agent prompts based on success/failure patterns
4. Add escalation result caching (if same error pattern seen before, skip
   agent and apply cached fix)
5. Add timeout handling and graceful degradation
6. Document escalation patterns in framework logs

**Estimated effort:** 2-3 days

**Total estimated effort: 6-10 days**


## 7. Integration with Current Codebase

### 7.1 New Module: `agent_escalation.py`

This is the only new file. It contains:

```python
"""
Agent escalation layer for the malware generation framework.

Provides tiered escalation when the deterministic pipeline cannot
resolve compilation errors, chunk generation failures, or main
wiring issues.

Tiers:
  1. Hermes Agent (local, free, fast)
  2. Claude Code Sonnet (cloud, ~$0.40/escalation)
  3. Claude Code Opus (cloud, ~$1.00/escalation)
"""

import os
import json
import logging
import subprocess
import asyncio
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("malware_gen.escalation")


class EscalationTier(Enum):
    HERMES_LOCAL = "hermes_local"
    CLAUDE_SONNET = "claude_sonnet"
    CLAUDE_OPUS = "claude_opus"


@dataclass
class EscalationConfig:
    """Configuration for the escalation layer."""
    enable_hermes: bool = True
    enable_claude: bool = True
    hermes_model: str = "hermes-3-llama-3.1-8b"
    hermes_base_url: str = "http://localhost:1234/v1"
    hermes_max_turns: int = 15
    claude_model: str = "sonnet"
    claude_max_turns: int = 20
    claude_budget_per_run: float = 5.00
    claude_budget_per_escalation: float = 2.00
    working_dir: str = "/tmp/escalation"
    mingw_include: str = "/usr/x86_64-w64-mingw32/include"
    mingw_lib: str = "/usr/x86_64-w64-mingw32/lib"


@dataclass
class EscalationResult:
    """Result of an escalation attempt."""
    tier: EscalationTier
    success: bool
    fixed_source: Optional[str] = None
    turns_used: int = 0
    cost_usd: float = 0.0
    error_message: Optional[str] = None
    duration_seconds: float = 0.0


class EscalationGate:
    """
    Central escalation coordinator.

    Decides when to escalate, which tier to use, and tracks
    budget/metrics across the pipeline run.
    """

    def __init__(self, config: EscalationConfig):
        self.config = config
        self.claude_spent = 0.0
        self.escalation_history: list[EscalationResult] = []
        self._hermes_agent = None
        self._claude_agent = None

    def should_escalate(self, error_text: str, attempts: int) -> Optional[EscalationTier]:
        """Determine if and how to escalate."""
        # ... (decision logic as shown in Section 5)

    def escalate(self, tier: EscalationTier, source_path: str,
                 errors: str, plan: dict,
                 link_flags: str = "") -> EscalationResult:
        """Execute the escalation and return the result."""
        # ... (dispatch to Hermes or Claude)

    def get_summary(self) -> dict:
        """Return escalation metrics for the pipeline report."""
        return {
            "total_escalations": len(self.escalation_history),
            "successful": sum(1 for r in self.escalation_history if r.success),
            "total_cost_usd": self.claude_spent,
            "by_tier": {
                tier.value: {
                    "count": sum(1 for r in self.escalation_history
                                if r.tier == tier),
                    "successes": sum(1 for r in self.escalation_history
                                    if r.tier == tier and r.success),
                }
                for tier in EscalationTier
            },
        }
```

### 7.2 Modifications to `generation_engine.py`

**Hook 1: Chunk retry exhaustion** (line ~4202)

```python
# BEFORE (existing):
else:
    logger.warning(f"Chunk {spec.name} still has errors after {retries} retries")
    # uses best_attempt

# AFTER (with escalation):
else:
    logger.warning(f"Chunk {spec.name} still has errors after {retries} retries")
    if self.escalation_gate:
        tier = self.escalation_gate.should_escalate(best_errors, retries)
        if tier:
            result = self.escalation_gate.escalate(
                tier, chunk_path, best_errors,
                {"function": spec.name, "signature": spec.signature}
            )
            if result.success:
                best_attempt = result.fixed_source
                logger.info(f"Escalation ({tier.value}) fixed chunk {spec.name}")
```

**Hook 2: Compile-fix LLM returns None** (line ~3150)

```python
# BEFORE:
if not fixed_source:
    return None

# AFTER:
if not fixed_source:
    if self.escalation_gate:
        tier = self.escalation_gate.should_escalate(error_text, 0)
        if tier:
            result = self.escalation_gate.escalate(
                tier, source_path, error_text, self._current_plan
            )
            if result.success:
                return result.fixed_source
    return None
```

**Hook 3: Compile-fix output unspliceable** (line ~3183)

Same pattern as Hook 2 -- escalate when the LLM output cannot be matched back
to source functions.

**Hook 4: Main wiring exhausted** (line ~4443)

```python
# BEFORE:
logger.error("Main rewire FAILED after 3 attempts")

# AFTER:
logger.error("Main rewire FAILED after 3 attempts")
if self.escalation_gate:
    tier = self.escalation_gate.should_escalate(
        "Main wiring failed: " + missing_calls_summary, 3
    )
    if tier:
        result = self.escalation_gate.escalate(
            tier, source_path,
            f"main() is missing calls to: {missing_calls_summary}",
            self._current_plan
        )
        if result.success:
            source = result.fixed_source
            logger.info("Escalation fixed main wiring")
```

### 7.3 Modifications to `pipeline.py`

**Hook 5: Pre-loop compile fails** (line ~459)

```python
# BEFORE:
logger.warning("Source still does not compile after 3 fix attempts")

# AFTER:
if self.escalation_gate:
    result = self.escalation_gate.escalate(
        EscalationTier.HERMES_LOCAL,  # Start with Hermes
        source_path, compile_errors, plan
    )
    if result.success:
        source = result.fixed_source
    elif self.escalation_gate.config.enable_claude:
        result = self.escalation_gate.escalate(
            EscalationTier.CLAUDE_SONNET,
            source_path, compile_errors, plan
        )
        if result.success:
            source = result.fixed_source
```

**Hook 6: Compile-fix streak in VM loop** (line ~676)

Same tiered pattern: try Hermes first, then Claude if Hermes fails.

### 7.4 Configuration

Add escalation config to the pipeline's configuration system:

```python
# In pipeline initialization
escalation_config = EscalationConfig(
    enable_hermes=config.get("escalation_hermes", True),
    enable_claude=config.get("escalation_claude", True),
    hermes_model=config.get("escalation_hermes_model", "hermes-3-llama-3.1-8b"),
    claude_budget_per_run=config.get("escalation_claude_budget", 5.00),
)
self.escalation_gate = EscalationGate(escalation_config)
```

### 7.5 Pipeline Report Integration

Add escalation metrics to the pipeline report output:

```python
# In pipeline report generation
escalation_summary = self.escalation_gate.get_summary()
report += f"\n--- Escalation Summary ---\n"
report += f"Total escalations: {escalation_summary['total_escalations']}\n"
report += f"Successful: {escalation_summary['successful']}\n"
report += f"Total Claude cost: ${escalation_summary['total_cost_usd']:.2f}\n"
for tier, stats in escalation_summary['by_tier'].items():
    if stats['count'] > 0:
        report += f"  {tier}: {stats['successes']}/{stats['count']} succeeded\n"
```

### 7.6 File Summary

| File                     | Action  | Changes                                          |
|--------------------------|---------|--------------------------------------------------|
| `agent_escalation.py`    | CREATE  | EscalationGate, HermesAgent, ClaudeEscalation    |
| `generation_engine.py`   | MODIFY  | 4 escalation hooks (chunk, compile-fix x2, main) |
| `pipeline.py`            | MODIFY  | 2 escalation hooks (pre-loop, VM streak)         |
| `__init__.py`            | MODIFY  | Export EscalationGate, EscalationConfig           |
| `requirements.txt`       | MODIFY  | Add `claude-agent-sdk`, `lmstudio` (optional)    |


---

## Appendix A: Hermes Tool-Call Wire Format Reference

```
# System prompt with tools
<|im_start|>system
You are a function calling AI model...
<tools>
[{"type": "function", "function": {"name": "...", ...}}]
</tools>
<|im_end|>

# User message
<|im_start|>user
Fix the compilation errors...
<|im_end|>

# Model emits tool call
<|im_start|>assistant
I need to check the header file first.
<tool_call>
{"name": "grep_headers", "arguments": {"pattern": "WinHttpOpen"}}
</tool_call>
<|im_end|>

# Tool result
<|im_start|>tool
<tool_response>
{"name": "grep_headers", "content": "HINTERNET WinHttpOpen(LPCWSTR, ...)"}
</tool_response>
<|im_end|>

# Model continues...
<|im_start|>assistant
Now I see the correct signature. Let me fix the arguments.
<tool_call>
{"name": "modify_source", "arguments": {"file_path": "...", "old_text": "...", "new_text": "..."}}
</tool_call>
<|im_end|>
```

## Appendix B: Claude Code CLI Quick Reference

```bash
# Basic compile-fix escalation
claude -p "Fix errors in source.c: <errors>" \
  --bare --output-format json \
  --allowedTools "Read,Edit,Bash(x86_64-w64-mingw32-gcc *)" \
  --max-turns 20 --max-budget-usd 2.00 \
  --model sonnet --permission-mode acceptEdits

# With stdin piping (source + errors)
cat errors.txt | claude -p "Fix the compile errors shown in stdin for source.c" \
  --bare --output-format json

# Structured output (get fix summary as JSON)
claude -p "Fix errors..." --json-schema '{
  "type": "object",
  "properties": {
    "fixed": {"type": "boolean"},
    "changes": {"type": "array", "items": {"type": "string"}},
    "additional_flags": {"type": "string"}
  }
}'

# Resume a previous session
claude -p "Continue fixing" --resume <session_id>
```

## Appendix C: Risk Mitigation

| Risk                        | Mitigation                                           |
|-----------------------------|------------------------------------------------------|
| Hermes modifies wrong files | Sandbox: only allow writes to working directory      |
| Claude Code runs wild       | `--max-budget-usd`, `--max-turns`, restricted tools  |
| Cost overrun                | Per-run budget cap, per-escalation cap, metrics       |
| VRAM exhaustion             | Use LM Studio model auto-load; 8B model is small     |
| API downtime                | Claude is Tier 2/3; pipeline works without it         |
| Agent loop hangs            | Timeout per escalation (5 min Hermes, 5 min Claude)  |
| Bad agent fix breaks code   | Always keep pre-escalation backup; verify after fix   |
| Privacy/data leak           | Hermes is fully local; Claude opt-in per config       |
