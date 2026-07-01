"""C source code analysis, parsing, and compiler-error fixing utilities."""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .generation_engine import ComponentSpec

from .llm_client import _strip_thinking

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# NT struct definitions for MinGW compatibility
# ---------------------------------------------------------------------------

_SAFE_NT_STRUCTS = """\
/* MinGW-safe NT handle struct definitions — injected by framework */
#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR                         NumberOfHandles;
    ULONG_PTR                         Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;\
"""

_BAD_NT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\bSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX\b'), "SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX"),
    (re.compile(r'\bSystemExtendedHandleInformation\b'),   "SystemExtendedHandleInformation"),
    (re.compile(r'\.ObjectName\b'),                        ".ObjectName (hallucinated field)"),
]


# ---------------------------------------------------------------------------
# C source utilities
# ---------------------------------------------------------------------------

def _is_guardrail_refusal(text: str) -> bool:
    """Return True if an LLM response is a guardrail refusal rather than code.

    Called on raw Fugu output before cleaning.  Detects two cases:
      1. Response has no code structure at all (no braces / parentheses).
      2. First 400 chars contain refusal language AND no C code markers appear
         in the opening 200 chars (avoids false-positives on valid code that
         happens to use a word like "illegal" in a comment).
    """
    if not text:
        return True
    stripped = text.strip()
    if len(stripped) < 30:
        return True
    if "{" not in stripped and "(" not in stripped:
        return True

    # If the response opens with recognisable C tokens, accept it regardless
    # of whatever natural-language noise follows.
    _c_openers = (
        "#include", "void ", "int ", "BOOL ", "HANDLE ", "DWORD ",
        "static ", "LRESULT", "HRESULT", "char ", "unsigned ",
    )
    if any(stripped[:200].startswith(tok) or f"\n{tok}" in stripped[:200] for tok in _c_openers):
        return False

    _refusal_phrases = (
        "i cannot", "i can't", "i'm not able", "i am not able",
        "i don't assist", "i do not assist", "i won't help", "i will not help",
        "i apologize", "i'm sorry, but", "i am sorry, but",
        "i'm unable", "i am unable",
        "cannot assist", "cannot help", "not able to assist",
        "against my guidelines", "my ethical guidelines",
        "harmful content", "illegal activity", "malicious software",
        "i must decline", "i need to decline",
        "as an ai", "as a language model",
    )
    head = stripped[:400].lower()
    return any(phrase in head for phrase in _refusal_phrases)


def _strip_chunk_noise(text: str) -> str:
    """Post-process a single-function chunk response.

    Applied after _clean_c_source specifically for chunk generation output.
    Removes two classes of noise that _clean_c_source doesn't handle:

      1. #include lines — the assembler owns includes; a chunk that adds its own
         causes duplicate includes in the final source.
      2. Trailing prose after the function body — anything after the last } that
         isn't part of the function (e.g. "Note: you should also...") gets cut.
    """
    if not text:
        return text

    # Strip standalone #include lines
    lines = []
    for line in text.splitlines():
        if re.match(r"^\s*#\s*include\s*[<\"]", line):
            continue
        lines.append(line)
    text = "\n".join(lines)

    # Truncate at last closing brace — everything after is trailing prose
    last_brace = text.rfind("}")
    if last_brace >= 0:
        text = text[: last_brace + 1]

    return text.strip()


def _brace_deficit(text: str) -> int:
    """Return opens - closes. 0 means balanced. Positive means unclosed blocks.

    Skips braces inside string literals and line/block comments to avoid false
    positives from printf format strings or comment examples.
    """
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == '\\':
                    i += 1  # skip escaped char
                i += 1
            i += 1
            continue
        if c == "'" and i + 2 < n and text[i + 2] == "'":
            i += 3
            continue
        if c == '/' and i + 1 < n:
            if text[i + 1] == '/':
                while i < n and text[i] != '\n':
                    i += 1
                continue
            if text[i + 1] == '*':
                i += 2
                while i + 1 < n and not (text[i] == '*' and text[i + 1] == '/'):
                    i += 1
                i += 2
                continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
        i += 1
    return depth


def _autoclose_braces(text: str) -> str:
    """Append the missing closing braces to repair a truncated function body."""
    deficit = _brace_deficit(text)
    if deficit > 0:
        text = text.rstrip() + "\n" + "}" * deficit
    return text


_WIN32_API_RE = re.compile(
    r'\b('
    r'CreateFile[AW]|ReadFile|WriteFile|DeleteFile[AW]|FindFirstFile[AW]|FindNextFile[AW]|'
    r'FindClose|GetFileSize(?:Ex)?|SetFilePointer(?:Ex)?|MoveFile[AW]|CopyFile[AW]|'
    r'GetLogicalDrives|CreateDirectory[AW]|RemoveDirectory[AW]|'
    r'RegOpenKeyEx[AW]|RegQueryValueEx[AW]|RegSetValueEx[AW]|RegEnumKeyEx[AW]|'
    r'RegEnumValue[AW]|RegCreateKeyEx[AW]|RegDeleteValue[AW]|RegCloseKey|'
    r'CreateToolhelp32Snapshot|Process32First|Process32Next|Module32First|Module32Next|'
    r'OpenProcess|TerminateProcess|GetCurrentProcessId|GetModuleFileName[AW]|'
    r'GetProcessHandleCount|'
    r'CryptAcquireContext[AW]|CryptGenRandom|CryptCreateHash|CryptHashData|'
    r'CryptDeriveKey|CryptEncrypt|CryptDecrypt|CryptReleaseContext|'
    r'CryptDestroyHash|CryptDestroyKey|CryptExportKey|'
    r'WNetOpenEnum[AW]|WNetEnumResource[AW]|WNetCloseEnum|'
    r'GetExtendedTcpTable|'
    r'SHGetFolderPath[AW]|GetEnvironmentVariable[AW]|ShellExecute[AW]|'
    r'GetComputerName[AW]|GetUserName[AW]|GetVersionEx[AW]|'
    r'LoadLibrary[AW]|GetProcAddress|FreeLibrary|'
    r'WSAStartup|socket|connect|send|recv|closesocket|inet_addr|htons|'
    r'CreateThread|WaitForSingleObject|Sleep|CloseHandle|'
    r'VirtualAlloc|VirtualProtect|HeapAlloc|HeapFree|'
    r'SetUnhandledExceptionFilter|SetErrorMode|'
    r'ExpandEnvironmentStrings[AW]|GetTempPath[AW]|GetTempFileName[AW]'
    r')\b'
)


def _validate_chunk_substance(
    chunk_code: str,
    func_name: str,
    responsibility: str,
    signature: str,
    language: str = "c",
) -> tuple[bool, str]:
    """Check whether a generated chunk is a stub or has obvious quality issues.

    Returns (ok, reason). When ok is False, reason explains why so a retry
    prompt can include it.
    """
    lines = chunk_code.splitlines()

    code_lines = []
    comment_lines = 0
    in_block_comment = False
    for ln in lines:
        stripped = ln.strip()
        if not stripped:
            continue
        if in_block_comment:
            comment_lines += 1
            if '*/' in stripped:
                in_block_comment = False
            continue
        if stripped.startswith('/*'):
            comment_lines += 1
            if '*/' not in stripped:
                in_block_comment = True
            continue
        if stripped.startswith('//'):
            comment_lines += 1
            continue
        code_lines.append(stripped)

    if func_name == "main":
        return True, ""

    _min_lines = 3 if language in ("go", "rust") else 5
    if len(code_lines) < _min_lines:
        return False, (
            f"Function body has only {len(code_lines)} code lines (excluding comments/blanks). "
            f"This looks like a stub. Implement the full logic described in the purpose."
        )

    if language == "c":
        ret_type = ""
        sig_lower = signature.lower() if signature else ""
        for t in ("bool", "dword", "int", "handle", "hresult", "long", "lstatus", "uint", "size_t", "char"):
            if t in sig_lower.split("(")[0].lower():
                ret_type = t
                break
        if ret_type and not any("return" in cl for cl in code_lines):
            return False, (
                f"Function returns {ret_type.upper()} but has no return statement. "
                f"Add proper return paths for success and failure."
            )

    if comment_lines > len(code_lines) and comment_lines > 3:
        return False, (
            f"Too many comments ({comment_lines}) vs code ({len(code_lines)}). "
            f"Remove all comments and implement the actual logic."
        )

    self_call_re = re.compile(r'\b' + re.escape(func_name) + r'\s*\(')
    for cl in code_lines:
        if self_call_re.search(cl) and '{' not in cl:
            return False, (
                f"Function calls itself recursively. This will cause infinite recursion or "
                f"stack overflow. Implement the logic iteratively instead."
            )

    if language == "c":
        resp_apis = set(m.group(1) for m in _WIN32_API_RE.finditer(responsibility))
        if len(resp_apis) >= 2:
            body_text = "\n".join(code_lines)
            found = sum(1 for api in resp_apis if api in body_text)
            coverage = found / len(resp_apis)
            if coverage < 0.3:
                missing = [a for a in resp_apis if a not in body_text]
                return False, (
                    f"Purpose mentions APIs [{', '.join(list(resp_apis)[:5])}] but only "
                    f"{found}/{len(resp_apis)} appear in the code. Missing: "
                    f"{', '.join(missing[:4])}. Implement the full API sequence."
                )

    return True, ""


def _extract_by_signature(text: str, func_name: str) -> Optional[str]:
    """Find a C function definition by name and brace-match to extract it.

    Looks for 'func_name(' in a line that starts a function definition,
    then counts braces to find the complete body. Returns None if not found.
    """
    lines = text.splitlines()
    start_idx = None
    for i, line in enumerate(lines):
        s = line.strip()
        if func_name + "(" in s or func_name + " (" in s:
            if re.search(r'\b\w+[\s*]+' + re.escape(func_name) + r'\s*\(', s):
                start_idx = i
                break
            if s.startswith(func_name + "("):
                if i > 0 and re.match(r'^(static\s+|const\s+)?\w+[\s*]*$', lines[i-1].strip()):
                    start_idx = i - 1
                    break
                start_idx = i
                break

    if start_idx is None:
        return None

    depth = 0
    found_open = False
    end_idx = start_idx
    for i in range(start_idx, len(lines)):
        for ch in lines[i]:
            if ch == '{':
                depth += 1
                found_open = True
            elif ch == '}':
                depth -= 1
        if found_open and depth <= 0:
            end_idx = i
            break
    else:
        if found_open:
            end_idx = len(lines) - 1
        else:
            return None

    return "\n".join(lines[start_idx:end_idx + 1]).strip()


def _graft_plan_signature(chunk_code: str, plan_sig: str) -> str:
    """Replace the LLM-generated function signature with the plan's pre-validated one.

    The plan's signature passed pre-validation (compiles). The LLM often
    generates malformed parameter lists (missing closing paren, wrong types).
    We only need the function BODY from the LLM — the signature is already known.
    """
    if not plan_sig or not chunk_code:
        return chunk_code
    sig = plan_sig.strip().rstrip(';').rstrip()
    sig = sig.strip('`')
    # Strip trailing prose/comments after the closing paren
    paren_match = re.search(r'\)\s*$', sig)
    if not paren_match:
        last_paren = sig.rfind(')')
        if last_paren != -1:
            sig = sig[:last_paren + 1]
    # Find the function body's opening brace — skip braces inside comments
    # and initializers by looking for ')' followed by optional whitespace then '{'
    m = re.search(r'\)\s*\{', chunk_code)
    if m:
        brace_pos = m.end() - 1
    else:
        brace_pos = chunk_code.find('{')
    if brace_pos == -1:
        return chunk_code
    body = chunk_code[brace_pos:]
    return sig + " " + body


def _clean_c_source(raw: str, func_name: str = "", language: str = "c") -> str:
    """Strip thinking, markdown, and prose lines from generated source code.

    Applied to all code generation output as a safety net for models that
    leak reasoning text inline into the code (e.g. Qwen3 with /no_think).

    When func_name is provided, uses signature-anchored extraction as the
    primary fallback before resorting to line-by-line heuristics.
    """
    if not raw:
        return raw

    # 1. Strip <think>...</think> blocks
    raw = _strip_thinking(raw)

    # 2. Unwrap markdown code fences if present — use the LAST fence, not the first.
    # Models sometimes put a "here is an example" fence first and the actual answer second.
    fences = list(re.finditer(r"```(?:c|cpp|C|rust|rs|go|golang)?\s*\n(.*?)```", raw, re.DOTALL | re.IGNORECASE))
    if fences:
        raw = fences[-1].group(1).strip()
        # For Rust/Go: fence extraction is sufficient — the C-specific line filter
        # mangles non-C code. Return directly after fence extraction.
        if language in ("rust", "go"):
            return raw
        # Fall through to line-by-line filter — fence content can contain prose

    # 2b. Signature-anchored extraction: find the expected function and brace-match.
    # This is far more robust than line-by-line heuristics because we know exactly
    # what we're looking for.
    if func_name:
        extracted = _extract_by_signature(raw, func_name)
        if extracted and len(extracted) > 20:
            return extracted

    # For Rust/Go without fences: strip thinking and return — don't apply C heuristics
    if language in ("rust", "go"):
        return raw

    # 3. Line-by-line filter — remove lines that are clearly prose/thinking
    out = []
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            out.append(line)
            continue

        # Markdown bullet points: "   - some prose text" or "   * ..."
        # Valid C lines never start with a bare hyphen/asterisk followed by a space
        # (pointer decls are like `int *p;` not `* pointer`; unary minus is never at line start)
        if re.match(r"^\s*[-*]\s+\w", s):
            continue

        # Lines with multiple inline-backtick spans mixed with English prose:
        # e.g. `IMAGE_SNAP_BY_ORDINAL` macro might not be defined if headers...
        # Heuristic: >=2 backtick pairs AND >4 prose words AND no semicolon/brace
        backtick_pairs = len(re.findall(r"`[^`]+`", s))
        if backtick_pairs >= 2 and ";" not in s and "{" not in s and "}" not in s:
            prose_words = re.findall(r"\b[a-z]{3,}\b", s)
            if len(prose_words) > 4:
                continue

        # Lines that are pure English prose starting with common thinking patterns
        _thinking_starts = (
            "Wait,", "Wait!", "Wait —", "Actually,", "Actually —",
            "I'll ", "I will ", "I should ", "I need ", "I can ",
            "Note:", "Note —", "Note that",
            "However,", "However —",
            "So,", "So —", "So the",
            "This means", "This is", "This should", "This will",
            "Since the", "Since we",
            "Let me", "Let's",
            "For the purposes", "For each",
            "The model", "The function", "The code", "The user",
            "Here's a", "Here is a", "Here are",
            "Alright,", "Alright —", "Okay,", "Okay —",
            "First,", "First —", "Now,", "Now —",
            "Finally,", "Finally —", "Next,", "Next —",
            "We need", "We should", "We can",
            "Call:", "Call ", "Calling ",
            "Maybe ", "Maybe,",
            "Check:", "Check ", "Checking ",
            "Match", "Matches", "Matched",
            "Yes,", "Yes!", "No,", "No!",
            "Good,", "Good.", "Good!",
            "Done.", "Done!", "Done,",
            "Correct", "Incorrect",
            "Looking ", "Result:",
            "Output:", "Expected",
            "But ", "But,",
            "Also,", "Also —",
            "Then,", "Then —",
            "It ", "It's ", "Its ",
            "There ",
            "That ", "That's",
        )
        if any(s.startswith(p) for p in _thinking_starts):
            # Extra safety: skip only if the line doesn't look like a C statement.
            # Lines with backtick-quoted code refs (e.g. `func(...)`) are still prose.
            _has_backtick_code = "`" in s
            _looks_like_c = (";" in s or "{" in s) and not _has_backtick_code
            if not _looks_like_c:
                continue

        # Lines containing backtick-quoted code references are LLM reasoning, not C.
        # e.g. "Call: `connect_c2_server(&c2_sock)` -> OK." or "Let's check `func(...)`"
        if "`" in s and ";" not in s and "{" not in s and "}" not in s:
            continue

        # Numbered reasoning steps: "1. **Analyze..." or "   2.  Foo bar" or "3. `func`:"
        if re.match(r"^\s*\d+\.\s+", s) and "{" not in s:
            continue
        # Markdown bullet points: "- Step 1: ..." or "  - collect data"
        if re.match(r"^\s*[-•]\s+", s) and ";" not in s and "{" not in s:
            continue
        # Markdown headers: "## Implementation" or "### Notes"
        if re.match(r"^\s*#{1,6}\s+", s):
            continue

        # Catch remaining prose: lines that are clearly English sentences, not C code.
        # Heuristic: starts with uppercase letter, has 2+ lowercase words, no semicolon,
        # no brace, and doesn't start with a C type/keyword.
        _c_line_starts = (
            "#", "//", "/*", "int ", "char ", "void ", "BOOL ", "DWORD ", "HANDLE ",
            "HKEY ", "SOCKET ", "LONG ", "HRESULT ", "LRESULT ", "BYTE ", "WORD ",
            "static ", "const ", "unsigned ", "signed ", "struct ", "typedef ",
            "if ", "if(", "else ", "else{", "for ", "for(", "while ", "while(",
            "switch ", "switch(", "case ", "return ", "break", "continue",
            "{", "}", "*", "(", ")", "do ", "do{", "goto ",
            # Rust keywords
            "fn ", "let ", "use ", "pub ", "mut ", "impl ", "mod ",
            "match ", "match(", "enum ", "trait ", "where ", "unsafe ",
            "extern ", "crate ", "super ", "self ", "Self ",
            # Go keywords
            "func ", "var ", "type ", "package ", "import ", "defer ",
            "go ", "chan ", "select ", "range ",
        )
        if s and s[0].isupper() and not any(s.startswith(k) for k in _c_line_starts):
            _no_c_ops = ";" not in s and "{" not in s and "}" not in s
            if _no_c_ops and "(" not in s and "=" not in s:
                continue
            _prose_words = re.findall(r"\b[a-z]{2,}\b", s)
            if len(_prose_words) >= 2 and _no_c_ops:
                continue
        # Short prose fragments: "Matches.", "OK.", "Call matches.", "Maybe not.", "Constraints:", etc.
        if re.match(r"^[A-Z][\w\s]{0,25}[\.\!\?:]$", s):
            continue
        # Arrow-result notation: "-> OK", "-> matches", "-> done" (LLM verification output)
        if re.match(r"^\s*->\s*[A-Za-z]", s) and ";" not in s and "{" not in s:
            continue

        out.append(line)

    result = "\n".join(out).strip()

    # 4. Structural cleanup: truncate trailing prose after last top-level '}'.
    # Any text after the final closing brace of the last function is guaranteed
    # to be LLM commentary, not C code.
    last_brace = result.rfind("\n}")
    if last_brace >= 0:
        trailing = result[last_brace + 2:].strip()
        if trailing and not trailing.startswith("#") and not trailing.startswith("//"):
            result = result[:last_brace + 2]

    return result



def _topo_sort(components: list[ComponentSpec]) -> list[ComponentSpec]:
    """Sort components so dependencies appear before dependents."""
    by_name = {c.name: c for c in components}
    result: list[ComponentSpec] = []
    visited: set[str] = set()

    def _visit(name: str) -> None:
        if name in visited or name not in by_name:
            return
        visited.add(name)
        for dep in by_name[name].dependencies:
            _visit(dep)
        result.append(by_name[name])

    for c in components:
        _visit(c.name)
    for c in components:
        if c.name not in visited:
            result.append(c)
    return result


def _extract_c_functions(source: str) -> dict[str, tuple[int, int]]:
    """Return {func_name: (start_char, end_char)} for each top-level C function."""
    _SKIP = frozenset(("if", "while", "for", "switch", "else", "do", "return",
                       "sizeof", "typedef", "struct", "enum", "union"))
    _pat = re.compile(
        r'^(?:(?:static|inline|__forceinline|WINAPI|APIENTRY|CALLBACK|__cdecl|__stdcall|'
        r'__declspec\([^)]*\)|__attribute__\([^)]*\))\s+)*'
        r'(?:(?:unsigned|signed|const|volatile|long|short)\s+)*'
        r'\w[\w\s\*]*\s+(?:(?:WINAPI|APIENTRY|CALLBACK|__cdecl|__stdcall)\s+)?(\w+)\s*\([^;{]*\)\s*\{',
        re.MULTILINE,
    )
    funcs: dict[str, tuple[int, int]] = {}
    for m in _pat.finditer(source):
        name = m.group(1)
        if name in _SKIP:
            continue
        depth, i, n = 1, m.end(), len(source)
        while i < n and depth > 0:
            ch = source[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            elif ch in ('"', "'"):
                q, i = ch, i + 1
                while i < n:
                    if source[i] == '\\':
                        i += 1
                    elif source[i] == q:
                        break
                    i += 1
            i += 1
        funcs[name] = (m.start(), i)
    return funcs


def _extract_go_functions(source: str) -> dict[str, tuple[int, int]]:
    """Return {func_name: (start_char, end_char)} for each top-level Go function."""
    _pat = re.compile(r'^func\s+(\w+)\s*\([^)]*\)[^{]*\{', re.MULTILINE)
    funcs: dict[str, tuple[int, int]] = {}
    for m in _pat.finditer(source):
        name = m.group(1)
        depth, i, n = 1, m.end(), len(source)
        while i < n and depth > 0:
            ch = source[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            elif ch in ('"', "'", '`'):
                if ch == '`':
                    i += 1
                    while i < n and source[i] != '`':
                        i += 1
                else:
                    q, i = ch, i + 1
                    while i < n:
                        if source[i] == '\\':
                            i += 1
                        elif source[i] == q:
                            break
                        i += 1
            i += 1
        funcs[name] = (m.start(), i)
    return funcs


def extract_functions(source: str, language: str = "c") -> dict[str, tuple[int, int]]:
    """Language-dispatching wrapper for function extraction."""
    if language == "go":
        return _extract_go_functions(source)
    return _extract_c_functions(source)


def _extract_chunk_signature(chunk_code: str) -> Optional[str]:
    """Extract the actual opening signature from a generated chunk.

    Returns everything from the start of the function up to (but not including)
    the opening brace, preserving any modifiers the LLM added (static, WINAPI, …).
    Used so the forward declaration matches the body exactly.
    """
    m = re.match(
        r'^((?:(?:static|inline|__forceinline|'
        r'__declspec\s*\([^)]*\)|__attribute__\s*\([^)]*\))\s+)*'
        r'(?:(?:unsigned|signed|const|volatile|long|short)\s+)*'
        r'\w[\w\*]*(?:\s+\*+|\s+)'
        r'(?:(?:WINAPI|APIENTRY|CALLBACK|__cdecl|__stdcall|__fastcall)\s+)?'
        r'\*?\w+\s*\([^;{]*\))\s*\{',
        chunk_code.strip(),
        re.DOTALL,
    )
    return m.group(1).strip() if m else None


def _replace_c_functions(source: str, patches: dict[str, str]) -> str:
    """Replace named C functions in source with patched versions (reverse order)."""
    funcs = _extract_c_functions(source)
    for name, (start, end) in sorted(
        [(n, funcs[n]) for n in patches if n in funcs],
        key=lambda x: x[1][0], reverse=True,
    ):
        source = source[:start] + patches[name].rstrip() + "\n" + source[end:]
    return source


# ---------------------------------------------------------------------------
# Compiler error fixers
# ---------------------------------------------------------------------------

def _scan_and_fix_nt_patterns(source: str) -> str:
    """Scan assembled source for known-bad NT patterns; inject correct defs if found.

    Called after _smooth_assembled_source and before compilation. Detects NT
    internals that the planner was forbidden to use but may have slipped through,
    and injects the correct struct definitions so the compiler at least has the
    type info — preventing cascading 'unknown type' errors.
    """
    found = [label for pat, label in _BAD_NT_PATTERNS if pat.search(source)]
    if not found:
        return source

    logger.warning(
        "Post-assembly NT pattern scan: found bad patterns %s — injecting correct structs",
        found,
    )

    # Check if the struct is already correctly defined (typedef present)
    if "typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX" in source:
        logger.info("Post-assembly NT scan: struct already defined — skipping injection")
        return source

    # Insert before the first function body so the type is available globally
    funcs = _extract_c_functions(source)
    if funcs:
        first_func_start = min(s for s, _ in funcs.values())
        return (
            source[:first_func_start].rstrip()
            + "\n\n"
            + _SAFE_NT_STRUCTS
            + "\n\n"
            + source[first_func_start:]
        )

    return _SAFE_NT_STRUCTS + "\n\n" + source


# ---------------------------------------------------------------------------
# Custom type fixer — catches LLM-invented typedefs not in any header
# ---------------------------------------------------------------------------

# Types that are defined in standard MinGW headers and should NOT be "fixed"
_KNOWN_WIN32_TYPES = frozenset({
    "HANDLE", "DWORD", "BOOL", "BYTE", "WORD", "LONG", "ULONG", "UINT", "INT",
    "PVOID", "LPVOID", "LPCVOID", "LPSTR", "LPCSTR", "LPWSTR", "LPCWSTR",
    "LPTSTR", "LPCTSTR", "TCHAR", "CHAR", "WCHAR", "HMODULE", "HINSTANCE",
    "HWND", "HDC", "HKEY", "HRESULT", "LPARAM", "WPARAM", "LRESULT",
    "PROCESSENTRY32", "PROCESSENTRY32W", "MODULEENTRY32", "MODULEENTRY32W",
    "THREADENTRY32", "HEAPENTRY32", "HEAPLIST32",
    "WIN32_FIND_DATAA", "WIN32_FIND_DATAW", "WIN32_FIND_DATA",
    "FILETIME", "SYSTEMTIME", "LARGE_INTEGER", "ULARGE_INTEGER",
    "SECURITY_ATTRIBUTES", "STARTUPINFOA", "STARTUPINFOW", "PROCESS_INFORMATION",
    "OVERLAPPED", "SOCKADDR", "SOCKADDR_IN", "SOCKET", "WSADATA", "ADDRINFO",
    "MIB_TCPROW_OWNER_PID", "MIB_TCPTABLE_OWNER_PID",
    "MIB_UDPROW_OWNER_PID", "MIB_UDPTABLE_OWNER_PID",
    "MIB_TCPROW", "MIB_TCPTABLE", "MIB_UDPROW", "MIB_UDPTABLE",
    "IP_ADAPTER_INFO", "PIP_ADAPTER_INFO",
    "SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX", "SYSTEM_HANDLE_INFORMATION_EX",
    "NTSTATUS", "ULONG_PTR", "USHORT", "SIZE_T", "SSIZE_T",
    "GUID", "IID", "CLSID", "VARIANT", "BSTR", "SAFEARRAY",
    "IUnknown", "IDispatch", "IStream", "ITaskService", "ITaskFolder",
    "ITaskDefinition", "IRegisteredTask", "IAction", "IActionCollection",
    "IExecAction", "ITrigger", "ITriggerCollection", "IRegistrationInfo",
    "IPrincipal", "ITaskSettings",
    "CONVINFO", "CTL_INFO",
    "PMIB_TCPROW_OWNER_PID", "PMIB_TCPTABLE_OWNER_PID",
    "SERVICE_STATUS", "SERVICE_TABLE_ENTRYA", "SERVICE_TABLE_ENTRYW",
    "SC_HANDLE", "HCRYPTPROV", "HCRYPTKEY", "HCRYPTHASH",
    "CRITICAL_SECTION", "CONDITION_VARIABLE", "SRWLOCK",
    "ULONG64", "LONG64", "UINT64", "INT64",
    "PDWORD", "LPDWORD", "LPBYTE", "PBOOL", "PHANDLE",
    "LPPROCESS_INFORMATION", "LPSTARTUPINFOA",
    "va_list", "FILE", "size_t", "ssize_t", "wchar_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "HCERTSTORE", "PCCERT_CONTEXT",
    "NETRESOURCEA", "NETRESOURCEW", "LPNETRESOURCEA", "LPNETRESOURCEW",
    "FARPROC", "LSTATUS", "REGSAM",
    "EXCEPTION_POINTERS", "PEXCEPTION_POINTERS", "LPEXCEPTION_POINTERS",
    "EXCEPTION_RECORD", "CONTEXT", "PCONTEXT",
})

# Pattern: identifier used as a type in function signatures (pointer or value)
_SIGNATURE_TYPE_PAT = re.compile(
    r'\b([A-Z][A-Z_a-z0-9]+)\s*\*?\s+\w+\s*[,)]'
)

# Common struct member patterns for known custom type categories
_CUSTOM_TYPE_TEMPLATES: dict[str, str] = {
    "PROCESS_ENTRY": (
        "typedef struct {\n"
        "    DWORD dwPID;\n"
        "    char szExeFile[MAX_PATH];\n"
        "    DWORD dwThreadCount;\n"
        "    DWORD dwParentPID;\n"
        "} PROCESS_ENTRY;\n"
    ),
    "MODULE_ENTRY": (
        "typedef struct {\n"
        "    HMODULE hModule;\n"
        "    char szModule[MAX_PATH];\n"
        "    char szExePath[MAX_PATH];\n"
        "    DWORD dwBaseAddr;\n"
        "    DWORD dwModuleSize;\n"
        "} MODULE_ENTRY;\n"
    ),
    "FILE_INFO": (
        "typedef struct {\n"
        "    char szFilePath[MAX_PATH];\n"
        "    char szFileName[MAX_PATH];\n"
        "    DWORD dwFileSize;\n"
        "    DWORD dwAttributes;\n"
        "    FILETIME ftLastWrite;\n"
        "} FILE_INFO;\n"
    ),
    "CONN_INFO": (
        "typedef struct {\n"
        "    char local_addr[64];\n"
        "    unsigned short local_port;\n"
        "    char remote_addr[64];\n"
        "    unsigned short remote_port;\n"
        "    DWORD pid;\n"
        "    DWORD state;\n"
        "} CONN_INFO;\n"
    ),
    "USER_DATA": (
        "typedef struct {\n"
        "    char username[256];\n"
        "    char computer_name[256];\n"
        "    char domain[256];\n"
        "    char user_profile[MAX_PATH];\n"
        "    BOOL is_admin;\n"
        "} USER_DATA;\n"
    ),
    "HANDLE_INFO": (
        "typedef struct {\n"
        "    HANDLE hObject;\n"
        "    DWORD dwProcessId;\n"
        "    DWORD dwHandleType;\n"
        "    DWORD dwAccess;\n"
        "} HANDLE_INFO;\n"
    ),
}


def _scan_and_fix_custom_types(source: str) -> str:
    """Detect LLM-invented custom typedefs used in signatures but never defined.

    Scans forward declarations and function signatures for type names that are
    not in any standard MinGW header. For known patterns (PROCESS_ENTRY, etc.)
    injects a sensible typedef struct. For unknown patterns, replaces the custom
    type with its closest Win32 equivalent in both signatures and bodies.
    """
    # Find all type names used in signatures (before the first function body)
    funcs = _extract_c_functions(source)
    if not funcs:
        return source

    first_func_start = min(s for s, _ in funcs.values())
    header = source[:first_func_start]

    # Collect type names from forward declarations in the header
    undefined_types: set[str] = set()
    for m in re.finditer(r'\b([A-Z][A-Z_a-z0-9]{3,})\s*\*', header):
        tname = m.group(1)
        if tname not in _KNOWN_WIN32_TYPES and f"typedef" not in header.split(tname)[0][-200:]:
            # Check it's not already typedef'd in the header
            if f"typedef struct" not in header or tname not in re.findall(r'}\s*(\w+)\s*;', header):
                undefined_types.add(tname)

    if not undefined_types:
        return source

    # Build injection block for known types; do replacements for others
    injections: list[str] = []
    replacements: dict[str, str] = {}

    _FALLBACK_REPLACEMENTS = {
        "PROCESS_ENTRY": "PROCESSENTRY32",
        "MODULE_ENTRY": "MODULEENTRY32",
        "FILE_INFO": "WIN32_FIND_DATAA",
        "CONN_INFO": None,
        "USER_DATA": None,
        "HANDLE_INFO": None,
    }

    for tname in sorted(undefined_types):
        if tname in _CUSTOM_TYPE_TEMPLATES:
            injections.append(_CUSTOM_TYPE_TEMPLATES[tname])
            logger.info("Custom type fix: injecting typedef for %s", tname)
        elif tname in _FALLBACK_REPLACEMENTS:
            repl = _FALLBACK_REPLACEMENTS[tname]
            if repl:
                replacements[tname] = repl
                logger.info("Custom type fix: replacing %s → %s", tname, repl)
            else:
                injections.append(_CUSTOM_TYPE_TEMPLATES.get(tname, ""))
        else:
            logger.warning("Custom type fix: unknown custom type %s — cannot auto-fix", tname)

    if not injections and not replacements:
        return source

    # Apply replacements globally
    result = source
    for old, new in replacements.items():
        result = re.sub(r'\b' + re.escape(old) + r'\b', new, result)

    # Inject typedefs before the first function
    if injections:
        injection_block = (
            "\n/* Framework-injected typedefs for custom types */\n"
            + "\n".join(inj for inj in injections if inj)
            + "\n"
        )
        funcs2 = _extract_c_functions(result)
        if funcs2:
            first_start = min(s for s, _ in funcs2.values())
            result = (
                result[:first_start].rstrip()
                + "\n\n"
                + injection_block
                + "\n"
                + result[first_start:]
            )
        else:
            result = injection_block + result

    # Fix member name mismatches: LLM often hallucinates member names
    # (e.g. .filename instead of .szFileName, .filesize instead of .dwFileSize)
    result = _fix_custom_type_members(result)

    logger.info(
        "Custom type fix: %d injected, %d replaced — %s",
        len(injections), len(replacements), sorted(undefined_types),
    )
    return result


# Map of custom type member names the LLM commonly hallucinates → correct names
_MEMBER_CORRECTIONS: dict[str, dict[str, str]] = {
    "FILE_INFO": {
        "filename": "szFileName", "file_name": "szFileName", "name": "szFileName",
        "filepath": "szFilePath", "file_path": "szFilePath", "path": "szFilePath",
        "filesize": "dwFileSize", "file_size": "dwFileSize", "size": "dwFileSize",
        "attributes": "dwAttributes", "attrs": "dwAttributes",
        "last_write": "ftLastWrite", "lastwrite": "ftLastWrite",
        "modified": "ftLastWrite", "mtime": "ftLastWrite",
    },
    "PROCESS_ENTRY": {
        "pid": "dwPID", "process_id": "dwPID", "processid": "dwPID",
        "exe_file": "szExeFile", "exefile": "szExeFile", "exe_name": "szExeFile",
        "process_name": "szExeFile", "name": "szExeFile",
        "thread_count": "dwThreadCount", "threadcount": "dwThreadCount",
        "threads": "dwThreadCount",
        "parent_pid": "dwParentPID", "parentpid": "dwParentPID", "ppid": "dwParentPID",
    },
    "MODULE_ENTRY": {
        "module": "szModule", "module_name": "szModule", "name": "szModule",
        "exe_path": "szExePath", "exepath": "szExePath", "path": "szExePath",
        "base_addr": "dwBaseAddr", "baseaddr": "dwBaseAddr", "base": "dwBaseAddr",
        "module_size": "dwModuleSize", "modulesize": "dwModuleSize",
        "size": "dwModuleSize",
    },
    "USER_DATA": {
        "user": "username", "user_name": "username", "name": "username",
        "computer": "computer_name", "hostname": "computer_name",
        "profile": "user_profile", "profile_path": "user_profile",
        "admin": "is_admin",
    },
}


def _fix_custom_type_members(source: str) -> str:
    """Fix hallucinated struct member names to match _CUSTOM_TYPE_TEMPLATES definitions."""
    count = 0
    for type_name, corrections in _MEMBER_CORRECTIONS.items():
        if type_name not in source:
            continue
        for wrong, right in corrections.items():
            if wrong == right:
                continue
            pattern = re.compile(r'(\.\s*)' + re.escape(wrong) + r'\b')
            if pattern.search(source):
                source = pattern.sub(r'\1' + right, source)
                count += 1
            pattern_arrow = re.compile(r'(->\s*)' + re.escape(wrong) + r'\b')
            if pattern_arrow.search(source):
                source = pattern_arrow.sub(r'\1' + right, source)
                count += 1
    if count:
        logger.info("Custom type member fix: corrected %d member name(s)", count)
    return source


_UNDECLARED_VAR_TYPES: dict[str, tuple[str, str]] = {
    "ok": ("BOOL", "FALSE"),
    "success": ("BOOL", "FALSE"),
    "result": ("BOOL", "FALSE"),
    "found": ("BOOL", "FALSE"),
    "done": ("BOOL", "FALSE"),
    "encrypted": ("BOOL", "FALSE"),
    "ret": ("int", "0"),
    "rc": ("LONG", "0"),
    "err": ("DWORD", "0"),
    "error": ("DWORD", "0"),
    "status": ("LONG", "0"),
    "count": ("DWORD", "0"),
    "len": ("DWORD", "0"),
    "size": ("DWORD", "0"),
    "bytes": ("DWORD", "0"),
    "written": ("DWORD", "0"),
    "read": ("DWORD", "0"),
    "total": ("int", "0"),
    "i": ("int", "0"),
    "j": ("int", "0"),
    "n": ("int", "0"),
    "idx": ("int", "0"),
    "index": ("int", "0"),
    "handle": ("HANDLE", "NULL"),
    "file": ("HANDLE", "INVALID_HANDLE_VALUE"),
    "key": ("HKEY", "NULL"),
    "ctx": ("HCRYPTPROV", "0"),
    "prov": ("HCRYPTPROV", "0"),
    "hash": ("HCRYPTHASH", "0"),
    "buf": ("char", "[4096] = {0}"),
    "buffer": ("char", "[4096] = {0}"),
    "path": ("char", "[MAX_PATH] = {0}"),
    "filename": ("char", "[MAX_PATH] = {0}"),
    "temp": ("char", "[MAX_PATH] = {0}"),
    "line": ("char", "[1024] = {0}"),
}


def _infer_var_type(var_name: str, func_body: str) -> tuple[str, str]:
    """Infer C type and default for an undeclared variable from its usage context."""
    vl = var_name.lower()
    for suffix, (t, d) in _UNDECLARED_VAR_TYPES.items():
        if vl == suffix or vl.endswith("_" + suffix):
            return t, d

    if vl.startswith("dw"):
        return "DWORD", "0"
    if vl.startswith("h") and len(vl) > 1 and vl[1].isupper():
        return "HANDLE", "NULL"
    if vl.startswith("sz") or vl.startswith("lpsz"):
        return "char", "[MAX_PATH] = {0}"
    if vl.startswith("cb") or (vl.startswith("n") and len(vl) > 1 and vl[1].isupper()):
        return "DWORD", "0"

    if re.search(r'CryptDestroyKey\s*\(\s*' + re.escape(var_name), func_body):
        return "HCRYPTKEY", "0"
    if re.search(r'CryptDestroyHash\s*\(\s*' + re.escape(var_name), func_body):
        return "HCRYPTHASH", "0"
    if re.search(r'CryptReleaseContext\s*\(\s*' + re.escape(var_name), func_body):
        return "HCRYPTPROV", "0"
    if re.search(r'CryptAcquireContext\s*\(\s*&' + re.escape(var_name), func_body):
        return "HCRYPTPROV", "0"
    if re.search(r'CryptCreateHash\s*\([^,]+,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*&' + re.escape(var_name), func_body):
        return "HCRYPTHASH", "0"
    if re.search(r'CryptDeriveKey\s*\([^,]+,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*&' + re.escape(var_name), func_body):
        return "HCRYPTKEY", "0"
    if re.search(r'CloseHandle\s*\(\s*' + re.escape(var_name), func_body):
        return "HANDLE", "NULL"
    if re.search(r'RegCloseKey\s*\(\s*' + re.escape(var_name), func_body):
        return "HKEY", "NULL"

    if re.search(rf'\b{re.escape(var_name)}\s*\[', func_body):
        return "void*", "NULL"
    if re.search(rf'\b{re.escape(var_name)}\s*>>', func_body):
        return "DWORD", "0"
    if re.search(rf'free\s*\(\s*{re.escape(var_name)}\s*\)', func_body):
        return "void*", "NULL"
    if re.search(rf'\(\s*{re.escape(var_name)}\s*>>', func_body):
        return "DWORD", "0"

    return "int", "0"


def _fix_compiler_suggestions(source: str, compiler_error: str) -> str:
    """Apply gcc's 'did you mean X?' suggestions for implicit/undefined function calls."""
    did_you_mean_pat = re.compile(
        r"(?:implicit declaration of function|undefined reference to)"
        r"\s+['‘](\w+)['’]"
        r".*?did you mean ['‘](\w+)['’]",
        re.DOTALL,
    )
    undef_ref_pat = re.compile(
        r"undefined reference to [`'‘](\w+)['’]"
    )
    renames: dict[str, str] = {}
    for m in did_you_mean_pat.finditer(compiler_error):
        bad, good = m.group(1), m.group(2)
        if bad != good and re.search(rf'\b{re.escape(good)}\b', source):
            renames[bad] = good
    if renames:
        for bad, good in renames.items():
            source = re.sub(rf'\b{re.escape(bad)}\b', good, source)
        logger.info("Applied compiler 'did you mean' renames: %s",
                     ", ".join(f"{b}→{g}" for b, g in renames.items()))

    # Remove/comment calls to functions that are still undefined after renames
    # (no 'did you mean' suggestion and not defined in source)
    defined_funcs = set(_extract_c_functions(source).keys())
    undef_calls: set[str] = set()
    for m in undef_ref_pat.finditer(compiler_error):
        fname = m.group(1)
        if fname not in renames and fname not in defined_funcs:
            undef_calls.add(fname)
    if undef_calls:
        for fname in undef_calls:
            source = re.sub(
                rf'^\s*{re.escape(fname)}\s*\([^;]*;\s*$',
                '',
                source,
                flags=re.MULTILINE,
            )
        logger.info("Removed calls to undefined functions: %s", ", ".join(sorted(undef_calls)))

    return source


def _fix_undeclared_variables(source: str, compiler_error: str) -> str:
    """Parse 'undeclared' errors and inject declarations at function top."""
    undecl_pat = re.compile(
        r"error: [''](\w+)[''] undeclared"
    )
    var_names = list(dict.fromkeys(undecl_pat.findall(compiler_error)))
    if not var_names:
        return source

    funcs = _extract_c_functions(source)
    lines = source.split('\n')
    injections: dict[int, list[str]] = {}
    declared: set[str] = set()

    for var_name in var_names:
        for fname, (start, end) in funcs.items():
            func_body = source[start:end]
            if not re.search(rf'\b{re.escape(var_name)}\b', func_body):
                continue
            has_decl = re.search(
                rf'(?:int|DWORD|LONG|BOOL|HANDLE|HKEY|BYTE|char|void|LPVOID|HCRYPTPROV|HCRYPTHASH|'
                rf'HCRYPTKEY|WORD|SHORT|ULONG|UINT|SIZE_T|LARGE_INTEGER|MIB_\w+|WIN32_FIND_\w+|'
                rf'MODULEENTRY32|PROCESSENTRY32|NETRESOURCEA|LPNETRESOURCEA)\s*\*?\s*'
                rf'\b{re.escape(var_name)}\b',
                func_body,
            )
            if has_decl:
                continue

            brace = source.find('{', start)
            if brace < 0:
                continue
            func_body_line = source[:brace].count('\n') + 1

            ctype, default = _infer_var_type(var_name, func_body)
            if default.startswith("["):
                decl = f"    {ctype} {var_name}{default};"
            else:
                decl = f"    {ctype} {var_name} = {default};"

            key = f"{fname}:{var_name}"
            if key in declared:
                continue
            declared.add(key)

            if func_body_line not in injections:
                injections[func_body_line] = []
            injections[func_body_line].append(decl)
            break

    if not injections:
        return source

    for line_num in sorted(injections.keys(), reverse=True):
        insert_text = '\n'.join(injections[line_num])
        lines.insert(line_num, insert_text)

    fixed = '\n'.join(lines)
    logger.info("Auto-declared %d undeclared variable(s): %s", len(declared), ", ".join(var_names))
    return fixed


def _fix_common_compile_errors(source: str) -> str:
    """Deterministic fixes for the most common compile errors across all runs.

    Applied after assembly and before first compilation. These are patterns that
    the LLM consistently gets wrong and that account for the majority of
    compile-fix iterations.
    """
    # ── Strip forbidden third-party includes the LLM adds despite instructions ──
    source = re.sub(
        r'^\s*#include\s*<(?:openssl|curl|zlib|glib|json-c|libxml|libpng|sqlite3)[/\w]*\.h>\s*$',
        '', source, flags=re.MULTILINE,
    )

    # ── Replace 'extern int errno;' with #include <errno.h> (TLS mismatch on Linux) ──
    if re.search(r'^\s*extern\s+int\s+errno\s*;', source, re.MULTILINE):
        source = re.sub(r'^\s*extern\s+int\s+errno\s*;\s*$', '', source, flags=re.MULTILINE)
        if '#include <errno.h>' not in source:
            source = re.sub(r'(#include\s*<[a-z]+\.h>)', r'#include <errno.h>\n\1', source, count=1)

    # ── Strip markdown fences that leak through from LLM output ──
    source = re.sub(r'^```[a-zA-Z]*\s*$', '', source, flags=re.MULTILINE)
    # Strip inline backticks wrapping C statements (backticks are never valid in C)
    source = re.sub(r'^`', '', source, flags=re.MULTILINE)
    source = re.sub(r'`$', '', source, flags=re.MULTILINE)

    # ── Fix missing ')' before '{' in function signatures ──
    # LLM generates e.g. `BOOL init_buffer(int min {` instead of `BOOL init_buffer(int min) {`
    # This breaks _extract_c_functions (and compilation), making the function invisible
    # to the compile-fix targeting logic.
    _CTYPE = (r'(?:(?:static|inline|extern|__declspec\s*\([^)]*\))\s+)*'
              r'(?:(?:unsigned|signed|const|volatile|long|short)\s+)*'
              r'\w[\w\*]*')
    _SKIP_KW = frozenset(("if", "while", "for", "switch", "else", "do", "return",
                           "sizeof", "typedef", "struct", "enum", "union", "case"))
    _BROKEN_SIG = re.compile(
        r'^(\s*' + _CTYPE + r'\s+(\w+)\s*\([^){}]*?)\s*(\{)',
        re.MULTILINE,
    )
    def _fix_sig(m: re.Match) -> str:
        if m.group(2) in _SKIP_KW:
            return m.group(0)
        return m.group(1) + ') ' + m.group(3)
    source = _BROKEN_SIG.sub(_fix_sig, source)

    # ── Fix missing '()' entirely before '{' in function signatures ──
    # LLM generates e.g. `HINSTANCE get {` instead of `HINSTANCE get(void) {`
    _NO_PARENS_SIG = re.compile(
        r'^(\s*' + _CTYPE + r'\s+(\w+))\s+(\{)\s*$',
        re.MULTILINE,
    )
    def _fix_no_parens(m: re.Match) -> str:
        if m.group(2) in _SKIP_KW:
            return m.group(0)
        return m.group(1) + '(void) ' + m.group(3)
    source = _NO_PARENS_SIG.sub(_fix_no_parens, source)

    # ── Fix common header name typos from LLM ──
    _HEADER_FIXES = {
        "thelp32.h": "tlhelp32.h",
        "tlink32.h": "tlhelp32.h",
        "Tlhelp32.h": "tlhelp32.h",
        "TlHelp32.h": "tlhelp32.h",
        "winnet>": "winnetwk.h>",
        "winnet.h": "winnetwk.h",
        "winsock.h": "winsock2.h",
        "Winsock2.h": "winsock2.h",
        "WinSock2.h": "winsock2.h",
        "iphlapi.h": "iphlpapi.h",
        "iphelpapi.h": "iphlpapi.h",
        "wincrpyt.h": "wincrypt.h",
        "wincyrpt.h": "wincrypt.h",
        "shellApi.h": "shellapi.h",
        "Shlobj.h": "shlobj.h",
        "ShlObj.h": "shlobj.h",
        "netapi32.h": "lm.h",
        "Netapi32.h": "lm.h",
        "lmaccess.h": "lm.h",
        "lh.h": "lm.h",
        "Lm.h": "lm.h",
        "LM.h": "lm.h",
    }
    for wrong, right in _HEADER_FIXES.items():
        if wrong in source:
            source = source.replace(wrong, right)

    # ── C++ style includes missing .h extension ──
    source = re.sub(
        r'#include\s*<(stdlib|stdio|string|math|signal|assert|ctype|errno'
        r'|locale|setjmp|stdarg|stddef|time|limits|float)>',
        r'#include <\1.h>',
        source,
    )

    # ── #include <X> where X is a short name without extension → add .h ──
    # Catches LLM typos like <lh> (should be <lm.h>), <winnet> etc.
    _BARE_INCLUDE_MAP = {"lh": "lm.h", "winnet": "winnetwk.h", "winsock": "winsock2.h"}
    def _fix_bare_include(m):
        name = m.group(1)
        replacement = _BARE_INCLUDE_MAP.get(name, f"{name}.h")
        return f"#include <{replacement}>"
    source = re.sub(
        r'#include\s*<([a-zA-Z][a-zA-Z0-9_]{0,15})>',
        lambda m: _fix_bare_include(m) if '.' not in m.group(1) else m.group(0),
        source,
    )

    # ── Define missing LLM-invented constants used in global declarations ──
    _MISSING_CONSTS = {
        "MAX_BLOB": 4096,
        "MAX_KEY": 256,
        "MAX_KEY_SIZE": 256,
        "MAX_KEY_LEN": 256,
        "MAX_BLOCK": 65536,
        "MAX_BLOCK_SIZE": 65536,
        "MAX_BUF": 4096,
        "MAX_BUFFER": 4096,
        "BLOCK_SIZE": 65536,
        "KEY_SIZE": 256,
        "AES_KEY_SIZE": 32,
        "AES_BLOCK_SIZE": 16,
        "IV_SIZE": 16,
        "MAX_DRIVES": 26,
        "MAX_FILES": 4096,
        "MAX_EXT": 16,
        "MAX_EXTENSIONS": 32,
        "MAX_PROCESSES": 1024,
        "MAX_MODULES": 256,
        "MAX_CONNECTIONS": 256,
        "MAX_RESOURCES": 256,
        "RANSOM_NOTE_SIZE": 4096,
        "MAX_HASH": 64,
        "MAX_HASH_LEN": 64,
    }
    for const_name, const_val in _MISSING_CONSTS.items():
        if re.search(r'\b' + const_name + r'\b', source) and f'#define {const_name}' not in source:
            last_inc = 0
            for m in re.finditer(r'^#include\s*<[^>]+>\s*$', source, re.MULTILINE):
                last_inc = m.end()
            if last_inc:
                source = source[:last_inc] + f"\n#define {const_name} {const_val}" + source[last_inc:]
            else:
                source = f"#define {const_name} {const_val}\n" + source

    # ── Ensure winsock2.h comes before windows.h ──
    if '#include <winsock2.h>' in source and '#include <windows.h>' in source:
        ws2_pos = source.index('#include <winsock2.h>')
        win_pos = source.index('#include <windows.h>')
        if ws2_pos > win_pos:
            source = source.replace('#include <winsock2.h>\n', '')
            source = source.replace('#include <windows.h>', '#include <winsock2.h>\n#include <windows.h>')
    if '#include <ws2tcpip.h>' in source and '#include <windows.h>' in source:
        tcpip_pos = source.index('#include <ws2tcpip.h>')
        win_pos = source.index('#include <windows.h>')
        if tcpip_pos < win_pos:
            source = source.replace('#include <ws2tcpip.h>\n', '')
            source = source.replace('#include <windows.h>', '#include <windows.h>\n#include <ws2tcpip.h>')

    # ── Missing headers ──

    if re.search(r'\buint(?:8|16|32|64)_t\b|\bint(?:8|16|32|64)_t\b', source) and '#include <stdint.h>' not in source:
        last_inc = 0
        for m in re.finditer(r'^#include\s*<[^>]+>\s*$', source, re.MULTILINE):
            last_inc = m.end()
        if last_inc:
            source = source[:last_inc] + "\n#include <stdint.h>" + source[last_inc:]
        else:
            source = "#include <stdint.h>\n" + source

    if (re.search(r'\bGetExtendedTcpTable\b|\bGetAdaptersInfo\b|\bMIB_TCPROW_OWNER_PID\b', source)
            and '#include <iphlpapi.h>' not in source):
        source = re.sub(
            r'(#include\s*<windows\.h>)',
            r'\1\n#include <iphlpapi.h>\n#pragma comment(lib, "iphlpapi.lib")',
            source, count=1,
        )

    if (re.search(r'\bNETRESOURCEA\b|\bLPNETRESOURCEA\b|\bWNetOpenEnum\b|\bWNetEnumResource\b', source)
            and '#include <winnetwk.h>' not in source):
        source = re.sub(
            r'(#include\s*<windows\.h>)',
            r'\1\n#include <winnetwk.h>',
            source, count=1,
        )

    if (re.search(r'\binet_pton\b|\binet_ntop\b|\bInetPtonA?\b|\bINET_ADDRSTRLEN\b|\bINET6_ADDRSTRLEN\b|\bgetaddrinfo\b|\bfreeaddrinfo\b|\bADDRINFO\b', source)
            and '#include <ws2tcpip.h>' not in source):
        _anchor = r'(#include\s*<winsock2\.h>)' if '#include <winsock2.h>' in source else r'(#include\s*<windows\.h>)'
        source = re.sub(_anchor, r'\1\n#include <ws2tcpip.h>', source, count=1)

    if (re.search(r'\bPROCESSENTRY32\b|\bLPPROCESSENTRY32\b|\bMODULEENTRY32\b|\bCreateToolhelp32Snapshot\b|\bProcess32First\b', source)
            and '#include <tlhelp32.h>' not in source):
        source = re.sub(
            r'(#include\s*<windows\.h>)',
            r'\1\n#include <tlhelp32.h>',
            source, count=1,
        )

    if (re.search(r'\bHINTERNET\b|\bInternetOpenA\b|\bInternetOpenUrlA\b|\bInternetReadFile\b|\bInternetCloseHandle\b', source)
            and '#include <wininet.h>' not in source):
        source = re.sub(
            r'(#include\s*<windows\.h>)',
            r'\1\n#include <wininet.h>',
            source, count=1,
        )

    if '__try' in source and '#include <excpt.h>' not in source:
        source = re.sub(
            r'(#include\s*<windows\.h>)',
            r'\1\n#include <excpt.h>',
            source, count=1,
        )

    if (re.search(r'\bGetUserProfileDirectory\b', source)
            and '#include <userenv.h>' not in source):
        source = re.sub(
            r'(#include\s*<windows\.h>)',
            r'\1\n#include <userenv.h>',
            source, count=1,
        )

    if (re.search(r'\bCSIDL_DESKTOP\b|\bCSIDL_PERSONAL\b|\bCSIDL_PROFILE\b|\bCSIDL_APPDATA\b|\bSHGetFolderPath', source)
            and '#include <shlobj.h>' not in source):
        source = re.sub(
            r'(#include\s*<windows\.h>)',
            r'\1\n#include <shlobj.h>',
            source, count=1,
        )

    # ── sprintf used like snprintf (LLM confusion) ──
    # Pattern: sprintf(buf, size_expr, "fmt"...) → snprintf(buf, size_expr, "fmt"...)
    # The tell: 2nd arg has no quote char (so it's a size, not a format string)
    source = re.sub(
        r'\bsprintf\s*\(([^,]+),\s*([^",]+),\s*(")',
        r'snprintf(\1, \2, \3',
        source,
    )

    # ── Toolhelp32 functions have NO A/W suffix ──
    source = re.sub(r'\bProcess32FirstA\b', 'Process32First', source)
    source = re.sub(r'\bProcess32NextA\b', 'Process32Next', source)
    source = re.sub(r'\bModule32FirstA\b', 'Module32First', source)
    source = re.sub(r'\bModule32NextA\b', 'Module32Next', source)
    source = re.sub(r'\bCreateToolhelp32SnapshotA\b', 'CreateToolhelp32Snapshot', source)

    # ── WNet functions: WNetCloseEnum has NO A/W suffix ──
    source = re.sub(r'\bWNetCloseEnumA\b', 'WNetCloseEnum', source)
    source = re.sub(r'\bWNetCloseEnumW\b', 'WNetCloseEnum', source)

    # ── File I/O functions have NO A/W suffix ──
    source = re.sub(r'\bReadFileA\b', 'ReadFile', source)
    source = re.sub(r'\bWriteFileA\b', 'WriteFile', source)
    source = re.sub(r'\bFindCloseA\b', 'FindClose', source)
    source = re.sub(r'\bFindCloseW\b', 'FindClose', source)
    source = re.sub(r'\bCloseHandleA\b', 'CloseHandle', source)
    source = re.sub(r'\bGetLastErrorA\b', 'GetLastError', source)
    source = re.sub(r'\bSetLastErrorA\b', 'SetLastError', source)

    # ── Wide (W) → ANSI (A) for ANSI build ──
    source = re.sub(r'\bFindFirstFileW\b', 'FindFirstFileA', source)
    source = re.sub(r'\bFindNextFileW\b', 'FindNextFileA', source)
    source = re.sub(r'\bWIN32_FIND_DATAW\b', 'WIN32_FIND_DATAA', source)
    source = re.sub(r'\bLPWIN32_FIND_DATAW\b', 'LPWIN32_FIND_DATAA', source)
    source = re.sub(r'\bCreateFileW\b', 'CreateFileA', source)
    source = re.sub(r'\bDeleteFileW\b', 'DeleteFileA', source)
    source = re.sub(r'\bMoveFileW\b', 'MoveFileA', source)
    source = re.sub(r'\bCopyFileW\b', 'CopyFileA', source)
    source = re.sub(r'\bGetModuleFileNameW\b', 'GetModuleFileNameA', source)
    source = re.sub(r'\bwcsncpy\b', 'strncpy', source)
    source = re.sub(r'\bwcscpy\b', 'strcpy', source)
    source = re.sub(r'\bwcslen\b', 'strlen', source)
    source = re.sub(r'\bwcscat\b', 'strcat', source)
    source = re.sub(r'\bwcscmp\b', 'strcmp', source)

    # ── Invented function names → correct Win32 API ──
    source = re.sub(r'\bclose_socket\b', 'closesocket', source)
    source = re.sub(r'\bget_current_directory\b', 'GetCurrentDirectoryA', source)

    # ── WNet functions: explicit A suffix causes link errors (use macro names) ──
    source = re.sub(r'\bWNetCloseEnumA\b', 'WNetCloseEnum', source)

    # ── Other API name fixes (no ANSI variant exists) ──
    source = re.sub(r'\bOpenProcessA\b', 'OpenProcess', source)
    source = re.sub(r'\bGetLogicalDrivesA\b', 'GetLogicalDrives', source)
    source = re.sub(r'\bGetForegroundWindowA\b', 'GetForegroundWindow', source)
    source = re.sub(r'\bGetDesktopWindowA\b', 'GetDesktopWindow', source)
    source = re.sub(r'\bGetActiveWindowA\b', 'GetActiveWindow', source)
    source = re.sub(r'\bSetForegroundWindowA\b', 'SetForegroundWindow', source)
    source = re.sub(r'\bGetKeyStateA\b', 'GetKeyState', source)
    source = re.sub(r'\bGetAsyncKeyStateA\b', 'GetAsyncKeyState', source)
    source = re.sub(r'\bGetKeyboardStateA\b', 'GetKeyboardState', source)
    source = re.sub(r'\bCallNextHookExA\b', 'CallNextHookEx', source)
    source = re.sub(r'\bUnhookWindowsHookExA\b', 'UnhookWindowsHookEx', source)
    source = re.sub(r'\bGetModuleHandleExA\b', 'GetModuleHandleExW', source)
    source = re.sub(r'\bCryptDeriveKeyA\b', 'CryptDeriveKey', source)
    source = re.sub(r'\bCryptAcquireContextW\b', 'CryptAcquireContextA', source)
    source = re.sub(r'\bCryptEncryptA\b', 'CryptEncrypt', source)
    source = re.sub(r'\bCryptDecryptA\b', 'CryptDecrypt', source)
    source = re.sub(r'\bCryptCreateHashA\b', 'CryptCreateHash', source)
    source = re.sub(r'\bCryptDestroyKeyA\b', 'CryptDestroyKey', source)
    source = re.sub(r'\bCryptDestroyHashA\b', 'CryptDestroyHash', source)
    source = re.sub(r'\bCryptReleaseContextA\b', 'CryptReleaseContext', source)
    source = re.sub(r'\bVirtualProtectA\b', 'VirtualProtect', source)
    source = re.sub(r'\bVirtualAllocA\b', 'VirtualAlloc', source)
    source = re.sub(r'\bVirtualFreeA\b', 'VirtualFree', source)
    source = re.sub(r'\bHeapAllocA\b', 'HeapAlloc', source)
    source = re.sub(r'\bHeapFreeA\b', 'HeapFree', source)
    source = re.sub(r'\bstrcatA\b', 'lstrcatA', source)
    source = re.sub(r'\b_lstrcatA\b', 'lstrcatA', source)
    source = re.sub(r'\blStrcatA\b', 'lstrcatA', source)
    source = re.sub(r'\b_lstrcpyA\b', 'lstrcpyA', source)
    source = re.sub(r'\blStrcpyA\b', 'lstrcpyA', source)
    source = re.sub(r'\bsprintfA\b', 'sprintf', source)
    source = re.sub(r'\bstrrchrA\b', 'strrchr', source)
    source = re.sub(r'\bstrchrA\b', 'strchr', source)
    source = re.sub(r'\bstrstrA\b', 'strstr', source)
    source = re.sub(r'\bstrncpyA\b', 'strncpy', source)
    source = re.sub(r'\bstrlenA\b', 'strlen', source)
    source = re.sub(r'\bstrcmpA\b', 'strcmp', source)
    source = re.sub(r'\bstrcpyA\b', 'strcpy', source)
    source = re.sub(r'\bmemcpyA\b', 'memcpy', source)
    source = re.sub(r'\bmemsetA\b', 'memset', source)
    source = re.sub(r'\bEnumValueA\b', 'RegEnumValueA', source)
    source = re.sub(r'\bEnumRegKeyA\b', 'RegEnumKeyExA', source)
    source = re.sub(r'\bEnumKeyA\b', 'RegEnumKeyExA', source)
    source = re.sub(r'\bRegQueryValueExW\b', 'RegQueryValueExA', source)
    source = re.sub(r'\bRegSetValueExW\b', 'RegSetValueExA', source)
    source = re.sub(r'\bRegOpenKeyExW\b', 'RegOpenKeyExA', source)
    source = re.sub(r'\bRegCreateKeyExW\b', 'RegCreateKeyExA', source)
    source = re.sub(r'\bRegEnumKeyExW\b', 'RegEnumKeyExA', source)
    source = re.sub(r'\bRegEnumValueW\b', 'RegEnumValueA', source)
    source = re.sub(r'\bMS_ENHANCED_PROVA\b', 'MS_ENHANCED_PROV_A', source)

    # ── Type name corrections ──
    source = re.sub(r'\bPNETRESOURCEA\b', 'LPNETRESOURCEA', source)
    source = re.sub(r'\bLPNETRESOURCE_A\b', 'LPNETRESOURCEA', source)
    source = re.sub(r'\bNETRESOURCE_A\b', 'NETRESOURCEA', source)
    source = re.sub(r'\bMIB_TCP_TABLE\b', 'MIB_TCPTABLE', source)
    source = re.sub(r'\bLPMIB_TCPTABLE\b', 'PMIB_TCPTABLE', source)

    # ── Incorrect constant names ──
    source = re.sub(r'\bRESOURCEGLOBALNET\b', 'RESOURCE_GLOBALNET', source)
    source = re.sub(r'\bRESOURCECURRENTCONNECTION\b', 'RESOURCE_CONNECTED', source)
    source = re.sub(r'\bRESOURCE_USAGE_CONNECTABLE\b', 'RESOURCEUSAGE_CONNECTABLE', source)
    source = re.sub(r'\bMIB_TCP_STATE_ESTABLISHED\b', 'MIB_TCP_STATE_ESTAB', source)
    source = re.sub(r'\bHKCU\b', 'HKEY_CURRENT_USER', source)
    source = re.sub(r'\bHKLM\b', 'HKEY_LOCAL_MACHINE', source)
    source = re.sub(r'\bCCH_MAX_PATH\b', 'MAX_PATH', source)
    source = re.sub(r'\bRESOURCEDISPLAYTYPE_WORKGROUP\b', 'RESOURCEDISPLAYTYPE_GROUP', source)
    source = re.sub(r'\bERROR_DEVICE_ALREADY_REMOTELY_CONNECTED\b', 'ERROR_DEVICE_ALREADY_REMEMBERED', source)
    source = re.sub(r'\bPF_SSE_INSTRUCTIONS_AVAILABLE\b', 'PF_XMMI_INSTRUCTIONS_AVAILABLE', source)
    source = re.sub(r'\bPF_SSE2_INSTRUCTIONS_AVAILABLE\b', 'PF_XMMI64_INSTRUCTIONS_AVAILABLE', source)

    # ── CryptoAPI constant fixes ──
    source = re.sub(r'\bCRYPT_RANDOM_IV\b', 'CRYPT_EXPORTABLE', source)
    source = re.sub(r'\bCRYPT_BLOCK_PADDING\b', '0', source)

    # ── MIB_TCPROW_OWNER_PID member name fixes ──
    source = re.sub(r'(\brow\b|\btcp_row\b|\bentry\b|\btcpRow\b)(->|\.)dwProcessId\b', r'\1\2dwOwningPid', source)
    source = re.sub(r'(\brow\b|\btcp_row\b|\bentry\b|\btcpRow\b)(->|\.)dwProtocol\b', r'\1\2dwState', source)

    # ── GetProcessHandleCount takes 2 args, not 3 ──
    source = re.sub(
        r'GetProcessHandleCount\s*\(\s*(\w+)\s*,\s*(&\w+)\s*,\s*sizeof\s*\([^)]*\)\s*\)',
        r'GetProcessHandleCount(\1, \2)',
        source,
    )

    # ── GetFilePointer doesn't exist → SetFilePointer ──
    source = re.sub(r'\bGetFilePointer\b', 'SetFilePointer', source)

    # ── CSIDL_DOWNLOADS doesn't exist ──
    if 'CSIDL_DOWNLOADS' in source:
        source = source.replace('CSIDL_DOWNLOADS', 'CSIDL_PROFILE')

    # ── GetExtendedTcpTable: 5th arg is TCP_TABLE_CLASS enum, not a type cast ──
    source = re.sub(
        r'\(ULONG\)\s*MIB_TCPTABLE_OWNER_PID',
        'TCP_TABLE_OWNER_PID_ALL',
        source,
    )
    source = re.sub(
        r'\(TCP_TABLE_CLASS\)\s*MIB_TCPTABLE_OWNER_PID',
        'TCP_TABLE_OWNER_PID_ALL',
        source,
    )

    # ── TCHAR macros (shouldn't appear in ANSI builds) ──
    source = re.sub(r'\b_tcslen\b', 'lstrlenA', source)
    source = re.sub(r'\b_tcscpy\b', 'lstrcpyA', source)

    # ── SetFilePointerEx: 2nd arg is LARGE_INTEGER by value, not pointer ──
    # Fix &liOffset → liOffset when passed to SetFilePointerEx
    source = re.sub(
        r'(SetFilePointerEx\s*\([^,]+,\s*)&(\w+)',
        r'\1\2',
        source,
    )
    # Fix SetFilePointerEx(h, 0, ...) → SetFilePointerEx(h, (LARGE_INTEGER){0}, ...)
    source = re.sub(
        r'(SetFilePointerEx\s*\([^,]+,\s*)0(\s*,)',
        r'\1(LARGE_INTEGER){0}\2',
        source,
    )

    # ── GetFileSizeEx: 2nd arg is PLARGE_INTEGER, ensure correct type in decl ──
    # Fix ULARGE_INTEGER used where LARGE_INTEGER expected
    source = re.sub(r'\bULARGE_INTEGER\s+fileSize\b', 'LARGE_INTEGER fileSize', source)

    # ── CryptEncrypt/CryptExportKey: 2nd arg is HCRYPTHASH/HCRYPTKEY, not void* ──
    source = re.sub(r'(CryptEncrypt\s*\([^,]+,\s*)NULL\b', r'\1(HCRYPTHASH)0', source)
    source = re.sub(r'(CryptExportKey\s*\([^,]+,\s*)NULL\b', r'\1(HCRYPTKEY)0', source)

    # ── Remove stdbool.h (not needed in Windows C with BOOL/TRUE/FALSE) ──
    source = re.sub(r'^\s*#include\s*<stdbool\.h>\s*$', '', source, flags=re.MULTILINE)
    source = re.sub(r'^\s*#include\s*<bool\.h>\s*$', '', source, flags=re.MULTILINE)

    # ── Python/Rust None/none → C NULL ──
    source = re.sub(r'\bnone\b', 'NULL', source)
    source = re.sub(r'\bNone\b', 'NULL', source)

    # ── C++ bool/true/false → Windows BOOL/TRUE/FALSE ──
    source = re.sub(r'\bbool\b', 'BOOL', source)
    source = re.sub(r'\btrue\b', 'TRUE', source)
    source = re.sub(r'\bfalse\b', 'FALSE', source)

    # ── Hallucinated API names ──
    source = re.sub(r'\blstrcmpIA\b', 'lstrcmpiA', source)
    source = re.sub(r'\bEnumProcessHandles\b', 'GetProcessHandleCount', source)
    source = re.sub(r'\bGetQueryVirtualMemoryInformation\b', 'VirtualQuery', source)

    # ── HCRYPTPROV/HCRYPTHASH/HCRYPTKEY are integer types, init with 0 not NULL ──
    source = re.sub(r'(HCRYPTPROV\s+\w+\s*=\s*)NULL\b', r'\g<1>0', source)
    source = re.sub(r'(HCRYPTHASH\s+\w+\s*=\s*)NULL\b', r'\g<1>0', source)
    source = re.sub(r'(HCRYPTKEY\s+\w+\s*=\s*)NULL\b', r'\g<1>0', source)

    # ── HANDLE used where HCRYPTPROV expected (LLM confusion) ──
    # Variables passed to CryptAcquireContext/CryptGenRandom/CryptReleaseContext
    # must be HCRYPTPROV, not HANDLE (which is void*; HCRYPTPROV is ULONG_PTR).
    _crypt_prov_vars: set[str] = set()
    for m in re.finditer(r'(?:CryptAcquireContext\w*|CryptGenRandom|CryptReleaseContext)\s*\(\s*&?(\w+)', source):
        _crypt_prov_vars.add(m.group(1))
    for m in re.finditer(r'(?:CryptCreateHash|CryptDeriveKey|CryptEncrypt|CryptDecrypt)\s*\(\s*(\w+)', source):
        _crypt_prov_vars.add(m.group(1))
    for v in _crypt_prov_vars:
        source = re.sub(
            rf'\bHANDLE\s+({re.escape(v)})\b',
            rf'HCRYPTPROV \1',
            source,
        )

    # ── Strip leaked LLM reasoning/thinking lines from assembled source ──
    _THINKING_LINE_RE = re.compile(
        r'^\s*(?:Wait[,!]|Actually[,!]|I\'ll |I will |I should |I need |I can '
        r'|Note:|However[,!]|Let me |Let\'s |It matches|Maybe |Alright[,!]'
        r'|Okay[,!]|Hmm[,!]|So[, ]the|Looking at|This (?:means|is|should|will)'
        r'|Since (?:the|we)|We (?:need|should|can)|Check(?:ing)?[ :]'
        r'|Here\'s |Here is |The (?:model|function|code|user|prompt))',
        re.IGNORECASE,
    )
    _PROSE_CALL_RE = re.compile(
        r'^\s*[a-z]+(?:\s+[a-z]+){2,}\s*\(',
    )
    _BARE_LETTER_RE = re.compile(r'^\s*[A-Z]\s*;\s*$')
    _NUMBERED_LIST_RE = re.compile(r'^\s*\d+\.\s+')
    _LABEL_PROSE_RE = re.compile(r'^\s*(?:Callee|Caller|Note|Explanation|Summary|Output|Issue|Fix|Change)\s*:', re.IGNORECASE)
    cleaned_lines = []
    for line in source.splitlines():
        if _THINKING_LINE_RE.match(line) and ';' not in line and '{' not in line:
            continue
        if '`' in line and ';' not in line and '{' not in line and '}' not in line:
            backtick_pairs = len(re.findall(r'`[^`]+`', line))
            prose_words = re.findall(r'\b[a-z]{3,}\b', line)
            if backtick_pairs >= 1 and len(prose_words) >= 3:
                continue
        if _PROSE_CALL_RE.match(line):
            continue
        if _BARE_LETTER_RE.match(line):
            continue
        if _NUMBERED_LIST_RE.match(line) and '{' not in line and '}' not in line:
            continue
        if _LABEL_PROSE_RE.match(line):
            continue
        cleaned_lines.append(line)
    source = '\n'.join(cleaned_lines)

    # ── Replace placeholder function bodies: { ... } or { /* ... */ } ──
    source = re.sub(
        r'(\)\s*\{)\s*\.\.\.(\s*\})',
        r'\1 /* stub */ return 0;\2',
        source,
    )
    source = re.sub(
        r'(\)\s*\{)\s*/\*\s*\.\.\.\s*\*/(\s*\})',
        r'\1 /* stub */ return 0;\2',
        source,
    )

    # ── Strip bare '...' tokens from function bodies (LLM pseudo-code filler) ──
    # Match '...' that is NOT inside a parameter list (i.e. not preceded by '(' on same line)
    source = re.sub(r'(?<!\()\.\.\.(?!\))', '', source)

    # ── Remove duplicate function definitions ──
    _SKIP_KW2 = frozenset(("if", "while", "for", "switch", "else", "do", "return",
                           "sizeof", "typedef", "struct", "enum", "union"))
    _func_def_pat = re.compile(
        r'^(?:(?:static|inline|__forceinline|WINAPI|APIENTRY|CALLBACK|__cdecl|__stdcall|'
        r'__declspec\([^)]*\)|__attribute__\([^)]*\))\s+)*'
        r'(?:(?:unsigned|signed|const|volatile|long|short)\s+)*'
        r'\w[\w\s\*]*\s+(?:(?:WINAPI|APIENTRY|CALLBACK|__cdecl|__stdcall)\s+)?(\w+)\s*\([^;{]*\)\s*\{',
        re.MULTILINE,
    )
    _all_defs: list[tuple[str, int]] = []
    for m in _func_def_pat.finditer(source):
        fname = m.group(1)
        if fname not in _SKIP_KW2:
            _all_defs.append((fname, m.start()))
    _seen_names: dict[str, int] = {}
    _dup_starts: list[int] = []
    for fname, fstart in _all_defs:
        if fname in _seen_names:
            _dup_starts.append(fstart)
            logger.info("Found duplicate function definition: %s (keeping first)", fname)
        else:
            _seen_names[fname] = fstart
    if _dup_starts:
        for dup_start in sorted(_dup_starts, reverse=True):
            depth, i, n = 0, dup_start, len(source)
            while i < n:
                if source[i] == '{':
                    depth += 1
                elif source[i] == '}':
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            source = source[:dup_start] + source[i:]

    # ── Remove (void)argc/(void)argv in non-main functions ──
    # LLM sometimes copies main() boilerplate into thread workers or other functions
    _main_funcs = _extract_c_functions(source)
    for fname, (fstart, fend) in _main_funcs.items():
        if fname == "main" or fname == "WinMain" or fname == "wWinMain":
            continue
        func_body = source[fstart:fend]
        if '(void)argc' in func_body or '(void)argv' in func_body:
            cleaned = re.sub(r'^\s*\(void\)argc\s*;\s*$', '', func_body, flags=re.MULTILINE)
            cleaned = re.sub(r'^\s*\(void\)argv\s*;\s*$', '', cleaned, flags=re.MULTILINE)
            if cleaned != func_body:
                source = source[:fstart] + cleaned + source[fend:]
                logger.info("Removed (void)argc/(void)argv from non-main function '%s'", fname)

    # ── WNetEnumResourceA 4th arg: sizeof(buf) → &bufSize ──
    # 4th arg must be LPDWORD, not size_t. Fix sizeof(X) → &_wnet_buf_sz with a decl.
    _wnet_sizeof_pat = re.compile(
        r'(_pWNetEnumResourceA|WNetEnumResourceA)\s*\(([^,]+),\s*([^,]+),\s*([^,]+),\s*sizeof\s*\(([^)]+)\)\s*\)'
    )
    if _wnet_sizeof_pat.search(source):
        source = _wnet_sizeof_pat.sub(
            r'\1(\2, \3, \4, &_wnet_buf_sz)',
            source,
        )
        if 'DWORD _wnet_buf_sz' not in source:
            source = re.sub(
                r'(#include\s*<windows\.h>)',
                r'\1\nstatic DWORD _wnet_buf_sz = 16384;',
                source, count=1,
            )

    # ── Keyboard hook callback stub generation ──
    # If SetWindowsHookExA references a callback name that isn't defined, create stub
    _hook_cb_pat = re.compile(
        r'SetWindowsHookExA\s*\(\s*WH_KEYBOARD_LL\s*,\s*'
        r'(?:\(\s*HOOKPROC\s*\)\s*)?(\w+)\s*,'
    )
    _hook_cb_match = _hook_cb_pat.search(source)
    if _hook_cb_match:
        cb_name = _hook_cb_match.group(1)
        _existing_funcs = _extract_c_functions(source)
        if cb_name not in _existing_funcs:
            stub = (
                f"\nLRESULT CALLBACK {cb_name}(int nCode, WPARAM wParam, LPARAM lParam) {{\n"
                f"    if (nCode == HC_ACTION) {{\n"
                f"        KBDLLHOOKSTRUCT *pKb = (KBDLLHOOKSTRUCT *)lParam;\n"
                f"        if (pKb && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {{\n"
                f"            /* key event captured */\n"
                f"        }}\n"
                f"    }}\n"
                f"    return CallNextHookEx(NULL, nCode, wParam, lParam);\n"
                f"}}\n"
            )
            first_func = min(
                (s for s, _ in _existing_funcs.values()),
                default=len(source),
            )
            source = source[:first_func] + stub + "\n" + source[first_func:]
            logger.info("Generated keyboard hook callback stub: %s", cb_name)

    # ── Remove stray '}' at file scope (brace imbalance from LLM) ──
    _brace_depth = 0
    _stray_brace_lines: list[int] = []
    _src_lines = source.split('\n')
    for _li, _line in enumerate(_src_lines):
        stripped = _line.strip()
        if stripped.startswith('#') or stripped.startswith('//'):
            continue
        for ch in stripped:
            if ch == '{':
                _brace_depth += 1
            elif ch == '}':
                _brace_depth -= 1
                if _brace_depth < 0:
                    _stray_brace_lines.append(_li)
                    _brace_depth = 0
    if _stray_brace_lines:
        for _li in reversed(_stray_brace_lines):
            _src_lines[_li] = ''
        source = '\n'.join(_src_lines)
        logger.info("Removed %d stray '}' at file scope (brace imbalance)", len(_stray_brace_lines))

    # ── De-obfuscate hallucinated _p<Api> calls without supporting typedefs ──
    # The evasion pass creates _t<Api> typedefs + _p<Api> function pointers.
    # If the LLM pre-obfuscated calls without declarations, revert to direct API.
    _hallucinated_apis = set()
    for m in re.finditer(r'\b_p([A-Z]\w+)\s*\(', source):
        api_name = m.group(1)
        typedef_name = f'_t{api_name}'
        if typedef_name not in source:
            _hallucinated_apis.add(api_name)
    for api_name in _hallucinated_apis:
        source = re.sub(rf'\b_p{re.escape(api_name)}\b', api_name, source)
        logger.info("De-obfuscated hallucinated _p%s back to %s", api_name, api_name)

    return source



# ---------------------------------------------------------------------------
# Post-assembly cross-reference validation
# ---------------------------------------------------------------------------

_SIG_PARSE_RE = re.compile(
    r'^(?:(?:static|inline|__forceinline|WINAPI|APIENTRY|__cdecl|__stdcall|'
    r'__declspec\s*\([^)]*\)|__attribute__\s*\([^)]*\))\s+)*'
    r'((?:(?:unsigned|signed|const|volatile|long|short|struct)\s+)*\w[\w\s\*]*?)'
    r'\s+(\w+)\s*\(([^)]*)\)',
    re.MULTILINE,
)

_CALL_RE = re.compile(r'\b(\w+)\s*\(')


def _quick_parse_sig(sig_str: str) -> Optional[dict]:
    """Parse a single signature string like 'BOOL get_system_info(char *buf, int max_len)'."""
    m = re.match(r'(\w[\w\s\*]*?)\s+\w+\s*\(([^)]*)\)', sig_str.strip().rstrip(';'))
    if not m:
        return None
    ret_type = m.group(1).strip()
    params_str = m.group(2).strip()
    if params_str in ("void", ""):
        return {"return_type": ret_type, "params": []}
    params = []
    for p in params_str.split(","):
        p = p.strip()
        if not p:
            continue
        pp = p.rsplit(None, 1)
        if len(pp) == 2:
            params.append((pp[0].strip(), pp[1].strip().lstrip('*')))
        else:
            params.append((p, ""))
    return {"return_type": ret_type, "params": params}


def _parse_func_signatures(source: str) -> dict[str, dict]:
    """Parse actual function definitions from assembled source.

    Returns {name: {'return_type': str, 'params': [(type, name), ...], 'param_count': int}}.
    Uses paren-depth counting so function-pointer parameters are handled correctly.
    """
    funcs = _extract_c_functions(source)
    result = {}
    for name, (start, _end) in funcs.items():
        sig = _extract_chunk_signature(source[start:start + 500])
        if not sig:
            continue
        paren_pos = sig.find('(')
        if paren_pos == -1:
            continue
        pre = sig[:paren_pos].strip()
        parts = pre.rsplit(None, 1)
        if len(parts) < 2:
            continue
        fname = parts[-1].lstrip('*')
        if fname != name:
            continue
        ret_type = parts[0] if len(parts) == 2 else " ".join(parts[:-1])
        depth = 0
        pstart = paren_pos
        pend = len(sig)
        for ci, ch in enumerate(sig[paren_pos:], paren_pos):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    pend = ci
                    break
        params_str = sig[pstart + 1:pend].strip()
        if params_str in ("void", ""):
            params = []
        else:
            params = []
            cur_depth = 0
            cur_param: list[str] = []
            for ch in params_str:
                if ch == '(':
                    cur_depth += 1
                    cur_param.append(ch)
                elif ch == ')':
                    cur_depth -= 1
                    cur_param.append(ch)
                elif ch == ',' and cur_depth == 0:
                    params.append("".join(cur_param).strip())
                    cur_param = []
                else:
                    cur_param.append(ch)
            if cur_param:
                params.append("".join(cur_param).strip())
            parsed_params = []
            for p in params:
                if not p:
                    continue
                pp = p.rsplit(None, 1)
                if len(pp) == 2:
                    ptype = pp[0].strip()
                    pname = pp[1].strip().lstrip('*')
                    parsed_params.append((ptype, pname))
                else:
                    parsed_params.append((p, ""))
            params = parsed_params
        result[name] = {
            "return_type": ret_type,
            "params": params,
            "param_count": len(params),
        }
    return result


def _validate_and_fix_call_sites(source: str) -> str:
    """Post-assembly: verify every call site matches the actual function definition.

    Fixes:
    1. Forward declarations that don't match function bodies (replace with actual sig)
    2. Call sites with wrong argument count (cannot auto-fix — log warning)
    3. Return value used as wrong type (cannot always auto-fix — log warning)

    The biggest win: forward declarations are rebuilt from actual bodies, which
    eliminates the "conflicting types" and "implicit declaration" cascades.
    """
    sigs = _parse_func_signatures(source)
    if not sigs:
        return source

    funcs = _extract_c_functions(source)
    first_func_start = min(s for s, _ in funcs.values()) if funcs else len(source)
    header = source[:first_func_start]
    body = source[first_func_start:]

    # -- Fix 1: Rebuild forward declarations from actual function bodies --
    # Use _extract_chunk_signature on each body to get the exact signature
    # (handles nested parens in function-pointer params correctly).
    new_decls = []
    for name, (fstart, fend) in funcs.items():
        func_text = source[fstart:fend]
        sig = _extract_chunk_signature(func_text)
        if sig:
            new_decls.append(f"{sig};")

    # Remove old forward declarations from the FULL source — match any line that
    # declares a known function name followed by (...); allowing nested parens.
    # Must check both header and body since splice operations can scatter them.
    _FWD_DECL_PREFIX = re.compile(
        r'^(?:(?:static|inline|extern|__forceinline)\s+)*'
        r'(?:(?:unsigned|signed|const|volatile|long|short|struct)\s+)*'
        r'(?:BOOL|DWORD|HANDLE|HRESULT|LPVOID|PVOID|void|int|char|BYTE|WORD|'
        r'LONG|ULONG|SIZE_T|LRESULT|UINT|LPSTR|LPCSTR|LPWSTR|LPCWSTR|HCRYPTPROV|'
        r'HCRYPTKEY|HCRYPTHASH|HMODULE|HINSTANCE|HWND|FARPROC|NTSTATUS|LSTATUS|'
        r'SOCKET|WSADATA|wchar_t|size_t|ssize_t|LPTSTR|LPCTSTR|PBYTE|PDWORD|'
        r'\w+)\s+(?:WINAPI\s+|CALLBACK\s+|APIENTRY\s+|__cdecl\s+|__stdcall\s+)?'
    )

    def _is_fwd_decl(line_text):
        stripped = line_text.strip()
        if not stripped.endswith(";"):
            return False
        if not _FWD_DECL_PREFIX.match(stripped):
            return False
        for name in funcs:
            m = re.search(r'\b' + re.escape(name) + r'\s*\(', stripped)
            if not m:
                continue
            pre = stripped[:m.start()]
            if '=' in pre:
                return False
            return True
        return False

    cleaned_header_lines = [l for l in header.splitlines() if not _is_fwd_decl(l)]
    cleaned_body_lines = [l for l in body.splitlines() if not _is_fwd_decl(l)]

    cleaned_header = "\n".join(cleaned_header_lines).rstrip() + "\n"
    if new_decls:
        cleaned_header += "\n" + "\n".join(new_decls) + "\n\n"

    source = cleaned_header + "\n".join(cleaned_body_lines)

    # -- Fix 2: Detect call-site argument count mismatches in function bodies --
    # Re-parse after Fix 1 modified the source (offsets changed)
    funcs = _extract_c_functions(source)
    sigs = _parse_func_signatures(source)
    for caller_name, (cstart, cend) in funcs.items():
        caller_body = source[cstart:cend]
        for m in _CALL_RE.finditer(caller_body):
            callee = m.group(1)
            if callee not in sigs or callee == caller_name:
                continue
            expected_count = sigs[callee]["param_count"]
            call_start = m.start() + len(caller_body[:m.start()].split('\n')[-1]) - len(caller_body[:m.start()].split('\n')[-1])
            paren_start = m.end() - 1
            abs_pos = cstart + paren_start
            depth = 1
            i = abs_pos + 1
            n = len(source)
            while i < n and depth > 0:
                if source[i] == '(':
                    depth += 1
                elif source[i] == ')':
                    depth -= 1
                elif source[i] in ('"', "'"):
                    q = source[i]
                    i += 1
                    while i < n and source[i] != q:
                        if source[i] == '\\':
                            i += 1
                        i += 1
                i += 1
            args_str = source[abs_pos + 1:i - 1].strip()
            if not args_str:
                actual_count = 0
            else:
                actual_count = 1
                depth = 0
                for ch in args_str:
                    if ch in ('(', '['):
                        depth += 1
                    elif ch in (')', ']'):
                        depth -= 1
                    elif ch == ',' and depth == 0:
                        actual_count += 1

            if actual_count != expected_count:
                logger.warning(
                    "Call-site mismatch: %s() in %s() passes %d args, expected %d",
                    callee, caller_name, actual_count, expected_count,
                )
                call_end = i  # position after closing paren
                if actual_count > expected_count and expected_count >= 0:
                    # Too many args — trim from the end
                    _args_raw = source[abs_pos + 1:call_end - 1]
                    _arg_parts = _split_args(_args_raw)
                    trimmed = ", ".join(_arg_parts[:expected_count])
                    source = source[:abs_pos + 1] + trimmed + source[call_end - 1:]
                    logger.info("  → auto-trimmed %s() call from %d to %d args",
                                callee, actual_count, expected_count)
                elif actual_count < expected_count:
                    callee_params = sigs[callee].get("params", [])
                    defaults = []
                    for pi in range(actual_count, expected_count):
                        if pi < len(callee_params):
                            ptype = callee_params[pi][0].lower()
                            if '*' in ptype or 'lp' in ptype or 'handle' in ptype or 'pvoid' in ptype:
                                defaults.append("NULL")
                            else:
                                defaults.append("0")
                        else:
                            defaults.append("0")
                    pad = ", ".join(defaults)
                    if actual_count == 0:
                        insert = pad
                    else:
                        insert = ", " + pad
                    source = source[:call_end - 1] + insert + source[call_end - 1:]
                    logger.info("  → auto-padded %s() call from %d to %d args",
                                callee, actual_count, expected_count)
                # Re-extract functions since source changed
                funcs = _extract_c_functions(source)

    logger.info(
        "Cross-reference validation: rebuilt %d forward declaration(s) from actual bodies",
        len(new_decls),
    )
    return source


def _split_args(args_str: str) -> list[str]:
    """Split a C argument string respecting nested parens and string literals."""
    parts = []
    current = []
    depth = 0
    i = 0
    while i < len(args_str):
        ch = args_str[i]
        if ch in ('"', "'"):
            q = ch
            current.append(ch)
            i += 1
            while i < len(args_str) and args_str[i] != q:
                if args_str[i] == '\\':
                    current.append(args_str[i])
                    i += 1
                if i < len(args_str):
                    current.append(args_str[i])
                    i += 1
            if i < len(args_str):
                current.append(args_str[i])
            i += 1
            continue
        if ch in ('(', '['):
            depth += 1
        elif ch in (')', ']'):
            depth -= 1
        elif ch == ',' and depth == 0:
            parts.append("".join(current).strip())
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    if current:
        parts.append("".join(current).strip())
    return parts



def _extract_erroring_functions(
    source: str,
    compiler_error: str,
) -> tuple[str, str, list[str]]:
    """Extract the file header and the specific functions that contain compiler errors.

    Returns:
        header_text:   #includes, typedefs, globals — everything before the first function
        funcs_text:    text of each erroring function joined by blank lines (empty str if none found)
        func_names:    names of the extracted functions (used for splicing the fix back in)
    """
    # Parse 1-indexed line numbers from compiler error output.
    # Handles: file.c:LINE:COL: ...  and  file.c:LINE: ...
    error_lnos: set[int] = set()
    for m in re.finditer(r'\.c:(\d+)[:\s]', compiler_error):
        n = int(m.group(1))
        if n >= 1:
            error_lnos.add(n)

    # Collect function names from GCC "In function 'NAME'" messages
    gcc_in_func: set[str] = set()
    for m in re.finditer(r"In function [`'](\w+)'", compiler_error):
        gcc_in_func.add(m.group(1))

    # Collect function names from "undefined reference to `NAME'"
    mentioned: set[str] = set()
    for m in re.finditer(r"undefined reference to [`'](\w+)'?", compiler_error):
        mentioned.add(m.group(1))

    funcs = _extract_c_functions(source)  # {name: (start_char, end_char)}
    if not funcs:
        return source[:2000], "", []

    # Build line-number → char-offset lookup
    line_starts: list[int] = [0]
    for i, ch in enumerate(source):
        if ch == '\n':
            line_starts.append(i + 1)

    def _lno_to_offset(lno: int) -> int:
        idx = lno - 1
        return line_starts[idx] if idx < len(line_starts) else len(source) - 1

    # Find which functions contain each error line
    erroring: set[str] = set()
    for lno in error_lnos:
        off = _lno_to_offset(lno)
        for name, (start, end) in funcs.items():
            if start <= off < end:
                erroring.add(name)
                break

    # Add explicitly mentioned names that are defined functions
    erroring.update(n for n in mentioned if n in funcs)

    # GCC "In function 'X'" — these are authoritative even for malformed signatures
    for gname in gcc_in_func:
        if gname in funcs:
            erroring.add(gname)
        elif gname not in erroring:
            # Function has a malformed signature so _extract_c_functions missed it.
            # Find it by regex and add to funcs dict for extraction.
            pat = re.compile(
                r'(?:^|\n)'
                r'((?:static\s+|unsigned\s+|const\s+)*'
                r'(?:BOOL|DWORD|int|void|char\s*\*|HANDLE|HRESULT|LONG|UINT|SIZE_T)\s+'
                r'(?:WINAPI\s+|CALLBACK\s+|__stdcall\s+)?'
                + re.escape(gname) +
                r'\s*\([^)]*(?:\)|[^{]*)\{)',
                re.MULTILINE
            )
            sig_m = pat.search(source)
            if sig_m:
                fn_start = sig_m.start() + (1 if source[sig_m.start()] == '\n' else 0)
                depth = 1
                pos = sig_m.end()
                while pos < len(source) and depth > 0:
                    if source[pos] == '{': depth += 1
                    elif source[pos] == '}': depth -= 1
                    pos += 1
                funcs[gname] = (fn_start, pos)
                erroring.add(gname)
                logger.info("Compile-fix: recovered '%s' via GCC error message (malformed signature)", gname)

    if not erroring:
        if error_lnos:
            first_func_off = min(s for s, _ in funcs.values())
            all_in_header = all(_lno_to_offset(ln) < first_func_off for ln in error_lnos)
            if not all_in_header:
                # Before falling back to "closest parseable function", try a loose
                # scan for function-like constructs near the error lines. This catches
                # malformed signatures that _extract_c_functions can't parse (e.g.
                # missing ')' before '{').
                _LOOSE_FUNC_PAT = re.compile(
                    r'(?:^|\n)'
                    r'((?:static\s+|unsigned\s+|const\s+|volatile\s+)*'
                    r'(?:BOOL|DWORD|int|void|char|HANDLE|HRESULT|LONG|UINT|SIZE_T|LPVOID|PVOID|NTSTATUS|SOCKET|LRESULT|HMODULE|FARPROC|WINBOOL)'
                    r'(?:\s*\*)*\s+'
                    r'(?:WINAPI\s+|CALLBACK\s+|__stdcall\s+|__cdecl\s+)?'
                    r'(\w+)\s*\()',
                    re.MULTILINE
                )
                first_err_off = _lno_to_offset(min(error_lnos))
                last_err_off = _lno_to_offset(max(error_lnos))
                for lm in _LOOSE_FUNC_PAT.finditer(source):
                    cand_name = lm.group(2)
                    if cand_name in funcs:
                        continue  # already parsed — skip
                    sig_start = lm.start() + (1 if source[lm.start()] == '\n' else 0)
                    # Find the opening brace after the signature
                    brace_pos = source.find('{', lm.end())
                    if brace_pos == -1 or brace_pos - lm.end() > 200:
                        continue  # no opening brace nearby
                    # Walk brace depth to find function end
                    depth, pos = 1, brace_pos + 1
                    while pos < len(source) and depth > 0:
                        if source[pos] == '{': depth += 1
                        elif source[pos] == '}': depth -= 1
                        pos += 1
                    fn_end = pos
                    # Check if any error line falls within this function
                    if any(sig_start <= _lno_to_offset(ln) < fn_end for ln in error_lnos):
                        funcs[cand_name] = (sig_start, fn_end)
                        erroring.add(cand_name)
                        logger.info(
                            "Compile-fix: recovered malformed function '%s' via loose scan (char %d–%d)",
                            cand_name, sig_start, fn_end,
                        )
                if not erroring:
                    # Last resort: closest parseable function
                    first_off = _lno_to_offset(min(error_lnos))
                    closest = min(funcs.items(), key=lambda kv: abs(kv[1][0] - first_off))
                    erroring.add(closest[0])
            # else: all errors are in the header — leave erroring empty so the
            # header-fix path is taken in fix_compile_error()
        elif mentioned:
            # Linker error (no line numbers): the fix is usually in main/WinMain
            for _candidate in ("main", "WinMain", "wWinMain"):
                if _candidate in funcs:
                    erroring.add(_candidate)
                    break
            if not erroring:
                # Last resort: the last function in source order is often the entry point
                last_name = max(funcs.items(), key=lambda kv: kv[1][0])[0]
                erroring.add(last_name)

    # File header = everything before the first function definition
    first_func_start = min(s for s, _ in funcs.values())
    header_text = source[:first_func_start].rstrip()

    # Extract erroring functions in source order
    func_name_list = sorted(erroring, key=lambda n: funcs[n][0])
    func_texts = [source[funcs[n][0]:funcs[n][1]].strip() for n in func_name_list]
    funcs_text = '\n\n'.join(func_texts)

    return header_text, funcs_text, func_name_list

