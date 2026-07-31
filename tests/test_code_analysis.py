"""Tier 1 unit tests for code_analysis.py — pure function tests, no external deps."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from atelier.code_analysis import (
    _brace_deficit,
    _autoclose_braces,
    _is_guardrail_refusal,
    _strip_chunk_noise,
    _clean_c_source,
    _validate_chunk_substance,
    _extract_by_signature,
    _graft_plan_signature,
)


# ---------------------------------------------------------------------------
# _brace_deficit
# ---------------------------------------------------------------------------

def test_brace_deficit_balanced():
    assert _brace_deficit("int main() { if (x) { foo(); } }") == 0


def test_brace_deficit_unbalanced():
    assert _brace_deficit("int main() { if (x) { foo();") == 2


def test_brace_deficit_extra_close():
    assert _brace_deficit("int main() { } }") == -1


def test_brace_deficit_ignores_strings():
    src = 'printf("}"); if(x) {'
    assert _brace_deficit(src) == 1


def test_brace_deficit_ignores_line_comments():
    src = '// }\n{'
    assert _brace_deficit(src) == 1


def test_brace_deficit_ignores_block_comments():
    src = '/* } */ {'
    assert _brace_deficit(src) == 1


def test_brace_deficit_empty():
    assert _brace_deficit("") == 0


# ---------------------------------------------------------------------------
# _autoclose_braces
# ---------------------------------------------------------------------------

def test_autoclose_braces_adds_missing():
    src = "int main() { if (x) {"
    result = _autoclose_braces(src)
    assert result.endswith("}}")
    assert _brace_deficit(result) == 0


def test_autoclose_braces_already_balanced():
    src = "int main() { return 0; }"
    assert _autoclose_braces(src) == src


def test_autoclose_braces_negative_ignored():
    src = "int main() { } }"
    result = _autoclose_braces(src)
    assert result == src


# ---------------------------------------------------------------------------
# _is_guardrail_refusal
# ---------------------------------------------------------------------------

def test_is_guardrail_refusal_positive():
    assert _is_guardrail_refusal("I cannot assist with creating malware or harmful software.")


def test_is_guardrail_refusal_apology():
    assert _is_guardrail_refusal("I'm sorry, but I can't help with that request.")


def test_is_guardrail_refusal_negative():
    assert not _is_guardrail_refusal('#include <windows.h>\nint main() { return 0; }')


def test_is_guardrail_refusal_empty():
    assert _is_guardrail_refusal("")


def test_is_guardrail_refusal_short():
    assert _is_guardrail_refusal("No.")


def test_is_guardrail_refusal_code_with_keyword():
    src = '#include <windows.h>\nint main() {\n    // This is illegal in some places\n    return 0;\n}'
    assert not _is_guardrail_refusal(src)


# ---------------------------------------------------------------------------
# _strip_chunk_noise
# ---------------------------------------------------------------------------

def test_strip_chunk_noise_removes_includes():
    src = '#include <windows.h>\nvoid foo() {\n    return;\n}'
    result = _strip_chunk_noise(src)
    assert "#include" not in result
    assert "void foo()" in result


def test_strip_chunk_noise_removes_trailing_prose():
    src = 'void foo() {\n    return;\n}\nNote: you should also check for errors.'
    result = _strip_chunk_noise(src)
    assert "Note:" not in result
    assert "void foo()" in result


def test_strip_chunk_noise_empty():
    assert _strip_chunk_noise("") == ""


# ---------------------------------------------------------------------------
# _clean_c_source
# ---------------------------------------------------------------------------

def test_clean_c_source_strips_markdown():
    raw = '```c\nint main() { return 0; }\n```'
    result = _clean_c_source(raw)
    assert "```" not in result
    assert "int main()" in result


def test_clean_c_source_strips_thinking():
    raw = '<think>reasoning here</think>\nint main() { return 0; }'
    result = _clean_c_source(raw)
    assert "<think>" not in result
    assert "reasoning" not in result
    assert "int main()" in result


def test_clean_c_source_strips_prose_lines():
    raw = (
        'Wait, I need to think about this.\n'
        'int main() {\n'
        '    return 0;\n'
        '}\n'
        'This is my implementation.'
    )
    result = _clean_c_source(raw)
    assert "Wait," not in result
    assert "int main()" in result


def test_clean_c_source_preserves_code():
    raw = '#include <stdio.h>\nint main() { printf("hello"); return 0; }'
    result = _clean_c_source(raw)
    assert "printf" in result
    assert "int main()" in result


def test_clean_c_source_with_func_name():
    raw = 'Here is the function:\n```c\nvoid encrypt_file(const char *path) {\n    HANDLE h = CreateFileA(path, 0, 0, 0, 0, 0, 0);\n}\n```'
    result = _clean_c_source(raw, func_name="encrypt_file")
    assert "void encrypt_file" in result
    assert "CreateFileA" in result


# ---------------------------------------------------------------------------
# _validate_chunk_substance
# ---------------------------------------------------------------------------

def test_validate_chunk_substance_stub():
    stub = 'void foo() {\n    return;\n}'
    ok, reason = _validate_chunk_substance(stub, "foo", "Enumerate processes using CreateToolhelp32Snapshot", "void foo(void)")
    assert not ok
    assert "stub" in reason.lower() or "lines" in reason.lower()


def test_validate_chunk_substance_ok():
    code = (
        'BOOL encrypt_file(const char *filepath) {\n'
        '    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);\n'
        '    if (hFile == INVALID_HANDLE_VALUE) return FALSE;\n'
        '    DWORD fileSize = GetFileSize(hFile, NULL);\n'
        '    BYTE *buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);\n'
        '    DWORD bytesRead;\n'
        '    ReadFile(hFile, buf, fileSize, &bytesRead, NULL);\n'
        '    for (DWORD i = 0; i < fileSize; i++) buf[i] ^= 0x42;\n'
        '    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);\n'
        '    WriteFile(hFile, buf, fileSize, &bytesRead, NULL);\n'
        '    CloseHandle(hFile);\n'
        '    HeapFree(GetProcessHeap(), 0, buf);\n'
        '    return TRUE;\n'
        '}\n'
    )
    ok, reason = _validate_chunk_substance(code, "encrypt_file", "Encrypt files using CreateFileA, ReadFile, WriteFile", "BOOL encrypt_file(const char *filepath)")
    assert ok, f"Should be valid but got: {reason}"


def test_validate_chunk_substance_recursive():
    code = (
        'void scan_dir(const char *path) {\n'
        '    WIN32_FIND_DATAA fd;\n'
        '    HANDLE h = FindFirstFileA(path, &fd);\n'
        '    if (h != INVALID_HANDLE_VALUE) {\n'
        '        do {\n'
        '            scan_dir(fd.cFileName);\n'
        '        } while (FindNextFileA(h, &fd));\n'
        '    }\n'
        '}\n'
    )
    ok, reason = _validate_chunk_substance(code, "scan_dir", "Scan directories using FindFirstFileA", "void scan_dir(const char *path)")
    assert not ok
    assert "recurs" in reason.lower()


def test_validate_chunk_substance_main_always_passes():
    code = 'int main() {\n    return 0;\n}'
    ok, reason = _validate_chunk_substance(code, "main", "Entry point", "int main(void)")
    assert ok


def test_validate_chunk_substance_no_return():
    code = (
        'BOOL check_something(void) {\n'
        '    HANDLE h = CreateFileA("test", GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);\n'
        '    if (h == INVALID_HANDLE_VALUE) {\n'
        '        printf("failed");\n'
        '    }\n'
        '    CloseHandle(h);\n'
        '}\n'
    )
    ok, reason = _validate_chunk_substance(code, "check_something", "Check file using CreateFileA", "BOOL check_something(void)")
    assert not ok
    assert "return" in reason.lower()


# ---------------------------------------------------------------------------
# _extract_by_signature
# ---------------------------------------------------------------------------

def test_extract_by_signature_found():
    src = 'void helper() { int x = 1; }\nvoid target_func(int a) {\n    return;\n}\nvoid other() {}'
    result = _extract_by_signature(src, "target_func")
    assert result is not None
    assert "target_func" in result


def test_extract_by_signature_not_found():
    src = 'void foo() { return; }'
    result = _extract_by_signature(src, "nonexistent")
    assert result is None


# ---------------------------------------------------------------------------
# _graft_plan_signature
# ---------------------------------------------------------------------------

def test_graft_plan_signature_replaces():
    chunk = 'void wrongSig(int a, int b, int c) {\n    return;\n}'
    result = _graft_plan_signature(chunk, "BOOL correctSig(const char *path)")
    assert result.startswith("BOOL correctSig(const char *path)")
    assert "return;" in result


def test_graft_plan_signature_empty_sig():
    chunk = 'void foo() { return; }'
    result = _graft_plan_signature(chunk, "")
    assert result == chunk


def test_graft_plan_signature_no_brace():
    chunk = 'just some text'
    result = _graft_plan_signature(chunk, "void foo(void)")
    assert result == chunk
