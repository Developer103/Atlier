"""Tier 1 unit tests for evasion_passes.py — transform correctness."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from malware_gen_framework.evasion_passes import (
    _mutate_source,
    _encrypt_string_literals,
    _obfuscate_api_calls,
    _inject_amsi_etw_bypass,
    _inject_anti_debug,
    _inject_seh_in_main,
    _inject_process_injection,
    _ensure_exfil_substance,
)
from malware_gen_framework.code_analysis import _brace_deficit


MINIMAL_SOURCE = (
    '#include <windows.h>\n'
    '#include <stdio.h>\n'
    '\n'
    'int main(int argc, char *argv[]) {\n'
    '    DWORD pid = GetCurrentProcessId();\n'
    '    char hostname[256];\n'
    '    DWORD size = sizeof(hostname);\n'
    '    GetComputerNameA(hostname, &size);\n'
    '    printf("Host: %s PID: %lu\\n", hostname, pid);\n'
    '    return 0;\n'
    '}\n'
)

API_SOURCE = (
    '#include <windows.h>\n'
    '#include <tlhelp32.h>\n'
    '#include <stdio.h>\n'
    '\n'
    'void enum_procs() {\n'
    '    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n'
    '    if (hSnap == INVALID_HANDLE_VALUE) return;\n'
    '    PROCESSENTRY32 pe = {sizeof(pe)};\n'
    '    if (Process32First(hSnap, &pe)) {\n'
    '        do {\n'
    '            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);\n'
    '            if (hProc) CloseHandle(hProc);\n'
    '        } while (Process32Next(hSnap, &pe));\n'
    '    }\n'
    '    CloseHandle(hSnap);\n'
    '}\n'
    '\n'
    'int main(int argc, char *argv[]) {\n'
    '    enum_procs();\n'
    '    return 0;\n'
    '}\n'
)


# ---------------------------------------------------------------------------
# _mutate_source
# ---------------------------------------------------------------------------

def test_mutate_source_changes_output():
    results = set()
    for _ in range(5):
        results.add(hash(_mutate_source(MINIMAL_SOURCE)))
    assert len(results) > 1, "Mutation should produce different results across calls"


def test_mutate_source_preserves_structure():
    result = _mutate_source(MINIMAL_SOURCE)
    assert "main" in result
    deficit = _brace_deficit(result)
    assert deficit == 0, f"Mutation broke brace balance: deficit={deficit}"


def test_mutate_source_keeps_main():
    result = _mutate_source(MINIMAL_SOURCE)
    assert "int main(" in result or "main(" in result


# ---------------------------------------------------------------------------
# _encrypt_string_literals
# ---------------------------------------------------------------------------

def test_encrypt_string_literals_removes_plaintext():
    source = (
        '#include <windows.h>\n'
        '#include <stdio.h>\n'
        '\n'
        'int main(int argc, char *argv[]) {\n'
        '    char *msg = "Hello World Test Message";\n'
        '    printf("Program started successfully\\n");\n'
        '    return 0;\n'
        '}\n'
    )
    result = _encrypt_string_literals(source)
    assert "Hello World Test Message" not in result
    assert "Program started successfully" not in result


def test_encrypt_string_literals_adds_xor_key():
    source = (
        '#include <windows.h>\n'
        '#include <stdio.h>\n'
        '\n'
        'int main(int argc, char *argv[]) {\n'
        '    char *msg = "Hello World Test Message";\n'
        '    return 0;\n'
        '}\n'
    )
    result = _encrypt_string_literals(source)
    assert "_xk[" in result
    assert "_xd_init" in result


def test_encrypt_string_literals_skips_format_strings():
    source = (
        '#include <windows.h>\n'
        '#include <stdio.h>\n'
        '\n'
        'int main(int argc, char *argv[]) {\n'
        '    printf("%d items processed\\n", count);\n'
        '    return 0;\n'
        '}\n'
    )
    result = _encrypt_string_literals(source)
    assert "%d" in result


def test_encrypt_string_literals_skips_short():
    source = (
        '#include <windows.h>\n'
        '#include <stdio.h>\n'
        '\n'
        'int main(int argc, char *argv[]) {\n'
        '    char *x = "ab";\n'
        '    return 0;\n'
        '}\n'
    )
    result = _encrypt_string_literals(source)
    # Short string should not be encrypted, _xk should not appear
    assert "_xk" not in result


def test_encrypt_string_literals_preserves_includes():
    source = (
        '#include <windows.h>\n'
        '#include <stdio.h>\n'
        '\n'
        'int main(int argc, char *argv[]) {\n'
        '    char *msg = "This is a long test message";\n'
        '    return 0;\n'
        '}\n'
    )
    result = _encrypt_string_literals(source)
    assert "#include <windows.h>" in result
    assert "#include <stdio.h>" in result


# ---------------------------------------------------------------------------
# _obfuscate_api_calls
# ---------------------------------------------------------------------------

def test_obfuscate_api_calls_resolves_at_runtime():
    result = _obfuscate_api_calls(API_SOURCE)
    assert "GetProcAddress" in result
    assert "_api_init" in result
    assert "_pCreateToolhelp32Snapshot" in result
    assert "_pOpenProcess" in result


def test_obfuscate_api_calls_no_suspicious():
    source = (
        '#include <windows.h>\n'
        '#include <stdio.h>\n'
        '\n'
        'int main(int argc, char *argv[]) {\n'
        '    printf("hello");\n'
        '    return 0;\n'
        '}\n'
    )
    result = _obfuscate_api_calls(source)
    assert result == source


def test_obfuscate_api_calls_preserves_structure():
    result = _obfuscate_api_calls(API_SOURCE)
    assert "main" in result
    assert _brace_deficit(result) == 0


# ---------------------------------------------------------------------------
# _inject_amsi_etw_bypass
# ---------------------------------------------------------------------------

def test_inject_amsi_etw_bypass():
    result = _inject_amsi_etw_bypass(MINIMAL_SOURCE)
    assert "_patch_amsi_etw" in result
    assert "AmsiScanBuffer" in result
    assert "EtwEventWrite" in result


def test_inject_amsi_etw_bypass_idempotent():
    first = _inject_amsi_etw_bypass(MINIMAL_SOURCE)
    second = _inject_amsi_etw_bypass(first)
    assert first == second


def test_inject_amsi_etw_bypass_adds_string_h():
    source = '#include <windows.h>\n\nint main(int argc, char *argv[]) {\n    return 0;\n}\n'
    result = _inject_amsi_etw_bypass(source)
    assert "#include <string.h>" in result


# ---------------------------------------------------------------------------
# _inject_anti_debug
# ---------------------------------------------------------------------------

def test_inject_anti_debug():
    result = _inject_anti_debug(MINIMAL_SOURCE)
    assert "_chk_dbg" in result
    assert "IsDebuggerPresent" in result


def test_inject_anti_debug_idempotent():
    first = _inject_anti_debug(MINIMAL_SOURCE)
    second = _inject_anti_debug(first)
    assert first == second


def test_inject_anti_debug_calls_in_entry():
    result = _inject_anti_debug(MINIMAL_SOURCE)
    # Should add _chk_dbg call after main's opening brace
    main_idx = result.index("int main(")
    chk_idx = result.index("_chk_dbg()", main_idx)
    assert chk_idx > main_idx


# ---------------------------------------------------------------------------
# _inject_seh_in_main
# ---------------------------------------------------------------------------

def test_inject_seh_in_main():
    result = _inject_seh_in_main(MINIMAL_SOURCE)
    assert "_worker_thread" in result
    assert "_crash_filter" in result
    assert "SetUnhandledExceptionFilter" in result
    assert "CreateThread" in result


def test_inject_seh_in_main_idempotent():
    first = _inject_seh_in_main(MINIMAL_SOURCE)
    second = _inject_seh_in_main(first)
    assert first == second


def test_inject_seh_moves_body():
    result = _inject_seh_in_main(MINIMAL_SOURCE)
    # Original main body (GetCurrentProcessId) should be in _worker_thread now
    worker_idx = result.index("_worker_thread")
    assert "GetCurrentProcessId" in result[worker_idx:]


def test_inject_seh_new_main_has_sleep():
    result = _inject_seh_in_main(MINIMAL_SOURCE)
    main_idx = result.index("int main(int argc")
    assert "Sleep(5000)" in result[main_idx:]


# ---------------------------------------------------------------------------
# _inject_process_injection
# ---------------------------------------------------------------------------

def test_inject_process_injection_adds_apis():
    result = _inject_process_injection(MINIMAL_SOURCE)
    assert "VirtualAllocEx" in result
    assert "CreateRemoteThread" in result
    assert "_inject_payload" in result


def test_inject_process_injection_idempotent():
    first = _inject_process_injection(MINIMAL_SOURCE)
    second = _inject_process_injection(first)
    assert first == second


def test_inject_process_injection_skips_existing():
    source = MINIMAL_SOURCE.replace("return 0;", "VirtualAllocEx(0,0,0,0,0);\n    return 0;")
    result = _inject_process_injection(source)
    assert result == source


def test_inject_process_injection_adds_tlhelp32():
    source = (
        '#include <windows.h>\n'
        '#include <stdio.h>\n'
        '\n'
        'int main(int argc, char *argv[]) {\n'
        '    printf("hello");\n'
        '    return 0;\n'
        '}\n'
    )
    result = _inject_process_injection(source)
    assert "tlhelp32.h" in result


# ---------------------------------------------------------------------------
# _ensure_exfil_substance (requires _extract_c_functions which uses generation_engine)
# ---------------------------------------------------------------------------

def test_ensure_exfil_substance_no_network():
    source = (
        '#include <windows.h>\n'
        'int main() {\n'
        '    CreateFileA("test.txt", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);\n'
        '    return 0;\n'
        '}\n'
    )
    result = _ensure_exfil_substance(source)
    assert result == source  # no send() = nothing to fix


def test_ensure_exfil_substance_already_substantial():
    source = (
        '#include <windows.h>\n'
        '#include <winsock2.h>\n'
        '#include <tlhelp32.h>\n'
        '#include <stdio.h>\n'
        '\n'
        'void exfil(SOCKET sock) {\n'
        '    char buf[4096];\n'
        '    DWORD sz = sizeof(buf);\n'
        '    GetComputerNameA(buf, &sz);\n'
        '    GetUserNameA(buf + strlen(buf), &sz);\n'
        '    ReadFile(INVALID_HANDLE_VALUE, buf, 100, &sz, NULL);\n'
        '    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n'
        '    send(sock, buf, strlen(buf), 0);\n'
        '}\n'
        '\n'
        'int main() { return 0; }\n'
    )
    result = _ensure_exfil_substance(source)
    # Should not add _collect_sysinfo since substance score >= 3
    assert "_collect_sysinfo" not in result
