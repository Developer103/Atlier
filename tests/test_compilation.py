"""Tier 2 integration tests — MinGW cross-compilation, no VM or LLM required."""

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ---------------------------------------------------------------------------
# MinGW cross-compilation
# ---------------------------------------------------------------------------

def test_mingw_compile_simple_exe(mingw_available, sample_c_source):
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "test.c"
        out = Path(tmpdir) / "test.exe"
        src.write_text(sample_c_source)
        ret = subprocess.run(
            ["x86_64-w64-mingw32-gcc", "-O2", "-s", "-static",
             str(src), "-o", str(out),
             "-lws2_32", "-ladvapi32", "-liphlpapi", "-lcrypt32", "-lole32", "-lshell32"],
            capture_output=True, text=True,
        )
        assert ret.returncode == 0, f"Compilation failed:\n{ret.stderr}"
        assert out.exists()
        assert out.stat().st_size > 0


def test_mingw_compile_existing_source(mingw_available):
    src = Path(__file__).resolve().parent.parent / "results" / "malware_source.c"
    if not src.exists():
        pytest.skip("results/malware_source.c not found")
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "test.exe"
        ret = subprocess.run(
            ["x86_64-w64-mingw32-gcc", "-O2", "-s", "-static",
             str(src), "-o", str(out),
             "-lws2_32", "-ladvapi32", "-liphlpapi", "-lcrypt32", "-lole32", "-lshell32",
             "-lmpr", "-lwininet", "-lshlwapi"],
            capture_output=True, text=True,
        )
        assert ret.returncode == 0, f"Compilation failed:\n{ret.stderr}"
        assert out.exists()


def test_mingw_compile_dll(mingw_available):
    source = (
        '#include <windows.h>\n'
        'BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {\n'
        '    if (fdwReason == DLL_PROCESS_ATTACH) {\n'
        '        MessageBoxA(NULL, "loaded", "DLL", MB_OK);\n'
        '    }\n'
        '    return TRUE;\n'
        '}\n'
        '__declspec(dllexport) void RunPayload(void) {\n'
        '    CreateFileA("test.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);\n'
        '}\n'
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "test.c"
        out = Path(tmpdir) / "test.dll"
        src.write_text(source)
        ret = subprocess.run(
            ["x86_64-w64-mingw32-gcc", "-shared", "-O2", "-s",
             str(src), "-o", str(out), "-luser32"],
            capture_output=True, text=True,
        )
        assert ret.returncode == 0, f"DLL compilation failed:\n{ret.stderr}"
        assert out.exists()


def test_mingw_compile_shellcode(mingw_available):
    source = (
        'void _start(void) {\n'
        '    volatile int x = 42;\n'
        '    (void)x;\n'
        '}\n'
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "test.c"
        obj = Path(tmpdir) / "test.o"
        out = Path(tmpdir) / "test.bin"
        src.write_text(source)
        # Compile to object
        ret = subprocess.run(
            ["x86_64-w64-mingw32-gcc", "-c", "-O2", "-fPIC", "-nostdlib",
             str(src), "-o", str(obj)],
            capture_output=True, text=True,
        )
        assert ret.returncode == 0, f"Shellcode compile failed:\n{ret.stderr}"
        # Extract .text
        ret = subprocess.run(
            ["x86_64-w64-mingw32-objcopy", "-O", "binary", "-j", ".text",
             str(obj), str(out)],
            capture_output=True, text=True,
        )
        assert ret.returncode == 0, f"objcopy failed:\n{ret.stderr}"
        assert out.exists()
        assert out.stat().st_size > 0


# ---------------------------------------------------------------------------
# verify_standalone
# ---------------------------------------------------------------------------

def test_verify_standalone_passes(mingw_available):
    import asyncio
    from malware_gen_framework.verifier import verify_standalone
    from malware_gen_framework.target_spec import TargetEnvironmentSpec

    source = (
        '#include <windows.h>\n'
        '#include <stdio.h>\n'
        '\n'
        'int main(int argc, char *argv[]) {\n'
        '    HANDLE hFile = CreateFileA("test.txt", GENERIC_WRITE, 0, NULL,\n'
        '                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n'
        '    if (hFile != INVALID_HANDLE_VALUE) {\n'
        '        const char *msg = "Hello";\n'
        '        DWORD written;\n'
        '        WriteFile(hFile, msg, 5, &written, NULL);\n'
        '        CloseHandle(hFile);\n'
        '    }\n'
        '    return 0;\n'
        '}\n'
    )
    spec = TargetEnvironmentSpec(
        os_platform="windows", os_version="windows-11",
        installed_compilers=["mingw-w64"], edrs=["defender"],
    )
    result = asyncio.run(verify_standalone(source, spec))
    assert result is not None


def test_verify_standalone_fails_bad_source(mingw_available):
    import asyncio
    from malware_gen_framework.verifier import verify_standalone
    from malware_gen_framework.target_spec import TargetEnvironmentSpec

    source = "this is not valid C code at all"
    spec = TargetEnvironmentSpec(
        os_platform="windows", os_version="windows-11",
        installed_compilers=["mingw-w64"], edrs=[],
    )
    result = asyncio.run(verify_standalone(source, spec))
    assert "error" in result.compilation_output.lower()
