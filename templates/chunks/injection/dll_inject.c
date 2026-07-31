// chunk: injection/dll_inject
// depends: (none)
// provides: inject_dll
// headers: windows.h
// note: Classic DLL injection via LoadLibrary

#ifndef CHUNK_INJECTION_DLL_INJECT
#define CHUNK_INJECTION_DLL_INJECT

static int inject_dll(DWORD target_pid, const char *dll_path) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) {
        return 0;
    }

    SIZE_T path_len = strlen(dll_path) + 1;
    PVOID remote_buf = VirtualAllocEx(hProcess, NULL, path_len,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) {
        CloseHandle(hProcess);
        return 0;
    }

    if (!WriteProcessMemory(hProcess, remote_buf, dll_path, path_len, NULL)) {
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoadLibrary,
                                        remote_buf, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    WaitForSingleObject(hThread, 10000);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 1;
}

static int inject_dll_by_name(const char *process_name, const char *dll_path) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);

    int result = 0;
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, process_name) == 0) {
                result = inject_dll(pe.th32ProcessID, dll_path);
                if (result) break;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return result;
}

#endif
