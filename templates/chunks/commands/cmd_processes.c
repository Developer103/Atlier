// chunk: commands/cmd_processes
// depends: (none)
// provides: cmd_processes
// headers: tlhelp32.h
// note: process list via Toolhelp32 API — zero child processes

#ifndef CHUNK_CMD_PROCESSES
#define CHUNK_CMD_PROCESSES

#include <tlhelp32.h>

static int cmd_processes(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    (void)args; (void)args_len;
    DWORD cap = *out_len;
    int pos = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        *out_len = 0;
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if ((DWORD)pos >= cap - 128) break;
            pos += snprintf(out + pos, cap - pos, "[%5lu] %s\r\n",
                            pe.th32ProcessID, pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    *out_len = (DWORD)pos;
    return 0;
}

#endif
