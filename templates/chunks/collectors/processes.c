// chunk: collectors/processes
// depends: core/emit_buffer
// provides: collect_processes
// headers: tlhelp32.h

#ifndef CHUNK_PROCESSES
#define CHUNK_PROCESSES

#include <tlhelp32.h>

static void collect_processes(void) {
    emitf("=== RUNNING PROCESSES ===\r\n");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            emitf("  [%5lu] %s\r\n", pe.th32ProcessID, pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    emitf("\r\n");
}

#endif
