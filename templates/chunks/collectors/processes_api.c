// chunk: collectors/processes_api
// depends: core/emit_buffer
// provides: collect_processes
// headers: psapi.h
// libs: psapi

#ifndef CHUNK_PROCESSES_API
#define CHUNK_PROCESSES_API

#include <psapi.h>

static void collect_processes(void) {
    emitf("=== RUNNING PROCESSES ===\r\n");

    DWORD pids[2048];
    DWORD cb_needed = 0;
    if (!EnumProcesses(pids, sizeof(pids), &cb_needed))
        return;

    DWORD count = cb_needed / sizeof(DWORD);
    for (DWORD i = 0; i < count; i++) {
        if (pids[i] == 0) continue;
        HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                FALSE, pids[i]);
        if (hp) {
            char name[MAX_PATH] = {0};
            HMODULE hmod;
            DWORD needed;
            if (EnumProcessModules(hp, &hmod, sizeof(hmod), &needed)) {
                GetModuleBaseNameA(hp, hmod, name, sizeof(name));
            }
            emitf("  [%5lu] %s\r\n", pids[i], name[0] ? name : "<unknown>");
            CloseHandle(hp);
        } else {
            emitf("  [%5lu] <access denied>\r\n", pids[i]);
        }
    }
    emitf("\r\n");
}

#endif
