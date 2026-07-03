// chunk: core/run_cmd
// depends: core/emit_buffer
// provides: run_cmd

#ifndef CHUNK_RUN_CMD
#define CHUNK_RUN_CMD

static void run_cmd(const char *cmd, char *out, DWORD out_sz, DWORD *out_len) {
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    HANDLE hRead, hWrite;
    *out_len = 0;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    char buf[512];
    strncpy(buf, cmd, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    if (!CreateProcessA(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite); return;
    }
    CloseHandle(hWrite);
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD total = 0, rd = 0;
    while (total < out_sz - 1 && ReadFile(hRead, out + total, out_sz - total - 1, &rd, NULL) && rd > 0)
        total += rd;
    out[total] = '\0';
    *out_len = total;
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

#endif
