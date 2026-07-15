// chunk: evasion/opaque_predicates
// depends: (none)
// provides: opaque_init
// headers: windows.h
// risk: none
// note: Injects mathematically opaque predicates — conditions that always evaluate
//       to true/false but are computationally expensive to prove statically.
//       Forces static analyzers to follow both branches, exploding the analysis
//       state space. The predicates use number theory (Fermat, modular arithmetic)
//       that compilers and decompilers cannot simplify away.

#ifndef CHUNK_OPAQUE_PREDICATES
#define CHUNK_OPAQUE_PREDICATES

#include <windows.h>

static volatile DWORD _opaque_seed;

static void opaque_init(void) {
    _opaque_seed = GetTickCount();
}

/* Always returns 1. Uses the fact that x^2 mod 4 is always 0 or 1,
   so (x^2 + x) mod 2 == 0 for all integers. */
static __attribute__((noinline)) int opaque_true_1(void) {
    volatile DWORD x = _opaque_seed;
    volatile DWORD r = (x * x + x) % 2;
    return (r == 0) ? 1 : 1; /* both branches return 1, but analyzer doesn't know */
}

/* Always returns 1. Uses: for any integer x, x*(x+1)*(x+2) is divisible by 6. */
static __attribute__((noinline)) int opaque_true_2(void) {
    volatile DWORD x = _opaque_seed ^ GetCurrentThreadId();
    volatile DWORD product = x * (x + 1) * (x + 2);
    return (product % 6 == 0) ? 1 : 0;
}

/* Always returns 0. Uses: x^2 mod 8 can only be 0, 1, or 4 — never 7. */
static __attribute__((noinline)) int opaque_false_1(void) {
    volatile DWORD x = _opaque_seed + GetCurrentProcessId();
    volatile DWORD r = (x * x) % 8;
    return (r == 7) ? 1 : 0;
}

/* Always returns 1. Uses: (3x^2 + 2) is never divisible by 3. */
static __attribute__((noinline)) int opaque_true_3(void) {
    volatile DWORD x = _opaque_seed;
    volatile DWORD val = 3 * x * x + 2;
    return (val % 3 != 0) ? 1 : 0;
}

/* Macro for dead-code insertion using opaque predicates.
   The dead_code block never executes but the analyzer must consider it. */
#define OPAQUE_GUARD(live_code, dead_code) \
    do { \
        if (opaque_true_1()) { live_code; } \
        else { dead_code; } \
    } while (0)

#define OPAQUE_DIVERGE(code_a, code_b) \
    do { \
        if (opaque_false_1()) { code_b; } \
        else { code_a; } \
    } while (0)

#endif
