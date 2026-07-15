// chunk: evasion/stack_strings
// depends: (none)
// provides: ss_build
// risk: none
// note: Stack string builder — constructs strings char-by-char on stack at runtime.
//       Prevents string literals from appearing in .rdata section (defeats static analysis).
//       Use ss_build(buf, "literal") macro — expands to per-char assignments at compile time.
//       For dynamic use, call ss_copy() which does byte-at-a-time copy with volatile barrier.

#ifndef CHUNK_STACK_STRINGS
#define CHUNK_STACK_STRINGS

static void ss_copy(char *dst, const volatile char *src, int len) {
    volatile int i;
    for (i = 0; i < len; i++)
        dst[i] = src[i];
    dst[len] = '\0';
}

static void ss_zero(volatile char *buf, int len) {
    volatile int i;
    for (i = 0; i < len; i++)
        buf[i] = 0;
}

#endif
