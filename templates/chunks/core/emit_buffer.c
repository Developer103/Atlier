// chunk: core/emit_buffer
// depends: (none)
// provides: emit, emitf, g_data, g_pos, g_cap, init_buffer, COLLECT_BUF
// headers: stdio.h, stdlib.h, string.h, stdarg.h, windows.h

#ifndef CHUNK_EMIT_BUFFER
#define CHUNK_EMIT_BUFFER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>

#define COLLECT_BUF (1024 * 1024)

static char *g_data = NULL;
static DWORD g_pos = 0;
static DWORD g_cap = 0;

static void init_buffer(void) {
    g_data = (char *)malloc(COLLECT_BUF);
    if (g_data) g_cap = COLLECT_BUF;
    g_pos = 0;
}

static void emit(const char *d, DWORD n) {
    if (!g_data) return;
    if (g_pos + n >= g_cap) {
        DWORD need = g_pos + n + (256 * 1024);
        char *re = (char *)realloc(g_data, need);
        if (!re) return;
        g_data = re;
        g_cap = need;
    }
    memcpy(g_data + g_pos, d, n);
    g_pos += n;
}

static void emitf(const char *fmt, ...) {
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0) emit(tmp, (DWORD)n);
}

#endif
