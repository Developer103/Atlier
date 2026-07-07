// chunk: collectors/drives
// depends: core/emit_buffer
// provides: collect_drives
// note: enumerate logical drives + type — KERNEL32 only, clean IAT

#ifndef CHUNK_DRIVES
#define CHUNK_DRIVES

static void collect_drives(void) {
    emitf("=== LOGICAL DRIVES ===\r\n");
    char buf[256] = {0};
    DWORD len = GetLogicalDriveStringsA(sizeof(buf), buf);
    if (len == 0) { emitf("(none)\r\n\r\n"); return; }

    char *p = buf;
    while (*p) {
        UINT dt = GetDriveTypeA(p);
        const char *type;
        switch (dt) {
            case DRIVE_REMOVABLE: type = "Removable"; break;
            case DRIVE_FIXED:     type = "Fixed";     break;
            case DRIVE_REMOTE:    type = "Network";   break;
            case DRIVE_CDROM:     type = "CD-ROM";    break;
            case DRIVE_RAMDISK:   type = "RAMDisk";   break;
            default:              type = "Unknown";   break;
        }

        ULARGE_INTEGER free_bytes, total_bytes;
        if (GetDiskFreeSpaceExA(p, NULL, &total_bytes, &free_bytes)) {
            emitf("  %s  %-10s  Total: %llu GB  Free: %llu GB\r\n",
                  p, type,
                  total_bytes.QuadPart / (1024ULL*1024*1024),
                  free_bytes.QuadPart / (1024ULL*1024*1024));
        } else {
            emitf("  %s  %-10s\r\n", p, type);
        }
        p += strlen(p) + 1;
    }
    emitf("\r\n");
}

#endif
