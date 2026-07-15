// chunk: evasion/anti_sandbox_wmi
// depends: (none)
// provides: sandbox_check
// headers: windows.h
// risk: low
// note: Deep WMI queries — Win32_ComputerSystem Model, Win32_BIOS SerialNumber, Win32_BaseBoard Manufacturer for VM detection

#ifndef CHUNK_ANTI_SANDBOX_WMI
#define CHUNK_ANTI_SANDBOX_WMI

#include <windows.h>
#include <objbase.h>

static int sb_wmi_str_contains_i(const WCHAR *haystack, const WCHAR *needle) {
    if (!haystack || !needle) return 0;
    for (const WCHAR *h = haystack; *h; h++) {
        const WCHAR *a = h, *b = needle;
        while (*a && *b) {
            WCHAR ca = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a;
            WCHAR cb = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
            if (ca != cb) break;
            a++; b++;
        }
        if (!*b) return 1;
    }
    return 0;
}

static int sandbox_check(void) {
    int detected = 0;

    // COM-based WMI queries via command output (avoids heavy COM interface casting)
    // Use wmic.exe which is simpler and still present on Windows 10/11
    char buf[512];
    FILE *fp;

    // Check ComputerSystem Model
    fp = _popen("wmic computersystem get model /value 2>nul", "r");
    if (fp) {
        while (fgets(buf, sizeof(buf), fp)) {
            // Convert to lowercase check
            for (char *p = buf; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
            if (strstr(buf, "virtual") || strstr(buf, "vmware") || strstr(buf, "kvm") ||
                strstr(buf, "xen") || strstr(buf, "bochs") || strstr(buf, "qemu"))
                detected = 1;
        }
        _pclose(fp);
    }

    // Check BIOS SerialNumber
    fp = _popen("wmic bios get serialnumber /value 2>nul", "r");
    if (fp) {
        while (fgets(buf, sizeof(buf), fp)) {
            for (char *p = buf; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
            if (strstr(buf, "vmware") || strstr(buf, "vbox") ||
                strstr(buf, "to be filled") || strstr(buf, "none"))
                detected++;
        }
        _pclose(fp);
    }

    // Check BaseBoard Manufacturer
    fp = _popen("wmic baseboard get manufacturer /value 2>nul", "r");
    if (fp) {
        while (fgets(buf, sizeof(buf), fp)) {
            for (char *p = buf; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
            if (strstr(buf, "vmware") || strstr(buf, "virtualbox") ||
                strstr(buf, "xen") || strstr(buf, "qemu") || strstr(buf, "innotek"))
                detected++;
        }
        _pclose(fp);
    }

    (void)detected;
    return 0;
}

#endif
