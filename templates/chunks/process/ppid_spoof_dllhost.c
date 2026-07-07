// chunk: process/ppid_spoof_dllhost
// depends: (none)
// provides: spoof_ppid_create_process, ppid_spoof_auto
// headers: windows.h,tlhelp32.h
// note: Create child process with spoofed parent (dllhost.exe) — COM surrogate host

#ifndef CHUNK_PPID_SPOOF_DLLHOST
#define CHUNK_PPID_SPOOF_DLLHOST

#define PPID_TARGET "dllhost.exe"

#include "ppid_spoof.c"

#endif
