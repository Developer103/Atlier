// chunk: process/ppid_spoof_sihost
// depends: (none)
// provides: spoof_ppid_create_process, ppid_spoof_auto
// headers: windows.h,tlhelp32.h
// note: Create child process with spoofed parent (sihost.exe) — Shell Infrastructure Host

#ifndef CHUNK_PPID_SPOOF_SIHOST
#define CHUNK_PPID_SPOOF_SIHOST

#define PPID_TARGET "sihost.exe"

#include "ppid_spoof.c"

#endif
