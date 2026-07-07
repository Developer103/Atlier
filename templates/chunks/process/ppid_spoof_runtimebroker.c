// chunk: process/ppid_spoof_runtimebroker
// depends: (none)
// provides: spoof_ppid_create_process, ppid_spoof_auto
// headers: windows.h,tlhelp32.h
// note: Create child process with spoofed parent (RuntimeBroker.exe) — UWP process broker

#ifndef CHUNK_PPID_SPOOF_RUNTIMEBROKER
#define CHUNK_PPID_SPOOF_RUNTIMEBROKER

#define PPID_TARGET "RuntimeBroker.exe"

#include "ppid_spoof.c"

#endif
