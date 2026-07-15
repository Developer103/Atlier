' chunk: evasion/deferred_exec
' depends: (none)
' provides: deferred_wait
' format: vbscript

Sub deferred_wait()
    Randomize
    Dim delay
    delay = 5000 + Int(Rnd * 25000)
    WScript.Sleep delay
End Sub
