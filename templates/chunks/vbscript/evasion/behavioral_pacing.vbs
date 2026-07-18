' chunk: evasion/behavioral_pacing
' depends: (none)
' provides: pace_execution
' format: vbscript
' note: Random sleep wrapper for behavioral diversity

Sub pace_execution(minMs, maxMs)
    On Error Resume Next
    Randomize
    Dim delay
    delay = Int(Rnd * (maxMs - minMs + 1)) + minMs
    WScript.Sleep delay
End Sub
