' chunk: evasion/sleep_jitter
' depends: (none)
' provides: jitter_sleep
' format: vbscript

Sub jitter_sleep(minMs, maxMs)
    Randomize
    Dim delay
    delay = minMs + Int(Rnd * (maxMs - minMs))
    WScript.Sleep delay
End Sub
