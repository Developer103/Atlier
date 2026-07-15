' chunk: core/emit_buffer
' depends: (none)
' provides: emit, _buf
' format: vbscript

Dim _buf
_buf = ""

Sub emit(s)
    _buf = _buf & s
End Sub
