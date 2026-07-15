// chunk: collectors/ad_gpos
// depends: core/emit_buffer, ad/ldap_client
// provides: collect_ad_gpos
// headers: (none)
// libs: (none)

#ifndef CHUNK_COLLECTOR_AD_GPOS
#define CHUNK_COLLECTOR_AD_GPOS

static void _emit_gpo_cb(LDAP *ld, LDAPMessage *entry, void *ctx) {
    int *count = (int *)ctx;
    char name[256], display[256] = "", path[1024] = "";
    int flags = 0;

    if (ad_ldap_get_str(ld, entry, "name", name, sizeof(name)) < 0) return;
    ad_ldap_get_str(ld, entry, "displayName", display, sizeof(display));
    ad_ldap_get_str(ld, entry, "gPCFileSysPath", path, sizeof(path));
    ad_ldap_get_int(ld, entry, "flags", &flags);

    const char *status = (flags == 0) ? "Enabled" :
                         (flags == 1) ? "UserDisabled" :
                         (flags == 2) ? "ComputerDisabled" :
                         (flags == 3) ? "AllDisabled" : "Unknown";

    emitf("  %s | %s | %s", display[0] ? display : name, status, path[0] ? path : "no-path");
    emitf("\r\n");
    (*count)++;
}

static void collect_ad_gpos(void) {
    if (!g_ldap && ad_ldap_init() != 0) {
        emitf("=== AD GPOS === (LDAP unavailable)\r\n");
        return;
    }
    emitf("=== AD GROUP POLICIES ===\r\n");

    char *attrs[] = {"name", "displayName", "gPCFileSysPath", "flags", NULL};
    int count = 0;
    ad_ldap_search(NULL, "(objectClass=groupPolicyContainer)", attrs, _emit_gpo_cb, &count);
    emitf("  Total: %d GPOs\r\n", count);
}

#endif
