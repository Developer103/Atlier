// chunk: collectors/ad_domain
// depends: core/emit_buffer, ad/ldap_client
// provides: collect_ad_domain
// headers: (none)
// libs: (none)

#ifndef CHUNK_COLLECTOR_AD_DOMAIN
#define CHUNK_COLLECTOR_AD_DOMAIN

static void collect_ad_domain(void) {
    if (!g_ldap && ad_ldap_init() != 0) {
        emitf("=== AD DOMAIN === (LDAP unavailable — not domain-joined?)\r\n");
        return;
    }
    emitf("=== AD DOMAIN ===\r\n");
    emitf("  Domain: %s\r\n", g_domain_name);
    emitf("  DC: %s\r\n", g_dc_name);
    emitf("  Base DN: %s\r\n", g_domain_dn);

    char *attrs[] = {"objectSid", "ms-DS-MachineAccountQuota",
                     "minPwdLength", "lockoutThreshold",
                     "lockoutDuration", "maxPwdAge", NULL};
    LDAPMessage *res = NULL;
    ULONG rc = ldap_search_sA(g_ldap, g_domain_dn, LDAP_SCOPE_BASE,
                               "(objectClass=*)", attrs, 0, &res);
    if (rc == LDAP_SUCCESS && res) {
        LDAPMessage *e = ldap_first_entry(g_ldap, res);
        if (e) {
            char sid[128];
            if (ad_ldap_get_sid(g_ldap, e, "objectSid", sid, sizeof(sid)) == 0)
                emitf("  Domain SID: %s\r\n", sid);
            int maq = 0, minpwd = 0, lockout = 0;
            if (ad_ldap_get_int(g_ldap, e, "ms-DS-MachineAccountQuota", &maq) == 0)
                emitf("  MachineAccountQuota: %d\r\n", maq);
            if (ad_ldap_get_int(g_ldap, e, "minPwdLength", &minpwd) == 0)
                emitf("  MinPwdLength: %d\r\n", minpwd);
            if (ad_ldap_get_int(g_ldap, e, "lockoutThreshold", &lockout) == 0)
                emitf("  LockoutThreshold: %d\r\n", lockout);
        }
        ldap_msgfree(res);
    }
}

#endif
