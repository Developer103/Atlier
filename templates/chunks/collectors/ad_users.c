// chunk: collectors/ad_users
// depends: core/emit_buffer, ad/ldap_client
// provides: collect_ad_users
// headers: (none)
// libs: (none)

#ifndef CHUNK_COLLECTOR_AD_USERS
#define CHUNK_COLLECTOR_AD_USERS

static void _emit_user_cb(LDAP *ld, LDAPMessage *entry, void *ctx) {
    int *count = (int *)ctx;
    char sam[256], dn[1024], sid[128], desc[512] = "";
    int uac = 0, admin_count = 0;

    if (ad_ldap_get_str(ld, entry, "sAMAccountName", sam, sizeof(sam)) < 0) return;
    ad_ldap_get_str(ld, entry, "distinguishedName", dn, sizeof(dn));
    ad_ldap_get_sid(ld, entry, "objectSid", sid, sizeof(sid));
    ad_ldap_get_int(ld, entry, "userAccountControl", &uac);
    ad_ldap_get_int(ld, entry, "adminCount", &admin_count);
    ad_ldap_get_str(ld, entry, "description", desc, sizeof(desc));

    int enabled = !(uac & 0x0002);
    int pwd_never_expires = (uac & 0x10000) ? 1 : 0;
    int dont_req_preauth = (uac & 0x400000) ? 1 : 0;

    char **spns = NULL;
    int spn_count = 0;
    ad_ldap_get_multi(ld, entry, "servicePrincipalName", &spns, &spn_count);

    emitf("  %s | SID=%s | %s | admin=%d | pwdNoExpire=%d | preauth=%d",
          sam, sid, enabled ? "ENABLED" : "DISABLED", admin_count,
          pwd_never_expires, dont_req_preauth ? 0 : 1);
    if (spn_count > 0) {
        emitf(" | SPNs:");
        for (int i = 0; i < spn_count && i < 5; i++)
            emitf(" %s", spns[i]);
    }
    if (desc[0]) emitf(" | %s", desc);
    emitf("\r\n");

    if (spns) ldap_value_freeA(spns);
    (*count)++;
}

static void collect_ad_users(void) {
    if (!g_ldap && ad_ldap_init() != 0) {
        emitf("=== AD USERS === (LDAP unavailable)\r\n");
        return;
    }
    emitf("=== AD USERS === Domain: %s  DC: %s\r\n", g_domain_name, g_dc_name);

    char *attrs[] = {
        "sAMAccountName", "distinguishedName", "objectSid",
        "userAccountControl", "adminCount", "description",
        "servicePrincipalName", NULL
    };
    int count = 0;
    ad_ldap_search(NULL, "(samaccounttype=805306368)", attrs, _emit_user_cb, &count);
    emitf("  Total: %d users\r\n", count);
}

#endif
