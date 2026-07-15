// chunk: collectors/ad_computers
// depends: core/emit_buffer, ad/ldap_client
// provides: collect_ad_computers
// headers: (none)
// libs: (none)

#ifndef CHUNK_COLLECTOR_AD_COMPUTERS
#define CHUNK_COLLECTOR_AD_COMPUTERS

static void _emit_computer_cb(LDAP *ld, LDAPMessage *entry, void *ctx) {
    int *count = (int *)ctx;
    char sam[256], sid[128], os[256] = "", dns[512] = "";
    int uac = 0;

    if (ad_ldap_get_str(ld, entry, "sAMAccountName", sam, sizeof(sam)) < 0) return;
    ad_ldap_get_sid(ld, entry, "objectSid", sid, sizeof(sid));
    ad_ldap_get_int(ld, entry, "userAccountControl", &uac);
    ad_ldap_get_str(ld, entry, "operatingSystem", os, sizeof(os));
    ad_ldap_get_str(ld, entry, "dNSHostName", dns, sizeof(dns));

    int enabled = !(uac & 0x0002);
    int unconstrained = (uac & 0x80000) ? 1 : 0;

    emitf("  %s | SID=%s | %s | %s | %s",
          sam, sid, enabled ? "ENABLED" : "DISABLED",
          os[0] ? os : "Unknown OS", dns[0] ? dns : "no-dns");
    if (unconstrained) emitf(" | UNCONSTRAINED_DELEGATION");
    emitf("\r\n");
    (*count)++;
}

static void collect_ad_computers(void) {
    if (!g_ldap && ad_ldap_init() != 0) {
        emitf("=== AD COMPUTERS === (LDAP unavailable)\r\n");
        return;
    }
    emitf("=== AD COMPUTERS ===\r\n");

    char *attrs[] = {
        "sAMAccountName", "objectSid", "userAccountControl",
        "operatingSystem", "dNSHostName", NULL
    };
    int count = 0;
    ad_ldap_search(NULL, "(samaccounttype=805306369)", attrs, _emit_computer_cb, &count);
    emitf("  Total: %d computers\r\n", count);
}

#endif
