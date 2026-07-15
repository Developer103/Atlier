// chunk: collectors/ad_groups
// depends: core/emit_buffer, ad/ldap_client
// provides: collect_ad_groups
// headers: (none)
// libs: (none)

#ifndef CHUNK_COLLECTOR_AD_GROUPS
#define CHUNK_COLLECTOR_AD_GROUPS

static void _emit_group_cb(LDAP *ld, LDAPMessage *entry, void *ctx) {
    int *count = (int *)ctx;
    char sam[256], sid[128], desc[512] = "";
    int admin_count = 0, group_type = 0;

    if (ad_ldap_get_str(ld, entry, "sAMAccountName", sam, sizeof(sam)) < 0) return;
    ad_ldap_get_sid(ld, entry, "objectSid", sid, sizeof(sid));
    ad_ldap_get_int(ld, entry, "adminCount", &admin_count);
    ad_ldap_get_int(ld, entry, "groupType", &group_type);
    ad_ldap_get_str(ld, entry, "description", desc, sizeof(desc));

    char **members = NULL;
    int member_count = 0;
    ad_ldap_get_multi(ld, entry, "member", &members, &member_count);

    const char *scope = (group_type & 0x00000004) ? "DomainLocal" :
                        (group_type & 0x00000002) ? "Global" :
                        (group_type & 0x00000008) ? "Universal" : "Unknown";

    emitf("  %s | SID=%s | %s | admin=%d | members=%d",
          sam, sid, scope, admin_count, member_count);
    if (desc[0]) emitf(" | %s", desc);
    emitf("\r\n");

    if (members) ldap_value_freeA(members);
    (*count)++;
}

static void collect_ad_groups(void) {
    if (!g_ldap && ad_ldap_init() != 0) {
        emitf("=== AD GROUPS === (LDAP unavailable)\r\n");
        return;
    }
    emitf("=== AD GROUPS ===\r\n");

    char *attrs[] = {
        "sAMAccountName", "objectSid", "adminCount",
        "groupType", "description", "member", NULL
    };
    int count = 0;
    ad_ldap_search(NULL, "(samaccounttype=268435456)", attrs, _emit_group_cb, &count);
    emitf("  Total: %d groups\r\n", count);
}

#endif
