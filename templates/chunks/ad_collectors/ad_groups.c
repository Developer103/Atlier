// chunk: ad_collectors/ad_groups
// depends: ad/ldap_client, ad/sid_resolver, ad/json_builder
// provides: collect_groups
// headers: (none)
// libs: (none)

typedef struct {
    int count;
} group_ctx_t;

static void _group_entry_cb(LDAP *ld, LDAPMessage *entry, void *ctx) {
    group_ctx_t *gc = (group_ctx_t *)ctx;
    char sam[256], dn[1024], sid[128], desc[512] = "";
    int admin_count = 0, group_type = 0;

    if (ad_ldap_get_str(ld, entry, "sAMAccountName", sam, sizeof(sam)) < 0) return;
    ad_ldap_get_str(ld, entry, "distinguishedName", dn, sizeof(dn));
    if (ad_ldap_get_sid(ld, entry, "objectSid", sid, sizeof(sid)) < 0) return;
    ad_ldap_get_int(ld, entry, "adminCount", &admin_count);
    ad_ldap_get_int(ld, entry, "groupType", &group_type);
    ad_ldap_get_str(ld, entry, "description", desc, sizeof(desc));

    char upn[512];
    wsprintfA(upn, "%s@%s", sam, g_domain_name);
    CharUpperA(upn);

    char **members = NULL;
    int member_count = 0;
    ad_ldap_get_multi(ld, entry, "member", &members, &member_count);

    jb_obj_open(JB_GROUPS);

    jb_key_str(JB_GROUPS, "ObjectIdentifier", sid);

    jb_key_obj_open(JB_GROUPS, "Properties");
    jb_key_str(JB_GROUPS, "name", upn);
    jb_key_str(JB_GROUPS, "domain", g_domain_name);
    jb_key_str(JB_GROUPS, "domainsid", g_domain_sid[0] ? g_domain_sid : sid);
    jb_key_str(JB_GROUPS, "distinguishedname", dn);
    jb_key_bool(JB_GROUPS, "admincount", admin_count ? 1 : 0);
    if (desc[0]) jb_key_str(JB_GROUPS, "description", desc);
    jb_key_bool(JB_GROUPS, "highvalue",
        (lstrcmpiA(sam, "Domain Admins") == 0 ||
         lstrcmpiA(sam, "Enterprise Admins") == 0 ||
         lstrcmpiA(sam, "Administrators") == 0 ||
         lstrcmpiA(sam, "Schema Admins") == 0) ? 1 : 0);
    jb_key_obj_close(JB_GROUPS);

    jb_arr_open(JB_GROUPS, "Members");
    for (int i = 0; i < member_count; i++) {
        jb_obj_open(JB_GROUPS);
        jb_key_str(JB_GROUPS, "ObjectIdentifier", members[i]);
        jb_key_str(JB_GROUPS, "ObjectType", "Base");
        jb_obj_close(JB_GROUPS);
        g_jb[JB_GROUPS].count--;
    }
    jb_arr_close(JB_GROUPS);

    jb_key_bool(JB_GROUPS, "IsDeleted", 0);
    jb_key_bool(JB_GROUPS, "IsACLProtected", 0);

    jb_arr_open(JB_GROUPS, "Aces");
    jb_arr_close(JB_GROUPS);

    jb_obj_close(JB_GROUPS);

    if (members) ldap_value_freeA(members);
    gc->count++;
}

static int collect_groups(void) {
    char *attrs[] = {
        "sAMAccountName", "distinguishedName", "objectSid",
        "adminCount", "groupType", "description", "member",
        NULL
    };

    group_ctx_t ctx = {0};
    ad_ldap_search(NULL,
        "(|(samaccounttype=268435456)(samaccounttype=268435457)"
        "(samaccounttype=536870912)(samaccounttype=536870913))",
        attrs, _group_entry_cb, &ctx);
    return ctx.count;
}
