// chunk: ad_collectors/ad_ous
// depends: ad/ldap_client, ad/json_builder
// provides: collect_ous
// headers: (none)
// libs: (none)

typedef struct {
    int count;
} ou_ctx_t;

static void _ou_entry_cb(LDAP *ld, LDAPMessage *entry, void *ctx) {
    ou_ctx_t *oc = (ou_ctx_t *)ctx;
    char name[256], dn[1024], guid[128];
    int flags = 0;

    ad_ldap_get_str(ld, entry, "name", name, sizeof(name));
    ad_ldap_get_str(ld, entry, "distinguishedName", dn, sizeof(dn));

    struct berval **guid_vals = ldap_get_values_lenA(ld, entry, "objectGUID");
    if (!guid_vals || !guid_vals[0]) return;
    unsigned char *g = (unsigned char *)guid_vals[0]->bv_val;
    wsprintfA(guid, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6],
              g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
    ldap_value_free_len(guid_vals);

    ad_ldap_get_int(ld, entry, "gPOptions", &flags);
    int blocks_inheritance = (flags & 1) ? 1 : 0;

    char upn[512];
    wsprintfA(upn, "%s@%s", name, g_domain_name);
    CharUpperA(upn);

    jb_obj_open(JB_OUS);

    jb_key_str(JB_OUS, "ObjectIdentifier", guid);

    jb_key_obj_open(JB_OUS, "Properties");
    jb_key_str(JB_OUS, "name", upn);
    jb_key_str(JB_OUS, "domain", g_domain_name);
    jb_key_str(JB_OUS, "domainsid", g_domain_sid[0] ? g_domain_sid : "");
    jb_key_str(JB_OUS, "distinguishedname", dn);
    jb_key_bool(JB_OUS, "blocksinheritance", blocks_inheritance);
    jb_key_obj_close(JB_OUS);

    jb_key_bool(JB_OUS, "IsDeleted", 0);
    jb_key_bool(JB_OUS, "IsACLProtected", 0);

    jb_arr_open(JB_OUS, "Aces");
    jb_arr_close(JB_OUS);
    jb_arr_open(JB_OUS, "ChildObjects");
    jb_arr_close(JB_OUS);
    jb_arr_open(JB_OUS, "Links");
    jb_arr_close(JB_OUS);

    jb_obj_close(JB_OUS);
    oc->count++;
}

static int collect_ous(void) {
    char *attrs[] = {
        "name", "distinguishedName", "objectGUID",
        "gPOptions", "gPLink",
        NULL
    };

    ou_ctx_t ctx = {0};
    ad_ldap_search(NULL, "(objectcategory=organizationalUnit)", attrs, _ou_entry_cb, &ctx);
    return ctx.count;
}
