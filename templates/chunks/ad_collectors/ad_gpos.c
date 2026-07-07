// chunk: ad_collectors/ad_gpos
// depends: ad/ldap_client, ad/json_builder
// provides: collect_gpos
// headers: (none)
// libs: (none)

typedef struct {
    int count;
} gpo_ctx_t;

static void _gpo_entry_cb(LDAP *ld, LDAPMessage *entry, void *ctx) {
    gpo_ctx_t *gc = (gpo_ctx_t *)ctx;
    char name[256], dn[1024], display[256] = "", gpcpath[512] = "";

    ad_ldap_get_str(ld, entry, "name", name, sizeof(name));
    ad_ldap_get_str(ld, entry, "distinguishedName", dn, sizeof(dn));
    ad_ldap_get_str(ld, entry, "displayName", display, sizeof(display));
    ad_ldap_get_str(ld, entry, "gPCFileSysPath", gpcpath, sizeof(gpcpath));

    struct berval **guid_vals = ldap_get_values_lenA(ld, entry, "objectGUID");
    if (!guid_vals || !guid_vals[0]) return;
    char guid[128];
    unsigned char *g = (unsigned char *)guid_vals[0]->bv_val;
    wsprintfA(guid, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6],
              g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
    ldap_value_free_len(guid_vals);

    char upn[512];
    wsprintfA(upn, "%s@%s", display[0] ? display : name, g_domain_name);
    CharUpperA(upn);

    jb_obj_open(JB_GPOS);

    jb_key_str(JB_GPOS, "ObjectIdentifier", guid);

    jb_key_obj_open(JB_GPOS, "Properties");
    jb_key_str(JB_GPOS, "name", upn);
    jb_key_str(JB_GPOS, "domain", g_domain_name);
    jb_key_str(JB_GPOS, "domainsid", g_domain_sid[0] ? g_domain_sid : "");
    jb_key_str(JB_GPOS, "distinguishedname", dn);
    if (gpcpath[0]) jb_key_str(JB_GPOS, "gpcpath", gpcpath);
    jb_key_obj_close(JB_GPOS);

    jb_key_bool(JB_GPOS, "IsDeleted", 0);
    jb_key_bool(JB_GPOS, "IsACLProtected", 0);

    jb_arr_open(JB_GPOS, "Aces");
    jb_arr_close(JB_GPOS);

    jb_obj_close(JB_GPOS);
    gc->count++;
}

static int collect_gpos(void) {
    char *attrs[] = {
        "name", "distinguishedName", "displayName",
        "objectGUID", "gPCFileSysPath", "flags",
        NULL
    };

    gpo_ctx_t ctx = {0};
    ad_ldap_search(NULL,
        "(&(objectcategory=groupPolicyContainer)(flags=*)(name=*)(gpcfilesyspath=*))",
        attrs, _gpo_entry_cb, &ctx);
    return ctx.count;
}
