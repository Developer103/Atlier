// chunk: ad_collectors/ad_users
// depends: ad/ldap_client, ad/sid_resolver, ad/json_builder
// provides: collect_users
// headers: (none)
// libs: (none)

typedef struct {
    int count;
} user_ctx_t;

static void _build_primary_group_sid(const char *user_sid, int pgid, char *out, int out_sz) {
    lstrcpynA(out, user_sid, out_sz);
    char *last_dash = NULL;
    for (char *p = out; *p; p++) {
        if (*p == '-') last_dash = p;
    }
    if (last_dash) wsprintfA(last_dash + 1, "%d", pgid);
}

static void _user_entry_cb(LDAP *ld, LDAPMessage *entry, void *ctx) {
    user_ctx_t *uc = (user_ctx_t *)ctx;
    char sam[256], dn[1024], sid[128], desc[512] = "";
    int uac = 0, pgid = 513, admin_count = 0;

    if (ad_ldap_get_str(ld, entry, "sAMAccountName", sam, sizeof(sam)) < 0) return;
    ad_ldap_get_str(ld, entry, "distinguishedName", dn, sizeof(dn));
    if (ad_ldap_get_sid(ld, entry, "objectSid", sid, sizeof(sid)) < 0) return;
    ad_ldap_get_int(ld, entry, "userAccountControl", &uac);
    ad_ldap_get_int(ld, entry, "primaryGroupID", &pgid);
    ad_ldap_get_int(ld, entry, "adminCount", &admin_count);
    ad_ldap_get_str(ld, entry, "description", desc, sizeof(desc));

    int enabled = !(uac & 0x0002);
    int pwd_never_expires = (uac & 0x10000) ? 1 : 0;
    int pwd_not_reqd = (uac & 0x0020) ? 1 : 0;
    int unconstrained = (uac & 0x80000) ? 1 : 0;
    int sensitive = (uac & 0x100000) ? 1 : 0;
    int dont_req_preauth = (uac & 0x400000) ? 1 : 0;

    long long lastlogon = ad_ldap_get_filetime(ld, entry, "lastLogonTimestamp");
    long long pwdlastset = ad_ldap_get_filetime(ld, entry, "pwdLastSet");
    long long whencreated = ad_ldap_get_filetime(ld, entry, "whenCreated");

    char display[256] = "", email[256] = "", title_str[256] = "";
    ad_ldap_get_str(ld, entry, "displayName", display, sizeof(display));
    ad_ldap_get_str(ld, entry, "mail", email, sizeof(email));
    ad_ldap_get_str(ld, entry, "title", title_str, sizeof(title_str));

    char **spns = NULL;
    int spn_count = 0;
    ad_ldap_get_multi(ld, entry, "servicePrincipalName", &spns, &spn_count);

    char upn[512];
    wsprintfA(upn, "%s@%s", sam, g_domain_name);
    CharUpperA(upn);

    char pg_sid[128];
    _build_primary_group_sid(sid, pgid, pg_sid, sizeof(pg_sid));

    jb_obj_open(JB_USERS);

    jb_key_str(JB_USERS, "ObjectIdentifier", sid);

    jb_key_obj_open(JB_USERS, "Properties");
    jb_key_str(JB_USERS, "name", upn);
    jb_key_str(JB_USERS, "domain", g_domain_name);
    jb_key_str(JB_USERS, "domainsid", g_domain_sid[0] ? g_domain_sid : sid);
    jb_key_str(JB_USERS, "distinguishedname", dn);
    jb_key_bool(JB_USERS, "enabled", enabled);
    jb_key_int(JB_USERS, "lastlogon", lastlogon >= 0 ? lastlogon : 0);
    jb_key_int(JB_USERS, "pwdlastset", pwdlastset >= 0 ? pwdlastset : 0);
    if (whencreated >= 0) jb_key_int(JB_USERS, "whencreated", whencreated);
    jb_key_bool(JB_USERS, "pwdneverexpires", pwd_never_expires);
    jb_key_bool(JB_USERS, "passwordnotreqd", pwd_not_reqd);
    jb_key_bool(JB_USERS, "unconstraineddelegation", unconstrained);
    jb_key_bool(JB_USERS, "sensitive", sensitive);
    jb_key_bool(JB_USERS, "dontreqpreauth", dont_req_preauth);
    jb_key_bool(JB_USERS, "admincount", admin_count ? 1 : 0);
    jb_key_bool(JB_USERS, "hasspn", spn_count > 0 ? 1 : 0);
    if (spn_count > 0) {
        jb_key_arr_str(JB_USERS, "serviceprincipalnames", (const char **)spns, spn_count);
    } else {
        jb_arr_open(JB_USERS, "serviceprincipalnames");
        jb_arr_close(JB_USERS);
    }
    jb_arr_open(JB_USERS, "sidhistory");
    jb_arr_close(JB_USERS);
    if (display[0]) jb_key_str(JB_USERS, "displayname", display);
    if (email[0]) jb_key_str(JB_USERS, "email", email);
    if (title_str[0]) jb_key_str(JB_USERS, "title", title_str);
    if (desc[0]) jb_key_str(JB_USERS, "description", desc);
    jb_key_obj_close(JB_USERS);

    jb_key_str(JB_USERS, "PrimaryGroupSID", pg_sid);
    jb_key_bool(JB_USERS, "IsDeleted", 0);
    jb_key_bool(JB_USERS, "IsACLProtected", 0);

    jb_arr_open(JB_USERS, "Aces");
    jb_arr_close(JB_USERS);
    jb_arr_open(JB_USERS, "SPNTargets");
    jb_arr_close(JB_USERS);
    jb_arr_open(JB_USERS, "HasSIDHistory");
    jb_arr_close(JB_USERS);
    jb_arr_open(JB_USERS, "AllowedToDelegate");
    jb_arr_close(JB_USERS);
    jb_arr_open(JB_USERS, "AllowedToAct");
    jb_arr_close(JB_USERS);

    jb_obj_close(JB_USERS);

    if (spns) ldap_value_freeA(spns);
    uc->count++;
}

static int collect_users(void) {
    char *attrs[] = {
        "sAMAccountName", "distinguishedName", "objectSid",
        "userAccountControl", "primaryGroupID", "adminCount",
        "lastLogonTimestamp", "pwdLastSet", "whenCreated",
        "displayName", "mail", "title", "description",
        "servicePrincipalName",
        NULL
    };

    user_ctx_t ctx = {0};
    ad_ldap_search(NULL, "(samaccounttype=805306368)", attrs, _user_entry_cb, &ctx);
    return ctx.count;
}
