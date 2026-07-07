// chunk: ad_collectors/ad_computers
// depends: ad/ldap_client, ad/sid_resolver, ad/json_builder
// provides: collect_computers
// headers: (none)
// libs: (none)

typedef struct {
    int count;
} computer_ctx_t;

static void _computer_entry_cb(LDAP *ld, LDAPMessage *entry, void *ctx) {
    computer_ctx_t *cc = (computer_ctx_t *)ctx;
    char sam[256], dn[1024], sid[128], os[256] = "", dns[512] = "";
    int uac = 0, pgid = 515;

    if (ad_ldap_get_str(ld, entry, "sAMAccountName", sam, sizeof(sam)) < 0) return;
    ad_ldap_get_str(ld, entry, "distinguishedName", dn, sizeof(dn));
    if (ad_ldap_get_sid(ld, entry, "objectSid", sid, sizeof(sid)) < 0) return;
    ad_ldap_get_int(ld, entry, "userAccountControl", &uac);
    ad_ldap_get_int(ld, entry, "primaryGroupID", &pgid);
    ad_ldap_get_str(ld, entry, "operatingSystem", os, sizeof(os));
    ad_ldap_get_str(ld, entry, "dNSHostName", dns, sizeof(dns));

    int enabled = !(uac & 0x0002);
    int unconstrained = (uac & 0x80000) ? 1 : 0;
    int dc = (pgid == 516 || pgid == 521);

    long long lastlogon = ad_ldap_get_filetime(ld, entry, "lastLogonTimestamp");
    long long whencreated = ad_ldap_get_filetime(ld, entry, "whenCreated");
    long long pwdlastset = ad_ldap_get_filetime(ld, entry, "pwdLastSet");

    char upn[512];
    if (dns[0]) {
        lstrcpynA(upn, dns, sizeof(upn));
    } else {
        int len = lstrlenA(sam);
        if (len > 0 && sam[len - 1] == '$') sam[len - 1] = '\0';
        wsprintfA(upn, "%s.%s", sam, g_domain_name);
    }
    CharUpperA(upn);

    char pg_sid[128];
    _build_primary_group_sid(sid, pgid, pg_sid, sizeof(pg_sid));

    jb_obj_open(JB_COMPUTERS);

    jb_key_str(JB_COMPUTERS, "ObjectIdentifier", sid);

    jb_key_obj_open(JB_COMPUTERS, "Properties");
    jb_key_str(JB_COMPUTERS, "name", upn);
    jb_key_str(JB_COMPUTERS, "domain", g_domain_name);
    jb_key_str(JB_COMPUTERS, "domainsid", g_domain_sid[0] ? g_domain_sid : sid);
    jb_key_str(JB_COMPUTERS, "distinguishedname", dn);
    jb_key_bool(JB_COMPUTERS, "enabled", enabled);
    jb_key_bool(JB_COMPUTERS, "unconstraineddelegation", unconstrained);
    if (os[0]) jb_key_str(JB_COMPUTERS, "operatingsystem", os);
    jb_key_bool(JB_COMPUTERS, "isdc", dc);
    jb_key_int(JB_COMPUTERS, "lastlogon", lastlogon >= 0 ? lastlogon : 0);
    if (whencreated >= 0) jb_key_int(JB_COMPUTERS, "whencreated", whencreated);
    jb_key_int(JB_COMPUTERS, "pwdlastset", pwdlastset >= 0 ? pwdlastset : 0);
    jb_key_bool(JB_COMPUTERS, "haslaps", 0);
    jb_key_obj_close(JB_COMPUTERS);

    jb_key_str(JB_COMPUTERS, "PrimaryGroupSID", pg_sid);

    jb_key_bool(JB_COMPUTERS, "IsDeleted", 0);
    jb_key_bool(JB_COMPUTERS, "IsACLProtected", 0);

    jb_arr_open(JB_COMPUTERS, "Aces");
    jb_arr_close(JB_COMPUTERS);
    jb_arr_open(JB_COMPUTERS, "AllowedToDelegate");
    jb_arr_close(JB_COMPUTERS);
    jb_arr_open(JB_COMPUTERS, "AllowedToAct");
    jb_arr_close(JB_COMPUTERS);
    jb_arr_open(JB_COMPUTERS, "Sessions");
    jb_arr_close(JB_COMPUTERS);
    jb_arr_open(JB_COMPUTERS, "PrivilegedSessions");
    jb_arr_close(JB_COMPUTERS);
    jb_arr_open(JB_COMPUTERS, "RegistrySessions");
    jb_arr_close(JB_COMPUTERS);
    jb_arr_open(JB_COMPUTERS, "LocalAdmins");
    jb_arr_close(JB_COMPUTERS);
    jb_arr_open(JB_COMPUTERS, "RemoteDesktopUsers");
    jb_arr_close(JB_COMPUTERS);
    jb_arr_open(JB_COMPUTERS, "DcomUsers");
    jb_arr_close(JB_COMPUTERS);
    jb_arr_open(JB_COMPUTERS, "PSRemoteUsers");
    jb_arr_close(JB_COMPUTERS);

    jb_obj_close(JB_COMPUTERS);

    cc->count++;
}

static int collect_computers(void) {
    char *attrs[] = {
        "sAMAccountName", "distinguishedName", "objectSid",
        "userAccountControl", "primaryGroupID",
        "operatingSystem", "dNSHostName",
        "lastLogonTimestamp", "whenCreated", "pwdLastSet",
        NULL
    };

    computer_ctx_t ctx = {0};
    ad_ldap_search(NULL, "(samaccounttype=805306369)", attrs, _computer_entry_cb, &ctx);
    return ctx.count;
}
