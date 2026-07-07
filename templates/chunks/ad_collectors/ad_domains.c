// chunk: ad_collectors/ad_domains
// depends: ad/ldap_client, ad/sid_resolver, ad/json_builder
// provides: collect_domains
// headers: (none)
// libs: (none)

static int collect_domains(void) {
    char *attrs[] = {
        "distinguishedName", "objectSid", "ms-DS-MachineAccountQuota",
        "objectClass", "name", "msDS-Behavior-Version",
        NULL
    };

    LDAPMessage *res = NULL;
    ULONG rc = ldap_search_sA(g_ldap, g_domain_dn, LDAP_SCOPE_BASE,
                               "(objectClass=domain)", attrs, 0, &res);
    if (rc != LDAP_SUCCESS || !res) return 0;

    LDAPMessage *entry = ldap_first_entry(g_ldap, res);
    if (!entry) { ldap_msgfree(res); return 0; }

    char dn[1024], sid[128];
    ad_ldap_get_str(g_ldap, entry, "distinguishedName", dn, sizeof(dn));
    ad_ldap_get_sid(g_ldap, entry, "objectSid", sid, sizeof(sid));

    lstrcpynA(g_domain_sid, sid, sizeof(g_domain_sid));

    int maq = 10, func_level = 0;
    ad_ldap_get_int(g_ldap, entry, "ms-DS-MachineAccountQuota", &maq);
    ad_ldap_get_int(g_ldap, entry, "msDS-Behavior-Version", &func_level);

    static const char *func_names[] = {
        "2000 Mixed", "2003 Interim", "2003", "2008", "2008 R2",
        "2012", "2012 R2", "2016"
    };
    const char *func_str = (func_level >= 0 && func_level < 8) ?
                            func_names[func_level] : "Unknown";

    jb_obj_open(JB_DOMAINS);

    jb_key_str(JB_DOMAINS, "ObjectIdentifier", g_domain_sid);

    jb_key_obj_open(JB_DOMAINS, "Properties");
    jb_key_str(JB_DOMAINS, "name", g_domain_name);
    jb_key_str(JB_DOMAINS, "domain", g_domain_name);
    jb_key_str(JB_DOMAINS, "domainsid", g_domain_sid);
    jb_key_str(JB_DOMAINS, "distinguishedname", dn);
    jb_key_str(JB_DOMAINS, "functionallevel", func_str);
    jb_key_int(JB_DOMAINS, "machineaccountquota", maq);
    jb_key_bool(JB_DOMAINS, "collected", 1);
    jb_key_obj_close(JB_DOMAINS);

    jb_key_bool(JB_DOMAINS, "IsDeleted", 0);
    jb_key_bool(JB_DOMAINS, "IsACLProtected", 0);

    jb_arr_open(JB_DOMAINS, "Aces");
    jb_arr_close(JB_DOMAINS);
    jb_arr_open(JB_DOMAINS, "ChildObjects");
    jb_arr_close(JB_DOMAINS);
    jb_arr_open(JB_DOMAINS, "Links");
    jb_arr_close(JB_DOMAINS);
    jb_arr_open(JB_DOMAINS, "Trusts");
    jb_arr_close(JB_DOMAINS);

    jb_obj_close(JB_DOMAINS);

    ldap_msgfree(res);
    return 1;
}
