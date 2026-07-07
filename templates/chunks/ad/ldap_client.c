// chunk: ad/ldap_client
// depends: (none)
// provides: ad_ldap_init, ad_ldap_close, ad_ldap_search, ad_ldap_get_str, ad_ldap_get_sid, ad_ldap_get_int, ad_ldap_get_multi, ad_ldap_get_filetime
// headers: winldap.h, winber.h, dsgetdc.h, lm.h, sddl.h
// libs: wldap32, netapi32, advapi32

#ifndef LDAP_SERVER_SD_FLAGS_OID
#define LDAP_SERVER_SD_FLAGS_OID "1.2.840.113556.1.4.801"
#endif

#ifndef SEC_WINNT_AUTH_IDENTITY_ANSI
#define SEC_WINNT_AUTH_IDENTITY_ANSI 0x1
typedef struct {
    unsigned char *User;
    unsigned long UserLength;
    unsigned char *Domain;
    unsigned long DomainLength;
    unsigned char *Password;
    unsigned long PasswordLength;
    unsigned long Flags;
} SEC_WINNT_AUTH_IDENTITY_A;
#endif

static LDAP *g_ldap = NULL;
static char g_domain_dn[512];
static char g_domain_name[256];
static char g_dc_name[256];

typedef void (*ldap_entry_cb)(LDAP *ld, LDAPMessage *entry, void *ctx);

static int ad_ldap_init(void) {
    PDOMAIN_CONTROLLER_INFOA dci = NULL;
    DWORD rc = DsGetDcNameA(NULL, NULL, NULL, NULL,
                            DS_RETURN_DNS_NAME | DS_DIRECTORY_SERVICE_REQUIRED, &dci);
    if (rc != ERROR_SUCCESS || !dci) return -1;

    lstrcpynA(g_dc_name, dci->DomainControllerName + 2, sizeof(g_dc_name));
    lstrcpynA(g_domain_name, dci->DomainName, sizeof(g_domain_name));
    NetApiBufferFree(dci);

    g_ldap = ldap_initA(g_dc_name, LDAP_PORT);
    if (!g_ldap) return -2;

    ULONG ver = LDAP_VERSION3;
    ldap_set_option(g_ldap, LDAP_OPT_PROTOCOL_VERSION, &ver);
    ULONG ref = 0;
    ldap_set_option(g_ldap, LDAP_OPT_REFERRALS, &ref);

    rc = ldap_bind_sA(g_ldap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) {
#ifdef LDAP_USER
        SEC_WINNT_AUTH_IDENTITY_A cred;
        ZeroMemory(&cred, sizeof(cred));
        cred.User = (unsigned char *)LDAP_USER;
        cred.UserLength = lstrlenA(LDAP_USER);
        cred.Domain = (unsigned char *)LDAP_DOMAIN;
        cred.DomainLength = lstrlenA(LDAP_DOMAIN);
        cred.Password = (unsigned char *)LDAP_PASS;
        cred.PasswordLength = lstrlenA(LDAP_PASS);
        cred.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
        rc = ldap_bind_sA(g_ldap, NULL, (char *)&cred, LDAP_AUTH_NEGOTIATE);
        if (rc != LDAP_SUCCESS) {
            char bind_dn[512];
            wsprintfA(bind_dn, "%s\\%s", LDAP_DOMAIN, LDAP_USER);
            rc = ldap_simple_bind_sA(g_ldap, bind_dn, LDAP_PASS);
            if (rc != LDAP_SUCCESS) {
                ldap_unbind(g_ldap);
                g_ldap = NULL;
                return -3;
            }
        }
#else
        ldap_unbind(g_ldap);
        g_ldap = NULL;
        return -3;
#endif
    }

    LDAPMessage *res = NULL;
    char *attrs[] = {"defaultNamingContext", NULL};
    rc = ldap_search_sA(g_ldap, "", LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res);
    if (rc == LDAP_SUCCESS && res) {
        LDAPMessage *e = ldap_first_entry(g_ldap, res);
        if (e) {
            char **vals = ldap_get_valuesA(g_ldap, e, "defaultNamingContext");
            if (vals && vals[0]) {
                lstrcpynA(g_domain_dn, vals[0], sizeof(g_domain_dn));
                ldap_value_freeA(vals);
            }
        }
        ldap_msgfree(res);
    }

    return 0;
}

static void ad_ldap_close(void) {
    if (g_ldap) {
        ldap_unbind(g_ldap);
        g_ldap = NULL;
    }
}

static int ad_ldap_search(const char *base_dn, const char *filter,
                          char **attrs, ldap_entry_cb callback, void *ctx) {
    if (!g_ldap) return -1;
    const char *base = base_dn ? base_dn : g_domain_dn;
    int total = 0;

    struct berval *cookie = NULL;
    do {
        LDAPControlA *page_ctrl = NULL;
        ldap_create_page_controlA(g_ldap, 500, cookie, FALSE, &page_ctrl);

        LDAPControlA *ctrls[2] = {page_ctrl, NULL};
        LDAPMessage *res = NULL;

        ULONG rc = ldap_search_ext_sA(g_ldap, (char *)base, LDAP_SCOPE_SUBTREE,
                                       (char *)filter, attrs, 0, ctrls, NULL,
                                       NULL, 0, &res);
        if (page_ctrl) ldap_control_freeA(page_ctrl);

        if (rc != LDAP_SUCCESS) {
            if (res) ldap_msgfree(res);
            break;
        }

        LDAPMessage *entry = ldap_first_entry(g_ldap, res);
        while (entry) {
            callback(g_ldap, entry, ctx);
            total++;
            entry = ldap_next_entry(g_ldap, entry);
        }

        LDAPControlA **ret_ctrls = NULL;
        ldap_parse_resultA(g_ldap, res, NULL, NULL, NULL, NULL, &ret_ctrls, FALSE);

        if (cookie) { ber_bvfree(cookie); cookie = NULL; }

        if (ret_ctrls) {
            ldap_parse_page_controlA(g_ldap, ret_ctrls, NULL, &cookie);
            ldap_controls_freeA(ret_ctrls);
        }

        ldap_msgfree(res);

        Sleep(100 + (GetTickCount() % 200));
    } while (cookie && cookie->bv_len > 0);

    if (cookie) ber_bvfree(cookie);
    return total;
}

static int ad_ldap_get_str(LDAP *ld, LDAPMessage *e, const char *attr,
                           char *out, int out_sz) {
    char **vals = ldap_get_valuesA(ld, e, (char *)attr);
    if (!vals || !vals[0]) return -1;
    lstrcpynA(out, vals[0], out_sz);
    ldap_value_freeA(vals);
    return 0;
}

static int ad_ldap_get_sid(LDAP *ld, LDAPMessage *e, const char *attr,
                           char *sid_str, int sid_sz) {
    struct berval **bvals = ldap_get_values_lenA(ld, e, (char *)attr);
    if (!bvals || !bvals[0]) return -1;

    PSID sid = (PSID)bvals[0]->bv_val;
    char *str = NULL;
    if (ConvertSidToStringSidA(sid, &str)) {
        lstrcpynA(sid_str, str, sid_sz);
        LocalFree(str);
    } else {
        ldap_value_free_len(bvals);
        return -1;
    }
    ldap_value_free_len(bvals);
    return 0;
}

static int ad_ldap_get_int(LDAP *ld, LDAPMessage *e, const char *attr, int *out) {
    char **vals = ldap_get_valuesA(ld, e, (char *)attr);
    if (!vals || !vals[0]) return -1;
    *out = atoi(vals[0]);
    ldap_value_freeA(vals);
    return 0;
}

static int ad_ldap_get_multi(LDAP *ld, LDAPMessage *e, const char *attr,
                             char ***out, int *count) {
    char **vals = ldap_get_valuesA(ld, e, (char *)attr);
    if (!vals) { *count = 0; *out = NULL; return -1; }
    *count = (int)ldap_count_valuesA(vals);
    *out = vals;
    return 0;
}

static long long ad_ldap_get_filetime(LDAP *ld, LDAPMessage *e, const char *attr) {
    char buf[64];
    if (ad_ldap_get_str(ld, e, attr, buf, sizeof(buf)) < 0) return -1;
    long long val = 0;
    for (int i = 0; buf[i] >= '0' && buf[i] <= '9'; i++)
        val = val * 10 + (buf[i] - '0');
    if (val == 0 || val == 0x7FFFFFFFFFFFFFFF) return -1;
    return (val / 10000000LL) - 11644473600LL;
}
