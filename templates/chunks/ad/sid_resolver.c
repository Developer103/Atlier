// chunk: ad/sid_resolver
// depends: ad/ldap_client
// provides: sid_cache_init, sid_resolve, sid_to_str, sid_domain_prefix
// headers: sddl.h
// libs: advapi32

#define SID_CACHE_BUCKETS 2048

typedef struct {
    char sid[128];
    char name[256];
    char type[24];
    int used;
} sid_entry_t;

static sid_entry_t g_sid_cache[SID_CACHE_BUCKETS];
static char g_domain_sid[128];

static unsigned int sid_hash(const char *s) {
    unsigned int h = 5381;
    for (; *s; s++) h = ((h << 5) + h) + (unsigned char)*s;
    return h % SID_CACHE_BUCKETS;
}

static void sid_cache_put(const char *sid, const char *name, const char *type) {
    unsigned int h = sid_hash(sid);
    for (int i = 0; i < 8; i++) {
        unsigned int idx = (h + i) % SID_CACHE_BUCKETS;
        if (!g_sid_cache[idx].used || lstrcmpA(g_sid_cache[idx].sid, sid) == 0) {
            lstrcpynA(g_sid_cache[idx].sid, sid, 128);
            lstrcpynA(g_sid_cache[idx].name, name, 256);
            lstrcpynA(g_sid_cache[idx].type, type, 24);
            g_sid_cache[idx].used = 1;
            return;
        }
    }
}

static int sid_cache_get(const char *sid, char *name, int name_sz, char *type, int type_sz) {
    unsigned int h = sid_hash(sid);
    for (int i = 0; i < 8; i++) {
        unsigned int idx = (h + i) % SID_CACHE_BUCKETS;
        if (!g_sid_cache[idx].used) return -1;
        if (lstrcmpA(g_sid_cache[idx].sid, sid) == 0) {
            if (name) lstrcpynA(name, g_sid_cache[idx].name, name_sz);
            if (type) lstrcpynA(type, g_sid_cache[idx].type, type_sz);
            return 0;
        }
    }
    return -1;
}

static void sid_cache_init(void) {
    ZeroMemory(g_sid_cache, sizeof(g_sid_cache));

    static const char *wellknown[][3] = {
        {"S-1-0-0",       "Nobody",                    "Base"},
        {"S-1-1-0",       "Everyone",                  "Base"},
        {"S-1-5-1",       "Dialup",                    "Base"},
        {"S-1-5-2",       "Network",                   "Base"},
        {"S-1-5-3",       "Batch",                     "Base"},
        {"S-1-5-4",       "Interactive",               "Base"},
        {"S-1-5-6",       "Service",                   "Base"},
        {"S-1-5-7",       "Anonymous",                 "Base"},
        {"S-1-5-9",       "Enterprise Domain Controllers", "Group"},
        {"S-1-5-10",      "Self",                      "Base"},
        {"S-1-5-11",      "Authenticated Users",       "Group"},
        {"S-1-5-18",      "Local System",              "User"},
        {"S-1-5-19",      "Local Service",             "User"},
        {"S-1-5-20",      "Network Service",           "User"},
        {"S-1-5-32-544",  "Administrators",            "Group"},
        {"S-1-5-32-545",  "Users",                     "Group"},
        {"S-1-5-32-546",  "Guests",                    "Group"},
        {"S-1-5-32-548",  "Account Operators",         "Group"},
        {"S-1-5-32-549",  "Server Operators",          "Group"},
        {"S-1-5-32-550",  "Print Operators",           "Group"},
        {"S-1-5-32-551",  "Backup Operators",          "Group"},
        {"S-1-5-32-552",  "Replicator",                "Group"},
        {"S-1-5-32-554",  "Pre-Windows 2000 Compatible Access", "Group"},
        {"S-1-5-32-555",  "Remote Desktop Users",      "Group"},
        {"S-1-5-32-556",  "Network Configuration Operators", "Group"},
        {"S-1-5-32-558",  "Performance Monitor Users", "Group"},
        {"S-1-5-32-559",  "Performance Log Users",     "Group"},
        {"S-1-5-32-568",  "IIS_IUSRS",                 "Group"},
        {"S-1-5-32-569",  "Cryptographic Operators",   "Group"},
        {"S-1-5-32-573",  "Event Log Readers",         "Group"},
        {"S-1-5-32-574",  "Certificate Service DCOM Access", "Group"},
        {"S-1-5-32-575",  "RDS Remote Access Servers", "Group"},
        {"S-1-5-32-576",  "RDS Endpoint Servers",      "Group"},
        {"S-1-5-32-577",  "RDS Management Servers",    "Group"},
        {"S-1-5-32-578",  "Hyper-V Administrators",    "Group"},
        {"S-1-5-32-579",  "Access Control Assistance Operators", "Group"},
        {"S-1-5-32-580",  "Remote Management Users",   "Group"},
        {NULL, NULL, NULL}
    };

    for (int i = 0; wellknown[i][0]; i++)
        sid_cache_put(wellknown[i][0], wellknown[i][1], wellknown[i][2]);
}

static int sid_to_str(PSID sid, char *out, int out_sz) {
    char *str = NULL;
    if (!ConvertSidToStringSidA(sid, &str)) return -1;
    lstrcpynA(out, str, out_sz);
    LocalFree(str);
    return 0;
}

static const char *sid_resolve(const char *sid_str, char *name_out, int name_sz) {
    char type[24];
    if (sid_cache_get(sid_str, name_out, name_sz, type, sizeof(type)) == 0)
        return name_out;

    PSID sid = NULL;
    if (!ConvertStringSidToSidA(sid_str, &sid)) return NULL;

    char name[256], domain[256];
    DWORD name_len = sizeof(name), dom_len = sizeof(domain);
    SID_NAME_USE use;
    if (LookupAccountSidA(NULL, sid, name, &name_len, domain, &dom_len, &use)) {
        if (domain[0]) {
            char full[512];
            wsprintfA(full, "%s\\%s", domain, name);
            lstrcpynA(name_out, full, name_sz);
        } else {
            lstrcpynA(name_out, name, name_sz);
        }
        const char *t = "Unknown";
        switch (use) {
            case SidTypeUser:           t = "User"; break;
            case SidTypeGroup:          t = "Group"; break;
            case SidTypeDomain:         t = "Domain"; break;
            case SidTypeAlias:          t = "Group"; break;
            case SidTypeWellKnownGroup: t = "Group"; break;
            case SidTypeComputer:       t = "Computer"; break;
            default: break;
        }
        sid_cache_put(sid_str, name_out, t);
        LocalFree(sid);
        return name_out;
    }

    LocalFree(sid);
    lstrcpynA(name_out, sid_str, name_sz);
    return name_out;
}

static const char *sid_domain_prefix(void) {
    return g_domain_sid;
}
