# SharpHound Technical Analysis

Comprehensive technical reference for reimplementing SharpHound's core functionality in C (MinGW cross-compiled for Windows). Covers architecture, collection methods, API calls, data formats, and detection surface.

---

## 1. What SharpHound Is

SharpHound is the official data collector for BloodHound, the Active Directory attack path mapping tool created by SpecterOps. It enumerates AD objects, permissions, sessions, and trust relationships, then exports them as structured JSON for BloodHound's graph database.

**Role in the AD attack chain**: SharpHound is a reconnaissance tool. It maps the entire AD environment to find paths from any compromised user to Domain Admin (or other high-value targets). The output feeds BloodHound's graph engine which computes shortest attack paths across relationships like group membership, ACL abuse, session hijacking, and delegation.

**Why it matters for our framework**: SharpHound replaces our infostealer concept. Instead of scraping credentials and files, it maps the AD infrastructure itself — the higher-value target for lateral movement and privilege escalation. A C reimplementation avoids the .NET/C# detection surface that Defender specifically targets (`HackTool:MSIL/SharpHound!MSR`, `Behavior:Win32/SharpHound.AM`).

---

## 2. Collection Methods

SharpHound supports 26 distinct collection methods, each targeting different data sources and using different protocols.

### 2.1 Collection Method Reference

| Method | Protocol | Target | What It Collects | Noise Level |
|--------|----------|--------|------------------|-------------|
| **Default** | LDAP + SMB | DC + computers | Groups, trusts, ACLs, OUs, GPO links, properties, local groups, sessions | Medium |
| **All** | LDAP + SMB + Registry | DC + all computers | Everything below combined | Very High |
| **DCOnly** | LDAP only | Domain Controller | Groups, trusts, ACLs, OUs, GPO links, properties, GPO-correlated local groups | Low |
| **ComputerOnly** | SMB + Registry | Domain computers | Sessions, local groups, user rights, CA/DC registry | High |
| **Group** | LDAP | DC | Security group memberships | Low |
| **ACL** | LDAP | DC | Abusable permissions (DACLs) on AD objects | Low |
| **ObjectProps** | LDAP | DC | Object properties (LastLogon, PwdLastSet, SPN, etc.) | Low |
| **Trusts** | LDAP | DC | Domain trust relationships | Very Low |
| **Container** | LDAP | DC | OU tree structure, GPO links | Low |
| **GPOLocalGroup** | LDAP + SMB (SYSVOL) | DC | GPO-enforced local group memberships (no computer contact) | Low |
| **Session** | SMB (srvsvc) | All computers | Active user sessions via NetSessionEnum | High |
| **LoggedOn** | SMB (wkssvc) | All computers | Interactive/service/batch logons via NetWkstaUserEnum | High (admin required) |
| **LocalGroup** | SMB (samr) | All computers | All local group members (Admins + RDP + DCOM + PSRemote) | High |
| **LocalAdmin** | SMB (samr) | All computers | Local Administrators group members | High |
| **RDP** | SMB (samr) | All computers | Remote Desktop Users group members | High |
| **DCOM** | SMB (samr) | All computers | Distributed COM Users group members | High |
| **PSRemote** | SMB (samr) | All computers | Remote Management Users group members | High |
| **SPNTargets** | LDAP | DC | Service Principal Name targets (service relationships) | Low |
| **UserRights** | SMB (lsarpc) | All computers | User Rights Assignment (SeRemoteInteractiveLogon, etc.) | High (admin required) |
| **CertServices** | LDAP | DC | ADCS objects (CAs, templates, enrollment rights) | Low |
| **CARegistry** | SMB (winreg) | CA servers | ADCS properties from CA server registry | Medium |
| **DCRegistry** | SMB (winreg) | DCs | Registry properties from Domain Controllers | Medium |
| **WebClientService** | SMB | All computers | WebClient service status (NTLM relay paths) | Medium |
| **NTLMRegistry** | SMB (winreg) | All computers | NTLM-related registry values | Medium |
| **SmbInfo** | SMB | All computers | SMB configuration details | Medium |
| **LdapServices** | LDAP | DC | LDAP service config and auth behavior | Low |

### 2.2 What "Default" Includes

The Default collection method combines: Group + ACL + ObjectProps + Trusts + Container + GPOLocalGroup + LocalGroup + Session. This is what most operators run.

### 2.3 Stealth Mode

When `--Stealth` is enabled:
- **Single-threaded** execution (vs. multi-threaded default)
- **Session collection**: Limited to DCs + identified file servers (derived from `homeDirectory`, `scriptPath`, `profilePath` attributes) — captures ~50-60% of sessions
- **Local admin collection**: Uses GPO analysis (SYSVOL parsing) instead of touching individual computers
- **DCOnly preferred**: Avoids all computer-to-computer SMB traffic

---

## 3. Data Collected — Full Inventory

### 3.1 Users

**LDAP filter**: `(samaccounttype=805306368)`

**Properties collected**:
- `sAMAccountName`, `distinguishedName`, `objectSID`, `objectGUID`
- `userAccountControl` (enabled/disabled, password policies, delegation flags)
- `pwdLastSet`, `lastLogon`, `lastLogonTimestamp`, `whenCreated`
- `servicePrincipalName` (SPN — Kerberoastable if set)
- `adminCount` (protected by AdminSDHolder)
- `email`, `title`, `description`, `displayName`
- `homeDirectory`, `scriptPath`, `profilePath` (stealth target selection)
- `sidHistory` (cross-domain migration artifacts)
- `allowedToDelegateTo` (constrained delegation targets)
- `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
- `userPassword`, `unixUserPassword`, `msSFU30Password`, `unicodePassword` (legacy cleartext)
- `primaryGroupID`
- `nTSecurityDescriptor` (DACL — who has what rights over this user)

### 3.2 Groups

**LDAP filter**: `(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913)(primarygroupid=*))`

**samAccountType values**:
- `268435456` = SAM_GROUP_OBJECT (security group, global scope)
- `268435457` = SAM_NON_SECURITY_GROUP_OBJECT (distribution group, global)
- `536870912` = SAM_ALIAS_OBJECT (security group, local/domain local scope)
- `536870913` = SAM_NON_SECURITY_ALIAS_OBJECT (distribution group, local)

**Properties collected**:
- `member` (direct members — resolved recursively for nested groups)
- `primaryGroupID` (users whose primary group is this group — not in `member` attribute)
- `groupType` (security vs. distribution, scope)
- `adminCount`, `description`, `whenCreated`
- `nTSecurityDescriptor`

**Nested membership resolution**: SharpHound recursively expands all nested group memberships. If Group A contains Group B which contains User C, User C has an effective MemberOf edge to both groups.

### 3.3 Computers

**LDAP filter**: `(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))`

This selects: computer accounts (SAM type 805306369) that are NOT disabled (UAC bit 0x2 not set).

**Properties collected via LDAP**:
- `sAMAccountName`, `dNSHostName`, `distinguishedName`, `objectSID`
- `operatingSystem`, `operatingSystemVersion`
- `passwordLastSet`, `lastLogonTimestamp`
- `userAccountControl` (trusted for delegation, unconstrained delegation)
- `servicePrincipalName`
- `allowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity`
- `msDS-HostServiceAccount` (gMSA)
- `nTSecurityDescriptor`

**Properties collected via SMB/RPC** (per-computer enumeration):
- **Local Administrators** (RID 544) — via SAMR
- **Remote Desktop Users** (RID 555) — via SAMR
- **Distributed COM Users** (RID 562) — via SAMR
- **Remote Management Users** (RID 580) — via SAMR
- **Active sessions** — via NetSessionEnum (srvsvc pipe)
- **Logged-on users** — via NetWkstaUserEnum (wkssvc pipe, admin only)
- **Registry sessions** — via Remote Registry (winreg pipe)

### 3.4 Domains

**LDAP filter**: `(objectclass=domain)`

**Properties collected**:
- `distinguishedName`, `objectSID`, `name`
- `msDS-Behavior-Version` (domain functional level)
- `machineAccountQuota` (how many computers a user can join)
- `expirePasswordsOnSmartCardOnlyAccounts`
- Password policy attributes: `minPwdLength`, `pwdProperties`, `minPwdAge`, `maxPwdAge`, `pwdHistoryLength`, `lockoutDuration`, `lockoutThreshold`, `lockOutObservationWindow`
- `dsHeuristics` (domain security settings)
- `nTSecurityDescriptor`

**Trust enumeration filter**: `(objectclass=trusteddomain)`

**Trust properties**:
- `trustAttributes` (forest transitive, SID filtering, etc.)
- `securityIdentifier` (trusted domain SID)
- `trustDirection` (inbound=1, outbound=2, bidirectional=3)
- `trustType` (downlevel=1, uplevel=2, MIT=3, DCE=4)
- `canonicalName`

### 3.5 OUs and Containers

**LDAP filter**: `(|(objectcategory=organizationalUnit)(objectClass=domain)(&(objectcategory=groupPolicyContainer)(flags=*)(name=*)(gpcfilesyspath=*)))`

**Properties collected**:
- `displayName`, `name`, `objectGUID`
- `gpLink` (linked GPOs — ordered, enforced/not)
- `groupPolicyOptions`
- `objectClass`

**GPLink format**: `[LDAP://cn={GUID},cn=policies,cn=system,DC=domain,DC=com;0]` where the trailing digit is 0=not enforced, 2=enforced.

### 3.6 GPOs

**LDAP filter**: `(&(objectcategory=groupPolicyContainer)(flags=*)(name=*)(gpcfilesyspath=*))`

**Properties collected**:
- `displayName`, `name`, `flags`
- `gPCFileSysPath` (SYSVOL path — e.g., `\\domain.com\sysvol\domain.com\Policies\{GUID}`)

**GPOLocalGroup processing**: SharpHound reads two files from SYSVOL:
1. `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` — Restricted Groups settings
2. `Machine\Preferences\Groups\Groups.xml` — Group Policy Preferences

Restricted Groups take precedence over GPP settings and override them.

### 3.7 ACLs (Access Control Entries)

**LDAP filter**: `(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectClass=domain)(&(objectcategory=groupPolicyContainer)(flags=*))(objectcategory=organizationalUnit))`

**Attribute**: `nTSecurityDescriptor` with `SecurityDescriptorFlagControl` requesting DACL + Owner (flags 0x05 or 0x04).

**Abusable permissions detected**:

| Permission | What It Allows |
|-----------|----------------|
| **GenericAll** | Full control — add to group, reset password, write any attribute |
| **GenericWrite** | Write any non-protected attribute (SPN, script path, etc.) |
| **WriteDacl** | Modify the object's DACL — grant yourself any permission |
| **WriteOwner** | Change ownership — then modify DACL as owner |
| **ForceChangePassword** | Reset password without knowing current (ExtendedRight) |
| **AddMember** | Add principals to a group (WriteProperty on `member`) |
| **AddSelf** | Add yourself to a group |
| **AllExtendedRights** | All extended rights including ForceChangePassword |
| **WriteAccountRestrictions** | Modify delegation settings (RBCD) |
| **WriteSPN** | Set ServicePrincipalName (enables Kerberoasting) |
| **WriteGPLink** | Link a GPO to an OU |
| **AddKeyCredentialLink** | Shadow Credentials attack |
| **AddAllowedToAct** | Configure RBCD |
| **ReadLAPSPassword** | Read local admin password from LAPS |
| **ReadGMSAPassword** | Read gMSA password blob |
| **GetChanges + GetChangesAll** | DCSync (combined = traversable DCSync edge) |

**SID resolution**: Each ACE contains a trustee SID. SharpHound resolves unknown SIDs via additional LDAP queries and caches the SID-to-name mapping.

### 3.8 Certificate Services (ADCS)

**CertServices** (LDAP-based):
- Certificate Authority objects and their properties
- Certificate templates (`pKICertificateTemplate` objects in `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration`)
- Template properties: `pKIExtendedKeyUsage`, `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `msPKI-Private-Key-Flag`, `msPKI-RA-Signature`, `msPKI-Certificate-Application-Policy`, `msPKI-Certificate-Policy`
- Enrollment rights (who can request certificates — from template DACL)
- CA permissions (who can manage the CA)
- `nTAuthCertificates` (trusted CAs for authentication)
- OID group links

**CARegistry** (remote registry on CA servers):
- `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` keys
- CA certificate, enrollment settings, policy modules

**ESC vulnerability conditions detected**:

| ESC | Condition |
|-----|-----------|
| ESC1 | Template allows `ENROLLEE_SUPPLIES_SUBJECT` + Client Auth EKU + low-priv enrollment |
| ESC2 | Template has Any Purpose EKU or no EKU |
| ESC3 | Template allows enrollment agent certificates |
| ESC4 | Template DACL allows low-priv users to modify template |
| ESC6 | CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag |
| ESC9/10 | Weak certificate mapping + writable account |
| ESC13 | OID group link abuse |

---

## 4. How It Enumerates — Technical Mechanisms

### 4.1 LDAP Enumeration

**Library**: `System.DirectoryServices.Protocols` (not `DirectorySearcher`/ADSI) — lower overhead, ~1min faster on 300K-user environments.

**Connection setup**:
- `LdapConnection` with `SearchRequest` and `SearchResponse`
- Kerberos signing by default (`SessionOptions.Signing = true`, `SessionOptions.Sealing = true`)
- Port 389 (LDAP) or 636 (LDAPS with `--SecureLdap`)
- Site-aware DC selection (nearest DC, not always PDC)

**Paging**: `PageResultRequestControl(500)` — retrieves 500 entries per page.

**ACL retrieval**: `SecurityDescriptorFlagControl` with flags 0x05 (DACL + Owner) — avoids SACL permission issues.

**Key LDAP filters used**:

```
# All enabled computers
(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))

# All security groups
(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913)(primarygroupid=*))

# All users
(samaccounttype=805306368)

# SPN targets (Kerberoastable)
(&(samaccounttype=805306368)(serviceprincipalname=*))

# Trusted domains
(objectclass=trusteddomain)

# Domain object
(objectclass=domain)

# ACL targets (users, computers, groups, domains, GPOs, OUs)
(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectClass=domain)(&(objectcategory=groupPolicyContainer)(flags=*))(objectcategory=organizationalUnit))

# GPOs with file system path
(&(objectcategory=groupPolicyContainer)(flags=*)(name=*)(gpcfilesyspath=*))

# OUs with GPO links
(&(|(objectcategory=organizationalUnit)(objectclass=domain))(gplink=*)(flags=*))

# Containers and OUs
(|(objectcategory=organizationalUnit)(objectClass=domain)(&(objectcategory=groupPolicyContainer)(flags=*)(name=*)(gpcfilesyspath=*)))
```

### 4.2 SAMR RPC — Local Group Enumeration

**Protocol**: SAMR (Security Account Manager Remote Protocol) over SMB port 445.

**Named pipe**: `\PIPE\samr` via `IPC$` share.

**Interface UUID**: `12345778-1234-abcd-ef00-0123456789ac`

**API call sequence** (SharpHound uses raw SAMR, not `NetLocalGroupGetMembers`):

```
1. SamrConnect5(ServerName)           → server handle
2. SamrLookupDomainInSamServer(handle, "Builtin")  → domain SID
3. SamrOpenDomain(handle, domainSID)  → domain handle
4. SamrOpenAlias(domainHandle, RID)   → alias handle
5. SamrGetMembersInAlias(aliasHandle) → array of SIDs
6. LsaOpenPolicy2(SystemName)         → policy handle
7. LsaLookupSids2(policyHandle, SIDs) → resolved names
```

**Why raw SAMR instead of NetLocalGroupGetMembers**: The API call wraps SAMR but queries the group by name (e.g., "Administrators"), which fails on non-English Windows where the group has a localized name (e.g., "Administratoren" in German). SharpHound queries by RID 544 directly, which is language-independent.

**Target RIDs**:

| RID | Group | Edge Created |
|-----|-------|-------------|
| 544 | Administrators | AdminTo |
| 555 | Remote Desktop Users | CanRDP |
| 562 | Distributed COM Users | ExecuteDCOM |
| 580 | Remote Management Users | CanPSRemote |

**Result filtering**: Filters out local accounts, service accounts (S-1-5-80), IIS AppPool identities, Window Manager accounts, Font Driver Host accounts.

**Permission requirement**: Windows 10 1607+ / Server 2016+ restricts remote SAMR to local Administrators by default (controlled by `RestrictRemoteSAM` registry key). DCs remain accessible to all authenticated users.

### 4.3 Session Enumeration — NetSessionEnum

**Named pipe**: `\PIPE\srvsvc` via `IPC$` share.

**Interface UUID**: `4b324fc8-1670-01d3-1278-5a47bf6ee188`

**API**: `NetSessionEnum` at level 10 — returns who has sessions and from where (IP addresses).

**Data returned**: Session username, client hostname/IP.

**Filtering**: Blank usernames, blank client names, computer account sessions, sessions matching the enumeration user, anonymous logons.

**Permission**: Modern Windows (10 1709+ / Server 2019+) restricts to Administrators, Server Operators, Power Users, and service/batch/interactive logons. Older systems allowed all authenticated users.

**Edge created**: `HasSession` (Computer → User).

### 4.4 Session Enumeration — NetWkstaUserEnum (LoggedOn)

**Named pipe**: `\PIPE\wkssvc` via `IPC$` share.

**Interface UUID**: `6BFFD098-A112-3610-9833-46C3F87E345A`

**API**: `NetWkstaUserEnum` — returns all interactive, service, and batch logons with their logon domains and servers.

**Permission**: Admin only. Fails silently for non-admin users.

**Filtering**: Local accounts, empty usernames, empty computer sessions, entries without logon domain, logon domains with whitespace ("NT Authority").

### 4.5 Session Enumeration — Remote Registry

**Named pipe**: `\PIPE\winreg` via `IPC$` share.

**Interface UUID**: `338cd001-2244-31f1-aaaa-900038001003`

**Mechanism**: Queries `HKEY_USERS` hive to list loaded user profiles (each profile is a subkey named by the user's SID).

**SID filter regex**: `S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$`

**Permission**: Everyone has read access to `HKEY_USERS` subkey listing — no admin required.

**Limitation**: Loaded hives persist after logoff if processes hold handles (scheduled tasks). Creates false positives.

**Service availability**:
- Windows 8.1-10 21H1: Disabled by default
- Windows Server 2012 R2-2022: Automatic (trigger start) — auto-starts when pipe is accessed, stops after 10min idle

### 4.6 Host Validation

Before SMB enumeration, SharpHound validates hosts:
- **TCP port 445 check** (not ICMP ping — more reliable indicator of SMB availability)
- Configurable timeout: `--PortCheckTimeout` (default 2000ms)
- Can be skipped: `--SkipPortCheck`

### 4.7 SID Resolution

SharpHound maintains in-memory caches (`ConcurrentDictionary` for thread safety):
- SID → display name
- Distinguished name → SID
- DNS resolution results
- Port check results

Cache is serialized to disk using protobuf for fast persistence between runs (`--CacheName`, `--RebuildCache`).

Foreign domain members: When an ACE or group member references a SID from a different domain, SharpHound follows trust chains to resolve it — querying the foreign domain's DC if trusts permit.

### 4.8 Stealth and Performance Controls

| Control | Effect |
|---------|--------|
| `--Stealth` | Single-threaded, DCOnly-preferred, file server targeting for sessions |
| `--Throttle N` | N ms delay after each computer request (default 0) |
| `--Jitter N` | N% random variation applied to throttle (default 0) |
| `--Threads N` | Number of enumeration threads |
| `--DistinguishedName` | Limit LDAP search to specific OU |
| `--LDAPFilter` | Additional LDAP filter to narrow scope |
| `--ExcludeDCs` | Don't touch DCs (avoids Microsoft ATA/ATP detection) |
| `--Loop` | Continuous session collection (with `--LoopDuration`, `--LoopInterval`) |
| `--ComputerFile` | Only enumerate specific computers from a file |

---

## 5. Output Format — BloodHound JSON

### 5.1 ZIP Structure

SharpHound produces a ZIP archive (default: `YYYYMMDDHHMMSS_BloodHound.zip`) containing:

```
BloodHound_output.zip
├── YYYYMMDDHHMMSS_users.json
├── YYYYMMDDHHMMSS_computers.json
├── YYYYMMDDHHMMSS_groups.json
├── YYYYMMDDHHMMSS_domains.json
├── YYYYMMDDHHMMSS_gpos.json
├── YYYYMMDDHHMMSS_ous.json
└── YYYYMMDDHHMMSS_containers.json
```

Options: `--NoZip` (raw JSON), `--ZipPassword` (encrypted), `--RandomFileNames`, `--PrettyPrint`.

### 5.2 JSON Entity Schema

Each JSON file follows this structure:

```json
{
    "data": [
        {
            "ObjectIdentifier": "S-1-5-21-...",
            "Properties": {
                "name": "JOHN.DOE@DOMAIN.COM",
                "domain": "DOMAIN.COM",
                "domainsid": "S-1-5-21-...",
                "distinguishedname": "CN=John Doe,OU=Users,DC=domain,DC=com",
                "enabled": true,
                "lastlogon": 1719800000,
                "pwdlastset": 1719700000,
                "serviceprincipalnames": ["MSSQLSvc/sql01.domain.com:1433"],
                "hasspn": true,
                "admincount": false,
                "description": "Service account",
                "whencreated": 1609459200,
                "sidhistory": [],
                "unconstraineddelegation": false,
                "allowedtodelegate": ["cifs/dc01.domain.com"]
            },
            "PrimaryGroupSID": "S-1-5-21-...-513",
            "Members": [],
            "Aces": [
                {
                    "PrincipalSID": "S-1-5-21-...",
                    "PrincipalType": "Group",
                    "RightName": "GenericAll",
                    "IsInherited": false
                }
            ],
            "AllowedToDelegate": ["S-1-5-21-..."],
            "AllowedToAct": [],
            "HasSIDHistory": [],
            "SPNTargets": [],
            "IsDeleted": false,
            "IsACLProtected": false
        }
    ],
    "meta": {
        "methods": 127679,
        "type": "users",
        "count": 1500,
        "version": 6
    }
}
```

### 5.3 Entity-Specific Fields

**Users**: Properties (name, domain, enabled, lastlogon, pwdlastset, hasspn, admincount, sidhistory, allowedtodelegate, unconstraineddelegation), Aces, AllowedToDelegate, HasSIDHistory, SPNTargets.

**Computers**: Properties (name, domain, operatingsystem, enabled, unconstraineddelegation, haslaps), LocalAdmins[], RemoteDesktopUsers[], DcomUsers[], PSRemoteUsers[], Sessions[], PrivilegedSessions[], RegistrySessions[], Aces.

**Groups**: Properties (name, domain, admincount), Members[] (each with ObjectIdentifier and ObjectType), Aces.

**Domains**: Properties (name, domain, functionallevel, machineaccountquota), Trusts[] (TargetDomainSid, TrustDirection, TrustType, IsTransitive, SidFilteringEnabled), Links[] (GPO links), ChildObjects[], Aces.

**OUs**: Properties (name, domain, blocksinheritance), Links[] (GPO links), ChildObjects[], Aces.

**GPOs**: Properties (name, domain, gpcpath), Aces.

### 5.4 Relationship Edges

BloodHound tracks 80+ edge types. Key AD traversable edges:

**Membership & Identity**:
- `MemberOf` — user/group/computer is member of group
- `HasSession` — computer has active session for user
- `HasSIDHistory` — principal has SID history from another domain
- `Contains` — OU/domain contains child object

**Local Group**:
- `AdminTo` — principal is local admin on computer
- `CanRDP` — principal can RDP to computer
- `ExecuteDCOM` — principal can DCOM on computer
- `CanPSRemote` — principal can PS remote to computer

**ACL Abuse**:
- `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns`
- `ForceChangePassword`, `AddMember`, `AddSelf`
- `AllExtendedRights`, `WriteAccountRestrictions`
- `WriteSPN`, `WriteGPLink`
- `AddKeyCredentialLink`, `AddAllowedToAct`
- `ReadLAPSPassword`, `ReadGMSAPassword`, `SyncLAPSPassword`, `DumpSMSAPassword`

**Delegation**:
- `AllowedToDelegate` — constrained delegation
- `AllowedToAct` — resource-based constrained delegation
- `AbuseTGTDelegation` — unconstrained delegation abuse

**Domain Trust**:
- `CrossForestTrust`, `SameForestTrust`, `HasTrustKeys`
- `SpoofSIDHistory`

**Certificate Services (ADCS)**:
- `ADCSESC1`, `ADCSESC3`, `ADCSESC4`, `ADCSESC6a/b`, `ADCSESC9a/b`, `ADCSESC10a/b`, `ADCSESC13`
- `Enroll`, `EnrollOnBehalfOf`, `DelegatedEnrollmentAgent`
- `ManageCA`, `ManageCertificates`, `GoldenCert`
- `HostsCAService`, `EnterpriseCAFor`, `RootCAFor`, `NTAuthStoreFor`, `TrustedForNTAuth`
- `IssuedSignedBy`, `PublishedTo`, `ExtendedByPolicy`, `OIDGroupLink`
- `CoerceAndRelayNTLMToADCS`, `CoerceAndRelayNTLMToLDAP/LDAPS/SMB`, `CoerceToTGT`

**GPO**:
- `GPLink` — GPO linked to OU/domain
- `DCFor` — DC is DC for domain

**Composite/Post-processed**:
- `DCSync` — derived from `GetChanges` + `GetChangesAll` on domain object
- `SQLAdmin` — SQL Server admin access

---

## 6. Detection Surface

### 6.1 LDAP Detection

| Indicator | Detail |
|-----------|--------|
| **ETW Provider** | `Microsoft-Windows-LDAP-Client` (Event ID 3) captures all LDAP queries including filters |
| **Event ID 4662** | Directory Service Access — many 4662 events in short period = enumeration |
| **Query volume** | SharpHound issues hundreds of LDAP queries in rapid succession |
| **Attribute requests** | Bulk requests for `nTSecurityDescriptor`, `servicePrincipalName`, `adminCount` are unusual |
| **SDFlags control** | Requesting DACL (0x04/0x05) on many objects at once is distinctive |
| **Filter patterns** | The specific `samaccounttype` filter combinations are SharpHound fingerprints |
| **Paging** | 500-entry page requests across entire directory |

**LDAP detection tools**: SilkETW (ETW wrapper) with YARA rules targeting SharpHound query patterns:
```
SilkETW.exe -t user -pn Microsoft-Windows-LDAP-Client -ot eventlog
```

### 6.2 SMB/RPC Detection

| Indicator | Detail |
|-----------|--------|
| **Event ID 5140** | File share access (IPC$ connections) |
| **Event ID 5145** | Detailed file share access — named pipe access patterns |
| **Named pipes** | `\PIPE\samr` + `\PIPE\srvsvc` + `\PIPE\wkssvc` + `\PIPE\winreg` + `\PIPE\lsarpc` from same source in short timeframe |
| **Port 445 sweep** | Hundreds of TCP 445 connections across many hosts |
| **DNS lookups** | Hundreds of DNS queries for computer names in rapid succession |
| **Event ID 4624/4625** | Logon/failed logon events from LDAP/SMB connections |

### 6.3 Behavioral Detection

| Indicator | Detail |
|-----------|--------|
| **Microsoft ATA/ATP** | Detects LDAP reconnaissance, SAMR enumeration, NetSessionEnum across many hosts |
| **Defender signatures** | `HackTool:MSIL/SharpHound!MSR` (static), `Behavior:Win32/SharpHound.AM` (behavioral), `Behavior:Win32/SharpHound.J` |
| **AMSI** | Scans PowerShell/in-memory .NET execution buffers — detects even obfuscated SharpHound |
| **Identity solutions** | LDAP query patterns trigger alerts "even in most stealthy configuration" |
| **AD decoys** | Honeypot accounts with `adminCount=1` or fake SPNs trigger on enumeration |

### 6.4 How SharpHound Tries to Evade

| Technique | Effect |
|-----------|--------|
| `--Stealth` | Single-threaded, reduced target set, DCOnly-preferred |
| `--Throttle` + `--Jitter` | Slows enumeration, randomizes timing |
| `--ExcludeDCs` | Avoids Microsoft ATA/ATP triggers on DC traffic |
| `--DistinguishedName` | Limits scope to specific OU |
| `--ComputerFile` | Only hits specific targets |
| Kerberos encryption | LDAP queries encrypted — network inspection infeasible |
| Cache reuse | Reduces repeat queries across runs |
| Port 445 check (not ICMP) | Less detectable than ping sweeps |

### 6.5 Required GPO Settings for Detection

To generate the relevant events, enable via Group Policy:
- `Object Access → Audit File Share` (5140)
- `Object Access → Audit Detailed File Share` (5145)
- `DS Access → Audit Directory Service Access` (4662)

### 6.6 SIGMA Rule Indicators

Detection rules look for:
- Strings: "Domain Admins", "Enterprise Admins", "admincount=1" in LDAP queries
- Multiple named pipe access (`samr`, `lsarpc`, `srvsvc`, `winreg`) from same source to IPC$ in short timeframe
- High-volume 4662 events from single source

---

## 7. Architecture Notes for C Reimplementation

### 7.1 Threading Model

SharpHound uses Task Parallel Library (TPL) with a producer-consumer pattern. LDAP results are produced and fed to multiple consumer threads that process each object through all applicable enumeration steps (group membership, ACLs, sessions) in a single pass.

For C: Use Windows thread pool (`QueueUserWorkItem` or `CreateThreadpoolWork`) with a shared work queue. Process each LDAP result through all collectors before moving to the next.

### 7.2 Key Windows APIs Needed

**LDAP**: `ldap_init`, `ldap_bind_s`, `ldap_search_ext_s`, `ldap_first_entry`, `ldap_next_entry`, `ldap_get_values_len`, `ldap_control_create` (paging, SDFlags).

**SAMR**: Direct RPC via `samr` pipe — `SamConnect`, `SamLookupDomainInSamServer`, `SamOpenDomain`, `SamOpenAlias`, `SamGetMembersInAlias`. Alternatively, P/Invoke equivalent via `samlib.dll` exports.

**LSA**: `LsaOpenPolicy`, `LsaLookupSids2` — for SID resolution.

**Sessions**: `NetSessionEnum` (level 10), `NetWkstaUserEnum` — from `netapi32.dll`.

**Registry**: `RegConnectRegistryW`, `RegOpenKeyExW`, `RegEnumKeyExW` — for remote registry session enumeration and CA/DC registry collection.

**Security descriptors**: `GetSecurityDescriptorDacl`, `GetAce`, `LookupAccountSid` — for DACL parsing.

### 7.3 Output

Generate BloodHound-compatible JSON. The v6 format is straightforward — objects + edges + metadata. Can use `cJSON` library or manual string formatting for JSON generation. ZIP with `miniz` or similar.

---

## Sources

- [SpecterOps/SharpHound GitHub](https://github.com/SpecterOps/SharpHound)
- [SharpHound CE Flags](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound-flags)
- [SharpHound: Technical Details — CptJesus](https://blog.cptjesus.com/posts/sharphoundtechnical/)
- [SharpHound: Target Selection — CptJesus](https://blog.cptjesus.com/posts/sharphoundtargetting/)
- [BloodHound Inner Workings Part 1: SAMR — Compass Security](https://blog.compass-security.com/2022/05/bloodhound-inner-workings-part-1/)
- [BloodHound Inner Workings Part 2: Sessions — Compass Security](https://blog.compass-security.com/2022/05/bloodhound-inner-workings-part-2/)
- [BloodHound Inner Workings Part 3: Registry — Compass Security](https://blog.compass-security.com/2022/05/bloodhound-inner-workings-part-3/)
- [SharpHound Detection — iPurple Team](https://ipurple.team/2024/07/15/sharphound-detection/)
- [Sniffing Out SharpHound — Sophos/Secureworks](https://www.sophos.com/en-us/blog/sniffing-out-sharphound-on-its-hunt-for-domain-admin)
- [LDAP Enumeration Detection — Securonix](https://medium.com/securonix-tech-blog/detecting-ldap-enumeration-and-bloodhound-s-sharphound-collector-using-active-directory-decoys-dfc840f2f644)
- [SharpHoundCommon CommonProperties.cs](https://github.com/SpecterOps/SharpHoundCommon/blob/68a68c6eab5375b46f975274b16ff1acdc35dc48/src/CommonLib/LdapQueries/CommonProperties.cs)
- [BloodHound Edge Types](https://bloodhound.specterops.io/resources/edges/traversable-edges)
- [SharpHound Data Collection Permissions](https://bloodhound.specterops.io/collect-data/permissions)
- [Cato CTRL Overview of BloodHound Collectors](https://www.catonetworks.com/blog/cato-ctrl-overview-of-bloodhound-and-associated-collectors/)
- [LDAP Reconnaissance Detection — FalconForce](https://github.com/FalconForceTeam/FalconFriday/blob/main/0xFF-0003-LDAP_reconnaissance_via_search_filters-Win.md)
- [Microsoft AMSI Detection of AD Attacks](https://www.microsoft.com/en-us/security/blog/2020/08/27/stopping-active-directory-attacks-and-other-post-exploitation-behavior-with-amsi-and-machine-learning/)
- [From Code to Coverage: SDFlags Detection — Huntress](https://www.huntress.com/blog/ldap-active-directory-detection-part-three)
