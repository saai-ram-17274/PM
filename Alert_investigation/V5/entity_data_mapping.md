# V5 Entity Slider — Data Source & AI Enrichment Mapping

> **Generated**: 07 May 2026
> **Purpose**: Maps every field in the V5 Alert Investigation entity slider to **(a)** its backend source in our product (Log360 Cloud / Log360 / EventLog Analyzer / ADAudit Plus / ADManager Plus), and **(b)** what additional context **AI agents** can fetch to enrich the same field.
> **Source of truth**: [`js/data/entities.js`](js/data/entities.js) (20 entities) + tab config in [`js/modules/entity-slider.js`](js/modules/entity-slider.js#L189) (6 entity types).
> **Companion doc**: [relation_catalog.md](relation_catalog.md) — the 24 canonical edge relations used in the graph.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Data exists in product backend — implementable today |
| 🟡 | Partial — needs aggregation, schema extension, or new collector |
| ❌ | Not in product — needs new feature or third-party integration |
| 🤖 | AI-fetchable — LLM/agent can enrich from external/public sources |
| 🤖✚ | AI-derivable — LLM can compute from product data (summary, classification, scoring) |

**AI-Enrichment column** lists what an AI agent (e.g. via tool-calling to VirusTotal, Shodan, MITRE ATT&CK, WHOIS, threat-feed APIs, or pure LLM reasoning over collected logs) can add **on top of** the product field.

---

## Entity Inventory

V5 ships **20 demo entities** across **8 entity types**. Each entity type has its own tab layout in `entity-slider.js`.

| Type | Tab Layout | Demo Entities |
|------|-----------|---------------|
| **user** | Overview · Risk & Identity · Activity · Account Changes · Recent Alerts | `user-m-henderson`, `user-admin` |
| **device** | Overview · Host Activity · Persistence & Exfil · Alerts & Response | `dev-ws045` (implicit; see processes/services) |
| **ip** | Overview · Threat Intel · Connections · Logon Activity | `ip-tor`, `ip-internal` |
| **domain** | Overview · Threat Intel · Connections · Logon Activity | `domain-c2` (implicit) |
| **service** | Overview · Config & Policy · Activity · Alerts & Response | `svc-azure-ad`, `svc-sharepoint`, `svc-oauth`, `svc-winupdatesvc` |
| **process** | Overview · Anomalies · Activity | `proc-powershell` |
| **alert** | Overview · Scope · Response | 11 alert entities (`alert-impossible-travel`, `alert-oauth-token`, …) |

---

## 1. USER Entity (`user-m-henderson`, `user-admin`)

Tabs: **Overview · Risk & Identity · Activity · Account Changes · Recent Alerts**

### 1.1 Risk Summary (`riskSummary`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Risk Score (0–100) | ✅ | `ITSEntityRiskScoreDetails.RISK_SCORE` (Log360) | `RiskScoreHandler` — computed `MODIFIED_SCORE × SEVERITY_SCORE`, cached in Redis |
| Severity | ✅ | Stored as `ITSEntityRiskScoreDetails.SESSION_SEVERITY` (INTEGER bucket id). Human label resolved via lookup join `ITSRiskSeverityDetails.SEVERITY_NAME WHERE SEVERITY_ID = SESSION_SEVERITY` → `CRITICAL` / `ATTENTION` / `TROUBLE`. The join is a convention — there is **no FK declared** in [`data-dictionary.xml`](../../../REPOS/itsf/product_package/conf/itsf/common/riskscore/data-dictionary.xml). The bucket itself is selected per-event via `LIKE_LI_HOOD_SEVERITY` mapping in [`RiskScoreHandler.java`](../../../REPOS/itsf/source/java_source/com/manageengine/itsf/common/riskscore/handler/RiskScoreHandler.java#L33-L34) (NOT mapped from score thresholds). | Lookup join |
| Status Badge ("Compromised Account") | 🟡 | Computed from anomaly types | Aggregate `ITSAlertProfileConfigurations` rule categories |
| Active Anomalies — session / lifetime | ✅ | `ITSEntityRiskScoreDetails.DETECTION_COUNT` (session, decays via `DecayHandler`) + `OVERALL_DETECTION_COUNT` (true lifetime tally — incremented `+1` per anomaly in [`RiskScoreHandler.java`](../../../REPOS/itsf/source/java_source/com/manageengine/itsf/common/riskscore/handler/RiskScoreHandler.java#L42), never decays, never resets) | Raw DB |
| Failed Logins (24h) | ✅ | Elasticsearch `eventid=4625` | Aggregated ES query on Windows Security logs |
| Last Anomaly | ✅ | `ITSEntityRiskScoreDetails.LAST_ANOMALY_UPDATE_TIME` — running `Math.max()` on every event in [`RiskScoreHandler.java`](../../../REPOS/itsf/source/java_source/com/manageengine/itsf/common/riskscore/handler/RiskScoreHandler.java#L47). Long-term storage, not bounded by ES retention. | `now() - LAST_ANOMALY_UPDATE_TIME`, humanized |
| ~~Dwell Time~~ — **REMOVED** | ❌ | No `FIRST_ANOMALY_TIME` column in `ITSEntityRiskScoreDetails`; the handler captures only the running max, not the min. ES `min(@timestamp)` is bounded by retention so silently truncates. Removed from the user summary card to avoid misleading numbers. To bring back: add `FIRST_ANOMALY_TIME BIGINT` to [`data-dictionary.xml`](../../../REPOS/itsf/product_package/conf/itsf/common/riskscore/data-dictionary.xml) and set it once on row insert in [`RiskScoreUtil.java`](../../../REPOS/itsf/source/java_source/com/manageengine/itsf/common/riskscore/util/RiskScoreUtil.java#L70). | — |
| Hero chip — **Last Logon** | ✅ | `ADSUserDetails.lastLogonTime` (ADAP — real DB column, never retention-bounded for users). Renders as a single chip via `summaryCard.heroChips[]` in [entity-slider.js](js/modules/entity-slider.js) (generic hook — other entity types can fill `heroChips` with their own schema-honest fields). | LDAP-synced into RDBMS |
| ~~First Seen / Last Activity~~ — **REMOVED from user hero** | ❌ | Was sourced from ES `min/max(_zl_timestamp)` filtered by entity. `MIN()` is silently truncated by log retention so it can't honestly answer *"when did the platform first observe this user"*. Replaced by the single **Last Logon** chip above. The renderer keeps the legacy `firstSeen` / `lastActivity` fields as a fallback so non-user entities (which haven't been re-reviewed yet) continue to render. | — |

### 1.2 User Details (`usersDetails`)

> **Cloud surface — verified.** Log360 Cloud uses APF discovery tables for full identity attributes, with `ELADomainUserDetails` only as a thin discovery-time index. Picked based on whether the entity is an AD user or an Entra/M365 user. Resolution paths verified in [`UserDetailsUtil.java`](../../../REPOS/itsf/source/java_source/com/manageengine/itsf/common/incident/workbench/tab/util/UserDetailsUtil.java) and the attribute manifest at [`APFADUserAttributes.xml`](../../../REPOS/ADSF-DD-DML/product_package/conf/adsf/common/appfw/applications/attributes/ad/APFADUserAttributes.xml).
>
> | Source | Table | Holds | Notes |
> |---|---|---|---|
> | AD-discovered users (rich) | [`APFDiscADUserDetails`](../../../REPOS/ADSF-DD-DML/product_package/conf/adsf/common/appfw/discovery/application/ad/data-dictionary.xml#L168) | ~120 columns: identity (NAME, FIRST_NAME, LAST_NAME, DISPLAY_NAME, FULL_NAME, COMMON_NAME, SAM_ACCOUNT_NAME, LOGON_NAME, EMAIL_ADDRESS), org (TITLE, DEPARTMENT, MANAGER, MANAGER_DN, COMPANY, OFFICE, EMPLOYEE_ID, EMPLOYEE_NUMBER, DIRECT_REPORTS), location (STREET_ADDRESS, CITY, STATE_PROVINCE, COUNTRY, ZIP_POSTAL_CODE), AD plumbing (DISTINGUISHED_NAME, OU_NAME, OU_DN_NAME, OU_UNIQUE_ID, DOMAIN_NAME, PRIMARY_GROUP_ID, SID_STRING, OBJECT_GUID), security (USER_ACCOUNT_CONTROL, ACCOUNT_STATUS, ACCOUNT_EXPIRY_DATE, LOCK_OUT_TIME, BAD_PASSWORD_COUNT, BAD_PASSWORD_TIME, PASSWORD_LAST_SET, PWD_NEV_EXP_FLAG, CAN_NOT_CHANGE_PWD, TRUSTED_FOR_DELEGATION, SMART_CARD_FOR_INTERACTIVE_LOGIN), logon (LAST_LOGON_TIME, LAST_LOGON_TIMESTAMP, DAYS_SINCE_LAST_LOGON, LAST_LOGOFF_TIME, LOGON_COUNT, LOGON_TO, LOGON_HOURS), lifecycle (WHEN_CREATED, WHEN_CHANGED, IS_DELETED), Exchange/LCS/RADIUS/TS extensions | **The real AD user table for cloud.** Discovered via APF AD application; attribute mapping declared in `APFADUserAttributes.xml`. |
> | AD discovery index (thin) | [`ELADomainUserDetails`](../../../REPOS/itsf/product_package/conf/itsf/common/LogCollection/discovery/data-dictionary.xml#L299) | OBJECT_GUID, OBJECT_SID, NAME, SAMACCOUNTNAME, USERPRINCIPALNAME, DISTINGUISHEDNAME, OBJECTROOT_DN, USERACCOUNTCONTROL, EMAIL_ID, DOMAIN_ID | Used by [`UserDetailsUtil.getUserObjectGUID()`](../../../REPOS/itsf/source/java_source/com/manageengine/itsf/common/incident/workbench/tab/util/UserDetailsUtil.java#L56) only to resolve `(domain, username) → OBJECT_GUID`. Not a full identity table — full attributes live in `APFDiscADUserDetails`. |
> | Entra / M365 users | [`APFDiscAADUserDetails`](../../../REPOS/ADSF-DD-DML/product_package/conf/adsf/common/appfw/discovery/application/azure/data-dictionary.xml#L177) | OBJECT_ID, IDENTITY, FIRST_NAME, LAST_NAME, USER_PRINCIPAL_NAME, DISPLAY_NAME, EMAIL_ADDRESS, PHONE_NUMBER, MOBILE_PHONE, TITLE, DEPARTMENT, COMPANY, OFFICE, EMPLOYEE_ID, MANAGER, COUNTRY/CITY/STATE/STREET, ACCOUNT_ENABLED, USER_ACCOUNT_CONTROL, WHEN_CREATED, WHEN_MODIFIED, LAST_PWD_CHANGE_TIME, PASSWORD_EXPIRY_DATE, LAST_DIR_SYNC_TIME, O365_USER_TYPE, IS_LICENSED, GROUP_COUNT, LITIGATION_HOLD_ENABLED, AUDIT_ENABLED, SOFT_DELETION_TIMESTAMP | Cloud-side APF discovery for Entra. Used by [`UserDetailsUtil.getAADUserDetails()`](../../../REPOS/itsf/source/java_source/com/manageengine/itsf/common/incident/workbench/tab/util/UserDetailsUtil.java#L72). |

| Field | Status | Cloud Source | How to Get |
|-------|--------|--------------|------------|
| Display Name | ✅ both | `APFDiscADUserDetails.DISPLAY_NAME` (AD) · `APFDiscAADUserDetails.DISPLAY_NAME` (Entra) | Direct read |
| SAM Account Name | ✅ AD · ❌ Entra | `APFDiscADUserDetails.SAM_ACCOUNT_NAME` (AD only — Entra has no SAM concept) | Direct read |
| UPN | ✅ both | `APFDiscADUserDetails.LOGON_NAME` (the AD `userPrincipalName` LDAP attr maps to LOGON_NAME column — see `APFADUserAttributes.xml` priority 6) · `APFDiscAADUserDetails.USER_PRINCIPAL_NAME` (Entra) | Direct read |
| Email | ✅ both | `APFDiscADUserDetails.EMAIL_ADDRESS` (AD) · `APFDiscAADUserDetails.EMAIL_ADDRESS` (Entra) | Direct read. Entra also has `ALTERNATE_EMAIL_ADDRESS`. |
| Job Title | ✅ both | `APFDiscADUserDetails.TITLE` (AD) · `APFDiscAADUserDetails.TITLE` (Entra) | Direct read |
| Department | ✅ both | `APFDiscADUserDetails.DEPARTMENT` (AD) · `APFDiscAADUserDetails.DEPARTMENT` (Entra) | Direct read |
| Manager | ✅ both | `APFDiscADUserDetails.MANAGER` (display) + `MANAGER_DN` (full DN) for AD · `APFDiscAADUserDetails.MANAGER` (stores OBJECT_ID; resolved to UPN via [`getUserUPN()`](../../../REPOS/itsf/source/java_source/com/manageengine/itsf/common/incident/workbench/tab/util/UserDetailsUtil.java#L107)) for Entra | Direct read (AD) · two-step lookup (Entra) |
| Last Logon Time | ✅ both | `APFDiscADUserDetails.LAST_LOGON_TIME` + `LAST_LOGON_TIMESTAMP` + precomputed `DAYS_SINCE_LAST_LOGON` (AD) · for Entra: not on `APFDiscAADUserDetails` directly — must come from M365 SignInLogs `max(createdDateTime) WHERE userPrincipalName=:upn` | Direct read (AD) · ES side-call (Entra, retention-bounded) |
| OU Name | ✅ AD · ❌ Entra | `APFDiscADUserDetails.OU_NAME` directly (also `OU_DN_NAME`, `OU_UNIQUE_ID`). Entra has no OU concept (administrative units instead — `APFDiscAADUserDetails.GROUP_COUNT` is the closest signal). | Direct read |
| Account Created | ✅ both | `APFDiscADUserDetails.WHEN_CREATED` (AD) · `APFDiscAADUserDetails.WHEN_CREATED` + `DAYS_SINCE_CREATED` (Entra) | Direct read |
| Account Status (with recommendation) | ✅ both (status) · 🤖 (recommendation) | Stored as pre-decoded BOOLEAN: `APFDiscADUserDetails.ACCOUNT_STATUS` — schema description is explicit: `0 → Disabled, 1 → Enabled`. The discovery handler resolves the `userAccountControl` disabled-bit during ingest (LDAP attr `uacAccountStatus`, [`APFADUserAttributes.xml` priority 18](../../../REPOS/ADSF-DD-DML/product_package/conf/adsf/common/appfw/applications/attributes/ad/APFADUserAttributes.xml#L18)) and writes the resolved boolean. Raw `USER_ACCOUNT_CONTROL` (BIGINT) is also retained for bits without their own column. Entra: `APFDiscAADUserDetails.ACCOUNT_ENABLED` (already a BOOLEAN per Graph API). The "Recommended: Disable" suffix is product-side business logic, not a stored column. | Direct read (BOOLEAN, no decoding needed) + AI for recommendation text |
| Logon Workstation | 🟡 both | **Two different concepts under one label** — see [§1.2.1](#121-logon-workstation--two-concepts-one-label) below. (a) **Allowlist (policy)** = `APFDiscADUserDetails.LOGON_TO` — direct read of LDAP `userWorkstations`, the workstations the AD admin permits this account to log on from. Usually empty (= all). (b) **Actual last logon from** (what the card shows as `CORP-WS-045`) = NOT on the user table at all — only in Windows Security event logs, requires ES query: `eventid=4624 \| stats latest(WorkstationName) by TargetUserName`. | (a) Direct read of `LOGON_TO` · (b) ES side-call (retention-bounded, typically 30/60/90 days) |
| Primary Group | ✅ AD (with join) · ❌ Entra | **One column + one join** — see [§1.2.2](#122-primary-group--one-column-one-join) below. `APFDiscADUserDetails` stores `PRIMARY_GROUP_ID` (the RID, e.g. `513`) and `PRIMARY_GROUP_GUID` (the group's OBJECT_GUID, manifest priority 100). Neither is the display name `"Domain Users"`. To resolve, join against [`APFDiscADGroupDetails`](../../../REPOS/ADSF-DD-DML/product_package/conf/adsf/common/appfw/discovery/application/ad/data-dictionary.xml) (same APF discovery, already in cloud schema) on `OBJECT_GUID = u.PRIMARY_GROUP_GUID`, return `GROUP_NAME`. Entra has no primary-group concept — `GROUP_COUNT` only; full membership lives in a separate APF group-membership table. | Direct read + 1 join |

> **Implication for the demo (corrected):** All 13 m.henderson User Details fields are now sourced from `APFDiscADUserDetails` directly with no two-table fallback needed for AD users. Only **two** caveats remain: (a) "Logon Workstation" on the card today shows `CORP-WS-045` which is "where m.henderson actually logged on from" — that's an ES side-call, **not** the `LOGON_TO` allowlist column. The doc should distinguish these. (b) For Entra-only tenants, **Last Logon Time** still requires an ES side-call into M365 SignInLogs (retention-bounded). For mixed tenants the slider should pick the path based on the discovered identity source.

#### 1.2.1 Logon Workstation — two concepts, one label

The single card label "Logon Workstation" conflates two unrelated things. They live in different stores and answer different questions:

| Concept | Question it answers | Where it lives | Cost |
|---|---|---|---|
| **Allowlist (policy)** | "Where is this account *permitted* to log on from?" | `APFDiscADUserDetails.LOGON_TO` — schema: `<column name="LOGON_TO"><description>userWorkstations</description><data-type>CHAR</data-type></column>`. Populated from LDAP `userWorkstations` (manifest priority 37). Static AD attribute set by the admin on the user object. **Usually empty** — meaning "allowed everywhere". | 1 indexed row read |
| **Actual last logon from** | "Where did this user *actually* log on from last?" | **Not** on any discovery table. Lives only in Windows Security event logs in Elasticsearch — `EventID 4624` (success) / `4625` (fail), fields `WorkstationName`, `IpAddress`, `IpPort`, `LogonType`. | 1 ES aggregation, **retention-bounded** (only as far back as ES retains 4624 events) |

**Resolution paths**

```sql
-- (a) Allowlist policy — direct read
SELECT LOGON_TO FROM APFDiscADUserDetails WHERE OBJECT_GUID = :userGuid;
```

```
# (b) Actual last logon from — ES query
index=wineventlog eventid=4624 TargetUserName="m.henderson"
| stats latest(WorkstationName) AS lastFromHost,
        latest(IpAddress)       AS lastFromIp
  by TargetUserName
```

**Why this matters for the card.** The demo today shows `CORP-WS-045` as "Logon Workstation". That value cannot come from `LOGON_TO` (that's the allowlist), it must come from ES `4624`. The two should be on separate rows on the card:

- **Last logon from:** `CORP-WS-045` (from ES 4624, retention-bounded)
- **Permitted from:** `LOGON_TO` value or `"All workstations"` (from discovery)

#### 1.2.2 Primary Group — one column, one join

`APFDiscADUserDetails` stores **two columns** related to the primary group, but neither is the display name a SOC analyst wants on the card:

```xml
<column name="PRIMARY_GROUP_ID">    <!-- e.g. "513" — the RID -->
<column name="PRIMARY_GROUP_GUID">  <!-- group's OBJECT_GUID, manifest priority 100 -->
```

`PRIMARY_GROUP_ID` is the AD primary-group RID (e.g. `513` = Domain Users, `512` = Domain Admins, `516` = Domain Controllers). It's just a number — useless on its own. To get `"Domain Users"` you join against [`APFDiscADGroupDetails`](../../../REPOS/ADSF-DD-DML/product_package/conf/adsf/common/appfw/discovery/application/ad/data-dictionary.xml), which is the AD groups table populated by the **same APF discovery** that fills `APFDiscADUserDetails`. Relevant columns on the groups table:

```
APFDiscADGroupDetails
├── OBJECT_GUID       -- group's GUID
├── SID_STRING        -- group's full SID (domain SID + RID)
├── GROUP_NAME        -- "Domain Users"   ← what the card shows
├── SAM_ACCOUNT_NAME  -- "Domain Users"
├── DISPLAY_NAME
└── APP_CONFIG_ID     -- same domain config as the user
```

**Resolution paths**

**Option A — via `PRIMARY_GROUP_GUID` (preferred, single clean join):**

```sql
SELECT g.GROUP_NAME
FROM   APFDiscADUserDetails u
JOIN   APFDiscADGroupDetails g
       ON g.OBJECT_GUID    = u.PRIMARY_GROUP_GUID
      AND g.APP_CONFIG_ID  = u.APP_CONFIG_ID
WHERE  u.OBJECT_GUID = :userGuid;
```

**Option B — via `PRIMARY_GROUP_ID` (RID) + SID match:** Only needed if `PRIMARY_GROUP_GUID` is null (older discoveries may not have populated it). Build the group's full SID by combining the user's domain SID prefix (from `u.SID_STRING`) with the RID, then match `g.SID_STRING`. Messier; prefer Option A.

**Why this isn't already pre-joined.** Look at the discovery schema — `APFDiscADUserDetails` and `APFDiscADGroupDetails` are **two separate tables with no FK between them**. The product keeps them denormalized because groups can be discovered before or after users; primary group is just a stored ID. The join is done at read time by whoever queries — in ADAP/ADManager the UI does this; on the cloud APF side the slider component does the same single join.

**Net.** Primary Group is **feasible with one join**, not impossible. The card just needs to show that the value `"Domain Users"` requires the user-row + groups-row join, not a single-column read.

### 1.3 Logon Activity (`logonActivity`) — Timeline

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Timestamp, Logon Type (2/3/10), Target Host, Source IP, Status | ✅ | EventID 4624 / 4625 in Elasticsearch | Standard auth-log parser |
| `dot` color (red/orange/green) | ✅ | Computed from UEBA peer-group baseline | UEBA scorer |

### 1.4 Processes (`processes`) — Timeline (per user-launched processes)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Process Name, Parent Process | ✅ | Sysmon EventID 1 + EID 8 (CreateRemoteThread) | Sysmon collector → ES |
| Action: Kill Process | ✅ | EDR API call (Defender/CrowdStrike/SentinelOne) | Existing remediation orchestrator |

### 1.5 Service Triggered (`serviceTriggered`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Service Name, Display Name, Startup type, Host, Status, Severity | ✅ | EventID 7045 (service installed) + 4697 + EID 12/13 | Windows Service log parser |
| Action: Stop Service | ✅ | WMI/PowerShell remoting via existing AAP runner | — |

### 1.6 Recent Alerts (`recentAlerts`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Time, Alert label, Type tag, MITRE technique, Source, Status, Severity | ✅ | `ITSAlertProfileConfigurations` + correlation engine output | Existing alert-profile API |
| Linked graph node (`viewOnGraph`) | ✅ | Internal entity-id mapping | — |

### 1.7 Resource / File Access (`resourceFileAccess`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Host, File Name, Location, Change Type | ✅ | File-server auditing (ADAudit Plus File Server module) + SharePoint audit | Existing FS collector + Graph API |

### 1.8 UEBA Risk Profile (`uebaProfile`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Risk Score / 100 + Severity | ✅ | UEBA scorer | Existing |
| Anomalies Detected | ✅ | UEBA model output | Existing |
| Account Type | ✅ | LDAP `adminCount` + group memberships | LDAP |

### 1.9 Login Statistics (7 days) (`loginStatistics`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Total / Successful / Failed | ✅ | ES agg over 4624/4625 | Existing |
| Unique Source IPs | ✅ | ES `terms` agg | Existing |
| Off-Hours Logins | ✅ | ES filter on hour-of-day vs business window | Existing |
| Unique Hosts | ✅ | ES `terms` agg on `Workstation` | Existing |

### 1.10 Cloud Identities & Assets (`cloudIdentities`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Azure AD UPN + Tenant + License (P1/P2/E5) | ✅ | M365 Manager Plus / Cloud Security Plus | Graph API `users/{id}` + `subscribedSkus` |
| Azure Roles | ✅ | Graph API `directoryRoles` | Existing |
| Conditional Access (count) | ✅ | Graph API `conditionalAccessPolicies` | Existing |

### 1.11 Identity Risk Assessment (`identityRisk`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Password Age (vs policy) | ✅ | LDAP `pwdLastSet` + domain pwd policy | ADAP |
| Group Memberships | ✅ | LDAP `memberOf` | ADAP |
| Privileged Groups + WriteDACL findings | 🟡 | ADAP risk-report module + ADMP Governance attack-path | Existing (Governance module) |
| Stale Account / Service Account flags | ✅ | LDAP attributes + heuristic | ADAP |
| Last Password Change | ✅ | LDAP `pwdLastSet` | ADAP |

### 1.12 Network Activity (24h) (`networkActivity`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| DNS Query (Domain, Resolution, Source Host) | ✅ | Sysmon EventID 22 + DNS-server logs | Existing collector |
| Firewall Allow / Deny (Dst, Proto, Bytes, Duration) | ✅ | Firewall syslog (Fortinet/PA/Checkpoint) | Existing parsers |
| Proxy log (URL, Method, UA) | ✅ | Proxy syslog | Existing |
| VPN Connection (Src, Assigned, Proto, Duration) | ✅ | VPN gateway logs | Existing |

### 1.13 Threat Intelligence Context (`threatIntelContext`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Primary IOC | 🟡 | Log360 Threat Analytics module | Internal IP/domain enrichment cache |
| VirusTotal verdict | ❌ | Not in product | — |
| First Seen (Global) | ❌ | Not in product | — |
| MITRE Techniques | 🟡 | Per-alert-profile mapping | `ITSAlertProfileConfigurations.MITRE_TECHNIQUE_ID` |

### 1.14 DLP Incidents (`dlpIncidents`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Policy, Action, File, Destination | ✅ | DataSecurity Plus / Defender for Cloud Apps DLP | Existing connector |

### 1.15 Account Lockouts (`accountLockouts`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| User, Locking DC, Source Computer, EventID | ✅ | EventID 4740 (account locked) | ADAP account-lockout analyzer |

### 1.16 Password Change / Reset History (`passwordHistory`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Operation, Caller, Target, Source, Result | ✅ | EventID 4723 (self) / 4724 (admin) — on-prem; Entra audit log — cloud | ADAP + M365MP |

### 1.17 Group Membership Changes (`groupMembershipChanges`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Operation, Group, Caller, Source | ✅ | EventID 4732/4756 — on-prem; Entra audit — cloud | ADAP + M365MP |

### 1.18 Mailbox Forwarding Rules (`mailboxForwarding`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Operation (New-InboxRule), Mailbox, Rule Name, ForwardTo, Creator IP | ✅ | Exchange Online audit log | M365 Manager Plus |

### 1.19 Recent Application Access (`recentAppAccess`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Application, Source IP, Risk Level, Result | ✅ | Entra ID Sign-in logs | M365MP |

### 1.20 Privileged Role Assignment Changes (`privilegedRoleChanges`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Empty-state when none | ✅ | Entra audit log | Existing |

### 1.21 Compliance & Regulatory Impact (`complianceImpact`) — **REMOVED**

> Data block existed in `entities.js` but was never wired into any tab. Removed in the constant-vs-dynamic revision (see [entity_constant_vs_dynamic.md](entity_constant_vs_dynamic.md#1-user-entity--8-constant--11-dynamic)). Regulated-data narrative is now covered by **DLP Incidents** (§1.20) and the **Recommendations & Remediation** card (§1.22), which already calls out GDPR Art. 33 / PII exposure. Re-introduce only if PM commits a real `ITSComplianceMapping` source rather than hard-coded cards.

### 1.22 Recommendations & Remediation (`remediationGuide`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Verdict, Severity | 🟡 | Aggregated from rule output | — |
| Recommendations (icon, title, desc, priority) | ❌ | Not in product | — |
| Playbooks (name, ID, desc, ETA, urgency) | 🟡 | SOAR connector / runbook catalog | Log360 Cloud Workflows |

---

## 2. DEVICE Entity (`dev-ws045` — CORP-WS-045)

Tabs: **Overview · Host Activity · Persistence & Exfil · Alerts & Response**

### 2.1 Risk Summary (`riskSummary`)
Same field structure as User §1.1; `metrics` are device-specific ("Suspicious Processes", "C2 Connections"). All ✅ from `ITSEntityRiskScoreDetails`.

### 2.2 Device Details (`deviceDetails`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Hostname, FQDN, OS, OS Build | ✅ | AD computer object + Sysmon system info | ADAP + Sysmon EID 1 |
| Domain, OU | ✅ | AD `distinguishedName` | ADAP |
| Last Logon, Last Boot | ✅ | AD `lastLogonTimestamp` + Sysmon EID 6005 | Existing |
| Owner / Primary User | ✅ | AD `managedBy` + heuristic on logon counts | ADAP |
| Hardware (CPU, RAM, Disk) | 🟡 | Asset-management integration (SCCM/Intune) | Optional connector |
| BitLocker / Disk encryption | 🟡 | Intune compliance | Existing |

### 2.3 Login Activity on Device (`loginActivity`)
Same shape as User §1.3 but reverse-pivoted (who logged into this host). ✅ from EventID 4624 on the host.

### 2.4 Processes on Host (`processesOnHost`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Process name, PID, Start time, Cmdline | ✅ | Sysmon EID 1 | Existing |

### 2.5 Services on Host (`servicesOnHost`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Service Name, Display Name, Startup, User, Status | ✅ | EID 7045 + WMI snapshot | Existing |

### 2.6 Users Logged On (`usersLoggedOn`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Active sessions (user, type, since) | ✅ | `quser` / `LogonSessions.exe` collector + 4624/4634 pairing | Existing |

### 2.7 Recent Alerts on Device (`recentAlerts`)
Same shape as User §1.6.

### 2.8 Agent Status & Health (`agentStatus`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| EDR (Defender / CrowdStrike / SentinelOne) status, version, last check-in | ✅ | EDR API | Existing connectors |
| Sysmon version, config hash | 🟡 | Sysmon registry key | Custom collector |
| AV definitions date | ✅ | EDR API | Existing |

### 2.9 GPO Applied to Device (`gpoApplied`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| GPO name, link OU, version, applied at | ✅ | ADManager Plus GPO module | Existing |

### 2.10 Security Event Summary (24h Counters) (`securityEventSummary`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Per-EventID counts (4624, 4625, 4672, 4688, 7045, …) | ✅ | ES `date_histogram` + `terms` agg | Existing |

### 2.11 USB Device Events (`usbDeviceEvents`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Time, Vendor/Product, Serial, Action (insert/remove), Bytes copied | ✅ | EventID 6416/4663 + DataSecurity Plus | Existing |

### 2.12 Scheduled Task Events (`scheduledTasks`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Task Name, Action, Trigger, Author, Result | ✅ | EventID 4698/4699/4700/4701/4702 | Existing |

---

## 3. IP Entity (`ip-tor`, `ip-internal`)

Tabs: **Overview · Threat Intel · Connections · Logon Activity**

### 3.1 Risk Summary (`riskSummary`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| "Tor Exit Node: Confirmed" | 🟡 | Log360 Threat Analytics + Tor consensus list | Internal TI cache |
| Threat Feeds Flagged (5) | ✅ | Threat Analytics aggregator | Existing |
| Active Connections | ✅ | ES agg over firewall/IDS | Existing |
| VirusTotal Detections (12/89) | ❌ | Not in product | — |

### 3.2 IP Details (`ipDetails`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| IP, Version, Type (Tor/Public/Private/VPN) | 🟡 | Threat Analytics + RFC1918 check | Existing + heuristic |
| Reverse DNS (PTR) | 🟡 | DNS server logs / live `dig` | Existing or live |
| Country, City | ✅ | MaxMind GeoIP (bundled) | Existing |

### 3.3 Geo Context (`geoContext`)
Same fields as §3.2 country/city + ASN. Map widget feeds from MaxMind. ✅.

### 3.4 Threat Intelligence (`threatIntelligence`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Detection counts per vendor | 🟡 | Internal TI aggregator (Webroot, Anomali, OTX) | Existing |
| Feed name, Category, Confidence, Last Updated | ✅ | Threat Analytics module | Existing |

### 3.5 Connection History (`connectionHistory`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Direction, Source/Dest IP, Port, Bytes, Duration, Action, Device | ✅ | Firewall syslog (PA, Fortinet, Checkpoint, Cisco ASA) | Existing parsers |

### 3.6 Firewall Action Summary (`firewallSummary`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Allow / Deny / Drop counts (24h) | ✅ | ES agg on firewall logs | Existing |

### 3.7 DNS Query History (`dnsHistory`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Domain, Record Type, Resolution, Querying Process, Source (Sysmon EID 22) | ✅ | Sysmon EID 22 + DNS server logs | Existing |

### 3.8 IDS/IPS Alerts (`idsAlerts`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Signature, Threat ID, Severity, Action, Source device | ✅ | Snort/Suricata/PaloAlto Threat Prevention syslog | Existing |

### 3.9 Associated Users / Devices (`associatedUsers`, `associatedDevices`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Pivot from IP → all users/devices that authenticated from / connected to this IP | ✅ | ES `terms` agg on auth logs filtered by IP | Existing |

### 3.10 VPN Sessions (`vpnSessions`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| User, Assigned IP, Tunnel type, Duration | ✅ | VPN gateway syslog | Existing |

### 3.11 Traffic Summary (`trafficSummary`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Total bytes in/out, Top protocols, Top destinations | ✅ | ES agg | Existing |

---

## 4. DOMAIN Entity (`domain-c2`)

Tabs: same as IP (Overview · Threat Intel · Connections · Logon Activity).

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Domain, Record Type, Resolved IPs | ✅ | DNS logs + Sysmon EID 22 | Existing |
| Threat Intel verdict | 🟡 | Internal TI aggregator | Existing |
| Domain age | ❌ | Not in product | — |
| Hosting / certificate (TLS issuer, validity) | 🟡 | Network sensor TLS metadata if Zeek/NDR present | Optional |
| Associated processes (which exe queried this domain) | ✅ | Sysmon EID 22 | Existing |
| Connection history (same as §3.5) | ✅ | Firewall + Zeek | Existing |

---

## 5. SERVICE Entity (`svc-azure-ad`, `svc-sharepoint`, `svc-oauth`, `svc-winupdatesvc`)

Tabs: **Overview · Config & Policy · Activity · Alerts & Response**

### 5.1 Service Details (`serviceDetails` / `serviceInfo`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Service / Tenant / Workload name | ✅ | M365 Manager Plus tenant config | Existing |
| Service Type (IDP, SaaS, Storage, OS-service) | ✅ | Internal classification | Existing |

### 5.2 OAuth App Consent Grants (`oauthConsentGrants`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Operation, App, Consenting User, Permissions, Source IP, Admin Consent | ✅ | Entra ID audit log (`Consent to application`) | M365MP |

### 5.3 Admin Activity on Service (`adminActivity`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Operation, Target, Caller, Workload, Source IP | ✅ | Unified Audit Log (Entra/Exchange/SharePoint) | M365MP |

### 5.4 Conditional Access Policies (`conditionalAccess`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| State (Enabled/Report-Only/Disabled), Scope, Conditions, Grant, Exclusions, Last Modified | ✅ | Graph API `conditionalAccessPolicies` | M365MP |

### 5.5 Sign-In Audit (`signInAudit`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| User, IP, Location, App, MFA result, Risk, Result | ✅ | Entra ID Sign-in logs | M365MP |

### 5.6 DLP Policies (`dlpPolicies`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Policy name, Scope, Action, Last triggered | ✅ | Defender for Cloud Apps DLP / Purview | Existing connector |

### 5.7 File Access Anomaly / Sensitive Files (`fileAccessAnomaly`, `sensitiveFiles`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| File, User, Operation, Sensitivity tag | ✅ | SharePoint audit + Purview labels | M365MP |

### 5.8 Service Timeline / Network Connections / File Drops / WMI / Processes (when service is OS-resident)

All ✅ from Sysmon (EID 1, 3, 11, 19, 22) when the "service" is an on-host artifact like `WinUpdateSvc`. AI enrichment same as §1.4 / §1.12.

### 5.9 Recent Alerts / Service Triggered

Same as §1.6.

---

## 6. PROCESS Entity (`proc-powershell`)

Tabs: **Overview · Anomalies · Activity**

### 6.1 Risk Summary (`riskSummary`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| AMSI Detections (count), C2 Connection (Active), Payload (filename), Encoded Commands, Obfuscation type, Child processes | ✅ | Sysmon (EID 1, 3, 11), AMSI provider events (EID 4104) | Existing |

### 6.2 Process Details (`processDetails`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Process Name, PID, Parent, Cmdline, User, Integrity, Start, Status, Signature (publisher, validity), Session ID, Threads, Handles | ✅ | Sysmon EID 1 + EID 8 | Existing |

### 6.3 Process Tree (`processTree`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Level (Grandparent/Parent/Current/Child), User, Started, Cmdline, Status, Notes | ✅ | Sysmon EID 1 chain | Existing |

### 6.4 Child Processes (`childProcesses`)
Same as §6.3 but filtered to direct children. ✅.

### 6.5 AMSI Events (`amsiEvents`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Detection (Suspicious/Malicious), Content Preview, Scan Result, Action, Script Block ID | ✅ | EventID 4104 (PowerShell ScriptBlock) + AMSI provider | Existing |

### 6.6 Token Anomaly / Token Usage (`tokenAnomaly`, `tokenUsage`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| SeDebugPrivilege, SeImpersonate, NewToken events | ✅ | EventID 4672 + Sysmon EID 8 (CreateRemoteThread) | Existing |

### 6.7 Registry Modifications (`registryModifications`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Key, Operation (Set/Delete), Old/New Value | ✅ | Sysmon EID 12/13/14 | Existing |

### 6.8 Named Pipes (`namedPipes`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Pipe Name, Operation (Create/Connect), Process | ✅ | Sysmon EID 17/18 | Existing |

### 6.9 Network Activity (`networkActivity`)
Same as §1.12, scoped to the process. ✅ from Sysmon EID 3.

### 6.10 File Operations (`fileOperations`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Operation (Create/Modify/Delete), Path, Hash | ✅ | Sysmon EID 11 + ADAP File Server | Existing |

### 6.11 DLL Loads (`dllLoads`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| DLL Name, Path, Signed?, Loaded at | ✅ | Sysmon EID 7 | Existing (if EID 7 enabled — high-volume) |

### 6.12 Process DNS Queries (`processDnsQueries`)
Same as §1.12 DNS row, scoped to the process. ✅ from Sysmon EID 22.

---

## 7. ALERT Entity (`alert-impossible-travel` and 10 sibling alert entities)

Tabs: **Overview · Scope · Response**

### 7.1 Alert Details (`alertDetails`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Alert ID, Name, Severity, MITRE Tactic+Technique, Detection Type, First Triggered, Last Updated, Source Service, Status | ✅ | `ITSAlertProfileConfigurations` + correlation engine result | Existing |

### 7.2 Trigger Conditions (`triggerConditions`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Rule Name, Rule Type (Correlation/UEBA/Threat-Intel), Conditions, Threshold, Window | ✅ | Rule-engine config (`CorrelationRules` / UEBA model metadata) | Existing |

### 7.3 Affected Entities (`affectedEntities`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| KV map of `{entity-id: role}` (Source, Target, Indicator, …) | ✅ | Alert-instance entity links | Existing |

### 7.4 Correlated Alerts (`correlatedAlerts`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Alert name, Source, Severity, MITRE | ✅ | Alert-correlation graph (existing) | Existing |

### 7.5 Service Triggered / Recent Alerts
Same as §1.5 / §1.6 but scoped to this alert's response actions.

### 7.6 Recommendations & Remediation
Same as §1.22 — primarily 🤖✚ AI-generated.

---

## 8. EDGE RELATION Slider — Data Source & AI Enrichment Mapping

> **What it is**: When a user clicks an edge icon (📡 / 🔐 / 📁 / etc.) on the attack graph, a side slider opens with enriched connection details between two entities (e.g., `user-m-henderson → AccessedFile → svc-sharepoint`). This section maps every field shown to its backend source and AI-enrichable extension.
>
> **Interaction model**:
> - Click edge icon on graph → `showEdgeRelation(evt, el)` in [`js/v4-extras.js`](js/v4-extras.js#L341)
> - Source / target entity pills in the flow header are clickable → `openEntitySlider(id)`
> - Edge slider reuses the same DOM panel as the entity slider
>
> **Data store**: `EDGE_ATTRIBUTES` in [`js/v4-extras.js`](js/v4-extras.js#L82) — keyed by `"source→target"` string; **16 demo edges**.
> **Catalog**: 24 canonical relations + 7 legacy aliases — see [relation_catalog.md](relation_catalog.md). Relation lookup goes through `canonicalRelation(label)` so legacy `data-label` strings still resolve.

### 8.1 Flow Diagram (Source → Relation → Target)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Source/Target Entity Icon | ✅ | `ENTITY_DISPLAY[id].icon` ([display-config.js](js/data/display-config.js)) | Lookup from graph node data |
| Source/Target Entity Name | ✅ | Node ID → `fmtName()` | Strips `user-`/`ip-`/`dev-`/`svc-`/`alert-`/`proc-`/`domain-` prefix and hyphens |
| Relation Label | ✅ | `EDGE_ATTRIBUTES[key].relation` (canonical via `canonicalRelation()`) | Stored per edge |
| Relation Color / Icon | ✅ | `REL_GUIDE[relation].color` / `.icon` | 24 canonical relations across 7 categories |
| Source/Target clickable | ✅ | `openEntitySlider(id)` | Same handler as graph node click |

### 8.2 Relation Description (`REL_GUIDE`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Description text (1–2 sentences explaining the relation type) | ✅ | `REL_GUIDE[key].desc` | Static catalog (24 entries) |
| Category badge (Detection / Identity / Privilege / Data Movement / Network / Process / Email / System Change) | ✅ | `REL_GUIDE[key].category` | Static catalog |

### 8.3 MITRE ATT&CK Mapping

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Tactic Name + ID (e.g. `Initial Access` / `TA0001`) | ✅ | `ITSDetectionRuleVsMitre.TACTIC` / `.TACTIC_ID` | Mapped from triggering detection rule |
| Technique Name + ID (e.g. `Valid Accounts` / `T1078`) | ✅ | `ITSDetectionRuleVsMitre.TECHNIQUE_NAME` / `.TECHNIQUE_ID` | Same as above |
| Sub-technique (e.g. `T1078.004`) | 🟡 | When mapped per-rule | Same source, sub-technique field |

> **Conditional**: Only RULE-type alert edges have native MITRE. Correlation/UEBA edges may not — AI can fill gaps by classifying the raw evidence against ATT&CK.

### 8.4 Detection Rule

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Rule Name (e.g. `Impossible Travel Detection`) | ✅ | `ITSAlertProfileConfigurations.DISPLAY_NAME` | DB lookup by alert ID |
| Rule Type (`Correlation` / `Anomaly (UEBA)` / `Threat Intel`) | ✅ | `ITSAlertProfileConfigurations.ALERT_TYPE` | Same |
| Rule ID (e.g. `CR-0042`) | ✅ | `ITSAlertProfileConfigurations.ALERT_PROFILE_ID` | Internal ID |

### 8.5 Connection Properties

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Event Count (`count`) | ✅ | `ZLogs COUNT(*)` between source→target in time window | ES range query |
| Risk Score (0–100) | ✅ | `ITSEntityRiskScoreDetails.RISK_SCORE` (combined source+target) | Existing scorer |
| Risk Bar (color: green/yellow/orange/red) | ✅ | Computed client-side from risk | Threshold mapping |
| Data Volume (e.g. `4.2 MB`) | 🟡 | `ZLogs SUM(BYTES_SENT + BYTES_RECEIVED)` | Available for FW/proxy/DLP logs only |
| First Seen / Last Seen | ✅ | `ZLogs MIN/MAX(_zl_timestamp)` | ES min/max agg |

### 8.6 Event Distribution (Sparkline, 12 buckets)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| 12-bucket sparkline (`sparkline:[…]`) | ✅ | `ZLogs COUNT(*) GROUP BY time_bucket` | 1-hour window / 12 × 5-min buckets |
| Total Events | ✅ | `SUM(buckets)` | Client-side |
| Time-axis labels | ✅ | Computed from `lastSeen − N×5min` | Client-side |
| Average line | ✅ | `total / 12` | Client-side |
| Peak marker | ✅ | `MAX(buckets)` | Client-side |
| Hover tooltip (per-bucket count) | ✅ | Same data | Client-side |

> **Backend API needed**: One endpoint `(source, target, relation, time_range)` → `{count, buckets[]}`. No new infra — existing ZLogs aggregation.

### 8.7 Behavioral Baseline (UEBA)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Expected (learned baseline) | ✅ | `DashBoardAnomalyDataProvider` (UEBA) | 30/90-day rolling-window model |
| Actual (observed in window) | ✅ | Same as event count | ES query |
| Deviation (`actual / expected`) | ✅ | Computed | Client-side |
| Severity classification (Normal ≤ 1.3×, Warning 1.3–2×, Danger > 2×, **First Occurrence**) | ✅ | `AnomalyDetectionDataImpl` thresholds | Existing |
| Visual dual bars (Expected vs Actual) | ✅ | Client-side | Same data |

### 8.8 Threat Intelligence (conditional, when edge involves an external IOC)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Vendor (`Webroot`, `Anomali`, `OTX`, etc.) | ✅ | `ThreatAnalyticsIntermediateProcessor` | Internal TI aggregator |
| Reputation Score (1=Critical / 2=Malicious / 3=Suspicious) | ✅ | `ES THREAT_REPUTATION` | Existing |
| Label (Critical / Malicious / Suspicious) | ✅ | Derived from score | Client-side |
| VirusTotal Detection (`62/94`) | ❌ | Not in product | — |
| Domain Age (WHOIS) | ❌ | Not in product | — |
| Passive DNS (other historical resolutions) | 🟡 | Internal cache (limited) | Existing partial |

### 8.9 Geo Context (conditional, when edge involves an external IP)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Country flag + name | ✅ | MaxMind GeoIP → emoji map | Bundled DB |
| City | 🟡 | MaxMind GeoLite2-City | City accuracy varies |
| ASN / ISP / Hosting Provider | 🟡 | Optional MaxMind ASN DB | Existing if licensed |
| IP Address | ✅ | `ES REMOTEIP` / `SrcIP` | Raw log |

### 8.10 Evidence (the AI-most-valuable section)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Summary (1-line) | ✅ | `EDGE_ATTRIBUTES.evidence.summary` (currently authored) | Composed from `ITSAlertProfileConfigurations.DESCRIPTION` + context |
| Findings (chips: distance, count, protocol, anomaly) | ✅ | `EDGE_ATTRIBUTES.evidence.findings[]` | Authored / extracted |
| Confidence Score (%) | 🟡 | Multi-signal aggregator (rule + UEBA + TI) | Logic to be built |
| Confidence Bar (green/yellow/orange/gray) | ✅ | Visual from confidence | Client-side |
| Severity Bar (Critical / High / Medium / Low) | ✅ | Derived from edge `risk` | Client-side |
| Source Badge (`Azure AD Sign-in Logs`, `Firewall + IDS`, …) | ✅ | `EDGE_ATTRIBUTES.source` | Authored per edge |
| Event Count Badge | ✅ | `EDGE_ATTRIBUTES.count` | Same as §8.5 |
| Raw Log preview | ✅ (data) / 🟡 (UI) | `EDGE_ATTRIBUTES.evidence.rawLog` | Stored in catalog, currently **not rendered** |

### 8.11 Per-Edge Authored Properties (for `EDGE_ATTRIBUTES` in V5)

These are the actual fields populated for each of the 16 demo edges in [v4-extras.js](js/v4-extras.js#L82):

| Property | Type | Required? | Example |
|----------|------|-----------|---------|
| `relation` | string (canonical) | ✅ | `'CommunicatedWith'` |
| `count` | number | ✅ | `47` |
| `risk` | number 0–100 | ✅ | `96` |
| `firstSeen` / `lastSeen` | ISO-ish string | ✅ | `'03 Apr 2026 15:20:05'` |
| `evidence.summary` | string | ✅ | `'Reverse shell traffic, 47 C2 beacon attempts detected'` |
| `evidence.findings[]` | string[] | ✅ | `['47 beacons in 5 min', 'Fixed interval: 6.3s ±0.2s', …]` |
| `evidence.confidence` | number 0–100 | ✅ | `99` |
| `evidence.rawLog` | string | optional | `'IDS \| Alert=ReverseShell \| SrcIP=185.220.101.42 \|
| `detectionRule.{name,type,id}` | object | optional | `{name:'C2 Beacon Pattern Detection', type:'Correlation', id:'CR-0101'}` |
| `mitre.{tactic,tacticId,technique,techId}` | object | optional | `{tactic:'Command and Control', tacticId:'TA0011', …}` |
| `threatIntel.{vendor,reputation,label,virusTotal}` | object | optional | `{vendor:'Webroot', reputation:2, label:'Malicious', virusTotal:'18/94'}` |
| `geo.{flag,country,city,ip}` | object | optional | `{flag:'🇷🇴', country:'Romania', city:'Bucharest', ip:'185.220.101.42'}` |
| `sparkline` | number[12] | optional | `[0,0,0,0,0,0,0,0,5,12,18,12]` |
| `baseline.{expected,actual,deviation}` | object | optional | `{expected:0, actual:47, deviation:null}` (`null` = first occurrence) |
| `dataVolume` | string | optional | `'4.2 MB'` |
| `source` | string | optional | `'Firewall Logs + IDS'` |

### 8.12 Demo Edge Inventory (16 in V5)

| `source→target` | Relation | Risk | Source |
|------------------|----------|------|--------|
| `alert-impossible-travel → user-m-henderson` | `TriggeredBy` | 95 | (correlation engine) |
| `alert-impossible-travel → svc-azure-ad` | `DetectedOn` | 95 | Azure AD Sign-in Logs |
| `user-m-henderson → ip-tor` | `AccessedFrom` | 92 | Azure AD Sign-in Logs |
| `user-m-henderson → ip-internal` | `AccessedFrom` | 15 | VPN Gateway Logs |
| `user-m-henderson → svc-azure-ad` | `LoginTo` | 78 | Azure AD Sign-in Logs |
| `ip-internal → dev-ws045` | `ResolvedTo` | 10 | DHCP Server Logs |
| `user-m-henderson → svc-sharepoint` | `AccessedFile` | 88 | SharePoint Audit Logs |
| `svc-azure-ad → svc-oauth` | `IssuedTo` | 85 | Azure AD Audit Logs |
| `user-admin → svc-azure-ad` | `LoginTo` | 86 | Azure AD Sign-in Logs |
| `ip-tor → dev-ws045` | `CommunicatedWith` | 96 | Firewall Logs + IDS |
| `dev-ws045 → svc-sharepoint` | `AccessedFile` | 90 | SharePoint Audit Logs |
| `user-m-henderson → dev-ws045` | `LoginTo` | 45 | Windows Security Event Logs |
| `dev-ws045 → user-admin` | `EscalatedTo` | 88 | Windows Security + Sysmon |
| `svc-oauth → svc-sharepoint` | `AccessedFile` | 88 | SharePoint API Audit |
| `ip-tor → domain-c2` | `CommunicatedWith` | 98 | DNS Logs + Firewall |
| `dev-ws045 → domain-c2` | `CommunicatedWith` | 97 | Sysmon + Firewall |

### 8.13 Edge Data Source Summary

| Data Type | Primary Source | Availability | AI Augmentation |
|-----------|---------------|--------------|------------------|
| Event Count | `ZLogs COUNT(*)` agg | ✅ Exists | — |
| Event Distribution (sparkline) | `ZLogs COUNT(*) GROUP BY time_bucket` | ✅ Exists | 🤖✚ Pattern-shape labelling |
| Behavioral Baseline | UEBA `DashBoardAnomalyDataProvider` | ✅ Exists | 🤖✚ Baseline rationale |
| Risk Score | `ITSEntityRiskScoreDetails` | ✅ Exists | 🤖✚ Path-criticality rerank |
| First/Last Seen | `ZLogs MIN/MAX(_zl_timestamp)` | ✅ Exists | — |
| MITRE Mapping | `ITSDetectionRuleVsMitre` | 🟡 RULE-type only | 🤖 Fill gaps for UEBA/correlation |
| Detection Rule | `ITSAlertProfileConfigurations` | ✅ Exists | 🤖✚ Plain-English explanation |
| Threat Intel | `ThreatAnalyticsIntermediateProcessor` + VT | 🟡 Limited vendors | 🤖 VT, GreyNoise, urlscan, ThreatFox, Censys, Shodan |
| Geo Context | MaxMind + `ES GEO_COUNTRY` | 🟡 Country reliable, city varies | 🤖 IPinfo / ipdata.co for ASN |
| Evidence Summary | Alert description + context | 🟡 Authored | 🤖✚ **Auto-generated** from raw logs |
| Evidence Findings | Authored chips | 🟡 Authored | 🤖✚ Auto-extracted |
| Confidence Score | Multi-signal aggregator | 🟡 Logic TBD | 🤖✚ Cross-signal agreement |
| Data Volume | `ZLogs SUM(BYTES)` | 🟡 FW/proxy/DLP only | 🤖✚ Estimate from event metadata |
| Raw Log Explanation | `EDGE_ATTRIBUTES.rawLog` | ✅ Stored | 🤖✚ Field-by-field explainer |

---

## 9. Cross-Cutting AI-Enrichment Patterns

These are patterns **AI can apply to any field**, not specific to one entity:

| Pattern | Description | Example |
|---------|-------------|---------|
| **Live IOC enrichment** | On-demand call to VT/urlscan/Webroot/OTX/GreyNoise | Any IP/domain/hash field |
| **WHOIS / passive DNS** | Domain age, registrar, historical resolutions | Any domain field |
| **Geo + ASN enrichment** | MaxMind/IPinfo for any IP | Any IP field |
| **MITRE ATT&CK mapping** | Map raw event → tactic/technique/sub-technique | Any process/login/registry event |
| **Natural-language summarization** | Convert log noise into a narrative paragraph | Any timeline section |
| **Kill-chain reconstruction** | Order all alerts/events into a TTP timeline | `recentAlerts`, `correlatedAlerts` |
| **Verdict + recommendation generation** | Synthesize "Compromised / Insider / FP" + next steps | `riskSummary.statusBadge`, `remediationGuide` |
| **Rule explanation** | Translate detection rule → plain English | `triggerConditions` |
| **Anomaly rationale** | Explain *why* a `dot:'red'` was assigned | Any `dot` field in timelines |
| **Compliance evidence chain** | Map evidence → control IDs → notification text | `complianceImpact` |
| **Playbook ranking + pre-fill** | Pick best playbook, pre-fill variables | `remediationGuide.playbooks` |
| **Sensitivity classification** | Filename/path → PII/PCI/PHI label | `resourceFileAccess`, `sensitiveFiles` |
| **Toxic-combination detection** | Group memberships → privilege escalation chain | `identityRisk.privilegedGroups` |

---

## 10. Section → Entity-Type Cross-Reference

Quick lookup: which sections appear in which entity tab.

| Section Key | Entity Type(s) | Tab |
|-------------|----------------|-----|
| `riskSummary` | user, device, ip, domain, service, process | Overview |
| `usersDetails` | user | Overview |
| `deviceDetails` | device | Overview |
| `ipDetails`, `geoContext` | ip, domain | Overview |
| `serviceDetails`, `serviceInfo` | service | Overview |
| `processDetails` | process | Overview |
| `alertDetails`, `triggerConditions` | alert | Overview |
| `uebaProfile`, `loginStatistics`, `cloudIdentities`, `identityRisk`, `privilegedRoleChanges`, `threatIntelContext`, `dlpIncidents` | user | Risk & Identity |
| `logonActivity`, `networkActivity`, `processes`, `serviceTriggered`, `resourceFileAccess`, `recentAppAccess` | user | Activity |
| `accountLockouts`, `passwordHistory`, `groupMembershipChanges`, `mailboxForwarding` | user | Account Changes |
| `recentAlerts` | user, device, service, process | (varies) |
| `agentStatus`, `gpoApplied`, `securityEventSummary` | device | Overview |
| `processesOnHost`, `servicesOnHost`, `usersLoggedOn`, `loginActivity` | device | Host Activity |
| `scheduledTasks`, `usbDeviceEvents` | device | Persistence & Exfil |
| `threatIntelligence`, `idsAlerts`, `firewallSummary` | ip, domain | Threat Intel |
| `connectionHistory`, `dnsHistory`, `vpnSessions`, `trafficSummary`, `associatedUsers`, `associatedDevices` | ip, domain | Connections |
| `oauthConsentGrants`, `conditionalAccess`, `dlpPolicies` | service | Config & Policy |
| `signInAudit`, `adminActivity`, `fileAccessAnomaly`, `sensitiveFiles`, `serviceTimeline`, `networkConnections`, `fileDrops`, `wmiEvents` | service | Activity |
| `processTree`, `childProcesses` | process | Overview |
| `tokenAnomaly`, `amsiEvents`, `registryModifications`, `namedPipes` | process | Anomalies |
| `tokenUsage`, `fileOperations`, `dllLoads`, `processDnsQueries` | process | Activity |
| `affectedEntities`, `correlatedAlerts` | alert | Scope |
| `complianceImpact` | user (extensible to others) | (currently inline) |
| `remediationGuide` | user, alert | (last section) |

---

## 11. Field-Status Summary

Across the V5 prototype:

| Status | Count (approx) | Notes |
|--------|----------------|-------|
| ✅ Available in product | ~80% | Most timeline/KV fields map to existing ES indices, AD attributes, M365 audit logs, or Sysmon events |
| 🟡 Partial / needs aggregation | ~12% | Mainly aggregator fields (peer-baseline %, threat-intel verdict aggregation) and compliance mappings |
| ❌ Not in product | ~5% | VirusTotal scores, domain age (WHOIS), AI-generated recommendations / verdicts |
| 🤖 AI-enrichable | **every section has at least one AI angle** | See §8 cross-cutting patterns |

---

## 12. Implementation Priority (AI-First)

If we ship AI augmentation, the highest-leverage fields to target first:

1. **Verdict + recommendations** (`statusBadge`, `remediationGuide.verdict`) — pure AI, no backend change, immediate UX win.
2. **`dot` rationale** — explain why each timeline entry is red/orange/green. Pure AI over already-collected data.
3. **Kill-chain narrative** for `recentAlerts` / `correlatedAlerts` — AI on existing alert links.
4. **Live IOC enrichment** for IP / domain / hash fields — adds VT, WHOIS, GreyNoise without backend changes.
5. **Compliance evidence + notification draft** (`complianceImpact`) — high analyst time-saver.
6. **Script deobfuscation** (`amsiEvents`) — AI reads encoded PowerShell content already collected, returns plain-English summary.
7. **Conditional Access "what-if"** — AI evaluates whether report-only policies would have stopped the attack.
8. **Playbook ranking + pre-fill** — AI picks the right playbook and fills variables.

---

## 13. Code References

| Artifact | File | Purpose |
|----------|------|---------|
| Entity definitions (20) | [`js/data/entities.js`](js/data/entities.js) | All entities + their `sections` |
| Tab config (6 entity types) | [`js/modules/entity-slider.js`](js/modules/entity-slider.js) | Tab → section mapping |
| Display config (icons, colors, names) | [`js/data/display-config.js`](js/data/display-config.js) | `ENTITY_DISPLAY` |
| Quick-card row config | [`js/modules/entity-quick-card.js`](js/modules/entity-quick-card.js) | Hover-card rows per entity type |
| Edge attributes (per-edge enrichment) | [`js/v4-extras.js`](js/v4-extras.js) | `EDGE_ATTRIBUTES` keyed by `source→target` |
| Relation catalog (24 canonical edges) | [`relation_catalog.md`](relation_catalog.md) | Edge taxonomy |

---

## 14. Changelog

| Date | Change |
|------|--------|
| 07 May 2026 | Added §8 EDGE RELATION Slider data-source mapping (13 sub-sections covering flow diagram, MITRE, detection rule, connection properties, sparkline, behavioral baseline, threat intel, geo, evidence, per-edge schema, demo inventory of 16 edges, data-source summary). Renumbered subsequent sections 8→13. |
| 07 May 2026 | Initial V5 mapping. Mirrors V4 structure but adds explicit **AI Enrichment** column showing what AI agents can fetch beyond product backend (live IOC enrichment, WHOIS, MITRE mapping, narrative generation, compliance drafting, script deobfuscation). Covers 8 entity types, ~50 distinct sections. Cross-references the canonical relation catalog. |
