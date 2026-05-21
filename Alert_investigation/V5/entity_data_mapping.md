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
| **device** | Overview · Host Activity · Device Activity · Alerts & Response | `dev-ws045` (implicit; see processes/services) |
| **ip** | Overview · Threat Intel · Connections · Logon Activity | `ip-tor`, `ip-internal` |
| **domain** | Overview · Threat Intel · Connections · Logon Activity | `domain-c2` (implicit) |
| **service** | Overview · Config & Policy · Activity · Alerts & Response | `svc-azure-ad`, `svc-sharepoint`, `svc-oauth`, `svc-winupdatesvc` |
| **process** | Overview · Anomalies · Activity | `proc-powershell` |
| **alert** | Overview · Scope · Response | 11 alert entities (`alert-impossible-travel`, `alert-oauth-token`, …) |

---

## 1. USER Entity (`user-m-henderson`, `user-admin`)

Tabs: **Overview · Risk & Identity · Activity · Account Changes · Recent Alerts**

### 🗂️ Tab — Overview

> Sections in this tab: `riskSummary` · `usersDetails`

#### 1.1 Risk Summary (`riskSummary`)

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

#### 1.2 User Details (`usersDetails`)

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
| Primary Group | ✅ AD (with join) · ❌ Entra | **One column + one join** — see [§1.2.1](#121-primary-group--one-column-one-join) below. `APFDiscADUserDetails` stores `PRIMARY_GROUP_ID` (the RID, e.g. `513`) and `PRIMARY_GROUP_GUID` (the group's OBJECT_GUID, manifest priority 100). Neither is the display name `"Domain Users"`. To resolve, join against [`APFDiscADGroupDetails`](../../../REPOS/ADSF-DD-DML/product_package/conf/adsf/common/appfw/discovery/application/ad/data-dictionary.xml) (same APF discovery, already in cloud schema) on `OBJECT_GUID = u.PRIMARY_GROUP_GUID`, return `GROUP_NAME`. Entra has no primary-group concept — `GROUP_COUNT` only; full membership lives in a separate APF group-membership table. | Direct read + 1 join |

> **Implication for the demo (corrected):** All 12 m.henderson User Details fields are now sourced from `APFDiscADUserDetails` directly with no two-table fallback needed for AD users. Only one caveat remains: for Entra-only tenants, **Last Logon Time** requires an ES side-call into M365 SignInLogs (retention-bounded). For mixed tenants the slider should pick the path based on the discovered identity source.

##### 1.2.1 Primary Group — one column, one join

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

### 🗂️ Tab — Risk & Identity

> Sections in this tab: `uebaProfile` · `loginStatistics` · `cloudIdentities` · `identityRisk` · `threatIntelContext` · `dlpIncidents`

#### 1.8 UEBA Risk Profile (`uebaProfile`)

**Source of truth.** All six fields are read by the existing query [`L3CUEBAUtil.formRiskScoreSelectQuery()`](../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/ueba/dashboard/util/L3CUEBAUtil.java#L143-L159) (single `INNER JOIN` between `ITSEntityRiskScoreDetails` ↔ `ADSAnomalyDetectionUniqueEntities` on `ENTITY_ID`) plus the notes CRUD already wired in the same class ([`addNote()`](../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/ueba/dashboard/util/L3CUEBAUtil.java#L606), [`editNote()`](../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/ueba/dashboard/util/L3CUEBAUtil.java#L619), [`deleteNote()`](../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/ueba/dashboard/util/L3CUEBAUtil.java#L654)). **Zero new tables, zero new joins.**

| # | Field | Sample value | Source column | Verdict |
|---|-------|--------------|---------------|---------|
| 1 | Risk Score | `94 / 100 — Critical` | `ITSEntityRiskScoreDetails.RISK_SCORE × 100` (mirrors [`getEntityRiskScore()`](../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/ueba/dashboard/util/L3CUEBAUtil.java#L668-L672)) | ✅ already selected |
| 2 | Last anomaly fired | `12 May 2026 09:14 (2h ago)` | `ITSEntityRiskScoreDetails.LAST_ANOMALY_UPDATE_TIME` (epoch ms) — used as sort key in [`recentlyDetectedEntities()`](../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/ueba/dashboard/util/L3CUEBAUtil.java#L208) | ✅ already selected |
| 3 | Last score update | `13 May 2026 03:00` | `ITSEntityRiskScoreDetails.LAST_UPDATE_TIME` | ✅ already selected |
| 4 | Under Observation | `Yes` / `No` | `ADSAnomalyDetectionUniqueEntities.IS_SURVEILLED` (BOOLEAN, default false) — see [anomalydetection/data-dictionary.xml#L154-L159](../../REPOS/ADSF-DD-DML/product_package/conf/adsf/common/anomalydetection/data-dictionary.xml#L154-L159) | ✅ already selected |
| 5 | Source | `Windows Event Log Collector` (which feed first flagged this entity) | `ADSAnomalyDetectionUniqueEntities.SOURCE` | ✅ already selected |
| 6 | Analyst notes | `"Investigated 11 May — escalated to T2" — j.doe, 11 May` `[+ Add note]` | `UEBAEntityNotes.NOTE` + `CREATION_TIME` + `CREATED_USER_ID → AaaUser` ([dashboard/ueba/data-dictionary.xml#L55-L115](../../REPOS/itsf/product_package/conf/itsf/common/dashboard/ueba/data-dictionary.xml#L55-L115)) | ✅ CRUD already exists; needs a read query on the card |

**Renamed.** "Watchlist" → **"Under Observation"** — clearer analyst phrasing for the same `IS_SURVEILLED` boolean.

**Removed from earlier mock.**
- `Anomalies Detected: 7` — bare integer dropped; the count is conveyed by the score itself plus the alerts/anomaly tabs.
- `Account Type: Standard User` — moved to §1.11 `identityRisk` (it's an AD-membership derivation, not a UEBA scorer output).

**Gaps to flag (not claiming on this card).**
- **Score breakdown** (`MODIFIED_SCORE × SEVERITY_SCORE × DECAY_FACTOR`) — columns exist on `ITSEntityRiskScoreDetails` but are not selected by `formRiskScoreSelectQuery()`. Adding them is a small `addSelectColumn` change, not a free read.
- **Lifetime vs session score** (`OVERALL_RISK_SCORE`, `OVERALL_DETECTION_COUNT`) — same situation: real columns, not currently selected.
- **"Watchlisted by `<user>` on `<date>`"** — schema gap. `ADSAnomalyDetectionUniqueEntities` has only the `IS_SURVEILLED` boolean; no `SURVEILLED_BY` / `SURVEILLED_TIME` columns.

#### 1.9 Login Statistics (7 days) (`loginStatistics`)

**Source of truth.** Elasticsearch — Windows Security log index. Queried live via `ZLogsQueryExecutorImpl` + `ZLogsUtil.executeAndRetrieveData()` (the generic ES wrapper used across the product, also used by UEBA — see [`L3CUEBAUtil.getZLogsQueryExecutor()`](../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/ueba/dashboard/util/L3CUEBAUtil.java#L84)). **No DB read, no pre-aggregation, no schema additions.**

| # | Field | Sample value | ES filter | ES aggregation |
|---|-------|--------------|-----------|----------------|
| 1 | Total Logins | `47` | `USERNAME=u AND EVENTID IN (4624,4625)` | `numFound` |
| 2 | Successful | `43 (91.5%)` | same as #1 | `groupBy EVENTID` → bucket `4624` |
| 3 | Failed | `4 (8.5%)` | same as #1 | `groupBy EVENTID` → bucket `4625` |
| 4 | Unique Source IPs | `3 (192.168.1.22, 10.18.1.81, 10.112.11.1)` | `USERNAME=u AND EVENTID=4624` | `groupBy IPADDRESS` → bucket count + top |
| 5 | Off-Hours Logins | `2` | `USERNAME=u AND EVENTID=4624` + `setDayHours(L3CWorkingHourHandler.getFromCache(DAY_HOURS, filterId))` | `numFound` |
| 6 | Unique Hosts | `3 (CORP-WS-045, CORP-SRV-01, CORP-FS-02)` | `USERNAME=u AND EVENTID=4624` | `groupBy WORKSTATIONNAME` |

**Calls per card refresh:** 4 ES queries (#1+#2+#3 share one call via `groupBy EVENTID`).

**Caveats**
- Window is **retention-bounded** — "7 days" only works if ES retains ≥7d Windows Security events for the tenant.
- **Username normalization** — events store `DOMAIN\sam` / `sam@upn` / bare `sam` depending on feed. The existing ELA logon-report normalization helper must be reused so all variants count.
- **Off-hours window is config-driven** — uses `L3CWorkingHourHandler` cache (admin-defined business hours), not hardcoded.

#### 1.10 Cloud Identities & Assets (`cloudIdentities`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| UPN | ✅ | M365 Entra discovery | `APFDiscAADUserDetails.USER_PRINCIPAL_NAME` |
| Sync Source | ✅ | M365 Entra discovery | `APFDiscAADUserDetails.ONPREMISES_SYNC_ENABLED` |
| Cloud Account | ✅ | M365 Entra discovery | `APFDiscAADUserDetails.ACCOUNT_ENABLED` + `IS_LICENSED` |
| Last Dir Sync | ✅ | M365 Entra discovery | `APFDiscAADUserDetails.DAYS_SINCE_LAST_DIR_SYNC` |
| Strong Password Required | ✅ | M365 Entra discovery | `APFDiscAADUserDetails.STRONG_PASSWORD_REQUIRED` |
| Days Since Password Change | ✅ | M365 Entra discovery | `APFDiscAADUserDetails.DAYS_SINCE_PASSWORD_CHANGE` |
| Hidden From Address List | ✅ | M365 Entra discovery | `APFDiscAADUserDetails.HIDDEN_FROM_ADDRESS_LIST` |

#### 1.11 Identity Risk Assessment (`identityRisk`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Password Age (days) | ✅ | AD discovery | `APFDiscADUserDetails.PASSWORD_LAST_SET` (now − value) |
| Days Since Last Logon | ✅ | AD discovery | `APFDiscADUserDetails.DAYS_SINCE_LAST_LOGON` |
| Account Status (Enabled/Disabled/Locked) | ✅ | AD discovery | `APFDiscADUserDetails.ACCOUNT_STATUS` + `LOCK_OUT_TIME` |
| Password Never Expires | ✅ | AD discovery | `APFDiscADUserDetails.PWD_NEV_EXP_FLAG` |
| Smartcard Required | ✅ | AD discovery | `APFDiscADUserDetails.SMART_CARD_FOR_INTERACTIVE_LOGIN` |
| Trusted for Kerberos Delegation | ✅ | AD discovery | `APFDiscADUserDetails.TRUSTED_FOR_DELEGATION` |
| Bad Password Count | ✅ | AD discovery | `APFDiscADUserDetails.BAD_PASSWORD_COUNT` |
| Privileged Group Membership | ✅ | AD discovery + well-known SID list | `APFDiscADGroupMemberDetails` join `APFDiscADGroupDetails` on `FRONTLINK_OBJECT_ID = group.UNIQUE_ID` filtered by `SID_STRING LIKE '%-512' / '-519' / '-518' / '-544'` |

#### 1.13 Threat Intelligence Context (`threatIntelContext`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Primary IOC | ✅ | ELA event | Source/Destination IP or domain from the triggering alert event |
| Reputation Verdict (Critical / Malicious / Suspicious) | ✅ | ELA Threat Analytics | `THREAT_REPUTATION.REPUTATION_SCORE` keyed on the IOC (1=Critical, 2=Malicious, 3=Suspicious) |
| Threat Category | ✅ | ELA Threat Analytics | `THREAT_REPUTATION.THREAT_CATEGORY` (e.g. C2, Tor, Phishing, Malware) |
| Threat Feed / Vendor | ✅ | ELA Threat Analytics | `THREAT_REPUTATION.SOURCE` (Webroot BrightCloud / STIX feed / custom) |
| First Seen (Local) | ✅ | ELA Threat Analytics | `THREAT_REPUTATION.FIRST_SEEN_TIME` (first time this IOC was observed by ELA) |
| VirusTotal verdict | 🟡 | Log360 ATA add-on | VT API integration — only if Advanced Threat Analytics module is licensed |
| MITRE Techniques | ✅ | Per-alert-profile mapping | `ITSAlertProfileConfigurations.MITRE_TECHNIQUE_ID` |

### 🗂️ Tab — Activity

> Sections in this tab: `logonActivity` · `networkActivity` · `processes` · `serviceTriggered` · `resourceFileAccess`

#### 1.3 Logon Activity (`logonActivity`) — Timeline

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Timestamp | ✅ | ELA | `TIME` field on the parsed event |
| EventID | ✅ | ELA | `EVENTID` (success: 528 / 540 / 4624; failure: 529-537 / 539 / 4625; logoff: 538 / 4634) |
| Logon Type | ✅ | ELA | `LOGONTYPE` (2=Interactive, 3=Network, 7=Unlock, 10=RemoteInteractive, 11=CachedInteractive) |
| Target Host | ✅ | ELA | `HOSTNAME` (host that received the event) |
| Source IP / Workstation | ✅ | ELA | `IPADDRESS` / `REMOTEHOST` / `WORKSTATION_NAME` |
| Authentication Package | ✅ | ELA | `AUTHENTICATIONPACKAGENAME` (NTLM / Kerberos / Negotiate) |

#### 1.12 Network Activity (24h) (`networkActivity`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Type label | ✅ | ELA | Derived from device-type / log format at parse time |
| DNS Query (Domain, Resolution, Source Host) | ✅ | ELA | Windows DNS Server analytical log OR Sysmon EID 22 — fields parsed into `QUERY_NAME`, `QUERY_RESULTS`, `HOSTNAME` |

#### 1.4 Processes (`processes`) — Timeline (per user-launched processes)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Process Name | ✅ | ELA | Win EID 4688 `New Process Name` OR Sysmon EID 1 `Image` → parsed into `PROCESSNAME` |
| Parent Process | ✅ | ELA | EID 4688 `Creator Process Name` / Sysmon EID 1 `ParentImage` |
| Command Line | ✅ | ELA | EID 4688 (if `ProcessCreationIncludeCmdLine` GPO enabled) / Sysmon EID 1 `CommandLine` |
| Executing User | ✅ | ELA | `USERNAME` + `DOMAIN` on the 4688 / Sysmon-1 event |
| Action: Kill Process | 🟡 | Log360 Incident Workflow → EDR API | Custom workflow calling Defender / CrowdStrike / SentinelOne; **not native** |

#### 1.5 Service Triggered (`serviceTriggered`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Service Name, Display Name | ✅ | ELA | EID 7045 `Service Name` / `Service File Name`; EID 4697 `Subject` + `Service Name` |
| Startup Type, Account | ✅ | ELA | EID 7045 `Service Type` + `Start Type` + `Service Account` |
| Host | ✅ | ELA | `HOSTNAME` of the event |
| Severity | 🟡 | Log360 correlation | Derived from alert profile fired on the 7045 event (not a native field) |
| Action: Stop Service | 🟡 | Log360 Incident Workflow | Custom workflow with `sc stop` / PSRemoting step; **not one-click native** |

#### 1.7 Resource / File Access (`resourceFileAccess`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Host | ✅ | ELA | `HOSTNAME` of the file server |
| File Name / Object Path | 🟡 | ELA + SACL | Win EID 4663 `OBJECTNAME` — requires SACL enabled on the share |
| Change Type | 🟡 | ELA | Derived from EID 4663 `ACCESSMASK` bits (0x1=Read, 0x2=Write, 0x10000=Delete) |
| Accessing Process | ✅ | ELA | EID 4663 `PROCESSNAME` |
| SharePoint / OneDrive activity | 🟡 | M365 Manager Plus | O365 Unified Audit Log; requires M365MP licence |

### 🗂️ Tab — Account Changes

> Sections in this tab: `accountLockouts` · `passwordHistory` · `groupMembershipChanges` · `mailboxForwarding`
>
> **Ingest paths used in this tab:**
> - **Windows agent → ZLogs** — Domain Controller security events parsed by [Windows.xml](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/Windows/Windows.xml) / [WMIWindows-Security.xml](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/Windows/WMIWindows-Security.xml) and indexed into Elasticsearch (ZLogs).
> - **M365 cloud-account → ZLogs** — Tenant onboarded via `M365CustomLogUploadImpl` ([Java](../../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/adminpanel/customlogupload/cloudaccount/M365CustomLogUploadImpl.java)); a scheduler (`/RestAPI/WC/M365ScheduleActions`) polls the **O365 Management Activity API** (`manage.office.com/api/v1.0/{tenant}/activity/feed/subscriptions/content`) for content types `Audit.AzureActiveDirectory`, `Audit.Exchange`, `Audit.General`, `Audit.SharePoint` and ingests every record into the same ZLogs index. Graph is used only for tenant validation.
> - **APF discovery** — Current state (`APFDiscADUserDetails`, `APFDiscADGroupDetails`, `APFDiscAADUserDetails`, `APFDiscAADGroupDetails`) for joins like *current group membership* or *current lockout state*.

#### 1.15 Account Lockouts (`accountLockouts`)

Trigger: Windows EventID `4740` written by the DC that detected the bad-password threshold breach.

| Slider field | Status | ZLogs column | Where it comes from |
|---|---|---|---|
| User | ✅ | `TARGETUSER` | Parser rule `RULE_ID:200160` for `EVENTID=4740` ([Windows.xml L909](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/Windows/Windows.xml)) |
| Locking DC | ✅ | `HOSTNAME` | Envelope — DC that wrote the event |
| Source Computer | ✅ | `REMOTEHOST` | Caller Computer Name extracted by same rule (empty for RDP/service-triggered lockouts) |
| Event ID | ✅ | `EVENTID` = `4740` | Envelope |
| Time | ✅ | `EVENT_TIME` | Envelope |
| Risk label | ✅ | `RISK_LEVEL` = `High`, `IENAME` = `Windows User Account LockedOut` | Set by parser transforms |

> **Not in 4740** — *unlock time*, *unlocked-by*, *cause*, *bad-password trail*. To enrich: query ZLogs for `EVENTID=4767` ([RULE_ID:2502193](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/Windows/WMIWindows-Security.xml)) on the same `TARGETUSER` for unlock; query `EVENTID=4625` in the preceding window for the failed-logon trail; read `APFDiscADUserDetails.LOCK_OUT_TIME` / `BAD_PASSWORD_COUNT` for current state.

#### 1.16 Password Change / Reset History (`passwordHistory`)

Unifies on-prem AD and Microsoft Entra ID (cloud) password events — both land in the same ZLogs index via different ingest paths.

| Slider field | Status | ZLogs column | Where it comes from |
|---|---|---|---|
| Operation | ✅ | derived from `EVENTID` (AD) or `OPERATION` (Entra) | AD: `4723` self-change · `4724` admin-reset (Windows agent). Entra: `Change user password.` · `Reset user password.` (M365 cloud-account, content type `Audit.AzureActiveDirectory`) |
| Caller | ✅ | `USERNAME` + `DOMAIN` (AD) / `USERID` (Entra) | Subject of the 4723/4724 event for AD; `UserId` (acting UPN) for Entra |
| Target | ✅ | `TARGETUSER` (AD) / `OBJECTID` (Entra) | Account whose password was changed |
| Source host | ✅ | `HOSTNAME` (AD) / `Workload`→`SOURCE=AzureActiveDirectory` (Entra) | DC for AD; tenant for Entra |
| Client IP | 🟡 | `CLIENTIP` (Entra only) | Populated only on Entra records — AD `4723/4724` carries no client IP |
| Result | ✅ | `SEVERITY` (AD) / `RESULT` (Entra) | `success`/`failure` for AD; `Succeeded`/`Failed` for Entra |
| Time | ✅ | `EVENT_TIME` | Envelope |

> **Unified slider query** — `(EVENTID in (4723,4724) AND TARGETUSER=<user>) OR (OPERATION in ('Change user password.','Reset user password.') AND OBJECTID=<userUPN>)`. Cloud-only users have **no** `4723/4724` record — only the Entra side; hybrid users may produce both (Entra → on-prem write-back fires `4724` on the DC).

#### 1.17 Group Membership Changes (`groupMembershipChanges`)

Same dual-ingest pattern: AD security-group changes via Windows agent, Entra group changes via M365 cloud-account.

| Slider field | Status | ZLogs column | Where it comes from |
|---|---|---|---|
| Operation | ✅ | derived from `EVENTID` (AD) or `OPERATION` (Entra) | AD add: `4728/4732/4756` · AD remove: `4729/4733/4757` (parser [`RULE_ID:200164`](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/Windows/Windows.xml)). Entra: `Add member to group` · `Remove member from group` |
| Group | ✅ | `GROUPNAME` (+ `GROUPDOMAIN`) for AD; `OBJECTID`/`PARAMETERS.Group.DisplayName` for Entra | Direct extraction by parser |
| Member added/removed | ✅ | `TARGETUSER` (+ `MEMBERSID`) for AD; `PARAMETERS.Member.userPrincipalName` for Entra | Same |
| Caller | ✅ | `USERNAME` + `DOMAIN` (AD) / `USERID` (Entra) | Acting admin UPN |
| Source host | ✅ | `HOSTNAME` (AD) / `SOURCE=AzureActiveDirectory` (Entra) | DC for AD; tenant for Entra |
| Time | ✅ | `EVENT_TIME` | Envelope |

> **Current state vs change history** — ZLogs answers *who changed what when*. For *current membership of this group right now*, join `APFDiscADGroupDetails` (on-prem) / `APFDiscAADGroupDetails` (cloud) discovered by APF — both already in cloud schema.

#### 1.18 Mailbox Forwarding Rules (`mailboxForwarding`)

Exchange Online only. No on-prem Exchange path. Source: M365 cloud-account → O365 Mgmt Activity API content type `Audit.Exchange` → ZLogs.

| Slider field | Status | ZLogs column | Where it comes from |
|---|---|---|---|
| Operation | ✅ | `OPERATION` | `New-InboxRule` · `Set-InboxRule` · `Set-Mailbox` (when `ForwardingSmtpAddress` set) · `Set-TransportRule` |
| Mailbox | ✅ | `OBJECTID` | Mailbox UPN/SMTP from the cmdlet record |
| Caller | ✅ | `USERID` | Acting principal UPN |
| Rule Name | ✅ | `PARAMETERS.Name` | Parsed from the `Parameters` blob of the cmdlet record |
| ForwardTo | ✅ | `PARAMETERS.ForwardTo` / `ForwardingSmtpAddress` / `RedirectTo` | Same blob — name varies by cmdlet |
| Client IP | ✅ | `CLIENTIP` | Exchange UAL `ClientIP` |
| Result | ✅ | `RESULT` | `Succeeded` / `Failed` |
| Time | ✅ | `EVENT_TIME` | `CreationTime` from UAL |

> **Why this row exists** — auto-forwarding to an external address is a classic post-compromise data-exfil signal. The slider should flag rules whose `ForwardTo` is outside the tenant's accepted-domains list (resolvable from APF Exchange discovery).

### 🗂️ Tab — Recent Alerts

> Sections in this tab: `recentAlerts`

#### 1.6 Recent Alerts (`recentAlerts`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Time, Alert label, Type tag, MITRE technique, Source, Status, Severity | ✅ | `ITSAlertProfileConfigurations` + correlation engine output | Existing alert-profile API |
| Linked graph node (`viewOnGraph`) | ✅ | Internal entity-id mapping | — |

### 🗂️ Other Sections (not bound to a slider tab)

> These sections exist in the data dictionary but are not currently routed to any tab in `entity-slider.js`. Kept here for completeness.

#### 1.20 Privileged Role Assignment Changes (`privilegedRoleChanges`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Empty-state when none | ✅ | Entra audit log | Existing |

#### 1.21 Compliance & Regulatory Impact (`complianceImpact`) — **REMOVED**

> Data block existed in `entities.js` but was never wired into any tab. Removed in the constant-vs-dynamic revision (see [entity_constant_vs_dynamic.md](entity_constant_vs_dynamic.md#1-user-entity--8-constant--11-dynamic)). Regulated-data narrative is now covered by **DLP Incidents** (§1.20) and the **Recommendations & Remediation** card (§1.22), which already calls out GDPR Art. 33 / PII exposure. Re-introduce only if PM commits a real `ITSComplianceMapping` source rather than hard-coded cards.

#### 1.22 Recommendations & Remediation (`remediationGuide`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Verdict, Severity | 🟡 | Aggregated from rule output | — |
| Recommendations (icon, title, desc, priority) | ❌ | Not in product | — |
| Playbooks (name, ID, desc, ETA, urgency) | 🟡 | SOAR connector / runbook catalog | Log360 Cloud Workflows |

---

## 2. DEVICE Entity (`dev-ws045` — CORP-WS-045)

Tabs: **Overview · Host Activity · Device Activity · Alerts & Response**

### 🗂️ Tab — Overview

> Sections in this tab: `riskSummary` · `deviceDetails` · `agentStatus` · `gpoApplied`
>
> **Ingest paths used in this tab:**
> - **APF AD discovery → `APFDiscADComputerDetails`** ([data-dictionary.xml L1661](../../../REPOS/ADSF-DD-DML/product_package/conf/adsf/common/appfw/discovery/application/ad/data-dictionary.xml)) — current state of the AD computer object pulled by APF's AD application.
> - **Windows agent → ZLogs** — security-channel events from this host (boot, GPO refresh, per-EventID counters).
> - **Agent registry tables** (`ELACONFIGUREDLOGCOLLECTION` + heartbeat) — Log360 Cloud agent health.

#### 2.1 Risk Summary (`riskSummary`)
Same field structure as User §1.1. Pulls from `ITSEntityRiskScoreDetails` filtered by `ENTITY_TYPE='device'`.

**Device-specific metric tiles (24h, host-scoped):**

| Tile | Status | Source / Query |
|---|---|---|
| Login Success (24h) | ✅ | ZLogs `EVENTID=4624 AND HOSTNAME=<host> AND TARGETUSER NOT LIKE '%$' AND TARGETUSER NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON')` — count over last 24h. Parser: [WMIWindows-Security.xml](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/Windows/WMIWindows-Security.xml). Filter excludes machine accounts (`$`-suffixed) and well-known service principals so the count reflects human-driven sessions on this host. |
| Login Failure (24h) | ✅ | ZLogs `EVENTID=4625 AND HOSTNAME=<host>` — count over last 24h. Click-through to Host Activity tab reveals `SUB_STATUS` breakdown (`0xC000006A` bad password / `0xC0000064` bad username / `0xC0000234` locked / `0xC000006F` outside hours). |

**Color rule:** Success neutral (green if non-zero, grey if zero); Failure red if > rolling-7d-median × 3, orange if > median × 1.5, else neutral.

**Replaces:** earlier `Suspicious Processes` / `Rogue Services` / `Tor Connections` tiles — those were derived from correlation-rule output and overlapped with the Alerts tab; the logon counters are direct host-side telemetry.

#### 2.2 Device Details (`deviceDetails`)

| Slider field | Status | ZLogs / APF source |
|---|---|---|
| Hostname | ✅ | `APFDiscADComputerDetails.COMPUTER_NAME` |
| FQDN / DNS Name | ✅ | `APFDiscADComputerDetails.DNS_NAME` |
| OS | ✅ | `APFDiscADComputerDetails.OPERATING_SYSTEM` |
| Domain | ✅ | `APFDiscADComputerDetails.DOMAIN_NAME` |
| OU | ✅ | `APFDiscADComputerDetails.OU_NAME` + `OU_DN_NAME` |
| Distinguished Name | ✅ | `APFDiscADComputerDetails.DISTINGUISHED_NAME` |
| Owner / Managed-By | ✅ | `APFDiscADComputerDetails.MANAGER` + `MANAGED_BY_DN` (resolve DN → user via join to `APFDiscADUserDetails.DISTINGUISHED_NAME`) |
| Last Logon | ✅ | `APFDiscADComputerDetails.LAST_LOGON_TIMESTAMP` |
| Last Boot | ✅ | ZLogs `EVENTID=6005` (event log started) on this host |
| Created / Modified | ✅ | `APFDiscADComputerDetails.CREATION_TIME` / `MODIFIED_TIME` |
| Computer Status | ✅ | `APFDiscADComputerDetails.COMPUTER_STATUS` |
| Role | ✅ | `APFDiscADComputerDetails.ROLE` (Workstation / Member-Server / DC) |
| Trusted for Delegation | ✅ | `APFDiscADComputerDetails.TRUSTED_FOR_DELEGATION` |
| LAPS password expiry | ✅ | `APFDiscADComputerDetails.LAPS_EXPIRATION_TIME` |

> **Out of scope for core Log360 Cloud** — hardware (CPU/RAM/Disk) is not in AD and there is no Intune/SCCM connector in core today. Primary-user heuristic (top `USERNAME` from 4624 over 30d) is doable but not a stored field.

#### 2.8 Agent Status & Health (`agentStatus`)

| Slider field | Status | Source |
|---|---|---|
| Log360 Cloud agent — version, last sync, status | ✅ | agent registration + heartbeat tables (`LCCommonDataProvider`) — *Last Sync* = timestamp of the most recent agent contact with the cloud collector |
| Collector ID | ✅ | agent registration record (cloud-collector binding) |

> EDR (Defender / CrowdStrike / SentinelOne) version + AV definitions are **only** available when an EDR cloud-source connector is onboarded — same onboarding pattern as M365.

#### 2.9 GPO Applied to Device (`gpoApplied`)

| Slider field | Status | ZLogs query |
|---|---|---|
| GPO change events on the DC | ✅ | `EVENTID in (5136, 5137, 5141)` AND `OBJECTTYPE=groupPolicyContainer` (Windows agent on DC → ZLogs) |
| GPO link/unlink to OU | ✅ | `EVENTID=5136` on `gPLink` attribute changes |
| Last GPO refresh on host | ✅ | `EVENTID=1502` on this host (Group Policy success) |

> Log360 Cloud has **no "ADManager Plus GPO module"** to call — live "what's applied right now" requires `gpresult` from the agent (not in core today).

### 🗂️ Tab — Host Activity

> Sections in this tab: `processesOnHost` · `servicesOnHost` · `usersLoggedOn` · `loginActivity`
>
> **Ingest path:** Windows agent → ZLogs (`windows-*` index), filtered by `HOSTNAME=<host>`. Parsers: [Windows.xml](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/Windows/Windows.xml), [WMIWindows-Security.xml](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/Windows/WMIWindows-Security.xml).

#### 2.4 Processes on Host (`processesOnHost`) — retitled "Processes Started on Host"

| Slider field | Status | ZLogs source |
|---|---|---|
| Time | ✅ | `@timestamp` |
| Process | ✅ | Sysmon EID 1 `IMAGE` **or** Security EID 4688 `PROCESS` |
| PID | ✅ | `PROCESS_ID` |
| User | ✅ | `USERNAME` + `DOMAIN` |
| Command line | 🟡 | Sysmon EID 1 `COMMAND_LINE` (always) **or** EID 4688 `PROCESS_COMMAND_LINE` (only if `Audit: Include cmdline in process creation` GPO is enabled) |
| Status ("Started") | ✅ | EID 1 / 4688 are *creation* events, not live-state. Label is **"Started"**, not "Running". |
| Action: ⊘ Kill Process | ✅ (SOAR) | Renders as playbook trigger; handed off to remediation pipeline (no direct agent kill channel today). |

#### 2.5 Services on Host (`servicesOnHost`) — retitled "Services Installed on Host"

| Slider field | Status | ZLogs source |
|---|---|---|
| Time | ✅ | `@timestamp` of EID 7045 |
| Service / Display Name | ✅ | `SERVICENAME` |
| Account | ✅ | `SERVICEACCOUNT` |
| Binary | ✅ | `IMAGEPATH` |
| Start Type | ✅ | `SERVICESTARTTYPE` (Auto / Manual / Disabled) |
| Status ("Installed") | ✅ | EID 7045 = install-time event. Label is **"Installed"**, not "Running". |
| ~~Signed~~ | ❌ **Removed** | Not in EID 7045 envelope; agent does not perform PE-signature lookup. |
| Action: ⊘ Stop Service | ✅ (SOAR) | Playbook trigger; same handoff pattern as Kill Process. |

#### 2.6 Recent Logon Sessions (`usersLoggedOn`) — retitled from "Users Logged On"

> Reframed: Log360 Cloud agent does **not** ship live `quser` / `LogonSessions.exe` output. Sessions are **derived** by pairing 4624 (logon) with 4634 / 4647 (logoff) on `LOGON_ID`.

| Slider field | Status | ZLogs derivation |
|---|---|---|
| User | ✅ | `TARGETUSER` (filter `$`-suffix + SYSTEM / LOCAL SERVICE / NETWORK SERVICE / ANONYMOUS LOGON) |
| Logon Type | ✅ | `LOGON_TYPE` (2 = Interactive, 3 = Network, 10 = RDP, 5 = Service) |
| Source | ✅ | `WORKSTATION_NAME` / `IPADDRESS` from 4624 |
| Session start | ✅ | `@timestamp` of latest 4624 with that `LOGON_ID` |
| Session state | 🟡 | **Active** if no 4634/4647 paired yet, else **Logged-off**. Caveat: agent may have missed the 4634; honest fallback is "Last seen active at …". |
| Duration | 🟡 | (4634/4647 ts − 4624 ts) or "(ongoing since …)" if no logoff seen. |

#### 2.3 Login Activity on Device (`loginActivity`)

Same shape as User §1.3, reverse-pivoted (filter `HOSTNAME=<host>` instead of `TARGETUSER=<user>`).

| Slider field | Status | ZLogs source |
|---|---|---|
| Time | ✅ | `@timestamp` |
| User | ✅ | `TARGETUSER` |
| Logon Type | ✅ | `LOGON_TYPE` |
| Source IP | ✅ | `IPADDRESS` (from 4624 / 4625) |
| Status | ✅ | EID 4624 = Success; EID 4625 = Failure with `STATUS` + `SUB_STATUS` (e.g. `0xC000006A` bad password, `0xC0000064` bad username, `0xC0000234` locked, `0xC000006F` outside hours). |
| ~~MFA~~ | ❌ **Removed** | Windows 4624/4625 has no MFA field for local/domain auth. |
| Risk | 🟡 | Derived — only present if a correlation rule fired on this event. |

### 🗂️ Tab — Device Activity

> Sections in this tab: `scheduledTasks` · `usbDeviceEvents` · `localAccountLifecycle`
>
> **Ingest path:** Windows agent → ZLogs (`windows-*` index), filtered by `HOSTNAME=<host>`. Parser: [WMIWindows-Security.xml](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/Windows/WMIWindows-Security.xml).

#### 2.12 Scheduled Task Events (`scheduledTasks`)

| Slider field | Status | ZLogs source |
|---|---|---|
| Time | ✅ | `@timestamp` |
| Event | ✅ | EID `4698` Created · `4699` Deleted · `4700` Enabled · `4701` Disabled · `4702` Updated |
| Task Name | ✅ | `TASKNAME` |
| User (caller) | ✅ | `USERNAME` + `DOMAIN` |
| Command | ✅ | `COMMAND` (parsed from `TaskContent` XML) |
| Trigger | ✅ | parsed from `TaskContent` XML (StartBoundary / Boot / Logon) |

#### 2.11 USB Device Events (`usbDeviceEvents`)

| Slider field | Status | ZLogs source |
|---|---|---|
| Time | ✅ | `@timestamp` |
| Event | ✅ | EID `6416` PnP device added/removed |
| Device | ✅ | `DEVICEDESCRIPTION` + `DEVICEID` |
| Class | ✅ | `CLASSNAME` (Mass Storage / HID / Printer) |
| User | ✅ | `USERNAME` |
| ~~Bytes copied~~ | 🟡 | EID 4663 (file access) requires SACL on removable-drive paths — not on by default; show only when audit policy is configured. |

#### 2.13 Local Account Lifecycle (`localAccountLifecycle`)

> Local SAM events on **this host** (distinct from domain account changes which surface on the user entity §1.15-§1.18). High signal for local backdoor / privilege escalation.

| Slider field | Status | ZLogs source |
|---|---|---|
| Time | ✅ | `@timestamp` |
| Event | ✅ | EID `4720` Local user created · `4722` Enabled · `4724` Password reset · `4725` Disabled · `4726` Deleted · `4732` Added to local group · `4733` Removed from local group |
| Account | ✅ | `TARGETUSER` (the account being modified) |
| Caller | ✅ | `USERNAME` + `DOMAIN` (the actor) |
| Group | ✅ | `GROUPNAME` (for 4732/4733 — most commonly `BUILTIN\Administrators`) |
| Account Type | ✅ | derived: `Local` if `TARGETDOMAIN = HOSTNAME`, else suppress (domain account — belongs on user entity) |

> **Filter rule:** show only events where `TARGETDOMAIN = HOSTNAME` of this device, so the section never duplicates domain-account changes already shown on the user entity's Account Changes tab.

### 🗂️ Tab — Alerts & Response

> Sections in this tab: `recentAlerts`

#### 2.7 Recent Alerts on Device (`recentAlerts`)
Same shape as User §1.6.

## 3. IP Entity (`ip-tor`, `ip-internal`)

Tabs: **Overview · Threat Intel · Connections · Logon Activity**

### 🗂️ Tab — Overview

> Sections in this tab: `riskSummary` · `ipDetails` · `associatedUsers` · `associatedDevices`
>
> The previous standalone `geoContext` section is **merged into `ipDetails`** (Country/City, VPN-Proxy, TI Feed Match are now KV rows in §3.2).

#### 3.1 Risk Summary (`riskSummary`)

**External public IP (`ip-tor`):**

| Tile / Field | Status | ZLogs / source |
|---|---|---|
| Risk Score, Severity, Status badge | ✅ | `ITSEntityRiskScoreDetails` |
| 🌐 Tor / Anonymizer flag | ✅ | `ADSThreatAnalyticsFeeds` category lookup |
| ⚠ Threat Feeds Flagged (count) | ✅ | `ADSThreatAnalyticsFeeds` aggregator (Webroot, Anomali, OTX, customer feeds) |
| 🔗 Active Connections (24h) | ✅ | ES `count` agg on firewall syslog where `DST_IP=<ip>` |
| 🦠 VirusTotal Detections | 🟡 | Periodic VT enrichment job (default 6 h refresh) calls `virustotal.com/api/v3/ip_addresses/{ip}` for IPs flagged by correlation rules; cached `detection_count / total_engines` stored in `ITSEntityRiskScoreDetails.TI_ENRICHMENT_BLOB`. Requires VT API key in tenant settings. |

**Internal IP (`ip-internal`):**

| Tile / Field | Status | ZLogs / source |
|---|---|---|
| Risk Score, Severity | ✅ | `ITSEntityRiskScoreDetails` |
| 🏢 Network Zone | ✅ | derived: subnet → zone mapping (RFC1918 / config-defined) |
| 👤 Currently Assigned User | ✅ | latest 4624 with `IPADDRESS=<ip>` (filter machine accounts) |
| 🔗 Unique Destinations (24h) | ✅ | ES `cardinality` agg on firewall `DST_IP` where `SRC_IP=<ip>` |
| 📡 Traffic Volume (24h) | ✅ | ES `sum` on firewall `BYTES_SENT` + `BYTES_RECEIVED` |
| ⚠ Anomalous Flows | ✅ | count of correlation-rule hits on this IP |

#### 3.2 IP Details (`ipDetails`)

**External public IP:**

| KV row | Status | Source |
|---|---|---|
| IP Address | ✅ | input |
| Network Type | ✅ | derived: RFC1918 check + Threat Analytics category (Tor / Public / VPN) |
| Country / City | ✅ | MaxMind GeoIP-Lite (bundled) |
| ASN / Org | ✅ | MaxMind GeoIP-Lite ASN db (bundled) |
| Reverse DNS (PTR) | 🟡 | DNS server logs if collected, else live `dig` from cloud collector |
| VPN / Proxy | ✅ | `ADSThreatAnalyticsFeeds` category |
| Threat Feed Match | ✅ | `ADSThreatAnalyticsFeeds` |
| Firewall Events (24h) | ✅ | ES `count` + `terms` on firewall syslog (`ACTION=allow|deny`) |
| Top Transport Protocols | ✅ | ES `terms` agg on `protocol_tr` (values are L4 only — `tcp`, `udp`, `icmp`, `ipv6-icmp`; **not** application-layer names like `HTTPS`/`DNS`) |
| Top Destination Ports | ✅ | ES `terms` agg on `DST_PORT` (raw port number; analyst infers service from well-known port mapping) |

**Internal IP:**

| KV row | Status | Source |
|---|---|---|
| IP Address | ✅ | input |
| Network Type | ✅ | "Internal — Private (RFC1918)" |
| Subnet / Zone | ✅ | derived from IP + collector subnet table |
| Hostname (resolved) | ✅ | reverse DNS lookup OR latest `WORKSTATION_NAME` from 4624 |
| DHCP Lease (current window) | 🟡 | DHCP server logs (EID 10 / 20 / 31 from `Microsoft-Windows-DHCP-Server`) — only if customer collects DHCP logs |
| Threat Feed Match | ✅ | always "Not listed (internal)" for RFC1918 |


#### 3.3 Geo Context (`geoContext`) — **REMOVED**

> Previously a 3-row standalone section (Country, VPN/Proxy, TI Feed Match). All three rows are now folded into `ipDetails` (§3.2). The `geoContext` block is kept in `entities.js` with `hidden: true` for now — safe to delete in a later cleanup pass.

#### 3.9 Associated Users / Devices (`associatedUsers`, `associatedDevices`)

| Pivot | Status | Source |
|---|---|---|
| Top-N users authenticated FROM this IP (Windows logons) | ✅ | ES `terms` agg on `TARGETUSER` from `hosttype="windows" AND EVENTID IN (4624,4625) AND IPADDRESS=<ip>` |
| Top-N internal hosts that connected TO this IP (outbound) | ✅ | ES `terms` agg on firewall syslog `SRC_IP` where `DST_IP=<ip>` |
| Top-N internal hosts that received connections FROM this IP (inbound) | ✅ | ES `terms` agg on firewall syslog `DST_IP` where `SRC_IP=<ip>` |
| Source firewall device(s) that observed this IP | ✅ | ES `terms` agg on `DEVICE_NAME` |
| Linked device entity (internal IPs only) | ✅ | match `IPADDRESS` → `APFDiscADComputerDetails.DNS_NAME` via reverse DNS |

### 🗂️ Tab — Threat Intel

> Sections in this tab: `threatIntelligence` · `idsAlerts`
>
> `firewallSummary` was previously listed here — removed on 18 May 2026 because the same flow data is already represented in the Connections tab via `connectionHistory` + `trafficSummary`; showing it twice was redundant.
>
> **Important boundary** — Log360 Cloud does **not** ship its own IDS/IPS engine. Every entry in this tab comes from one of two ingest paths: (1) the customer's **perimeter firewall/IPS syslog** (PaloAlto Threat Prevention, CheckPoint IPS blade, Fortinet IPS) or (2) **Log360 Threat Analytics** (in-line ingest-time enrichment via `ThreatDataEnrichment` + on-demand VirusTotal lookup). Snort / Suricata are **not** in the product — they were in an earlier doc draft and have been removed.

#### 3.4 Threat Intelligence (`threatIntelligence`)

**How TI verdicts are actually fetched** (grounded in [ThreatDataEnrichment.java](../../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/zqueue/logenrichment/threat/ThreatDataEnrichment.java)):

- At ingest time, every event passes through `ThreatDataEnrichment.processRecords()` which extracts source/dest IPs, URLs and domains and looks them up in [ThreatDataCache](../../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/threat/data/ThreatDataCache.java) (in-process LRU, capacity 2000) → on miss falls through to [RedisJVMThreatCache](../../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/threat/data/RedisJVMThreatCache.java) (Redis-backed shared cache).
- Two engines populate the cache: **ATA** (Log360 Threat Analytics — Webroot + customer-loaded feeds, default `THREAT_SERVER` value) and **AppSense** (Zoho TIP via `TIPAgent.searchIP()`).
- When a hit is found, the verdict is written **onto the log event itself** as four fields (see [Configuration.java](../../../REPOS/adsf/source/java_source/com/manageengine/ads/fw/common/threat/Configuration.java) lines 33-35): `THREAT_SOURCE` (matched IOC string), `THREAT_REPUTATION` (integer score, lower = worse), `THREAT_CATEGORIES` (JSON array e.g. `["Tor","Anonymizer"]`), `THREAT_SERVER` (which engine matched).
- The slider therefore reads TI data by **aggregating over already-enriched log events** — no separate per-IOC verdict table to query.

| KV / row | Status | Source |
|---|---|---|
| TI engines that matched (`Webroot / ATA`, `AppSense`, customer feeds) | ✅ | ES `terms` agg on `THREAT_SERVER` field, filtered by `THREAT_SOURCE = <ip>`. Distinct values present in code: `ATA` (default) and `appsense`; customer-loaded feeds appear under `ATA`. |
| Threat Categories (e.g. `Tor`, `Anonymizer`, `Phishing`) | ✅ | ES `terms` agg on `THREAT_CATEGORIES` field — array values written by `ThreatDataEnrichment.addThreatFieldsToLog()`. |
| Worst Reputation Score | ✅ | ES `min` agg on `THREAT_REPUTATION` field (lower = worse, per Webroot convention). |
| Events Flagged (count) | ✅ | ES `count` over events where `THREAT_SOURCE = <ip>`. |
| Feed Subscription Status (which feeds the tenant has loaded) | ✅ | `ADSThreatAnalyticsFeeds` table — feed-registry only (`ANALYTICS_FEED_TYPE`, `ANALYTICS_FEED_VERSION`, `ANALYTICS_FEED_FILE_META`). Use for the "Last Feed Update" timestamp, NOT for per-IOC verdicts. |
| VirusTotal detection (`detection_count / total_engines`) | 🟡 | **On-demand** REST call: analyst-triggered or correlation-rule-triggered POST to `/RestAPI/V2/threat/getVirusTotalAnalysisData` ([VirusTotalActionHandler](../../../REPOS/log360_cloud/source/cloud/com/zoho/log360/server/rest/version2/threat/handler/ThreatAPIHandler.java) line 128). **Not** a periodic enrichment job. Results cached client-side per session. Requires VT API key in tenant settings; row hidden when key not configured. |

#### 3.8 IDS/IPS Alerts (`idsAlerts`)

All entries come from customer perimeter syslog. Field availability varies by vendor:

| Vendor | hosttype | Parser | Parsed signature field | Action field | Severity |
|---|---|---|---|---|---|
| PaloAlto Threat Prevention | `paloalto device` | [PaloAlto-Threat.xml](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/PaloAlto/PaloAlto-Threat.xml) | `THREAT_ID` ✅ | `ACTION_TAG` ✅ | derived from `THREAT_ID` lookup |
| CheckPoint IPS blade | `checkpoint device` | [CheckPoint.xml](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/CheckPoint/CheckPoint.xml) | `PROTECTION_NAME` ✅, `ATTACK` ✅ | `ACTION` ✅ | `SEVERITY` / `SEVERITYLEVEL` ✅ |
| Fortinet IPS | `fortinet device` | [Fortinet-Attacks.xml](../../../REPOS/itsf/product_package/conf/itsf/common/LogFormats/DeviceTypes/Fortinet/Fortinet-Attacks.xml) | `SUBTYPE` (coarse: `ips` / `virus` / `webfilter`) — signature name is **not** a parsed column, lives in raw `message` body | `ACTION_TAG` ✅ | not parsed as a dedicated column |
| Cisco ASA / FTD | `cisco device` | (Cisco directory exists but no IPS-specific parsed fields found in this grep pass) | 🟡 raw text only | 🟡 | 🟡 |
| ~~Snort / Suricata~~ | — | ❌ **No parser in product** | — | — | — |

> **Practical impact for the slider** — a PA or CheckPoint IPS event renders with full structured details; a Fortinet IPS event renders with `SUBTYPE` + `ACTION_TAG` and the analyst must click "View raw" to read the signature; a Cisco IPS event renders mostly as raw message text.

#### 3.6 Firewall Action Summary (`firewallSummary`)

| KV row | Status | Source |
|---|---|---|
| Total Flows | ✅ | ES `count` over firewall syslog filtered by IP |
| Allowed / Denied | ✅ | ES `terms` agg on `ACTION_TAG` (PA/Fortinet) or `ACTION` (CheckPoint) |
| Top Destination Ports | ✅ | ES `terms` agg on `DST_PORT` — raw port number, no L7 label fabrication |
| Top Transport Protocols | ✅ | ES `terms` agg on `protocol_tr` (L4 only: `tcp`, `udp`, `icmp`) |
| Source Devices | ✅ | ES `terms` agg on `DEVICE_NAME` / `hosttype` |

### 🗂️ Tab — Connections

> Sections in this tab: `connectionHistory` · `dnsHistory` · `vpnSessions` · `trafficSummary`

#### 3.5 Connection History (`connectionHistory`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Direction, Source/Dest IP, Port, Bytes, Duration, Action, Device | ✅ | Firewall syslog (PA, Fortinet, Checkpoint, Cisco ASA) | Existing parsers |

#### 3.7 DNS Query History (`dnsHistory`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Domain, Record Type, Resolution, Querying Process, Source (Sysmon EID 22) | ✅ | Sysmon EID 22 + DNS server logs | Existing |

#### 3.10 VPN Sessions (`vpnSessions`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| User, Assigned IP, Tunnel type, Duration | ✅ | VPN gateway syslog | Existing |

#### 3.11 Traffic Summary (`trafficSummary`)

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

### 🗂️ Tab — Overview

> Sections in this tab: `riskSummary` · `serviceDetails` · `serviceInfo`

#### 5.1 Service Details (`serviceDetails` / `serviceInfo`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Service / Tenant / Workload name | ✅ | M365 Manager Plus tenant config | Existing |
| Service Type (IDP, SaaS, Storage, OS-service) | ✅ | Internal classification | Existing |

### 🗂️ Tab — Config & Policy

> Sections in this tab: `oauthConsentGrants` · `conditionalAccess` · `dlpPolicies`

#### 5.2 OAuth App Consent Grants (`oauthConsentGrants`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Operation, App, Consenting User, Permissions, Source IP, Admin Consent | ✅ | Entra ID audit log (`Consent to application`) | M365MP |

#### 5.4 Conditional Access Policies (`conditionalAccess`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| State (Enabled/Report-Only/Disabled), Scope, Conditions, Grant, Exclusions, Last Modified | ✅ | Graph API `conditionalAccessPolicies` | M365MP |

#### 5.6 DLP Policies (`dlpPolicies`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Policy name, Scope, Action, Last triggered | ✅ | Defender for Cloud Apps DLP / Purview | Existing connector |

### 🗂️ Tab — Activity

> Sections in this tab: `signInAudit` · `adminActivity` · `fileAccessAnomaly` · `sensitiveFiles` · `serviceTimeline` · `networkConnections` · `fileDrops` · `wmiEvents` · `processes`

#### 5.5 Sign-In Audit (`signInAudit`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| User, IP, Location, App, MFA result, Risk, Result | ✅ | Entra ID Sign-in logs | M365MP |

#### 5.3 Admin Activity on Service (`adminActivity`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Operation, Target, Caller, Workload, Source IP | ✅ | Unified Audit Log (Entra/Exchange/SharePoint) | M365MP |

#### 5.7 File Access Anomaly / Sensitive Files (`fileAccessAnomaly`, `sensitiveFiles`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| File, User, Operation, Sensitivity tag | ✅ | SharePoint audit + Purview labels | M365MP |

#### 5.8 Service Timeline / Network Connections / File Drops / WMI / Processes (when service is OS-resident)

All ✅ from Sysmon (EID 1, 3, 11, 19, 22) when the "service" is an on-host artifact like `WinUpdateSvc`. AI enrichment same as §1.4 / §1.12.

### 🗂️ Tab — Alerts & Response

> Sections in this tab: `recentAlerts` · `serviceTriggered`

#### 5.9 Recent Alerts / Service Triggered

Same as §1.6.

---

## 6. PROCESS Entity (`proc-powershell`)

Tabs: **Overview · Anomalies · Activity**

### 🗂️ Tab — Overview

> Sections in this tab: `riskSummary` · `processDetails` · `details` · `processTree` · `childProcesses` · `serviceTriggered` · `recentAlerts`

#### 6.1 Risk Summary (`riskSummary`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| AMSI Detections (count), C2 Connection (Active), Payload (filename), Encoded Commands, Obfuscation type, Child processes | ✅ | Sysmon (EID 1, 3, 11), AMSI provider events (EID 4104) | Existing |

#### 6.2 Process Details (`processDetails`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Process Name, PID, Parent, Cmdline, User, Integrity, Start, Status, Signature (publisher, validity), Session ID, Threads, Handles | ✅ | Sysmon EID 1 + EID 8 | Existing |

#### 6.3 Process Tree (`processTree`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Level (Grandparent/Parent/Current/Child), User, Started, Cmdline, Status, Notes | ✅ | Sysmon EID 1 chain | Existing |

#### 6.4 Child Processes (`childProcesses`)
Same as §6.3 but filtered to direct children. ✅.

### 🗂️ Tab — Anomalies

> Sections in this tab: `tokenAnomaly` · `amsiEvents` · `registryModifications` · `namedPipes`

#### 6.6 Token Anomaly / Token Usage (`tokenAnomaly`, `tokenUsage`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| SeDebugPrivilege, SeImpersonate, NewToken events | ✅ | EventID 4672 + Sysmon EID 8 (CreateRemoteThread) | Existing |

#### 6.5 AMSI Events (`amsiEvents`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Detection (Suspicious/Malicious), Content Preview, Scan Result, Action, Script Block ID | ✅ | EventID 4104 (PowerShell ScriptBlock) + AMSI provider | Existing |

#### 6.7 Registry Modifications (`registryModifications`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Key, Operation (Set/Delete), Old/New Value | ✅ | Sysmon EID 12/13/14 | Existing |

#### 6.8 Named Pipes (`namedPipes`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Pipe Name, Operation (Create/Connect), Process | ✅ | Sysmon EID 17/18 | Existing |

### 🗂️ Tab — Activity

> Sections in this tab: `tokenUsage` · `networkActivity` · `fileOperations` · `processes` · `dllLoads` · `processDnsQueries`

#### 6.9 Network Activity (`networkActivity`)
Same as §1.12, scoped to the process. ✅ from Sysmon EID 3.

#### 6.10 File Operations (`fileOperations`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Operation (Create/Modify/Delete), Path, Hash | ✅ | Sysmon EID 11 + ADAP File Server | Existing |

#### 6.11 DLL Loads (`dllLoads`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| DLL Name, Path, Signed?, Loaded at | ✅ | Sysmon EID 7 | Existing (if EID 7 enabled — high-volume) |

#### 6.12 Process DNS Queries (`processDnsQueries`)
Same as §1.12 DNS row, scoped to the process. ✅ from Sysmon EID 22.

---

## 7. ALERT Entity (`alert-impossible-travel` and 10 sibling alert entities)

Tabs: **Overview · Scope · Response**

### 🗂️ Tab — Overview

> Sections in this tab: `alertDetails` · `triggerConditions` · `details`

#### 7.1 Alert Details (`alertDetails`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Alert ID, Name, Severity, MITRE Tactic+Technique, Detection Type, First Triggered, Last Updated, Source Service, Status | ✅ | `ITSAlertProfileConfigurations` + correlation engine result | Existing |

#### 7.2 Trigger Conditions (`triggerConditions`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Rule Name, Rule Type (Correlation/UEBA/Threat-Intel), Conditions, Threshold, Window | ✅ | Rule-engine config (`CorrelationRules` / UEBA model metadata) | Existing |

### 🗂️ Tab — Scope

> Sections in this tab: `affectedEntities` · `correlatedAlerts` · `processes`

#### 7.3 Affected Entities (`affectedEntities`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| KV map of `{entity-id: role}` (Source, Target, Indicator, …) | ✅ | Alert-instance entity links | Existing |

#### 7.4 Correlated Alerts (`correlatedAlerts`)

| Field | Status | Product Source | How to Get |
|-------|--------|----------------|------------|
| Alert name, Source, Severity, MITRE | ✅ | Alert-correlation graph (existing) | Existing |

### 🗂️ Other Sections (not bound to a slider tab)

> These sections exist in the data dictionary but are not currently routed to any tab in `entity-slider.js`. Kept here for completeness.

#### 7.5 Service Triggered / Recent Alerts
Same as §1.5 / §1.6 but scoped to this alert's response actions.

#### 7.6 Recommendations & Remediation
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
| ~~First Seen / Last Seen~~ — **REMOVED** | ❌ | Was `ZLogs MIN/MAX(_zl_timestamp)` over the source→target edge. Silently truncated by log retention so `MIN()` answers "first time we saw this edge **within retention**", not the true first sighting. Misleading; dropped. The edge timestamps shown elsewhere (alert record creation, event-distribution sparkline) come from non-retention-bounded sources. | — |

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
| `firstSeen` / `lastSeen` | ISO-ish string | 🟡 (legacy / optional) | `'03 Apr 2026 15:20:05'` — retention-bounded; new edges should omit |
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
| ~~First/Last Seen~~ | ❌ removed | retention-truncated | — |
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
| `scheduledTasks`, `usbDeviceEvents`, `localAccountLifecycle` | device | Device Activity |
| `threatIntelligence`, `idsAlerts` | ip, domain | Threat Intel |
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

## 9. APPENDIX — Static Field Projections per Section

> **Purpose**: For each section ID rendered by the slider, declare the **fixed** ES `_source` / SQL-select projection that the backend must fetch, independent of the entity instance. This is the contract between the slider front-end and the API. No dynamic field selection — analyst sees the same column set every time; blanks appear where a vendor / source didn't emit a field.
>
> **Companion machine-readable config**: [`js/data/section-projections.json`](js/data/section-projections.json) — same data, JSON-shaped, for runtime consumption.
>
> **Coverage**: 29 sections fully inventoried below from real backend sources (data-dictionary.xml / parser XMLs / verified ES fields). **~38 additional section IDs** (listed in §9.31) are referenced by the slider but not yet ground-truthed — they will be added as code/parser audits complete. **Do not fabricate** projections for the pending list.

### 9.1 `riskSummary`
**Used by**: user · device · ip · domain · service · alert
**Backing source**: `ITSEntityRiskScoreDetails` table (Postgres) + ZLogs ES for host/IP-scoped aggregates

| Field | Backend source | Type | Hosttypes/source | Status |
|---|---|---|---|---|
| Risk Score (0–100) | `ITSEntityRiskScoreDetails.RISK_SCORE` | decimal | all | ✅ |
| Severity | `ITSEntityRiskScoreDetails.SESSION_SEVERITY` → join `ITSRiskSeverityDetails.SEVERITY_NAME` | enum (join) | all | ✅ |
| Status Badge | Derived from `ITSAlertProfileConfigurations` rule categories | enum (derived) | all | 🟡 |
| Active Anomalies (session / lifetime) | `DETECTION_COUNT` + `OVERALL_DETECTION_COUNT` | integer | all | ✅ |
| Last Anomaly | `LAST_ANOMALY_UPDATE_TIME` | timestamp | all | ✅ |
| Login Success 24h (device) | ZLogs `count(EVENTID=4624 AND HOSTNAME=<host>)` | integer (agg) | windows | ✅ |
| Login Failure 24h (device) | ZLogs `count(EVENTID=4625 AND HOSTNAME=<host>)` | integer (agg) | windows | ✅ |
| Tor / Anonymizer flag (ext IP) | ZLogs `THREAT_CATEGORIES` contains `Tor`/`Anonymizer` | boolean (derived) | all (TI-enabled) | ✅ |
| Threat Feeds Flagged count (ext IP) | ZLogs `count(THREAT_SOURCE=<ip>)` | integer (agg) | all (TI-enabled) | ✅ |
| Active Connections 24h (ext IP) | ZLogs `count(DST_IP=<ip>)` | integer (agg) | paloalto/checkpoint/fortinet/cisco | ✅ |
| VirusTotal Detections (ext IP) | On-demand REST `/RestAPI/V2/threat/getVirusTotalAnalysisData` | string (ratio) | all (if VT key) | 🟡 |

**Filter**: `entity-type-specific` (see per-tab filters)

### 9.2 `usersDetails`
**Used by**: user
**Backing source**: `APFDiscADUserDetails` (AD) OR `APFDiscAADUserDetails` (Entra)

| Field | Backend source | Type | Source | Status |
|---|---|---|---|---|
| Display Name | `DISPLAY_NAME` (both) | string | AD/Entra | ✅ |
| SAM Account Name | `APFDiscADUserDetails.SAM_ACCOUNT_NAME` | string | AD only | ✅/❌ |
| UPN | `LOGON_NAME` (AD) / `USER_PRINCIPAL_NAME` (Entra) | string | AD/Entra | ✅ |
| Email | `EMAIL_ADDRESS` (both) | string | AD/Entra | ✅ |
| Job Title | `TITLE` (both) | string | AD/Entra | ✅ |
| Department | `DEPARTMENT` (both) | string | AD/Entra | ✅ |
| Manager | `MANAGER` + `MANAGER_DN` (AD) / `MANAGER` w/ lookup (Entra) | string (join) | AD/Entra | ✅ |
| Last Logon | `LAST_LOGON_TIME` (AD) / ES `max(createdDateTime)` (Entra) | timestamp | AD ✅ / Entra 🟡 | mixed |
| OU Name | `OU_NAME` | string | AD only | ✅/❌ |
| Account Created | `WHEN_CREATED` (both) | timestamp | AD/Entra | ✅ |
| Account Status | `ACCOUNT_STATUS` (AD) / `ACCOUNT_ENABLED` (Entra) | boolean | AD/Entra | ✅ |
| Primary Group | `PRIMARY_GROUP_GUID` → join `APFDiscADGroupDetails` | string (join) | AD only | ✅/❌ |

**Filter**: `OBJECT_GUID=<user_guid> AND APP_CONFIG_ID=<ad_config_id>` (AD) OR `OBJECT_ID=<aad_id> AND APP_CONFIG_ID=<azure_config_id>` (Entra)

### 9.3 `deviceDetails`
**Used by**: device
**Backing source**: `APFDiscADComputerDetails` table

| Field | Backend source | Type | Status |
|---|---|---|---|
| Hostname | `COMPUTER_NAME` | string | ✅ |
| FQDN | `DNS_NAME` | string | ✅ |
| Operating System | `OPERATING_SYSTEM` | string | ✅ |
| Domain | `DOMAIN_NAME` | string | ✅ |
| OU Name | `OU_NAME` | string | ✅ |
| Distinguished Name | `DISTINGUISHED_NAME` | string | ✅ |
| Managed-By | `MANAGED_BY_DN` → join `APFDiscADUserDetails` | string (join) | ✅ |
| Last Logon | `LAST_LOGON_TIMESTAMP` | timestamp | ✅ |
| Last Boot | ZLogs `max(@timestamp WHERE EVENTID=6005 AND HOSTNAME=<host>)` | timestamp (agg) | ✅ |
| Created | `CREATION_TIME` | timestamp | ✅ |
| Modified | `MODIFIED_TIME` | timestamp | ✅ |
| Status | `COMPUTER_STATUS` | boolean | ✅ |
| Role | `ROLE` | enum | ✅ |
| Trusted for Delegation | `TRUSTED_FOR_DELEGATION` | boolean | ✅ |
| LAPS Password Expiry | `LAPS_EXPIRATION_TIME` | timestamp | ✅ |

**Filter**: `COMPUTER_NAME=<hostname> AND APP_CONFIG_ID=<ad_config_id>`

### 9.4 `logonActivity`
**Used by**: user · device · ip
**Backing source**: ZLogs ES — Windows Security EID 4624/4625/4634/4647

| Field | Backend source | Type | Status |
|---|---|---|---|
| Timestamp | `@timestamp` | timestamp | ✅ |
| Event ID | `EVENTID` (4624/4625/4634/4647) | integer | ✅ |
| Logon Type | `LOGONTYPE` (2/3/7/10/11) | integer → enum | ✅ |
| Target Host | `HOSTNAME` | string | ✅ |
| Source IP | `IPADDRESS` | string | ✅ |
| Workstation Name | `WORKSTATION_NAME` | string | ✅ |
| Authentication Package | `AUTHENTICATIONPACKAGENAME` | string | ✅ |
| Result Status | derived from `EVENTID` + `SUB_STATUS` (4625) | enum | ✅ |

**Filter**:
- For user: `EVENTID IN (4624,4625,4634,4647) AND USERNAME=<user>`
- For device: `EVENTID IN (4624,4625,4634,4647) AND HOSTNAME=<device>`
- For IP: `EVENTID IN (4624,4625) AND IPADDRESS=<ip>`

### 9.5 `networkActivity`
**Used by**: user · process
**Backing source**: ZLogs ES — DNS (EID 1033/1034 / Sysmon 22) + Firewall syslog

> **User-attribution caveat** — None of these sources carry a `USERNAME` field. For the **user** entity this section requires a two-step pivot: (1) resolve which `HOSTNAME`/`SRC_IP` values map to the user via concurrent Windows 4624 sessions in the time window, then (2) filter network logs by those host/IP values. That pivot is why most rows are 🟡 for `user`. For the **process** entity rows are ✅ because Sysmon ties events directly to `PROCESSNAME`+`PROCESS_ID`.

| Field | Backend source | Type | Hosttype | Status (user / process) |
|---|---|---|---|---|
| Type Label | derived (DNS/Firewall/Proxy/VPN) | enum (derived) | various | ✅ / ✅ |
| Domain Queried | `QUERY_NAME` | string | windows | 🟡 / ✅ |
| Resolution | `QUERY_RESULTS` / `ANSWER_RECORDS` | string | windows | 🟡 / ✅ |
| Source Host | `HOSTNAME` | string | windows | ✅ / ✅ |
| Query Process | Sysmon EID 22 `IMAGE` | string | windows (Sysmon) | 🟡 / ✅ |
| Destination Port | `DST_PORT` | integer | firewall families | 🟡 / — |
| Protocol | `PROTOCOL_TR` (L4: tcp/udp/icmp) | enum | firewall families | 🟡 / — |
| Bytes Sent | `SENT_BYTES` | integer | paloalto/fortinet/sophos/firepower/topsec | 🟡 / — |
| Bytes Received | `RECEIVED_BYTES` | integer | paloalto/fortinet/sophos/firepower/topsec | 🟡 / — |
| Packets Sent | `SENT_PACKETS` | integer | paloalto/fortinet | 🟡 / — |
| Packets Received | `RECEIVED_PACKETS` | integer | paloalto/fortinet | 🟡 / — |

> **CheckPoint exception** — byte counts are present only in the raw message text for CheckPoint, not as parsed columns. CheckPoint flows will render blanks in the bytes columns.

### 9.6 `processes`
**Used by**: user · device · process · alert · service
**Backing source**: ZLogs ES — Windows Security EID 4688 / Sysmon EID 1

| Field | Backend source | Type | Status |
|---|---|---|---|
| Timestamp | `@timestamp` | timestamp | ✅ |
| Process Name | `PROCESSNAME` | string | ✅ |
| PID | `PROCESS_ID` | integer | ✅ |
| Parent Process | `PARENT_PROCESS_NAME` | string | ✅ |
| Command Line | `COMMAND_LINE` (4688 conditional / Sysmon always) | string | 🟡 |
| Executing User | `USERNAME` + `DOMAIN` | string | ✅ |
| Integrity Level | `INTEGRITY_LEVEL` | enum | 🟡 |
| Status | derived constant "Started" | enum | ✅ |

**Filter**: `(EVENTID=4688 OR SYSMON_EVENTID=1) AND (USERNAME=<user> OR HOSTNAME=<device> OR PARENT_PROCESS_NAME=<process>)`

### 9.7 `serviceTriggered`
**Used by**: user · device · service · process · alert
**Backing source**: ZLogs ES — Windows Security EID 7045/7046/7047

| Field | Backend source | Type | Status |
|---|---|---|---|
| Timestamp | `@timestamp` | timestamp | ✅ |
| Event Type Label | derived from `EVENTID` | enum | ✅ |
| Service Name | `SERVICENAME` | string | ✅ |
| Display Name | `DISPLAY_NAME` | string | ✅ |
| Service Account | `SERVICEACCOUNT` | string | ✅ |
| Binary Path | `IMAGEPATH` | string | ✅ |
| Start Type | `SERVICESTARTTYPE` | enum | ✅ |
| Host | `HOSTNAME` | string | ✅ |
| Severity | derived from correlation rule | enum (derived) | 🟡 |

**Filter**: `EVENTID IN (7045,7046,7047) AND (HOSTNAME=<device> OR CALLER_USERNAME=<user>)`

### 9.8 `threatIntelligence`
**Used by**: ip · domain · service
**Backing source**: ZLogs ES (TI-enriched events) + `ADSThreatAnalyticsFeeds` (feed registry only) + on-demand VirusTotal REST

| Field | Backend source | Type | Status |
|---|---|---|---|
| TI Engines matched | `terms` agg on `THREAT_SERVER` (values: `ATA`, `appsense`, customer-feed-name) | string[] (agg) | ✅ |
| Threat Categories | `terms` agg on `THREAT_CATEGORIES` | string[] (agg) | ✅ |
| Worst Reputation | `min(THREAT_REPUTATION)` (lower = worse) | integer (agg) | ✅ |
| Events Flagged count | `count(THREAT_SOURCE=<ioc>)` | integer (agg) | ✅ |
| Feed Subscription Status | `ADSThreatAnalyticsFeeds.ANALYTICS_FEED_TYPE/VERSION/FILE_META` | string | ✅ |
| Last Feed Update | `ADSThreatAnalyticsFeeds` row timestamp | timestamp | ✅ |
| VirusTotal Detections | REST `POST /RestAPI/V2/threat/getVirusTotalAnalysisData` (on-demand, client cache) | string (ratio) | 🟡 |

**Filter**: `THREAT_SOURCE=<ioc> OR REMOTEIP=<ioc>` ORDER BY `THREAT_REPUTATION ASC`

### 9.9 `idsAlerts`
**Used by**: ip · domain
**Backing source**: ZLogs ES — perimeter firewall/IPS syslog (PA / CheckPoint / Fortinet / Cisco). **No native IDS in product.**

> **Static projection** — the same 13 columns are always returned for every event regardless of vendor. The backend reads each parsed field directly from ZLogs; if the vendor's parser didn't emit a given field, the column is `null`/empty and the slider renders a dash. **No per-vendor branching, no derived signature strings.** If multiple vendor fields could represent "the signature" (e.g. PA's `THREAT_ID` vs CP's `PROTECTION_NAME`), each has its own column — the slider does not collapse them.

| # | Field | ES source (raw, no derivation) | Type |
|---|---|---|---|
| 1 | `timestamp` | `@timestamp` | timestamp |
| 2 | `hosttype` | `hosttype` | enum (paloalto device / checkpoint device / fortinet device / cisco device) |
| 3 | `deviceName` | `DEVICE_NAME` (firewall hostname that logged the event) | string |
| 4 | `srcIp` | `SRC_IP` | string |
| 5 | `srcPort` | `SRC_PORT` | integer |
| 6 | `dstIp` | `DST_IP` | string |
| 7 | `dstPort` | `DST_PORT` | integer |
| 8 | `protocol` | `PROTOCOL_TR` (L4 only: tcp/udp/icmp) | string |
| 9 | `threatId` | `THREAT_ID` | string |
| 10 | `protectionName` | `PROTECTION_NAME` | string |
| 11 | `attack` | `ATTACK` | string |
| 12 | `subtype` | `SUBTYPE` | string |
| 13 | `severityLevel` | `SEVERITYLEVEL` (or `SEVERITY` when `SEVERITYLEVEL` absent — same column read with COALESCE) | string |
| 14 | `actionTag` | `ACTION_TAG` | string |
| 15 | `action` | `ACTION` | string |
| 16 | `rawMessage` | `MESSAGE` (truncated to 500 chars) — fallback for vendors whose parser didn't extract a signature column | string |

**Vendor population reference** (informational only — not part of the projection; documents which columns each parser actually fills so analyst knows what "blank" means):

| Column | PaloAlto | CheckPoint | Fortinet | Cisco |
|---|---|---|---|---|
| `threatId` | populated | empty | empty | empty |
| `protectionName` | empty | populated | empty | empty |
| `attack` | empty | populated | empty | empty |
| `subtype` | populated (`vulnerability`/`spyware`/`virus`) | empty | populated (`ips`/`virus`/`webfilter`) | empty |
| `severityLevel` | populated (derived from threat-id lookup at parse time) | populated | empty | empty |
| `actionTag` | populated | empty | populated | empty |
| `action` | empty | populated | empty | empty |
| `rawMessage` | always | always | always (Fortinet signature name lives here) | always (entire alert lives here) |

**Filter**: `hosttype IN ('paloalto device','checkpoint device','fortinet device','cisco device') AND (SRC_IP=<ioc> OR DST_IP=<ioc>)` ORDER BY `@timestamp DESC`

**UI render shape** (slider event card) — the 16-column backend response is projected down to **5 fixed rows** that are identical for every event, regardless of vendor. Empty backend fields render as an em-dash (`—`):

| Row label | Derived from backend columns |
|---|---|
| Signature | `threatId` lookup name (PA) → else `protectionName` (CP) → else first line of `rawMessage` (Fortinet/Cisco) |
| Threat ID | `threatId` (PA only — blank elsewhere) |
| Severity | `severityLevel` |
| Action | `actionTag` (PA/Fortinet) → else `action` (CP) |
| Source Device | `deviceName` |

### 9.10 `firewallSummary`
**Used by**: ip · domain
**Backing source**: ZLogs ES — firewall syslog aggregated

| Field | Backend source | Type | Status |
|---|---|---|---|
| Total Flows | `count(SRC_IP=<ioc> OR DST_IP=<ioc>)` | integer (agg) | ✅ |
| Allowed | `count(ACTION_TAG=allow OR ACTION=accept)` | integer (agg) | ✅ |
| Denied | `count(ACTION_TAG IN (deny,drop) OR ACTION IN (deny,drop))` | integer (agg) | ✅ |
| Top Destination Ports | `terms` agg on `DST_PORT` (top-10, raw port number) | integer[] (agg) | ✅ |
| Top Transport Protocols | `terms` agg on `PROTOCOL_TR` (L4 only) | string[] (agg) | ✅ |
| Source Firewall Devices | `terms` agg on `DEVICE_NAME` | string[] (agg) | ✅ |

**Filter**: `(SRC_IP=<ioc> OR DST_IP=<ioc>) AND hosttype IN (paloalto,checkpoint,fortinet,cisco)`

### 9.11 `connectionHistory`
**Used by**: ip · domain
**Backing source**: ZLogs ES — firewall/proxy syslog

| Field | Backend source | Type | Status |
|---|---|---|---|
| Timestamp | `@timestamp` | timestamp | ✅ |
| Direction | derived from RFC1918 SRC/DST | enum (derived) | ✅ |
| Source IP / Port | `SRC_IP` / `SRC_PORT` | string / int | ✅ |
| Destination IP / Port | `DST_IP` / `DST_PORT` | string / int | ✅ |
| Bytes Sent | `SENT_BYTES` | integer | ✅ (PA/Fortinet/Sophos/FirePower/Topsec) · 🟡 CheckPoint (raw msg only) |
| Bytes Received | `RECEIVED_BYTES` | integer | ✅ (PA/Fortinet/Sophos/FirePower/Topsec) · 🟡 CheckPoint (raw msg only) |
| Duration | `DURATION` | integer | 🟡 |
| Action | `ACTION_TAG` / `ACTION` | enum | ✅ |
| Firewall Device | `DEVICE_NAME` / `HOSTNAME` | string | ✅ |
| Protocol | `PROTOCOL_TR` (L4 only) | string | ✅ |

**Filter**: `(SRC_IP=<ioc> OR DST_IP=<ioc>) AND hosttype IN (paloalto,checkpoint,fortinet,cisco,proxy)` ORDER BY `@timestamp DESC`

**UI render shape** (slider event card) — backend returns the full column set above; the slider projects each row to **9 fixed labels**, identical across every event and every IP entity. `Action` / `Device` render as `—` for endpoint-/flow-only sources (Sysmon, Windows) where there is no firewall in the path:

| Row label | Backend column |
|---|---|
| Direction | derived (RFC1918 SRC vs DST) |
| Source | `SRC_IP` (+ optional reverse-DNS host) |
| Destination | `DST_IP` (+ optional reverse-DNS host) |
| Port | `DST_PORT` |
| Bytes Sent | `SENT_BYTES` |
| Bytes Received | `RECEIVED_BYTES` |
| Duration | `DURATION` |
| Action | `ACTION_TAG` / `ACTION` (— if absent) |
| Device | `HOSTNAME` of firewall appliance (— if non-firewall source) |

### 9.12 `dnsHistory`
**Used by**: ip · domain
**Backing source**: ZLogs ES — Windows DNS Server (EID 1033/1034) / Sysmon EID 22

| Field | Backend source | Type | Status |
|---|---|---|---|
| Timestamp | `@timestamp` | timestamp | ✅ |
| Domain Queried | `QUERY_NAME` | string | ✅ |
| Record Type | `RECORD_TYPE` | string | ✅ |
| Resolution | `ANSWER_RECORDS` / `QUERY_RESULTS` | string | ✅ |
| Querying Process | Sysmon `IMAGE` (EID 22) | string | 🟡 |
| Querying Host | `HOSTNAME` | string | ✅ |
| Query Status | `QUERY_STATUS` | enum | ✅ |

**Filter**: `(QUERY_NAME=<domain> OR QUERY_RESULTS contains <ioc>) AND (EVENTID IN (1033,1034) OR SYSMON_EVENTID=22)` ORDER BY `@timestamp DESC`

**UI render shape** (slider event card) — projected to **4 fixed rows**. Backing source (Sysmon EID 22 vs Windows DNS EID 1033/1034) is documented here, not shown per-row, to avoid collision with network "source" semantics:

| Row label | Backend column |
|---|---|
| Domain | `QUERY_NAME` |
| Record Type | `RECORD_TYPE` |
| Resolution | `ANSWER_RECORDS` / `QUERY_RESULTS` |
| Querying Process | Sysmon `IMAGE` (EID 22) — — when backing source is Windows DNS Server logs |

### 9.13 `recentAlerts`
**Used by**: user · device · ip · domain · service · process · alert
**Backing source**: `ITSAlertProfileConfigurations` + alert instance store + `ITSDetectionRuleVsMitre` (MITRE join)

| Field | Backend source | Type | Status |
|---|---|---|---|
| Alert ID | rule `ALERT_PROFILE_ID` + instance UID | string | ✅ |
| Alert Name | `ITSAlertProfileConfigurations.DISPLAY_NAME` | string | ✅ |
| Alert Source / Type | `ALERT_TYPE` | enum | ✅ |
| Severity | `SEVERITY` | enum | ✅ |
| MITRE Tactic + Technique | `ITSDetectionRuleVsMitre.TACTIC/TECHNIQUE_NAME` (join) | string (join) | 🟡 |
| First Triggered | instance creation timestamp | timestamp | ✅ |
| Status | workflow state | enum | ✅ |
| Linked Entity ID | alert-entity link | string | ✅ |

**Filter**: `alert.source_entity=<entity_id>` ORDER BY `first_triggered DESC`

### 9.14 `accountLockouts`
**Used by**: user
**Backing source**: ZLogs ES — Windows Security EID 4740

| Field | Backend source | Type | Status |
|---|---|---|---|
| Timestamp | `@timestamp` | timestamp | ✅ |
| Target User | `TARGETUSER` | string | ✅ |
| Locking DC | `HOSTNAME` | string | ✅ |
| Source Computer | `REMOTEHOST` / `WORKSTATION_NAME` | string | 🟡 |
| Event ID | `EVENTID` (4740) | integer | ✅ |
| Risk Label | derived from correlation rule | enum | 🟡 |

**Filter**: `EVENTID=4740 AND TARGETUSER=<user>` ORDER BY `@timestamp DESC`

### 9.15 `passwordHistory`
**Used by**: user
**Backing source**: ZLogs ES — Windows EID 4723/4724 OR Entra UAL `Change/Reset user password`

| Field | Backend source | Type | Status |
|---|---|---|---|
| Timestamp | `@timestamp` | timestamp | ✅ |
| Operation | derived from `EVENTID` / `OPERATION` | enum | ✅ |
| Caller | `USERNAME`+`DOMAIN` / Entra `USERID` | string | ✅ |
| Target User | `TARGETUSER` / Entra `OBJECTID` | string | ✅ |
| Source Host | `HOSTNAME` / Entra `Workload=AzureActiveDirectory` | string | ✅ |
| Client IP | Entra `CLIENTIP` (not on Windows) | string | Windows ❌ · Entra ✅ |
| Result | `SEVERITY` / Entra `RESULT` | enum | ✅ |

**Filter**: `(EVENTID IN (4723,4724) AND TARGETUSER=<user>) OR (OPERATION IN ('Change user password.','Reset user password.') AND OBJECTID=<user_upn>)` ORDER BY `@timestamp DESC`

### 9.16 `groupMembershipChanges`
**Used by**: user
**Backing source**: ZLogs ES — Windows EID 4728/4729/4732/4733/4756/4757 OR Entra UAL `Add/Remove member to group`

| Field | Backend source | Type | Status |
|---|---|---|---|
| Timestamp | `@timestamp` | timestamp | ✅ |
| Operation | derived from `EVENTID` / Entra `OPERATION` | enum | ✅ |
| Group Name | `GROUPNAME`+`GROUPDOMAIN` / Entra `PARAMETERS.Group.DisplayName` | string | ✅ |
| Member Added/Removed | `TARGETUSER`+`MEMBERSID` / Entra `PARAMETERS.Member.userPrincipalName` | string | ✅ |
| Caller (admin) | `USERNAME`+`DOMAIN` / Entra `USERID` | string | ✅ |
| Source Host | `HOSTNAME` / Entra source | string | ✅ |

**Filter**: see strict DSL in subagent report.

### 9.17 `mailboxForwarding`
**Used by**: user
**Backing source**: ZLogs ES — M365 UAL `Audit.Exchange`, ops `New/Set-InboxRule`, `Set-Mailbox`, `Set-TransportRule`

| Field | Backend source | Type | Status |
|---|---|---|---|
| Timestamp | `@timestamp` (UAL `CreationTime`) | timestamp | ✅ |
| Operation | `OPERATION` | string | ✅ |
| Mailbox | `OBJECTID` | string | ✅ |
| Caller | `USERID` | string | ✅ |
| Rule Name | `PARAMETERS.Name` | string | ✅ |
| Forward To / Redirect | `PARAMETERS.ForwardTo` / `ForwardingSmtpAddress` / `RedirectTo` | string | ✅ |
| Client IP | `CLIENTIP` | string | ✅ |
| Result | `RESULT` | enum | ✅ |

**Filter**: `hosttype=m365 AND OPERATION IN ('New-InboxRule','Set-InboxRule','Set-Mailbox','Set-TransportRule') AND OBJECTID=<user_mailbox>` ORDER BY `@timestamp DESC`

### 9.18 `uebaProfile`
**Used by**: user
**Backing source**: `ITSEntityRiskScoreDetails` + `ADSAnomalyDetectionUniqueEntities` + `UEBAEntityNotes`

| Field | Backend source | Type | Status |
|---|---|---|---|
| Risk Score (0–100) | `RISK_SCORE × 100` | integer | ✅ |
| Last Anomaly Fired | `LAST_ANOMALY_UPDATE_TIME` | timestamp | ✅ |
| Last Score Update | `LAST_UPDATE_TIME` | timestamp | ✅ |
| Under Observation | `ADSAnomalyDetectionUniqueEntities.IS_SURVEILLED` | boolean | ✅ |
| Detection Source | `ADSAnomalyDetectionUniqueEntities.SOURCE` | string | ✅ |
| Analyst Notes | `UEBAEntityNotes.NOTE` | string | ✅ |

**Filter**: `ITSEntityRiskScoreDetails.ENTITY_ID=<user_id> AND ENTITY_TYPE='user'` INNER JOIN `ADSAnomalyDetectionUniqueEntities`

### 9.19 `loginStatistics`
**Used by**: user
**Backing source**: ZLogs ES — Windows Security 4624/4625 over 7-day window

| Field | Backend source | Type | Status |
|---|---|---|---|
| Total Logins | `count(EVENTID IN (4624,4625))` | integer (agg) | ✅ |
| Successful Logins | `count(EVENTID=4624)` | integer (agg) | ✅ |
| Failed Logins | `count(EVENTID=4625)` | integer (agg) | ✅ |
| Unique Source IPs | `terms` agg on `IPADDRESS` (4624) | string[] (agg) | ✅ |
| Off-Hours Logins | `count(EVENTID=4624)` filtered via `L3CWorkingHourHandler.isOffHours()` | integer (agg) | 🟡 |
| Unique Target Hosts | `terms` agg on `HOSTNAME` (4624) | string[] (agg) | ✅ |

**Filter**: `USERNAME=<user> AND EVENTID IN (4624,4625) AND @timestamp >= now-7d`

### 9.20 `cloudIdentities`
**Used by**: user (conditional — requires M365 onboarding)
**Backing source**: `APFDiscAADUserDetails`

| Field | Backend source | Type | Status |
|---|---|---|---|
| UPN | `USER_PRINCIPAL_NAME` | string | ✅ |
| Sync Source | `ONPREMISES_SYNC_ENABLED` | boolean | ✅ |
| Cloud Account Status | `ACCOUNT_ENABLED` | boolean | ✅ |
| Licensed | `IS_LICENSED` | boolean | ✅ |
| Last Dir Sync | `DAYS_SINCE_LAST_DIR_SYNC` / `LAST_DIRSYNC_TIME` | integer/timestamp | 🟡 |
| Strong Password Required | `STRONG_PASSWORD_REQUIRED` | boolean | ✅ |
| Password Days Since Change | `DAYS_SINCE_PASSWORD_CHANGE` | integer | 🟡 |
| Hidden From Address List | `HIDDEN_FROM_ADDRESS_LIST` | boolean | ✅ |

**Filter**: `USER_PRINCIPAL_NAME=<user_upn> AND APP_CONFIG_ID=<azure_config_id>` (only render when tenant has M365 connector)

### 9.21 `identityRisk`
**Used by**: user
**Backing source**: `APFDiscADUserDetails` + optional join `APFDiscADGroupMemberDetails`/`APFDiscADGroupDetails`

| Field | Backend source | Type | Status |
|---|---|---|---|
| Password Age (days) | `PASSWORD_LAST_SET` (client derives) | integer (derived) | ✅ |
| Days Since Last Logon | `DAYS_SINCE_LAST_LOGON` | integer | ✅ |
| Account Status | `ACCOUNT_STATUS` + `LOCK_OUT_TIME` | enum | ✅ |
| Password Never Expires | `PWD_NEV_EXP_FLAG` | boolean | ✅ |
| Smartcard Required | `SMART_CARD_FOR_INTERACTIVE_LOGIN` | boolean | ✅ |
| Trusted for Kerberos Delegation | `TRUSTED_FOR_DELEGATION` | boolean | ✅ |
| Bad Password Count | `BAD_PASSWORD_COUNT` | integer | ✅ |
| Privileged Group Membership | join `APFDiscADGroupMemberDetails`+`APFDiscADGroupDetails` where `SID_STRING` matches well-known admin RIDs (512/519/518/544) | string[] (join) | ✅ |

### 9.22 `processDetails`
**Used by**: process
**Backing source**: ZLogs ES — Windows EID 4688 + Sysmon EID 1

| Field | Backend source | Status |
|---|---|---|
| Process Name | `PROCESSNAME` | ✅ |
| PID | `PROCESS_ID` | ✅ |
| Parent Process | `PARENT_PROCESS_NAME` | ✅ |
| Command Line | `COMMAND_LINE` | 🟡 |
| Executing User | `USERNAME`+`DOMAIN` | ✅ |
| Integrity Level | `INTEGRITY_LEVEL` | 🟡 |
| Start Time | `@timestamp` | ✅ |
| Status | derived "Running"/"Exited" | 🟡 |
| Code Signature Status | `SIGNATURE_STATUS` (Sysmon) | 🟡 |
| Session ID | `SESSION_ID` | ✅ |
| ~~Thread Count~~ | not in logs (live-process only via EDR) | ❌ |
| ~~Handle Count~~ | not in logs (live-process only via EDR) | ❌ |

### 9.23 `amsiEvents`
**Used by**: process
**Backing source**: ZLogs ES — Windows PowerShell EID 4104 with AMSI

| Field | Backend source | Status |
|---|---|---|
| Timestamp | `@timestamp` | ✅ |
| AMSI Detection Level | `AMSI_RESULT` | ✅ |
| Script Content Preview | `SCRIPTBLOCK_TEXT` (first 500 chars) | ✅ |
| Scan Result | `AMSI_SCAN_RESULT` | ✅ |
| Action Taken | derived from policy | 🟡 |
| Script Block ID | `SCRIPTBLOCK_ID` | ✅ |

**Filter**: `EVENTID=4104 AND (AMSI_RESULT IN (Suspicious,Malicious) OR AMSI_SCAN_RESULT=DETECTED) AND PROCESSNAME contains powershell`

### 9.24 `registryModifications`
**Used by**: process
**Backing source**: ZLogs ES — Sysmon EID 12/13/14

| Field | Backend source | Status |
|---|---|---|
| Timestamp | `@timestamp` | ✅ |
| Operation | Sysmon EID type | ✅ |
| Registry Key Path | `REGISTRY_KEY_PATH` | ✅ |
| Value Name | `VALUE_NAME` | 🟡 |
| Old Value | `OLD_VALUE` | 🟡 |
| New Value | `NEW_VALUE` | 🟡 |
| Process | `PROCESSNAME`+`PROCESS_ID` | ✅ |

**Filter**: `SYSMON_EVENTID IN (12,13,14) AND PROCESSNAME=<process_name>`

### 9.25 `tokenAnomaly`
**Used by**: process
**Backing source**: ZLogs ES — Windows EID 4672 + Sysmon EID 8

| Field | Backend source | Status |
|---|---|---|
| Anomaly Type | derived (SeDebugPrivilege / SeImpersonate / CreateRemoteThread) | 🟡 |
| Privilege Name | `PRIVILEGE_NAME` | ✅ |
| Process | `PROCESSNAME` | ✅ |
| Caller | `USERNAME` | ✅ |
| Timestamp | `@timestamp` | ✅ |

**Filter**: `(EVENTID=4672 AND PRIVILEGE_NAME contains 'Se') OR SYSMON_EVENTID=8 AND PROCESSNAME=<process_name>`

### 9.26 `fileOperations`
**Used by**: process
**Backing source**: ZLogs ES — Sysmon EID 11

| Field | Backend source | Status |
|---|---|---|
| Timestamp | `@timestamp` | ✅ |
| Operation | Create/Delete/Modify (EID 11) | 🟡 |
| File Path | `FILE_PATH` | ✅ |
| File Size | `FILE_SIZE` | ✅ |
| Hash (SHA256) | `FILE_HASH`/`HASH_SHA256` | ✅ |
| Signed | `SIGNED` | ✅ |
| Process | `PROCESSNAME`+`PROCESS_ID` | ✅ |

**Filter**: `SYSMON_EVENTID=11 AND PROCESSNAME=<process_name>`

### 9.27 `dllLoads`
**Used by**: process
**Backing source**: ZLogs ES — Sysmon EID 7 (high-volume)

| Field | Backend source | Status |
|---|---|---|
| Timestamp | `@timestamp` | ✅ |
| DLL Name | `IMAGE_NAME` | ✅ |
| DLL Path | `IMAGE_PATH` | ✅ |
| Signed | `SIGNED` | ✅ |
| Loaded By Process | `PROCESSNAME`+`PROCESS_ID` | ✅ |
| Load Address | `BASE_ADDRESS` | 🟡 |

**Filter**: `SYSMON_EVENTID=7 AND PROCESSNAME=<process_name>` ORDER BY `@timestamp DESC` LIMIT 50

### 9.28 `processDnsQueries`
**Used by**: process
**Backing source**: ZLogs ES — Sysmon EID 22

| Field | Backend source | Status |
|---|---|---|
| Timestamp | `@timestamp` | ✅ |
| Domain Queried | `QUERY_NAME` | ✅ |
| Record Type | `RECORD_TYPE` | ✅ |
| Resolution | `QUERY_RESULTS` | ✅ |
| Querying Process | `PROCESSNAME`+`PROCESS_ID` | ✅ |

**Filter**: `SYSMON_EVENTID=22 AND PROCESSNAME=<process_name>`

### 9.29 `alertDetails`
**Used by**: alert
**Backing source**: `ITSAlertProfileConfigurations` + alert instance + `ITSDetectionRuleVsMitre`

| Field | Backend source | Status |
|---|---|---|
| Alert Name | `DISPLAY_NAME` | ✅ |
| Alert ID | instance UID | ✅ |
| Alert Source | `ALERT_TYPE` | ✅ |
| Severity | `SEVERITY` | ✅ |
| Confidence | `CONFIDENCE_SCORE` (if present) | 🟡 |
| Rule | `RULE_NAME` | ✅ |
| MITRE ATT&CK | `ITSDetectionRuleVsMitre.TACTIC`/`TECHNIQUE_NAME` (join) | 🟡 |
| First Seen | instance creation timestamp | ✅ |
| Status | workflow state | ✅ |
| Assigned To | analyst assignment | 🟡 |
| Incident ID | linked incident | 🟡 |
| Correlation | count of linked alerts | 🟡 |

### 9.30 Common payload envelope (every section)

Regardless of section, every API response wraps the projected fields in this envelope so the slider can render section-status uniformly:

| Envelope field | Type | Meaning |
|---|---|---|
| `sectionId` | string | matches one of §9.1–9.29 IDs |
| `label` | string | display label |
| `status` | enum: `ok` / `partial` / `unavailable` | `partial` = some fields 🟡, `unavailable` = backing source not configured (e.g. M365 not onboarded for `cloudIdentities`) |
| `statusReason` | string | when `partial`/`unavailable`, explain why (`"M365 connector not configured"`, `"Sysmon not deployed on this host"`, `"VT API key missing"`) |
| `rows` or `kv` or `timeline` | array/object | actual projected payload — shape determined by the section's render mode in [entity-slider.js](js/modules/entity-slider.js) |
| `truncated` | boolean | true if result set was capped by `LIMIT` (e.g. `dllLoads` LIMIT 50) |
| `queriedAt` | timestamp | server-side query execution time |

### 9.31 Pending inventory — sections referenced by the slider but not yet ground-truthed

These section IDs appear in [entity-slider.js](js/modules/entity-slider.js) tab definitions but their static projections have not been verified against parser XMLs / data-dictionary.xml. **Do not fabricate projections — to be added as code/parser audits complete.**

| Section ID | Used by | Likely backing source (unverified — needs audit) |
|---|---|---|
| `threatIntelContext` | user | ZLogs `THREAT_*` fields filtered by user's recent activity |
| `dlpIncidents` | user | M365 DLP / `Audit.DLP` UAL events |
| `resourceFileAccess` | user | Windows EID 4663 + file-server audit |
| `recentAppAccess` | user | M365 sign-in audit / SaaS proxy logs |
| `agentStatus` | device | EDR/MDE agent health endpoint (likely not in ZLogs) |
| `gpoApplied` | device | `APFDiscADComputerDetails` + GPO RSoP discovery |
| `processesOnHost` | device | same projection as `processes` (§9.6) — verify filter |
| `servicesOnHost` | device | Windows EID 7045 host-scoped — verify columns |
| `usersLoggedOn` | device | 4624 host-scoped distinct-user agg — verify |
| `loginActivity` | device | same as `logonActivity` (§9.4) — confirm alias |
| `scheduledTasks` | device | Windows EID 4698/4699/4700/4701/4702 |
| `usbDeviceEvents` | device | Windows EID 6416/6420 (Plug-and-Play) |
| `localAccountLifecycle` | device | Windows EID 4720/4722/4725/4726 host-scoped |
| `ipDetails` | ip · domain | derived: `IPADDRESS`/`HOSTNAME` + MaxMind GeoIP + `ADSCountries.xml` lookup |
| `associatedUsers` | ip · domain | Windows 4624/4625 + IPADDRESS pivot |
| `associatedDevices` | ip · domain | Windows 4624 + HOSTNAME pivot |
| `vpnSessions` | ip · domain | firewall VPN logs (PA GlobalProtect / Fortinet SSLVPN / Cisco AnyConnect) |
| `trafficSummary` | ip · domain | aggregate variant of `connectionHistory` |
| `serviceDetails` | service | unclear — possibly correlation rule definition for the service entity |
| `serviceInfo` | service | same as `serviceDetails` — confirm if duplicate |
| `oauthConsentGrants` | service | M365 UAL `Add OAuth2PermissionGrant`/`Consent to application` |
| `conditionalAccess` | service | Entra CA policy snapshot (likely from Graph API, not ZLogs) |
| `dlpPolicies` | service | M365 DLP policy snapshot |
| `signInAudit` | service | M365 `Audit.AzureActiveDirectory` SignIn records |
| `adminActivity` | service | M365 UAL admin operations |
| `fileAccessAnomaly` | service | SharePoint/OneDrive `FileAccessed` UAL events with anomaly score |
| `sensitiveFiles` | service | M365 sensitivity-label tagged file access |
| `serviceTimeline` | service | aggregated timeline across UAL records for the service |
| `networkConnections` | service | Sysmon EID 3 scoped to service-related process |
| `fileDrops` | service | Sysmon EID 11 scoped |
| `wmiEvents` | service | Sysmon EID 19/20/21 |
| `processTree` | process | computed graph from EID 4688/Sysmon-1 parent chain |
| `childProcesses` | process | inverse of `processTree` |
| `namedPipes` | process | Sysmon EID 17/18 |
| `tokenUsage` | process | similar to `tokenAnomaly` minus the anomaly filter |
| `triggerConditions` | alert | rule definition from `ITSAlertProfileConfigurations` |
| `affectedEntities` | alert | alert-entity link table |
| `correlatedAlerts` | alert | correlation engine output |

---

## 14. Changelog

| Date | Change |
|------|--------|
| 18 May 2026 | Slider UI hardening: enforced uniform row-key contract on `idsAlerts` (5 rows), `connectionHistory` (9 rows across both IP entities), `dnsHistory` (4 rows). Dropped `firewallSummary` from the Threat Intel tab (ip + domain) — redundant with `connectionHistory` + `trafficSummary` under Connections. Added "UI render shape" tables to §9.9 / §9.11 / §9.12 documenting the projection from backend columns to fixed slider row labels. |
| 18 May 2026 | Added §9 APPENDIX — Static Field Projections per Section (29 sections fully inventoried with backend-grounded ES `_source` / SQL-select projections; 38 sections listed as pending inventory). Companion JSON config at `js/data/section-projections.json`. Per-section common envelope (§9.30) standardizes status/truncation/queriedAt across all responses. |
| 18 May 2026 | §3.4 Threat Intelligence rewritten to match actual code path: `ThreatDataEnrichment` writes `THREAT_SOURCE/REPUTATION/CATEGORIES/SERVER` fields onto every TI-matched event at ingest; verdicts queryable as ES aggs (not a separate verdict-cache table). Engines verified in code: `ATA` (default) + `appsense` (Zoho TIP). VT corrected from "periodic 6h job" to on-demand REST `/RestAPI/V2/threat/getVirusTotalAnalysisData`. `ADSThreatAnalyticsFeeds` clarified as feed-registry metadata only. Per-vendor breakdown restored as ✅ via `terms` agg on `THREAT_SERVER`. |
| 07 May 2026 | Added §8 EDGE RELATION Slider data-source mapping (13 sub-sections covering flow diagram, MITRE, detection rule, connection properties, sparkline, behavioral baseline, threat intel, geo, evidence, per-edge schema, demo inventory of 16 edges, data-source summary). Renumbered subsequent sections 8→13. |
| 07 May 2026 | Initial V5 mapping. Mirrors V4 structure but adds explicit **AI Enrichment** column showing what AI agents can fetch beyond product backend (live IOC enrichment, WHOIS, MITRE mapping, narrative generation, compliance drafting, script deobfuscation). Covers 8 entity types, ~50 distinct sections. Cross-references the canonical relation catalog. |
