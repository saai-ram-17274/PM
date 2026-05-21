# Baseline Entity Inventory — User · Device · IP · Location · Process · File · Domain

> **Scope:** What each entity slider can show on a **fresh Log360 Cloud install** with **only AD directory sync + Windows Security Event Log forwarding** enabled. No firewall syslog, no M365/Azure AD audit, no Sysmon, no EDR, no DLP module.
>
> **On-demand exceptions allowed at baseline:** Webroot threat-intel lookups (URL/Domain WHOIS, verdict, CDB) are fired per-IOC from the workbench (no subscription required for IP/Domain enrichment). Treated as baseline because they ship enabled.
>
> **Source of truth:** verified against `adsf` / `itsf` / `log360_cloud` parsers, `APFDiscAD*` table definitions, AND **actual parsed zlog field names from production-tenant screenshots** (4624 / 4663 / 4688 / 4738). See `entity_data_mapping.md` §9 for full per-field projections.

---

## Baseline data sources (the only inputs assumed)

| Source | What it gives us | Powers entities |
|---|---|---|
| **AD directory sync** | **User / Computer / Group inventory:** `APFDiscADUserDetails` · `APFDiscADComputerDetails` · `APFDiscADGroupDetails` — all object attributes (DN, OU, UAC flags, manager, last-logon, when-created). **Domain / DC / Forest topology:** `ADSDomainConfiguration` · `ADSDCConfiguration` · `ADSForestConfiguration` (the AD-sync configuration / topology tables — see [data-dictionary.xml](/home/saairam-17274/Documents/REPOS/ADSF-DD-DML/product_package/conf/adsf/common/domain/data-dictionary.xml)). **`APFDiscADGPO*` tables do not exist** at baseline. | 👤 User · 🖥️ Device · 🌐 Domain (AD-flavor) |
| **Windows Security Event Log** (forwarded) | Logon: **4624 / 4625 / 4634** · Lockout: **4740** · Kerberos (DC): **4768 / 4771 / 4776** · Account lifecycle: **4720 / 4722 / 4723 / 4724 / 4725 / 4726 / 4738** · Group changes: **4727–4729 / 4731–4733 / 4754–4757** · Process: **4688 / 4689** · Object access: **4663** (needs SACL) · Scheduled task: **4698–4702** · Service install: **7045** | 👤 User · 🖥️ Device · 🌐 IP · ⚙️ Process · 📁 File · 🌐 Domain (AD-flavor) |
| **⚠️ Parser path (rich vs thin)** | Win-Sec events arrive via two parser code-paths discriminated by the `source` field on the parsed event: **rich path** (`source: microsoft-windows-security-auditing`, hyphenated) extracts every structured field — `username`, `domain`, `remoteip`, `remotehost`, `logontype`, `processname`, `processid`, `parentprocessname`, `parentprocessid`, `objectname`, `objecttype`, `accesses`, `accessmask`, `package_name`, `authenticationpackage`, `risk_level`, `elevatedtoken`, `virtualaccount`, `sourceport`, `clientip`, `linkedlogonid`. **Thin path** (`source: microsoft windows security`, space-separated) carries only header + raw message; sub-fields are NOT extracted. **Every claim below assumes rich-path collectors.** Thin-path tenants get only `eventid` + raw `message` + `hostname`. | Discriminator — gates every entity except User-AD-only and Device-AD-only |
| **Built-in ingest enrichments** | `GeoInfoEnrichment` writes only `SOURCE_COUNTRY` and only for AWS / Azure AD / Salesforce / VPN-success logtypes — **Windows Security 4624/4625 is NOT in this allow-list**. `IPGeoInfo` (City / Region / ASN / Lat / Long) is populated only by on-demand Webroot lookups, not on the event row. | 🌐 IP (on-demand only) · 📍 Location (after Path B) |
| **Webroot threat-intel (on-demand)** | `WebrootProviderAPI.java` — per-IOC URL/Domain WHOIS, reputation verdict, CDB stats/connections. Fires from workbench/slider, never indexed onto the event row. | 🌐 IP (verdict) · 🌐 Domain (DNS-flavor) |
| **UEBA (rule-based anomaly detection)** | `AnomalyRuleHandler.java` fires rule-matched anomalies (first-time-action, after-hours-action). **No peer-group baselines, no rolling-mean baselines, no `current_vs_baseline_delta`** — grep on `peerGroup` / `baseline_logons` / `baseline_hours` returns zero hits. | `riskSummary` anomaly counts on User / Device |
| **Built-in alert catalog** (`ITSAlertProfileConfigurations`) | Alert profiles whose detection rules use only the data above. | `recentAlerts` on every entity |

Everything below is achievable with **only** the rows in that table. Anything requiring more is explicitly out of scope and called out as **Gated by integration**.

---

## 👤 USER entity — 8 baseline sections

Keyed on AD `sAMAccountName` / `LOGON_NAME` (UPN), joined to Win-Sec via the parsed **`username`** field (rich-path) on every event. Actor-side events use the same `username` field — the parser does not split into Subject/Target like the raw EVTX schema does. The `domain` field on the event identifies the user's AD domain.

| Tab | Section | Backing data (one-line) |
|---|---|---|
| Overview | `riskSummary` | Rule-based anomaly count over 4624/4625 + AD account-age signals (no statistical peer-group score — see note below) |
| Overview | `usersDetails` | `APFDiscADUserDetails` |
| Risk & Identity | `loginStatistics` | `count`/`agg` on 4624 (success) + 4625 (failure) |
| Activity | `logonActivity` | 4624 / 4625 timeline |
| Account Changes | `accountLockouts` | 4740 |
| Account Changes | `passwordHistory` | 4723 (user-initiated) + 4724 (admin-initiated) |
| Account Changes | `groupMembershipChanges` | 4727 / 4728 / 4729 / 4755 / 4756 / 4757 |
| Recent Alerts | `recentAlerts` | Alert profiles whose rules use only Win-Sec + AD data |

### Sub-field breakdown (in top-table order)

#### 1. `riskSummary` (fields actually rendered by the prototype — [entities.js#L530-L552](js/data/entities.js#L530-L552))

| Sub-field | Prototype value | Real backing | Status |
|---|---|---|---|
| `riskScore` / `maxScore` | `94 / 100` | `ITSEntityRiskScoreDetails.RISK_SCORE` (the entity-level rolling score) | ✅ |
| `severity` | `Critical` | `ITSEntityRiskScoreDetails.SESSION_SEVERITY` → `ITSRiskSeverityDetails.SEVERITY_NAME` | ✅ |
| `metrics[0]` | `Anomalies (session / lifetime)` = `7 / 47` | session = anomaly hits in current `ITSEntityRiskScoreDetails` session row; lifetime = `SUM` across all session rows for entity | ✅ |
| `metrics[1]` | `Failed Logins (24h)` = `4` | `count(eventid=4625 AND username=:user AND _zl_timestamp > now-24h)` | ✅ |
| `metrics[2]` | `Last Anomaly` (dynamic) | `ITSEntityRiskScoreDetails.LAST_ANOMALY_UPDATE_TIME` | ✅ |
| `heroChips[0]` | `Last Logon` = `11 May 2026 09:41:10` | `APFDiscADUserDetails.LAST_LOGON_TIME` (real DB column, retention-immune) | ✅ |

#### 2. `usersDetails` (fields actually rendered by the prototype — [entities.js#L552-L555](js/data/entities.js#L552-L555))

| Prototype label | Prototype value | Real backing | Status |
|---|---|---|---|
| Display Name | `m.henderson` | `APFDiscADUserDetails.DISPLAY_NAME` | ✅ |
| SAM Account Name | `m.henderson` | `APFDiscADUserDetails.SAM_ACCOUNT_NAME` | ✅ |
| UPN | `m.henderson@contoso.com` | `APFDiscADUserDetails.LOGON_NAME` | ✅ |
| Email | `m.henderson@corp.local` | `APFDiscADUserDetails.EMAIL_ADDRESS` | ✅ |
| Job Title | `IT Support Engineer` | `APFDiscADUserDetails.TITLE` | ✅ |
| Department | `IT` | `APFDiscADUserDetails.DEPARTMENT` | ✅ |
| Manager | `j.williams (IT Manager)` | `APFDiscADUserDetails.MANAGER_DN` (resolve to display name) | ✅ |
| Last Logon Time | `09:41:10` | `APFDiscADUserDetails.LAST_LOGON_TIME` (or `LAST_LOGON_TIMESTAMP`) | ✅ |
| OU Name | `OU 1` | parsed from `APFDiscADUserDetails.DISTINGUISHED_NAME` | ✅ |
| Account Created | `2024-03-15` | `APFDiscADUserDetails.WHEN_CREATED` | ✅ |

#### 3. `loginStatistics` (fields actually rendered — [entities.js#L658-L668](js/data/entities.js#L658-L668), 7-day window)

| Prototype label | Prototype value | Real backing | Status |
|---|---|---|---|
| Total Logins | `47` | `count(eventid IN (4624,4625) AND username=:user AND _zl_timestamp > now-7d)` | ✅ |
| Successful | `43 (91.5%)` | `count(eventid=4624 ...)` | ✅ |
| Failed | `4 (8.5%)` | `count(eventid=4625 ...)` | ✅ |
| Unique Source IPs | `3 (192.168.1.22, 10.18.1.81, 10.112.11.1)` | `cardinality(remoteip)` + `terms` agg for the list | ✅ |
| Off-Hours Logins | `2` | `count(... AND HOUR(_zl_timestamp) NOT BETWEEN 8 AND 20)` | ✅ |
| Unique Hosts | `3 (CORP-WS-045, CORP-SRV-01, CORP-FS-02)` | `cardinality(hostname)` + `terms` agg | ✅ |

#### 4. `logonActivity` (timeline)

Driven entirely by **Windows Security Event IDs 4624 (logon success) / 4625 (logon failure)** filtered by `username=:user`. Row severity dot (red / orange / green) maps from `ITSEntityRiskScoreDetails.SESSION_SEVERITY` → `ITSRiskSeverityDetails.SEVERITY_NAME` (CRITICAL→red, ATTENTION→orange, TROUBLE/none→green). **Rich-path bonus facets available per-event:** `logontype` (2/3/10/11), `package_name` (NTLM/Kerberos/Negotiate), `authenticationpackage`, `remoteip`, `remotehost`, `sourceport`, `elevatedtoken` (yes/no — admin token usage), `virtualaccount`, `linkedlogonid` (correlate paired sessions), `risk_level` (per-event score from the parser). ✅

#### 5–7. `accountLockouts` / `passwordHistory` / `groupMembershipChanges` (timelines)

| Section | Windows Security Event IDs | Status |
|---|---|---|
| `accountLockouts` | **4740** (account locked out) | ✅ |
| `passwordHistory` | **4723** (self-service change) ∪ **4724** (admin reset) | ✅ |
| `groupMembershipChanges` | Global: **4727 / 4728 / 4729** · Local: **4731 / 4732 / 4733** · Universal: **4754 / 4755 / 4756 / 4757** | ✅ |

#### 8. `recentAlerts`

Any alert profile in `ITSAlertProfileConfigurations` whose detection rule pivots on baseline Win-Sec + AD data, filtered by `username=:user`. ✅

#### Bonus baseline-reachable User sections (rich-path only)

| Section | Backing | Status |
|---|---|---|
| `authMethodBreakdown` | `terms(package_name)` over 4624 filtered by `username=:user` — NTLM vs Kerberos vs Negotiate split | ✅ rich-path |
| `elevatedTokenUsage` | `count(eventid=4624 AND elevatedtoken="yes")` — admin-token logon detection | ✅ rich-path |
| `processesLaunched` | 4688 filtered by `username=:user` — `processname` + `commandline` + `parentprocessname` (rich-path 4688 only — see Process entity caveats) | 🟡 rich-path conditional |
| `objectsAccessed` | 4663 filtered by `username=:user` — `objectname` + `accesses` + `severity` (success/failure) | 🟡 needs SACL on resources |

**Gated by integration** (would appear empty/hidden at baseline): `cloudIdentities`, `identityRisk`, `threatIntelContext`, `dlpIncidents`, `networkActivity`, `recentAppAccess`, `mailboxForwarding`, `serviceTriggered` (partial).

---

## 🖥️ DEVICE (host) entity — 6 baseline sections

Keyed on AD `DNS_NAME` / `NAME` (the `cn`), joined to Win-Sec via the parsed **`hostname`** field (rich-path). **Caveat:** `hostname` can be either a DNS-form name (e.g., `corp-ws-045.contoso.local`) or an **IP literal** (e.g., `192.168.60.1`, as seen in the 4663 production screenshot). Device-entity join therefore needs **two-step**: (1) direct match on AD `NAME` / `DNS_NAME`; (2) fallback reverse-IP lookup via `APFDiscADComputerDetails` when `hostname` is an IPv4/IPv6 literal.

| Tab | Section | Backing data (one-line) |
|---|---|---|
| Overview | `riskSummary` | Derived from baseline events targeting this computer |
| Overview | `deviceDetails` | `APFDiscADComputerDetails` |
| Host Activity | `usersLoggedOn` | 4624 filtered by `hostname` |
| Host Activity | `loginActivity` | 4624 / 4625 on this host |
| Device Activity | `localAccountLifecycle` | 4720 / 4722 / 4723 / 4724 / 4726 against local SAM |
| Alerts & Response | `recentAlerts` | Baseline-data alert profiles |

### Sub-field breakdown (in top-table order)

#### 1. `riskSummary` (fields actually rendered by the prototype — [entities.js#L1198-L1210](js/data/entities.js#L1198-L1210))

| Sub-field | Prototype value | Real backing | Status |
|---|---|---|---|
| `riskScore` / `maxScore` | `82 / 100` | `ITSEntityRiskScoreDetails.RISK_SCORE` for this computer entity row | ✅ |
| `severity` | `Critical` | `ITSEntityRiskScoreDetails.SESSION_SEVERITY` → `ITSRiskSeverityDetails.SEVERITY_NAME` | ✅ |
| `metrics[0]` | `Login Success (24h)` = `47` | `count(eventid=4624 AND hostname=:host AND _zl_timestamp > now-24h)` | ✅ |
| `metrics[1]` | `Login Failure (24h)` = `14` | `count(eventid=4625 AND hostname=:host AND _zl_timestamp > now-24h)` | ✅ |

#### 2. `deviceDetails` (fields actually rendered by the prototype — [entities.js#L1211-L1229](js/data/entities.js#L1211-L1229))

| Prototype label | Prototype value | Real backing | Status |
|---|---|---|---|
| Hostname | `CORP-WS-045` | `APFDiscADComputerDetails.NAME` (the `cn`) | ✅ |
| FQDN / DNS Name | `corp-ws-045.contoso.local` | `APFDiscADComputerDetails.DNS_NAME` | ✅ |
| OS | `Windows 11 Pro` | `APFDiscADComputerDetails.OPERATING_SYSTEM` | ✅ |
| Domain | `contoso.local` | `APFDiscADComputerDetails.DOMAIN_NAME` | ✅ |
| OU | `Workstations` | parsed from `DISTINGUISHED_NAME` | ✅ |
| Distinguished Name | `CN=CORP-WS-045,OU=Workstations,DC=contoso,DC=local` | `APFDiscADComputerDetails.DISTINGUISHED_NAME` | ✅ |
| Owner / Managed-By | `m.henderson (CN=m.henderson,OU=Users,DC=contoso,DC=local)` | `APFDiscADComputerDetails.MANAGED_BY` | ✅ |
| Last Logon | `11 May 2026  10:36:22` | `APFDiscADComputerDetails.LAST_LOGON_TIME` | ✅ |
| Created | `15 Mar 2024  09:00:00` | `APFDiscADComputerDetails.WHEN_CREATED` | ✅ |
| Modified | `11 May 2026  10:36:55` | `APFDiscADComputerDetails.WHEN_CHANGED` | ✅ |
| Computer Status | `Enabled` | `USER_ACCOUNT_CONTROL` ACCOUNTDISABLE flag decode | ✅ |
| Role | `Workstation` | derived: `USER_ACCOUNT_CONTROL` (WORKSTATION_TRUST / SERVER_TRUST) | ✅ |
| Trusted for Delegation | `False` | `USER_ACCOUNT_CONTROL` TRUSTED_FOR_DELEGATION flag | ✅ |

#### 3. `usersLoggedOn` / `loginActivity` (timelines)

| Section | Windows Security Event IDs | Status |
|---|---|---|
| `usersLoggedOn` | **4624** (logon success), filtered by `hostname=:host` | ✅ |
| `loginActivity` | **4624** (success) / **4625** (failure), filtered by `hostname=:host` | ✅ |

#### 4. `localAccountLifecycle` (timeline)

Driven by local-SAM account-lifecycle event IDs, filtered to rows whose `securityid` has the machine-SID prefix (domain-SID prefix excluded — those belong on the User entity):

| Action | Event ID |
|---|---|
| Local user created | **4720** |
| Local user enabled | **4722** |
| Self-service password change (local) | **4723** |
| Admin password reset (local) | **4724** |
| Local user disabled | **4725** |
| Local user deleted | **4726** |

Status: ✅

#### 5. `recentAlerts`

Any alert profile in `ITSAlertProfileConfigurations` whose detection rule pivots on baseline Win-Sec data, filtered by `hostname=:host`. ✅

#### Bonus baseline-reachable Device sections (rich-path only)

| Section | Backing | Status |
|---|---|---|
| `processesOnHost` | 4688 filtered by `hostname=:host` — `processname` + `commandline` + `parentprocessname` + `username` (who launched what) | 🟡 rich-path 4688 only |
| `processTerminations` | 4689 filtered by `hostname=:host` — `processname` + `processid` | 🟡 rich-path |
| `objectAccessOnHost` | 4663 filtered by `hostname=:host` — `objectname` + `accesses` + `severity` | 🟡 needs SACL |

**Gated by integration**: `agentStatus`, `usbDeviceEvents`, `servicesOnHost` (7045 install-time only; runtime status needs agent), `scheduledTasks` (4698–4702 parsed but task-XML payload extraction is rule-grouped, not per-field).

---

## 🌐 IP entity — 5 baseline sections + 2 partial

Keyed on the raw **`remoteip`** field parsed from every rich-path Win-Sec event (and `clientip` on a subset of events) — **no GeoIP enrichment required for the key.** The prototype ships two variants (`ip-external` 185.220.101.42 and `ip-internal` 10.18.1.81); the section list below is the union of both, filtered to what a vanilla install (AD-sync + Windows Security rich-path) can actually render.

| # | Section (as rendered) | Backing data | Status |
|---|---|---|---|
| 1 | `riskSummary` | Auth-plane composite over 4624/4625 filtered by `remoteip`: success count · failure count split by `substatuscode` · distinct-user fanout · failure-burst flag · **per-event `risk_level`** (parser-emitted score, can be averaged). **No row exists in `ITSEntityRiskScoreDetails` for IP entities** — entity-level numeric score is synthesized, but per-event `risk_level` is real. | 🟡 Counts ✅; entity score heuristic; per-event `risk_level` ✅ |
| 2 | `ipDetails` | See sub-field breakdown below — 4 of the 10 prototype fields are baseline-reachable (Webroot adds verdict/WHOIS on-demand). | 🟡 Partial; Webroot on-demand |
| 3 | `associatedUsers` | Distinct `username` from 4624 ∪ 4625 ∪ 4768 ∪ 4776 where `remoteip=:ip` | ✅ |
| 4 | `associatedDevices` (internal IPs only) | Distinct `hostname` / `remotehost` from 4624/4625 where `remoteip=:ip`; reverse-resolve via `APFDiscADComputerDetails.DNS_NAME` | ✅ |
| 5 | `logonActivity` | 4624 / 4625 timeline filtered by `remoteip=:ip`; `logontype` faceted (2 interactive / 3 network / 10 RemoteInteractive / 11 CachedInteractive); rich-path bonus: `sourceport`, `package_name` | ✅ |
| 6 | `recentAlerts` | Any alert profile in `ITSAlertProfileConfigurations` whose detection rule pivots on `remoteip`, filtered by the IOC. | ✅ |
| 7 | `remediationGuide` | Static UI — verdict + recommendation cards + playbook references (Webroot verdict populates the verdict card on-demand) | ✅ |

### `ipDetails` sub-field breakdown (baseline-reachable rows only)

| Prototype label | Prototype value (example) | Real backing on baseline install | Status |
|---|---|---|---|
| `IP Address` | `185.220.101.42` / `10.18.1.81` | `remoteip` on the event row | ✅ |
| `Network Type` | `Internal — Private (RFC1918)` / `Public` | Inline RFC 1918 / link-local regex on `remoteip` (private/public split only — descriptive labels like `Tor Exit Relay` need TI verdict, available via Webroot on-demand) | ✅ Private/Public; 🟡 Webroot for verdict |
| `Hostname (resolved)` | `corp-ws-045.contoso.local` | `remotehost` on the event row (when present) ∪ `APFDiscADComputerDetails.DNS_NAME` reverse lookup (internal IPs only) | ✅ For internal IPs |
| `Webroot Verdict / WHOIS` | `Malicious / Tor Exit` | On-demand `WebrootProviderAPI.getURLInfo` / `getURLWhoIsInfo` (no subscription required) | 🟡 On-demand only |

### `riskSummary` sub-field breakdown

| Prototype label | Prototype value (example) | Real backing on baseline install | Status |
|---|---|---|---|
| `riskScore` / `severity` | `15 / Low` (internal) · `98 / Critical` (external) | No `ITSEntityRiskScoreDetails` row for IPs; entity score synthesized from 4624/4625 failure ratio + burst flag + `avg(risk_level)` over recent events. | 🟡 Heuristic, but `risk_level` per-event is real |
| Metric: `Network Zone` | `Internal` / `Public` | RFC 1918 regex on `remoteip` | ✅ |
| Metric: `Assigned User` | `m.henderson` | Most-frequent `username` from 4624 where `remoteip=:ip` (internal IPs only) | ✅ For internal IPs |
| Metric: `Total Logons (24h)` | (synthesized) | `count(4624 where remoteip=:ip)` over last 24h | ✅ |
| Metric: `Failed Logons (24h)` | (synthesized) | `count(4625 where remoteip=:ip)` over last 24h | ✅ |

### `associatedUsers` · `associatedDevices` · `logonActivity` — event-ID-driven

| Section | Event IDs · field filter |
|---|---|
| `associatedUsers` | **4624** ∪ **4625** ∪ **4768** ∪ **4776** where `remoteip=:ip`; group by `username` |
| `associatedDevices` (internal IPs only) | **4624** ∪ **4625** where `remoteip=:ip`; group by `hostname` / `remotehost` → reverse-resolve via `APFDiscADComputerDetails.DNS_NAME` |
| `logonActivity` | **4624** / **4625** timeline where `remoteip=:ip`; `logontype` faceted (2 / 3 / 10 / 11); rich-path bonuses `sourceport` + `package_name` |

**Gated by integration**: `connectionHistory`, `firewallSummary`, `dnsHistory`, `idsAlerts`, `vpnSessions`, `trafficSummary`, full `geoContext`. Also gated `ipDetails` rows: `Subnet / Zone` (admin-maintained map), `DHCP Lease` (DHCP logs), `Country / City` and `ASN / Org` (on-demand `IPGeoInfo` or Path-B GeoIP enrichment), `Reverse DNS (PTR)` (external resolver), `Firewall Events (24h)` and `Top Transport Protocols / Ports` (firewall logs). **`threatIntelligence` is on-demand baseline** via Webroot, not gated.

---

## 📍 LOCATION entity (proposed) — gated by a small engineering change

**Prerequisite**: the current `GeoInfoEnrichment` enricher in `log360_cloud` writes `SOURCE_COUNTRY` only for AWS / Azure AD / Salesforce / VPN-success logtypes — Windows Security 4624/4625 are not enrolled, so the Location entity has no usable key field at baseline. **Path B** (~10 LOC patch adding `windows device` to `GeoInfoEnrichment.LOGTYPE_FIELD` keyed on `remoteip`) unlocks country-level geo. **Path C** (query-time `IPGeoInfo` lookup per distinct IP) unlocks City / Region / ASN / Lat / Long. The table below assumes Path B + C are in place.

| # | Section | Backing data | Status |
|---|---|---|---|
| 1 | `riskSummary` | Composite over below sections: failed-logon ratio (4625 / 4624) · after-hours density (`HOUR(_zl_timestamp)` outside 08-20) · distinct `username` count · allow-list-country compliance. No `ITSEntityRiskScoreDetails` row exists for Location entities — numeric score is synthesized. | 🟡 Counts work; riskScore heuristic |
| 2 | `locationDetails` | GeoIP enrichment fields on `remoteip`. See sub-field breakdown below. | 🟡 Country baseline (Path B); City/ASN on-demand (Path C) |
| 3 | `associatedUsers` | Distinct `username` from 4624 ∪ 4625 ∪ 4768 ∪ 4776 where `SOURCE_COUNTRY=:geo` | ✅ after Path B |
| 4 | `associatedDevices` | Distinct `hostname` / `remotehost` from 4624 / 4625 where `SOURCE_COUNTRY=:geo`; reverse-resolve via `APFDiscADComputerDetails.DNS_NAME` | ✅ after Path B |
| 5 | `observedSourceIPs` | `terms` agg on `remoteip` (ranked by event count) across 4624 / 4625 / 4768 / 4776 where `SOURCE_COUNTRY=:geo` | ✅ after Path B |
| 6 | `logonActivity` | 4624 / 4625 timeline filtered by `SOURCE_COUNTRY=:geo`; `logontype` faceted (2 / 3 / 10 / 11) | ✅ after Path B |
| 7 | `logonStatistics` | `count(4624)` · `count(4625)` split by `substatuscode` (0xC000006A · 0xC0000064 · 0xC0000234 · 0xC000006F) · `count(4740)` lockouts · peak-hour histogram on `_zl_timestamp` | ✅ after Path B |
| 8 | `travelPattern` | Per-user from 4624 history: first-time-from-geo flag · haversine distance from user's home geo (mode `SOURCE_COUNTRY` over trailing 30d) · concurrent-elsewhere check | ✅ after Path B+C |
| 9 | `recentAlerts` | Any alert profile in `ITSAlertProfileConfigurations` whose detection rule pivots on the GeoIP fields, filtered by the IOC. | ✅ after Path B |

### `locationDetails` sub-field breakdown

| Sub-field | Real backing | Status |
|---|---|---|
| `country` / `country_code` / `country_flag` | `SOURCE_COUNTRY` on event row | ✅ after Path B |
| `first_seen` / `last_seen` | `min` / `max(_zl_timestamp)` over events at this geo | ✅ after Path B |
| `event_count_30d` | `count(*)` over trailing 30 d at this geo | ✅ after Path B |
| `distinct_users_30d` / `distinct_ips_30d` | `cardinality(username)` / `cardinality(remoteip)` | ✅ after Path B |
| `city` / `region` / `latitude` / `longitude` / `asn` / `isp` / `timezone` | `IPGeoInfo` lookup per distinct IP | 🟡 on-demand (Path C) |

**Gated by integration**: `ispBreakdown` (needs Path-C ASN data), `vpnAnonymizerStatus`, `firewallTrafficFromGeo`, `idsAlertsFromGeo`, `cloudSignInsFromGeo`, `dnsQueriesFromGeo`, `physicalLocationContext`.

---

## ⚙️ PROCESS entity — 9 baseline sections (rich-path conditional)

Keyed on **`processname`** (full path lowercased, e.g., `c:\windows\system32\svchost.exe`) parsed from **rich-path 4688** (process creation) and **4689** (process termination). The companion [AnalysisZLogsDataConstants.java#L26](/home/saairam-17274/Documents/REPOS/log360_cloud/source/cloud/com/zoho/log360/server/incident/workbench/data/constants/AnalysisZLogsDataConstants.java#L26) `PROCESS_AUDIT` enum in `log360_cloud` confirms the canonical process-audit set as **`{592, 4688, 593, 4689}`** — the 592/593 pair is the legacy NT5 (pre-Vista) variant, retained for back-compat; 4688/4689 are the NT6+ variants you'll see in all modern tenants.

> **⚠️ Critical caveat:** the Process entity is **viable ONLY when the tenant ingests events via the rich path** (`source: microsoft-windows-security-auditing`). A thin-path 4688 (`source: microsoft windows security`, category `none`, `username: n/a`, message just `"A new process has been created. 134"`) carries NONE of `processname` / `processid` / `commandline` / `parentprocessname` / `parentprocessid`. If your tenant is thin-path-only, **the slider has nothing to render below the entity key** — advertise it as gated by collector configuration, not as baseline.

| Tab | Section | Backing data (one-line) |
|---|---|---|
| Overview | `riskSummary` | Composite over 4688: launch count · distinct-host fanout · distinct-user fanout · `elevatedtoken` ratio · unusual-parent flag |
| Overview | `processDetails` | Most-recent 4688 row: `processname`, `processid`, `commandline`, `parentprocessname`, `parentprocessid`, `username`, `domain`, `elevatedtoken` |
| Activity | `launchActivity` | 4688 creation timeline filtered by `processname=:proc` |
| Activity | `terminationActivity` | 4689 termination timeline filtered by `processname=:proc` |
| Lineage | `parentProcessTree` | `terms(parentprocessname)` filtered by `processname=:proc` — who launches this binary |
| Lineage | `childProcessTree` | Inverse: `terms(processname) WHERE parentprocessname=:proc` — what this binary spawns |
| Actors | `launchingUsers` | `terms(username) + domain` filtered by `processname=:proc` |
| Hosts | `hostsObserved` | `terms(hostname)` (with IP-fallback resolve) |
| Recent Alerts | `recentAlerts` | Alert profiles pivoting on `processname` / `commandline` |

### Sub-field breakdown (in top-table order)

#### 1. `riskSummary`

| Sub-field | Real backing | Status |
|---|---|---|
| `riskScore` / `severity` | No `ITSEntityRiskScoreDetails` row for processes — synthesized from launch-count + distinct-host fanout + `elevatedtoken` ratio | 🟡 Heuristic |
| Metric: `Launches (24h)` | `count(eventid=4688 AND processname=:proc AND _zl_timestamp > now-24h)` | ✅ rich-path |
| Metric: `Distinct Hosts (24h)` | `cardinality(hostname) WHERE eventid=4688 AND processname=:proc AND _zl_timestamp > now-24h` | ✅ rich-path |
| Metric: `Distinct Users (24h)` | `cardinality(username) WHERE eventid=4688 AND processname=:proc AND _zl_timestamp > now-24h` | ✅ rich-path |
| Metric: `Elevated Token %` | `count(elevatedtoken="yes") / count(*)` over 4688 | ✅ rich-path |

#### 2. `processDetails` (flat KV from most-recent 4688)

| Field | Real backing | Status |
|---|---|---|
| Process Name | `processname` | ✅ rich-path |
| Process ID | `processid` | ✅ rich-path |
| Command Line | `commandline` (when 4688 command-line auditing enabled — separate GPO toggle) | 🟡 needs command-line auditing GPO |
| Parent Process Name | `parentprocessname` | ✅ rich-path |
| Parent Process ID | `parentprocessid` | ✅ rich-path |
| Launching User | `username` + `domain` | ✅ rich-path |
| Elevated Token | `elevatedtoken` | ✅ rich-path |

#### 3–4. `launchActivity` / `terminationActivity` (timelines)

| Section | Event ID | Status |
|---|---|---|
| `launchActivity` | **4688** filtered by `processname=:proc` | ✅ rich-path |
| `terminationActivity` | **4689** filtered by `processname=:proc` | ✅ rich-path |

#### 5–6. `parentProcessTree` / `childProcessTree`

| Section | Backing | Status |
|---|---|---|
| `parentProcessTree` | `terms(parentprocessname)` WHERE `processname=:proc` over 4688 | ✅ rich-path |
| `childProcessTree` | `terms(processname)` WHERE `parentprocessname=:proc` over 4688 | ✅ rich-path |

#### 7–8. `launchingUsers` / `hostsObserved`

| Section | Backing | Status |
|---|---|---|
| `launchingUsers` | `terms(username, domain)` WHERE `processname=:proc` over 4688 | ✅ rich-path |
| `hostsObserved` | `terms(hostname)` WHERE `processname=:proc` (with IP-literal fallback to AD reverse-lookup) | ✅ rich-path |

#### 9. `recentAlerts`

Any alert profile in `ITSAlertProfileConfigurations` whose detection rule pivots on `processname` / `commandline`. ✅

**Gated by integration**: `hashContext` (needs Sysmon EID 1 — 4688 carries no hash), `signerContext` (needs Sysmon), `networkConnections` (needs Sysmon EID 3 or EDR), `loadedModules` (needs Sysmon EID 7), `threatIntelContext` on hash (needs hash + TI subscription).

---

## 📁 FILE entity — 9 baseline sections (SACL-gated, dual-source)

The File entity has **two distinct backing data paths**:

**(A) Windows native object-access auditing (`eventid=4663`)** — **the path that surfaces in the unified log stream and powers the slider.** Rich-path 4663 carries `objectname` (full path), `objecttype` (`file` / `key` / etc.), `accesses` (`objectmodified` / `read` / `write` / `delete`), `accessmask`, `processname` + `processid`, `username` + `domain` + `securityid`, `severity` (`success` / `failure`), `handleid` + `logonid`. **Requires `Audit Object Access` + per-file SACL.** Production-tenant sample: 1.22k 4663 events / 1 year for one deployment with registry-only auditing.

**(B) In-product FIM module** ([FimTransformer.java](/home/saairam-17274/Documents/REPOS/log360_cloud/source/cloud/com/zoho/log360/server/mickeyclient/transformers/FimTransformer.java) + [WinFimHandler.java](/home/saairam-17274/Documents/REPOS/log360/sa/agentcomponents/source/com/manageengine/itom/log360/agent/handlers/WinFimHandler.java) / [LinFimHandler.java](/home/saairam-17274/Documents/REPOS/log360/sa/agentcomponents/source/com/manageengine/itom/log360/agent/handlers/LinFimHandler.java)) — agent-based, emits dedicated change events with `changetype ∈ {created, modified, deleted}` keyed by `agentid`. Covers Windows + Linux + NetApp / Isilon CIFS ([VerifyLocationsAPI.java](/home/saairam-17274/Documents/REPOS/log360_cloud/source/cloud/com/zoho/log360/server/api/fim/VerifyLocationsAPI.java)). **Events go to dedicated FIM tables — NOT the `logtype="log360"` log search** — so the slider must cross-query the FIM index to surface them.

Keyed on **`objectname`** (full file path, lowercased) with `objecttype="file"` filter (to exclude registry / kernel-object rows).

| Tab | Section | Backing data (one-line) |
|---|---|---|
| Overview | `riskSummary` | Composite over 4663: access count · failure ratio (`severity=failure`) · distinct-actor fanout · distinct-process fanout |
| Overview | `fileDetails` | Most-recent 4663 row: `objectname`, last `accesses`, last `username` + `domain`, last `processname`, last `hostname` |
| Activity | `accessActivity` | 4663 timeline filtered by `objectname=:path AND objecttype="file"` |
| Activity | `changeActivity` | FIM-module change events (cross-index query): `changetype ∈ {created, modified, deleted}` |
| Actors | `accessingProcesses` | `terms(processname)` filtered by `objectname=:path` — **per-file process attribution (bonus over FIM module)** |
| Actors | `actorUsers` | `terms(username) + domain` filtered by `objectname=:path` |
| Outcomes | `accessOutcome` | `terms(severity)` facet — success vs denied |
| Outcomes | `accessMaskBreakdown` | `terms(accessmask)` decoded to read/write/delete/append |
| Hosts | `hostsObserved` | `terms(hostname)` (with IP-fallback resolve) |
| Recent Alerts | `recentAlerts` | Alert profiles pivoting on file path / `accesses` |

### Sub-field breakdown (in top-table order)

#### 1. `riskSummary`

| Sub-field | Real backing | Status |
|---|---|---|
| `riskScore` / `severity` | Synthesized from access volume + failure ratio + distinct-actor fanout | 🟡 Heuristic |
| Metric: `Accesses (24h)` | `count(eventid=4663 AND objectname=:path AND _zl_timestamp > now-24h)` | ✅ 4663 + SACL |
| Metric: `Denied Accesses (24h)` | `count(... AND severity="failure" ...)` | ✅ 4663 + SACL |
| Metric: `Distinct Actors (24h)` | `cardinality(username)` | ✅ 4663 + SACL |
| Metric: `Distinct Processes (24h)` | `cardinality(processname)` | ✅ 4663 + SACL |

#### 2. `fileDetails` (flat KV from most-recent 4663)

| Field | Real backing | Status |
|---|---|---|
| File Path | `objectname` | ✅ 4663 + SACL |
| Last Access Type | `accesses` (e.g., `objectmodified`, `read`, `delete`) | ✅ 4663 + SACL |
| Last Actor | `username` + `domain` | ✅ 4663 + SACL |
| Last Process | `processname` (+ `processid`) | ✅ 4663 + SACL |
| Last Host | `hostname` (with IP-fallback resolve) | ✅ 4663 + SACL |
| Object Type | `objecttype` (should be `file` for this slider) | ✅ 4663 + SACL |
| File Hash | — not carried by 4663 | ❌ needs Sysmon EID 11 |

#### 3–4. `accessActivity` / `changeActivity`

| Section | Backing | Status |
|---|---|---|
| `accessActivity` | **4663** filtered by `objectname=:path AND objecttype="file"` | ✅ 4663 + SACL |
| `changeActivity` | FIM-module table query: `changetype` + `agentid` keyed by file path | 🟡 needs FIM module enabled + cross-index query |

#### 5–6. `accessingProcesses` / `actorUsers`

| Section | Backing | Status |
|---|---|---|
| `accessingProcesses` | `terms(processname)` WHERE `objectname=:path` over 4663 | ✅ 4663 + SACL |
| `actorUsers` | `terms(username, domain)` WHERE `objectname=:path` over 4663 | ✅ 4663 + SACL |

#### 7–8. `accessOutcome` / `accessMaskBreakdown`

| Section | Backing | Status |
|---|---|---|
| `accessOutcome` | `terms(severity)` facet (`success` / `failure`) | ✅ 4663 + SACL |
| `accessMaskBreakdown` | `terms(accessmask)` over 4663, decoded by `accesses` label | ✅ 4663 + SACL |

#### 9. `hostsObserved` / `recentAlerts`

| Section | Backing | Status |
|---|---|---|
| `hostsObserved` | `terms(hostname)` over 4663 (IP-literal fallback to AD reverse-lookup) | ✅ 4663 + SACL |
| `recentAlerts` | Alert profiles pivoting on file path / `accesses` | ✅ |

**Setup cost (path A):** customer must enable `Audit Object Access` policy + apply SACL to each monitored directory — typically only done for sensitive shares (HR, Finance, source code) due to log-volume noise.

**Gated by integration**: `hashHistory` (needs Sysmon EID 11), `contentDiff` (Windows native impossible — permanently gated), `dlpClassification` (needs DLP module), `cloudSyncStatus` (needs M365 / OneDrive audit).

---

## 🌐 DOMAIN entity — two distinct flavors

The Domain entity has **two completely separate flavors** depending on which `IndicatorType` the user pivots from. Both are baseline-reachable, with different backing data. **The slider should detect the flavor at query time** (DNS-form string → flavor B; AD short-name → flavor A) and render the corresponding section set.

### Flavor A: AD / Windows domain — 12 baseline sections

Keyed on the parsed **`domain`** field (rich-path Win-Sec). Confirmed via production-tenant 4738 (user-account-modified) screenshot: 183 matches in 1 year, every event carries `domain: elanew2017` (the AD domain short name).

| Tab | Section | Backing data (one-line) |
|---|---|---|
| Overview | `riskSummary` | Composite: lockout rate · failed-logon ratio · account-lifecycle change velocity · cross-domain-auth count |
| Overview | `domainDetails` | `ADSDomainConfiguration` row WHERE `DOMAIN_FLAT_NAME=:dom` (or `DOMAIN_NAME` match) · joined to `ADSForestConfiguration` via `FOREST_ID` for forest context |
| Inventory | `usersInDomain` | `APFDiscADUserDetails WHERE DOMAIN_NAME=:dom` (cross-checked with `cardinality(username) WHERE domain=:dom` over 4624) |
| Inventory | `devicesInDomain` | `APFDiscADComputerDetails WHERE DOMAIN_NAME=:dom` (cross-checked with `cardinality(hostname) WHERE domain=:dom`) |
| Inventory | `domainControllers` | `ADSDCConfiguration WHERE DOMAIN_ID=:domain_id` (join via `ADSDomainConfiguration.DOMAIN_ID`) |
| Activity | `logonActivity` | 4624 / 4625 timeline `WHERE domain=:dom` |
| Activity | `kerberosActivity` | 4768 / 4771 / 4776 `WHERE domain=:dom` |
| Account Changes | `accountLockouts` | 4740 `WHERE domain=:dom` |
| Account Changes | `accountLifecycle` | 4720 / 4722 / 4723 / 4724 / 4725 / 4726 / 4738 `WHERE domain=:dom` |
| Account Changes | `groupChanges` | 4727–4729 / 4731–4733 / 4754–4757 `WHERE domain=:dom` |
| Cross-Realm | `crossDomainAuth` | 4624 events where `domain != hostname-domain-suffix` |
| Cross-Realm | `trustRelationships` | ❌ not in `ADSF-DD-DML` — no `ADSTrust*` table; would need AD-sync extension |
| Recent Alerts | `recentAlerts` | Alert profiles pivoting on `domain` |

### Sub-field breakdown (in top-table order)

#### 1. `riskSummary`

| Sub-field | Real backing | Status |
|---|---|---|
| `riskScore` / `severity` | Synthesized; no `ITSEntityRiskScoreDetails` row for domain entity | 🟡 Heuristic |
| Metric: `Failed Logons (24h)` | `count(eventid=4625 AND domain=:dom AND _zl_timestamp > now-24h)` | ✅ |
| Metric: `Lockouts (24h)` | `count(eventid=4740 AND domain=:dom ...)` | ✅ |
| Metric: `Account Changes (24h)` | `count(eventid IN (4720,4722,4723,4724,4725,4726,4738) AND domain=:dom ...)` | ✅ |
| Metric: `Cross-Domain Auth (24h)` | `count(eventid=4624 AND domain=:dom AND NOT hostname LIKE %.:dom-fqdn ...)` | ✅ |

#### 2. `domainDetails` (flat KV)

Backing row: `ADSDomainConfiguration WHERE DOMAIN_FLAT_NAME=:dom` (the Win-Sec `domain` field carries the flat / NetBIOS name, e.g., `ELANEW2017`) joined to `ADSForestConfiguration` via `FOREST_ID`.

| Field | Real backing | Status |
|---|---|---|
| Flat / NetBIOS Name | `ADSDomainConfiguration.DOMAIN_FLAT_NAME` (matches Win-Sec `domain` field) | ✅ |
| FQDN / DNS Name | `ADSDomainConfiguration.DOMAIN_DNS_NAME` | ✅ |
| Domain Name (display) | `ADSDomainConfiguration.DOMAIN_NAME` | ✅ |
| Default Naming Context | `ADSDomainConfiguration.DEFAULT_NAMING_CONTEXT` | ✅ |
| Domain Functional Level | `ADSDomainConfiguration.DOMAIN_FUNCTIONAL_LEVEL` | ✅ |
| Is Default Domain | `ADSDomainConfiguration.IS_DEFAULT_DOMAIN` | ✅ |
| Domain GUID | `ADSDomainConfiguration.GUID` | ✅ |
| Admin Status | `ADSDomainConfiguration.ADMIN_STATUS` (enabled / disabled / deleted) | ✅ |
| Forest | `ADSForestConfiguration` row via `FOREST_ID` FK | ✅ |
| User Count | `count(APFDiscADUserDetails WHERE DOMAIN_NAME=:dom)` | ✅ |
| Computer Count | `count(APFDiscADComputerDetails WHERE DOMAIN_NAME=:dom)` | ✅ |
| DC Count | `count(ADSDCConfiguration WHERE DOMAIN_ID=:domain_id)` | ✅ |
| PDC Emulator / FSMO Roles | ❌ not stored in `ADSDomainConfiguration` | ❌ needs AD-sync schema extension |

#### 3–5. `usersInDomain` / `devicesInDomain` / `domainControllers`

| Section | Backing | Status |
|---|---|---|
| `usersInDomain` | `APFDiscADUserDetails WHERE DOMAIN_NAME=:dom` (paginated table) | ✅ |
| `devicesInDomain` | `APFDiscADComputerDetails WHERE DOMAIN_NAME=:dom` | ✅ |
| `domainControllers` | `ADSDCConfiguration WHERE DOMAIN_ID = (SELECT DOMAIN_ID FROM ADSDomainConfiguration WHERE DOMAIN_FLAT_NAME=:dom)` — the authoritative DC inventory from AD-sync | ✅ |

#### 6–7. `logonActivity` / `kerberosActivity`

| Section | Event IDs |
|---|---|
| `logonActivity` | **4624** / **4625** WHERE `domain=:dom`; faceted by `logontype` |
| `kerberosActivity` | **4768** (TGT) / **4771** (Kerb pre-auth fail) / **4776** (NTLM validation) WHERE `domain=:dom` |

#### 8–10. `accountLockouts` / `accountLifecycle` / `groupChanges`

| Section | Event IDs |
|---|---|
| `accountLockouts` | **4740** WHERE `domain=:dom` |
| `accountLifecycle` | **4720** / **4722** / **4723** / **4724** / **4725** / **4726** / **4738** WHERE `domain=:dom` |
| `groupChanges` | Global: **4727** / **4728** / **4729** · Local: **4731** / **4732** / **4733** · Universal: **4754** / **4755** / **4756** / **4757** |

#### 11–12. `crossDomainAuth` / `trustRelationships`

| Section | Backing | Status |
|---|---|---|
| `crossDomainAuth` | 4624 events where `domain != hostname-domain-suffix` (cross-realm logons) | ✅ |
| `trustRelationships` | ❌ not in `ADSF-DD-DML` — no `ADSTrust*` table exists; `ADSDomainConfiguration` carries no trust columns | ❌ needs AD-sync schema extension (engineering gap) |

#### 13. `recentAlerts`

Any alert profile in `ITSAlertProfileConfigurations` whose detection rule pivots on `domain`. ✅

### Flavor B: DNS / internet domain — 6 baseline sections

Keyed on a DNS-form domain string (e.g., `evil-c2.example.com`). Confirmed first-class IOC via [RestThreatUtil.java#L107](/home/saairam-17274/Documents/REPOS/log360_cloud/source/cloud/com/zoho/log360/server/rest/version2/threat/util/RestThreatUtil.java#L107) (`Configuration.ThreatFeedType.DOMAIN` branch), [L3CThreatAnalyticsTabDataHandler.java#L89](/home/saairam-17274/Documents/REPOS/log360_cloud/source/cloud/com/zoho/log360/server/incident/workbench/tab/handler/L3CThreatAnalyticsTabDataHandler.java#L89) (`ITSThreatConstants.IndicatorType` switch), [BreachAnalysisTabDataHandler.java#L49](/home/saairam-17274/Documents/REPOS/log360_cloud/source/cloud/com/zoho/log360/server/incident/workbench/tab/handler/BreachAnalysisTabDataHandler.java#L49) (`DARKWEB_DOMAIN_NOT_CONFIGURED` status code). At baseline (no firewall syslog, no DNS logs, no proxy logs) this flavor has **no event-driven activity sections** — it relies entirely on on-demand Webroot enrichment.

| Tab | Section | Backing data (one-line) |
|---|---|---|
| Overview | `riskSummary` | Webroot verdict tier + dark-web mention count |
| Overview | `domainDetails` | Webroot WHOIS: registrar, creation date, age, country (on-demand) |
| Threat Intel | `threatVerdict` | `WebrootProviderAPI.getURLInfo` per IOC (on-demand) |
| Threat Intel | `cdbStats` | `WebrootProviderAPI.getCDBStats` (on-demand) |
| Threat Intel | `cdbConnections` | `WebrootProviderAPI.getCDBConnections` (on-demand) |
| Threat Intel | `darkWebMentions` | `BreachAnalysisTabDataHandler` domain breach lookup |
| Recent Alerts | `recentAlerts` | Alert profiles pivoting on DOMAIN IOC |

### Sub-field breakdown (in top-table order)

#### 1. `riskSummary`

| Sub-field | Real backing | Status |
|---|---|---|
| `riskScore` / `severity` | Webroot verdict tier (Trustworthy / Low Risk / Moderate / Suspicious / High Risk) + dark-web hit count | ✅ on-demand |
| Metric: `Reputation Verdict` | `WebrootProviderAPI.getURLInfo.reputation` | ✅ on-demand |
| Metric: `Categories` | `WebrootProviderAPI.getURLInfo.categories` | ✅ on-demand |
| Metric: `Dark Web Mentions` | `BreachAnalysisTabDataHandler` count | ✅ on-demand |

#### 2. `domainDetails` (flat KV from WHOIS)

| Field | Real backing | Status |
|---|---|---|
| Domain | The DOMAIN IOC string | ✅ |
| Registrar | `getURLWhoIsInfo.registrar` | ✅ on-demand |
| Created | `getURLWhoIsInfo.creationDate` | ✅ on-demand |
| Age | derived from creation date | ✅ on-demand |
| Registrant Country | `getURLWhoIsInfo.country` | ✅ on-demand |

#### 3–6. `threatVerdict` / `cdbStats` / `cdbConnections` / `darkWebMentions`

| Section | Backing | Status |
|---|---|---|
| `threatVerdict` | `WebrootProviderAPI.getURLInfo` | ✅ on-demand |
| `cdbStats` | `WebrootProviderAPI.getCDBStats` | ✅ on-demand |
| `cdbConnections` | `WebrootProviderAPI.getCDBConnections` | ✅ on-demand |
| `darkWebMentions` | `BreachAnalysisTabDataHandler` | ✅ on-demand |

#### 7. `recentAlerts`

Alert profiles pivoting on the DOMAIN IOC. ✅

**Gated by integration (DNS-flavor)**: `dnsQueries` (DNS-resolver / proxy ingest), `httpRequests` (proxy / web-gateway), `firewallEgress` (firewall syslog), `emailMentions` (mail-gateway), `dlpExfilDestinations` (DLP module).

---

## Summary

| Entity | Baseline-shippable sections | Partial (synthesized / on-demand) | Gated by integration / engineering |
|---|---|---|---|
| 👤 User | **8** of 8 prototype sections + 2 rich-path bonuses (`authMethodBreakdown`, `elevatedTokenUsage`) | `processesLaunched` (rich-path 4688 only), `objectsAccessed` (needs SACL) | UEBA peer-group baseline (engineering: rolling-baseline job not in `AnomalyRuleHandler.java`); `cloudIdentities`, `dlpIncidents`, `mailboxForwarding` |
| 🖥️ Device | **6** of 6 prototype sections + 3 rich-path bonuses (`processesOnHost` 4688, `processTerminations` 4689, `objectAccessOnHost` 4663) | — | `agentStatus`, `usbDeviceEvents`, `scheduledTasks` (payload); GPO-applied view (engineering: `APFDiscADGPO*` tables not in `ADSF-DD-DML`) |
| 🌐 IP | **5** — `associatedUsers`, `associatedDevices`, `logonActivity`, `recentAlerts`, `remediationGuide` | **3** — `riskSummary` (counts ✅, entity-score heuristic, per-event `risk_level` ✅), `ipDetails` (4 of 10 prototype fields incl. Webroot verdict on-demand), `threatIntelligence` (Webroot on-demand) | `connectionHistory`, `firewallSummary`, `dnsHistory`, `idsAlerts`, `vpnSessions`, `trafficSummary`, full `geoContext` |
| 📍 Location | **0** at baseline · **8** after Path B (`GeoInfoEnrichment` ~10 LOC) · **9** after Path B + Path C (on-demand `IPGeoInfo`) | `locationDetails` (Country baseline after Path B; City/ASN/Lat-Long/ISP/Timezone on-demand after Path C); `riskSummary` (counts ✅, score heuristic) | `ispBreakdown`, `vpnAnonymizerStatus`, `firewallTrafficFromGeo`, `idsAlertsFromGeo`, `cloudSignInsFromGeo`, `dnsQueriesFromGeo`, `physicalLocationContext` |
| ⚙️ Process | **9** of 9 sections — IFF rich-path collector. Sections: `riskSummary`, `processDetails`, `launchActivity`, `terminationActivity`, `parentProcessTree`, `childProcessTree`, `launchingUsers`, `hostsObserved`, `recentAlerts` | `commandline` field needs separate command-line-auditing GPO | Entire entity gated by **rich-path collector configuration**. Thin-path tenants get entity-key only. `hashContext`, `signerContext`, `networkConnections`, `loadedModules` need Sysmon / EDR |
| 📁 File | **9** of 9 sections via path A — IFF rich-path + SACL on the resource. Sections: `riskSummary`, `fileDetails`, `accessActivity`, `accessingProcesses`, `actorUsers`, `accessOutcome`, `accessMaskBreakdown`, `hostsObserved`, `recentAlerts` | `changeActivity` from FIM module (separate index, needs cross-query) | `hashHistory` (Sysmon EID 11), `contentDiff` (Windows-native impossible), `dlpClassification`, `cloudSyncStatus` |
| 🌐 Domain (AD-flavor) | **11** of 13 sections — every Win-Sec event carries `domain` + AD-sync provides topology tables. Sections: `riskSummary`, `domainDetails` (`ADSDomainConfiguration` + `ADSForestConfiguration`), `usersInDomain`, `devicesInDomain`, `domainControllers` (`ADSDCConfiguration`), `logonActivity`, `kerberosActivity`, `accountLockouts`, `accountLifecycle`, `groupChanges`, `crossDomainAuth`, `recentAlerts` | — | `trustRelationships` (engineering gap — no `ADSTrust*` table in `ADSF-DD-DML`); `PDC Emulator / FSMO Roles` not in `ADSDomainConfiguration` |
| 🌐 Domain (DNS-flavor) | **7** of 7 sections — Webroot on-demand. Sections: `riskSummary`, `domainDetails`, `threatVerdict`, `cdbStats`, `cdbConnections`, `darkWebMentions`, `recentAlerts` | All sections are on-demand (not pre-indexed) | `dnsQueries`, `httpRequests`, `firewallEgress`, `emailMentions`, `dlpExfilDestinations` |

**Takeaways**
1. **User, Device, and Domain (AD-flavor) are fully baseline-shippable** — every section in their prototype contracts works on a vanilla AD-sync + Win-Sec install, **provided the rich-path collector is used**.
2. **Process and File are rich-path conditional and SACL-conditional respectively** — the slider should detect collector mode + SACL coverage at query time and display a setup-required banner when empty.
3. **IP is the most integration-dependent for traffic context** — 5 of 7 sections work from auth-plane data; Webroot on-demand adds verdict/WHOIS; the visually dominant tabs (Connections, DNS, IDS, VPN, Traffic) all stay empty until firewall + DNS feeds are added.
4. **Location has the largest gated ROI** — a ~10-line `GeoInfoEnrichment` patch (Path B) unlocks country-level geo on the 4624/4625 stream we already index. Path C (query-time `IPGeoInfo` lookup) unlocks City / ASN / Lat-Long.
5. **Domain has two flavors and must be presented as such** — AD-flavor (`domain` field) is 12/13 baseline; DNS-flavor (`IndicatorType.DOMAIN`) is 7/10 via Webroot on-demand. They share the slider key but back to different data.
6. **Two engineering gaps to plan for** (separate from customer-side integrations):
   - **Statistical UEBA baseline engine** does not exist in `log360_cloud` today. `AnomalyRuleHandler.java` is rule-based only. A rolling-baseline + peer-group job is required to compute a real 0–100 score with statistical `top_contributors`.
   - **AD GPO discovery** is not in `ADSF-DD-DML`. Adding `APFDiscADGPODetails` / `APFDiscADGPOLink` / `APFDiscADGPOSettings` to the AD-sync agent + data-dictionary is required to ship a Device-entity GPO-applied view.
   - **AD trust discovery** is not in `ADSF-DD-DML`. `ADSDomainConfiguration` carries domain identity + forest FK only — no trust columns. Adding an `ADSTrust*` table (trust direction, type, target domain) is required to ship the Domain-entity `trustRelationships` section. Same applies to FSMO-role columns (PDC emulator, RID master, etc.) on `ADSDomainConfiguration`.
7. **Honesty note (May 2026 — revised)**: Multiple claims from earlier drafts have been corrected against actual production-tenant zlog field schema:
   - Field names corrected: `TargetUserName` → `username`, `TargetComputerName` / `ComputerName` → `hostname`, `IPADDRESS` → `remoteip`, `WorkstationName` → `remotehost`, `LOGONTYPE` → `logontype`, `TargetSid` → `securityid`, `SUBSTATUSCODE` → `substatuscode`, `EventTime` → `_zl_timestamp`, `EventID` → `eventid`. The old names belonged to `AnalysisCriteriaConstants.java` (workbench input vocabulary) and to the raw EVTX schema, **not** to the parsed event row.
   - `hostname` can be either DNS form or IP literal (confirmed by 4663 screenshot showing `hostname: 192.168.60.1`); Device-entity join must use two-step (direct AD match → reverse-IP fallback).
   - **Parser path (rich vs thin) is a global discriminator** that gates Process / File / Domain (DNS) / rich-path bonuses on every other entity. The earlier draft did not call this out.
   - Process entity was over-promised — thin-path 4688 has NONE of the structured process fields. Only rich-path 4688 has them.
   - File entity was wrongly framed as "FIM module" — the FIM module writes to a separate index that doesn't appear in the unified log stream. The realistic File entity backing is **4663 + SACL**, which is actually richer (per-event process attribution).
   - Domain entity was wrongly framed as Webroot-only — there are TWO flavors, and the AD-flavor (via `domain` field on every Win-Sec event) is 11/13 baseline without any new integration. The Domain-topology backing is `ADSDomainConfiguration` / `ADSDCConfiguration` / `ADSForestConfiguration` (the AD-sync configuration tables — see [data-dictionary.xml](/home/saairam-17274/Documents/REPOS/ADSF-DD-DML/product_package/conf/adsf/common/domain/data-dictionary.xml)), **not** a fictional `APFDiscADDomainDetails` table (which does not exist). Domain controllers come from `ADSDCConfiguration`, not from a UAC-flag heuristic on `APFDiscADComputerDetails`.
   - IP `riskScore` was too pessimistic — per-event `risk_level` is a real parser-emitted field. Entity-rollup score remains heuristic, but the per-event number is real.
   - Rich-path bonus fields (`authMethodBreakdown`, `elevatedTokenUsage`, `sourceport`, `package_name`, `clientip`, `virtualaccount`, `linkedlogonid`) were missing from earlier drafts and are now surfaced as bonus sections / facets on User / Device / IP.
   - Webroot threat-intel was earlier listed as "gated by TI subscription" — it actually ships enabled and is on-demand baseline (no subscription required for IP/Domain IOC lookups).
   - Original (May 2026) honesty items still stand: City/ASN/Lat-Long are not pre-enriched on every event; UEBA does not compute peer-group baselines; GPO discovery tables do not exist. Verified against [GeoInfoEnrichment.java](/home/saairam-17274/Documents/REPOS/log360_cloud/source/cloud/com/zoho/log360/server/zqueue/logenrichment/threat/GeoInfoEnrichment.java), [AnomalyRuleHandler.java](/home/saairam-17274/Documents/REPOS/log360_cloud/source/cloud/com/zoho/log360/server/anomalydetection/AnomalyRuleHandler.java), and [data-dictionary.xml](/home/saairam-17274/Documents/REPOS/ADSF-DD-DML/product_package/conf/adsf/common/appfw/discovery/application/ad/data-dictionary.xml).

---

## Cross-reference

For exact per-field ES projections of every section in this doc, see `entity_data_mapping.md` §9 (sections §9.1–§9.29 verified; §9.31 lists 38 pending-inventory sections).
