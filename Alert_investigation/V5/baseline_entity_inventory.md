# Baseline Entity Inventory — User · Device · IP · Location · Process · File · Domain

> **Scope:** What each entity slider can show on a **fresh Log360 Cloud install** with **only AD directory sync + Windows Security Event Log forwarding** enabled. No firewall syslog, no M365/Azure AD audit, no Sysmon, no EDR, no DLP module.
>
> **On-demand exceptions allowed at baseline:** Webroot threat-intel lookups (URL/Domain WHOIS, verdict, CDB) are fired per-IOC from the workbench (no subscription required for IP/Domain enrichment). Treated as baseline because they ship enabled.
>
> **Source of truth:** verified against `adsf` / `itsf` / `log360_cloud` parsers, `APFDiscAD*` table definitions, AND **actual parsed zlog field names from production-tenant screenshots** (4624 / 4663 / 4688 / 4738). See `entity_data_mapping.md` §9 for full per-field projections.

> **Structure (revised — aligned to the Attack-vector entity specs).** This doc now mirrors the canonical section taxonomy defined in the per-entity specs under [`MD files/Attack vector/`](../../../MD%20files/Attack%20vector/) — `user_entity_spec.md`, `device_and_other_entity_spec.md`, `ip_entity_spec.md`, `domain_entity_spec.md`, `file_entity_spec.md`, `process_entity_spec.md`. Each entity is presented as the spec defines it: **Fixed tabs → Baseline sub-sections (`*B*` IDs, rendered on slider open) → Enriched sub-sections (`*E*` IDs, rendered after _Investigate Entity_) → gaps.** The value this doc adds on top of the spec is the **baseline-install reachability verdict** in the *Baseline status* column:
>
> | Status | Meaning on a vanilla AD-sync + Windows-Security (rich-path) install |
> |---|---|
> | ✅ | Renders real data at baseline — no extra integration. |
> | 🟡 | Partial at baseline — synthesized score, on-demand Webroot, rich-path-only, or SACL/GPO-gated. |
> | ❌ | Gated — needs a collector / license / module / schema the baseline install does not have. (Enriched `*E*` sections are ❌ at baseline by definition; the column states *what* unlocks them.) |
>
> Sub-section IDs (UB1, IE4, DB2, …) are the spec's IDs verbatim, so the two docs cross-reference 1:1. **Location has no spec file** in the Attack-vector folder yet — it is retained here as a proposed entity (gated by the `GeoInfoEnrichment` Path-B/C change) and flagged as such.

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

## 👤 USER entity — 10 baseline + 12 enriched sub-sections

> **Spec:** [user_entity_spec.md](../../../MD%20files/Attack%20vector/user_entity_spec.md). **Key:** AD `sAMAccountName` / `LOGON_NAME` (UPN) → Win-Sec `username` (rich-path) on every event; `domain` identifies the AD domain. **Sub-types:** AD (1), AD-Priv (2), AD-Svc (3), Disabled/Stale (4), Entra (5), Mailbox-overlay (6), SaaS (7), Local (8), Foreign/FSP (9).

### Fixed tabs

| Tab | Purpose |
|---|---|
| Overview | Identity, standing risk, account state, headline indicators |
| Authentication Activity | Logons / failures / lockouts / Kerberos / cloud sign-ins (primary event surface) |
| Account Activity | Password reset, group/role changes, account create/disable/delete |
| Recent Alerts | Other alerts naming this user |

### Baseline sub-sections (`UB1–UB10`, rendered on slider open)

| Id | Sub-section | Tab | Baseline status | Backing / note |
|---|---|---|---|---|
| **UB1** | Risk Summary KPIs | Overview | 🟡 | Generic chips (`Total Events 24h`, `Failed Logins 24h`, `Recent Alerts 7d`, `Off-Hours Logins 7d`) ✅; the `Risk Score (0–100)` + `Anomaly Count` chips need an `ITSEntityRiskScoreDetails` row (rule-based anomaly only — no statistical peer-group score). |
| **UB2** | User Details (identity card) | Overview | ✅ | `APFDiscADUserDetails` Tier 1+2+3 (AD). Tier 4 Entra / Tier 5 mailbox / Tier 6 SaaS overlays are ❌ at baseline (need Entra / Exchange / SaaS discovery). |
| **UB3** | Login Statistics (7d) | Authentication Activity | ✅ | `count`/`agg` on 4624 ∪ 4625 by `username`; off-hours via `L3CWorkingHourHandler`. |
| **UB4** | Logon Activity (timeline) | Authentication Activity | ✅ | 4624 / 4625 by `username`; rich-path facets `logontype`, `package_name`, `elevatedtoken`, `risk_level`. |
| **UB5** | Account Lockouts (timeline) | Authentication Activity | ✅ | EID 4740 + `APFDiscADUserDetails.LOCK_OUT_TIME` / `BAD_PASSWORD_COUNT`. |
| **UB6** | Password History (timeline) | Account Activity | ✅ | EID 4723 (self) ∪ 4724 (admin reset) + `PASSWORD_LAST_SET`. (Entra variant ❌ — needs M365 audit.) |
| **UB7** | Group Membership Changes | Account Activity | ✅ | EIDs 4727–4729 / 4731–4733 / 4754–4757 + `APFDiscADGroupMemberDetails` join. |
| **UB8** | Recent Alerts | Recent Alerts | ✅ | Alert profiles naming this user (baseline Win-Sec + AD rules). |
| **UB9** | Cloud Sign-ins (timeline) | Authentication Activity | ❌ | Needs M365 / Entra SignInLogs connector (`source: azure_active_directory`). |
| **UB10** | SaaS App Audit Summary | Account Activity | ❌ | Needs SaaS-app discovery + per-app audit connector. |

### Enriched sub-sections (`UE1–UE12`, after *Investigate Entity*)

| Id | Sub-section | Tab | Baseline status | Gate / note |
|---|---|---|---|---|
| **UE1** | UEBA Risk Profile | Overview | 🟡 | Score chip + notes render only with UEBA models trained for the entity; baseline rule-based score is partial. |
| **UE2** | Auth Method Breakdown | Authentication Activity | 🟡 | `terms(package_name)` over 4624 — **reachable at baseline rich-path** (NTLM/Kerberos/Negotiate split). Cloud-OAuth slice needs Entra. |
| **UE3** | TI — Dark Web / Breach (email-keyed) | Overview | ❌ | Advanced-Threat add-on **+** Constella Dark-Web monitoring domain configured. |
| **UE4** | Processes Launched on Hosts | Account Activity | 🟡 | 4688 + Sysmon EID 1 by `username`; rich-path 4688 only (thin-path drops `commandline`). |
| **UE5** | Services Triggered | Account Activity | 🟡 | EID 7045 where install caller resolves to user — install-time only. |
| **UE6** | Objects Accessed | Account Activity | 🟡 | EID 4663 by `username` — needs SACL on the resource. |
| **UE7** | Effective Group Memberships (transitive) | Overview | ✅ | Transitive closure over `APFDiscADGroupMemberDetails`; limited by FSP/gMSA/contact drop (see gaps). |
| **UE8** | Direct Reports & Manager Chain | Overview | ✅ | `APFDiscADUserDirectReports` + `APFDiscADUserDetails.MANAGER`. |
| **UE9** | Mailbox Activity Overview | Account Activity | ❌ | Needs Exchange / Exchange Online discovery (`APFUserExchangeDetails`). |
| **UE10** | Account Lifecycle Audit | Account Activity | ✅ | EIDs 4720/4722/4723/4724/4725/4726/4738/4781 by `targetuser`. |
| **UE11** | Cross-App SaaS Activity | Account Activity | ❌ | Needs SaaS-app discovery + audit connectors. |
| **UE12** | Privileged Action Surface | Overview | 🟡 | Group-membership-derived only; `adminCount` not collected, PIM eligibility ❌ (see gaps). |

### Baseline field provenance (rich-path AD + Win-Sec)

- **UB1 KPIs** — `riskScore`/`severity` from `ITSEntityRiskScoreDetails.RISK_SCORE` / `SESSION_SEVERITY` → `ITSRiskSeverityDetails.SEVERITY_NAME`; `Failed Logins 24h` = `count(eventid=4625 AND username=:user)`; `Last Anomaly` = `LAST_ANOMALY_UPDATE_TIME`; `Last Logon` chip = `APFDiscADUserDetails.LAST_LOGON_TIME` (DB column, retention-immune).
- **UB2 Identity card** — every Tier 1+2+3 field is a real `APFDiscADUserDetails` column (`DISPLAY_NAME`, `SAM_ACCOUNT_NAME`, `LOGON_NAME`, `EMAIL_ADDRESS`, `TITLE`, `DEPARTMENT`, `MANAGER_DN`, `WHEN_CREATED`, `DISTINGUISHED_NAME`→OU).
- **UB3 Login Statistics** — `count`/`cardinality`/`terms` over 4624 ∪ 4625 by `username` (7d): totals, unique source IPs (`remoteip`), unique hosts (`hostname`), off-hours.
- **UB4 rich-path facets per 4624/4625 event** — `logontype` (2/3/10/11), `package_name`, `authenticationpackage`, `remoteip`, `remotehost`, `sourceport`, `elevatedtoken`, `virtualaccount`, `linkedlogonid`, `risk_level`.

### Baseline gaps the slider inherits (from spec §5)

- **Thin-path tenants** (legacy `microsoft windows security` source) get only `eventid` + raw `message` + `hostname` — UB3–UB7 + UE2–UE6 are silently empty; slider must show a "Limited mode — rich-path collector required" banner.
- `servicePrincipalName`, `adminCount`, `sIDHistory`, `msDS-AllowedToDelegateTo` **not collected** → AD-Svc sub-type undetectable, UE12 falls back to group-membership-only.
- FSP / gMSA / AD-Contact membership rows dropped in `applyMembershipCriteriaToCaseExpression` → sub-type 9 stub-only, UE7 closure incomplete.
- `ENTITY_ID → UNIQUE_ID` join is name-string-based — fragile across renames / case / FQDN-vs-short-name.
- Off-hours definition is per-tenant (`L3CWorkingHourHandler`); defaults to 9–5 weekday when unconfigured (wrong for 24/7 ops).

---

## 🖥️ DEVICE (host) entity — 11 baseline + 14 enriched sub-sections

> **Spec:** [device_and_other_entity_spec.md](../../../MD%20files/Attack%20vector/device_and_other_entity_spec.md). **Key:** AD `DNS_NAME` / `NAME` (`cn`) → Win-Sec `hostname` (rich-path). **Two-step join caveat:** `hostname` can be a DNS-form name *or* an IP literal (e.g. `192.168.60.1`, seen in the 4663 production screenshot) — (1) direct match on AD `NAME`/`DNS_NAME`; (2) fallback reverse-IP lookup via `APFDiscADComputerDetails`. **Sub-classes:** the spec spans 39 log-types; a baseline AD-sync + Windows-Security install only populates the **Windows host** sub-class — appliance/DB/web/NAS/hypervisor sub-classes are ❌ until their log sources are connected.

### Fixed tabs

| Tab | Purpose |
|---|---|
| Overview | Standing identity + headline risk + agent / policy health |
| Host Activity | OS-side events: logons, process creation, service installs, local users |
| Device Activity | State-change events: scheduled tasks, USB, traffic flows, file shares, admin config |
| Recent Alerts | Other alerts naming this device |

### Baseline sub-sections (`B1–B11`, rendered on slider open)

| Id | Sub-section | Tab | Baseline status | Backing / note |
|---|---|---|---|---|
| **B1** | Overview KPIs | Overview | 🟡 | Generic chips (`Total Events 24h`, severity breakdown, `Recent Alerts 7d`, login success/failure 24h by `hostname`) ✅; `Risk Score` chip needs UEBA models + `ITSENTITYRISKSCOREDETAILS` row. |
| **B2** | Device Details | Overview | ✅ | Tier 4 AD identity from `APFDiscADComputerDetails` (`NAME`, `DNS_NAME`, `OPERATING_SYSTEM`, `DOMAIN_NAME`, `DISTINGUISHED_NAME`→OU, `MANAGED_BY`, `LAST_LOGON_TIME`, `WHEN_CREATED/CHANGED`, `USER_ACCOUNT_CONTROL` decode → status/role/delegation). Tiers 5–7 (Entra/Cloud-VM/multi-homed) ❌. |
| **B3** | Users Logged On | Host Activity | ✅ | 4624 by `hostname` (rich-path adds `logontype`, `logonid`, `domain`). |
| **B4** | Login Activity | Host Activity | ✅ | 4624 ∪ 4625 by `hostname` (+ `failurereason`). |
| **B5** | Account Lifecycle | Device Activity | ✅ | Local-SAM CRUD filtered to `securityid` with the machine-SID prefix: 4720/4722/4723/4724/4725/4726. |
| **B6** | Recent Alerts | Recent Alerts | ✅ | Baseline Win-Sec alert profiles by `hostname`. |
| **B7** | DB Auth & Privileged Ops | Host Activity | ❌ | Database-server log source. |
| **B8** | Web Server Activity | Host Activity | ❌ | Web/app/FTP server log source. |
| **B9** | Traffic Flow Summary | Device Activity | ❌ | Firewall / network-appliance log source. |
| **B10** | NAS Share Access Summary | Device Activity | ❌ | File/NAS appliance log source. |
| **B11** | VM / Cluster Inventory | Overview | ❌ | Hypervisor / virtualisation log source. |

### Enriched sub-sections (`E1–E19`, after *Investigate Entity*)

| Id | Sub-section | Tab | Baseline status | Gate / note |
|---|---|---|---|---|
| **E1** | Agent Status & Health | Overview | ❌ | Needs Log360 agent on the host. |
| **E2** | GPO / Policy Applied | Overview | 🟡 | EIDs 5136/5137 — needs *Audit Directory Service Changes* enabled. |
| **E3** | Processes Started on Host | Host Activity | 🟡 | 4688 by `hostname` (`processname`+`commandline`+`parentprocessname`) — rich-path 4688 only / Sysmon EID 1. |
| **E4** | Services Installed on Host | Host Activity | 🟡 | EID 7045 — install-time only (runtime status needs agent). |
| **E5** | Scheduled Task Events | Device Activity | 🟡 | EIDs 4698–4702 parsed but task-XML payload is rule-grouped, not per-field. |
| **E6** | USB / Peripheral Events | Device Activity | ❌ | EID 6416 — needs *Audit PNP Activity*. |
| **E7** | Full DB Query Audit | Host Activity | ❌ | DB-server log source. |
| **E8** | URL / Category Breakdown | Host Activity | ❌ | Web/proxy log source. |
| **E9** | Per-flow Firewall Lookup | Device Activity | ❌ | Firewall log source. |
| **E10** | Threat / IPS Event Detail | Device Activity | ❌ | NSA / EDR log source. |
| **E11** | VPN Session Detail | Device Activity | ❌ | VPN appliance log source. |
| **E12** | Admin / Config Changes | Device Activity | ❌ | Appliance / cloud config log source. |
| **E13** | System & Service Events | Device Activity | ❌ | Windows **System** log not assumed at baseline (Security-log-only). |
| **E14** | SNMP Trap Stream | Device Activity | ❌ | SNMP source. |
| **E15** | NAS / FTP File-level Access | Device Activity | ❌ | File/NAS/FTP source. |
| **E16** | Hypervisor Management Plane | Device Activity | ❌ | Hypervisor source. |
| **E18** | File Integrity & Permission Changes | Device Activity | 🟡 | EIDs 4663/4670 by `hostname` — SACL-gated. |
| **E19** | Print Queue Activity | Device Activity | ❌ | EID 307 (PrintService/Operational channel). |

### Baseline field provenance & gaps

- **B2 identity card** every rendered field is a real `APFDiscADComputerDetails` column; `Computer Status`/`Role`/`Trusted for Delegation` decode from `USER_ACCOUNT_CONTROL` flags (ACCOUNTDISABLE / WORKSTATION_TRUST / SERVER_TRUST / TRUSTED_FOR_DELEGATION).
- **B5** must filter local-SAM events by machine-SID prefix on `securityid` — domain-SID-prefixed rows belong on the **User** entity, not here.
- `ELANetworkNodeInfo`/`Hosts`/`HostDetails` tiers (collection status, syslog port, agent integration) are empty until the device is configured as a *log source* — at baseline the card is AD-discovery-only.

---

## 🌐 IP entity — 5 baseline + 13 enriched sub-sections

> **Spec:** [ip_entity_spec.md](../../../MD%20files/Attack%20vector/ip_entity_spec.md). **Key:** raw **`remoteip`** parsed from every rich-path Win-Sec event (and `clientip` on a subset) — **no GeoIP needed for the key.** **Sub-types:** Internal-Asset (1), Internal-Private (2), External (3), Flagged-External (4), NAT (5), Loopback (6), Pending (7).

### Fixed tabs

| Tab | Internal-IP emphasis | External-IP emphasis |
|---|---|---|
| Overview | Identity card (asset chips), classification, host/OS/domain chips | Identity card, classification, TI verdict / geo / ASN chips |
| Activity | Inbound/outbound connections + auth events keyed on this IP | Same shape, reversed perspective |
| Asset Profile | Hostname, OS, domain, owner, last seen, logged-on user | *Hidden* for a foreign IP |
| Recent Alerts | Alerts naming this IP | Same |

### Baseline sub-sections (`IB1–IB5`, rendered on slider open)

| Id | Sub-section | Tab | Baseline status | Backing / note |
|---|---|---|---|---|
| **IB1** | Risk Summary KPIs (common 4-chip strip) | Overview | 🟡 | Common chips: `Network Zone` (Internal/External) ✅ via RFC1918 regex on `remoteip`; `Threat Feeds Flagged` 🟡 via on-demand Webroot / cached IE13; `Distinct Peers (24h)` + `Traffic (24h)` ❌ at baseline (summed from IB3/IE4 flow events — show `—` until a flow log source is connected). Same four labels render for every IP. |
| **IB2** | IP Identity Card | Overview | 🟡 | Tier 1 common (`IP_Literal`, `Address_Family`, `Classification`, `First/Last_Seen`) ✅; Tier 2 Internal-Asset (hostname/OS/domain via `APFDiscADComputerDetails` reverse-resolve) ✅ for internal IPs; Tier 3 External (reverse-DNS/WHOIS) deferred to IE1 ❌. |
| **IB3** | Recent Activity | Activity | ✅ | ZLogs over the auth-event union by `remoteip` (4624/4625/4768/4769/4771), latest ~50; `logontype` faceted, rich-path `sourceport`+`package_name`. |
| **IB4** | Top Peers (24h) | Overview | ✅ | Top-10 by `username` / `hostname` / peer-IP over baseline auth events (at baseline peers come from auth, not firewall flows). |
| **IB5** | Recent Alerts | Recent Alerts | ✅ | Alert profiles pivoting on `remoteip`. |

### Enriched sub-sections (`IE1–IE13`, after *Investigate Entity*)

| Id | Sub-section | Tab | Baseline status | Gate / note |
|---|---|---|---|---|
| **IE1** | TI — L3C + Webroot Reputation | Overview | 🟡 | On-demand Webroot verdict / WHOIS reachable at baseline; full L3C Advanced-Threat verdict is license + module gated. |
| **IE2** | TI — VirusTotal | Overview | ❌ | License + module + VT API key. |
| **IE3** | IDS / IPS Alerts | Activity | ❌ | IDS/IPS appliance log source. |
| **IE4** | Connection History (firewall / proxy) | Activity | ❌ | Firewall / proxy log source. |
| **IE5** | Auth Activity (multi-source) | Activity | 🟡 | Win 4624/4625 + Kerberos 4768/4769/4771 ✅ at baseline; M365 / CloudTrail slices ❌. |
| **IE6** | DNS Activity | Activity | ❌ | Windows DNS Server / Sysmon EID 22 / firewall DNS source. |
| **IE7** | Asset Profile (internal-only) | Asset Profile | ✅ | `APFDiscADComputerDetails` for internal IPs (hostname/OS/domain/owner/last-seen). |
| **IE8** | Geo & ASN | Overview | ❌ | License + module / GeoIP enrichment (Path-B `GeoInfoEnrichment`). |
| **IE9** | IP-to-Host History (DHCP) | Activity | ❌ | DHCP server log source. |
| **IE10** | Process Network Connections | Activity | ❌ | Sysmon EID 3. |
| **IE11** | VPN / RAS Sessions | Activity | ❌ | VPN/RAS log source. |
| **IE12** | Cloud Sign-In | Activity | ❌ | M365 / CloudTrail connector. |
| **IE13** | Custom Threat Feed Match | Overview | 🟡 | Customer-imported feed (`ITSThreatBreachMonitoring`) — independent of Advanced-Threat license. |

### Baseline field provenance & gaps

- **No `ITSEntityRiskScoreDetails` row exists for IP entities** — any entity-level numeric score is synthesized from 4624/4625 failure ratio + burst flag + `avg(risk_level)` over recent events; per-event `risk_level` is real, the rolled-up score is heuristic.
- `Network Type` resolves only to **Private/Public** at baseline (RFC1918 regex); descriptive labels (`Tor Exit Relay`, etc.) need a TI verdict (Webroot on-demand).
- `associatedDevices` / IE7 work for **internal IPs only** (reverse-resolve via `APFDiscADComputerDetails.DNS_NAME`); external IPs have no asset profile.
- All flow-derived surfaces (Distinct Peers, Traffic, IE3/IE4/IE6/IE9/IE10/IE11) need a non-baseline log source — they render `—` / empty-state, never stubbed numbers.

---

## 📍 LOCATION entity (proposed — no spec file yet) — gated by a small engineering change

> **No `location_entity_spec.md` exists** in the Attack-vector folder. Location is retained here as a *proposed* entity; the `LB*` IDs below are provisional (this doc's own numbering) until a spec is authored. **Prerequisite:** the current `GeoInfoEnrichment` enricher writes `SOURCE_COUNTRY` only for AWS / Azure AD / Salesforce / VPN-success logtypes — Windows Security 4624/4625 are not enrolled, so Location has **no usable key field at baseline**. **Path B** (~10 LOC adding `windows device` to `GeoInfoEnrichment.LOGTYPE_FIELD` keyed on `remoteip`) unlocks country-level geo; **Path C** (query-time `IPGeoInfo` lookup per distinct IP) unlocks City / Region / ASN / Lat / Long. The table assumes Path B + C.

### Provisional baseline sub-sections (`LB1–LB9`)

| Id | Sub-section | Backing data | Baseline status |
|---|---|---|---|
| **LB1** | Risk Summary KPIs | Failed-logon ratio (4625/4624) · after-hours density · distinct `username` · allow-list-country compliance. No `ITSEntityRiskScoreDetails` row for Location — score synthesized. | 🟡 Counts after Path B; score heuristic |
| **LB2** | Location Details | GeoIP fields on `remoteip` (see breakdown). | 🟡 Country (Path B); City/ASN (Path C) |
| **LB3** | Associated Users | Distinct `username` from 4624∪4625∪4768∪4776 where `SOURCE_COUNTRY=:geo` | ❌→✅ after Path B |
| **LB4** | Associated Devices | Distinct `hostname`/`remotehost`; reverse-resolve via `APFDiscADComputerDetails.DNS_NAME` | ❌→✅ after Path B |
| **LB5** | Observed Source IPs | `terms(remoteip)` across 4624/4625/4768/4776 where `SOURCE_COUNTRY=:geo` | ❌→✅ after Path B |
| **LB6** | Logon Activity | 4624/4625 timeline by `SOURCE_COUNTRY=:geo`; `logontype` faceted | ❌→✅ after Path B |
| **LB7** | Logon Statistics | `count(4624)`·`count(4625)` split by `substatuscode` · `count(4740)` · peak-hour histogram | ❌→✅ after Path B |
| **LB8** | Travel Pattern | Per-user first-time-from-geo flag · haversine distance from home geo · concurrent-elsewhere check | ❌→✅ after Path B+C |
| **LB9** | Recent Alerts | Alert profiles pivoting on GeoIP fields | ❌→✅ after Path B |

### `LB2` Location Details sub-field breakdown

| Sub-field | Real backing | Baseline status |
|---|---|---|
| `country` / `country_code` / `country_flag` | `SOURCE_COUNTRY` on event row | ❌→✅ after Path B |
| `first_seen` / `last_seen` | `min`/`max(_zl_timestamp)` at this geo | ❌→✅ after Path B |
| `event_count_30d` · `distinct_users_30d` · `distinct_ips_30d` | `count`/`cardinality` over trailing 30d | ❌→✅ after Path B |
| `city` / `region` / `latitude` / `longitude` / `asn` / `isp` / `timezone` | `IPGeoInfo` lookup per distinct IP | 🟡 on-demand (Path C) |

**Gated by integration:** `ispBreakdown` (Path-C ASN), `vpnAnonymizerStatus`, `firewallTrafficFromGeo`, `idsAlertsFromGeo`, `cloudSignInsFromGeo`, `dnsQueriesFromGeo`, `physicalLocationContext`.

---

## ⚙️ PROCESS entity — 6 baseline + 16 enriched sub-sections (rich-path conditional)

> **Spec:** [process_entity_spec.md](../../../MD%20files/Attack%20vector/process_entity_spec.md). **Key:** `processname` (full path lowercased) parsed from **rich-path 4688/4689** (canonical `PROCESS_AUDIT` set `{592, 4688, 593, 4689}` — 592/593 are legacy NT5 variants). **Anchor types:** Sysmon (1), Windows-Security (2), Pending (3). **Sub-types here are Windows-Security only** — Sysmon anchor is ❌ at baseline.
>
> **⚠️ Critical caveat:** the Process slider is viable **only on the rich path** (`source: microsoft-windows-security-auditing`). A thin-path 4688 (`source: microsoft windows security`, `username: n/a`, message `"A new process has been created. 134"`) carries none of `processname`/`processid`/`commandline`/`parentprocessname`. Thin-path-only tenants → slider has nothing to render below the key; advertise as gated by collector config, not baseline.

### Fixed tabs

| Tab | Purpose |
|---|---|
| Overview | Process identity card, command line, hash/signature surface, risk KPIs |
| Activity | Process tree, timeline, child events (network, DNS, file, registry, image-load, IPC) |
| Threat Intel | File-hash reputation (Webroot + VT), custom feed matches |
| Recent Alerts | Alerts naming this process |

### Baseline sub-sections (`PB1–PB6`, rendered on slider open)

| Id | Sub-section | Tab | Baseline status | Backing / note |
|---|---|---|---|---|
| **PB1** | Process Risk KPIs | Overview | 🟡 | `Total Activity Events 24h`, `Recent Alerts 7d` ✅ (Windows anchor, ±8h `LOGTIMESPAN`); `Distinct Network Peers` ❌ (Sysmon EID3/5156); `Sigma Match Count` chip 🟡 (needs Sigma transforms); no `ITSEntityRiskScoreDetails` row → score heuristic. |
| **PB2** | Process Identity Card | Overview | 🟡 | Tier 1 (`Process_Name`, `PROCESSID`, host, domain, user, `LogonId`, created/exited/lifetime) ✅ rich-path; Tier 2 (MD5/SHA/IMPHASH/IntegrityLevel/Signature/CWD) ❌ (Sysmon-only); Tier 3 parent (name/PID) ✅, `Parent_CommandLine` needs GPO. |
| **PB3** | Command Line | Overview | 🟡 | 4688 `commandline` only when *Audit Process Creation → Include command line* GPO enabled; else CTA stub. |
| **PB4** | Process Tree (depth-3) | Activity | ✅ | `terms(parentprocessname)`/inverse over 4688 (`ProcessHuntingTreeAdapter`; default depth 3, max child 50). |
| **PB5** | Process Timeline (±8h, 100 rows) | Activity | ✅ | 4688 ∪ 4689 by `processname` (`getProcessTimeLine`). |
| **PB6** | Recent Alerts | Recent Alerts | ✅ | Alert profiles pivoting on `processname`/`commandline`. |

### Enriched sub-sections (`PE1–PE16`, after *Investigate Entity*)

| Id | Sub-section | Tab | Baseline status | Gate / note |
|---|---|---|---|---|
| **PE1** | File-Hash Reputation (Webroot) | Threat Intel | ❌ | Sysmon hash + Advanced-Threat license + Webroot egress. |
| **PE2** | File-Hash Reputation (VirusTotal) | Threat Intel | ❌ | Sysmon hash + license + module + VT API key. |
| **PE3** | Code-Signing Detail | Overview | ❌ | Sysmon EID 1 `SIGNATURE`/`SIGNATURESTATUS`. |
| **PE4** | Network Connections (Sysmon EID 3) | Activity | ❌ | Sysmon. |
| **PE5** | DNS Queries (Sysmon EID 22) | Activity | ❌ | Sysmon. |
| **PE6** | Files Touched (Sysmon 11/15/23/26) | Activity | ❌ | Sysmon. |
| **PE7** | Registry Activity (Sysmon 12/13/14) | Activity | ❌ | Sysmon. |
| **PE8** | Image / DLL Loads (Sysmon EID 7) | Activity | ❌ | Sysmon (EID 7 often disabled). |
| **PE9** | Inter-Process Access & Tampering (Sysmon 8/10/25) | Activity | ❌ | Sysmon. |
| **PE11** | Host Context (asset + UEBA host risk) | Asset Profile | 🟡 | `ELAWorkgroupComputerDetails` by `HOSTID` ✅; UEBA host risk needs UEBA. |
| **PE12** | Custom Threat-Feed Match (file hash) | Threat Intel | ❌ | Needs a hash (Sysmon) + customer feed. |
| **PE13** | Filtering Platform Connection (Win EID 5156) | Activity | 🟡 | Process-level network attribution **without Sysmon** — needs *Audit Filtering Platform Connection* GPO. |
| **PE14** | Service Install Footprint (Win 4697 + 7045) | Threat Intel | 🟡 | 4697 (Security) ✅ baseline; 7045 (System log) ❌ unless System log forwarded. |
| **PE15** | Scheduled Task Footprint (Win 4698–4702) | Threat Intel | 🟡 | Parsed but task-XML payload rule-grouped; needs object-access/task auditing. |
| **PE16** | Sysmon Self-Defence Events (16/4/24) | Threat Intel | ❌ | Sysmon. |

> **Sigma is a filter chip, not a section** (`PE10` deprecated). At baseline, Sigma transforms require the `Windows-*-Sigma.xml` parser pipeline to be active.

### Baseline gaps

- Everything Sysmon-anchored (PE1–PE9, PE12, PE16, PB2 Tier 2 hash/signature) is ❌ at baseline — no hash, no signature, no per-process network/DNS/file/registry without Sysmon.
- `PE13`/`PE14`/`PE15` give *some* Windows-native depth (network attribution, persistence) but each needs a specific GPO or the System log.

---

## 📁 FILE entity — 6 baseline + 12 enriched sub-sections (SACL-gated, dual-source)

> **Spec:** [file_entity_spec.md](../../../MD%20files/Attack%20vector/file_entity_spec.md). **Key:** `objectname` (full file path lowercased) with `objecttype="file"`. **Anchor types:** Hash (1), Local-path (2), SMB-share (3), Cloud-app (4), Pending (5).
>
> **Two backing data paths:** **(A) Windows native object-access auditing (`eventid=4663`)** — the path that surfaces in the unified log stream and powers the slider; carries `objectname`, `objecttype`, `accesses`, `accessmask`, `processname`/`processid`, `username`/`domain`/`securityid`, `severity`, `handleid`/`logonid`. **Requires `Audit Object Access` + per-file SACL** (a customer-applied policy, typically only on sensitive shares — so at baseline these render empty until SACL is set). **(B) In-product FIM module** ([FimTransformer.java](/home/saairam-17274/Documents/REPOS/log360_cloud/source/cloud/com/zoho/log360/server/mickeyclient/transformers/FimTransformer.java) + WinFimHandler/LinFimHandler) — agent-based, emits `changetype ∈ {created, modified, deleted}` to dedicated FIM tables (NOT `logtype="log360"` search), so the slider must cross-query the FIM index.

### Fixed tabs

| Tab | Purpose |
|---|---|
| Overview | Verdict + risk KPIs, file identity card, top accessors |
| Activity | Access timeline (action-grouped), ACL change history |
| Threat & Containment | Hash reputation, execution/provenance footprint, AV/EDR, containment actions |
| Recent Alerts | Alerts naming this file (filter chips) |

### Baseline sub-sections (`FB1–FB6`)

| Id | Sub-section | Tab | Baseline status | Backing / note |
|---|---|---|---|---|
| **FB1** | Verdict + Risk KPIs | Overview | 🟡 | Access count / failure ratio / distinct-actor / distinct-process from 4663 ✅ (SACL); reputation **verdict** chip ❌ (needs hash + TI); no `ITSEntityRiskScoreDetails` row → score heuristic. |
| **FB2** | File Identity Card | Overview | 🟡 | Path / last-access-type / last-actor / last-process / last-host / `objecttype` from most-recent 4663 ✅ (SACL); File Hash ❌ (4663 carries no hash — needs Sysmon EID 11). |
| **FB3** | Access Timeline (action-tab grouped) | Activity | 🟡 | Read/Write/Delete tabs via 4663 ✅ + Permission-Change via 4670 ✅ (both SACL-gated); file-share access 5145 ✅ (share SACL); **Execute** tab ❌ (Sysmon 1); Sysmon 11/15/23/26 file-op detail ❌. |
| **FB4** | Top Accessors (first-seen flag) | Overview | 🟡 | `terms(username,domain)` + `terms(processname)` over 4663, first-seen flag ✅ — all SACL-gated. |
| **FB5** | ACL Change History | Activity | 🟡 | 4670 (permissions changed) ✅ but needs `Audit Object Access` + SACL. |
| **FB6** | Recent Alerts | Recent Alerts | ✅ | Alert profiles pivoting on file path / `accesses`, filter chips. |

### Enriched sub-sections (`FE1–FE12`, after *Investigate Entity*)

| Id | Sub-section | Tab | Baseline status | Gate / note |
|---|---|---|---|---|
| **FE1** | Hash Reputation (Webroot) | Threat & Containment | ❌ | Needs file hash (Sysmon 11/15) + Advanced-Threat license. |
| **FE2** | Hash Reputation (VirusTotal) | Threat & Containment | ❌ | Hash + license + module + VT API key. |
| **FE3** | Execution Footprint | Threat & Containment | ❌ | Sysmon EID 1 (file run as a process). |
| **FE4** | Provenance / Mark-of-the-Web | Threat & Containment | ❌ | Sysmon EID 15 (+ parser gap on the MOTW stream). |
| **FE5** | Process Lineage | Activity | ❌ | Sysmon process-create chain. |
| **FE6** | Cross-Host Spread | Activity | ❌ | Sysmon hash correlation across hosts. |
| **FE7** | Network Egress | Activity | ❌ | Sysmon EID 3 from the spawned process. |
| **FE8** | Logon-Session Attribution | Activity | 🟡 | `logonid` on 4663 ✅ joins to 4624 session — reachable when SACL is on; full session pivot needs the auth slice. |
| **FE9** | Image-Load Footprint | Threat & Containment | ❌ | Sysmon EID 7. |
| **FE10** | AV / EDR Quarantine | Threat & Containment | ❌ | AV / EDR connector. |
| **FE11** | Persistence References | Threat & Containment | ❌ | Sysmon registry (12/13/14) / autoruns. |
| **FE12** | Containment Actions | Threat & Containment | ❌ | Response/SOAR action module + agent. |

### Baseline gaps

- The entire File slider is **SACL-gated**: nothing renders until the customer enables `Audit Object Access` and applies a SACL to the monitored path. At a fresh baseline (no SACL) FB1–FB5 are empty-state; FB6 still works (alerts).
- `File Hash`, execution, provenance, image-load, network egress (FE1–FE7, FE9) all need Sysmon — ❌ at baseline.
- `contentDiff` is **permanently gated** (Windows native cannot diff file content); `dlpClassification` needs the DLP module; `cloudSyncStatus` needs M365/OneDrive audit.

---

## 🌐 DOMAIN entity — 5 baseline + 10 enriched sub-sections

> **Spec:** [domain_entity_spec.md](../../../MD%20files/Attack%20vector/domain_entity_spec.md). **Key:** the parsed **`domain`** field (rich-path Win-Sec, flat/NetBIOS name) for internal sub-types, or a DNS-form string for external. **Sub-types:** AD-Internal (1), Entra-Internal (2), Hybrid (3), External (4), Flagged-External (5), Pending (6). The slider detects sub-type at query time (DNS-form → External; AD short-name → AD-Internal). The **Configuration & Policy** tab is hidden for external sub-types; the **TI** sections (DE1/DE2) are hidden for internal sub-types.

### Fixed tabs

| Tab | Internal (AD/Entra) emphasis | External (DNS) emphasis |
|---|---|---|
| Overview | Identity card, DC/user/computer counts, risk KPIs | Identity card, TI verdict / WHOIS chips |
| Activity | Logon + Kerberos + account-change events keyed on the domain | *On-demand only* — no event activity at baseline |
| Configuration & Policy | Trust topology, DC inventory, account/password policy | *Hidden* |
| Recent Alerts | Alerts naming the domain | Same |

### Baseline sub-sections (`DB1–DB5`)

| Id | Sub-section | Tab | Baseline status | Backing / note |
|---|---|---|---|---|
| **DB1** | Risk KPIs (sub-class-aware) | Overview | 🟡 | Internal: `Failed Logons 24h` (4625) · `Lockouts 24h` (4740) · `Account Changes 24h` (4720/4722-4726/4738) · `Cross-Domain Auth 24h` all ✅ by `domain`. External: Webroot verdict tier + dark-web mentions ✅ on-demand. No `ITSEntityRiskScoreDetails` row → score heuristic. |
| **DB2** | Identity Card (tiered) | Overview | 🟡 | Tier 1 common (`domain`, classification) ✅; Tier 2 AD (`ADSDomainConfiguration`: `DOMAIN_FLAT_NAME`, `DOMAIN_DNS_NAME`, `DOMAIN_NAME`, `DEFAULT_NAMING_CONTEXT`, `DOMAIN_FUNCTIONAL_LEVEL`, `IS_DEFAULT_DOMAIN`, `GUID`, `ADMIN_STATUS`, forest via `FOREST_ID`, user/computer/DC counts) ✅ for AD-Internal; Tier 3 Entra ❌; Tier 4 External WHOIS deferred to DE1 ❌ (on-demand). `PDC Emulator / FSMO Roles` ❌ (not in `ADSDomainConfiguration` — schema gap). |
| **DB3** | Recent Activity | Activity | ✅ | 4624/4625 timeline `WHERE domain=:dom`, faceted by `logontype` (internal only). |
| **DB4** | Top Callers | Overview | ✅ | `terms(username)` / `terms(hostname)` over 4624/4625 `WHERE domain=:dom`; cross-checked vs `APFDiscADUserDetails`/`APFDiscADComputerDetails WHERE DOMAIN_NAME=:dom`. |
| **DB5** | Recent Alerts | Recent Alerts | ✅ | Alert profiles pivoting on `domain` / DOMAIN IOC. |

### Enriched sub-sections (`DE1–DE10`, after *Investigate Entity*)

| Id | Sub-section | Tab | Baseline status | Gate / note |
|---|---|---|---|---|
| **DE1** | TI — L3C + Webroot Reputation | Overview | 🟡 | External sub-types only; Webroot verdict / WHOIS / CDB stats / dark-web mentions ✅ on-demand at baseline; full L3C verdict license-gated. Hidden for internal. |
| **DE2** | TI — VirusTotal | Overview | ❌ | License + module + VT API key. |
| **DE3** | IDS / IPS Alerts | Activity | ❌ | IDS/IPS log source. |
| **DE4** | Logon from Domain | Activity | ✅ | 4624/4625/4768/4771/4776 `WHERE domain=:dom` — baseline rich-path. |
| **DE5** | DNS Query History | Activity | ❌ | Windows DNS Server / Sysmon EID 22 / firewall DNS source. |
| **DE6** | Connection History | Activity | ❌ | Firewall / proxy / TLS log source. |
| **DE7** | Trust Topology | Configuration & Policy | 🟡 | Forest membership via `ADSForestConfiguration` ✅; directional trusts ❌ — no `ADSTrust*` table in `ADSF-DD-DML` (AD-sync schema extension needed). |
| **DE8** | DC Inventory | Configuration & Policy | ✅ | `ADSDCConfiguration WHERE DOMAIN_ID = (SELECT DOMAIN_ID FROM ADSDomainConfiguration WHERE DOMAIN_FLAT_NAME=:dom)` — authoritative DC list from AD-sync. |
| **DE9** | Account & Password Policy | Configuration & Policy | ❌ | AD domain password policy not in current AD-sync schema; Entra policy partial (needs Entra connector). |
| **DE10** | Verified Domain / Federation | Configuration & Policy | ❌ | Entra connector (verified-domain + federation config). |

### Baseline field provenance & gaps

- **DB2 AD tier + DB3/DB4 + DE4/DE8** are the strong baseline surface — backed by AD-sync (`ADSDomainConfiguration`/`ADSForestConfiguration`/`ADSDCConfiguration`/`APFDiscAD*Details`) joined to rich-path Win-Sec by the flat `domain` field (confirmed in production: 4738 events carry `domain: elanew2017`).
- **Cross-domain auth** (4624 where `domain` ≠ host's domain suffix) is reachable ✅; **directional trust relationships** are not (no `ADSTrust*` table — engineering gap).
- **External/DNS flavor** has no event-driven activity at baseline (no firewall/DNS/proxy ingest); it relies entirely on on-demand Webroot enrichment (DE1).
- Account/password policy and Entra federation (DE9/DE10) need a schema extension or the Entra connector.

---

## Summary

Counts use the per-entity sub-section IDs from each Attack-vector spec (`✅` renders real data at baseline · `🟡` partial/on-demand/GPO-or-SACL-gated · `❌` needs a non-baseline collector/license/module/schema). All enriched (`*E*`) sub-sections are `❌` at baseline by definition unless noted.

| Entity | Baseline (`*B*`) ✅ / 🟡 / ❌ | Enriched (`*E*`) reachable at baseline | Biggest gate |
|---|---|---|---|
| 👤 User (UB1–UB10 / UE1–UE12) | ✅ UB2-UB8 (7) · 🟡 UB1 · ❌ UB9-UB10 (2, M365/SaaS) | 🟡 UE2 (rich-path), UE4/UE5/UE6/UE12; ✅ UE7/UE8/UE10 (AD-derived) | M365/Entra connector (UB9, UE9/UE11); UEBA engine (UE1) |
| 🖥️ Device (B1–B11 / E1–E19) | ✅ B2-B6 (5) · 🟡 B1 · ❌ B7-B11 (5, DB/web/flow/NAS/VM) | 🟡 E2-E5, E18 (SACL/GPO); ❌ rest | Non-Windows log sources; Sysmon; GPO discovery schema |
| 🌐 IP (IB1–IB5 / IE1–IE13) | ✅ IB3/IB4/IB5 · 🟡 IB1/IB2 | ✅ IE5/IE7; 🟡 IE1/IE13; ❌ rest | Firewall/flow + GeoIP feeds |
| 📍 Location (LB1–LB9, **no spec**) | ❌ all at baseline (no key) → ✅ LB3-LB9 after Path B; 🟡 LB1/LB2 | — | `GeoInfoEnrichment` Path-B/C change (engineering) |
| ⚙️ Process (PB1–PB6 / PE1–PE16) | ✅ PB4/PB5/PB6 · 🟡 PB1/PB2/PB3 (rich-path + GPO) | 🟡 PE11/PE13/PE14/PE15; ❌ Sysmon-anchored rest | Rich-path collector; Sysmon |
| 📁 File (FB1–FB6 / FE1–FE12) | ✅ FB6 · 🟡 FB1-FB5 (all SACL-gated) | 🟡 FE8; ❌ rest | `Audit Object Access` + SACL; Sysmon; AV/EDR |
| 🌐 Domain (DB1–DB5 / DE1–DE10) | ✅ DB3/DB4/DB5 · 🟡 DB1/DB2 (AD-internal ✅, external/Entra ❌) | ✅ DE4/DE8; 🟡 DE1/DE7; ❌ rest | Entra connector; `ADSTrust*` + policy schema (engineering) |

**Takeaways**
1. **User, Device, and Domain (AD-internal) are the strongest baseline surfaces** — most of their `*B*` sub-sections render real data on a vanilla AD-sync + Win-Sec install, **provided the rich-path collector is used**.
2. **Process and File are rich-path-conditional and SACL-conditional** — the slider should detect collector mode + SACL coverage at query time and show a setup-required banner when empty.
3. **IP is the most integration-dependent for traffic context** — IB3/IB4/IB5 + IE5/IE7 work from auth-plane/AD data; Webroot (IE1) adds verdict on-demand; the flow-derived chips/sections (Distinct Peers, Traffic, IE3/IE4/IE6/IE9/IE10/IE11) stay empty until firewall + DNS feeds are added.
4. **Location has the largest gated ROI** — it has **no spec yet** and **no key at baseline**; a ~10-line `GeoInfoEnrichment` patch (Path B) unlocks country-level geo on the 4624/4625 stream we already index, and Path C unlocks City/ASN/Lat-Long.
5. **Domain must be presented sub-type-aware** — AD-internal (`domain` field + AD-sync tables) is mostly baseline (DB2-AD/DB3/DB4/DE4/DE8); external/DNS relies on Webroot on-demand (DE1); the Configuration & Policy tab is hidden for external sub-types.
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

This doc now mirrors the per-entity taxonomies in [the Attack-vector entity specs](../../../MD%20files/Attack%20vector/) — sub-section IDs (`UB*`/`UE*`, `B*`/`E*`, `IB*`/`IE*`, `PB*`/`PE*`, `FB*`/`FE*`, `DB*`/`DE*`, and the provisional `LB*`) are the spec IDs verbatim for 1:1 cross-reference. For exact per-field ES projections of every section, see `entity_data_mapping.md` §9 (sections §9.1–§9.29 verified; §9.31 lists 38 pending-inventory sections).
