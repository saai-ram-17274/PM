# V4 Entity & Edge Relation Slider — Data Source Mapping & Feasibility

> **Generated**: 24 Apr 2026 | **Updated**: 05 May 2026 (v4 — edge relation slider data mapping)  
> **Purpose**: Maps every field in the V4 Alert Investigation prototype to its backend source. Fields marked ❌ have been removed from the prototype. Section 6 documents **fields to remove**. **Section 7** documents the **Edge Relation Slider**. Section 8 documents **new SOC enrichments**.  
> **v4 Note**: Edge relation slider added with 7 data-enriched sections. All fields validated against backend code. See Section 9 changelog for details.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ YES | Data exists in backend — can be implemented |
| 🟡 PARTIAL | Some data available, not all fields or needs aggregation |
| ❌ NO | Not available in current product — remove from prototype |

---

## 1. USER Entity (`user-m-henderson`, `user-admin`)

### 1.1 Risk Summary
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Risk Score (0–100) | ✅ | `ITSEntityRiskScoreDetails.RISK_SCORE` | `RiskScoreHandler` — computed `MODIFIED_SCORE × SEVERITY_SCORE`. Cached in Redis |
| Severity | ✅ | `ITSRiskSeverityDetails.SEVERITY_NAME` | Mapped from score thresholds |
| Active Anomalies | ✅ | `ITSEntityRiskScoreDetails.DETECTION_COUNT` | Raw DB field |
| Failed Logins (24h) | ✅ | Elasticsearch `eventid=4625` | Aggregated ES query on Windows Security logs |
| Time Since First Alert | ✅ | `ITSAlertProfileConfigurations` | Computed: `now() - first_alert_timestamp` |
| First Seen | ✅ | `ADSAnomalyDetectionUniqueEntities.FIRST_SEEN_TIME` | Raw DB |
| Last Activity | ✅ | ES latest `_zl_timestamp` | ES max-timestamp aggregation |
| ~~Investigation Status~~ | ❌ | ~~Incident tables~~ | **Removed v3**: Entities are not incidents. One entity can span multiple incidents. `ADSIncidentStatus` only has 3 manual statuses (Open/In Progress/Closed) — showing per-entity status is misleading |

### 1.2 User Details
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Display Name | ✅ | `APFDiscADUserDetails.DISPLAY_NAME` | AD Sync (LDAP `displayName`) |
| SAM Account Name | ✅ | `APFDiscADUserDetails.SAM_ACCOUNT_NAME` | AD Sync (`sAMAccountName`) |
| UPN | ✅ | `APFDiscADUserDetails.LOGON_NAME` | AD Sync (`userPrincipalName`) |
| Email | ✅ | `APFDiscADUserDetails.EMAIL_ADDRESS` | AD Sync (`mail`) |
| Job Title | ✅ | `APFDiscADUserDetails.TITLE` | AD Sync (`title`) |
| Department | ✅ | `APFDiscADUserDetails.DEPARTMENT` | AD Sync (`department`) |
| Manager | ✅ | `APFDiscADUserDetails.MANAGER` | AD Sync (`manager`) |
| Last Logon Time | ✅ | `APFDiscADUserDetails.LAST_LOGON_TIME` | Multi-DC MAX via `APFMultiDCAttrConfig` |
| OU Name | ✅ | `APFDiscADUserDetails.OU_NAME` | AD Sync (`ouName`) |
| Account Created | ✅ | `APFDiscADUserDetails.WHEN_CREATED` | AD Sync (`whenCreated`) |
| Account Status | ✅ | `APFDiscADUserDetails.ACCOUNT_STATUS` | UAC flags |
| Logon Workstation | ✅ | `APFDiscADUserDetails.LOGON_TO` | AD Sync (`userWorkstations`) |
| Primary Group | ✅ | `APFDiscADUserDetails.PRIMARY_GROUP_ID` | Join with `APFDiscADGroupDetails` |

### 1.3 Logon Activity
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Logon Type | ✅ | ES `LOGONTYPE` | Windows 4624/4625: 2=Interactive, 3=Network, 10=RDP |
| Target Host | ✅ | ES `HOSTNAME` | Raw from Windows Security log |
| Source IP | ✅ | ES `REMOTEIP` | Raw from Windows Security log |
| Status | ✅ | ES `EVENTID` | 4624=Success, 4625=Failure |

### 1.4 Processes
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Process Name | ✅ | ES `PROCESSNAME`/`IMAGE` | Sysmon Event 1 / Windows 4688 |
| Parent Process | ✅ | ES `PARENTIMAGE` | Sysmon Event 1 |

### 1.5 Service Triggered
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Service Name | ✅ | ES parsed field | Windows Event 7045/4697 |
| Display Name | ✅ | ES parsed field | Windows Event 7045 |
| Startup Type | ✅ | ES parsed field | Windows Event 7045 |
| Host | ✅ | ES `HOSTNAME` | Raw |
| Status | ✅ | ES `SEVERITY` | Raw |

### 1.6 Recent Alerts
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Alert label | ✅ | `ITSAlertProfileConfigurations.DISPLAY_NAME` | DB |
| Type | ✅ | `ITSAlertProfileConfigurations.ALERT_TYPE` | 12 types: PRE_DEFINED, CUSTOM, RULE, CORRELATION, ANOMALY, etc. |
| MITRE Technique | 🟡 | `ITSDetectionRuleVsMitre.TECHNIQUE_ID` | Only RULE-type alerts have MITRE mapping |
| Source | ✅ | `ITSAlertProfileConfigurations.LOG_TYPE` | Raw |
| Status | ✅ | Incident status tables | `IncidentStatusUpdaterActions` |
| Severity | ✅ | `ITSAlertProfileConfigurations.ALERT_SEVERITY` | Raw |

### 1.7 Resource/File Access
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Host | ✅ | ES `HOSTNAME` | Raw |
| File Name | ✅ | ES `OBJECTNAME`/`SourceFileName` | Win 4663 / M365 SharePoint audit |
| Location | ✅ | ES `OBJECTNAME` path / `SiteURL` | Reports: `SP_FILE_ACCESS_ACTIVITIES` |
| Change Type | ✅ | ES `OPERATION`/`ACCESS_MASK` | M365: `FileDownloaded`, `FileModified`, `FileDeleted` |

### 1.8 UEBA Risk Profile
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Risk Score | ✅ | `ITSEntityRiskScoreDetails.RISK_SCORE` | Same as 1.1 |
| ~~Peer Group~~ | ❌ | ~~`ADSAnomalyDetectionSource.IS_PG_CONFIGURED`~~ | **Removed v3**: Peer group concept exists but avg score not directly queryable. Displaying partial data is misleading |
| ~~Deviation~~ | ❌ | ~~Computed: `entityScore / peerGroupAvg`~~ | **Removed v3**: Requires peer group avg which isn't stored. Runtime computation too expensive for slider |
| ~~Risk Trend~~ | ❌ | ~~`ITSEntityRiskScoreDetails`~~ | **Removed v3**: Only current score stored — no time-series history. Cannot show trend without historical snapshots |
| Anomalies Detected | ✅ | `ITSEntityRiskScoreDetails.DETECTION_COUNT` | Raw |
| Account Type | ✅ | `APFDiscADUserDetails` + SID analysis | Derived from SID (-500 = admin) |
| ~~Watch List~~ | ❌ | ~~`ADSAnomalyDetectionUniqueEntities.IS_WATCHLISTED`~~ | **Removed v3**: Manual UEBA dashboard toggle — workflow preference, not a security attribute relevant to investigation |

### 1.9 Login Statistics
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Total Logins | ✅ | ES count: `eventid=4624` | Aggregated |
| Successful | ✅ | ES count: `eventid=4624` | Aggregated |
| Failed | ✅ | ES count: `eventid=4625` | Aggregated |
| Unique Source IPs | ✅ | ES `distinct_count(REMOTEIP)` | Aggregated — prototype shows count + actual IPs (e.g. `3 (192.168.1.22, 10.18.1.81, 10.112.11.1)`) |
| ~~Unique Geolocations~~ | ❌ | ~~GeoIP enrichment on REMOTEIP~~ | **Removed v3**: City-level GeoIP unreliable (depends on MaxMind DB tier). Country-level doesn't add value as a count |
| ~~MFA Challenges~~ | ❌ | ~~M365 Entra ID sign-in logs~~ | **Removed v3**: Arbitrary number mixing on-prem (no MFA data in 4624/4625) and cloud sign-ins. Not a meaningful metric |
| Off-Hours Logins | ✅ | `UserWorkHoursUtils.isOffHours()` | log360cloudcommon |
| Unique Hosts | ✅ | ES `distinct_count(HOSTNAME)` | Aggregated |

### 1.10 Cloud Identities
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Azure AD identity | ✅ | `APFDiscAADUserDetails.USER_PRINCIPAL_NAME` | MS Graph API sync |
| Azure Roles | ✅ | `APFDiscAADUserDetails` + role tables | APF Azure role sync |
| Conditional Access | 🟡 | M365 sign-in log CA evaluation results | Sign-in events only — no policy table |
| M365 License | ✅ | `APFDiscAADUserDetails` + `LicenseSKUDetails.json` | License mapping |

### 1.11 Identity Risk
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Password Age | ✅ | Computed: `now() - PASSWORD_LAST_SET` | APF AD sync |
| Group Memberships | ✅ | `APFDiscADGroupDetails` + member-of join | APF group sync |
| Privileged Groups | ✅ | SID analysis + group check | `DefaultAdminUserRuleAnalyzer` |
| Stale Account | ✅ | Computed from `LAST_LOGON_TIME` | `InactiveUserBasedADRuleAnalyzer` |
| Service Account | ✅ | UAC flags analysis | Derived |
| Last Password Change | ✅ | `APFDiscADUserDetails.PASSWORD_LAST_SET` | Raw |

### 1.12 Network Activity
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Type (DNS/FW/Proxy/VPN) | ✅ | ES `HOSTTYPE`/`LOGTYPE` | itsf `LogFormats` — 20+ vendors |
| Domain/Destination | ✅ | ES `QUERY_NAME`/`DST_IP`/`DST_HOST` | Raw from parsed syslog |
| Resolution | ✅ | ES DNS `RESOLVED_IP` | Raw |
| Protocol | ✅ | ES `PROTOCOL` | Raw |
| Bytes Out/In | ✅ | ES `BYTES_SENT`/`BYTES_RECEIVED` | Raw from FW/proxy |
| Duration | ✅ | ES `SESSION_DURATION` | Raw from VPN/FW |
| Method | ✅ | ES `METHOD` | Raw from proxy/IIS |
| User-Agent | ✅ | ES `USER_AGENT` | Raw from proxy/IIS |

### 1.13 Compliance Impact
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Framework | ✅ | `CompliancePolicy` + `CompliancePolicyAct` | Predefined: PCI-DSS, HIPAA, SOX, GDPR, NIST |
| Status | ✅ | `ComplianceRuleResultList` | Pass/Fail/High Risk/Manual |
| Controls | ✅ | `CompliancePolicyAct` rules | Config-driven |
| Impact (per-alert auto-tag) | 🟡 | Manual mapping only | **Gap**: No auto-tag when alerts fire |

### 1.14 Threat Intel
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Primary IOC | ✅ | ES `THREAT_REPUTATION`, `THREAT_SOURCE` | `ThreatAnalyticsIntermediateProcessor` enrichment |
| VirusTotal | ✅ | `VirusTotalActionHandler` | External API, Vendor ID=2 |
| First Seen (Global) | ✅ | ES `min(_zl_timestamp)` | Aggregated |
| MITRE Techniques | 🟡 | `ITSDetectionRuleVsMitre` | Only for RULE-type alerts |

### 1.15 DLP Incidents
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Policy | ✅ | M365 audit `OPERATION` / DSP rules | M365 SharePoint events + `DLPHandler` (117 rules) |
| Action | ✅ | M365 audit — Alert/Block | Raw, read-only |
| File | ✅ | ES `SourceFileName`/`OBJECTNAME` | Raw |
| Destination | ✅ | ES transfer destination | Raw |

### 1.16 Remediation & Playbooks
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Verdict | 🟡 | Combined confidence scoring | **New**: Signals exist, aggregation logic needs building |
| Recommendations | ✅ | `PlayBookRecommendation.xml` | `PlaybookRecommendationEngine` |
| Playbooks | ✅ | `ADSPlayBookQuickActionBlocks.xml` + `IMWorkflow` | adsf `imworkflow` module |

### 1.17 Account Lockout History
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Locked User | ✅ | ES `EVENTID=4740` | Windows-ActiveDirectory.xml → `usr_userMOD` rule |
| Source Computer | ✅ | ES `CALLER_WORKSTATION` | Windows.xml parser regex for 4740 |
| Locking DC | ✅ | ES `HOSTNAME` | DC that processed the lockout |
| Event ID | ✅ | ES `EVENTID` | Raw (4740) |
| Time | ✅ | ES `TIME` / `_zl_timestamp` | Raw |

> **ES Query**: `EVENTID=4740 AND (CALLER=<user> OR USERNAME=<user>)` → order by TIME desc

### 1.18 Password Change / Reset History
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Operation | ✅ | ES `EVENTID` 4723/4724/4726 | Windows-ActiveDirectory.xml dedicated rules |
| Caller | ✅ | ES `CALLER` | Who performed the change |
| Target | ✅ | ES `TARGET` / `USERNAME` | Whose password changed |
| Source | ✅ | ES `HOSTNAME` / `IPADDRESS` | Origin host/IP |
| Result | ✅ | ES `EVENTID` mapping | Success (4724) / Reset (4724 by admin) |

> **ES Query**: `(EVENTID IN [4723,4724,4726] AND TARGET=<user>) OR (HOSTTYPE=azure_active_directory AND OPERATION IN ['change user password','reset user password'] AND TARGET=<user>)`

### 1.19 Group Membership Changes
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Operation | ✅ | ES `OPERATION` / `CATEGORY=GROUP MODIFIED` | Add vs Remove |
| Group | ✅ | ES `RESOURCE` / `RESOURCE_NAME` | Windows AD events 4728/4732/4756/4729/4733/4757 + Entra NR8/NR9 |
| Caller | ✅ | ES `CALLER` | Who made the change |
| Source | ✅ | ES `HOSTNAME` / `IPADDRESS` | Origin |

> **ES Query**: `(CATEGORY='GROUP MODIFIED' AND (USERNAME=<user> OR TARGET=<user>)) OR (HOSTTYPE=azure_active_directory AND OPERATION IN ['Add member to group','Remove member from group'] AND TARGET_NAME=<user>)`

### 1.20 Mailbox Forwarding Rules
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Operation | ✅ | ES `OPERATION` | new-inboxrule, set-inboxrule, set-mailbox |
| Mailbox | ✅ | ES `TARGET` (ObjectId) | Exchange.xml parser |
| Rule Name | ✅ | ES `PARAMETERS` JSON | Inside PARAMETERS — extractable, not top-level indexed |
| ForwardTo | ✅ | ES `PARAMETERS` JSON | Inside PARAMETERS — forwarding destination address |
| Creator IP | ✅ | ES `IPADDRESS` | Source IP of the rule creator |

> **ES Query**: `HOSTTYPE=exchange_online AND OPERATION IN ['new-inboxrule','set-inboxrule','set-mailbox'] AND (TARGET=<user> OR CALLER=<user>)`

### 1.21 Recent Application Access
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Application | ✅ | ES `APPLICATIONNAME` | Entra_Graph.xml parses `appDisplayName` |
| Source IP | ✅ | ES `IPADDRESS` | Sign-in source |
| Risk Level | ✅ | ES `RISK_LEVEL` | `riskLevelDuringSignIn` from Entra |
| Result | ✅ | ES `STATUS` | Success/Failure |

> **ES Query**: `HOSTTYPE=azure_active_directory AND RECORD_TYPE_L=15 AND CALLER=<user>` → group by `APPLICATIONNAME`

### 1.22 Privileged Role Assignment Changes
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Role Name | ✅ | ES `RESOURCE` / `RESOURCE_NAME` | Entra_Graph.xml NR6/NR7 extracts `Role.DisplayName` |
| Operation | ✅ | ES `OPERATION` | Add/Remove member to role |
| Target User | ✅ | ES `TARGET_NAME` | Who was assigned/removed |
| PIM Activity | ✅ | ES `OPERATION='update role setting in pim'` | Entra PredefinedReports.xml |
| IS_PRIVILEGED flag | ✅ | `APFDiscAADRoleDefinitionDetails.IS_PRIVILEGED` | DB table |

> **ES Query**: `HOSTTYPE=azure_active_directory AND OPERATION IN ['Add member to role','Remove member from role'] AND (TARGET_NAME=<user> OR CALLER=<user>)`  
> **Prototype**: `user-m-henderson` uses `emptyText` (no role changes); `user-admin` has actual timeline data.

---

## 2. DEVICE Entity (`dev-ws045` — CORP-WS-045)

### 2.1 Risk Summary
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Risk Score | ✅ | `ITSEntityRiskScoreDetails` (HOST entity type=2) | UEBA — entity type HOST |
| Severity | ✅ | `ITSRiskSeverityDetails` | Mapped from score |
| Vulnerabilities count | ❌ | **Not available** | No vulnerability scanner in product |
| Suspicious Processes count | ✅ | Alert count for detection rules on host | ES + alert queries |
| Rogue Services count | ✅ | Alert count from Event 7045 alerts | ES + alert queries |
| Unpatched Days | ❌ | **Not available** | No patch management data |
| EDR Status | ❌ | **No live agent status** | Only license SKU, no health endpoint |
| Tor Connections count | ✅ | ES threat-enriched network events | Firewall/proxy logs with threat reputation |

### 2.2 Device Details
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Hostname | ✅ | `APFDiscADComputerDetails.COMPUTER_NAME` | AD Sync |
| OS | ✅ | `APFDiscADComputerDetails.OPERATING_SYSTEM` + `VERSION` | AD Sync |
| Domain | ✅ | `APFDiscADComputerDetails.DOMAIN_NAME` | AD Sync |
| OU | ✅ | `APFDiscADComputerDetails.OU_NAME` | AD Sync |
| Last Patch | ❌ | **Not available** | No patch data |
| AV Status | ❌ | **No live AV status** | No EDR health API |
| EDR Agent | ❌ | **No live agent status** | Only license SKU |
| Compliance | ❌ | **No Intune compliance data** | No MDM API integration |
| Assigned User | ✅ | ES latest logon event for host | ES query `HOSTNAME=X` latest user |
| IP Address | 🟡 | DHCP logs or ES logon events | Available from DHCP/logon events if collected |
| MAC Address | 🟡 | DHCP log parsing `DHCP_MAC` | Only if DHCP logs collected |
| Last Seen | ✅ | `APFDiscADComputerDetails.LAST_LOGON_TIME` or ES | AD Sync or ES latest event |
| Uptime | ❌ | **Not available** | No WMI/live telemetry |
| Disk Encryption | ✅ | `APFDiscADComputerDetails.BITLOCKER_STATUS` | AD Sync — BitLocker recovery info |
| TPM | ❌ | **Not available** | No TPM attribute in AD sync |

### 2.3 Vulnerabilities
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| CVE ID, CVSS, Component, Exploit, Patch, CISA KEV | ❌ | **Not available** | No vulnerability scanner. Would need Vulnerability Manager Plus / Qualys integration |

### 2.4 Misconfigurations (CIS Benchmark)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| CIS Rule, Status, Expected, Impact | ❌ | **Not available** | No CIS benchmark assessment engine |

### 2.5 Installed Software
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Name, Publisher, Version, Signed, Location | ❌ | **Not available** | No software inventory. Would need Endpoint Central/UEM |

### 2.6 Cloud Asset & MDM
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Intune Device ID | ❌ | **Not available** | No Intune device API |
| Intune Compliance | ❌ | **Not available** | No MDM compliance data |
| Azure AD Registered | 🟡 | AAD device discovery exists | Partial — knows device is AAD joined |
| Autopilot | ❌ | **Not available** | No Autopilot data |
| Configuration Profiles | ❌ | **Not available** | No Intune config profiles |

### 2.7 Login Activity (on device)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| User, Logon Type, Source IP, Target, Status | ✅ | ES Windows 4624/4625 filtered by `HOSTNAME` | Raw from Windows Security log |

### 2.8 Processes on Host
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Process Name, PID, User, Command Line | ✅ | ES Sysmon Event 1 / Windows 4688 | Raw from Sysmon |
| CPU%, Memory | ❌ | **Not available** | No live telemetry — only launch-time events |

### 2.9 Services on Host
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Service Name, Display Name, Account, Binary, Signed, Status | ✅ | ES Windows 7045/4697 | Raw from Windows Security/System log |

### 2.10 Users Logged On
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| User, Logon Type, Source, Session, Duration | 🟡 | ES 4624 logon + 4634 logoff | Duration requires correlating logon/logoff pairs |

### 2.11 Recent Alerts (on device)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Alert label, Type, MITRE, Source, Status, Severity | ✅ | `ITSAlertProfileConfigurations` filtered by host | Same as User 1.6 |

### 2.12 Remediation & Playbooks
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Recommendations | ✅ | `PlayBookRecommendation.xml` | Config-driven |
| Playbooks | ✅ | `IMWorkflow` engine | adsf imworkflow |

### 2.13 Agent Status & Health
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Agent Status | ✅ | `ELALogCollectors.STATUS` | `LCStatus.getLogCollectorStatus()` — 40+ statuses (RUNNING, STOPPED, CRASHED, NOT_COMMUNICATING, etc.) |
| Collector ID | ✅ | `ELALogCollectors.COLLECTOR_ID` | DB query |
| Last Sync | ✅ | Sync timestamp from `L3CSyncServlet` | Derived from last successful sync |
| Agent Version | ✅ | `ELALogCollectors` metadata | DB |
| Log Collection | ✅ | ES event count by collector | Aggregated |

> **Implementation**: Query `ELALogCollectors` table → resolve `STATUS` via `LCStatus` enum → display status badge

### 2.14 GPO Applied to Device
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| GPO Name | ✅ | `APFDiscADGPODetails.DISPLAY_NAME` | Join: Computer → OU → `GP_LINK` → GPO table |
| Status | ✅ | `APFDiscADGPODetails.GPO_FLAGS` | Enabled/Disabled/User-disabled/Computer-disabled |
| Last Changed | ✅ | `APFDiscADGPODetails.WHEN_CHANGED` | Raw DB |
| Type | ✅ | `APFDiscADGPODetails.GPO_COMP_EXTENSIONS` | Applied policy types |
| Scope | ✅ | OU chain via `APFDiscADOrganizationalUnitDetails` | GP_LINK resolution |

> **Implementation**: 1) Find device OU from `APFDiscADComputerDetails.PARENT` 2) Read `GP_LINK` from OU chain 3) Resolve GPO DNs to `APFDiscADGPODetails`

### 2.15 Security Event Summary (24h Counters)

Grouped by risk relevance. Event IDs shown as secondary detail per row (visible but non-dominant).

**Needs Review** (any count > 0 is actionable):
| Field | Event ID | Status | Source | How to Get |
|-------|----------|--------|--------|------------|
| Failed Logons | 4625 | 🔧 | ES aggregation | `EVENTID=4625 AND HOSTNAME=<device> AND TIME>now-24h` → count |
| Service Installs | 7045 | 🔧 | ES aggregation | `EVENTID=7045 AND HOSTNAME=<device>` → count |
| Scheduled Tasks | 4698 | 🔧 | ES aggregation | `EVENTID=4698 AND HOSTNAME=<device>` → count |

**Normal** (volume counters for context):
| Field | Event ID | Status | Source | How to Get |
|-------|----------|--------|--------|------------|
| Process Creation | 4688 | 🔧 | ES aggregation | `EVENTID=4688 AND HOSTNAME=<device>` → count |
| Object Access | 4663 | 🔧 | ES aggregation | `EVENTID=4663 AND HOSTNAME=<device>` → count |
| Privilege Use | 4672 | 🔧 | ES aggregation | `EVENTID=4672 AND HOSTNAME=<device>` → count |
| Policy Changes | 4719 | 🔧 | ES aggregation | `EVENTID=4719 AND HOSTNAME=<device>` → count |

> **Implementation**: Single ES multi-aggregation query with `HOSTNAME=<device> AND TIME>now-24h`, group by `EVENTID` buckets.  
> **UI**: Grouped by risk — "Needs Review" (red dot) and "Normal" (green dot). Event IDs shown as subtle secondary text next to each label. Flagged rows show count in red. No editorial annotations (removed `⚠`, `"unsigned"`, `"from unknown sources"` etc).

### 2.16 USB Device Events
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Event | ✅ | ES `EVENTID` 6416/6420/6422/6423/6424 | Windows.xml parser |
| Device Description | ✅ | ES `DEVICEDESCRIPTION` | Raw |
| Device Class | ✅ | ES `DEVICECLASSNAME` | USB storage vs HID vs other |
| User | ✅ | ES `USERNAME` | Who plugged in |
| Event ID | ✅ | ES `EVENTID` | Raw |

> **ES Query**: `HOSTNAME=<device> AND EVENTID IN [6416,6420,6422,6423,6424]`

### 2.17 Scheduled Task Events
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Event | ✅ | ES `EVENTID` 4698-4702 | Operation type |
| Task Name | ✅ | ES `SERVICENAME` | Windows.xml parser |
| User | ✅ | ES `USERNAME` / `SECURITYID` | Who created/modified |
| Command | ✅ | ES `TASKCONTENTNEW` | Full task XML with exec action |
| Trigger | ✅ | ES `TASKCONTENTNEW` XML | Trigger condition inside task XML |

> **ES Query**: `HOSTNAME=<device> AND EVENTID IN [4698,4699,4700,4701,4702]`

---

## 3. IP Entity (`ip-tor`, `ip-internal`)

### 3.1 Risk Summary
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Risk Score | 🟡 | Threat reputation enrichment | Available for external IPs via threat feeds; no score for internal IPs |
| Tor Exit Node | ✅ | `ADSThreatAnalyticsFeeds` — Tor exit list | Enriched during ingestion |
| Threat Feeds Flagged | 🟡 | Query-time lookup across all feed stores | **Not available from ingestion**: `THREAT_SERVER` only records first matching feed (`findAny()`). Needs new query-time method that checks Webroot + each STIX/TAXII server + file import and counts all hits. Show binary `Flagged` / `Not flagged` until implemented |
| Active Connections | ✅ | ES connection count | Aggregated from FW/proxy logs |
| AbuseIPDB Score | ❌ | **Not integrated** | Need new connector (ThreatTPIVendors ID=4) |
| VirusTotal Detections | ✅ | `VirusTotalActionHandler` | External API call |
| Campaign Attribution | ❌ | **Not available** | No MISP/campaign DB |

### 3.2 IP Details
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| IP Address | ✅ | From alert/log event | Raw |
| Geo Location (Country only) | ✅ | ES `GEO_COUNTRY` via MaxMind GeoIP | Country-level only — city/lat-lon unreliable. Prototype shows `Romania 🇷🇴` |
| ~~ASN~~ | ❌ | ~~MaxMind GeoIP~~ | **Removed v3**: No parser extracts ASN. Not a field in any ES index |
| ~~ISP~~ | ❌ | ~~MaxMind GeoIP~~ | **Removed v3**: No parser extracts ISP. Not a field in any ES index |
| Network Type (Tor/VPN/Datacenter) | ✅ | Threat feed enrichment | `THREAT_CATEGORIES` field |
| ~~Reverse DNS~~ | ❌ | **Not built** | No live DNS PTR lookup service |
| First Seen / Last Seen | ✅ | ES `min/max(_zl_timestamp)` | Aggregated |
| Firewall Events (24h) | ✅ | ES count filtered by IP | Aggregated from FW logs — prototype shows `4 (2 denied, 2 allowed)` breakdown |
| Protocols | ✅ | ES `PROTOCOL` distinct values | Aggregated |

> **Internal IP (`ip-internal`) variant**: Only shows IP Address, DHCP, Last Seen, Network Zone. Geo/ASN/ISP/Subnet/VLAN/Firewall Zone removed in v3.

### 3.3 Threat Intelligence
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| AbuseIPDB | ❌ | **Not integrated** | Need new connector |
| VirusTotal (Detection Ratio) | ✅ | `VirusTotalActionHandler` | API, needs key. **Only returns detection ratio** (e.g. `18/94 engines flagged`) |
| ~~VirusTotal Community Score~~ | ❌ | ~~VirusTotalActionHandler~~ | **Removed v3**: Handler does not parse community score — only detection ratio |
| ~~VirusTotal Tags~~ | ❌ | ~~VirusTotalActionHandler~~ | **Removed v3**: Handler does not parse tags array |
| Microsoft Threat Intel | ❌ | **Not integrated** | No MS TI API connector |
| CrowdStrike Falcon X | ❌ | **Not integrated** | Only CEF log parsing, no API |
| ~~AlienVault OTX~~ | ❌ | ~~STIX/TAXII feed integration~~ | **Removed v3**: Product has bulk STIX/TAXII feed download but no live OTX API query. Cannot show pulse counts or enrichment details |
| ADSThreatAnalyticsFeeds | ✅ | `ADSThreatAnalyticsFeeds` table | Internal threat feed — shows category, confidence, last updated. Prototype shows this as second TI entry |

### 3.4 Related Campaigns & IOCs
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Campaign name, Type, Targets, TTPs | ❌ | **Not available** | No campaign attribution engine |
| IOC Clusters | ❌ | **Not available** | No IOC clustering |

### 3.5 Connection History
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Direction | ✅ | ES `DIRECTION` or inferred from SRC/DST | Inbound/Outbound |
| Source Host | ✅ | ES `HOSTNAME` | Firewall reporting device identifies source host |
| Dest IP | ✅ | ES `DEST_IP` / `DST_IP` | Raw from firewall log |
| Dest Port | ✅ | ES `DEST_PORT` | Raw from firewall log |
| Bytes Sent / Received | ✅ | ES `SENT_BYTES` / `RECEIVED_BYTES` | Raw from firewall log |
| Duration | ✅ | ES `DURATION` / `SESSION_DURATION` | Raw from firewall log |
| Action | ✅ | ES `ACTION` | allow/deny/drop from firewall |
| Device | ✅ | ES `HOSTNAME` (firewall device) | Reporting device name |

> **v3 Note**: Azure AD sign-in entry removed — cloud identity events are not network connections. Connection history is now firewall-only data.

### 3.6 Geo & Network Context
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Country | ✅ | ES `GEO_COUNTRY` | GeoIP enrichment — country only |
| ~~City~~ | ❌ | ~~MaxMind GeoIP~~ | **Removed v3**: City-level unreliable — depends on MaxMind DB tier |
| ~~Latitude/Longitude~~ | ❌ | ~~MaxMind GeoIP~~ | **Removed v3**: Unreliable at city level, misleading precision |
| ~~Timezone~~ | ❌ | ~~GeoIP derived~~ | **Removed v3**: Derived from unreliable city-level data |
| ~~Hosting (Datacenter/Residential)~~ | ❌ | **Not available** | No IP classification service |
| VPN/Proxy detection | ✅ | Threat feed categories | `THREAT_CATEGORIES` |
| Threat Feed Match | 🟡 | Query-time lookup across all feed stores | **Renamed from "Blocklist Status"**. Current ingestion records only first matching feed (`findAny()` in `checkAndAddIsMaliciousFieldToLog`). To show a count, need new query-time method: `countFeedsForIP(ip)` that checks (1) Webroot via `getIPDataInThreatAnalyticsFeeds()`, (2) each enabled STIX/TAXII server via loop in `getSTIXTAXIIServerNameOfFlaggedIP()`, (3) file import via `isIPFlaggedInThreatImportFeeds()`. Until built, show `Listed` / `Not listed` (binary) |
| ~~VLAN (internal IPs)~~ | ❌ | ~~Network device logs~~ | **Removed v3**: No IP→VLAN mapping table. Event-level field not reliable |
| ~~NAC Status~~ | ❌ | **Not available** | No NAC parser |
| DHCP Lease | ✅ | `DHCP_WINDOWS`/`DHCP_LINUX` log formats | If DHCP logs collected |
| ~~Subnet~~ | ❌ | ~~Derived from IP + known network config~~ | **Removed v3**: No subnet table — would require manual config with no API |

> **External IP (`ip-tor`) geoContext**: Country, VPN/Proxy, Threat Feed Match (3 fields).  
> **Internal IP (`ip-internal`) geoContext**: Network Type, VPN/Proxy, Threat Feed Match (3 fields). Country/City/Building/Timezone/Corporate Location all removed in v3.
>
> **Why "Threat Feed Match" instead of "Blocklist Status"**: The original label "Blocklist Status" implied the IP is checked against external public blocklists (e.g., Spamhaus, DNSBL, AbuseIPDB). The product does **not** query external blocklists. It checks against its own internal threat feed stores (Webroot BrightCloud, configured STIX/TAXII servers, imported threat indicator files). "Threat Feed Match" accurately describes what the system actually does — it tells the analyst whether the IP appears in the product's configured threat intelligence feeds.

### 3.7 Associated Users
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| User, Action, Result | ✅ | ES logon events filtered by `REMOTEIP` | Aggregated |

### 3.8 Associated Devices
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Device | ✅ | ES events filtered by IP for `HOSTNAME` | Aggregated |
| MAC | 🟡 | DHCP logs `DHCP_MAC` | If DHCP collected |
| Switch Port | ❌ | **Not available** | No network infrastructure mapping |

### 3.9 Traffic Summary
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Total Flows | ✅ | ES count per IP | Aggregated from FW logs |
| Unique Destinations | ✅ | ES distinct count | Aggregated |
| Bytes Sent/Received | ✅ | ES `BYTES_SENT`/`BYTES_RECEIVED` | Aggregated |
| Anomalous Flows | 🟡 | Threat-enriched events count | Count of events with `THREAT_REPUTATION` flagged |
| Internal/External split | 🟡 | IP range classification | Needs private IP range config |

### 3.10 Logon Activity (from IP)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| User, Logon Type, App, MFA, Result, Location | ✅ | ES 4624/4625 + M365 sign-in filtered by IP | Raw |

### 3.11 Remediation & Playbooks
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Recommendations | ✅ | Config-driven | Analyst guidance |
| Playbooks | ✅ | `IMWorkflow` — firewall IP block actions | `IMPaloAltoActions`, `IMFortigateActions`, `IMCiscoActions`, etc. |

### 3.12 Firewall Action Summary
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Total Flows | ✅ | ES count per IP | Aggregated from FW logs |
| Allowed | ✅ | ES `ACTION=allow` aggregation | Fortinet/PaloAlto/CheckPoint/SonicWall |
| Denied | ✅ | ES `ACTION=deny` aggregation | Same |
| Top Dest Ports | ✅ | ES `DEST_PORT` aggregation | Per-IP port distribution |
| Protocols | ✅ | ES `PROTOCOL_TR` aggregation | TCP/UDP/ICMP breakdown |
| First Allowed | ✅ | ES `min(TIME) WHERE ACTION=allow` | Time of first allowed flow |
| First Blocked | ✅ | ES `min(TIME) WHERE ACTION=deny` | Time of first blocked flow |
| Source Devices | ✅ | ES `distinct(HOSTNAME)` | Reporting firewalls |

> **ES Query**: `(SOURCE_IP=<ip> OR DEST_IP=<ip>) AND HOSTTYPE IN [fortinet,paloalto,checkpoint,sonicwall,sophos]` → aggregate by `ACTION`

### 3.13 DNS Query History
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Domain | ✅ | ES `DNS_QUERY` / `QueryName` | Fortinet DNS + Windows-DNS-Server + Sysmon Event 22 |
| Record Type | ✅ | ES `DNS_RECORD_TYPE` | Lookup table in Eventlog-Lookup.xml (A/AAAA/MX/CNAME) |
| Resolution | ✅ | ES `QueryResults` / `RESOLVED_IP` | Sysmon Event 22 / DNS server logs |
| Querying Process | ✅ | ES `IMAGE` (Sysmon 22 only) | Process that made the DNS query |
| Source | ✅ | ES `HOSTNAME` | Source host |

> **ES Query**: `(DNS_QUERY IS NOT NULL AND (SOURCE_IP=<ip> OR DEST_IP=<ip>)) OR (EVENTID=22 AND QueryResults CONTAINS <ip>)`

### 3.14 IDS/IPS Alerts
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Signature | ✅ | ES `IDS_NAME` | Fortinet/PaloAlto/FirePower — all parse IDS fields |
| Threat ID | ✅ | ES `THREAT_ID` | PaloAlto unique threat IDs |
| Severity | ✅ | ES `SEVERITYLEVEL` | IDS severity rating |
| Action | ✅ | ES `ACTION` | allow/deny/drop/alert/reset |
| Source | ✅ | ES `HOSTNAME` | Reporting device |

> **ES Query**: `(SOURCE_IP=<ip> OR DEST_IP=<ip>) AND IDS_NAME IS NOT NULL` → aggregate by `IDS_NAME`, `SEVERITYLEVEL`

### 3.15 VPN Session History (`ip-internal` only)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| VPN User | ✅ | ES `VPN_USERNAME` | Fortinet VPN + PaloAlto GlobalProtect + Cisco AnyConnect |
| VPN Name | ✅ | ES `VPN_NAME` | Tunnel/portal name |
| Action | ✅ | ES `ACTION` (tunnel-up/tunnel-down) | Session start/end |
| Remote IP | ✅ | ES `REMOTE_IP` | Source IP of VPN connection |
| Assigned IP | ✅ | ES `PRIVATE_IP` | Tunnel IP assigned to client |
| Duration | ✅ | ES `DURATION` | Session length |
| Bytes Sent / Received | ✅ | ES `SENT_BYTES` / `RECEIVED_BYTES` | Data transferred |
| Source | ✅ | ES `HOSTNAME` | VPN concentrator device |

> **ES Query**: `(REMOTE_IP=<ip> OR PRIVATE_IP=<ip> OR SOURCE_IP=<ip>) AND (VPN_NAME IS NOT NULL OR ACTION IN ['tunnel-up','tunnel-down'])`

---

## 4. SERVICE Entity (`svc-azure-ad`, `svc-sharepoint`, `svc-winupdatesvc`, `svc-oauth`)

### 4.1 Risk Summary
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Risk Score | 🟡 | Alert count/severity aggregation per service | Computed from alert data |
| Files Exfiltrated (SharePoint) | ✅ | ES M365 audit `FileDownloaded` count | Aggregated |
| Anomalous Sessions | ✅ | UEBA / alert data | Detection rules |
| DLP Violations | ✅ | ES M365 DLP audit events | Count from audit log |

### 4.2 Service Details
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Service Name, Category, Provider | ✅ | Config / M365 Cloud Source registration | Known from source config |
| Tenant ID / Name | ✅ | M365 integration config | Stored during Cloud Source setup |
| License | ✅ | `LicenseSKUDetails.json` | License mapping |
| Status | ✅ | M365 API / last event timestamp | Active if recent events |

### 4.3 Configuration Issues (CIS Benchmark)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| CIS Rule, Status, Impact, Recommendation | ❌ | **Not available** | No CIS assessment for cloud services |

### 4.4 Conditional Access Policies
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| State, Scope, Conditions, Grant, Exclusions | 🟡 | M365 sign-in logs `conditionalAccessStatus` | Status captured in sign-in events, but **no policy definition sync** |

### 4.5 Sign-in Audit
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| User, IP, Location, App, MFA, Risk, Result | ✅ | `ENTRA_EVENT_SIGNINS` log format | Full Entra ID sign-in parsing via Graph API |

### 4.6 DLP Policy Status
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Policy names & status | 🟡 | M365 audit log DLP events | **Events** captured, but no policy config API. Knows DLP fired, not full policy rules |

### 4.7 File Access Anomaly (SharePoint)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| User, Action, Files Accessed count, Deviation | 🟡 | M365 audit + alert threshold rules | Bulk detection via alert rules, no ML model |

### 4.8 Sensitive Files Accessed
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| File, Site, Label, Action | 🟡 | ES M365 audit + `SP_SENSITIVITY_LABEL_ACTIVITY` | Label change audits captured; not deep classification |
| Classification, Size | ❌ | **Not available** | No Purview classification API |

### 4.9 Service Events (WinUpdateSvc)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Binary Dropped, Service Installed, Started, C2 Beacon | ✅ | ES Sysmon 11 (FileCreate) + Windows 7045 + FW logs | Raw from Sysmon/Windows/Firewall events |

### 4.10 Network Connections (per service)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Destination, Protocol, Bytes, DNS | ✅ | ES Sysmon Event 3 / FW logs | Per-process network connections |

### 4.11 File Drops (per service)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Operation, Path, Size, Signed, Hash | ✅ | ES Sysmon 11 (FileCreate) / 23 (FileDelete) | Raw Sysmon events |

### 4.12 Service Dependencies
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Depends On, Required By, Load Order, Recovery | ❌ | **Not available** | No service topology/dependency mapping |

### 4.13 Related Processes / Services
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Process/Service relationships | 🟡 | ES event correlation by time/host | Needs join on `HOSTNAME` + time window |

### 4.14 Recent Alerts
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Alert label, Type, MITRE, Source, Status, Severity | ✅ | `ITSAlertProfileConfigurations` | Same as User 1.6 |

### 4.15 Remediation & Playbooks
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Recommendations | ✅ | Config-driven | Analyst guidance |
| Playbooks | ✅ | `IMWorkflow` engine | Available |

### 4.16 OAuth App Consent Grants (`svc-azure-ad`)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Operation | ✅ | ES `OPERATION` | `Consent to application`, `Add delegated permission grant` |
| App | ✅ | ES `TARGET` / `TARGET_NAME` | Entra PredefinedReports: `ENTRA_RECENTLY_GRANTED_CONSENT_TO_APPLICATION` |
| Consenting User | ✅ | ES `CALLER` | Who approved the consent |
| Permissions | ✅ | ES audit detail fields | Scope/permissions granted |
| Source IP | ✅ | ES `IPADDRESS` | Where consent was granted from |
| Admin Consent | ✅ | ES audit field | Whether admin consent was granted |

> **ES Query**: `HOSTTYPE=azure_active_directory AND OPERATION IN ['consent to application','add delegated permission grant']`

### 4.17 Admin Activity on Service (`svc-azure-ad`)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Operation | ✅ | ES `OPERATION` | Entra directory audit actions |
| Target | ✅ | ES `TARGET` / `TARGET_NAME` | Resource affected |
| Caller | ✅ | ES `CALLER` | Who performed the action |
| Workload | ✅ | ES `WORKLOAD_S` | ExchangeOnline / SharePoint / AzureActiveDirectory |
| Source IP | ✅ | ES `IPADDRESS` | Origin |

> **ES Query**: Per-workload: `WORKLOAD_S=<service_workload> AND RECORD_TYPE_L IN [1,8]`

### 4.18 WMI Persistence Events (`svc-winupdatesvc`)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Event Type | ✅ | ES `EVENT_TYPE` | Sysmon Event 19/20/21 |
| Name | ✅ | ES `WMI_NAME` | WMI subscription name |
| Query / Type / Consumer | ✅ | ES `WMI_QUERY` / `DESTINATION` | Trigger condition / consumer command |
| Operation / Destination / Filter | ✅ | ES parsed fields | Created/Deleted/Modified + payload |
| User | ✅ | ES `USERNAME` | Who created the subscription |

> **ES Query**: `EVENTID IN [19,20,21] AND HOSTTYPE=sysmon AND HOSTNAME=<device>`

---

## 5. PROCESS Entity (`proc-powershell`)

> **Note (27 Apr 2026)**: `proc-oauth` was reclassified from `process` to `service` (`svc-oauth`). Token-related sections (5.9–5.12) below remain valid as the field-level data mapping for the OAuth token service — they are now surfaced under the SERVICE entity rather than PROCESS.

### 5.1 Risk Summary
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Risk Score | 🟡 | Alert severity aggregation for process | Computed from detection rules |
| AMSI Detections count | ✅ | ES PowerShell 4104 events | Count of AMSI_RESULT_DETECTED |
| C2 Connection | ✅ | ES Sysmon Event 3 + threat enrichment | Network events with threat reputation |
| Payload Downloaded | ✅ | ES Sysmon Event 11 (FileCreate) | File creation by process |
| Encoded Commands | ✅ | ES 4104 ScriptBlock | Script block content analysis |
| Child Processes count | ✅ | ES Sysmon Event 1 parent-child | Count children by ParentProcessGuid |

### 5.2 Process Details
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Process Name | ✅ | ES `IMAGE` | Sysmon Event 1 |
| PID | ✅ | ES `ProcessId` | Sysmon Event 1 |
| Parent Process | ✅ | ES `ParentImage`, `ParentProcessId` | Sysmon Event 1 |
| Command Line | ✅ | ES `CommandLine` | Sysmon Event 1 / Windows 4688 |
| User | ✅ | ES `User` | Sysmon Event 1 |
| Integrity Level | ✅ | ES `IntegrityLevel` | Sysmon Event 1 |
| Start Time | ✅ | ES `UtcTime` | Sysmon Event 1 |
| Status | 🟡 | Sysmon Event 5 (ProcessTerminate) | Need to check if terminated |
| Signature | ✅ | ES Sysmon fields | If Sysmon captures signature info |
| Thread Count, Handle Count | ❌ | **Not available** | No live process telemetry |

### 5.3 Process Tree
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Parent-child chain | 🟡 | Sysmon Event 1 `ParentProcessGuid`→`ProcessGuid` | **Available** but needs join/reconstruction — no pre-built tree |

### 5.4 AMSI Events (Script Content)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| AMSI Detection, Content Preview, Scan Result | ✅ | Windows Event 4104 (ScriptBlock) | Full PowerShell script block text + AMSI result |
| Script Block ID | ✅ | Event 4104 `ScriptBlockId` | Raw |

### 5.5 Registry Modifications
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Operation (SetValue/Create/Delete), Key, Value, Data | ✅ | Sysmon Event 12/13/14 | Full registry audit |

### 5.6 Network Activity (per process)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Destination IP, Port, Protocol, Bytes, Domain | ✅ | Sysmon Event 3 (NetworkConnect) | Per-process network connections |

### 5.7 File Operations
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Operation, File Path, Size, Hash, Signed | ✅ | Sysmon Event 11/23/15 | File create/delete/stream events |

### 5.8 Child Processes
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Process, PID, Command, MITRE | ✅ | Sysmon Event 1 filtered by `ParentProcessGuid` | Raw |

### 5.9 Token Details (OAuth — `svc-oauth`)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Token Type, Grant Type, Client App | 🟡 | M365 audit log OAuth consent events | Audit log captures consent action |
| Scope | 🟡 | M365 audit log | Scope visible in raw event data |
| Issued, Expires | 🟡 | M365 audit log timestamps | Event timestamps, not token metadata |
| IP at Issuance | ✅ | M365 sign-in log source IP | Raw |
| MFA Claim | ✅ | M365 sign-in `amr` field | Raw in Entra sign-in data |

### 5.10 Token Anomalies
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Broad Scope detection | 🟡 | M365 audit + alert rules | Rule-based, no ML |
| App verification status | 🟡 | M365 audit event fields | "publisherVerified" in audit data |
| Token Replay indicators | 🟡 | Correlate sign-in IPs vs time | Impossible travel logic applies |

### 5.11 Token Usage (Graph API Calls)
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| API Call, Purpose, Response, Data Volume | 🟡 | M365 unified audit log | Some API activity in audit, but **no dedicated Graph API call audit** |

### 5.12 Related Tokens
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Refresh Token status, Other Active Tokens | ❌ | **Not available** | No token inventory from Entra API |

### 5.13 Recent Alerts
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Alert label, Type, MITRE, Source, Status, Severity | ✅ | `ITSAlertProfileConfigurations` | Same as User 1.6 |

### 5.14 Remediation & Playbooks
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Recommendations | ✅ | Config-driven | Analyst guidance |
| Playbooks | ✅ | `IMWorkflow` engine | Available |

### 5.15 DLL/Module Loads (Sysmon Event 7) — `proc-powershell`
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| DLL Path | ✅ | ES `IMAGE_LOADED` | Sysmon.xml Event 7 parser |
| Signed | ✅ | ES `SIGNED` | Boolean from Sysmon |
| Signature Status | ✅ | ES `SIGNATURE_STATUS` | Valid/Invalid/Expired |
| Hash (SHA256) | ✅ | ES `HASHES` | MD5/SHA1/SHA256 from Sysmon |
| Company / Product | ✅ | ES `COMPANY` / `PRODUCT` | PE metadata from Sysmon |

> **ES Query**: `EVENTID=7 AND HOSTTYPE=sysmon AND (IMAGE=<process_path> OR PROCESSGUID=<guid>)`

### 5.16 DNS Queries by Process (Sysmon Event 22) — `proc-powershell`
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Domain | ✅ | ES `QUERY_NAME` | Sysmon.xml Event 22 parser |
| Query Results | ✅ | ES `QUERY_RESULTS` | Resolved IPs |
| Query Status | ✅ | ES `QUERY_STATUS` | Success/Failure |

> **ES Query**: `EVENTID=22 AND HOSTTYPE=sysmon AND IMAGE=<process_path>`

### 5.17 Named Pipe Events (Sysmon Event 17/18) — `proc-powershell`
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Event Type | ✅ | ES `EVENT_TYPE` | CreatePipe / ConnectPipe |
| Pipe Name | ✅ | ES `PIPE_NAME` | Sysmon.xml Event 17/18 parser |

> **ES Query**: `EVENTID IN [17,18] AND HOSTTYPE=sysmon AND IMAGE=<process_path>`

---

## 6. Summary: What to Remove from Prototype

### DEVICE Entity — Remove These Sections
- ❌ **Vulnerabilities** (entire section) — no vulnerability scanner
- ❌ **Misconfigurations / CIS Benchmark** (entire section) — no CIS engine
- ❌ **Installed Software** (entire section) — no software inventory
- ❌ **Cloud Asset & MDM** (entire section) — no Intune API
- Remove from Device Details: `Last Patch`, `AV`, `EDR Agent`, `Compliance`, `Uptime`, `TPM`
- Remove from Processes on Host: `CPU%`, `Memory`
- Remove from Risk Summary metrics: `Vulnerabilities`, `Unpatched Days`, `EDR Status`

### IP Entity — Remove These Fields
- ❌ Remove from Risk Summary: `AbuseIPDB Score`, `Campaign Attribution`
- ❌ Remove from IP Details: `Reverse DNS`
- ❌ Remove from Threat Intelligence: AbuseIPDB, Microsoft Threat Intel, CrowdStrike Falcon X entries
- ❌ Remove **Related Campaigns & IOCs** (entire section)
- ❌ Remove from Geo Context: `Hosting (Datacenter/Residential)`, `NAC Status`
- ❌ Remove from Associated Devices: `Switch Port`

### SERVICE Entity — Remove These Sections
- ❌ **Configuration Issues / CIS Benchmark** (entire section for Azure AD)
- ❌ **Service Dependencies** (entire section for WinUpdateSvc)
- Remove from Sensitive Files: `Classification`, `Size` fields
- Remove from Conditional Access: full policy definitions (keep status from sign-in logs)
- Remove from DLP Policies: detailed policy rules (keep event-based status)

### PROCESS Entity — Remove These Fields
- ❌ Remove from Process Details: `Thread Count`, `Handle Count`
- ❌ Remove from Token entity: `Related Tokens` section (no token inventory)
- Simplify Token Usage: keep as partial (some API activity in audit)

---

## 7. Edge Relation Slider — Data Source Mapping

> **Added**: 05 May 2026  
> **What it is**: When a user clicks an edge icon on the attack graph, a right-side slider opens showing enriched connection details between two entities (e.g., User → AccessedFile → SharePoint). This section maps every field in the edge relation slider to its backend source.
>
> **Interaction Model**:
> - Click edge icon on graph → slider opens with edge-specific data
> - Source/Target entity nodes in the flow diagram are **clickable** → opens entity detail slider
> - Edge slider reuses the same `entity-details-slider` panel (shared DOM element)
>
> **Data Store**: `EDGE_ATTRIBUTES` (15 edges with structured data objects)

---

### 7.1 Flow Diagram (Source → Relation → Target)

| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Source Entity Icon | ✅ | `ENTITY_DISPLAY[source]` | Lookup from graph node data |
| Source Entity Name | ✅ | Node ID → `fmtName()` | Strips prefix, formats display name |
| Relation Label | ✅ | `EDGE_ATTRIBUTES[key].relation` | Stored per edge |
| Relation Color | ✅ | `REL_GUIDE[relation].color` | 28 relation types defined |
| Target Entity Icon | ✅ | `ENTITY_DISPLAY[target]` | Lookup from graph node data |
| Target Entity Name | ✅ | Node ID → `fmtName()` | Same formatting |
| **Clickable** | ✅ | `openEntitySlider(id)` | Click source/target to open entity slider |

### 7.2 Relation Description

| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Description Text | ✅ | `REL_GUIDE[relation].desc` | 28 relation types, each with human-readable description |
| Relation Icon | ✅ | `REL_GUIDE[relation].icon` | Category-specific icon |

### 7.3 MITRE ATT&CK Mapping

| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Tactic Name | ✅ | `ITSDetectionRuleVsMitre.TACTIC` | Mapped from detection rule |
| Tactic ID | ✅ | `ITSDetectionRuleVsMitre.TACTIC_ID` | e.g., `TA0001` |
| Technique Name | ✅ | `ITSDetectionRuleVsMitre.TECHNIQUE_NAME` | e.g., `Valid Accounts` |
| Technique ID | ✅ | `ITSDetectionRuleVsMitre.TECHNIQUE_ID` | e.g., `T1078` |

> **Backend**: Only RULE-type alerts have MITRE mapping. Correlation and anomaly alerts may not have MITRE tags — field is conditionally rendered.

### 7.4 Detection Rule

| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Rule Name | ✅ | `ITSAlertProfileConfigurations.DISPLAY_NAME` | DB lookup by alert ID |
| Rule Type | ✅ | `ITSAlertProfileConfigurations.ALERT_TYPE` | Correlation / Anomaly (UEBA) / Threat Intel |
| Rule ID | ✅ | `ITSAlertProfileConfigurations.ALERT_PROFILE_ID` | Internal ID |

### 7.5 Connection Properties

| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Event Count | ✅ | ZLogs `COUNT(*)` | `SELECT COUNT(*) FROM logs WHERE src_entity=? AND tgt_entity=? AND time BETWEEN ? AND ?` |
| Risk Score (0–100) | ✅ | `ITSEntityRiskScoreDetails.RISK_SCORE` | Combined score of source + target entities |
| Risk Bar (visual) | ✅ | Computed from risk score | Color-coded: green (<40), yellow (<70), orange (<90), red (≥90) |
| Data Volume | 🟡 | ZLogs `SUM(BYTES_SENT + BYTES_RECEIVED)` | Available for FW/proxy logs; not all log types have byte counts |
| First Seen | ✅ | ZLogs `MIN(_zl_timestamp)` | Earliest event between the two entities |
| Last Seen | ✅ | ZLogs `MAX(_zl_timestamp)` | Latest event between the two entities |

### 7.6 Event Distribution Chart

| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Sparkline Bars (12 buckets) | ✅ | ZLogs `COUNT(*) GROUP BY time_bucket` | 1-hour window divided into 12 × 5-minute buckets |
| Total Events | ✅ | `SUM(all buckets)` | Computed client-side from sparkline array |
| Time Axis Labels | ✅ | Computed from `lastSeen` | Exact clock times (HH:MM) derived by subtracting bucket intervals from lastSeen |
| Average Line | ✅ | Computed: `total / buckets` | Client-side computation |
| Peak Marker | ✅ | `MAX(buckets)` | Client-side — highlights the tallest bar |
| Bar Color | ✅ | `#FFC600` (Graph.svg style) | Single yellow color, consistent with product chart style |
| Hover Tooltip | ✅ | Per-bar event count + time | Client-side interaction |

> **Backend API needed**: Single endpoint accepting `(source_entity, target_entity, relation_type, time_range)` returning `{ count, buckets[] }`. No new backend infrastructure required — standard ZLogs aggregation query.

### 7.7 Behavioral Baseline

| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Expected (baseline count) | ✅ | `DashBoardAnomalyDataProvider` | UEBA learned baseline over 30/90-day rolling window |
| Actual (observed count) | ✅ | ZLogs `COUNT(*)` for current window | Same as event count |
| Deviation | ✅ | Computed: `actual / expected` | Client-side ratio computation |
| Severity Classification | ✅ | Computed from deviation | Normal (≤1.3×), Warning (1.3–2×), Danger (>2×), First Occurrence (no baseline) |
| Visual Bars | ✅ | Dual progress bars | Expected (blue) vs Actual (color-coded by severity) |
| Pulsing Dot | ✅ | CSS animation | Severity indicator in the deviation badge |

> **Backend**: UEBA module (`AnomalyDetectionDataImpl`) computes behavioral baselines per entity-pair over rolling windows. The `expected` value comes from the learned model; `actual` is the current query result. When `expected = 0` (first occurrence), the system flags it as a novel connection.

### 7.8 Threat Intelligence

| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Vendor | ✅ | `ThreatAnalyticsIntermediateProcessor` | Webroot / file-import / STIX feed |
| Reputation Score | ✅ | `ES THREAT_REPUTATION` | 1=Critical, 2=Malicious, 3=Suspicious |
| Label | ✅ | Derived from reputation | Critical / Malicious / Suspicious |
| VirusTotal Detection | ✅ | `VirusTotalActionHandler` | Format: `18/94` (detections/total engines) |

> **Conditional**: Only shown for edges involving threat-intel-enriched entities (malicious IPs, C2 domains). Not applicable for internal-only connections.

### 7.9 Geo Context

| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Country Flag | ✅ | GeoIP → emoji mapping | Lookup from MaxMind DB |
| Country | ✅ | `ES GEO_COUNTRY` | From firewall/proxy/VPN logs |
| City | 🟡 | `MaxMind GeoLite2-City` | City-level accuracy varies — reliable for known exit nodes |
| IP Address | ✅ | `ES REMOTEIP` / `SrcIP` | Raw from log source |

> **Conditional**: Only shown for edges with external IP entities. Internal-only edges don't show geo context.

### 7.10 Evidence

| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Summary | ✅ | Alert description + enrichment | Composite from `ITSAlertProfileConfigurations.DESCRIPTION` + context |
| Key Findings (chips) | ✅ | Parsed from detection context | Extracted key facts: distances, counts, protocols, anomalies |
| Confidence Score (%) | 🟡 | Combined signal scoring | **New**: Aggregation of detection rule confidence + UEBA anomaly score + threat intel match. Logic needs building |
| Confidence Bar | ✅ | Visual from confidence % | Color-coded: green (≥90%), yellow (≥70%), orange (≥40%), gray (<40%) |
| Severity Bar | ✅ | Derived from edge risk score | Critical (≥90) / High (≥70) / Medium (≥40) / Low (<40) |
| Source Badge | ✅ | `EDGE_ATTRIBUTES.source` | Log source name: "Azure AD Sign-in Logs", "Firewall Logs", etc. |
| Event Count Badge | ✅ | `EDGE_ATTRIBUTES.count` | Same as Connection Properties count |

> **Note**: ~~Sample Log Entry~~ and ~~View in Log Search~~ button were removed from the prototype. The `rawLog` field data is retained in EDGE_ATTRIBUTES but not rendered.

---

### 7.11 Removed Sections

| Section | Reason for Removal |
|---------|--------------------|
| ~~View in Log Search~~ | Prototype scope — would need deep-link integration with Log Search module |
| ~~Sample Log Entry~~ | Mock raw log preview — not useful in prototype context |
| ~~Connected Entities~~ | Redundant — flow diagram at top already shows source/target entities with clickable navigation |

---

### 7.12 Summary — Edge Data Sources

| Data Type | Primary Source | Availability |
|-----------|---------------|---------------|
| Event Count | ZLogs `COUNT(*)` aggregation | ✅ Exists |
| Event Distribution | ZLogs `COUNT(*) GROUP BY time_bucket` | ✅ Exists |
| Behavioral Baseline | UEBA `DashBoardAnomalyDataProvider` | ✅ Exists |
| Risk Score | `ITSEntityRiskScoreDetails` | ✅ Exists |
| First/Last Seen | ZLogs `MIN/MAX(_zl_timestamp)` | ✅ Exists |
| MITRE Mapping | `ITSDetectionRuleVsMitre` | 🟡 RULE-type alerts only |
| Detection Rule | `ITSAlertProfileConfigurations` | ✅ Exists |
| Threat Intel | `ThreatAnalyticsIntermediateProcessor` + VirusTotal API | ✅ Exists |
| Geo Context | MaxMind GeoIP + `ES GEO_COUNTRY` | 🟡 Country reliable, city varies |
| Evidence Summary | Alert description + enriched context | ✅ Exists |
| Confidence Score | Multi-signal aggregation | 🟡 Needs new scoring logic |
| Data Volume | ZLogs `SUM(BYTES)` | 🟡 Only for FW/proxy logs |

---

## 8. NEW SOC Enrichments — Additions to Prototype

> All items below are **verified as implementable** with existing backend data and are now **implemented in the V3 prototype**.
>
> **Implementation Status (Prototype)**:
> | Entity Instance | New Sections Added | Status |
> |---|---|---|
> | `user-m-henderson` | accountLockouts, passwordHistory, groupMembershipChanges, mailboxForwarding, recentAppAccess, privilegedRoleChanges | ✅ Done |
> | `user-admin` | accountLockouts, passwordHistory, groupMembershipChanges, mailboxForwarding, recentAppAccess, privilegedRoleChanges | ✅ Done |
> | `dev-ws045` | agentStatus, gpoApplied, securityEventSummary, usbDeviceEvents, scheduledTasks | ✅ Done |
> | `ip-tor` | firewallSummary, dnsHistory, idsAlerts | ✅ Done |
> | `ip-internal` | vpnSessions | ✅ Done |
> | `svc-azure-ad` | oauthConsentGrants, adminActivity | ✅ Done |
> | `svc-winupdatesvc` | wmiEvents | ✅ Done |
> | `proc-powershell` | dllLoads, processDnsQueries, namedPipes | ✅ Done |
> | `svc-sharepoint` | — (N/A: DLP/file entity, no additional enrichments needed) | — |
> | `proc-oauth` | — (N/A: token entity, process-level enrichments don't apply) | — |
>
> **Tab Configuration**: Updated for all 5 entity types. User entity has new "Changes" tab; Device entity has new "Persistence" tab; IP/Service/Process tabs expanded.
> **Summary Cards**: `buildQuickCardRows()` updated with new enrichment summary rows for all entity types.

### Legend (Additional)

| Symbol | Meaning |
|--------|---------|
| ✅ YES | Data exists — ready to implement |
| 🟡 PARTIAL | Some data available, needs extra parsing or aggregation |
| 🔧 BUILDABLE | Raw data exists in ES; needs new aggregation query (no new parsing) |

---

### 8.1 USER Entity — New Sections

#### 6.1.1 Account Lockout History
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Locked User | ✅ | ES `EVENTID=4740` | Windows-ActiveDirectory.xml → `usr_userMOD` rule | Brute-force indicator |
| Source Computer | ✅ | ES `CALLER_WORKSTATION` | Windows.xml parser regex for 4740 | Reveals attack origin |
| Locking DC | ✅ | ES `HOSTNAME` | DC that processed the lockout | Locates domain controller |
| Time | ✅ | ES `TIME` / `_zl_timestamp` | Raw | Timeline correlation |
> **v3 Note**: `Note` field removed from prototype — was fabricated analyst commentary, not from any log source.
**ES Query**: `EVENTID=4740 AND (CALLER=<user> OR USERNAME=<user>)` → order by TIME desc

**Why SOC needs this**: Repeated lockouts = brute force or misconfigured service account. Source computer reveals lateral movement origin.

#### 6.1.2 Password Change / Reset History
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Operation | ✅ | ES `EVENTID` 4723/4724/4726 | Windows-ActiveDirectory.xml dedicated rules | Distinguishes self vs admin reset |
| Caller | ✅ | ES `CALLER` | Who performed the change | Detects unauthorized resets |
| Target | ✅ | ES `TARGET` / `USERNAME` | Whose password changed | Identifies victim account |
| M365 Operations | ✅ | ES M365 Entra audit | `ENTRA_RECENT_PASSWORD_CHANGE_ACTIVITIES` report | Hybrid AD + cloud coverage |

> **v3 Note**: `Note` field removed from prototype — was fabricated analyst commentary.

**ES Query**: `(EVENTID IN [4723,4724,4726] AND TARGET=<user>) OR (HOSTTYPE=azure_active_directory AND OPERATION IN ['change user password','reset user password','reset password (by admin)'] AND TARGET=<user>)`

**Why SOC needs this**: Unauthorized password resets are a top account takeover indicator. Correlating AD + M365 gives full hybrid view.

#### 6.1.3 Group Membership Changes
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Group Name | ✅ | ES `RESOURCE` / `RESOURCE_NAME` | Windows AD events 4728/4732/4756/4729/4733/4757 + Entra_Graph.xml NR8/NR9 | Privilege escalation detection |
| Operation | ✅ | ES `OPERATION` / `CATEGORY=GROUP MODIFIED` | Parser categorization | Add vs Remove |
| Caller | ✅ | ES `CALLER` | Who made the change | Attribution |
| M365 Cloud Groups | ✅ | `ENTRA_RECENTLY_ADDED_MEMBERS_TO_GROUP` report | Entra PredefinedReports.xml | Cloud-native groups |

> **v3 Note**: `Note` field removed from prototype. Editorial annotations like "(compromised session)" also removed — not from log data.

**ES Query**: `(CATEGORY='GROUP MODIFIED' AND (USERNAME=<user> OR TARGET=<user>)) OR (HOSTTYPE=azure_active_directory AND OPERATION IN ['Add member to group','Remove member from group'] AND TARGET_NAME=<user>)`

**Why SOC needs this**: Adding a user to Domain Admins / Global Admins = highest severity privilege escalation.

#### 6.1.4 Mailbox Forwarding Rules
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Rule Operation | ✅ | ES `OPERATION` | new-inboxrule, set-inboxrule, set-mailbox | BEC #1 indicator |
| Target Mailbox | ✅ | ES `TARGET` (ObjectId) | Exchange.xml parser | Whose mailbox was modified |
| Parameters (ForwardTo) | ✅ | ES `PARAMETERS` JSON | Raw parameters contain forwarding addresses | Exfiltration destination |
| Creator IP | ✅ | ES `IPADDRESS` | Source IP of the rule creator | Attribution |

> **v3 Note**: `Note` field removed. Editorial annotations like "⚠" and "(Tor proxy)" suffix removed — not from log data. `Rule Name` and `ForwardTo` are inside `PARAMETERS` JSON — extractable but not top-level indexed fields.

**ES Query**: `HOSTTYPE=exchange_online AND OPERATION IN ['new-inboxrule','set-inboxrule','set-mailbox'] AND (TARGET=<user> OR CALLER=<user>)`

**Why SOC needs this**: #1 BEC technique — attackers create forwarding rules to silently exfiltrate email. Detection prevents data loss.

#### 6.1.5 Recent Application Access
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| App Name | ✅ | ES `APPLICATIONNAME` | Entra_Graph.xml parses `appDisplayName` | Blast radius assessment |
| Access Time | ✅ | ES `TIME` | Sign-in event timestamp | Timeline |
| Source IP | ✅ | ES `IPADDRESS` | Sign-in source | Location correlation |
| Risk Level | ✅ | ES `RISK_LEVEL` | `riskLevelDuringSignIn` from Entra | Auto risk flag |

**ES Query**: `HOSTTYPE=azure_active_directory AND RECORD_TYPE_L=15 AND CALLER=<user>` → group by `APPLICATIONNAME`

**Why SOC needs this**: Shows which cloud apps a compromised user accessed — critical for understanding blast radius.

#### 6.1.6 Privileged Role Assignment Changes
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Role Name | ✅ | ES `RESOURCE` / `RESOURCE_NAME` | Entra_Graph.xml NR6/NR7 extracts `Role.DisplayName` | Privilege escalation |
| Operation | ✅ | ES `OPERATION` | Add/Remove member to role | Direction of change |
| Target User | ✅ | ES `TARGET_NAME` | Who was assigned/removed | Identifies elevated user |
| PIM Activity | ✅ | ES `OPERATION='update role setting in pim'` | Entra PredefinedReports.xml | JIT admin access |
| IS_PRIVILEGED flag | ✅ | `APFDiscAADRoleDefinitionDetails.IS_PRIVILEGED` | DB table | Built-in privilege classification |

> **v3 Note**: `user-m-henderson` has `emptyText` for this section: "No privileged role changes found — m.henderson has no Azure AD admin role assignments." This demonstrates the empty-state pattern for sections with no data.

**ES Query**: `HOSTTYPE=azure_active_directory AND OPERATION IN ['Add member to role','Remove member from role'] AND (TARGET_NAME=<user> OR CALLER=<user>)`

**Why SOC needs this**: Global Admin assignment = highest severity indicator. PIM events show just-in-time escalation.

---

### 8.2 DEVICE Entity — New Sections

#### 6.2.1 Agent Status & Health
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Agent Status | ✅ | `ELALogCollectors.STATUS` | `LCStatus.getLogCollectorStatus()` — 40+ statuses (RUNNING, STOPPED, CRASHED, NOT_COMMUNICATING, etc.) | Visibility gap detection |
| Collector ID | ✅ | `ELALogCollectors.COLLECTOR_ID` | DB query | Links device to collector |
| Last Sync | ✅ | Sync timestamp from `L3CSyncServlet` | Derived from last successful sync | Staleness indicator |

**Implementation**: Query `ELALogCollectors` table → resolve `STATUS` via `LCStatus` enum → display status badge

**Why SOC needs this**: A disconnected/crashed agent = blind spot. SOC must know if telemetry from this device is trustworthy and current.

#### 6.2.2 GPO Applied to Device
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| GPO Name | ✅ | `APFDiscADGPODetails.DISPLAY_NAME` | Join: Computer → OU → `GP_LINK` → GPO table | Security policy enforcement |
| GPO Flags | ✅ | `APFDiscADGPODetails.GPO_FLAGS` | Enabled/Disabled/User-disabled/Computer-disabled | Enforcement status |
| Created / Changed | ✅ | `APFDiscADGPODetails.WHEN_CREATED` / `WHEN_CHANGED` | Raw DB | Policy freshness |
| Computer Extensions | ✅ | `APFDiscADGPODetails.GPO_COMP_EXTENSIONS` | Raw DB | Applied policy types |

**Implementation**: 1) Find device OU from `APFDiscADComputerDetails.PARENT` 2) Read `GP_LINK` from `APFDiscADOrganizationalUnitDetails` for OU chain 3) Resolve GPO DNs to `APFDiscADGPODetails`

**Why SOC needs this**: GPOs enforce security — shows if password policies, audit policies, AppLocker, or firewall rules are applied.

#### 6.2.3 Security Event Summary (24h Counters)

Grouped by risk relevance. Event IDs shown as secondary detail per row.

**Needs Review** (any count > 0 is actionable):
| Field | Event ID | Status | Source | How to Get | SOC Value |
|-------|----------|--------|--------|------------|-----------|
| Failed Logons | 4625 | 🔧 | ES aggregation | `EVENTID=4625 AND HOSTNAME=<device> AND TIME>now-24h` → count | Brute force indicator |
| Service Installs | 7045 | 🔧 | ES aggregation | `EVENTID=7045 AND HOSTNAME=<device>` → count | Rogue service / persistence |
| Scheduled Tasks | 4698 | 🔧 | ES aggregation | `EVENTID=4698 AND HOSTNAME=<device>` → count | Persistence mechanism |

**Normal** (volume counters for context):
| Field | Event ID | Status | Source | How to Get | SOC Value |
|-------|----------|--------|--------|------------|-----------|
| Process Creation | 4688 | 🔧 | ES aggregation | `EVENTID=4688 AND HOSTNAME=<device>` → count | Execution volume |
| Object Access | 4663 | 🔧 | ES aggregation | `EVENTID=4663 AND HOSTNAME=<device>` → count | Data access volume |
| Privilege Use | 4672 | 🔧 | ES aggregation | `EVENTID=4672 AND HOSTNAME=<device>` → count | Admin activity volume |
| Policy Changes | 4719 | 🔧 | ES aggregation | `EVENTID=4719 AND HOSTNAME=<device>` → count | Tampering indicator |

**Implementation**: Single ES multi-aggregation query with `HOSTNAME=<device> AND TIME>now-24h`, group by `EVENTID` buckets.

**Why SOC needs this**: At-a-glance security heatmap grouped by risk. "Needs Review" items (failed logons, service installs, scheduled tasks) are always worth investigating if count > 0. "Normal" items provide execution volume context.

#### 6.2.4 USB Device Events
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Device Description | ✅ | ES `DEVICEDESCRIPTION` | Windows.xml parses Events 6416/6420/6422/6423/6424 | Device identification |
| Device Class | ✅ | ES `DEVICECLASSNAME` | Windows.xml parser | USB storage vs HID vs other |
| User | ✅ | ES `USERNAME` | Who plugged in | Attribution |
| Time | ✅ | ES `TIME` | When connected | Timeline |
| File Operations | ✅ | ES `OBJECTTYPE=removable` events | USB file read/write/delete from report definitions | Data exfiltration evidence |

**ES Query**: `HOSTNAME=<device> AND EVENTID IN [6416,6420,6422,6423,6424]` + file-level: `OBJECTTYPE=removable AND HOSTNAME=<device>`

**Why SOC needs this**: USB exfiltration detection — USB on a server is almost always suspicious. File operations on removable media = data theft.

#### 6.2.5 Scheduled Task Events
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Task Name | ✅ | ES `SERVICENAME` | Windows.xml parser for 4698-4702 | Identifies persistence tasks |
| Task Content (XML) | ✅ | ES `TASKCONTENTNEW` | Full task XML with command/exec action | Reveals malicious commands |
| Operation | ✅ | ES `EVENTID` | 4698=Created, 4699=Deleted, 4700=Enabled, 4701=Disabled | Action type |
| User | ✅ | ES `USERNAME` / `SECURITYID` | Who created/modified the task | Attribution |

**ES Query**: `HOSTNAME=<device> AND EVENTID IN [4698,4699,4700,4701,4702]`

**Why SOC needs this**: MITRE T1053 — scheduled tasks are the #1 persistence mechanism used by APTs and ransomware.

---

### 8.3 IP Entity — New Sections

#### 6.3.1 Firewall Action Summary
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Allow Count | ✅ | ES `ACTION=allow` aggregation | Fortinet/PaloAlto/CheckPoint/SonicWall — all parse `ACTION` field | Traffic volume |
| Deny Count | ✅ | ES `ACTION=deny` aggregation | Same | Block effectiveness |
| Drop Count | ✅ | ES `ACTION=drop` aggregation | PaloAlto: `drop`, `drop-all-packets`, `reset-*` | Active blocking |
| Top Ports | ✅ | ES `DEST_PORT` aggregation | Per-IP port distribution | Unusual port detection |
| Protocols | ✅ | ES `PROTOCOL_TR` aggregation | TCP/UDP/ICMP breakdown | Protocol anomaly |

**ES Query**: `(SOURCE_IP=<ip> OR DEST_IP=<ip>) AND HOSTTYPE IN [fortinet,paloalto,checkpoint,sonicwall,sophos]` → aggregate by `ACTION`

**Why SOC needs this**: Shows if an IP is being actively blocked or still allowed — critical for containment verification.

#### 6.3.2 DNS Query History
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Domain Queried | ✅ | ES `DNS_QUERY` / `QueryName` | Fortinet DNS + Windows-DNS-Server + Sysmon Event 22 | C2 domain discovery |
| Record Type | ✅ | ES `DNS_RECORD_TYPE` | Lookup table in Eventlog-Lookup.xml (A/AAAA/MX/CNAME) | Attack technique id |
| Resolution | ✅ | ES `QueryResults` / `RESOLVED_IP` | Sysmon Event 22 / DNS server logs | IP-to-domain mapping |
| Source Process | ✅ | ES `IMAGE` (Sysmon 22) | Process that made the DNS query | Process attribution |

**ES Query**: `(DNS_QUERY IS NOT NULL AND (SOURCE_IP=<ip> OR DEST_IP=<ip>)) OR (EVENTID=22 AND QueryResults CONTAINS <ip>)`

**Why SOC needs this**: Connect IPs to domains — reveals C2 domains, DGA patterns, DNS tunneling.

#### 6.3.3 VPN Session History
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| VPN User | ✅ | ES `VPN_USERNAME` | Fortinet VPN + PaloAlto GlobalProtect + Cisco AnyConnect | Session owner |
| VPN Name | ✅ | ES `VPN_NAME` | Tunnel/portal name | Tunnel identification |
| Action | ✅ | ES `ACTION` (tunnel-up/tunnel-down) | Fortinet-Reports.xml filter | Session start/end |
| Remote IP | ✅ | ES `REMOTE_IP` | Source IP of VPN connection | GeoIP correlation |
| Assigned IP | ✅ | ES `PRIVATE_IP` | Tunnel IP assigned to client | Internal mapping |
| Duration | ✅ | ES `DURATION` | Session length | Anomaly detection |
| Bytes Sent/Received | ✅ | ES `SENT_BYTES` / `RECEIVED_BYTES` | Data transferred | Exfil volume |

**ES Query**: `(REMOTE_IP=<ip> OR PRIVATE_IP=<ip> OR SOURCE_IP=<ip>) AND (VPN_NAME IS NOT NULL OR ACTION IN ['tunnel-up','tunnel-down'])`

**Why SOC needs this**: VPN sessions show if attacker accessed network remotely; data volume reveals exfiltration.

#### 6.3.4 IDS/IPS Alerts
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Signature Name | ✅ | ES `IDS_NAME` | Fortinet/PaloAlto/FirePower — all parse IDS fields | Attack identification |
| Threat ID | ✅ | ES `THREAT_ID` | PaloAlto unique threat IDs | Signature lookup |
| Malware Type | ✅ | ES `MALWARETYPE` | PaloAlto classification | Malware family |
| Severity | ✅ | ES `SEVERITYLEVEL` | IDS severity rating | Prioritization |
| Action Taken | ✅ | ES `ACTION` | allow/deny/drop/alert/reset | Was it blocked? |

**ES Query**: `(SOURCE_IP=<ip> OR DEST_IP=<ip>) AND IDS_NAME IS NOT NULL` → aggregate by `IDS_NAME`, `SEVERITYLEVEL`

**Why SOC needs this**: IDS/IPS hits directly indicate exploit attempts, malware delivery, or C2 communication from this IP.

---

### 8.4 SERVICE Entity — New Sections

#### 6.4.1 OAuth App Consent Grants
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Operation | ✅ | ES `OPERATION` | `Consent to application`, `Add delegated permission grant`, `Remove delegated permission grant` | Consent graph |
| App Name | ✅ | ES `TARGET` / `TARGET_NAME` | Entra PredefinedReports: `ENTRA_RECENTLY_GRANTED_CONSENT_TO_APPLICATION` | Identifies suspicious apps |
| Consenting User | ✅ | ES `CALLER` | Who approved the consent | Attribution |
| Source IP | ✅ | ES `IPADDRESS` | Where consent was granted from | Location verification |

**ES Query**: `HOSTTYPE=azure_active_directory AND OPERATION IN ['consent to application','add delegated permission grant'] AND (CALLER=<user> OR TARGET=<app_name>)`

**Why SOC needs this**: Illicit consent grants are the primary OAuth phishing vector — an attacker tricks a user into granting permissions to a malicious app.

#### 6.4.2 Admin Activity on Service
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Exchange Admin Ops | 🟡 | ES `WORKLOAD_S=ExchangeOnline AND RECORD_TYPE_L=1` | set-mailbox, add-mailboxpermission, etc. | Mailbox privilege changes |
| SharePoint Admin Ops | ✅ | ES SharePoint admin events | `sitecollectionadminadded`, `sitecollectionadminremoved` | Site takeover detection |
| Azure AD Admin Ops | ✅ | ES Entra directory audit | `CATEGORY=RoleManagement` | Identity admin changes |
| Teams Admin Ops | ✅ | ES Teams admin events | `teamsadminaction`, `teamstenantsettingchanged` | Policy changes |

**ES Query**: Per-workload: `WORKLOAD_S=<service_workload> AND RECORD_TYPE_L IN [1,8]`

**Why SOC needs this**: Admin-level changes (mailbox delegation, site admin modifications) are high-impact actions attackers use for persistence.

---

### 8.5 PROCESS Entity — New Sections

#### 6.5.1 DLL/Module Loads (Sysmon Event 7)
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| DLL Path | ✅ | ES `IMAGE_LOADED` | Sysmon.xml Event 7 parser | DLL sideloading detection |
| Signed | ✅ | ES `SIGNED` | Boolean from Sysmon | Unsigned = suspicious |
| Signature Status | ✅ | ES `SIGNATURE_STATUS` | Valid/Invalid/Expired | Tampered binaries |
| Hash | ✅ | ES `HASHES` | MD5/SHA1/SHA256 from Sysmon | VirusTotal lookup |
| Company / Product | ✅ | ES `COMPANY` / `PRODUCT` | PE metadata from Sysmon | Legitimacy check |

**ES Query**: `EVENTID=7 AND HOSTTYPE=sysmon AND (IMAGE=<process_path> OR PROCESSGUID=<guid>)`

**Why SOC needs this**: MITRE T1574 (DLL Sideloading/Injection) — unsigned or anomalous DLL loads indicate process hijacking.

#### 6.5.2 DNS Queries by Process (Sysmon Event 22)
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Domain Queried | ✅ | ES `QUERY_NAME` | Sysmon.xml Event 22 parser | C2 domain identification |
| Query Results | ✅ | ES `QUERY_RESULTS` | Resolved IPs | IP correlation |
| Query Status | ✅ | ES `QUERY_STATUS` | Success/Failure | DNS sinkhole detection |
| Process | ✅ | ES `IMAGE` | Process that made the query | Attribution |

**ES Query**: `EVENTID=22 AND HOSTTYPE=sysmon AND IMAGE=<process_path>`

**Why SOC needs this**: Directly shows which domains a suspicious process contacted — reveals C2, DGA, and exfil endpoints by process.

#### 6.5.3 Named Pipe Events (Sysmon Event 17/18)
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| Pipe Name | ✅ | ES `PIPE_NAME` | Sysmon.xml Event 17/18 parser | C2 channel detection |
| Event Type | ✅ | ES `EVENT_TYPE` | CreatePipe / ConnectPipe | Lateral movement |
| Process | ✅ | ES `IMAGE` | Process using the pipe | Attribution |

**ES Query**: `EVENTID IN [17,18] AND HOSTTYPE=sysmon AND IMAGE=<process_path>`

**Why SOC needs this**: Named pipes are used by Cobalt Strike, PsExec, and Mimikatz for IPC/lateral movement.

#### 6.5.4 WMI Persistence Events (Sysmon Event 19/20/21)
| Field | Status | Source | How to Get | SOC Value |
|-------|--------|--------|------------|-----------|
| WMI Name | ✅ | ES `WMI_NAME` | Sysmon.xml Event 19/20/21 parser | Persistence identification |
| WMI Query | ✅ | ES `WMI_QUERY` | EventFilter trigger condition | Trigger reveal |
| Destination | ✅ | ES `DESTINATION` | EventConsumer command/script | Payload detection |
| Operation | ✅ | ES `OPERATION` | Created/Deleted/Modified | Change tracking |

**ES Query**: `EVENTID IN [19,20,21] AND HOSTTYPE=sysmon AND HOSTNAME=<device>`

**Why SOC needs this**: MITRE T1546.003 — WMI subscriptions survive reboots, execute on login/boot, and are missed by most analysts.

---

### 8.6 Summary — New Enrichment Additions

| # | Entity | Section | Status | Priority | MITRE |
|---|--------|---------|--------|----------|-------|
| 1 | User | Account Lockout History | ✅ | High | T1110 (Brute Force) |
| 2 | User | Password Change/Reset History | ✅ | High | T1098 (Account Manipulation) |
| 3 | User | Group Membership Changes | ✅ | Critical | T1078/T1098 |
| 4 | User | Mailbox Forwarding Rules | ✅ | Critical | T1114.003 (Email Forwarding Rule) |
| 5 | User | Recent Application Access | ✅ | Medium | T1550 |
| 6 | User | Privileged Role Assignments | ✅ | Critical | T1098.003 |
| 7 | Device | Agent Status & Health | ✅ | High | — (Visibility Gap) |
| 8 | Device | GPO Applied | ✅ | Medium | T1484 |
| 9 | Device | Security Event Summary (24h) | 🔧 | High | — (Posture Assessment) |
| 10 | Device | USB Device Events | ✅ | High | T1052/T1091 |
| 11 | Device | Scheduled Task Events | ✅ | Critical | T1053 |
| 12 | IP | Firewall Action Summary | ✅ | High | — (Containment Verification) |
| 13 | IP | DNS Query History | ✅ | High | T1071.004 (DNS C2) |
| 14 | IP | VPN Session History | ✅ | High | T1133 |
| 15 | IP | IDS/IPS Alerts | ✅ | Critical | — (Attack Detection) |
| 16 | Service | OAuth App Consent Grants | ✅ | Critical | T1550.001 |
| 17 | Service | Admin Activity | 🟡 | Medium | T1098 |
| 18 | Process | DLL/Module Loads | ✅ | High | T1574 |
| 19 | Process | DNS Queries by Process | ✅ | High | T1071 |
| 20 | Process | Named Pipe Events | ✅ | High | T1570/T1021 |
| 21 | Process | WMI Persistence Events | ✅ | Critical | T1546.003 |

**Total: 21 new enrichments — 18 ✅, 2 🟡, 1 🔧 — all implemented in prototype**

---

## 9. ALERT Entity (`alert-impossible-travel` and 13 other alert nodes)

> **Added 06 May 2026**: Documents the alert-as-entity slider that opens when an alert node on the attack graph (or the originating alert chip) is clicked. All 14 alert IDs in `ENTITIES` (alert-impossible-travel, alert-arp-spoofing-1/2, alert-oauth-token, alert-app-consent, alert-enc-powershell, alert-sam-access, alert-c2-conn, alert-sus-service, alert-tor-conn, alert-data-exfil, alert-bulk-download, alert-sensitive-access, alert-admin-offhours) follow the same section schema.

### 9.1 Alert Details
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Alert Name | ✅ | `ITSAlertProfileConfigurations.DISPLAY_NAME` | DB lookup by alert profile id |
| Alert Type | ✅ | `ITSAlertProfileConfigurations.ALERT_TYPE` | Correlation / Anomaly (UEBA) / Threat Intel / Rule |
| Severity | ✅ | `ITSAlertProfileConfigurations.SEVERITY` | Critical / High / Medium / Low |
| Status | ✅ | `ITSAlertHistory.STATUS` | Open / Acknowledged / Resolved / Closed |
| First/Last Seen | ✅ | `ITSAlertHistory.FIRST_OCCURRED`, `LAST_OCCURRED` | Raw timestamps |
| MITRE Tactic / Technique | 🟡 | `ITSDetectionRuleVsMitre` | Only RULE-type alerts have MITRE mapping; correlation/anomaly alerts may be empty |
| Source Device / IP | ✅ | Underlying log event fields | Resolved from triggering events |

### 9.2 Trigger Conditions
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Rule Logic Summary | ✅ | `ITSAlertProfileConfigurations.RULE_DEFINITION` | Stored rule expression / criteria |
| Threshold / Window | ✅ | Rule definition fields | e.g., "5 failures in 10 min" |
| Matched Field Values | ✅ | Triggering event JSON | Raw event payload at alert generation time |

### 9.3 Affected Entities
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Entity ID, Type, Display Name | ✅ | Graph node / `ENTITY_DISPLAY` | Same node lookup as edge slider |
| Role in Alert (source / target / correlated) | ✅ | Edge data + alert metadata | Derived at render time |
| **Clickable** | ✅ | `openEntitySlider(id)` | Click any affected entity to pivot |

### 9.4 Correlated Alerts
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Related Alert IDs | ✅ | `ITSAlertCorrelationGroup` | Alerts grouped by correlation rule / shared entity |
| Time Delta | ✅ | `ITSAlertHistory.LAST_OCCURRED` diff | Computed |
| Severity / Status of related | ✅ | Same as 9.1 fields | Per-alert lookup |

### 9.5 Remediation & Playbooks
| Field | Status | Source | How to Get |
|-------|--------|--------|------------|
| Verdict (Malicious / Suspicious / Benign / Resolved) | ✅ | `ITSAlertHistory.VERDICT` | Analyst classification |
| Recommendations | ✅ | Static catalog keyed by alert type | `ALERT_REMEDIATION_CATALOG[alertType]` |
| Playbooks (Run buttons) | ✅ | Static catalog | Same playbook engine as user/device entities |

> **Tab grouping** (per `tabConfig.alert` in `index.html`): `overview` = [alertDetails, triggerConditions, details], `scope` = [affectedEntities, correlatedAlerts, processes], `response` = [serviceTriggered, recentAlerts]. Tabs auto-hide if their sections are empty for that alert.

---

## 10. Implementation Changelog

| Date | Change | Entities Affected |
|------|--------|-------------------|
| 24 Apr 2026 | Removed unachievable sections (vulnerabilities, misconfigurations, installedSoftware, cloudAsset, CIS benchmarks, serviceDependencies, relatedCampaigns, relatedTokens) | All |
| 24 Apr 2026 | Added Section 6 new enrichments to mapping doc | — (doc only) |
| 24 Apr 2026 | Implemented 6 new user sections in `user-m-henderson` | User |
| 24 Apr 2026 | Implemented 5 new device sections in `dev-ws045` | Device |
| 24 Apr 2026 | Implemented 3 new IP sections in `ip-tor`, 1 in `ip-internal` | IP |
| 24 Apr 2026 | Implemented 2 new service sections in `svc-azure-ad`, 1 in `svc-winupdatesvc` | Service |
| 24 Apr 2026 | Implemented 3 new process sections in `proc-powershell` | Process |
| 24 Apr 2026 | Updated tabConfig — added "Changes" tab (user), "Persistence" tab (device), expanded all entity tabs | All |
| 24 Apr 2026 | Updated `buildQuickCardRows()` summary rows for all entity types | All |
| 24 Apr 2026 | Implemented 6 new user sections in `user-admin` (admin-context data) | User |
| 25 Apr 2026 | **v3 field-level validation pass** — audited every field against backend code/parsers | All |
| 25 Apr 2026 | Removed `investigationStatus` from all entities — entities are not incidents; `ADSIncidentStatus` has only 3 manual statuses | All |
| 25 Apr 2026 | Removed `Watch List` from UEBA Risk Profile — manual UEBA toggle, not investigation-relevant | User |
| 25 Apr 2026 | Removed `Peer Group`, `Deviation`, `Risk Trend` from UEBA Risk Profile — no time-series history, peer avg not stored | User |
| 25 Apr 2026 | Removed `MFA Challenges`, `Unique Geolocations` from Login Statistics — arbitrary mixing of on-prem/cloud; city GeoIP unreliable | User |
| 25 Apr 2026 | Updated `Unique Source IPs` to show actual IP addresses alongside count | User |
| 25 Apr 2026 | Removed `ASN`, `ISP` from IP Details — no parser extracts these fields | IP |
| 25 Apr 2026 | Simplified Geo Location to country-only (`GEO_COUNTRY`) — city/lat-lon unreliable | IP |
| 25 Apr 2026 | Renamed `Total Connections` → `Firewall Events (24h)` with allow/deny breakdown | IP |
| 25 Apr 2026 | Removed `City`, `Latitude/Longitude`, `Timezone` from Geo Context — unreliable precision | IP |
| 25 Apr 2026 | Removed `Subnet`, `VLAN`, `Firewall Zone` from internal IP Details — no mapping tables | IP |
| 25 Apr 2026 | Removed ip-internal geoContext fields: Country, City, Building, Timezone, Corporate Location | IP |
| 25 Apr 2026 | Removed `AlienVault OTX` from Threat Intel — bulk STIX feed only, no live API query | IP |
| 25 Apr 2026 | Removed VT `Community Score` and `Tags` — `VirusTotalActionHandler` only returns detection ratio | IP |
| 25 Apr 2026 | Added `ADSThreatAnalyticsFeeds` as second TI source in prototype | IP |
| 25 Apr 2026 | Cleaned Connection History — removed Azure AD sign-in entry (not a network connection); added Dest IP, Action, Device fields | IP |
| 25 Apr 2026 | Removed all `Note` fields from account change sections (accountLockouts, passwordHistory, groupMembershipChanges, mailboxForwarding) — fabricated analyst commentary | User |
| 25 Apr 2026 | Removed editorial annotations: `⚠`, `(Tor proxy)`, `(compromised session)` from data fields | User |
| 25 Apr 2026 | Added `emptyText` renderer support for sections with no data; used in `privilegedRoleChanges` | User |
| 26 Apr 2026 | Renamed `Blocklist Status` → `Threat Feed Match` — product checks internal feed stores (Webroot, STIX/TAXII, file import), not external blocklists. Label was misleading | IP |
| 26 Apr 2026 | Downgraded `Threat Feeds Flagged` and `Threat Feed Match` from ✅ to 🟡 — ingestion uses `findAny()` (records only first match). Count requires new query-time `countFeedsForIP()` method. Show binary until built | IP |
| 27 Apr 2026 | Restructured Security Event Summary from flat KV to risk-grouped format: "Needs Review" (4625, 7045, 4698) and "Normal" (4688, 4663, 4672, 4719). Event IDs shown as subtle secondary text. Removed editorial annotations (`⚠`, `"unsigned"`, `"from unknown sources"`, `"during attack window"`) | Device |
| 27 Apr 2026 | Added urgency severity chips to playbooks: "Run Immediate" (red — containment: block/kill/isolate/revoke), "High Priority" (orange — investigation/hunt/analysis), "Standard" (green — hardening/monitoring). Applied to all 37 playbook entries | All |
| 27 Apr 2026 | Reclassified OAuth Tokens from `process` to `service` entity (`proc-oauth` → `svc-oauth`). Updated display color, modal title, graph filter counts. Removed empty Processes filter from dropdown | Service |
| 27 Apr 2026 | Fixed entity filter connection matching: replaced coordinate proximity logic (`< 30px` threshold) with `data-source`/`data-target` attribute lookup. Users filter now correctly shows Azure AD, ip-tor, SharePoint as connected neighbors. Edge labels also light up for connected edges | Graph |
| 29 Apr 2026 | **Design note — Response actions must be alert-contextual**: Right-click actions on graph entities (Revoke Tokens, Block IP, Isolate Host, etc.) are currently based on entity type alone. In the real product, actions must be dynamically surfaced based on the **alert type, MITRE techniques, and the entity's role in the attack chain**. Example: "Revoke Tokens" is relevant for OAuth abuse alerts but not for a brute-force or malware alert. The action set should be determined by the investigation context, not hardcoded per entity type | All |
| 05 May 2026 | **V4 — Edge Relation Slider**: Added edge click behavior — clicking edge icons on graph opens right-side slider with enriched connection details | Graph/Edge |
| 05 May 2026 | Added MITRE ATT&CK mapping section to edge slider — tactic/technique chips from `ITSDetectionRuleVsMitre` | Edge |
| 05 May 2026 | Added Detection Rule card to edge slider — rule name, type badge, rule ID | Edge |
| 05 May 2026 | Added Connection Properties section — event count, risk score with bar, data volume, first/last seen | Edge |
| 05 May 2026 | Added Event Distribution chart — 12-bucket sparkline with `#FFC600` bars (Graph.svg style), exact clock time labels, average line, peak marker, hover tooltips | Edge |
| 05 May 2026 | Added Behavioral Baseline card — dual progress bars (expected vs actual), severity classification, pulsing deviation badge | Edge |
| 05 May 2026 | Added Threat Intelligence section — vendor badge, reputation score, VirusTotal detection ratio | Edge |
| 05 May 2026 | Added Geo Context section — country flag, city, IP address | Edge |
| 05 May 2026 | Added Evidence panel — severity bar, summary, key findings chips, confidence meter with progress bar, source/count badges | Edge |
| 05 May 2026 | Converted evidence data from flat strings to structured objects: `{ summary, findings[], confidence, rawLog }` for all 15 edges | Edge |
| 05 May 2026 | Made flow diagram entity nodes clickable — click source/target opens entity detail slider | Edge |
| 05 May 2026 | Removed ~~View in Log Search~~ button — prototype scope | Edge |
| 05 May 2026 | Removed ~~Sample Log Entry~~ section — not useful in prototype | Edge |
| 05 May 2026 | Removed ~~Connected Entities~~ section — redundant with clickable flow diagram at top | Edge |
| 05 May 2026 | Updated entity_data_mapping.md — added Section 8 (Edge Relation Slider) with 12 subsections | Doc |
| 06 May 2026 | Doc drift fix: added Section 9 (ALERT Entity) covering the 14 alert nodes (alertDetails, triggerConditions, affectedEntities, correlatedAlerts, remediationGuide); previously undocumented | Doc/Alert |
| 06 May 2026 | Doc drift fix: updated Section 4 header to include `svc-oauth` and added reclassification note above Section 5 (token sections 5.9–5.12 now describe the OAuth service, not a process) | Doc/Service |
| 06 May 2026 | Renumbered Implementation Changelog from Section 9 → Section 10 to make room for ALERT Entity section | Doc |
