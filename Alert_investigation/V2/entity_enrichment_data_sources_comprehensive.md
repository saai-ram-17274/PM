# Comprehensive Entity Enrichment Data Source Inventory

> **Generated**: Research across `log360_cloud`, `log360cloudcommon`, `itsf`, `adsf`, `adsm`, `app-fw`, `log360`, `ADSF-DD-DML`  
> **Purpose**: Complete inventory of all data sources, tables, log types, ES fields, and APIs available for SOC analyst entity investigation enrichment.

---

## Table of Contents
1. [USER Entity](#1-user-entity)
2. [DEVICE Entity](#2-device-entity)
3. [IP Entity](#3-ip-entity)
4. [SERVICE Entity](#4-service-entity)
5. [PROCESS Entity](#5-process-entity)
6. [Cross-Cutting Data Sources](#6-cross-cutting-data-sources)
7. [No-Data Gaps Summary](#7-no-data-gaps-summary)

---

## Legend

| Symbol | Meaning |
|--------|---------|
| **DB** | Relational database table (Mickey/PostgreSQL) — queryable via SelectQuery |
| **ES** | Elasticsearch / ZLogs — queryable via ES aggregation or search API |
| **Redis** | In-memory cache — queryable via Redis key prefix |
| **API** | External API call required (VirusTotal, M365 Graph, etc.) |
| **Config** | Static configuration file (XML/JSON) |

---

## 1. USER Entity

### 1.1 Identity Attributes (DB — APF Sync)

| Data Point | Table | Key Columns | Source Repo | How Populated |
|------------|-------|-------------|-------------|---------------|
| **AD User Profile** | `APFDiscADUserDetails` | `DISPLAY_NAME`, `SAM_ACCOUNT_NAME`, `LOGON_NAME` (UPN), `EMAIL_ADDRESS`, `TITLE`, `DEPARTMENT`, `MANAGER`, `OU_NAME`, `WHEN_CREATED`, `ACCOUNT_STATUS` | app-fw, ADSF-DD-DML | LDAP sync via APF discovery |
| **AD Logon Info** | `APFDiscADUserDetails` | `LAST_LOGON_TIME`, `LOGON_TO` (workstation), `PRIMARY_GROUP_ID`, `LOGON_COUNT` | app-fw | Multi-DC MAX via `APFMultiDCAttrConfig` |
| **Password/Lockout** | `APFDiscADUserDetails` | `PASSWORD_LAST_SET`, `LOCK_OUT_TIME` | app-fw | AD sync, UAC flags |
| **Azure AD User** | `APFDiscAADUserDetails` | `USER_PRINCIPAL_NAME`, `LAST_PWD_CHANGE_TIME`, `DAYS_SINCE_PASSWORD_CHANGE`, `SHARING_POLICY` | app-fw | MS Graph API sync |
| **JumpCloud User** | `APFDiscJumpCloudUserDetails` | `ACCOUNT_LOCKED`, `ACCOUNT_LOCKED_DATE`, `SUSPENDED` | app-fw | JumpCloud API sync |
| **Salesforce User** | `APFDiscSalesforceUserDetails` | `LAST_PASSWORD_CHANGE_DATE`, `LAST_LOGIN_DATE` | app-fw | Salesforce API sync |
| **ServiceNow User** | `APFDiscServiceNowUserDetails` | `ENABLE_MULTIFACTOR_AUTHN` | app-fw | ServiceNow API sync |
| **GSuite User** | `APFDiscGSuiteUserDetails` | Standard identity fields | app-fw | Google Admin API sync |
| **Zoho User** | `APFDiscZohoUserDetails` | `IS_MFA_ENABLED` | app-fw | Zoho Admin API sync |
| **Slack User** | `APFDiscSlackUserDetails` | Standard identity fields | app-fw | Slack API sync |
| **Zendesk User** | `APFDiscZendeskUserDetails` | Standard identity fields | app-fw | Zendesk API sync |
| **Freshdesk User** | `APFDiscFreshdeskUserDetails` | Standard identity fields | app-fw | Freshdesk API sync |
| **BambooHR User** | `APFDiscBambooHRUserDetails` | Standard identity fields | app-fw | BambooHR API sync |

### 1.2 MFA Status (DB — APF Sync)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| JumpCloud MFA | `APFDiscJumpCloudUserDetails` | `MFA_EXCLUDED`, `MFA_CONFIGURED`, `MFA_TOTP_STATUS`, `MFA_WEB_AUTH_STATUS`, `MFA_PUSH_STATUS`, `MFA_OVERALL_STATUS`, `ENABLE_USER_PORTAL_MFA` | app-fw |
| Zoho MFA | `APFDiscZohoUserDetails` | `IS_MFA_ENABLED` | app-fw |
| ServiceNow MFA | `APFDiscServiceNowUserDetails` | `ENABLE_MULTIFACTOR_AUTHN` | app-fw |
| Azure MFA (sign-in) | ES `ENTRA_EVENT_SIGNINS` | `AUTH_TYPE`, `MFA_DETAIL`, `amr` field | itsf (log parser) |
| Azure MFA license | `LicenseSKUDetails.json` | License includes MFA SKUs | Config |

### 1.3 Group Membership (DB — APF Sync)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| AD Groups | `APFDiscADGroupMemberDetails` | Group→User mapping | app-fw |
| Azure AD Groups | `APFDiscAADGroupMemberDetails` | Group→User mapping | app-fw |
| Azure Groups | `APFDiscAzureGroupMemberDetails` | Group→User mapping | app-fw |
| GSuite Groups | `APFDiscGSuiteGroupMemberDetails` | Group→User mapping | app-fw |
| Zoho Groups | `APFDiscZohoGroupMemberDetails` | Group→User mapping | app-fw |
| JumpCloud Groups | `APFDiscJumpCloudGroupMemberDetails` | Group→User mapping | app-fw |
| Slack Groups | `APFDiscSlackGroupMemberDetails` | Group→User mapping | app-fw |
| Freshdesk Groups | `APFDiscFreshdeskGroupMemberDetails` | Group→User mapping | app-fw |
| Zendesk Groups | `APFDiscZendeskGroupMemberDetails` | Group→User mapping | app-fw |
| Salesforce Groups | `APFDiscSalesforceGroupMemberDetails` | Group→User mapping | app-fw |
| ServiceNow Groups | `APFDiscServiceNowGroupMemberDetails` | Group→User mapping | app-fw |
| Group Details | `APFDiscADGroupDetails` | `GROUP_MEMBERSHIP_TYPE`, `MEMBER_COUNT` | app-fw |
| AAD Group Details | `APFDiscAADGroupDetails` | `GROUP_MEMBERSHIP_TYPE`, `ROLE_ASSIGNABLE` | app-fw |
| Membership Watchlist | `APFMembershipWatchList` | Watched group/OU membership changes | app-fw |

### 1.4 Privileged Role Analysis (DB + Derived)

| Data Point | Source | How to Get |
|------------|--------|------------|
| Admin user detection | SID analysis (`-500` = built-in admin) | `DefaultAdminUserRuleAnalyzer` in adsf compliance |
| Privileged group membership | AD group SIDs: Domain Admins, Enterprise Admins, Schema Admins | APF group sync + SID check |
| Azure IS_PRIVILEGED | `APFDiscAADGroupDetails.IS_PRIVILEGED` | MS Graph API sync |
| Stale account | Computed from `LAST_LOGON_TIME` | `InactiveUserBasedADRuleAnalyzer` in adsf compliance |
| Service account | UAC flags analysis | Derived from `APFDiscADUserDetails` |
| Azure Role Assignments | `APFDiscAADRoleAssignmentPolicyDetails` | MS Graph API sync |
| GSuite Role Assignments | `APFDiscGWRoleAssignmentDetails` | Google Admin API sync |
| GSuite Privileges | `APFDiscGWPrivilegeDetails` | Google Admin API sync |

### 1.5 Logon Activity (ES)

| Data Point | ES Field(s) | Windows Event ID | Source |
|------------|-------------|------------------|--------|
| Successful Logon | `EVENTID=4624` | 4624 | Windows Security log |
| Failed Logon | `EVENTID=4625` | 4625 | Windows Security log |
| Logon Type | `LOGONTYPE` | 4624/4625 | 2=Interactive, 3=Network, 10=RDP |
| Source IP | `REMOTEIP` | 4624/4625 | Raw field |
| Target Host | `HOSTNAME` | 4624/4625 | Raw field |
| Account Lockout | `EVENTID=4740` | 4740 | Windows Security log |
| Azure Sign-In | `ENTRA_EVENT_SIGNINS` format | — | M365 Entra ID via Graph API |
| MFA Challenges | M365 sign-in log `amr`, `mfaDetail` | — | `azure_active_directory` log format |
| Off-Hours Logins | `_zl_timestamp` + `UserWorkHoursUtils.isOffHours()` | — | log360cloudcommon |
| Unique Source IPs | `distinct_count(REMOTEIP)` | 4624 | ES aggregation |
| Unique Hosts | `distinct_count(HOSTNAME)` | 4624 | ES aggregation |
| Unique Geolocations | GeoIP enrichment on `REMOTEIP` | — | MaxMind DB |

### 1.6 Mailbox & Email (DB + ES)

| Data Point | Source | Key Fields |
|------------|--------|------------|
| Mailbox Forwarding | `APFDiscAADUserDetails` (mgmtFw dataTables) | `MAILBOX_FORWARD_TO` |
| Inbox Rules | M365 audit log | `OPERATION=New-InboxRule` in ES |
| Email Delegation | `APFDiscAADUserDetails.SHARING_POLICY` | APF sync |
| Exchange Role Assignment | `ROLE_ASSIGNMENT_POLICY` column on user tables | APF sync |

### 1.7 Cloud Identities (DB + ES)

| Data Point | Source | Key Fields |
|------------|--------|------------|
| Azure AD identity | `APFDiscAADUserDetails.USER_PRINCIPAL_NAME` | MS Graph sync |
| Azure Roles | Azure role assignment tables | APF sync |
| Conditional Access (status) | M365 sign-in log `conditionalAccessStatus` | ES — sign-in events only |
| M365 License | `APFDiscAADUserDetails` + `LicenseSKUDetails.json` | License mapping |

### 1.8 Compliance Impact (DB)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| Policy Framework | `CompliancePolicy` | `IS_SECURITY_POSTURE`, `IS_PREDEFINED`, `IS_ENABLED` | adsf |
| Policy Acts/Rules | `CompliancePolicyAct` | PCI-DSS, HIPAA, SOX, GDPR, NIST, ISO27001, FISMA | adsf |
| Rule Results | `ComplianceRuleResultList` | Pass/Fail/High Risk/Manual | adsf |
| GPO-based Compliance | `BasicGPOBasedRuleAnalyzer` | Analyzes GPO settings against compliance rules | adsf |
| User/Group Compliance | `BasicUserGroupRuleAnalyzer` | Analyzes user/group configs against compliance rules | adsf |

### 1.9 DLP Incidents (ES)

| Data Point | ES Source | Key Fields |
|------------|-----------|------------|
| DLP Policy Fire | M365 audit unified log | `OPERATION` including DLP actions |
| File Access | M365 SharePoint audit | `SourceFileName`, `OBJECTNAME`, `SiteURL` |
| Sensitivity Labels | `SP_SENSITIVITY_LABEL_ACTIVITY` | Label change audit events |
| DLP Handler | `DLPHandler` (117 rules) | itsf rule engine |

---

## 2. DEVICE Entity

### 2.1 Device Attributes (DB — APF Sync)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| AD Computer | `APFDiscADComputerDetails` | `COMPUTER_NAME`, `OPERATING_SYSTEM`, `VERSION`, `DOMAIN_NAME`, `OU_NAME`, `WHEN_CREATED` | app-fw |
| Last Logon | `APFDiscADComputerDetails` | `LAST_LOGON_TIME` | app-fw |
| BitLocker | `APFDiscADComputerDetails` | `BITLOCKER_STATUS` | app-fw |
| Assigned User | ES latest logon event for host | `HOSTNAME=X` → latest user | ES aggregation |
| IP Address | DHCP logs or ES logon events | `REMOTEIP` from logon events | ES / DHCP |
| MAC Address | DHCP log parsing | `DHCP_MAC` | ES (if collected) |

### 2.2 GPO Configuration (DB — APF Sync)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| GPO Details | `APFDiscADGPODetails` | `OBJECT_GUID`, `DISPLAY_NAME`, `WHEN_CREATED`, `WHEN_CHANGED`, `GPO_USER_EXTENSIONS`, `GPO_COMP_EXTENSIONS`, `COMPUTER_VERSION`, `USER_VERSION`, `GPO_DN`, `GPO_FLAGS` | app-fw (XML: `APFADGPOAttributes.xml`) |
| OU GPO Links | `APFADOrganizationalUnitDetails` | `GP_OPTIONS`, `GP_LINK` | app-fw |

### 2.3 Installed Windows Services (DB — Agent Collection)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| Service List | `ITSWinServiceList` | `SYSTEM_NAME`, `START_NAME`, `NAME`, `DISPLAY_NAME`, `STATE`, `PATH_NAME`, `START_MODE` | itsf |
| Request History | `ITSWinServiceListReqHistory` | `REQUEST_ID`, `USER_ID`, `DOMAIN_ID`, `REQUEST_TIME`, `RESPONSE_TIME`, `STATUS` | itsf |
| Error Report | `ITSWinServiceErrorReport` | `HOSTNAME`, `ERROR_MESSAGE` | itsf |
| API | `ServiceListAPI` → `ServiceListReqHandler` → `ServiceListDSHandler` | REST API to request service list from agent | itsf |

### 2.4 Agent/Log Collector Status (DB + Runtime)

| Data Point | Source | Key Values | Source Repo |
|------------|--------|------------|-------------|
| Agent Status | `LCStatus` enum | `RUNNING(0)`, `STOPPED(1)`, `CRASHED(2)`, `AGENT_NOT_COMMUNICATING(27)`, `INSTALL_SUCCESS(1000)`, `UNINSTALLED(100)`, etc. | itsf |
| Status Groups | `LCStatus.StatusGroup` | `SUCCESS`, `INSTALL_FAILED`, `OTHER_FAILURE`, `LC_STOPPED` | itsf |
| Collector Down Check | `LCStatus.isCollectorDownStatus()` | Boolean check for service list/LDAP operations | itsf |
| Agent Install/Upgrade | `AgentExecutionHandler`, `InstallationTask`, `UpgradationTask` | Execution status tracking | adsf |

### 2.5 Processes on Host (ES)

| Data Point | ES Field(s) | Event Source |
|------------|-------------|--------------|
| Process Create | `IMAGE`, `ProcessId`, `CommandLine`, `User`, `IntegrityLevel`, `UtcTime` | Sysmon Event 1 |
| Parent Process | `ParentImage`, `ParentProcessId`, `ParentCommandLine` | Sysmon Event 1 |
| Windows Process | `PROCESSNAME`, `COMMANDEXECUTED`, `PARENTPROCESSNAME`, `PARENTPROCESSID` | Windows Event 4688 |

### 2.6 Services on Host (ES)

| Data Point | ES Field(s) | Event Source |
|------------|-------------|--------------|
| New Service Install | `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`, `ServiceAccount` | Windows Event 7045 |
| Service Install (audit) | Similar fields | Windows Event 4697 |

### 2.7 Login Activity on Device (ES)

Same as User 1.5, filtered by `HOSTNAME=<device_name>`

### 2.8 Device Risk Score (DB)

| Data Point | Table | Key Columns |
|------------|-------|-------------|
| Host Risk Score | `ITSEntityRiskScoreDetails` (entity_type=2 for HOST) | `RISK_SCORE`, `MODIFIED_SCORE`, `SEVERITY_SCORE`, `DETECTION_COUNT`, `OVERALL_RISK_SCORE` |
| Risk Severity | `ITSRiskSeverityDetails` | `SEVERITY_NAME` mapped from score thresholds |

---

## 3. IP Entity

### 3.1 Threat Intelligence (DB + ES + API)

| Data Point | Source | Key Fields/Tables | Source Repo |
|------------|--------|-------------------|-------------|
| Threat Feed Enrichment | `ADSThreatAnalyticsFeeds` table | `ANALYTICS_FEED_ID`, `ANALYTICS_FEED_TYPE`, `ANALYTICS_FEED_SERVER_ID` | adsf |
| Threat Reputation | ES field `THREAT_REPUTATION` | Enriched during log ingestion by `ThreatAnalyticsIntermediateProcessor` | adsf |
| Threat Categories | ES field `THREAT_CATEGORIES` | Tor exit node, VPN, Datacenter, Malware C2, etc. | adsf |
| Threat Source | ES field `THREAT_SOURCE` | Which feed(s) flagged the IP | adsf |
| Tor Exit Node List | `ADSThreatAnalyticsFeeds` — Tor exit list | Tor feed type | adsf |
| VirusTotal Lookup | `VirusTotalActionHandler` (Vendor ID=2) | External API call for IP/URL/hash | adsf |
| TAXII/STIX Feeds | `TAXIIActionExecutor` | Integration with TAXII servers for IOC feeds | log360 |
| IP Threat Data Store | `ThreatSourceData` (in-memory + ES) | `reputation`, `categories` per IP/URL | adsf |
| IP Range Threat Data | `DataStore.putIPRangeThreatSourceData()` | Subnet/range-level threat tagging | adsf |
| URL Threat Data | `DataStore.putURLThreatSourceData()` | URL-level threat reputation | adsf |

### 3.2 GeoIP (Runtime Enrichment)

| Data Point | Source | Notes |
|------------|--------|-------|
| Country | MaxMind GeoIP DB | ✅ Always available |
| City | MaxMind GeoIP DB | Depends on DB tier |
| ASN | MaxMind GeoIP DB | Partial — depends on DB tier |
| Latitude/Longitude | MaxMind GeoIP DB | Depends on DB tier |

### 3.3 Connection History (ES)

| Data Point | ES Field(s) | Log Source |
|------------|-------------|------------|
| Firewall Connections | `SRC_IP`, `DST_IP`, `DST_PORT`, `PROTOCOL`, `BYTES_SENT`, `BYTES_RECEIVED`, `SESSION_DURATION` | Firewall vendors (see 3.7) |
| Proxy Connections | `METHOD`, `USER_AGENT`, `URL`, `RESPONSE_CODE` | Proxy/IIS logs |
| VPN Sessions | `SESSION_DURATION`, `REMOTEIP`, `USERNAME` | VPN logs |
| DNS Queries | `QUERY_NAME`, `RESOLVED_IP` | Sysmon Event 22 (DNSQuery) |
| DHCP Lease | `DHCP_MAC`, client IP | `DHCP_WINDOWS`/`DHCP_LINUX` log formats |

### 3.4 Associated Users (ES)

| Data Point | ES Query | Source |
|------------|----------|--------|
| Users from IP | Filter `REMOTEIP=<ip>` on logon events | ES 4624/4625 aggregation |
| Logon types from IP | Group by `LOGONTYPE` | ES aggregation |
| M365 sign-ins from IP | Filter source IP on Entra sign-in logs | ES |

### 3.5 Associated Devices (ES)

| Data Point | ES Query | Source |
|------------|----------|--------|
| Devices from IP | Filter by IP → get `HOSTNAME` | ES aggregation |
| MAC from IP | DHCP logs `DHCP_MAC` matching IP | ES (if DHCP collected) |

### 3.6 Traffic Summary (ES Aggregations)

| Data Point | ES Aggregation |
|------------|----------------|
| Total Flows | Count per IP from FW logs |
| Unique Destinations | Distinct count `DST_IP` or `DST_HOST` |
| Bytes Sent/Received | Sum `BYTES_SENT`/`BYTES_RECEIVED` |
| Anomalous Flows | Count of events with `THREAT_REPUTATION` flagged |
| Protocols | Distinct `PROTOCOL` values |

### 3.7 Supported Firewall/Network Vendors

| Vendor | ES HOSTTYPE | Key Fields | Repo |
|--------|-------------|------------|------|
| **Fortinet FortiGate** | `fortinet` | `APP_NAME`, `SERVICENAME` | itsf |
| **Palo Alto** | `paloalto` | `APPLICATION` | itsf |
| **Check Point** | `checkpoint` | `SERVICENAME`, `SERVICE_ID` | itsf |
| **Sophos XG** | `sophos_xg` | Standard FW fields | itsf |
| **SonicWall** | `sonicwall` | Standard FW fields | itsf |
| **WatchGuard** | `watchguard` | Standard FW fields | itsf |
| **Cisco** | Various | Standard FW fields | itsf |
| **Barracuda** | `barracuda` | Standard FW fields | itsf |

### 3.8 Playbook Remediation Actions for IP Blocking

| Action Class | Target Vendor | Source Repo |
|-------------|---------------|-------------|
| `IMPaloAltoActions` | Palo Alto firewall | adsf |
| `IMPaloAltoUpdateActions` | Palo Alto (update rules) | adsf |
| `IMFortigateActions` | Fortinet FortiGate | adsf |
| `IMCiscoActions` | Cisco ASA/FTD | adsf |
| `IMSophosXGActions` | Sophos XG | adsf |
| `IMSophosXGUpdateActions` | Sophos XG (update rules) | adsf |
| `IMBarracudaActions` | Barracuda | adsf |

---

## 4. SERVICE Entity

### 4.1 Cloud Service Configuration (DB — APF)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| OAuth Configuration | `APFOAuthProps` | OAuth provider settings | app-fw |
| OAuth Config Params | `APFOAuthConfigProps` | Per-app OAuth config | app-fw |
| OAuth Keys | `APFOAuthKeys` | Token/secret storage | app-fw |
| Cloud Source Registration | M365/AWS/GCP integration config | Tenant ID, source type | log360_cloud |

### 4.2 Azure AD / M365 Service Enrichment (DB + ES)

| Data Point | Source | Key Fields |
|------------|--------|------------|
| Azure Role Assignment Policies | `APFDiscAADRoleAssignmentPolicyDetails` | Policy definition | app-fw |
| Exchange Sharing Policies | `APFDiscAADUserDetails.SHARING_POLICY` | Per-user sharing policy | app-fw |
| Exchange Mailbox Forward | `MAILBOX_FORWARD_TO` in mgmtFw dataTables | Forwarding config | app-fw |
| M365 Sign-In Audit | `ENTRA_EVENT_SIGNINS` log format | User, IP, Location, App, MFA, Risk, Result | ES |
| M365 Unified Audit | M365 audit log events | `OPERATION`, timestamps | ES |
| License SKUs | `LicenseSKUDetails.json` | Product names, enabled features | Config |

### 4.3 Google Workspace Service Enrichment (DB)

| Data Point | Table | Key Columns |
|------------|-------|-------------|
| GSuite Role Assignments | `APFDiscGWRoleAssignmentDetails` | Role→User mapping |
| GSuite Privileges | `APFDiscGWPrivilegeDetails` | Privilege definitions |
| Admin Activity | GSuite admin audit log | ES events |

### 4.4 Windows Service Events (ES)

| Data Point | ES Field(s) | Event Source |
|------------|-------------|--------------|
| Service Install | `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`, `ServiceAccount` | Windows Event 7045 |
| Service Install (audit) | Similar fields | Windows Event 4697 |
| File Drops by Service | `TargetFilename`, `Image` | Sysmon Event 11 (FileCreate) |
| Network Connections | `DestinationIp`, `DestinationPort`, `Protocol` | Sysmon Event 3 (NetworkConnect) |

### 4.5 SharePoint/OneDrive (ES)

| Data Point | ES Source | Key Fields |
|------------|-----------|------------|
| File Access | M365 SharePoint audit | `FileDownloaded`, `FileModified`, `FileDeleted` |
| File Access Report | `SP_FILE_ACCESS_ACTIVITIES` report | `SourceFileName`, `SiteURL` |
| Sensitivity Labels | `SP_SENSITIVITY_LABEL_ACTIVITY` | Label change events |
| DLP Violations | M365 DLP audit events | DLP rule names, actions |

---

## 5. PROCESS Entity

### 5.1 Process Details (ES — Sysmon + Windows)

| Data Point | ES Field(s) | Event Source |
|------------|-------------|--------------|
| Process Name | `IMAGE` | Sysmon Event 1 |
| PID | `ProcessId` | Sysmon Event 1 |
| Parent Process | `ParentImage`, `ParentProcessId` | Sysmon Event 1 |
| Command Line | `CommandLine` | Sysmon Event 1 / Windows 4688 |
| User | `User` | Sysmon Event 1 |
| Integrity Level | `IntegrityLevel` | Sysmon Event 1 |
| Start Time | `UtcTime` | Sysmon Event 1 |
| Process Terminate | `ProcessGuid` | Sysmon Event 5 |
| Process GUID Chain | `ParentProcessGuid` → `ProcessGuid` | Sysmon Event 1 (for tree reconstruction) |

### 5.2 Script/AMSI Events (ES — PowerShell)

| Data Point | ES Field(s) | Event Source |
|------------|-------------|--------------|
| Script Block Content | Full script text | Windows Event 4104 (ScriptBlock) |
| Script Block ID | `ScriptBlockId` | Windows Event 4104 |
| AMSI Detection | `AMSI_RESULT_DETECTED` field | Windows Event 4104 |

### 5.3 Network Activity by Process (ES — Sysmon)

| Data Point | ES Field(s) | Event Source |
|------------|-------------|--------------|
| Destination IP | `DestinationIp` | Sysmon Event 3 (NetworkConnect) |
| Destination Port | `DestinationPort` | Sysmon Event 3 |
| Protocol | `Protocol` | Sysmon Event 3 |
| DNS Query | `QueryName`, `QueryResults` | Sysmon Event 22 (DNSQuery) |

### 5.4 File Operations by Process (ES — Sysmon)

| Data Point | ES Field(s) | Event Source |
|------------|-------------|--------------|
| File Create | `TargetFilename` | Sysmon Event 11 (FileCreate) |
| File Delete | `TargetFilename` | Sysmon Event 23 (FileDelete) |
| File Stream | `TargetFilename` | Sysmon Event 15 (FileCreateStreamHash) |
| Hash | File hash | Sysmon Events 11/15 |

### 5.5 Registry Modifications by Process (ES — Sysmon)

| Data Point | ES Field(s) | Event Source |
|------------|-------------|--------------|
| Registry Event (Create/Delete) | `TargetObject` | Sysmon Event 12 |
| Registry Value Set | `TargetObject`, `Details` | Sysmon Event 13 |
| Registry Rename | `TargetObject`, `NewName` | Sysmon Event 14 |

### 5.6 Child Processes (ES — Sysmon)

| Data Point | ES Query | Source |
|------------|----------|--------|
| Children of Process | Filter `ParentProcessGuid=<guid>` | Sysmon Event 1 |
| Process Tree Reconstruction | Recursive `ParentProcessGuid → ProcessGuid` joins | ES (needs app-layer reconstruction) |

### 5.7 OAuth Token / Cloud Process (ES — M365)

| Data Point | ES Source | Key Fields |
|------------|-----------|------------|
| Token Type, Grant Type | M365 audit OAuth consent events | Audit log |
| Client App | M365 audit | App name in consent event |
| Scope | M365 audit | Raw event data |
| IP at Issuance | M365 sign-in log | Source IP |
| MFA Claim | M365 sign-in `amr` field | Raw |
| Publisher Verification | M365 audit `publisherVerified` | Audit event field |

---

## 6. Cross-Cutting Data Sources

### 6.1 UEBA / Risk Score (DB + Redis)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| Entity Risk Score | `ITSEntityRiskScoreDetails` | `RISK_SCORE`, `MODIFIED_SCORE`, `SEVERITY_SCORE`, `DETECTION_COUNT`, `OVERALL_DETECTION_COUNT`, `OVERALL_RISK_SCORE` | itsf |
| Risk Severity Mapping | `ITSRiskSeverityDetails` | `SEVERITY_NAME` | itsf |
| Redis Cache | Key prefix `RISKSCORE_` | Cached risk scores | itsf |
| Entity Types | Enum: User=0, Host=1, ~~IP/Service/Process NOT supported~~ | `RiskScoreHandler.computeAndLoadRiskScoreDetails()` | itsf |
| UEBA Unique Entities | `ADSAnomalyDetectionUniqueEntities` | `FIRST_SEEN_TIME` | itsf |
| UEBA Watchlist | `ADSAnomalyDetectionUniqueEntities` watchlist flag | Analyst-managed | itsf |
| Anomaly Detection Source | `ADSAnomalyDetectionSource` | `SOURCE_TYPE_ID`, `IS_PG_CONFIGURED` (peer group), `IS_REAL_TIME_CONFIGURED` | itsf |
| Anomaly Detection Models | `ADSAnomalyDetectionModelTable` | `BASE_MODEL_NAME`, `FEATURE_LIST`, `ENTITY_MAPPING`, `IS_ENABLED` | itsf |
| Risk Score UI Helper | `get-risk-status.js` | Ember helper for risk display | adsf |

### 6.2 Alerts / Detection Rules (DB + ES)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| Alert Profiles | `ITSAlertProfileConfigurations` | `ALERT_PROFILE_ID`, `DISPLAY_NAME`, `ALERT_TYPE`, `LOG_TYPE`, `ALERT_SEVERITY`, `IS_ENABLED` | itsf |
| Alert Types | Enum | PRE_DEFINED, CUSTOM, RULE, CORRELATION, ANOMALY, etc. (12 types) | itsf |
| Detection Rules | `ADSDetectionRuleInfo` | `RULE_ID`, `RULE_TYPE`, `RULE_UPDATE_HISTORY` | itsf |
| Detection Rule Actions | `ADSDetectionActionInfo` | `ACTION_ID`, `DISPLAY_NAME`, `CRITERIA`, `SOURCE` | itsf |
| Rule→Action Mapping | `ADSDetectionRuleVsActions` | `RULE_ID`, `ACTION_ID`, `CONFIG_ORDER` | itsf |
| Rule→Alert Mapping | `ITSDetectionRuleVsAlerts` | `RULE_ID`, `ALERT_ID` | itsf |
| Rule→LogType Mapping | `ITSDetectionRuleVsLogType` | `RULE_ID`, `LOGTYPE_ID` | itsf |
| Rule Additional Configs | `ADSDetectionRuleAdditionalConfigs` | `RULE_ID`, `CONFIG`, `CONFIG_VALUE` | itsf |
| Rule Tuning | `ITSDetectionRuleTuningInfo` | `TUNING_EXPRESSION` | itsf |
| Rule Exceptions | `ITSDetectionRuleException` | `RULE_ID`, `EXCEPTION` | itsf |
| Detection Field Config | `ITSDetectionRuleFieldConfig` | `RULE_ID`, `FIELD_ID`, `CRITERIA` | itsf |
| L3C Rule Scheduling | `L3CDetectionRuleScheduleInfo` | `SCHEDULE_FREQUENCY`, `LOOKBACK_TIME`, `QUERY_TIMEOUT` | itsf |

### 6.3 MITRE ATT&CK Mapping (DB)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| MITRE Tactics | `ITSMitreTactics` | `TACTIC_ID`, `TACTIC_NAME`, `DISPLAY_ORDER` | itsf |
| MITRE Techniques | `ITSMitreTechniques` | `TECHNIQUE_ID`, `TECHNIQUE_NAME`, `PARENT_TECHNIQUE_ID` | itsf |
| Tactic↔Technique Mapping | `ITSMitreTacVsTech` | `TACTIC_UNIQUE_ID`, `TECHNIQUE_UNIQUE_ID` | itsf |
| Rule→MITRE Mapping | `ITSDetectionRuleVsMitre` | `RULE_ID`, `TACTIC_ID`, `TECHNIQUE_ID` | itsf |

### 6.4 Tags / Custom Labels (DB)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| Tag Keys | `ITSTagKeysInfo` | `KEY_ID`, `KEY_NAME`, `DISPLAY_ORDER` | itsf |
| Tag Values | `ITSTagValuesInfo` | `VALUE_ID`, `KEY_ID`, `VALUE`, `IS_PREDEFINED` | itsf |
| Rule→Tags Mapping | `ITSDetectionRuleVsTags` | `RULE_ID`, `VALUE_ID` | itsf |
| Custom Tags (constant) | `RuleLibraryConstants.CUSTOM_TAGS` | Used in detection rule library | itsf |

### 6.5 Correlation Rules (DB)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| Correlation Rule Info | `CorrelationRuleInfo` | Rule configuration | itsf |
| Correlation Actions | `CorrelationConfiguredActions` | Configured response actions | itsf |
| Correlation→Alert Map | `CorrelationNotificationMapping` → `ITSAlertProfileConfigurations` | Notification setup | itsf |
| Correlation Criteria | `ITSAlertLAExpression`, `ITSAlertLACriteria2Expression` | Expression/criteria logic | itsf |

### 6.6 Incident Management (DB)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| Incidents | `ADSIncidents` | `INCIDENT_ID`, `INCIDENT_NAME`, `INCIDENT_DESCRIPTION`, `CREATED_TIME`, `INCIDENT_SEVERITY_ID` | adsf |
| Incident Severity | `ADSIncidentSeverity` | Severity levels | adsf |
| Incident Status | `ADSIncidentStatus` | `STATUS_ID`, `IS_DEFAULT` | adsf |
| Incident→User | `ADSIncidentVsUser` | Assignment tracking | adsf |
| Incident Activity | `ADSIncidentActivityDetails` | Timeline of actions | adsf |
| Incident User Data | `ADSIncidentUserData` | User-specific incident data | adsf |
| Incident Participants | `ADSIncidentParticipantsDataHandler` | Participant tracking | adsf |
| Incident Rules | `ADSIncidentRules` | `INCIDENT_RULE_NAME`, `THRESHOLD_VALUE`, `THRESHOLD_TIME_RANGE`, `IS_ENABLED` | adsf |
| Incident Rule→User | `ADSIncidentRuleVsUser` | `ASSIGN_TO`, `USER_NAME` | adsf |
| Incident UI Tabs | `ADSIncidentUITabDetails` | UI configuration | adsf |
| Incident↔Ticket Tools | `ADSIncidentVsTicketIntegratedTool` | ServiceDesk/ITSM integration | adsf |
| Status Mapping | `ADSIncidentStatusVsToolStatus` | Cross-tool status mapping | adsf |
| Severity Mapping | `ADSIncidentSeverityVsToolSeverity` | Cross-tool severity mapping | adsf |

### 6.7 Playbook / Workflow Engine (DB + Config)

| Data Point | Source | Key Info | Source Repo |
|------------|--------|----------|-------------|
| Playbook Recommendations | `PlayBookRecommendation.xml` | Config-driven recommendations per CRN/hosttype | adsf |
| Recommendation Engine | `PlaybookRecommendationEngine` | Prioritizes playbooks based on CRN, time, hosttype | adsf |
| Playbook Quick Actions | `ADSPlayBookQuickActionBlocks.xml` | Pre-built action blocks | adsf |
| IM Workflow Engine | `IMWorkflow` module | Full workflow orchestration | adsf |
| Workflow REST Credentials | `ADSIMWorkflowRESTTokenCredentials` | `HOST`, `PORT`, `PROTOCOL`, `AUTH_TOKEN` | adsf |
| Firewall Block Actions | `IMPaloAltoActions`, `IMFortigateActions`, `IMCiscoActions`, `IMSophosXGActions`, `IMBarracudaActions` | IP blocking on firewalls | adsf |

### 6.8 Threat Intelligence Infrastructure (DB + API)

| Data Point | Table/Source | Key Info | Source Repo |
|------------|--------------|----------|-------------|
| Threat Analytics Servers | `ADSThreatAnalyticsServers` | `ANALYTICS_SERVER_ID` | adsf |
| Threat Analytics Feeds | `ADSThreatAnalyticsFeeds` | `ANALYTICS_FEED_TYPE` (IP/URL), versioning | adsf |
| Feed Processing | `ThreatAnalyticsIntermediateProcessor` | Enriches logs during ingestion | adsf |
| VirusTotal | `VirusTotalActionHandler` (Vendor ID=2) | External API | adsf |
| TAXII/STIX | `TAXIIActionExecutor` | TAXII 1.x server integration | log360 |
| Threat TPIVendors | `ThreatTPIVendors` | Vendor registry (VT=2, Webroot, ME feed, etc.) | adsf |
| In-Memory Threat Data | `DataStore` interface | IP→ThreatSourceData, URL→ThreatSourceData, IPRange→ThreatSourceData | adsf |

### 6.9 Log Type / Host Type Registry (DB)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| Log Types | `ADSLogTypeVsFields` | `LOGTYPE_ID`, `FIELD_ID`, `IS_INDEXED_FIELD`, `IS_VIEW_FIELD` | itsf |
| Fields Registry | `ADSFields` | `FIELD_ID`, `NAME`, `DISPLAY_NAME`, `FIELD_TYPE_ID`, `IS_PREDEFINED` | itsf |
| Host Type Constants | `HOSTTYPE` in ES documents | Lookup via `LogtypeFieldUtil.getLogType(hostType)` | itsf |
| Detection Rule Log Types | `ITSDetectionRuleVsLogType` | `RULE_ID` → `LOGTYPE_ID` | itsf |

### 6.10 Rule Library / Content Packs (DB)

| Data Point | Table | Key Columns | Source Repo |
|------------|-------|-------------|-------------|
| Rule Library Categories | `RuleLibraryCategories` | `CATEGORY_NAME`, `DISPLAY_NAME`, `IMAGE_NAME`, `PRIORITY` | itsf |
| Category Settings | `RLCategorySettings` | `SETTING_NAME`, `SETTING_VALUE` | itsf |
| Installed Profiles | `RLCategoryInstalledProfiles` | `CATEGORY_ID`, `PROFILE_ID` | itsf |
| Installed Rules | `RLCategoryInstalledRules` | `CATEGORY_PROFILE_ID`, `RULE_ID`, `INSTALLATION_MODE` | itsf |

---

## 7. No-Data Gaps Summary

### Confirmed NOT Available (remove from UI)

| Category | Specific Gap | Why |
|----------|-------------|-----|
| **Device** | Vulnerability scanning / CVE data | No vulnerability scanner in product |
| **Device** | CIS Benchmark / Misconfigurations | No CIS assessment engine |
| **Device** | Installed Software inventory | No software inventory — need Endpoint Central/UEM |
| **Device** | Intune/MDM compliance | No Intune device API integration |
| **Device** | AV status / EDR agent health | No live AV/EDR health endpoint |
| **Device** | CPU%, Memory (live telemetry) | Only launch-time events, no WMI/live telemetry |
| **Device** | Uptime | No live telemetry |
| **Device** | TPM status | Not in AD sync attributes |
| **Device** | Last Patch date | No patch management data |
| **IP** | AbuseIPDB score | Not integrated (ThreatTPIVendors ID=4 placeholder) |
| **IP** | Reverse DNS | No live DNS PTR lookup service |
| **IP** | Campaign attribution / MISP | No campaign DB |
| **IP** | IOC clustering | No IOC clustering engine |
| **IP** | Hosting type (Datacenter/Residential) | No IP classification service |
| **IP** | NAC status | No NAC parser |
| **IP** | Switch port mapping | No network infrastructure mapping |
| **IP** | Microsoft Threat Intel API | Not integrated |
| **IP** | CrowdStrike Falcon X API | Only CEF log parsing, no API |
| **Service** | CIS Benchmark for cloud services | No CIS assessment for cloud |
| **Service** | Service dependency mapping | No topology/dependency data |
| **Service** | Conditional Access policy definitions | Only status from sign-in logs |
| **Service** | Purview classification details | No Purview API |
| **Process** | Thread Count, Handle Count | No live process telemetry |
| **Process** | Related/Active Tokens inventory | No Entra token inventory API |
| **Process** | DLL/Module loads | Sysmon Event 7 (ImageLoad) — **available if Sysmon configured**, but no built-in agent DLL monitoring |
| **Cross-entity** | Risk Score for IP/Service/Process | UEBA only supports User (0) and Host (1) entity types |
| **Cross-entity** | Risk trend time-series | Only last snapshot in `ITSEntityRiskScoreDetails`, no history |
| **Cross-entity** | Auto-tagging compliance impact on alert fire | Manual mapping only |

### Partially Available (needs aggregation or conditional)

| Category | Data Point | Condition |
|----------|-----------|-----------|
| IP | City-level GeoIP | Depends on MaxMind DB tier |
| IP | VLAN mapping for internal IPs | Needs network device log parsing |
| IP | Subnet mapping | No subnet config table — needs manual/config |
| Device | IP Address | Available from DHCP/logon events only if collected |
| Device | MAC Address | Only if DHCP logs collected |
| Device | Users logged on duration | Requires correlating 4624/4634 logon/logoff pairs |
| Device | Azure AD registered | Partial — knows device is AAD joined |
| Process | Process tree reconstruction | Available data, needs app-layer join logic |
| Process | Token anomaly detection | Rule-based only, no ML |
| Service | File access anomaly count | Bulk detection via alert rules, no ML model |
| Service | Related processes/services | Needs join on `HOSTNAME` + time window |

---

## Appendix: Key Source Files by Repo

### app-fw
- Data dictionaries: `ADSF-DD-DML/product_package/conf/adsf/common/appfw/*.xml` (304+ files)
- Master index: `ADSF-DD-DML/product_package/conf/adsf/common/appfw/dd-sas-files.xml`
- OAuth tables: `APFOAuthProps`, `APFOAuthConfigProps`, `APFOAuthKeys`
- Orchestration: `APFOrchestrationProfileHandler` (user creation/update/delete workflows)

### itsf
- Alert system: `com.manageengine.itsf.common.alert.constant.AlertConstants`
- Detection rules: `com.manageengine.itsf.common.detection.constants.TableNameConstants`
- Service list: `com.manageengine.itsf.common.servicelist.constants.ServiceListConstants`
- Correlation: `com.manageengine.itsf.common.correlation.*`
- Agent status: `com.manageengine.itsf.common.settings.agentadministration.agentsync.constants.LCStatus`
- UEBA: `ADSAnomalyDetectionSource`, `ADSAnomalyDetectionModelTable`
- MITRE: `ITSMitreTactics`, `ITSMitreTechniques`, `ITSDetectionRuleVsMitre`

### adsf
- Incident mgmt: `com.manageengine.ads.fw.common.incident.constants.IncidentTableNameConstants`
- IM Workflow: `com.manageengine.ads.fw.incident.imworkflow.*`
- Playbooks: `com.manageengine.ads.fw.incident.imworkflow.playBookRecommendation.*`
- Threat Intel: `com.manageengine.ads.fw.common.threat.*`
- Compliance: `com.manageengine.ads.fw.common.compliance.*`
- Agent install: `com.manageengine.ads.fw.agent.installation.*`
- Credentials: `com.manageengine.ads.fw.common.credentials.*`

### log360
- TAXII/STIX: `com.manageengine.ela.server.dataenrichment.threat.action.taxii.TAXIIActionExecutor`

### log360cloudcommon
- Work hours: `UserWorkHoursUtils.isOffHours()`
- Common utilities shared across L3C modules

### ADSF-DD-DML
- All data-dictionary XML files defining DB schemas for APF sync tables
- 304+ files covering: AD, AAD, Azure, GSuite, JumpCloud, Salesforce, ServiceNow, Zoho, BambooHR, Slack, Freshdesk, Zendesk
