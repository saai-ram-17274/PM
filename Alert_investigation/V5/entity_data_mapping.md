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

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Risk Score (0–100) | ✅ | `ITSEntityRiskScoreDetails.RISK_SCORE` (Log360) | `RiskScoreHandler` — computed `MODIFIED_SCORE × SEVERITY_SCORE`, cached in Redis | 🤖✚ AI can re-rank by considering the **full alert chain context** (e.g. boost score if entity also appears in a parallel attack-path graph) |
| Severity | ✅ | `ITSRiskSeverityDetails.SEVERITY_NAME` | Mapped from score thresholds | 🤖✚ AI suggests severity-vs-blast-radius adjustment |
| Status Badge ("Compromised Account") | 🟡 | Computed from anomaly types | Aggregate `ITSAlertProfileConfigurations` rule categories | 🤖✚ AI generates a one-line **verdict** ("Compromised", "Insider", "Misconfigured") from log evidence |
| Active Anomalies (count) | ✅ | `ITSEntityRiskScoreDetails.DETECTION_COUNT` | Raw DB | — |
| Failed Logins (24h) | ✅ | Elasticsearch `eventid=4625` | Aggregated ES query on Windows Security logs | 🤖✚ AI clusters failures by source IP and labels each cluster (brute-force vs misconfig vs typo) |
| Time Since First Alert | ✅ | `ITSAlertProfileConfigurations` first timestamp | `now() - first_alert_ts` | — |
| First Seen / Last Activity | ✅ | `ADSAnomalyDetectionUniqueEntities.FIRST_SEEN_TIME` + ES max `_zl_timestamp` | Raw DB + ES agg | — |

### 1.2 User Details (`usersDetails`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Display Name, SAM, UPN, Email | ✅ | ADAudit Plus / ADManager Plus — `ADSUserDetails` | LDAP sync into RDBMS | — |
| Job Title, Department, Manager | ✅ | AD attributes (`title`, `department`, `manager`) | LDAP attribute pull | 🤖 Cross-reference with HRIS (Workday, BambooHR) for verified org-chart |
| Last Logon Time | ✅ | `ADSUserDetails.LAST_LOGON` (replicated from all DCs) | ADAP nightly aggregator | — |
| OU Name | ✅ | AD `distinguishedName` parsed | ADAP | — |
| Account Created | ✅ | AD `whenCreated` | LDAP | — |
| Account Status (with recommendation) | 🟡 | `userAccountControl` flags | LDAP + business rule | 🤖✚ AI generates the **recommendation text** ("Disable" / "Force password change") from current risk + attack chain |
| Logon Workstation | ✅ | `ADSUserLogonDetails.WORKSTATION` | EventID 4624 parser | — |
| Primary Group | ✅ | AD `primaryGroupID` | LDAP | — |

### 1.3 Logon Activity (`logonActivity`) — Timeline

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Timestamp, Logon Type (2/3/10), Target Host, Source IP, Status | ✅ | EventID 4624 / 4625 in Elasticsearch | Standard auth-log parser | 🤖✚ AI labels each entry as "normal", "anomalous (geo)", "anomalous (time)", "credential-stuffing pattern" with rationale |
| `dot` color (red/orange/green) | ✅ | Computed from UEBA peer-group baseline | UEBA scorer | 🤖✚ AI provides a **natural-language reason** for the color ("Red because Tor exit + off-hours + new device") |

### 1.4 Processes (`processes`) — Timeline (per user-launched processes)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Process Name, Parent Process | ✅ | Sysmon EventID 1 + EID 8 (CreateRemoteThread) | Sysmon collector → ES | 🤖 AI looks up binary hash on **VirusTotal**, classifies parent-child anomaly via MITRE T1059 catalog |
| Action: Kill Process | ✅ | EDR API call (Defender/CrowdStrike/SentinelOne) | Existing remediation orchestrator | 🤖✚ AI pre-validates kill safety (e.g. avoid killing system-critical PIDs) |

### 1.5 Service Triggered (`serviceTriggered`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Service Name, Display Name, Startup type, Host, Status, Severity | ✅ | EventID 7045 (service installed) + 4697 + EID 12/13 | Windows Service log parser | 🤖 AI matches service name against **LOLBAS** + known-malware catalogs (e.g. `WinUpdateSvc` masquerade) |
| Action: Stop Service | ✅ | WMI/PowerShell remoting via existing AAP runner | — | — |

### 1.6 Recent Alerts (`recentAlerts`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Time, Alert label, Type tag, MITRE technique, Source, Status, Severity | ✅ | `ITSAlertProfileConfigurations` + correlation engine output | Existing alert-profile API | 🤖✚ AI generates **alert-cluster summary** ("These 4 alerts form a kill-chain: Initial Access → Execution → Exfiltration") |
| Linked graph node (`viewOnGraph`) | ✅ | Internal entity-id mapping | — | — |

### 1.7 Resource / File Access (`resourceFileAccess`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Host, File Name, Location, Change Type | ✅ | File-server auditing (ADAudit Plus File Server module) + SharePoint audit | Existing FS collector + Graph API | 🤖✚ AI classifies file sensitivity (PII/PCI/PHI) by filename + path heuristics; flags **uncommon access patterns** for the user's role |

### 1.8 UEBA Risk Profile (`uebaProfile`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Risk Score / 100 + Severity | ✅ | UEBA scorer | Existing | — |
| Anomalies Detected | ✅ | UEBA model output | Existing | 🤖✚ AI clusters anomalies into **TTP buckets** (Lateral, Persistence, Exfil) |
| Account Type | ✅ | LDAP `adminCount` + group memberships | LDAP | — |

### 1.9 Login Statistics (7 days) (`loginStatistics`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Total / Successful / Failed | ✅ | ES agg over 4624/4625 | Existing | — |
| Unique Source IPs | ✅ | ES `terms` agg | Existing | 🤖 AI enriches each IP with **geo + ASN + threat-feed reputation** in one call |
| Off-Hours Logins | ✅ | ES filter on hour-of-day vs business window | Existing | 🤖✚ AI infers "business hours" from the **user's own historical baseline** instead of a global rule |
| Unique Hosts | ✅ | ES `terms` agg on `Workstation` | Existing | — |

### 1.10 Cloud Identities & Assets (`cloudIdentities`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Azure AD UPN + Tenant + License (P1/P2/E5) | ✅ | M365 Manager Plus / Cloud Security Plus | Graph API `users/{id}` + `subscribedSkus` | — |
| Azure Roles | ✅ | Graph API `directoryRoles` | Existing | 🤖✚ AI flags **dormant role assignments** (assigned but unused for N days) |
| Conditional Access (count) | ✅ | Graph API `conditionalAccessPolicies` | Existing | 🤖✚ AI evaluates **policy-coverage gaps** for this user |

### 1.11 Identity Risk Assessment (`identityRisk`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Password Age (vs policy) | ✅ | LDAP `pwdLastSet` + domain pwd policy | ADAP | — |
| Group Memberships | ✅ | LDAP `memberOf` | ADAP | 🤖✚ AI tags **toxic combinations** ("VPN-Users + SharePoint-Editors + WriteDACL on SVC_Backup = privilege chain") |
| Privileged Groups + WriteDACL findings | 🟡 | ADAP risk-report module + ADMP Governance attack-path | Existing (Governance module) | 🤖✚ AI cross-walks with BloodHound-style attack paths |
| Stale Account / Service Account flags | ✅ | LDAP attributes + heuristic | ADAP | — |
| Last Password Change | ✅ | LDAP `pwdLastSet` | ADAP | — |

### 1.12 Network Activity (24h) (`networkActivity`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| DNS Query (Domain, Resolution, Source Host) | ✅ | Sysmon EventID 22 + DNS-server logs | Existing collector | 🤖 AI checks domain on **VirusTotal, urlscan.io, ThreatFox**; computes domain age via WHOIS |
| Firewall Allow / Deny (Dst, Proto, Bytes, Duration) | ✅ | Firewall syslog (Fortinet/PA/Checkpoint) | Existing parsers | 🤖 AI maps Dst IP to ASN + hosting reputation |
| Proxy log (URL, Method, UA) | ✅ | Proxy syslog | Existing | 🤖 AI flags suspicious **paste-site** / **anonymous-share** destinations |
| VPN Connection (Src, Assigned, Proto, Duration) | ✅ | VPN gateway logs | Existing | — |

### 1.13 Threat Intelligence Context (`threatIntelContext`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Primary IOC | 🟡 | Log360 Threat Analytics module | Internal IP/domain enrichment cache | 🤖 AI fetches **fresh** IOC reputation (VirusTotal, Webroot, AlienVault OTX) on-demand |
| VirusTotal verdict | ❌ | Not in product | — | 🤖 **AI-only** — direct VT API call |
| First Seen (Global) | ❌ | Not in product | — | 🤖 **AI-only** — VT/passive-DNS lookup |
| MITRE Techniques | 🟡 | Per-alert-profile mapping | `ITSAlertProfileConfigurations.MITRE_TECHNIQUE_ID` | 🤖✚ AI walks the **alert chain** to predict next-likely-technique |

### 1.14 DLP Incidents (`dlpIncidents`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Policy, Action, File, Destination | ✅ | DataSecurity Plus / Defender for Cloud Apps DLP | Existing connector | 🤖✚ AI **classifies file content sensitivity** (PII/PCI/PHI) when filename is ambiguous |

### 1.15 Account Lockouts (`accountLockouts`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| User, Locking DC, Source Computer, EventID | ✅ | EventID 4740 (account locked) | ADAP account-lockout analyzer | 🤖✚ AI suggests **likely root cause** (cached creds on phone, mapped drive, scheduled task) |

### 1.16 Password Change / Reset History (`passwordHistory`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Operation, Caller, Target, Source, Result | ✅ | EventID 4723 (self) / 4724 (admin) — on-prem; Entra audit log — cloud | ADAP + M365MP | — |

### 1.17 Group Membership Changes (`groupMembershipChanges`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Operation, Group, Caller, Source | ✅ | EventID 4732/4756 — on-prem; Entra audit — cloud | ADAP + M365MP | 🤖✚ AI flags **abnormal group additions** for this user's role band |

### 1.18 Mailbox Forwarding Rules (`mailboxForwarding`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Operation (New-InboxRule), Mailbox, Rule Name, ForwardTo, Creator IP | ✅ | Exchange Online audit log | M365 Manager Plus | 🤖✚ AI detects **classic exfil rule patterns** (forward-to-external + `_sync_` / `.` rule names) |

### 1.19 Recent Application Access (`recentAppAccess`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Application, Source IP, Risk Level, Result | ✅ | Entra ID Sign-in logs | M365MP | 🤖 AI looks up **app publisher reputation** + Microsoft App Governance score |

### 1.20 Privileged Role Assignment Changes (`privilegedRoleChanges`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Empty-state when none | ✅ | Entra audit log | Existing | 🤖✚ AI generates an **empty-state explanation** ("No privileged-role assignments — risk vector: lateral via group, not role") |

### 1.21 Compliance & Regulatory Impact (`complianceImpact`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Framework (PCI/HIPAA/SOX/GDPR/NIST) + Status + Controls + Impact | 🟡 | Log360 Compliance module | Compliance report mapping | 🤖✚ **High-value AI use case** — AI maps the **specific evidence chain** in this incident to control IDs and drafts the **breach-notification text** for GDPR Art.33, HIPAA §164, etc. |

### 1.22 Recommendations & Remediation (`remediationGuide`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Verdict, Severity | 🟡 | Aggregated from rule output | — | 🤖✚ **AI-generated** — synthesized from all evidence |
| Recommendations (icon, title, desc, priority) | ❌ | Not in product | — | 🤖✚ **AI-generated** — context-specific next steps with playbook links |
| Playbooks (name, ID, desc, ETA, urgency) | 🟡 | SOAR connector / runbook catalog | Log360 Cloud Workflows | 🤖✚ AI **selects + ranks** playbooks based on alert composition; pre-fills variables |

---

## 2. DEVICE Entity (`dev-ws045` — CORP-WS-045)

Tabs: **Overview · Host Activity · Persistence & Exfil · Alerts & Response**

### 2.1 Risk Summary (`riskSummary`)
Same field structure as User §1.1; `metrics` are device-specific ("Suspicious Processes", "C2 Connections"). All ✅ from `ITSEntityRiskScoreDetails`.

### 2.2 Device Details (`deviceDetails`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Hostname, FQDN, OS, OS Build | ✅ | AD computer object + Sysmon system info | ADAP + Sysmon EID 1 | — |
| Domain, OU | ✅ | AD `distinguishedName` | ADAP | — |
| Last Logon, Last Boot | ✅ | AD `lastLogonTimestamp` + Sysmon EID 6005 | Existing | — |
| Owner / Primary User | ✅ | AD `managedBy` + heuristic on logon counts | ADAP | 🤖✚ AI infers primary user from logon-pattern when `managedBy` is empty |
| Hardware (CPU, RAM, Disk) | 🟡 | Asset-management integration (SCCM/Intune) | Optional connector | 🤖 AI can correlate with **CMDB** if available |
| BitLocker / Disk encryption | 🟡 | Intune compliance | Existing | — |

### 2.3 Login Activity on Device (`loginActivity`)
Same shape as User §1.3 but reverse-pivoted (who logged into this host). ✅ from EventID 4624 on the host.

### 2.4 Processes on Host (`processesOnHost`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Process name, PID, Start time, Cmdline | ✅ | Sysmon EID 1 | Existing | 🤖 AI hashes binary → VT lookup; flags LOLBin abuse |

### 2.5 Services on Host (`servicesOnHost`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Service Name, Display Name, Startup, User, Status | ✅ | EID 7045 + WMI snapshot | Existing | 🤖 AI matches against **service-masquerading** catalog |

### 2.6 Users Logged On (`usersLoggedOn`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Active sessions (user, type, since) | ✅ | `quser` / `LogonSessions.exe` collector + 4624/4634 pairing | Existing | — |

### 2.7 Recent Alerts on Device (`recentAlerts`)
Same shape as User §1.6.

### 2.8 Agent Status & Health (`agentStatus`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| EDR (Defender / CrowdStrike / SentinelOne) status, version, last check-in | ✅ | EDR API | Existing connectors | 🤖✚ AI flags **agent-tampering** (sudden uninstall, definition-update lag) |
| Sysmon version, config hash | 🟡 | Sysmon registry key | Custom collector | — |
| AV definitions date | ✅ | EDR API | Existing | — |

### 2.9 GPO Applied to Device (`gpoApplied`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| GPO name, link OU, version, applied at | ✅ | ADManager Plus GPO module | Existing | 🤖✚ AI flags **conflicting** policies (e.g. one enables RDP, another blocks NLA) |

### 2.10 Security Event Summary (24h Counters) (`securityEventSummary`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Per-EventID counts (4624, 4625, 4672, 4688, 7045, …) | ✅ | ES `date_histogram` + `terms` agg | Existing | 🤖✚ AI surfaces **anomalous deltas** vs the host's own baseline |

### 2.11 USB Device Events (`usbDeviceEvents`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Time, Vendor/Product, Serial, Action (insert/remove), Bytes copied | ✅ | EventID 6416/4663 + DataSecurity Plus | Existing | 🤖 AI classifies device type (mass-storage vs HID-injector / Rubber Ducky) by VID/PID |

### 2.12 Scheduled Task Events (`scheduledTasks`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Task Name, Action, Trigger, Author, Result | ✅ | EventID 4698/4699/4700/4701/4702 | Existing | 🤖✚ AI matches against **persistence-via-scheduled-task** patterns (T1053.005) |

---

## 3. IP Entity (`ip-tor`, `ip-internal`)

Tabs: **Overview · Threat Intel · Connections · Logon Activity**

### 3.1 Risk Summary (`riskSummary`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| "Tor Exit Node: Confirmed" | 🟡 | Log360 Threat Analytics + Tor consensus list | Internal TI cache | 🤖 AI re-checks against **live** Tor consensus; identifies **bridge** vs **exit** vs **guard** |
| Threat Feeds Flagged (5) | ✅ | Threat Analytics aggregator | Existing | 🤖 AI lists **which** feeds and the verdict from each |
| Active Connections | ✅ | ES agg over firewall/IDS | Existing | — |
| VirusTotal Detections (12/89) | ❌ | Not in product | — | 🤖 **AI-only** — VT API |

### 3.2 IP Details (`ipDetails`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| IP, Version, Type (Tor/Public/Private/VPN) | 🟡 | Threat Analytics + RFC1918 check | Existing + heuristic | 🤖 AI enriches with **ASN, hosting provider, ISP** (MaxMind / IPinfo) |
| Reverse DNS (PTR) | 🟡 | DNS server logs / live `dig` | Existing or live | 🤖 Live DNS query if not cached |
| Country, City | ✅ | MaxMind GeoIP (bundled) | Existing | 🤖 AI cross-checks against **historical user geo** |

### 3.3 Geo Context (`geoContext`)
Same fields as §3.2 country/city + ASN. Map widget feeds from MaxMind. ✅.

### 3.4 Threat Intelligence (`threatIntelligence`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Detection counts per vendor | 🟡 | Internal TI aggregator (Webroot, Anomali, OTX) | Existing | 🤖 **VirusTotal, GreyNoise, Censys, Shodan** for additional verdicts |
| Feed name, Category, Confidence, Last Updated | ✅ | Threat Analytics module | Existing | — |

### 3.5 Connection History (`connectionHistory`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Direction, Source/Dest IP, Port, Bytes, Duration, Action, Device | ✅ | Firewall syslog (PA, Fortinet, Checkpoint, Cisco ASA) | Existing parsers | 🤖✚ AI clusters connections into **sessions/flows** and labels each flow ("C2 beacon", "data exfil chunk") |

### 3.6 Firewall Action Summary (`firewallSummary`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Allow / Deny / Drop counts (24h) | ✅ | ES agg on firewall logs | Existing | — |

### 3.7 DNS Query History (`dnsHistory`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Domain, Record Type, Resolution, Querying Process, Source (Sysmon EID 22) | ✅ | Sysmon EID 22 + DNS server logs | Existing | 🤖 AI computes **DGA score** for each domain (`c2-update.darkoperator.net` → low DGA score; `xkj92qnda.com` → high) |

### 3.8 IDS/IPS Alerts (`idsAlerts`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Signature, Threat ID, Severity, Action, Source device | ✅ | Snort/Suricata/PaloAlto Threat Prevention syslog | Existing | 🤖 AI maps signature ID → **MITRE technique + ATT&CK procedure example** |

### 3.9 Associated Users / Devices (`associatedUsers`, `associatedDevices`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Pivot from IP → all users/devices that authenticated from / connected to this IP | ✅ | ES `terms` agg on auth logs filtered by IP | Existing | — |

### 3.10 VPN Sessions (`vpnSessions`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| User, Assigned IP, Tunnel type, Duration | ✅ | VPN gateway syslog | Existing | — |

### 3.11 Traffic Summary (`trafficSummary`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Total bytes in/out, Top protocols, Top destinations | ✅ | ES agg | Existing | 🤖✚ AI compares to **expected baseline** for this IP-class |

---

## 4. DOMAIN Entity (`domain-c2`)

Tabs: same as IP (Overview · Threat Intel · Connections · Logon Activity).

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Domain, Record Type, Resolved IPs | ✅ | DNS logs + Sysmon EID 22 | Existing | 🤖 **WHOIS** (registrar, registered date, expiry, registrant); **passive DNS** (other historical resolutions) |
| Threat Intel verdict | 🟡 | Internal TI aggregator | Existing | 🤖 **VirusTotal, urlscan.io, ThreatFox, AlienVault OTX** |
| Domain age | ❌ | Not in product | — | 🤖 **AI-only** — WHOIS computation |
| Hosting / certificate (TLS issuer, validity) | 🟡 | Network sensor TLS metadata if Zeek/NDR present | Optional | 🤖 Live `openssl s_client` style fetch |
| Associated processes (which exe queried this domain) | ✅ | Sysmon EID 22 | Existing | — |
| Connection history (same as §3.5) | ✅ | Firewall + Zeek | Existing | 🤖✚ AI labels **C2-beaconing pattern** (fixed interval + jitter detection) |

---

## 5. SERVICE Entity (`svc-azure-ad`, `svc-sharepoint`, `svc-oauth`, `svc-winupdatesvc`)

Tabs: **Overview · Config & Policy · Activity · Alerts & Response**

### 5.1 Service Details (`serviceDetails` / `serviceInfo`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Service / Tenant / Workload name | ✅ | M365 Manager Plus tenant config | Existing | — |
| Service Type (IDP, SaaS, Storage, OS-service) | ✅ | Internal classification | Existing | 🤖✚ AI auto-classifies new/unknown services from telemetry |

### 5.2 OAuth App Consent Grants (`oauthConsentGrants`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Operation, App, Consenting User, Permissions, Source IP, Admin Consent | ✅ | Entra ID audit log (`Consent to application`) | M365MP | 🤖 AI looks up app's **Microsoft App Governance score**, publisher verification, install-base, and known-bad app catalog |

### 5.3 Admin Activity on Service (`adminActivity`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Operation, Target, Caller, Workload, Source IP | ✅ | Unified Audit Log (Entra/Exchange/SharePoint) | M365MP | 🤖✚ AI flags **admin actions taken from a compromised session** by joining to active alerts |

### 5.4 Conditional Access Policies (`conditionalAccess`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| State (Enabled/Report-Only/Disabled), Scope, Conditions, Grant, Exclusions, Last Modified | ✅ | Graph API `conditionalAccessPolicies` | M365MP | 🤖✚ AI runs **policy what-if** ("If this Report-Only policy were Enabled, would it have blocked this attack?") |

### 5.5 Sign-In Audit (`signInAudit`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| User, IP, Location, App, MFA result, Risk, Result | ✅ | Entra ID Sign-in logs | M365MP | 🤖 AI explains MFA result ("Satisfied via stale token" → likely **token replay**) |

### 5.6 DLP Policies (`dlpPolicies`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Policy name, Scope, Action, Last triggered | ✅ | Defender for Cloud Apps DLP / Purview | Existing connector | — |

### 5.7 File Access Anomaly / Sensitive Files (`fileAccessAnomaly`, `sensitiveFiles`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| File, User, Operation, Sensitivity tag | ✅ | SharePoint audit + Purview labels | M365MP | 🤖✚ AI **infers sensitivity** when no Purview label exists, using filename + path heuristics + content-classifier (if data-access permitted) |

### 5.8 Service Timeline / Network Connections / File Drops / WMI / Processes (when service is OS-resident)

All ✅ from Sysmon (EID 1, 3, 11, 19, 22) when the "service" is an on-host artifact like `WinUpdateSvc`. AI enrichment same as §1.4 / §1.12.

### 5.9 Recent Alerts / Service Triggered

Same as §1.6.

---

## 6. PROCESS Entity (`proc-powershell`)

Tabs: **Overview · Anomalies · Activity**

### 6.1 Risk Summary (`riskSummary`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| AMSI Detections (count), C2 Connection (Active), Payload (filename), Encoded Commands, Obfuscation type, Child processes | ✅ | Sysmon (EID 1, 3, 11), AMSI provider events (EID 4104) | Existing | 🤖✚ AI **deobfuscates** Base64/IEX content and produces a plain-English summary of what the script does |

### 6.2 Process Details (`processDetails`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Process Name, PID, Parent, Cmdline, User, Integrity, Start, Status, Signature (publisher, validity), Session ID, Threads, Handles | ✅ | Sysmon EID 1 + EID 8 | Existing | 🤖 AI looks up file hash on VT; flags **signed-binary abuse** (e.g. signed `regsvr32.exe` running malicious script) |

### 6.3 Process Tree (`processTree`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Level (Grandparent/Parent/Current/Child), User, Started, Cmdline, Status, Notes | ✅ | Sysmon EID 1 chain | Existing | 🤖✚ AI labels **suspicious chains** ("explorer → powershell → certutil → cmd /c whoami" matches **HAFNIUM-style hands-on-keyboard pattern**) |

### 6.4 Child Processes (`childProcesses`)
Same as §6.3 but filtered to direct children. ✅.

### 6.5 AMSI Events (`amsiEvents`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Detection (Suspicious/Malicious), Content Preview, Scan Result, Action, Script Block ID | ✅ | EventID 4104 (PowerShell ScriptBlock) + AMSI provider | Existing | 🤖✚ AI **explains the script block** in plain English; classifies into MITRE technique |

### 6.6 Token Anomaly / Token Usage (`tokenAnomaly`, `tokenUsage`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| SeDebugPrivilege, SeImpersonate, NewToken events | ✅ | EventID 4672 + Sysmon EID 8 (CreateRemoteThread) | Existing | 🤖✚ AI maps to **specific exploit primitive** (Token impersonation → T1134.001) |

### 6.7 Registry Modifications (`registryModifications`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Key, Operation (Set/Delete), Old/New Value | ✅ | Sysmon EID 12/13/14 | Existing | 🤖 AI matches against **known persistence keys** (Run, RunOnce, Image File Execution Options, AppInit_DLLs) |

### 6.8 Named Pipes (`namedPipes`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Pipe Name, Operation (Create/Connect), Process | ✅ | Sysmon EID 17/18 | Existing | 🤖 AI matches against **Cobalt Strike named-pipe patterns** (`\\.\pipe\msagent_*`, `\\.\pipe\status_*`) |

### 6.9 Network Activity (`networkActivity`)
Same as §1.12, scoped to the process. ✅ from Sysmon EID 3.

### 6.10 File Operations (`fileOperations`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Operation (Create/Modify/Delete), Path, Hash | ✅ | Sysmon EID 11 + ADAP File Server | Existing | 🤖 AI hashes new files → VT |

### 6.11 DLL Loads (`dllLoads`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| DLL Name, Path, Signed?, Loaded at | ✅ | Sysmon EID 7 | Existing (if EID 7 enabled — high-volume) | 🤖 AI flags **unsigned / unusual-path DLL injection** patterns |

### 6.12 Process DNS Queries (`processDnsQueries`)
Same as §1.12 DNS row, scoped to the process. ✅ from Sysmon EID 22.

---

## 7. ALERT Entity (`alert-impossible-travel` and 10 sibling alert entities)

Tabs: **Overview · Scope · Response**

### 7.1 Alert Details (`alertDetails`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Alert ID, Name, Severity, MITRE Tactic+Technique, Detection Type, First Triggered, Last Updated, Source Service, Status | ✅ | `ITSAlertProfileConfigurations` + correlation engine result | Existing | 🤖✚ AI generates a **one-paragraph summary** of what triggered this alert and why |

### 7.2 Trigger Conditions (`triggerConditions`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Rule Name, Rule Type (Correlation/UEBA/Threat-Intel), Conditions, Threshold, Window | ✅ | Rule-engine config (`CorrelationRules` / UEBA model metadata) | Existing | 🤖✚ AI rewrites the rule in **natural language** for non-experts |

### 7.3 Affected Entities (`affectedEntities`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| KV map of `{entity-id: role}` (Source, Target, Indicator, …) | ✅ | Alert-instance entity links | Existing | 🤖✚ AI infers **missing roles** when alert doesn't tag them explicitly |

### 7.4 Correlated Alerts (`correlatedAlerts`)

| Field | Status | Product Source | How to Get | AI Enrichment |
|-------|--------|----------------|------------|---------------|
| Alert name, Source, Severity, MITRE | ✅ | Alert-correlation graph (existing) | Existing | 🤖✚ AI **clusters into a kill-chain narrative** ordered by MITRE tactic |

### 7.5 Service Triggered / Recent Alerts
Same as §1.5 / §1.6 but scoped to this alert's response actions.

### 7.6 Recommendations & Remediation
Same as §1.22 — primarily 🤖✚ AI-generated.

---

## 8. Cross-Cutting AI-Enrichment Patterns

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

## 9. Section → Entity-Type Cross-Reference

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

## 10. Field-Status Summary

Across the V5 prototype:

| Status | Count (approx) | Notes |
|--------|----------------|-------|
| ✅ Available in product | ~80% | Most timeline/KV fields map to existing ES indices, AD attributes, M365 audit logs, or Sysmon events |
| 🟡 Partial / needs aggregation | ~12% | Mainly aggregator fields (peer-baseline %, threat-intel verdict aggregation) and compliance mappings |
| ❌ Not in product | ~5% | VirusTotal scores, domain age (WHOIS), AI-generated recommendations / verdicts |
| 🤖 AI-enrichable | **every section has at least one AI angle** | See §8 cross-cutting patterns |

---

## 11. Implementation Priority (AI-First)

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

## 12. Code References

| Artifact | File | Purpose |
|----------|------|---------|
| Entity definitions (20) | [`js/data/entities.js`](js/data/entities.js) | All entities + their `sections` |
| Tab config (6 entity types) | [`js/modules/entity-slider.js`](js/modules/entity-slider.js) | Tab → section mapping |
| Display config (icons, colors, names) | [`js/data/display-config.js`](js/data/display-config.js) | `ENTITY_DISPLAY` |
| Quick-card row config | [`js/modules/entity-quick-card.js`](js/modules/entity-quick-card.js) | Hover-card rows per entity type |
| Edge attributes (per-edge enrichment) | [`js/v4-extras.js`](js/v4-extras.js) | `EDGE_ATTRIBUTES` keyed by `source→target` |
| Relation catalog (24 canonical edges) | [`relation_catalog.md`](relation_catalog.md) | Edge taxonomy |

---

## 13. Changelog

| Date | Change |
|------|--------|
| 07 May 2026 | Initial V5 mapping. Mirrors V4 structure but adds explicit **AI Enrichment** column showing what AI agents can fetch beyond product backend (live IOC enrichment, WHOIS, MITRE mapping, narrative generation, compliance drafting, script deobfuscation). Covers 8 entity types, ~50 distinct sections. Cross-references the canonical relation catalog. |
