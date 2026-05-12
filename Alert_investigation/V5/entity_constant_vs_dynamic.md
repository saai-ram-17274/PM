# Entity Slider Sections — Constant vs Dynamic (Alert-Family Driven)

> **Date:** 12 May 2026
> **Scope:** All 7 entity types in V5 (user, service, ip, domain, device, process, alert).
> **Principle:** *Render decision is keyed to alert relevance, not to data availability.* zLogs can fetch almost everything for any entity, but showing "Mailbox Forwarding Rules" on a brute-force alert is noise. A section is **CONSTANT** if it's useful regardless of why the alert fired (identity + baseline posture). A section is **DYNAMIC** if it only makes sense when the alert is in that data domain.
> **Companion to:** [`entity_data_mapping.md`](entity_data_mapping.md) (field → backend column) and [`entity_slider_feasibility.md`](entity_slider_feasibility.md) (per-field feasibility).

---

## Guiding Rules

1. **Constant = "who/what is this entity, is it hot right now"** — identity + baseline + standing risk. Always rendered.
2. **Dynamic = "what evidence does the alert imply matters"** — rendered only when the alert family triggers it.
3. The trigger key is **alert family**, not raw MITRE tag — easier for PMs and engineers to reason about, and matches how analysts mentally categorize alerts.
4. **Zero-row auto-hide**: a dynamic section that fires its trigger but returns 0 rows is hidden — empty cards are worse than missing cards.
5. **Feasibility is orthogonal**: every section below is sourced from data Log360 Cloud already collects (sources tabulated per entity).

---

# 1. USER Entity — 8 constant / 12 dynamic

## Constant (8)

| Section | Why universal | Source |
|---|---|---|
| Risk Summary | "Is this account hot?" — always needed | `ITSEntityRiskScoreDetails` + ES alert index |
| User Details | Identity card — name, role, dept, OU, manager | ADAP `ADSUserDetails` |
| UEBA Risk Profile | Standing UEBA verdict | UEBA scorer |
| Login Statistics (7d) | Baseline analysts compare anomalies against | ES agg on sign-in events |
| Cloud Identities & Assets | Static identity-system footprint | Graph API |
| Identity Risk Assessment | Account hygiene posture | ADAP attributes + Risk Module |
| Logon Activity | "Where has this user been signing in?" — first question for any alert | Win Security 4624/4625 + Entra SignInLogs |
| Recent Alerts | Always-useful pivot to other alerts on the user | Alert search keyed by user |

## Dynamic (12)

| # | Section | Show when alert family is… | Hide for… |
|---:|---|---|---|
| 1 | Processes | Endpoint execution, malware, fileless, LOLBin, credential dumping | Cloud-sign-in, OAuth-only |
| 2 | Service Triggered | Persistence, masquerading-service, scheduled task | Sign-in/OAuth/cloud alerts |
| 3 | Resource & File Access | Data access, exfil, SharePoint/OneDrive download | Auth failures, lockouts, password resets |
| 4 | Network Activity (24h) | C2, beacon, Tor, exfil channel, lateral movement | Pure identity-only alerts |
| 5 | Recent Application Access | OAuth grant, app consent, SaaS anomaly | Brute-force, host-malware |
| 6 | Account Lockouts | **Brute force, password spray, lockout-anomaly, MFA fatigue** | Data-exfil, OAuth, host-malware |
| 7 | Password Change/Reset History | Credential operations — reset, DCSync, theft | Pure data-access/network alerts |
| 8 | Group Membership Changes | Privilege escalation, role-elevation, permission grant | Brute force, network alerts |
| 9 | Mailbox Forwarding Rules | Mailbox manipulation, email exfil, inbox-rule abuse | **Brute force**, malware, network, file-access |
| 10 | DLP Incidents | Data-handling policy violation, regulated-data exposure | Auth/lockout-only |
| 11 | Threat Intel Context | Alert chain contains external IOC | Pure insider/policy-violation alerts |
| 12 | Compliance & Regulatory Impact | Regulated data (PII/PHI/PCI/EU) accessed or exposed | Any alert without regulated-data scope |

## Alert-family decision matrix (USER)

| Alert family | Proc | Svc | File | Net | App | Lock | Pwd | Group | Mbox | DLP | TI | Comp |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Impossible Travel / Geo-anomaly | | | ✓ | ✓ | ✓ | | | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Brute Force / Password Spray** | | | | | | ✓ | ✓ | | | | | |
| Account Lockout Anomaly | | | | | | ✓ | ✓ | | | | | |
| MFA Fatigue / Bypass | | | | | ✓ | ✓ | ✓ | | | | | |
| OAuth Consent / App Governance | | | ✓ | | ✓ | | | ✓ | | | ✓ | |
| Suspicious OAuth Token | | | ✓ | | ✓ | | | | | | ✓ | |
| Encoded PowerShell / Execution | ✓ | ✓ | ✓ | ✓ | | | | | | | ✓ | |
| Suspicious Service Install | ✓ | ✓ | | ✓ | | | | | | | ✓ | |
| C2 / Tor Connection | ✓ | ✓ | | ✓ | | | | | | | ✓ | |
| SAM / Credential Dump | ✓ | | ✓ | | | | ✓ | ✓ | | | | |
| Bulk File Download / Sensitive Access | | | ✓ | ✓ | ✓ | | | | | ✓ | ✓ | ✓ |
| Data Exfiltration | ✓ | | ✓ | ✓ | | | | | ✓ | ✓ | ✓ | ✓ |
| ARP Spoofing / LAN MITM | ✓ | | | ✓ | | | | | | | ✓ | |
| Admin Off-Hours Login | | | | | ✓ | | | ✓ | | | | |
| Mailbox Forwarding to External | | | ✓ | | ✓ | | | | ✓ | ✓ | | ✓ |

---

# 2. SERVICE Entity — 3 constant / 11 dynamic

The service entity is heterogeneous (Azure AD, SharePoint, OAuth token, on-host service like WinUpdateSvc). Constant set is minimal because the relevant sections vary by service type.

## Constant (3)

| Section | Why universal | Source |
|---|---|---|
| Risk Summary | Service's standing risk and key metrics | UEBA + service-specific aggregates |
| Service Details / Service Info | What is this service — provider, tenant, status, account | Graph API / Win Security 7045 / svc registry |
| Recent Alerts | Other alerts implicating this service | Alert search keyed by service id |

## Dynamic (11)

| Section | Show when alert family is… |
|---|---|
| OAuth App Consent Grants | OAuth/app-consent, suspicious-token, privilege-escalation via app |
| Conditional Access Policies | Sign-in anomaly, MFA bypass, geo-anomaly |
| Sign-In Audit | Any sign-in-related alert |
| Admin Activity on Service | Privilege escalation, admin-impersonation, config-tampering |
| File Access Anomaly | Bulk download, sensitive-file access (SharePoint/OneDrive) |
| Sensitive Files Accessed | Same as above |
| DLP Policies | Data-handling, exfil, regulated-data exposure |
| Token Details / Anomalies / Usage | OAuth-token alerts |
| Service Timeline (install events) | Persistence, masquerading-service, rogue-service |
| Network Connections (from service) | C2, beacon, exfil involving this service |
| File Drops & Modifications | Malware, masquerading-binary, fileless |
| Related Processes | Any alert with process-evidence dimension |
| Spawned Processes | Persistence, malware, masquerading-service |
| Service Dependencies | Persistence, service-tampering |

## Alert-family decision matrix (SERVICE)

| Alert family | OAuth | CA Pol | Sign-In | Admin | File | DLP | Token | Timeline | Net | Drops | Procs |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Impossible Travel (svc-azure-ad) | | ✓ | ✓ | ✓ | | | | | | | |
| Suspicious OAuth Token (svc-oauth) | ✓ | | ✓ | | | | ✓ | | | | ✓ |
| New App Consent (svc-azure-ad) | ✓ | ✓ | | ✓ | | | | | | | |
| Bulk File Download (svc-sharepoint) | | | ✓ | | ✓ | ✓ | | | | | ✓ |
| Sensitive File Access (svc-sharepoint) | | | | | ✓ | ✓ | | | | | |
| Suspicious Service Install (svc-winupdatesvc) | | | | | | | | ✓ | ✓ | ✓ | ✓ |
| Outbound Tor (svc-winupdatesvc) | | | | | | | | ✓ | ✓ | | ✓ |
| Data Exfiltration (svc-sharepoint or svc-winupdatesvc) | | | | | ✓ | ✓ | | | ✓ | | ✓ |

---

# 3. IP Entity — 4 constant / 7 dynamic

## Constant (4)

| Section | Why universal | Source |
|---|---|---|
| Risk Summary | IP risk score, threat-feed flag, traffic volume | Firewall agg + threat feed |
| IP Details | IP address, network type, first/last seen, protocols | Firewall logs + DHCP / config |
| Geo & Network Context | Country, network type (VPN/Proxy/ISP), threat-feed match | `ADSThreatAnalyticsFeeds` + GeoIP |
| Associated Users | Which user(s) used this IP — universal pivot for any IP alert | ES join on Entra SignInLogs `clientIP` |

## Dynamic (7)

| Section | Show when alert family is… |
|---|---|
| Threat Intelligence (VirusTotal, feed details) | IP flagged malicious — TI-driven alerts |
| Connection History (per-flow rows) | C2, exfil, lateral movement, anomalous traffic |
| Firewall Action Summary (aggregates) | Same as above, plus policy-violation alerts |
| DNS Query History | DNS-tunnel, C2-domain, fast-flux, beaconing |
| IDS/IPS Alerts (signatures) | IDS-driven alerts (Suricata/Snort/IPS signatures fired) |
| VPN Session History | VPN-related alerts, anomalous-VPN-session, split-tunnel |
| Logon Activity (Entra SignInLogs from IP) | Sign-in anomaly, impossible-travel, brute-force from IP |
| Traffic Summary (24h) | Volume anomaly, exfil, beacon, scanning |

## Alert-family decision matrix (IP)

| Alert family | TI | Conn | FW Summ | DNS | IDS | VPN | Logon | Traffic |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **Impossible Travel (ip-tor)** | ✓ | ✓ | ✓ | | | | ✓ | |
| C2 Connection (ip-tor) | ✓ | ✓ | ✓ | ✓ | ✓ | | | ✓ |
| Tor Exit Detected (ip-tor) | ✓ | ✓ | ✓ | | ✓ | | ✓ | |
| Data Exfil (any external IP) | ✓ | ✓ | ✓ | | | | | ✓ |
| ARP Spoofing (ip-internal) | | ✓ | | | | | ✓ | |
| Internal IP investigation (ip-internal) | | ✓ | | | | ✓ | ✓ | ✓ |
| Port-scan / IDS sig | ✓ | ✓ | ✓ | | ✓ | | | ✓ |

---

# 4. DOMAIN Entity — 4 constant / 4 dynamic

Same tab config as IP but only 4 sections currently populated.

## Constant (4)

| Section | Why universal | Source |
|---|---|---|
| Risk Summary | Domain risk score, threat-feed flags, exfil volume | `ADSThreatAnalyticsFeeds` + DNS+firewall agg |
| Domain & IP Details | Domain, resolved IP, registrar, ASN, hosting, feed flags | Threat-feed + DNS logs + WHOIS (AI enrichment) |
| Geo & Network Context | Country, hosting reputation | Threat feed |
| Associated Users | Who touched this domain | ES join on DNS query + firewall by `username`/`host` |

## Dynamic (4)

| Section | Show when alert family is… |
|---|---|
| Threat Intelligence (VT, feed details, beacon profile) | Domain flagged malicious — TI-driven |
| Connection History | C2, exfil, beacon |
| DNS Query History | DNS-tunnel, beacon, fast-flux |
| IDS/IPS Alerts | IDS signature on the domain |

## Alert-family decision matrix (DOMAIN)

| Alert family | TI | Conn | DNS | IDS |
|---|:-:|:-:|:-:|:-:|
| C2 Connection (domain-c2) | ✓ | ✓ | ✓ | ✓ |
| Data Exfil (any external domain) | ✓ | ✓ | ✓ | |
| DNS-Tunnel | ✓ | | ✓ | ✓ |
| Newly Registered Domain | ✓ | | ✓ | |

---

# 5. DEVICE Entity — 5 constant / 7 dynamic

## Constant (5)

| Section | Why universal | Source |
|---|---|---|
| Risk Summary | Device risk score + key indicators | UEBA + host telemetry agg |
| Device Details | Hostname, OS, domain, OU, owner, encryption | ADAP `ADSComputerDetails` + Defender |
| Agent Status & Health | Collector status, last sync, agent version, log channels | Log360 Cloud collector table |
| Users Logged On | Who is/was on this host — universal pivot | Win Security 4624 sessions |
| Login Activity | All recent logons to/from device | Win Security 4624/4625 |

## Dynamic (7)

| Section | Show when alert family is… |
|---|---|
| GPO Applied | GPO-tampering, policy-violation, configuration alerts |
| Security Event Summary (24h) | Any host-based alert — quick situational overview |
| USB Device Events | Removable-media policy, USB-exfil, data-theft |
| Scheduled Task Events | Persistence, scheduled-task abuse |
| Processes Running on Host | Malware, fileless, execution, credential-dump |
| Services Created on Host | Persistence, masquerading-service, rogue-service |
| Recent Alerts on Host | Always relevant when device-specific alerts exist (currently constant via wiring; treat as dynamic = show only when ≥1 alert exists) |

## Alert-family decision matrix (DEVICE)

| Alert family | GPO | SecSum | USB | SchedTask | Procs | Svcs | Alerts |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Encoded PowerShell (dev-ws045) | | ✓ | | | ✓ | | ✓ |
| Suspicious Service Install | | ✓ | | ✓ | ✓ | ✓ | ✓ |
| ARP Spoofing / LAN MITM | | ✓ | | | ✓ | | ✓ |
| SAM Database Access | | ✓ | | | ✓ | | ✓ |
| USB Exfil / Data Theft | | ✓ | ✓ | | | | ✓ |
| Scheduled-Task Persistence | | ✓ | | ✓ | ✓ | ✓ | ✓ |
| GPO Tampering | ✓ | ✓ | | | | | ✓ |

---

# 6. PROCESS Entity — 3 constant / 8 dynamic

Process slider opens because the process IS the evidence, so most sections are alert-relevant. But process types vary — a process opened for "encoded PowerShell" is different from one opened for "process tree investigation".

## Constant (3)

| Section | Why universal | Source |
|---|---|---|
| Risk Summary | Process risk score, AMSI detections, C2-connection flag | Aggregates over Sysmon/AMSI/EDR |
| Process Details | Name, PID, parent, command line, user, start time, signature | Sysmon EID 1 / Win Security 4688 |
| Process Tree | Grandparent → parent → this → children | Sysmon EID 1 |

## Dynamic (8)

| Section | Show when alert family is… |
|---|---|
| AMSI Events (Script Content) | PowerShell/script-execution, fileless, AMSI-bypass |
| Registry Modifications | Persistence, AMSI-bypass, defender-disable |
| Network Activity (process-level) | C2, beacon, exfil from process |
| File Operations | Malware drop, ingress-tool-transfer, file-write |
| Child Processes | Malware execution, LOLBin chain, discovery |
| Token Usage (Graph API) | OAuth token / Graph API misuse |
| DLL Loads | DLL-injection, side-loading, reflective-load |
| Process DNS Queries | DNS-tunnel, C2-domain resolution by process |
| Named Pipes | Inter-process injection, beacon-IPC |
| Related Services | Service-creation by process, masquerading |
| Recent Alerts | Always shown if process has fired alerts |

## Alert-family decision matrix (PROCESS)

| Alert family | AMSI | Reg | Net | File | Child | Token | DLL | DNS | Pipes | Svcs | Alerts |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Encoded PowerShell | ✓ | ✓ | ✓ | ✓ | ✓ | | | ✓ | | | ✓ |
| Credential Dump (SAM/LSASS) | | ✓ | | ✓ | | | | | | | ✓ |
| C2 Connection from process | | | ✓ | | | | | ✓ | | | ✓ |
| DLL Injection | | | ✓ | | | | ✓ | | ✓ | | ✓ |
| Service Persistence via process | | ✓ | | ✓ | ✓ | | | | | ✓ | ✓ |

---

# 7. ALERT Entity — 5 constant / 0 dynamic

The alert entity *is* the alert — every section is by definition relevant.

## Constant (5)

| Section | Why universal | Source |
|---|---|---|
| Alert Details | The alert object itself — ID, severity, MITRE tag, rule | `ITSAlertProfileConfigurations` + ES alert |
| Trigger Conditions | What evidence made the alert fire | Rule + alert payload |
| Affected Entities | Which entities the alert implicates | Alert correlation graph |
| Correlated Alerts | Other alerts in the same incident | `ITSAlertCorrelation` |
| Recommendations & Remediation | Verdict + playbooks | LLM + SOAR playbook catalog |

No dynamic sections — the alert slider is intentionally compact and always shows the full alert dossier.

---

# Feasibility Roll-Up (Log360 Cloud)

Every section above is sourced from data the product already collects or can collect via existing collectors. Sources by entity type:

| Entity | Source channels (already ingested in Log360 Cloud) |
|---|---|
| user | Entra SignInLogs, Entra audit, Win Security 4624/4625/4732/4740/4756/4723, Win Sec 7045 + Sysmon EID 1 (host onboarding), M365 UAL, firewall flows, ADAP `ADSUserDetails`, UEBA, `ADSThreatAnalyticsFeeds`, DLP collectors |
| service | Graph API (orgs, apps, CA policies, roles, grants), Entra audit, M365 UAL, Win Security 7045, Sysmon |
| ip | Firewall flow logs (Fortinet/PAN/CP), IDS/IPS, DNS server / Sysmon EID 22, `ADSThreatAnalyticsFeeds`, GeoIP, Entra SignInLogs (clientIP), VPN logs |
| domain | DNS server logs, firewall, `ADSThreatAnalyticsFeeds`, WHOIS/passive-DNS (AI enrichment), IDS |
| device | ADAP `ADSComputerDetails`, Defender, Win Security (full audit), Sysmon, GPO collector, USB events 6416, scheduled-task 4698/4700 |
| process | Sysmon EID 1/3/7/11/12/13/22, AMSI ScriptBlockLogging 4104, Win Security 4688, EDR |
| alert | `ITSAlertProfileConfigurations`, ES alert index, `ITSAlertCorrelation`, ITSF incident framework |

**Sysmon / AMSI / EDR caveat:** the process slider and the device's process/registry/AMSI sections require the customer to enable those audit channels. Log360 Cloud has the agent and ingestion pipeline; the gap is host-side audit configuration. This is a customer-onboarding step, not a product gap.

---

# Implementation Notes

1. **Trigger rules in a table, not code** — `(entity_type, section_id, alert_family_predicate, priority_band)`. Editable without redeploy.
2. **AI layered on top of rules** — rules give deterministic baseline (the matrices above); AI handles edge cases ("looks like APT29 — also surface mailbox-forwarding even though Exchange isn't in the workload tags").
3. **Cache the render-list per alert** — selector runs once when the alert opens, result is stored on the alert document.
4. **Zero-row auto-hide** — if predicate fires but query returns 0 rows, hide the section.
5. **"+ N more sections" chip** — let the analyst force-render the suppressed set; log clicks as feedback to refine trigger rules.
6. **Rationale tooltip per dynamic section** — "Showing because alert family = Encoded PowerShell, which implicates Processes + Service Triggered + Network Activity."

---

# Wiring path for V5

1. Add `dynamicTrigger: { alertFamilies: ['BruteForce', 'PasswordSpray', ...] }` to each section in [entities.js](js/data/entities.js).
2. Add `alertFamily: 'ImpossibleTravel'` (or similar) to each alert entity.
3. Add `_shouldRenderSection(section, alertCtx)` helper in [entity-slider.js](js/modules/entity-slider.js) — constant sections always true; dynamic sections check `section.dynamicTrigger.alertFamilies.includes(alertCtx.alertFamily)`.
4. Filter `tabConfig[entityType]` through the helper before painting.
5. Render "+ N hidden sections" chip at the bottom of the slider.

**Effort:** small. Data is structured, only the gate + family-tagging is missing.
