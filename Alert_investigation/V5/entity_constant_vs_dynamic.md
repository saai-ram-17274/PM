# Entity Slider — Section Visibility Specification

**Log360 Cloud · Alert Investigation V6**
**Document version:** 4.0 · 21 May 2026
**Audience:** Product reviewers, design reviewers, engineering leads
**Companion document:** Entity field-level data mapping (separate spec)

---

## 1. Purpose of this document

When an analyst clicks any node in the Attack Vector graph, an **Entity Slider** opens with a structured dossier of that entity. This document specifies, for each of the seven entity types we support, **which sections render by default and which are deferred until the analyst signals deeper intent**.

It is the source of truth for:

- The default (Baseline) content set of every entity slider.
- The deeper (Enriched) content set unlocked by the *Investigate Entity* action.
- The alert-family-aware pruning of the Enriched set once an entity is investigated.

---

## 2. Design principles

The slider is governed by four principles, applied uniformly across every entity type.

**Principle 1 — Two stages of investment.** Every slider opens in *Baseline* mode, showing only the lightweight, identity-and-recent-signal sections. Heavier content — behavioural analytics, cloud-identity enrichment, threat-intelligence correlation, deep activity windows — is held back until the analyst clicks **Investigate Entity**. This keeps triage fast and proportional to intent: false positives are dismissed at Baseline, real incidents are deepened on demand.

**Principle 2 — One uniform interaction model.** The same Baseline → Investigate → Enriched flow applies to all seven entity types. An analyst who learns the surface on a User entity already knows it for Devices, IP addresses, Domains, Services, Processes, and Alerts.

**Principle 3 — Empty content is invisible.** Tabs whose sections are all hidden (because the entity is not yet investigated, or because the underlying queries returned no data) collapse automatically. The slider never shows an empty tab.

**Principle 4 — Investigated state is explicit and recorded.** Clicking *Investigate Entity* is a deliberate, audited action. The slider header shows an *Investigated* badge once unlocked, and the action is recorded against the alert for shift-handover and post-incident review.

---

## 3. Two-stage gating model

| Stage | Trigger | What renders |
|---|---|---|
| **Baseline** | Slider opens (any entity click) | The curated default section set for that entity type. |
| **Enriched** | Analyst clicks *Investigate Entity* on this specific entity | The full section set for that entity type. |

The gating is per-entity, per-session: investigating User A unlocks User A's Enriched view but does not auto-investigate User B. Every entity in the same investigation can be deepened or left at Baseline independently.

A third stage — **alert-family pruning within Enriched** — sits on top of these two. Once an entity is investigated, the Enriched set is filtered again so that only sections relevant to the alert family that triggered the investigation remain visible. The matrices in the per-entity sections (§4) are the rules that drive this stage. If the alert does not match a known family, the full Enriched set is shown as a safe fallback.

---

## 4. Per-entity content specification

The seven entity types follow the same template. Each entity has:

- A **Baseline** table — the sections shown the moment the slider opens.
- An **Enriched** table — the additional sections unlocked by *Investigate Entity*.
- An **Alert-family pruning matrix** — the rules used to filter the Enriched set further once the entity is investigated.

---

### 4.1 USER entity — 8 Baseline / 10 Enriched

The User slider is the most heavily used entity surface. Baseline covers identity, recent sign-in posture, and account-state changes. Enriched fans out into behavioural analytics, cloud identity, and deep activity windows.

#### Baseline — 8 sections

| Section | Tab | What it shows |
|---|---|---|
| Risk Summary | Overview | The user's standing risk score and the headline indicators behind it. |
| User Details | Overview | Identity attributes — title, department, manager, OU, account status. |
| Login Statistics (7 days) | Risk & Identity | Successful and failed sign-in counts over the last week. |
| Logon Activity | Activity | Recent logon events with source IP, device, and result. |
| Account Lockout History | Account Changes | Recent lockout events on this account. |
| Password Change / Reset History | Account Changes | Password reset and change events. |
| Group Membership Changes | Account Changes | Recent additions or removals from security groups. |
| Recent Alerts | Recent Alerts | Other alerts that name this user, ordered by recency. |

#### Enriched — 10 sections (after Investigate Entity)

| Section | Tab | Why deferred to Enriched |
|---|---|---|
| UEBA Risk Profile | Risk & Identity | Behavioural risk score, last anomaly, and observation flag — only meaningful when the analyst is actively investigating this user. |
| Cloud Identities & Assets | Risk & Identity | Cloud-identity enrichment (UPN, sync source, assigned roles, owned apps). Carries an external API call cost per investigation. |
| Identity Risk Assessment | Risk & Identity | Composite identity-risk view drawn from multiple directory attributes and the AD risk module. |
| Threat Intelligence Context | Risk & Identity | Cross-source correlation between the user and threat-intel feeds. |
| Network Activity (24h) | Activity | 24-hour firewall-flow aggregation — heavy aggregation. |
| Processes | Activity | Process executions attributed to this user; only meaningful for host-side alerts. |
| Service Triggered | Activity | Service-install events triggered by this user. |
| Resource and File Access | Activity | Recent file and resource access from collaboration platforms. |
| Recent Application Access | Activity | OAuth grants and recent application access events. |
| Mailbox Forwarding Rules | Account Changes | Inbox-rule and mailbox-forwarding lookups; only relevant for mailbox-manipulation cases. |

#### Alert-family pruning within Enriched (shipped)

The matrix below is the planned second-stage gate: once the analyst Investigates, only the Enriched sections relevant to the alert family that triggered the investigation remain visible.

| Alert family | Processes | Services | File | Network | Apps | Mailbox | Threat-Intel |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Impossible Travel / Geo-anomaly | | | ✓ | ✓ | ✓ | ✓ | ✓ |
| Brute Force / Password Spray | | | | | | | |
| Account Lockout Anomaly | | | | | | | |
| MFA Fatigue / Bypass | | | | | ✓ | | |
| OAuth Consent / App Governance | | | ✓ | | ✓ | | ✓ |
| Suspicious OAuth Token | | | ✓ | | ✓ | | ✓ |
| Encoded PowerShell / Execution | ✓ | ✓ | ✓ | ✓ | | | ✓ |
| Suspicious Service Install | ✓ | ✓ | | ✓ | | | ✓ |
| C2 / Tor Connection | ✓ | ✓ | | ✓ | | | ✓ |
| SAM / Credential Dump | ✓ | | ✓ | | | | |
| Bulk File Download / Sensitive Access | | | ✓ | ✓ | ✓ | | ✓ |
| Data Exfiltration | ✓ | | ✓ | ✓ | | ✓ | ✓ |
| Mailbox Forwarding to External | | | ✓ | | ✓ | ✓ | |

---

### 4.2 SERVICE entity — 4 Baseline / 13 Enriched

The Service entity is heterogeneous — it covers cloud apps, identity-platform services, OAuth tokens, and on-host services. Baseline is intentionally minimal because what matters varies by service type; Enriched fans out into thirteen sections covering policy, sign-in, file activity, host activity, and correlations.

#### Baseline — 4 sections

| Section | Tab | What it shows |
|---|---|---|
| Risk Summary | Overview | Standing risk for the service and the headline indicators. |
| Service Details | Overview | Service identity — name, type, owner, current state. |
| Service Info | Overview | Extended attributes presented as a key-value reference card. |
| Recent Alerts | Alerts & Response | Other alerts naming this service. |

#### Enriched — 13 sections (after Investigate Entity)

| Section | Tab | Why deferred to Enriched |
|---|---|---|
| OAuth App Consent Grants | Config & Policy | Cloud-identity enrichment — only relevant for OAuth investigations. |
| Conditional Access Policies | Config & Policy | Cloud-identity enrichment. |
| DLP Policies | Config & Policy | DLP policy lookup. |
| Recent Sign-In Audit | Activity | Tenant-scope sign-in lookup — expensive at large tenants. |
| Admin Activity on Service | Activity | Administrative actions taken on the service. |
| File Access Anomaly | Activity | Behavioural scoring over file-access events. |
| Sensitive Files Accessed | Activity | Labelled-file access events. |
| Service Timeline | Activity | Install and lifecycle events; only relevant for on-host services. |
| Network Connections (from service) | Activity | Outbound connections attributed to the service. |
| File Drops & Modifications | Activity | File-system modifications attributed to the service. |
| WMI Events | Activity | WMI subscription and execution events. |
| Related Processes | Activity | Process correlations for the service. |
| Service Triggered | Alerts & Response | Cross-alert correlation by service. |

#### Alert-family pruning within Enriched (shipped)

| Alert family | OAuth | CA Policy | Sign-In | Admin | File | DLP | Timeline | Network | File Drops | WMI | Procs | Svc-Trig |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Impossible Travel (cloud-identity) | | ✓ | ✓ | ✓ | | | | | | | | |
| Suspicious OAuth Token | ✓ | | ✓ | | | | | | | | ✓ | ✓ |
| New App Consent | ✓ | ✓ | | ✓ | | | | | | | | |
| Bulk File Download | | | ✓ | | ✓ | ✓ | | | | | ✓ | |
| Sensitive File Access | | | | | ✓ | ✓ | | | | | | |
| Suspicious Service Install | | | | | | | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Outbound Tor (on-host service) | | | | | | | ✓ | ✓ | | | ✓ | |
| Data Exfiltration | | | | | ✓ | ✓ | | ✓ | | | ✓ | |

---

### 4.3 IP entity — 5 Baseline / 6 Enriched

#### Baseline — 5 sections

| Section | Tab | What it shows |
|---|---|---|
| Risk Summary | Overview | Standing risk for the IP and the headline indicators. |
| IP Details | Overview | Geo, ASN, ownership, current network classification. |
| Associated Users | Overview | Users observed signing in from this IP. |
| Associated Devices | Overview | Devices observed using this IP. |
| Logon Activity | Logon Activity | Sign-in events from this IP. |

#### Enriched — 6 sections (after Investigate Entity)

| Section | Tab | Why deferred to Enriched |
|---|---|---|
| Threat Intelligence | Threat Intel | External reputation lookup — outbound API cost. |
| IDS/IPS Alerts | Threat Intel | IDS signature correlation. |
| Connection History | Connections | Per-flow firewall lookup — heavy aggregation. |
| DNS Query History | Connections | DNS-server log filter scoped to the IP. |
| VPN Session History | Connections | VPN-collector lookup; only relevant for VPN-flagged IPs. |
| Traffic Summary | Connections | 24-hour rolled-up flow statistics. |

#### Alert-family pruning within Enriched (shipped)

| Alert family | Threat-Intel | Connections | DNS | IDS | VPN | Traffic |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Impossible Travel (anonymising IP) | ✓ | ✓ | | | | |
| C2 Connection | ✓ | ✓ | ✓ | ✓ | | ✓ |
| Tor Exit Detected | ✓ | ✓ | | ✓ | | |
| Data Exfiltration | ✓ | ✓ | | | | ✓ |
| ARP Spoofing (internal IP) | | ✓ | | | | |
| Internal IP investigation | | ✓ | | | ✓ | ✓ |
| Port-scan / IDS signature | ✓ | ✓ | | ✓ | | ✓ |

---

### 4.4 DOMAIN entity — 4 Baseline / 7 Enriched

The Domain slider mirrors IP in shape but is one row narrower at Baseline — domain-side sign-in lookups are heavier and are deferred to Enriched.

#### Baseline — 4 sections

| Section | Tab | What it shows |
|---|---|---|
| Risk Summary | Overview | Standing risk for the domain and headline indicators. |
| Domain & IP Details | Overview | Resolved IPs, registrar, hosting, threat-feed flags. |
| Associated Users | Overview | Users observed querying or connecting to this domain. |
| Associated Devices | Overview | Devices observed querying or connecting to this domain. |

#### Enriched — 7 sections (after Investigate Entity)

| Section | Tab | Why deferred to Enriched |
|---|---|---|
| Threat Intelligence | Threat Intel | External reputation, passive-DNS, and beacon-profile enrichment. |
| IDS/IPS Alerts | Threat Intel | IDS signature correlation on the FQDN. |
| Connection History | Connections | Per-flow firewall lookup. |
| DNS Query History | Connections | DNS-server log filter. |
| VPN Session History | Connections | Rare for domain investigations. |
| Traffic Summary | Connections | 24-hour rolled-up flow statistics. |
| Logon Activity | Logon Activity | Sign-in events touching the domain. |

#### Alert-family pruning within Enriched (shipped)

| Alert family | Threat-Intel | Connections | DNS | IDS |
|---|:-:|:-:|:-:|:-:|
| C2 Connection | ✓ | ✓ | ✓ | ✓ |
| Data Exfiltration (external domain) | ✓ | ✓ | ✓ | |
| DNS Tunnel | ✓ | | ✓ | ✓ |
| Newly Registered Domain | ✓ | | ✓ | |

---

### 4.5 DEVICE entity — 6 Baseline / 6 Enriched

#### Baseline — 6 sections

| Section | Tab | What it shows |
|---|---|---|
| Risk Summary | Overview | Standing risk for the device and headline indicators. |
| Device Details | Overview | Hostname, OS, domain, OU, owner, encryption status. |
| Users Logged On | Host Activity | Current and recent interactive sessions. |
| Login Activity | Host Activity | Recent successful and failed logons. |
| Local Account Lifecycle | Device Activity | Local-account create/modify/delete events. |
| Recent Alerts | Alerts & Response | Other alerts naming this device. |

#### Enriched — 6 sections (after Investigate Entity)

| Section | Tab | Why deferred to Enriched |
|---|---|---|
| Agent Status & Health | Overview | Collector health and last sync status. |
| GPO Applied | Overview | Policy-applied lookup. |
| Processes Running on Host | Host Activity | Live and recent process inventory — heavy aggregation. |
| Services Created on Host | Host Activity | Recent service-install events. |
| Scheduled Task Events | Device Activity | Scheduled-task create and modify events. |
| USB Device Events | Device Activity | USB connect / disconnect events. |

#### Alert-family pruning within Enriched (shipped)

| Alert family | GPO | USB | Sched-Task | Procs | Svcs |
|---|:-:|:-:|:-:|:-:|:-:|
| Encoded PowerShell | | | | ✓ | |
| Suspicious Service Install | | | ✓ | ✓ | ✓ |
| ARP Spoofing / LAN MITM | | | | ✓ | |
| SAM Database Access | | | | ✓ | |
| USB Exfil / Data Theft | | ✓ | | | |
| Scheduled-Task Persistence | | | ✓ | ✓ | ✓ |
| GPO Tampering | ✓ | | | | |

---

### 4.6 PROCESS entity — 4 Baseline / 13 Enriched

The Process slider opens only when a process is itself the evidence. Baseline stays minimal — identity and tree context — while everything else (script content, network, file operations, DLLs, child processes) is deferred to Enriched.

#### Baseline — 4 sections

| Section | Tab | What it shows |
|---|---|---|
| Risk Summary | Overview | Standing risk for the process and headline indicators. |
| Process Details | Overview | Name, PID, parent, command line, user, signature. |
| Details | Overview | Extended key-value reference card. |
| Recent Alerts | Overview | Other alerts naming this process. |

#### Enriched — 13 sections (after Investigate Entity)

| Section | Tab | Why deferred to Enriched |
|---|---|---|
| Process Tree | Overview | Grandparent → parent → this → children traversal. |
| Child Processes | Overview | Descendant lookup. |
| Service Triggered | Overview | Service-correlation join. |
| Token Anomaly | Anomalies | Token-usage anomaly — relevant for cloud-identity alerts. |
| AMSI / Script Content | Anomalies | Captured script content. |
| Registry Modifications | Anomalies | Registry create/modify events. |
| Named Pipes | Anomalies | Named-pipe create / connect events. |
| Token Usage | Activity | Token-usage enrichment. |
| Network Activity | Activity | Outbound connections from the process. |
| File Operations | Activity | File-system reads, writes, and deletes. |
| Processes | Activity | Cross-host occurrences of the same process. |
| DLL Loads | Activity | Loaded modules. |
| Process DNS Queries | Activity | DNS resolutions from the process. |

#### Alert-family pruning within Enriched (shipped)

| Alert family | AMSI | Registry | Network | File | Child | Token | DLL | DNS | Pipes | Svc-Trig |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Encoded PowerShell | ✓ | ✓ | ✓ | ✓ | ✓ | | | ✓ | | |
| Credential Dump | | ✓ | | ✓ | | | | | | |
| C2 from process | | | ✓ | | | | | ✓ | | |
| DLL Injection | | | ✓ | | | | ✓ | | ✓ | |
| Service Persistence | | ✓ | | ✓ | ✓ | | | | | ✓ |

---

### 4.7 ALERT entity — 4 Baseline / 4 Enriched

The Alert entity *is* the alert. Baseline shows the dossier of the alert itself; Enriched fans the analyst out into the wider scope — affected entities, correlated alerts, and process evidence.

#### Baseline — 4 sections

| Section | Tab | What it shows |
|---|---|---|
| Alert Details | Overview | Severity, MITRE technique, source rule, timestamp. |
| Trigger Conditions | Overview | The evidence that caused the alert to fire. |
| Details | Overview | Extended key-value reference card. |
| Recent Alerts | Response | Other alerts naming the same source entity. |

#### Enriched — 4 sections (after Investigate Entity)

| Section | Tab | Why deferred to Enriched |
|---|---|---|
| Affected Entities | Scope | Alert-correlation graph traversal. |
| Correlated Alerts | Scope | Correlation join with other recent alerts. |
| Processes | Scope | Process evidence enumeration. |
| Service Triggered | Response | Service-correlation join. |

The *Recommendations & Remediation* card (verdict and suggested playbooks) renders inside the Alert Details area today and is part of the Baseline alert dossier.

#### Alert-family pruning within Enriched (shipped)

The Alert slider already exposes a small Enriched set, and every field on an alert is by definition relevant to that alert. **No further per-family pruning is planned.**

---

## 5. Slider chrome and shared widgets

The following widgets sit around the section content and are constant across every slider open (with a few well-defined exceptions).

| Widget | Where | Behaviour | Skipped for |
|---|---|---|---|
| **Reachability strip** | Top of slider body, above the first section | Pills for related entities, each with a quick-tag micro-action. | Alert and Location entities. |
| **Header tag chips** | Slider header, right of the title | Current tag set for the entity, with click-to-edit. | Alert entity. |
| **Actions ▾ dropdown** | Slider header, immediately before *Hide Details* | Full playbook catalog scoped to this entity type. | — |
| **Action card** | Pinned to the top of the Overview body section | In-slider rendering of the same playbook catalog with full descriptions and decision metadata. | Alert entity (uses the dropdown only). |
| **Action card meta strip** | Inside every playbook row | Three plain-language facts: *Blast radius*, *Time to complete*, *Can undo?* The time-to-complete chip is hidden when the action is instant, to keep the strip free of noise. | — |
| **Pre-filter applied banner** | Inside the action drawer when an Investigate-verb playbook is launched | States the filter and time window the next view will be pre-narrowed to. | All non-Investigate verbs. |

When the same slider is reused for an edge-relation popup, entity-scoped widgets (reachability strip, header tag chips, in-slider action card) are removed because they do not apply to a relationship.

---

## 6. Playbook catalog by entity type

Playbooks available from the **Actions ▾** dropdown and the in-slider Action card. The catalog is fixed per entity type. Actions marked 🔒 require an explicit confirm dialog because their blast radius is High.

| Entity | Investigate (no state change) | Disrupt (breaks foothold) | Contain (stops the bleed) | Hygiene (metadata) |
|---|---|---|---|---|
| **User** | Entity timeline · Mark as compromised · Investigate entity | Force password reset · Revoke active tokens | Disable account 🔒 | Notify line manager · Manage tags |
| **Device** | Entity timeline · Collect forensics · Investigate entity | Run AV scan · Kill suspicious process | Isolate device 🔒 | Manage tags |
| **IP** | Entity timeline · Hunt past logins from IP · Investigate entity | — | Block IP at firewall 🔒 · Block ASN 🔒 | Add to threat-intel feed · Manage tags |
| **Service** | Entity timeline · Investigate entity | Revoke OAuth consent | Block app tenant-wide 🔒 | Manage tags |
| **Process** | Entity timeline · Investigate entity | Stop process | Quarantine parent file 🔒 · Add hash to blocklist 🔒 | Manage tags |
| **Domain** | Entity timeline · Hunt past DNS lookups · Investigate entity | DNS sinkhole 🔒 | Block domain at proxy 🔒 | Add to threat-intel feed · Manage tags |
| **Alert** | Entity timeline · Investigate entity | Run response playbook | — | Assign to (analyst picker) · Close as false positive |

*Investigate Entity* is the dedicated gating action that moves the slider from Baseline to Enriched.

### Verb taxonomy

The four verbs drive the colour of the action chip and the wording of the confirm dialog, so the analyst can recognise what kind of action they are about to take without reading the label.

| Verb | Meaning |
|---|---|
| **Contain** | Stops the bleed. Always reversible by design. |
| **Disrupt** | Breaks the attacker's current foothold. |
| **Investigate** | Pivot for more data. No state change. |
| **Hygiene** | Metadata or bookkeeping. No security impact. |

---

## 7. Alert-level additions on the Attack Vector tab

A small set of alert-scope widgets sit on the Attack Vector tab itself, alongside the slider.

| Widget | Behaviour | When it appears |
|---|---|---|
| **Assignee picker** | Searchable list of SOC analysts with *Assign to self* and *Clear* shortcuts. | Constant on every alert. |
| **Choke-point analyser** | Lazy-loaded analysis with explicit *Analyze* / *Analyze again* states; flags itself stale when the underlying graph drifts. | Ready once the graph has enough nodes; runs on opt-in. |
| **Preview top workflow** | One-click peek at the most-likely lateral-movement workflow rooted at a choke-point entity. | Only when a choke-point has a mapped workflow. |
| **Workflow overlay** | Full-page step-by-step rendering of the selected workflow. | Only when *Preview top workflow* is invoked. |

---

## 8. Roadmap

| Stage | Status | Description |
|---|---|---|
| **Stage 1 — Baseline vs Enriched gating** | Shipped (V6) | The two-stage slider gating described in §3, applied uniformly across all seven entity types. |
| **Stage 2 — Alert-family pruning within Enriched** | Shipped (V6) | Once an entity is investigated, the Enriched set is pruned further so that only sections relevant to the alert family that triggered the investigation remain visible. The matrices in §4 are the per-entity rules. |
| **Stage 3 — Adaptive prioritisation** | Exploratory | Layer behavioural-analytics signals on top of the rule-based pruning to surface or suppress sections based on observed analyst-utility patterns. |

Stage 2 behaviour as shipped:

1. The per-entity matrices are encoded as data, editable without redeploy.
2. The alert family is derived from the alert that opened the investigation; the family then selects the visible Enriched sections for each entity type.
3. A section is suppressed if its alert-family rule does not fire **or** its underlying query returns zero rows.
4. If the alert does not match any family in the taxonomy, the full Enriched set is shown as a safe fallback rather than an empty view.
5. Every visible Enriched section carries a tooltip explaining the alert family that caused it to be shown.

---

## 9. Data sourcing summary

Every section in this specification is sourced from data Log360 Cloud already collects through existing collectors. No new ingestion is required for any entity in any state.

| Entity | Primary source channels |
|---|---|
| User | Cloud sign-in logs, identity audit logs, on-prem security logs, mailbox/audit logs, firewall flows, directory attributes, behavioural analytics, threat-intel feeds. |
| Service | Cloud-identity and audit APIs, mailbox/audit logs, on-host security logs. |
| IP | Firewall flow logs, intrusion-detection logs, DNS-server logs, threat-intel feeds, geo-IP, sign-in logs, VPN logs. |
| Domain | DNS-server logs, firewall logs, threat-intel feeds, registration and passive-DNS enrichment, intrusion-detection logs. |
| Device | Directory attributes, endpoint protection, on-host security logs, host telemetry, policy and lifecycle collectors. |
| Process | Host telemetry (process, network, registry, file, module, DNS), script-block logging, endpoint-protection signals. |
| Alert | Alert profile catalog, alert index, alert-correlation framework, incident framework. |

A small number of Process and Device sections depend on host-side audit channels (extended host telemetry, script-block logging, endpoint protection) being enabled on the customer's endpoints. The ingestion pipeline supports them today; turning them on is a customer-onboarding step rather than a product gap.
