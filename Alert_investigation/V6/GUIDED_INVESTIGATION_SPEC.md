# Guided Investigation — Go Hunt with Zia ✦
## Requirement Specification · Sample I/O · Supported Operations

---

## 1. Overview

**Go Hunt with Zia** is a contextual, guided investigation panel embedded inside the Attack Vector Explorer. When a SOC analyst right-clicks any node on the attack graph, they can open a Zia chat panel scoped to that specific entity. The panel auto-loads relevant intelligence and lets the analyst ask follow-up questions using natural language or one-click suggestion chips.

**Goal:** Reduce mean-time-to-investigate (MTTI) by surfacing the most relevant security data for a given entity without the analyst needing to navigate to multiple product views or run manual queries.

---

## 3. Supported Entity Types

The panel supports **6 entity types**, each with its own auto-preview and suggestion set:

| Entity Type | Icon | Examples |
|-------------|------|---------|
| `user` | 👤 | Domain accounts, cloud identities |
| `device` | 💻 | Workstations, servers, endpoints |
| `ip` | 🌐 | External IPs, internal hosts |
| `service` | ⚙ | Cloud services, Azure AD, SharePoint |
| `process` | 🔧 | Executables, scripts, child processes |
| `alert` | 🔔 | Triggered alert nodes on the graph |

---

## 4. Panel Behaviour on Open

When the panel opens, **Entity Preview Cards** are auto-generated before the analyst types anything.

### 4a. Entity Preview Cards
The same four cards appear for every entity type, giving the analyst a consistent starting point regardless of what they right-clicked:

| Card | Description |
|------|-------------|
| 🛡 Risk Summary | Risk score, severity, and status |
| 🚨 Recent Alerts | Latest triggered alerts for this entity |
| 🔐 Recent Logon Activity | Most recent sign-in / authentication events |
| 🌐 Network Activity | Recent network connections |

> **Exception:** Alert entities show Alert Details · Trigger Conditions · Affected Entities instead.

---

## 5. Suggestion Chips

The same **7 chips** appear for every entity type, so the analyst always knows where to start regardless of what they right-clicked. All chips always appear (none are conditional).

| Chip | Routes to |
|------|-----------|
| 🚨 List triggered alerts | Recent alerts for this entity |
| 🔐 Show logon activity | Logon / sign-in timeline |
| 🌐 Show network connections | Network activity / connection history |
| 📊 UEBA risk profile | Risk score, severity, anomaly metrics |
| 🛡 Is this entity malicious? | Threat intelligence feed lookup |
| 📋 Show audit logs | Audit log events |
| 🛠 What should I do? | Remediation guide + Zia mitigation steps |

---

## 6. Supported Chat Operations — Full List

The following table lists every question the analyst can ask (by chip or free text), the data source, and a sample response.

### 6.1 Remediation

| Input (chip or free text) | Data Source | Sample Output |
|--------------------------|-------------|---------------|
| "What should I do?" | `sections.remediationGuide` + `ALERT_DETAIL.mitigationSteps` + `recommendations` | Remediation card with numbered steps, mitigation bullets from Zia alert analysis, and recommendation cards |

**Sample Input:**
> What should I do?

**Sample Output:**
```
🛠 Recommended Actions
✅ Disable user account immediately
✅ Revoke all active sessions (Azure AD > Revoke sign-in sessions)
✅ Reset credentials and enforce MFA re-registration
✨ Block external email forwarding at transport rule level
✨ Review and revoke OAuth grants for third-party apps
⚡ Isolate affected workstation CORP-WS-045 from network
```

---

### 6.2 Alert-Specific Operations

| Input | Data Source | Sample Output |
|-------|-------------|---------------|
| "Why did this alert fire?" | `sections.triggerConditions` | List of trigger conditions with values |
| "What entities are at immediate risk?" / "What entities are affected?" | `sections.affectedEntities` | List of impacted entities with type labels |
| "Are there related alerts in this campaign?" / "Show correlated alerts" | `sections.correlatedAlerts` | List of correlated alert names and severities |
| "Summarize this incident" | `ALERT_DETAIL.investSummary` + `keyFindings` | Zia bridge card with full AI summary (if investigation was run) |

**Sample — "Why did this alert fire?"**
> Input: `Why did this alert fire?`
```
⚡ Trigger Conditions
🟠 Impossible Travel      Distance: 8,700 km in 3h 20min
🟠 Logon Risk Level       High — Azure AD Identity Protection
🟠 MFA Status             MFA not challenged (trusted location bypass)
```

**Sample — "Summarize this incident"**
> Input: `Summarize this incident`
```
✦ Incident Summary
"Credential compromise and data exfiltration attempt detected. User
 m.henderson's account was accessed from Bucharest, Romania — a location
 inconsistent with their normal pattern (New York, NY). Simultaneous
 mailbox forwarding rule was created, suggesting intentional exfiltration
 setup. Three correlated alerts fired within a 5-minute window."

Key Findings:
🔴 Impossible Travel Detected
🔴 Mailbox Forwarding Rule Created
🔴 Suspicious OAuth Token
```

---

### 6.3 User-Specific Operations

| Input | Data Source | Sample Output |
|-------|-------------|---------------|
| "Is mailbox forwarding active?" | `sections.mailboxForwarding` | Warning card listing forwarding rules with destinations |
| "Are credentials exposed on dark web?" | `sections.darkWebExposure` | Warning card with breach records |
| "What privileged resources can they reach?" | `sections.privilegedSurface` / `effectiveGroups` | List of privileged roles and resource access |
| "What groups propagate their access?" | `sections.groupMembershipChanges` | Group change history with add/remove status |
| "Which devices has this user accessed?" | `sections.logonActivity` | Logon activity list showing target hosts |
| "List triggered alerts" | `sections.recentAlerts` | Alert list with names and severities |

**Sample — "Is mailbox forwarding active?"**
> Input: `Is mailbox forwarding active?`
```
⚠ 2 forwarding rules detected — common data exfiltration technique.
📨 Mailbox Forwarding Rules
🔴 Forward To      attacker@protonmail.com
🔴 Rule Created    11 May 2026 09:41:10
```

**Sample — "Are credentials exposed on dark web?"**
> Input: `Are credentials exposed on dark web?`
```
🌑 1 dark web record found — credentials may be compromised.
🌑 Dark Web Exposure
🔴 Source         BreachForums — May 2026
🔴 Data Type      Email + password hash (NTLM)
```

---

### 6.4 Device-Specific Operations

| Input | Data Source | Sample Output |
|-------|-------------|---------------|
| "What processes could spread laterally?" | `sections.processesOnHost` | Process list, suspicious ones highlighted red |
| "Any persistence mechanisms?" / "Show scheduled tasks" | `sections.scheduledTasks` | Task list, obfuscated commands highlighted red |
| "USB-based data exfiltration risk?" | `sections.usbDeviceEvents` | USB event list (plug/eject events) |
| "What network neighbours are at risk?" | `sections.networkActivity` / `connectionHistory` | Connection list |
| "Active exploitable vulnerabilities?" | `sections.vulnerabilities` | CVE list with severity |

**Sample — "What processes could spread laterally?"**
> Input: `What processes could spread laterally?`
```
⚙ 5 processes active on this host
🔴 powershell.exe   PID 4821 (suspicious)
🔴 mshta.exe        PID 3301 (suspicious)
🔵 svchost.exe      PID 812
🔵 lsass.exe        PID 624
🔵 explorer.exe     PID 2048
```

---

### 6.5 IP-Specific Operations

| Input | Data Source | Sample Output |
|-------|-------------|---------------|
| "Which internal hosts are communicating here?" | `sections.associatedUsers` + `associatedDevices` | Combined user and device list |
| "Any lateral movement detected? (IDS/IPS)" | `sections.idsAlerts` | IDS alert list with rule names |
| "What's the firewall exposure?" | `sections.firewallSummary` | Block/allow breakdown |
| "DNS-based C2 activity?" | `sections.dnsHistory` | DNS query list, suspicious domains highlighted |
| "Is this IP in threat intelligence feeds?" | `sections.threatIntelligence` / IP reputation | Reputation verdict with feed name |

**Sample — "Which internal hosts are communicating here?"**
> Input: `Which internal hosts are communicating here?`
```
5 entity connections linked to this IP.
👤 Associated Users
🔵 m.henderson     Last seen: 11 May 09:38
🔵 svc-azure-ad    Last seen: 11 May 09:40
💻 Associated Devices
🟠 CORP-WS-045     Last connection: 11 May 09:38
🟠 CORP-SRV-01     Last connection: 11 May 09:39
```

---

### 6.6 Process-Specific Operations

| Input | Data Source | Sample Output |
|-------|-------------|---------------|
| "What did this process spawn?" | `sections.processTree` / `childProcesses` | Parent → child process chain |
| "What files were touched? (data staging)" | `sections.fileOperations` | File create/write/delete events |
| "Persistence via registry modifications?" | `sections.registryModifications` | Registry key changes, run keys highlighted |
| "Any AV/AMSI detections?" | `sections.amsiEvents` | Detection events with verdict |
| "Network connections (C2 beaconing)?" | `sections.networkActivity` | Outbound connections list |

**Sample — "What did this process spawn?"**
> Input: `What did this process spawn?`
```
🌲 Process Tree
🔴 cmd.exe (PID 3120)         parent: explorer.exe
🔴 powershell.exe (PID 4821)  parent: cmd.exe
🔴 mshta.exe (PID 3301)       parent: powershell.exe
```

---

### 6.7 Service-Specific Operations

| Input | Data Source | Sample Output |
|-------|-------------|---------------|
| "What data can be reached via OAuth?" | `sections.oauthConsentGrants` / `conditionalAccess` | OAuth permission list, high-risk scopes highlighted |
| "What admin actions were performed?" | `sections.adminActivity` | Admin action log |
| "What users/devices authenticate here?" | `sections.signInAudit` | Sign-in audit list |
| "Show full audit trail" | `sections.auditLogs` / `signInAudit` / `adminActivity` | Combined audit events |

**Sample — "What data can be reached via OAuth?"**
> Input: `What data can be reached via OAuth?`
```
🔐 3 OAuth permissions for this service.
🔐 OAuth Consent Grants
🔴 Mail.ReadWrite         Read and write all mailboxes (high risk)
🔴 Files.ReadWrite.All    Read and write all files (high risk)
🟠 User.Read              Read user profile
```

---

### 6.8 General Operations (all entity types)

| Input | Data Source | Sample Output |
|-------|-------------|---------------|
| "Show failed login attempts" | `sections.logonActivity` (filtered for failures) | Filtered logon list, only failures |
| "Show logon activity" / "Sign-in history" | `sections.logonActivity` | Full logon timeline |
| "UEBA risk profile" / "Show risk" | `sections.riskSummary` + `uebaProfile` | Risk score card with severity and anomaly metrics |
| "Show network connections" | `sections.networkActivity` / `connectionHistory` | Network activity list |
| "Show vulnerabilities" | `sections.vulnerabilities` | CVE list |
| "Show blast radius" | `sections.blastRadius` | Opens blast radius graph, shows reachable node count |
| "Is this malicious?" / "Threat intel" | `sections.threatIntelligence` | Threat feed reputation verdict |
| "Show misconfigurations" | `sections.misconfigurations` / `gpoApplied` | Misconfig list |
| "Show audit logs" | `sections.auditLogs` | Audit event list |
| Unrecognised input | — | Fallback message with top 3 relevant chip suggestions |

---

## 7. Response Format

Every bot response consists of:

1. **Text message** — 1–2 sentence plain-English summary (e.g. *"Found 3 mailbox forwarding rules — common data exfiltration technique."*)
2. **Data card** (optional) — structured HTML card with one of these layouts:
   - **List rows** — coloured dot · label · value
   - **KV grid** — key / value pairs in 2-column grid
   - **Zia bridge card** — dark indigo card showing AI-generated alert summary
   - **Warning card** — red-bordered card for high-risk findings (mailbox forwarding, dark web)
   - **Remediation card** — green-bordered card with action steps

**Dot colour semantics:**

| Colour | Meaning |
|--------|---------|
| 🔴 Red | Malicious / critical / failure |
| 🟠 Orange | Suspicious / medium risk |
| 🔵 Blue | Informational / normal |
| 🟢 Green | Clean / success / remediation step |

---

## 8. Zia Alert Analysis Bridge

When a SOC analyst has run **Start Investigation** on the alert detail panel, the Zia chat panel automatically bridges the AI-generated analysis:

- **On panel open:** First bot message shows `investSummary` + top 3 `keyFindings` from the alert
- **"Summarize this incident" chip:** Always shows the full summary + all key findings
- **"What should I do?" chip:** Merges `remediationGuide` (entity-level) + `mitigationSteps` + `recommendations` (alert-level) into a single unified action list

If the investigation has **not** been run yet, "Summarize this incident" shows a prompt to run it first.

---

## 9. Data Sources (current prototype)

All data in the prototype is served from `js/data/entities.js` (static mock data). In production, each operation maps to a real data source:

| Operation | Production Data Source |
|-----------|----------------------|
| Logon activity | Windows Security Event Log (Event 4624/4625) via AD Audit Plus |
| Mailbox forwarding | Exchange / M365 audit log (Set-Mailbox, New-InboxRule) |
| Dark web exposure | Dark Web Monitor threat feed |
| Privileged access | AD User Groups + Azure AD role assignments |
| Process tree | Endpoint DLP / EDR telemetry |
| Registry modifications | Endpoint DLP / Windows Sysmon (Event 13) |
| AMSI / AV detections | Windows Defender / AV integration feed |
| IDS/IPS alerts | Firewall Analyzer / ManageEngine OpManager |
| DNS history | DNS server logs |
| OAuth grants | Azure AD app consent audit |
| Threat intelligence | Log360 Threat Intelligence feed |
| Blast radius | Log360 internal graph traversal API |

---

## 10. Out of Scope (current version)

- Free-form log search / ZCQL queries entered in the chat
- Creating or modifying alerts from the panel
- Cross-entity pivoting (e.g. "show me all users on this device") — follow-up via Entity Details panel
- Real-time streaming responses
- Chat history persistence across sessions
