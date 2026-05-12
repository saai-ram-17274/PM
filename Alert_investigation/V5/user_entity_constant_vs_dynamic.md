# User Entity Slider — Constant vs Dynamic Sections

> **Date:** 12 May 2026
> **Scope:** The `user` entity type in V5 (`user-m-henderson`, `user-admin`). Splits its 17 sections into **CONSTANT** (always rendered for every user — identity facts + baseline risk posture) vs **DYNAMIC** (only rendered when the alert chain implicates that data domain).
> **Why this matters:** rendering every section for every alert is noisy, slow, and exposes irrelevant data. The dynamic-set should be **AI-selected from the alert's MITRE techniques + affected workloads + correlated entities**.
> **Companion to:** [`entity_slider_feasibility.md`](entity_slider_feasibility.md) (per-field feasibility) and [`entity_data_mapping.md`](entity_data_mapping.md) (backend mapping).

---

## TL;DR

| Bucket | Section count | Render rule |
|---|---:|---|
| **CONSTANT — always shown** | 7 | Identity + baseline risk posture. Renders the same for any user, any alert. |
| **DYNAMIC — alert-driven, AI-selected** | 10 | Renders only when the alert's MITRE technique / affected workload / correlated entity matches the section's trigger condition. |

Result: an alert that has nothing to do with SharePoint should not show "Recent Application Access" or "DLP Incidents" tabs. An alert with no MFA bypass should not show "Mailbox Forwarding Rules". This is what makes the slider feel intelligent rather than encyclopedic.

---

## CONSTANT sections (7) — identity + baseline posture

These render for **every** user entity regardless of which alert opened the slider. They answer the analyst's first question — "who is this person?" — and never change shape based on the attack chain.

| Section | Why constant | Source today |
|---|---|---|
| **1. Risk Summary** (`riskSummary`) | The risk score, severity, dwell time, first/last seen are universal "is this account hot right now?" signals. Always needed. | `ITSEntityRiskScoreDetails` + ES alert index `min(@timestamp)` |
| **2. User Details** (`usersDetails`) | Display name, SAM, UPN, email, job title, department, manager, OU, account-created, account-status, primary group. Pure AD identity card. | ADAP `ADSUserDetails` |
| **3. UEBA Risk Profile** (`uebaProfile`) | Current UEBA score and account-type classification. Constant baseline regardless of alert. | UEBA scorer |
| **4. Login Statistics (7d)** (`loginStatistics`) | Total logins, success/fail ratio, unique IPs, off-hours count. The "baseline of how this user normally signs in" — needed for **every** alert as the reference point. | ES agg on sign-in events |
| **5. Cloud Identities & Assets** (`cloudIdentities`) | Azure AD UPN, license, conditional access policies, roles. Static identity-system facts. | Graph API `users`, `subscribedSkus`, `conditionalAccess/policies` |
| **6. Identity Risk Assessment** (`identityRisk`) | Password age, group memberships, privileged groups, stale-account flag. Static account-hygiene posture. | ADAP attributes + Risk Module |
| **7. Recent Alerts** (`recentAlerts`) | Last N alerts on this user — always relevant context, regardless of current alert. | Alert search keyed by user |

**Constant set covers:** *"Who is this user, what's their normal pattern, and what other alerts have they collected?"*

---

## DYNAMIC sections (10) — alert-driven

These render only when the alert's signature implies the data domain is relevant. The **AI selector** reads the alert payload (MITRE technique IDs, `WORKLOAD_S` enumeration, correlated entity types, IOC categories) and emits a render-list.

### Section-by-section trigger conditions

| # | Section | Show when… | Source / current-alert match |
|---:|---|---|---|
| 1 | **Logon Activity** (`logonActivity`) | Alert involves any authentication event — sign-in anomaly, failed-logon spike, off-hours logon, brute-force, impossible-travel | MITRE tactic = `Initial Access`, `Credential Access`, `Defense Evasion` → T1078.*, T1110.*, T1556.*; OR alert source = AAD SignInLogs / Win Security 4624/4625 |
| 2 | **Processes** (`processes`) | Alert involves user-launched processes — encoded PowerShell, suspicious parent-child, LOLBins, credential dumping | MITRE = `Execution` (T1059.*) / `Credential Access` (T1003.*); requires Sysmon EID 1 ingested for that host |
| 3 | **Service Triggered** (`serviceTriggered`) | Alert involves service install/modification — masquerading service, persistence | MITRE = `Persistence` (T1543.003); Win Security 7045 events present in correlation window |
| 4 | **Resource & File Access** (`resourceFileAccess`) | Alert involves file operations — SharePoint download, sensitive-file access, DLP violation | `WORKLOAD_S` ∈ {SharePoint, OneDrive, ExchangeFiles}; MITRE = `Collection` (T1213.*) / `Exfiltration` (T1041, T1567.*) |
| 5 | **Account Lockouts** (`accountLockouts`) | Alert involves authentication failures — brute force, password-spray, lockout-anomaly | Win Security 4740 events on user in the last 24 h, OR alert family = lockout/brute-force |
| 6 | **Password Change/Reset History** (`passwordHistory`) | Alert involves credential operations — password reset by non-self, password-spray, "DCSync" | MITRE = `Credential Access` (T1003.*) / `Persistence` (T1098.001); OR Entra audit "Reset password"/"Change user password" on the user |
| 7 | **Group Membership Changes** (`groupMembershipChanges`) | Alert involves privilege/permission changes — group-add, role-elevation | MITRE = `Privilege Escalation` (T1098.*); Win Security 4732/4756 or Entra `Add member to group` in window |
| 8 | **Mailbox Forwarding Rules** (`mailboxForwarding`) | Alert involves mailbox manipulation — inbox-rule abuse, mail-flow tampering | `WORKLOAD_S` = Exchange; MITRE = `Collection` (T1114.003); Exchange audit `New-InboxRule`/`Set-InboxRule` in window |
| 9 | **Recent Application Access** (`recentAppAccess`) | Alert involves OAuth grants / app consent / unverified-publisher / SaaS access | MITRE = T1550.001 / T1098.003; Entra audit `Consent to application` in window |
| 10 | **Network Activity (24h)** (`networkActivity`) | Alert involves outbound traffic — C2, Tor, exfiltration, beaconing | MITRE = `Command & Control` (T1071.*) / `Exfiltration` (T1041); firewall flow or Sysmon EID 3 (or DNS) referencing user's host |
| 11 | **Compliance & Regulatory Impact** (`complianceImpact`) | Alert involves regulated data — PII/PHI/PCI access, GDPR-scope EU user, financial data | DLP policy hit OR sensitivity label `Confidential/Highly Confidential` OR user `country` ∈ EU AND alert tactic includes `Collection`/`Exfiltration` |
| 12 | **Threat Intelligence Context** (`threatIntelContext`) | Alert involves external IOC — malicious IP/domain/hash/Tor/known-bad-app | At least one IOC entity present in the alert chain (matches `ADSThreatAnalyticsFeeds` feed) |
| 13 | **DLP Incidents** (`dlpIncidents`) | Alert involves data-classification policy violation | M365 DLP event present, OR external DLP collector event present |

> **Note on numbering:** the section file has 10 dynamic sections; the table above expands two of them (compliance impact + threat intel + DLP) that the JS treats as separate sections. The render-rule count is 13 individual data domains.

### Default fallback when no trigger fires

If the alert chain doesn't match any dynamic-section trigger, render **only the 7 constant sections plus "Recent Alerts"**. Don't show empty-state placeholders for the 10 dynamic ones — that's what made the prior "Privileged Role Assignment Changes" tile noise (just removed in `e0af6a2`).

---

## How the AI selector should work

A single deterministic function, **invoked once when the slider opens**:

```text
INPUT
  alert:
    mitreTechniques: ['T1078.004', 'T1550.001', 'T1098.003', 'T1213.002', 'T1041']
    workloads:       ['AzureActiveDirectory', 'SharePoint']
    iocEntities:     ['ip-tor', 'svc-oauth', 'domain-c2']
    correlatedAlerts: [3 IDs]
  user: m.henderson

OUTPUT
  constantSections:  [7 — always the same set]
  dynamicSections:   [subset of 10, in priority order]
  rationale:         { section_id: 'matched because T1213.002 → SharePoint workload', … }
```

**Priority ordering** (so the most relevant evidence is above the fold):

1. Sections whose MITRE match is the **highest-severity** technique in the alert (T1003, T1041 outrank T1087)
2. Sections whose source is **already in the alert's `affectedEntities`** (if the alert lists `svc-sharepoint` as affected, push `resourceFileAccess` to the top)
3. Sections with **freshest evidence** (event timestamps in the alert window)
4. Sections with **most rows** (a section with 142 file-access events is more useful than one with 1)

The rationale field is what surfaces under each section as "**Showing this because** the alert is tagged `T1213.002 (SharePoint)` and the user accessed 142 SharePoint files in the correlation window."

---

## Worked example — current demo alert (Impossible Travel)

| Section | Type | Render? | Reason |
|---|:-:|:-:|---|
| Risk Summary | C | ✅ | Always |
| User Details | C | ✅ | Always |
| UEBA Risk Profile | C | ✅ | Always |
| Login Statistics 7d | C | ✅ | Always |
| Cloud Identities | C | ✅ | Always |
| Identity Risk | C | ✅ | Always |
| Recent Alerts | C | ✅ | Always |
| Logon Activity | D | ✅ | Alert is T1078.004 — direct match |
| Recent Application Access | D | ✅ | Alert is T1098.003 + Entra consent event in window |
| Mailbox Forwarding Rules | D | ✅ | Exchange `New-InboxRule` from attacker IP in window |
| Group Membership Changes | D | ✅ | T1098.003 + Entra `Add member to group` event in window |
| Resource & File Access | D | ✅ | T1213.002 + `WORKLOAD_S=SharePoint` |
| DLP Incidents | D | ✅ | DLP policy hit on `HR_Benefits_*.xlsx` |
| Network Activity (24h) | D | ✅ | C2 firewall flow + Tor IOC in chain |
| Compliance Impact | D | ✅ | EU employee PII in exfiltrated files |
| Threat Intel Context | D | ✅ | `ip-tor` + `domain-c2` in IOC list |
| Processes | D | ✅ | T1059.001 (encoded PowerShell) in correlated alert |
| Service Triggered | D | ✅ | T1543.003 in correlated alert |
| Account Lockouts | D | ❌ | No lockout events in window |
| Password Change/Reset History | D | ❌ | No password-change events in window (last reset 25 Nov 2025, well before alert) |

**Outcome:** 7 constant + 10 of 12 dynamic = **17 sections shown**, 2 hidden. Each dynamic section carries a tooltip like *"Showing because alert is tagged T1213.002 and 142 SharePoint files accessed in window."*

## Worked example — hypothetical alert (account-lockout brute force only)

Same user, but an alert that's just "100 failed logons → lockout" with no C2, no SharePoint, no OAuth:

| Section | Render? |
|---|:-:|
| 7 constant sections | ✅ |
| Logon Activity | ✅ (T1110.*) |
| Account Lockouts | ✅ (4740 events) |
| Password Change/Reset History | ✅ (T1110 → credential access tactic) |
| Group Membership Changes | ❌ |
| Mailbox Forwarding Rules | ❌ |
| Recent Application Access | ❌ |
| Resource & File Access | ❌ |
| DLP Incidents | ❌ |
| Network Activity (24h) | ❌ |
| Compliance Impact | ❌ |
| Threat Intel Context | ❌ (no external IOC) |
| Processes | ❌ |
| Service Triggered | ❌ |

**Outcome:** 10 sections shown instead of 17 — the slider is half the height, and every section visible is justified by the alert. This is the "intelligence" the dynamic selector buys.

---

## Implementation notes for engineering

1. **Trigger rules live in a table**, not in code. Each row: `(section_id, match_predicate, priority_band, source_log_check)`. Editable without redeploy.
2. **AI selector is layered on top, not replacing rules**. Rules give deterministic baseline; AI handles the edge cases ("this looks like APT29 because of X+Y+Z, also surface mailbox-forwarding even though Exchange isn't in the workload tags").
3. **Cache the render-list per alert**. The selector runs once when the alert opens, result is stored on the alert document — fast to re-render on slider toggle.
4. **Track suppression**. If the analyst manually opens a hidden section, log it as feedback to refine the trigger rule.
5. **Never empty-state a dynamic section**. If the predicate fires but the query returns 0 rows, hide it. Empty cards are worse than missing cards.

---

## What this looks like in the V5 prototype today

The V5 slider currently renders **all 17 sections unconditionally**. That's fine for a demo because every section has hand-crafted data. For the production version, the dynamic-vs-constant split above is the contract between the alert engine and the slider renderer.

**Action items if we wanted to wire this into V5 now:**

1. Add a `dynamicTrigger` field to each section in `js/data/entities.js` (e.g. `dynamicTrigger: { mitre: ['T1213.*'], workload: ['SharePoint'] }`).
2. Add a `_shouldRenderSection(section, alertCtx)` helper in `js/modules/entity-slider.js` that returns true for constant sections always, and evaluates the predicate for dynamic ones.
3. In the slider renderer, filter `tabConfig.user.sections` through that helper before painting.
4. Show a "+ N hidden sections" chip at the bottom that lets the analyst force-render the suppressed set.

Estimated effort: small — the data is already structured, only the gate is missing.
