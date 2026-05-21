# Competitor "Attack View" Comparison — V6 Attack Vector

> **Purpose:** Position Log360 Cloud's entity sliders (👤 User · 🖥️ Device · 🌐 IP · 📍 Location) against the three competitor patterns customers will mention in evaluations: **graph-style Attack Path Management**, **identity attack-path mapping**, and **per-incident causality narratives** — and define **what new "attack vector" features V6 should ship** to close the most credible gaps.
>
> **Scope note:** V5 shipped the four entity sliders (post-incident drill-down — Pattern C). **V6 adds an "Attack Vector" capability** layered on the same AD-sync + Win-Sec baseline; see §4 below.
>
> **Baseline assumed for Log360 Cloud:** AD directory sync + Windows Security Event Log forwarding only — no firewall syslog, no M365/Azure AD audit, no Sysmon, no EDR, no TI feed. See [V5/baseline_entity_inventory.md](../V5/baseline_entity_inventory.md).
>
> **Sourcing rules applied:** every competitor claim has a vendor URL + a recency tag; screenshots embedded where the vendor publishes them. Claims I could not re-verify in this session are tagged `🟡 unverified — vendor wording from training data, may be outdated`.

---

## TL;DR — three different things customers call "attack view"

| Pattern | Question it answers | Representative product | Closest analog in V5 today | V6 plan |
|---|---|---|---|---|
| **A. Attack Path Management (APM)** | "If an attacker landed here, where could they reach?" — **predictive, graph-based, before an attack** | Microsoft Security Exposure Management; CrowdStrike Falcon APA; XM Cyber | ❌ No graph. `riskSummary` lists *what already happened*. | 🟢 Ship **2-hop reachability strip** + **cut-options table** — non-graph, data we already have (§4.A, §4.B) |
| **B. Identity Attack Path** | "Which AD/Entra principals could escalate to Domain Admin?" — **identity-graph specific** | SpecterOps BloodHound Enterprise | ❌ AD-sync ingests `APFDiscADUserDetails` / `APFDiscADGroupDetails` but no path computation. | 🟡 Feasibility spike: compute `MemberOf*` closure over existing AD tables (§4.C) |
| **C. Causality / Attack Story** | "For this alert, what process / user / IP chain led here?" — **reactive, per-incident, after detection** | Palo Alto Cortex XDR "Causality View"; Microsoft Defender XDR "Attack story" | 🟡 V5 sliders aggregate the same Win-Sec event chain, but as **separate per-entity timelines**. | 🟢 Add **"Observed vs. Reachable" tab split** + **pivot-as-root** action (§4.D, §4.E) |

**Strategic implication:** V5's slider design competes credibly on **Pattern C** with only AD-sync + Win-Sec. **V6 should not build a graph engine** — instead, ship the *outputs* customers associate with attack vectors (hop counts, cut options, reachable sets) using flat queries against tables we already index. See §4 for the concrete feature list.

---

## 1. Microsoft Security Exposure Management — Pattern A (graph APM)

**Vendor page (verified 2026-05-19):** [learn.microsoft.com/security-exposure-management/work-attack-paths-overview](https://learn.microsoft.com/en-us/security-exposure-management/work-attack-paths-overview) — last updated 2026-05-14.
**Related (Defender for Cloud variant):** [learn.microsoft.com/azure/defender-for-cloud/how-to-manage-attack-path](https://learn.microsoft.com/en-us/azure/defender-for-cloud/how-to-manage-attack-path) — last updated 2026-04-19.

**Vendor screenshots (public, hot-linkable):**
- Attack path dashboard: https://learn.microsoft.com/en-us/security-exposure-management/media/work-attack-paths-overview/attack-paths-dashboard.png
- Attack path overview (Defender portal): https://learn.microsoft.com/en-us/azure/defender-for-cloud/media/how-to-manage-attack-path/attack-path-overview-defender-portal.png
- Attack path node detail: https://learn.microsoft.com/en-us/azure/defender-for-cloud/media/how-to-manage-attack-path/attack-path-node-defender-portal.png

**Their vocabulary (quoted from the docs above):** "Attack paths", "Enterprise exposure graph", "Choke points", "Blast radius", "Entry points", "Target assets", "Critical assets", "End Game assets".

### Side-by-side vs. V5

| Capability | MS Exposure Management | V5 Log360 Cloud (baseline) | Verdict |
|---|---|---|---|
| **Primary UI metaphor** | Force-directed graph of assets + edges | Per-entity sliders with sectioned timelines | Different paradigms |
| **Input data needed** | Defender for Endpoint sensors + Defender for Identity + Defender for Cloud (CSPM) — i.e., a full Microsoft sensor mesh | AD-sync + Win-Sec 4624/4625/4740/etc. | We need far less data — but also produce far less |
| **Path computation** | Proprietary algorithm "from external entry point → critical asset" | None | ❌ Gap (and intentionally so — see strategic implication above) |
| **Critical-asset tagging** | Customer designates "critical assets" in portal | No equivalent — every entity is treated equally | ❌ Gap |
| **Choke point analysis** | First-class: "nodes where multiple attack paths converge" | None | ❌ Gap |
| **On-prem AD coverage** | Yes — terminates paths at Domain Admins / Enterprise Admins / DCs | AD attributes available (`APFDiscADUserDetails.MEMBER_OF`, group membership in `APFDiscADGroupDetails`) — raw material exists, no graph | Raw data present, missing the engine |
| **Per-incident drill-down** | Not the focus — APM is prevention, not investigation | ✅ This is exactly what our sliders do | We win on Pattern C |
| **License / cost** | Requires Defender XDR E5 + Defender for Cloud (CSPM tier) | Included in Log360 Cloud | Massive cost delta for customer |

### Honest positioning lines for the V6 deck
- **Do say:** "Log360 Cloud answers *what happened* on this user / host / IP, and *what's 2 hops away* from it. Microsoft Exposure Management answers *what could happen* across a full Defender mesh. Both have a place."
- **Do not say:** "We compete with Microsoft Exposure Management on attack paths." We do not. We have no graph engine.

---

## 2. SpecterOps BloodHound Enterprise — Pattern B (identity attack paths)

**Vendor page (verified 2026-05-19):** [specterops.io/bloodhound-overview](https://specterops.io/bloodhound-overview/) (and [bloodhound.specterops.io](https://bloodhound.specterops.io/) for docs).
**Free community edition:** [github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) — almost every AD admin has used this; high recall.

**Vendor screenshots (public, hot-linkable):**
- Hero attack-path map: https://specterops.io/wp-content/uploads/sites/3/2025/07/BHE-HeroImage@2x.png
- Privilege Zones blade: https://specterops.io/wp-content/uploads/sites/3/2026/03/BHE-Blade2@2x.png
- Integrations blade: https://specterops.io/wp-content/uploads/sites/3/2026/03/BHE-Blade3@2x.png

**Their vocabulary (quoted from the page above):** "Identity Attack Path Management (Identity APM)", "Privilege Zones", "Tier Zero", "Choke points", "Cypher-style queries" (`(b:BloodHoundUsers) -[h:Think_In]-> (e:Graphs)`).

**Vendor stat claims (from the page, treat as marketing):** 100M+ attack paths remediated; 35% average risk reduction in first 30 days; 17K+ paths cut per choke point.

### Side-by-side vs. V5

| Capability | BloodHound Enterprise | V5 Log360 Cloud (baseline) | Verdict |
|---|---|---|---|
| **Primary UI metaphor** | AD / Entra graph with Cypher query layer | Per-entity sliders | Different paradigms |
| **Input data needed** | SharpHound collector or AzureHound collector (LDAP + AD ACL enumeration + Entra API) | `APFDiscADUserDetails`, `APFDiscADGroupDetails`, `APFDiscADComputerDetails` from AD-sync | We already have most of the LDAP-derived data |
| **Edge types computed** | `MemberOf`, `HasSession`, `AdminTo`, `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AddMember`, `AllExtendedRights`, `Owns`, `CanRDP`, `ExecuteDCOM`, etc. (~30+ AD ACL edge types) | None — we store `MEMBER_OF` strings but never compute reachability | ❌ Big gap; this is BloodHound's entire moat |
| **Tier Zero / critical asset identification** | First-class — auto-tags Domain Admins, Enterprise Admins, DCs | None | ❌ Gap |
| **Per-user "what can this account reach"** | Native (`Shortest Path from Owned`) | ❌ Not in V5 | Would be a strong V6 addition with data we already index |
| **Post-incident "what did this account do"** | Weak — BloodHound is pre-attack analysis | ✅ Strong — our `logonActivity`, `accountLockouts`, `groupMembershipChanges` sections | We win on Pattern C |
| **License / cost** | BHCE free (community); BHE commercial, separately licensed | Included in Log360 Cloud | Cost advantage for "good enough" identity story |

### Honest positioning lines
- **Do say:** "We ingest the same AD attributes BloodHound's collectors gather, and surface them per-user in the Account Changes tab. If you need the *graph* — escalation paths, attack-path-to-Domain-Admin — BloodHound is the right tool."
- **Do not say:** "We replace BloodHound." We don't compute any ACL-edge reachability.
- **Engineering roadmap note:** Computing `(user) -[MemberOf*]-> (Group) -[AdminTo]-> (Computer)` reachability over `APFDiscADUserDetails` + `APFDiscADGroupDetails` + `APFDiscADComputerDetails` is a tractable engineering project — the data is already in our warehouse. **Scheduled as the V6 §4.C feasibility spike.**

---

## 3. Palo Alto Cortex XDR — Pattern C (Causality View)

**Vendor docs:** [docs-cortex.paloaltonetworks.com — Causality View](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Causality-View) (page exists but requires sign-in; could not re-verify wording in this session — 🟡).
**Public product page:** [paloaltonetworks.com/cortex/cortex-xdr](https://www.paloaltonetworks.com/cortex/cortex-xdr) (redirects through tag-manager; content not extractable in this session — 🟡).
**Recency:** Cortex XDR Pro 3.x is current as of 2026; Causality View has been the marquee feature since 2019 — well-documented in third-party reviews.

**Their vocabulary (🟡 from training data — recollection):** "Causality View" / "Causality Chain" / "CGO (Causality Group Owner)" — the alert's root cause process; "Incident graph" — entities + alerts linked.

### Side-by-side vs. V5

| Capability | Cortex XDR Causality View | V5 Log360 Cloud (baseline) | Verdict |
|---|---|---|---|
| **Primary UI metaphor** | Single linked process/entity tree per alert, rooted at CGO | Per-entity slider — User, Device, IP, Location each separate | Different decomposition; Cortex is alert-centric, we are entity-centric |
| **Input data needed** | Cortex XDR Agent (EDR-grade telemetry: process, file, network, registry, DLL load) | Win-Sec event log (4624 / 4625 / 4740 / 4720-26 / 4768 / 4776) — no process telemetry | Cortex sees process trees; we see authentication chains only |
| **What links the chain** | Process-ancestor relationships from the agent (PID → parent PID → CGO) | Shared field values: `IPADDRESS`, `TargetUserName`, `TargetComputerName` across event-ID-faceted timelines | We do correlation, not causation |
| **Per-process drill-down** | ✅ Native — file hash, signer, network connections, registry writes | ❌ `processesOnHost` is gated by integration (Sysmon / EDR agent) per [baseline_entity_inventory.md](baseline_entity_inventory.md#L168) | Real gap, but only for orgs that bought EDR |
| **Per-user auth chain** | Partial — needs Cortex Identity Analytics add-on | ✅ Strong — `logonActivity`, `loginStatistics`, `passwordHistory`, `accountLockouts` from 4624/4625/4723/4724/4740 | We are competitive here |
| **MITRE ATT&CK mapping** | ✅ Per-CGO TTP labels | ✅ `recentAlerts` carries ATT&CK fields from `ITSAlertProfileConfigurations` (verify with Threat Manager team) | Parity claim achievable |
| **License / cost** | Cortex XDR Pro per endpoint, separately metered; Pro per TB licensing | Included in Log360 Cloud | Cost advantage |

### Honest positioning lines
- **Do say:** "Without an EDR agent, you can't get a process-level causality chain — that's true for us and for every SIEM. We give you the strongest authentication-level chain available from AD + Win-Sec alone."
- **Do not say:** "We have a causality view." We have correlated per-entity timelines, not a single linked graph.
- **UX idea worth stealing:** Cortex's CGO concept (one root, expand to siblings) is a strong pattern. For V5 we could add an **"investigation root"** action on each slider section — "pivot to User from this row" / "pivot to IP from this row" — without building a real graph. Cheap UX win.

---

## Per-entity competitive readout

How each V5 slider stacks up against the closest competitor pattern.

### 👤 User slider
| | Closest competitor | We are stronger on | They are stronger on |
|---|---|---|---|
| Pattern A | MS Exposure Mgmt — `User` node on attack path | — | "what can this user reach" graph |
| Pattern B | BloodHound — user as graph node | — | Privilege escalation paths from this user |
| Pattern C | Cortex XDR — user identity panel | `loginStatistics`, `accountLockouts`, `passwordHistory`, `groupMembershipChanges` — all driven by AD-sync + Win-Sec | Process-level activity on the user's session |

**Verdict:** Strongest entity in our prototype. **Genuinely competitive on Pattern C** with zero additional integrations.

### 🖥️ Device slider
| | Closest competitor | We are stronger on | They are stronger on |
|---|---|---|---|
| Pattern A | MS Exposure Mgmt — device node + vulnerability edges | — | Vuln-derived edges; we have no vuln data at baseline |
| Pattern B | BloodHound — `Computer` node, `HasSession` edges | `usersLoggedOn`, `loginActivity` — equivalent data, exposed as a timeline not a graph | The graph itself |
| Pattern C | Cortex XDR — process tree per host | `deviceDetails`, `localAccountLifecycle` | `processesOnHost`, `usbDeviceEvents`, runtime `servicesOnHost` (all gated for us — see [V5/baseline_entity_inventory.md](../V5/baseline_entity_inventory.md#L185)) |

**Verdict:** Competitive on identity-side device data; **clear gap on process telemetry** which is honest and EDR-dependent.

### 🌐 IP slider
| | Closest competitor | We are stronger on | They are stronger on |
|---|---|---|---|
| Pattern A | MS Exposure Mgmt — external IP as entry-point node | — | Reachability from this IP to critical asset |
| Pattern B | BloodHound — N/A (BloodHound is identity-only) | All of it | — |
| Pattern C | Cortex XDR — network-connection panel | `associatedUsers`, `associatedDevices`, `logonActivity` for internal IPs | TI verdict, firewall flow data, DNS history — gated for us (see [V5/baseline_entity_inventory.md](../V5/baseline_entity_inventory.md#L237)) |

**Verdict:** Weakest entity at baseline — 5 of 7 sections work, but the visually dominant Threat-Intel / Firewall / DNS / VPN tabs need integrations no competitor would need either, because they're customer-side log sources.

### 📍 Location slider
| | Closest competitor | We are stronger on | They are stronger on |
|---|---|---|---|
| Pattern A | MS Exposure Mgmt — N/A | All of it | — |
| Pattern B | BloodHound — N/A | All of it | — |
| Pattern C | Cortex XDR — geo-context strip on incidents | `travelPattern`, `associatedUsers`, `observedSourceIPs` (after Path B + C) | Built-in IP reputation feeds |

**Verdict:** **No direct competitor at this slider's altitude.** Geo-centric entity views are unusual; most competitors fold geo into the IP entity. This is a potential differentiator for V6 — assuming Path B (the ~10 LOC `GeoInfoEnrichment` patch) ships.

---

## Verification & sourcing log

| Claim source | Status | Last verified | Notes |
|---|---|---|---|
| MS Exposure Mgmt — feature wording, screenshot URLs | ✅ Verified | 2026-05-19 | Page last updated 2026-05-14 |
| MS Defender for Cloud — Attack Path Map, screenshot URLs | ✅ Verified | 2026-05-19 | Page last updated 2026-04-19 |
| SpecterOps BloodHound — Identity APM wording, screenshots, customer stats | ✅ Verified | 2026-05-19 | Site copyright 2026 |
| XM Cyber — "Attack Path Management" wording, choke points | ✅ Verified | 2026-05-19 | Page accessed; no public screenshots hot-linkable |
| Cortex XDR — "Causality View" / "CGO" wording | 🟡 Unverified | (Cortex docs gated, marketing page redirects through tag manager) | High-confidence recollection from training data; verify with PAN docs login before quoting in deck |
| Cortex XDR licensing / per-endpoint metering | 🟡 Unverified | — | Recollection; confirm with PAN pricing page |
| CGO concept availability per tier | 🟡 Unverified | — | Confirm whether Causality View ships in Cortex XDR Prevent or only Cortex XDR Pro |

---

---

## 4. V6 Attack Vector — features we can ship

> **Framing:** The question "what new features can we show in attack vector?" has two honest answers. (1) We **cannot** ship a graph engine, a CSPM, an EDR, or an LLM copilot in V6. (2) We **can** ship 6 features that produce the *outputs* customers associate with attack-vector analysis, using only AD-sync + Win-Sec data we already index. Each feature below names the competitor UX that inspired it and the exact backing tables.

### 4.A — "Cut options" table on every alert (inspired by CrowdStrike APA)

**Competitor UX (verified 2026-05-19, [crowdstrike.com/.../attack-path-analysis](https://www.crowdstrike.com/en-us/platform/exposure-management/attack-path-analysis/)):** CrowdStrike's Attack Path screen renders a left-side table with rows `Source / Least effort option 1 / 2 / 3 / Destination` and columns `Assets | Remediations | Risks`. It tells the admin **where to cut the chain for least effort**.

**V6 feature:** On each `recentAlerts` row (and on the `riskSummary` panel), render a compact "Cut options" table:

| Cut option | Affects (users / hosts) | Effort (steps) | Alerts prevented (7d) |
|---|---|---|---|
| Disable account `m.henderson` | 1 user · 3 hosts | 1 step | 4 |
| Isolate host `CORP-WS-045` | 5 users · 1 host | 1 step | 12 |
| Block source IP `185.220.101.42` | 0 users · 6 hosts | 1 step | 7 |

**Backing data (already indexed):** counts come from `COUNT(EventID IN (4624,4625,4740) WHERE TargetUserName=:u / TargetComputerName=:h / IPADDRESS=:ip)` against the same projections that feed `loginStatistics`. **No new tables, no graph.** Rendering layer only.

### 4.B — Hop-count strip on User / Device / IP sliders (inspired by CrowdStrike "Closest assets with internet exposure: 2 hops")

**Competitor UX (verified 2026-05-19, same page):** CrowdStrike's asset side panel shows a numeric strip: `Closest assets with internet exposure: 2 hops | 1 asset | [Show paths]`. Quantifies blast radius in one line.

**V6 feature:** Add a one-line strip to the User and Device slider headers:

> `2 hops to a privileged user · 1 hop to a domain controller · 3 hops to internet exposure`

**Backing data (joins on existing AD tables — no graph engine required for hop counts ≤ 2):**
- **Hops to privileged user** = does this account share `GroupName` with anyone in `APFDiscADGroupDetails.MEMBER` for `Domain Admins` / `Enterprise Admins`?
- **Hops to DC** = did this account log on (Win-Sec 4624) to any computer where `APFDiscADComputerDetails.OS LIKE '%Server%'` AND `OU LIKE '%Domain Controllers%'`?
- **Hops to internet exposure** = does the associated `IPADDRESS` fall outside RFC 1918?

### 4.C — "Reachable" tab on User / Device sliders (inspired by BloodHound + CrowdStrike "Internet exposure entry node")

**Competitor UX (verified 2026-05-19, [specterops.io/bloodhound-overview](https://specterops.io/bloodhound-overview/)):** BloodHound's flagship view is *"Shortest Path from Owned"* — given a compromised account, list every privileged target it can reach. CrowdStrike's panel shows the inverse — given an internet-exposed asset, list everything it can reach.

**V6 feature:** Each slider gets a new tab next to the existing "Observed" timelines:

| Tab | What it shows | Equivalent competitor pattern |
|---|---|---|
| **Observed** (already shipped in V5) | `logonActivity`, `accountLockouts`, `groupMembershipChanges` — *what did happen* | Cortex Causality / Process graph |
| **Reachable** (new in V6) | Flat list: *"this account is a member of N groups; those groups grant `AdminTo` on M computers; K of those are tier-0"* — *what could happen* | BloodHound / MS APM |

**Important: this is not a graph.** It is a 2-hop SQL closure over `APFDiscADUserDetails.MEMBER_OF` → `APFDiscADGroupDetails.MEMBER` → computer membership. Ship as a flat list. **Feasibility spike scheduled** — see honest positioning lines in §2.

### 4.D — "Pivot as investigation root" action (inspired by Cortex XDR's CGO concept)

**Competitor UX (🟡 from training data — Cortex docs are gated):** Cortex XDR's "Causality Group Owner" treats one process as the root of an investigation and renders ancestors/siblings around it.

**V6 feature:** Every row in every slider section gets a `Pivot to … as root` action:
- Row in `logonActivity` → "Pivot to **this IP** as root" / "Pivot to **this host** as root"
- Row in `accountLockouts` → "Pivot to **the lockout source IP** as root"
- Row in `groupMembershipChanges` → "Pivot to **the actor account** as root"

This is **pure UX plumbing** — opens the existing target-entity slider with the alert-time-window pre-filtered. Sells the "single linked investigation" story without building a real graph. **Cheapest item in the V6 list.**

### 4.E — Edge-style separation on `recentAlerts` timeline (inspired by CrowdStrike's red-dashed vs. solid-gray edges)

**Competitor UX (verified 2026-05-19, same CrowdStrike page):** CrowdStrike overlays **red dashed** edges (predictive attack path) on top of **solid gray** edges (observed network connections) in the same canvas. Visually separates *"could happen"* from *"did happen"*.

**V6 feature:** On the per-entity `recentAlerts` timeline, distinguish three row styles:
- **Solid red** — alert fired (`ITSAlertProfileConfigurations` match, severity High/Critical)
- **Dashed amber** — risk-score delta only (`ITSEntityRiskScoreDetails.RISK_SCORE` rose, no alert fired)
- **Solid gray** — informational (login from new geo, new device, etc.)

**Backing data:** all three already exist in `ITSAlertProfileConfigurations` + `ITSEntityRiskScoreDetails` + `ITSRiskSeverityDetails`. Styling only.

### 4.F — Workflow-canvas preview inside `recentAlerts` (inspired by Falcon Fusion SOAR)

**Competitor UX (verified 2026-05-19, same CrowdStrike page, screenshot `exposure-attack-path-maximize`):** Falcon Fusion renders response playbooks as a vertical flowchart `Trigger → Condition → Action → Human input` directly inside the alert view.

**V6 feature:** Log360 Cloud already has a Workflow module (referenced from `ITSAlertProfileConfigurations`). Render the **already-configured** workflow for an alert as a small inline flowchart on the `recentAlerts` row — same node vocabulary (Trigger / Condition / Action / Human input). **No new SOAR engine; visual layer over an existing module.** Closes the most credible gap on the "Maximize impact with targeted risk remediation" pillar.

### Summary — V6 Attack Vector feature matrix

| # | Feature | Inspiration | Engineering size | Net-new data needed? | Ship tier |
|---|---|---|---|---|---|
| 4.A | Cut-options table | CrowdStrike APA | S — rendering + 3 count queries | ❌ No | **Tier 1 (ship first)** |
| 4.B | Hop-count strip | CrowdStrike asset panel | S — 3 SQL joins on AD tables | ❌ No | **Tier 1** |
| 4.D | Pivot-as-root action | Cortex CGO | XS — UX plumbing only | ❌ No | **Tier 1** |
| 4.E | Alert-row style differentiation | CrowdStrike edge-style overlay | XS — CSS + 1 query field | ❌ No | **Tier 1** |
| 4.F | Workflow-canvas preview | Falcon Fusion SOAR | M — render existing workflow as flowchart | ❌ No (uses existing Workflow module) | **Tier 2** |
| 4.C | "Reachable" tab (2-hop closure) | BloodHound + MS APM | M — closure job + new tab | ❌ No (uses existing AD tables) | **Tier 2** |

**What V6 deliberately does NOT ship (and why):**

| Out-of-scope item | Reason |
|---|---|
| Force-directed graph canvas | Requires graph storage + layout engine; no warehouse support; would compete head-on with MS/CrowdStrike on their strongest axis. |
| EDR-grade process telemetry / process graph | Requires customer-side Sysmon or EDR agent. Honest gap; not a Log360 Cloud decision. |
| CSPM / Cloud IOMs / "Internet exposure" inventory | Requires AWS/Azure resource enumeration. Out of scope; refer customers to ManageEngine CloudSpend / dedicated CSPM. |
| LLM copilot (Charlotte AI / Security Copilot equivalent) | Zia integration is a separate Zoho-AI roadmap track; do not bundle into V6. |
| Cypher-style ad-hoc query language | BloodHound's moat; would require the graph engine we're explicitly not building. |

### Honest competitive lines for the V6 deck

- **Do say:** "V6 adds *attack-vector* outputs — hop counts, cut options, reachability lists — using your existing AD and Windows Security Event Log data. No new sensors. No new licenses."
- **Do say:** "If you need a graph canvas, BloodHound and Microsoft Exposure Management are the right tools — and V6 doesn't try to replace them."
- **Do not say:** "We have predictive attack paths." We have 2-hop reachability lists.
- **Do not say:** "We have a causality view." We have linked per-entity timelines with pivot-as-root.

---

## Cross-reference

- Baseline data sources & per-section feasibility: [V5/baseline_entity_inventory.md](../V5/baseline_entity_inventory.md)
- Per-field ES projections: [V5/entity_data_mapping.md](../V5/entity_data_mapping.md) §9
- Slider feasibility detail: [V5/entity_slider_feasibility.md](../V5/entity_slider_feasibility.md)
