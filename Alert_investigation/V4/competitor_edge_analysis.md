# Competitive Edge & Relation Models — Consolidated Analysis

> Compiled: 07 May 2026
> Scope: how 9 competing security platforms model **entities, edges/relations, and attack-path graphs**, with implications for our V5 design.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [BloodHound / SpecterOps — Entity & Edge Deep Dive](#1-bloodhound--specterops--entity--edge-deep-dive)
3. [Microsoft Security Exposure Management](#2-microsoft-security-exposure-management)
4. [XM Cyber](#3-xm-cyber)
5. [Google SecOps (Chronicle) — UDM Entity Graph](#4-google-secops-chronicle--udm-entity-graph)
6. [Splunk Enterprise Security](#5-splunk-enterprise-security)
7. [Palo Alto Cortex XSIAM / XDR](#6-palo-alto-cortex-xsiam--xdr)
8. [CrowdStrike Falcon](#7-crowdstrike-falcon-insight-xdr--identity-protection)
9. [SentinelOne Singularity](#8-sentinelone-singularity-storyline--identity)
10. [ManageEngine ADManager Plus (ADMP) Governance](#9-manageengine-admanager-plus-admp--governance-attack-path)
11. [Comparison Matrix](#comparison-matrix)
12. [Cross-Vendor Pattern Analysis](#cross-vendor-pattern-analysis)
13. [Recommendations for V5](#recommendations-for-v5)
14. [Play-the-Attack Timeline — Competitor Precedent](#play-the-attack-timeline--competitor-precedent)
15. [References](#references)

---

## Executive Summary

The market has converged on **two opposite philosophies** for modelling attack-graph edges, with a clear preference for the lighter one:

| Philosophy | Vendors | Edge count | Trade-off |
|------------|---------|-----------|-----------|
| **Edge-label-rich** (each abuse technique = its own edge type) | BloodHound, **ADMP Governance** | 18–250 | Fast pattern queries + remediation-per-edge UX; brittle without an extension mechanism (BH solved with OpenGraph; ADMP has none) |
| **Property-rich / hybrid** (small named-relation enum + dynamic event-types + properties) | Chronicle, XM Cyber, CrowdStrike, Palo Alto, SentinelOne | 0–20 | Flexible, extensible, slower for path queries; requires good property design |
| **Fully open / dynamic** | Microsoft Exposure Mgmt | Unbounded (free string) | Ingest anything; no catalog to maintain; harder to query against fixed patterns |
| **Tabular / no relations** | Splunk ES | 0 | Maximum flexibility; no graph queries possible |

**Key finding:** Most competitors use ≤20 named edges. Only BloodHound (~250) and ADMP Governance (18) maintain a fixed AD-abuse taxonomy — and only BloodHound has an extension mechanism (OpenGraph).

**Validation for V5:** Our hybrid recommendation (6–10 stable named relations + behavioural event-type edges + rich properties + MITRE tagging) matches what **Chronicle and CrowdStrike Identity have already converged on**.

---

## 1. BloodHound / SpecterOps — Entity & Edge Deep Dive

BloodHound is the **gold-standard public attack-graph schema**. Originally for AD only, now (BloodHound CE / Enterprise) covers Active Directory, Entra ID (Azure AD), and — via **OpenGraph** — arbitrary third-party data.

### 1.1 Node Types (Entities)

#### Active Directory (~17 native node types)
| Node | Represents |
|------|-----------|
| `User` | AD user account (incl. service accounts) |
| `Computer` | Domain-joined workstation/server |
| `Group` | AD security/distribution group |
| `Domain` | AD domain object |
| `OU` | Organizational Unit |
| `GPO` | Group Policy Object |
| `Container` | AD container (e.g. `CN=Users`) |
| `AIACA`, `RootCA`, `EnterpriseCA`, `NTAuthStore`, `CertTemplate`, `IssuancePolicy` | ADCS (added 2022, "Certified Pre-Owned" research) |
| `LocalGroup`, `LocalUser` | SAM-local accounts (collected by SharpHound) |

#### Entra ID / Azure AD (~17 node types)
`AZUser`, `AZGroup`, `AZTenant`, `AZSubscription`, `AZResourceGroup`, `AZApp`, `AZServicePrincipal`, `AZManagedIdentity`, `AZRole`, `AZDevice`, `AZVM`, `AZKeyVault`, `AZWebApp`, `AZFunctionApp`, `AZAutomationAccount`, `AZContainerRegistry`, `AZLogicApp`.

#### OpenGraph (BloodHound CE 6.0+, late 2024)
Anything you ingest — `SnowflakeUser`, `OktaApp`, `GitHubRepo`, `K8sServiceAccount`. You define the node `kind` and properties.

### 1.2 Edge Types — ~250 named, full catalog public

#### A. Directory Membership / Containment (~15)
`MemberOf`, `Contains`, `HasSIDHistory`, `TrustedBy`, `SameForestTrust`, `CrossForestTrust`, `SpoofSIDHistory`, `AbuseTGTDelegation`.

#### B. Permissions / DACL Abuse (~30)
The largest category — every abusable AD ACE.
`GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDacl`, `Owns`, `OwnsRaw`, `WriteSPN`, `AddSelf`, `AddMember`, `AddKeyCredentialLink`, `ForceChangePassword`, `AllExtendedRights`, `ReadLAPSPassword`, `ReadGMSAPassword`, `ManageCA`, `ManageCertificates`, `WriteAccountRestrictions`, `WritePKINameFlag`, `WritePKIEnrollmentFlag`.

#### C. Kerberos Delegation (~8)
`AllowedToAct`, `AllowedToDelegate`, `Unconstrained` (property), `TrustedToAuth`.

#### D. ADCS / Certificate Abuse (~20) — ESC1–ESC15
`Enroll`, `EnrollOnBehalfOf`, `DelegatedEnrollmentAgent`, `GoldenCert`, `ADCSESC1` … `ADCSESC15` (each ESC technique is its own edge type).

#### E. Session / Logon Telemetry (~7)
`HasSession`, `HasSIDHistory`, `CanLogon`, `CanRDP`, `CanPSRemote`, `ExecuteDCOM`, `SQLAdmin`.

#### F. GPO / OU (~2)
`GPLink`, `GPOAppliesTo`.

#### G. Entra ID (~80)
`AZGlobalAdmin`, `AZPrivilegedRoleAdmin`, `AZApplicationAdmin`, `AZCloudAppAdmin`, `AZIntuneAdmin`, `AZHelpdeskAdmin`, `AZAddSecret`, `AZAddOwner`, `AZMGAddSecret`, `AZMGAddOwner`, `AZMGGrantAppRoles`, `AZMGGrantRole`, `AZContains`, `AZContributor`, `AZOwner`, `AZUserAccessAdministrator`, `AZRunAs`, `AZHasRole`, `AZManagedIdentity`, `AZWebsiteContributor`, `AZVMAdminLogin`, `AZVMContributor`, `AZAvereContributor`, `AZAKSContributor`, `AZAutomationContributor`, `AZKeyVaultContributor`, `AZGetSecrets`, `AZGetCertificates`, `AZGetKeys`, `AZLogicAppContributor`, `AZAddMembers`, `AZResetPassword`, `AZExecuteCommand` … (list grows every release).

#### H. Cross-Platform / Hybrid (~5)
`SyncedToEntraUser`, `SyncedToADUser` — bridges on-prem ↔ cloud identities.

### 1.3 Edge Properties (the differentiator)

Every edge carries:
- `traversable` (bool) — can the attacker actually use this in a path?
- `composition` — for derived edges (e.g. `ADCSESC3` = `Enroll` + `DelegatedEnrollmentAgent` + …)
- `last_seen` — when the relationship was last observed
- `isacl` (bool) — distinguishes ACL-derived edges from telemetry-derived
- `cost` — Tier-Zero traversal weight (used by shortest-path queries)

This is why BloodHound can answer **"shortest attack path from any user to Domain Admins"** in one Cypher query.

### 1.4 OpenGraph Extension Model

You write a JSON spec:

```json
{
  "graph": {
    "nodes": [
      { "id": "okta-app-1", "kinds": ["OktaApp"],
        "properties": { "name": "GitHub-SSO" } }
    ],
    "edges": [
      { "kind": "OktaAssignedTo", "start": "user-42", "end": "okta-app-1",
        "properties": { "via": "group", "last_seen": "2026-05-01" } }
    ]
  }
}
```

Push via `POST /api/v2/opengraph/ingest`. BloodHound auto-renders new node/edge `kinds` in the UI and lets you write Cypher against them. **This is what makes the 250 fixed edges actually extensible** — without OpenGraph, the model would be brittle.

### 1.5 Why The Vocabulary is So Large

BloodHound chose **edge-type-as-attack-technique**: every distinct abuse primitive gets its own edge label so analysts can query directly:

```cypher
MATCH p = shortestPath((u:User)-[:GenericAll|WriteDacl|AddMember*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p
```

This is **opposite** to Chronicle's approach (small enum + property `relationship_type`). Both are valid; BH optimises for pattern-matching, others for flexibility.

---

## 2. Microsoft Security Exposure Management ✅ confirmed from Microsoft Learn

**Approach:** **Dynamic enterprise exposure graph** queried via **KQL** in Defender Advanced Hunting. Built from Defender XDR (endpoint, identity, email, SaaS) + Defender for Cloud (Azure/AWS/GCP) + Entra ID. Targets **choke-point** and **hybrid attack-path** analysis — not BloodHound-style enumerated path queries.

### 2.1 Schema — two tables

| Table | Purpose |
|-------|---------|
| `ExposureGraphNodes` | One row per entity. Columns: `NodeId`, `NodeName`, `NodeLabel`, `Categories`, `EntityIds`, `NodeProperties` (dynamic JSON) |
| `ExposureGraphEdges` | One row per relationship. Columns: `SourceNodeId`, `SourceNodeLabel`, `TargetNodeId`, `TargetNodeLabel`, `EdgeLabel` (string — open-ended) |

KQL `make-graph` + `graph-match` operators turn it into a queryable graph.

### 2.2 Node Labels (entity types)
**Open-ended** — anything ingested becomes a `NodeLabel`. Examples confirmed in docs:
- Cloud: `microsoft.compute/virtualmachines`, `aws.*`, `gcp.*` (Azure/AWS/GCP resource types follow ARM naming)
- On-prem: `device`, `identity`, `ip_address`, `virtual_machine`
- Higher-level grouping via `Categories` array: `device`, `identity`, `ip_address`, `virtual_machine`, `data` …

To enumerate the live set in a tenant, Microsoft tells you to run:
```kql
ExposureGraphNodes | summarize by NodeLabel
```

### 2.3 Edge Labels — open-ended string, no fixed enum

Microsoft does **not publish a fixed edge taxonomy**. The docs explicitly recommend discovering them per-tenant:
```kql
ExposureGraphEdges | summarize by EdgeLabel
```

**Edge labels confirmed from KQL examples in the official docs:**
- `Can Authenticate As`
- `CanRemoteInteractiveLogonTo`

That's all the docs show by name. Other edges *exist* (the schema would be useless otherwise) but Microsoft treats the edge-label set as **discovery-driven, not catalog-driven**. This is a major design choice — it means Microsoft considered an enumerated taxonomy and rejected it.

### 2.4 Differentiators

- **Critical Assets** — pre-classified Tier-0 equivalent (`NodeProperties.rawData.criticalityLevel < 4` = critical).
- **Hybrid attack paths** — explicit pattern in docs for `(CloudVM)-[edge1]->(Identity)-[edge2]->(OnPremDevice)`.
- **Choke points** — surfaces single nodes whose compromise enables many attack paths.
- **Rich `NodeProperties`** — `exposedToInternet`, `vulnerableToRCE`, `vulnerableToPrivilegeEscalation`, `IsInternetFacing`, `containsSensitiveData`, `criticalityLevel` — properties carry the semantic weight, not the edges.

**Verdict:** Property-rich, **deliberately open-ended edge vocabulary** (no published catalog by design), strong KQL/graph-match query layer. Sacrifices Cypher-style fixed pattern matching for tenant-specific discovery and rich node properties.

**Sources:**
- https://learn.microsoft.com/en-us/security-exposure-management/microsoft-security-exposure-management
- https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph (KQL examples — source of confirmed edge labels)

---

## 3. XM Cyber

**Approach:** **Continuous attack-path simulation** — runs a "virtual red team" against your environment and produces ranked attack paths. Edges are derived from simulation, not from a fixed schema.

**Entities:** Asset (host), Identity, Cloud Resource, Network Segment, Application.

**Edges:** ~50, **MITRE ATT&CK technique-tagged** (`T1078 Valid Accounts`, `T1003 OS Credential Dumping`, `T1550.002 Pass the Hash`, `T1484.001 GPO Modification`, etc.). The MITRE catalog is the de-facto edge vocabulary.

**Differentiator:** Every attack path is end-to-end simulated and assigned a **risk score**, **exploitability**, and **business-impact** value. The output is a list of **"choke point" remediations** ranked by how many paths they break.

**Verdict:** MITRE-as-edge-vocab is elegant — instantly familiar to analysts, evolves with MITRE updates, and removes the need for a proprietary taxonomy.

**Source:** https://www.xmcyber.com/platform/

---

## 4. Google SecOps (Chronicle) — UDM Entity Graph ✅ confirmed from official docs

**Approach:** **Hybrid — small fixed relation enum + rich entity context.** Chronicle is *not* a BloodHound-style attack-graph product; it's a SIEM with an Entity Graph layered on top of UDM events.

### 4.1 Edge taxonomy — exactly 6 named relationships (`Relation.Relationship` enum)

| Edge | Semantics |
|------|-----------|
| `OWNS` | user owns device asset |
| `ADMINISTERS` | user administers a group |
| `MEMBER` | user is member of group |
| `EXECUTES` | primary may have executed related |
| `DOWNLOADED_FROM` | primary may have been downloaded from related |
| `CONTACTS` | primary contacts related |

Plus structural metadata: `direction` (UNIDIRECTIONAL / BIDIRECTIONAL) and `entity_label` (PRINCIPAL / TARGET / SRC / OBSERVER / INTERMEDIARY / NETWORK / SECURITY_RESULT).

### 4.2 Real "edges" come from the Noun model

Each event has slots — `principal`, `src`, `target`, `intermediary`, `observer`, `about` — and the *event_type* (~140 enums: `USER_LOGIN`, `PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `FILE_MODIFICATION`, `ENTITY_RISK_CHANGE`, etc.) effectively becomes the edge label.

### 4.3 Entity types (`EntityMetadata.EntityType`)
`ASSET`, `USER`, `GROUP`, `RESOURCE`, `IP_ADDRESS`, `DOMAIN_NAME`, `URL`, `FILE`, `MUTEX`.

**Verdict:** Chronicle uses the same hybrid pattern recommended in our V5 design — **tiny named relation set (6) + behavioural verbs from event_type + context properties (`risk_score`, `prevalence`, MITRE tactic/technique).**

**Source:** https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list (sections "Relation", "Relation.Relationship", "Noun", "Metadata.EventType")

---

## 5. Splunk Enterprise Security

**Approach:** **Tabular, not graph.** Splunk ES is built on the Common Information Model (CIM) and the **Asset & Identity** framework. Relationships are *implicit joins* on shared field values (`user`, `src`, `dest`, `process_name`), not stored edges.

- **Asset & Identity correlation** maps events → entities via `asset` / `identity` lookups (CIM `Identity_Management` data model).
- **Investigation Workbench / Mission Control** shows a timeline + entity panel, not a typed-edge graph.
- **Splunk SOAR (Phantom)** has a visual "Investigation graph" — uses generic `related_to` / `member_of` / `contains` edges (~5–10 types).
- **UEBA (formerly Caspida)** does build behavioural graphs but the edge vocabulary is internal and not publicly catalogued.

**Verdict:** Splunk treats relations as **search-time joins**, not stored predicates. No published edge taxonomy. Closest to the "everything is a property" extreme.

**Sources** (best-effort, paywall/redirect):
- https://docs.splunk.com/Documentation/CIM/latest/User/Overview
- https://docs.splunk.com/Documentation/ES/latest/Admin/Manageassetsandidentities

---

## 6. Palo Alto Cortex XSIAM / XDR

**Approach:** **Causality chain (tree, not graph).** Each alert is anchored to a **CGO (Causality Group Owner)** — the root process — and edges represent process lineage and side-effects.

**Edge vocabulary (~7–10 verbs, undocumented publicly):**
- `caused` / `spawned` (process → child process)
- `injected_into`
- `loaded` (module load)
- `accessed` (file/registry/network)
- `connected_to` (network)
- `authenticated_as` (identity)

**Stitching** combines XDR (endpoint), network, identity, cloud telemetry into a single causality timeline. It's *one tree per alert*, not a persistent enterprise graph like BloodHound.

**Verdict:** Small generic verb set + heavy reliance on the CGO concept to anchor everything. Closer to Microsoft Defender's "incident graph" than BloodHound.

**Source:** https://www.paloaltonetworks.com/cortex/cortex-xsiam — Causality Chain concept covered in Cortex XDR analyst guides.

---

## 7. CrowdStrike Falcon (Insight XDR + Identity Protection)

**Approach:** **Two graphs stitched together.**
- **Process Tree** (Insight XDR): same model as Palo Alto — parent/child process edges, generic verbs (`spawned`, `loaded`, `connected`, `wrote`, `read`).
- **Threat Graph** (cloud-side): a massive event graph of every endpoint event globally, queried at detection time. Edges are event-type-derived; not exposed as a named taxonomy.
- **Falcon Identity Protection** (formerly Preempt): builds an **identity store graph** from AD/Entra ID — uses BloodHound-style relations (`MemberOf`, `HasSession`, `AdminTo`, `CanRDP`) but with a smaller vocabulary (~15–20) and risk-scored.

**Verdict:** Process-causality + identity-graph hybrid. Identity side borrows heavily from BloodHound's vocabulary (logical, since CrowdStrike acquired and integrated Preempt). Process side is generic verbs.

**Source:** https://www.crowdstrike.com/en-us/platform/identity-protection/ (Falcon documentation gated behind login).

---

## 8. SentinelOne Singularity (Storyline + Identity)

**Approach:** **Storyline ID (causal grouping), not a typed-edge graph.** Storyline auto-correlates every event on an endpoint into a single ID by tracing process ancestry — there are *no semantic edge labels at all*. The "edge" is implicit: events sharing a `storyline_id` are part of the same story.

**Singularity Identity** (formerly Attivo Networks): adds an AD attack-path view with deception. Edges are MITRE-tagged (`T1003 OS Credential Dumping`, `T1550 Use Alternate Authentication Material`) — closer to XM Cyber's MITRE-tag approach than BloodHound's named edges.

**Verdict:** Storyline = causal event clustering (no edge vocab). Identity = MITRE-technique-tagged paths. Not a unified named-edge graph.

**Source:** https://www.sentinelone.com/platform/singularity-identity/ — Storyline whitepaper (link 404'd; referenced in product datasheets).

---

## 9. ManageEngine ADManager Plus (ADMP) — Governance Attack Path ✅ verified in source

**Approach:** **Strictly static BloodHound-style attack-path graph** for on-prem AD, surfaced under the **Governance → Risk Report** module. Built on RDBMS + Elasticsearch (not Neo4j), rendered with an in-house `z-graph.js` force-directed library. Same shape as BloodHound but a much smaller, immutable edge vocabulary.

### 9.1 Node Types (6)

| Type | Color |
|------|-------|
| User | Blue `#0278D7` |
| Group | Green `#0E7C10` |
| Computer | Purple `#4B0082` |
| Contact | Orange `#E8710A` |
| Other AD Object | Orange `#E8710A` |
| Cluster (collapsed) | Gray `#627E89` |

Special markers: **Target** = red border, **Entry Point** = dashed border.

### 9.2 Edge Types — 18 fixed, no extension mechanism

Defined as seed data in [ADSMPrivilegedAssurance.xml](https://example.invalid/) (table `ADSMAccessPathRelations`) and as Java constants in `PrivilegedAssuranceConstants.java`:

| ID | Edge | Priority | BloodHound equivalent |
|----|------|----------|------------------------|
| 1  | Member Of | 15 | `MemberOf` |
| 2  | Owns | 1 | `Owns` |
| 3  | Write DACL | 6 | `WriteDacl` |
| 4  | DCSync | 7 | `DCSync` (composition of `GetChanges` + `GetChangesAll`) |
| 5  | Allowed to Act | 16 | `AllowedToAct` (RBCD) |
| 6  | Grant Allowed To Act | 12 | `WriteAccountRestrictions`-derived |
| 7  | Add Key Credential | 11 | `AddKeyCredentialLink` |
| 8  | Reset Password | 5 | `ForceChangePassword` |
| 9  | Write Owner | 4 | `WriteOwner` |
| 10 | Generic All | 2 | `GenericAll` |
| 11 | Write SPN | 9 | `WriteSPN` |
| 12 | Extended Rights | 8 | `AllExtendedRights` (single bucket — not expanded per GUID) |
| 13 | Allowed To Delegate | 17 | `AllowedToDelegate` |
| 14 | Has SID History | 14 | `HasSIDHistory` |
| 15 | RODC Manage | 13 | (RODC-specific abuse) |
| 16 | Generic Write | 3 | `GenericWrite` |
| 17 | Add Member | 10 | `AddMember` |
| 18 | Domain Trust (hidden in UI) | 18 | `TrustedBy` / `SameForestTrust` |

Each edge carries `displayValue`, `relationId[]` (multiple relations can collapse onto one edge), `iconType`, plus per-relation help text: `DESCRIPTION`, `EXPLOITATION`, `REMEDIATION`. The remediation/exploitation text per relation is a UX win BloodHound doesn't ship out of the box.

### 9.3 Data Model (5 tables)

| Table | Role |
|-------|------|
| `ADSMAccessPathNodes` | Vertices: `OBJECT_ID` PK, `NAME`, `OBJECT_CLASS`, `DISTINGUISHED_NAME`, `OBJECT_GUID`, `OBJECT_SID`, `DOMAIN_NAME` |
| `ADSMAccessPathDetails` | Paths: `PATH_ID` PK, `OBJECT_ID` (entry), `PARENT_ID` (intermediate), `TARGET_ID` (privileged) |
| `ADSMAccessPathRelationDetails` | Edge instances: `UNIQUE_ID` PK, `PATH_ID` FK, `RELATION_ID` FK |
| `ADSMAccessPathRelations` | **Relation catalog — exactly 18 immutable rows** (XML-seeded, `UNIQUE` constraint on `RELATION_ID`) |
| `ADSMBlastRadius*` | Same shape, blast-radius view |

### 9.4 Static vs Dynamic — Strictly Static

Three layers all hard-code the same 18 IDs:
1. **XML seed:** `ADSMPrivilegedAssurance.xml` rows 14–31.
2. **Java constants:** `PrivilegedAssuranceConstants.java` (`MEMBEROF=1` … `TRUST=18`).
3. **Compute logic:** `AssetExposure.updateAccessPaths()` is an exhaustive `if-else` chain over the 18 — **no fallback / `OTHER` / `UNKNOWN`** edge type. Unmapped permissions are silently dropped.

No plugin API, no factory, no class-loader hook, no XML reload. Adding edge #19 = schema migration + new XML seed + new Java constant + new `if`-branch + new icon + new help-text strings + rebuild.

**Notable behavior — Extended Rights collapse:** Every AD Extended Right GUID (Send-As, Receive-As, individual control-access rights, etc.) collapses into the single `Extended Rights` edge (ID 12). Per-GUID expansion (which BloodHound does for ADCS ESC1–ESC15) is not done.

### 9.5 Backend & Frontend

- **REST:** `POST /api/json/reports/privilegedassurance/getAccessPath` returns `{vertices: [], edges: []}`
- **Java:** `PrivilegedAssuranceUtil`, `AccessPathHandler`, `AccessPathUpdater`, `AssetExposure`, `BlastRadius` (under `reports/privilegedassurance/`)
- **Data source:** AD permissions ingested into Elasticsearch security indices → batch-computed via BFS into `ADSMAccessPath*` tables (this differs from the rest of ADMP which uses LDAP→SQL sync)
- **Frontend:** Ember addon `lib/governance/`, routes `governance.riskreport` / `governance.riskreportresult`, custom `z-graph.js` (force-directed)

### 9.6 What's Missing vs BloodHound

No ADCS edges (ESC1–ESC15), no session telemetry (`HasSession`, `CanRDP`, `CanPSRemote`, `SQLAdmin`), no `WriteGPLink`, no Entra ID edges. ADMP is **a focused subset of BloodHound's on-prem AD edges** — the most exploitable abuse primitives, no cert services, no live-session data, no cloud.

**Verdict:** A production BloodHound-shaped attack graph with 18/250 of the edges, zero extension mechanism, and best-in-class per-edge remediation UX. Sits at the **most rigid end** of the spectrum (more rigid than BloodHound thanks to no OpenGraph equivalent), but with strong analyst-actionable workflows.

**Source:** Direct repo inspection (`REPOS/adsm`):
- Seed: `product_package/conf/adsm/ADSMPrivilegedAssurance.xml`
- Constants: `source/java_source/server/com/adventnet/sym/adsm/common/server/reports/privilegedassurance/PrivilegedAssuranceConstants.java`
- Computation: `AssetExposure.java`, `AccessPathUpdater.java`, `AccessPathHandler.java`
- Schema: `product_package/conf/adsm/data-dictionary.xml` (`ADSMAccessPath*` tables)
- Frontend: `web/adsm/emberapp/lib/governance/`, `web/adsm/emberapp/vendor/js/z-graph.js`
- Help: `help/governance/how-to-manage-risk-exposure-using-admanager-plus.html`

---

## Comparison Matrix

| Vendor | Approach | Named edges | Vocabulary size | Extensible? | Public catalog? | MITRE-tagged |
|--------|----------|-------------|-----------------|-------------|-----------------|--------------|
| **BloodHound / SpecterOps** | Static + OpenGraph | Yes | ~250 | ✅ (OpenGraph) | ✅ Full | Partial |
| **Microsoft Exposure Mgmt** | Dynamic (KQL graph) | Open-ended string | Unbounded (discover via KQL) | ✅ (any source) | ❌ (by design) | ✅ |
| **XM Cyber** | Simulation | MITRE-tagged | ~50 (MITRE) | Via MITRE | ⚠️ Partial | ✅ Native |
| **Google SecOps (Chronicle)** | Hybrid | Yes (small) | **6** + 140 event types | Via custom parsers | ✅ Full | ✅ |
| **Splunk ES** | Tabular joins | None (implicit) | N/A | ✅ (any field) | N/A | Via CIM |
| **Palo Alto Cortex XSIAM** | Causality tree | Generic verbs | ~7–10 | ❌ | ❌ | ✅ |
| **CrowdStrike Falcon** | Process tree + identity | Generic + BH-style | ~15–20 (identity) | ❌ | ❌ | ✅ |
| **SentinelOne Singularity** | Storyline ID | None (causal) | 0 (MITRE on identity) | ❌ | ❌ | Identity only |
| **ADMP Governance (ManageEngine)** | Static (BH subset) | Yes | **18 fixed** | ❌ (no extension) | ✅ Full (in-source) | ❌ |

---

## Cross-Vendor Pattern Analysis

Looking across all 8 vendors, four clear patterns emerge:

### Pattern 1: Edge-count distribution is tri-modal
- **High catalog:** BloodHound at ~250 (extensible via OpenGraph), ADMP Governance at 18 (no extension).
- **Open / dynamic:** Microsoft (no catalog at all — `EdgeLabel` is a free string column).
- **Lightweight hybrid:** 0–20 named edges + properties + event-types (Chronicle, CrowdStrike Identity, XM Cyber, Palo Alto).
- The middle band (10–50 named edges with no extension hook) is where ADMP sits — **highest risk position**: too many edges to be flexible, too few to compete with BloodHound's research depth, and no escape hatch.

### Pattern 2: MITRE ATT&CK is the universal second axis
6 of 8 vendors tag edges/paths with MITRE technique IDs. This works because:
- MITRE is maintained externally (no vendor lock-in for the taxonomy).
- Analysts already know it.
- It evolves on its own schedule.
- It complements (doesn't replace) the named-edge model.

### Pattern 3: "Causality" is winning over "Pattern matching" for endpoint
Palo Alto (CGO), CrowdStrike (Process Tree), SentinelOne (Storyline) all use **process-ancestry causal grouping** instead of named edges for endpoint telemetry. Reason: process trees are deterministic and don't need a vocabulary.

### Pattern 4: Identity gets BloodHound-style; everything else gets generic
CrowdStrike Identity, SentinelOne Identity, and XM Cyber all switch to richer named-edge vocabularies *only* for identity/AD data. For cloud, network, endpoint — generic verbs win.

---

## Recommendations for V5

1. **Don't try to match BloodHound's 250 edges.** That's their decade-long moat from AD/ESC research.
2. **Adopt Chronicle's hybrid model as the baseline:**
   - 6–10 stable named relations (`OWNS`, `MEMBER_OF`, `ADMINISTERS`, `EXECUTES`, `CONNECTS_TO`, `ACCESSED`, `DOWNLOADED_FROM`, `AUTHENTICATED_AS`)
   - Behavioural event-type as dynamic edge label (~50 from our existing event taxonomy)
   - Rich properties on every edge: `risk_score`, `prevalence`, `last_seen`, `mitre_technique`, `confidence`
3. **Steal BloodHound's edge property model wholesale:** `traversable`, `composition`, `cost`, `last_seen`, `isacl`. These are independent of vocabulary size.
4. **Steal OpenGraph:** a JSON ingest endpoint that lets customers add new entity/edge kinds without a code release is the single biggest UX win BH shipped in 2024.
5. **Steal the Tier-Zero / Critical Asset concept** (BH + Microsoft) — pre-classified "crown jewel" nodes that path queries terminate at (analogous to our `criticality_tier` flag).
6. **Tag every edge with MITRE technique IDs** — joins us to the universal taxonomy used by 6 of 8 competitors and removes pressure to invent our own attack vocabulary.
7. **Don't go full Splunk** (no relations at all → only joins). Kills graph queries.
8. **Use causal grouping (`story_id`) for endpoint events** alongside named edges — it's how Palo Alto, CrowdStrike, and SentinelOne handle the volume problem.

**Bottom line:** The hybrid pattern is what **Chronicle and CrowdStrike Identity have already converged on**. Adopting it is low-risk, well-validated, and leaves room to grow toward BloodHound-density for AD specifically if the market demands it later.

---

## Play-the-Attack Timeline — Competitor Precedent

The **Play** chip we ship in V5 (chronological replay of the kill-chain on the same incident graph the analyst is already looking at) is **not a net-new SOC concept** — it has direct precedent in **Microsoft Defender XDR's Attack Story** and parallels in three other XDR/SecOps suites. This section catalogs who shipped what, so the V5 design is defensible in PM reviews.

### Direct precedent — Microsoft Defender XDR · *Attack Story*

From Microsoft's official *Investigate incidents in the Microsoft Defender portal* documentation, the **Attack story** view on every incident page includes the ability to:

> *"Play the alerts and the nodes on the graph as they occurred over time to understand the chronology of the attack."*

Microsoft ships an animated demo of the feature in the docs (`play-alert-attack-story.gif`). The mechanics are essentially identical to V5: same incident graph, a Play control above the canvas, nodes/edges light up step-by-step in chronological order, and the analyst keeps full investigation context (entity sliders, go-hunt, isolate-device, etc.) on the side.

- Source: <https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents#attack-story>
- Demo GIF: <https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/play-alert-attack-story.gif>
- Status: GA today (Microsoft Defender XDR, formerly Microsoft 365 Defender)

### Adjacent — graph + chronology, no explicit *Play* button

| Vendor | Feature | Mental model |
|---|---|---|
| **Palo Alto Cortex XDR / XSIAM** | *Causality View* | Causality chain rendered as a tree; analyst scrubs through it chronologically. No explicit play, but same time-anchored graph idea. |
| **CrowdStrike Falcon** | *Incident Workbench* + Process Tree replay | Time-scrub over the process tree with cross-host pivots. |
| **SentinelOne Singularity** | *Storyline* (S1QL `storyline_id`) | Auto-correlated graph with timeline scrubber; events re-played by storyline ID. |
| **Google SecOps (Chronicle / Mandiant)** | Case timeline + entity graph | Timeline scrubber tied to UDM events on the graph. |
| **Splunk Enterprise Security / Mission Control** | Investigation timeline | Time-scrub over events, less graph-centric. |
| **IBM QRadar Suite** | *Threat Investigator* timeline | Chronological replay of correlated observables. |

### Where V5 differentiates

V5's Play feature reaches Defender-XDR parity but **adds two tiers Defender doesn't surface on the graph today**:

1. **AI-correlated tier** (✨ glyph) — events the AI agent enriched after Start Investigation, distinct from raw observed events.
2. **Predicted tier** (⏱ amber) — projected next steps in the kill chain (e.g. LSASS dump, DC pivot) shown *on the same graph and the same timeline* as observed events. Defender's blast-radius graph shows *possible attack paths* but not *time-stamped predicted events on the replay timeline*.

Combined with the **partial-mode → Start Investigation → full-graph reveal** flow (which no competitor ships today), this gives Log360 a defensible "Defender-Attack-Story-plus-AI-prediction" positioning for the alert-investigation workflow.

### Implication for the Log360 product line

ManageEngine Log360 / ADAudit Plus / EventLog Analyzer **do not currently ship a play-the-attack-on-the-graph experience**. Adopting it in V5 closes a clear capability gap against Microsoft Defender XDR (the most-cited XDR competitor in PM briefs) without entering uncharted UX territory — Defender has already validated the pattern in production with enterprise SOCs.

---

## References

### BloodHound / SpecterOps
- Schema overview: https://bloodhound.specterops.io/resources/nodes/overview
- Edge reference (full ~250-entry catalog): https://bloodhound.specterops.io/resources/edges/overview
- ADCS edges (ESC1–ESC15): https://bloodhound.specterops.io/resources/edges/adcs-esc1
- OpenGraph spec: https://bloodhound.specterops.io/opengraph/overview
- SharpHound collector: https://bloodhound.specterops.io/collect-data/ce-collection/sharphound
- AzureHound collector: https://bloodhound.specterops.io/collect-data/ce-collection/azurehound
- "Six Degrees of Domain Admin" (DEFCON 24, 2016): https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf

### Microsoft
- Security Exposure Management overview: https://learn.microsoft.com/en-us/security-exposure-management/
- Critical asset management: https://learn.microsoft.com/en-us/security-exposure-management/critical-asset-management

### XM Cyber
- Platform overview: https://www.xmcyber.com/platform/
- Attack path analysis: https://www.xmcyber.com/use-cases/attack-path-management/

### Google SecOps (Chronicle) ✅
- UDM field list: https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list
- UDM usage guide: https://docs.cloud.google.com/chronicle/docs/unified-data-model/udm-usage
- Entity graph YARA-L examples: https://docs.cloud.google.com/chronicle/docs/reference/sample-yaral-for-native-dashboard

### Splunk
- CIM data model: https://docs.splunk.com/Documentation/CIM/latest/User/Overview
- Asset & Identity framework: https://docs.splunk.com/Documentation/ES/latest/Admin/Manageassetsandidentities

### Palo Alto Networks
- Cortex XSIAM: https://www.paloaltonetworks.com/cortex/cortex-xsiam
- Cortex XDR Causality Chain: https://docs-cortex.paloaltonetworks.com/

### CrowdStrike
- Identity Protection: https://www.crowdstrike.com/en-us/platform/identity-protection/
- Falcon Insight XDR: https://www.crowdstrike.com/platform/insight-xdr/

### SentinelOne
- Singularity Identity: https://www.sentinelone.com/platform/singularity-identity/
- Storyline technology: https://www.sentinelone.com/platform/singularity-platform/

### Play-the-Attack Timeline (§14)
- Microsoft Defender XDR — Investigate incidents (Attack story): https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents#attack-story
- Microsoft Defender XDR — Attack story Play demo (GIF): https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/play-alert-attack-story.gif
- Palo Alto Cortex XDR — Causality View: https://docs-cortex.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/investigation-and-response/investigate-incidents/causality-view
- SentinelOne Storyline: https://www.sentinelone.com/platform/singularity-platform/
- CrowdStrike Incident Workbench: https://www.crowdstrike.com/platform/insight-xdr/
- Google SecOps case timeline + entity graph: https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list

> ⚠️ **Source caveat:** Chronicle and BloodHound data are verified from official docs. Splunk, Palo Alto, CrowdStrike, SentinelOne sections are from public product knowledge as authoritative pages either redirect, 404, or sit behind login walls — anyone validating should pull the gated docs directly.
