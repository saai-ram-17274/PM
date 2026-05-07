# V5 Relation Catalog — Canonical Edge Vocabulary

> **Generated**: 07 May 2026
> **Purpose**: Documents the canonical relation taxonomy used by the V5 Alert Investigation prototype. Defines all edge types that can appear between entities on the graph, their semantics, the legacy synonyms they replace, and the source-of-truth in code.
> **Source of truth**: [`REL_GUIDE`](js/v4-extras.js) and [`REL_ALIASES`](js/v4-extras.js) in `js/v4-extras.js`.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ Active | Canonical relation — use this name for new data |
| ♻ Alias | Legacy name — auto-resolved to a canonical relation via `REL_ALIASES` |
| ⚠ Removed | No longer in catalog (collapsed into another relation) |

---

## Design Principles

1. **PascalCase only** — no `UPPER_SNAKE`, no `kebab-case`, no `camelCase`. One naming style for predictable lookups.
2. **One direction per relation** — inverses (e.g. `ParentOf` for `SpawnedBy`) are represented by **reversing source/target**, not by adding a second relation name.
3. **Synonyms are collapsed** — semantically equivalent edges are merged (e.g. `BelongsTo` → `OwnedBy`). Sub-type information (transport, protocol, mechanism) lives in **edge properties**, not edge names.
4. **Categorized for UI** — every relation belongs to one of 7 categories so the Relationship Guide popup can group them visually.
5. **Backward-compatible** — legacy names continue to work via the alias map; `canonicalRelation(label)` is called before any `REL_GUIDE` lookup.

---

## 1. Detection (2 relations)

| # | Relation | Icon | Color | Description |
|---|----------|------|-------|-------------|
| 1 | `TriggeredBy` | ⚡ | `#DD1616` | A detection rule or correlation alert was triggered due to the suspicious behavior or anomalous activity of this entity. Connects an alert to the primary entity responsible for the triggering event. |
| 2 | `DetectedOn` | 🔍 | `#FABB34` | The alert or detection event was observed on this service, platform, or system. Links an alert to the infrastructure component where the suspicious activity was recorded. |

**Direction:** `Alert → Entity` for `TriggeredBy`; `Alert → Service/Host` for `DetectedOn`.

---

## 2. Identity & Access (5 relations)

| # | Relation | Icon | Color | Description |
|---|----------|------|-------|-------------|
| 3 | `LoginTo` | 🔐 | `#2C66DD` | A user or service account authenticated and established a session on a target service, device, or application. Captured from authentication logs. |
| 4 | `AccessedFrom` | 🌐 | `#f97316` | A user session or activity originated from this source IP address. Traces the network origin of the session — useful for geographic anomalies or VPN/proxy usage. |
| 5 | `IssuedTo` | 📜 | `#0891b2` | An identity provider (Azure AD, Okta, ADFS) issued an authentication token, OAuth credential, or certificate to an entity, granting it access to downstream services. |
| 6 | `MemberOf` | 👥 | `#2C66DD` | A user or service account is a member of a security group, distribution list, or organizational unit. Tracks identity-to-group membership relevant for privilege analysis. |
| 7 | `OwnedBy` | 👤 | `#2C66DD` | A resource, application, or device is owned, assigned to, or managed by a specific user, service account, or organizational unit. Identifies the responsible party for an asset. |

---

## 3. Privilege (2 relations)

| # | Relation | Icon | Color | Description |
|---|----------|------|-------|-------------|
| 8 | `EscalatedTo` | ⬆️ | `#FF5900` | A user or process escalated privileges to a higher-level account or role. Detects lateral movement and privilege-escalation attempts such as local-admin elevation or token impersonation. |
| 9 | `GrantedAccess` | 🔓 | `#FF5900` | An identity provider or administrator granted access permissions, roles, or entitlements to an entity. Tracks permission changes that could indicate unauthorized access provisioning. |

---

## 4. Data Movement (4 relations)

| # | Relation | Icon | Color | Description |
|---|----------|------|-------|-------------|
| 10 | `AccessedFile` | 📁 | `#7c3aed` | An entity performed a file operation (read, write, modify) on a file-hosting service such as SharePoint, OneDrive, or a network share. Tracks data access patterns. |
| 11 | `DownloadedFrom` | ⬇️ | `#D14900` | An entity downloaded data or files from an external or internal source. Tracks inbound data transfers that may include malware delivery or unauthorized content retrieval. |
| 12 | `UploadedTo` | ⬆️ | `#D14900` | An entity uploaded data or files to a cloud service, external server, or removable media. Critical for detecting data exfiltration to external destinations. |
| 13 | `ExfiltratedTo` | 🚨 | `#DD1616` | Sensitive data was transferred to an unauthorized external destination. High-severity edge indicating confirmed or suspected data exfiltration via network, cloud, or physical channels. |

---

## 5. Network (4 relations)

| # | Relation | Icon | Color | Description |
|---|----------|------|-------|-------------|
| 14 | `CommunicatedWith` | 📡 | `#DD1616` | A device or IP established network communication (TCP/UDP, DNS query, HTTP request) with an external domain or host. Critical for C2 callback and exfiltration detection. **Transport details (VPN/gateway/interface) are carried as edge properties, not as separate relation names.** |
| 15 | `TunneledThrough` | 🕳️ | `#198019` | Network traffic was encapsulated through a tunnel (VPN, SSH, DNS, or ICMP). Detects covert communication channels used to bypass network security controls. |
| 16 | `ProxiedBy` | 🔀 | `#198019` | Network traffic was routed through a proxy server, load balancer, or anonymization service. Identifies traffic obfuscation and the actual origin behind proxied connections. |
| 17 | `ResolvedTo` | 📌 | `#198019` | An IP address was mapped to a specific device or hostname through DNS resolution or DHCP lease records. Links network-layer addresses to physical or virtual endpoints. |

---

## 6. Process (2 relations)

| # | Relation | Icon | Color | Description |
|---|----------|------|-------|-------------|
| 18 | `ExecutedOn` | ▶️ | `#7c3aed` | A process or binary was executed on a specific device or endpoint. Tracks which programs ran on which hosts — essential for identifying malicious execution chains. |
| 19 | `SpawnedBy` | 🔗 | `#7c3aed` | A child process was spawned by a parent process. Maps the process tree to detect suspicious chains such as Word spawning PowerShell or cmd.exe launching encoded scripts. **The inverse `ParentOf` is represented by reversing source/target.** |

---

## 7. Email (2 relations)

| # | Relation | Icon | Color | Description |
|---|----------|------|-------|-------------|
| 20 | `SentTo` | 📤 | `#0891b2` | An email was sent from one entity to another. Tracks outbound email relevant for phishing campaigns, social engineering, and insider-threat patterns. **The inverse `ReceivedFrom` is represented by reversing source/target.** |
| 21 | `ContainedAttachment` | 📎 | `#0891b2` | An email contained a file attachment. Links email messages to attached files for tracking malware delivery, macro-enabled documents, and executable payloads. |

---

## 8. System Change (3 relations)

| # | Relation | Icon | Color | Description |
|---|----------|------|-------|-------------|
| 22 | `ModifiedRegistry` | 🔧 | `#D14900` | A process or user modified a Windows registry key or value. Tracks persistence mechanisms, startup entries, and configuration changes commonly used by malware. |
| 23 | `CreatedService` | ⚙️ | `#D14900` | A process or user installed a new system service or scheduled task. Detects persistence techniques, backdoor installation, and unauthorized service creation. |
| 24 | `InstalledOn` | 💿 | `#D14900` | A software package, driver, or update was installed on a device. Tracks software deployment events for detecting unauthorized installations or trojanized updates. |

---

## 9. Legacy Aliases

These names are accepted as input (e.g. from older datasets, SVG markup, or pre-canonicalization edge data) and are auto-resolved to their canonical equivalents by `canonicalRelation(label)` before any `REL_GUIDE` lookup. **Do not use these names in new code.**

| Legacy Name | → Canonical | Reason |
|-------------|-------------|--------|
| `TRIGGERED_BY` | `TriggeredBy` | Casing normalization (UPPER_SNAKE → PascalCase) |
| `DETECTED_ON` | `DetectedOn` | Casing normalization |
| `ISSUED` | `IssuedTo` | Casing + clarified direction (issuer → recipient) |
| `BelongsTo` | `OwnedBy` | Synonym — both mean asset-ownership |
| `ParentOf` | `SpawnedBy` | Inverse — represented by reversing source/target |
| `ReceivedFrom` | `SentTo` | Inverse — represented by reversing source/target |
| `ConnectedVia` | `CommunicatedWith` | Synonym — transport (VPN/gateway/interface) is now an edge property |

---

## 10. Code References

| Artifact | File | Purpose |
|----------|------|---------|
| `REL_GUIDE` (24 entries) | [`js/v4-extras.js`](js/v4-extras.js) | Canonical catalog: `key`, `category`, `color`, `icon`, `name`, `desc` |
| `REL_ALIASES` (7 entries) | [`js/v4-extras.js`](js/v4-extras.js) | Legacy → canonical mapping |
| `canonicalRelation(label)` | [`js/v4-extras.js`](js/v4-extras.js) | Helper used by `showEdgeRelation()` for alias-aware lookup |
| `EDGE_ATTRIBUTES` | [`js/v4-extras.js`](js/v4-extras.js) | Per-edge instance data; `relation` field uses canonical names |
| `<line data-label="…">` / `<g data-label="…">` | [`js/graph.js`](js/graph.js) | SVG markup; all `data-label` attributes use canonical names |
| `toggleRelGuide()` | [`js/v4-extras.js`](js/v4-extras.js) | Renders the popup, grouped by `category` in this order: Detection → Identity & Access → Privilege → Data Movement → Network → Process → Email → System Change |

---

## 11. How to Add a New Relation

1. Pick a category (or add a new one to `catOrder` in `toggleRelGuide`).
2. Append a `{ key, category, color, icon, name, desc }` entry to `REL_GUIDE` in `js/v4-extras.js`.
3. Use **PascalCase** for `key`. If the relation has a natural inverse, **do not** add the inverse — represent it by swapping source/target.
4. If the relation is a synonym for an existing canonical, **do not** add a new `REL_GUIDE` entry — add an alias to `REL_ALIASES` instead.
5. Update this document's relevant section (1–8) and re-number.

---

## 12. Changelog

| Date | Change |
|------|--------|
| 07 May 2026 | Initial canonical catalog. Reduced 27 ad-hoc relations → 24 canonical + 7 aliases. Normalized casing, collapsed inverses (`ParentOf`, `ReceivedFrom`), merged synonyms (`BelongsTo`, `ConnectedVia`). Added `category` field and grouped popup UI. |
