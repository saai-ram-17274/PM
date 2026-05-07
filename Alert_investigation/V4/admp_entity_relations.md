# ADMP / ADSM (ManageEngine ADManager Plus) — Entity & Relationship Model

> Compiled: 07 May 2026
> Source repo: `REPOS/adsm`
> Companion to `competitor_edge_analysis.md`.
> Evidence-based — every claim links back to a source file in the repo.

---

## TL;DR

ADMP models AD as a **relational graph**, not a native graph DB:

- **Nodes** = `User`, `Group`, `Computer`, `OU`, `Contact`, `Domain`, `GPO`, `Mailbox`, `Role`, `Technician`, `Workflow Request`
- **Edges** = stored in **denormalized join tables** (`ADSMLinkedAttrMemberDetails`, `ADSMNestedLinkedAttrMemberDetails`, `ADSMLinkedAttrManagerDetails`, `ADSMCrossDomainMemberDetails`)
- **Source of truth** = live AD via LDAP, but **all reports/UI queries hit a synchronized local DB** (MySQL/PostgreSQL/MSSQL)
- **No graph DB** — pure SQL with type-discriminator columns + `HIERARCHY_PATH` for transitive nesting
- **No "edge label" vocabulary** — relationships are encoded as **separate join tables per relation kind**

---

## 1. Entity Inventory

| Entity | Master Table | Source File |
|--------|-------------|-------------|
| **User** | `ADSMUserGeneralDetails`, `ADSMUserMemberOf` | [AdUser.java](source/java_source/server/com/adventnet/sym/adsm/serverapi/AdUser.java) |
| **Group** | `ADSMGroupGeneralDetails`, `ADSMGroupMembers`, `ADSMGroupMemberOf` | [GroupHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/reports/GroupHandler.java) |
| **Computer** | `ADSMComputerGeneralDetails` | [ComputerHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/reports/ComputerHandler.java) |
| **OU** | `ADSMOUDetails` (`PARENT_OU_ID` FK) | [OUHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/reports/OUHandler.java) |
| **Contact** | `ADSMContactGeneralDetails` | [LinkedAttributesUtil.java](source/java_source/server/com/adventnet/sym/adsm/common/server/util/LinkedAttributesUtil.java) |
| **Domain** | `ADSMDomainConfiguration` | [data-dictionary.xml](product_package/conf/adsm/data-dictionary.xml) |
| **GPO** | Multiple GPO tables | [GPOMgmtHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/gpomgmt/GPOMgmtHandler.java) |
| **Exchange Mailbox** | Exchange-specific tables | [ExchangeHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/ExchangeHandler.java) |
| **Technician (admin)** | `AAALOGIN` + role FKs | [DBSyncHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/dbsync/DBSyncHandler.java) |
| **Role** | ADMP micro-roles | [ADMPRoleHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/admin/authentication/ADMPRoleHandler.java) |
| **Workflow Request** | Orchestration tables | [OrchestrationProfile.java](source/java_source/server/com/adventnet/sym/adsm/common/server/automation/orchestration/OrchestrationProfile.java) |
| **DirectoryObject (base)** | `ADMPObjects` (registry) | [DirectoryObject.java](source/java_source/server/com/adventnet/sym/adsm/common/server/model/DirectoryObject.java) |

The `ADMPObjects` table acts as a **registry**: maps `OBJECT_CLASS` → `OBJECT_ID` → `BASE_TABLE_NAME`. Loaded by [DirectoryObjectAPI.java](source/java_source/server/com/adventnet/sym/adsm/common/server/objects/DirectoryObjectAPI.java).

---

## 2. Relationship Model — the Heart of ADMP

ADMP uses **one join table per relation kind**, not one big edge table with an `edge_type` column. Each relationship has its own schema.

### 2.1 Canonical join table: `ADSMLinkedAttrMemberDetails`

Used for **User↔Group, Group↔Group, Computer↔Group, Contact↔Group** memberships.

```
ADSMLinkedAttrMemberDetails
├── UNIQUE_ID                  (PK)
├── FRONTLINK_OBJECT_ID        FK → Group.UNIQUE_ID
├── BACKLINK_OBJECT_ID         FK → User|Group|Computer|Contact.UNIQUE_ID
├── BACKLINK_OBJECT_TYPE_ID    1=User, 2=Group, 3=Computer, 4=Contact
├── IS_PRIMARY_GROUP_LINK      bool — true for primary group
└── HIERARCHY_PATH             (used for nesting traversal)
```

Evidence: [LinkedAttributesUtil.java#L36-L53](source/java_source/server/com/adventnet/sym/adsm/common/server/util/LinkedAttributesUtil.java).

The **type discriminator** (`BACKLINK_OBJECT_TYPE_ID`) is how ADMP keeps one join table for all member types — closest analog to BloodHound's `MemberOf` edge but resolved at SQL-query time, not graph-query time.

### 2.2 Full relationship inventory

| Relationship | Storage | Cardinality | Mechanism |
|--------------|---------|-------------|-----------|
| User ↔ Group (direct) | `ADSMLinkedAttrMemberDetails` | M:N | Join table + type discriminator |
| User ↔ Group (memberOf) | `ADSMUserMemberOf` (materialized view) + join table | M:N | Denormalized for fast user-side lookup |
| Group ↔ Group (nesting) | `ADSMNestedLinkedAttrMemberDetails` + `HIERARCHY_PATH` | M:N recursive | Path-based, computed at sync |
| User ↔ Manager | `ADSMLinkedAttrManagerDetails` | M:1 | Separate join table |
| User ↔ OU | `ADSMUserGeneralDetails.PARENT_OU_ID` + DN parsing | M:1 | FK + DN walk |
| Computer ↔ OU | Same pattern as User↔OU | M:1 | FK + DN walk |
| OU ↔ OU (hierarchy) | `ADSMOUDetails.PARENT_OU_ID` | 1:N | Parent FK |
| User → PrimaryGroup | `ADSMLinkedAttrMemberDetails` with `IS_PRIMARY_GROUP_LINK=true` | M:1 | Flag in join table |
| GPO ↔ OU | GPO linkage tables | M:N | LDAP path-derived |
| Cross-domain members | `ADSMCrossDomainMemberDetails` | M:N | Foreign domain SID |
| User ↔ Computer | **Not stored directly** — computed via group membership chains | — | Implicit, derived |

### 2.3 What's missing vs. BloodHound

ADMP does **not model** these as first-class edges (the AD ACE-abuse edges that make BloodHound powerful):

- `GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDacl`
- `ForceChangePassword`, `AddMember`, `AddSelf`
- `AllowedToAct`, `AllowedToDelegate` (Kerberos delegation)
- `ADCSESC1…ESC15` (certificate abuse)
- `HasSession`, `CanRDP`, `CanPSRemote`

Permissions/ACLs are exposed for **management** (e.g. delegate "Reset Password" to a help-desk technician via [PermissionObject.java](source/java_source/server/com/adventnet/sym/adsm/security/server/model/PermissionObject.java)) but not as **traversable graph edges** for attack-path analysis. ADMP is an AD **management** tool, not an attack-graph tool.

---

## 3. Persistence Layer

| Aspect | Detail |
|--------|--------|
| **ORM** | Custom AdventNet `com.adventnet.ds.query` framework (`SelectQueryImpl`, `Criteria`, `Column`, `Table`, `Join`). NOT Hibernate. |
| **Persistence interface** | `com.adventnet.persistence.DataObject`, `Row` |
| **Supported DBs** | MySQL, PostgreSQL, MSSQL |
| **Schema source of truth** | [product_package/conf/adsm/data-dictionary.xml](product_package/conf/adsm/data-dictionary.xml) — XML DTD with PK/FK/nullable constraints |
| **Object-class registry** | `ADMPObjects` table (via [DirectoryObjectAPI.java](source/java_source/server/com/adventnet/sym/adsm/common/server/objects/DirectoryObjectAPI.java)) |

Typical query pattern (membership lookup):

```java
SelectQuery sq = new SelectQueryImpl(Table.getTable("ADSMLinkedAttrMemberDetails"));
sq.addJoin(new Join("ADSMLinkedAttrMemberDetails", "ADSMGroupGeneralDetails",
    new String[]{"FRONTLINK_OBJECT_ID"}, new String[]{"UNIQUE_ID"}, Join.INNER_JOIN));
sq.addJoin(new Join("ADSMLinkedAttrMemberDetails", "ADSMUserGeneralDetails",
    new String[]{"BACKLINK_OBJECT_ID"}, new String[]{"UNIQUE_ID"}, Join.INNER_JOIN));
sq.setCriteria(new Criteria(
    Column.getColumn("ADSMLinkedAttrMemberDetails", "BACKLINK_OBJECT_TYPE_ID"),
    1, QueryConstants.EQUAL));   // 1 = User
DataObject result = CommonUtil.getPersistence().get(sq);
```

Evidence: [ADViewerUtil.java#L143-L223](source/java_source/server/com/adventnet/sym/adsm/adviewer/server/util/ADViewerUtil.java), [DefaultPercentileCalculator.java](source/java_source/server/com/adventnet/sym/adsm/common/server/ziaassistant/accessinsights/accessanalyzer/DefaultPercentileCalculator.java).

---

## 4. Source of Truth — Hybrid Live/Cached

```
        ┌──────────────────────────────┐
   AD ──┤ LDAP (live)                  │── ADHandler.java (real-time read for change ops)
        └──────────────┬───────────────┘
                       │ scheduled + on-demand sync
                       ▼
        ┌──────────────────────────────┐
        │ ADSyncImpl                   │
        │ GroupMemberSyncImpl          │── computes transitive nesting
        │ DBSyncHandler                │── pushes technician/role changes
        └──────────────┬───────────────┘
                       ▼
        ┌──────────────────────────────┐
        │ Local DB (MySQL/PG/MSSQL)    │── PRIMARY source for all reports & UI
        │  ├─ Detail tables            │
        │  ├─ Link tables              │
        │  └─ HIERARCHY_PATH cache     │
        └──────────────────────────────┘
```

| Component | Behavior | Evidence |
|-----------|----------|----------|
| Live LDAP | Real-time directory ops (create user, reset password) go straight to AD | [ADHandler.java#L1724-L1859](source/java_source/server/com/adventnet/sym/adsm/common/server/ADHandler.java) |
| Sync daemon | Periodic full + delta sync from AD → local DB | [ADSyncImpl.java](source/java_source/server/com/adventnet/sym/adsm/common/server/adsync/ADSyncImpl.java), [GroupMemberSyncImpl.java](source/java_source/server/com/adventnet/sym/adsm/common/server/adsync/GroupMemberSyncImpl.java) |
| On-demand sync | "Sync Now" button | [DBSyncHandler.java#L29-L39](source/java_source/server/com/adventnet/sym/adsm/common/server/dbsync/DBSyncHandler.java) `synchronizeNow()` |
| Domain cache | In-memory singleton for domain metadata, GC, SIDs | [DomainInfoCache.java#L35-L37](source/java_source/server/com/adventnet/sym/adsm/common/server/DomainInfoCache.java) |
| Reports & UI | **Always hit local DB** — never live LDAP | All `*Handler.java` reports use `Table.getTable(...)` |

**Key consequence:** group nesting / membership chains are computed **once at sync time** into `ADSMNestedLinkedAttrMemberDetails` with a `HIERARCHY_PATH` column, so report queries are flat SQL JOINs (no recursive CTEs).

---

## 5. Reporting Model

Reports are **multi-table SQL JOINs** on link tables + detail tables.

| Report | Joins |
|--------|-------|
| Group Membership | `ADSMGroupGeneralDetails` ⨝ `ADSMLinkedAttrMemberDetails` ⨝ `ADSMUserGeneralDetails` |
| Nested Group | + `ADSMNestedLinkedAttrMemberDetails` (uses `HIERARCHY_PATH`) |
| User's Groups (memberOf) | `ADSMUserMemberOf` ⨝ `ADSMLinkedAttrMemberDetails` |
| Cross-Domain Membership | `ADSMCrossDomainMemberDetails` ⨝ domain cache |
| Manager Chain | `ADSMLinkedAttrManagerDetails` recursive on `BACKLINK_OBJECT_ID` |

Evidence: [GroupHandler.java#L57](source/java_source/server/com/adventnet/sym/adsm/common/server/reports/GroupHandler.java), [DefaultPercentileCalculator.java#L24-L48](source/java_source/server/com/adventnet/sym/adsm/common/server/ziaassistant/accessinsights/accessanalyzer/DefaultPercentileCalculator.java).

---

## 6. Workflow & Delegation

| Entity | Storage | Purpose |
|--------|---------|---------|
| Technician | `AAALOGIN` + role FK | Admin user with role assignments |
| Role (Admin) | `ADSMMicroRoles` | User-mgmt, GPO-mgmt, etc. |
| Delegation scope | Delegation tables | Which technician → which domain/OU/group |
| Workflow Request | Orchestration tables | "Add user to group" requests |
| Workflow Approval | Same + status | Approval chain |
| Helpdesk Role | `HDTDomainHandler` + technician | Domain-scoped helpdesk access |

Evidence: [DBSyncHandler.java#L45-L60](source/java_source/server/com/adventnet/sym/adsm/common/server/dbsync/DBSyncHandler.java), [TechnicianHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/delegation/TechnicianHandler.java), [OrchestrationProfile.java](source/java_source/server/com/adventnet/sym/adsm/common/server/automation/orchestration/OrchestrationProfile.java).

---

## 7. Graph / Hierarchy Visualization

ADMP renders AD as **trees**, not graphs. Closest things to graph code:

| Component | Purpose | Evidence |
|-----------|---------|----------|
| `TreeObject` interface | Base for all hierarchical objects | [TreeObject.java#L9](source/java_source/server/com/adventnet/sym/adsm/common/server/model/TreeObject.java) |
| `DirectoryObjectTreeModel` | Swing `TreeModel` for AD hierarchy | [DirectoryObjectTreeModel.java](source/java_source/server/com/adventnet/sym/adsm/common/server/model/DirectoryObjectTreeModel.java) |
| `DirectoryObjectTreeNode` | Parent-child tree node | [DirectoryObjectTreeNode.java](source/java_source/server/com/adventnet/sym/adsm/common/server/model/DirectoryObjectTreeNode.java) |
| OU picker tree | Tree picker for OU selection | [OUDataSource.java#L58](source/java_source/server/com/adventnet/sym/adsm/common/server/popup/datasource/OUDataSource.java) |
| Circular group detection | Cycle detection in nesting | [SupportHandler.java#L745](source/java_source/server/com/adventnet/sym/adsm/common/server/support/SupportHandler.java) `getCircularGroups()` |
| Deep-nesting detection | Depth analysis | [SupportHandler.java#L749](source/java_source/server/com/adventnet/sym/adsm/common/server/support/SupportHandler.java) `getDeepNestedGroups(domain, 3)` |
| Access Hierarchy (Zia AI) | AI-powered access insight | [UserContext.java#L102-L119](source/java_source/server/com/adventnet/sym/adsm/common/server/ziaassistant/accessinsights/UserContext.java) `getAccessHierarchyValues()` |
| Permission tree | ACL tree with selected/undetermined nodes | [PermissionObject.java](source/java_source/server/com/adventnet/sym/adsm/security/server/model/PermissionObject.java) |
| Orchestration GraphState | Workflow state machine (not entity graph) | [ToolRepository.java#L11-L27](source/java_source/server/com/adventnet/sym/adsm/common/server/ziaassistant/tools/ToolRepository.java) |

**No attack-path / blast-radius / shortest-path graph UI.** Trees only.

---

## 8. Key Design Patterns

1. **One join table per relation kind** — `ADSMLinkedAttrMemberDetails` (membership), `ADSMLinkedAttrManagerDetails` (manager), `ADSMNestedLinkedAttrMemberDetails` (transitive nesting). No generic edge table with `edge_type` column.
2. **Type discriminator** — `BACKLINK_OBJECT_TYPE_ID` (1=User, 2=Group, 3=Computer, 4=Contact) lets one join table cover heterogeneous member types.
3. **Materialized transitive closure** — group nesting flattened at sync time into `ADSMNestedLinkedAttrMemberDetails` + `HIERARCHY_PATH`. No recursive SQL needed for reports.
4. **DN-derived hierarchy** — OU parent-child relations encoded in LDAP DN; reconstructed by parsing.
5. **Sync-driven consistency** — local DB is primary; LDAP is consulted only for write ops or explicit refresh.
6. **Tree-based UI** — `TreeObject` composite pattern; no force-directed graph rendering.
7. **Cross-domain isolation** — separate `ADSMCrossDomainMemberDetails` instead of polluting main link table with foreign SIDs.
8. **Object-class registry** — `ADMPObjects` table abstracts entity-type → table-name mapping; allows runtime extensibility.

---

## 9. Where ADMP Sits in the Competitive Landscape

Mapping ADMP onto the competitive matrix from `competitor_edge_analysis.md`:

| Dimension | ADMP |
|-----------|------|
| **Approach** | Relational graph (SQL link tables) |
| **Named edges** | Implicit — one table per relation kind |
| **Vocabulary size** | ~5 relation kinds (member, nested-member, manager, primary-group, cross-domain) |
| **Extensible?** | ❌ Adding a new relation = schema change + new table + sync code |
| **Public catalog?** | ✅ via [data-dictionary.xml](product_package/conf/adsm/data-dictionary.xml) |
| **MITRE-tagged?** | ❌ — ADMP is management, not detection |
| **Persistence** | RDBMS (MySQL/PG/MSSQL) — local cache |
| **Path queries** | ❌ No shortest-path / blast-radius |
| **Graph viz** | Tree only (no force-directed) |

### vs. competitors

- **vs. BloodHound** — ADMP has the same raw entity model (User, Group, Computer, OU, GPO, Contact, Domain) but **none of the abuse-edges** (`GenericAll`, `WriteDacl`, ADCS ESCs, Kerberos delegation). ADMP is a SQL-backed AD admin console; BloodHound is a Cypher-backed attack graph. Both source the same LDAP data.
- **vs. Microsoft Exposure Management** — Microsoft's KQL-graph approach is far more flexible (open-ended `EdgeLabel`); ADMP is rigid (one table per relation).
- **vs. Chronicle UDM** — Chronicle's hybrid model (small enum + event-types + properties) is much more SOC-friendly. ADMP's model is admin-friendly (clean SQL JOINs) but useless for behavioural correlation.

### What ADMP could borrow

If Log360/ADAudit Plus wants attack-path features for AD, the gap is:
1. **Add ACE/permission edges** (GenericAll, WriteDacl, etc.) as new link tables with the same `BACKLINK_OBJECT_TYPE_ID` pattern.
2. **Add session/logon edges** (HasSession, CanRDP) sourced from ADAudit Plus event data.
3. **Add a "Tier-Zero" flag** to `ADSMUserGeneralDetails` / `ADSMGroupGeneralDetails` (mirrors BH's Tier-Zero, Microsoft's Critical Asset).
4. **Layer a graph UI** on top — the SQL model already supports it; just need a viz component.

---

## 10. References (in repo)

- Schema: [product_package/conf/adsm/data-dictionary.xml](product_package/conf/adsm/data-dictionary.xml)
- Linked attributes: [LinkedAttributesUtil.java](source/java_source/server/com/adventnet/sym/adsm/common/server/util/LinkedAttributesUtil.java)
- Object registry: [DirectoryObjectAPI.java](source/java_source/server/com/adventnet/sym/adsm/common/server/objects/DirectoryObjectAPI.java)
- Sync: [ADSyncImpl.java](source/java_source/server/com/adventnet/sym/adsm/common/server/adsync/ADSyncImpl.java), [GroupMemberSyncImpl.java](source/java_source/server/com/adventnet/sym/adsm/common/server/adsync/GroupMemberSyncImpl.java)
- Tree model: [TreeObject.java](source/java_source/server/com/adventnet/sym/adsm/common/server/model/TreeObject.java), [DirectoryObjectTreeModel.java](source/java_source/server/com/adventnet/sym/adsm/common/server/model/DirectoryObjectTreeModel.java)
- Reports: [GroupHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/reports/GroupHandler.java), [OUHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/reports/OUHandler.java), [ComputerHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/reports/ComputerHandler.java)
- Cycle/depth detection: [SupportHandler.java](source/java_source/server/com/adventnet/sym/adsm/common/server/support/SupportHandler.java)
