# Competitor Analysis: Attack Path / Investigation Graph — Relationship & Edge Visualization

> **Date:** June 2025  
> **Purpose:** Benchmark how leading SIEM/XDR/EDR products visualize entity relationships and edges in their attack investigation graphs. Identify patterns, gaps, and differentiation opportunities for Log360 Cloud Alert Investigation.

---

## 1. Microsoft Defender XDR / Sentinel

### Graph Type: **Incident Attack Story Graph + Blast Radius Graph**

| Aspect | Details |
|---|---|
| **Graph Layout** | Force-directed entity graph showing the full scope of the attack. Nodes represent entities; edges represent relationships/alerts. |
| **Entity Types (Nodes)** | Users, Devices, IP Addresses, Files, Mailboxes, Apps, Cloud Resources. Each entity type has a distinct icon. |
| **Edge/Relationship Display** | Edges connect suspicious entities to related assets. **Dotted lines** for related alerts, **solid lines** for direct entity relationships. Edges are not explicitly labeled with relationship names on the canvas. |
| **Edge Click Behavior** | Clicking an entity opens a **side pane** with: Info tab (identifying details), Timeline tab (chronological events), Insights tab (ML-driven risk signals). No dedicated edge popup — context is entity-centric. |
| **Legend/Guide** | **Entity type filter** above the graph lets you toggle visibility of entity types (File, User, etc.). No explicit relationship/edge type legend. |
| **Filtering** | Filter by: Severity (High/Medium/Low), Status (New/In Progress/Resolved), Service Sources (Defender for Endpoint, Identity, Office 365). Entity type toggle to hide/show specific types. |
| **Timeline Integration** | Animated playback: alerts and nodes appear on the graph chronologically. Users can "play" the attack story over time. |
| **Blast Radius (Advanced)** | Right-click a node → "View blast radius" shows **possible lateral movement paths** (up to 7 hops). Shows attack path from entry point to critical targets. Paths shown with directional edges. |
| **Unique Features** | - AI-generated incident description via Copilot<br>- "Go Hunt" button on any entity for advanced hunting queries<br>- Blast radius replaces older "Attack Path Analysis"<br>- MITRE ATT&CK kill chain alignment in summary view |

### Screenshot References
- Attack story graph: `https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/play-alert-attack-story.gif`
- Entity details pane: `https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/review-entity-details-attack-story.gif`
- Blast radius graph: `https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/blast-radius-graph.png`
- Graph filter: `https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/incident-graph-filter-criteria.png`
- Entity type toggle: `https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/incident-graph-hide-entity.png`

---

## 2. Microsoft Sentinel (Investigation Graph)

### Graph Type: **Entity Investigation Graph**

| Aspect | Details |
|---|---|
| **Graph Layout** | Radial/force-directed graph centered on the investigated entity. Entities expand outward as you explore. |
| **Entity Types (Nodes)** | Users, Devices/Hosts, IP Addresses, Files, URLs, Azure Resources. Distinct icons per type. Color-coded by entity type. |
| **Edge/Relationship Display** | Edges are **auto-extracted from raw data**. Relationships shown as thin connecting lines. Labels appear on hover (e.g., "logged in to", "accessed"). Edges are directional. |
| **Edge Click Behavior** | Clicking an entity (not edge) expands the graph with "exploration queries" — pre-built queries that discover more related entities. Side panel shows entity-specific Info, Timeline, and Insights. |
| **Legend/Guide** | Minimal. Entity types distinguished by icon/color. Alert nodes shown with colored severity badges (red/orange/yellow). No formal relationship type legend. |
| **Filtering** | Time range filter. Entity scope narrowing via investigation bookmarks. |
| **Exploration** | "Exploration queries" per entity type allow expanding the graph dynamically. E.g., clicking a User shows: "Related Alerts", "Devices logged into", "Peer users". |
| **Unique Features** | - UEBA (User/Entity Behavior Analytics) integration<br>- "Top Insights" ML widget showing anomalies<br>- Bookmarking entities during investigation<br>- Graph auto-stitching from raw data across all log sources |

### Screenshot References
- Investigation graph: `https://learn.microsoft.com/en-us/azure/sentinel/media/investigate-cases/investigation-graph.png`
- Entity exploration: `https://learn.microsoft.com/en-us/azure/sentinel/media/investigate-cases/entity-exploration.png`

---

## 3. Palo Alto Cortex XDR

### Graph Type: **Causality Chain / Causality View**

| Aspect | Details |
|---|---|
| **Graph Layout** | **Horizontal tree (left-to-right)** process causality chain. Root process on the left, child processes branch rightward. Not a force-directed graph — it's a **process tree**. |
| **Entity Types (Nodes)** | Processes (primary), Files, Network connections, Registry modifications, Users. Nodes are **rectangular cards** (not circles) with process name, PID, user, and timestamp. |
| **Edge/Relationship Display** | Edges represent **parent-child process spawning** (solid arrows, left→right). Additional edges for: file operations, network connections, registry changes. Edges labeled implicitly by position in tree (parent spawns child). No explicit edge type labels on canvas. |
| **Edge Click Behavior** | Clicking a process node opens a **detail drawer** showing: Full command line, Process arguments, File hash, Signing info, Network connections, MITRE ATT&CK mapping. |
| **Legend/Guide** | Color-coded node borders: **Red** = malicious/alerted, **Orange** = suspicious, **Gray** = benign. Alert badges (⚠️) on nodes that triggered detections. Separate legend for action types (file write, network connection, etc.). |
| **Filtering** | Filter by: Action type (process, file, registry, network), Severity, Time range within the causality chain. Collapsible sub-trees for large chains. |
| **Log Stitching** | Cortex XDR **automatically stitches** firewall logs, endpoint data, and cloud data into a unified causality story. |
| **Unique Features** | - **Causality Group Owner (CGO)** concept — identifies the root cause process<br>- Automatic "dot connection" across millions of data points<br>- Process tree can span across multiple endpoints<br>- "Spawners" concept shows intermediate execution chains<br>- Actor types: Action Actor, OS Actor, Causality Actor, DST Action Actor |

### Screenshot References
- Causality chain view: Available in Cortex XDR product documentation (requires login)
- Alert investigation: `https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Investigate-an-Alert`

---

## 4. CrowdStrike Falcon (Threat Graph)

### Graph Type: **Process Tree + Threat Graph**

| Aspect | Details |
|---|---|
| **Graph Layout** | **Vertical process tree** (top-down). Parent processes at top, child processes cascade downward. Separate "Threat Graph" shows cross-host lateral movement. |
| **Entity Types (Nodes)** | Processes, Files, DNS queries, Network connections, Registry keys, Users. Process nodes show: executable name, PID, command line preview. |
| **Edge/Relationship Display** | Arrows indicate process spawning (parent→child). Dotted lines for network connections. Color-coded edges: **Red** for malicious, **Yellow** for suspicious, **Gray** for normal. No explicit relationship type labels on edges. |
| **Edge Click Behavior** | Clicking a process node reveals a **right-side detail panel**: Full process tree context, Command line arguments, File details (hash, path, signature), Network connections made, Associated threat intelligence. |
| **Legend/Guide** | Icon-based legend at top: 🟥 Detection, 🟧 Suspicious, ⬜ Informational. Entity type icons (file, process, network, DNS). No relationship type legend — relationships are implicit from tree structure. |
| **Filtering** | Time-range slider, Detection type filter, Host-based grouping. |
| **Threat Graph (Unique)** | A **global-scale graph database** processing 2.5+ trillion events/week. Connects: endpoints, cloud workloads, identities, and data. Real-time situational awareness across the entire customer base. Not visible in the individual alert UI but powers detections. |
| **Unique Features** | - **Falcon Threat Graph**: Cloud-scale graph DB powering real-time correlation<br>- Process tree with inline MITRE ATT&CK tactic/technique tags<br>- "Falcon OverWatch" managed hunting overlay<br>- Indicator of Attack (IOA) behavior patterns highlighted inline<br>- AI-powered "Charlotte AI" natural language investigation |

### Screenshot References
- Process tree detection: Available in CrowdStrike Falcon console (requires login)
- Threat Graph overview: `https://www.crowdstrike.com/cybersecurity-101/threat-graph/`

---

## 5. Elastic Security (Visual Event Analyzer)

### Graph Type: **Process-Based Visual Event Analyzer**

| Aspect | Details |
|---|---|
| **Graph Layout** | **Horizontal tree** (left-to-right). Each cube represents a process. Parent-child relationships flow left→right. |
| **Entity Types (Nodes)** | Processes (cubes), Files, Registry events, Network events to be selected. **Each process is a 3D cube icon** — unique visual style. |
| **Edge/Relationship Display** | Tree-structure edges (no explicit labels). Event category "pills" on each node: `x file`, `x registry`, `x network`, `x alert`. Edge source defined by schema: `SOURCE` (data source), `ID` (unique node), `EDGE` (relationship field). |
| **Edge Click Behavior** | Clicking a process cube opens the **preview analyzer panel**: Number of events, Timestamp, File path, PID, Username/domain, Associated alerts. Clicking an event category pill (e.g., "3 file") lists all file events for that process. |
| **Legend/Guide** | **Legend icon** (toggleable) shows node states: Analyzed Event (highlighted with blue outline), Running process, Terminated process. Schema info button shows: SOURCE, ID, EDGE fields used. |
| **Filtering** | Data view selector, Time filter, Process list panel for navigation. |
| **Multi-Source Support** | Works with: Elastic Defend, Sysmon/Winlogbeat, CrowdStrike Falcon logs, SentinelOne Cloud Funnel, Microsoft Defender for Endpoint. |
| **Unique Features** | - **3D cube** process icons (distinctive visual)<br>- Event category pills (file, network, registry, alert) on each node<br>- Timeline shows time elapsed between process events<br>- Schema transparency: users can see which fields are used for graph construction<br>- Process list panel for quick navigation<br>- Alert pill shows rule name that generated detection |

### Screenshot References
- Visual event analyzer: `https://www.elastic.co/docs/solutions/security/investigate/visual-event-analyzer`
- Process tree with cubes: Available in Elastic Security documentation

---

## 6. SentinelOne (Storyline)

### Graph Type: **Storyline Process Tree**

| Aspect | Details |
|---|---|
| **Graph Layout** | **Horizontal process tree** (left-to-right). Each event is a node on the storyline. Connected by directed edges showing execution flow. |
| **Entity Types (Nodes)** | Processes, Files, Network connections, DNS resolutions, Registry modifications, Login events. Nodes are color-coded cards. |
| **Edge/Relationship Display** | **Directed arrows** showing execution order and causality. Edges represent: spawned, wrote, connected, modified, loaded. No explicit text labels on edges in default view — relationship inferred from position and type. |
| **Edge Click Behavior** | Clicking a node opens full event details: Process command line, File hash and path, Network destination, Full JSON event data. Side panel with MITRE ATT&CK mapping. |
| **Legend/Guide** | Color indicators: **Red** = threat/malicious, **Orange** = suspicious, **Green** = mitigated, **Gray** = informational. Threat indicators badge on nodes. No formal relationship type legend. |
| **Filtering** | Filter by: Event type (process, file, network, registry, DNS), Threat confidence, Time range. |
| **Unique Features** | - **Storyline** technology: auto-correlates hundreds of events into a single narrative<br>- **STAR (Storyline Active Response)** rules — custom detection on storylines<br>- Every process automatically tracked with unique Storyline ID<br>- Deep Visibility for raw telemetry drill-down<br>- One-click rollback/remediation from storyline view |

---

## 7. Cybereason (MalOp Detection)

### Graph Type: **MalOp (Malicious Operation) Graph**

| Aspect | Details |
|---|---|
| **Graph Layout** | **Centered radial graph** with the malicious operation at center. Affected elements radiate outward. Multi-stage attack visualized across machines. |
| **Entity Types (Nodes)** | Processes, Users, Machines, Files, Network connections, Persistence mechanisms, Registry entries. Large colored circles with icons per type. |
| **Edge/Relationship Display** | Thick directed edges with **explicit labels**: "executed on", "connected to", "wrote file", "injected into", "escalated privilege". One of the **few products that labels edges explicitly**. Color indicates severity. |
| **Edge Click Behavior** | Clicking an edge or node opens a **rich detail card**: Operation timeline, Affected endpoints count, Evidence collected, Remediation actions available. |
| **Legend/Guide** | Color-coded by operation phase: Initial Access → Execution → Persistence → Lateral Movement → Exfiltration. Entity type icons in legend. Relationship types visible on edges. |
| **Filtering** | Filter by: Machine, User, Attack stage, Severity, Time. |
| **Unique Features** | - **MalOp-centric** view (not alert-centric) — focuses on the complete malicious operation<br>- **Explicit edge labels** (rare among competitors)<br>- Cross-machine attack visualization in single graph<br>- Automated root cause identification<br>- One-click remediation per node/machine |

---

## 8. IBM QRadar (Offense Investigation)

### Graph Type: **Offense-Centric Tabular + Network Graph**

| Aspect | Details |
|---|---|
| **Graph Layout** | Primarily **tabular offense view** with a supplementary network topology graph. Not a native process tree or entity graph in the investigation flow. |
| **Entity Types** | Source IPs, Destination IPs, Log Sources, Users, Offenses, Events, Flows. |
| **Edge/Relationship Display** | Network topology: IP-to-IP connections with directional arrows. Edge weight reflects traffic volume. Relationship is implicit (network flow). No explicit relationship labels. |
| **Legend/Guide** | Magnitude-based color scale (1-10) on offenses. Category-based grouping (Recon, Exploit, Denial of Service, etc.). |
| **Unique Features** | - "Offense" concept groups correlated events<br>- Reference sets and reference maps for custom lookups<br>- Network activity graph for flow visualization<br>- Strong timeline and drill-down into raw events<br>- QRadar Advisor with Watson for AI-powered investigation |

---

## Comparative Summary Matrix

| Feature | MS Defender XDR | Sentinel | Cortex XDR | CrowdStrike | Elastic | SentinelOne | Cybereason | QRadar |
|---|---|---|---|---|---|---|---|---|
| **Graph Layout** | Force-directed | Radial | Horizontal tree | Vertical tree | Horizontal tree | Horizontal tree | Radial | Tabular + topo |
| **Node Shape** | Icons | Icons | Rectangular cards | Icons | 3D Cubes | Cards | Large circles | Icons |
| **Node Color by Type** | ✅ | ✅ | ✅ (severity) | ✅ (severity) | ✅ (state) | ✅ (severity) | ✅ (phase) | ✅ (magnitude) |
| **Edge Labels on Canvas** | ❌ | Hover only | ❌ (implicit) | ❌ (implicit) | ❌ (implicit) | ❌ (implicit) | ✅ **Explicit** | ❌ (implicit) |
| **Edge Click Popup** | Entity pane | Entity pane | Detail drawer | Side panel | Preview panel | Event details | Detail card | Drill-down |
| **Relationship Legend** | ❌ | ❌ | Action type filter | ❌ | Schema info | ❌ | On-edge labels | ❌ |
| **Relationship Guide** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Entity Type Filter** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Animated Timeline** | ✅ | ❌ | ❌ | ❌ | Timeline between nodes | ❌ | ❌ | ❌ |
| **MITRE ATT&CK Mapping** | Kill chain view | ❌ | ✅ per node | ✅ inline tags | ❌ | ✅ per node | ✅ by phase | ✅ categories |
| **Blast Radius / Lateral** | ✅ (blast radius) | ❌ | Cross-endpoint | Threat Graph | ❌ | ❌ | Cross-machine | ❌ |
| **AI/ML Integration** | Copilot | Top Insights | ML detections | Charlotte AI | ❌ | ❌ | Auto root cause | Watson |

---

## Key Insights & Differentiation Opportunities for Log360 Cloud

### What competitors do well:
1. **Process-tree layouts** dominate (Cortex XDR, CrowdStrike, Elastic, SentinelOne) — useful for endpoint-focused analysis
2. **Entity-centric side panels** are the industry standard (MS Defender, Sentinel, CrowdStrike)
3. **Node color-coding** by severity/type is universal
4. **Animated timeline playback** (MS Defender) is a premium differentiator
5. **Blast radius / lateral movement** visualization (MS Defender) is emerging as critical for SOC workflows

### Where competitors fall short:
1. **Almost no one labels edges explicitly** — Only Cybereason shows relationship labels on edges. This is a major gap.
2. **No product offers a "Relationship Guide"** — Our static reference popup with 28 relation types + descriptions is unique.
3. **Edge click popups with descriptions** are rare — Most products only show entity details, not relationship details.
4. **No product combines** entity-type graph + edge labeling + relationship guide + edge attributes (count, risk, evidence). Our approach is more comprehensive.

### Our Differentiation (Log360 Cloud Alert Investigation V4):
| Feature | Log360 Cloud (Ours) | Industry Standard |
|---|---|---|
| **Edge Labels on Canvas** | ✅ Explicit (LoginTo, AccessedFrom, etc.) | ❌ Mostly implicit |
| **Edge Click with Description** | ✅ Shows relation description + attributes (count, risk, evidence, timestamp) | ❌ Only entity details |
| **Relationship Guide (28 types)** | ✅ Static reference with icon + name + description | ❌ Does not exist |
| **Dual Legend (Malicious/Normal + Relations)** | ✅ Bottom toolbar with both | ❌ Only severity colors |
| **Entity Type Dropdown with Counts** | ✅ All 8+ types with counts | ✅ Similar (entity type toggle) |
| **Force-Directed + Entity Graph** | ✅ | ✅ (MS Defender/Sentinel) |

### Recommendations:
1. **Keep explicit edge labels** — This is our strongest differentiator vs. all competitors
2. **Keep the Relationship Guide** — No competitor offers this; it's a unique analyst productivity tool
3. **Consider adding**: Animated timeline playback (like MS Defender XDR)
4. **Consider adding**: Blast radius / "what if" lateral movement paths from any compromised entity
5. **Consider adding**: MITRE ATT&CK tactic/technique tags on edges or nodes
6. **Consider adding**: Process tree view as an alternative layout (toggle between entity graph and process tree)
7. **Edge risk scoring** on edges is unique to us — competitors only show risk at the alert or entity level

---

## Screenshot Reference URLs

| Product | Screenshot URL |
|---|---|
| MS Defender XDR — Attack Story | https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/play-alert-attack-story.gif |
| MS Defender XDR — Entity Details | https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/review-entity-details-attack-story.gif |
| MS Defender XDR — Blast Radius | https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/blast-radius-graph.png |
| MS Defender XDR — Filter | https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/incident-graph-filter-criteria.png |
| MS Defender XDR — Entity Type Toggle | https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/incident-graph-hide-entity.png |
| MS Defender XDR — Blast Radius List | https://learn.microsoft.com/en-us/defender-xdr/media/investigate-incidents/blast-radius-list.png |
| MS Sentinel — Investigation Graph | https://learn.microsoft.com/en-us/azure/sentinel/media/investigate-cases/investigation-graph.png |
| Elastic — Visual Event Analyzer | https://www.elastic.co/docs/solutions/security/investigate/visual-event-analyzer (inline screenshots) |

> **Note:** CrowdStrike, Cortex XDR, SentinelOne, and Cybereason require login to access their console screenshots. The URLs above are from official public documentation.
