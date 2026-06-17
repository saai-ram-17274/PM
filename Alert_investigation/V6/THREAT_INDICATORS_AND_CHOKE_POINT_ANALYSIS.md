# Threat Indicators and Choke Point Analysis

## Purpose

This note explains how a SOC analyst should read these two graph surfaces.

The graph is showing more than related entities. It is showing which parts of the incident are suspicious, how they connect, and where response action will have the highest impact.

## 1. Threat Indicators

### What it is

Threat Indicators represent the risky parts of the graph.

They tell the analyst which nodes or relationships deserve attention because they contribute to the suspicious behavior shown in the investigation path.

### Why it is needed

An analyst looking at a graph first needs triage context.

Threat Indicators exist to answer:

- What in this graph looks dangerous?
- Which entities or links are driving the incident?
- Does this look isolated or connected?

### What it does not do

Threat Indicators do not tell the analyst what to remediate first.

They identify concern, not response priority.

## 2. Choke Point Analysis

### What it is

Choke Point Analysis is the **response-priority layer** of the graph.

It does not try to show every suspicious object. It narrows the graph to the few entities where action will break the most useful parts of the attack chain.

### Why it is needed

An analyst may understand that the graph is dangerous and still not know where to act first.

Choke Point Analysis exists to answer:

- If I take one action now, where should it be?
- Which entity has the highest containment value?
- Which intervention will reduce attacker reach most effectively?

### What it does not do

Choke Point Analysis does not replace investigation.

It is not a full explanation of why the entity is suspicious. It is a prioritization aid for response.

## 3. Difference Between Them

| Area | Threat Indicators | Choke Point Analysis |
|------|-------------------|----------------------|
| Main purpose | Show what is risky in the graph | Show where response will have the highest impact |
| Analyst question | What is suspicious here? | What should I act on first? |
| Scope | Broad | Narrow and prioritized |
| Operational use | Triage and investigation | Containment and remediation |

## 4. Are they redundant?

No.

They may refer to some of the same entities, but they are not saying the same thing.

- In **Threat Indicators**, an entity is highlighted because it is part of the suspicious incident story.
- In **Choke Point Analysis**, an entity is highlighted because acting on it gives the best operational leverage.

So overlap is expected. It is useful overlap, not duplicate meaning.

## 5. What a SOC analyst should do

Use this sequence:

1. Read **Threat Indicators** first to understand what in the graph is concerning.
2. Confirm the attack shape, suspicious paths, and important pivots.
3. Use **Choke Point Analysis** next to decide where immediate containment should begin.

In short:

- **Threat Indicators** explain concern.
- **Choke Point Analysis** explains action priority.

## 6. Practical Rule

- **Threat Indicators** = what in the graph is dangerous
- **Choke Point Analysis** = which dangerous point is worth acting on first