# Threat Indicators and Choke Point Analysis

## Scope

This note explains these two graph surfaces using the incident graph that is currently shown in V6.

The explanation below is based on the graph as given to the analyst: the alert, the user, the internal and external IPs, the workstation, Azure AD, OAuth tokens, SharePoint, the Administrator account, and the C2 domain.

## 1. What the graph is showing

The graph is not just listing related entities. It is presenting a compromise story.

At a high level, the graph shows this chain:

1. An impossible-travel alert is raised on the user account.
2. The same user is associated with both an internal corporate IP and a Tor exit IP.
3. The user authenticates to Azure AD and accesses SharePoint.
4. The internal workstation communicates with the Tor-linked infrastructure.
5. The workstation is associated with privilege escalation to Administrator.
6. OAuth tokens and SharePoint access appear as the likely cloud access and data-access path.
7. The C2 domain represents the external command-and-control or exfiltration side of the chain.

So the graph is giving the analyst a linked narrative of identity compromise, endpoint involvement, privilege escalation, cloud access, and external communication.

## 2. Threat Indicators

### What it means in this graph

Threat Indicators are the parts of the graph that tell the analyst:

**"These entities or relationships are risky, suspicious, or operationally important to the incident."**

In this graph, that includes items such as:

- the impossible-travel alert
- the Tor exit IP
- the compromised user account
- the workstation involved in the suspicious activity
- the OAuth tokens issued after compromise
- the SharePoint access path
- the C2 domain
- the malicious relationships connecting them

### Why it is shown

This surface helps the analyst quickly answer:

- Where is the clearly suspicious activity?
- Which parts of the graph deserve immediate attention?
- Is this just an isolated alert, or a multi-stage compromise chain?

### What the analyst should take from it

Threat Indicators help the analyst understand the **shape and seriousness** of the incident.

They are there to support triage, confidence, and investigative direction.

They tell the analyst which nodes and relationships are concerning.

They do **not** by themselves tell the analyst which action will reduce the attacker's reach most effectively.

## 3. Choke Point Analysis

### What it means in this graph

Choke Point Analysis is not trying to show every risky object.

It is trying to answer a narrower question:

**"If I can act on only a small number of things, which ones will break the most useful parts of the attack chain?"**

In this graph, the choke-point view focuses on three entities:

- **m.henderson**
- **CORP-WS-045**
- **185.220.101.42**

### Why these three are singled out

#### 1. m.henderson

This is the identity foothold at the center of the incident.

The user is tied to:

- the impossible-travel alert
- the suspicious external access point
- the internal access point
- Azure AD sign-in
- SharePoint access
- the workstation

From an analyst perspective, disabling this account breaks the identity layer of the attack and cuts multiple downstream paths at once.

#### 2. CORP-WS-045

This is the strongest endpoint pivot in the graph.

It sits between:

- the internal IP
- the Tor-linked communication
- the Administrator escalation path
- the SharePoint access path
- the C2 domain communication

From an analyst perspective, isolating this host disrupts the attacker’s active execution and lateral movement path.

#### 3. 185.220.101.42

This is the external access and communication origin in the graph.

It is tied to:

- the suspicious sign-in path
- communication with the workstation
- communication with the C2 domain

From an analyst perspective, blocking this IP can immediately reduce external access pressure, even if it is less durable than disabling the user or isolating the host.

## 4. Threat Indicators vs Choke Point Analysis

| Area | Threat Indicators | Choke Point Analysis |
|------|-------------------|----------------------|
| Main purpose | Show what looks dangerous in the graph | Show where action has the highest containment value |
| Scope | Broad | Narrow and prioritized |
| Analyst question | What is suspicious here? | What should I act on first? |
| Output style | Risky nodes and malicious relationships | Ranked response targets |
| Operational value | Triage and investigation | Containment and response prioritization |

## 5. Are they showing the same data?

Not exactly.

They are using the same investigation graph, but they are not presenting it for the same purpose.

- **Threat Indicators** highlights the risky parts of the incident story.
- **Choke Point Analysis** selects the few entities that give the best operational leverage if the analyst intervenes.

So the overlap is expected, because the most operationally useful choke points usually come from the risky part of the graph.

## 6. Is there redundancy?

Some overlap is natural, but it is not useless duplication.

For example:

- **m.henderson** appears as a threat indicator because the account is central to the compromise.
- The same **m.henderson** appears as a choke point because disabling it breaks multiple incident paths.

That is not redundant because the meaning changes:

- in **Threat Indicators**, the entity is being flagged as risky
- in **Choke Point Analysis**, the entity is being flagged as a high-impact response target

The same logic applies to **CORP-WS-045** and **185.220.101.42**.

## 7. What a SOC analyst should conclude

When reading this graph:

- Use **Threat Indicators** to understand the incident structure and identify suspicious entities and relationships.
- Use **Choke Point Analysis** to decide where immediate containment will have the highest impact.

In this incident, the graph is effectively saying:

- the account is compromised
- the workstation is part of the active attack path
- the external IP is part of the entry or control channel
- the cloud path involves Azure AD, OAuth tokens, and SharePoint

That is why the threat view is broad, while the choke-point view is deliberately limited to the user, the workstation, and the external IP.

## 8. Practical reading rule

Use this mental model:

- **Threat Indicators** = what in this graph is dangerous
- **Choke Point Analysis** = which dangerous entity is worth acting on first