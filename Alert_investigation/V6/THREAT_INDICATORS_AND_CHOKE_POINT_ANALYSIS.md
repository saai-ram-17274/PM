# Threat Indicators and Choke Point Analysis

## Purpose

This note explains how a SOC analyst should read **Threat Indicators** and **Choke Point Analysis** in the attack-investigation experience.

These two surfaces may reference some of the same entities, but they do **not** answer the same question.

---

## 1. Threat Indicators

### What it means

Threat Indicators answer this question:

**"What evidence suggests that this entity, attribute, or related artifact is suspicious, malicious, or already known to be risky?"**

### Why it is shown

Threat indicators are shown to help the analyst quickly understand whether there is a credible signal of compromise, abuse, or known malicious association.

### Typical examples

- A user email appearing in dark-web or breach exposure data
- An IP appearing in threat-intelligence or customer threat-feed matches
- A domain, URL, or file hash receiving a malicious or suspicious verdict
- Suspicious network, authentication, or process evidence that strengthens the threat assessment

### What the analyst should use it for

- Validate whether the alert or entity has real threat context behind it
- Decide whether escalation is justified
- Identify the next pivot for investigation
- Support a verdict such as malicious, suspicious, or requires further validation

### What it does **not** tell you

Threat indicators do **not** tell you which control, relationship, or privilege path should be removed first to contain the blast radius.

---

## 2. Choke Point Analysis

### What it means

Choke Point Analysis answers this question:

**"Which single relationship, permission, group membership, or path segment gives the attacker disproportionate access, and what should be removed first to break the most attack paths?"**

### Why it is shown

Choke points are shown to help the analyst prioritize containment and remediation.

### Typical examples

- A group membership that enables several attack paths to a crown-jewel asset
- A delegated permission or access-control weakness that reduces hop count to high-value targets
- A relationship whose removal collapses multiple viable attack paths at once

### What the analyst should use it for

- Prioritize the first containment step
- Reduce attacker reach with the smallest high-impact change
- Explain why a specific permission, group, or trust path matters operationally
- Support remediation planning, not just threat confirmation

### What it does **not** tell you

Choke Point Analysis does **not** prove that the related entity is malicious by reputation, breached, or present in a threat feed.

---

## 3. Key Difference

| Area | Threat Indicators | Choke Point Analysis |
|------|-------------------|----------------------|
| Primary question | Is this suspicious or known-bad? | What should be broken first to reduce attacker reach? |
| Evidence type | Reputation, breach, feed, anomaly, suspicious activity | Graph relationships, privilege paths, reachable targets, path concentration |
| Analyst outcome | Triage and confidence building | Containment and remediation prioritization |
| Time horizon | What is risky now or already known | What enables further movement if left unchanged |
| Typical action | Investigate, enrich, confirm, escalate | Remove access, isolate path, change permissions, break the chain |

---

## 4. Why both are needed

Both surfaces are needed because they solve different SOC problems:

- **Threat Indicators** help answer whether the entity deserves attention.
- **Choke Point Analysis** helps answer what change will reduce the attacker's options fastest.

An analyst may have strong threat evidence but weak containment guidance, or strong containment guidance without a public threat-intel hit. Both are valid scenarios.

---

## 5. Is there redundant data?

### Short answer

**Some overlap is expected, but the two surfaces are not redundant.**

### Why overlap happens

The same user, IP, domain, group, or host can appear in both places:

- In **Threat Indicators**, it appears because it has suspicious or known-bad context.
- In **Choke Point Analysis**, it appears because it is structurally important in one or more attack paths.

### When the overlap is useful

Overlap is useful when it tells the analyst two different things about the same object:

- **Threat meaning:** this object is risky
- **Path meaning:** this object is important to attacker movement

That combination is high-value because it supports both **verdict** and **action**.

### When it becomes redundant

It becomes redundant only if both sections repeat the same fact in the same form without changing analyst action.

The intended split is:

- **Threat Indicators** should summarize why the entity is concerning.
- **Choke Point Analysis** should summarize why changing that relationship or permission matters.

---

## 6. Analyst Guidance

### If Threat Indicators are present, but no strong choke point is visible

Treat the entity as suspicious and continue pivot-based investigation, but containment may still require broader review.

### If a choke point is present, but threat indicators are weak or absent

Treat it as an exposure or escalation risk. Lack of threat-intel evidence does **not** make the path safe.

### If both are present

Prioritize the entity or relationship for rapid containment. This is the strongest operational case because it combines **threat confidence** with **remediation leverage**.

---

## 7. Practical Reading Rule

Use this mental model:

- **Threat Indicators** = **Why should I worry?**
- **Choke Point Analysis** = **What should I break first?**

That distinction should remain clear even when both sections reference the same entity.