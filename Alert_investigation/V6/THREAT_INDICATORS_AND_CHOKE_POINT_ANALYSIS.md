# Threat Indicators and Choke Point Analysis in V6

## Scope

This note describes what V6 actually supports today.

It is intentionally limited to the current prototype behavior. It does not describe an ideal future SOC design.

## 1. Threat Indicators

### What V6 currently means

In V6, Threat Indicators is a graph-level risk summary.

It is derived from the current visible graph view using two signals:

- visible malicious connections
- visible critical nodes

So in the current prototype, Threat Indicators should be read as:

"How much clearly risky structure is visible in the graph right now?"

### Why it is shown

It helps the analyst quickly understand whether the visible graph contains suspicious or high-priority elements before opening deeper entity views.

### What it is useful for

- quick graph triage
- comparing one visible graph state to another
- spotting whether expansion of the graph has exposed more risky nodes or edges

### What it does not mean in V6

Threat Indicators in V6 is not, by itself:

- a full threat-intelligence verdict
- an IOC feed correlation summary
- a breach-confirmation surface
- a remediation-priority engine

Those ideas may appear elsewhere in entity details, but they are not what this graph summary number currently represents.

## 2. Choke Point Analysis

### Current V6 status

Choke Point Analysis is not currently implemented as a concrete V6 feature.

I could not verify any separate V6 choke-point data model, renderer, or computation that identifies a node, edge, permission, or relationship as a choke point.

### What that means for documentation

If we document V6 accurately, Choke Point Analysis must be described only as:

- a future analytical capability, or
- a design concept not yet implemented in this prototype

It should not be described as an active V6 graph output.

## 3. Are Threat Indicators and Choke Point Analysis showing the same data?

In current V6, the answer is no.

The reason is simple: only one of these surfaces is actually implemented in the graph today.

- Threat Indicators exists as a graph summary signal.
- Choke Point Analysis does not yet exist as a verified V6 analysis surface.

So we should not claim that V6 is showing the same data in both places.

## 4. Is there redundancy?

In current V6, the main risk is not data redundancy. The main risk is inaccurate documentation.

If we describe Threat Indicators as though it already includes path-priority or choke-point reasoning, the document overstates what the prototype can do.

The correct separation for V6 is:

- Threat Indicators = current graph-risk summary
- Choke Point Analysis = not yet implemented in V6

## 5. Proper SOC reading of V6 today

### Threat Indicators

Read it as a fast visual signal that the currently visible graph contains malicious links, critical entities, or both.

It is useful for triage, not as a complete explanation of why an entity is malicious.

### Choke Point Analysis

Do not treat this as an active V6 feature today.

If the term is used in discussions, it should mean a future capability that identifies which node or relationship should be removed first to reduce attacker reach.

## 6. Recommended wording for V6 docs

Use wording close to this:

### Threat Indicators

"Shows the count of visible malicious connections and critical nodes in the current graph view. This helps the analyst quickly assess whether the visible investigation path contains high-risk entities or relationships."

### Choke Point Analysis

"Not currently implemented in V6. Intended future capability for identifying the highest-impact node or relationship to remediate in order to reduce attacker reach across the graph."

## 7. Final position

If the goal is to document current V6 behavior, then:

- Threat Indicators can be documented
- Choke Point Analysis should be documented only as not currently available

If the goal is to document a future SOC design, that should be written as a separate design note rather than mixed into current V6 behavior.