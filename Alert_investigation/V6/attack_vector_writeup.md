# Attack Vector — Product Writeup

*Log360 Cloud · Alert Investigation V6 · 20 May 2026*

---

## 1. Introduction

Security operations teams spend the majority of their working day inside the alert queue. Every alert that arrives is, at heart, the same question: *what happened, who is involved, how serious is it, and what should I do next?* Today, answering that question is a manual, multi-tool exercise. The analyst opens an alert, reads a list of fields, opens a second console for identity context, a third for user-behaviour analytics, a fourth for threat intelligence, and a fifth to actually run a response action. The investigation lives inside the analyst's head; the product is only a source of raw data.

**Attack Vector** is our answer to this problem. It is a single, graph-first investigation surface that takes an alert and renders it as a visual story — the entities that are involved, the relationships between them, the enrichments the analyst can pull on demand, and the response actions they can fire without leaving the screen. It is designed around one principle: *the analyst should not have to leave the alert to understand the alert or to act on it.*

---

## 2. The Problem We Are Solving

Three problems define the current alert-handling workflow in Log360 Cloud, and Attack Vector is designed to solve all three.

**First, alerts have no visual or causal context.** A row in a table cannot show *"this user signed in from this IP, which then connected to this command-and-control domain, which was contacted by this process on this device."* The analyst has to reconstruct that chain mentally, every time. For a junior analyst this means slower decisions and a higher chance of missing a step; for a senior analyst it is repetitive cognitive load that the product should be absorbing.

**Second, every alert costs the same to investigate.** Today the same identity-enrichment, behaviour-analytics, and threat-intelligence joins run for an obvious false positive as for a confirmed lateral-movement chain. The analyst pays the same waiting time on both, and the system pays the same backend workload. There is no notion of *triage now, deepen later*.

**Third, response lives outside the alert.** Response actions — disable user, isolate host, reset password, block IP — live in a separate Workflow / Incident Management module. To act on an alert, the analyst has to copy the entity name out of the alert, switch to Workflow, find the right playbook, paste the entity name back in, and run it. Three context switches for every response, multiplied across a typical shift.

Each of these is individually painful. Combined, they push the SOC's Mean Time To Respond (MTTR) into a range that is uncomfortable to defend in front of a CISO.

---

## 3. What Attack Vector Is

Attack Vector replaces the flat alert dossier with a visual, interactive surface built around three layers.

**The graph layer** is the canvas. When an analyst opens an alert, they see the alert itself at the centre of a force-directed graph, surrounded by every entity it touches — users, devices, IP addresses, domains, processes, services — and connected by the events that link them (signed-in-from, executed-on, connected-to, triggered-by). The graph is the primary surface; the analyst can pan, zoom, filter by entity type or by edge type, and immediately see the shape of the incident.

**The entity slider** is the dossier. When the analyst clicks any node on the graph, a side panel opens with a structured view of that entity organised into tabs (Overview, Risk & Identity, Activity, Account Changes, Recent Alerts). Every entity follows the same Baseline → Investigate → Enriched pattern, which we describe in the next section. The slider also exposes a playbook dropdown that lets the analyst run a response on that specific entity.

**The action panel** is the response surface. Every playbook the analyst runs — whether from a node, from the alert itself, or from the global Actions menu — appears in a tabbed action panel that keeps a per-alert history of what was investigated and what was done. Each playbook card carries plain-language metadata: **Blast radius** (low / medium / high), **Time to complete**, and **Can undo?** A confirm modal restates the same metadata before the action fires, so the analyst sees the consequences before clicking.

Together, the three layers turn a flat row into a workspace.

---

## 4. The Investigation Flow: Baseline, Investigate, Enriched

The most important design decision in Attack Vector is the **two-stage gating** of entity content. When the analyst clicks a node, the entity slider does not load every available section. It loads a small, deliberately curated **Baseline** — the identity of the entity, its risk summary, and the recent alerts that touch it. These are the questions an analyst asks of every entity, every time: *who is this, how risky is it, has it been involved in anything recently?*

Anything heavier — the UEBA risk profile, cloud identity enrichment, threat-intelligence context, full activity history, account changes, mailbox forwarding rules — is hidden behind a single, deliberate action: the **Investigate Entity** button. Clicking it unlocks the **Enriched** section set for that entity. Tabs that have no Enriched content collapse automatically; tabs that gain new content highlight themselves.

This pattern matters for two reasons. It keeps triage lightweight (the analyst is not waiting on enrichment calls they do not need), and it makes the analyst's intent explicit (deciding to Investigate is a recorded action, which gives the SOC manager an audit trail of what was looked at on a given alert).

The same flow applies to every entity type — user, device, IP address, domain, service, process, alert — so an analyst who learns the surface once learns it for everything.

---

## 5. From Investigation to Response

Once the analyst understands what they are looking at, Attack Vector lets them act on it from the same surface.

Every playbook is grouped under one of four verbs the analyst already thinks in: **contain** (isolate host, disable user), **disrupt** (kill process, block IP, revoke session), **investigate** (deep-dive a process, hunt a pattern), and **hygiene** (force password reset, expire token, mark for review). The verb drives the colour of the action chip and the phrasing of the confirm modal, so the analyst's eye learns to recognise *"this is a destructive containment action"* vs *"this is a reversible hygiene action"* without reading the label.

Playbooks can be run on a specific entity (from the entity slider), on the alert as a whole (from the alert dossier), or globally from the floating Actions menu. Each fired action lands in the **Action Panel** as a tab. The analyst can flip between tabs to see what each playbook returned, what evidence it surfaced, and (where applicable) how to roll it back from the Action History.

The result is that an analyst can move from *I see the alert* → *I understand the chain* → *I have run the containment* in one continuous flow, on one screen, without ever copying an entity name into another module.

---

## 6. Representative Scenarios

To make the flow concrete, consider how an analyst uses Attack Vector across a typical day.

**A privileged user triggers an impossible-travel alert.** The graph opens with the user node at the centre, connected to two geographically distant IP nodes. The analyst clicks one IP — the Baseline shows country, ASN, and a threat-feed flag. They click the other — clean. They click **Investigate Entity** on the suspicious IP; the slider unlocks VPN and Tor enrichment and shows that the source is a known anonymising service. They run **Disable User** from the user node, confirm in the modal, and the action lands in the Action Panel. Elapsed time: well under a minute.

**A workstation makes a beacon-pattern outbound connection.** The graph shows the device node connected to a process node connected to an external IP and a domain. The analyst clicks the process — Baseline shows the name, parent, command line, and recent alerts touching that process. Investigate unlocks AMSI events, DLL loads, and child processes; the script is encoded PowerShell with a clear C2 download chain. The analyst runs **Isolate Host** on the device and **Block Domain** on the domain node, both from the graph, both recorded against the alert.

**A surge of failed sign-ins targets a service account.** The graph shows the service node with a fan-out of source IPs. Baseline gives lockout count and recent alerts. Investigate on the service shows OAuth consent grants, Conditional Access policy posture, and admin activity. The analyst runs **Reset Password** on the service and **Block IP** on the worst offender.

**A large false-positive batch arrives at shift change.** The analyst skims the graph for each alert without clicking Investigate. Baseline alone — risk summary, identity, recent alerts — is sufficient to dismiss the benign cases. The expensive enrichment is never paid for the alerts that do not need it.

Each scenario uses the same surface, the same verbs, and the same Baseline → Investigate → Enriched flow.

---

## 7. Benefits

The user-visible benefits of Attack Vector fall into six themes.

**Mean Time To Understand drops.** The causal chain is visible in one screen instead of reconstructed across five modules. A first-glance read of the incident is typically possible in under five seconds.

**Investigation overhead is proportional to the alert.** Heavy enrichments run only when the analyst signals intent by clicking Investigate Entity. False positives are dismissed at Baseline; real incidents get the full dossier on demand.

**Investigation and response live on the same screen.** Playbooks are launched from the same surface as the investigation. There is no tool-switching, no copy-pasted entity names, and the Action Panel keeps a per-alert history of everything that was run.

**The language is consistent across entity types.** Every entity — user, device, IP, domain, service, process, alert — follows the same Baseline → Investigate → Enriched flow and the same four-verb playbook taxonomy. New analysts learn the surface once.

**Decisions are defensible.** Each playbook card and confirm modal carries Blast radius, Time to complete, and Can undo? metadata in plain language. The analyst sees the consequences before clicking, and the SOC manager has a record of why each action was taken.

**The surface is audit-grade by default.** Every Investigate-click and every playbook fire is recorded against the alert, giving the SOC manager a clean record of what was looked at and what was done — useful for shift handover, post-incident review, and compliance reporting.

---

## 8. Competitive Position

The visual incident-graph view is no longer optional in the SIEM/XDR category. Microsoft Sentinel, Google Chronicle, Palo Alto XSIAM, and Exabeam all ship some form of investigation graph today. Log360 Cloud is currently the outlier in our segment for not having one. Attack Vector brings us to parity on the surface and differentiates us on two axes — the two-stage Baseline / Investigate / Enriched gating (which competitors largely do not have; most load everything on entity click), and the in-graph playbook execution with verb-coded action chips (which removes a tool switch competitors still require).

---

## 9. In One Line

> Attack Vector turns a flat alert row into an investigative surface where the SOC analyst *sees* the attack, *pulls* only the enrichment they need, and *acts* on it — all on one screen.
