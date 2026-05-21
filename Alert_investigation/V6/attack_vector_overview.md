# Attack Vector — Overview

*Log360 Cloud · Alert Investigation V6 · 20 May 2026*

---

## What is it?

The **Attack Vector** view is the visual, graph-first investigation surface for a single alert. Instead of opening a flat alert dossier, the analyst sees the alert at the centre of a force-directed graph of every entity the alert touches — users, devices, IPs, domains, processes, services — connected by the events that link them (sign-in, executed-on, connected-to, triggered-by, etc.).

Each entity is a node the analyst can click to open the **Entity Slider**, which renders a two-stage dossier:

- **Baseline** — the small, lightweight, always-on set of sections (identity, risk summary, recent alerts).
- **Enriched** — the heavier sections (UEBA profile, threat-intel context, cloud identities, process tree, etc.), unlocked only after the analyst clicks **Investigate Entity**.

Backed by playbook actions (contain / disrupt / investigate / hygiene) and a tabbed **Action Panel**, the analyst can pivot from "what happened" to "what do I do about it" without leaving the graph.

---

## Why we need it for the product

Today the Log360 Cloud alert experience is **list-first**: the SOC analyst sees a row in a table, opens it, reads a dense list of fields, then manually queries five other modules (ADAP, UEBA, Threat Analytics, Audit, EDR) to reconstruct what actually happened. Three problems:

1. **No spatial / causal context.** A row in a list cannot show *"this user signed in from this IP, which then connected to this C2 domain, which was contacted by this process on this device."* The analyst rebuilds that story in their head every time.
2. **Investigation overhead is fixed and high.** Every alert incurs the same identity / UEBA / TI enrichment workload, even on obvious false positives.
3. **Response lives outside the alert.** Today, response actions (disable user, isolate host, reset password, block IP) live in a separate Workflow / Incident Management module. To act on an alert, the analyst has to copy the entity name out of the alert, switch to Workflow, find the right playbook, paste the entity name back in, and run it — three context switches for every response.

Attack Vector solves all three:

- **Attack Vector graph as the primary surface** makes the causal chain visible at a glance.
- **Baseline-vs-Enriched gating** keeps triage lightweight; only alerts the analyst chooses to dig into incur the heavier enrichment workload.
- **In-graph playbook actions** (per-entity and per-alert) close the investigate → respond loop in one surface.

It also positions Log360 Cloud against SIEM/XDR competitors (Sentinel, Chronicle, XSIAM, Exabeam) who all ship some form of incident-graph view — today we are the outlier without one.

---

## Use cases

| # | Scenario | What the analyst does in Attack Vector |
|---|---|---|
| 1 | **Impossible-travel alert on a privileged user** | Open the alert → graph shows the user node linked to two geographically distant IPs → click each IP for Baseline (geo, ASN, threat-feed flag) → Investigate the suspicious IP for VPN/Tor enrichment → fire **Disable User** playbook in-graph. |
| 2 | **C2 connection from a workstation** | Graph shows device → process → external IP → domain. Click the process for Baseline (name, parent, cmdline). Investigate → AMSI events, DLL loads, child processes. Fire **Isolate Host** + **Block Domain** playbooks. |
| 3 | **Brute-force on a service account** | Graph shows service + cluster of source IPs. Baseline gives lockout count + recent alerts. Investigate the service for OAuth grants / CA policy / admin activity. Fire **Reset Password** + **Block IP** playbooks. |
| 4 | **OAuth-consent / app-governance alert** | Service node at centre, fan-out to consenting users + granted scopes. Investigate the service for sign-in audit + admin activity. Fire **Revoke Consent** playbook. |
| 5 | **Data-exfiltration via cloud upload** | User → device → process → external domain. Baseline + Investigate on user gives recent app access and resource/file access. Fire **Quarantine Account** + **Block Upload Path**. |
| 6 | **Triage of a high-volume false-positive batch** | Analyst skims the graph for each alert without Investigate-clicking — Baseline alone is enough to dismiss obvious benign cases, keeping enrichment overhead minimal. |

---

## How the user benefits

| Benefit | What it means day-to-day |
|---|---|
| **Faster Mean Time To Understand (MTTU)** | The causal chain is visible in one screen instead of reconstructed across 5 modules. Typical first-glance dossier in < 5 seconds. |
| **Lower investigation overhead** | Heavy enrichments (identity, UEBA, TI joins) only run when the analyst clicks Investigate Entity — not on every alert open. Empty tabs auto-collapse so the surface stays clean. |
| **Closer to one-screen response** | Playbooks are launched from the same surface as the investigation. No tool-switching, no copy-pasted entity names. The Action Panel keeps a per-alert history. |
| **Consistent language across entities** | Every entity (user, device, IP, domain, service, process, alert) follows the same Baseline → Investigate → Enriched flow. New analysts learn the surface once. |
| **Defensible decisions** | Each playbook card carries **Blast radius**, **Time to complete**, and **Can undo?** metadata in plain language, plus a confirm modal. The analyst sees the consequences before clicking. |
| **Audit-grade trail** | Every Investigate-click and every playbook fire is recorded against the alert, giving the SOC manager a defensible record of what was looked at and what was done. |

---

## In one line

> Attack Vector turns a flat alert row into an investigative surface where the SOC analyst *sees* the attack, *pulls* only the enrichment they need, and *acts* on it — all in one screen.
