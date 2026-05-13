# AI Alert Investigation — Competitive Analysis

> **Revision history**
> - **v2.17 (May 12, 2026)** — **Section 2 cleaned up.** Removed the inline `([source](URL))` hyperlinks and `[unverified]` markers per request; section now reads as plain "Who has it: A, B, C" bullets like the original. To keep the section legitimate, every vendor entry that could not be backed by a primary source already cited in section 6 has been dropped entirely (rather than carried as speculation). Removals applied this pass: Google from 2.1 (no response action in TIN docs); CrowdStrike *Event Search* from 2.2; Microsoft *Phishing Triage Agent* line from 2.3 LLM tier (no dedicated source fetched); CrowdStrike from 2.4 (no formal report export); CrowdStrike *Storyline* from 2.5; Microsoft and CrowdStrike from 2.6 (not described as automatic server-side enrichment on fetched pages); Microsoft and Google from 2.7 (graph UI not pulled verbatim from a fetched source); Google *Suggested next steps* and CrowdStrike from 2.8; Google *YARA-L* and CrowdStrike *IOA* from 2.9; Google from 2.10; old section 2.11 (Proactive threat-hunting AI) deleted entirely because no fetched source supports it for any vendor (sections renumbered 2.11–2.14); Google from 2.13 (cross-domain breadth was implied, not verbatim). Items kept and now legitimate by section-6 anchoring: Sumo Logic SOC Analyst Agent in 2.3 (preview); Elastic in 2.2 / 2.4 / 2.5 / 2.8 / 2.9; CrowdStrike Workbench in 2.7; CrowdStrike *decode attack commands* in 2.12; CrowdStrike Falcon Insight XDR in 2.13; Sumo Logic MCP in 2.14.
> - **v2.16 (May 12, 2026)** — **Elastic re-added** based on https://www.elastic.co/docs/solutions/security/ai/triage-alerts (the earlier Attack Discovery URL that returned an ad-tracking redirect was a different page; this docs URL is fully readable). Verified facts now in doc: (a) **Elastic Security AI Assistant** alert-triage workflow — open alert → Chat → AI Assistant receives alert context → summarize / follow-up Q&A / ES|QL query generation / case-ready report; (b) **Knowledge Base** supports up to **500 alerts** as prompt context for multi-alert triage; (c) worked example on the page: *"Multiple Failed Logins Followed by Success - user: jsmith"* — analyst drives criticality assessment, asks follow-ups, decides TP/FP, escalates. Honest classification: **AI-assisted, not autonomous** (the page repeatedly uses analyst-driven verbs — *customize the prompt, ask follow-up questions*); added to section 3.2 only, not 3.1 or 3.3. Vendor count is now 6. Source #6 added.
> - **v2.15 (May 12, 2026)** — **Sumo Logic profile rewritten with Dojo AI multi-agent platform.** Verified two additional Sumo Logic sources: https://www.sumologic.com/glossary/agentic-ai (glossary page that names every Dojo AI agent and discloses which ones process customer data) and https://www.sumologic.com/blog/2026-security-operations-insights-report (Jan 28, 2026 report on 500+ security leaders). Key new findings now in the doc: (a) the platform is officially named **Dojo AI**; (b) the agent lineup is **Mobot + Query Agent + Knowledge Agent + Summary Agent + SOC Analyst Agent**; (c) only the **SOC Analyst Agent** processes customer data and it is **in preview as of February 2026 with certain chosen customers** — not GA, opt-in only, gated by an AI addendum; (d) Mobot's foundation model is on **Amazon Bedrock**; (e) Dojo AI supports **MCP** for customer-supplied models/tools; (f) industry context from the report: 90% of security leaders say AI is important in buying decisions but only 9% actually deploy AI for incident triage today. Honest classification preserved: the GA agents are AI-assisted (analyst-driven); the SOC Analyst Agent is the genuine AI alert-investigation component but is preview-only. Sources 5a and 5b added.
> - **v2.14 (May 12, 2026)** — **CrowdStrike row expanded with second primary source.** Verified https://www.crowdstrike.com/es-latam/platform/endpoint-security/ai-powered-investigation/ (Spanish-Latin-America product page, *"Acelera las investigaciones con IA agéntica"*). New facts added to the vendor row (translated verbatim from page): (a) **CrowdStrike Signal** product name now in the doc; (b) Charlotte AI capability list expanded — *"automatically decode attack commands, triage detections, filter false positives, summarize cases, guide response, and leverage agentic AI directly within automated playbooks"*; (c) **Workbench view** = real-time collaborative incident graph with annotations and third-party-data overlay; (d) cross-domain visibility across Falcon Insight XDR (endpoint → identity → cloud) included at no extra cost for EDR customers. Page-grounding caveats preserved: no accuracy %, no training-volume claim, no 40-hr/week figure are on this page — those remain attributed to source #3 (the Feb 2025 blog). Source #3b added.
> - **v2.13 (May 12, 2026)** — **CrowdStrike strengthened with primary-source blog.** Re-grounded all CrowdStrike entries against the Feb 13, 2025 announcement blog (Elia Zaitsev, *"CrowdStrike Leads Agentic AI Innovation in Cybersecurity with Charlotte AI Detection Triage"*). Verbatim facts now in doc: (a) Charlotte AI Detection Triage *"autonomously evaluates each new endpoint detection"* and outputs **priority level + true/false-positive classification + recommended course of action**; (b) trained on *"millions of real-world triage decisions"* from Falcon Complete (resolves the earlier "training-volume claim not on the page" caveat — the volume claim IS on the blog); (c) **>98% agreement rate** with Falcon Complete human-expert triage; (d) reported **40+ hours/week** time savings with footnote-1 methodology (avg alerts × 5 min/alert estimate); (e) optional Falcon Fusion SOAR hand-off; (f) *"customer-defined bounded autonomy"* model. Important caveat preserved: scope is **endpoint detections only** (Falcon EDR scope), not arbitrary SIEM alerts, and the blog does NOT describe iterative search / cross-source pivot — it's still autonomous **triage**, not full investigation. Updated vendor-table row, section 3.1, 3.3, 3.4 side-by-side, and source list (blog promoted to source #3, product page demoted to 3a).
> - **v2.12 (May 12, 2026)** — **Removed IBM QRadar SIEM.** Re-verification of https://www.ibm.com/products/qradar-siem/ai shows the page describes UBA (ML anomaly detection), Sigma community rules (signature rules), and QRadar NDR (network traffic analytics) — none of which are AI alert investigation. The 90% Forrester TEI figure is a commissioned study about general SIEM time savings, not an AI-investigated-the-alert claim. The page contains zero occurrences of "AI", "LLM", "agent", "watsonx", or "automated investigation". By the same standard applied to Rapid7, IBM does not belong in this document. Removed vendor row, every capability-list mention (2.1, 2.2, 2.3 non-LLM, 2.4, 2.5, 2.6, 2.10, 2.13, 2.14), and source #5. Vendor count is now 5 (Microsoft, Google, CrowdStrike, Splunk, Sumo Logic).
> - **v2.11 (May 12, 2026)** — **Splunk row strengthened with Lantern LLM/MCP recipe.** Added reference to the Splunk Lantern article *"Automating alert investigations by integrating LLMs with the Splunk platform and Confluence"*, which documents an LLM-driven adaptive investigation loop using the Atlassian MCP (Confluence runbooks) + Splunk MCP (`run_splunk_query`, `get_indexes`, `get_metadata`) ending in a summary report + recommended next steps. Honest framing: this is an **IT/observability use case** (not security alert investigation) and a **customer-buildable recipe** — NOT a shipped Splunk product agent. The Splunk vendor-table row now distinguishes (1) the ES product features from (2) this documented integration pattern. Source 4b added.
> - **v2.10 (May 12, 2026)** — **Removed Rapid7 InsightIDR.** The Investigations docs page (https://docs.rapid7.com/insightidr/investigations/) describes only rule-based investigation aggregation: system-created investigations triggered by detection rules, related detections of same type + same primary actor appended to the open case, timeline + audit logs. **Zero mention of AI, LLM, ML, automated triage, or intelligent investigation** anywhere on the page. Per project rule "keep only links related to AI/autonomous alert investigation", the Rapid7 vendor row, every Rapid7 capability-list mention (2.1, 2.2, 2.3 non-LLM ML, 2.4, 2.5, 2.6, 2.10, 2.12, 2.15), and source #6 have been removed. Vendor count is now 6 (Microsoft, Google, CrowdStrike, Splunk, IBM, Sumo Logic).
> - **v2.9 (May 12, 2026)** — **Reclassified Sumo Logic as AI-assisted, not autonomous.** Re-read of the Cloud SIEM page confirms there is no agent that auto-triggers on an alert and emits a verdict — Query Agent is NL-to-query (analyst-driven) and Summary Agent only summarizes signals. Tightened the vendor-table row to call this out explicitly ("AI-assisted only — not an autonomous investigation agent") and added Sumo Logic to section 3.2 (AI-assisted investigation) alongside Microsoft Security Copilot and Splunk AI Assistant. Sumo Logic does NOT belong in section 3.1 / 3.3 (autonomous or LLM-driven auto-triage).
> - **v2.8 (May 12, 2026)** — Removed **Arctic Wolf**. The Aurora platform page is generic AI-marketing copy ("act faster", "grounded in real-world security expertise") and does not describe an AI alert-investigation workflow specifically; no public Arctic Wolf URL was found that documents how Aurora investigates an alert (inputs / steps / outputs). Per project rule "keep only links related to AI/autonomous alert investigation", the Arctic Wolf vendor table row and every Arctic Wolf mention in capability lists (2.3 non-LLM auto-triage, 2.6 entity enrichment, 2.14 cross-domain) has been dropped. Sumo Logic was retained because the Cloud SIEM page has a dedicated "Intuitive investigation" section describing Mobot + Query Agent + entity-centric relationship graph, plus a separate Summary Agent for signal summaries inside Insights — the row was tightened to point at that section.
> - **v2.7 (May 12, 2026)** — Full on-page validation pass for all remaining vendors. Removed **Elastic** (Attack Discovery docs page redirects to a DoubleClick ad-tracking script — unreadable). Rewrote **IBM** row: the QRadar SIEM AI page does NOT use the words "watsonx", "automated investigation", "federated search" or "threat case generation" — grounded the row in the page's actual features (UBA, Sigma community rules, QRadar NDR) and the verbatim 90% Forrester TEI footnote. Rewrote **Arctic Wolf** row: "delivered alongside the 24/7 Concierge SOC" wording is not on the Aurora page — replaced with verbatim language *"grounded in real-world security expertise, golden datasets, and customer-specific context"* and *"bounded autonomy, guardrails, and human-in-the-loop oversight"*. Re-grounded **Sumo Logic** row in verbatim page wording (Query Agent translates NL to queries; Summary Agent generates AI summaries of signals within an Insight). Re-grounded **Rapid7** row in verbatim docs-page wording (system-created investigations, related-detection aggregation, timeline view). Corrected **Google TIN** trial-limit description: limits are 5 auto + 5 manual per hour (Enterprise) and 10 auto + 10 manual per hour (Enterprise Plus / GUS), not flat "10/hr / 20/hr". Disposition output is "true/false positive + confidence level + summary".
> - **v2.6 (May 12, 2026)** — Tightened Splunk Enterprise Security description to use only on-page wording. The product page DOES list "AI Assistant" as a feature and describes AI-driven workflows as *"natural language queries, guided workflows, instant summaries, and automated reports"*. It does NOT explicitly say the natural-language layer translates to SPL — that was an inference, so the "→ SPL" claim has been dropped from both the vendor table and section 3.2. Removed Splunk from the section 2.2 NLQ list since "Splunk (SPL)" was making the same SPL-translation inference.
> - **v2.5 (May 12, 2026)** — Removed all SentinelOne content. The `/cybersecurity-101/threat-intelligence/purple-ai/` URL redirects to a DoubleClick ad-tracking script (no readable content); `/platform/purple-ai/` returns HTTP 404; `/platform/` also redirects to ad-tracking. SentinelOne vendor table row, Purple AI row in section 3.2, Purple-AI-auto-triage row in section 3.3, and every "SentinelOne / Storyline / Purple AI / S1QL" mention across capability lists 2.1–2.14 have been dropped. Per project rule "if you can't read the link, you don't add the data".
> - **v2.4 (May 12, 2026)** — Removed all Palo Alto Networks content. Re-verification found that `paloaltonetworks.com/cortex/cortex-copilot`, `cortex-agentic-assistant`, and `cortex-xsiam` all redirect to a DoubleClick ad-tracking script (no readable product copy), and the cited `docs-cortex` XSIAM "Alerts and incidents" page returns "document has been moved or deleted". Palo Alto vendor table row, XSIAM alert-stitching row in section 3.5, Cortex Copilot row in section 3.2, Cortex Marketplace 1,500+ figure, and all Palo Alto mentions in capability lists 2.1–2.15 have been dropped. Per project rule "if you can't read the link, you don't add the data".
> - **v2.3 (May 12, 2026)** — Corrected CrowdStrike Detection Triage Agent description after re-reading the Charlotte AI page. The agent name is **"Detection Triage Agent"** (not "Agentic Detection Triage Agent"). The page does NOT use "TP/FP" or "recommended next steps" phrasing — it says *"triages detections, filters false positives, and surfaces only what matters"*. The page DOES say the agent is *"trained on decisions of elite analysts"*, while footnote 5 separately describes the accuracy rating as *measured against* the Falcon Complete Next-Gen MDR team. Section 5 "trained on millions of decisions" row re-graded from `[unverified]` to `[partially verified]` with the volume figure still flagged.
> - **v2.2 (May 12, 2026)** — Removed all content sourced from URLs that could not be read by automated verification (HTTP 403 / bot-blocked). Specifically: Exabeam (Smart Timelines page), Securonix (Sam page), Microsoft Digital Defense Report 2024 (78T signals figure), Splunk RBA docs, and the SecurityWeek merger article. Exabeam and Securonix have been dropped from the vendor table and from every "Who has it" list; the unverified 1,800+ ML models claim has been removed; the 78+ trillion daily signals figure has been removed from the Defender XDR AIR row; Splunk RBA description has been re-grounded on the public Splunk ES product page only.
> - **v2.1 (May 12, 2026)** — Full source verification pass. Every cited URL was fetched and its content compared to the claim. Corrections applied: URL replaced (old techcommunity link 404'd as Excel forum thread); Phishing Triage Agent re-labelled "announced Mar 2025 / preview Apr 2025" (was incorrectly listed as GA); CrowdStrike "trained on Falcon Complete decisions" softened to "published accuracy measured against Falcon Complete decisions" (the page footnote describes measurement, not training); Microsoft Defender XDR embedded capability list aligned with the official table; Arctic Wolf description rewritten to use language from the Aurora page; Promptbooks now cite a separate page.
> - **v2 (May 12, 2026)** — Rewritten with primary-source citations; corrected Microsoft AIR verdict label, "only 2 LLM auto-triage vendors" claim, LogRhythm/Exabeam vendor split; Google TIN section reconciled against the official Google SecOps docs page.
> - v1 — Original draft (no citations).

Citation convention: every numeric or proper-noun claim is followed by a `[n]` superscript that resolves to a source link in the **Sources** section at the end. Claims that cannot be verified from a public primary source are tagged `[unverified]`.

---

## 1. Vendor landscape

Vendors below ship some form of AI-powered alert investigation today. Each vendor profile reflects what is on the vendor's own public product page or announcement (May 2026), with verbatim wording quoted where claims are sourced. Vendors removed from this analysis (in earlier verification passes) and the documented reason for each: **Exabeam, Securonix** — product pages were not accessible to automated verification; **Palo Alto, SentinelOne** — pages redirected to DoubleClick ad-tracking scripts (no readable product copy); **Rapid7** — the InsightIDR Investigations docs page describes only rule-based investigation aggregation with no AI/LLM/ML content; **IBM QRadar** — the `/ai` page describes UBA + Sigma rules + NDR, none of which is AI alert investigation; **Arctic Wolf** — the Aurora page is generic AI-marketing copy with no described investigation workflow; **LogRhythm** — dropped in an earlier pass. Six vendors remain.

### Microsoft — Security Copilot + Defender XDR AIR

LLM-powered (OpenAI GPT-class) Security Copilot is embedded in Defender XDR and Sentinel. **Automated Investigation and Response (AIR)** is a virtual analyst that auto-investigates alerts and produces verdicts of *Malicious*, *Suspicious*, or *No threats found*. Primary reference: https://learn.microsoft.com/en-us/defender-xdr/m365d-autoir.

### Google — Google SecOps + Gemini

**Triage and Investigation Agent (TIN)** is a Gemini-driven 3-stage pipeline (initial assessment → contextual enrichment → adaptive investigation) that produces a true/false-positive disposition together with a confidence level and a natural-language summary. Primary reference: https://docs.cloud.google.com/chronicle/docs/secops/triage-investigation-agent.

### CrowdStrike — Charlotte AI Detection Triage

**Charlotte AI Detection Triage** is an agentic-AI capability that *"autonomously evaluates each new endpoint detection"* and outputs **priority level + true/false-positive classification + recommended course of action**. Trained on *"millions of real-world triage decisions"* from Falcon Complete Next-Gen MDR; reports a **>98% agreement rate** with Falcon Complete human-expert triage. Scope is **endpoint detections only**; optional hand-off to **Falcon Fusion SOAR**. Primary reference: https://www.crowdstrike.com/en-us/blog/agentic-ai-innovation-in-cybersecurity-charlotte-ai-detection-triage/ (Feb 13, 2025 announcement).

### Splunk (Cisco) — Splunk AI Assistant + LLM/MCP recipe

**Product:** Splunk Enterprise Security's AI Assistant provides *"natural language queries, guided workflows, instant summaries, and automated reports"* and AI-powered alert prioritization. **Pattern (not a shipped agent):** Splunk Lantern documents an IT/observability recipe in which an external LLM uses the **Atlassian MCP** (Confluence runbooks) and **Splunk MCP** (`run_splunk_query`, `get_indexes`, `get_metadata`) in a *Plan → Run → Adapt → Re-run* loop. Primary references: https://www.splunk.com/en_us/products/enterprise-security.html &nbsp;·&nbsp; https://lantern.splunk.com/Observability_Use_Cases/Troubleshoot/Automating_alert_investigations_by_integrating_LLMs_with_the_Splunk_platform_and_Confluence.

### Sumo Logic — Dojo AI + SOC Analyst Agent (preview)

**Dojo AI** is Sumo Logic's multi-agent platform. Per the glossary, **Mobot** (conversational interface), **Query Agent** (NL → query), **Knowledge Agent**, and **Summary Agent** *"do NOT process or analyze customer data"*. The **SOC Analyst Agent** is the only Dojo AI component that processes customer data and is **in preview as of February 2026 with certain chosen customers** (opt-in + AI addendum required); its scope per the glossary is to *"help review insight data, correlate activity, and assist in triage and investigation as directed by the user."* Foundation model: Amazon Bedrock; MCP-supported. Primary reference: https://www.sumologic.com/glossary/agentic-ai.

### Elastic — Elastic Security AI Assistant

**AI-assisted only — no autonomous agent.** Per the *Triage alerts* docs, an analyst opens an alert, clicks **Chat**, and the alert context is sent to **Elastic AI Assistant** which can summarize the alert, answer follow-up questions, generate **ES|QL queries**, and produce reports that can be added to a case. **Knowledge Base** can feed up to **500 alerts** as context for multi-alert triage. The page is explicit that the analyst drives — *"Improve the quality of AI Assistant's response by customizing the prompt"*, *"Ask AI Assistant follow-up questions"*. Primary reference: https://www.elastic.co/docs/solutions/security/ai/triage-alerts.

---

## 2. Capability gaps — what L3C lacks

For each capability, the "Who has it" list names only the vendors whose primary source (see section 6) explicitly describes the capability. Vendors that could not be confirmed against a fetched primary source have been dropped from the relevant list rather than carried as speculation.

### 2.1 Response / Remediation actions

- **Who has it:** Microsoft (AIR auto-remediation), CrowdStrike (Falcon Fusion SOAR hand-off), Splunk (Splunkbase SOAR apps).
- **What it does:** After investigation, the agent can take action — isolate hosts, disable users, block IPs, quarantine files, run SOAR playbooks.
- **Our gap:** *"The AI finds the problem but can't fix it — I still have to switch tools to remediate."*
- **Our architecture readiness:** `HUMAN_IN_THE_LOOP_TOOL` type already exists. Adding new tools to `AITools.xml` + Java classes + PII unmasking is sufficient.

### 2.2 Natural-language query (NLQ) chat

- **Who has it:** Microsoft (KQL generation in Security Copilot), Google (dynamic UDM search in TIN), Sumo Logic (Query Agent), Elastic (ES|QL generation).
- **What it does:** Analyst asks live data questions during or outside an investigation and gets back data-backed answers, not just summaries from memory.
- **Our gap:** *"I can't ask follow-up questions with live data."*
- **Our architecture readiness:** ~90% in place. `FETCH_RELATED_LOGS` already does NLQ → L3C query conversion. We need to wire `ANSWER_USER_QUERY` to trigger `FETCH_RELATED_LOGS` on data questions.

### 2.3 Automated alert triage (auto-triage)

- **Who has it (LLM-based):** Google (TIN), CrowdStrike (Charlotte AI Detection Triage), Sumo Logic (SOC Analyst Agent — preview only, Feb 2026).
- **Who has it (non-LLM ML/rules):** Microsoft (Defender XDR AIR), Splunk (Risk-Based Alerting on ES product page).
- **Our gap:** *"We still have to look at every alert."*
- **Our architecture readiness:** Agent framework supports multiple agent types. Needs a `TriageAgent` class, slimmer tool set, new prompt in `PromptData.json`.

### 2.4 Investigation reports / summaries

- **Who has it:** Microsoft (Security Copilot *"Create incident reports"*), Google (TIN natural-language summary), Elastic (AI Assistant reports added to cases).
- **What it does:** Auto-generates investigation reports / summaries with timeline, entities, evidence, and recommended actions.

### 2.5 Multi-alert / incident-level investigation

- **Who has it:** Microsoft (unified Defender/Sentinel incidents), Google (TIN consumes case metadata), Splunk (ES notable events), Elastic (Knowledge Base up to 500 alerts as context), Sumo Logic (Insights group signals per entity).
- **What it does:** Investigates a correlated group of alerts as one incident rather than alert-by-alert.

### 2.6 Server-side entity auto-enrichment

- **Who has it:** Google (TIN uses Entity Context Graph as a built-in tool), Sumo Logic (Dojo AI entity model).
- **What it does:** Entities are enriched with TI data deterministically the moment they appear — not gated on the LLM remembering to call an enrichment tool.

### 2.7 Visual attack graph / entity-relationship graph

- **Who has it:** CrowdStrike (Workbench collaborative incident graph with annotations and third-party overlay).
- **What it does:** Interactive graph where entities are nodes and relationships are edges; clickable to pivot/expand.

### 2.8 Contextual question generation / guided investigation

- **Who has it:** Microsoft (Security Copilot *"Use guided response"*), Elastic (AI Assistant follow-up Q&A with alert context attached).

### 2.9 Detection-rule suggestions

- **Who has it:** Microsoft (KQL generation in Security Copilot), Elastic (ES|QL generation in AI Assistant).

### 2.10 Investigation playbooks / templates

- **Who has it:** Microsoft (Promptbooks), Splunk (SOAR apps on Splunkbase), CrowdStrike (*"agentic AI directly within automated playbooks"*).

### 2.11 Verdict / confidence scoring

- **Who has it:** CrowdStrike (priority level + true/false-positive classification + recommended course of action), Google (explicit *"Confidence level"* field in TIN output).

### 2.12 Script / file deobfuscation

- **Who has it:** Microsoft (Security Copilot *"Analyze files"*, *"Analyze scripts and code"*), Google (*"Command-line analysis"* tool in TIN), CrowdStrike (*"automatically decode attack commands"*).

### 2.13 Cross-domain investigation (endpoint + identity + cloud + network)

- **Who has it:** CrowdStrike (Falcon Insight XDR spans endpoint → identity → cloud), Microsoft (Sentinel unified into Defender portal).

### 2.14 Custom plugins / extensions

- **Who has it:** Microsoft (Security Copilot custom plugins), Splunk (Splunkbase ecosystem; customer-buildable LLM + MCP recipe on Splunk Lantern), Sumo Logic (Dojo AI Model Context Protocol support).

---

## 3. Investigation type classification

### 3.1 Fully autonomous AI investigation (no analyst click)

| Vendor | Agent | How it investigates | Is it "investigation"? | LLM? | Limitation |
|---|---|---|---|---|---|
| Google SecOps | **Triage and Investigation Agent (TIN)** | Auto-triggers → 3-stage pipeline (initial assessment → contextual enrichment → adaptive investigation) → disposition (TP/FP) + confidence + summary | **Yes** — searches, enriches, reasons, iterates | Gemini | Trial Apr 1 – Jun 30, 2026. Hourly caps split between auto and manual: Enterprise = 5 auto + 5 manual; Enterprise Plus / GUS = 10 auto + 10 manual. No queue — once the hourly cap is hit, the agent doesn't investigate further alerts. TIN is not FedRAMP or CMEK compliant; single-tenant only |
| CrowdStrike | **Charlotte AI Detection Triage** | Per CrowdStrike's Feb 13 2025 announcement blog: *"autonomously evaluates each new endpoint detection"* and produces **priority level + true/false-positive classification + recommended course of action**. Trained on *"millions of real-world triage decisions"* from Falcon Complete; **>98% agreement** with Falcon Complete human-expert triage | Honest: this is **autonomous endpoint-detection triage**, not iterative cross-source investigation. Blog does not describe a multi-step search/enrich/reason loop; it describes per-detection triage at scale | LLM + ML ("agentic AI") | **Endpoint-scoped only.** Output is per-detection (not per-incident). Requires Charlotte AI license. "Customer-defined bounded autonomy" — analyst retains control over final decisions; SOAR actions only fire if customer enables them in Falcon Fusion |
| Microsoft | **Defender XDR AIR** | Auto-triggers → crawls entity graph → reaches verdict → can auto-remediate | **Partial** — investigates via fixed ML pipeline, not LLM reasoning | ML/Rules (not LLM) | Verdicts are **Malicious / Suspicious / No threats found** (not "Clean"). Historically Defender-XDR-scoped; post-2024 Defender/Sentinel unification widens scope to Sentinel incidents in the same portal |
| Sumo Logic | **SOC Analyst Agent** (Dojo AI) | Per Sumo Logic glossary: *"processes customer data in order to help review insight data, correlate activity, and assist in triage and investigation as directed by the user"* | **Preview only — NOT GA.** In preview as of February 2026 with certain chosen customers; opt-in + AI addendum required | LLM (Amazon Bedrock) + ML | Glossary page describes scope (insight review + activity correlation + triage/investigation assistance) but does NOT describe pipeline stages, output format, throughput, latency, or accuracy metrics. Treat as roadmap evidence, not a measurable capability today |
> **Correction vs. v1.** v1 used the verdict label "Clean" for AIR. Microsoft's documented verdict is "No threats found". Also: v1 said AIR "only works on Defender XDR alerts (not Sentinel)" — that was true pre-2024 but Sentinel was unified into the Defender portal in 2024; AIR-style automation now spans Sentinel incidents in the same workspace.

### 3.2 AI-assisted investigation (analyst drives, AI helps)

| Vendor | Product | What it does | LLM? |
|---|---|---|---|
| Microsoft | Security Copilot embedded in Sentinel / Defender XDR | Per the embedded experiences table: Analyze files; Analyze scripts and code; Create incident reports; Generate KQL queries for hunting; Summarize device / identity / incident; Use guided response. (Plus Sentinel: "Summarize Sentinel incidents with Security Copilot".) | OpenAI (GPT-class) |
| Splunk | Splunk AI Assistant | Per ES page: natural-language queries, guided workflows, instant summaries, automated reports | LLM |
| Sumo Logic | Cloud SIEM — Mobot + Query Agent + Summary Agent (Dojo AI, non-customer-data agents) | Mobot is the unified conversational interface; **Query Agent** translates analyst natural-language questions into precise queries; **Summary Agent** produces AI-generated summaries of signals inside an Insight. Per Sumo Logic's glossary, these agents *do NOT process customer data*. Analyst drives the investigation. (Sumo Logic's autonomous **SOC Analyst Agent** is listed in section 3.1 as a preview-only entry.) | LLM (NL-to-query, Amazon Bedrock) + ML |
| Elastic | Elastic Security AI Assistant | Per the *Triage alerts* docs: analyst opens an alert → Chat → AI Assistant receives alert context, summarizes, answers follow-ups, generates **ES|QL** queries, and produces case-ready reports. **Knowledge Base** supports up to **500 alerts** as prompt context for multi-alert triage. Analyst drives the investigation; no auto-triggered agent | LLM |
### 3.3 Auto-triage WITH LLM

| Vendor | Product | How it works |
|---|---|---|
| **CrowdStrike** | Charlotte AI Detection Triage | Per the Feb 13 2025 announcement blog: agentic-AI capability that *"autonomously evaluates each new endpoint detection"* and outputs **priority level + true/false-positive classification + recommended course of action**. Trained on *"millions of real-world triage decisions"* from Falcon Complete Next-Gen MDR. **>98% agreement rate** with Falcon Complete human-expert triage. Reported time savings: *"more than 40 hours of manual work per week on average"* (footnote: avg alerts triaged × 5-min/alert estimate from the Falcon Complete team). Optional Falcon Fusion SOAR hand-off for containment / ticketing |
| **Google SecOps** | TIN | 5–20 min configurable delay → Gemini agent runs 3-stage pipeline using built-in tools (dynamic UDM search, GTI enrichment, command-line analysis, process tree reconstruction, ECG, network context, case metadata) → disposition (true/false positive) + confidence level + NL summary. Average ~60 s, max 20 min |
| **Microsoft** | Phishing Triage Agent in Security Copilot (announced Mar 2025, preview Apr 2025) | LLM-driven auto-classification of user-reported phish; triages phishing alerts to identify real cyberthreats vs false alarms |
> **Correction vs. v1.** v1 stated *"Only 2 vendors use actual AI (LLM) for auto-triage: CrowdStrike + Google."* Microsoft also qualifies (Phishing Triage Agent).

### 3.4 CrowdStrike vs. Google — side-by-side, citation-grade

```
CrowdStrike Charlotte AI Detection Triage (announced Feb 13, 2025)
 Blog wording: "autonomously evaluates each new endpoint detection and
 provides a detailed analysis that includes the detection's priority level,
 its classification as a true or false positive, and a recommended
 course of action."
 → Scope: ENDPOINT detections (Falcon EDR scope; not arbitrary SIEM alerts)
 → Outputs: priority level + TP/FP classification + recommended next action
 → Training: "millions of real-world triage decisions" from Falcon Complete
 → Reported accuracy: ">98% agreement rate" with Falcon Complete human-expert triage
 → Reported savings: "more than 40 hours of manual work per week on average"
   (footnote 1: avg alerts triaged × 5-min/alert estimate from Falcon Complete team)
 → Architecture model: "customer-defined bounded autonomy" — analyst retains final-decision control
 → Optional hand-off: Falcon Fusion SOAR for containment / ticketing / routing
 → NOT described in blog: iterative search/enrich/reason loop, cross-source pivot,
   confidence percentages, queue/throughput limits, FedRAMP status
Google TIN
 Alert → 5–20 min configurable delay → Gemini agent starts investigation
 → 3-stage pipeline, 7 named built-in tools
 → Outputs: disposition (true/false positive) + confidence level + NL summary
 → Speed: ~60 s average; 20 min hard ceiling
 → Scale: 5 auto + 5 manual/hr (Enterprise), 10 auto + 10 manual/hr (Enterprise Plus / GUS) — NO QUEUE
 → Constraints: single-tenant only; not FedRAMP / CMEK compliant
```

### 3.5 Auto-triage WITHOUT LLM (ML / rules / formulas)

| Vendor | Product | Technology | How it works | Output |
|---|---|---|---|---|
| Microsoft | Defender XDR AIR | ML + entity graph | Crawls user → device → mailbox → file graph, applies decision-tree models, auto-remediates at high confidence | Malicious / Suspicious / No threats found + auto-remediation actions |
| Microsoft | Sentinel automation rules | Rule conditionals | Admin writes "if alert.source = X and alert.severity < Medium then auto-close" style rules | Auto-close, auto-assign, auto-tag, severity rewrite |
| Splunk | Risk-Based Alerting (RBA) | Rule-based risk aggregation | Per Splunk Enterprise Security product page: admin-assigned per-rule risk contributions aggregated per entity; notable events fire on cumulative risk thresholds | Per-entity cumulative risk score + notable events |
> **Clarification vs. v1.** v1 quoted specific RBA score numbers ("brute force = +40, failed login = +5"). Splunk's authoritative RBA documentation could not be verified by our automated check, so those numeric examples have been dropped.

---

## 4. Layouts (figures)

- **Google SecOps:** investigation panel layout.
- **Microsoft Sentinel:** Security Copilot + incident layout.

*(Screenshots intentionally omitted from this version; reference vendor docs above.)*

---

## 5. Outstanding unverified claims

These items remain in the doc because they are widely cited by analysts but I could not pull a primary-source URL that loaded without a login wall:

| Claim | Status | Note |
|---|---|---|
| Microsoft *"100+ tools"* in Security Copilot | `[unverified]` | Plugin gallery exists but a "100+" total isn't published on the Learn page. |
| CrowdStrike *"trained on millions of Falcon Complete decisions"* | `[partially verified]` | The Charlotte AI page DOES state *"Trained on decisions of elite analysts"* — so a generic "trained on analyst decisions" claim is supported. What is NOT on the page is a **volume figure** ("millions of decisions") or an explicit mention of Falcon Complete being the training set (footnote 5 only describes Falcon Complete Next-Gen MDR as the *benchmark for accuracy measurement*). Drop any specific volume number. |

---

## 6. Sources

All URLs below were fetched and their content read end-to-end. Vendors / pages whose primary marketing or product pages returned HTTP 403 to automated verification (Exabeam, Securonix, Splunk RBA docs, Microsoft Digital Defense Report, SecurityWeek) have been removed from this document; the corresponding claims have been dropped.

1. **Microsoft Security Copilot — overview.** https://learn.microsoft.com/en-us/copilot/security/microsoft-security-copilot
 - 1a. **"Microsoft unveils Microsoft Security Copilot agents and new protections for AI" — announces the Phishing Triage Agent (Mar 24, 2025; preview Apr 2025).** https://www.microsoft.com/en-us/security/blog/2025/03/24/microsoft-unveils-microsoft-security-copilot-agents-and-new-protections-for-ai/
 - 1b. **Microsoft Defender XDR — Automated investigation and response (AIR).** https://learn.microsoft.com/en-us/defender-xdr/m365d-autoir
 - 1c. **Manage plugins (custom + preinstalled).** https://learn.microsoft.com/en-us/copilot/security/manage-plugins
 - 1d. **Microsoft Sentinel is now generally available in the unified Defender portal.** https://techcommunity.microsoft.com/blog/microsoftsentinelblog/microsoft-sentinel-is-now-generally-available-within-the-microsoft-unified-secur/4144971
 - 1e. **Security Copilot experiences (embedded capabilities table).** https://learn.microsoft.com/en-us/copilot/security/experiences-security-copilot
 - 1f. **Microsoft Sentinel automation rules.** https://learn.microsoft.com/en-us/azure/sentinel/automate-incident-handling-with-automation-rules
 - 1g. **Build your own promptbooks.** https://learn.microsoft.com/en-us/copilot/security/build-promptbooks
2. **Google SecOps — Triage and Investigation Agent (TIN).** https://docs.cloud.google.com/chronicle/docs/secops/triage-investigation-agent *(Primary source for hourly caps, 5–20 min delay, ~60 s runtime, 3-stage pipeline, tool list, trial dates, FedRAMP/CMEK note.)*
3. **CrowdStrike — Agentic AI Innovation in Cybersecurity: Charlotte AI Detection Triage** (announcement blog, Feb 13, 2025, Elia Zaitsev). https://www.crowdstrike.com/en-us/blog/agentic-ai-innovation-in-cybersecurity-charlotte-ai-detection-triage/ *(Primary source for: autonomous endpoint-detection triage; priority + TP/FP + recommended action output; trained on "millions of real-world triage decisions" from Falcon Complete; >98% agreement rate; 40+ hrs/week savings with footnote-1 methodology; Falcon Fusion SOAR integration; customer-defined bounded autonomy.)*
 - 3a. **CrowdStrike Charlotte AI — product page.** https://www.crowdstrike.com/en-us/platform/charlotte-ai/
 - 3b. **CrowdStrike — *Acelera las investigaciones con IA agéntica*** (AI-powered investigation product page, es-latam, May 2026). https://www.crowdstrike.com/es-latam/platform/endpoint-security/ai-powered-investigation/ *(Primary source for: CrowdStrike Signal product name; Workbench collaborative incident graph; expanded Charlotte AI capability list — decode attack commands, triage, filter FPs, summarize cases, guide response, agentic AI inside playbooks; cross-domain visibility through Falcon Insight XDR.)*
4. **Splunk Enterprise Security.** https://www.splunk.com/en_us/products/enterprise-security.html
 - 4a. **Splunkbase SOAR apps.** https://splunkbase.splunk.com/apps?filters=product%3Asoar
 - 4b. **Splunk Lantern — Automating alert investigations by integrating LLMs with the Splunk platform and Confluence.** https://lantern.splunk.com/Observability_Use_Cases/Troubleshoot/Automating_alert_investigations_by_integrating_LLMs_with_the_Splunk_platform_and_Confluence *(IT/observability use case; demonstrates LLM + Atlassian MCP + Splunk MCP adaptive investigation loop; not a shipped Splunk product agent.)*
5. **Sumo Logic Cloud SIEM — "Intuitive investigation" section.** https://www.sumologic.com/solutions/cloud-siem-enterprise/
 - 5a. **Sumo Logic Glossary — Agentic AI / Dojo AI multi-agent platform.** https://www.sumologic.com/glossary/agentic-ai *(Primary source for: Dojo AI; Mobot; Query Agent; Knowledge Agent; Summary Agent; **SOC Analyst Agent (preview as of February 2026 with certain chosen customers)** — the only Dojo AI agent that processes customer data; Amazon Bedrock foundation model; MCP support; opt-in + AI addendum gating.)*
 - 5b. **Sumo Logic 2026 Security Operations Insights report blog** (Zoe Hawkins, Jan 28, 2026). https://www.sumologic.com/blog/2026-security-operations-insights-report *(Survey of 500+ security leaders. Verbatim figures cited: 90% say AI is extremely/very important in buying decisions; 90% say AI/ML is valuable in reducing alert fatigue; 49% deploy AI for basic threat detection; 20% for automated response; 9% for incident triage.)*
6. **Elastic Security docs — *Triage alerts***. https://www.elastic.co/docs/solutions/security/ai/triage-alerts *(Primary source for: Elastic AI Assistant alert-triage workflow; Chat with alert context; Knowledge Base up to 500 alerts; ES|QL query generation; report generation and case integration; worked example "Multiple Failed Logins Followed by Success".)*
