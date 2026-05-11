/* ═══ V5 ATTACK-VECTOR MOUNT (uses ported V4 modules) ═════════════════
   Provides the attack-vector tab content + initializes the V4 graph
   modules (entity slider, action panel, context menu, quick card,
   filter chips, draggable nodes, pan/zoom).
   ─────────────────────────────────────────────────────────────────── */

/* Globals expected by V4 modules */
var activeAlertId   = 1;
var invOpen         = false;
var invLoaded       = false;
var graphViewActive = true;
var currentGraphZoom = 1;
var ctxEntityId     = null;
var sliderEntityId  = null; // entity currently displayed in the open slider
const nodeRegistry  = {};
const drillDownGroups = {};

/* Stubs the V4 modules occasionally call but are not relevant in V5.
   showToast is provided by js/modules/utils.js — do NOT redefine here. */
function renderDetailHeader(_a){ /* no-op in V5 */ }
function renderTimelineTab(){ /* no-op in V5 */ }
function renderAlertList(){ /* no-op in V5 */ }

/* The attack-vector page HTML — taken from V4 (lines 3503-3759), with V5
   wrapper and graphViewActive=true so the modules render correctly. */
function attackVectorHTML(){
  return `
  <div class="inv-attack-content av-host" id="invAttackPage" style="display:flex;">
    <div class="inv-graph-view" id="invGraphView">
      <div class="inv-graph-container" id="graphContainer">
        <div class="inv-graph-canvas" id="graphCanvas">
          <div class="graph-cmd-bar" id="graphSummaryPanel">
            <div class="cmd-stats">
              <div style="position:relative;display:inline-block;">
                <div class="gcb-chip" id="entityChip" onclick="toggleGraphChipMenu('entityChipMenu',this)">
                  <span class="gcb-icon">◉</span>
                  <span class="gcb-label" id="entityChipLabel">All Entities</span>
                  <span class="gcb-caret">▾</span>
                </div>
                <div class="gcb-menu" id="entityChipMenu">
                  <div class="gcb-option active" data-val="all" onclick="pickEntityChip(this,'all','All Entities')">All Entities <span class="gcb-count">10</span></div>
                  <div class="gcb-option" data-val="user" onclick="pickEntityChip(this,'user','Users')"><span class="gcb-dot" style="background:#2C66DD;"></span> Users <span class="gcb-count">2</span></div>
                  <div class="gcb-option" data-val="asset" onclick="pickEntityChip(this,'asset','Assets')"><span class="gcb-dot" style="background:#198019;"></span> Assets <span class="gcb-count">2</span></div>
                  <div class="gcb-option" data-val="ip" onclick="pickEntityChip(this,'ip','IP Addresses')"><span class="gcb-dot" style="background:#f97316;"></span> IP Addresses <span class="gcb-count">2</span></div>
                  <div class="gcb-option" data-val="domain" onclick="pickEntityChip(this,'domain','Domains')"><span class="gcb-dot" style="background:#DD1616;"></span> Domains <span class="gcb-count">1</span></div>
                  <div class="gcb-option" data-val="account" onclick="pickEntityChip(this,'account','Accounts')"><span class="gcb-dot" style="background:#0891b2;"></span> Accounts <span class="gcb-count">2</span></div>
                  <div class="gcb-option" data-val="process" onclick="pickEntityChip(this,'process','File/Process')"><span class="gcb-dot" style="background:#7c3aed;"></span> File/Process <span class="gcb-count">0</span></div>
                  <div class="gcb-option" data-val="location" onclick="pickEntityChip(this,'location','Location')"><span class="gcb-dot" style="background:#eab308;"></span> Location <span class="gcb-count">0</span></div>
                  <div class="gcb-option" data-val="alert" onclick="pickEntityChip(this,'alert','Alerts')"><span class="gcb-dot" style="background:#DD1616;"></span> Alerts <span class="gcb-count">1</span></div>
                </div>
              </div>
              <span class="cmd-pill cmd-pill-danger cmd-pill-clickable" id="cmdPillMalCount" onclick="toggleCmdPillPopup(event,'malicious')"><span class="cmd-pill-dot" style="background:#DD1616;"></span><span class="cmd-pill-num">0</span> Malicious<span class="cmd-pill-caret">▾</span></span>
              <span class="cmd-pill cmd-pill-warn cmd-pill-clickable" id="cmdPillCritCount" onclick="toggleCmdPillPopup(event,'critical')"><span class="cmd-pill-dot" style="background:#FABB34;"></span><span class="cmd-pill-num">0</span> Critical<span class="cmd-pill-caret">▾</span></span>
            </div>
            <div class="cmd-pill-popup" id="cmdPillPopup"></div>
            <div class="cmd-spacer"></div>
            <div style="position:relative;display:inline-block;">
              <div class="gcb-chip" id="timeChip" onclick="toggleGraphChipMenu('timeChipMenu',this)">
                <span class="gcb-icon">⏱</span>
                <span class="gcb-label" id="timeChipLabel">Last 1 Hour</span>
                <span class="gcb-caret">▾</span>
              </div>
              <div class="gcb-menu" id="timeChipMenu">
                <div class="gcb-option" onclick="pickTimeChip(this,'Last 30 Min')">Last 30 Min</div>
                <div class="gcb-option active" onclick="pickTimeChip(this,'Last 1 Hour')">Last 1 Hour</div>
                <div class="gcb-option" onclick="pickTimeChip(this,'Last 6 Hours')">Last 6 Hours</div>
                <div class="gcb-option" onclick="pickTimeChip(this,'Last 12 Hours')">Last 12 Hours</div>
                <div class="gcb-option" onclick="pickTimeChip(this,'Last 24 Hours')">Last 24 Hours</div>
              </div>
            </div>
            <div class="gcb-chip gcb-chip-action" id="tlPlayBtn" onclick="openTimelinePlayer()" title="Replay the attack chronologically">
              <span class="gcb-icon">▶</span>
              <span class="gcb-label">Replay</span>
            </div>
          </div>

          <svg viewBox="0 0 1200 700" xmlns="http://www.w3.org/2000/svg" id="graphSvg" overflow="visible">
            <defs>
              <marker id="arrow-mal" viewBox="0 0 10 10" refX="35" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444"/>
              </marker>
              <marker id="arrow-norm" viewBox="0 0 10 10" refX="35" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#2C66DD"/>
              </marker>
              <marker id="arrow-predicted" viewBox="0 0 10 10" refX="32" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#d97706"/>
              </marker>
              <filter id="glow-r" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="4" result="b"/>
                <feFlood flood-color="#DD1616" flood-opacity=".15" result="c"/>
                <feComposite in="c" in2="b" operator="in" result="s"/>
                <feMerge><feMergeNode in="s"/><feMergeNode in="SourceGraphic"/></feMerge>
              </filter>
              <filter id="glow-p" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="3" result="b"/>
                <feFlood flood-color="#6366B3" flood-opacity=".12" result="c"/>
                <feComposite in="c" in2="b" operator="in" result="s"/>
                <feMerge><feMergeNode in="s"/><feMergeNode in="SourceGraphic"/></feMerge>
              </filter>
            </defs>

            <line x1="580" y1="85" x2="280" y2="230" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="alert-impossible-travel" data-target="user-m-henderson" data-label="TriggeredBy"/>
            <line x1="600" y1="85" x2="890" y2="175" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="alert-impossible-travel" data-target="svc-azure-ad" data-label="DetectedOn"/>
            <line x1="250" y1="265" x2="120" y2="410" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="user-m-henderson" data-target="ip-tor" data-label="AccessedFrom"/>
            <line x1="300" y1="265" x2="420" y2="420" class="graph-edge-norm" marker-end="url(#arrow-norm)" data-source="user-m-henderson" data-target="ip-internal" data-label="AccessedFrom"/>
            <line x1="310" y1="240" x2="860" y2="185" class="graph-edge-norm" marker-end="url(#arrow-norm)" data-source="user-m-henderson" data-target="svc-azure-ad" data-label="LoginTo"/>
            <line x1="420" y1="455" x2="320" y2="560" class="graph-edge-norm" marker-end="url(#arrow-norm)" data-source="ip-internal" data-target="dev-ws045" data-label="ResolvedTo"/>
            <line x1="310" y1="260" x2="870" y2="400" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="user-m-henderson" data-target="svc-sharepoint" data-label="AccessedFile"/>
            <line x1="910" y1="210" x2="940" y2="550" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="svc-azure-ad" data-target="svc-oauth" data-label="IssuedTo"/>
            <line x1="630" y1="360" x2="870" y2="195" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="user-admin" data-target="svc-azure-ad" data-label="LoginTo"/>
            <line x1="120" y1="450" x2="310" y2="560" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="ip-tor" data-target="dev-ws045" data-label="CommunicatedWith"/>
            <line x1="340" y1="560" x2="870" y2="410" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="dev-ws045" data-target="svc-sharepoint" data-label="AccessedFile"/>
            <line x1="340" y1="560" x2="605" y2="365" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="dev-ws045" data-target="user-admin" data-label="EscalatedTo"/>
            <line x1="280" y1="265" x2="320" y2="555" class="graph-edge-norm" marker-end="url(#arrow-norm)" data-source="user-m-henderson" data-target="dev-ws045" data-label="LoginTo"/>
            <line x1="940" y1="570" x2="880" y2="420" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="svc-oauth" data-target="svc-sharepoint" data-label="AccessedFile"/>
            <line x1="120" y1="460" x2="120" y2="620" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="ip-tor" data-target="domain-c2" data-label="CommunicatedWith"/>
            <line x1="320" y1="580" x2="140" y2="640" class="graph-edge-mal" marker-end="url(#arrow-mal)" data-source="dev-ws045" data-target="domain-c2" data-label="CommunicatedWith"/>
            <!-- PREDICTED edge: administrator -> DC-01 (LoginTo via RDP/SMB) -->
            <line x1="635" y1="370" x2="685" y2="620" marker-end="url(#arrow-predicted)" data-predicted="1" data-source="user-admin" data-target="dev-dc01-predicted" data-label="LoginTo"/>
            <!-- PREDICTED edge: dev-ws045 -> Credential Dump (ExecutedOn) — bridges admin abuse to DC pivot -->
            <line x1="340" y1="590" x2="475" y2="645" marker-end="url(#arrow-predicted)" data-predicted="1" data-source="dev-ws045" data-target="proc-credump-predicted" data-label="ExecutedOn"/>

            <g class="graph-node" data-entity="alert-impossible-travel" onclick="openEntitySlider('alert-impossible-travel')" oncontextmenu="showGraphCtx(event,'alert-impossible-travel')">
              <circle cx="580" cy="65" r="24" fill="#ffffff" stroke="#DD1616" stroke-width="2" filter="url(#glow-r)"/>
              <text x="580" y="70" text-anchor="middle" font-size="16" dominant-baseline="central">⚠</text>
              <text x="580" y="100" text-anchor="middle" font-size="10.5" fill="#DD1616" font-family="Inter,sans-serif" font-weight="600">Impossible Travel</text>
            </g>
            <g class="graph-node" data-entity="user-m-henderson" onclick="openEntitySlider('user-m-henderson')" oncontextmenu="showGraphCtx(event,'user-m-henderson')">
              <circle cx="280" cy="245" r="22" fill="#ffffff" stroke="#2C66DD" stroke-width="2" filter="url(#glow-r)"/>
              <text x="280" y="250" text-anchor="middle" font-size="15" dominant-baseline="central">👤</text>
              <text x="280" y="278" text-anchor="middle" font-size="10.5" fill="#2C66DD" font-family="Inter,sans-serif" font-weight="600">m.henderson</text>
            </g>
            <g class="graph-node" data-entity="svc-azure-ad" onclick="openEntitySlider('svc-azure-ad')" oncontextmenu="showGraphCtx(event,'svc-azure-ad')">
              <circle cx="890" cy="185" r="20" fill="#ffffff" stroke="#0891b2" stroke-width="2"/>
              <text x="890" y="190" text-anchor="middle" font-size="14" dominant-baseline="central">⚙</text>
              <text x="890" y="213" text-anchor="middle" font-size="10" fill="#0891b2" font-family="Inter,sans-serif">Azure AD Portal</text>
            </g>
            <g class="graph-node" data-entity="ip-tor" onclick="openEntitySlider('ip-tor')" oncontextmenu="showGraphCtx(event,'ip-tor')">
              <circle cx="120" cy="430" r="20" fill="#ffffff" stroke="#f97316" stroke-width="2" filter="url(#glow-r)"/>
              <text x="120" y="435" text-anchor="middle" font-size="14" dominant-baseline="central">◆</text>
              <text x="120" y="460" text-anchor="middle" font-size="9.5" fill="#f97316" font-family="Inter,sans-serif" font-weight="600">185.220.101.42</text>
              <text x="120" y="472" text-anchor="middle" font-size="8" fill="#8a94a6" font-family="Inter,sans-serif">(Tor · Romania)</text>
            </g>
            <g class="graph-node" data-entity="ip-internal" onclick="openEntitySlider('ip-internal')" oncontextmenu="showGraphCtx(event,'ip-internal')">
              <circle cx="420" cy="440" r="18" fill="#ffffff" stroke="#f97316" stroke-width="2"/>
              <text x="420" y="445" text-anchor="middle" font-size="13" dominant-baseline="central">◆</text>
              <text x="420" y="467" text-anchor="middle" font-size="9.5" fill="#f97316" font-family="Inter,sans-serif">10.18.1.81</text>
            </g>
            <g class="graph-node" data-entity="dev-ws045" onclick="openEntitySlider('dev-ws045')" oncontextmenu="showGraphCtx(event,'dev-ws045')">
              <circle cx="320" cy="575" r="20" fill="#ffffff" stroke="#198019" stroke-width="2" filter="url(#glow-r)"/>
              <text x="320" y="580" text-anchor="middle" font-size="14" dominant-baseline="central">🖥</text>
              <text x="320" y="605" text-anchor="middle" font-size="10" fill="#198019" font-family="Inter,sans-serif" font-weight="600">CORP-WS-045</text>
            </g>
            <g class="graph-node" data-entity="svc-sharepoint" onclick="openEntitySlider('svc-sharepoint')" oncontextmenu="showGraphCtx(event,'svc-sharepoint')">
              <circle cx="890" cy="410" r="20" fill="#ffffff" stroke="#198019" stroke-width="2" filter="url(#glow-r)"/>
              <text x="890" y="415" text-anchor="middle" font-size="14" dominant-baseline="central">📁</text>
              <text x="890" y="440" text-anchor="middle" font-size="10" fill="#198019" font-family="Inter,sans-serif" font-weight="600">SharePoint</text>
            </g>
            <g class="graph-node" data-entity="svc-oauth" onclick="openEntitySlider('svc-oauth')" oncontextmenu="showGraphCtx(event,'svc-oauth')">
              <circle cx="950" cy="565" r="18" fill="#ffffff" stroke="#0891b2" stroke-width="2" filter="url(#glow-r)"/>
              <text x="950" y="570" text-anchor="middle" font-size="13" dominant-baseline="central">🔑</text>
              <text x="950" y="593" text-anchor="middle" font-size="9.5" fill="#0891b2" font-family="Inter,sans-serif" font-weight="600">OAuth Tokens (3)</text>
            </g>
            <g class="graph-node" data-entity="user-admin" onclick="openEntitySlider('user-admin')" oncontextmenu="showGraphCtx(event,'user-admin')">
              <circle cx="620" cy="355" r="18" fill="#ffffff" stroke="#DD1616" stroke-width="2" filter="url(#glow-r)"/>
              <text x="620" y="360" text-anchor="middle" font-size="14" dominant-baseline="central">👤</text>
              <text x="620" y="381" text-anchor="middle" font-size="10" fill="#DD1616" font-family="Inter,sans-serif" font-weight="600">Administrator</text>
            </g>
            <g class="graph-node" data-entity="domain-c2" onclick="openEntitySlider('domain-c2')" oncontextmenu="showGraphCtx(event,'domain-c2')">
              <circle cx="120" cy="650" r="22" fill="#ffffff" stroke="#DD1616" stroke-width="2" filter="url(#glow-r)"/>
              <text x="120" y="655" text-anchor="middle" font-size="14" dominant-baseline="central">🌐</text>
              <text x="120" y="680" text-anchor="middle" font-size="8.5" fill="#DD1616" font-family="Inter,sans-serif" font-weight="600">c2-update.darkoperator.net</text>
              <text x="120" y="692" text-anchor="middle" font-size="7.5" fill="#8a94a6" font-family="Inter,sans-serif">(185.220.101.99 · C2 Server)</text>
            </g>
            <!-- PREDICTED node: Domain Controller (AI-projected next step) -->
            <g class="graph-node" data-entity="dev-dc01-predicted" data-predicted="1" onclick="showPredictionDetails('dev-dc01-predicted')" oncontextmenu="event.preventDefault();showPredictionDetails('dev-dc01-predicted')">
              <circle cx="700" cy="640" r="20" fill="#fffbeb" stroke="#d97706" stroke-width="2"/>
              <text x="700" y="645" text-anchor="middle" font-size="14" dominant-baseline="central">🖥</text>
              <text class="predicted-glyph" x="717" y="630" text-anchor="middle">⏱</text>
              <text x="700" y="670" text-anchor="middle" font-size="10" fill="#d97706" font-family="Inter,sans-serif" font-weight="600">DC-01</text>
              <text class="predicted-sublabel" x="700" y="683" text-anchor="middle">PREDICTED · LATERAL MOVEMENT</text>
            </g>
            <!-- PREDICTED node: LSASS Credential Dump (bridges admin-creds-on-WS045 to DC-01 LoginTo) -->
            <g class="graph-node" data-entity="proc-credump-predicted" data-predicted="1" onclick="showPredictionDetails('proc-credump-predicted')" oncontextmenu="event.preventDefault();showPredictionDetails('proc-credump-predicted')">
              <circle cx="490" cy="660" r="18" fill="#fffbeb" stroke="#d97706" stroke-width="2"/>
              <text x="490" y="664" text-anchor="middle" font-size="13" dominant-baseline="central">🔧</text>
              <text class="predicted-glyph" x="506" y="650" text-anchor="middle">⏱</text>
              <text x="490" y="686" text-anchor="middle" font-size="9.5" fill="#d97706" font-family="Inter,sans-serif" font-weight="600">LSASS Dump</text>
              <text class="predicted-sublabel" x="490" y="698" text-anchor="middle">PREDICTED · CREDENTIAL ACCESS</text>
            </g>

            <g class="edge-info-btn" data-label="TriggeredBy" data-source="alert-impossible-travel" data-target="user-m-henderson" onclick="showEdgeRelation(event,this)"><circle cx="430" cy="155" r="10" fill="#fff" stroke="#ef4444" stroke-width="1.5"/><text x="430" y="159" text-anchor="middle" font-size="11" dominant-baseline="central">⚡</text></g>
            <g class="edge-info-btn" data-label="DetectedOn" data-source="alert-impossible-travel" data-target="svc-azure-ad" onclick="showEdgeRelation(event,this)"><circle cx="740" cy="125" r="10" fill="#fff" stroke="#ef4444" stroke-width="1.5"/><text x="740" y="129" text-anchor="middle" font-size="11" dominant-baseline="central">🔍</text></g>
            <g class="edge-info-btn" data-label="AccessedFrom" data-source="user-m-henderson" data-target="ip-tor" onclick="showEdgeRelation(event,this)"><circle cx="185" cy="337" r="10" fill="#fff" stroke="#ef4444" stroke-width="1.5"/><text x="185" y="341" text-anchor="middle" font-size="11" dominant-baseline="central">🌐</text></g>
            <g class="edge-info-btn" data-label="AccessedFrom" data-source="user-m-henderson" data-target="ip-internal" onclick="showEdgeRelation(event,this)"><circle cx="360" cy="342" r="10" fill="#fff" stroke="#2C66DD" stroke-width="1.5"/><text x="360" y="346" text-anchor="middle" font-size="11" dominant-baseline="central">🌐</text></g>
            <g class="edge-info-btn" data-label="LoginTo" data-source="user-m-henderson" data-target="svc-azure-ad" onclick="showEdgeRelation(event,this)"><circle cx="585" cy="212" r="10" fill="#fff" stroke="#2C66DD" stroke-width="1.5"/><text x="585" y="216" text-anchor="middle" font-size="11" dominant-baseline="central">🔐</text></g>
            <g class="edge-info-btn" data-label="ResolvedTo" data-source="ip-internal" data-target="dev-ws045" onclick="showEdgeRelation(event,this)"><circle cx="370" cy="487" r="10" fill="#fff" stroke="#2C66DD" stroke-width="1.5"/><text x="370" y="491" text-anchor="middle" font-size="11" dominant-baseline="central">📌</text></g>
            <g class="edge-info-btn" data-label="AccessedFile" data-source="user-m-henderson" data-target="svc-sharepoint" onclick="showEdgeRelation(event,this)"><circle cx="590" cy="330" r="10" fill="#fff" stroke="#ef4444" stroke-width="1.5"/><text x="590" y="334" text-anchor="middle" font-size="11" dominant-baseline="central">📁</text></g>
            <g class="edge-info-btn" data-label="IssuedTo" data-source="svc-azure-ad" data-target="svc-oauth" onclick="showEdgeRelation(event,this)"><circle cx="925" cy="377" r="10" fill="#fff" stroke="#ef4444" stroke-width="1.5"/><text x="925" y="381" text-anchor="middle" font-size="11" dominant-baseline="central">📜</text></g>
            <g class="edge-info-btn" data-label="LoginTo" data-source="user-admin" data-target="svc-azure-ad" onclick="showEdgeRelation(event,this)"><circle cx="755" cy="275" r="10" fill="#fff" stroke="#ef4444" stroke-width="1.5"/><text x="755" y="279" text-anchor="middle" font-size="11" dominant-baseline="central">🔐</text></g>
            <g class="edge-info-btn" data-label="CommunicatedWith" data-source="ip-tor" data-target="dev-ws045" onclick="showEdgeRelation(event,this)"><circle cx="220" cy="505" r="10" fill="#fff" stroke="#ef4444" stroke-width="1.5"/><text x="220" y="509" text-anchor="middle" font-size="11" dominant-baseline="central">📡</text></g>
            <g class="edge-info-btn" data-label="AccessedFile" data-source="dev-ws045" data-target="svc-sharepoint" onclick="showEdgeRelation(event,this)"><circle cx="605" cy="492" r="10" fill="#fff" stroke="#ef4444" stroke-width="1.5"/><text x="605" y="496" text-anchor="middle" font-size="11" dominant-baseline="central">📁</text></g>
            <g class="edge-info-btn" data-label="LoginTo" data-source="user-m-henderson" data-target="dev-ws045" onclick="showEdgeRelation(event,this)"><circle cx="300" cy="410" r="10" fill="#fff" stroke="#2C66DD" stroke-width="1.5"/><text x="300" y="414" text-anchor="middle" font-size="11" dominant-baseline="central">💻</text></g>
            <g class="edge-info-btn" data-label="EscalatedTo" data-source="dev-ws045" data-target="user-admin" onclick="showEdgeRelation(event,this)"><circle cx="472" cy="462" r="10" fill="#fff" stroke="#FF5900" stroke-width="1.5"/><text x="472" y="466" text-anchor="middle" font-size="11" dominant-baseline="central">⬆</text></g>
            <g class="edge-info-btn" data-label="AccessedFile" data-source="svc-oauth" data-target="svc-sharepoint" onclick="showEdgeRelation(event,this)"><circle cx="915" cy="490" r="10" fill="#fff" stroke="#ef4444" stroke-width="1.5"/><text x="915" y="494" text-anchor="middle" font-size="11" dominant-baseline="central">🎟</text></g>
            <g class="edge-info-btn" data-label="CommunicatedWith" data-source="ip-tor" data-target="domain-c2" onclick="showEdgeRelation(event,this)"><circle cx="120" cy="540" r="10" fill="#fff" stroke="#ef4444" stroke-width="1.5"/><text x="120" y="544" text-anchor="middle" font-size="11" dominant-baseline="central">📡</text></g>
            <g class="edge-info-btn" data-label="CommunicatedWith" data-source="dev-ws045" data-target="domain-c2" onclick="showEdgeRelation(event,this)"><circle cx="230" cy="610" r="10" fill="#fff" stroke="#ef4444" stroke-width="1.5"/><text x="230" y="614" text-anchor="middle" font-size="11" dominant-baseline="central">📡</text></g>
            <!-- PREDICTED edge-info button: administrator -> DC-01 -->
            <g class="edge-info-btn" data-predicted="1" data-label="LoginTo" data-source="user-admin" data-target="dev-dc01-predicted" onclick="showEdgePrediction(event,this)"><circle cx="660" cy="495" r="10" fill="#fffbeb" stroke="#d97706" stroke-width="1.5"/><text x="660" y="499" text-anchor="middle" font-size="11" dominant-baseline="central">🔐</text></g>
            <!-- PREDICTED edge-info button: dev-ws045 -> Credential Dump -->
            <g class="edge-info-btn" data-predicted="1" data-label="ExecutedOn" data-source="dev-ws045" data-target="proc-credump-predicted" onclick="showEdgePrediction(event,this)"><circle cx="407" cy="615" r="10" fill="#fffbeb" stroke="#d97706" stroke-width="1.5"/><text x="407" y="619" text-anchor="middle" font-size="11" dominant-baseline="central">▶</text></g>
          </svg>

          <div class="graph-canvas-toolbar">
            <span class="canvas-edge-tag"><span class="legend-line-red"></span> Malicious</span>
            <span class="canvas-edge-tag"><span class="legend-line-blue"></span> Normal</span>
            <span style="margin:0 4px;border-left:1px solid #e2e8f0;height:14px;align-self:center;"></span>
            <span class="canvas-edge-tag" id="legendAiCorrelated" title="Entities and relationships surfaced by AI from existing log evidence (observed, not predicted)"><span class="legend-ai-spark">\u2728</span> AI-correlated</span>
            <span class="canvas-edge-tag" id="legendPredicted" title="AI-projected next attack step based on TTP patterns (not yet observed)"><span class="legend-predicted-glyph">⏱</span> Predicted</span>
            <span style="margin:0 4px;border-left:1px solid #e2e8f0;height:14px;align-self:center;"></span>
            <span class="canvas-edge-tag" style="cursor:pointer;" onclick="toggleRelGuide(event)" title="Relationship Guide">⟷ Relations</span>
          </div>
          <div class="rel-guide-popup" id="relGuidePopup"></div>

          <div class="graph-zoom">
            <button onclick="zoomGraph(1.2)" title="Zoom in">+</button>
            <button onclick="zoomGraph(0.8)" title="Zoom out">−</button>
            <button onclick="resetGraphView()" title="Reset view" style="font-size:12px;">⟲</button>
            <button id="avMaxBtn" onclick="toggleAttackVectorMaximize()" title="Maximize" style="font-size:12px;">⛶</button>
          </div>
          <div class="zia-float" onclick="showToast('✦','Zia AI: Ask me about this graph…')" title="Ask Zia">✦</div>
          <div class="edge-relation-popup" id="edgeRelPopup"></div>
        </div>

        <div class="entity-details-slider" id="entitySlider">
          <div class="eds-hdr">
            <div style="display:flex;flex-direction:column;gap:4px;flex:1;min-width:0;">
              <div style="display:flex;align-items:center;gap:8px;">
                <span id="edsTypeBadge" class="eds-type-badge" style="display:none;"></span>
                <span class="eds-hdr-title" id="edsTitle">Entity Details</span>
              </div>
              <div id="edsDepthBadge" class="eds-depth-badge" style="display:none;"></div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;">
              <a class="eds-hide-link" onclick="closeEntitySlider()">Hide Details</a>
            </div>
          </div>
          <div class="eds-tabs-host" id="edsTabsHost"></div>
          <div class="eds-body" id="edsBody"></div>
          <div class="action-panel" id="actionPanel">
            <div class="ap-hdr">
              <button class="ap-back" onclick="closeActionPanel()">← Back</button>
              <span class="ap-title" id="apTitle"></span>
              <span class="ap-badge" id="apBadge" style="display:none;"></span>
            </div>
            <div class="ap-body" id="apBody"></div>
            <div class="ap-confirm-bar" id="apActions" style="display:none;"></div>
          </div>
        </div>

        <div class="graph-ctx" id="graphCtxMenu"></div>
        <div class="eqc-overlay" id="eqcOverlay">
          <div class="eqc-card" id="eqcCard"></div>
        </div>
      </div>
    </div>
  </div>`;
}

let _avMounted = false;

/* V4: Graph is embedded in tab — just update chip counts.
   Verbatim copy from V4/index.html line 7181. */
function initGraphChips() {
  graphViewActive = true;
  const visibleLines = [...document.querySelectorAll('#graphSvg line.graph-edge-mal')]
    .filter(l => l.style.display !== 'none');
  const malChip = document.querySelector('#cmdPillMalCount .cmd-pill-num');
  if (malChip) malChip.textContent = visibleLines.length;
  let critNodes = 0;
  document.querySelectorAll('#graphSvg g.graph-node').forEach(n => {
    if (n.style.display === 'none') return;
    const c = n.querySelector('circle:not(.expand-indicator)');
    if (c && (c.getAttribute('filter') || '').includes('glow-r')) critNodes++;
  });
  const critChip = document.querySelector('#cmdPillCritCount .cmd-pill-num');
  if (critChip) critChip.textContent = critNodes;

  /* Update entity-type dropdown counts based on currently visible nodes */
  const typeCounts = { user:0, device:0, ip:0, service:0, process:0, alert:0, domain:0 };
  let total = 0;
  document.querySelectorAll('#graphSvg g.graph-node').forEach(n => {
    if (n.style.display === 'none') return;
    total++;
    const eid = n.getAttribute('data-entity') || '';
    const ent = (typeof ENTITIES !== 'undefined') ? ENTITIES[eid] : null;
    const t = ent && ent.type;
    if (t && typeCounts.hasOwnProperty(t)) { typeCounts[t]++; return; }
    if (eid.startsWith('user-'))   typeCounts.user++;
    else if (eid.startsWith('dev-'))    typeCounts.device++;
    else if (eid.startsWith('ip-'))     typeCounts.ip++;
    else if (eid.startsWith('svc-'))    typeCounts.service++;
    else if (eid.startsWith('proc-'))   typeCounts.process++;
    else if (eid.startsWith('alert-'))  typeCounts.alert++;
    else if (eid.startsWith('domain-')) typeCounts.domain++;
  });
  const countMap = { all:total, user:typeCounts.user, asset:typeCounts.device, ip:typeCounts.ip, account:typeCounts.service, process:typeCounts.process, alert:typeCounts.alert, domain:typeCounts.domain, location:0 };
  const menu = document.getElementById('entityChipMenu');
  if (menu) {
    menu.querySelectorAll('.gcb-option').forEach(opt => {
      const v = opt.getAttribute('data-val');
      const cEl = opt.querySelector('.gcb-count');
      if (cEl && countMap.hasOwnProperty(v)) cEl.textContent = countMap[v];
    });
  }
}
function openInvestigationGraph() { initGraphChips(); }

function mountAttackGraph(){
  const panel = document.getElementById('panel-attack-vector');
  if (!panel) return;
  panel.innerHTML = attackVectorHTML();
  graphViewActive = true;
  _avMounted = true;

  /* Init V4 graph behaviors — mirrors V4 app.js + switchInvPageTab('invAttackPage') */
  try {
    if (typeof initNodeRegistry === 'function') initNodeRegistry();
    if (typeof initGraphPan      === 'function') initGraphPan();
    /* V4 calls initGraphChips() (NOT updateGraphSummary) on initial mount —
       updateGraphSummary wipes the entity-chip dropdown and replaces it with
       plain pills. Keep the V4 chip HTML and only refresh the counts. */
    initGraphChips();

    /* Make all static nodes draggable */
    document.querySelectorAll('#graphSvg g.graph-node').forEach(g => {
      const nodeId = g.getAttribute('data-entity');
      const circle = g.querySelector('circle:not(.expand-indicator)');
      const texts  = g.querySelectorAll('text');
      const iconEl = texts[0] || null;
      const labelEl = texts[1] || texts[0] || null;
      if (circle && iconEl && labelEl && typeof makeNodeDraggable === 'function') {
        makeNodeDraggable(g, circle, iconEl, labelEl, nodeId);
      }
    });

    /* Partial-mode: hide AI-discovered entities until "Start Investigation"
       is clicked in the Investigation tab. The visible set is derived from
       the alert summary (alert + main user + IPs + workstation). */
    applyAttackGraphPartialMode();
  } catch(err){
    console.error('[mountAttackGraph]', err);
  }

  /* Dev hook: ?openSlider=<entityId> auto-opens the slider for screenshots
     ?openEdge=src,tgt — auto-opens the edge relation slider
     ?openCtx=<entityId> — auto-opens right-click context menu */
  try {
    const m = location.search.match(/openSlider=([\w-]+)/);
    if (m && typeof openEntitySlider === 'function') {
      setTimeout(() => openEntitySlider(m[1]), 100);
    }
    const me = location.search.match(/openEdge=([\w-]+),([\w-]+)/);
    if (me && typeof showEdgeRelation === 'function') {
      setTimeout(() => {
        const btn = document.querySelector(`#graphSvg .edge-info-btn[data-source="${me[1]}"][data-target="${me[2]}"]`);
        if (btn) showEdgeRelation({ stopPropagation:()=>{} }, btn);
      }, 100);
    }
    const mc = location.search.match(/openCtx=([\w-]+)/);
    if (mc && typeof showGraphCtx === 'function') {
      setTimeout(() => showGraphCtx({ preventDefault:()=>{}, stopPropagation:()=>{}, clientX:600, clientY:300 }, mc[1]), 100);
    }
    if (location.search.includes('openEntityChip') && typeof toggleGraphChipMenu === 'function') {
      setTimeout(() => {
        const chip = document.getElementById('entityChip');
        if (chip) toggleGraphChipMenu('entityChipMenu', chip);
      }, 150);
    }
  } catch(_){}
}

/* Global click — close menus / context */
document.addEventListener('click', e => {
  if (typeof hideGraphCtx === 'function' && !e.target.closest('.graph-ctx')) hideGraphCtx();
});

/* ─────────────────────────────────────────────────────────────────────────
   Attack Vector — maximize / fullscreen mode
   Hides the app header, alerts sub-nav, detail sidebar and tab strip;
   adds a dedicated breadcrumb (Explorer › <alert title> › Attack Vector).
   ───────────────────────────────────────────────────────────────────────── */
function toggleAttackVectorMaximize(){
  const on = !document.body.classList.contains('av-maximized');
  document.body.classList.toggle('av-maximized', on);

  let bc = document.getElementById('avMaxBreadcrumb');
  if (on) {
    if (!bc) {
      bc = document.createElement('div');
      bc.id = 'avMaxBreadcrumb';
      bc.className = 'av-max-breadcrumb';
      document.body.appendChild(bc);
    }
    const alertTitle = (typeof currentAlertId !== 'undefined' && typeof ALERT_DETAIL !== 'undefined' && ALERT_DETAIL[currentAlertId])
      ? ALERT_DETAIL[currentAlertId].title : 'Alert';
    bc.innerHTML = `
      <a class="bc-link" onclick="exitAttackVectorMaximize();showListView()">Explorer</a>
      <span class="bc-sep">›</span>
      <a class="bc-link" onclick="exitAttackVectorMaximize()">${alertTitle}</a>
      <span class="bc-sep">›</span>
      <span class="bc-current">Attack Vector</span>
      <button class="av-max-exit" onclick="exitAttackVectorMaximize()" title="Exit fullscreen">✕</button>`;
    bc.style.display = 'flex';
    const btn = document.getElementById('avMaxBtn');
    if (btn) { btn.textContent = '⛶'; btn.title = 'Exit fullscreen'; }
  } else {
    if (bc) bc.style.display = 'none';
    const btn = document.getElementById('avMaxBtn');
    if (btn) { btn.textContent = '⛶'; btn.title = 'Maximize'; }
  }
}

function exitAttackVectorMaximize(){
  if (document.body.classList.contains('av-maximized')) toggleAttackVectorMaximize();
}

/* ESC exits fullscreen */
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && document.body.classList.contains('av-maximized')) {
    exitAttackVectorMaximize();
  }
});

/* Entities that are only known after AI investigation. In partial mode
   (before the user clicks "Start Investigation" in the Investigation tab)
   these nodes and any edges touching them are hidden, leaving only the
   entities present in the alert summary / sidebar. */
const PARTIAL_HIDDEN_ENTITIES = ['svc-azure-ad','svc-sharepoint','svc-oauth','user-admin','domain-c2','dev-dc01-predicted','proc-credump-predicted'];

/* Entities flagged as AI-PREDICTED (not yet observed). Rendered with
   amber dashed outline + ⏱ glyph + PREDICTED sub-label. Predictions
   are TTP-based projections of the most likely next attack step;
   they should never be confused with observed events. */
const PREDICTED_ENTITIES = new Set(['dev-dc01-predicted','proc-credump-predicted']);

function isAiInvestigated(){
  const d = (typeof currentAlertId !== 'undefined' && typeof ALERT_DETAIL !== 'undefined')
    ? ALERT_DETAIL[currentAlertId] : null;
  return !!(d && d.aiInvestigatedRuntime);
}

function applyAttackGraphPartialMode(){
  const container = document.getElementById('graphContainer');
  const svg = document.getElementById('graphSvg');
  if (!container || !svg) return;

  /* Remove any existing partial-mode footer note (re-mount safety) */
  const existingNote = document.getElementById('avPartialNote');
  if (existingNote) existingNote.remove();

  const hidden = new Set(PARTIAL_HIDDEN_ENTITIES);
  const partial = !isAiInvestigated();

  /* Toggle node visibility */
  svg.querySelectorAll('g.graph-node').forEach(n => {
    const eid = n.getAttribute('data-entity');
    n.style.display = (partial && hidden.has(eid)) ? 'none' : '';
  });

  /* Toggle edge lines + edge-info buttons */
  const edgeTouchesHidden = el => {
    const s = el.getAttribute('data-source');
    const t = el.getAttribute('data-target');
    return hidden.has(s) || hidden.has(t);
  };
  svg.querySelectorAll('line[data-source]').forEach(l => {
    if (partial && edgeTouchesHidden(l)) l.style.display = 'none';
    else if (!partial) l.style.display = '';
  });
  svg.querySelectorAll('g.edge-info-btn').forEach(b => {
    if (partial && edgeTouchesHidden(b)) b.style.display = 'none';
    else if (!partial) b.style.display = '';
  });

  /* Tag AI-correlated nodes/edges with data-ai="1" once the investigation
     has run, so CSS can render them with a dashed purple halo and a ✨
     glyph. AI-correlated == any element touching an AI-only entity. */
  const tagAi = !partial;
  svg.querySelectorAll('g.graph-node').forEach(n => {
    const eid = n.getAttribute('data-entity');
    const isPredicted = PREDICTED_ENTITIES.has(eid);
    if (tagAi && hidden.has(eid) && !isPredicted) {
      n.setAttribute('data-ai', '1');
      /* Inject the ✨ corner glyph exactly once per AI node */
      if (!n.querySelector('.ai-spark-glyph')) {
        const c = n.querySelector('circle');
        if (c) {
          const cx = parseFloat(c.getAttribute('cx'));
          const cy = parseFloat(c.getAttribute('cy'));
          const r  = parseFloat(c.getAttribute('r'));
          const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
          t.setAttribute('class', 'ai-spark-glyph');
          t.setAttribute('x', cx + r * 0.85);
          t.setAttribute('y', cy - r * 0.55);
          t.setAttribute('text-anchor', 'middle');
          t.setAttribute('pointer-events', 'none');
          t.textContent = '\u2728';
          n.appendChild(t);
        }
      }
    } else if (!isPredicted) {
      n.removeAttribute('data-ai');
    }
  });
  svg.querySelectorAll('line[data-source]').forEach(l => {
    if (tagAi && edgeTouchesHidden(l)) l.setAttribute('data-ai', '1');
    else l.removeAttribute('data-ai');
    /* Predicted edges already carry data-predicted="1" in markup;
       toggle visibility based on partial mode */
    if (l.getAttribute('data-predicted') === '1') {
      l.style.display = partial ? 'none' : '';
    }
  });
  svg.querySelectorAll('g.edge-info-btn').forEach(b => {
    if (tagAi && edgeTouchesHidden(b)) b.setAttribute('data-ai', '1');
    else b.removeAttribute('data-ai');
    if (b.getAttribute('data-predicted') === '1') {
      b.style.display = partial ? 'none' : '';
    }
  });

  /* Toggle a container-level class so the legend chip can show/hide */
  container.classList.toggle('av-ai-investigated', tagAi);

  /* Refresh chip counts to reflect what's visible */
  if (typeof initGraphChips === 'function') initGraphChips();

  /* Top note in partial mode (anchored to inv-graph-container so it can
     never escape above the tabs row) */
  if (partial) {
    const host = document.querySelector('.inv-graph-container');
    if (host) {
      const note = document.createElement('div');
      note.id = 'avPartialNote';
      note.className = 'av-partial-note';
      note.innerHTML = '<span class="av-partial-icon">\u2728</span> Quick view \u2014 expand with AI <button class="av-partial-btn inv-ai-cta-btn" onclick="startInvestigation()"><span class="ai-spark">\u2728</span> Start Investigation</button>';
      host.appendChild(note);
    }
  }
}
