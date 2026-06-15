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
/* Per-(parent,category) collapse hub: a single edge from the parent ends in a
   ✕ hub; all leaves branch off the hub. Clicking ✕ groups the leaves into a
   single "Category (N)" count node; clicking that count node re-expands. */
const groupHubs = {};

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
                  <div class="gcb-option active" data-val="all" onclick="pickEntityChip(this,'all','All Entities')">All Entities <span class="gcb-count">0</span></div>
                  <div class="gcb-option" data-val="host" onclick="pickEntityChip(this,'host','Hosts')"><span class="gcb-dot" style="background:#198019;"></span> Hosts <span class="gcb-count">0</span></div>
                  <div class="gcb-option" data-val="ip" onclick="pickEntityChip(this,'ip','IP Addresses')"><span class="gcb-dot" style="background:#f97316;"></span> IP Addresses <span class="gcb-count">0</span></div>
                  <div class="gcb-option" data-val="domain" onclick="pickEntityChip(this,'domain','Domains')"><span class="gcb-dot" style="background:#DD1616;"></span> Domains <span class="gcb-count">0</span></div>
                  <div class="gcb-option" data-val="user" onclick="pickEntityChip(this,'user','Users')"><span class="gcb-dot" style="background:#2C66DD;"></span> Users <span class="gcb-count">0</span></div>
                  <div class="gcb-option" data-val="file" onclick="pickEntityChip(this,'file','Files')"><span class="gcb-dot" style="background:#0891b2;"></span> Files <span class="gcb-count">0</span></div>
                  <div class="gcb-option" data-val="process" onclick="pickEntityChip(this,'process','Processes')"><span class="gcb-dot" style="background:#7c3aed;"></span> Processes <span class="gcb-count">0</span></div>
                  <div class="gcb-option" data-val="other" onclick="pickEntityChip(this,'other','Others')"><span class="gcb-dot" style="background:#64748b;"></span> Others <span class="gcb-count">0</span></div>
                </div>
              </div>
              <span class="cmd-pill cmd-pill-threat cmd-pill-clickable" id="cmdPillThreatIndicators" onclick="toggleCmdPillPopup(event,'threatIndicators')" title="View malicious connections and critical entities">
                <span class="cmd-pill-dot" style="background:#DD1616;"></span>
                <span class="cmd-pill-num">0</span>
                Threat Indicators
                <span class="cmd-pill-caret">▾</span>
              </span>
            </div>
            <div class="cmd-pill-popup" id="cmdPillPopup"></div>
            <div class="cmd-spacer"></div>
            <div class="gcb-chip gcb-chip-action" id="tlPlayBtn" style="display:none;" onclick="openTimelinePlayer()" title="Play the attack chronologically">
              <span class="gcb-icon">▶</span>
              <span class="gcb-label">Attack Story</span>
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
          </svg>

          <div class="graph-canvas-toolbar">
            <span class="canvas-edge-tag"><span class="legend-line-red"></span> Malicious</span>
            <span class="canvas-edge-tag"><span class="legend-line-blue"></span> Normal</span>
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

        <!-- Ask Zia — Guided Investigation / Go Hunt chat panel -->
        <div class="zia-hunt-panel" id="ziaHuntPanel">
          <div class="zhp-hdr">
            <div class="zhp-zia-logo">✦</div>
            <div class="zhp-hdr-info">
              <div class="zhp-hdr-title">Ask Zia <span class="zhp-hdr-badge">Guided Investigation</span></div>
              <div class="zhp-hdr-entity" id="zhpEntityName"></div>
            </div>
            <button class="zhp-close" onclick="closeZiaHuntPanel()" title="Close">✕</button>
          </div>
          <div class="zhp-chat" id="zhpChat"></div>
          <div class="zhp-suggestions" id="zhpSuggestions"></div>
          <div class="zhp-input-bar">
            <input type="text" class="zhp-input" id="zhpInput"
              placeholder="Ask about this entity…"
              autocomplete="off"
              onkeydown="if(event.key==='Enter')zhpSend()">
            <button class="zhp-send-btn" onclick="zhpSend()" title="Send">
              <svg width="15" height="15" viewBox="0 0 16 16" fill="none">
                <path d="M2 8h12M10 4l4 4-4 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </button>
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
  const malCount = visibleLines.length;
  let critNodes = 0;
  document.querySelectorAll('#graphSvg g.graph-node').forEach(n => {
    if (n.style.display === 'none') return;
    const c = n.querySelector('circle:not(.expand-indicator)');
    if (c && (c.getAttribute('filter') || '').includes('glow-r')) critNodes++;
  });
  const threatChip = document.querySelector('#cmdPillThreatIndicators .cmd-pill-num');
  if (threatChip) threatChip.textContent = malCount + critNodes;

  /* Update entity-type dropdown counts based on currently visible nodes */
  // Bucket nodes into the 7 dropdown categories (per device_and_other_entity_spec.md):
  //   host    ← type=device          (id prefix dev-)
  //   ip      ← type=ip              (id prefix ip-)
  //   domain  ← type=domain          (id prefix domain-)
  //   user    ← type=user            (id prefix user-)
  //   file    ← type=file            (id prefix file-)
  //   process ← type=process, plus type=service ONLY for OS-level services
  //             (svc-winupdatesvc, svc-wuauserv, svc-spooler, ...)
  //   other   ← type=service for SaaS tenants / cloud apps / tokens
  //             (svc-azure-ad, svc-sharepoint, svc-oauth, ...), plus anything
  //             else (incl. type=outline, hash, url, email, mailbox, token).
  // The alert node is the centre of the graph and is intentionally NOT bucketed.
  const SAAS_SVC_RE = /^svc-(azure|aad|sharepoint|exchange|m365|o365|onedrive|teams|salesforce|aws|gcp|okta|oauth|slack|saas)/i;
  const buckets = { host:0, ip:0, domain:0, user:0, file:0, process:0, other:0 };
  let total = 0;
  const classify = (eid, ent) => {
    const t = ent && ent.type;
    if (t === 'device'  || eid.startsWith('dev-'))    return 'host';
    if (t === 'ip'      || eid.startsWith('ip-'))     return 'ip';
    if (t === 'domain'  || eid.startsWith('domain-')) return 'domain';
    if (t === 'user'    || eid.startsWith('user-'))   return 'user';
    if (t === 'file'    || eid.startsWith('file-'))   return 'file';
    if (t === 'process' || eid.startsWith('proc-'))   return 'process';
    if (t === 'service' || eid.startsWith('svc-')) {
      return SAAS_SVC_RE.test(eid) ? 'other' : 'process';
    }
    if (t === 'alert'   || eid.startsWith('alert-')) return null; // centre, not bucketed
    return 'other';
  };
  document.querySelectorAll('#graphSvg g.graph-node').forEach(n => {
    if (n.style.display === 'none') return;
    total++;
    const eid = n.getAttribute('data-entity') || '';
    const ent = (typeof ENTITIES !== 'undefined') ? ENTITIES[eid] : null;
    const b = classify(eid, ent);
    if (b) buckets[b]++;
  });
  const countMap = { all: total, ...buckets };
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
    /* Re-count chips AFTER partial-mode hides the AI-only nodes so the
       entity-type dropdown and malicious / critical pills reflect only
       what is actually on the canvas. */
    initGraphChips();
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
const PARTIAL_HIDDEN_ENTITIES = ['svc-azure-ad','svc-sharepoint','svc-oauth','user-admin','domain-c2'];

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

  /* The "Attack Story" replay button is only meaningful once the full
     attack chain has been revealed — keep it hidden until the analyst
     clicks "Start Investigation". */
  const playBtn = document.getElementById('tlPlayBtn');
  if (playBtn) playBtn.style.display = partial ? 'none' : '';

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
