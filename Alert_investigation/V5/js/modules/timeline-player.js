/* ────────────────────────────────────────────────────────────────────────
 * timeline-player.js — Attack Timeline Replay (right-slider variant)
 *
 * Chronological playback of the kill-chain rendered inside the SAME right
 * slider used for entity / edge details (#entitySlider with edsTitle /
 * edsTypeBadge / edsBody). The graph stays fully visible on the left and
 * is highlighted step-by-step.
 *
 * Public API:
 *   openTimelinePlayer()   — open the timeline in the right slider
 *   closeTimelinePlayer()  — restore graph & close slider
 *   timelineNext() / timelinePrev() / timelineJump(i)
 *   timelinePlayPause()    — toggle auto-advance
 * ──────────────────────────────────────────────────────────────────────── */

/* Wall-clock base time for the incident. Each step has its own offset in
 * minutes; we render absolute timestamps so the analyst doesn't have to
 * do T+ math. */
const _TL_BASE = new Date('2026-05-11T09:42:00');
const _TL_MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

function _tlFormat(offsetMin) {
  const d = new Date(_TL_BASE.getTime() + offsetMin * 60 * 1000);
  const pad = n => String(n).padStart(2, '0');
  return `${_TL_MONTHS[d.getMonth()]} ${d.getDate()}, ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const TIMELINE_STEPS = [
  {
    offsetMin: 0,
    tier: 'observed',
    title: 'Impossible Travel alert fires',
    narrative: 'Azure AD sign-in logs show m.henderson authenticating from Bucharest, Romania only 14 minutes after a successful login from the corporate office in Austin — a geographic transition that is physically impossible.',
    mitre: 'TA0001 · Initial Access',
    entities: ['alert-impossible-travel', 'user-m-henderson', 'svc-azure-ad'],
    edges: [
      ['alert-impossible-travel', 'user-m-henderson'],
      ['alert-impossible-travel', 'svc-azure-ad']
    ]
  },
  {
    offsetMin: 2,
    tier: 'observed',
    title: 'Foreign sign-in from Tor exit node',
    narrative: 'The Romanian login originates from 185.220.101.42 — a well-known Tor exit node tagged by threat intelligence as actively involved in credential-stuffing campaigns.',
    mitre: 'T1078.004 · Valid Accounts: Cloud',
    entities: ['user-m-henderson', 'ip-tor'],
    edges: [['user-m-henderson', 'ip-tor']]
  },
  {
    offsetMin: 5,
    tier: 'observed',
    title: 'Tor node beacons to C2 infrastructure',
    narrative: 'Firewall logs show 185.220.101.42 establishing outbound HTTPS to c2-update.darkoperator.net — a domain registered 3 days ago and previously linked to FIN-class actors.',
    mitre: 'TA0011 · Command & Control',
    entities: ['ip-tor', 'domain-c2'],
    edges: [['ip-tor', 'domain-c2']]
  },
  {
    offsetMin: 8,
    tier: 'observed',
    title: 'Inbound contact to internal workstation',
    narrative: 'CORP-WS-045 receives an inbound SMB session from the Tor exit — an unusual reverse-direction connection that suggests a tunneled remote shell.',
    mitre: 'T1021 · Remote Services',
    entities: ['ip-tor', 'dev-ws045'],
    edges: [['ip-tor', 'dev-ws045']]
  },
  {
    offsetMin: 12,
    tier: 'observed',
    title: 'Interactive logon to CORP-WS-045',
    narrative: 'm.henderson signs into CORP-WS-045 from internal IP 10.18.1.81. The session is interactive (Type 2) — consistent with the attacker pivoting onto an endpoint after credential reuse.',
    mitre: 'T1078 · Valid Accounts',
    entities: ['user-m-henderson', 'ip-internal', 'dev-ws045'],
    edges: [
      ['user-m-henderson', 'dev-ws045'],
      ['ip-internal', 'dev-ws045'],
      ['user-m-henderson', 'ip-internal']
    ]
  },
  {
    offsetMin: 18,
    tier: 'observed',
    title: 'Workstation beacons to C2',
    narrative: 'CORP-WS-045 establishes its own outbound channel to c2-update.darkoperator.net — confirming foothold and enabling subsequent hands-on-keyboard activity.',
    mitre: 'T1071.001 · Application Layer Protocol: Web',
    entities: ['dev-ws045', 'domain-c2'],
    edges: [['dev-ws045', 'domain-c2']]
  },
  {
    offsetMin: 24,
    tier: 'observed',
    title: 'Privilege escalation to Administrator',
    narrative: 'A local privilege-escalation primitive on CORP-WS-045 results in the attacker obtaining a process token impersonating the built-in Administrator account.',
    mitre: 'T1068 · Exploitation for Privilege Escalation',
    entities: ['dev-ws045', 'user-admin'],
    edges: [['dev-ws045', 'user-admin']]
  },
  {
    offsetMin: 31,
    tier: 'observed',
    title: 'Administrator authenticates to Azure AD',
    narrative: 'The newly-obtained Administrator credentials are exercised against Azure AD — likely to enumerate available cloud apps and OAuth scopes before exfiltration.',
    mitre: 'T1078.004 · Valid Accounts: Cloud',
    entities: ['user-admin', 'svc-azure-ad'],
    edges: [['user-admin', 'svc-azure-ad']]
  },
  {
    offsetMin: 36,
    tier: 'observed',
    title: 'OAuth tokens issued',
    narrative: 'Azure AD issues 3 refresh tokens covering Files.ReadWrite.All and Sites.Read.All — providing durable, MFA-bypassing access to SharePoint Online.',
    mitre: 'T1528 · Steal Application Access Token',
    entities: ['svc-azure-ad', 'svc-oauth'],
    edges: [['svc-azure-ad', 'svc-oauth']]
  },
  {
    offsetMin: 42,
    tier: 'observed',
    title: 'SharePoint file access via stolen tokens',
    narrative: 'The OAuth tokens are used to enumerate and download files from the Finance and HR document libraries on SharePoint Online. Both m.henderson and CORP-WS-045 also touch SharePoint directly.',
    mitre: 'T1213.002 · Data from Information Repositories: SharePoint',
    entities: ['svc-oauth', 'svc-sharepoint', 'dev-ws045', 'user-m-henderson'],
    edges: [
      ['svc-oauth', 'svc-sharepoint'],
      ['dev-ws045', 'svc-sharepoint'],
      ['user-m-henderson', 'svc-sharepoint']
    ]
  },
  {
    offsetMin: 48,
    tier: 'predicted',
    title: '[Predicted] LSASS credential dump on CORP-WS-045',
    narrative: 'AI projects the attacker will run procdump / comsvcs to extract cleartext credentials and Kerberos tickets from LSASS — converting the workstation foothold into reusable domain creds.',
    mitre: 'T1003.001 · OS Credential Dumping: LSASS Memory',
    entities: ['dev-ws045', 'proc-credump-predicted'],
    edges: [['dev-ws045', 'proc-credump-predicted']]
  },
  {
    offsetMin: 55,
    tier: 'predicted',
    title: '[Predicted] Administrator pivots to DC-01',
    narrative: 'Using the freshly-dumped credentials, AI expects an RDP or SMB login from Administrator to the domain controller DC-01 within ~7 minutes — the canonical lateral-movement step before domain-wide impact.',
    mitre: 'T1021.002 · Remote Services: SMB · TA0008 · Lateral Movement',
    entities: ['user-admin', 'dev-dc01-predicted'],
    edges: [['user-admin', 'dev-dc01-predicted']]
  }
];

let _tlIndex = 0;
let _tlAutoTimer = null;
let _tlOpen = false;
const _TL_AUTO_MS = 3500;

/* Return the chronological steps appropriate for the current graph mode.
 * Before "Start Investigation" is clicked, the attack-vector graph hides
 * AI-discovered entities (PARTIAL_HIDDEN_ENTITIES from graph.js). The
 * timeline must mirror that — any step involving a hidden entity (as a
 * node OR an edge endpoint) is suppressed until investigation begins. */
function _tlVisibleSteps() {
  const hidden = (typeof PARTIAL_HIDDEN_ENTITIES !== 'undefined')
    ? new Set(PARTIAL_HIDDEN_ENTITIES) : new Set();
  const investigated = (typeof isAiInvestigated === 'function') ? isAiInvestigated() : true;
  if (investigated) return TIMELINE_STEPS;
  return TIMELINE_STEPS.filter(s => {
    const ents = s.entities || [];
    const edges = s.edges || [];
    if (ents.some(e => hidden.has(e))) return false;
    if (edges.some(e => hidden.has(e[0]) || hidden.has(e[1]))) return false;
    return true;
  });
}

function openTimelinePlayer() {
  _tlOpen = true;
  if (typeof sliderEntityId !== 'undefined') {
    try { sliderEntityId = null; } catch (e) { /* noop */ }
  }
  if (typeof closeActionPanel === 'function') {
    try { closeActionPanel(); } catch (e) { /* noop */ }
  }

  const titleEl = document.getElementById('edsTitle');
  const badge = document.getElementById('edsTypeBadge');
  const depthBadge = document.getElementById('edsDepthBadge');
  const tabsHost = document.getElementById('edsTabsHost');
  if (titleEl) titleEl.textContent = 'Attack Timeline · Replay';
  if (badge) {
    badge.textContent = '▶ Chronological';
    badge.className = 'eds-type-badge';
    badge.style.cssText = 'display:inline-flex;background:#fff7ed;color:#9a3412;border:1px solid #fed7aa;';
  }
  if (depthBadge) depthBadge.style.display = 'none';
  if (tabsHost) tabsHost.innerHTML = '';

  _tlIndex = 0;
  _tlRenderSlider();

  document.getElementById('graphContainer').classList.add('slider-open');
  document.addEventListener('keydown', _tlKeyHandler);
}

function closeTimelinePlayer() {
  _tlClearAuto();
  _tlOpen = false;
  if (typeof closeEntitySlider === 'function') {
    closeEntitySlider();
  } else {
    document.getElementById('graphContainer').classList.remove('slider-open');
    if (typeof restoreGraphHighlights === 'function') restoreGraphHighlights();
  }
  document.removeEventListener('keydown', _tlKeyHandler);
}

function timelineNext() {
  const steps = _tlVisibleSteps();
  if (_tlIndex < steps.length - 1) {
    _tlIndex++;
    _tlRenderSlider();
  } else {
    _tlClearAuto();
    _tlRefreshControls();
  }
}

function timelinePrev() {
  if (_tlIndex > 0) {
    _tlIndex--;
    _tlRenderSlider();
  }
}

function timelineJump(i) {
  const steps = _tlVisibleSteps();
  if (i < 0 || i >= steps.length) return;
  _tlIndex = i;
  _tlRenderSlider();
}

function timelinePlayPause() {
  if (_tlAutoTimer) {
    _tlClearAuto();
    _tlRefreshControls();
  } else {
    _tlAutoTimer = setInterval(() => {
      const steps = _tlVisibleSteps();
      if (_tlIndex >= steps.length - 1) {
        _tlClearAuto();
        _tlRefreshControls();
        return;
      }
      _tlIndex++;
      _tlRenderSlider();
    }, _TL_AUTO_MS);
    _tlRefreshControls();
  }
}

function _tlClearAuto() {
  if (_tlAutoTimer) { clearInterval(_tlAutoTimer); _tlAutoTimer = null; }
}

function _tlKeyHandler(e) {
  if (!_tlOpen) return;
  // Ignore when typing into an input
  const t = e.target;
  if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
  if (e.key === 'Escape') { closeTimelinePlayer(); }
  else if (e.key === 'ArrowDown' || e.key === 'ArrowRight') { e.preventDefault(); timelineNext(); }
  else if (e.key === 'ArrowUp'   || e.key === 'ArrowLeft')  { e.preventDefault(); timelinePrev(); }
}

function _tlRefreshControls() {
  const total = _tlVisibleSteps().length;
  const ppIcon = document.getElementById('tlPlayPauseIcon');
  const ppLabel = document.getElementById('tlPlayPauseLabel');
  if (ppIcon)  ppIcon.textContent  = _tlAutoTimer ? '⏸' : '▶';
  if (ppLabel) ppLabel.textContent = _tlAutoTimer ? 'Pause' : 'Play';
  const prev = document.getElementById('tlPrevBtn');
  const next = document.getElementById('tlNextBtn');
  if (prev) prev.disabled = _tlIndex === 0;
  if (next) next.disabled = _tlIndex >= total - 1;
}

function _tlRenderSlider() {
  const body = document.getElementById('edsBody');
  if (!body) return;
  const steps = _tlVisibleSteps();
  const total = steps.length;
  if (_tlIndex >= total) _tlIndex = Math.max(0, total - 1);
  const current = steps[_tlIndex];

  // Sticky controls header (Prev / counter / Play / Next)
  const controls = `
    <div class="tl-controls">
      <button class="tl-btn" id="tlPrevBtn" onclick="timelinePrev()" ${_tlIndex === 0 ? 'disabled' : ''}>◀ Previous</button>
      <div class="tl-controls-mid">
        <span class="tl-counter">Step <strong>${_tlIndex + 1}</strong> of ${total}</span>
        <button class="tl-btn tl-btn-ghost" onclick="timelinePlayPause()" title="Auto-play">
          <span id="tlPlayPauseIcon">${_tlAutoTimer ? '⏸' : '▶'}</span>
          <span id="tlPlayPauseLabel">${_tlAutoTimer ? 'Pause' : 'Play'}</span>
        </button>
      </div>
      <button class="tl-btn tl-btn-primary" id="tlNextBtn" onclick="timelineNext()" ${_tlIndex >= total - 1 ? 'disabled' : ''}>Next ▶</button>
    </div>`;



  // Highlight banner for the active step
  const tierBadge = current.tier === 'predicted'
    ? '<span class="tl-tier-badge predicted">⏱ PREDICTED</span>'
    : '<span class="tl-tier-badge observed">● OBSERVED</span>';
  const activeCard = `
    <div class="tl-active-card ${current.tier === 'predicted' ? 'predicted' : ''}">
      <div class="tl-active-row">
        <span class="tl-active-time">${_tlFormat(current.offsetMin)}</span>
        ${tierBadge}
      </div>
      <div class="tl-active-title">${current.title}</div>
      <div class="tl-active-mitre">${current.mitre}</div>
      <div class="tl-active-narrative">${current.narrative}</div>
    </div>`;

  // Row-style timeline list (one row per event)
  const rows = steps.map((s, i) => {
    const cls = [
      'tl-row',
      i === _tlIndex ? 'active' : '',
      i < _tlIndex ? 'past' : '',
      s.tier === 'predicted' ? 'predicted' : ''
    ].filter(Boolean).join(' ');
    const marker = s.tier === 'predicted'
      ? '⏱'
      : (i < _tlIndex ? '✓' : i === _tlIndex ? '▶' : '•');
    return `
      <button class="${cls}" onclick="timelineJump(${i})" data-idx="${i}">
        <span class="tl-row-marker">${marker}</span>
        <span class="tl-row-body">
          <span class="tl-row-time">${_tlFormat(s.offsetMin)}</span>
          <span class="tl-row-title">${s.title}</span>
          <span class="tl-row-mitre">${s.mitre}</span>
        </span>
      </button>`;
  }).join('');

  body.innerHTML = `
    ${controls}
    ${activeCard}
    <div class="tl-section-label">Timeline · ${total} event${total === 1 ? '' : 's'}</div>
    <div class="tl-rows">${rows}</div>
  `;

  // scroll the active row into view inside the slider body
  const activeRow = body.querySelector('.tl-row.active');
  if (activeRow && typeof activeRow.scrollIntoView === 'function') {
    activeRow.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  _tlApplyHighlight(current);
}

function _tlApplyHighlight(step) {
  const entitySet = new Set(step.entities || []);
  const edgeKeys = new Set((step.edges || []).map(e => e[0] + '→' + e[1]));

  document.querySelectorAll('.graph-node').forEach(n => {
    const id = n.getAttribute('data-entity');
    if (entitySet.has(id)) {
      n.style.opacity = '1';
      n.classList.add('active-focus');
      n.classList.add('tl-pulse');
    } else {
      n.style.opacity = '0.18';
      n.classList.remove('active-focus');
      n.classList.remove('tl-pulse');
    }
  });
  document.querySelectorAll('line[data-source]').forEach(line => {
    const ls = line.getAttribute('data-source');
    const lt = line.getAttribute('data-target');
    const k = ls + '→' + lt;
    if (edgeKeys.has(k)) {
      line.style.opacity = '1';
      line.style.strokeWidth = '3';
    } else {
      line.style.opacity = '0.08';
      line.style.strokeWidth = '';
    }
  });
  document.querySelectorAll('.edge-info-btn').forEach(btn => {
    const bs = btn.getAttribute('data-source');
    const bt = btn.getAttribute('data-target');
    const k = bs + '→' + bt;
    btn.style.opacity = edgeKeys.has(k) ? '1' : '0.1';
  });
}
