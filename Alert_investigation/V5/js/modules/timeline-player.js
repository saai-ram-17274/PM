/* ────────────────────────────────────────────────────────────────────────
 * timeline-player.js — Attack Timeline Replay
 *
 * Chronological playback of the attack's kill-chain over the existing
 * attack-vector graph. Mounts a bottom slider with prev/next controls;
 * each step highlights the responsible nodes + edges and dims the rest,
 * with a narrative card describing what happened and the MITRE tactic.
 *
 * Final step(s) are tagged as PREDICTED — these correspond to the amber
 * predicted entities (LSASS Dump, DC-01) and use the amber accent.
 *
 * Public API:
 *   openTimelinePlayer()   — open the slider (called from "▶ Replay" chip)
 *   closeTimelinePlayer()  — restore graph & remove slider
 *   timelineNext() / timelinePrev() / timelineJump(i)
 *   timelinePlayPause()    — toggle auto-advance
 * ──────────────────────────────────────────────────────────────────────── */

/* Steps are ordered chronologically. Each step lists the entities and
 * directed edges (source→target) to bring to full opacity; everything
 * else is dimmed so the active step pops. */
const TIMELINE_STEPS = [
  {
    time: 'T+00:00',
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
    time: 'T+00:02',
    tier: 'observed',
    title: 'Foreign sign-in from Tor exit node',
    narrative: 'The Romanian login originates from 185.220.101.42 — a well-known Tor exit node tagged by threat intelligence as actively involved in credential-stuffing campaigns.',
    mitre: 'T1078.004 · Valid Accounts: Cloud',
    entities: ['user-m-henderson', 'ip-tor'],
    edges: [['user-m-henderson', 'ip-tor']]
  },
  {
    time: 'T+00:05',
    tier: 'observed',
    title: 'Tor node beacons to C2 infrastructure',
    narrative: 'Firewall logs show 185.220.101.42 establishing outbound HTTPS to c2-update.darkoperator.net — a domain registered 3 days ago and previously linked to FIN-class actors.',
    mitre: 'TA0011 · Command & Control',
    entities: ['ip-tor', 'domain-c2'],
    edges: [['ip-tor', 'domain-c2']]
  },
  {
    time: 'T+00:08',
    tier: 'observed',
    title: 'Inbound contact to internal workstation',
    narrative: 'CORP-WS-045 receives an inbound SMB session from the Tor exit — an unusual reverse-direction connection that suggests a tunneled remote shell.',
    mitre: 'T1021 · Remote Services',
    entities: ['ip-tor', 'dev-ws045'],
    edges: [['ip-tor', 'dev-ws045']]
  },
  {
    time: 'T+00:12',
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
    time: 'T+00:18',
    tier: 'observed',
    title: 'Workstation beacons to C2',
    narrative: 'CORP-WS-045 establishes its own outbound channel to c2-update.darkoperator.net — confirming foothold and enabling subsequent hands-on-keyboard activity.',
    mitre: 'T1071.001 · Application Layer Protocol: Web',
    entities: ['dev-ws045', 'domain-c2'],
    edges: [['dev-ws045', 'domain-c2']]
  },
  {
    time: 'T+00:24',
    tier: 'observed',
    title: 'Privilege escalation to Administrator',
    narrative: 'A local privilege-escalation primitive on CORP-WS-045 results in the attacker obtaining a process token impersonating the built-in Administrator account.',
    mitre: 'T1068 · Exploitation for Privilege Escalation',
    entities: ['dev-ws045', 'user-admin'],
    edges: [['dev-ws045', 'user-admin']]
  },
  {
    time: 'T+00:31',
    tier: 'observed',
    title: 'Administrator authenticates to Azure AD',
    narrative: 'The newly-obtained Administrator credentials are exercised against Azure AD — likely to enumerate available cloud apps and OAuth scopes before exfiltration.',
    mitre: 'T1078.004 · Valid Accounts: Cloud',
    entities: ['user-admin', 'svc-azure-ad'],
    edges: [['user-admin', 'svc-azure-ad']]
  },
  {
    time: 'T+00:36',
    tier: 'observed',
    title: 'OAuth tokens issued',
    narrative: 'Azure AD issues 3 refresh tokens covering Files.ReadWrite.All and Sites.Read.All — providing durable, MFA-bypassing access to SharePoint Online.',
    mitre: 'T1528 · Steal Application Access Token',
    entities: ['svc-azure-ad', 'svc-oauth'],
    edges: [['svc-azure-ad', 'svc-oauth']]
  },
  {
    time: 'T+00:42',
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
    time: 'T+00:48',
    tier: 'predicted',
    title: '[Predicted] LSASS credential dump on CORP-WS-045',
    narrative: 'AI projects the attacker will run procdump/comsvcs to extract cleartext credentials and Kerberos tickets from LSASS — converting the workstation foothold into reusable domain creds.',
    mitre: 'T1003.001 · OS Credential Dumping: LSASS Memory',
    entities: ['dev-ws045', 'proc-credump-predicted'],
    edges: [['dev-ws045', 'proc-credump-predicted']]
  },
  {
    time: 'T+00:55',
    tier: 'predicted',
    title: '[Predicted] Administrator pivots to DC-01',
    narrative: 'Using the freshly-dumped credentials, AI expects an RDP or SMB login from Administrator to the domain controller DC-01 within ~7 minutes — the canonical lateral-movement step before domain-wide impact.',
    mitre: 'T1021.002 · Remote Services: SMB / TA0008 · Lateral Movement',
    entities: ['user-admin', 'dev-dc01-predicted'],
    edges: [['user-admin', 'dev-dc01-predicted']]
  }
];

let _tlIndex = 0;
let _tlAutoTimer = null;
const _TL_AUTO_MS = 3500;

function openTimelinePlayer() {
  if (document.getElementById('tlPlayer')) {
    // already open — just bring to step 0
    _tlIndex = 0;
    _tlRender();
    return;
  }
  // close any open entity slider so the bottom panel has room
  if (typeof closeEntitySlider === 'function') {
    try { closeEntitySlider(); } catch (e) { /* noop */ }
  }
  const host = document.getElementById('graphCanvas') || document.getElementById('graphContainer') || document.body;
  const wrap = document.createElement('div');
  wrap.id = 'tlPlayer';
  wrap.className = 'tl-player';
  wrap.innerHTML = `
    <div class="tl-player-header">
      <div class="tl-player-title">
        <span class="tl-player-icon">▶</span>
        <span>Attack Timeline · Replay</span>
        <span class="tl-step-counter" id="tlStepCounter">1 / ${TIMELINE_STEPS.length}</span>
      </div>
      <div class="tl-player-actions">
        <button class="tl-btn tl-btn-ghost" id="tlPlayPauseBtn" onclick="timelinePlayPause()" title="Auto-play"><span id="tlPlayPauseIcon">▶</span> Play</button>
        <button class="tl-btn tl-btn-ghost" onclick="closeTimelinePlayer()" title="Close timeline">✕</button>
      </div>
    </div>
    <div class="tl-track" id="tlTrack"></div>
    <div class="tl-card" id="tlCard"></div>
    <div class="tl-player-footer">
      <button class="tl-btn" id="tlPrevBtn" onclick="timelinePrev()">◀ Previous</button>
      <div class="tl-mini-hint">Click any pip to jump · ESC to close</div>
      <button class="tl-btn tl-btn-primary" id="tlNextBtn" onclick="timelineNext()">Next ▶</button>
    </div>`;
  host.appendChild(wrap);
  const gc = document.getElementById('graphContainer');
  if (gc) gc.classList.add('av-replay-on');

  // build track pips
  const track = wrap.querySelector('#tlTrack');
  track.innerHTML = TIMELINE_STEPS.map((s, i) => {
    const cls = s.tier === 'predicted' ? 'tl-pip predicted' : 'tl-pip';
    return `<button class="${cls}" data-idx="${i}" onclick="timelineJump(${i})" title="${s.time} · ${s.title.replace(/"/g, '&quot;')}">
      <span class="tl-pip-dot"></span>
      <span class="tl-pip-time">${s.time}</span>
    </button>`;
  }).join('<span class="tl-pip-sep"></span>');

  _tlIndex = 0;
  _tlRender();

  // ESC to close
  document.addEventListener('keydown', _tlKeyHandler);
}

function closeTimelinePlayer() {
  _tlClearAuto();
  const wrap = document.getElementById('tlPlayer');
  if (wrap) wrap.remove();
  const gc = document.getElementById('graphContainer');
  if (gc) gc.classList.remove('av-replay-on');
  if (typeof restoreGraphHighlights === 'function') restoreGraphHighlights();
  document.removeEventListener('keydown', _tlKeyHandler);
}

function timelineNext() {
  if (_tlIndex < TIMELINE_STEPS.length - 1) {
    _tlIndex++;
    _tlRender();
  } else {
    _tlClearAuto();
  }
}

function timelinePrev() {
  if (_tlIndex > 0) {
    _tlIndex--;
    _tlRender();
  }
}

function timelineJump(i) {
  if (i < 0 || i >= TIMELINE_STEPS.length) return;
  _tlIndex = i;
  _tlRender();
}

function timelinePlayPause() {
  const icon = document.getElementById('tlPlayPauseIcon');
  const btn = document.getElementById('tlPlayPauseBtn');
  if (_tlAutoTimer) {
    _tlClearAuto();
    if (icon) icon.textContent = '▶';
    if (btn) btn.lastChild.textContent = ' Play';
  } else {
    if (icon) icon.textContent = '⏸';
    if (btn) btn.lastChild.textContent = ' Pause';
    _tlAutoTimer = setInterval(() => {
      if (_tlIndex >= TIMELINE_STEPS.length - 1) {
        _tlClearAuto();
        if (icon) icon.textContent = '▶';
        if (btn) btn.lastChild.textContent = ' Play';
        return;
      }
      _tlIndex++;
      _tlRender();
    }, _TL_AUTO_MS);
  }
}

function _tlClearAuto() {
  if (_tlAutoTimer) { clearInterval(_tlAutoTimer); _tlAutoTimer = null; }
}

function _tlKeyHandler(e) {
  if (!document.getElementById('tlPlayer')) return;
  if (e.key === 'Escape') { closeTimelinePlayer(); }
  else if (e.key === 'ArrowRight') { timelineNext(); }
  else if (e.key === 'ArrowLeft') { timelinePrev(); }
}

function _tlRender() {
  const step = TIMELINE_STEPS[_tlIndex];
  if (!step) return;
  // counter
  const counter = document.getElementById('tlStepCounter');
  if (counter) counter.textContent = `${_tlIndex + 1} / ${TIMELINE_STEPS.length}`;
  // pips
  document.querySelectorAll('#tlTrack .tl-pip').forEach(p => {
    const idx = parseInt(p.getAttribute('data-idx'), 10);
    p.classList.toggle('active', idx === _tlIndex);
    p.classList.toggle('past', idx < _tlIndex);
  });
  // prev/next disabled state
  const prevBtn = document.getElementById('tlPrevBtn');
  const nextBtn = document.getElementById('tlNextBtn');
  if (prevBtn) prevBtn.disabled = _tlIndex === 0;
  if (nextBtn) nextBtn.disabled = _tlIndex === TIMELINE_STEPS.length - 1;
  // card
  const tierBadge = step.tier === 'predicted'
    ? '<span class="tl-tier-badge predicted">⏱ PREDICTED</span>'
    : '<span class="tl-tier-badge observed">● OBSERVED</span>';
  const card = document.getElementById('tlCard');
  if (card) {
    card.className = 'tl-card' + (step.tier === 'predicted' ? ' predicted' : '');
    card.innerHTML = `
      <div class="tl-card-row">
        <span class="tl-card-time">${step.time}</span>
        ${tierBadge}
        <span class="tl-card-mitre">${step.mitre}</span>
      </div>
      <div class="tl-card-title">${step.title}</div>
      <div class="tl-card-narrative">${step.narrative}</div>`;
  }
  // apply graph focus
  _tlApplyHighlight(step);
}

function _tlApplyHighlight(step) {
  const entitySet = new Set(step.entities || []);
  const edgeKeys = new Set((step.edges || []).map(e => e[0] + '→' + e[1]));

  // nodes
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
  // edges
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
  // edge-info buttons
  document.querySelectorAll('.edge-info-btn').forEach(btn => {
    const bs = btn.getAttribute('data-source');
    const bt = btn.getAttribute('data-target');
    const k = bs + '→' + bt;
    btn.style.opacity = edgeKeys.has(k) ? '1' : '0.1';
  });
}
