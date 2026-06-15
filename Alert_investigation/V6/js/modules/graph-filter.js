/* graph-filter.js — Entity type filter, chip menus, pill popups, section toggles
 * Depends on: entities.js, display-config.js, entity-slider.js, utils.js */
function toggleGraphChipMenu(menuId, chipEl) {
  const menu = document.getElementById(menuId);
  const isOpen = menu.classList.contains('show');
  // Close all chip menus first
  document.querySelectorAll('.gcb-menu.show').forEach(m => { m.classList.remove('show'); m.style.top=''; m.style.left=''; });
  document.querySelectorAll('.gcb-chip.open').forEach(c => c.classList.remove('open'));
  // Also close any open pill popup so the menus don't overlap
  if (typeof closeCmdPillPopup === 'function') closeCmdPillPopup();
  if (!isOpen) {
    // Position with fixed coords directly below the chip (escapes overflow:hidden ancestors)
    const rect = chipEl.getBoundingClientRect();
    menu.style.left = rect.left + 'px';
    menu.style.top = (rect.bottom + 1) + 'px';
    menu.classList.add('show');
    chipEl.classList.add('open');
  }
}

function closeAllChipMenus() {
  document.querySelectorAll('.gcb-menu.show').forEach(m => m.classList.remove('show'));
  document.querySelectorAll('.gcb-chip.open').forEach(c => c.classList.remove('open'));
}

function pickEntityChip(optionEl, val, label) {
  // Update active state
  optionEl.closest('.gcb-menu').querySelectorAll('.gcb-option').forEach(o => o.classList.remove('active'));
  optionEl.classList.add('active');
  document.getElementById('entityChipLabel').textContent = label;
  closeAllChipMenus();
  legendFilter(val);
}

/* ─── Investigation time window ─────────────────────────────────────
 * The window is anchored on the alert TRIGGER time (not "now"), so the
 * analyst can pull events both BEFORE the trigger (the lead-up: recon,
 * initial access) and AFTER it (what the attacker did once the alert
 * fired: lateral movement, exfil, persistence). Two independent
 * dropdowns drive a From → To range shown to the right.            */
let _twBeforeHrs = 1;        // hours before the trigger
let _twAfterHrs  = 1;        // hours after the trigger; null => "Until now"

/* Parse the current alert's trigger timestamp (e.g. "11 May 2026, 10:04:00"). */
function _twTriggerDate() {
  let raw = null;
  try {
    const d = (typeof currentAlertId !== 'undefined' && typeof ALERT_DETAIL !== 'undefined')
      ? ALERT_DETAIL[currentAlertId] : null;
    raw = d && (d.createdTime || d.timeGenerated);
  } catch (e) {}
  const t = raw ? Date.parse(String(raw).replace(',', '')) : NaN;
  return isNaN(t) ? new Date('2026-05-11T10:04:00') : new Date(t);
}

function _twFmtTime(d) {
  return d.toTimeString().slice(0, 8); // HH:MM:SS
}
function _twFmtFull(d) {
  return d.toLocaleString('en-GB', { day:'2-digit', month:'short', year:'numeric',
    hour:'2-digit', minute:'2-digit', second:'2-digit' });
}

/* Recompute the investigation window from the trigger anchor + dropdown
 * picks and paint the trigger pill with the full date & time. */
function refreshTimeWindow() {
  const trigger = _twTriggerDate();

  const trigEl = document.getElementById('twTriggerTime');
  if (trigEl) {
    trigEl.textContent = _twFmtFull(trigger);
    const pill = document.getElementById('twTriggerPill');
    if (pill) pill.title = 'Alert trigger time (anchor) · ' + _twFmtFull(trigger);
  }
}

/* The "Analyze" button only appears once the user changes the window; it
 * disappears again after the (re-)analysis runs. */
function _twShowAnalyze() {
  const btn = document.getElementById('twAnalyzeBtn');
  if (btn && !btn.classList.contains('loading')) btn.style.display = '';
}

function analyzeTimeWindow() {
  const btn = document.getElementById('twAnalyzeBtn');
  if (!btn || btn.disabled) return;
  const canvas = document.getElementById('graphCanvas');
  if (!canvas) return;

  // Hide the button and show a loader over the graph while it "re-pulls".
  btn.disabled = true;
  btn.style.display = 'none';

  let overlay = document.getElementById('graphLoadOverlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'graphLoadOverlay';
    overlay.className = 'graph-load-overlay';
    overlay.innerHTML = '<div class="graph-load-spin"></div>' +
      '<div class="graph-load-text">Loading investigation window…</div>';
    canvas.appendChild(overlay);
  }
  overlay.classList.add('show');

  setTimeout(() => {
    overlay.classList.remove('show');
    btn.disabled = false;
    const beforeL = (document.getElementById('beforeChipLabel') || {}).textContent;
    const afterL  = (document.getElementById('afterChipLabel') || {}).textContent;
    showToast('⏱', 'Window analyzed: ' + beforeL + ' before → ' +
      (_twAfterHrs === null ? 'now' : afterL + ' after') + ' trigger');
  }, 1200);
}

function pickBeforeChip(optionEl, label, hrs) {
  optionEl.closest('.gcb-menu').querySelectorAll('.gcb-option').forEach(o => o.classList.remove('active'));
  optionEl.classList.add('active');
  document.getElementById('beforeChipLabel').textContent = label;
  _twBeforeHrs = hrs;
  closeAllChipMenus();
  refreshTimeWindow();
  _twShowAnalyze();
}

function pickAfterChip(optionEl, label, hrs) {
  optionEl.closest('.gcb-menu').querySelectorAll('.gcb-option').forEach(o => o.classList.remove('active'));
  optionEl.classList.add('active');
  document.getElementById('afterChipLabel').textContent = label;
  _twAfterHrs = hrs;
  closeAllChipMenus();
  refreshTimeWindow();
  _twShowAnalyze();
}

// Close chip menus when clicking outside
document.addEventListener('click', e => {
  if (!e.target.closest('.gcb-chip') && !e.target.closest('.gcb-menu')) {
    closeAllChipMenus();
  }
});

/* Entity type filter — highlight nodes of a specific type.
 * The 7 buckets here mirror the entity-chip dropdown in graph.js initGraphChips
 * and the per-log-type mapping in V6/device_and_other_entity_spec.md:
 *   host    = type=device                              (Device slider)
 *   ip      = type=ip
 *   domain  = type=domain
 *   user    = type=user
 *   file    = type=file
 *   process = type=process; also type=service when the service is an OS-level
 *             service (WinUpdateSvc, wuauserv, sshd, ...). Services folded in.
 *   other   = type=service when it's a SaaS-tenant style node (SharePoint
 *             Online, Azure AD, OAuth Token, M365, AWS, ...), plus anything
 *             else (incl. type=outline, hash, url, email, mailbox, token).
 *             Matches the Other slider in device_and_other_entity_spec.md §2.2.
 * The alert node is the centre of the graph and is intentionally NOT a bucket.
 */
let activeLegendType = 'all';
// SaaS-service id pattern: any 'service'-typed node whose id matches this is
// a tenant / cloud-app / token — it belongs in Other, not Process.
const SAAS_SVC_RE = /^svc-(azure|aad|sharepoint|exchange|m365|o365|onedrive|teams|salesforce|aws|gcp|okta|oauth|slack|saas)/i;
function classifyEntityBucket(eid, ent) {
  const t = ent && ent.type;
  if (t === 'device'  || eid.startsWith('dev-'))    return 'host';
  if (t === 'ip'      || eid.startsWith('ip-'))     return 'ip';
  if (t === 'domain'  || eid.startsWith('domain-')) return 'domain';
  if (t === 'user'    || eid.startsWith('user-'))   return 'user';
  if (t === 'file'    || eid.startsWith('file-'))   return 'file';
  if (t === 'process' || eid.startsWith('proc-'))   return 'process';
  if (t === 'service' || eid.startsWith('svc-')) {
    // Split: SaaS services / tokens → Other; OS-level services → Process.
    return SAAS_SVC_RE.test(eid) ? 'other' : 'process';
  }
  if (t === 'alert'   || eid.startsWith('alert-'))  return 'alert';
  return 'other';
}
function legendFilter(type) {
  activeLegendType = type;
  // Sync the chip label
  const chipLabel = document.getElementById('entityChipLabel');
  const labels = {
    all:'All Entities', host:'Hosts', ip:'IP Addresses', domain:'Domains',
    user:'Users', file:'Files', process:'Processes', other:'Others'
  };
  if (chipLabel) chipLabel.textContent = labels[type] || type;

  const allNodes = document.querySelectorAll('#graphSvg g.graph-node');

  if (type === 'all') {
    allNodes.forEach(n => { n.style.opacity = '1'; n.style.pointerEvents = 'auto'; });
    document.querySelectorAll('#graphSvg > line').forEach(el => { el.style.opacity = ''; });
    // Restore edge info buttons
    const svg = document.getElementById('graphSvg');
    if (svg) {
      svg.querySelectorAll('.edge-info-btn').forEach(btn => { btn.style.opacity = ''; });
    }
    if (document.getElementById('graphContainer')?.classList.contains('slider-open')) closeEntitySlider();
    showToast('🔍', 'Showing all entities');
    return;
  }

  // Determine which nodes match the selected bucket
  const matchingIds = new Set();
  allNodes.forEach(n => {
    const eid = n.getAttribute('data-entity') || '';
    const ent = (typeof ENTITIES !== 'undefined') ? ENTITIES[eid] : null;
    if (classifyEntityBucket(eid, ent) === type) matchingIds.add(eid);
  });

  // Build a lookup from circle position -> entity id
  const posMap = []; // [{eid, cx, cy}]
  allNodes.forEach(n => {
    const eid = n.getAttribute('data-entity');
    const c = n.querySelector('circle:not(.expand-indicator)');
    if (c) posMap.push({ eid, cx: parseFloat(c.getAttribute('cx')), cy: parseFloat(c.getAttribute('cy')) });
  });

  // Find connected neighbors using data-source / data-target attributes
  const connectedIds = new Set(matchingIds);
  const svgLines = document.querySelectorAll('#graphSvg > line');
  svgLines.forEach(line => {
    const src = line.getAttribute('data-source');
    const tgt = line.getAttribute('data-target');
    if (src && tgt) {
      if (matchingIds.has(src) && !matchingIds.has(tgt)) connectedIds.add(tgt);
      if (matchingIds.has(tgt) && !matchingIds.has(src)) connectedIds.add(src);
    }
  });

  // Apply opacity to nodes
  allNodes.forEach(n => {
    const eid = n.getAttribute('data-entity');
    if (matchingIds.has(eid)) { n.style.opacity = '1'; n.style.pointerEvents = 'auto'; }
    else if (connectedIds.has(eid)) { n.style.opacity = '0.4'; n.style.pointerEvents = 'auto'; }
    else { n.style.opacity = '0.08'; n.style.pointerEvents = 'none'; }
  });

  // Apply opacity to edges using data-source / data-target
  svgLines.forEach(line => {
    const src = line.getAttribute('data-source');
    const tgt = line.getAttribute('data-target');
    const touchesMatch = matchingIds.has(src) || matchingIds.has(tgt);
    line.style.opacity = touchesMatch ? '0.8' : '0.05';
  });

  // Edge info buttons — show buttons for edges touching matched entities
  const svg = document.getElementById('graphSvg');
  if (svg) {
    svg.querySelectorAll('.edge-info-btn').forEach(btn => {
      const src = btn.getAttribute('data-source');
      const tgt = btn.getAttribute('data-target');
      const touches = (src && matchingIds.has(src)) || (tgt && matchingIds.has(tgt));
      btn.style.opacity = touches ? '1' : '0.08';
    });
  }

  if (document.getElementById('graphContainer')?.classList.contains('slider-open')) closeEntitySlider();
  const count = matchingIds.size;
  const typeLabel = type.charAt(0).toUpperCase() + type.slice(1) + (count !== 1 ? 's' : '');
  showToast('🔍', `Showing ${count} ${typeLabel} and their connections`);
}

/* ── Impact Assessment row toggle ────────────────────────────── */
function toggleImpactRow(id) {
  const el = document.getElementById(id);
  const chev = document.getElementById(id + '-chev');
  if (!el) return;
  if (el.style.display === 'none') {
    el.style.display = 'block';
    if (chev) chev.textContent = '▾';
  } else {
    el.style.display = 'none';
    if (chev) chev.textContent = '▸';
  }
}

/* ── Attack section heading toggle (Kill Chain, Impact, etc.) ── */
function toggleAttackSection(bodyId, chevId) {
  const body = document.getElementById(bodyId);
  const chev = document.getElementById(chevId);
  if (!body) return;
  if (body.style.display === 'none') {
    body.style.display = 'block';
    if (chev) chev.textContent = '▾';
  } else {
    body.style.display = 'none';
    if (chev) chev.textContent = '▸';
  }
}

/* ── New .atk-section collapse toggle ── */
function toggleAtkSection(sectionId) {
  const sec = document.getElementById(sectionId);
  if (!sec) return;
  sec.classList.toggle('collapsed');
}

function toggleGraphSummary() {
  const f = document.getElementById('graphFindings');
  const caret = document.getElementById('findingsCaret');
  if (f.style.display === 'none') {
    f.style.display = 'flex';
    if (caret) caret.textContent = '▴';
  } else {
    f.style.display = 'none';
    if (caret) caret.textContent = '▾';
  }
}

/* ── Pill Detail Popups (Malicious / Critical) ──────────────── */
/* ENTITY_DISPLAY and CRITICAL_REASONS are defined in js/data/display-config.js */

let activePillPopup = null;
let threatPopupSearchTerm = '';

function getEntityChip(entityId) {
  const d = ENTITY_DISPLAY[entityId] || { icon:'●', name:entityId, color:'#555', bg:'#f5f7fa' };
  return `<span class="cpp-entity-chip" style="border-color:${d.color}20;background:${d.bg};">
    <span class="cpp-entity-icon">${d.icon}</span>
    <span style="color:${d.color};">${d.name}</span>
  </span>`;
}

function buildMaliciousPopup(searchTerm = '', includeHeader = true) {
  const edges = Array.from(document.querySelectorAll('#graphSvg line.graph-edge-mal'))
    .filter(e => e.style.display !== 'none');
  const q = (searchTerm || '').toLowerCase();
  let items = '';
  edges.forEach(e => {
    const src = e.getAttribute('data-source');
    const tgt = e.getAttribute('data-target');
    const lbl = e.getAttribute('data-label') || '';
    if (!src || !tgt) return;
    const srcName = (ENTITY_DISPLAY[src] || {}).name || src;
    const tgtName = (ENTITY_DISPLAY[tgt] || {}).name || tgt;
    const haystack = `${srcName} ${tgtName} ${lbl}`.toLowerCase();
    if (q && !haystack.includes(q)) return;
    items += `<div class="cpp-item" onclick="openEntitySlider('${tgt}');closeCmdPillPopup();" title="Click to investigate ${(ENTITY_DISPLAY[tgt]||{}).name||tgt}">
      <div class="cpp-edge-row">
        ${getEntityChip(src)}
        <span class="cpp-arrow">→</span>
        ${getEntityChip(tgt)}
      </div>
      <div class="cpp-edge-label">${lbl}</div>
      <div class="cpp-action-hint">Click to investigate →</div>
    </div>`;
  });
  const emptyMsg = q
    ? 'No malicious connections match your search'
    : 'No malicious connections detected';
  const body = items || `<div style="padding:12px;color:#8a94a6;font-size:11px;">${emptyMsg}</div>`;
  if (!includeHeader) return body;
  return `<div class="cpp-header"><span class="cpp-header-icon">🔴</span> Malicious Connections</div>${body}`;
}

function buildCriticalPopup(searchTerm = '', includeHeader = true) {
  const nodes = Array.from(document.querySelectorAll('#graphSvg g.graph-node'))
    .filter(n => n.style.display !== 'none');
  const q = (searchTerm || '').toLowerCase();
  let items = '';
  nodes.forEach(n => {
    const circle = n.querySelector('circle:not(.expand-indicator)');
    const isCrit = circle && (circle.getAttribute('filter') || '').includes('glow-r');
    if (!isCrit) return;
    const eid = n.getAttribute('data-entity');
    const d = ENTITY_DISPLAY[eid] || { icon:'●', name:eid, color:'#ef4444', bg:'#fef2f2' };
    const reason = CRITICAL_REASONS[eid] || 'High-risk entity requiring immediate attention';
    const haystack = `${d.name} ${reason} ${eid}`.toLowerCase();
    if (q && !haystack.includes(q)) return;
    items += `<div class="cpp-item" onclick="openEntitySlider('${eid}');closeCmdPillPopup();" title="Click to investigate ${d.name}">
      <div class="cpp-entity-row">
        <span class="cpp-entity-badge" style="background:${d.bg};border:2px solid ${d.color};">${d.icon}</span>
        <span style="color:${d.color};">${d.name}</span>
      </div>
      <div class="cpp-reason">${reason}</div>
      <div class="cpp-action-hint">Click to investigate →</div>
    </div>`;
  });
  const emptyMsg = q
    ? 'No critical entities match your search'
    : 'No critical entities detected';
  const body = items || `<div style="padding:12px;color:#8a94a6;font-size:11px;">${emptyMsg}</div>`;
  if (!includeHeader) return body;
  return `<div class="cpp-header"><span class="cpp-header-icon">🟡</span> Critical Entities</div>${body}`;
}

function buildThreatIndicatorsPopup(searchTerm = '') {
  const q = (searchTerm || '').replace(/"/g, '&quot;');
  return `
    <div class="cpp-ti-title"><span class="cpp-header-icon">📈</span> Threat Indicators</div>
    <div class="cpp-ti-search-wrap">
      <input
        id="cppThreatSearch"
        class="cpp-ti-search"
        type="text"
        placeholder="Search"
        value="${q}"
        oninput="filterThreatIndicatorsPopup(this.value)"
      />
    </div>
    <div class="cpp-ti-section">
      <button class="cpp-ti-section-hdr" onclick="toggleThreatIndicatorSection('cppThreatMalBody', this)">
        <span class="cpp-ti-chev">▾</span>
        <span>Malicious Connections</span>
      </button>
      <div class="cpp-ti-section-body" id="cppThreatMalBody">${buildMaliciousPopup(searchTerm, false)}</div>
    </div>
    <div class="cpp-ti-section">
      <button class="cpp-ti-section-hdr" onclick="toggleThreatIndicatorSection('cppThreatCritBody', this)">
        <span class="cpp-ti-chev">▾</span>
        <span>Critical Entities</span>
      </button>
      <div class="cpp-ti-section-body" id="cppThreatCritBody">${buildCriticalPopup(searchTerm, false)}</div>
    </div>`;
}

function filterThreatIndicatorsPopup(value) {
  threatPopupSearchTerm = (value || '').trim();
  const malBody = document.getElementById('cppThreatMalBody');
  const critBody = document.getElementById('cppThreatCritBody');
  if (malBody) malBody.innerHTML = buildMaliciousPopup(threatPopupSearchTerm, false);
  if (critBody) critBody.innerHTML = buildCriticalPopup(threatPopupSearchTerm, false);
}

function toggleThreatIndicatorSection(bodyId, btn) {
  const body = document.getElementById(bodyId);
  if (!body) return;
  const collapsed = body.style.display === 'none';
  body.style.display = collapsed ? 'block' : 'none';
  if (btn) {
    const chev = btn.querySelector('.cpp-ti-chev');
    if (chev) chev.textContent = collapsed ? '▾' : '▸';
  }
}

function toggleCmdPillPopup(event, type) {
  event.stopPropagation();
  const popup = document.getElementById('cmdPillPopup');
  if (!popup) return;

  // Close any open chip dropdowns so popups don't overlap them
  if (typeof closeAllChipMenus === 'function') closeAllChipMenus();

  // If same type already open, close
  if (popup.classList.contains('active') && activePillPopup === type) {
    closeCmdPillPopup();
    return;
  }

  // Build content
  popup.innerHTML = type === 'threatIndicators'
    ? buildThreatIndicatorsPopup(threatPopupSearchTerm)
    : (type === 'malicious' ? buildMaliciousPopup() : buildCriticalPopup());

  // Position below the clicked pill (fixed positioning)
  const pill = event.currentTarget;
  const pillRect = pill.getBoundingClientRect();
  popup.style.left = pillRect.left + 'px';
  popup.style.top = (pillRect.bottom + 4) + 'px';

  popup.classList.add('active');
  activePillPopup = type;

  if (type === 'threatIndicators') {
    const searchEl = document.getElementById('cppThreatSearch');
    if (searchEl) {
      searchEl.focus();
      const len = searchEl.value.length;
      searchEl.setSelectionRange(len, len);
    }
  }

  // Close when clicking outside
  setTimeout(() => {
    document.addEventListener('click', closeCmdPillPopupOutside, { once: true });
  }, 10);
}

function closeCmdPillPopup() {
  const popup = document.getElementById('cmdPillPopup');
  if (popup) popup.classList.remove('active');
  activePillPopup = null;
}

function closeCmdPillPopupOutside(e) {
  const popup = document.getElementById('cmdPillPopup');
  if (popup && !popup.contains(e.target) && !e.target.closest('.cmd-pill-clickable')) {
    closeCmdPillPopup();
  }
}

