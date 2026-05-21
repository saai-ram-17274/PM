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

function pickTimeChip(optionEl, label) {
  optionEl.closest('.gcb-menu').querySelectorAll('.gcb-option').forEach(o => o.classList.remove('active'));
  optionEl.classList.add('active');
  document.getElementById('timeChipLabel').textContent = label;
  closeAllChipMenus();
  showToast('⏱', 'Time window: ' + label);
}

// Close chip menus when clicking outside
document.addEventListener('click', e => {
  if (!e.target.closest('.gcb-chip') && !e.target.closest('.gcb-menu')) {
    closeAllChipMenus();
  }
});

/* Entity type filter — highlight nodes of a specific type */
let activeLegendType = 'all';
function legendFilter(type) {
  activeLegendType = type;
  // Sync the chip label
  const chipLabel = document.getElementById('entityChipLabel');
  const labels = { all:'All Entities', user:'Users', asset:'Assets', ip:'IP Addresses', domain:'Domains', process:'File/Process', account:'Accounts', location:'Location', alert:'Alerts' };
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

  // Map entity ID prefixes to types
  const typeMap = {
    'alert': ['alert-'],
    'user': ['user-'],
    'asset': ['dev-'],
    'ip': ['ip-'],
    'account': ['svc-'],
    'domain': ['domain-'],
    'process': ['proc-'],
    'location': ['loc-']
  };
  const prefixes = typeMap[type] || [];

  // Determine which nodes match
  const matchingIds = new Set();
  allNodes.forEach(n => {
    const eid = n.getAttribute('data-entity');
    const entityData = ENTITIES[eid];
    const entityType = entityData ? entityData.type : null;
    const matches = entityType === type || prefixes.some(p => eid.startsWith(p));
    if (matches) matchingIds.add(eid);
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

function getEntityChip(entityId) {
  const d = ENTITY_DISPLAY[entityId] || { icon:'●', name:entityId, color:'#555', bg:'#f5f7fa' };
  return `<span class="cpp-entity-chip" style="border-color:${d.color}20;background:${d.bg};">
    <span class="cpp-entity-icon">${d.icon}</span>
    <span style="color:${d.color};">${d.name}</span>
  </span>`;
}

function buildMaliciousPopup() {
  const edges = Array.from(document.querySelectorAll('#graphSvg line.graph-edge-mal'))
    .filter(e => e.style.display !== 'none');
  let items = '';
  edges.forEach(e => {
    const src = e.getAttribute('data-source');
    const tgt = e.getAttribute('data-target');
    const lbl = e.getAttribute('data-label') || '';
    if (!src || !tgt) return;
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
  return `<div class="cpp-header"><span class="cpp-header-icon">🔴</span> Malicious Connections</div>${items || '<div style="padding:12px;color:#8a94a6;font-size:11px;">No malicious connections detected</div>'}`;
}

function buildCriticalPopup() {
  const nodes = Array.from(document.querySelectorAll('#graphSvg g.graph-node'))
    .filter(n => n.style.display !== 'none');
  let items = '';
  nodes.forEach(n => {
    const circle = n.querySelector('circle:not(.expand-indicator)');
    const isCrit = circle && (circle.getAttribute('filter') || '').includes('glow-r');
    if (!isCrit) return;
    const eid = n.getAttribute('data-entity');
    const d = ENTITY_DISPLAY[eid] || { icon:'●', name:eid, color:'#ef4444', bg:'#fef2f2' };
    const reason = CRITICAL_REASONS[eid] || 'High-risk entity requiring immediate attention';
    items += `<div class="cpp-item" onclick="openEntitySlider('${eid}');closeCmdPillPopup();" title="Click to investigate ${d.name}">
      <div class="cpp-entity-row">
        <span class="cpp-entity-badge" style="background:${d.bg};border:2px solid ${d.color};">${d.icon}</span>
        <span style="color:${d.color};">${d.name}</span>
      </div>
      <div class="cpp-reason">${reason}</div>
      <div class="cpp-action-hint">Click to investigate →</div>
    </div>`;
  });
  return `<div class="cpp-header"><span class="cpp-header-icon">🟡</span> Critical Entities</div>${items || '<div style="padding:12px;color:#8a94a6;font-size:11px;">No critical entities detected</div>'}`;
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
  popup.innerHTML = type === 'malicious' ? buildMaliciousPopup() : buildCriticalPopup();

  // Position below the clicked pill (fixed positioning)
  const pill = event.currentTarget;
  const pillRect = pill.getBoundingClientRect();
  popup.style.left = pillRect.left + 'px';
  popup.style.top = (pillRect.bottom + 4) + 'px';

  popup.classList.add('active');
  activePillPopup = type;

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

