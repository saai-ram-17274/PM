/* graph-filter.js — Entity type filter, chip menus, pill popups, section toggles
 * Depends on: entities.js, display-config.js, entity-slider.js, utils.js */
function toggleGraphChipMenu(menuId, chipEl) {
  const menu = document.getElementById(menuId);
  const isOpen = menu.classList.contains('show');
  // Close all chip menus first
  document.querySelectorAll('.gcb-menu.show').forEach(m => m.classList.remove('show'));
  document.querySelectorAll('.gcb-chip.open').forEach(c => c.classList.remove('open'));
  if (!isOpen) {
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
  const labels = { all:'All Entities', user:'Users', device:'Devices', ip:'IPs', service:'Services', process:'Processes', alert:'Alerts' };
  if (chipLabel) chipLabel.textContent = labels[type] || type;

  const allNodes = document.querySelectorAll('#graphSvg g.graph-node');

  if (type === 'all') {
    allNodes.forEach(n => { n.style.opacity = '1'; n.style.pointerEvents = 'auto'; });
    document.querySelectorAll('#graphSvg > line').forEach(el => { el.style.opacity = ''; });
    // Restore edge labels (direct text children of SVG)
    const svg = document.getElementById('graphSvg');
    if (svg) {
      Array.from(svg.children).forEach(child => {
        if (child.tagName === 'text') child.style.opacity = '';
      });
    }
    closeEntitySlider();
    showToast('🔍', 'Showing all entities');
    return;
  }

  // Map entity ID prefixes to types
  const typeMap = {
    'alert': ['alert-'],
    'user': ['user-'],
    'device': ['dev-'],
    'ip': ['ip-'],
    'service': ['svc-'],
    'process': ['proc-']
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

  // Find connected neighbors
  const connectedIds = new Set(matchingIds);
  const svgLines = document.querySelectorAll('#graphSvg > line');
  svgLines.forEach(line => {
    const x1 = parseFloat(line.getAttribute('x1')), y1 = parseFloat(line.getAttribute('y1'));
    const x2 = parseFloat(line.getAttribute('x2')), y2 = parseFloat(line.getAttribute('y2'));
    let end1 = null, end2 = null;
    for (const p of posMap) {
      if (Math.abs(x1 - p.cx) < 30 && Math.abs(y1 - p.cy) < 30) end1 = p.eid;
      if (Math.abs(x2 - p.cx) < 30 && Math.abs(y2 - p.cy) < 30) end2 = p.eid;
    }
    if (end1 && end2) {
      if (matchingIds.has(end1) && !matchingIds.has(end2)) connectedIds.add(end2);
      if (matchingIds.has(end2) && !matchingIds.has(end1)) connectedIds.add(end1);
    }
  });

  // Apply opacity to nodes
  allNodes.forEach(n => {
    const eid = n.getAttribute('data-entity');
    if (matchingIds.has(eid)) { n.style.opacity = '1'; n.style.pointerEvents = 'auto'; }
    else if (connectedIds.has(eid)) { n.style.opacity = '0.4'; n.style.pointerEvents = 'auto'; }
    else { n.style.opacity = '0.08'; n.style.pointerEvents = 'none'; }
  });

  // Apply opacity to edges
  svgLines.forEach(line => {
    const x1 = parseFloat(line.getAttribute('x1')), y1 = parseFloat(line.getAttribute('y1'));
    const x2 = parseFloat(line.getAttribute('x2')), y2 = parseFloat(line.getAttribute('y2'));
    let touchesMatch = false;
    for (const p of posMap) {
      if (!matchingIds.has(p.eid)) continue;
      if ((Math.abs(x1 - p.cx) < 30 && Math.abs(y1 - p.cy) < 30) ||
          (Math.abs(x2 - p.cx) < 30 && Math.abs(y2 - p.cy) < 30)) { touchesMatch = true; break; }
    }
    line.style.opacity = touchesMatch ? '0.8' : '0.05';
  });

  // Edge labels (direct SVG children only)
  const svg = document.getElementById('graphSvg');
  if (svg) {
    Array.from(svg.children).forEach(child => {
      if (child.tagName === 'text') child.style.opacity = '0.08';
    });
  }

  closeEntitySlider();
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
const ENTITY_DISPLAY = {
  'alert-impossible-travel': { icon:'⚠', name:'Impossible Travel', color:'#ef4444', bg:'#fef2f2' },
  'user-m-henderson':        { icon:'👤', name:'m.henderson', color:'#7c3aed', bg:'#f5f0ff' },
  'svc-azure-ad':            { icon:'⚙', name:'Azure AD Portal', color:'#0891b2', bg:'#ecfeff' },
  'ip-tor':                  { icon:'◆', name:'185.220.101.42', color:'#ef4444', bg:'#fef2f2' },
  'ip-internal':             { icon:'◆', name:'10.18.1.81', color:'#16a34a', bg:'#f0fdf4' },
  'dev-ws045':               { icon:'🖥', name:'CORP-WS-045', color:'#dc2626', bg:'#fef2f2' },
  'svc-sharepoint':          { icon:'📁', name:'SharePoint', color:'#ea580c', bg:'#fff7ed' },
  'proc-oauth':              { icon:'🔑', name:'OAuth Tokens (3)', color:'#d97706', bg:'#fffbeb' },
  'user-admin':              { icon:'👤', name:'Administrator', color:'#0891b2', bg:'#ecfeff' },
  'proc-powershell':         { icon:'⚙', name:'PowerShell.exe', color:'#d97706', bg:'#fffbeb' },
  'svc-winupdatesvc':        { icon:'⚙', name:'WinUpdateSvc', color:'#ea580c', bg:'#fff7ed' },
  'alert-arp-spoofing-1':    { icon:'🔔', name:'ARP Spoofing (14:43)', color:'#ef4444', bg:'#fef2f2' },
  'alert-arp-spoofing-2':    { icon:'🔔', name:'ARP Spoofing (14:41)', color:'#ef4444', bg:'#fef2f2' },
  'proc-cmd':                { icon:'⚙', name:'cmd.exe', color:'#d97706', bg:'#fffbeb' },
  'proc-outlook':            { icon:'⚙', name:'outlook.exe', color:'#16a34a', bg:'#f0fdf4' },
  'svc-wuauserv':            { icon:'⚙', name:'wuauserv', color:'#d97706', bg:'#fffbeb' },
  'svc-spooler':             { icon:'⚙', name:'Spooler', color:'#16a34a', bg:'#f0fdf4' }
};

const CRITICAL_REASONS = {
  'alert-impossible-travel': 'Critical severity alert · UEBA Engine triggered · Confidence 92%',
  'ip-tor': 'Known Tor exit node · AbuseIPDB confidence 100% · 5 threat feeds flagged',
  'user-m-henderson': 'UEBA Risk Score 94/100 · Compromised account',
  'proc-oauth': 'Unregistered app tokens · Issued post-compromise',
  'svc-sharepoint': '24 files exfiltrated in 3 min from /Finance/Sensitive',
  'proc-powershell': 'Encoded command execution · AMSI detections · C2 communication',
  'svc-winupdatesvc': 'Masquerading service · Unsigned binary · C2 beacon active'
};

let activePillPopup = null;

function getEntityChip(entityId) {
  const d = ENTITY_DISPLAY[entityId] || { icon:'●', name:entityId, color:'#555', bg:'#f5f7fa' };
  return `<span class="cpp-entity-chip" style="border-color:${d.color}20;background:${d.bg};">
    <span class="cpp-entity-icon">${d.icon}</span>
    <span style="color:${d.color};">${d.name}</span>
  </span>`;
}

function buildMaliciousPopup() {
  const edges = document.querySelectorAll('#graphSvg line.graph-edge-mal');
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
  const nodes = document.querySelectorAll('#graphSvg g.graph-node');
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

