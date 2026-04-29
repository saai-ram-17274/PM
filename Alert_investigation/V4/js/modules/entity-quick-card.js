/* entity-quick-card.js — Node click popup (Log360-native quick card)
 * Depends on: entities.js, display-config.js, entity-slider.js, utils.js */
let eqcVisible = false;

function showEntityQuickCard(entityId, evt) {
  const e = ENTITIES[entityId];
  if (!e) { openEntitySlider(entityId); return; }

  // If quick card already showing for same entity, open full slider
  const card = document.getElementById('eqcCard');
  if (eqcVisible && card.dataset.activeEntity === entityId) {
    hideEntityQuickCard();
    openEntitySlider(entityId);
    return;
  }

  // If slider is already open, just switch entity
  if (document.getElementById('graphContainer').classList.contains('slider-open')) {
    openEntitySlider(entityId);
    return;
  }

  const display = ENTITY_DISPLAY[entityId] || {};
  const typeLabels = { user:'User', device:'Host', ip:'IP Address', service:'Service', process:'Process', alert:'Alert' };
  const typeColors = { user:'#7c3aed', device:'#2563eb', ip:'#0891b2', service:'#0891b2', process:'#d97706', alert:'#ef4444' };
  const typeBgs = { user:'rgba(124,58,237,.2)', device:'rgba(37,99,235,.2)', ip:'rgba(8,145,178,.2)', service:'rgba(8,145,178,.2)', process:'rgba(217,119,6,.2)', alert:'rgba(239,68,68,.2)' };

  // Determine risk level from data
  let riskLevel = 'info', riskLabel = 'Info';
  if (e.sections.riskSummary?.summaryCard) {
    const sc = e.sections.riskSummary.summaryCard;
    const score = sc.score ?? sc.riskScore ?? 0;
    if (score >= 80) { riskLevel = 'critical'; riskLabel = 'Critical'; }
    else if (score >= 60) { riskLevel = 'high'; riskLabel = 'High'; }
    else if (score >= 40) { riskLevel = 'medium'; riskLabel = 'Medium'; }
    else { riskLevel = 'low'; riskLabel = 'Low'; }
  } else {
    // For alert entities, read severity from alertDetails kv
    const sevStr = (e.sections.alertDetails?.kv?.Severity || '').toLowerCase();
    if (sevStr === 'critical')     { riskLevel = 'critical'; riskLabel = 'Critical'; }
    else if (sevStr === 'high')    { riskLevel = 'high';     riskLabel = 'High'; }
    else if (sevStr === 'medium')  { riskLevel = 'medium';   riskLabel = 'Medium'; }
    else if (sevStr === 'low')     { riskLevel = 'low';      riskLabel = 'Low'; }
    else {
      const alerts = e.sections.recentAlerts?.timeline || [];
      const malCount = alerts.filter(a => a.malicious || a.dot === 'red').length;
      if (malCount >= 3) { riskLevel = 'critical'; riskLabel = 'Critical'; }
      else if (malCount >= 2) { riskLevel = 'high'; riskLabel = 'High'; }
      else if (malCount >= 1) { riskLevel = 'medium'; riskLabel = 'Medium'; }
      else { riskLevel = 'low'; riskLabel = 'Low'; }
    }
  }

  // Build category rows based on entity type
  const rows = buildQuickCardRows(e, entityId);

  let html = '';
  // Header
  html += `<div class="eqc-header">`;
  html += `<div class="eqc-icon" style="background:${typeBgs[e.type]};color:${typeColors[e.type]}">${display.icon || '📄'}</div>`;
  html += `<div>`;
  html += `<div class="eqc-title">${e.modalTitle.split('·').pop()?.trim() || entityId}</div>`;
  html += `<div class="eqc-subtitle">${typeLabels[e.type] || e.type}</div>`;
  html += `</div>`;
  html += `<span class="eqc-risk-pill eqc-risk-${riskLevel}">${riskLabel}</span>`;
  html += `</div>`;

  // Rows
  html += `<div class="eqc-rows">`;
  rows.forEach((row, i) => {
    if (row.divider) { html += '<div class="eqc-divider"></div>'; return; }
    const countCls = row.count > 0 ? (row.critical ? ' critical' : ' has-data') : '';
    html += `<div class="eqc-row" onclick="hideEntityQuickCard();openEntitySlider('${entityId}');setTimeout(()=>switchToTabSection('${entityId}','${row.tabId}','${row.secKey}'),100)">`;
    html += `<span class="eqc-row-icon">${row.icon}</span>`;
    html += `<span class="eqc-row-label">${row.label}</span>`;
    html += `<span class="eqc-row-count${countCls}">${row.count}</span>`;
    html += `<span class="eqc-row-arrow">›</span>`;
    html += `</div>`;
  });
  html += `</div>`;

  // Footer
  html += `<div class="eqc-footer">`;
  html += `<button class="eqc-btn eqc-btn-primary" onclick="hideEntityQuickCard();openEntitySlider('${entityId}')">Open Details</button>`;
  html += `<button class="eqc-btn eqc-btn-secondary" onclick="hideEntityQuickCard();ctxEntityId='${entityId}';ctxSearchLogs()">🔍 Logs</button>`;
  html += `</div>`;

  card.innerHTML = html;
  card.dataset.activeEntity = entityId;

  // Position near the clicked node
  const canvas = document.getElementById('graphCanvas');
  const canvasRect = canvas.getBoundingClientRect();
  const svg = document.getElementById('graphSvg');
  const circle = document.querySelector(`#graphSvg g.graph-node[data-entity="${entityId}"] circle:not(.expand-indicator)`);

  if (circle && svg) {
    const svgRect = svg.getBoundingClientRect();
    const cx = parseFloat(circle.getAttribute('cx'));
    const cy = parseFloat(circle.getAttribute('cy'));
    const viewBox = svg.viewBox.baseVal;
    const scaleX = svgRect.width / viewBox.width;
    const scaleY = svgRect.height / viewBox.height;
    let px = (cx * scaleX) + (svgRect.left - canvasRect.left) + 30;
    let py = (cy * scaleY) + (svgRect.top - canvasRect.top) - 60;
    // Keep card within canvas bounds
    if (px + 290 > canvasRect.width) px = px - 320;
    if (py + 300 > canvasRect.height) py = canvasRect.height - 310;
    if (py < 10) py = 10;
    card.style.left = px + 'px';
    card.style.top = py + 'px';
  } else if (evt) {
    const rect = canvas.getBoundingClientRect();
    card.style.left = (evt.clientX - rect.left + 20) + 'px';
    card.style.top = (evt.clientY - rect.top - 40) + 'px';
  }

  // Highlight node
  document.querySelectorAll('.graph-node').forEach(n => n.style.opacity = '0.35');
  const activeNode = document.querySelector(`.graph-node[data-entity="${entityId}"]`);
  if (activeNode) activeNode.style.opacity = '1';

  card.classList.add('visible');
  eqcVisible = true;
}

function buildQuickCardRows(e, entityId) {
  const rows = [];
  const sec = e.sections;
  const count = (s) => s?.timeline?.length || s?.viewAllData?.length || 0;
  const kvCount = (s) => s?.kv ? Object.keys(s.kv).length : 0;

  if (e.type === 'user') {
    rows.push({ icon:'🔔', label:'Recent Alerts', count: count(sec.recentAlerts), critical: count(sec.recentAlerts)>=2, tabId:'threats', secKey:'recentAlerts' });
    rows.push({ icon:'🔑', label:'Logon Activity', count: count(sec.logonActivity), tabId:'activity', secKey:'logonActivity' });
    rows.push({ icon:'⚙', label:'Processes', count: count(sec.processes), tabId:'activity', secKey:'processes' });
    rows.push({ icon:'🔧', label:'Services Triggered', count: count(sec.serviceTriggered), tabId:'activity', secKey:'serviceTriggered' });
    rows.push({ divider:true });
    rows.push({ icon:'📁', label:'File Access', count: count(sec.resourceFileAccess), tabId:'activity', secKey:'resourceFileAccess' });
    rows.push({ icon:'🌐', label:'Cloud Identities', count: kvCount(sec.cloudIdentities), tabId:'risk', secKey:'cloudIdentities' });
  } else if (e.type === 'device') {
    rows.push({ icon:'🔔', label:'Recent Alerts', count: count(sec.recentAlerts), critical: count(sec.recentAlerts)>=2, tabId:'alerts', secKey:'recentAlerts' });
    rows.push({ icon:'⚙', label:'Processes on Host', count: count(sec.processesOnHost), tabId:'host', secKey:'processesOnHost' });
    rows.push({ icon:'🔧', label:'Services on Host', count: count(sec.servicesOnHost), tabId:'host', secKey:'servicesOnHost' });
    rows.push({ icon:'👤', label:'Users Logged On', count: count(sec.usersLoggedOn), tabId:'host', secKey:'usersLoggedOn' });
    rows.push({ divider:true });
    rows.push({ icon:'🛡', label:'Vulnerabilities', count: count(sec.vulnerabilities), critical: count(sec.vulnerabilities)>=2, tabId:'security', secKey:'vulnerabilities' });
    rows.push({ icon:'⚠', label:'Misconfigurations', count: count(sec.misconfigurations), tabId:'security', secKey:'misconfigurations' });
  } else if (e.type === 'ip') {
    rows.push({ icon:'🔔', label:'Threat Intelligence', count: count(sec.threatIntelligence), critical:true, tabId:'threat', secKey:'threatIntelligence' });
    rows.push({ icon:'🔗', label:'Connections', count: count(sec.connectionHistory), tabId:'connections', secKey:'connectionHistory' });
    rows.push({ icon:'👤', label:'Associated Users', count: count(sec.associatedUsers) || kvCount(sec.associatedUsers), tabId:'overview', secKey:'associatedUsers' });
    rows.push({ icon:'💻', label:'Associated Devices', count: kvCount(sec.associatedDevices), tabId:'overview', secKey:'associatedDevices' });
  } else if (e.type === 'service') {
    rows.push({ icon:'🔔', label:'Recent Alerts', count: count(sec.recentAlerts), critical: count(sec.recentAlerts)>=2, tabId:'alerts', secKey:'recentAlerts' });
    rows.push({ icon:'�', label:'Related Services', count: count(sec.serviceTriggered), tabId:'alerts', secKey:'serviceTriggered' });
    rows.push({ icon:'⚙', label:'Related Processes', count: count(sec.processes), tabId:'activity', secKey:'processes' });
    rows.push({ icon:'📋', label:'Service Events', count: count(sec.serviceTimeline), tabId:'activity', secKey:'serviceTimeline' });
    rows.push({ divider:true });
    rows.push({ icon:'🌐', label:'Network Connections', count: count(sec.networkConnections), tabId:'activity', secKey:'networkConnections' });
    rows.push({ icon:'📁', label:'File Access Anomaly', count: count(sec.fileAccessAnomaly), tabId:'activity', secKey:'fileAccessAnomaly' });
    rows.push({ icon:'🔑', label:'Sign-In Audit', count: count(sec.signInAudit), tabId:'activity', secKey:'signInAudit' });
    rows.push({ icon:'⚠', label:'Config Issues', count: count(sec.configurationIssues), tabId:'config', secKey:'configurationIssues' });
  } else if (e.type === 'process') {
    rows.push({ icon:'🔔', label:'Recent Alerts', count: count(sec.recentAlerts), critical: count(sec.recentAlerts)>=2, tabId:'related', secKey:'recentAlerts' });
    rows.push({ icon:'🔧', label:'Related Services', count: count(sec.serviceTriggered), tabId:'related', secKey:'serviceTriggered' });
    rows.push({ icon:'⚙', label:'Child Processes', count: count(sec.childProcesses), tabId:'activity', secKey:'childProcesses' });
    rows.push({ icon:'🌳', label:'Process Tree', count: count(sec.processTree), tabId:'overview', secKey:'processTree' });
    rows.push({ divider:true });
    rows.push({ icon:'🛡', label:'AMSI Events', count: count(sec.amsiEvents), critical:true, tabId:'anomaly', secKey:'amsiEvents' });
    rows.push({ icon:'🌐', label:'Network Activity', count: count(sec.networkActivity), tabId:'activity', secKey:'networkActivity' });
    rows.push({ icon:'📁', label:'File Operations', count: count(sec.fileOperations), tabId:'activity', secKey:'fileOperations' });
    rows.push({ icon:'📝', label:'Registry Mods', count: count(sec.registryModifications), tabId:'anomaly', secKey:'registryModifications' });
  } else if (e.type === 'alert') {
    rows.push({ icon:'🔗', label:'Correlated Alerts', count: count(sec.correlatedAlerts), tabId:'scope', secKey:'correlatedAlerts' });
    rows.push({ icon:'📋', label:'Affected Entities', count: kvCount(sec.affectedEntities), tabId:'scope', secKey:'affectedEntities' });
    rows.push({ icon:'⚙', label:'Processes', count: count(sec.processes), tabId:'scope', secKey:'processes' });
    rows.push({ icon:'🔧', label:'Services', count: count(sec.serviceTriggered), tabId:'response', secKey:'serviceTriggered' });
  }

  // Filter out rows where the section doesn't exist
  return rows.filter(r => r.divider || e.sections[r.secKey] !== undefined);
}

function switchToTabSection(entityId, tabId, secKey) {
  const body = document.getElementById('edsBody');
  if (!body) return;
  // Activate the right tab
  const tabBtn = Array.from(body.querySelectorAll('.eds-tab')).find(btn => {
    const label = btn.textContent.toLowerCase();
    // Match tab by navigating tab panels
    return true; // We'll use data-tab matching instead
  });
  // Find and click the tab that owns this section
  const panel = body.querySelector(`.eds-tab-panel[data-tab="${tabId}"]`);
  if (panel) {
    body.querySelectorAll('.eds-tab').forEach(t => t.classList.remove('eds-tab-active'));
    body.querySelectorAll('.eds-tab-panel').forEach(p => p.style.display = 'none');
    panel.style.display = '';
    // Find matching tab button
    const tabs = body.querySelectorAll('.eds-tab');
    const panels = body.querySelectorAll('.eds-tab-panel');
    panels.forEach((p, i) => {
      if (p === panel && tabs[i]) tabs[i].classList.add('eds-tab-active');
    });
    // Scroll to the section
    const secEl = panel.querySelector(`#em-${secKey}`);
    if (secEl) {
      // Expand if collapsed
      secEl.classList.remove('collapsed');
      setTimeout(() => secEl.scrollIntoView({ behavior:'smooth', block:'start' }), 50);
    }
  }
}

function hideEntityQuickCard() {
  const card = document.getElementById('eqcCard');
  card.classList.remove('visible');
  eqcVisible = false;
  card.dataset.activeEntity = '';
  // Restore node opacity
  document.querySelectorAll('.graph-node').forEach(n => n.style.opacity = '1');
}

