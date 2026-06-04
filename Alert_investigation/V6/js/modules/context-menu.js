/* context-menu.js — Right-click context menu on graph nodes
 * Depends on: entities.js, display-config.js, entity-slider.js, graph-nodes.js, utils.js */
function showGraphCtx(evt, entityId) {
  evt.preventDefault();
  evt.stopPropagation();
  if (eqcVisible) hideEntityQuickCard();
  ctxEntityId = entityId;
  const ctx = document.getElementById('graphCtxMenu');

  const e = ENTITIES[entityId];
  const type = e ? e.type : 'unknown';
  const groups = drillDownGroups[entityId] || {};
  const display = ENTITY_DISPLAY[entityId] || {};

  let html = '';

  // ── Entity Info Header ──
  if (e) {
    const typeLabels = { user:'User', device:'Host', ip:'IP Address', service:'Service', process:'Process', alert:'Alert' };
    const typeColors = { user:'#7c3aed', device:'#2563eb', ip:'#0891b2', service:'#0891b2', process:'#d97706', alert:'#ef4444' };
    const typeBgs   = { user:'rgba(124,58,237,.12)', device:'rgba(37,99,235,.1)', ip:'rgba(8,145,178,.1)', service:'rgba(8,145,178,.1)', process:'rgba(217,119,6,.1)', alert:'rgba(239,68,68,.1)' };

    // -- Risk level (fix: check both .score and .riskScore) --
    let riskLevel = 'info', riskLabel = 'Info';
    if (e.sections.riskSummary?.summaryCard) {
      const sc = e.sections.riskSummary.summaryCard;
      const score = sc.score ?? sc.riskScore ?? 0;
      if (score >= 80)      { riskLevel = 'critical'; riskLabel = 'Critical'; }
      else if (score >= 60) { riskLevel = 'high';     riskLabel = 'High'; }
      else if (score >= 40) { riskLevel = 'medium';   riskLabel = 'Medium'; }
      else                  { riskLevel = 'low';      riskLabel = 'Low'; }
    } else {
      // For alert entities, read severity from alertDetails kv
      const sevStr = (e.sections.alertDetails?.kv?.Severity || '').toLowerCase();
      if (sevStr === 'critical')     { riskLevel = 'critical'; riskLabel = 'Critical'; }
      else if (sevStr === 'high')    { riskLevel = 'high';     riskLabel = 'High'; }
      else if (sevStr === 'medium')  { riskLevel = 'medium';   riskLabel = 'Medium'; }
      else if (sevStr === 'low')     { riskLevel = 'low';      riskLabel = 'Low'; }
      else {
        // Fallback: infer from recentAlerts, threatIntelligence, or connectionHistory malicious entries
        const alerts = e.sections.recentAlerts?.timeline || [];
        const threatEntries = e.sections.threatIntelligence?.timeline || [];
        const connEntries = e.sections.connectionHistory?.timeline || [];
        const malCount = [...alerts, ...threatEntries, ...connEntries].filter(a => a.malicious || a.dot === 'red').length;
        if (malCount >= 3)      { riskLevel = 'critical'; riskLabel = 'Critical'; }
        else if (malCount >= 2) { riskLevel = 'high';     riskLabel = 'High'; }
        else if (malCount >= 1) { riskLevel = 'medium';   riskLabel = 'Medium'; }
        else                    { riskLevel = 'low';      riskLabel = 'Low'; }
      }
    }
    html += `<div class="ctx-entity-hdr">`;
    html += `<div class="ctx-entity-icon" style="background:${typeBgs[e.type]};color:${typeColors[e.type]}">${display.icon || '📄'}</div>`;
    html += `<div><div class="ctx-entity-name">${e.modalTitle.split('·').pop()?.trim() || entityId}</div>`;
    html += `<div class="ctx-entity-type">${typeLabels[e.type] || e.type}</div></div>`;
    html += `<span class="ctx-risk-pill ctx-risk-${riskLevel}">${riskLabel}</span>`;
    html += `</div>`;
  }

  // ── Graph expand / collapse actions (primary purpose) ──
  let hasGraphActions = false;
  if (e && e.sections.recentAlerts) {
    hasGraphActions = true;
    const expanded = (groups.alert && groups.alert.length > 0) || !!(typeof groupHubs !== 'undefined' && groupHubs[entityId] && groupHubs[entityId].alert);
    const cnt = (e.sections.recentAlerts.viewAllData || e.sections.recentAlerts.timeline || []).length;
    const cntCls = cnt >= 2 ? ' critical' : (cnt > 0 ? ' has-data' : '');
    html += `<div class="ctx-item" onclick="ctxRelatedAlerts()">`;
    html += expanded ? '🔔 Hide Alert Profiles <span class="ctx-badge-collapse">−</span>' : `🔔 Alert Profiles <span class="ctx-badge-count${cntCls}">${cnt}</span>`;
    html += `</div>`;
  }
  if (e && (e.sections.processes || e.sections.processesOnHost || e.sections.serviceTriggered || e.sections.servicesOnHost)) {
    hasGraphActions = true;
    const hubCats = (typeof groupHubs !== 'undefined' && groupHubs[entityId]) || {};
    const expanded = (groups.process && groups.process.length > 0) || (groups.service && groups.service.length > 0) || !!hubCats.process || !!hubCats.service;
    const procSec = e.sections.processes || e.sections.processesOnHost;
    const svcSec = e.sections.serviceTriggered || e.sections.servicesOnHost;
    const procCnt = procSec ? (procSec.viewAllData || procSec.timeline || []).length : 0;
    const svcCnt = svcSec ? (svcSec.viewAllData || svcSec.timeline || []).length : 0;
    const cnt = procCnt + svcCnt;
    const cntCls = cnt > 0 ? ' has-data' : '';
    html += `<div class="ctx-item" onclick="ctxShowProcess()">`;
    html += expanded ? '⚙ Hide Processes <span class="ctx-badge-collapse">−</span>' : `⚙ Processes <span class="ctx-badge-count${cntCls}">${cnt}</span>`;
    html += `</div>`;
  }
  // Blast-radius path node → expand the AD objects (members) along the path
  if (e && e._blastMembers && e._blastMembers.length) {
    hasGraphActions = true;
    const bmExpanded = (groups.blastmember && groups.blastmember.length > 0) || !!(typeof groupHubs !== 'undefined' && groupHubs[entityId] && groupHubs[entityId].blastmember);
    const cnt = e._blastMembers.length;
    const cntCls = e._blastMembers.some(m => m.crownJewel) ? ' critical' : ' has-data';
    html += `<div class="ctx-item" onclick="ctxExpandBlastMembers()">`;
    html += bmExpanded ? '👥 Hide Path Members <span class="ctx-badge-collapse">−</span>' : `👥 Path Members <span class="ctx-badge-count${cntCls}">${cnt}</span>`;
    html += `</div>`;
  }

  // ── Core actions ──
  if (hasGraphActions) html += '<div class="ctx-sep"></div>';
  html += '<div class="ctx-item" onclick="ctxEntityDetails()">🔍 Entity Details</div>';
  if (e && e.sections.blastRadius && (typeof isAiInvestigated === 'function' && isAiInvestigated())) {
    const blastExpanded = (groups.blast && groups.blast.length > 0) || !!(typeof groupHubs !== 'undefined' && groupHubs[entityId] && groupHubs[entityId].blast);
    html += '<div class="ctx-item" onclick="ctxBlastRadiusGraph()" style="color:#dc2626;">💥 ' + (blastExpanded ? 'Collapse Blast Radius' : 'Blast Radius') + ' <span style="margin-left:auto;font-size:9px;color:var(--text-dim);">attack paths</span></div>';
  }
  html += '<div class="ctx-item" onclick="ctxSearchLogs()">📋 Search in Logs</div>';

  // ── More Actions (collapsible, Microsoft-style) ──
  // V6: native investigative/triage items are removed — the only entries here
  // are the two V6 pivots ("Entity timeline" + "Investigate entity") injected
  // by v6-attack-vector.js after this menu is built.
  let moreHtml = '';
  if (moreHtml) {
    html += '<div class="ctx-sep"></div>';
    html += `<div class="ctx-more-toggle" onclick="this.classList.toggle('expanded');this.nextElementSibling.classList.toggle('expanded');reclampCtxMenu()">`;
    html += `<span>More actions</span><span class="ctx-chevron">▸</span>`;
    html += `</div>`;
    html += `<div class="ctx-more-body">${moreHtml}</div>`;
  }

  ctx.innerHTML = html;

  // Position — fixed to viewport, clamp within screen bounds
  ctx.style.display = 'block';
  ctx.style.maxHeight = ''; // reset before measuring
  let mx = evt.clientX;
  let my = evt.clientY;
  const ctxW = ctx.offsetWidth, ctxH = ctx.offsetHeight;
  const vw = window.innerWidth, vh = window.innerHeight;
  if (mx + ctxW > vw - 8) mx = vw - ctxW - 8;
  if (my + ctxH > vh - 8) {
    // If menu doesn't fit below, try flipping up
    if (evt.clientY - ctxH > 8) {
      my = evt.clientY - ctxH;
    } else {
      // Clamp to bottom and set max-height so it scrolls
      my = 8;
      ctx.style.maxHeight = (vh - 16) + 'px';
    }
  }
  ctx.style.left = mx + 'px';
  ctx.style.top = my + 'px';
}

function hideGraphCtx() {
  const ctx = document.getElementById('graphCtxMenu');
  if (ctx) ctx.style.display = 'none';
}

function reclampCtxMenu() {
  const ctx = document.getElementById('graphCtxMenu');
  if (!ctx || ctx.style.display === 'none') return;
  requestAnimationFrame(() => {
    const vh = window.innerHeight;
    // Temporarily remove max-height to measure full content
    const prevMax = ctx.style.maxHeight;
    ctx.style.maxHeight = 'none';
    const fullH = ctx.scrollHeight;
    const top = parseFloat(ctx.style.top) || 0;

    if (top + fullH > vh - 8) {
      // Try moving menu up first
      let newTop = vh - fullH - 8;
      if (newTop >= 8) {
        ctx.style.top = newTop + 'px';
        ctx.style.maxHeight = '';
      } else {
        // Can't fit — pin to top and cap height so it scrolls
        ctx.style.top = '8px';
        ctx.style.maxHeight = (vh - 16) + 'px';
      }
    } else {
      ctx.style.maxHeight = '';
    }
  });
}

/* ── Cascading Investigation Data Generator ──────────────────── */
/* Generates realistic sub-investigation sections for dynamically expanded entities
   so that SOC analysts can drill deeper — services → alerts, processes → services, etc. */
