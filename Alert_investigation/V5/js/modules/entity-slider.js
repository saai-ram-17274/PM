/* entity-slider.js — Entity detail slider panel (right panel in graph view)
 * Depends on: entities.js, display-config.js, utils.js, action-panel.js, app.js */

/* ─── Dynamic metric helpers ───
 * `firstSeen` is rendered as e.g. "11 May 2026 09:22:45". Parse that into a
 * Date so we can compute "time since first alert" relative to the incident
 * wall-clock (the play-the-attack timeline ends at 11 May 2026 11:24).
 * We anchor "now" to the latest event in the demo timeline so the metric
 * stays stable across days and matches the rest of the narrative. */
const _ENTITY_NOW = new Date('2026-05-11T11:24:00');
const _ENTITY_MONTHS = { Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11 };
function _parseEntityTs(s) {
  // Accepts "11 May 2026 09:22:45" or "11 May 2026  09:22:45" (double space)
  const m = String(s||'').trim().match(/^(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})$/);
  if (!m) return null;
  const mo = _ENTITY_MONTHS[m[2]];
  if (mo === undefined) return null;
  return new Date(+m[3], mo, +m[1], +m[4], +m[5], +m[6]);
}
function _humanizeDelta(then, now) {
  if (!then) return null;
  now = now || _ENTITY_NOW;
  let s = Math.max(0, Math.floor((now - then) / 1000));
  const d = Math.floor(s / 86400); s -= d*86400;
  const h = Math.floor(s / 3600);  s -= h*3600;
  const m = Math.floor(s / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function openEntitySlider(entityId) {
  // Dismiss quick card if open
  if (eqcVisible) hideEntityQuickCard();
  ctxEntityId = entityId;
  sliderEntityId = entityId;
  const e = ENTITIES[entityId];
  if (!e) return;
  // Apply full focus highlights (dim non-related nodes & edges)
  restoreGraphHighlights(entityId);
  const activeNode = document.querySelector(`.graph-node[data-entity="${entityId}"]`);
  // set title and type badge
  document.getElementById('edsTitle').textContent = e.modalTitle;
  const badge = document.getElementById('edsTypeBadge');
  const typeLabels = { user:'User', device:'Device', ip:'IP Address', service:'Service', process:'Process', alert:'Alert' };
  const typeIcons = { user:'👤', device:'💻', ip:'🌐', service:'⚙', process:'🔧', alert:'🔔' };
  badge.textContent = (typeIcons[e.type]||'') + ' ' + (typeLabels[e.type]||cap(e.type));
  badge.className = 'eds-type-badge type-' + e.type;
  badge.style.display = 'inline-flex';
  // Show investigation depth chain for drilled-down entities
  const depthBadge = document.getElementById('edsDepthBadge');
  if (depthBadge) {
    const nodeDepth = parseInt(activeNode?.getAttribute('data-depth') || '0');
    if (nodeDepth > 0) {
      // Build chain path: trace back from this node through parents
      const chainParts = [];
      let traceEid = entityId;
      for (let d = 0; d < nodeDepth && d < 5; d++) {
        for (const [pEid, cats] of Object.entries(drillDownGroups)) {
          for (const [cat, items] of Object.entries(cats)) {
            if (items.some(it => it.nodeId === traceEid)) {
              const pEnt = ENTITIES[pEid];
              chainParts.unshift(pEnt ? (pEnt.modalTitle.split('·').pop()?.trim() || pEid) : pEid);
              traceEid = pEid;
            }
          }
        }
      }
      chainParts.push(e.modalTitle.split('·').pop()?.trim() || entityId);
      depthBadge.innerHTML = `<span class="eds-chain-icon">🔗</span> ${chainParts.join(' → ')}`;
      depthBadge.style.display = 'flex';
    } else {
      depthBadge.style.display = 'none';
    }
  }
  // populate actions dropdown based on entity type
  populateActionsDropdown(e.type, e.modalTitle);
  // render body
  renderEntitySliderBody(entityId);
  // V5 adapt: slider is an absolute overlay over the canvas. To keep the
  // clicked entity visible (especially right-side nodes which would be
  // hidden by the overlay) shift the SVG left by ~half the slider width.
  if (typeof panOffsetX !== 'undefined' && typeof applyGraphTransform === 'function') {
    const slider = document.getElementById('entitySlider');
    const canvas = document.getElementById('graphCanvas');
    if (slider && canvas) {
      const sliderW = Math.min(560, Math.max(380, canvas.clientWidth * 0.42));
      // Shift left by 55% of slider width — enough to bring right-edge nodes
      // back into the visible area while keeping the existing zoom intact.
      panOffsetX = -Math.round(sliderW * 0.55);
      applyGraphTransform();
    }
  }
  // slide open (overlay – does not resize the canvas)
  document.getElementById('graphContainer').classList.add('slider-open');
}

function populateActionsDropdown(type, name) {
  const dd = document.getElementById('edsActionsDd');
  if (!dd) return;
  let html = '';
  // Universal
  html += `<div class="dropdown-item" onclick="showActionPanel('searchLogs',ctxEntityId);closeDropdowns()">🔍 Search in Logs</div>`;
  // User & Device
  if (['user','device'].includes(type)) {
    html += `<div class="dropdown-item" onclick="showActionPanel('uebaTimeline',ctxEntityId);closeDropdowns()">📊 UEBA Timeline</div>`;
  }
  // User, Device, IP — login actions
  if (['user','device','ip'].includes(type)) {
    html += `<div class="dropdown-item" onclick="showActionPanel('loginActivity',ctxEntityId);closeDropdowns()">🔐 Login Activity</div>`;
  }
  // Device — security
  if (type === 'device') {
    html += '<div class="dropdown-sep"></div>';
    html += `<div class="dropdown-item" onclick="showActionPanel('vulnerabilities',ctxEntityId);closeDropdowns()">🛡 Vulnerabilities</div>`;
    html += `<div class="dropdown-item" onclick="showActionPanel('misconfigurations',ctxEntityId);closeDropdowns()">⚙ Misconfigurations</div>`;
  }
  // Service — config
  if (type === 'service') {
    html += '<div class="dropdown-sep"></div>';
    html += `<div class="dropdown-item" onclick="showActionPanel('configIssues',ctxEntityId);closeDropdowns()">⚙ Configuration Issues</div>`;
    html += `<div class="dropdown-item" onclick="showActionPanel('auditLogs',ctxEntityId);closeDropdowns()">📋 Audit Logs</div>`;
  }
  // Process — kill
  if (type === 'process') {
    html += '<div class="dropdown-sep"></div>';
    html += `<div class="dropdown-item" onclick="showActionPanel('networkActivity',ctxEntityId);closeDropdowns()">📊 Network Activity</div>`;
    html += `<div class="dropdown-item" onclick="showActionPanel('killProcess',ctxEntityId);closeDropdowns()" style="color:#dc2626;">⊘ Kill Process</div>`;
  }
  // User — account actions
  if (type === 'user') {
    html += '<div class="dropdown-sep"></div>';
    html += `<div class="dropdown-item" onclick="showActionPanel('revokeTokens',ctxEntityId);closeDropdowns()" style="color:#ea580c;">🔑 Revoke All Tokens</div>`;
    html += `<div class="dropdown-item" onclick="showActionPanel('forcePasswordReset',ctxEntityId);closeDropdowns()" style="color:#ea580c;">🔄 Force Password Reset</div>`;
    html += `<div class="dropdown-item" onclick="showActionPanel('blockEntity',ctxEntityId);closeDropdowns()" style="color:#dc2626;">🚫 Disable Account</div>`;
  }
  // IP — block
  if (type === 'ip') {
    html += '<div class="dropdown-sep"></div>';
    html += `<div class="dropdown-item" onclick="showActionPanel('blockEntity',ctxEntityId);closeDropdowns()" style="color:#dc2626;">🚫 Block IP</div>`;
  }
  // Device — isolate
  if (type === 'device') {
    html += '<div class="dropdown-sep"></div>';
    html += `<div class="dropdown-item" onclick="showActionPanel('isolateHost',ctxEntityId);closeDropdowns()" style="color:#dc2626;">🔒 Isolate Host</div>`;
  }
  // Alert — incident actions
  if (type === 'alert') {
    html += '<div class="dropdown-sep"></div>';
    html += `<div class="dropdown-item" onclick="showActionPanel('addToIncident',ctxEntityId);closeDropdowns()">📌 Add to Incident</div>`;
    html += `<div class="dropdown-item" onclick="showActionPanel('runPlaybook',ctxEntityId);closeDropdowns()">▶ Run Playbook</div>`;
    html += `<div class="dropdown-item" onclick="showActionPanel('closeAlert',ctxEntityId);closeDropdowns()">✓ Close Alert</div>`;
  }
  dd.innerHTML = html;
}

function closeEntitySlider() {
  closeActionPanel();
  document.getElementById('graphContainer').classList.remove('slider-open');
  sliderEntityId = null;
  // restore original pan position
  if (typeof panOffsetX !== 'undefined' && typeof applyGraphTransform === 'function') {
    panOffsetX = 0;
    panOffsetY = 0;
    applyGraphTransform();
  }
  restoreGraphHighlights();
}

/* Reset all per-element opacity / stroke styles applied by entity / edge focus.
   If `focusEntityId` is given, dim non-related nodes/edges around that entity. */
function restoreGraphHighlights(focusEntityId) {
  // Always clear residual inline styles first
  document.querySelectorAll('.graph-node').forEach(n => { n.style.opacity = ''; n.classList.remove('active-focus'); });
  document.querySelectorAll('line[data-source]').forEach(line => { line.style.opacity = ''; line.style.strokeWidth = ''; });
  document.querySelectorAll('.edge-info-btn').forEach(btn => { btn.style.opacity = ''; });

  if (!focusEntityId) return;

  // Re-apply entity focus dim
  document.querySelectorAll('.graph-node').forEach(n => n.style.opacity = '0.4');
  const activeNode = document.querySelector(`.graph-node[data-entity="${focusEntityId}"]`);
  if (activeNode) { activeNode.style.opacity = '1'; activeNode.classList.add('active-focus'); }
  document.querySelectorAll('line[data-source]').forEach(line => {
    if (line.style.display === 'none' || line.getAttribute('style')?.includes('display:none')) return;
    const ls = line.getAttribute('data-source');
    const lt = line.getAttribute('data-target');
    if (ls === focusEntityId || lt === focusEntityId) {
      line.style.opacity = '1';
      const neighborId = ls === focusEntityId ? lt : ls;
      const neighbor = document.querySelector(`.graph-node[data-entity="${neighborId}"]`);
      if (neighbor) neighbor.style.opacity = '1';
    } else {
      line.style.opacity = '0.12';
    }
  });
  document.querySelectorAll('.edge-info-btn').forEach(btn => {
    const bs = btn.getAttribute('data-source');
    const bt = btn.getAttribute('data-target');
    btn.style.opacity = (bs === focusEntityId || bt === focusEntityId) ? '1' : '0.2';
  });
}

function openEntityModal(entityId) {
  openEntitySlider(entityId);
}

function closeEntityModal() {
  closeEntitySlider();
}

function renderEntitySliderBody(entityId) {
  const e = ENTITIES[entityId];
  if (!e || !e.sections) return;
  const body = document.getElementById('edsBody');
  let html = '';

  // Define tab groupings per entity type
  const tabConfig = {
    user: [
      { id:'overview', label:'Overview', sections:['riskSummary','usersDetails'] },
      { id:'risk', label:'Risk & Identity', sections:['uebaProfile','loginStatistics','cloudIdentities','identityRisk','threatIntelContext','dlpIncidents'] },
      { id:'activity', label:'Activity', sections:['logonActivity','networkActivity','processes','serviceTriggered','resourceFileAccess','recentAppAccess'] },
      { id:'changes', label:'Account Changes', sections:['accountLockouts','passwordHistory','groupMembershipChanges','mailboxForwarding'] },
      { id:'recentAlerts', label:'Recent Alerts', sections:['recentAlerts'] }
    ],
    device: [
      { id:'overview', label:'Overview', sections:['riskSummary','deviceDetails','agentStatus','gpoApplied','securityEventSummary'] },
      { id:'host', label:'Host Activity', sections:['processesOnHost','servicesOnHost','usersLoggedOn','loginActivity'] },
      { id:'persistence', label:'Persistence & Exfil', sections:['scheduledTasks','usbDeviceEvents'] },
      { id:'alerts', label:'Alerts & Response', sections:['recentAlerts'] }
    ],
    ip: [
      { id:'overview', label:'Overview', sections:['riskSummary','ipDetails','geoContext','associatedUsers','associatedDevices'] },
      { id:'threat', label:'Threat Intel', sections:['threatIntelligence','idsAlerts','firewallSummary'] },
      { id:'connections', label:'Connections', sections:['connectionHistory','dnsHistory','vpnSessions','trafficSummary'] },
      { id:'logon', label:'Logon Activity', sections:['logonActivity'] }
    ],
    domain: [
      { id:'overview', label:'Overview', sections:['riskSummary','ipDetails','geoContext','associatedUsers','associatedDevices'] },
      { id:'threat', label:'Threat Intel', sections:['threatIntelligence','idsAlerts','firewallSummary'] },
      { id:'connections', label:'Connections', sections:['connectionHistory','dnsHistory','vpnSessions','trafficSummary'] },
      { id:'logon', label:'Logon Activity', sections:['logonActivity'] }
    ],
    service: [
      { id:'overview', label:'Overview', sections:['riskSummary','serviceDetails','serviceInfo'] },
      { id:'config', label:'Config & Policy', sections:['oauthConsentGrants','conditionalAccess','dlpPolicies'] },
      { id:'activity', label:'Activity', sections:['signInAudit','adminActivity','fileAccessAnomaly','sensitiveFiles','serviceTimeline','networkConnections','fileDrops','wmiEvents','processes'] },
      { id:'alerts', label:'Alerts & Response', sections:['recentAlerts','serviceTriggered'] }
    ],
    process: [
      { id:'overview', label:'Overview', sections:['riskSummary','processDetails','details','processTree','childProcesses','serviceTriggered','recentAlerts'] },
      { id:'anomaly', label:'Anomalies', sections:['tokenAnomaly','amsiEvents','registryModifications','namedPipes'] },
      { id:'activity', label:'Activity', sections:['tokenUsage','networkActivity','fileOperations','processes','dllLoads','processDnsQueries'] }
    ],
    alert: [
      { id:'overview', label:'Overview', sections:['alertDetails','triggerConditions','details'] },
      { id:'scope', label:'Scope', sections:['affectedEntities','correlatedAlerts','processes'] },
      { id:'response', label:'Response', sections:['serviceTriggered','recentAlerts'] }
    ]
  };

  const tabs = tabConfig[e.type];
  const sectionKeys = Object.keys(e.sections);
  const tabsHost = document.getElementById('edsTabsHost');
  if (tabsHost) tabsHost.innerHTML = '';

  if (tabs && sectionKeys.length > 3) {
    // Render tabs into the dedicated host (outside the scrolling body)
    let tabsHtml = '<div class="eds-tabs">';
    tabs.forEach((tab, i) => {
      const hasContent = tab.sections.some(s => e.sections[s]);
      if (!hasContent) return;
      const active = i === 0 ? ' eds-tab-active' : '';
      tabsHtml += `<button class="eds-tab${active}" onclick="switchEdsTab('${entityId}','${tab.id}',this)">${tab.label}</button>`;
    });
    tabsHtml += '</div>';
    if (tabsHost) tabsHost.innerHTML = tabsHtml;

    // Render tab panels into the scrolling body
    tabs.forEach((tab, i) => {
      const hasContent = tab.sections.some(s => e.sections[s]);
      if (!hasContent) return;
      const display = i === 0 ? '' : ' style="display:none;"';
      html += `<div class="eds-tab-panel" data-tab="${tab.id}"${display}>`;

      /* Special flat rendering for Recent Alerts tab — alert list only, no section wrapper */
      if (tab.id === 'recentAlerts' && e.sections.recentAlerts) {
        const alertSec = e.sections.recentAlerts;
        const allEntries = alertSec.viewAllData || alertSec.timeline || [];
        const maxShow = 10;
        const visibleEntries = allEntries.slice(0, maxShow);
        if (visibleEntries.length === 0) {
          html += `<div style="padding:24px 20px;color:#8a94a6;font-size:12px;text-align:center;">No recent alerts found.</div>`;
        } else {
          html += `<div class="em-section-body" style="padding:8px 20px 12px;">`;
          html += renderTimelineEntries(visibleEntries);
          html += `</div>`;
        }
      } else {
        tab.sections.forEach(secKey => {
          const sec = e.sections[secKey];
          if (!sec) return;
          html += renderEntitySection(entityId, secKey, sec);
        });
      }

      html += '</div>';
    });
  } else {
    // Simple list — no tabs needed
    Object.entries(e.sections).forEach(([secKey, sec]) => {
      html += renderEntitySection(entityId, secKey, sec);
    });
  }

  body.innerHTML = html;
}

function switchEdsTab(entityId, tabId, btn) {
  const body = document.getElementById('edsBody');
  const tabsHost = document.getElementById('edsTabsHost');
  (tabsHost || body).querySelectorAll('.eds-tab').forEach(t => t.classList.remove('eds-tab-active'));
  btn.classList.add('eds-tab-active');
  body.querySelectorAll('.eds-tab-panel').forEach(p => {
    p.style.display = p.dataset.tab === tabId ? '' : 'none';
  });
}

/* Navigate to a specific tab and scroll to a section — used by View All back button */
function navigateToTabSection(entityId, tabId, secKey) {
  const body = document.getElementById('edsBody');
  if (!body) return;
  const tabsHost = document.getElementById('edsTabsHost');
  const tabsRoot = tabsHost || body;
  // Activate the right tab
  const tabBtn = Array.from(tabsRoot.querySelectorAll('.eds-tab')).find(t => {
    // Match by tab id stored in onclick
    return t.getAttribute('onclick') && t.getAttribute('onclick').includes("'" + tabId + "'");
  });
  if (tabBtn) {
    tabsRoot.querySelectorAll('.eds-tab').forEach(t => t.classList.remove('eds-tab-active'));
    tabBtn.classList.add('eds-tab-active');
  }
  body.querySelectorAll('.eds-tab-panel').forEach(p => {
    p.style.display = p.dataset.tab === tabId ? '' : 'none';
  });
  // Scroll to the section and expand it if collapsed
  setTimeout(() => {
    const sec = document.getElementById('em-' + secKey);
    if (sec) {
      sec.classList.remove('collapsed');
      sec.scrollIntoView({ behavior:'smooth', block:'start' });
    }
  }, 80);
}

function renderEntitySection(entityId, secKey, sec) {
  let html = '';

  /* ── Summary Card (special full-width rendering, no collapse) ── */
  if (sec.summaryCard) {
    html += renderSummaryCard(sec.summaryCard);
    return html;
  }

  /* ── Action Buttons (special rendering, no collapse) ── */
  if (sec.actionButtons) {
    html += renderActionButtons(sec.actionButtons);
    return html;
  }

  const collapsed = sec.expanded ? '' : ' collapsed';
  const noCollapse = sec.noCollapse ? ' no-collapse' : '';
  html += `<div class="em-section${collapsed}${noCollapse}" id="em-${secKey}">`;

  if (!sec.noCollapse) {
    // Build label with dynamic count if section has timeline or viewAllData
    const count = sec.timeline ? sec.timeline.length : (sec.viewAllData ? sec.viewAllData.length : 0);
    const countBadge = count > 0 ? ` <span class="em-sec-count">(${count})</span>` : '';
    html += `<div class="em-section-hdr" onclick="toggleEmSec('em-${secKey}')">`;
    html += `<span class="em-section-title"><span class="chev">▾</span> ${sec.label}${countBadge}</span>`;
    if (sec.viewAll) html += `<span class="em-view-all" onclick="event.stopPropagation();viewAllSection('${entityId}','${secKey}')">View All</span>`;
    html += `</div>`;
  } else {
    html += `<div class="em-section-hdr">`;
    html += `<span class="em-section-title">${sec.label}</span>`;
    html += `</div>`;
  }

  html += `<div class="em-section-body">`;

  // Key-value table
  if (sec.kv) {
    html += `<table class="em-kv-table">`;
    Object.entries(sec.kv).forEach(([k, v]) => {
      let cls = '';
      const vStr = String(v);
      if (vStr.includes('Critical') || vStr.includes('⚠')) cls = ' style="color:#dc2626;font-weight:600;"';
      else if (vStr.includes('High')) cls = ' style="color:#ea580c;font-weight:600;"';
      html += `<tr><td>${k}</td><td${cls}>${v}</td></tr>`;
    });
    html += `</table>`;
  }

  // Timeline entries
  if (sec.timeline) {
    html += renderTimelineEntries(sec.timeline);
  }

  // Attack path context
  if (sec.attackPath) {
    html += renderAttackPath(sec.attackPath);
  }

  // Geo & Travel Analysis
  if (sec.travelMap) {
    html += renderTravelMap(sec.travelMap);
  }

  // Compliance cards
  if (sec.complianceCards) {
    html += renderComplianceCards(sec.complianceCards);
  }

  // Peer comparison
  if (sec.peerData) {
    html += renderPeerComparison(sec.peerData);
  }

  // Remediation guide (verdict + recommendations + playbooks)
  if (sec.remediationData) {
    html += renderRemediationGuide(sec.remediationData, entityId);
  }

  html += `</div>`; // section-body
  html += `</div>`; // section
  return html;
}

function renderTimelineEntries(entries) {
  let html = '';
  entries.forEach((entry) => {
    html += `<div class="em-timeline-entry">`;
    html += `<div class="em-timeline-hdr">`;
    html += `<span class="em-dot em-dot-${entry.dot}"></span>`;
    html += `<span class="em-timestamp">${entry.time}</span>`;
    if (entry.malicious) html += `<span class="em-badge-mal">● Malicious</span>`;
    if (entry.viewOnGraph) {
      const vog = entry.viewOnGraph;
      if (typeof vog === 'object') {
        html += `<a class="em-link" onclick="event.stopPropagation();viewOnGraph('${vog.nodeId}','${vog.label}','${vog.icon}','${vog.sourceEntity}',${!!entry.malicious})">View On Map</a>`;
      } else {
        html += `<a class="em-link" onclick="event.stopPropagation();viewOnGraph('${vog}')">View On Map</a>`;
      }
    }
    html += `</div>`;

    if (entry.details) {
      html += `<div class="em-detail-grid">`;
      Object.entries(entry.details).forEach(([k, v]) => {
        let valCls = 'em-detail-value';
        if (v === 'Success' || v === 'Success to DC') valCls += ' status-success';
        else if (v === 'Failure') valCls += ' status-failure';
        else if (v === 'Paused') valCls += ' status-paused';
        else if (v === 'High') valCls += ' sev-high';
        else if (v === 'Critical') valCls += ' sev-critical';
        html += `<span class="em-detail-label">${k}</span><span class="${valCls}">${v}</span>`;
      });
      html += `</div>`;
    }

    if (entry.detailsGrid) {
      entry.detailsGrid.forEach(dg => {
        html += `<div class="em-detail-grid">`;
        html += `<span class="em-detail-label">${dg.label}</span><span class="em-detail-value">${dg.value}</span>`;
        html += `<span class="em-detail-label">${dg.tag}</span><span class="em-detail-value">${dg.tagVal}</span>`;
        html += `<span class="em-detail-label">MITRE</span><span class="em-detail-value">${dg.mitre}</span>`;
        html += `<span class="em-detail-label">Source</span><span class="em-detail-value">${dg.source}</span>`;
        html += `<span class="em-detail-label">Status</span><span class="em-detail-value">${dg.status}</span>`;
        html += `<span class="em-detail-label">Severity</span><span class="em-detail-value sev-critical">${dg.severity}</span>`;
        html += `</div>`;
      });
    }

    // "View Alert Profile" link for alert entries
    if (entry.alertProfileId) {
      html += `<a class="em-link em-alert-profile-link" onclick="event.stopPropagation();openEntitySlider('${entry.alertProfileId}')">📋 View Alert Profile</a>`;
    }

    if (entry.action) {
      const toastMsg = entry.action.toast || entry.action.label.replace(/^[^\w]+/, '') + '…';
      const toastIcon = entry.action.label.charAt(0) || '⊘';
      html += `<button class="btn-action-outline" onclick="showToast('${toastIcon}','${toastMsg}')">${entry.action.label}</button>`;
    }

    html += `</div>`;
  });
  return html;
}

function renderAttackPath(ap) {
  let html = `<div class="em-attack-path">`;
  html += `<div class="em-path-stats">`;
  html += `<span class="em-path-stat">🛡 <strong>${ap.stats.paths} Paths</strong></span>`;
  html += `<span class="em-path-stat">💎 <strong>${ap.stats.crownJewels} Crown Jewels</strong></span>`;
  html += `<span class="em-path-stat">Min Hops: <strong>${ap.stats.minHops}</strong></span>`;
  html += `<span class="em-path-stat critical">⚠ ${ap.stats.severity}</span>`;
  html += `</div>`;
  html += `<div class="em-path-desc">${ap.description}</div>`;
  html += `<div class="em-path-visual">`;
  ap.nodes.forEach((nd, i) => {
    html += `<div style="text-align:center;">`;
    html += `<div class="em-path-node ${nd.color}">👤</div>`;
    html += `<div class="em-path-label">${nd.label}</div>`;
    html += `</div>`;
    if (i < ap.nodes.length - 1) html += `<div class="em-path-arrow"></div>`;
  });
  html += `</div>`;
  if (ap.remediation) {
    html += `<div class="em-remediation">`;
    html += `<div class="em-remediation-title">◈ Remediation</div>`;
    html += `<div class="em-remediation-text">${ap.remediation.text}</div>`;
    html += `<button class="btn-run-playbook" onclick="showToast('▶','Running playbook…')">▶ ${ap.remediation.playbook}</button>`;
    html += `</div>`;
  }
  html += `</div>`;
  return html;
}

/* ─── Risk Summary Card ─── */
function renderSummaryCard(card) {
  let html = '<div class="em-summary-card">';

  // Gauge SVG — handle both .riskScore and .score field names
  const scoreVal = card.riskScore ?? card.score ?? 0;
  const pct = (scoreVal / card.maxScore) * 100;
  const gaugeColor = pct >= 80 ? '#ef4444' : pct >= 50 ? '#f97316' : pct >= 30 ? '#eab308' : '#22c55e';
  const glowColor  = pct >= 80 ? 'rgba(239,68,68,.3)' : 'rgba(34,197,94,.2)';
  const R = 30, C = 2 * Math.PI * R;
  const off = C - (pct / 100) * C;

  html += '<div class="em-sc-hero">';
  html += '<div class="em-sc-gauge-wrap">';
  html += `<svg width="72" height="72" viewBox="0 0 72 72">`;
  html += `<circle cx="36" cy="36" r="${R}" fill="none" stroke="#e2e8f0" stroke-width="5"/>`;
  html += `<circle cx="36" cy="36" r="${R}" fill="none" stroke="${gaugeColor}" stroke-width="5" stroke-linecap="round" stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 36 36)" style="transition:stroke-dashoffset .6s ease;filter:drop-shadow(0 0 4px ${glowColor});"/>`;
  html += `<text x="36" y="34" text-anchor="middle" font-size="18" font-weight="800" fill="${gaugeColor}" font-family="var(--font)">${scoreVal}</text>`;
  html += `<text x="36" y="46" text-anchor="middle" font-size="8" fill="#94a3b8" font-family="var(--font)">/ ${card.maxScore}</text>`;
  html += `</svg>`;
  html += '<span class="em-sc-gauge-label">Risk Score</span>';
  html += '</div>';

  html += '<div class="em-sc-right">';
  html += '<div class="em-sc-badges">';
  html += `<span class="em-sc-sev-badge sev-${card.severity.toLowerCase()}">${card.severity}</span>`;
  if (card.statusBadge) html += `<span class="em-sc-status-badge">${card.statusBadge}</span>`;
  html += '</div>';
  if (card.investigationStatus) html += `<div class="em-sc-status-text"><strong>${card.investigationStatus}</strong></div>`;
  // Hero chip row.
  // New (preferred): card.heroChips = [{label, value}, ...] — honest, schema-backed labels per entity type.
  // Legacy fallback: firstSeen / lastActivity (kept for non-user entities until each is reviewed).
  // Rationale: 'First Seen' from ES min(@timestamp) is silently truncated by log retention,
  // so it's misleading on its own — prefer a real DB-backed field per entity type.
  // See entity_data_mapping.md §1.1.
  html += '<div class="em-sc-time-row">';
  if (Array.isArray(card.heroChips) && card.heroChips.length) {
    card.heroChips.forEach(c => { html += `<span>${c.label}: ${c.value}</span>`; });
  } else {
    if (card.firstSeen)    html += `<span>First Seen: ${card.firstSeen}</span>`;
    if (card.lastActivity) html += `<span>Last Activity: ${card.lastActivity}</span>`;
  }
  html += '</div>';
  html += '</div>'; // sc-right
  html += '</div>'; // sc-hero

  // Metric strip
  html += '<div class="em-sc-metrics">';
  card.metrics.forEach(m => {
    let val = m.value;
    // Resolve dynamic metric values at render time.
    // 'lastAnomaly' ← LAST_ANOMALY_UPDATE_TIME from ITSEntityRiskScoreDetails.
    // (Previously this slot was 'Dwell Time' / timeSinceFirst, computed from card.firstSeen —
    //  but the schema has no FIRST_ANOMALY_TIME column, so that value was misleading.
    //  See entity_data_mapping.md §1.1 for the rationale.)
    if (!val && m.dynamic === 'lastAnomaly' && card.lastAnomaly) {
      val = _humanizeDelta(_parseEntityTs(card.lastAnomaly)) + ' ago';
    } else if (!val && m.dynamic === 'timeSinceFirst' && card.firstSeen) {
      val = _humanizeDelta(_parseEntityTs(card.firstSeen));
    }
    html += `<div class="em-sc-metric">`;
    html += `<span class="em-sc-metric-dot" style="background:${m.color};"></span>`;
    html += `<div class="em-sc-metric-body">`;
    html += `<span class="em-sc-metric-val" style="color:${m.color};">${val || '—'}</span>`;
    html += `<span class="em-sc-metric-lbl">${m.label}</span>`;
    html += `</div></div>`;
  });
  html += '</div>';

  html += '</div>'; // summary-card
  return html;
}

/* ─── Geo & Travel Analysis ─── */
function renderTravelMap(tm) {
  let html = '<div class="em-travel-map">';

  // Alert banner
  html += `<div class="em-travel-alert">${tm.alert}</div>`;

  // Vertical location flow
  html += '<div class="em-travel-flow">';
  tm.locations.forEach((loc, i) => {
    const trustCls = loc.trusted ? 'trusted' : 'suspicious';
    const tagCls = loc.trusted ? 'safe' : 'threat';
    const tagText = loc.trusted ? 'Trusted' : 'Suspicious';
    html += `<div class="em-travel-loc ${trustCls}">`;
    html += `<div class="em-travel-loc-dot"></div>`;
    html += `<div class="em-travel-loc-body">`;
    html += `<div class="em-travel-city">${loc.city} <span class="em-travel-city-tag ${tagCls}">${tagText}</span></div>`;
    html += `<div class="em-travel-detail">${loc.ip} · ${loc.type} · ${loc.time.split('  ')[1] || loc.time}</div>`;
    html += `</div></div>`;
    if (i < tm.locations.length - 1) {
      html += `<div class="em-travel-between">${tm.distance} in ${tm.timeDelta} <span class="em-travel-between-line"></span></div>`;
    }
  });
  html += '</div>';

  // Verdict box
  html += '<div class="em-travel-verdict">';
  html += `<div class="em-travel-verdict-row"><span class="em-travel-verdict-lbl">Speed</span><span class="em-travel-verdict-val critical">${tm.requiredSpeed}</span></div>`;
  html += `<div class="em-travel-verdict-row"><span class="em-travel-verdict-lbl">Verdict</span><span class="em-travel-verdict-val critical">${tm.verdict}</span></div>`;
  html += `<div class="em-travel-verdict-row"><span class="em-travel-verdict-lbl">VPN History</span><span class="em-travel-verdict-val">${tm.vpnHistory}</span></div>`;
  html += `<div class="em-travel-verdict-row"><span class="em-travel-verdict-lbl">New Geo</span><span class="em-travel-verdict-val critical">${tm.newGeo}</span></div>`;
  html += '</div>';

  html += '</div>';
  return html;
}

/* ─── Compliance Cards (Accordion) ─── */
function renderComplianceCards(cards) {
  let html = '<div class="em-compliance-list">';
  cards.forEach((card, i) => {
    const statusCls = card.status.includes('Violation') ? 'violation' :
                      card.status.includes('Non-Compliant') ? 'violation' :
                      card.status.includes('Notification') ? 'warning' : 'at-risk';
    const openCls = i === 0 ? ' cc-open' : '';
    html += `<div class="em-compliance-card${openCls}">`;
    html += `<div class="em-compliance-hdr" onclick="this.parentElement.classList.toggle('cc-open')">`;
    html += `<span class="em-compliance-fw">${card.framework}</span>`;
    html += `<span class="em-compliance-status ${statusCls}">${card.status}</span>`;
    html += `</div>`;
    html += `<div class="em-compliance-body">`;
    html += `<div class="em-compliance-impact">${card.impact}</div>`;
    html += `<div class="em-compliance-controls">`;
    card.controls.forEach(ctrl => {
      html += `<span class="em-compliance-ctrl">${ctrl}</span>`;
    });
    html += `</div></div></div>`;
  });
  html += '</div>';
  return html;
}

/* ─── Action Buttons ─── */
function renderActionButtons(buttons) {
  let html = '<div class="em-actions-wrap">';
  html += '<div class="em-actions-label">Quick Actions</div>';
  html += '<div class="em-actions-grid">';
  buttons.forEach(btn => {
    const sev = btn.severity || 'info';
    const desc = btn.desc || btn.label;
    html += `<button class="em-action-btn em-action-${sev}" onclick="executeEntityAction('${btn.action}')" title="${desc}">`;
    html += `<span class="em-action-icon">${btn.icon}</span>`;
    html += `<span class="em-action-label">${btn.label}</span>`;
    html += `</button>`;
  });
  html += '</div></div>';
  return html;
}

function executeEntityAction(action) {
  const labels = {
    disableAccount: '🔒 Disabling account in AD & Entra ID…',
    forcePasswordReset: '🔑 Forcing password reset & revoking tokens…',
    revokeMFA: '📱 Revoking all MFA sessions…',
    isolateEndpoint: '🖥 Isolating CORP-WS-045 via EDR agent…',
    blockIP: '🚫 Adding 185.220.101.42 to firewall deny list…',
    createIncident: '📋 Creating incident in ServiceDesk Plus…',
    forensicCapture: '🔍 Triggering forensic memory + disk capture…',
    notifyManager: '📧 Sending investigation summary to j.williams…'
  };
  showToast('▶', labels[action] || 'Executing action…');
}

/* ─── Peer Comparison (Visual bars) ─── */
function renderPeerComparison(pd) {
  let html = '<div class="em-peer-comparison">';
  html += `<div class="em-peer-group-label">${pd.group}</div>`;
  html += '<div class="em-peer-rows">';
  pd.comparison.forEach(row => {
    // Parse numeric values for bar widths
    const uVal = parseFloat(String(row.user).replace(/[^\d.]/g, '')) || 0;
    const aVal = parseFloat(String(row.peerAvg).replace(/[^\d.]/g, '')) || 0;
    const maxVal = Math.max(uVal, aVal, 1) * 1.15;
    const uPct = Math.min((uVal / maxVal) * 100, 100);
    const aPct = Math.min((aVal / maxVal) * 100, 100);
    const barCls = row.flag ? (uPct > 80 ? 'danger' : 'warn') : 'safe';

    html += '<div class="em-peer-row">';
    html += '<div class="em-peer-row-hdr">';
    html += `<span class="em-peer-row-metric">${row.metric}</span>`;
    html += '<span class="em-peer-row-vals">';
    html += `<span class="usr">${row.user}</span>`;
    html += `<span class="avg">avg ${row.peerAvg}</span>`;
    html += `<span class="dev${row.flag ? ' flag' : ''}">${row.deviation}</span>`;
    html += '</span></div>';
    html += '<div class="em-peer-bar-track">';
    html += `<div class="em-peer-bar-avg" style="width:${aPct.toFixed(0)}%;"></div>`;
    html += `<div class="em-peer-bar-user ${barCls}" style="width:${uPct.toFixed(0)}%;"></div>`;
    html += '</div></div>';
  });
  html += '</div></div>';
  return html;
}

/* ─── Remediation Guide (Verdict + Recommendations + Playbooks) ─── */

/* Type-level default playbooks. Merged in below the entity-specific ones
   so every node — even ones without a curated remediation list — still
   surfaces sensible standard runbooks for the analyst. */
const TYPE_DEFAULT_PLAYBOOKS = {
  user: [
    { id:'PB-USR-01', name:'Force-revoke all sessions',    desc:'Sign user out of every active session and require re-authentication.',          urgency:'High Priority',  status:'Ready', estimatedTime:'~30s' },
    { id:'PB-USR-02', name:'Disable AD / cloud account',   desc:'Disable the account in AD and the cloud directory; preserve for forensics.',     urgency:'Run Immediate',  status:'Ready', estimatedTime:'~1m'  },
    { id:'PB-USR-03', name:'Step-up MFA / reset password', desc:'Force password reset and enforce MFA on next login.',                            urgency:'Standard',       status:'Ready', estimatedTime:'~2m'  },
    { id:'PB-USR-04', name:'Audit trail (last 24h)',       desc:'Generate full logon, file-access and email audit for the user.',                 urgency:'Standard',       status:'Ready', estimatedTime:'~3m'  }
  ],
  device: [
    { id:'PB-DEV-01', name:'EDR isolate endpoint',         desc:'Network-isolate the device via EDR while preserving response channel.',          urgency:'Run Immediate',  status:'Ready', estimatedTime:'~30s' },
    { id:'PB-DEV-02', name:'Collect triage package',       desc:'Pull volatile memory, MFT, EDR telemetry and prefetch.',                         urgency:'High Priority',  status:'Ready', estimatedTime:'~10m' },
    { id:'PB-DEV-03', name:'Block C2 egress at firewall',  desc:'Add deny rules for any C2/Tor destinations seen on this host.',                  urgency:'High Priority',  status:'Ready', estimatedTime:'~1m'  },
    { id:'PB-DEV-04', name:'Schedule reimage',             desc:'Queue device for golden-image rebuild after triage data is captured.',           urgency:'Standard',       status:'Ready', estimatedTime:'~1h'  }
  ],
  ip: [
    { id:'PB-IP-01',  name:'Firewall block IP',            desc:'Add the IP to the perimeter / cloud-firewall deny list.',                        urgency:'Run Immediate',  status:'Ready', estimatedTime:'~30s' },
    { id:'PB-IP-02',  name:'Push to TI feed',              desc:'Submit indicator to local TI platform and update SIEM watchlists.',              urgency:'High Priority',  status:'Ready', estimatedTime:'~1m'  },
    { id:'PB-IP-03',  name:'Notify upstream / abuse',      desc:'Send abuse report to upstream ISP, hosting provider or anonymizer operator.',    urgency:'Standard',       status:'Ready', estimatedTime:'~5m'  }
  ],
  domain: [
    { id:'PB-DOM-01', name:'DNS sinkhole',                 desc:'Redirect resolution of this domain to an internal sinkhole IP.',                 urgency:'Run Immediate',  status:'Ready', estimatedTime:'~30s' },
    { id:'PB-DOM-02', name:'Add to deny-list',             desc:'Block the domain at the secure web gateway / DNS firewall.',                     urgency:'High Priority',  status:'Ready', estimatedTime:'~1m'  },
    { id:'PB-DOM-03', name:'Notify CERT / TI partners',    desc:'Share the IoC with sector CERT and TI sharing groups.',                          urgency:'Standard',       status:'Ready', estimatedTime:'~5m'  }
  ],
  service: [
    { id:'PB-SVC-01', name:'Revoke OAuth grants',          desc:'Revoke all OAuth/refresh tokens issued for this service or user.',               urgency:'Run Immediate',  status:'Ready', estimatedTime:'~1m'  },
    { id:'PB-SVC-02', name:'Rotate service secrets',       desc:'Rotate API keys, client secrets and certificates associated with this service.', urgency:'High Priority',  status:'Ready', estimatedTime:'~5m'  },
    { id:'PB-SVC-03', name:'Review consent grants',        desc:'Audit application consent grants and high-privilege role assignments.',          urgency:'Standard',       status:'Ready', estimatedTime:'~10m' }
  ],
  process: [
    { id:'PB-PRC-01', name:'Terminate process',            desc:'Kill the PID across all hosts where it is running.',                             urgency:'Run Immediate',  status:'Ready', estimatedTime:'~30s' },
    { id:'PB-PRC-02', name:'Hash to AV / EDR deny',        desc:'Add the executable hash to AV/EDR block-list.',                                  urgency:'High Priority',  status:'Ready', estimatedTime:'~1m'  },
    { id:'PB-PRC-03', name:'Block parent path',            desc:'Add an EDR rule to block this binary path from launching.',                      urgency:'Standard',       status:'Ready', estimatedTime:'~2m'  }
  ],
  alert: [
    { id:'PB-ALR-01', name:'Open IR ticket',               desc:'Create an incident in the IR platform with this alert as the seed event.',       urgency:'High Priority',  status:'Ready', estimatedTime:'~1m'  },
    { id:'PB-ALR-02', name:'Suppress similar (24h)',       desc:'Auto-suppress identical alerts for the next 24 hours to reduce noise.',          urgency:'Standard',       status:'Ready', estimatedTime:'~30s' },
    { id:'PB-ALR-03', name:'Mark as TP / FP',              desc:'Tag the alert verdict so the detection model can learn.',                        urgency:'Standard',       status:'Ready', estimatedTime:'~30s' }
  ]
};

function mergePlaybooksWithDefaults(playbooks, entityId) {
  const e = (typeof ENTITIES !== 'undefined') ? ENTITIES[entityId] : null;
  const defaults = (e && TYPE_DEFAULT_PLAYBOOKS[e.type]) || [];
  if (!defaults.length) return playbooks || [];
  const seen = new Set();
  const merged = [];
  (playbooks || []).forEach(p => {
    const k = (p.id || p.name || '').toLowerCase();
    if (k && !seen.has(k)) { seen.add(k); merged.push(p); }
  });
  defaults.forEach(p => {
    const k = (p.id || p.name || '').toLowerCase();
    if (!seen.has(k)) { seen.add(k); merged.push({ ...p, _default: true }); }
  });
  return merged;
}

function renderRemediationGuide(rd, entityId) {
  let html = '<div class="em-remediation-guide">';
  // Verdict banner
  html += `<div class="em-rg-verdict ${rd.severity}">`;
  html += `<span class="em-rg-verdict-dot"></span>`;
  html += `${rd.verdict}`;
  html += `</div>`;
  // Recommendations
  if (rd.recommendations && rd.recommendations.length > 0) {
    html += `<div class="em-rg-sub-title"><span class="rg-icon">💡</span> Recommendations</div>`;
    html += '<div class="em-rg-rec-list">';
    rd.recommendations.forEach(rec => {
      html += '<div class="em-rg-rec">';
      html += `<span class="em-rg-rec-icon">${rec.icon}</span>`;
      html += '<div class="em-rg-rec-body">';
      html += `<div class="em-rg-rec-title">${rec.title} <span class="em-rg-rec-priority ${rec.priority}">${rec.priority}</span></div>`;
      html += `<div class="em-rg-rec-desc">${rec.desc}</div>`;
      html += '</div></div>';
    });
    html += '</div>';
  }
  // Playbooks (only the curated, entity-specific ones for normal entities;
  // type-defaults are reserved for PREDICTED entities in the prediction
  // slider where pre-emptive runbooks are most actionable)
  if (rd.playbooks && rd.playbooks.length > 0) {
    html += `<div class="em-rg-sub-title"><span class="rg-icon">▶</span> Available Playbooks <span class="em-rg-pb-count">(${rd.playbooks.length})</span></div>`;
    html += '<div class="em-rg-playbooks">';
    rd.playbooks.forEach(pb => {
      html += '<div class="em-rg-pb">';
      html += '<div class="em-rg-pb-info">';
      html += `<div class="em-rg-pb-name">${pb.name} <span class="em-rg-pb-id">${pb.id}</span></div>`;
      html += `<div class="em-rg-pb-desc">${pb.desc}</div>`;
      html += '<div class="em-rg-pb-meta">';
      if (pb.urgency) {
        const urgCls = pb.urgency === 'Run Immediate' ? 'urg-immediate' : pb.urgency === 'High Priority' ? 'urg-high' : 'urg-standard';
        html += `<span class="em-rg-pb-badge ${urgCls}">${pb.urgency}</span>`;
      }
      html += `<span class="em-rg-pb-badge ready">● ${pb.status}</span>`;
      html += `<span class="em-rg-pb-badge time">⏱ ${pb.estimatedTime}</span>`;
      html += '</div></div>';
      html += `<button class="em-rg-pb-run" onclick="if(typeof showToast==='function')showToast('▶','Running ${pb.name}…')">▶ Run</button>`;
      html += '</div>';
    });
    html += '</div>';
  } else if (rd.playbooks !== undefined && rd.playbooks.length === 0) {
    html += `<div class="em-rg-sub-title"><span class="rg-icon">▶</span> Available Playbooks</div>`;
    html += '<div class="em-rg-no-playbooks">No automated playbooks required for this entity.</div>';
  }
  html += '</div>';
  return html;
}

/* View All — opens the slider with full expanded data for that section */
function viewAllSection(entityId, secKey) {
  const e = ENTITIES[entityId];
  if (!e || !e.sections || !e.sections[secKey]) return;
  const sec = e.sections[secKey];

  // Determine which tab contains this section so Back returns to the right tab
  const tabConfig = {
    user: [
      { id:'overview', sections:['riskSummary','usersDetails','responseActions'] },
      { id:'risk', sections:['uebaProfile','loginStatistics','peerComparison','cloudIdentities','identityRisk'] },
      { id:'activity', sections:['logonActivity','geoTravelAnalysis','networkActivity','processes','serviceTriggered','resourceFileAccess'] },
      { id:'threats', sections:['recentAlerts','threatIntelContext','dlpIncidents','endpointSecurity','attackPathContext'] }
    ]
  };
  let returnTabId = null;
  const entityType = e.type;
  if (tabConfig[entityType]) {
    for (const tab of tabConfig[entityType]) {
      if (tab.sections.includes(secKey)) { returnTabId = tab.id; break; }
    }
  }

  document.getElementById('edsTitle').textContent = sec.label + ' — All Records';
  const body = document.getElementById('edsBody');
  let html = '';

  // Back link — returns to same tab and scrolls to the section
  html += `<div style="padding:12px 20px;border-bottom:1px solid var(--border);">`;
  if (returnTabId) {
    html += `<a class="em-link" style="margin:0;font-size:12px;" onclick="openEntitySlider('${entityId}');setTimeout(function(){navigateToTabSection('${entityId}','${returnTabId}','${secKey}')},50)">← Back</a>`;
  } else {
    html += `<a class="em-link" style="margin:0;font-size:12px;" onclick="openEntitySlider('${entityId}')">← Back</a>`;
  }
  html += `</div>`;

  // Render all data — prefer viewAllData if available
  const data = sec.viewAllData || sec.timeline || null;
  if (data && data.length) {
    html += `<div style="padding:0 20px 14px;">`;
    html += renderTimelineEntries(data);
    html += `</div>`;
  } else if (sec.kv) {
    html += `<div style="padding:12px 20px;">`;
    html += `<table class="em-kv-table">`;
    Object.entries(sec.kv).forEach(([k, v]) => {
      html += `<tr><td>${k}</td><td>${v}</td></tr>`;
    });
    html += `</table></div>`;
  } else {
    html += `<div style="padding:20px;color:var(--text-dim);font-size:12px;">No records available.</div>`;
  }

  body.innerHTML = html;
}

/* View On Graph — find existing node by ID or label, else create new one */
function viewOnGraph(targetNodeId, nodeLabel, nodeIcon, sourceEntityId, isMalicious) {
  // Determine category from nodeId prefix for color selection
  const cat = targetNodeId.startsWith('svc-') ? 'service'
            : targetNodeId.startsWith('proc-') ? 'process'
            : targetNodeId.startsWith('alert-') ? 'alert' : 'process';
  // Color palettes per category
  const palette = isMalicious
    ? { stroke:'#ef4444', text:'#dc2626', edgeClass:'graph-edge-mal', bg:'#fef2f2', edgeLabel:'EXECUTED_BY' }
    : cat === 'service'
      ? { stroke:'#0891b2', text:'#0891b2', edgeClass:'graph-edge-norm', bg:'#ecfeff', edgeLabel:'TRIGGERED' }
      : cat === 'alert'
        ? { stroke:'#ef4444', text:'#dc2626', edgeClass:'graph-edge-mal', bg:'#fef2f2', edgeLabel:'INVOLVED_IN' }
        : { stroke:'#16a34a', text:'#16a34a', edgeClass:'graph-edge-norm', bg:'#f0fdf4', edgeLabel:'EXECUTED' };

  // 1. Try to find by exact data-entity ID
  let existingNode = document.querySelector(`#graphSvg g.graph-node[data-entity="${targetNodeId}"]`);
  // 2. If not found, search by label text (handles ctx-created nodes like proc-ctx-*)
  if (!existingNode && nodeLabel) {
    existingNode = findNodeByLabel(nodeLabel);
  }

  if (existingNode) {
    // Node exists — highlight with pulse
    document.querySelectorAll('#graphSvg g.graph-node').forEach(n => n.style.opacity = '0.3');
    existingNode.style.opacity = '1';
    existingNode.style.transition = 'transform 0.3s ease';
    existingNode.style.transform = 'scale(1.4)';
    if (sourceEntityId) {
      const srcNode = document.querySelector(`#graphSvg g.graph-node[data-entity="${sourceEntityId}"]`);
      if (srcNode) srcNode.style.opacity = '1';
    }
    setTimeout(() => {
      existingNode.style.transform = 'scale(1)';
      setTimeout(() => {
        document.querySelectorAll('#graphSvg g.graph-node').forEach(n => n.style.opacity = '1');
      }, 800);
    }, 600);
    showToast('📍', `Highlighting ${nodeLabel || targetNodeId} on graph`);
  } else {
    // Create new node with collision-free positioning
    const svg = document.getElementById('graphSvg');
    if (!svg) return;
    const ns = 'http://www.w3.org/2000/svg';
    let srcCx = 480, srcCy = 260;
    if (sourceEntityId) {
      const srcCircle = document.querySelector(`#graphSvg g.graph-node[data-entity="${sourceEntityId}"] circle:not(.expand-indicator)`);
      if (srcCircle) { srcCx = parseFloat(srcCircle.getAttribute('cx')); srcCy = parseFloat(srcCircle.getAttribute('cy')); }
    }

    const pos = findFreePosition(srcCx, srcCy, 0, 1, -0.3);
    const cx = pos.cx, cy = pos.cy;
    const firstG = svg.querySelector('g.graph-node');

    // Edge
    const edge = document.createElementNS(ns, 'line');
    edge.setAttribute('x1', srcCx); edge.setAttribute('y1', srcCy);
    edge.setAttribute('x2', cx); edge.setAttribute('y2', cy);
    edge.setAttribute('class', palette.edgeClass);
    edge.setAttribute('data-source', sourceEntityId || 'unknown');
    edge.setAttribute('data-target', targetNodeId);
    edge.setAttribute('data-label', palette.edgeLabel);
    edge.style.opacity = '0';
    if (firstG) svg.insertBefore(edge, firstG); else svg.appendChild(edge);

    // Register display info for popup
    if (!ENTITY_DISPLAY[targetNodeId]) {
      ENTITY_DISPLAY[targetNodeId] = {
        icon: nodeIcon || '⚙',
        name: nodeLabel || targetNodeId.replace(/-/g, ' '),
        color: palette.stroke,
        bg: palette.bg
      };
    }

    const edgeLbl = document.createElementNS(ns, 'text');
    edgeLbl.setAttribute('x', (srcCx + cx) / 2); edgeLbl.setAttribute('y', (srcCy + cy) / 2 - 6);
    edgeLbl.setAttribute('text-anchor', 'middle'); edgeLbl.setAttribute('font-size', '8');
    edgeLbl.setAttribute('fill', palette.text); edgeLbl.setAttribute('font-family', 'IBM Plex Mono,monospace');
    edgeLbl.setAttribute('style', 'paint-order:stroke fill;stroke:#f5f7fa;stroke-width:3px;');
    edgeLbl.setAttribute('data-source', sourceEntityId || 'unknown');
    edgeLbl.setAttribute('data-target', targetNodeId);
    edgeLbl.textContent = palette.edgeLabel;
    edgeLbl.style.opacity = '0';
    if (firstG) svg.insertBefore(edgeLbl, firstG); else svg.appendChild(edgeLbl);

    const g = document.createElementNS(ns, 'g');
    g.setAttribute('class', 'graph-node'); g.setAttribute('data-entity', targetNodeId);
    g.setAttribute('onclick', `openEntitySlider('${targetNodeId}')`);
    g.setAttribute('oncontextmenu', `showGraphCtx(event,'${targetNodeId}')`);

    const circle = document.createElementNS(ns, 'circle');
    circle.setAttribute('cx', cx); circle.setAttribute('cy', cy); circle.setAttribute('r', '20');
    circle.setAttribute('fill', '#ffffff'); circle.setAttribute('stroke', palette.stroke);
    circle.setAttribute('stroke-width', '2');
    if (isMalicious) circle.setAttribute('filter', 'url(#glow-r)');

    const icon = document.createElementNS(ns, 'text');
    icon.setAttribute('x', cx); icon.setAttribute('y', cy + 4);
    icon.setAttribute('text-anchor', 'middle'); icon.setAttribute('font-size', '14');
    icon.setAttribute('dominant-baseline', 'central');
    icon.textContent = nodeIcon || '⚙';

    const label = document.createElementNS(ns, 'text');
    label.setAttribute('x', cx); label.setAttribute('y', cy + 30);
    label.setAttribute('text-anchor', 'middle'); label.setAttribute('font-size', '10');
    label.setAttribute('fill', palette.text); label.setAttribute('font-family', 'Lato,sans-serif');
    label.setAttribute('font-weight', '600');
    label.textContent = nodeLabel || targetNodeId.replace(/-/g, ' ');

    g.appendChild(circle); g.appendChild(icon); g.appendChild(label);
    svg.appendChild(g);

    // Make the dynamically-created node draggable
    makeNodeDraggable(g, circle, icon, label, targetNodeId);

    registerNode(targetNodeId, nodeLabel);

    // NOTE: viewOnGraph nodes are intentionally NOT tracked in drillDownGroups.
    // They are standalone nodes. If the user later expands the full category
    // via right-click (e.g. "Processes"), branchChildNodes will absorb
    // existing viewOnGraph nodes into the group for proper collapse.

    // Animate
    g.style.opacity = '0'; edge.style.opacity = '0'; edgeLbl.style.opacity = '0';
    requestAnimationFrame(() => {
      g.style.transition = 'opacity 0.5s ease';
      edge.style.transition = 'opacity 0.5s ease 0.2s';
      edgeLbl.style.transition = 'opacity 0.5s ease 0.3s';
      g.style.opacity = '1'; edge.style.opacity = '0.7'; edgeLbl.style.opacity = '1';
    });

    document.querySelectorAll('#graphSvg g.graph-node').forEach(n => { if (n !== g) n.style.opacity = '0.3'; });
    g.style.opacity = '1';
    if (sourceEntityId) {
      const srcG = document.querySelector(`#graphSvg g.graph-node[data-entity="${sourceEntityId}"]`);
      if (srcG) srcG.style.opacity = '1';
    }
    setTimeout(() => { document.querySelectorAll('#graphSvg g.graph-node').forEach(n => n.style.opacity = '1'); }, 2000);

    showToast('✦', `${nodeLabel || targetNodeId} node created — linked to ${sourceEntityId ? sourceEntityId.replace(/-/g,' ') : 'graph'}`);
    updateGraphSummary();
  }
}

