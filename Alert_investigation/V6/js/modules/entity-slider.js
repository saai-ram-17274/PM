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
  if (typeof _blastHL !== 'undefined') _blastHL = null;
  document.querySelectorAll('.graph-node').forEach(n => { n.style.opacity = ''; n.classList.remove('active-focus', 'blast-reach'); });
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

  // Define tab groupings per entity type.
  // Tabs follow the analyzed entity-slider specs (Attack vector/*_entity_spec.md):
  // each entity exposes a fixed 4-tab shape. Within each tab, sections are ordered
  // Baseline-first; Enriched sub-sections (see enrichedByType below) only render
  // after "Investigate Entity" (isAiInvestigated()).
  const tabConfig = {
    // User: Overview | Authentication Activity | Account Activity | Recent Alerts
    user: [
      // Overview per user_entity_spec.md §3.2/§3.3: UB1 Risk Summary KPIs, UB2 tiered
      // identity card, UE1 UEBA Risk Profile, UE12 Privileged Action Surface, UE7 Effective
      // Group Memberships, UE8 Direct Reports & Manager Chain, UE3 Dark Web / Breach Exposure.
      // (blastRadius + remediationGuide are V6 UX/AI overlays kept at the tail.)
      { id:'overview', label:'Overview', sections:['riskSummary','usersDetails','uebaProfile','privilegedSurface','effectiveGroups','directReports','darkWebExposure','blastRadius','remediationGuide'] },
      { id:'auth', label:'Authentication Activity', sections:['loginStatistics','logonActivity','accountLockouts'] },
      { id:'account', label:'Account Activity', sections:['passwordHistory','groupMembershipChanges','privilegedRoleChanges','processes','serviceTriggered','resourceFileAccess','recentAppAccess','mailboxForwarding','networkActivity'] },
      { id:'recentAlerts', label:'Recent Alerts', sections:['recentAlerts'] }
    ],
    // Device: Overview | Host Activity | Device Activity | Recent Alerts
    device: [
      { id:'overview', label:'Overview', sections:['riskSummary','deviceDetails','agentStatus','gpoApplied','blastRadius','remediationGuide'] },
      { id:'host', label:'Host Activity', sections:['usersLoggedOn','loginActivity','processesOnHost','servicesOnHost','securityEventSummary'] },
      { id:'device', label:'Device Activity', sections:['localAccountLifecycle','scheduledTasks','usbDeviceEvents'] },
      { id:'recentAlerts', label:'Recent Alerts', sections:['recentAlerts'] }
    ],
    // IP: Overview | Activity | Asset Profile (internal-only) | Recent Alerts
    // Baseline-first per ip_entity_spec.md §3.2: Overview = IB1 Risk Summary,
    // IB2 IP Identity Card, IB4 Top Peers (associated users/devices). IB5 Recent
    // Alerts lives in its own tab. Enriched (TI IE1/IE2, Geo IE8) trail in Overview;
    // connection/dns/ids/auth/vpn enriched (IE3–IE6, IE9–IE12) sit under Activity.
    ip: [
      { id:'overview', label:'Overview', sections:['riskSummary','ipDetails','associatedUsers','associatedDevices','threatIntelligence','geoContext','remediationGuide'] },
      { id:'activity', label:'Activity', sections:['connectionHistory','firewallSummary','trafficSummary','dnsHistory','idsAlerts','logonActivity','vpnSessions'] },
      { id:'asset', label:'Asset Profile', sections:['assetProfile'] },
      { id:'recentAlerts', label:'Recent Alerts', sections:['recentAlerts'] }
    ],
    // Domain: Overview | Activity | Configuration & Policy (internal-only) | Recent Alerts
    domain: [
      { id:'overview', label:'Overview', sections:['riskSummary','ipDetails','threatIntelligence','geoContext','associatedUsers','associatedDevices','remediationGuide'] },
      { id:'activity', label:'Activity', sections:['connectionHistory','dnsHistory','idsAlerts','logonActivity','trafficSummary','vpnSessions'] },
      { id:'config', label:'Configuration & Policy', sections:['trustTopology','dcInventory','passwordPolicy'] },
      { id:'recentAlerts', label:'Recent Alerts', sections:['recentAlerts'] }
    ],
    // Service account: Overview | Activity | Configuration & Policy | Recent Alerts
    service: [
      { id:'overview', label:'Overview', sections:['riskSummary','serviceDetails','serviceInfo'] },
      { id:'activity', label:'Activity', sections:['signInAudit','adminActivity','fileAccessAnomaly','sensitiveFiles','serviceTimeline','networkConnections','fileDrops','processes','serviceTriggered'] },
      { id:'config', label:'Configuration & Policy', sections:['oauthConsentGrants','conditionalAccess','dlpPolicies','serviceDependencies'] },
      { id:'recentAlerts', label:'Recent Alerts', sections:['recentAlerts'] }
    ],
    // Process: Overview | Activity | Threat Intel | Recent Alerts
    process: [
      { id:'overview', label:'Overview', sections:['processDetails','processTree','childProcesses'] },
      { id:'activity', label:'Activity', sections:['networkActivity','fileOperations','registryModifications','amsiEvents'] },
      { id:'threat', label:'Threat Intel', sections:['serviceTriggered'] },
      { id:'recentAlerts', label:'Recent Alerts', sections:['recentAlerts'] }
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

  // NOTE: Baseline vs Enriched gating is NOT done here. Every section is
  // rendered into the DOM (each as #em-<key>); the v6-attack-vector
  // applyBaselineFilter() / investigateCurrentEntity() layer toggles their
  // display + hides empty tabs after the slider opens. Skipping render here
  // would leave nothing for "Investigate entity" to reveal.

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

  // Blast radius / asset exposure (AD attack graph — 18-relation taxonomy)
  // Only available once the AI investigation has run (Start Investigation).
  if (sec.blastRadius && (typeof isAiInvestigated === 'function' && isAiInvestigated())) {
    html += renderBlastRadius(sec.blastRadius, entityId);
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

/* ─── Blast Radius / Asset Exposure (AD attack graph) ───
 * Edge taxonomy ported from the execution plan's 18-relation model
 * (PrivilegedAssuranceConstants.java). `cls` drives the pill colour;
 * `desc` is the hover tooltip; `mitre` is the default technique when a
 * hop does not override it. Two traversal directions are rendered:
 *   outgoing  = Blast Radius   (if this principal is compromised, what falls)
 *   incoming  = Asset Exposure (who can compromise this principal)
 */
const AD_RELATIONS = {
  MEMBEROF:             { label:'MemberOf',           cls:'rel-member', desc:'Group membership (transitive)' },
  OWNS:                 { label:'Owns',               cls:'rel-own',    desc:'Object owner — implicit WriteDACL' },
  WRITE_DACL:           { label:'WriteDacl',          cls:'rel-acl',    desc:'Can rewrite the DACL → grant self any right' },
  WRITE_OWNER:          { label:'WriteOwner',         cls:'rel-acl',    desc:'Can take ownership of the object' },
  GENERIC_ALL:          { label:'GenericAll',         cls:'rel-acl',    desc:'Full control over the object' },
  GENERIC_WRITE:        { label:'GenericWrite',       cls:'rel-acl',    desc:'Write any non-protected attribute' },
  ADD_MEMBER:           { label:'AddMember',          cls:'rel-acl',    desc:'Can add members to the group' },
  RESET_PASSWORD:       { label:'ForceChangePassword',cls:'rel-cred',   desc:"Can reset the principal's password", mitre:'T1098' },
  WRITE_SPN:            { label:'WriteSPN',           cls:'rel-cred',   desc:'Can set an SPN → Kerberoast', mitre:'T1558.003' },
  EXTENDED_RIGHTS:      { label:'ExtendedRight',      cls:'rel-acl',    desc:'Control-access right (e.g. DS-Replication)' },
  DC_SYNC_RIGHTS:       { label:'DCSync',             cls:'rel-crit',   desc:'Replicating Directory Changes (All) → dump domain hashes', mitre:'T1003.006' },
  GRANT_ALLOWED_TO_ACT: { label:'GrantAllowedToAct',  cls:'rel-acl',    desc:'Can grant RBCD on the target', mitre:'T1550.003' },
  ADD_KEY_CREDENTIAL:   { label:'AddKeyCredential',   cls:'rel-cred',   desc:'Shadow Credentials — write msDS-KeyCredentialLink', mitre:'T1556.007' },
  ALLOWED_TO_ACT:       { label:'AllowedToAct',       cls:'rel-deleg',  desc:'RBCD configured — impersonate any user on target', mitre:'T1550.003' },
  ALLOWED_TO_DELEGATE:  { label:'AllowedToDelegate',  cls:'rel-deleg',  desc:'Constrained delegation to target SPN' },
  HAS_SID_HISTORY:      { label:'HasSIDHistory',      cls:'rel-deleg',  desc:"Carries another principal's SID in history", mitre:'T1134.005' },
  TRUST:                { label:'Trust',              cls:'rel-trust',  desc:'Cross-domain / forest trust edge' },
  RODC_MANAGE:          { label:'RODCManage',         cls:'rel-trust',  desc:'Manages an RODC (managedBy)' }
};

function renderBlastRadius(br, entityId) {
  const id = 'br-' + (entityId || 'x');
  const s = br.stats || {};
  let html = `<div class="em-blast" id="${id}">`;

  // Alert-resolved seed banner (execution-plan Step 6: ENTITY_ID → UNIQUE_ID)
  if (br.seed) {
    html += `<div class="em-blast-seed">`;
    html += `<span class="em-blast-seed-ico">🎯</span>`;
    html += `<span class="em-blast-seed-name">${br.seed.name}</span>`;
    html += `<span class="em-blast-seed-meta">${br.seed.type}${br.seed.domain ? ' · ' + br.seed.domain : ''}${br.seed.tier ? ' · ' + br.seed.tier : ''}</span>`;
    html += `</div>`;
  }

  // Stat chips
  html += `<div class="em-blast-stats">`;
  if (s.outgoingPaths != null) html += `<span class="em-blast-stat"><strong>${s.outgoingPaths}</strong> blast paths</span>`;
  if (s.incomingPaths != null) html += `<span class="em-blast-stat"><strong>${s.incomingPaths}</strong> exposure paths</span>`;
  if (s.crownJewels != null)   html += `<span class="em-blast-stat">💎 <strong>${s.crownJewels}</strong> crown jewels</span>`;
  if (s.minHops != null)       html += `<span class="em-blast-stat">min hops <strong>${s.minHops}</strong></span>`;
  if (s.tier0Reached)          html += `<span class="em-blast-stat crit">⚠ reaches Tier 0</span>`;
  html += `</div>`;

  // Direction toggle
  const nOut = (br.outgoing || []).length, nIn = (br.incoming || []).length;
  html += `<div class="em-blast-toggle">`;
  html += `<button class="em-blast-tg active" data-tg="out" onclick="switchBlastDir('${id}','out',this)">⬇ Blast Radius${nOut ? ` (${nOut})` : ''}</button>`;
  html += `<button class="em-blast-tg" data-tg="in" onclick="switchBlastDir('${id}','in',this)">⬆ Asset Exposure${nIn ? ` (${nIn})` : ''}</button>`;
  html += `</div>`;

  const seedName = br.seed ? br.seed.name : 'this entity';
  html += `<div class="em-blast-hint" data-dir="out">If <strong>${seedName}</strong> is compromised, these AD objects fall:</div>`;
  html += `<div class="em-blast-hint" data-dir="in" style="display:none;">Principals that can take over <strong>${seedName}</strong>:</div>`;
  html += `<div class="em-blast-paths" data-dir="out">${renderBlastPaths(br.outgoing, 'out')}</div>`;
  html += `<div class="em-blast-paths" data-dir="in" style="display:none;">${renderBlastPaths(br.incoming, 'in')}</div>`;

  html += `</div>`;
  return html;
}

function renderBlastPaths(paths, dir) {
  if (!paths || !paths.length) {
    return `<div class="em-blast-empty">No ${dir === 'out' ? 'blast-radius' : 'asset-exposure'} paths computed for this seed.</div>`;
  }
  let html = '';
  paths.forEach((p, idx) => {
    const crown = p.crownJewel ? ' crown' : '';
    const endLabel = dir === 'out' ? (p.target || '') : (p.source || '');
    html += `<div class="em-blast-path${crown}">`;
    html += `<div class="em-blast-path-hdr">`;
    html += `<span class="em-blast-path-n">#${idx + 1}</span>`;
    html += `<span class="em-blast-path-end">${dir === 'out' ? '→ ' + endLabel : endLabel + ' →'}</span>`;
    if (p.crownJewel) html += `<span class="em-blast-crown">💎 Crown Jewel</span>`;
    html += `<span class="em-blast-hops">${p.hops.length} hop${p.hops.length > 1 ? 's' : ''}</span>`;
    html += `</div>`;
    html += `<div class="em-blast-chain">`;
    p.hops.forEach((h, i) => {
      if (i === 0) html += `<span class="em-blast-node">${h.from}</span>`;
      const rel = AD_RELATIONS[h.rel] || { label: h.rel, cls: 'rel-acl', desc: '' };
      const mitre = h.mitre || rel.mitre;
      html += `<span class="em-blast-edge">`;
      html += `<span class="em-blast-rel ${rel.cls}" title="${rel.desc}">${rel.label}</span>`;
      if (mitre) html += `<span class="em-blast-mitre">${mitre}</span>`;
      html += `</span>`;
      const isLast = i === p.hops.length - 1;
      html += `<span class="em-blast-node${isLast && p.crownJewel ? ' crown-node' : ''}">${h.to}</span>`;
    });
    html += `</div>`;
    html += `</div>`;
  });
  return html;
}

function switchBlastDir(id, dir, btn) {
  const root = document.getElementById(id);
  if (!root) return;
  root.querySelectorAll('.em-blast-tg').forEach(b => b.classList.toggle('active', b === btn));
  root.querySelectorAll('.em-blast-hint, .em-blast-paths').forEach(el => {
    el.style.display = el.getAttribute('data-dir') === dir ? '' : 'none';
  });
}

/* ═══════════════ BLAST RADIUS — EXPAND INTO THE LIVE GRAPH ═══════════════
   Right-click an entity → "💥 Blast Radius". Grows the entity's AD
   blast-radius paths as REAL graph nodes/edges branching out from the
   node — exactly like the existing drill-down expansion (branchChildNodes).
   A second click collapses them again. Only the OUTGOING AD radius is shown:
   asset-exposure (incoming) describes the attack-vector's start/target, not
   an entity-scoped concept, so it is intentionally omitted here. */

const _BLAST_REL_COLOR = {
  'rel-member': '#6366f1',
  'rel-own':    '#7c3aed',
  'rel-acl':    '#d97706',
  'rel-cred':   '#ea580c',
  'rel-crit':   '#dc2626',
  'rel-deleg':  '#0891b2',
  'rel-trust':  '#16a34a'
};

/* Relation-class → midpoint icon (mirrors the existing graph's edge-info-btn glyphs). */
const _BLAST_REL_ICON = {
  'rel-member': '👥',
  'rel-own':    '👤',
  'rel-acl':    '🔑',
  'rel-cred':   '🔓',
  'rel-crit':   '🚨',
  'rel-deleg':  '🎭',
  'rel-trust':  '🤝'
};

/* cls → MITRE tactic (used to build attr.mitre for the relation slider). */
const _BLAST_REL_TACTIC = {
  'rel-cred':  { tactic:'Credential Access', tacticId:'TA0006' },
  'rel-crit':  { tactic:'Credential Access', tacticId:'TA0006' },
  'rel-deleg': { tactic:'Lateral Movement',  tacticId:'TA0008' },
  'rel-trust': { tactic:'Lateral Movement',  tacticId:'TA0008' },
  'rel-acl':   { tactic:'Privilege Escalation', tacticId:'TA0004' },
  'rel-member':{ tactic:'Privilege Escalation', tacticId:'TA0004' },
  'rel-own':   { tactic:'Privilege Escalation', tacticId:'TA0004' }
};

/* Register the 18 AD relations into REL_GUIDE once, so blast edges open the
   same relation slider (icon / colour / description) as native graph edges. */
function _ensureBlastRelGuide() {
  if (typeof REL_GUIDE === 'undefined' || _ensureBlastRelGuide._done) return;
  _ensureBlastRelGuide._done = true;
  Object.values(AD_RELATIONS).forEach(meta => {
    if (REL_GUIDE.some(r => r.key === meta.label)) return;
    REL_GUIDE.push({
      key: meta.label,
      category: 'Active Directory',
      color: _BLAST_REL_COLOR[meta.cls] || '#64748b',
      icon: _BLAST_REL_ICON[meta.cls] || '🔗',
      name: meta.label,
      desc: meta.desc || 'Active Directory privileged relationship.'
    });
  });
}

function _blastIcon(label, type) {
  if (type === 'user') return '👤';
  if (type === 'device') return '💻';
  const l = (label || '').toLowerCase();
  if (/corp\.local|domain|forest|contoso|\bdc\b/.test(l)) return '🏛';
  if (/svc|backup|sql|monitor|service/.test(l)) return '⚙';
  if (/admin|support|editor|users|group|operators/.test(l)) return '👥';
  if (/ou=|ou-/.test(l)) return '📁';
  if (/ws-|corp-|srv|host|\$$/.test(l)) return '💻';
  return '🔹';
}

/* Toast that never throws even if the global toast container is absent. */
function _blastToast(icon, msg) {
  try { if (typeof showToast === 'function' && document.getElementById('toast')) showToast(icon, msg); } catch (_) {}
}

/* ──────────────────────────────────────────────────────────────────────────
   AD object categorisation — used both by the context menu (to list the
   categories present) and by the on-graph expansion.
   ────────────────────────────────────────────────────────────────────────── */
const _AD_CAT_META = {
  group:    { icon: '👥', label: 'Groups' },
  account:  { icon: '⚙', label: 'Service Accounts' },
  computer: { icon: '💻', label: 'Computers' },
  ou:       { icon: '📁', label: 'Organizational Units' },
  data:     { icon: '📄', label: 'Data Assets' },
  domain:   { icon: '🏛', label: 'Domain / DC' }
};
const _AD_CAT_ORDER = ['group', 'account', 'computer', 'ou', 'data', 'domain'];

/* Infer the AD object category from its label. Order matters: group keywords
   (admin/editor/…) are checked before computer so "WS-Local-Admins" → group. */
function _adCategory(label) {
  const l = (label || '').toLowerCase();
  if (/\bou\b|ou=|^ou-|organizational unit/.test(l)) return 'ou';
  if (/^svc[-_]|service account/.test(l)) return 'account';
  if (/admin|editor|support|operators|\busers\b|local-admins|domain admins|\bgroup\b|-admins|gpo-edit/.test(l)) return 'group';
  if (/ws-|srv|-pc|\$$|desktop|laptop|server|host|corp-ws|corp-srv/.test(l)) return 'computer';
  if (/sensitive|finance|sharepoint|file|\bdata\b|secret/.test(l)) return 'data';
  if (/corp\.local|\.local|forest|\bdc\b|domain controller/.test(l)) return 'domain';
  return 'group';
}

/* Collect the distinct AD objects from the outgoing paths, grouped by category.
   Each object keeps the relation it is reached by and its parent (`from`). */
function _blastCollectAD(br) {
  const cats = {};
  (br.outgoing || []).forEach(p => {
    (p.hops || []).forEach((hop, hi) => {
      const isLast = hi === p.hops.length - 1;
      const cat = _adCategory(hop.to);
      const meta = AD_RELATIONS[hop.rel] || { label: hop.rel, cls: 'rel-acl', desc: '' };
      const list = (cats[cat] = cats[cat] || []);
      let obj = list.find(o => o.label === hop.to);
      if (!obj) {
        list.push({ label: hop.to, from: hop.from, rel: hop.rel, meta,
          mitre: hop.mitre || meta.mitre, crown: !!(isLast && p.crownJewel) });
      } else if (isLast && p.crownJewel) {
        obj.crown = true;
      }
    });
  });
  return cats;
}

/* Categories present for an entity — consumed by the context menu. */
function blastADCategories(eid) {
  const e = eid && ENTITIES[eid];
  const br = e && e.sections && e.sections.blastRadius && e.sections.blastRadius.blastRadius;
  if (!br) return [];
  const cats = _blastCollectAD(br);
  return _AD_CAT_ORDER.filter(c => cats[c] && cats[c].length).map(c => ({
    cat: c, icon: _AD_CAT_META[c].icon, label: _AD_CAT_META[c].label, count: cats[c].length
  }));
}

/* Angle pointing from the existing node-cluster centroid out towards (px,py),
   so new objects radiate into open canvas. */
function _outwardAngle(svg, px, py) {
  let cgx = 0, cgy = 0, n = 0;
  svg.querySelectorAll('g.graph-node:not([data-blast]) circle:not(.expand-indicator)').forEach(c => {
    cgx += parseFloat(c.getAttribute('cx')); cgy += parseFloat(c.getAttribute('cy')); n++;
  });
  if (n) { cgx /= n; cgy /= n; }
  return (n && (Math.abs(px - cgx) > 1 || Math.abs(py - cgy) > 1))
    ? Math.atan2(py - cgy, px - cgx)
    : Math.atan2(py - 350, px - 600);
}

/* ──────────────────────────────────────────────────────────────────────────
   BLAST RADIUS — reachability highlight over the *current* graph.
   Does not add nodes; it dims everything the entity cannot reach and lights
   up the subgraph it can (including any AD objects already expanded).
   ────────────────────────────────────────────────────────────────────────── */
var _blastHL = null;

/* BFS over the directed graph edges from `eid`. */
function _graphReachable(eid) {
  const svg = document.getElementById('graphSvg');
  const adj = {};
  svg.querySelectorAll('line[data-source][data-target]').forEach(l => {
    const s = l.getAttribute('data-source'), t = l.getAttribute('data-target');
    (adj[s] = adj[s] || []).push({ t, line: l });
  });
  const seen = new Set([eid]);
  const edges = new Set();
  const stack = [eid];
  while (stack.length) {
    const cur = stack.pop();
    (adj[cur] || []).forEach(({ t, line }) => {
      edges.add(line);
      if (!seen.has(t)) { seen.add(t); stack.push(t); }
    });
  }
  return { nodes: seen, edges };
}

function _applyBlastHighlight(eid) {
  const svg = document.getElementById('graphSvg');
  if (!svg) return 0;
  const { nodes, edges } = _graphReachable(eid);
  svg.querySelectorAll('g.graph-node').forEach(n => {
    const id = n.getAttribute('data-entity');
    if (nodes.has(id)) { n.style.opacity = '1'; n.classList.add('blast-reach'); }
    else { n.style.opacity = '0.12'; n.classList.remove('blast-reach'); }
  });
  svg.querySelectorAll('line[data-source]').forEach(l => {
    if (edges.has(l)) { l.style.opacity = '1'; l.style.strokeWidth = '2.6'; }
    else { l.style.opacity = '0.08'; }
  });
  svg.querySelectorAll('.edge-info-btn').forEach(b => {
    b.style.opacity = nodes.has(b.getAttribute('data-source')) ? '1' : '0.12';
  });
  _blastHL = { eid };
  return nodes.size - 1;
}

function _clearBlastHighlight() {
  const svg = document.getElementById('graphSvg');
  if (svg) {
    svg.querySelectorAll('g.graph-node').forEach(n => { n.style.opacity = ''; n.classList.remove('blast-reach'); });
    svg.querySelectorAll('line[data-source]').forEach(l => { l.style.opacity = ''; l.style.strokeWidth = ''; });
    svg.querySelectorAll('.edge-info-btn').forEach(b => { b.style.opacity = ''; });
  }
  _blastHL = null;
}

/* Entry point — reveals every possible way an attacker can move through this
   entity: expands ALL of its hidden objects (AD groups/OUs/domain/computers,
   plus the alerts, processes and services it is involved in), then highlights
   the full subgraph the entity can reach. Clicking again clears + collapses. */
function ctxBlastRadius(entityId) {
  const eid = entityId || (typeof ctxEntityId !== 'undefined' ? ctxEntityId : null);
  const svg = document.getElementById('graphSvg');
  const seedNode = eid && svg && svg.querySelector(`g.graph-node[data-entity="${eid}"]`);
  if (!seedNode) { _blastToast('💥', 'Entity is not on the graph'); return; }

  // Toggle OFF — clear the highlight and collapse anything blast radius expanded.
  if (_blastHL) {
    const auto = (_blastHL && _blastHL.autoCats) || [];
    const branched = (_blastHL && _blastHL.autoBranch) || [];
    _clearBlastHighlight();
    auto.forEach(c => _collapseADBucket(eid, c));
    if (branched.length) {
      const prev = (typeof ctxEntityId !== 'undefined') ? ctxEntityId : null;
      ctxEntityId = eid;
      branched.forEach(s => { try { s.fn(); } catch (_) {} }); // re-invoking these toggles them shut
      ctxEntityId = prev;
    }
    _blastToast('➖', 'Blast radius cleared');
    return;
  }

  // Toggle ON.
  const e = ENTITIES[eid];
  const br = e && e.sections && e.sections.blastRadius && e.sections.blastRadius.blastRadius;
  const seedName = (br && br.seed && br.seed.name) || (ENTITY_DISPLAY[eid] && ENTITY_DISPLAY[eid].name) || eid;

  // 1. Branch the other attack avenues the entity is involved in
  //    (alerts it triggered, processes it executed, services it touched).
  const autoBranch = _blastBranchExtras(eid, e);

  // 2. Expand every AD category present in the blast-radius data.
  const autoCats = [];
  let added = 0;
  if (br) {
    _ensureBlastRelGuide();
    const present = _blastCollectAD(br);
    const adBuckets = (drillDownGroups[eid] = drillDownGroups[eid] || {}).ad = drillDownGroups[eid].ad || {};
    // Order matters so parents (groups) exist before children (accounts/domain).
    _AD_CAT_ORDER.forEach(cat => {
      if (!present[cat] || !present[cat].length) return;
      if (adBuckets[cat] && adBuckets[cat].length) return; // keep manual expansions; don't auto-collapse them
      added += _expandADCategory(eid, cat, svg, seedNode, br, seedName);
      autoCats.push(cat);
    });
  }
  if (typeof updateGraphSummary === 'function') updateGraphSummary();

  // 3. Highlight everything the entity can now reach.
  const count = _applyBlastHighlight(eid);
  _blastHL.autoCats = autoCats;
  _blastHL.autoBranch = autoBranch;
  const expandedTotal = added + autoBranch.reduce((s, b) => s + (b.count || 0), 0);
  _blastToast('💥', expandedTotal
    ? `Blast radius — revealed ${expandedTotal} attack node${expandedTotal === 1 ? '' : 's'}; ${count} reachable from ${seedName}`
    : `Blast radius — ${count} node${count === 1 ? '' : 's'} reachable from ${seedName}`);
}

/* Branch the non-AD attack avenues (alerts / processes / services) the entity
   is involved in, reusing the existing context-menu expansion functions.
   Returns the specs that were actually expanded, so they can be collapsed
   again when blast radius is toggled off. Manual expansions are left alone. */
function _blastBranchExtras(eid, e) {
  if (!e || !e.sections) return [];
  const sec = e.sections;
  const specs = [
    { cat: 'alert',   has: !!sec.recentAlerts,                         fn: (typeof ctxRelatedAlerts === 'function') ? ctxRelatedAlerts : null },
    { cat: 'process', has: !!(sec.processes || sec.processesOnHost),   fn: (typeof ctxShowProcess === 'function')   ? ctxShowProcess   : null },
    { cat: 'service', has: !!(sec.serviceTriggered || sec.servicesOnHost), fn: (typeof ctxShowServices === 'function') ? ctxShowServices : null }
  ];
  const prev = (typeof ctxEntityId !== 'undefined') ? ctxEntityId : null;
  ctxEntityId = eid;
  const done = [];
  specs.forEach(s => {
    if (!s.has || !s.fn) return;
    const g = drillDownGroups[eid];
    if (g && g[s.cat] && g[s.cat].length) return; // already expanded manually — leave it
    try { s.fn(); } catch (_) {}
    const after = drillDownGroups[eid] && drillDownGroups[eid][s.cat];
    if (after && after.length) done.push({ cat: s.cat, fn: s.fn, count: after.length });
  });
  ctxEntityId = prev;
  return done;
}

/* ──────────────────────────────────────────────────────────────────────────
   AD EXPANSION — adds the AD objects of one category as real graph nodes,
   chained off their parent (so categories compose as you expand them).
   ────────────────────────────────────────────────────────────────────────── */

/* Expand one category's objects onto the graph (no toggle). Returns the count
   of new nodes added (cross-links to existing nodes are not counted). */
function _expandADCategory(eid, cat, svg, seedNode, br, seedName) {
  const adBuckets = (drillDownGroups[eid] = drillDownGroups[eid] || {}).ad = drillDownGroups[eid].ad || {};
  if (adBuckets[cat] && adBuckets[cat].length) return 0; // already expanded
  const objs = _blastCollectAD(br)[cat] || [];
  if (!objs.length) return 0;
  const bucket = adBuckets[cat] = [];
  objs.forEach((obj, i) => {
    const item = _blastDrawADObject(svg, eid, seedNode, seedName, obj, i, cat);
    if (item) bucket.push(item);
  });
  return bucket.filter(b => !b.crossLink).length;
}

function ctxExpandAD(eid, cat) {
  eid = eid || (typeof ctxEntityId !== 'undefined' ? ctxEntityId : null);
  const e = eid && ENTITIES[eid];
  const br = e && e.sections && e.sections.blastRadius && e.sections.blastRadius.blastRadius;
  const svg = document.getElementById('graphSvg');
  const seedNode = eid && svg && svg.querySelector(`g.graph-node[data-entity="${eid}"]`);
  if (!br || !seedNode) { _blastToast('💥', 'No AD data for this entity'); return; }
  _ensureBlastRelGuide();
  const adBuckets = (drillDownGroups[eid] = drillDownGroups[eid] || {}).ad = drillDownGroups[eid].ad || {};

  // Toggle: collapse if this category is already expanded.
  if (adBuckets[cat] && adBuckets[cat].length) {
    _collapseADBucket(eid, cat);
    _blastToast('➖', `${_AD_CAT_META[cat].label} collapsed`);
    return;
  }

  const seedName = (br.seed && br.seed.name) || eid;
  const added = _expandADCategory(eid, cat, svg, seedNode, br, seedName);
  if (!added && !(adBuckets[cat] && adBuckets[cat].length)) {
    _blastToast('💥', `No ${_AD_CAT_META[cat].label} in this blast radius`);
    return;
  }

  if (typeof updateGraphSummary === 'function') updateGraphSummary();
  _blastToast(_AD_CAT_META[cat].icon, `${added} ${_AD_CAT_META[cat].label} added to the graph`);
  // Keep an active blast highlight in sync with the new nodes.
  if (_blastHL && _blastHL.eid) _applyBlastHighlight(_blastHL.eid);
}

/* Draw a single AD object node (+ edge + relation button) chained to its parent. */
function _blastDrawADObject(svg, eid, seedNode, seedName, obj, idx, cat) {
  const ns = 'http://www.w3.org/2000/svg';
  const parentG = (obj.from === seedName) ? seedNode : (findNodeByLabel(obj.from) || seedNode);
  const pc = parentG && parentG.querySelector('circle:not(.expand-indicator)');
  if (!pc) return null;
  const px = parseFloat(pc.getAttribute('cx')), py = parseFloat(pc.getAttribute('cy'));
  const parentId = parentG.getAttribute('data-entity');
  const parentLabel = (ENTITY_DISPLAY[parentId] && ENTITY_DISPLAY[parentId].name) || obj.from;
  const label = obj.label;
  const meta = obj.meta;
  const relColor = _BLAST_REL_COLOR[meta.cls] || '#64748b';
  const mitre = obj.mitre;
  const crown = obj.crown;
  const firstG = svg.querySelector('g.graph-node');

  const existing = findNodeByLabel(label);
  let tgtId, tcx, tcy;
  if (existing) {
    tgtId = existing.getAttribute('data-entity');
    const ec = existing.querySelector('circle:not(.expand-indicator)');
    tcx = parseFloat(ec.getAttribute('cx')); tcy = parseFloat(ec.getAttribute('cy'));
  } else {
    tgtId = `ad-${eid}-${cat}-${idx}`;
    const pos = findFreePosition(px, py, 0, 1, _outwardAngle(svg, px, py));
    tcx = pos.cx; tcy = pos.cy;
  }

  // ── Edge (parent → target), styled like the existing graph edges ──
  const edgeKey = parentId + '→' + tgtId;
  const malicious = crown || meta.cls === 'rel-crit' || meta.cls === 'rel-cred';
  const edge = document.createElementNS(ns, 'line');
  edge.setAttribute('x1', px); edge.setAttribute('y1', py);
  edge.setAttribute('x2', tcx); edge.setAttribute('y2', tcy);
  edge.setAttribute('class', malicious ? 'graph-edge-mal' : 'graph-edge-norm');
  edge.setAttribute('data-source', parentId);
  edge.setAttribute('data-target', tgtId);
  edge.setAttribute('data-label', meta.label);
  edge.setAttribute('data-blast', '1');
  edge.setAttribute('marker-end', malicious ? 'url(#arrow-mal)' : 'url(#arrow-norm)');
  edge.style.opacity = '0';
  if (firstG) svg.insertBefore(edge, firstG); else svg.appendChild(edge);

  if (typeof EDGE_ATTRIBUTES !== 'undefined') {
    const attr = {
      relation: meta.label, count: 1, risk: crown ? 95 : (malicious ? 80 : 55),
      firstSeen: '11 May 2026 09:22:45', lastSeen: '11 May 2026 09:22:45',
      evidence: { summary: `${parentLabel} → ${meta.label} → ${label}` + (crown ? ' (Tier 0 crown jewel)' : '') }
    };
    if (mitre) {
      const tac = _BLAST_REL_TACTIC[meta.cls] || { tactic: 'Privilege Escalation', tacticId: 'TA0004' };
      attr.mitre = { tactic: tac.tactic, tacticId: tac.tacticId, technique: meta.label, techId: mitre };
    }
    EDGE_ATTRIBUTES[edgeKey] = attr;
  }

  // ── Relation icon button at the midpoint ──
  const mx = (px + tcx) / 2, my = (py + tcy) / 2;
  const btn = document.createElementNS(ns, 'g');
  btn.setAttribute('class', 'edge-info-btn');
  btn.setAttribute('data-label', meta.label);
  btn.setAttribute('data-source', parentId);
  btn.setAttribute('data-target', tgtId);
  btn.setAttribute('data-blast', '1');
  btn.setAttribute('onclick', 'showEdgeRelation(event,this)');
  const btnC = document.createElementNS(ns, 'circle');
  btnC.setAttribute('cx', mx); btnC.setAttribute('cy', my); btnC.setAttribute('r', '10');
  btnC.setAttribute('fill', '#fff'); btnC.setAttribute('stroke', relColor); btnC.setAttribute('stroke-width', '1.5');
  btn.appendChild(btnC);
  const btnT = document.createElementNS(ns, 'text');
  btnT.setAttribute('x', mx); btnT.setAttribute('y', my + 4);
  btnT.setAttribute('text-anchor', 'middle'); btnT.setAttribute('font-size', '11');
  btnT.setAttribute('dominant-baseline', 'central');
  btnT.textContent = _BLAST_REL_ICON[meta.cls] || '🔗';
  btn.appendChild(btnT);
  const relTitle = document.createElementNS(ns, 'title');
  relTitle.textContent = meta.label + (meta.desc ? ' — ' + meta.desc : '') + (mitre ? ` (${mitre})` : '');
  btn.appendChild(relTitle);
  btn.style.opacity = '0';
  svg.appendChild(btn);

  const delay = (idx * 0.08).toFixed(2);
  requestAnimationFrame(() => {
    edge.style.transition = `opacity 0.4s ease ${delay}s`;
    btn.style.transition = `opacity 0.4s ease ${delay}s`;
    edge.style.opacity = '1'; btn.style.opacity = '1';
  });

  if (existing) {
    // Cross-link to a node already on the graph — pulse, don't recreate.
    existing.style.transition = 'transform 0.3s ease';
    existing.style.transform = 'scale(1.2)';
    setTimeout(() => { existing.style.transform = 'scale(1)'; }, 450);
    return { nodeId: tgtId, gEl: null, edgeEl: edge, btnEl: btn, edgeKey, crossLink: true };
  }

  // ── New AD node ──
  const color = crown ? '#dc2626' : '#475569';
  const icon = _blastIcon(label);
  ENTITIES[tgtId] = {
    type: 'ad', modalTitle: `AD Object · ${label}`,
    sections: { adInfo: { label: 'AD Object', expanded: true, kv: {
      'Object': label, 'Category': _AD_CAT_META[cat].label,
      'Reached Via': meta.label + (mitre ? ` (${mitre})` : ''),
      'From': parentLabel, 'Crown Jewel': crown ? 'Yes — Tier 0 asset' : 'No'
    } } }
  };
  ENTITY_DISPLAY[tgtId] = {
    icon, name: label.length > 20 ? label.slice(0, 18) + '…' : label,
    color, bg: crown ? '#fef2f2' : '#f8fafc'
  };

  const g = document.createElementNS(ns, 'g');
  g.setAttribute('class', 'graph-node');
  g.setAttribute('data-entity', tgtId);
  g.setAttribute('data-blast', '1');
  g.setAttribute('data-ad-cat', cat);
  g.setAttribute('onclick', `openEntitySlider('${tgtId}')`);
  g.setAttribute('oncontextmenu', `showGraphCtx(event,'${tgtId}')`);

  if (crown) {
    const ring = document.createElementNS(ns, 'circle');
    ring.setAttribute('cx', tcx); ring.setAttribute('cy', tcy); ring.setAttribute('r', '23');
    ring.setAttribute('fill', 'none'); ring.setAttribute('stroke', '#f59e0b');
    ring.setAttribute('stroke-width', '2'); ring.setAttribute('stroke-dasharray', '3 3');
    g.appendChild(ring);
  }
  const circle = document.createElementNS(ns, 'circle');
  circle.setAttribute('cx', tcx); circle.setAttribute('cy', tcy); circle.setAttribute('r', '20');
  circle.setAttribute('fill', crown ? '#fef2f2' : '#ffffff');
  circle.setAttribute('stroke', color); circle.setAttribute('stroke-width', '2');
  circle.setAttribute('filter', 'url(#glow-r)');
  g.appendChild(circle);

  const iconEl = document.createElementNS(ns, 'text');
  iconEl.setAttribute('x', tcx); iconEl.setAttribute('y', tcy + 4);
  iconEl.setAttribute('text-anchor', 'middle'); iconEl.setAttribute('font-size', '14');
  iconEl.setAttribute('dominant-baseline', 'central');
  iconEl.textContent = icon;
  g.appendChild(iconEl);

  if (crown) {
    const gem = document.createElementNS(ns, 'text');
    gem.setAttribute('x', tcx + 17); gem.setAttribute('y', tcy - 15);
    gem.setAttribute('text-anchor', 'middle'); gem.setAttribute('font-size', '12');
    gem.textContent = '💎';
    g.appendChild(gem);
  }

  const lblEl = document.createElementNS(ns, 'text');
  lblEl.setAttribute('x', tcx); lblEl.setAttribute('y', tcy + 30);
  lblEl.setAttribute('text-anchor', 'middle'); lblEl.setAttribute('font-size', '10');
  lblEl.setAttribute('fill', color); lblEl.setAttribute('font-family', 'Inter,sans-serif');
  lblEl.setAttribute('font-weight', '600');
  lblEl.textContent = label.length > 20 ? label.slice(0, 18) + '…' : label;
  g.appendChild(lblEl);

  svg.appendChild(g);
  if (typeof makeNodeDraggable === 'function') makeNodeDraggable(g, circle, iconEl, lblEl, tgtId);
  registerNode(tgtId, label);
  g.style.opacity = '0';
  requestAnimationFrame(() => { g.style.transition = `opacity 0.4s ease ${delay}s`; g.style.opacity = '1'; });

  return { nodeId: tgtId, gEl: g, edgeEl: edge, btnEl: btn, edgeKey };
}

/* Remove every node/edge added by one AD category expansion. */
function _collapseADBucket(eid, cat) {
  const bucket = drillDownGroups[eid] && drillDownGroups[eid].ad && drillDownGroups[eid].ad[cat];
  if (!bucket || !bucket.length) return;
  bucket.forEach(item => {
    if (item.edgeEl) { item.edgeEl.style.transition = 'opacity 0.25s ease'; item.edgeEl.style.opacity = '0'; setTimeout(() => item.edgeEl.remove(), 280); }
    if (item.btnEl)  { item.btnEl.style.transition = 'opacity 0.25s ease';  item.btnEl.style.opacity = '0';  setTimeout(() => item.btnEl.remove(), 280); }
    if (item.edgeKey && typeof EDGE_ATTRIBUTES !== 'undefined') delete EDGE_ATTRIBUTES[item.edgeKey];
    if (item.crossLink || !item.gEl) return;
    item.gEl.style.transition = 'opacity 0.25s ease'; item.gEl.style.opacity = '0';
    setTimeout(() => item.gEl.remove(), 280);
    delete nodeRegistry[item.nodeId];
    delete ENTITIES[item.nodeId];
    delete ENTITY_DISPLAY[item.nodeId];
  });
  drillDownGroups[eid].ad[cat] = [];
  if (_blastHL && _blastHL.eid) setTimeout(() => _applyBlastHighlight(_blastHL.eid), 300);
  setTimeout(() => { if (typeof updateGraphSummary === 'function') updateGraphSummary(); }, 300);
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
  // See entity_data_mapping.md §1.1.OVERALL_DETECTION_COUNT
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

