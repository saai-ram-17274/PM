/* ═══ V5 DETAIL VIEW (Img_2..Img_5) ═══ */

let currentAlertId = null;

function openAlertDetail(alertId) {
  currentAlertId = alertId;
  const detail = ALERT_DETAIL[alertId];
  if (!detail) {
    /* fallback: use list summary */
    const list = ALERTS.find(x => x.id === alertId);
    if (!list) return;
    /* synthesize a minimal detail */
    ALERT_DETAIL[alertId] = {
      title: list.title, severityLabel: list.severityLabel, severityClass: list.severity,
      score: list.score, aiInvestigated: false, assignee: list.assignee.name,
      status: list.statusLabel, statusClass: list.status,
      severity: list.severityLabel, severityPillClass: list.severity,
      createdTime: list.timeGenerated, sla: '—',
      tags: [], devices: [], ips: [], files: [],
      summary: list.desc.replace(/<\/?span[^>]*>/g, ''),
      insights: [], relatedAlerts: [],
      investSummary: list.desc.replace(/<\/?span[^>]*>/g, ''),
      recommendations: [], keyFindings: []
    };
  }
  /* Reset AI investigation runtime state so each open starts in partial mode */
  ALERT_DETAIL[alertId].aiInvestigatedRuntime = false;
  showDetailView();
}

function showListView() {
  document.getElementById('listView').style.display = 'flex';
  document.getElementById('detailView').style.display = 'none';
  document.getElementById('breadcrumb').style.display = 'none';
  /* show sub-tabs */
  document.querySelectorAll('.alerts-subnav .asn-tab').forEach(t => t.style.display = '');
  /* show profile buttons */
  ['addAlertProfileBtn', 'manageAlertProfilesBtn'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = '';
    const sep = el && el.previousElementSibling;
    if (sep && sep.classList.contains('asn-sep')) sep.style.display = '';
  });
  window.scrollTo(0, 0);
}

function showDetailView() {
  document.getElementById('listView').style.display = 'none';
  document.getElementById('detailView').style.display = 'flex';
  document.getElementById('breadcrumb').style.display = 'flex';
  /* hide sub-tabs in detail (only breadcrumb) */
  document.querySelectorAll('.alerts-subnav .asn-tab').forEach(t => t.style.display = 'none');
  /* hide profile buttons in detail view */
  ['addAlertProfileBtn', 'manageAlertProfilesBtn'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
    const sep = el && el.previousElementSibling;
    if (sep && sep.classList.contains('asn-sep')) sep.style.display = 'none';
  });
  document.getElementById('bcCurrent').textContent = ALERT_DETAIL[currentAlertId].title;
  renderDetailSidebar();
  renderAllTabs();
  /* default tab */
  switchDetailTab('overview');
  window.scrollTo(0, 0);
}

function renderDetailSidebar() {
  const d = ALERT_DETAIL[currentAlertId];
  const sb = document.getElementById('dvSidebar');
  if (!sb || !d) return;

  const aiBadge = d.aiInvestigated
    ? '<span class="dv-meta-pill ai"><span class="ai-spark">✦</span> AI Investigated</span>'
    : '';

  sb.innerHTML = `
    <div class="dv-alert-title">
      <span class="alert-icon-circle ${d.severityClass || 'crit'}">✕</span>
      <span>${d.title}</span>
    </div>
    <div class="dv-meta-badges">
      <span class="dv-meta-pill ${d.severityClass || 'high'}">${d.severityLabel} ${d.score}</span>
      ${aiBadge}
      <button class="dv-doc-icon" title="Notes">📝</button>
    </div>

    <div class="dv-meta-field">
      <div class="dv-meta-field-label">Assignee</div>
      <div class="dv-meta-select assignee">
        <span class="assignee-avatar">JW</span>
        <span>${d.assignee}</span>
        <span class="caret">▾</span>
      </div>
    </div>

    <div class="dv-meta-field">
      <div class="dv-meta-field-label">Status</div>
      <div class="dv-meta-select">
        <span class="status-pill ${d.statusClass || 'open'}" style="padding:1px 8px;">${d.status}</span>
        <span class="caret">▾</span>
      </div>
    </div>

    <div class="dv-meta-field">
      <div class="dv-meta-field-label">Severity</div>
      <div class="dv-meta-select">
        <span class="severity-badge ${d.severityPillClass || 'crit'}" style="padding:1px 8px;">
          <span class="alert-icon-circle ${d.severityPillClass || 'crit'}" style="width:12px;height:12px;font-size:8px;">✕</span>
          ${d.severity}
        </span>
        <span class="caret">▾</span>
      </div>
    </div>

    <div class="dv-meta-field">
      <div class="dv-meta-field-label">Created Time</div>
      <div class="dv-meta-field-value" style="font-weight:400;">${d.createdTime}</div>
    </div>

    <div class="dv-sla-card">
      <div class="dv-sla-label">SLA</div>
      <div class="dv-sla-value"><span class="hourglass">⏳</span> ${d.sla}</div>
    </div>

    <div class="dv-meta-field">
      <div class="dv-meta-field-label">Tags</div>
      <div class="dv-tags-wrap">
        ${(d.tags || []).map(t => `
          <span class="dv-tag">
            <span class="tag-cat">${t.cat}</span>
            <span>${t.label}</span>
            <span class="tag-x">×</span>
          </span>
        `).join('')}
      </div>
    </div>

    <div class="dv-meta-section">
      <div class="dv-meta-section-head" onclick="this.parentElement.classList.toggle('collapsed')">
        <span class="left"><span class="icon">💻</span> Devices</span>
        <span class="chev">▾</span>
      </div>
      <div class="dv-meta-section-body">
        ${(d.devices || []).map(dv => `
          <div class="dv-meta-item">
            <span class="item-name">${dv.name}</span>
            <span class="item-sep">-</span>
            <span class="item-sub">${dv.ip}</span>
          </div>
        `).join('')}
      </div>
    </div>

    <div class="dv-meta-section collapsed">
      <div class="dv-meta-section-head" onclick="this.parentElement.classList.toggle('collapsed')">
        <span class="left"><span class="icon">🌐</span> IPs</span>
        <span class="chev">▾</span>
      </div>
      <div class="dv-meta-section-body">
        ${(d.ips && d.ips.length) ? d.ips.map(ip => `<div class="dv-meta-item"><span class="item-name">${ip}</span></div>`).join('') : '<div class="dv-meta-item"><span class="item-sub">No IPs</span></div>'}
      </div>
    </div>

    <div class="dv-meta-section collapsed">
      <div class="dv-meta-section-head" onclick="this.parentElement.classList.toggle('collapsed')">
        <span class="left"><span class="icon">📄</span> Files</span>
        <span class="chev">▾</span>
      </div>
      <div class="dv-meta-section-body">
        ${(d.files && d.files.length) ? d.files.map(f => `<div class="dv-meta-item"><span class="item-name">${f}</span></div>`).join('') : '<div class="dv-meta-item"><span class="item-sub">No files</span></div>'}
      </div>
    </div>
  `;
}

/* ═══ TABS ═══ */
function switchDetailTab(tabId) {
  document.querySelectorAll('.dv-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
  document.querySelectorAll('.dv-panel').forEach(p => p.classList.toggle('active', p.id === 'panel-' + tabId));
}

function renderAllTabs() {
  renderOverviewPanel();
  renderInvestigationPanel();
  renderAttackVectorPanel();
  renderTimelinePanel();
  renderRemediationPanel();
  renderIntegrationPanel();
  renderActivityPanel();
}

/* ─── OVERVIEW (Img_2) ─── */
function renderOverviewPanel() {
  const d = ALERT_DETAIL[currentAlertId];
  const panel = document.getElementById('panel-overview');
  if (!d || !panel) return;

  panel.innerHTML = `
    <div class="ov-summary">${d.summary}</div>
    <div class="ov-meta-line">⏱ ${d.createdTime} <span class="info-i">i</span></div>

    <div class="ov-grid">
      <!-- Insights -->
      <div>
        <div class="ov-section-title">Insights</div>
        <div class="ov-insights-list">
          ${(d.insights || []).map(ins => `
            <div class="ov-insight-card">
              <div class="ov-insight-head">
                <span class="ov-insight-icon">${ins.icon}</span>
                <div>
                  <div class="ov-insight-name">${ins.name}</div>
                  <div class="ov-insight-sub">${ins.sub}</div>
                </div>
                <span class="ov-insight-score ${ins.scoreClass}"><span>⊗</span> ${ins.score}</span>
              </div>
              <div class="ov-insight-body">
                <span class="body-icon">↩</span>
                <span>${ins.text}</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Related Alerts -->
      <div>
        <div class="ov-related-card">
          <div class="ov-related-head">
            <div class="ov-related-head-left">
              <span class="ov-related-title">Related Alerts</span>
              <button class="ov-related-filter-btn">Based on Same Alert Profile <span class="caret">▾</span></button>
            </div>
            <div class="ov-related-head-right">
              <button class="lv-icon-btn" title="Filter">🔽</button>
              <span class="ov-related-pager"><span class="cur">1-25</span> of <span class="tot">100</span></span>
              <button class="lv-icon-btn">‹</button>
              <button class="lv-icon-btn">›</button>
            </div>
          </div>
          <table class="ov-related-table">
            <thead>
              <tr>
                <th>Malicious URL requests</th>
                <th>Status <span style="color:var(--text-tertiary);">↑</span></th>
                <th>Assign</th>
                <th>Matching Entity</th>
              </tr>
            </thead>
            <tbody>
              ${(d.relatedAlerts || []).map(r => `
                <tr>
                  <td>
                    <span class="url-cell">${r.url}</span>
                    <span class="severity-badge ${r.sev}" style="margin-left:6px;">${capitalize(r.sev)} ${r.score}</span>
                  </td>
                  <td><span class="status-pill ${r.status}">${capitalize(r.status)}</span></td>
                  <td><span class="assignee-cell"><span class="assignee-avatar">JW</span>${r.assign}</span></td>
                  <td>
                    <span class="matching-cell">
                      <span class="icon-circle">${r.matchType === 'device' ? '💻' : '👤'}</span>
                      ${r.match}
                    </span>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function capitalize(s) {
  if (!s) return '';
  const map = { open: 'Open', crit: 'Critical', high: 'High', med: 'Medium', low: 'Low', vlow: 'Very Low' };
  return map[s] || (s.charAt(0).toUpperCase() + s.slice(1));
}

/* ─── INVESTIGATION (Img_3) ─── */
function renderInvestigationPanel() {
  const d = ALERT_DETAIL[currentAlertId];
  const panel = document.getElementById('panel-investigation');
  if (!d || !panel) return;

  const investigated = !!d.aiInvestigatedRuntime;

  /* Insight bullets shown inside the collapsible (partial → brief; full keeps same brief list).
     Falls back to plain text derived from d.insights when no dedicated bullets are provided. */
  const insightBullets = (d.investInsightBullets && d.investInsightBullets.length)
    ? d.investInsightBullets
    : (d.insights || []).map(i => i.text).filter(Boolean);

  const mitigationSteps = d.mitigationSteps || [];

  const aiPromoHTML = `
    <div class="inv-ai-cta">
      <div class="inv-ai-cta-text">Get <span class="inv-ai-cta-hl">AI-powered</span> alert analysis and instant remediation suggestions</div>
      <button class="inv-ai-cta-btn" onclick="startInvestigation()">
        <span class="ai-spark">✨</span> Start Investigation
      </button>
    </div>`;

  const recommendationsHTML = `
    <div class="inv-recommend-section inv-card">
      <div class="inv-card-title">Recommendations</div>
      ${(d.recommendations || []).map(r => `
        <div class="inv-rec-card">
          <div class="inv-rec-icon">${r.icon}</div>
          <div class="inv-rec-body">
            <div class="inv-rec-title">${r.title}</div>
            <div class="inv-rec-desc">${r.desc}</div>
            <button class="inv-rec-action">${r.actionLabel}</button>
          </div>
        </div>
      `).join('')}
    </div>

    <div class="inv-keyfind-section inv-card">
      <div class="inv-card-title">Key Findings</div>
      ${(d.keyFindings || []).map(k => `
        <div class="inv-keyfind-item">
          <span class="inv-keyfind-icon">⚡</span>
          <div class="inv-keyfind-body">
            <div class="inv-keyfind-title">⚠ ${k.title}</div>
            <div class="inv-keyfind-text">${k.text}</div>
          </div>
        </div>
      `).join('')}
    </div>`;

  panel.innerHTML = `
    <div class="inv-card">
      <div class="inv-card-title">Summary</div>
      <div class="inv-summary-text">${d.investSummary}</div>
      <div class="inv-suggest-row">
        <span class="alert-icon-circle crit" style="width:14px;height:14px;font-size:8px;">✕</span>
        <span class="label-pill fp">False Positive</span>
        <span>Suggested with</span>
        <span class="alert-icon-circle high" style="width:14px;height:14px;font-size:8px;">!</span>
        <span class="label-pill med-conf">Medium</span>
        <span>Confidence Level</span>
        <button class="inv-deep-search-btn">✦ Deep Search</button>
      </div>
    </div>

    <div class="inv-card" style="padding:8px 16px;">
      <div class="inv-collapsible open" onclick="this.classList.toggle('open');this.nextElementSibling.classList.toggle('open')">
        <span class="chev">›</span> 🔍 Insights
      </div>
      <div class="inv-collapsible-body open">
        ${insightBullets.map(t => `<div class="inv-bullet"><span class="inv-bullet-icon">✨</span><div class="inv-bullet-text">${t}</div></div>`).join('')}
      </div>
      <div class="inv-collapsible" onclick="this.classList.toggle('open');this.nextElementSibling.classList.toggle('open')">
        <span class="chev">›</span> 💡 Potential Mitigation Steps
      </div>
      <div class="inv-collapsible-body">
        ${mitigationSteps.length
          ? mitigationSteps.map(t => `<div class="inv-bullet"><span class="inv-bullet-icon">✨</span><div class="inv-bullet-text">${t}</div></div>`).join('')
          : '<div class="inv-bullet"><span class="inv-bullet-icon">✨</span><div class="inv-bullet-text">No mitigation steps available.</div></div>'}
      </div>
    </div>

    ${investigated ? recommendationsHTML : aiPromoHTML}
  `;
}

/* Triggered by the "Start Investigation" CTA — unlocks AI-analyzed data
   in both Investigation and Attack Vector tabs for the current alert.
   Shows a brief "AI Analyzing…" loading state before revealing results. */
function startInvestigation() {
  const d = ALERT_DETAIL[currentAlertId];
  if (!d) return;
  const overlayHTML = `
    <div class="inv-ai-loading">
      <div class="inv-ai-loading-card">
        <div class="inv-ai-spinner"></div>
        <div class="inv-ai-loading-text"><span class="inv-ai-cta-hl">AI Analyzing</span><span class="inv-ai-dots"><span>.</span><span>.</span><span>.</span></span></div>
        <div class="inv-ai-loading-sub">Correlating events, entities, and threat intel</div>
      </div>
    </div>`;
  const panel = document.getElementById('panel-investigation');
  if (panel) {
    /* Inline overlay covers the panel so the existing summary stays in
       place but the CTA / cards transition through a clear loading step. */
    const overlay = document.createElement('div');
    overlay.className = 'inv-ai-loading';
    overlay.innerHTML = `
      <div class="inv-ai-loading-card">
        <div class="inv-ai-spinner"></div>
        <div class="inv-ai-loading-text"><span class="inv-ai-cta-hl">AI Analyzing</span><span class="inv-ai-dots"><span>.</span><span>.</span><span>.</span></span></div>
        <div class="inv-ai-loading-sub">Correlating events, entities, and threat intel</div>
      </div>`;
    panel.appendChild(overlay);
  }
  /* Same overlay on the Attack Vector panel when triggered from its CTA */
  const avPanel = document.getElementById('panel-attack-vector');
  if (avPanel) {
    const ov = document.createElement('div');
    ov.className = 'inv-ai-loading';
    ov.innerHTML = `
      <div class="inv-ai-loading-card">
        <div class="inv-ai-spinner"></div>
        <div class="inv-ai-loading-text"><span class="inv-ai-cta-hl">AI Analyzing</span><span class="inv-ai-dots"><span>.</span><span>.</span><span>.</span></span></div>
        <div class="inv-ai-loading-sub">Correlating events, entities, and threat intel</div>
      </div>`;
    avPanel.appendChild(ov);
  }
  setTimeout(() => {
    d.aiInvestigatedRuntime = true;
    renderInvestigationPanel();
    renderAttackVectorPanel();
    if (typeof showToast === 'function') showToast('✨', 'AI investigation complete — full analysis loaded');
  }, 1000);
}

/* ─── ATTACK VECTOR — full V4 attack-vector ported via graph.js ─── */
function renderAttackVectorPanel() {
  if (typeof mountAttackGraph === 'function') mountAttackGraph();
}

/* ─── TIMELINE / REMEDIATION / INTEGRATION / ACTIVITY ─── */
function renderTimelinePanel() {
  const panel = document.getElementById('panel-timeline');
  if (!panel) return;
  const events = [
    { time:'11 May 2026  10:04:00', sev:'high',   score:91, dot:'red',   icon:'✕', desc:'Impossible Travel detected — Azure AD sign-ins from Austin (10.18.1.81, baseline 06:42) and Bucharest (185.220.101.42, Tor exit, 09:56) — 9,400 km in 3 h 14 min, physically impossible.', who:'m.henderson', where:'CORP-NET',     app:'Azure AD Portal', expanded:true },
    { time:'11 May 2026  11:18:00', sev:'crit',   score:97, dot:'red',   icon:'⚠', desc:'OAuth token issued with Files.ReadWrite.All scope to unverified third-party application "FileSync Pro".', who:'m.henderson', where:'Azure AD',     app:'OAuth Service' },
    { time:'11 May 2026  11:16:00', sev:'high',   score:82, dot:'amber', icon:'⚠', desc:'Encoded PowerShell execution (hidden window) on CORP-WS-045 — process tree includes svchost_update.dll write to C:\\Temp.', who:'SYSTEM',      where:'CORP-WS-045',  app:'powershell.exe' },
    { time:'11 May 2026  11:08:00', sev:'medium', score:55, dot:'amber', icon:'⚠', desc:'24 files bulk-downloaded from /Finance/Sensitive directory in 3 minutes — well above user baseline (3 files/day).', who:'m.henderson', where:'SharePoint',    app:'OneDrive Sync' },
    { time:'11 May 2026  10:28:00', sev:'low',    score:22, dot:'green', icon:'⚠', desc:'Successful interactive logon from internal IP 10.18.1.81 (CORP-WS-045). Normal weekday office hours.', who:'m.henderson', where:'CORP-WS-045', app:'Windows Logon' },
  ];
  panel.innerHTML = `
    <div class="tl-header">
      <div class="tl-title">Alert Events <span class="tl-count-pill">250</span></div>
      <button class="tl-filter-btn" title="Filter events">
        <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
      </button>
    </div>
    ${events.map((e,i) => `
      <div class="tl-event-card ${e.expanded?'expanded':''}">
        <div class="tl-event-top">
          <div class="tl-event-top-left">
            <span class="tl-event-dot ${e.dot}">${e.icon}</span>
            <span class="tl-event-time">${e.time}</span>
            <span class="tl-event-chev">▾</span>
          </div>
          <span class="severity-badge ${e.sev}">${capitalize(e.sev)} ${e.score}</span>
        </div>
        <div class="tl-event-desc">${e.desc}</div>
        <div class="tl-event-foot">
          <div class="tl-event-meta">
            <span><span class="tl-meta-lbl">Who</span><span class="tl-meta-val">${e.who}</span></span>
            <span><span class="tl-meta-lbl">Where</span><span class="tl-meta-val">${e.where}</span></span>
            <span><span class="tl-meta-lbl">Application</span><span class="tl-meta-val">${e.app}</span></span>
          </div>
          <button class="tl-run-pb-btn">
            <svg width="11" height="11" fill="currentColor" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            Run Playbook
          </button>
        </div>
      </div>
    `).join('')}
  `;
}

function renderRemediationPanel() {
  const panel = document.getElementById('panel-remediation');
  if (!panel) return;
  const playbooks = [
    { id:'PB-001', name:'Disable Compromised Account',     status:'pending', sev:'crit', desc:'Disable m.henderson in Active Directory & Azure AD; force sign-out from all sessions.', steps:5, eta:'~2 min', auto:true },
    { id:'PB-002', name:'Revoke OAuth Tokens',             status:'pending', sev:'crit', desc:'Revoke all OAuth tokens issued in the last 24h, including FileSync Pro consent.',           steps:3, eta:'~30 sec', auto:true },
    { id:'PB-003', name:'Block Tor Exit Node IP',          status:'pending', sev:'high', desc:'Add 185.220.101.42 to global firewall blocklist across all edge devices.',                  steps:2, eta:'~15 sec', auto:true },
    { id:'PB-004', name:'Isolate CORP-WS-045',             status:'pending', sev:'high', desc:'Network-quarantine the workstation; allow only SOC management traffic.',                    steps:4, eta:'~1 min',  auto:true },
    { id:'PB-005', name:'Force Password Reset + MFA',      status:'pending', sev:'med',  desc:'Trigger password reset for m.henderson and require fresh MFA enrollment on re-enable.',     steps:3, eta:'~5 min',  auto:false },
    { id:'PB-006', name:'Notify Manager & HR',             status:'pending', sev:'med',  desc:'Send incident notification to j.williams (manager) and HR per IR runbook.',                steps:2, eta:'~10 sec', auto:false },
  ];
  const sevColor = s => s==='crit'?'#dc2626':s==='high'?'#ea580c':s==='med'?'#d97706':'#16a34a';
  panel.innerHTML = `
    <div class="rm-header">
      <div>
        <div class="rm-title">Recommended Remediation Actions</div>
        <div class="rm-sub">Suggested playbooks based on alert classification, MITRE techniques, and entity risk profile.</div>
      </div>
      <button class="rm-run-all">
        <svg width="12" height="12" fill="currentColor" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        Run All Auto-Playbooks
      </button>
    </div>

    <div class="rm-stat-row">
      <div class="rm-stat"><div class="rm-stat-val">${playbooks.length}</div><div class="rm-stat-lbl">Total Playbooks</div></div>
      <div class="rm-stat"><div class="rm-stat-val" style="color:#16a34a;">${playbooks.filter(p=>p.auto).length}</div><div class="rm-stat-lbl">Auto-Executable</div></div>
      <div class="rm-stat"><div class="rm-stat-val" style="color:#dc2626;">${playbooks.filter(p=>p.sev==='crit').length}</div><div class="rm-stat-lbl">Critical Severity</div></div>
      <div class="rm-stat"><div class="rm-stat-val">~9 min</div><div class="rm-stat-lbl">Total ETA</div></div>
    </div>

    <div class="rm-list">
      ${playbooks.map(p => `
        <div class="rm-card">
          <div class="rm-card-left">
            <div class="rm-card-icon" style="background:${sevColor(p.sev)}15;color:${sevColor(p.sev)};">⚙</div>
          </div>
          <div class="rm-card-body">
            <div class="rm-card-head">
              <div>
                <span class="rm-card-id">${p.id}</span>
                <span class="rm-card-name">${p.name}</span>
                ${p.auto ? '<span class="rm-auto-pill">Auto</span>' : '<span class="rm-manual-pill">Manual</span>'}
                <span class="severity-badge ${p.sev==='crit'?'crit':p.sev==='high'?'high':p.sev==='med'?'medium':'low'}" style="margin-left:6px;">${capitalize(p.sev==='crit'?'critical':p.sev==='med'?'medium':p.sev)}</span>
              </div>
              <div class="rm-card-meta">
                <span>${p.steps} steps</span>
                <span class="dot">·</span>
                <span>${p.eta}</span>
              </div>
            </div>
            <div class="rm-card-desc">${p.desc}</div>
            <div class="rm-card-actions">
              <button class="rm-btn rm-btn-outline">View Steps</button>
              <button class="rm-btn rm-btn-primary">
                <svg width="11" height="11" fill="currentColor" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                Run Playbook
              </button>
            </div>
          </div>
        </div>
      `).join('')}
    </div>

    <div class="rm-history">
      <div class="rm-history-title">Recent Remediation History</div>
      <table class="rm-history-table">
        <thead><tr><th>Time</th><th>Playbook</th><th>Triggered By</th><th>Status</th></tr></thead>
        <tbody>
          <tr><td>05:04:12</td><td>PB-002 Revoke OAuth Tokens</td><td>Auto</td><td><span class="rm-status-pill ok">✓ Success</span></td></tr>
          <tr><td>05:03:50</td><td>PB-003 Block IP 185.220.101.42</td><td>Johnson Williams</td><td><span class="rm-status-pill ok">✓ Success</span></td></tr>
          <tr><td>05:03:22</td><td>PB-001 Disable Account</td><td>Auto</td><td><span class="rm-status-pill running">◷ Running</span></td></tr>
        </tbody>
      </table>
    </div>
  `;
}
function renderIntegrationPanel() {
  const panel = document.getElementById('panel-integration');
  if (!panel) return;
  panel.innerHTML = `<div class="placeholder-card"><h2>Integration</h2><p>Coming soon.</p></div>`;
}
function renderActivityPanel() {
  const panel = document.getElementById('panel-activity');
  if (!panel) return;
  panel.innerHTML = `<div class="placeholder-card"><h2>Activity</h2><p>Coming soon.</p></div>`;
}
