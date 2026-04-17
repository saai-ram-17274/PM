/* alert-detail.js — Center panel: detail header, tabs, overview
 * Depends on: alerts.js, utils.js, app.js (state vars) */
function renderDetailHeader(a) {
  document.getElementById('detailHeader').innerHTML = `
    <div class="detail-title-row">
      <div class="detail-title">
        <span style="color:#e74c3c;font-size:16px;">✕</span>
        ${a.title}
      </div>
      <span class="badge badge-${a.severity}" style="font-size:11.5px;">${cap(a.severity)} ${a.score}</span>
      <span style="display:inline-flex;align-items:center;gap:4px;font-size:11px;color:#6366f1;font-weight:600;background:#eef2ff;padding:4px 10px;border-radius:10px;">✦ AI Investigated</span>
      <span style="font-size:13px;cursor:pointer;color:#94a3b8;" onclick="showToast('📋','Copied to clipboard')">📋</span>
      <div class="detail-actions">
        <button class="btn-icon" onclick="showToast('👍','Liked')" title="Thumbs up" style="width:32px;height:32px;border-radius:50%;border:1px solid var(--border);background:var(--surface);cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--text-dim);font-size:14px;">👍</button>
        <button class="btn-action" onclick="addToIncident()">
          <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 5v14m-7-7h14"/></svg>
          Add to Incident
        </button>
        <button class="btn-action btn-action-primary" onclick="runPlaybook()">
          <svg width="12" height="12" fill="currentColor" stroke="none" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          Run Playbook
        </button>
        <button class="btn-investigate${invOpen?' active-inv':''}" id="investigateBtn" onclick="toggleInvestigation()">
          <span class="inv-sparkle">✦</span>
          View Investigation
        </button>
      </div>
    </div>
    <p class="detail-summary">
      User corp\\m.henderson (10.18.1.81) authenticated successfully from external IP <strong>185.220.101.42</strong>
      (Tor exit node, Romania) at 2026-03-24 03:12:44, and then again from internal IP 10.18.1.81 on CORP-NET
      at 2026-03-24 03:41:22 — a gap of only 28 minutes across geographically impossible locations. This simultaneous presence indicates active credential compromise or concurrent session hijacking. Following the anomalous logins, the account performed suspicious OAuth token generation, accessed the mailbox, and downloaded files from sensitive SharePoint directories. Classified as a True Positive — no authorized remote access or travel activity exists for this user. Immediate account suspension, token revocation, and session termination are required.
    </p>
    <div style="display:flex;align-items:center;gap:5px;font-size:11.5px;color:var(--text-dim);margin-bottom:14px;">
      <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
      07 Jun 2017, 05:02:40
      <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>
    </div>
    <div class="detail-meta-grid">
      <div class="meta-cell dropdown">
        <div class="meta-lbl">Assignee</div>
        <div class="meta-val" onclick="toggleDropdown('assigneeDd')">
          <span style="width:20px;height:20px;border-radius:50%;background:#e8f0fe;display:inline-flex;align-items:center;justify-content:center;font-size:9px;">👤</span>
          Johnson Williams ▾
        </div>
        <div class="dropdown-menu" id="assigneeDd">
          <div class="dropdown-item" onclick="setAssignee('Johnson Williams')">Johnson Williams</div>
          <div class="dropdown-item" onclick="setAssignee('Sarah Chen')">Sarah Chen</div>
          <div class="dropdown-item" onclick="setAssignee('Mike Torres')">Mike Torres</div>
          <div class="dropdown-sep"></div>
          <div class="dropdown-item" onclick="setAssignee('Unassigned')">Unassigned</div>
        </div>
      </div>
      <div class="meta-cell dropdown">
        <div class="meta-lbl">Status</div>
        <div class="meta-val" onclick="toggleDropdown('statusDd')">Open ▾</div>
        <div class="dropdown-menu" id="statusDd">
          <div class="dropdown-item" onclick="setStatus('Open','')">Open</div>
          <div class="dropdown-item" onclick="setStatus('In Progress','')">In Progress</div>
          <div class="dropdown-item" onclick="setStatus('Resolved','')">Resolved</div>
          <div class="dropdown-item" onclick="setStatus('Closed','')">Closed</div>
        </div>
      </div>
      <div class="meta-cell dropdown">
        <div class="meta-lbl">Severity</div>
        <div class="meta-val critical" onclick="toggleDropdown('severityDd')">
          <span style="color:#dc2626;">●</span> Critical ▾
        </div>
        <div class="dropdown-menu" id="severityDd">
          <div class="dropdown-item" onclick="setSeverity('Critical','#dc2626')">🔴 Critical</div>
          <div class="dropdown-item" onclick="setSeverity('High','#f97316')">🟠 High</div>
          <div class="dropdown-item" onclick="setSeverity('Medium','#d97706')">🟡 Medium</div>
          <div class="dropdown-item" onclick="setSeverity('Low','#16a34a')">🟢 Low</div>
        </div>
      </div>
      <div class="meta-cell">
        <div class="meta-lbl">SLA</div>
        <div class="meta-val sla-warn">
          <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
          3 Days 5 Hrs
        </div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:0;">
      <span style="font-size:11.5px;color:#8a94a6;font-weight:600;">Tags</span>
      <span class="tag tag-mitre">MITRE ATT&amp;CK <span style="margin:0 2px;">·</span> Native API (T1106) <button class="tag-close" onclick="event.stopPropagation()">✕</button></span>
      <span class="tag tag-mitre">MITRE ATT&amp;CK <span style="margin:0 2px;">·</span> Native API (T1106) <button class="tag-close" onclick="event.stopPropagation()">✕</button></span>
      <span class="tag tag-mitre">MITRE ATT&amp;CK <span style="margin:0 2px;">·</span> Execution (TA0002) <button class="tag-close" onclick="event.stopPropagation()">✕</button></span>
      <span style="margin-left:auto;font-size:11.5px;color:#8a94a6;display:inline-flex;align-items:center;gap:5px;white-space:nowrap;">
        <svg width="12" height="12" fill="none" stroke="#8a94a6" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
        3 Days 23 Hrs 50 Mins
      </span>
    </div>
  `;
}

/* ── RENDER TIMELINE TAB ─────────────────────────────────────── */
function renderTimelineTab() {
  document.getElementById('tabContent').innerHTML = `
    <div class="events-header">
      <div class="events-title">Alert Events <span class="count-pill">250</span></div>
      <button class="btn-filter-icon" onclick="showToast('🔽','Filtering events…')">
        <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
      </button>
    </div>
    ${[
      { time:'07 Jun 2017  05:02:40', sev:'medium', score:55, desc:'The application Firefox 109.0.1 was failed to install on zohocorp.com/santhosh-8457. Reason: Unstable network', who:'Santhosh', where:'santhosh-8457', app:'Firefox 109.0.1', dotColor:'amber' },
      { time:'07 Jun 2017  05:02:40', sev:'high', score:80, desc:'The application Firefox 109.0.1 was failed to install on zohocorp.com/ramesh-8457. Reason: Unstable network', who:'Ramesh', where:'ramesh-8457', app:'Firefox 109.0.1', dotColor:'amber', expanded:true },
      { time:'07 Jun 2017  05:02:40', sev:'low', score:22, desc:'The application Firefox 109.0.1 was failed to install on zohocorp.com/santhosh-8457. Reason: Unstable network', who:'Santhosh', where:'santhosh-8457', app:'Firefox 109.0.1', dotColor:'green' },
      { time:'07 Jun 2017  05:01:55', sev:'high', score:91, desc:'Impossible Travel login detected — login from Tor exit node (Romania) followed by internal CORP-NET access within 28 minutes.', who:'m.henderson', where:'CORP-NET', app:'Azure AD Portal', dotColor:'red' },
    ].map((e,i) => `
      <div class="event-card">
        <div class="event-top">
          <div class="event-top-left">
            <span class="event-dot event-dot-${e.dotColor}">${e.dotColor==='red'?'✕':'⚠'}</span>
            <span class="event-time">${e.time}</span>
            <span class="event-chevron"${e.expanded?' style="transform:rotate(180deg)"':''}>▾</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px;">
            <span class="badge badge-${e.sev}">${cap(e.sev)} ${e.score}</span>
          </div>
        </div>
        <div class="event-desc">${e.desc}</div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-left:32px;">
          <div class="event-meta" style="margin-left:0;">
            <span><span class="event-meta-label">Who</span><span class="event-meta-val">${e.who}</span></span>
            <span><span class="event-meta-label">Where</span><span class="event-meta-val">${e.where}</span></span>
            <span><span class="event-meta-label">Application Name</span><span class="event-meta-val">${e.app}</span></span>
          </div>
          <button class="btn-run-pb" onclick="event.stopPropagation();showToast('▶','Running playbook for event ${i+1}…')">
            <svg width="11" height="11" fill="currentColor" stroke="none" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            Run Playbook
          </button>
        </div>
        <div class="event-actions">
          <span class="event-link" onclick="showToast('🔎','Opening event details…')">Details</span>
        </div>
      </div>
    `).join('')}
  `;
}

/* ── CHECKPOINT: Original renderOverviewTab (revert target) ──────
function renderOverviewTab_ORIGINAL() {
  document.getElementById('tabContent').innerHTML = `
    <div style="padding:4px 0;">
      <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:12px;">Alert Overview</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
        ${[
          {lbl:'Alert ID', val:'#ALT-2024-8901'},
          {lbl:'Created', val:'2026-03-24 03:41:22'},
          {lbl:'Source', val:'SIEM Correlation Engine'},
          {lbl:'Detection Rule', val:'Impossible Travel v2.1'},
          {lbl:'Log Source', val:'Azure AD + Windows Event'},
          {lbl:'MITRE Tactic', val:'Initial Access / Exfiltration'},
        ].map(r=>`
          <div style="background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:9px 12px;">
            <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px;">${r.lbl}</div>
            <div style="font-size:12.5px;color:var(--text-primary);font-weight:500;">${r.val}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}
── END CHECKPOINT ──────────────────────────────────────────── */

function renderOverviewTab() {
  const a = ALERTS.find(x=>x.id===activeAlertId) || ALERTS[0];
  document.getElementById('tabContent').innerHTML = `
    <div style="padding:4px 0;display:flex;flex-direction:column;gap:16px;">

      <!-- ═══ Section 1: Alert Identity ═══ -->
      <div>
        <div class="ov-section-title">Alert Identity</div>
        <div class="ov-grid">
          ${[
            {lbl:'Alert ID',       val:'#ALT-2024-8901',              icon:'🔖'},
            {lbl:'Created',        val:'2026-03-24 03:41:22 UTC',     icon:'🕐'},
            {lbl:'Source',         val:'SIEM Correlation Engine',      icon:'📡'},
            {lbl:'Detection Rule', val:'Impossible Travel v2.1',       icon:'⚙'},
            {lbl:'Log Sources',    val:'Azure AD Sign-In, Windows Security (Event 4624)', icon:'📋'},
            {lbl:'Alert Type',     val:'CORRELATION',                  icon:'🔗', chip:true, chipColor:'#2563eb'},
            {lbl:'Correlation Window', val:'03:12:44 – 03:41:22 UTC (28 min)', icon:'⏱'},
            {lbl:'Matched Events', val:'250 events across 3 log sources', icon:'📊'},
          ].map(r=>'<div class="ov-card"><div class="ov-card-icon">'+r.icon+'</div><div><div class="ov-card-lbl">'+r.lbl+'</div>'+(r.chip?'<span style="display:inline-block;font-size:10.5px;font-weight:700;color:'+r.chipColor+';background:'+r.chipColor+'15;padding:2px 8px;border-radius:3px;">'+r.val+'</span>':'<div class="ov-card-val">'+r.val+'</div>')+'</div></div>').join('')}
        </div>
      </div>

      <!-- ═══ Section 2: Affected User ═══ -->
      <div>
        <div class="ov-section-title">Affected User</div>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:14px 16px;">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
            <div style="width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#8b5cf6);display:flex;align-items:center;justify-content:center;color:#fff;font-size:14px;font-weight:700;">MH</div>
            <div>
              <div style="font-size:13px;font-weight:700;color:var(--text-primary);">m.henderson</div>
              <div style="font-size:11px;color:var(--text-dim);">m.henderson@corp.local · IT Support Engineer</div>
            </div>
            <span style="margin-left:auto;font-size:10px;font-weight:700;color:#dc2626;background:#fde8e8;padding:3px 8px;border-radius:10px;">Risk: 94/100</span>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;">
            ${[
              {lbl:'Department',    val:'IT — Marketing Floor'},
              {lbl:'Manager',       val:'j.williams (IT Manager)'},
              {lbl:'Account Type',  val:'Standard User (No admin)'},
              {lbl:'Last Logon',    val:'2026-03-24 14:41:10 UTC'},
              {lbl:'Logon Baseline',val:'08:00 – 18:00 EST (weekdays)'},
              {lbl:'OU',            val:'OU=ITSupport,DC=corp,DC=local'},
            ].map(r=>`
              <div style="padding:6px 0;">
                <div style="font-size:9.5px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px;">${r.lbl}</div>
                <div style="font-size:11.5px;color:var(--text-primary);font-weight:500;">${r.val}</div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>

      <!-- ═══ Section 3: Affected Device ═══ -->
      <div>
        <div class="ov-section-title">Affected Device</div>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:14px 16px;">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;">
            <div style="width:34px;height:34px;border-radius:6px;background:var(--surface-3);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:16px;">🖥</div>
            <div>
              <div style="font-size:13px;font-weight:700;color:var(--text-primary);">CORP-WS-045</div>
              <div style="font-size:11px;color:var(--text-dim);">Windows 11 Pro · 10.18.1.81 · NYC Office VLAN-120</div>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;">
            ${[
              {lbl:'Host Type',     val:'Windows Workstation'},
              {lbl:'Internal IP',   val:'10.18.1.81'},
              {lbl:'Domain',        val:'CORP.LOCAL'},
              {lbl:'Last Patched',  val:'2026-03-20'},
              {lbl:'Agent Status',  val:'Online — Reporting'},
              {lbl:'Log Sources',   val:'WinEventLog, Sysmon'},
            ].map(r=>`
              <div style="padding:6px 0;">
                <div style="font-size:9.5px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px;">${r.lbl}</div>
                <div style="font-size:11.5px;color:var(--text-primary);font-weight:500;">${r.val}</div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>

      <!-- ═══ Section 4: UEBA Risk Summary ═══ -->
      <div>
        <div class="ov-section-title">UEBA Risk Summary</div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px;">
          <div class="ov-stat-card" style="border-left:3px solid #dc2626;">
            <div class="ov-stat-val" style="color:#dc2626;">94<span style="font-size:11px;font-weight:500;color:var(--text-dim);">/100</span></div>
            <div class="ov-stat-lbl">Risk Score</div>
          </div>
          <div class="ov-stat-card" style="border-left:3px solid #d97706;">
            <div class="ov-stat-val" style="color:#d97706;">↑ +67</div>
            <div class="ov-stat-lbl">24h Change (was 27)</div>
          </div>
          <div class="ov-stat-card" style="border-left:3px solid #7c3aed;">
            <div class="ov-stat-val" style="color:#7c3aed;">7</div>
            <div class="ov-stat-lbl">Anomalies (24h)</div>
          </div>
          <div class="ov-stat-card" style="border-left:3px solid #2563eb;">
            <div class="ov-stat-val" style="color:#2563eb;">4.3×</div>
            <div class="ov-stat-lbl">Above Peer Avg (22)</div>
          </div>
        </div>
      </div>

      <!-- ═══ Section 5: Threat Intelligence ═══ -->
      <div>
        <div class="ov-section-title">Threat Intelligence</div>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;overflow:hidden;">
          <div style="padding:12px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border);">
            <div style="width:34px;height:34px;border-radius:6px;background:#fde8e8;border:1px solid rgba(220,38,38,.2);display:flex;align-items:center;justify-content:center;font-size:15px;">🌐</div>
            <div style="flex:1;">
              <div style="font-size:12.5px;font-weight:700;color:var(--text-primary);">185.220.101.42</div>
              <div style="font-size:10.5px;color:var(--text-dim);">Bucharest, Romania · AS24961 (myLoc managed IT AG)</div>
            </div>
            <span style="font-size:10px;font-weight:700;color:#dc2626;background:#fde8e8;padding:3px 10px;border-radius:10px;">Malicious</span>
          </div>
          <div style="padding:12px 16px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;">
            ${[
              {lbl:'L3C Reputation',  val:'97 / 100', color:'#dc2626'},
              {lbl:'VirusTotal',      val:'12 / 89 vendors flagged', color:'#d97706'},
              {lbl:'AbuseIPDB',       val:'98% confidence malicious', color:'#dc2626'},
              {lbl:'Tor Exit Node',   val:'Yes — confirmed relay', color:'#dc2626'},
              {lbl:'Threat Category', val:'APT / Credential Theft', color:'#7c3aed'},
              {lbl:'First Seen',      val:'2024-11-02 (active 1.4 yrs)', color:'var(--text-secondary)'},
            ].map(r=>`
              <div style="padding:4px 0;">
                <div style="font-size:9.5px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px;">${r.lbl}</div>
                <div style="font-size:11.5px;color:${r.color};font-weight:600;">${r.val}</div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>

      <!-- ═══ Section 6: Incident & Compliance ═══ -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
        <!-- Incident -->
        <div>
          <div class="ov-section-title">Linked Incident</div>
          <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:14px 16px;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
              <span style="font-size:14px;">📂</span>
              <span style="font-size:12.5px;font-weight:700;color:var(--blue);cursor:pointer;" onclick="showToast('📂','Opening incident INC-2026-00142…')">INC-2026-00142</span>
              <span style="font-size:10px;font-weight:600;color:#d97706;background:#fef3c7;padding:2px 7px;border-radius:3px;">In Progress</span>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;">
              ${[
                {lbl:'Created',       val:'2026-03-24 03:45'},
                {lbl:'Owner',         val:'Johnson Williams'},
                {lbl:'Evidence Count', val:'3 alerts + 2 logs'},
                {lbl:'Priority',      val:'P1 — Critical'},
              ].map(r=>`
                <div style="padding:3px 0;">
                  <div style="font-size:9.5px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:1px;">${r.lbl}</div>
                  <div style="font-size:11px;color:var(--text-primary);font-weight:500;">${r.val}</div>
                </div>
              `).join('')}
            </div>
          </div>
        </div>

        <!-- Compliance -->
        <div>
          <div class="ov-section-title">Compliance Mapping</div>
          <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:14px 16px;">
            <div style="display:flex;flex-wrap:wrap;gap:6px;">
              ${[
                {std:'PCI DSS', req:'Req 10.2.4', desc:'Invalid access attempts'},
                {std:'HIPAA', req:'§164.312(b)', desc:'Audit controls'},
                {std:'SOX', req:'Section 404', desc:'Access monitoring'},
                {std:'GDPR', req:'Art. 33', desc:'Breach notification'},
                {std:'ISO 27001', req:'A.12.4.1', desc:'Event logging'},
                {std:'NIST 800-53', req:'AU-6', desc:'Audit review'},
              ].map(r=>`
                <div class="ov-compliance-chip" onclick="showToast('📋','Opening ${r.std} ${r.req} report…')">
                  <div style="font-size:10.5px;font-weight:700;color:var(--text-primary);">${r.std}</div>
                  <div style="font-size:9px;color:var(--text-dim);">${r.req} · ${r.desc}</div>
                </div>
              `).join('')}
            </div>
          </div>
        </div>
      </div>

      <!-- ═══ Section 7: Related Alerts ═══ -->
      <div>
        <div class="ov-section-title">Related Alerts <span style="font-size:11px;font-weight:500;color:var(--text-dim);margin-left:6px;">12 similar in last 7 days</span></div>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;overflow:hidden;">
          ${[
            {time:'Mar 24, 03:38', name:'LAN ARP Spoofing — MITM', sev:'critical', src:'CORP-WS-045', mitre:'T1557.002'},
            {time:'Mar 24, 03:36', name:'Suspicious Service Installed', sev:'high', src:'CORP-WS-045', mitre:'T1543.003'},
            {time:'Mar 24, 03:37', name:'Encoded PowerShell Execution', sev:'critical', src:'CORP-WS-045', mitre:'T1059.001'},
            {time:'Mar 23, 22:15', name:'Impossible Travel (m.henderson)', sev:'high', src:'Azure AD', mitre:'T1078.004'},
          ].map((r,i)=>`
            <div style="display:flex;align-items:center;gap:10px;padding:9px 16px;${i<3?'border-bottom:1px solid var(--border);':''}cursor:pointer;transition:background .12s;" onmouseover="this.style.background='var(--navy-light)'" onmouseout="this.style.background='transparent'">
              <span style="width:6px;height:6px;border-radius:50%;background:${r.sev==='critical'?'#dc2626':'#d97706'};flex-shrink:0;"></span>
              <span style="font-size:10.5px;color:var(--text-dim);min-width:90px;font-family:var(--mono);">${r.time}</span>
              <span style="flex:1;font-size:11.5px;font-weight:600;color:var(--text-primary);">${r.name}</span>
              <span style="font-size:9.5px;color:var(--text-dim);font-family:var(--mono);">${r.src}</span>
              <span style="font-size:9px;background:rgba(124,58,237,.08);color:#7c3aed;padding:2px 6px;border-radius:3px;font-weight:600;">${r.mitre}</span>
            </div>
          `).join('')}
          <div style="padding:8px 16px;text-align:center;">
            <span style="font-size:11px;color:var(--blue);cursor:pointer;font-weight:600;" onclick="showToast('🔎','Loading all 12 related alerts…')">View all 12 related alerts →</span>
          </div>
        </div>
      </div>

    </div>
  `;
}

function renderPlaceholderTab(name) {
  document.getElementById('tabContent').innerHTML = `
    <div style="flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;padding:40px;text-align:center;">
      <div style="font-size:32px;">📂</div>
      <div style="font-size:14px;font-weight:600;color:var(--text-primary);">${name}</div>
      <div style="font-size:12.5px;color:var(--text-secondary);">No ${name.toLowerCase()} data available for this alert.</div>
    </div>
  `;
}

/* ── INTERACTIONS ────────────────────────────────────────────── */
