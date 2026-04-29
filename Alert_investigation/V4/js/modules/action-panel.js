/* action-panel.js — SOC action panels (log search, UEBA, block, vulnerabilities, etc.)
 * Depends on: entities.js, utils.js */
function showActionPanel(actionType, entityId) {
  const panel = document.getElementById('actionPanel');
  const title = document.getElementById('apTitle');
  const badge = document.getElementById('apBadge');
  const body = document.getElementById('apBody');
  const actions = document.getElementById('apActions');
  if (!panel) return;

  const e = ENTITIES[entityId];
  const eName = e ? (e.modalTitle.split('·').pop()?.trim() || e.modalTitle) : entityId;
  const eType = e ? e.type : 'unknown';

  badge.style.display = 'none';
  actions.style.display = 'none';
  actions.innerHTML = '';

  const content = buildActionContent(actionType, entityId, eName, eType, e);
  if (!content) return;
  title.textContent = content.title;
  if (content.badge) {
    badge.textContent = content.badge.text;
    badge.className = 'ap-badge ' + content.badge.cls;
    badge.style.display = '';
  }
  body.innerHTML = content.html;
  if (content.actions) {
    actions.innerHTML = content.actions;
    actions.style.display = 'flex';
  }

  panel.classList.add('visible');
}

function closeActionPanel() {
  const panel = document.getElementById('actionPanel');
  if (panel) panel.classList.remove('visible');
}

function buildActionContent(action, eid, name, type, entity) {
  const ts = '03 Apr 2026';
  switch (action) {

  // ═══════════════ SEARCH IN LOGS ═══════════════
  case 'searchLogs': {
    const logsByType = {
      user: [
        { time:'15:37:01', src:'Windows Security', id:'4624', msg:`Logon Success — ${name} from 185.220.101.42 (Type 10)`, sev:'high' },
        { time:'15:36:22', src:'Windows Security', id:'4648', msg:`Explicit credential used — ${name} → CORP-WS-045`, sev:'high' },
        { time:'15:35:10', src:'Azure AD Sign-In', id:'—', msg:`Interactive login from Bucharest, Romania (Tor exit)`, sev:'crit' },
        { time:'15:30:01', src:'Windows Security', id:'4624', msg:`Logon Success — ${name} from 10.18.1.81 (Type 3)`, sev:'info' },
        { time:'14:38:22', src:'UEBA', id:'UBA-1847', msg:`Risk score spike: 27 → 94 in 30 min`, sev:'crit' },
        { time:'14:32:10', src:'Azure AD Sign-In', id:'—', msg:`MFA bypassed — token replay from Bucharest`, sev:'crit' },
        { time:'14:20:00', src:'Windows Security', id:'4624', msg:`Logon Success — ${name} from 10.18.1.81 (Type 2)`, sev:'low' },
      ],
      device: [
        { time:'15:36:30', src:'Sysmon', id:'11', msg:`File created: C:\\Temp\\svchost_update.dll (842 KB, unsigned)`, sev:'crit' },
        { time:'15:36:22', src:'Windows Security', id:'7045', msg:`Service installed: WinUpdateSvc (NT AUTHORITY\\SYSTEM)`, sev:'high' },
        { time:'15:36:22', src:'Sysmon', id:'1', msg:`Process created: powershell.exe -encodedcommand …`, sev:'crit' },
        { time:'15:35:50', src:'Windows Security', id:'4688', msg:`New process: cmd.exe /c whoami && ipconfig /all`, sev:'high' },
        { time:'15:37:01', src:'Sysmon', id:'3', msg:`Network connection: powershell.exe → 185.220.101.42:443`, sev:'crit' },
        { time:'14:30:01', src:'Windows Update', id:'19', msg:`Update KB5034441 installation started`, sev:'low' },
      ],
      ip: [
        { time:'15:37:01', src:'Firewall', id:'CONN', msg:`Outbound 185.220.101.42:443 from CORP-WS-045 (14.2 KB sent)`, sev:'crit' },
        { time:'15:36:45', src:'Firewall', id:'CONN', msg:`Outbound 185.220.101.42:443 from powershell.exe (beacon)`, sev:'crit' },
        { time:'14:32:10', src:'Azure AD', id:'SIGN', msg:`Sign-in from 185.220.101.42 — m.henderson — MFA bypassed`, sev:'crit' },
        { time:'14:32:05', src:'Threat Intel', id:'IOC', msg:`IP flagged by AbuseIPDB (100%), VirusTotal (14/90)`, sev:'high' },
        { time:'14:31:58', src:'Firewall', id:'CONN', msg:`Inbound connection attempt from 185.220.101.42:8443`, sev:'high' },
      ],
      service: [
        { time:'15:36:22', src:'Azure AD Audit', id:'SIGN', msg:`Sign-in anomaly: ${name} from Tor exit node`, sev:'crit' },
        { time:'15:34:00', src:'SharePoint Audit', id:'FILE', msg:`24 files downloaded from /Finance/Sensitive in 3 min`, sev:'crit' },
        { time:'14:33:00', src:'Azure AD Audit', id:'APP', msg:`OAuth consent: FileSync Pro (unverified publisher)`, sev:'high' },
        { time:'14:32:10', src:'Azure AD', id:'AUTH', msg:`Token issued: Files.ReadWrite.All scope`, sev:'high' },
      ],
      process: [
        { time:'15:37:01', src:'Sysmon', id:'3', msg:`${name} → 185.220.101.42:443 (HTTPS, 14.2 KB sent)`, sev:'crit' },
        { time:'15:36:45', src:'Sysmon', id:'3', msg:`${name} → 91.215.85.12:8080 (staging-payload.net)`, sev:'crit' },
        { time:'15:36:30', src:'Sysmon', id:'11', msg:`File write: svchost_update.dll (hash: a3f4b8c1…)`, sev:'high' },
        { time:'15:36:28', src:'Sysmon', id:'10', msg:`Process access: SAM database read attempt`, sev:'crit' },
        { time:'15:36:22', src:'Sysmon', id:'1', msg:`Process start: -nop -w hidden -encodedcommand …`, sev:'high' },
      ],
      alert: [
        { time:'15:37:01', src:'UEBA', id:'ALT-847', msg:`Impossible Travel: NY → Bucharest in 12 min`, sev:'crit' },
        { time:'15:36:22', src:'SIEM', id:'COR-221', msg:`Correlated: ARP Spoofing + Service Install + PowerShell`, sev:'crit' },
        { time:'14:38:22', src:'SIEM', id:'COR-220', msg:`LAN ARP Spoofing detected from CORP-WS-045`, sev:'high' },
      ]
    };
    const logs = logsByType[type] || logsByType.user;
    let rows = logs.map(l => `<tr>
      <td style="white-space:nowrap;font-family:'IBM Plex Mono',monospace;font-size:10px;color:#8a94a6;">${ts} ${l.time}</td>
      <td><span class="ap-tag ap-tag-${l.sev}">${l.sev.toUpperCase()}</span></td>
      <td style="white-space:nowrap;">${l.src}</td>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;">${l.id}</td>
      <td>${l.msg}</td>
    </tr>`).join('');
    return {
      title: `Log Search — ${name}`,
      badge: { text: `${logs.length} results`, cls: 'ap-tag-info' },
      html: `<div class="ap-section">
        <div class="ap-section-title">📋 Log Events (last 24h)</div>
        <div style="overflow-x:auto;">
        <table class="ap-table"><thead><tr><th>Timestamp</th><th>Sev</th><th>Source</th><th>Event ID</th><th>Message</th></tr></thead><tbody>${rows}</tbody></table>
        </div>
      </div>
      <div class="ap-section" style="font-size:10px;color:#8a94a6;">Query: <code style="background:#f5f7fa;padding:2px 6px;border-radius:3px;font-size:10px;">entity="${name}" AND time > now-24h | sort timestamp desc</code></div>`,
      actions: `<button class="ap-btn ap-btn-outline" onclick="showToast('📋','Exporting ${logs.length} log entries…')">Export CSV</button>
        <button class="ap-btn ap-btn-primary" onclick="showToast('🔍','Opening in Log Explorer…')">Open in Log Explorer</button>`
    };
  }

  // ═══════════════ UEBA TIMELINE ═══════════════
  case 'uebaTimeline': {
    const score = type === 'user' ? 94 : 67;
    const peerAvg = type === 'user' ? 22 : 15;
    const events = [
      { time:'15:37', score:94, delta:'+12', event:'C2 beacon detected — outbound to Tor exit', risk:'crit' },
      { time:'15:36', score:82, delta:'+15', event:'Encoded PowerShell execution (hidden window)', risk:'crit' },
      { time:'15:35', score:67, delta:'+8', event:'Service installed: WinUpdateSvc (unsigned)', risk:'high' },
      { time:'15:34', score:59, delta:'+18', event:'24 files bulk-downloaded from SharePoint /Finance', risk:'high' },
      { time:'14:38', score:41, delta:'+14', event:'LAN ARP Spoofing detected from CORP-WS-045', risk:'high' },
      { time:'14:32', score:27, delta:'+0', event:'Login from Bucharest (Tor) — MFA bypassed', risk:'crit' },
      { time:'09:15', score:22, delta:'+0', event:'Normal interactive logon from NYC office', risk:'low' },
    ];
    let timeline = events.map(ev => `<tr>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;white-space:nowrap;">${ts} ${ev.time}</td>
      <td><strong style="color:${ev.score>70?'#dc2626':ev.score>40?'#ea580c':'#16a34a'};">${ev.score}</strong></td>
      <td style="color:${ev.delta!=='+0'?'#dc2626':'#8a94a6'};font-weight:600;">${ev.delta}</td>
      <td><span class="ap-tag ap-tag-${ev.risk}">${ev.risk.toUpperCase()}</span></td>
      <td>${ev.event}</td>
    </tr>`).join('');
    return {
      title: `UEBA Timeline — ${name}`,
      badge: { text: `Score: ${score}/100`, cls: score > 70 ? 'ap-tag-crit' : 'ap-tag-med' },
      html: `<div class="ap-stat-row">
        <div class="ap-stat"><div class="ap-stat-val" style="color:#dc2626;">${score}</div><div class="ap-stat-label">Risk Score</div></div>
        <div class="ap-stat"><div class="ap-stat-val">${peerAvg}</div><div class="ap-stat-label">Peer Average</div></div>
        <div class="ap-stat"><div class="ap-stat-val" style="color:#dc2626;">4.3×</div><div class="ap-stat-label">Deviation</div></div>
        <div class="ap-stat"><div class="ap-stat-val">7</div><div class="ap-stat-label">Anomalies</div></div>
      </div>
      <div class="ap-section">
        <div class="ap-section-title">📈 Risk Score Progression</div>
        <div class="ap-chart-row"><div class="ap-chart-label">09:00</div><div class="ap-chart-bar"><div class="ap-chart-fill" style="width:22%;background:#16a34a;"></div></div><div class="ap-chart-val">22</div></div>
        <div class="ap-chart-row"><div class="ap-chart-label">14:32</div><div class="ap-chart-bar"><div class="ap-chart-fill" style="width:27%;background:#f59e0b;"></div></div><div class="ap-chart-val">27</div></div>
        <div class="ap-chart-row"><div class="ap-chart-label">14:38</div><div class="ap-chart-bar"><div class="ap-chart-fill" style="width:41%;background:#ea580c;"></div></div><div class="ap-chart-val">41</div></div>
        <div class="ap-chart-row"><div class="ap-chart-label">15:34</div><div class="ap-chart-bar"><div class="ap-chart-fill" style="width:59%;background:#ea580c;"></div></div><div class="ap-chart-val">59</div></div>
        <div class="ap-chart-row"><div class="ap-chart-label">15:36</div><div class="ap-chart-bar"><div class="ap-chart-fill" style="width:82%;background:#dc2626;"></div></div><div class="ap-chart-val">82</div></div>
        <div class="ap-chart-row"><div class="ap-chart-label">15:37</div><div class="ap-chart-bar"><div class="ap-chart-fill" style="width:94%;background:#dc2626;"></div></div><div class="ap-chart-val" style="color:#dc2626;font-weight:800;">94</div></div>
      </div>
      <div class="ap-section">
        <div class="ap-section-title">🕐 Event Timeline</div>
        <table class="ap-table"><thead><tr><th>Time</th><th>Score</th><th>Δ</th><th>Risk</th><th>Event</th></tr></thead><tbody>${timeline}</tbody></table>
      </div>`,
      actions: `<button class="ap-btn ap-btn-outline" onclick="showToast('📊','Opening full UEBA profile…')">Full UEBA Profile</button>
        <button class="ap-btn ap-btn-primary" onclick="showToast('📋','Adding to watchlist…')">Add to Watchlist</button>`
    };
  }

  // ═══════════════ LOGIN ACTIVITY ═══════════════
  case 'loginActivity': {
    closeActionPanel();
    // Switch to the Activity tab in the entity slider
    const body = document.getElementById('edsBody');
    if (body) {
      const actTab = body.querySelector('.eds-tab-panel[data-tab="activity"]');
      if (actTab) {
        body.querySelectorAll('.eds-tab').forEach(t => {
          t.classList.toggle('eds-tab-active', t.textContent.trim() === 'Activity');
        });
        body.querySelectorAll('.eds-tab-panel').forEach(p => {
          p.style.display = p.dataset.tab === 'activity' ? '' : 'none';
        });
      }
    }
    return null;
  }

  // ═══════════════ BLOCK ENTITY ═══════════════
  case 'blockEntity': {
    const isIP = type === 'ip';
    const blockTarget = isIP ? name : `${name} (${eid})`;
    return {
      title: isIP ? `Block IP — ${name}` : `Disable Account — ${name}`,
      badge: { text: 'DESTRUCTIVE', cls: 'ap-tag-crit' },
      html: `<div class="ap-section" style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:14px;margin-bottom:14px;">
        <div style="font-size:12px;font-weight:700;color:#dc2626;margin-bottom:6px;">⚠ Confirm ${isIP ? 'IP Block' : 'Account Disable'}</div>
        <div style="font-size:11px;color:#555e6e;line-height:1.5;">
          ${isIP ? `This will add <strong>${name}</strong> to the global firewall blocklist across all edge devices. All inbound and outbound traffic from this IP will be dropped immediately.` :
          `This will disable the account <strong>${name}</strong> in Active Directory and Azure AD. The user will be signed out of all active sessions within 60 seconds. All OAuth tokens will be revoked.`}
        </div>
      </div>
      <div class="ap-section">
        <div class="ap-section-title">📋 Impact Assessment</div>
        <table class="ap-table">
          <tr><td style="font-weight:600;">Target</td><td>${blockTarget}</td></tr>
          <tr><td style="font-weight:600;">Scope</td><td>${isIP ? 'All firewalls, WAF, and proxy servers' : 'Active Directory + Azure AD + M365'}</td></tr>
          <tr><td style="font-weight:600;">Active Sessions</td><td>${isIP ? '2 connections from this IP' : '3 active sessions (laptop, phone, VPN)'}</td></tr>
          <tr><td style="font-weight:600;">Reversal</td><td>${isIP ? 'Manual unblock required from Firewall console' : 'Re-enable via AD admin console + manager approval'}</td></tr>
          <tr><td style="font-weight:600;">Notification</td><td>${isIP ? 'SOC team + Network team notified' : 'Manager (j.williams) + HR notified automatically'}</td></tr>
        </table>
      </div>`,
      actions: `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-danger" onclick="showToast('${isIP?'🚫':'🔒'}','${isIP?name+' added to blocklist':'Account '+name+' disabled'}');closeActionPanel();">${isIP ? '🚫 Block IP Now' : '🔒 Disable Account'}</button>`
    };
  }

  // ═══════════════ VULNERABILITIES ═══════════════
  case 'vulnerabilities': {
    const vulns = [
      { cve:'CVE-2024-21412', title:'SmartScreen Bypass', cvss:8.1, sev:'high', status:'Unpatched', exploit:'Yes' },
      { cve:'CVE-2024-30088', title:'Kernel Elevation of Privilege', cvss:9.8, sev:'crit', status:'Unpatched', exploit:'Yes (in wild)' },
      { cve:'CVE-2023-36884', title:'Office HTML RCE', cvss:8.3, sev:'high', status:'Mitigated', exploit:'PoC available' },
      { cve:'CVE-2024-38063', title:'TCP/IP IPv6 RCE', cvss:9.8, sev:'crit', status:'Unpatched', exploit:'No' },
    ];
    let rows = vulns.map(v => `<tr>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;">${v.cve}</td>
      <td>${v.title}</td>
      <td><strong style="color:${v.cvss>=9?'#dc2626':v.cvss>=7?'#ea580c':'#b45309'};">${v.cvss}</strong></td>
      <td><span class="ap-tag ap-tag-${v.sev}">${v.sev.toUpperCase()}</span></td>
      <td style="color:${v.status==='Unpatched'?'#dc2626':'#16a34a'};font-weight:600;">${v.status}</td>
      <td>${v.exploit}</td>
    </tr>`).join('');
    return {
      title: `Vulnerabilities — ${name}`,
      badge: { text: `${vulns.filter(v=>v.status==='Unpatched').length} unpatched`, cls: 'ap-tag-crit' },
      html: `<div class="ap-stat-row">
        <div class="ap-stat"><div class="ap-stat-val" style="color:#dc2626;">${vulns.length}</div><div class="ap-stat-label">Total CVEs</div></div>
        <div class="ap-stat"><div class="ap-stat-val" style="color:#dc2626;">${vulns.filter(v=>v.cvss>=9).length}</div><div class="ap-stat-label">Critical</div></div>
        <div class="ap-stat"><div class="ap-stat-val">${vulns.filter(v=>v.exploit.includes('Yes')).length}</div><div class="ap-stat-label">Exploitable</div></div>
      </div>
      <div class="ap-section">
        <div class="ap-section-title">🛡 Vulnerability Assessment</div>
        <div style="overflow-x:auto;"><table class="ap-table"><thead><tr><th>CVE</th><th>Title</th><th>CVSS</th><th>Severity</th><th>Status</th><th>Exploit</th></tr></thead><tbody>${rows}</tbody></table></div>
      </div>`,
      actions: `<button class="ap-btn ap-btn-outline" onclick="showToast('📋','Exporting vulnerability report…')">Export Report</button>
        <button class="ap-btn ap-btn-primary" onclick="showToast('🔄','Initiating emergency patch…')">Emergency Patch</button>`
    };
  }

  // ═══════════════ MISCONFIGURATIONS ═══════════════
  case 'misconfigurations': {
    const misconfigs = [
      { id:'CIS-1.1.1', title:'Guest account not disabled', sev:'high', benchmark:'CIS Windows 11', status:'Fail' },
      { id:'CIS-2.3.7', title:'SMBv1 enabled', sev:'crit', benchmark:'CIS Windows 11', status:'Fail' },
      { id:'CIS-18.9.5', title:'PowerShell Script Block Logging disabled', sev:'med', benchmark:'CIS Windows 11', status:'Fail' },
    ];
    let rows = misconfigs.map(m => `<tr>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;">${m.id}</td>
      <td>${m.title}</td>
      <td><span class="ap-tag ap-tag-${m.sev}">${m.sev.toUpperCase()}</span></td>
      <td>${m.benchmark}</td>
      <td style="color:#dc2626;font-weight:700;">${m.status}</td>
    </tr>`).join('');
    return {
      title: `Misconfigurations — ${name}`,
      badge: { text: `${misconfigs.length} issues`, cls: 'ap-tag-high' },
      html: `<div class="ap-section">
        <div class="ap-section-title">⚙ CIS Benchmark Violations</div>
        <table class="ap-table"><thead><tr><th>ID</th><th>Issue</th><th>Severity</th><th>Benchmark</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>
      </div>`,
      actions: `<button class="ap-btn ap-btn-primary" onclick="showToast('🔧','Applying auto-remediation…')">Auto-Remediate</button>`
    };
  }

  // ═══════════════ CONFIG ISSUES (Service) ═══════════════
  case 'configIssues': {
    const issues = [
      { title:'Legacy Authentication Enabled', desc:'IMAP/POP3 allowed — bypasses MFA for all users', sev:'crit', fix:'Disable via Conditional Access policy' },
      { title:'No Conditional Access for Risky Logins', desc:'Medium/High risk sign-ins not blocked or challenged', sev:'high', fix:'Enable risk-based Conditional Access' },
      { title:'Self-Service Password Reset without MFA', desc:'Users can reset passwords with only email verification', sev:'med', fix:'Require MFA for SSPR' },
    ];
    let items = issues.map(i => `<div style="background:#fff;border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:8px;">
      <div style="display:flex;justify-content:space-between;align-items:center;"><strong style="font-size:11.5px;">${i.title}</strong><span class="ap-tag ap-tag-${i.sev}">${i.sev.toUpperCase()}</span></div>
      <div style="font-size:10.5px;color:#555e6e;margin-top:4px;">${i.desc}</div>
      <div style="font-size:10px;color:var(--blue);margin-top:6px;font-weight:600;">💡 Fix: ${i.fix}</div>
    </div>`).join('');
    return {
      title: `Configuration Issues — ${name}`,
      badge: { text: `${issues.length} issues`, cls: 'ap-tag-high' },
      html: `<div class="ap-section">${items}</div>`,
      actions: `<button class="ap-btn ap-btn-primary" onclick="showToast('⚙','Opening Azure AD admin console…')">Open Admin Console</button>`
    };
  }

  // ═══════════════ AUDIT LOGS (Service) ═══════════════
  case 'auditLogs': {
    const logs = [
      { time:'15:36:22', actor:'m.henderson', action:'Sign-In', target:'Azure AD Portal', result:'Success', risk:'high' },
      { time:'14:33:00', actor:'m.henderson', action:'Consent to App', target:'FileSync Pro', result:'Success', risk:'crit' },
      { time:'14:32:10', actor:'m.henderson', action:'Acquire Token', target:'Graph API — Files.ReadWrite.All', result:'Success', risk:'high' },
      { time:'10:15:00', actor:'admin', action:'Sign-In', target:'Azure AD Portal', result:'Success', risk:'low' },
      { time:'09:00:00', actor:'SYSTEM', action:'CA Policy Evaluated', target:'Require MFA for admins', result:'Pass', risk:'low' },
    ];
    let rows = logs.map(l => `<tr>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;white-space:nowrap;">${ts} ${l.time}</td>
      <td>${l.actor}</td><td>${l.action}</td><td>${l.target}</td>
      <td>${l.result}</td>
      <td><span class="ap-tag ap-tag-${l.risk}">${l.risk.toUpperCase()}</span></td>
    </tr>`).join('');
    return {
      title: `Audit Log — ${name}`,
      html: `<div class="ap-section">
        <div class="ap-section-title">📋 Azure AD Audit Events</div>
        <div style="overflow-x:auto;"><table class="ap-table"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>Risk</th></tr></thead><tbody>${rows}</tbody></table></div>
      </div>`
    };
  }

  // ═══════════════ NETWORK ACTIVITY (Process) ═══════════════
  case 'networkActivity': {
    const conns = [
      { time:'15:37:01', proto:'HTTPS', dest:'185.220.101.42:443', domain:'c2-relay.onion.ws', bytes:'14.2 KB', dir:'Outbound', flag:true },
      { time:'15:36:45', proto:'HTTP', dest:'91.215.85.12:8080', domain:'staging-payload.net', bytes:'2.1 KB', dir:'Outbound', flag:true },
      { time:'15:36:30', proto:'SMB', dest:'10.0.0.5:445', domain:'CORP-DC-01', bytes:'4.8 KB', dir:'Outbound', flag:false },
    ];
    let rows = conns.map(c => `<tr${c.flag?' style="background:#fef2f2;"':''}>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;white-space:nowrap;">${ts} ${c.time}</td>
      <td>${c.proto}</td>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;">${c.dest}</td>
      <td>${c.domain}</td><td>${c.bytes}</td>
      <td>${c.dir} ${c.flag?'<span class="ap-tag ap-tag-crit">C2</span>':''}</td>
    </tr>`).join('');
    return {
      title: `Network Activity — ${name}`,
      badge: { text: `${conns.filter(c=>c.flag).length} C2 connections`, cls: 'ap-tag-crit' },
      html: `<div class="ap-section">
        <div class="ap-section-title">🌐 Network Connections</div>
        <div style="overflow-x:auto;"><table class="ap-table"><thead><tr><th>Time</th><th>Protocol</th><th>Destination</th><th>Domain</th><th>Data</th><th>Direction</th></tr></thead><tbody>${rows}</tbody></table></div>
      </div>`,
      actions: `<button class="ap-btn ap-btn-danger" onclick="showToast('🚫','Blocking C2 domains in firewall…')">Block C2 Domains</button>`
    };
  }

  // ═══════════════ KILL PROCESS ═══════════════
  case 'killProcess': {
    return {
      title: `Kill Process — ${name}`,
      badge: { text: 'DESTRUCTIVE', cls: 'ap-tag-crit' },
      html: `<div class="ap-section" style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:14px;margin-bottom:14px;">
        <div style="font-size:12px;font-weight:700;color:#dc2626;margin-bottom:6px;">⚠ Confirm Process Termination</div>
        <div style="font-size:11px;color:#555e6e;line-height:1.5;">This will remotely terminate <strong>${name}</strong> and all child processes on the target host. Any unsaved data will be lost.</div>
      </div>
      <div class="ap-section">
        <div class="ap-section-title">📋 Process Details</div>
        <table class="ap-table">
          <tr><td style="font-weight:600;">Process</td><td>${name}</td></tr>
          <tr><td style="font-weight:600;">PID</td><td>4892</td></tr>
          <tr><td style="font-weight:600;">Child Processes</td><td>cmd.exe (5120), certutil.exe (5244)</td></tr>
          <tr><td style="font-weight:600;">Host</td><td>CORP-WS-045</td></tr>
          <tr><td style="font-weight:600;">Active Connections</td><td>2 C2 beacons (185.220.101.42, 91.215.85.12)</td></tr>
        </table>
      </div>`,
      actions: `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-danger" onclick="showToast('⊘','Process ${name} (PID 4892) + 2 children terminated');closeActionPanel();">⊘ Kill Process Tree</button>`
    };
  }

  // ═══════════════ REVOKE TOKENS ═══════════════
  case 'revokeTokens': {
    const tokens = [
      { app:'FileSync Pro', scope:'Files.ReadWrite.All, Mail.ReadWrite', issued:'14:33', src:'Bucharest (Tor)', risk:'crit' },
      { app:'Outlook Web', scope:'Mail.Read', issued:'09:15', src:'New York', risk:'low' },
      { app:'Teams Desktop', scope:'Chat.Read', issued:'09:15', src:'New York', risk:'low' },
    ];
    let rows = tokens.map(t => `<tr${t.risk==='crit'?' style="background:#fef2f2;"':''}>
      <td>${t.app} ${t.risk==='crit'?'<span class="ap-tag ap-tag-crit">SUSPICIOUS</span>':''}</td>
      <td style="font-size:10px;font-family:'IBM Plex Mono',monospace;">${t.scope}</td>
      <td>${ts} ${t.issued}</td><td>${t.src}</td>
    </tr>`).join('');
    return {
      title: `Revoke Tokens — ${name}`,
      badge: { text: `${tokens.length} active tokens`, cls: 'ap-tag-high' },
      html: `<div class="ap-section">
        <div class="ap-section-title">🔑 Active OAuth Tokens</div>
        <table class="ap-table"><thead><tr><th>Application</th><th>Scope</th><th>Issued</th><th>Source</th></tr></thead><tbody>${rows}</tbody></table>
      </div>`,
      actions: `<button class="ap-btn ap-btn-outline" onclick="showToast('🔑','Revoking FileSync Pro token only…')">Revoke Suspicious Only</button>
        <button class="ap-btn ap-btn-danger" onclick="showToast('🔑','All ${tokens.length} tokens revoked for ${name}')">Revoke All Tokens</button>`
    };
  }

  // ═══════════════ FORCE PASSWORD RESET ═══════════════
  case 'forcePasswordReset': {
    return {
      title: `Force Password Reset — ${name}`,
      badge: { text: 'ACTION', cls: 'ap-tag-high' },
      html: `<div class="ap-section" style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:14px;margin-bottom:14px;">
        <div style="font-size:12px;font-weight:700;color:#b45309;margin-bottom:6px;">🔄 Password Reset Confirmation</div>
        <div style="font-size:11px;color:#555e6e;line-height:1.5;">The user will be forced to change their password at next login. All active sessions will be invalidated. MFA will be required for re-authentication.</div>
      </div>
      <div class="ap-section">
        <table class="ap-table">
          <tr><td style="font-weight:600;">User</td><td>${name}</td></tr>
          <tr><td style="font-weight:600;">Current Password Age</td><td style="color:#dc2626;">142 days (policy: 90 days) ⚠</td></tr>
          <tr><td style="font-weight:600;">Last Changed</td><td>2025-11-14</td></tr>
          <tr><td style="font-weight:600;">MFA Status</td><td>Will require re-enrollment</td></tr>
          <tr><td style="font-weight:600;">Active Sessions</td><td>3 (will be terminated)</td></tr>
        </table>
      </div>`,
      actions: `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-danger" onclick="showToast('🔄','Password reset enforced for ${name}. User will be prompted at next login.');closeActionPanel();">🔄 Force Reset</button>`
    };
  }

  // ═══════════════ ISOLATE HOST ═══════════════
  case 'isolateHost': {
    return {
      title: `Isolate Host — ${name}`,
      badge: { text: 'DESTRUCTIVE', cls: 'ap-tag-crit' },
      html: `<div class="ap-section" style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:14px;margin-bottom:14px;">
        <div style="font-size:12px;font-weight:700;color:#dc2626;margin-bottom:6px;">🔒 Network Isolation Confirmation</div>
        <div style="font-size:11px;color:#555e6e;line-height:1.5;">This will immediately isolate <strong>${name}</strong> from the corporate network. The device will retain only management connectivity (EDR agent). All user sessions will be terminated.</div>
      </div>
      <div class="ap-section">
        <table class="ap-table">
          <tr><td style="font-weight:600;">Device</td><td>${name}</td></tr>
          <tr><td style="font-weight:600;">Current User</td><td>m.henderson</td></tr>
          <tr><td style="font-weight:600;">Active Connections</td><td>5 (2 malicious, 3 legitimate)</td></tr>
          <tr><td style="font-weight:600;">EDR Agent</td><td>Active — will maintain connectivity</td></tr>
          <tr><td style="font-weight:600;">Restoration</td><td>Manual release via EDR console</td></tr>
        </table>
      </div>`,
      actions: `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-danger" onclick="showToast('🔒','${name} isolated from network. EDR connectivity maintained.');closeActionPanel();">🔒 Isolate Now</button>`
    };
  }

  // ═══════════════ ADD TO INCIDENT ═══════════════
  case 'addToIncident': {
    return {
      title: `Add to Incident — ${name}`,
      html: `<div class="ap-section">
        <div class="ap-section-title">📌 Select Incident</div>
        <div style="cursor:pointer;border:2px solid var(--blue);background:#eff6ff;border-radius:8px;padding:10px 12px;margin-bottom:8px;">
          <div style="font-size:11.5px;font-weight:700;color:var(--blue);">INC-2026-04-03-001 — Impossible Travel + Data Exfiltration</div>
          <div style="font-size:10px;color:#555e6e;margin-top:2px;">Created 03 Apr 2026 · 7 entities · Assigned: Johnson Williams</div>
        </div>
        <div style="cursor:pointer;border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:8px;">
          <div style="font-size:11.5px;font-weight:600;">INC-2026-04-02-014 — Suspicious Azure AD Activity</div>
          <div style="font-size:10px;color:#555e6e;margin-top:2px;">Created 02 Apr 2026 · 3 entities · Assigned: Sarah Chen</div>
        </div>
        <div style="cursor:pointer;border:1px dashed var(--border);border-radius:8px;padding:10px 12px;text-align:center;">
          <div style="font-size:11px;color:var(--blue);font-weight:600;">+ Create New Incident</div>
        </div>
      </div>`,
      actions: `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-primary" onclick="showToast('📌','${name} added to INC-2026-04-03-001');closeActionPanel();">Add to Selected</button>`
    };
  }

  // ═══════════════ RUN PLAYBOOK ═══════════════
  case 'runPlaybook': {
    return {
      title: `Run Playbook — ${name}`,
      html: `<div class="ap-section">
        <div class="ap-section-title">▶ Available Playbooks</div>
        <div style="cursor:pointer;border:2px solid var(--blue);background:#eff6ff;border-radius:8px;padding:10px 12px;margin-bottom:8px;">
          <div style="display:flex;justify-content:space-between;"><strong style="font-size:11.5px;color:var(--blue);">Impossible Travel Response</strong><span class="ap-tag ap-tag-info">RECOMMENDED</span></div>
          <div style="font-size:10px;color:#555e6e;margin-top:2px;">Auto: Disable account → Revoke tokens → Isolate device → Notify SOC</div>
        </div>
        <div style="cursor:pointer;border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:8px;">
          <strong style="font-size:11.5px;">Data Exfiltration Containment</strong>
          <div style="font-size:10px;color:#555e6e;margin-top:2px;">Auto: Block IPs → Revoke OAuth → Export forensic timeline</div>
        </div>
        <div style="cursor:pointer;border:1px solid var(--border);border-radius:8px;padding:10px 12px;">
          <strong style="font-size:11.5px;">Generic Investigation</strong>
          <div style="font-size:10px;color:#555e6e;margin-top:2px;">Manual: Collect evidence → Assign analyst → Create ticket</div>
        </div>
      </div>`,
      actions: `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-primary" onclick="showToast('▶','Playbook \\'Impossible Travel Response\\' executing…');closeActionPanel();">▶ Run Selected</button>`
    };
  }

  // ═══════════════ CLOSE ALERT ═══════════════
  case 'closeAlert': {
    return {
      title: `Close Alert — ${name}`,
      html: `<div class="ap-section">
        <div class="ap-section-title">✓ Close Reason</div>
        <div style="cursor:pointer;border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:8px;">
          <strong style="font-size:11.5px;">True Positive — Confirmed Threat</strong>
          <div style="font-size:10px;color:#555e6e;margin-top:2px;">Investigation confirmed malicious activity. Incident created.</div>
        </div>
        <div style="cursor:pointer;border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:8px;">
          <strong style="font-size:11.5px;">True Positive — Benign</strong>
          <div style="font-size:10px;color:#555e6e;margin-top:2px;">Activity is legitimate but triggered the alert (e.g., authorized travel).</div>
        </div>
        <div style="cursor:pointer;border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:8px;">
          <strong style="font-size:11.5px;">False Positive</strong>
          <div style="font-size:10px;color:#555e6e;margin-top:2px;">Alert incorrectly fired. Suggest tuning rule.</div>
        </div>
      </div>
      <div class="ap-section">
        <div class="ap-section-title">📝 Notes</div>
        <div contenteditable="true" style="border:1px solid var(--border);border-radius:6px;padding:8px 10px;min-height:50px;font-size:11px;font-family:var(--font);color:var(--text-primary);outline:none;" placeholder="Add investigation notes…"></div>
      </div>`,
      actions: `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-primary" onclick="showToast('✓','Alert closed as True Positive. Incident INC-2026-04-03-001 updated.');closeActionPanel();">Close Alert</button>`
    };
  }

  default:
    return { title: action, html: '<div style="padding:20px;color:#8a94a6;">No data available for this action.</div>' };
  }
}

/* ── ACTION WRAPPERS (for dropdown + context menu inline calls) ── */
function actionSearchLogs(name) { showActionPanel('searchLogs', ctxEntityId); closeDropdowns(); }
function actionUebaTimeline(name) { showActionPanel('uebaTimeline', ctxEntityId); closeDropdowns(); }
function actionLoginActivity(name) { showActionPanel('loginActivity', ctxEntityId); closeDropdowns(); }
function actionVulnerabilities(name) { showActionPanel('vulnerabilities', ctxEntityId); closeDropdowns(); }
function actionMisconfigurations(name) { showActionPanel('misconfigurations', ctxEntityId); closeDropdowns(); }
function actionConfigIssues(name) { showActionPanel('configIssues', ctxEntityId); closeDropdowns(); }
function actionAuditLogs(name) { showActionPanel('auditLogs', ctxEntityId); closeDropdowns(); }
function actionNetworkActivity(name) { showActionPanel('networkActivity', ctxEntityId); closeDropdowns(); }
function actionKillProcess(name) { showActionPanel('killProcess', ctxEntityId); closeDropdowns(); }
function actionRevokeTokens(name) { showActionPanel('revokeTokens', ctxEntityId); closeDropdowns(); }
function actionForcePasswordReset(name) { showActionPanel('forcePasswordReset', ctxEntityId); closeDropdowns(); }
function actionDisableAccount(name) { showActionPanel('blockEntity', ctxEntityId); closeDropdowns(); }
function actionBlockIP(name) { showActionPanel('blockEntity', ctxEntityId); closeDropdowns(); }
function actionIsolateHost(name) { showActionPanel('isolateHost', ctxEntityId); closeDropdowns(); }
function actionAddToIncident(name) { showActionPanel('addToIncident', ctxEntityId); closeDropdowns(); }
function actionRunPlaybook(name) { showActionPanel('runPlaybook', ctxEntityId); closeDropdowns(); }
function actionCloseAlert(name) { showActionPanel('closeAlert', ctxEntityId); closeDropdowns(); }

/* ── DYNAMIC SUMMARY UPDATE ──────────────────────────────────── */
