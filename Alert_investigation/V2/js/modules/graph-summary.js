/* graph-summary.js — Dynamic graph summary / command bar stats
 * Depends on: entities.js, display-config.js, entity-slider.js */
function updateGraphSummary() {
  const allNodes = document.querySelectorAll('#graphSvg g.graph-node');
  const allEdges = document.querySelectorAll('#graphSvg > line');
  const totalEntities = allNodes.length;
  const totalConnections = allEdges.length;

  // Count malicious edges
  let malCount = 0;
  allEdges.forEach(e => {
    if (e.classList.contains('graph-edge-mal')) malCount++;
  });

  // Count critical nodes (those with red glow filter)
  let critCount = 0;
  allNodes.forEach(n => {
    const c = n.querySelector('circle:not(.expand-indicator)');
    if (c && (c.getAttribute('filter') || '').includes('glow-r')) critCount++;
  });

  // Count by entity type
  const typeCounts = { user:0, device:0, ip:0, service:0, process:0, alert:0 };
  allNodes.forEach(n => {
    const eid = n.getAttribute('data-entity');
    const ent = ENTITIES[eid];
    if (ent && typeCounts.hasOwnProperty(ent.type)) typeCounts[ent.type]++;
    else {
      // Infer type from prefix
      if (eid.startsWith('user-')) typeCounts.user++;
      else if (eid.startsWith('dev-')) typeCounts.device++;
      else if (eid.startsWith('ip-')) typeCounts.ip++;
      else if (eid.startsWith('svc-')) typeCounts.service++;
      else if (eid.startsWith('proc-')) typeCounts.process++;
      else if (eid.startsWith('alert-')) typeCounts.alert++;
    }
  });

  // Update command bar pills
  const statsDiv = document.querySelector('.cmd-stats');
  if (statsDiv) {
    statsDiv.innerHTML = `
      <span class="cmd-pill"><span class="cmd-pill-dot" style="background:#3b82f6;"></span>${totalEntities} Entities</span>
      <span class="cmd-pill"><span class="cmd-pill-dot" style="background:#8b5cf6;"></span>${totalConnections} Edges</span>
      <span class="cmd-pill cmd-pill-danger cmd-pill-clickable" onclick="toggleCmdPillPopup(event,'malicious')"><span class="cmd-pill-dot" style="background:#ef4444;"></span>${malCount} Malicious<span class="cmd-pill-caret">▾</span></span>
      <span class="cmd-pill cmd-pill-warn cmd-pill-clickable" onclick="toggleCmdPillPopup(event,'critical')"><span class="cmd-pill-dot" style="background:#f59e0b;"></span>${critCount} Critical<span class="cmd-pill-caret">▾</span></span>
    `;
  }

  // Update entity chip menu counts
  const countMap = { all:totalEntities, user:typeCounts.user, device:typeCounts.device, ip:typeCounts.ip, service:typeCounts.service, process:typeCounts.process, alert:typeCounts.alert };
  const entityMenu = document.getElementById('entityChipMenu');
  if (entityMenu) {
    entityMenu.querySelectorAll('.gcb-option').forEach(opt => {
      const val = opt.getAttribute('data-val');
      const countEl = opt.querySelector('.gcb-count');
      if (countEl && countMap.hasOwnProperty(val)) countEl.textContent = countMap[val];
    });
  }

  // Update findings drawer — add/update/remove dynamic finding
  const findingsDiv = document.getElementById('graphFindings');
  if (findingsDiv) {
    const dynItem = findingsDiv.querySelector('.gf-dynamic');
    if (totalEntities > 9) {
      if (!dynItem) {
        const f = document.createElement('div');
        f.className = 'gf-item gf-dynamic';
        f.innerHTML = `<span class="gf-sev gf-high">NEW</span><span class="gf-text">Graph expanded: ${totalEntities} entities, ${malCount} malicious connections detected</span>`;
        findingsDiv.appendChild(f);
      } else {
        dynItem.querySelector('.gf-text').textContent = `Graph expanded: ${totalEntities} entities, ${malCount} malicious connections detected`;
      }
    } else if (dynItem) {
      dynItem.remove();
    }
  }
}

