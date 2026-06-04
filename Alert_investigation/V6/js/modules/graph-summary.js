/* graph-summary.js — Dynamic graph summary / command bar stats
 * Depends on: entities.js, display-config.js, entity-slider.js */
function updateGraphSummary() {
  // Skip nodes/edges that are hidden in partial mode (display:none). The
  // entity chip menu and the malicious / critical pills should reflect
  // only what's actually visible on the canvas.
  const isVisible = el => el.style.display !== 'none'
    && !(el.getAttribute('style') || '').includes('display:none')
    && !(el.getAttribute('style') || '').includes('display: none');
  const allNodes = Array.from(document.querySelectorAll('#graphSvg g.graph-node')).filter(isVisible);
  const allEdges = Array.from(document.querySelectorAll('#graphSvg > line')).filter(isVisible);
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

  // Count by entity type — must mirror the 7-bucket scheme used in graph.js
  // initGraphChips (host / ip / domain / user / file / process / other).
  // SaaS-typed service nodes (SharePoint, Azure AD, OAuth, ...) go to Other,
  // not Process — see V6/device_and_other_entity_spec.md §2.2.
  const SAAS_SVC_RE = /^svc-(azure|aad|sharepoint|exchange|m365|o365|onedrive|teams|salesforce|aws|gcp|okta|oauth|slack|saas)/i;
  const buckets = { host:0, ip:0, domain:0, user:0, file:0, process:0, other:0 };
  const classify = (eid, ent) => {
    const t = ent && ent.type;
    if (t === 'device'  || eid.startsWith('dev-'))    return 'host';
    if (t === 'ip'      || eid.startsWith('ip-'))     return 'ip';
    if (t === 'domain'  || eid.startsWith('domain-')) return 'domain';
    if (t === 'user'    || eid.startsWith('user-'))   return 'user';
    if (t === 'file'    || eid.startsWith('file-'))   return 'file';
    if (t === 'process' || eid.startsWith('proc-'))   return 'process';
    if (t === 'service' || eid.startsWith('svc-')) {
      return SAAS_SVC_RE.test(eid) ? 'other' : 'process';
    }
    if (t === 'alert'   || eid.startsWith('alert-')) return null; // centre, not bucketed
    return 'other';
  };
  allNodes.forEach(n => {
    const eid = n.getAttribute('data-entity') || '';
    const ent = (typeof ENTITIES !== 'undefined') ? ENTITIES[eid] : null;
    const b = classify(eid, ent);
    if (b) buckets[b]++;
  });

  // Update command bar pills in-place (don't wipe entityChip dropdown)
  const setNum = (id, n) => { const el = document.querySelector('#' + id + ' .cmd-pill-num'); if (el) el.textContent = n; };
  setNum('cmdPillMalCount', malCount);
  setNum('cmdPillCritCount', critCount);

  // Update entity chip menu counts
  const countMap = { all: totalEntities, ...buckets };
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

