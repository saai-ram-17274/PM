/* graph-core.js — Node registry, positioning, drag, pan/zoom, graph open/close
 * Depends on: entities.js, display-config.js, utils.js, app.js (state vars) */
function registerNode(nodeId, label) {
  if (label) nodeRegistry[label.toLowerCase()] = nodeId;
  nodeRegistry[nodeId] = nodeId;
}

function findNodeByLabel(label) {
  if (!label) return null;
  // Check registry first
  const regId = nodeRegistry[label.toLowerCase()];
  if (regId) {
    const el = document.querySelector(`#graphSvg g.graph-node[data-entity="${regId}"]`);
    if (el) return el;
  }
  // Fallback: scan all node labels in SVG
  const allNodes = document.querySelectorAll('#graphSvg g.graph-node');
  for (const n of allNodes) {
    const texts = n.querySelectorAll('text');
    for (const t of texts) {
      if (t.textContent.toLowerCase().trim() === label.toLowerCase().trim()) return n;
    }
  }
  return null;
}

/* Find a position that doesn't overlap existing nodes */
function findFreePosition(srcCx, srcCy, index, total, baseAngle) {
  const svg = document.getElementById('graphSvg');
  const vb = svg.viewBox.baseVal;
  const allNodes = document.querySelectorAll('#graphSvg g.graph-node');
  const positions = [];
  allNodes.forEach(n => {
    const c = n.querySelector('circle:not(.expand-indicator)');
    if (c) positions.push({ x: parseFloat(c.getAttribute('cx')), y: parseFloat(c.getAttribute('cy')) });
  });

  const minDist = 85;       // minimum distance between any two nodes
  const baseDist = 130;     // starting radius from parent
  const angleSpan = Math.PI * 0.9;
  const startAngle = baseAngle - angleSpan / 2;
  const step = total > 1 ? angleSpan / (total - 1) : 0;
  const angle = startAngle + step * index;

  let cx = srcCx + Math.cos(angle) * baseDist;
  let cy = srcCy + Math.sin(angle) * baseDist;

  // Iteratively find a non-overlapping position
  function hasOverlap(px, py) {
    for (const p of positions) {
      const dx = px - p.x, dy = py - p.y;
      if (Math.sqrt(dx * dx + dy * dy) < minDist) return true;
    }
    return false;
  }

  // Try outward spiral if initial position overlaps
  if (hasOverlap(cx, cy)) {
    let found = false;
    for (let ring = 1; ring <= 5 && !found; ring++) {
      const r = baseDist + ring * 60;
      for (let a = 0; a < 12 && !found; a++) {
        const tryAngle = angle + (a * Math.PI / 6) * (a % 2 === 0 ? 1 : -1);
        const tx = srcCx + Math.cos(tryAngle) * r;
        const ty = srcCy + Math.sin(tryAngle) * r;
        if (!hasOverlap(tx, ty)) {
          cx = tx; cy = ty; found = true;
        }
      }
    }
  }

  // Expand viewBox if node goes beyond current bounds (with 50px padding)
  const pad = 50;
  let vbW = vb.width, vbH = vb.height;
  let changed = false;
  if (cx + pad > vbW)  { vbW = cx + pad + 80; changed = true; }
  if (cy + pad > vbH)  { vbH = cy + pad + 80; changed = true; }
  if (cx < pad)        { cx = pad; }  // keep within left bound
  if (cy < pad)        { cy = pad; }  // keep within top bound
  if (changed) {
    svg.setAttribute('viewBox', `0 0 ${Math.round(vbW)} ${Math.round(vbH)}`);
  }

  return { cx: Math.round(cx), cy: Math.round(cy) };
}

function initNodeRegistry() {
  document.querySelectorAll('#graphSvg g.graph-node').forEach(n => {
    const eid = n.getAttribute('data-entity');
    const texts = n.querySelectorAll('text');
    texts.forEach(t => {
      const txt = t.textContent.trim();
      if (txt && txt.length > 1 && !txt.match(/^[\w\d⚠👤⚙◆🖥📁🔑🔔🔧]$/)) {
        nodeRegistry[txt.toLowerCase()] = eid;
      }
    });
    nodeRegistry[eid] = eid;
  });
}

/* ── RENDER ALERT LIST ───────────────────────────────────────── */

function openInvestigationGraph() {
  graphViewActive = true;
  document.getElementById('invContent').style.display = 'none';
  document.getElementById('invGraphView').style.display = 'flex';
  // Hide Zia header and footer in graph view
  document.querySelector('.inv-header').style.display = 'none';
  document.querySelector('.inv-footer').style.display = 'none';
  showToast('✦', 'Investigation Graph loaded — 9 entities, 12 connections');
}

function backToAttackVector() {
  graphViewActive = false;
  closeEntityModal();
  document.getElementById('invGraphView').style.display = 'none';
  document.getElementById('invContent').style.display = 'block';
  // Restore Zia header and footer
  document.querySelector('.inv-header').style.display = 'flex';
  document.querySelector('.inv-footer').style.display = 'flex';
  // ensure Attack Vector sub-tab is active
  document.querySelectorAll('.inv-subtab').forEach(t => t.classList.remove('active'));
  const tabs = document.querySelectorAll('.inv-subtab');
  if (tabs.length > 1) tabs[1].classList.add('active');
  document.getElementById('invTimeline').style.display = 'none';
  document.getElementById('invAttack').style.display = 'block';
}

/* ── Entity Quick Card (Log360-native node info popup) ──────── */

function toggleEmSec(id) {
  const sec = document.getElementById(id);
  if (sec) sec.classList.toggle('collapsed');
}


function makeNodeDraggable(g, circle, iconEl, labelEl, nodeId) {
  let isDragging = false, hasDragged = false;
  let startX = 0, startY = 0, origCx = 0, origCy = 0;
  // Saved offsets captured once at pointerdown (prevents cumulative drift)
  let labelYOff0 = 0;
  let subOffsets = []; // [{el, type:'circle'|'text', offX, offY}]

  function getSvgPoint(clientX, clientY) {
    const svg = document.getElementById('graphSvg');
    const pt = svg.createSVGPoint();
    pt.x = clientX; pt.y = clientY;
    return pt.matrixTransform(svg.getScreenCTM().inverse());
  }

  function onPointerDown(e) {
    if (e.button !== 0) return;
    e.stopPropagation();
    isDragging = true;
    hasDragged = false;
    const svgPt = getSvgPoint(e.clientX, e.clientY);
    startX = svgPt.x; startY = svgPt.y;
    origCx = parseFloat(circle.getAttribute('cx'));
    origCy = parseFloat(circle.getAttribute('cy'));
    // Capture label Y offset once
    labelYOff0 = parseFloat(labelEl.getAttribute('y')) - origCy;
    // Capture offsets of all sub-elements (expand indicators etc) ONCE
    subOffsets = [];
    g.querySelectorAll('circle').forEach(c => {
      if (c === circle) return;
      subOffsets.push({ el: c, type: 'circle', offX: parseFloat(c.getAttribute('cx')) - origCx, offY: parseFloat(c.getAttribute('cy')) - origCy });
    });
    g.querySelectorAll('text').forEach(t => {
      if (t === iconEl || t === labelEl) return;
      subOffsets.push({ el: t, type: 'text', offX: parseFloat(t.getAttribute('x')) - origCx, offY: parseFloat(t.getAttribute('y')) - origCy });
    });
    g.setPointerCapture(e.pointerId);
    g.style.cursor = 'grabbing';
  }

  function onPointerMove(e) {
    if (!isDragging) return;
    const svgPt = getSvgPoint(e.clientX, e.clientY);
    const dx = svgPt.x - startX, dy = svgPt.y - startY;
    if (!hasDragged && Math.abs(dx) < 3 && Math.abs(dy) < 3) return;
    hasDragged = true;
    const newCx = origCx + dx, newCy = origCy + dy;

    // Move main circle, icon, label
    circle.setAttribute('cx', newCx);
    circle.setAttribute('cy', newCy);
    iconEl.setAttribute('x', newCx);
    iconEl.setAttribute('y', newCy + 4);
    labelEl.setAttribute('x', newCx);
    labelEl.setAttribute('y', newCy + labelYOff0);

    // Move sub-elements using saved offsets (no drift)
    subOffsets.forEach(item => {
      if (item.type === 'circle') {
        item.el.setAttribute('cx', newCx + item.offX);
        item.el.setAttribute('cy', newCy + item.offY);
      } else {
        item.el.setAttribute('x', newCx + item.offX);
        item.el.setAttribute('y', newCy + item.offY);
      }
    });

    // Update connected edges + their labels via data attributes
    const svg = document.getElementById('graphSvg');
    svg.querySelectorAll('line[data-source="' + nodeId + '"]').forEach(edge => {
      edge.setAttribute('x1', newCx); edge.setAttribute('y1', newCy);
      const x2 = parseFloat(edge.getAttribute('x2')), y2 = parseFloat(edge.getAttribute('y2'));
      const tgt = edge.getAttribute('data-target');
      const lbl = tgt && svg.querySelector('text[data-source="' + nodeId + '"][data-target="' + tgt + '"]');
      if (lbl) { lbl.setAttribute('x', (newCx + x2) / 2); lbl.setAttribute('y', (newCy + y2) / 2 - 6); }
    });
    svg.querySelectorAll('line[data-target="' + nodeId + '"]').forEach(edge => {
      edge.setAttribute('x2', newCx); edge.setAttribute('y2', newCy);
      const x1 = parseFloat(edge.getAttribute('x1')), y1 = parseFloat(edge.getAttribute('y1'));
      const src = edge.getAttribute('data-source');
      const lbl = src && svg.querySelector('text[data-source="' + src + '"][data-target="' + nodeId + '"]');
      if (lbl) { lbl.setAttribute('x', (x1 + newCx) / 2); lbl.setAttribute('y', (y1 + newCy) / 2 - 6); }
    });
  }

  function onPointerUp(e) {
    isDragging = false;
    g.releasePointerCapture(e.pointerId);
    g.style.cursor = 'pointer';
    if (hasDragged) {
      // Suppress the upcoming click
      const suppress = (ev) => { ev.stopPropagation(); ev.preventDefault(); };
      g.addEventListener('click', suppress, { capture: true, once: true });
    }
  }

  g.style.cursor = 'grab';
  g.addEventListener('pointerdown', onPointerDown);
  g.addEventListener('pointermove', onPointerMove);
  g.addEventListener('pointerup', onPointerUp);
}

/* ── Graph Canvas Chip Menus ─────────────────────────────────── */

function zoomGraph(factor) {
  currentGraphZoom = Math.max(0.3, Math.min(3, currentGraphZoom * factor));
  applyGraphTransform();
}

/* ── Pan / Drag ──────────────────────────────────────────────── */
let graphPanning = false;
let panStartX = 0, panStartY = 0;
let panOffsetX = 0, panOffsetY = 0;

function applyGraphTransform() {
  const svg = document.getElementById('graphSvg');
  if (svg) svg.style.transform = `translate(${panOffsetX}px, ${panOffsetY}px) scale(${currentGraphZoom})`;
}

function resetGraphView() {
  // Collapse all expanded child nodes first
  for (const parentEid of Object.keys(drillDownGroups)) {
    const groups = drillDownGroups[parentEid];
    if (!groups) continue;
    for (const category of Object.keys(groups)) {
      if (groups[category] && groups[category].length > 0) {
        collapseCategory(parentEid, category);
      }
    }
  }
  // Reset zoom and pan
  currentGraphZoom = 1;
  panOffsetX = 0;
  panOffsetY = 0;
  applyGraphTransform();
  setTimeout(() => updateGraphSummary(), 450);
  showToast('🔄', 'Graph reset — all expanded nodes collapsed');
}

function initGraphPan() {
  const canvas = document.getElementById('graphCanvas');
  if (!canvas) return;

  canvas.addEventListener('mousedown', (e) => {
    // Don't pan if clicking on a node, button, control, or overlay
    if (e.target.closest('.graph-node, .graph-zoom, .graph-canvas-toolbar, .gcb-menu, .zia-float, .graph-ctx, button, select')) return;
    graphPanning = true;
    panStartX = e.clientX - panOffsetX;
    panStartY = e.clientY - panOffsetY;
    canvas.style.cursor = 'grabbing';
    e.preventDefault();
  });

  canvas.addEventListener('mousemove', (e) => {
    if (!graphPanning) return;
    panOffsetX = e.clientX - panStartX;
    panOffsetY = e.clientY - panStartY;
    applyGraphTransform();
  });

  canvas.addEventListener('mouseup', () => {
    graphPanning = false;
    canvas.style.cursor = 'grab';
  });

  canvas.addEventListener('mouseleave', () => {
    graphPanning = false;
    canvas.style.cursor = 'grab';
  });

  // Mouse wheel zoom
  canvas.addEventListener('wheel', (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.1 : 0.9;
    currentGraphZoom = Math.max(0.3, Math.min(3, currentGraphZoom * factor));
    applyGraphTransform();
  }, { passive: false });

  canvas.style.cursor = 'grab';

  // Left-click on graph nodes opens entity slider directly (via inline onclick on each node)
}

