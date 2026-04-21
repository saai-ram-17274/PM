/* ═══════════════════════════════════════════════════════════════
 * app.js — Application entry point & global state
 *
 * This file:
 *  1. Declares shared state variables
 *  2. Sets up global event listeners
 *  3. Runs the init sequence
 *
 * Load order (all via <script> tags in index.html):
 *   Data:     alerts.js → display-config.js → entities.js
 *   Modules:  utils.js → alert-list.js → alert-detail.js →
 *             interactions.js → graph-summary.js → graph-core.js →
 *             entity-slider.js → entity-quick-card.js →
 *             graph-filter.js → context-menu.js → graph-nodes.js →
 *             action-panel.js
 *   Init:     app.js (this file — loaded last)
 * ═══════════════════════════════════════════════════════════════ */

/* ── Global State ────────────────────────────────────────────── */
let activeAlertId = 1;
let invOpen = false;
let invLoaded = false;
let graphViewActive = false;
let currentGraphZoom = 1;
let ctxEntityId = null;

/* ── Node registry — tracks all nodes on graph by label for dedup ── */
const nodeRegistry = {};   // { 'powershell.exe': 'proc-powershell', ... }

/* ── Drill-down groups — tracks children per parent for collapse ── */
const drillDownGroups = {}; // { 'user-m-henderson': { process: [{nodeId, edgeEl, lblEl, groupEl}], alert: [...], service: [...] } }

/* ── Global Event Listeners ──────────────────────────────────── */
document.addEventListener('click', e => {
  if (!e.target.closest('.dropdown')) closeDropdowns();
  if (!e.target.closest('.graph-ctx')) hideGraphCtx();
});

/* ── INIT ────────────────────────────────────────────────────── */
renderAlertList();
renderDetailHeader(ALERTS[0]);
renderTimelineTab();
initNodeRegistry();
initGraphPan();

// Make ALL static graph nodes draggable
document.querySelectorAll('#graphSvg g.graph-node').forEach(g => {
  const nodeId = g.getAttribute('data-entity');
  const circle = g.querySelector('circle:not(.expand-indicator)');
  const texts = g.querySelectorAll('text');
  const iconEl = texts[0] || null;
  const labelEl = texts[1] || texts[0] || null;
  if (circle && iconEl && labelEl) {
    makeNodeDraggable(g, circle, iconEl, labelEl, nodeId);
  }
});
