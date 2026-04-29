/* ═══════════════════════════════════════════════════════════════
 * alert-list.js — Left-panel alert list rendering
 * Depends on: alerts.js, utils.js, app.js (activeAlertId)
 * ═══════════════════════════════════════════════════════════════ */

function renderAlertList() {
  const el = document.getElementById('alertList');
  el.innerHTML = ALERTS.map(a => {
    const iconClass = a.severity === 'high' || a.severity === 'critical' ? 'alert-icon-red' : a.severity === 'medium' ? 'alert-icon-amber' : 'alert-icon-green';
    const iconChar = a.severity === 'high' || a.severity === 'critical' ? '✕' : a.severity === 'medium' ? '●' : '●';
    return `
    <div class="alert-item${a.id === activeAlertId ? ' active' : ''}" id="alert-item-${a.id}" onclick="selectAlert(${a.id})">
      <div class="alert-item-top">
        <div class="alert-title-row">
          <div class="alert-icon ${iconClass}">${iconChar}</div>
          <div class="alert-title">${a.title}</div>
        </div>
        <span class="badge badge-${a.severity}">${cap(a.severity)} ${a.score}</span>
      </div>
      <div class="alert-meta">${a.meta}</div>
      <div class="alert-footer">
        <span class="alert-user">
          <span class="alert-user-avatar">👤</span>
          ${a.user}
        </span>
        <button class="btn-open" onclick="event.stopPropagation();openAlert(${a.id})">Open</button>
      </div>
    </div>`;
  }).join('');
}
