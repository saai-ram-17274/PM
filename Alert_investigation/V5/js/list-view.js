/* ═══ V5 LIST VIEW (Img_1) ═══ */

function renderListView() {
  renderListSidebar();
  renderAlertsTable();
}

function renderListSidebar() {
  const sb = document.getElementById('lvSidebar');
  if (!sb) return;

  sb.innerHTML = `
    <div class="lv-status-card">
      <h3>Alert Status and Severity</h3>
      <div class="donut-wrap">
        ${renderStatusDonut()}
      </div>
    </div>

    <div class="lv-insights-head">
      <span>Insights</span>
      <div class="lv-collapse-actions">
        <span class="collapse-all" onclick="toggleAllGroups()">Collapse All</span>
        <span class="caret-sm">⋮</span>
      </div>
    </div>

    <div class="lv-group" data-group="alertProfile">
      <div class="lv-group-head" onclick="toggleGroup(this)">
        <span class="lv-group-icon">Alert Profile</span>
        <span class="chev">▾</span>
      </div>
      <div class="lv-group-body">
        ${SIDEBAR_INSIGHTS.alertProfile.map(r => renderInsightRow(r)).join('')}
      </div>
    </div>

    <div class="lv-group" data-group="topSuspects">
      <div class="lv-group-head" onclick="toggleGroup(this)">
        <span class="lv-group-icon">Top Suspects</span>
        <span class="chev">▾</span>
      </div>
      <div class="lv-group-body">
        ${SIDEBAR_INSIGHTS.topSuspects.map(r => renderInsightRow(r)).join('')}
      </div>
    </div>

    <div class="lv-group collapsed" data-group="logSource">
      <div class="lv-group-head" onclick="toggleGroup(this)">
        <span class="lv-group-icon">Log Source</span>
        <span class="chev">▾</span>
      </div>
      <div class="lv-group-body"></div>
    </div>
  `;
}

function renderStatusDonut() {
  /* Use the designed Alert_chart.svg from /SVG/ as the status/severity gauge */
  return `<img src="SVG/Alert_chart.svg" alt="Alert status &amp; severity" class="lv-status-chart"/>`;
}

function renderInsightRow(r) {
  const pct = Math.round((r.value / (r.max || 1400)) * 100);
  return `
    <div class="lv-row">
      <div class="lv-row-cell">
        <span class="lv-row-label" title="${r.name}">${r.name}</span>
        <div class="lv-row-bar"><div class="lv-row-bar-inner" style="width:${pct}%"></div></div>
        <span class="lv-row-value">${r.value}</span>
      </div>
    </div>
  `;
}

function toggleGroup(headEl) {
  headEl.parentElement.classList.toggle('collapsed');
}
function toggleAllGroups() {
  document.querySelectorAll('.lv-group').forEach(g => g.classList.toggle('collapsed'));
}

function renderAlertsTable() {
  const tbody = document.getElementById('alertsTableBody');
  if (!tbody) return;
  tbody.innerHTML = ALERTS.map(a => renderAlertRow(a)).join('');
}

function renderAlertRow(a) {
  const sevIconChar = a.severity === 'crit' || a.severity === 'high' ? '✕' : '!';
  const tools = (a.tools || []).map(t => {
    if (t === 'ai') return '<span class="alert-tool-icon" title="AI">🤖</span>';
    if (t === 'log') return '<span class="alert-tool-icon" title="Log">📄</span>';
    return '';
  }).join('');

  const remCell = a.remediation === 'btn'
    ? `<button class="remediation-btn" onclick="event.stopPropagation()"><span>▶</span> ${a.remediationLabel}</button>`
    : `<span class="remediation-success"><span class="check">✓</span> Success. <a>View Details</a></span>`;

  const assigneeUnassigned = a.assignee.unassigned ? ' unassigned' : '';

  return `
    <tr class="row-clickable" onclick="openAlertDetail('${a.id}')">
      <td class="col-cb"><input type="checkbox" class="lv-cb" onclick="event.stopPropagation()"/></td>
      <td class="col-react">
        <div class="alert-thumb">
          <span>${a.likeIcon}</span>
          <span class="count">${a.likeCount}</span>
        </div>
      </td>
      <td class="col-details">
        <div class="alert-title-row">
          <span class="alert-icon-circle ${a.severity}">${sevIconChar}</span>
          <span class="alert-title">${a.title}</span>
          <span class="severity-badge ${a.severity}">${a.severityLabel} <span class="score">${a.score}</span></span>
          <span class="alert-tools">${tools}</span>
        </div>
        <div class="alert-desc">${a.desc}</div>
      </td>
      <td class="time-cell">${a.timeGenerated}</td>
      <td>
        <div class="assignee-cell${assigneeUnassigned}">
          <span class="assignee-avatar">${a.assignee.initials}</span>
          <span>${a.assignee.name}</span>
          <span class="caret">▾</span>
        </div>
      </td>
      <td>
        <span class="status-pill ${a.status}">${a.statusLabel} <span class="caret">▾</span></span>
      </td>
      <td>${remCell}</td>
    </tr>
  `;
}
