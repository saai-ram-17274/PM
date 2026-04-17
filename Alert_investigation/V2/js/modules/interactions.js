/* interactions.js — User interactions: alert selection, investigation toggle, tabs, dropdowns
 * Depends on: alerts.js, utils.js, alert-list.js, alert-detail.js, app.js (state vars) */
function selectAlert(id) {
  activeAlertId = id;
  invOpen = false;
  invLoaded = false;
  graphViewActive = false;
  document.getElementById('invGraphView').style.display = 'none';
  closeEntityModal();
  document.getElementById('invPanel').classList.remove('open');
  document.getElementById('mainLayout').classList.remove('inv-active');
  renderAlertList();
  const a = ALERTS.find(x=>x.id===id);
  renderDetailHeader(a);
  renderTimelineTab();
  // reset tab
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab')[1].classList.add('active');
}

function openAlert(id) {
  selectAlert(id);
  showToast('📂', `Alert #${id} opened`);
}

function toggleInvestigation() {
  if (!invOpen) {
    invOpen = true;
    const panel = document.getElementById('invPanel');
    panel.classList.add('open');
    document.getElementById('mainLayout').classList.add('inv-active');
    renderDetailHeader(ALERTS.find(x=>x.id===activeAlertId)); // refresh button state
    if (!invLoaded) {
      document.getElementById('invLoading').style.display = 'flex';
      document.getElementById('invContent').style.display = 'none';
      setTimeout(() => {
        document.getElementById('invLoading').style.display = 'none';
        document.getElementById('invContent').style.display = 'block';
        invLoaded = true;
      }, 1200);
    }
  } else {
    closeInvestigation();
  }
}

function closeInvestigation() {
  invOpen = false;
  if (graphViewActive) {
    graphViewActive = false;
    document.getElementById('invGraphView').style.display = 'none';
    if (invLoaded) document.getElementById('invContent').style.display = 'block';
  }
  // Restore Zia header and footer
  document.querySelector('.inv-header').style.display = 'flex';
  document.querySelector('.inv-footer').style.display = 'flex';
  closeEntityModal();
  document.getElementById('invPanel').classList.remove('open');
  document.getElementById('mainLayout').classList.remove('inv-active');
  renderDetailHeader(ALERTS.find(x=>x.id===activeAlertId));
}

function rerunInvestigation() {
  invLoaded = false;
  document.getElementById('invLoading').style.display = 'flex';
  document.getElementById('invContent').style.display = 'none';
  showToast('🔄', 'Re-running investigation…');
  setTimeout(() => {
    document.getElementById('invLoading').style.display = 'none';
    document.getElementById('invContent').style.display = 'block';
    invLoaded = true;
    showToast('✓', 'Investigation complete');
  }, 2200);
}

function switchTab(el, name) {
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  if (name==='timeline') renderTimelineTab();
  else if (name==='overview') renderOverviewTab();
  else renderPlaceholderTab(el.textContent);
}

function switchInvTab(el, targetId) {
  document.querySelectorAll('.inv-subtab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  ['invTimeline','invAttack'].forEach(id => {
    document.getElementById(id).style.display = id===targetId ? 'block' : 'none';
  });
}

function toggleCard(id) {
  document.getElementById(id).classList.toggle('collapsed');
}

function toggleEvidence(id) {
  const el = document.getElementById(id);
  el.style.display = el.style.display==='none' ? 'block' : 'none';
}


function setAssignee(name) {
  showToast('👤', `Assigned to ${name}`);
  closeDropdowns();
}
function setStatus(status, icon) {
  showToast('🔄', `Status changed to ${status}`);
  closeDropdowns();
}
function setSeverity(sev, color) {
  showToast('⚠️', `Severity set to ${sev}`);
  closeDropdowns();
}

function addToIncident() { showToast('📌', 'Added to incident queue…'); }
function runPlaybook()    { showToast('▶', 'Running playbook…'); }
function thumbsUp()       { showToast('👍', 'Marked as helpful'); }

