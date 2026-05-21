/* ═══ V5 APP BOOT ═══ */
document.addEventListener('DOMContentLoaded', () => {
  renderListView();

  /* tab click handlers (event delegation) */
  document.getElementById('dvTabs').addEventListener('click', (e) => {
    const tab = e.target.closest('.dv-tab');
    if (tab) switchDetailTab(tab.dataset.tab);
  });

  /* sub-nav: clicking SOC Overview / Explorer / Incident from detail view returns to list */
  document.querySelectorAll('.alerts-subnav .asn-tab').forEach(t => {
    t.addEventListener('click', () => showListView());
  });

  /* deep-link via URL hash: #alert/<id>[/tab] */
  function handleHash() {
    const m = location.hash.match(/^#alert\/([^/]+)(?:\/(.+))?$/);
    if (m) {
      openAlertDetail(m[1]);
      if (m[2]) switchDetailTab(m[2]);
    }
  }
  window.addEventListener('hashchange', handleHash);
  handleHash();
});
