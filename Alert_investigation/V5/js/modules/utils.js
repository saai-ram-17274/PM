/* ═══════════════════════════════════════════════════════════════
 * utils.js — Shared utility functions
 * ═══════════════════════════════════════════════════════════════ */

/** Capitalize first letter */
function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

/* ── TOAST ───────────────────────────────────────────────────── */
let toastTimer;
function showToast(icon, msg) {
  const t = document.getElementById('toast');
  document.getElementById('toastIcon').textContent = icon;
  document.getElementById('toastMsg').textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2400);
}

/* ── DROPDOWN MANAGEMENT ─────────────────────────────────────── */
function toggleDropdown(id) {
  const dd = document.getElementById(id);
  const isOpen = dd.classList.contains('open');
  closeDropdowns();
  if (!isOpen) dd.classList.add('open');
}

function closeDropdowns() {
  document.querySelectorAll('.dropdown-menu.open').forEach(d => d.classList.remove('open'));
}

/* ── NAVIGATION HELPERS ──────────────────────────────────────── */
function navClick(e, name) {
  e.preventDefault();
  if (name === 'Alerts') return;
  showToast('🔗', `Navigating to ${name}…`);
}

function handleSearch(e) {
  if (e.key === 'Enter') {
    const q = e.target.value.trim();
    if (q) showToast('🔍', `Searching: "${q}"`);
  }
}
