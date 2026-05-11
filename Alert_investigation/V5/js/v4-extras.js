/* ═══ V4 INLINE EXTRAS — exported for V5 attack-vector ═══ */

/* ── Icon system (V4 inline) ── */
const ICON_SVG_MAP = {
  '⚠': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  '🔔': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`,
  '⚙': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
  '👤': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
  '📁': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`,
  '📂': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`,
  '🔑': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>`,
  '📋': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/></svg>`,
  '🔍': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>`,
  '📊': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/></svg>`,
  '🛡': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  '🔗': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
  '🌐': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  '📧': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>`,
  '📱': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>`,
  '🎯': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></svg>`,
  '📡': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4.9 16.1C1 12.2 1 5.8 4.9 1.9"/><path d="M7.8 4.7a6.14 6.14 0 0 0-.8 7.5"/><circle cx="12" cy="9" r="2"/><path d="M16.2 4.7a6.14 6.14 0 0 1 .8 7.5"/><path d="M19.1 1.9a10.56 10.56 0 0 1 0 14.2"/><path d="M12 11v10"/></svg>`,
  '✓': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
  '🔴': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c||'#DD1616'}" stroke-width="2" fill="${c||'#DD1616'}" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/></svg>`,
  '🟡': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c||'#d97706'}" stroke-width="2" fill="${c||'#d97706'}" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/></svg>`,
  '🏠': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`,
  '💬': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`,
  '🔄': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`,
  '🔖': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m19 21-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v16z"/></svg>`,
  '📄': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`,
  '🕐': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  '🌍': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  '🚫': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`,
  '✦': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>`,
  '✨': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>`,
  '❓': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  '➕': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
  '🔒': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  '👍': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 10v12"/><path d="M15 5.88 14 10h5.83a2 2 0 0 1 1.92 2.56l-2.33 8A2 2 0 0 1 17.5 22H4a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h2.76a2 2 0 0 0 1.79-1.11L12 2h0a3.13 3.13 0 0 1 3 3.88Z"/></svg>`,
  '▶': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>`,
  '🔎': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>`,
  '🖥': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`,
  '💻': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`,
  '◆': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  '●': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="${c}" stroke="none"><circle cx="12" cy="12" r="6"/></svg>`,
  '✕': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  '▾': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 12 12" fill="none"><path d="M2.57 4.29L6 7.71L9.43 4.29" stroke="${c}" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  '⟲': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>`,
  '🔽': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>`,
  '🔧': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>`,
  '📌': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg>`,
  '✅': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c||'#198019'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
  '❌': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c||'#DD1616'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
  '💡': (s,c)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18h6"/><path d="M10 22h4"/><path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"/></svg>`,
};


/**
 * resolveIcon — Icon priority chain (per Elegant MCP Server spec)
 * @param {string} emoji - The emoji character to resolve
 * @param {number} [size=14] - Icon size in pixels
 * @param {string} [color='currentColor'] - Stroke color
 * @returns {string} Inline SVG string or original emoji as fallback
 */
function resolveIcon(emoji, size, color) {
  if (!emoji) return '';
  size = size || 14;
  color = color || 'currentColor';
  const fn = ICON_SVG_MAP[emoji];
  return fn ? fn(size, color) : emoji; // Tier 2 fallback: keep emoji if no SVG
}

/* ── SEV_SHAPE ── */
const SEV_SHAPE = {
  critical: '<svg width="12" height="12" viewBox="13 3 14 12" fill="none"><path d="M26.8064 8.30718C27.0645 8.7359 27.0645 9.2641 26.8064 9.69282L24.0288 14.3072C23.7707 14.7359 23.2938 15 22.7777 15L17.2223 15C16.7062 15 16.2293 14.7359 15.9712 14.3072L13.1936 9.69282C12.9355 9.2641 12.9355 8.7359 13.1936 8.30718L15.9712 3.69282C16.2293 3.2641 16.7062 3 17.2224 3L22.7777 3C23.2938 3 23.7707 3.2641 24.0288 3.69282L26.8064 8.30718Z" fill="#DD1616"/><path d="M22.7585 11.7585C23.0771 11.4399 23.0839 10.918 22.7585 10.5927L18.4099 6.24402C18.0913 5.92544 17.5694 5.91867 17.244 6.24402C16.9187 6.56937 16.9187 7.08451 17.244 7.40986L21.5927 11.7585C21.9112 12.0771 22.4332 12.0839 22.7585 11.7585Z" fill="white"/><path d="M17.244 11.7585C17.5626 12.0771 18.0845 12.0839 18.4099 11.7585L22.7585 7.40985C23.0771 7.09128 23.0839 6.56936 22.7585 6.24401C22.4332 5.91866 21.918 5.91866 21.5927 6.24401L17.244 10.5927C16.9255 10.9113 16.9187 11.4332 17.244 11.7585Z" fill="white"/></svg>',
  high: '<svg width="12" height="12" viewBox="13 3 14 12" fill="none"><path d="M26.8064 8.30718C27.0645 8.7359 27.0645 9.2641 26.8064 9.69282L24.0288 14.3072C23.7707 14.7359 23.2938 15 22.7777 15L17.2223 15C16.7062 15 16.2293 14.7359 15.9712 14.3072L13.1936 9.69282C12.9355 9.2641 12.9355 8.7359 13.1936 8.30718L15.9712 3.69282C16.2293 3.2641 16.7062 3 17.2224 3L22.7777 3C23.2938 3 23.7707 3.2641 24.0288 3.69282L26.8064 8.30718Z" fill="#DD1616"/><path d="M22.7585 11.7585C23.0771 11.4399 23.0839 10.918 22.7585 10.5927L18.4099 6.24402C18.0913 5.92544 17.5694 5.91867 17.244 6.24402C16.9187 6.56937 16.9187 7.08451 17.244 7.40986L21.5927 11.7585C21.9112 12.0771 22.4332 12.0839 22.7585 11.7585Z" fill="white"/><path d="M17.244 11.7585C17.5626 12.0771 18.0845 12.0839 18.4099 11.7585L22.7585 7.40985C23.0771 7.09128 23.0839 6.56936 22.7585 6.24401C22.4332 5.91866 21.918 5.91866 21.5927 6.24401L17.244 10.5927C16.9255 10.9113 16.9187 11.4332 17.244 11.7585Z" fill="white"/></svg>',
  medium: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" fill="#D14900"/><line x1="12" y1="9" x2="12" y2="13" stroke="white" stroke-width="2.5" stroke-linecap="round"/><circle cx="12" cy="17" r="1.2" fill="white"/></svg>',
  low: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" fill="#198019"/><path d="M12 8v4" stroke="white" stroke-width="2.5" stroke-linecap="round"/><circle cx="12" cy="16.5" r="1.2" fill="white"/></svg>',
  verylow: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" fill="#626262"/><path d="M12 8v4" stroke="white" stroke-width="2.5" stroke-linecap="round"/><circle cx="12" cy="16.5" r="1.2" fill="white"/></svg>'
};

/* ── EDGE_ATTRIBUTES + showEdgeRelation ── */
var EDGE_ATTRIBUTES = {
  'alert-impossible-travel→user-m-henderson': {
    relation:'TriggeredBy', count:1, risk:95,
    firstSeen:'03 Apr 2026 14:22:45', lastSeen:'03 Apr 2026 14:22:45',
    evidence:{
      summary:'Impossible travel detected: Romania → New York in 28 min',
      findings:['Geo distance: 8,847 km','Travel time: 28 min (impossible)','Source IP: Tor exit node'],
      confidence:96,
      rawLog:'EventID=4624 | User=m.henderson | SrcIP=185.220.101.42 | Auth=NTLM | Status=Success | Geo=RO→US'
    },
    detectionRule:{ name:'Impossible Travel Detection', type:'Correlation', id:'CR-0042' },
    mitre:{ tactic:'Initial Access', tacticId:'TA0001', technique:'Valid Accounts', techId:'T1078' },
    sparkline:[0,0,0,0,0,0,0,0,0,0,0,1],
    baseline:{ expected:0, actual:1, deviation:null }
  },
  'alert-impossible-travel→svc-azure-ad': {
    relation:'DetectedOn', count:1, risk:95,
    firstSeen:'03 Apr 2026 14:22:45', lastSeen:'03 Apr 2026 14:22:45',
    evidence:{
      summary:'Azure AD sign-in logs flagged anomalous authentication',
      findings:['Sign-in risk: High','Location anomaly flagged','Conditional access policy bypassed'],
      confidence:92,
      rawLog:'AuditLog | Action=UserLoggedIn | UserId=m.henderson@corp | ClientIP=185.220.101.42 | RiskLevel=High'
    },
    detectionRule:{ name:'Impossible Travel Detection', type:'Correlation', id:'CR-0042' },
    mitre:{ tactic:'Initial Access', tacticId:'TA0001', technique:'Valid Accounts', techId:'T1078' },
    source:'Azure AD Sign-in Logs'
  },
  'user-m-henderson→ip-tor': {
    relation:'AccessedFrom', count:3, risk:92,
    firstSeen:'03 Apr 2026 14:18:02', lastSeen:'03 Apr 2026 14:22:45',
    evidence:{
      summary:'Tor exit node (Romania), 3 successful logons in 24h',
      findings:['Tor exit node confirmed','3 logons from same IP','All logons successful (no failures)'],
      confidence:98,
      rawLog:'SignInLog | IP=185.220.101.42 | TorExitNode=true | Logons=3/3 Success | Country=RO'
    },
    detectionRule:{ name:'Tor Exit Node Login', type:'Threat Intel', id:'TI-0117' },
    mitre:{ tactic:'Defense Evasion', tacticId:'TA0005', technique:'Proxy: Multi-hop Proxy', techId:'T1090.003' },
    threatIntel:{ vendor:'Webroot', reputation:2, label:'Malicious', virusTotal:'18/94' },
    geo:{ flag:'🇷🇴', country:'Romania', city:'Bucharest', ip:'185.220.101.42' },
    sparkline:[0,0,0,0,0,0,0,0,1,1,0,1],
    baseline:{ expected:0, actual:3, deviation:null },
    source:'Azure AD Sign-in Logs'
  },
  'user-m-henderson→ip-internal': {
    relation:'AccessedFrom', count:12, risk:15,
    firstSeen:'03 Apr 2026 08:02:10', lastSeen:'03 Apr 2026 14:50:30',
    evidence:{
      summary:'Internal VPN IP, routine access from corp network',
      findings:['VPN IP in corp range','Access during business hours','Standard auth pattern'],
      confidence:35,
      rawLog:'VPNLog | User=m.henderson | SrcIP=10.18.1.81 | Tunnel=IPSec | Duration=8h12m'
    },
    geo:{ flag:'🇺🇸', country:'United States', city:'New York (Corp)', ip:'10.18.1.81' },
    sparkline:[1,2,1,1,1,2,1,0,1,1,0,1],
    baseline:{ expected:10, actual:12, deviation:1.2 },
    source:'VPN Gateway Logs'
  },
  'user-m-henderson→svc-azure-ad': {
    relation:'LoginTo', count:5, risk:78,
    firstSeen:'03 Apr 2026 14:18:02', lastSeen:'03 Apr 2026 15:02:18',
    evidence:{
      summary:'MFA bypassed via legacy auth protocol',
      findings:['IMAP legacy auth used','MFA not enforced on protocol','5 sessions in 47 min'],
      confidence:89,
      rawLog:'SignInLog | Protocol=IMAP | MFAResult=notApplicable | ClientApp=OtherClients | Status=Success'
    },
    detectionRule:{ name:'Legacy Auth Protocol Usage', type:'Anomaly (UEBA)', id:'UE-0033' },
    mitre:{ tactic:'Credential Access', tacticId:'TA0006', technique:'MFA Interception', techId:'T1111' },
    sparkline:[0,1,0,0,1,0,0,0,1,1,0,1],
    baseline:{ expected:2, actual:5, deviation:2.5 },
    source:'Azure AD Sign-in Logs'
  },
  'ip-internal→dev-ws045': {
    relation:'ResolvedTo', count:1, risk:10,
    firstSeen:'03 Apr 2026 14:41:10', lastSeen:'03 Apr 2026 14:41:10',
    evidence:{
      summary:'DHCP lease mapping, IP assigned to CORP-WS-045',
      findings:['DHCP lease confirmed','MAC: 00:1A:2B:3C:4D:5E','Lease active since 08:00'],
      confidence:100,
      rawLog:'DHCPLog | IP=10.18.1.81 | MAC=00:1A:2B:3C:4D:5E | Hostname=CORP-WS-045 | LeaseStart=08:00'
    },
    geo:{ flag:'🇺🇸', country:'United States', city:'New York (Corp)', ip:'10.18.1.81' },
    source:'DHCP Server Logs'
  },
  'user-m-henderson→svc-sharepoint': {
    relation:'AccessedFile', count:24, risk:88,
    firstSeen:'03 Apr 2026 15:28:00', lastSeen:'03 Apr 2026 15:36:22',
    evidence:{
      summary:'24 sensitive files downloaded from /finance/ and /hr/',
      findings:['24 files in 8 min','Sensitive folders targeted','Download rate 14× above baseline'],
      confidence:94,
      rawLog:'SPAudit | Op=FileDownloaded | User=m.henderson | Path=/finance/*,/hr/* | Count=24 | Duration=8min'
    },
    detectionRule:{ name:'Bulk Sensitive File Download', type:'Anomaly (UEBA)', id:'UE-0071' },
    mitre:{ tactic:'Collection', tacticId:'TA0009', technique:'Data from Information Repositories', techId:'T1213' },
    sparkline:[0,0,0,0,0,0,0,0,2,4,8,10],
    baseline:{ expected:3, actual:24, deviation:8.0 },
    source:'SharePoint Audit Logs'
  },
  'svc-azure-ad→svc-oauth': {
    relation:'IssuedTo', count:3, risk:85,
    firstSeen:'03 Apr 2026 15:08:12', lastSeen:'03 Apr 2026 15:10:00',
    evidence:{
      summary:'3 OAuth refresh tokens issued, unusual scope elevation',
      findings:['Scope: Files.ReadWrite.All added','3 tokens in 2 min','Consent granted without admin review'],
      confidence:91,
      rawLog:'AuditLog | Op=Consent | AppId=a3e2f… | Scope=Files.ReadWrite.All | GrantedBy=m.henderson'
    },
    detectionRule:{ name:'OAuth Scope Elevation', type:'Correlation', id:'CR-0088' },
    mitre:{ tactic:'Persistence', tacticId:'TA0003', technique:'Account Manipulation: Additional Cloud Credentials', techId:'T1098.001' },
    sparkline:[0,0,0,0,0,0,0,0,0,1,1,1],
    baseline:{ expected:0, actual:3, deviation:null },
    source:'Azure AD Audit Logs'
  },
  'user-admin→svc-azure-ad': {
    relation:'LoginTo', count:4, risk:86,
    firstSeen:'03 Apr 2026 15:24:42', lastSeen:'03 Apr 2026 15:33:18',
    evidence:{
      summary:'Administrator session originated from compromised CORP-WS-045 immediately after privilege escalation — 4 sign-ins in 9 min',
      findings:['Source host = CORP-WS-045 (compromised)','Sign-ins began <2 min after EscalatedTo event','MFA satisfied via stale session token (no fresh prompt)','4 sign-ins in 9 min vs baseline 0–1/day','Conditional access risk: High'],
      confidence:90,
      rawLog:'SignInLog | User=admin | SrcIP=10.18.1.81 | Device=CORP-WS-045 | RiskLevel=High | MFA=Satisfied(stale) | SessionId=abc123'
    },
    detectionRule:{ name:'Admin Login from Compromised Host', type:'Correlation', id:'CR-0091' },
    mitre:{ tactic:'Lateral Movement', tacticId:'TA0008', technique:'Use Alternate Authentication Material', techId:'T1550' },
    sparkline:[0,0,0,0,0,0,0,0,0,0,2,2],
    baseline:{ expected:1, actual:4, deviation:3.5 },
    source:'Azure AD Sign-in Logs'
  },
  'ip-tor→dev-ws045': {
    relation:'CommunicatedWith', count:47, risk:96,
    firstSeen:'03 Apr 2026 15:20:05', lastSeen:'03 Apr 2026 15:25:10',
    evidence:{
      summary:'Reverse shell traffic, 47 C2 beacon attempts detected',
      findings:['47 beacons in 5 min','Fixed interval: 6.3s ±0.2s','Payload: encrypted binary'],
      confidence:99,
      rawLog:'IDS | Alert=ReverseShell | SrcIP=185.220.101.42 | DstIP=10.18.1.81 | Beacons=47 | Interval=6.3s'
    },
    detectionRule:{ name:'C2 Beacon Pattern Detection', type:'Correlation', id:'CR-0101' },
    mitre:{ tactic:'Command and Control', tacticId:'TA0011', technique:'Application Layer Protocol', techId:'T1071' },
    threatIntel:{ vendor:'Webroot', reputation:2, label:'Malicious', virusTotal:'18/94' },
    geo:{ flag:'🇷🇴', country:'Romania', city:'Bucharest', ip:'185.220.101.42' },
    sparkline:[0,0,0,0,0,0,0,0,5,12,18,12],
    baseline:{ expected:0, actual:47, deviation:null },
    source:'Firewall Logs + IDS'
  },
  'dev-ws045→svc-sharepoint': {
    relation:'AccessedFile', count:24, risk:90,
    firstSeen:'03 Apr 2026 15:30:00', lastSeen:'03 Apr 2026 15:36:22',
    evidence:{
      summary:'Bulk file exfiltration via WebDAV, 4.2 MB transferred',
      findings:['WebDAV protocol used','4.2 MB outbound','24 files in single session'],
      confidence:95,
      rawLog:'SPAudit | Op=FileDownloaded | Protocol=WebDAV | Size=4.2MB | Files=24 | Session=single'
    },
    detectionRule:{ name:'Bulk File Exfiltration', type:'Correlation', id:'CR-0055' },
    mitre:{ tactic:'Exfiltration', tacticId:'TA0010', technique:'Exfiltration Over Web Service', techId:'T1567' },
    sparkline:[0,0,0,0,0,0,0,0,0,4,10,10],
    baseline:{ expected:2, actual:24, deviation:12.0 },
    dataVolume:'4.2 MB',
    source:'SharePoint Audit Logs'
  },
  'user-m-henderson→dev-ws045': {
    relation:'LoginTo', count:8, risk:45,
    firstSeen:'03 Apr 2026 08:15:00', lastSeen:'03 Apr 2026 14:41:10',
    evidence:{
      summary:'Primary workstation, 8 interactive logon sessions',
      findings:['Interactive logon type (2)','Consistent 8h usage','No remote sessions'],
      confidence:15,
      rawLog:'WinSec | EventID=4624 | LogonType=2 | User=m.henderson | Workstation=CORP-WS-045'
    },
    sparkline:[1,1,1,1,0,1,0,1,0,1,0,1],
    baseline:{ expected:6, actual:8, deviation:1.3 },
    source:'Windows Security Event Logs'
  },
  'dev-ws045→user-admin': {
    relation:'EscalatedTo', count:2, risk:88,
    firstSeen:'03 Apr 2026 15:24:18', lastSeen:'03 Apr 2026 15:31:02',
    evidence:{
      summary:'PowerShell on CORP-WS-045 elevated to local Administrator via runas / token impersonation',
      findings:['UAC elevation prompt bypassed (auto-approve)','New process spawned with SYSTEM/Administrator token','2 elevation events within 7 minutes','User m.henderson is not a member of local Administrators'],
      confidence:90,
      rawLog:'WinSec | EventID=4672 | SubjectUser=Administrator | LogonId=0x3e7 | PrivilegesAssigned=SeDebugPrivilege,SeImpersonatePrivilege | Host=CORP-WS-045'
    },
    detectionRule:{ name:'Privilege Escalation to Admin Account', type:'Correlation', id:'CR-0073' },
    mitre:{ tactic:'Privilege Escalation', tacticId:'TA0004', technique:'Access Token Manipulation', techId:'T1134' },
    sparkline:[0,0,0,0,0,0,0,0,0,0,1,1],
    baseline:{ expected:0, actual:2, deviation:null },
    source:'Windows Security Event Logs + Sysmon'
  },
  'svc-oauth→svc-sharepoint': {
    relation:'AccessedFile', count:24, risk:88,
    firstSeen:'03 Apr 2026 15:25:00', lastSeen:'03 Apr 2026 15:28:33',
    evidence:{
      summary:'OAuth token used to access SharePoint API, 24 file downloads',
      findings:['Graph API calls detected','Token scope: Files.ReadWrite.All','24 sequential downloads'],
      confidence:93,
      rawLog:'APILog | App=GraphAPI | Token=OAuth_refresh | Op=DriveItem.Content | Count=24 | Scope=Files.ReadWrite.All'
    },
    detectionRule:{ name:'Suspicious OAuth API Access', type:'Anomaly (UEBA)', id:'UE-0089' },
    mitre:{ tactic:'Collection', tacticId:'TA0009', technique:'Data from Information Repositories', techId:'T1213' },
    sparkline:[0,0,0,0,0,0,0,0,0,6,10,8],
    baseline:{ expected:0, actual:24, deviation:null },
    source:'SharePoint API Audit'
  },
  'ip-tor→domain-c2': {
    relation:'CommunicatedWith', count:142, risk:98,
    firstSeen:'03 Apr 2026 14:45:00', lastSeen:'03 Apr 2026 15:35:44',
    evidence:{
      summary:'142 DNS queries + TLS sessions to c2-update.darkoperator.net',
      findings:['Known C2 domain','142 DNS queries','TLS cert: self-signed, CN=randomstring'],
      confidence:99,
      rawLog:'DNS | Query=c2-update.darkoperator.net | Type=A | Count=142 | TLS=self-signed'
    },
    detectionRule:{ name:'Known C2 Domain Communication', type:'Threat Intel', id:'TI-0203' },
    mitre:{ tactic:'Command and Control', tacticId:'TA0011', technique:'Application Layer Protocol: DNS', techId:'T1071.004' },
    threatIntel:{ vendor:'Webroot', reputation:1, label:'Critical', virusTotal:'62/94' },
    geo:{ flag:'🇷🇺', country:'Russia', city:'Moscow', ip:'185.220.101.99' },
    sparkline:[0,2,4,6,8,10,12,14,16,18,24,28],
    baseline:{ expected:0, actual:142, deviation:null },
    dataVolume:'6.8 MB',
    source:'DNS Logs + Firewall'
  },
  'dev-ws045→domain-c2': {
    relation:'CommunicatedWith', count:23, risk:97,
    firstSeen:'03 Apr 2026 15:22:00', lastSeen:'03 Apr 2026 15:30:22',
    evidence:{
      summary:'PowerShell.exe initiated 23 TLS connections, 4.2 MB outbound',
      findings:['PowerShell.exe (PID 4812)','23 TLS conns to C2 domain','4.2 MB exfiltrated outbound'],
      confidence:97,
      rawLog:'Sysmon | EventID=3 | Process=PowerShell.exe | PID=4812 | DstIP=185.220.101.99 | Bytes=4404019'
    },
    detectionRule:{ name:'Process C2 Outbound Traffic', type:'Correlation', id:'CR-0101' },
    mitre:{ tactic:'Exfiltration', tacticId:'TA0010', technique:'Exfiltration Over C2 Channel', techId:'T1041' },
    threatIntel:{ vendor:'Webroot', reputation:1, label:'Critical', virusTotal:'62/94' },
    sparkline:[0,0,0,0,0,0,0,0,3,5,8,7],
    baseline:{ expected:0, actual:23, deviation:null },
    dataVolume:'4.2 MB',
    source:'Sysmon + Firewall'
  }
};

function showEdgeRelation(evt, el) {
  evt.stopPropagation();
  const label = el.getAttribute('data-label');
  const source = el.getAttribute('data-source');
  const target = el.getAttribute('data-target');

  const srcD = ENTITY_DISPLAY[source] || {};
  const tgtD = ENTITY_DISPLAY[target] || {};
  const fmtName = (id) => {
    const d = ENTITY_DISPLAY[id];
    return d ? d.name : id.replace(/^(user-|ip-|dev-|svc-|alert-|proc-|domain-)/, '').replace(/-/g,' ');
  };

  // Lookup edge attributes & relation guide
  const key = source + '→' + target;
  const attr = EDGE_ATTRIBUTES[key] || {};
  const risk = attr.risk || 0;
  const riskColor = risk >= 80 ? '#ef4444' : risk >= 50 ? '#f97316' : risk >= 30 ? '#eab308' : '#22c55e';
  const riskLabel = risk >= 80 ? 'Critical' : risk >= 50 ? 'High' : risk >= 30 ? 'Medium' : 'Low';
  const canonicalLabel = (typeof canonicalRelation === 'function') ? canonicalRelation(label) : label;
  const relGuide = REL_GUIDE.find(r => r.key === canonicalLabel);
  const edgeColor = relGuide ? relGuide.color : '#64748b';
  const edgeIcon = relGuide ? relGuide.icon : '🔗';

  // Type labels
  const typeLabel = (d) => {
    const m = {user:'User',asset:'Device',ip:'IP Address',account:'Service',alert:'Alert',process:'Process',domain:'Domain'};
    return m[d.type] || 'Entity';
  };

  // Highlight the edge on graph — dim other nodes, edges, and edge labels
  document.querySelectorAll('.graph-node').forEach(n => n.style.opacity = '0.25');
  const srcNode = document.querySelector(`.graph-node[data-entity="${source}"]`);
  const tgtNode = document.querySelector(`.graph-node[data-entity="${target}"]`);
  if (srcNode) srcNode.style.opacity = '1';
  if (tgtNode) tgtNode.style.opacity = '1';

  // Dim all edges (lines) and edge info buttons (labels)
  document.querySelectorAll('line[data-source]').forEach(line => {
    const ls = line.getAttribute('data-source');
    const lt = line.getAttribute('data-target');
    if (ls === source && lt === target) {
      line.style.opacity = '1';
      line.style.strokeWidth = '2.5';
    } else {
      line.style.opacity = '0.12';
    }
  });
  document.querySelectorAll('.edge-info-btn').forEach(btn => {
    const bs = btn.getAttribute('data-source');
    const bt = btn.getAttribute('data-target');
    if (bs === source && bt === target) {
      btn.style.opacity = '1';
    } else {
      btn.style.opacity = '0.2';
    }
  });

  // Set slider header
  document.getElementById('edsTitle').textContent = label;
  const badge = document.getElementById('edsTypeBadge');
  badge.textContent = edgeIcon + ' Relationship';
  badge.className = 'eds-type-badge';
  badge.style.cssText = `display:inline-flex;background:${edgeColor}20;color:${edgeColor};border:1px solid ${edgeColor}40;`;
  const depthBadge = document.getElementById('edsDepthBadge');
  if (depthBadge) depthBadge.style.display = 'none';
  // Clear any leftover entity tabs (the slider is shared with the entity view)
  const tabsHost = document.getElementById('edsTabsHost');
  if (tabsHost) tabsHost.innerHTML = '';

  // Build slider body
  let html = '';

  // ── Flow diagram: Source → Relation → Target ──
  html += `<div class="ers-flow">`;
  html += `<div class="ers-flow-node" onclick="openEntitySlider('${source}')" title="View ${fmtName(source)} details">`;
  html += `<span class="ers-node-icon" style="background:${srcD.bg||'#f1f5f9'};color:${srcD.color||'#334155'};">${srcD.icon||'●'}</span>`;
  html += `<span class="ers-node-name">${fmtName(source)}</span></div>`;
  html += `<div class="ers-flow-arrow">`;
  html += `<span class="ers-arrow-label" style="color:${edgeColor};">${label}</span>`;
  html += `<div class="ers-arrow-line" style="background:${edgeColor};"><span style="position:absolute;right:-1px;top:-3px;border:4px solid transparent;border-left:6px solid ${edgeColor};"></span></div>`;
  html += `</div>`;
  html += `<div class="ers-flow-node" onclick="openEntitySlider('${target}')" title="View ${fmtName(target)} details">`;
  html += `<span class="ers-node-icon" style="background:${tgtD.bg||'#f1f5f9'};color:${tgtD.color||'#334155'};">${tgtD.icon||'●'}</span>`;
  html += `<span class="ers-node-name">${fmtName(target)}</span></div>`;
  html += `</div>`;

  // ── Relation description ──
  if (relGuide) {
    html += `<div class="ers-desc"><span class="ers-desc-icon">${relGuide.icon}</span>${relGuide.desc}</div>`;
  }

  // ── MITRE ATT&CK Mapping ──
  if (attr.mitre) {
    html += `<div class="ers-section">`;
    html += `<div class="ers-section-title">MITRE ATT&CK</div>`;
    html += `<div class="ers-mitre-row">`;
    html += `<span class="ers-mitre-chip">${attr.mitre.tacticId} · ${attr.mitre.tactic}</span>`;
    html += `<span class="ers-mitre-chip tech">${attr.mitre.techId} · ${attr.mitre.technique}</span>`;
    html += `</div></div>`;
  }

  // ── Detection Rule ──
  if (attr.detectionRule) {
    html += `<div class="ers-section">`;
    html += `<div class="ers-section-title">Detection Rule</div>`;
    html += `<div class="ers-detect-card">`;
    const drIcon = attr.detectionRule.type === 'Correlation' ? '🔗' : attr.detectionRule.type === 'Threat Intel' ? '🛡' : '📊';
    const drBg = attr.detectionRule.type === 'Correlation' ? '#dbeafe' : attr.detectionRule.type === 'Threat Intel' ? '#fee2e2' : '#ede9fe';
    html += `<span class="ers-detect-icon" style="background:${drBg};">${drIcon}</span>`;
    html += `<div><div class="ers-detect-name">${attr.detectionRule.name}</div>`;
    html += `<div class="ers-detect-type">${attr.detectionRule.type} · ${attr.detectionRule.id}</div></div>`;
    html += `</div></div>`;
  }

  // ── Connection Properties section ──
  if (attr.count != null) {
    html += `<div class="ers-section">`;
    html += `<div class="ers-section-title" style="display:flex;align-items:center;justify-content:space-between;">`;
    html += `  <span>Connection Properties</span>`;
    html += `  <span class="ers-time-badge">⏱ Last 1 hour</span>`;
    html += `</div>`;
    html += `<div class="ers-grid">`;
    // Count metric
    html += `<div class="ers-metric">`;
    html += `<div class="ers-metric-label">Event Count</div>`;
    html += `<div class="ers-metric-value">${attr.count}</div></div>`;
    // Risk metric
    html += `<div class="ers-metric">`;
    html += `<div class="ers-metric-label">Risk Score</div>`;
    html += `<div class="ers-metric-value" style="color:${riskColor};">${risk}<span style="font-size:11px;font-weight:400;color:var(--text-dim);">/100</span></div>`;
    html += `<div class="ers-risk-bar"><div class="ers-risk-fill" style="width:${risk}%;background:${riskColor};"></div></div></div>`;
    html += `</div>`; // close grid

    // Data volume (if available)
    if (attr.dataVolume) {
      html += `<div style="display:flex;align-items:center;gap:8px;margin-top:10px;padding:8px 12px;background:var(--surface-3);border:1px solid var(--border);border-radius:8px;">`;
      html += `<span style="font-size:12px;">📦</span>`;
      html += `<div><div style="font-size:9.5px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.4px;">Data Transferred</div>`;
      html += `<div style="font-size:13px;font-weight:700;color:var(--text-primary);">${attr.dataVolume}</div></div></div>`;
    }

    // First Seen / Last Seen
    if (attr.firstSeen || attr.lastSeen) {
      html += `<div class="ers-time-range">`;
      if (attr.firstSeen) {
        html += `<div class="ers-time-card"><div class="ers-time-card-label">First Seen</div>`;
        html += `<div class="ers-time-card-value">${attr.firstSeen}</div></div>`;
      }
      if (attr.lastSeen) {
        html += `<div class="ers-time-card"><div class="ers-time-card-label">Last Seen</div>`;
        html += `<div class="ers-time-card-value">${attr.lastSeen}</div></div>`;
      }
      html += `</div>`;
    }

    // Event Distribution Chart — enhanced
    if (attr.sparkline && attr.sparkline.length) {
      const sp = attr.sparkline;
      const total = sp.reduce((a,b) => a + b, 0);
      const maxS = Math.max(...sp, 1);
      const avg = total / sp.length;
      const peakIdx = sp.indexOf(maxS);
      const chartH = 54;
      const avgY = chartH - Math.max(2, (avg / maxS) * chartH);

      // Time labels — compute exact clock times from lastSeen
      const buckets = sp.length;
      const minutesPerBucket = Math.round(60 / buckets);
      let endTime = null;
      if (attr.lastSeen) {
        const parsed = new Date(attr.lastSeen.replace(/(\d{2}) (\w{3}) (\d{4})/, '$2 $1, $3'));
        if (!isNaN(parsed)) endTime = parsed;
      }
      if (!endTime) endTime = new Date();
      const timeLabels = sp.map((_, i) => {
        const minAgo = (buckets - 1 - i) * minutesPerBucket;
        const t = new Date(endTime.getTime() - minAgo * 60000);
        const hh = String(t.getHours()).padStart(2, '0');
        const mm = String(t.getMinutes()).padStart(2, '0');
        return `${hh}:${mm}`;
      });

      html += `<div class="ers-dist-card">`;
      html += `<div class="ers-dist-header">`;
      html += `  <div><div class="ers-dist-title"><span style="font-size:14px;">📊</span> Event Distribution</div>`;
      html += `  <div class="ers-dist-window">⏱ Last 1 hour</div></div>`;
      html += `  <div style="text-align:right;"><div class="ers-dist-total">${total.toLocaleString()}</div>`;
      html += `  <div class="ers-dist-total-label">Total Events</div></div>`;
      html += `</div>`;

      html += `<div class="ers-dist-chart" style="height:${chartH}px;">`;

      // Average line
      if (avg > 0) {
        html += `<div class="ers-dist-avg-line" style="bottom:${Math.max(2,(avg/maxS)*chartH)}px;">`;
        html += `<span class="ers-dist-avg-label">avg ${avg.toFixed(1)}</span></div>`;
      }

      sp.forEach((v, i) => {
        const h = Math.max(2, (v / maxS) * chartH);
        const isPeak = i === peakIdx && v > 0;
        html += `<div class="ers-dist-bar-wrap">`;
        if (isPeak) html += `<div class="ers-dist-peak">▼</div>`;
        html += `<div class="ers-dist-tip">${v} events<br><span style="font-size:8px;opacity:.7;">${timeLabels[i]}</span></div>`;
        if (v === 0) {
          html += `<div class="ers-dist-bar" style="height:2px;background:var(--border);border-radius:4px 4px 0 0;"></div>`;
        } else {
          html += `<div class="ers-dist-bar" style="height:${h}px;background:#FFC600;border-radius:4px 4px 0 0;"></div>`;
        }
        html += `</div>`;
      });
      html += `</div>`;

      // Time axis
      html += `<div class="ers-dist-axis">`;
      const axisLabels = [0, Math.floor(buckets/4), Math.floor(buckets/2), Math.floor(3*buckets/4), buckets-1];
      const uniqueAxis = [...new Set(axisLabels)];
      uniqueAxis.forEach(i => {
        html += `<span>${timeLabels[i]}</span>`;
      });
      html += `</div>`;

      // Legend
      html += `<div class="ers-dist-legend">`;
      html += `<span><span class="ers-dist-legend-dot" style="background:#FFC600;"></span>Events</span>`;
      html += `<span>Avg: ${avg.toFixed(1)}/interval</span>`;
      html += `<span style="margin-left:auto;font-weight:600;">Peak: ${maxS} at ${timeLabels[peakIdx]}</span>`;
      html += `</div>`;

      html += `</div>`;
    }

    // Baseline comparison — visual dual-bar design
    if (attr.baseline) {
      const b = attr.baseline;
      const maxVal = Math.max(b.expected, b.actual, 1);
      const expPct = Math.min((b.expected / maxVal) * 100, 100);
      const actPct = Math.min((b.actual / maxVal) * 100, 100);
      let severity, devLabel, devIcon;
      if (b.expected === 0 || b.deviation === null) {
        severity = 'first'; devLabel = 'First occurrence'; devIcon = '✦';
      } else if (b.deviation > 2) {
        severity = 'danger'; devLabel = `${b.deviation}× above normal`; devIcon = '▲';
      } else if (b.deviation > 1.3) {
        severity = 'warning'; devLabel = `${b.deviation}× above normal`; devIcon = '▲';
      } else {
        severity = 'normal'; devLabel = 'Within normal range'; devIcon = '●';
      }
      html += `<div class="ers-baseline-card">`;
      html += `<div class="ers-bl-header" style="display:flex;align-items:center;justify-content:space-between;">`;
      html += `  <span><span style="font-size:13px;">📊</span> Behavioral Baseline</span>`;
      html += `  <span class="ers-time-badge">⏱ Last 1 hour</span>`;
      html += `</div>`;
      html += `<div class="ers-bl-bar-row">`;
      html += `  <span class="ers-bl-label">Expected</span>`;
      html += `  <div class="ers-bl-track"><div class="ers-bl-fill expected" style="width:${expPct}%"></div></div>`;
      html += `  <span class="ers-bl-num">${b.expected}</span>`;
      html += `</div>`;
      html += `<div class="ers-bl-bar-row">`;
      html += `  <span class="ers-bl-label">Actual</span>`;
      html += `  <div class="ers-bl-track"><div class="ers-bl-fill actual ${severity}" style="width:${actPct}%"></div></div>`;
      html += `  <span class="ers-bl-num">${b.actual}</span>`;
      html += `</div>`;
      html += `<div class="ers-bl-divider"></div>`;
      html += `<div class="ers-bl-footer">`;
      html += `  <span class="ers-bl-dev-badge ${severity}"><span class="ers-bl-dev-dot"></span>${devIcon} ${devLabel}</span>`;
      if (b.expected > 0 && b.deviation !== null) {
        html += `<span class="ers-bl-ratio">${b.expected} → ${b.actual} events</span>`;
      }
      html += `</div>`;
      html += `</div>`;
    }

    html += `</div>`;
  }

  // ── Threat Intelligence ──
  if (attr.threatIntel) {
    const ti = attr.threatIntel;
    const tiBg = ti.reputation <= 2 ? '#fee2e2' : ti.reputation <= 30 ? '#fff7ed' : '#f0fdf4';
    const tiColor = ti.reputation <= 2 ? '#991b1b' : ti.reputation <= 30 ? '#9a3412' : '#166534';
    html += `<div class="ers-section">`;
    html += `<div class="ers-section-title">Threat Intelligence</div>`;
    html += `<div class="ers-ti-row">`;
    html += `<div class="ers-ti-badge" style="background:${tiBg};color:${tiColor};border-color:${tiColor}20;">`;
    html += `<span>🛡</span> <span>${ti.vendor}</span> <span class="ers-ti-score">${ti.label}</span></div>`;
    if (ti.virusTotal) {
      const vtParts = ti.virusTotal.split('/');
      const vtRatio = parseInt(vtParts[0]) / parseInt(vtParts[1]);
      const vtBg = vtRatio > 0.3 ? '#fee2e2' : vtRatio > 0.1 ? '#fff7ed' : '#f0fdf4';
      const vtColor = vtRatio > 0.3 ? '#991b1b' : vtRatio > 0.1 ? '#9a3412' : '#166534';
      html += `<div class="ers-ti-badge" style="background:${vtBg};color:${vtColor};border-color:${vtColor}20;">`;
      html += `<span>🔬</span> <span>VirusTotal</span> <span class="ers-ti-score">${ti.virusTotal}</span></div>`;
    }
    html += `</div></div>`;
  }

  // ── Geo Context ──
  if (attr.geo) {
    html += `<div class="ers-section">`;
    html += `<div class="ers-section-title">Geo Context</div>`;
    html += `<div class="ers-geo-row">`;
    html += `<span class="ers-geo-flag">${attr.geo.flag}</span>`;
    html += `<div><div class="ers-geo-loc">${attr.geo.city}, ${attr.geo.country}</div>`;
    html += `<div class="ers-geo-ip">${attr.geo.ip}</div></div></div>`;
    html += `</div>`;
  }

  // ── Evidence section ── (enhanced panel)
  const ev = typeof attr.evidence === 'string' ? { summary: attr.evidence } : attr.evidence;
  if (ev && ev.summary) {
    const risk = attr.risk || 0;
    let sevClass, sevLabel;
    if (risk >= 90) { sevClass = 'critical'; sevLabel = 'Critical'; }
    else if (risk >= 70) { sevClass = 'high'; sevLabel = 'High'; }
    else if (risk >= 40) { sevClass = 'medium'; sevLabel = 'Medium'; }
    else { sevClass = 'low'; sevLabel = 'Low'; }

    const conf = ev.confidence || 0;
    let confColor;
    if (conf >= 90) confColor = '#22c55e';
    else if (conf >= 70) confColor = '#eab308';
    else if (conf >= 40) confColor = '#f97316';
    else confColor = '#64748b';

    html += `<div class="ers-section">`;
    html += `<div class="ers-section-title">Evidence</div>`;
    html += `<div class="ers-evidence-panel">`;

    // Header with severity bar + summary
    html += `<div class="ers-evp-header">`;
    html += `<div class="ers-evp-sev ${sevClass}" title="Severity: ${sevLabel}"></div>`;
    html += `<div class="ers-evp-summary">${ev.summary}</div>`;
    html += `</div>`;

    html += `<div class="ers-evp-body">`;

    // Key findings chips
    if (ev.findings && ev.findings.length) {
      html += `<div class="ers-evp-findings">`;
      const dotColors = ['#ef4444','#f97316','#3b82f6','#8b5cf6','#22c55e','#eab308'];
      ev.findings.forEach((f, i) => {
        const dc = dotColors[i % dotColors.length];
        html += `<span class="ers-evp-finding"><span class="evf-dot" style="background:${dc}"></span>${f}</span>`;
      });
      html += `</div>`;
    }

    // Confidence meter
    if (ev.confidence !== undefined) {
      html += `<div class="ers-evp-confidence">`;
      html += `<span class="ers-evp-conf-label">Confidence</span>`;
      html += `<div class="ers-evp-conf-track"><div class="ers-evp-conf-fill" style="width:${conf}%;background:${confColor};"></div></div>`;
      html += `<span class="ers-evp-conf-val" style="color:${confColor};">${conf}%</span>`;
      html += `</div>`;
    }

    // Source & count badges
    if (attr.source || attr.count) {
      html += `<div class="ers-evp-source-row">`;
      if (attr.source) {
        html += `<span class="ers-evp-source-badge">📡 ${attr.source}</span>`;
      }
      if (attr.count) {
        html += `<span class="ers-evp-count-badge"># ${attr.count} events</span>`;
      }
      html += `</div>`;
    }

    html += `</div></div>`;
    html += `</div>`;
  }

  // Populate slider body and open
  document.getElementById('edsBody').innerHTML = html;
  document.getElementById('graphContainer').classList.add('slider-open');
  // Close any action panel that might be open
  closeActionPanel();
}

/* Legacy popup dismiss (kept for safety) */
document.addEventListener('click', () => {
  const popup = document.getElementById('edgeRelPopup');
  if (popup) popup.classList.remove('show');
});

/* ── AI Prediction details ─────────────────────────────────────────────
 * Opens the shared slider with a "predicted next step" card. This is
 * deliberately styled differently from observed entities/edges so the
 * analyst never confuses a projection with a fact. Reasoning is grounded
 * in real observed events (Evidence Basis section). */
const PREDICTION_DETAILS = {
  'dev-dc01-predicted': {
    title: 'DC-01 · AI-projected target',
    summary: 'Domain Controller (DC-01) is the most likely next target for lateral movement using the compromised administrator credentials observed on CORP-WS-045.',
    confidence: 78,
    eta: 'Within next ~30 min',
    mitre: [
      { id: 'T1078.003', name: 'Valid Accounts: Local Accounts' },
      { id: 'T1021.001', name: 'Remote Services: RDP' },
      { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory' }
    ],
    basis: [
      'Observed: EID 4648 — Explicit credential used (administrator) on CORP-WS-045 @ 15:36:22',
      'Observed: EID 4624 — Logon type 9 (NewCredentials) chained with token impersonation',
      'Pattern match: 87% similarity to prior incidents that pivoted to DC within 30 min'
    ],
    recommendation: [
      'Force-revoke administrator session and disable account (auto-suggested in Recommendation tab)',
      'Block SMB/RDP from CORP-WS-045 → DC-01 at firewall',
      'Trigger LSASS protection / Credential Guard policy on DC-01'
    ]
  },
  'proc-credump-predicted': {
    title: 'LSASS Credential Dump · AI-projected step',
    summary: 'The AI projects credential dumping from LSASS memory on CORP-WS-045 as the next step — needed to harvest DC service tickets/NTLM hashes before pivoting to DC-01. Not yet observed.',
    confidence: 72,
    eta: 'Within next ~15 min',
    mitre: [
      { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory' },
      { id: 'T1059.001', name: 'PowerShell' },
      { id: 'T1078.003', name: 'Valid Accounts: Local Accounts' }
    ],
    basis: [
      'Observed: Encoded PowerShell execution by m.henderson on CORP-WS-045 (T1059.001)',
      'Observed: Suspicious service WinUpdateSvc installed — typical staging for credential dumpers',
      'Observed: Administrator credentials already abused (EID 4648) but no DC ticket yet — dump is the missing pre-req',
      'Pattern match: 81% of similar kill-chains executed LSASS dump within 15 min of admin-cred abuse'
    ],
    recommendation: [
      'Enable Credential Guard / LSA Protection (RunAsPPL=1) on CORP-WS-045 immediately',
      'EDR isolate CORP-WS-045 before dump tooling executes',
      'Trigger memory acquisition for forensic capture of LSASS state',
      'Force-rotate all cached domain admin credentials'
    ]
  }
};

/* Edge-level predictions: same shared slider, but the framing is the
 * *relationship* (the projected action), not the target entity. */
const PREDICTION_EDGE_DETAILS = {
  'user-admin→dev-dc01-predicted': {
    title: 'Administrator → DC-01',
    relation: 'LoginTo',
    summary: 'The AI projects the compromised administrator account will be used to log in to the Domain Controller (DC-01) from CORP-WS-045 \u2014 a lateral-movement pivot. This authentication has not been observed yet.',
    confidence: 78,
    eta: 'Within next ~30 min',
    method: 'Remote Services (RDP / SMB) using stolen administrator credentials',
    mitre: [
      { id: 'T1021.001', name: 'Remote Services: Remote Desktop Protocol' },
      { id: 'T1021.002', name: 'Remote Services: SMB / Windows Admin Shares' },
      { id: 'T1078.003', name: 'Valid Accounts: Local Accounts' }
    ],
    basis: [
      'Observed: EID 4648 — Explicit credential used (administrator) on CORP-WS-045 @ 15:36:22',
      'Observed: PowerShell parent → child chain consistent with credential dumping',
      'Pattern match: 87% of similar kill-chains pivoted to a DC within 30 min via RDP/SMB'
    ],
    recommendation: [
      'Block 192.168.1.22 → DC-01 on TCP/445 (SMB) and TCP/3389 (RDP) at the network firewall',
      'Force-disable the administrator account in AD',
      'Enable Restricted Admin Mode for RDP on DC-01',
      'Increase audit policy on DC-01 (4624, 4672, 4769) for next 24h'
    ]
  },
  'dev-ws045→proc-credump-predicted': {
    title: 'CORP-WS-045 → LSASS Dump',
    relation: 'ExecutedOn',
    summary: 'The AI projects credential-dumping tooling will execute on CORP-WS-045 to harvest cached domain-admin material from LSASS memory. This execution has not been observed yet.',
    confidence: 72,
    eta: 'Within next ~15 min',
    method: 'Encoded PowerShell (already observed) loading a reflective in-memory dumper against lsass.exe',
    mitre: [
      { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory' },
      { id: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell' }
    ],
    basis: [
      'Observed: Encoded PowerShell execution by m.henderson on CORP-WS-045',
      'Observed: Suspicious service WinUpdateSvc installed (typical loader staging)',
      'Observed: Administrator credentials already used — attacker has local elevation but no DC ticket yet',
      'Pattern match: 81% of similar chains performed LSASS dump within 15 min of admin-cred abuse'
    ],
    recommendation: [
      'Enable LSA Protection (RunAsPPL=1) and Credential Guard on CORP-WS-045 right now',
      'EDR isolate CORP-WS-045 before any dumper binary loads',
      'Trigger Sysmon EID 10 alerts for any handle to lsass.exe with GrantedAccess 0x1010/0x1410',
      'Force-rotate domain admin credentials before the dump completes'
    ]
  }
};

function showPredictionDetails(entityId) {
  const data = PREDICTION_DETAILS[entityId];
  if (!data) return;
  if (typeof event !== 'undefined' && event && event.stopPropagation) event.stopPropagation();

  // Highlight the predicted node and its connected edges/neighbors
  if (typeof restoreGraphHighlights === 'function') restoreGraphHighlights(entityId);

  // Reuse shared slider DOM
  document.getElementById('edsTitle').textContent = data.title;
  const badge = document.getElementById('edsTypeBadge');
  badge.textContent = '⏱ AI Prediction';
  badge.className = 'eds-type-badge';
  badge.style.cssText = 'display:inline-flex;background:#fef3c7;color:#92400e;border:1px solid #fde68a;';
  const depthBadge = document.getElementById('edsDepthBadge');
  if (depthBadge) depthBadge.style.display = 'none';
  const tabsHost = document.getElementById('edsTabsHost');
  if (tabsHost) tabsHost.innerHTML = '';

  const confColor = data.confidence >= 75 ? '#dc2626' : data.confidence >= 50 ? '#d97706' : '#65a30d';
  const mitreHtml = data.mitre.map(m => `<span class="ers-mitre-chip" style="background:#fef3c7;color:#92400e;border:1px solid #fde68a;padding:2px 8px;border-radius:6px;font-size:11px;margin-right:6px;display:inline-block;margin-bottom:4px;">${m.id} · ${m.name}</span>`).join('');
  const basisHtml = data.basis.map(b => `<li style="margin-bottom:6px;line-height:1.5;">${b}</li>`).join('');
  const recHtml = data.recommendation.map(r => `<li style="margin-bottom:6px;line-height:1.5;">${r}</li>`).join('');

  document.getElementById('edsBody').innerHTML = `
    <div class="eds-section" style="padding:12px 16px;border-bottom:1px solid var(--border);background:#fffbeb;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <span style="font-size:22px;">⏱</span>
        <div style="flex:1;">
          <div style="font-size:12px;font-weight:700;color:#92400e;letter-spacing:0.5px;">NOT YET OBSERVED · AI PROJECTION</div>
          <div style="font-size:11px;color:#78350f;margin-top:2px;">This is the AI's most likely next step based on observed kill-chain patterns. It has not happened yet.</div>
        </div>
      </div>
      <div style="font-size:12.5px;color:#1f2937;line-height:1.5;">${data.summary}</div>
    </div>
    <div class="eds-section" style="padding:12px 16px;border-bottom:1px solid var(--border);">
      <div style="display:flex;gap:12px;">
        <div style="flex:1;background:#fafafa;border:1px solid var(--border);border-radius:6px;padding:8px 10px;">
          <div style="font-size:10px;color:#64748b;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;">Confidence</div>
          <div style="font-size:18px;font-weight:700;color:${confColor};margin-top:2px;">${data.confidence}%</div>
          <div style="height:4px;background:#e5e7eb;border-radius:2px;margin-top:4px;overflow:hidden;">
            <div style="width:${data.confidence}%;background:${confColor};height:100%;"></div>
          </div>
        </div>
        <div style="flex:1;background:#fafafa;border:1px solid var(--border);border-radius:6px;padding:8px 10px;">
          <div style="font-size:10px;color:#64748b;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;">Expected Within</div>
          <div style="font-size:13px;font-weight:600;color:#1f2937;margin-top:6px;">${data.eta}</div>
        </div>
      </div>
    </div>
    <div class="eds-section" style="padding:12px 16px;border-bottom:1px solid var(--border);">
      <div style="font-size:11px;color:#64748b;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px;">MITRE ATT&amp;CK Techniques</div>
      <div>${mitreHtml}</div>
    </div>
    <div class="eds-section" style="padding:12px 16px;border-bottom:1px solid var(--border);">
      <div style="font-size:11px;color:#64748b;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px;">Evidence Basis <span style="font-weight:500;color:#94a3b8;text-transform:none;letter-spacing:0;">(why AI predicts this)</span></div>
      <ul style="margin:0;padding-left:18px;font-size:12px;color:#334155;">${basisHtml}</ul>
    </div>
    <div class="eds-section" style="padding:12px 16px;">
      <div style="font-size:11px;color:#64748b;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px;">Recommended Pre-emptive Actions</div>
      <ul style="margin:0;padding-left:18px;font-size:12px;color:#334155;">${recHtml}</ul>
    </div>`;

  document.getElementById('graphContainer').classList.add('slider-open');
  if (typeof closeActionPanel === 'function') closeActionPanel();
}

function showEdgePrediction(evt, el) {
  if (evt && evt.stopPropagation) evt.stopPropagation();
  const source = el.getAttribute('data-source');
  const target = el.getAttribute('data-target');
  const data = PREDICTION_EDGE_DETAILS[source + '\u2192' + target];
  if (!data) return;

  // Highlight the predicted edge: focus source + target, dim everything else
  document.querySelectorAll('.graph-node').forEach(n => { n.style.opacity = '0.25'; n.classList.remove('active-focus'); });
  const srcNode = document.querySelector(`.graph-node[data-entity="${source}"]`);
  const tgtNode = document.querySelector(`.graph-node[data-entity="${target}"]`);
  if (srcNode) srcNode.style.opacity = '1';
  if (tgtNode) tgtNode.style.opacity = '1';
  document.querySelectorAll('line[data-source]').forEach(line => {
    const ls = line.getAttribute('data-source');
    const lt = line.getAttribute('data-target');
    if (ls === source && lt === target) {
      line.style.opacity = '1';
      line.style.strokeWidth = '2.5';
    } else {
      line.style.opacity = '0.12';
      line.style.strokeWidth = '';
    }
  });
  document.querySelectorAll('.edge-info-btn').forEach(btn => {
    const bs = btn.getAttribute('data-source');
    const bt = btn.getAttribute('data-target');
    btn.style.opacity = (bs === source && bt === target) ? '1' : '0.2';
  });

  document.getElementById('edsTitle').textContent = data.title;
  const badge = document.getElementById('edsTypeBadge');
  // Resolve the canonical relation from REL_GUIDE so icon/color match
  // the rest of the graph (predicted edge uses LoginTo → 🔐 blue).
  const relGuide = (typeof REL_GUIDE !== 'undefined')
    ? REL_GUIDE.find(r => r.key === data.relation) : null;
  const relIcon = relGuide ? relGuide.icon : '🔗';
  const relName = relGuide ? relGuide.name : data.relation;
  badge.textContent = '⏱ ' + relIcon + ' ' + relName + ' · Predicted';
  badge.className = 'eds-type-badge';
  badge.style.cssText = 'display:inline-flex;background:#fef3c7;color:#92400e;border:1px solid #fde68a;';
  const depthBadge = document.getElementById('edsDepthBadge');
  if (depthBadge) depthBadge.style.display = 'none';
  const tabsHost = document.getElementById('edsTabsHost');
  if (tabsHost) tabsHost.innerHTML = '';

  const confColor = data.confidence >= 75 ? '#dc2626' : data.confidence >= 50 ? '#d97706' : '#65a30d';
  const mitreHtml = data.mitre.map(m => `<span style="background:#fef3c7;color:#92400e;border:1px solid #fde68a;padding:2px 8px;border-radius:6px;font-size:11px;margin-right:6px;display:inline-block;margin-bottom:4px;">${m.id} · ${m.name}</span>`).join('');
  const basisHtml = data.basis.map(b => `<li style="margin-bottom:6px;line-height:1.5;">${b}</li>`).join('');
  const recHtml = data.recommendation.map(r => `<li style="margin-bottom:6px;line-height:1.5;">${r}</li>`).join('');

  document.getElementById('edsBody').innerHTML = `
    <div class="eds-section" style="padding:12px 16px;border-bottom:1px solid var(--border);background:#fffbeb;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <span style="font-size:22px;">⏱</span>
        <div style="flex:1;">
          <div style="font-size:12px;font-weight:700;color:#92400e;letter-spacing:0.5px;">NOT YET OBSERVED · PREDICTED ATTACK STEP</div>
          <div style="font-size:11px;color:#78350f;margin-top:2px;">The AI projects this relationship as the most likely next action in the kill-chain.</div>
        </div>
      </div>
      <div style="font-size:12.5px;color:#1f2937;line-height:1.5;">${data.summary}</div>
    </div>
    <div class="eds-section" style="padding:12px 16px;border-bottom:1px solid var(--border);">
      <div style="display:flex;gap:12px;flex-wrap:wrap;">
        <div style="flex:1;min-width:140px;background:#fafafa;border:1px solid var(--border);border-radius:6px;padding:8px 10px;">
          <div style="font-size:10px;color:#64748b;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;">Relation</div>
          <div style="font-size:13px;font-weight:600;color:#1f2937;margin-top:4px;">${relIcon} ${relName}</div>
          <div style="font-size:10.5px;color:#94a3b8;margin-top:2px;">${relGuide ? relGuide.category : ''}</div>
        </div>
        <div style="flex:1;min-width:120px;background:#fafafa;border:1px solid var(--border);border-radius:6px;padding:8px 10px;">
          <div style="font-size:10px;color:#64748b;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;">Confidence</div>
          <div style="font-size:18px;font-weight:700;color:${confColor};margin-top:2px;">${data.confidence}%</div>
          <div style="height:4px;background:#e5e7eb;border-radius:2px;margin-top:4px;overflow:hidden;">
            <div style="width:${data.confidence}%;background:${confColor};height:100%;"></div>
          </div>
        </div>
        <div style="flex:1;min-width:140px;background:#fafafa;border:1px solid var(--border);border-radius:6px;padding:8px 10px;">
          <div style="font-size:10px;color:#64748b;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;">Expected Within</div>
          <div style="font-size:13px;font-weight:600;color:#1f2937;margin-top:6px;">${data.eta}</div>
        </div>
      </div>
    </div>
    <div class="eds-section" style="padding:12px 16px;border-bottom:1px solid var(--border);">
      <div style="font-size:11px;color:#64748b;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:6px;">Predicted Method</div>
      <div style="font-size:12.5px;color:#334155;line-height:1.5;">${data.method}</div>
    </div>
    <div class="eds-section" style="padding:12px 16px;border-bottom:1px solid var(--border);">
      <div style="font-size:11px;color:#64748b;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px;">MITRE ATT&amp;CK Techniques</div>
      <div>${mitreHtml}</div>
    </div>
    <div class="eds-section" style="padding:12px 16px;border-bottom:1px solid var(--border);">
      <div style="font-size:11px;color:#64748b;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px;">Evidence Basis <span style="font-weight:500;color:#94a3b8;text-transform:none;letter-spacing:0;">(why AI predicts this)</span></div>
      <ul style="margin:0;padding-left:18px;font-size:12px;color:#334155;">${basisHtml}</ul>
    </div>
    <div class="eds-section" style="padding:12px 16px;">
      <div style="font-size:11px;color:#64748b;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px;">Recommended Pre-emptive Actions</div>
      <ul style="margin:0;padding-left:18px;font-size:12px;color:#334155;">${recHtml}</ul>
    </div>`;

  document.getElementById('graphContainer').classList.add('slider-open');
  if (typeof closeActionPanel === 'function') closeActionPanel();
}


/* ── REL_GUIDE + toggleRelGuide ──
 * Canonical relation catalog — 24 edges across 7 categories.
 * Conventions:
 *   • All names are PascalCase (no UPPER_SNAKE, no kebab-case).
 *   • One direction per relation. Inverses are not added separately
 *     (e.g. SpawnedBy covers ParentOf; SentTo covers ReceivedFrom).
 *   • Synonyms are collapsed (OwnedBy absorbs BelongsTo;
 *     CommunicatedWith absorbs ConnectedVia — transport is a property).
 *   • `category` groups edges for the legend UI.
 * Legacy aliases (UPPER_SNAKE / synonyms) are mapped via REL_ALIASES below
 * so older data still resolves.
 */
const REL_GUIDE = [
  // ── Detection ──
  { key:'TriggeredBy',         category:'Detection',         color:'#DD1616', icon:'⚡',  name:'Triggered By',         desc:'A detection rule or correlation alert was triggered due to the suspicious behavior or anomalous activity of this entity. Connects an alert to the primary entity responsible for the triggering event.' },
  { key:'DetectedOn',          category:'Detection',         color:'#FABB34', icon:'🔍', name:'Detected On',          desc:'The alert or detection event was observed on this service, platform, or system. Links an alert to the infrastructure component where the suspicious activity was recorded.' },
  // ── Identity & Access ──
  { key:'LoginTo',             category:'Identity & Access', color:'#2C66DD', icon:'🔐', name:'Login To',             desc:'A user or service account authenticated and established a session on a target service, device, or application. Captured from authentication logs.' },
  { key:'AccessedFrom',        category:'Identity & Access', color:'#f97316', icon:'🌐', name:'Accessed From',        desc:'A user session or activity originated from this source IP address. Traces the network origin of the session — useful for geographic anomalies or VPN/proxy usage.' },
  { key:'IssuedTo',            category:'Identity & Access', color:'#0891b2', icon:'📜', name:'Issued To',            desc:'An identity provider (Azure AD, Okta, ADFS) issued an authentication token, OAuth credential, or certificate to an entity, granting it access to downstream services.' },
  { key:'MemberOf',            category:'Identity & Access', color:'#2C66DD', icon:'👥', name:'Member Of',            desc:'A user or service account is a member of a security group, distribution list, or organizational unit. Tracks identity-to-group membership relevant for privilege analysis.' },
  { key:'OwnedBy',             category:'Identity & Access', color:'#2C66DD', icon:'👤', name:'Owned By',             desc:'A resource, application, or device is owned, assigned to, or managed by a specific user, service account, or organizational unit. Identifies the responsible party for an asset.' },
  // ── Privilege ──
  { key:'EscalatedTo',         category:'Privilege',         color:'#FF5900', icon:'⬆️', name:'Escalated To',         desc:'A user or process escalated privileges to a higher-level account or role. Detects lateral movement and privilege-escalation attempts such as local-admin elevation or token impersonation.' },
  { key:'GrantedAccess',       category:'Privilege',         color:'#FF5900', icon:'🔓', name:'Granted Access',       desc:'An identity provider or administrator granted access permissions, roles, or entitlements to an entity. Tracks permission changes that could indicate unauthorized access provisioning.' },
  // ── Data Movement ──
  { key:'AccessedFile',        category:'Data Movement',     color:'#7c3aed', icon:'📁', name:'Accessed File',        desc:'An entity performed a file operation (read, write, modify) on a file-hosting service such as SharePoint, OneDrive, or a network share. Tracks data access patterns.' },
  { key:'DownloadedFrom',      category:'Data Movement',     color:'#D14900', icon:'⬇️', name:'Downloaded From',      desc:'An entity downloaded data or files from an external or internal source. Tracks inbound data transfers that may include malware delivery or unauthorized content retrieval.' },
  { key:'UploadedTo',          category:'Data Movement',     color:'#D14900', icon:'⬆️', name:'Uploaded To',          desc:'An entity uploaded data or files to a cloud service, external server, or removable media. Critical for detecting data exfiltration to external destinations.' },
  { key:'ExfiltratedTo',       category:'Data Movement',     color:'#DD1616', icon:'🚨', name:'Exfiltrated To',       desc:'Sensitive data was transferred to an unauthorized external destination. High-severity edge indicating confirmed or suspected data exfiltration via network, cloud, or physical channels.' },
  // ── Network ──
  { key:'CommunicatedWith',    category:'Network',           color:'#DD1616', icon:'📡', name:'Communicated With',    desc:'A device or IP established network communication (TCP/UDP, DNS query, HTTP request) with an external domain or host. Critical for C2 callback and exfiltration detection. Transport details (VPN/gateway/interface) are carried as edge properties.' },
  { key:'TunneledThrough',     category:'Network',           color:'#198019', icon:'🕳️', name:'Tunneled Through',     desc:'Network traffic was encapsulated through a tunnel (VPN, SSH, DNS, or ICMP). Detects covert communication channels used to bypass network security controls.' },
  { key:'ProxiedBy',           category:'Network',           color:'#198019', icon:'🔀', name:'Proxied By',           desc:'Network traffic was routed through a proxy server, load balancer, or anonymization service. Identifies traffic obfuscation and the actual origin behind proxied connections.' },
  { key:'ResolvedTo',          category:'Network',           color:'#198019', icon:'📌', name:'Resolved To',          desc:'An IP address was mapped to a specific device or hostname through DNS resolution or DHCP lease records. Links network-layer addresses to physical or virtual endpoints.' },
  // ── Process ──
  { key:'ExecutedOn',          category:'Process',           color:'#7c3aed', icon:'▶️', name:'Executed On',          desc:'A process or binary was executed on a specific device or endpoint. Tracks which programs ran on which hosts — essential for identifying malicious execution chains.' },
  { key:'SpawnedBy',           category:'Process',           color:'#7c3aed', icon:'🔗', name:'Spawned By',           desc:'A child process was spawned by a parent process. Maps the process tree to detect suspicious chains such as Word spawning PowerShell or cmd.exe launching encoded scripts. (Inverse "ParentOf" is represented by reversing source/target.)' },
  // ── Email ──
  { key:'SentTo',              category:'Email',             color:'#0891b2', icon:'📤', name:'Sent To',              desc:'An email was sent from one entity to another. Tracks outbound email relevant for phishing campaigns, social engineering, and insider-threat patterns. (Inverse "ReceivedFrom" is represented by reversing source/target.)' },
  { key:'ContainedAttachment', category:'Email',             color:'#0891b2', icon:'📎', name:'Contained Attachment', desc:'An email contained a file attachment. Links email messages to attached files for tracking malware delivery, macro-enabled documents, and executable payloads.' },
  // ── System Change ──
  { key:'ModifiedRegistry',    category:'System Change',     color:'#D14900', icon:'🔧', name:'Modified Registry',    desc:'A process or user modified a Windows registry key or value. Tracks persistence mechanisms, startup entries, and configuration changes commonly used by malware.' },
  { key:'CreatedService',      category:'System Change',     color:'#D14900', icon:'⚙️', name:'Created Service',      desc:'A process or user installed a new system service or scheduled task. Detects persistence techniques, backdoor installation, and unauthorized service creation.' },
  { key:'InstalledOn',         category:'System Change',     color:'#D14900', icon:'💿', name:'Installed On',         desc:'A software package, driver, or update was installed on a device. Tracks software deployment events for detecting unauthorized installations or trojanized updates.' }
];

/* Legacy → canonical mapping for backwards-compat with older data. */
const REL_ALIASES = {
  'TRIGGERED_BY': 'TriggeredBy',
  'DETECTED_ON':  'DetectedOn',
  'ISSUED':       'IssuedTo',
  'BelongsTo':    'OwnedBy',
  'ParentOf':     'SpawnedBy',
  'ReceivedFrom': 'SentTo',
  'ConnectedVia': 'CommunicatedWith'
};
function canonicalRelation(key) { return REL_ALIASES[key] || key; }

function toggleRelGuide(event) {
  event.stopPropagation();
  const popup = document.getElementById('relGuidePopup');
  if (popup.classList.contains('show')) { popup.classList.remove('show'); return; }

  let html = '<div class="rel-guide-hdr">⟷ Relationship Guide <span class="rg-close" onclick="document.getElementById(\'relGuidePopup\').classList.remove(\'show\')">&times;</span></div>';
  html += '<div class="rel-guide-list">';
  // Group relations by category for readability
  const grouped = REL_GUIDE.reduce((acc, r) => {
    const cat = r.category || 'Other';
    (acc[cat] = acc[cat] || []).push(r);
    return acc;
  }, {});
  const catOrder = ['Detection','Identity & Access','Privilege','Data Movement','Network','Process','Email','System Change','Other'];
  catOrder.forEach(cat => {
    if (!grouped[cat]) return;
    html += `<div class="rel-guide-cat" style="font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.5px;margin:8px 4px 4px;">${cat}</div>`;
    grouped[cat].forEach(r => {
      html += `<div class="rel-guide-item" style="cursor:default;">
        <span style="font-size:16px;line-height:1;flex-shrink:0;">${r.icon}</span>
        <div style="flex:1;min-width:0;">
          <div class="rel-guide-name">${r.name}</div>
          <div class="rel-guide-text">${r.desc}</div>
        </div>
      </div>`;
    });
  });
  html += '</div>';
  popup.innerHTML = html;

  // Position above the button, aligned to left edge of button
  const btn = event.currentTarget;
  const rect = btn.getBoundingClientRect();
  popup.style.left = rect.left + 'px';
  popup.style.right = 'auto';
  popup.style.bottom = (window.innerHeight - rect.top + 6) + 'px';
  popup.style.top = 'auto';
  popup.classList.add('show');
  const popRect = popup.getBoundingClientRect();
  if (popRect.right > window.innerWidth - 12) {
    popup.style.left = 'auto';
    popup.style.right = '12px';
  }
  const popRect2 = popup.getBoundingClientRect();
  if (popRect2.top < 8) {
    popup.style.bottom = 'auto';
    popup.style.top = '8px';
    popup.querySelector('.rel-guide-list').style.maxHeight = (rect.top - 60) + 'px';
  }

  setTimeout(() => {
    document.addEventListener('click', function closeGuide(e) {
      if (!popup.contains(e.target) && e.target !== btn) {
        popup.classList.remove('show');
        document.removeEventListener('click', closeGuide);
      }
    });
  }, 10);
}


