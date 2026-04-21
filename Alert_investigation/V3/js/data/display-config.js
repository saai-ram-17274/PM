/* ═══════════════════════════════════════════════════════════════
 * display-config.js — Entity display metadata & critical reasons
 *
 * ENTITY_DISPLAY: Maps entity IDs → icon, name, color, bg for
 *   graph node tooltips, quick cards, and pill popups.
 *
 * CRITICAL_REASONS: Maps entity IDs → reason strings shown in
 *   the "Critical Entities" popup.
 *
 * When adding a new entity to entities.js, also register its
 * visual config here.
 * ═══════════════════════════════════════════════════════════════ */

const ENTITY_DISPLAY = {
  'alert-impossible-travel': { icon:'⚠', name:'Impossible Travel', color:'#ef4444', bg:'#fef2f2' },
  'user-m-henderson':        { icon:'👤', name:'m.henderson', color:'#7c3aed', bg:'#f5f0ff' },
  'svc-azure-ad':            { icon:'⚙', name:'Azure AD Portal', color:'#0891b2', bg:'#ecfeff' },
  'ip-tor':                  { icon:'◆', name:'185.220.101.42', color:'#ef4444', bg:'#fef2f2' },
  'ip-internal':             { icon:'◆', name:'10.18.1.81', color:'#16a34a', bg:'#f0fdf4' },
  'dev-ws045':               { icon:'🖥', name:'CORP-WS-045', color:'#dc2626', bg:'#fef2f2' },
  'svc-sharepoint':          { icon:'📁', name:'SharePoint', color:'#ea580c', bg:'#fff7ed' },
  'proc-oauth':              { icon:'🔑', name:'OAuth Tokens (3)', color:'#d97706', bg:'#fffbeb' },
  'user-admin':              { icon:'👤', name:'Administrator', color:'#0891b2', bg:'#ecfeff' },
  'proc-powershell':         { icon:'⚙', name:'PowerShell.exe', color:'#d97706', bg:'#fffbeb' },
  'svc-winupdatesvc':        { icon:'⚙', name:'WinUpdateSvc', color:'#ea580c', bg:'#fff7ed' },
  'alert-arp-spoofing-1':    { icon:'🔔', name:'ARP Spoofing (14:43)', color:'#ef4444', bg:'#fef2f2' },
  'alert-arp-spoofing-2':    { icon:'🔔', name:'ARP Spoofing (14:41)', color:'#ef4444', bg:'#fef2f2' },
  'proc-cmd':                { icon:'⚙', name:'cmd.exe', color:'#d97706', bg:'#fffbeb' },
  'proc-outlook':            { icon:'⚙', name:'outlook.exe', color:'#16a34a', bg:'#f0fdf4' },
  'svc-wuauserv':            { icon:'⚙', name:'wuauserv', color:'#d97706', bg:'#fffbeb' },
  'svc-spooler':             { icon:'⚙', name:'Spooler', color:'#16a34a', bg:'#f0fdf4' }
};

const CRITICAL_REASONS = {
  'alert-impossible-travel': 'Critical severity alert · UEBA Engine triggered · Confidence 92%',
  'ip-tor': 'Known Tor exit node · AbuseIPDB confidence 100% · 5 threat feeds flagged',
  'user-m-henderson': 'UEBA Risk Score 94/100 · Compromised account',
  'proc-oauth': 'Unregistered app tokens · Issued post-compromise',
  'svc-sharepoint': '24 files exfiltrated in 3 min from /Finance/Sensitive',
  'proc-powershell': 'Encoded command execution · AMSI detections · C2 communication',
  'svc-winupdatesvc': 'Masquerading service · Unsigned binary · C2 beacon active'
};
