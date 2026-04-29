/* ═══════════════════════════════════════════════════════════════
 * alerts.js — Alert data definitions
 *
 * Each alert object drives the left-panel alert list and detail
 * header. To add a new alert, push an object with { id, title,
 * severity, score, meta, user }.
 * ═══════════════════════════════════════════════════════════════ */

const ALERTS = [
  { id:1, title:'Impossible Travel Attack', severity:'high', score:80, meta:'Malicious URL malicious-site.in (185.234.217.19) has been requested by santhosh-8457 (10.18.1.81)', user:'Johnson Williams' },
  { id:2, title:'Malicious URL requests', severity:'low', score:36, meta:'Malicious URL malicious-site.in (185.234.217.19) has been requested by santhosh-8457 (10.18.1.81)', user:'Johnson Williams' },
  { id:3, title:'Malicious URL reque...', severity:'medium', score:55, meta:'Malicious URL malicious-site.in (185.234.217.19) has been requested by santhosh-8457 (10.18.1.81)', user:'Johnson Williams' },
  { id:4, title:'User Account Lockout...', severity:'high', score:80, meta:'User Account zohocorp/santhosh-8457 (185.234.217.19) has been locked out due to multiple failed logon...', user:'Johnson Williams' },
  { id:5, title:'Malicious URL requests', severity:'low', score:36, meta:'Malicious URL malicious-site.in (185.234.217.19) has been requested by santhosh-8457 (10.18.1.81)', user:'Johnson Williams' },
  { id:6, title:'Malicious URL requests', severity:'high', score:80, meta:'Malicious URL malicious-site.in (185.234.217.19) has been requested by santhosh-8457 (10.18.1.81)', user:'Johnson Williams' },
];
