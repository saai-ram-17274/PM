/* zia-hunt.js — Ask Zia Guided Investigation / Go Hunt chat panel
 * Depends on: entities.js, graph.js (panel mount), utils.js
 *
 * Public API (on window):
 *   openZiaHuntPanel(entityId)   — open chat panel for an entity
 *   closeZiaHuntPanel()          — close the panel
 *   zhpSend(text?)               — send a message (or read from #zhpInput)
 */

(function () {

  // ── State ──────────────────────────────────────────────────────────
  var _huntEntityId = null;
  var _typing = false;

  // ── Open / Close ───────────────────────────────────────────────────
  window.openZiaHuntPanel = function (entityId) {
    if (!entityId) return;
    /* entities.js uses `const ENTITIES` (not window.ENTITIES) — access both */
    var _ent = (typeof ENTITIES !== 'undefined' ? ENTITIES : null) || window.ENTITIES || {};
    var e = _ent[entityId];
    if (!e) return;

    _huntEntityId = entityId;

    // Close entity slider if open so the two panels don't overlap
    if (typeof closeEntitySlider === 'function') closeEntitySlider();

    var panel = document.getElementById('ziaHuntPanel');
    if (!panel) return;

    // Populate entity name in header
    var nameEl = document.getElementById('zhpEntityName');
    if (nameEl) {
      var typeIcons = { user: '👤', device: '💻', ip: '🌐', service: '⚙', process: '🔧', alert: '🔔' };
      var shortName = (e.modalTitle || '').split('·').pop().trim() || entityId;
      nameEl.textContent = (typeIcons[e.type] || '◇') + ' ' + shortName;
    }

    // Reset chat and render welcome + preview cards
    var chat = document.getElementById('zhpChat');
    if (chat) chat.innerHTML = '';
    _typing = false;
    _renderInitialPreview(entityId, e);

    // Render suggestion chips
    _renderSuggestions(e.type);

    // Slide panel open
    document.getElementById('graphContainer').classList.add('zia-hunt-open');
    panel.classList.add('open');

    // Focus input
    setTimeout(function () {
      var inp = document.getElementById('zhpInput');
      if (inp) inp.focus();
    }, 280);
  };

  window.closeZiaHuntPanel = function () {
    var panel = document.getElementById('ziaHuntPanel');
    if (panel) panel.classList.remove('open');
    var gc = document.getElementById('graphContainer');
    if (gc) gc.classList.remove('zia-hunt-open');
    _huntEntityId = null;
  };

  // ── Initial Preview ────────────────────────────────────────────────
  function _renderInitialPreview(entityId, e) {
    var shortName = (e.modalTitle || '').split('·').pop().trim() || entityId;
    var cards = _buildPreviewCards(entityId, e);
    _addBotMessage(
      'Here\'s a quick overview of <strong>' + _escHtml(shortName) + '</strong>. ' +
      'Tap a suggestion or ask me anything about this entity.',
      cards
    );
  }

  function _buildPreviewCards(entityId, e) {
    var html = '';

    // Risk / Summary card
    var rs = e.sections && e.sections.riskSummary && e.sections.riskSummary.summaryCard;
    if (rs) {
      html += '<div class="zhp-card zhp-card-risk">';
      html += '<div class="zhp-card-ttl">🛡 Risk Summary</div>';
      html += '<div class="zhp-card-kv">';
      var score = rs.riskScore !== undefined ? rs.riskScore : rs.score;
      if (score !== undefined) {
        html += '<span class="zhp-kv-k">Risk Score</span>' +
          '<span class="zhp-kv-v zhp-risk-score" data-score="' + score + '">' + score + ' / ' + (rs.maxScore || 100) + '</span>';
      }
      if (rs.severity) html += '<span class="zhp-kv-k">Severity</span><span class="zhp-kv-v">' + _escHtml(rs.severity) + '</span>';
      if (rs.statusBadge) html += '<span class="zhp-kv-k">Status</span><span class="zhp-kv-v">' + _escHtml(rs.statusBadge) + '</span>';
      if (rs.metrics) {
        rs.metrics.slice(0, 3).forEach(function (m) {
          html += '<span class="zhp-kv-k">' + _escHtml(m.label) + '</span><span class="zhp-kv-v">' + _escHtml(String(m.value)) + '</span>';
        });
      }
      html += '</div></div>';
    }

    // Recent alerts card
    var alertsSec = e.sections && e.sections.recentAlerts;
    var alertItems = alertsSec ? (alertsSec.kv || alertsSec.timeline || []) : [];
    if (alertItems.length) {
      html += '<div class="zhp-card zhp-card-alerts">';
      html += '<div class="zhp-card-ttl">🚨 Recent Alerts</div>';
      html += '<div class="zhp-card-list">';
      alertItems.slice(0, 3).forEach(function (item) {
        var label = item.label || item.key || item.event || item.name || '';
        var val = item.value || item.time || item.severity || '';
        html += '<div class="zhp-list-row"><span class="zhp-list-dot zhp-dot-red"></span>' +
          '<span class="zhp-list-label">' + _escHtml(String(label)) + '</span>' +
          '<span class="zhp-list-val">' + _escHtml(String(val)) + '</span></div>';
      });
      html += '</div></div>';
    }

    // Logon activity card (user / device)
    if (['user', 'device'].includes(e.type)) {
      var logonSec = (e.sections && (e.sections.logonActivity || e.sections.loginStatistics)) || null;
      var logonItems = logonSec ? (logonSec.timeline || logonSec.kv || []) : [];
      if (logonItems.length) {
        html += '<div class="zhp-card zhp-card-logon">';
        html += '<div class="zhp-card-ttl">🔐 Recent Logon Activity</div>';
        html += '<div class="zhp-card-list">';
        logonItems.slice(0, 4).forEach(function (item) {
          var label = item.event || item.label || item.key || '';
          var time = item.time || item.value || '';
          var isFail = item.malicious || /fail/i.test(String(label));
          var dot = isFail ? 'zhp-dot-red' : 'zhp-dot-blue';
          html += '<div class="zhp-list-row"><span class="zhp-list-dot ' + dot + '"></span>' +
            '<span class="zhp-list-label">' + _escHtml(String(label)) + '</span>' +
            '<span class="zhp-list-val">' + _escHtml(String(time)) + '</span></div>';
        });
        html += '</div></div>';
      }
    }

    // Network activity card (ip / device)
    if (['ip', 'device'].includes(e.type)) {
      var netSec = e.sections && e.sections.networkActivity;
      var netItems = netSec ? (netSec.kv || netSec.timeline || []) : [];
      if (netItems.length) {
        html += '<div class="zhp-card zhp-card-net">';
        html += '<div class="zhp-card-ttl">🌐 Network Activity</div>';
        html += '<div class="zhp-card-list">';
        netItems.slice(0, 3).forEach(function (item) {
          var label = item.label || item.key || '';
          var val = item.value || '';
          html += '<div class="zhp-list-row"><span class="zhp-list-dot zhp-dot-orange"></span>' +
            '<span class="zhp-list-label">' + _escHtml(String(label)) + '</span>' +
            '<span class="zhp-list-val">' + _escHtml(String(val)) + '</span></div>';
        });
        html += '</div></div>';
      }
    }

    // Audit log card (service)
    if (e.type === 'service') {
      var auditSec = e.sections && e.sections.auditLogs;
      var auditItems = auditSec ? (auditSec.kv || auditSec.timeline || []) : [];
      if (auditItems.length) {
        html += '<div class="zhp-card zhp-card-audit">';
        html += '<div class="zhp-card-ttl">📋 Audit Log Summary</div>';
        html += '<div class="zhp-card-list">';
        auditItems.slice(0, 3).forEach(function (item) {
          var label = item.label || item.key || '';
          var val = item.value || item.time || '';
          html += '<div class="zhp-list-row"><span class="zhp-list-dot zhp-dot-blue"></span>' +
            '<span class="zhp-list-label">' + _escHtml(String(label)) + '</span>' +
            '<span class="zhp-list-val">' + _escHtml(String(val)) + '</span></div>';
        });
        html += '</div></div>';
      }
    }

    return html;
  }

  // ── Suggestion Chips ───────────────────────────────────────────────
  var SUGGESTIONS = {
    user: [
      { icon: '🔐', text: 'Show failed login attempts' },
      { icon: '📊', text: 'UEBA risk profile' },
      { icon: '📁', text: 'What files were accessed?' },
      { icon: '🚨', text: 'List triggered alerts' },
      { icon: '🌐', text: 'Network connections' }
    ],
    device: [
      { icon: '🔍', text: 'Show vulnerabilities' },
      { icon: '🌐', text: 'Recent network connections' },
      { icon: '🚨', text: 'List triggered alerts' },
      { icon: '⚙', text: 'Check misconfigurations' }
    ],
    ip: [
      { icon: '🛡', text: 'Is this IP malicious?' },
      { icon: '🌐', text: 'Show connection history' },
      { icon: '🚨', text: 'List triggered alerts' }
    ],
    service: [
      { icon: '📋', text: 'Show audit logs' },
      { icon: '💥', text: 'Show blast radius' },
      { icon: '🚨', text: 'List triggered alerts' }
    ],
    process: [
      { icon: '💥', text: 'Show blast radius' },
      { icon: '🚨', text: 'List triggered alerts' },
      { icon: '🔍', text: 'Is this process malicious?' }
    ]
  };

  function _renderSuggestions(type) {
    var el = document.getElementById('zhpSuggestions');
    if (!el) return;
    var items = SUGGESTIONS[type] || [
      { icon: '🔍', text: 'Search in logs' },
      { icon: '🚨', text: 'List triggered alerts' }
    ];
    el.innerHTML = items.map(function (s) {
      return '<button class="zhp-chip" onclick="zhpSend(\'' + _esc(s.text) + '\')">' + s.icon + ' ' + s.text + '</button>';
    }).join('');
  }

  // ── Send / Receive ─────────────────────────────────────────────────
  window.zhpSend = function (text) {
    var input = document.getElementById('zhpInput');
    var q = text || (input ? input.value.trim() : '');
    if (!q || _typing) return;
    if (input) input.value = '';
    _addUserMessage(q);
    _respond(q);
  };

  function _respond(q) {
    if (!_huntEntityId) return;
    var _ent = (typeof ENTITIES !== 'undefined' ? ENTITIES : null) || window.ENTITIES || {};
    var e = _ent[_huntEntityId];
    if (!e) return;

    _typing = true;
    var typingId = 'zhp-typing-' + Date.now();
    _addBotTyping(typingId);

    setTimeout(function () {
      var typingEl = document.getElementById(typingId);
      if (typingEl) typingEl.remove();
      _typing = false;

      var ql = q.toLowerCase();
      var response = null;

      if (/fail|wrong.pass|bad.login|invalid.cred/.test(ql)) {
        response = _rFailedLogin(e);
      } else if (/logon|login|sign.in|auth/.test(ql)) {
        response = _rLogon(e);
      } else if (/alert|alarm|trigger/.test(ql)) {
        response = _rAlerts(e);
      } else if (/ueba|anomal|risk|behavior|unusual/.test(ql)) {
        response = _rUeba(e);
      } else if (/file|access|sharepoint|document|download/.test(ql)) {
        response = _rFileAccess(e);
      } else if (/network|connect|traffic|ip.addr|port/.test(ql)) {
        response = _rNetwork(e);
      } else if (/vulner|cve|patch|exploit/.test(ql)) {
        response = _rVulnerabilities(e);
      } else if (/blast|impact|spread|lateral|reach/.test(ql)) {
        response = _rBlastRadius(e);
      } else if (/malicious|threat|bad.actor|reputation|intel/.test(ql)) {
        response = _rThreatIntel(e);
      } else if (/misconfig|setting|config/.test(ql)) {
        response = _rMisconfig(e);
      } else if (/audit|log.event/.test(ql)) {
        response = _rAuditLogs(e);
      } else {
        response = _rFallback(e, q);
      }

      if (response) {
        _addBotMessage(response.text, response.card || '');
        if (response.action) {
          try { response.action(); } catch (_) {}
        }
      }
      _scrollBottom();
    }, 700 + Math.random() * 500);
  }

  // ── Response Builders ──────────────────────────────────────────────
  function _rLogon(e) {
    var sec = (e.sections && (e.sections.logonActivity || e.sections.loginStatistics)) || null;
    var items = sec ? (sec.timeline || sec.kv || []) : [];
    if (!items.length) return { text: 'No logon activity data is available for this entity in the current window.' };
    var card = _listCard('🔐 Logon Activity', items, function (i) {
      var label = i.event || i.label || i.key || '';
      var time = i.time || i.value || '';
      var isFail = i.malicious || /fail/i.test(String(label));
      return { dot: isFail ? 'red' : 'blue', label: String(label), val: String(time) };
    });
    return { text: 'Found <strong>' + items.length + ' logon event' + (items.length !== 1 ? 's' : '') + '</strong> for this entity.', card: card };
  }

  function _rFailedLogin(e) {
    var sec = e.sections && e.sections.logonActivity;
    var all = (sec && sec.timeline) || [];
    var fails = all.filter(function (i) { return i.malicious || /fail/i.test(String(i.event || i.label || '')); });
    var rs = e.sections && e.sections.riskSummary && e.sections.riskSummary.summaryCard;
    var metricFail = rs && rs.metrics && rs.metrics.find(function (m) { return /failed/i.test(m.label || ''); });
    var count = fails.length || (metricFail && metricFail.value) || '—';
    var displayItems = fails.length ? fails : [{ event: 'Failed login events detected', value: String(count) }];
    var card = _listCard('⚠ Failed Login Attempts', displayItems, function (i) {
      return { dot: 'red', label: String(i.event || i.label || 'Failed Login'), val: String(i.time || i.value || '') };
    });
    return { text: 'Detected <strong>' + count + ' failed login attempt' + (count !== 1 ? 's' : '') + '</strong> in the investigation window.', card: card };
  }

  function _rAlerts(e) {
    var sec = e.sections && e.sections.recentAlerts;
    var items = sec ? (sec.kv || sec.timeline || []) : [];
    if (!items.length) return { text: 'No triggered alerts found for this entity in the current period.' };
    var card = _listCard('🚨 Triggered Alerts', items, function (i) {
      return { dot: 'red', label: String(i.label || i.key || i.event || i.name || ''), val: String(i.value || i.time || i.severity || '') };
    });
    return { text: '<strong>' + items.length + ' alert' + (items.length !== 1 ? 's' : '') + '</strong> have been triggered by this entity.', card: card };
  }

  function _rUeba(e) {
    var rs = e.sections && e.sections.riskSummary && e.sections.riskSummary.summaryCard;
    if (!rs) return { text: 'No UEBA profile data available for this entity.' };
    var html = '<div class="zhp-card zhp-card-risk"><div class="zhp-card-ttl">📊 UEBA Risk Profile</div><div class="zhp-card-kv">';
    var score = rs.riskScore !== undefined ? rs.riskScore : rs.score;
    if (score !== undefined) html += '<span class="zhp-kv-k">Risk Score</span><span class="zhp-kv-v zhp-risk-score" data-score="' + score + '">' + score + ' / ' + (rs.maxScore || 100) + '</span>';
    if (rs.severity) html += '<span class="zhp-kv-k">Severity</span><span class="zhp-kv-v">' + _escHtml(rs.severity) + '</span>';
    if (rs.heroChips) rs.heroChips.forEach(function (c) {
      html += '<span class="zhp-kv-k">' + _escHtml(c.label) + '</span><span class="zhp-kv-v">' + _escHtml(String(c.value)) + '</span>';
    });
    html += '</div></div>';
    var sev = rs.severity || 'Unknown';
    var tail = sev === 'High' ? 'significant anomalous behavior detected.' : sev === 'Medium' ? 'some elevated activity worth monitoring.' : 'behaviour within normal thresholds.';
    return { text: 'Risk score: <strong>' + score + '</strong> (' + sev + '). ' + tail, card: html };
  }

  function _rNetwork(e) {
    var sec = e.sections && e.sections.networkActivity;
    var items = sec ? (sec.kv || sec.timeline || []) : [];
    if (!items.length) return { text: 'No network activity data found for this entity.' };
    var card = _listCard('🌐 Network Activity', items, function (i) {
      return { dot: i.malicious ? 'red' : 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
    });
    return { text: 'Found <strong>' + items.length + ' network connection' + (items.length !== 1 ? 's' : '') + '</strong> associated with this entity.', card: card };
  }

  function _rVulnerabilities(e) {
    var sec = e.sections && e.sections.vulnerabilities;
    var items = sec ? (sec.kv || sec.timeline || []) : [];
    if (!items.length) return { text: 'No vulnerability data available for this entity.' };
    var card = _listCard('🔍 Vulnerability Scan', items, function (i) {
      var isCrit = /critical|high/i.test(String(i.value || ''));
      return { dot: isCrit ? 'red' : 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
    });
    return { text: 'Found <strong>' + items.length + ' vulnerabilit' + (items.length !== 1 ? 'ies' : 'y') + '</strong> on this entity.', card: card };
  }

  function _rBlastRadius(e) {
    var br = e.sections && e.sections.blastRadius && e.sections.blastRadius.blastRadius;
    var count = br && br.reachNodes ? br.reachNodes.length : 0;
    return {
      text: 'This entity can reach <strong>' + count + ' other node' + (count !== 1 ? 's' : '') + '</strong>. Opening blast radius graph…',
      card: '',
      action: function () {
        if (typeof ctxBlastRadiusGraph === 'function') {
          window.ctxEntityId = _huntEntityId;
          ctxBlastRadiusGraph();
        }
      }
    };
  }

  function _rThreatIntel(e) {
    var isMal = e.type === 'ip' && (
      /tor|c2|malicious/i.test(e.modalTitle || '') ||
      ((e.sections && e.sections.riskSummary && e.sections.riskSummary.summaryCard || {}).severity === 'High')
    );
    var html = '<div class="zhp-card zhp-card-risk"><div class="zhp-card-ttl">🛡 Threat Intelligence</div><div class="zhp-card-kv">';
    if (e.type === 'ip') {
      html += '<span class="zhp-kv-k">IP Reputation</span><span class="zhp-kv-v" style="color:' + (isMal ? '#dc2626' : '#16a34a') + '">' + (isMal ? '⚠ Malicious' : '✓ Clean') + '</span>';
      html += '<span class="zhp-kv-k">Feed Match</span><span class="zhp-kv-v">' + (isMal ? 'Tor Exit Node / C2' : 'No match') + '</span>';
      html += '<span class="zhp-kv-k">Source</span><span class="zhp-kv-v">STIX/TAXII Feed</span>';
    } else {
      html += '<span class="zhp-kv-k">Threat Feed</span><span class="zhp-kv-v">No known IOC match</span>';
    }
    html += '</div></div>';
    return {
      text: isMal
        ? 'This IP is <strong>flagged as malicious</strong> in the Log360 threat intelligence feeds (Tor exit node / C2 server).'
        : 'No matches found in configured threat intelligence feeds for this entity.',
      card: html
    };
  }

  function _rFileAccess(e) {
    var sec = e.sections && (e.sections.recentFileAccess || e.sections.fileActivity);
    var items = sec ? (sec.kv || sec.timeline || []) : [];
    if (!items.length) return { text: 'No file access records found for this entity in the current investigation window.' };
    var card = _listCard('📁 File Access', items, function (i) {
      return { dot: 'blue', label: String(i.label || i.key || ''), val: String(i.value || i.time || '') };
    });
    return { text: 'Found <strong>' + items.length + ' file access event' + (items.length !== 1 ? 's' : '') + '</strong>.', card: card };
  }

  function _rMisconfig(e) {
    var sec = e.sections && (e.sections.misconfigurations || e.sections.configIssues);
    var items = sec ? (sec.kv || sec.timeline || []) : [];
    if (!items.length) return { text: 'No misconfiguration data found for this entity.' };
    var card = _listCard('⚙ Misconfigurations', items, function (i) {
      return { dot: 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
    });
    return { text: 'Found <strong>' + items.length + ' misconfiguration' + (items.length !== 1 ? 's' : '') + '</strong>.', card: card };
  }

  function _rAuditLogs(e) {
    var sec = e.sections && e.sections.auditLogs;
    var items = sec ? (sec.kv || sec.timeline || []) : [];
    if (!items.length) return { text: 'No audit log data available for this entity.' };
    var card = _listCard('📋 Audit Logs', items, function (i) {
      return { dot: 'blue', label: String(i.label || i.key || ''), val: String(i.value || i.time || '') };
    });
    return { text: 'Found <strong>' + items.length + ' audit log event' + (items.length !== 1 ? 's' : '') + '</strong>.', card: card };
  }

  function _rFallback(e, q) {
    var shortName = (e.modalTitle || '').split('·').pop().trim() || _huntEntityId;
    return {
      text: 'I searched for "<strong>' + _escHtml(q) + '</strong>" in ' + _escHtml(shortName) + '\'s data. ' +
        'Try one of the suggested questions for a structured view, or open Entity Details for the full profile.',
      card: ''
    };
  }

  // ── Card builder helper ────────────────────────────────────────────
  function _listCard(title, items, rowFn) {
    var html = '<div class="zhp-card"><div class="zhp-card-ttl">' + title + '</div><div class="zhp-card-list">';
    items.forEach(function (item) {
      var r = rowFn(item);
      html += '<div class="zhp-list-row">' +
        '<span class="zhp-list-dot zhp-dot-' + r.dot + '"></span>' +
        '<span class="zhp-list-label">' + _escHtml(r.label) + '</span>' +
        '<span class="zhp-list-val">' + _escHtml(r.val) + '</span>' +
        '</div>';
    });
    html += '</div></div>';
    return html;
  }

  // ── Chat DOM helpers ───────────────────────────────────────────────
  function _addBotMessage(text, cardHtml) {
    var chat = document.getElementById('zhpChat');
    if (!chat) return;
    var row = document.createElement('div');
    row.className = 'zhp-msg zhp-msg-bot';
    row.innerHTML = '<span class="zhp-msg-avatar">✦</span>' +
      '<div class="zhp-msg-bubble">' +
        '<p class="zhp-msg-text">' + text + '</p>' +
        (cardHtml ? '<div class="zhp-msg-card">' + cardHtml + '</div>' : '') +
      '</div>';
    chat.appendChild(row);
    // Apply risk-score colours after DOM insert
    row.querySelectorAll('.zhp-risk-score[data-score]').forEach(function (el) {
      var s = parseInt(el.getAttribute('data-score'), 10);
      el.style.color = s >= 70 ? '#dc2626' : s >= 40 ? '#ea580c' : '#16a34a';
      el.style.fontWeight = '700';
    });
    _scrollBottom();
  }

  function _addUserMessage(text) {
    var chat = document.getElementById('zhpChat');
    if (!chat) return;
    var row = document.createElement('div');
    row.className = 'zhp-msg zhp-msg-user';
    row.innerHTML = '<div class="zhp-msg-bubble"><p class="zhp-msg-text">' + _escHtml(text) + '</p></div>';
    chat.appendChild(row);
    _scrollBottom();
  }

  function _addBotTyping(id) {
    var chat = document.getElementById('zhpChat');
    if (!chat) return;
    var row = document.createElement('div');
    row.id = id;
    row.className = 'zhp-msg zhp-msg-bot';
    row.innerHTML = '<span class="zhp-msg-avatar">✦</span>' +
      '<div class="zhp-msg-bubble zhp-typing"><span></span><span></span><span></span></div>';
    chat.appendChild(row);
    _scrollBottom();
  }

  function _scrollBottom() {
    var chat = document.getElementById('zhpChat');
    if (chat) chat.scrollTop = chat.scrollHeight;
  }

  // ── String utils ───────────────────────────────────────────────────
  function _esc(s) { return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'"); }
  function _escHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

})();
