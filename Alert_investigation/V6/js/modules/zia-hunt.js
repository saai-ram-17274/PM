/* zia-hunt.js — Ask Zia Guided Investigation / Go Hunt chat panel
 * Depends on: entities.js, data.js (ALERT_DETAIL), graph.js (panel mount)
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

  // ── Entity lookup helper ───────────────────────────────────────────
  function _getEnt() {
    return (typeof ENTITIES !== 'undefined' ? ENTITIES : null) || window.ENTITIES || {};
  }

  // ── Open / Close ───────────────────────────────────────────────────
  window.openZiaHuntPanel = function (entityId) {
    if (!entityId) return;
    var e = _getEnt()[entityId];
    if (!e) return;

    _huntEntityId = entityId;

    if (typeof closeEntitySlider === 'function') closeEntitySlider();

    var panel = document.getElementById('ziaHuntPanel');
    if (!panel) return;

    var nameEl = document.getElementById('zhpEntityName');
    if (nameEl) {
      var TYPE_ICONS = { user:'👤', device:'💻', ip:'🌐', service:'⚙', process:'🔧', alert:'🔔' };
      var shortName = (e.modalTitle || '').split('·').pop().trim() || entityId;
      nameEl.textContent = (TYPE_ICONS[e.type] || '◇') + ' ' + shortName;
    }

    var chat = document.getElementById('zhpChat');
    if (chat) chat.innerHTML = '';
    _typing = false;

    _renderInitialPreview(entityId, e);
    _renderSuggestions(entityId, e);

    document.getElementById('graphContainer').classList.add('zia-hunt-open');
    panel.classList.add('open');

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

    // 1 — Zia alert-level analysis bridge (if AI investigation has run)
    _renderZiaAlertBridge(e);

    // 2 — entity data preview cards
    var cards = _buildPreviewCards(entityId, e);
    _addBotMessage(
      'Here\'s a quick overview of <strong>' + _escHtml(shortName) + '</strong>. ' +
      'Tap a suggestion below or ask me anything.',
      cards
    );
  }

  /* Pull investSummary + keyFindings from the active ALERT_DETAIL when
     the analyst has already run "Start Investigation" on the alert. */
  function _renderZiaAlertBridge(e) {
    var aid = (typeof currentAlertId !== 'undefined') ? currentAlertId : null;
    if (!aid) return;
    var det = ((typeof ALERT_DETAIL !== 'undefined') ? ALERT_DETAIL : (window.ALERT_DETAIL || {}))[aid];
    if (!det || !det.aiInvestigatedRuntime) return;

    var html = '<div class="zhp-card zhp-card-zia-bridge">';
    html += '<div class="zhp-card-ttl">✦ Zia Alert Analysis</div>';
    if (det.investSummary) {
      html += '<p class="zhp-bridge-summary">' + _escHtml(det.investSummary) + '</p>';
    }
    if (det.keyFindings && det.keyFindings.length) {
      html += '<div class="zhp-card-list">';
      det.keyFindings.slice(0, 3).forEach(function (k) {
        html += '<div class="zhp-list-row"><span class="zhp-list-dot zhp-dot-red"></span>' +
          '<span class="zhp-list-label">' + _escHtml(k.title || '') + '</span>' +
          '<span class="zhp-list-val"></span></div>';
      });
      html += '</div>';
    }
    html += '</div>';

    _addBotMessage('Alert-level Zia analysis is available for this investigation.', html);
  }

  // ── Preview Cards (auto-rendered on panel open) ────────────────────
  function _buildPreviewCards(entityId, e) {
    var s = e.sections || {};
    var html = '';

    /* ── ALERT entity ── */
    if (e.type === 'alert') {
      var ad = s.alertDetails;
      if (ad && ad.kv && ad.kv.length) {
        html += '<div class="zhp-card zhp-card-risk"><div class="zhp-card-ttl">🔔 Alert Details</div><div class="zhp-card-kv">';
        ad.kv.slice(0, 6).forEach(function (item) {
          html += '<span class="zhp-kv-k">' + _escHtml(item.label || item.key || '') + '</span>' +
                  '<span class="zhp-kv-v">' + _escHtml(String(item.value || '')) + '</span>';
        });
        html += '</div></div>';
      }
      var tc = s.triggerConditions;
      if (tc) {
        var tcItems = tc.kv || tc.items || [];
        if (tcItems.length) html += _listCardHtml('⚡ Trigger Conditions', tcItems.slice(0, 4), function (i) {
          return { dot: 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
        });
      }
      var ae = s.affectedEntities;
      if (ae) {
        var aeItems = ae.kv || ae.items || ae.list || [];
        if (aeItems.length) html += _listCardHtml('🎯 Affected Entities', aeItems.slice(0, 4), function (i) {
          return { dot: 'red', label: String(i.label || i.key || i.name || ''), val: String(i.value || i.type || '') };
        });
      }
      return html;
    }

    /* ── Risk Summary (all non-alert types) ── */
    var rs = s.riskSummary && s.riskSummary.summaryCard;
    if (rs) {
      html += '<div class="zhp-card zhp-card-risk"><div class="zhp-card-ttl">🛡 Risk Summary</div><div class="zhp-card-kv">';
      var score = rs.riskScore !== undefined ? rs.riskScore : rs.score;
      if (score !== undefined) {
        html += '<span class="zhp-kv-k">Risk Score</span>' +
          '<span class="zhp-kv-v zhp-risk-score" data-score="' + score + '">' + score + ' / ' + (rs.maxScore || 100) + '</span>';
      }
      if (rs.severity)    html += '<span class="zhp-kv-k">Severity</span><span class="zhp-kv-v">'    + _escHtml(rs.severity)    + '</span>';
      if (rs.statusBadge) html += '<span class="zhp-kv-k">Status</span><span class="zhp-kv-v">'      + _escHtml(rs.statusBadge) + '</span>';
      if (rs.heroChips) {
        rs.heroChips.slice(0, 3).forEach(function (c) {
          html += '<span class="zhp-kv-k">' + _escHtml(c.label) + '</span><span class="zhp-kv-v">' + _escHtml(String(c.value)) + '</span>';
        });
      } else if (rs.metrics) {
        rs.metrics.slice(0, 3).forEach(function (m) {
          html += '<span class="zhp-kv-k">' + _escHtml(m.label) + '</span><span class="zhp-kv-v">' + _escHtml(String(m.value)) + '</span>';
        });
      }
      html += '</div></div>';
    }

    /* ── USER — critical flags in preview ── */
    if (e.type === 'user') {
      var mfItems = _secItems(s.mailboxForwarding, ['kv', 'rules', 'items']);
      if (mfItems.length) {
        html += '<div class="zhp-card zhp-card-warn"><div class="zhp-card-ttl" style="color:#dc2626">⚠ Mailbox Forwarding Active</div>';
        html += _listBody(mfItems.slice(0, 3), function (i) {
          return { dot: 'red', label: String(i.label || i.key || ''), val: String(i.value || '') };
        }) + '</div>';
      }
      var dwItems = _secItems(s.darkWebExposure, ['kv', 'items']);
      if (dwItems.length) {
        html += '<div class="zhp-card zhp-card-warn"><div class="zhp-card-ttl" style="color:#9333ea">🌑 Dark Web Exposure</div>';
        html += _listBody(dwItems.slice(0, 3), function (i) {
          return { dot: 'red', label: String(i.label || i.key || ''), val: String(i.value || '') };
        }) + '</div>';
      }
    }

    /* ── Recent Alerts ── */
    var alertItems = _secItems(s.recentAlerts, ['kv', 'timeline']);
    if (alertItems.length) html += _listCardHtml('🚨 Recent Alerts', alertItems.slice(0, 3), function (i) {
      return { dot: 'red', label: String(i.label || i.key || i.event || i.name || ''), val: String(i.value || i.time || i.severity || '') };
    });

    /* ── Logon Activity (user / device) ── */
    if (e.type === 'user' || e.type === 'device') {
      var logonItems = _secItems(s.logonActivity || s.loginStatistics || s.loginActivity, ['timeline', 'kv']);
      if (logonItems.length) html += _listCardHtml('🔐 Recent Logon Activity', logonItems.slice(0, 4), function (i) {
        var label = i.event || i.label || i.key || '';
        var isFail = i.malicious || /fail/i.test(String(label));
        return { dot: isFail ? 'red' : 'blue', label: String(label), val: String(i.time || i.value || '') };
      });
    }

    /* ── Network / Connection (ip / device) ── */
    if (e.type === 'ip' || e.type === 'device') {
      var netItems = _secItems(s.networkActivity || s.connectionHistory || s.trafficSummary, ['kv', 'timeline', 'items']);
      if (netItems.length) html += _listCardHtml('🌐 Network Activity', netItems.slice(0, 3), function (i) {
        return { dot: i.malicious ? 'red' : 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
      });
      if (e.type === 'ip' && s.geoContext) {
        var gcItems = _secItems(s.geoContext, ['kv', 'items']);
        if (gcItems.length) {
          html += '<div class="zhp-card"><div class="zhp-card-ttl">🗺 Geo Context</div><div class="zhp-card-kv">';
          gcItems.slice(0, 4).forEach(function (i) {
            html += '<span class="zhp-kv-k">' + _escHtml(String(i.label || i.key || '')) + '</span>' +
                    '<span class="zhp-kv-v">' + _escHtml(String(i.value || '')) + '</span>';
          });
          html += '</div></div>';
        }
      }
    }

    /* ── Device — security event summary ── */
    if (e.type === 'device') {
      var sesItems = _secItems(s.securityEventSummary, ['kv', 'items']);
      if (sesItems.length) {
        html += '<div class="zhp-card"><div class="zhp-card-ttl">🖥 Security Event Summary</div><div class="zhp-card-kv">';
        sesItems.slice(0, 6).forEach(function (i) {
          html += '<span class="zhp-kv-k">' + _escHtml(String(i.label || i.key || '')) + '</span>' +
                  '<span class="zhp-kv-v">' + _escHtml(String(i.value || '')) + '</span>';
        });
        html += '</div></div>';
      }
    }

    /* ── Process — process tree ── */
    if (e.type === 'process') {
      var ptItems = _secItems(s.processTree || s.processDetails, ['kv', 'items', 'tree']);
      if (ptItems.length) html += _listCardHtml('🌲 Process Tree', ptItems.slice(0, 5), function (i) {
        return { dot: i.malicious ? 'red' : 'blue', label: String(i.label || i.name || i.key || ''), val: String(i.value || i.pid || '') };
      });
    }

    /* ── Service — audit / sign-in ── */
    if (e.type === 'service') {
      var auditItems = _secItems(s.auditLogs || s.signInAudit || s.adminActivity, ['kv', 'timeline']);
      if (auditItems.length) html += _listCardHtml('📋 Audit Log Summary', auditItems.slice(0, 3), function (i) {
        return { dot: 'blue', label: String(i.label || i.key || ''), val: String(i.value || i.time || '') };
      });
    }

    return html;
  }

  /* Helper — extract items from the first matching key in a section obj */
  function _secItems(sec, keys) {
    if (!sec) return [];
    for (var k = 0; k < keys.length; k++) {
      var arr = sec[keys[k]];
      if (arr && arr.length) return arr;
    }
    return [];
  }

  // ── Suggestion Chips — blast-radius-centric, data-driven ──────────
  /*
   * SOC blast-radius philosophy:
   *   1. Scope      — what can this entity reach / access?
   *   2. Propagation — what lateral-movement paths exist?
   *   3. Persistence — how can an attacker maintain a foothold?
   *   4. Exfil risk  — what data is in danger?
   *   5. Containment — what needs to be isolated?
   *
   * Chips are built dynamically: a chip only appears when the entity
   * actually has data backing it, keeping the panel signal-not-noise.
   * All entity types always get a blast-radius chip + remediation chip.
   */
  function _buildBlastRadiusSuggestions(entityId, e) {
    var s = e.sections || {};
    var chips = [];

    switch (e.type) {

      // ── USER — blast = every system they can authenticate to / access ─
      case 'user':
        // Scope: what privileged resources does their credential unlock?
        if (_secItems(s.privilegedSurface || s.effectiveGroups, ['kv','items']).length)
          chips.push({ icon: '🔑', text: 'What privileged resources can they reach?' });
        // Entry-point risk: credential already compromised?
        if (_secItems(s.darkWebExposure, ['kv','items']).length)
          chips.push({ icon: '🌑', text: 'Are credentials exposed on dark web?' });
        // Exfil vector: is mail silently leaving the org?
        if (_secItems(s.mailboxForwarding, ['kv','rules','items']).length)
          chips.push({ icon: '📨', text: 'Is mailbox forwarding active?' });
        // Propagation: group memberships amplify access
        if (_secItems(s.groupMembershipChanges, ['kv','items','timeline']).length)
          chips.push({ icon: '👥', text: 'What groups propagate their access?' });
        // Lateral reach: which devices carry their session token?
        chips.push({ icon: '💻', text: 'Which devices has this user accessed?' });
        chips.push({ icon: '🚨', text: 'List triggered alerts' });
        break;

      // ── DEVICE — blast = network neighbours + processes that can spread
      case 'device':
        // Propagation: suspicious processes = potential lateral movers
        if (_secItems(s.processesOnHost || s.processes, ['kv','items','list']).length)
          chips.push({ icon: '⚙', text: 'What processes could spread laterally?' });
        // Persistence: scheduled tasks = attacker footholds
        if (_secItems(s.scheduledTasks, ['kv','items','tasks']).length)
          chips.push({ icon: '📅', text: 'Any persistence mechanisms? (scheduled tasks)' });
        // Exfil: USB as data-out channel
        if (_secItems(s.usbDeviceEvents, ['kv','items','timeline']).length)
          chips.push({ icon: '💾', text: 'USB-based data exfiltration risk?' });
        // Scope: which network neighbours are already in the blast zone?
        chips.push({ icon: '🌐', text: 'What network neighbours are at risk?' });
        // Entry point: unpatched CVEs = how attacker got in
        if (_secItems(s.vulnerabilities, ['kv','timeline']).length)
          chips.push({ icon: '🔍', text: 'Active exploitable vulnerabilities?' });
        chips.push({ icon: '🚨', text: 'List triggered alerts' });
        break;

      // ── IP — blast = all internal hosts communicating with this IP ───
      case 'ip':
        // Scope: which hosts are already in the blast zone?
        if (_secItems(s.associatedUsers, ['kv','items']).length ||
            _secItems(s.associatedDevices, ['kv','items']).length)
          chips.push({ icon: '🖥', text: 'Which internal hosts are communicating here?' });
        // Lateral movement: IDS/IPS caught anything mid-path?
        if (_secItems(s.idsAlerts, ['kv','items','alerts']).length)
          chips.push({ icon: '🚦', text: 'Any lateral movement detected? (IDS/IPS)' });
        // Containment scope: firewall allow/block posture
        if (_secItems(s.firewallSummary, ['kv','items']).length)
          chips.push({ icon: '🔥', text: "What's the firewall exposure?" });
        // C2 channel: DNS tunnelling / beaconing?
        if (_secItems(s.dnsHistory, ['kv','items','queries']).length)
          chips.push({ icon: '🔎', text: 'DNS-based C2 activity?' });
        // Reputation: is this in threat intel feeds?
        chips.push({ icon: '🛡', text: 'Is this IP in threat intelligence feeds?' });
        chips.push({ icon: '🚨', text: 'List triggered alerts' });
        break;

      // ── SERVICE — blast = all data accessible via OAuth / admin scope
      case 'service':
        // Scope: OAuth permissions define the data blast radius
        if (_secItems(s.oauthConsentGrants || s.conditionalAccess, ['kv','items','grants']).length)
          chips.push({ icon: '🔐', text: 'What data can be reached via OAuth?' });
        // Propagation: admin actions already performed in blast zone
        if (_secItems(s.adminActivity, ['kv','timeline']).length)
          chips.push({ icon: '⚙', text: 'What admin actions were performed?' });
        // Scope: who authenticates here = users in blast zone
        if (_secItems(s.signInAudit, ['kv','timeline']).length)
          chips.push({ icon: '👤', text: 'What users/devices authenticate here?' });
        // Containment: full audit trail
        chips.push({ icon: '📋', text: 'Show full audit trail' });
        chips.push({ icon: '🚨', text: 'List triggered alerts' });
        break;

      // ── PROCESS — blast = spawned children + files/registry touched ─
      case 'process':
        // Propagation: what did this process spawn?
        if (_secItems(s.processTree || s.childProcesses, ['kv','items','tree','children']).length)
          chips.push({ icon: '🌲', text: 'What did this process spawn?' });
        // Exfil/staging: files touched
        if (_secItems(s.fileOperations, ['kv','items']).length)
          chips.push({ icon: '📂', text: 'What files were touched? (data staging)' });
        // Persistence: registry run keys / startup entries
        if (_secItems(s.registryModifications, ['kv','items']).length)
          chips.push({ icon: '📝', text: 'Persistence via registry modifications?' });
        // Detection: did AV/AMSI catch anything?
        if (_secItems(s.amsiEvents, ['kv','items','detections']).length)
          chips.push({ icon: '🛡', text: 'Any AV/AMSI detections?' });
        // C2 channel: outbound network connections
        chips.push({ icon: '🌐', text: 'Network connections (C2 beaconing)?' });
        break;

      // ── ALERT — blast = all entities in scope + campaign correlation ─
      case 'alert':
        // Scope: how many entities are inside the blast zone?
        chips.push({ icon: '🎯', text: 'What entities are at immediate risk?' });
        // Campaign scope: are these part of a broader attack?
        chips.push({ icon: '🔗', text: 'Are there related alerts in this campaign?' });
        // Root cause
        chips.push({ icon: '⚡', text: 'Why did this alert fire?' });
        // Summary
        chips.push({ icon: '📝', text: 'Summarize this incident' });
        break;

      default:
        chips.push({ icon: '🔐', text: 'Show logon activity' });
        chips.push({ icon: '🌐', text: 'Show network connections' });
        chips.push({ icon: '🚨', text: 'List triggered alerts' });
    }

    // Always last: remediation = containment playbook
    chips.push({ icon: '🛠', text: 'What should I do?' });

    return chips.slice(0, 8); // max 8 to avoid chip overflow
  }

  function _renderSuggestions(entityId, e) {
    var el = document.getElementById('zhpSuggestions');
    if (!el) return;
    var items = _buildBlastRadiusSuggestions(entityId, e);
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
    var e = _getEnt()[_huntEntityId];
    if (!e) return;

    _typing = true;
    var typingId = 'zhp-typing-' + Date.now();
    _addBotTyping(typingId);

    setTimeout(function () {
      var typingEl = document.getElementById(typingId);
      if (typingEl) typingEl.remove();
      _typing = false;

      var ql = q.toLowerCase();
      var r = null;

      // ── Remediation (highest priority) ──
      if (/what.should|remediat|fix|action|next.step|how.to.respond|contain|what.do.i/.test(ql)) {
        r = _rRemediation(e);

      // ── Alert-specific ──
      } else if (/why.did|trigger|rule.fire|condition|what.caused/.test(ql)) {
        r = _rTriggerConditions(e);
      } else if (/affect|impacted.entit|which.entit|entit.*risk|immediate.risk|entit.*at.risk/.test(ql)) {
        r = _rAffectedEntities(e);
      } else if (/correlat|related.alert|same.incident|campaign/.test(ql)) {
        r = _rCorrelatedAlerts(e);
      } else if (/summari|incident.summary|overview|brief|tldr/.test(ql)) {
        r = _rIncidentSummary(e);

      // ── User-specific ──
      } else if (/mail.*forward|forward.*mail|inbox.rule/.test(ql)) {
        r = _rMailboxForwarding(e);
      } else if (/dark.web|credential.leak|paste|breach|credential.*expos/.test(ql)) {
        r = _rDarkWeb(e);
      } else if (/privileg|admin.role|role.access|elevated|resource.*reach|reach.*resource/.test(ql)) {
        r = _rPrivilegedAccess(e);
      } else if (/group.member|ad.group|membership.change|group.*propagat|propagat.*access/.test(ql)) {
        r = _rGroupChanges(e);
      } else if (/account.lock|lockout/.test(ql)) {
        r = _rAccountLockouts(e);
      // user devices — logon activity reveals device footprint
      } else if (/which.device|devices.*access|accessed.*device/.test(ql)) {
        r = _rLogon(e);

      // ── Device-specific ──
      } else if (/usb|removable|storage.device|exfil.*risk/.test(ql)) {
        r = _rUsbActivity(e);
      } else if (/process.*run|running.*process|what.process|spread.lateral|lateral.*process|processes.*spread/.test(ql)) {
        r = _rProcessesOnHost(e);
      } else if (/scheduled.task|task.sched|persistence.mech/.test(ql)) {
        r = _rScheduledTasks(e);
      // network neighbours (device context)
      } else if (/neighbour|neighbor/.test(ql)) {
        r = _rNetwork(e);

      // ── IP-specific ──
      } else if (/dns|lookup|resolv|c2.activ|dns.*c2/.test(ql)) {
        r = _rDnsHistory(e);
      } else if (/who.connect|connect.*to.this.ip|assoc.user|associated.device|internal.host|communicat.*here/.test(ql)) {
        r = _rAssociatedEntities(e);
      } else if (/ids|ips|intrusion|snort|suricata|lateral.*detect/.test(ql)) {
        r = _rIdsAlerts(e);
      } else if (/firewall|blocked.traffic|allowed.traffic|block.*allow|firewall.*expos/.test(ql)) {
        r = _rFirewallSummary(e);

      // ── Process-specific ──
      } else if (/process.tree|parent.process|child.process|spawn|what.did.*process/.test(ql)) {
        r = _rProcessTree(e);
      } else if (/registry|regedit|hklm|hkcu|persist.*registry/.test(ql)) {
        r = _rRegistryMods(e);
      } else if (/amsi|antivirus|av.detect|defender/.test(ql)) {
        r = _rAmsiEvents(e);
      } else if (/file.oper|file.creat|file.delet|file.writ|file.*touch|data.*stag/.test(ql)) {
        r = _rFileOperations(e);

      // ── Service ──
      } else if (/oauth|consent|grant|app.permission|data.*oauth|oauth.*reach/.test(ql)) {
        r = _rOauthGrants(e);
      // service: who authenticates here = audit/sign-in logs
      } else if (/admin.activ|admin.action|users.*authenticat|authenticat.*here/.test(ql)) {
        r = _rAuditLogs(e);

      // ── General ──
      } else if (/fail|wrong.pass|bad.login|invalid.cred/.test(ql)) {
        r = _rFailedLogin(e);
      } else if (/logon|login|sign.in|auth/.test(ql)) {
        r = _rLogon(e);
      } else if (/alert|alarm/.test(ql)) {
        r = _rAlerts(e);
      } else if (/ueba|anomal|risk|behavior|unusual/.test(ql)) {
        r = _rUeba(e);
      } else if (/file|access|sharepoint|document|download/.test(ql)) {
        r = _rFileAccess(e);
      } else if (/network|connect|traffic|ip.addr|port|beaconing/.test(ql)) {
        r = _rNetwork(e);
      } else if (/vulner|cve|patch|exploit/.test(ql)) {
        r = _rVulnerabilities(e);
      } else if (/blast|impact|spread|lateral|reach|reachable/.test(ql)) {
        r = _rBlastRadius(e);
      } else if (/malicious|threat|bad.actor|reputation|intel/.test(ql)) {
        r = _rThreatIntel(e);
      } else if (/misconfig|setting|config/.test(ql)) {
        r = _rMisconfig(e);
      } else if (/audit|log.event/.test(ql)) {
        r = _rAuditLogs(e);
      } else {
        r = _rFallback(e, q);
      }

      if (r) {
        _addBotMessage(r.text, r.card || '');
        if (r.action) { try { r.action(); } catch (_) {} }
      }
      _scrollBottom();
    }, 700 + Math.random() * 500);
  }

  // ══════════════════════════════════════════════════════════════════
  // ── Response Builders ─────────────────────────────────────────────
  // ══════════════════════════════════════════════════════════════════

  /* ── REMEDIATION — "What should I do?" ── */
  function _rRemediation(e) {
    var rg = e.sections && e.sections.remediationGuide;
    var steps = _secItems(rg, ['steps', 'items', 'kv']);
    var aid = (typeof currentAlertId !== 'undefined') ? currentAlertId : null;
    var det = aid && ((typeof ALERT_DETAIL !== 'undefined') ? ALERT_DETAIL : (window.ALERT_DETAIL || {}))[aid];
    var mitigSteps = (det && det.mitigationSteps) || [];
    var recCards   = (det && det.recommendations)  || [];

    if (!steps.length && !mitigSteps.length && !recCards.length) {
      return { text: 'No remediation guide available. Open the <strong>Investigation</strong> tab and click "Start Investigation" to generate AI-powered steps.' };
    }

    var html = '<div class="zhp-card zhp-card-remediation"><div class="zhp-card-ttl">🛠 Recommended Actions</div>';

    if (steps.length) {
      html += '<div class="zhp-card-list">';
      steps.forEach(function (item, idx) {
        var label = item.label || item.title || item.key || ('Step ' + (idx + 1));
        var val   = item.value || item.desc || '';
        html += '<div class="zhp-list-row"><span class="zhp-list-dot zhp-dot-green"></span>' +
          '<span class="zhp-list-label">' + _escHtml(String(label)) + '</span>' +
          '<span class="zhp-list-val">' + _escHtml(String(val)) + '</span></div>';
      });
      html += '</div>';
    }

    if (mitigSteps.length) {
      html += '<div class="zhp-bridge-mitig">';
      mitigSteps.slice(0, 4).forEach(function (t) {
        html += '<div class="zhp-bullet"><span class="zhp-bullet-icon">✨</span><div class="zhp-bullet-text">' + _escHtml(t) + '</div></div>';
      });
      html += '</div>';
    }

    recCards.slice(0, 2).forEach(function (r) {
      html += '<div class="zhp-rec-row"><span>' + _escHtml(r.icon || '⚡') + '</span>' +
        '<div class="zhp-rec-body"><strong>' + _escHtml(r.title || '') + '</strong>' +
        '<div class="zhp-rec-desc">' + _escHtml(r.desc || '') + '</div></div></div>';
    });

    html += '</div>';
    return { text: 'Here are the recommended remediation actions.', card: html };
  }

  /* ── ALERT — trigger conditions ── */
  function _rTriggerConditions(e) {
    var items = _secItems(e.sections && e.sections.triggerConditions, ['kv', 'items']);
    if (!items.length) return { text: 'No trigger condition data available for this entity.' };
    return { text: 'This alert fired based on the following conditions:',
      card: _listCard('⚡ Trigger Conditions', items, function (i) {
        return { dot: 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── ALERT — affected entities ── */
  function _rAffectedEntities(e) {
    var ae = e.sections && e.sections.affectedEntities;
    var items = _secItems(ae, ['kv', 'items', 'list']);
    if (!items.length) return { text: 'No affected entity data available for this alert.' };
    return {
      text: '<strong>' + items.length + ' entit' + (items.length !== 1 ? 'ies are' : 'y is') + '</strong> affected by this alert.',
      card: _listCard('🎯 Affected Entities', items, function (i) {
        return { dot: 'red', label: String(i.label || i.key || i.name || ''), val: String(i.value || i.type || '') };
      })
    };
  }

  /* ── ALERT — correlated alerts ── */
  function _rCorrelatedAlerts(e) {
    var s = e.sections || {};
    var items = _secItems(s.correlatedAlerts || s.recentAlerts, ['kv', 'items', 'timeline']);
    if (!items.length) return { text: 'No correlated alerts found for this entity.' };
    return {
      text: 'Found <strong>' + items.length + ' correlated alert' + (items.length !== 1 ? 's' : '') + '</strong>.',
      card: _listCard('🔗 Correlated Alerts', items, function (i) {
        return { dot: 'red', label: String(i.label || i.key || i.event || ''), val: String(i.value || i.time || i.severity || '') };
      })
    };
  }

  /* ── INCIDENT SUMMARY — bridges to Zia alert analysis ── */
  function _rIncidentSummary(e) {
    var aid = (typeof currentAlertId !== 'undefined') ? currentAlertId : null;
    var det = aid && ((typeof ALERT_DETAIL !== 'undefined') ? ALERT_DETAIL : (window.ALERT_DETAIL || {}))[aid];

    var html = '<div class="zhp-card zhp-card-zia-bridge"><div class="zhp-card-ttl">✦ Incident Summary</div>';

    if (det && det.investSummary) {
      html += '<p class="zhp-bridge-summary">' + _escHtml(det.investSummary) + '</p>';
      if (det.keyFindings && det.keyFindings.length) {
        html += '<div class="zhp-card-list">';
        det.keyFindings.forEach(function (k) {
          html += '<div class="zhp-list-row"><span class="zhp-list-dot zhp-dot-red"></span>' +
            '<span class="zhp-list-label">' + _escHtml(k.title || '') + '</span>' +
            '<span class="zhp-list-val">' + _escHtml((k.text || '').substring(0, 60) + ((k.text || '').length > 60 ? '…' : '')) + '</span></div>';
        });
        html += '</div>';
      }
    } else {
      var rs = e.sections && e.sections.riskSummary && e.sections.riskSummary.summaryCard;
      var score = rs ? (rs.riskScore !== undefined ? rs.riskScore : rs.score) : '—';
      html += '<p class="zhp-bridge-summary">Risk score: ' + score + '. Click <strong>Start Investigation</strong> in the Investigation tab to generate a full AI-powered summary.</p>';
    }
    html += '</div>';

    return {
      text: (det && det.investSummary)
        ? 'Here\'s the current incident summary from Zia\'s alert analysis.'
        : 'No AI summary yet — run "Start Investigation" first.',
      card: html
    };
  }

  /* ── USER — mailbox forwarding ── */
  function _rMailboxForwarding(e) {
    var items = _secItems(e.sections && e.sections.mailboxForwarding, ['kv', 'rules', 'items']);
    if (!items.length) return { text: 'No mailbox forwarding rules detected for this user. ✓' };
    return {
      text: '⚠ <strong>' + items.length + ' forwarding rule' + (items.length !== 1 ? 's' : '') + ' detected</strong> — common data exfiltration technique.',
      card: _listCard('📨 Mailbox Forwarding Rules', items, function (i) {
        return { dot: 'red', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── USER — dark web exposure ── */
  function _rDarkWeb(e) {
    var items = _secItems(e.sections && e.sections.darkWebExposure, ['kv', 'items']);
    if (!items.length) return { text: 'No dark web exposure found in configured threat intelligence feeds. ✓' };
    return {
      text: '🌑 <strong>' + items.length + ' dark web record' + (items.length !== 1 ? 's' : '') + '</strong> found — credentials may be compromised.',
      card: _listCard('🌑 Dark Web Exposure', items, function (i) {
        return { dot: 'red', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── USER — privileged access ── */
  function _rPrivilegedAccess(e) {
    var s = e.sections || {};
    var items = _secItems(s.privilegedSurface || s.effectiveGroups, ['kv', 'items']);
    if (!items.length) return { text: 'No privileged access data found for this user.' };
    return {
      text: 'This user has access to <strong>' + items.length + ' privileged resource' + (items.length !== 1 ? 's' : '') + '</strong>.',
      card: _listCard('🔑 Privileged Access', items, function (i) {
        var isHigh = /admin|domain|global|owner|root/i.test(String(i.value || i.label || ''));
        return { dot: isHigh ? 'red' : 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── USER — group membership changes ── */
  function _rGroupChanges(e) {
    var items = _secItems(e.sections && e.sections.groupMembershipChanges, ['kv', 'items', 'timeline']);
    if (!items.length) return { text: 'No group membership changes detected in the investigation window.' };
    return {
      text: 'Found <strong>' + items.length + ' group change' + (items.length !== 1 ? 's' : '') + '</strong> for this user.',
      card: _listCard('👥 Group Membership Changes', items, function (i) {
        var isAdd = /add|join/i.test(String(i.value || i.action || ''));
        return { dot: isAdd ? 'orange' : 'blue', label: String(i.label || i.key || ''), val: String(i.value || i.time || '') };
      })
    };
  }

  /* ── USER — account lockouts ── */
  function _rAccountLockouts(e) {
    var items = _secItems(e.sections && e.sections.accountLockouts, ['kv', 'items', 'timeline']);
    if (!items.length) return { text: 'No account lockout events found for this user.' };
    return {
      text: 'Found <strong>' + items.length + ' lockout event' + (items.length !== 1 ? 's' : '') + '</strong>.',
      card: _listCard('🔒 Account Lockouts', items, function (i) {
        return { dot: 'red', label: String(i.label || i.key || ''), val: String(i.value || i.time || '') };
      })
    };
  }

  /* ── DEVICE — USB activity ── */
  function _rUsbActivity(e) {
    var items = _secItems(e.sections && e.sections.usbDeviceEvents, ['kv', 'items', 'timeline']);
    if (!items.length) return { text: 'No USB device activity recorded in the investigation window.' };
    return {
      text: 'Found <strong>' + items.length + ' USB event' + (items.length !== 1 ? 's' : '') + '</strong> on this device.',
      card: _listCard('💾 USB Device Events', items, function (i) {
        var isPlug = /plug|insert|connect|attach/i.test(String(i.value || i.event || ''));
        return { dot: isPlug ? 'orange' : 'blue', label: String(i.label || i.key || ''), val: String(i.value || i.time || '') };
      })
    };
  }

  /* ── DEVICE — processes on host ── */
  function _rProcessesOnHost(e) {
    var s = e.sections || {};
    var items = _secItems(s.processesOnHost || s.processes, ['kv', 'items', 'list']);
    if (!items.length) return { text: 'No process data available for this device in the investigation window.' };
    return {
      text: 'Found <strong>' + items.length + ' process' + (items.length !== 1 ? 'es' : '') + '</strong> active on this host.',
      card: _listCard('⚙ Processes on Host', items, function (i) {
        var isSus = i.malicious || /powershell|cmd|wscript|mshta|rundll/i.test(String(i.label || i.key || ''));
        return { dot: isSus ? 'red' : 'blue', label: String(i.label || i.key || ''), val: String(i.value || i.pid || '') };
      })
    };
  }

  /* ── DEVICE — scheduled tasks ── */
  function _rScheduledTasks(e) {
    var items = _secItems(e.sections && e.sections.scheduledTasks, ['kv', 'items', 'tasks']);
    if (!items.length) return { text: 'No scheduled tasks found for this device.' };
    return {
      text: 'Found <strong>' + items.length + ' scheduled task' + (items.length !== 1 ? 's' : '') + '</strong> — review suspicious entries.',
      card: _listCard('📅 Scheduled Tasks', items, function (i) {
        var isSus = i.malicious || /powershell|cmd|wscript|base64|hidden/i.test(String(i.value || i.label || ''));
        return { dot: isSus ? 'red' : 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── IP — DNS history ── */
  function _rDnsHistory(e) {
    var items = _secItems(e.sections && e.sections.dnsHistory, ['kv', 'items', 'queries']);
    if (!items.length) return { text: 'No DNS query history found for this IP.' };
    return {
      text: 'Found <strong>' + items.length + ' DNS record' + (items.length !== 1 ? 's' : '') + '</strong> associated with this IP.',
      card: _listCard('🔎 DNS Lookup History', items, function (i) {
        return { dot: i.malicious ? 'red' : 'blue', label: String(i.label || i.key || ''), val: String(i.value || i.time || '') };
      })
    };
  }

  /* ── IP — associated users / devices ── */
  function _rAssociatedEntities(e) {
    var s = e.sections || {};
    var usrs = _secItems(s.associatedUsers,   ['kv', 'items']);
    var devs = _secItems(s.associatedDevices, ['kv', 'items']);
    if (!usrs.length && !devs.length) return { text: 'No associated users or devices found for this IP.' };
    var html = '';
    if (usrs.length) html += _listCardHtml('👤 Associated Users',   usrs.slice(0, 5), function (i) {
      return { dot: 'blue',   label: String(i.label || i.key || ''), val: String(i.value || '') };
    });
    if (devs.length) html += _listCardHtml('💻 Associated Devices', devs.slice(0, 5), function (i) {
      return { dot: 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
    });
    var total = usrs.length + devs.length;
    return { text: '<strong>' + total + ' entity connection' + (total !== 1 ? 's' : '') + '</strong> linked to this IP.', card: html };
  }

  /* ── IP — IDS alerts ── */
  function _rIdsAlerts(e) {
    var items = _secItems(e.sections && e.sections.idsAlerts, ['kv', 'items', 'alerts']);
    if (!items.length) return { text: 'No IDS / IPS alerts found for this IP.' };
    return {
      text: 'Found <strong>' + items.length + ' IDS/IPS alert' + (items.length !== 1 ? 's' : '') + '</strong> for this IP.',
      card: _listCard('🚦 IDS / IPS Alerts', items, function (i) {
        return { dot: 'red', label: String(i.label || i.key || ''), val: String(i.value || i.rule || i.time || '') };
      })
    };
  }

  /* ── IP — firewall summary ── */
  function _rFirewallSummary(e) {
    var items = _secItems(e.sections && e.sections.firewallSummary, ['kv', 'items']);
    if (!items.length) return { text: 'No firewall data available for this IP.' };
    return {
      text: 'Firewall activity summary for this IP:',
      card: _listCard('🔥 Firewall Summary', items, function (i) {
        var isBlock = /block|deny|drop/i.test(String(i.value || ''));
        return { dot: isBlock ? 'red' : 'green', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── PROCESS — process tree ── */
  function _rProcessTree(e) {
    var s = e.sections || {};
    var items = _secItems(s.processTree || s.childProcesses || s.processDetails, ['kv', 'items', 'tree', 'children']);
    if (!items.length) return { text: 'No process tree data available for this process.' };
    return {
      text: 'Process execution chain:',
      card: _listCard('🌲 Process Tree', items, function (i) {
        var isSus = i.malicious || /powershell|cmd|wscript|mshta|rundll|base64/i.test(String(i.label || i.key || ''));
        return { dot: isSus ? 'red' : 'blue', label: String(i.label || i.key || ''), val: String(i.value || i.pid || '') };
      })
    };
  }

  /* ── PROCESS — registry modifications ── */
  function _rRegistryMods(e) {
    var items = _secItems(e.sections && e.sections.registryModifications, ['kv', 'items']);
    if (!items.length) return { text: 'No registry modification data found for this process.' };
    return {
      text: 'Found <strong>' + items.length + ' registry modification' + (items.length !== 1 ? 's' : '') + '</strong>.',
      card: _listCard('📝 Registry Modifications', items, function (i) {
        var isSus = /run|startup|currentversion|policies|winlogon/i.test(String(i.label || i.key || ''));
        return { dot: isSus ? 'red' : 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── PROCESS — AMSI / AV detections ── */
  function _rAmsiEvents(e) {
    var items = _secItems(e.sections && e.sections.amsiEvents, ['kv', 'items', 'detections']);
    if (!items.length) return { text: 'No AMSI / antivirus detection events found for this process. ✓' };
    return {
      text: '⚠ <strong>' + items.length + ' AMSI/AV detection' + (items.length !== 1 ? 's' : '') + '</strong> triggered.',
      card: _listCard('🛡 AMSI / AV Detections', items, function (i) {
        return { dot: 'red', label: String(i.label || i.key || ''), val: String(i.value || i.verdict || '') };
      })
    };
  }

  /* ── PROCESS — file operations ── */
  function _rFileOperations(e) {
    var items = _secItems(e.sections && e.sections.fileOperations, ['kv', 'items']);
    if (!items.length) return { text: 'No file operation data found for this process.' };
    return {
      text: 'Found <strong>' + items.length + ' file operation' + (items.length !== 1 ? 's' : '') + '</strong>.',
      card: _listCard('📂 File Operations', items, function (i) {
        var isDel = /delet|remov/i.test(String(i.value || i.action || ''));
        return { dot: isDel ? 'red' : 'blue', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── SERVICE — OAuth consent grants ── */
  function _rOauthGrants(e) {
    var s = e.sections || {};
    var items = _secItems(s.oauthConsentGrants || s.conditionalAccess, ['kv', 'items', 'grants']);
    if (!items.length) return { text: 'No OAuth consent or conditional access data found for this service.' };
    return {
      text: 'Found <strong>' + items.length + ' OAuth permission' + (items.length !== 1 ? 's' : '') + '</strong> for this service.',
      card: _listCard('🔐 OAuth Consent Grants', items, function (i) {
        var isDanger = /Files\.ReadWrite|Mail\.|User\.ReadWrite|Group\.|RoleManagement/i.test(String(i.value || i.label || ''));
        return { dot: isDanger ? 'red' : 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── Logon ── */
  function _rLogon(e) {
    var s = e.sections || {};
    var items = _secItems(s.logonActivity || s.loginStatistics || s.loginActivity, ['timeline', 'kv']);
    if (!items.length) return { text: 'No logon activity data available in the current window.' };
    return {
      text: 'Found <strong>' + items.length + ' logon event' + (items.length !== 1 ? 's' : '') + '</strong>.',
      card: _listCard('🔐 Logon Activity', items, function (i) {
        var label = i.event || i.label || i.key || '';
        return { dot: (i.malicious || /fail/i.test(String(label))) ? 'red' : 'blue', label: String(label), val: String(i.time || i.value || '') };
      })
    };
  }

  /* ── Failed login ── */
  function _rFailedLogin(e) {
    var sec = e.sections && e.sections.logonActivity;
    var all = _secItems(sec, ['timeline', 'kv']);
    var fails = all.filter(function (i) { return i.malicious || /fail/i.test(String(i.event || i.label || '')); });
    var rs = e.sections && e.sections.riskSummary && e.sections.riskSummary.summaryCard;
    var metricFail = rs && rs.metrics && rs.metrics.find(function (m) { return /failed/i.test(m.label || ''); });
    var count = fails.length || (metricFail && metricFail.value) || '—';
    var displayItems = fails.length ? fails : [{ event: 'Failed login events detected', value: String(count) }];
    return {
      text: 'Detected <strong>' + count + ' failed login attempt' + (count !== 1 ? 's' : '') + '</strong>.',
      card: _listCard('⚠ Failed Login Attempts', displayItems, function (i) {
        return { dot: 'red', label: String(i.event || i.label || 'Failed Login'), val: String(i.time || i.value || '') };
      })
    };
  }

  /* ── Alerts ── */
  function _rAlerts(e) {
    var items = _secItems(e.sections && e.sections.recentAlerts, ['kv', 'timeline']);
    if (!items.length) return { text: 'No triggered alerts found for this entity in the current period.' };
    return {
      text: '<strong>' + items.length + ' alert' + (items.length !== 1 ? 's' : '') + '</strong> triggered by this entity.',
      card: _listCard('🚨 Triggered Alerts', items, function (i) {
        return { dot: 'red', label: String(i.label || i.key || i.event || i.name || ''), val: String(i.value || i.time || i.severity || '') };
      })
    };
  }

  /* ── UEBA ── */
  function _rUeba(e) {
    var rs = e.sections && e.sections.riskSummary && e.sections.riskSummary.summaryCard;
    var ub = e.sections && e.sections.uebaProfile;
    if (!rs && !ub) return { text: 'No UEBA profile data available for this entity.' };
    var html = '<div class="zhp-card zhp-card-risk"><div class="zhp-card-ttl">📊 UEBA Risk Profile</div><div class="zhp-card-kv">';
    if (rs) {
      var score = rs.riskScore !== undefined ? rs.riskScore : rs.score;
      if (score !== undefined) html += '<span class="zhp-kv-k">Risk Score</span><span class="zhp-kv-v zhp-risk-score" data-score="' + score + '">' + score + ' / ' + (rs.maxScore || 100) + '</span>';
      if (rs.severity) html += '<span class="zhp-kv-k">Severity</span><span class="zhp-kv-v">' + _escHtml(rs.severity) + '</span>';
      if (rs.heroChips) rs.heroChips.slice(0, 4).forEach(function (c) {
        html += '<span class="zhp-kv-k">' + _escHtml(c.label) + '</span><span class="zhp-kv-v">' + _escHtml(String(c.value)) + '</span>';
      });
    }
    if (ub) _secItems(ub, ['kv', 'items']).slice(0, 4).forEach(function (i) {
      html += '<span class="zhp-kv-k">' + _escHtml(String(i.label || i.key || '')) + '</span><span class="zhp-kv-v">' + _escHtml(String(i.value || '')) + '</span>';
    });
    html += '</div></div>';
    var sev = (rs && rs.severity) || 'Unknown';
    var tail = sev === 'High' ? 'significant anomalous behavior detected.' : sev === 'Medium' ? 'some elevated activity worth monitoring.' : 'behaviour within normal thresholds.';
    var sc2 = rs ? (rs.riskScore !== undefined ? rs.riskScore : rs.score) : '—';
    return { text: 'Risk score: <strong>' + sc2 + '</strong> (' + sev + '). ' + tail, card: html };
  }

  /* ── Network ── */
  function _rNetwork(e) {
    var s = e.sections || {};
    var items = _secItems(s.networkActivity || s.connectionHistory || s.trafficSummary, ['kv', 'timeline', 'items']);
    if (!items.length) return { text: 'No network activity data found for this entity.' };
    return {
      text: 'Found <strong>' + items.length + ' network connection' + (items.length !== 1 ? 's' : '') + '</strong>.',
      card: _listCard('🌐 Network Activity', items, function (i) {
        return { dot: i.malicious ? 'red' : 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── Vulnerabilities ── */
  function _rVulnerabilities(e) {
    var items = _secItems(e.sections && e.sections.vulnerabilities, ['kv', 'timeline']);
    if (!items.length) return { text: 'No vulnerability data available for this entity.' };
    return {
      text: 'Found <strong>' + items.length + ' vulnerabilit' + (items.length !== 1 ? 'ies' : 'y') + '</strong>.',
      card: _listCard('🔍 Vulnerability Scan', items, function (i) {
        var isCrit = /critical|high/i.test(String(i.value || ''));
        return { dot: isCrit ? 'red' : 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── Blast radius ── */
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

  /* ── Threat intel ── */
  function _rThreatIntel(e) {
    var ti = e.sections && e.sections.threatIntelligence;
    var tiItems = _secItems(ti, ['kv', 'items']);
    var isMal = e.type === 'ip' && (
      /tor|c2|malicious/i.test(e.modalTitle || '') ||
      ((e.sections && e.sections.riskSummary && e.sections.riskSummary.summaryCard || {}).severity === 'High') ||
      tiItems.some(function (i) { return /malicious|tor|c2|block/i.test(String(i.value || '')); })
    );
    var html = '<div class="zhp-card zhp-card-risk"><div class="zhp-card-ttl">🛡 Threat Intelligence</div><div class="zhp-card-kv">';
    if (tiItems.length) {
      tiItems.slice(0, 5).forEach(function (i) {
        var isFlag = /malicious|tor|c2|block|high/i.test(String(i.value || ''));
        html += '<span class="zhp-kv-k">' + _escHtml(String(i.label || i.key || '')) + '</span>' +
          '<span class="zhp-kv-v" style="color:' + (isFlag ? '#dc2626' : 'inherit') + '">' + _escHtml(String(i.value || '')) + '</span>';
      });
    } else if (e.type === 'ip') {
      html += '<span class="zhp-kv-k">IP Reputation</span><span class="zhp-kv-v" style="color:' + (isMal ? '#dc2626' : '#16a34a') + '">' + (isMal ? '⚠ Malicious' : '✓ Clean') + '</span>';
      html += '<span class="zhp-kv-k">Feed Match</span><span class="zhp-kv-v">' + (isMal ? 'Tor Exit Node / C2' : 'No match') + '</span>';
    } else {
      html += '<span class="zhp-kv-k">Threat Feed</span><span class="zhp-kv-v">No known IOC match</span>';
    }
    html += '</div></div>';
    return {
      text: isMal ? 'This IP is <strong>flagged as malicious</strong> in Log360 threat intelligence feeds.' : 'No IOC matches found in configured threat feeds.',
      card: html
    };
  }

  /* ── File access ── */
  function _rFileAccess(e) {
    var s = e.sections || {};
    var items = _secItems(s.recentFileAccess || s.fileActivity || s.resourceFileAccess, ['kv', 'timeline']);
    if (!items.length) return { text: 'No file access records found in the current investigation window.' };
    return {
      text: 'Found <strong>' + items.length + ' file access event' + (items.length !== 1 ? 's' : '') + '</strong>.',
      card: _listCard('📁 File Access', items, function (i) {
        return { dot: 'blue', label: String(i.label || i.key || ''), val: String(i.value || i.time || '') };
      })
    };
  }

  /* ── Misconfig ── */
  function _rMisconfig(e) {
    var s = e.sections || {};
    var items = _secItems(s.misconfigurations || s.configIssues || s.gpoApplied, ['kv', 'timeline']);
    if (!items.length) return { text: 'No misconfiguration data found for this entity.' };
    return {
      text: 'Found <strong>' + items.length + ' misconfiguration' + (items.length !== 1 ? 's' : '') + '</strong>.',
      card: _listCard('⚙ Misconfigurations / Policy', items, function (i) {
        return { dot: 'orange', label: String(i.label || i.key || ''), val: String(i.value || '') };
      })
    };
  }

  /* ── Audit logs ── */
  function _rAuditLogs(e) {
    var s = e.sections || {};
    var items = _secItems(s.auditLogs || s.signInAudit || s.adminActivity, ['kv', 'timeline']);
    if (!items.length) return { text: 'No audit log data available for this entity.' };
    return {
      text: 'Found <strong>' + items.length + ' audit log event' + (items.length !== 1 ? 's' : '') + '</strong>.',
      card: _listCard('📋 Audit Logs', items, function (i) {
        return { dot: 'blue', label: String(i.label || i.key || ''), val: String(i.value || i.time || '') };
      })
    };
  }

  /* ── Fallback ── */
  function _rFallback(e, q) {
    var shortName = (e.modalTitle || '').split('·').pop().trim() || _huntEntityId;
    var hints = _buildBlastRadiusSuggestions(_huntEntityId, e).slice(0, 3)
      .map(function (s) { return s.icon + ' ' + s.text; }).join(', ');
    return {
      text: 'I searched for "<strong>' + _escHtml(q) + '</strong>" in ' + _escHtml(shortName) + '\'s data. ' +
        'Try: ' + hints + ' — or open Entity Details for the full profile.',
      card: ''
    };
  }

  // ── Card builder helpers ───────────────────────────────────────────
  function _listCard(title, items, rowFn) {
    return _listCardHtml(title, items, rowFn);
  }

  function _listCardHtml(title, items, rowFn) {
    var html = '<div class="zhp-card"><div class="zhp-card-ttl">' + title + '</div><div class="zhp-card-list">';
    items.forEach(function (item) {
      var r = rowFn(item);
      html += '<div class="zhp-list-row">' +
        '<span class="zhp-list-dot zhp-dot-' + r.dot + '"></span>' +
        '<span class="zhp-list-label">' + _escHtml(r.label) + '</span>' +
        '<span class="zhp-list-val">' + _escHtml(r.val) + '</span></div>';
    });
    return html + '</div></div>';
  }

  function _listBody(items, rowFn) {
    var html = '<div class="zhp-card-list">';
    items.forEach(function (item) {
      var r = rowFn(item);
      html += '<div class="zhp-list-row">' +
        '<span class="zhp-list-dot zhp-dot-' + r.dot + '"></span>' +
        '<span class="zhp-list-label">' + _escHtml(r.label) + '</span>' +
        '<span class="zhp-list-val">' + _escHtml(r.val) + '</span></div>';
    });
    return html + '</div>';
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
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

})();
