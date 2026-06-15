/* ═══════════════════════════════════════════════════════════════════════
   V6 ATTACK VECTOR — additive UI layer (v2: slider-integrated cuts)
   Loads AFTER all V5 modules. Wraps V5 globals; no V5 source edits.

   §4.A  Cut suggestions live in each entity slider's actions dropdown
         and render rich content in the existing action panel.
   §4.B  Hop-Count Strip — visible above the dark graph canvas.
   §4.D  Pivot-as-Investigation-Root — dim other nodes + pulse +
         persistent banner with Clear button.
   §4.F  Workflow Preview — modal popover launched from cut action.
   ═══════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  /* ─── DATA ──────────────────────────────────────────────────────── */

  // Direct hops from a selected entity. For demo, hard-coded for the
  // m.henderson alert universe; in product these come from the graph.
  const V6_HOP_DATA = [
    { id: 'dev-ws045',  num: 1, kind: 'crit', label: 'devices',  tail: '· 1 critical' },
    { id: 'ip-tor',     num: 1, kind: 'crit', label: 'IPs',      tail: '· Tor exit' },
    { id: 'svc-ad',     num: 1, kind: 'warn', label: 'services', tail: '· Azure AD' },
    { id: 'alert-847',  num: 2, kind: 'crit', label: 'alerts',   tail: '(2-hop)' },
    { id: 'svc-share',  num: 2, kind: 'warn', label: 'services', tail: 'reachable' }
  ];

  // Cut suggestions keyed by entityId. Each is a single Action Panel card.
  const V6_CUT_DATA = {
    'user-m-henderson': {
      key: 'v6CutDisableUser',
      title: 'Disable Account — m.henderson',
      icon: '🚫',
      rank: 1,
      rankLabel: 'BEST CUT',
      reuseAction: 'blockEntity',
      summary: 'Disabling m.henderson severs the attacker’s identity foothold across every connected host, IP and service.',
      metrics: {
        prevented: { num: 12, label: 'Alerts prevented · 7d' },
        affects:   { num: 3,  label: 'Hosts affected' },
        effort:    { num: 1,  label: 'Steps · ~30s' }
      },
      source: 'UEBA score 94 · 3 of 3 alerts trace back to this user · ATT&CK T1078',
      workflowKey: 'disableUser'
    },
    'dev-ws045': {
      key: 'v6CutIsolateHost',
      title: 'Isolate Host — CORP-WS-045',
      icon: '🔒',
      rank: 2,
      rankLabel: 'STRONG CUT',
      reuseAction: 'isolateHost',
      summary: 'Network-isolating CORP-WS-045 stops the live C2 beacon and prevents the running implant from reaching new targets.',
      metrics: {
        prevented: { num: 7,  label: 'Alerts prevented · 7d' },
        affects:   { num: 5,  label: 'Users on host' },
        effort:    { num: 1,  label: 'Steps · ~45s' }
      },
      source: 'Sysmon Event 3 · beacon every 60s · file: svchost_update.dll (unsigned)',
      workflowKey: 'isolateHost'
    },
    'ip-tor': {
      key: 'v6CutBlockIp',
      title: 'Block Source IP — 185.220.101.42',
      icon: '🌐',
      rank: 3,
      rankLabel: 'PERIMETER CUT',
      reuseAction: 'blockEntity',
      summary: 'Firewall-blocking 185.220.101.42 cuts the inbound login vector. Less surgical: attacker may pivot to another Tor exit.',
      metrics: {
        prevented: { num: 4,  label: 'Alerts prevented · 7d' },
        affects:   { num: 6,  label: 'Hosts shielded' },
        effort:    { num: 2,  label: 'Steps · ~1m' }
      },
      source: 'Threat Intel · AbuseIPDB 100% · VirusTotal 14/90 · Tor exit list',
      workflowKey: 'blockIp'
    }
  };

  // Workflow preview models (Trigger → Cond → TRUE → Action → Human)
  const V6_WORKFLOWS = {
    disableUser: {
      title: 'Workflow · Auto-disable user on UEBA spike',
      nodes: [
        { kind: 'trigger', label: 'TRIGGER', sub: 'UEBA risk score change' },
        { kind: 'cond',    label: 'IF score ≥ 90 AND impossible-travel = TRUE' },
        { kind: 'branch',  label: '— TRUE —' },
        { kind: 'action',  label: 'ACTION', sub: 'Azure AD · disable user account' },
        { kind: 'human',   label: 'HUMAN APPROVAL', sub: 'SOC lead · Slack #soc-approvals' }
      ]
    },
    isolateHost: {
      title: 'Workflow · Auto-isolate host on confirmed C2',
      nodes: [
        { kind: 'trigger', label: 'TRIGGER', sub: 'EDR alert · C2 beacon detected' },
        { kind: 'cond',    label: 'IF dest ∈ TI feed AND beacon period < 5m' },
        { kind: 'branch',  label: '— TRUE —' },
        { kind: 'action',  label: 'ACTION', sub: 'CrowdStrike · network-contain host' },
        { kind: 'human',   label: 'HUMAN APPROVAL', sub: 'On-call · PagerDuty ack' }
      ]
    },
    blockIp: {
      title: 'Workflow · Auto-block malicious source IP',
      nodes: [
        { kind: 'trigger', label: 'TRIGGER', sub: 'Login from new IP' },
        { kind: 'cond',    label: 'IF IP ∈ Tor-exit OR AbuseIPDB ≥ 90' },
        { kind: 'branch',  label: '— TRUE —' },
        { kind: 'action',  label: 'ACTION', sub: 'Palo Alto · add to block-list' },
        { kind: 'human',   label: 'INFORM', sub: 'Ticket · ServiceNow auto-created' }
      ]
    }
  };

  /* Choke-point entity IDs (must have a matching V6_CUT_DATA entry). */
  const V6_CHOKE_POINTS = Object.keys(V6_CUT_DATA);

  /* Playbook options per choke point. Each opens an automation workflow on Run. */
  const V6_PLAYBOOKS = {
    'user-m-henderson': [
      { id: 'disableUser',        icon: '🚫', name: 'Disable account',          desc: 'Azure AD · set account to disabled, invalidate all sessions',                risk: 'high',   eta: '~30s' },
      { id: 'forcePasswordReset', icon: '🔄', name: 'Force password reset',      desc: 'Azure AD · require new password at next sign-in + revoke refresh tokens',     risk: 'med',    eta: '~45s' },
      { id: 'revokeTokens',       icon: '🔑', name: 'Revoke active tokens',     desc: 'Azure AD · revoke OAuth refresh tokens across all apps',                     risk: 'low',    eta: '~20s' },
      { id: 'notifyManager',      icon: '✉',  name: 'Notify line manager',      desc: 'Send templated email + Teams DM to user’s manager and SOC channel',         risk: 'low',    eta: '~5s'  }
    ],
    'dev-ws045': [
      { id: 'isolateHost',        icon: '🔒', name: 'Isolate host',             desc: 'CrowdStrike · network-contain endpoint (allow only EDR comms)',              risk: 'high',   eta: '~45s' },
      { id: 'killProcess',        icon: '⊘',  name: 'Kill suspicious processes', desc: 'CrowdStrike RTR · terminate svchost_update.dll and child processes',         risk: 'med',    eta: '~30s' },
      { id: 'collectForensics',   icon: '💾', name: 'Collect forensic package', desc: 'CrowdStrike RTR · memory dump + Sysmon export + recent file deltas',         risk: 'low',    eta: '~3m'  },
      { id: 'openIncident',       icon: '📌', name: 'Open ServiceNow incident',  desc: 'Create Sev-1 incident with auto-populated host + alert details',            risk: 'low',    eta: '~10s' }
    ],
    'ip-tor': [
      { id: 'blockIp',            icon: '🌐', name: 'Block source IP',           desc: 'Palo Alto firewall · add 185.220.101.42 to deny-list (perimeter)',          risk: 'high',   eta: '~1m'  },
      { id: 'blockAsn',           icon: '🚫', name: 'Block ASN range',           desc: 'Palo Alto firewall · block known Tor exit ASN block (broader)',             risk: 'med',    eta: '~2m'  },
      { id: 'addToTiFeed',        icon: '🔍', name: 'Add to threat-intel feed', desc: 'Push indicator to internal TI feed for cross-product enforcement',         risk: 'low',    eta: '~15s' },
      { id: 'huntPastLogins',     icon: '⛏',  name: 'Hunt past logins from IP',  desc: 'Run scheduled hunt: all auth events from this IP across last 30 days',     risk: 'low',    eta: '~1m'  }
    ]
  };

  /* Per-entity-TYPE default playbooks. Used for every entity in the graph,
     not just choke points. Each action carries a "verb" (Contain / Disrupt /
     Investigate / Hygiene) that drives the colored chip + confirm-modal copy. */
  const V6_PLAYBOOKS_BY_TYPE = {
    user: [
      { id:'openUserPage',     verb:'investigate', icon:'�', name:'Entity timeline',         desc:'Chronological activity for this user — sign-ins, group changes, password events, alerts',                risk:'low',  eta:'instant', reversible:true,  panel:'uebaTimeline' },
      { id:'disableUser',      verb:'contain',     icon:'🚫', name:'Disable account',         desc:'AD/Entra · set account to disabled — user cannot log in anywhere',                                  risk:'high', eta:'~30s',    reversible:true,  confirm:true, panel:'blockEntity' },
      { id:'forcePasswordReset',verb:'disrupt',    icon:'🔄', name:'Force password reset',    desc:'Invalidate current password, force change at next sign-in — kills credential reuse',                risk:'med',  eta:'~45s',    reversible:true,  panel:'forcePasswordReset' },
      { id:'revokeTokens',     verb:'disrupt',     icon:'🔑', name:'Revoke active tokens',    desc:'Invalidate all OAuth & refresh tokens — kicks attacker out of cloud apps',                          risk:'low',  eta:'~20s',    reversible:false, panel:'revokeTokens' },
      { id:'markCompromised',  verb:'investigate', icon:'⚠',  name:'Mark as compromised',    desc:'Tag in UEBA · raises risk score, tightens monitoring rules',                                          risk:'low',  eta:'instant', reversible:true, panel:'addToIncident' },
      { id:'notifyManager',    verb:'hygiene',     icon:'✉',  name:'Notify line manager',     desc:'Templated email + Teams DM to user’s manager and SOC channel',                                    risk:'low',  eta:'~5s',     reversible:false, panel:'addToIncident' },
      { id:'manageTags',       verb:'hygiene',     icon:'🏷',  name:'Manage tags',             desc:'Add tags like crown-jewel, pci-scope, vip, contractor · affects future alert priority',         risk:'low',  eta:'instant', reversible:true, panel:'addToIncident' },
      { id:'goHunt',           verb:'investigate', icon:'⛏',  name:'Investigate entity',     desc:'Load AI-enriched sections for this user (hidden by default to save AI cost)',                       risk:'low',  eta:'instant', reversible:false, panel:'searchLogs' }
    ],
    device: [
      { id:'openDevicePage',   verb:'investigate', icon:'�', name:'Entity timeline',         desc:'Chronological activity for this device — logons, local account changes, alerts',                       risk:'low',  eta:'instant', reversible:true,  panel:'uebaTimeline' },
      { id:'isolateHost',      verb:'contain',     icon:'🔒', name:'Isolate device',          desc:'CrowdStrike · network-contain endpoint (only EDR comms allowed)',                                    risk:'high', eta:'~45s',    reversible:true,  confirm:true, panel:'isolateHost' },
      { id:'runAvScan',        verb:'disrupt',     icon:'🛡',  name:'Run AV scan',             desc:'Trigger on-demand full antivirus scan via EDR agent',                                                  risk:'low',  eta:'~5m',     reversible:false, panel:'runPlaybook' },
      { id:'collectForensics', verb:'investigate', icon:'💾', name:'Collect forensics',       desc:'CrowdStrike RTR · memory dump + Sysmon export + recent file deltas + netstat — packaged as .zip',     risk:'low',  eta:'~3m',     reversible:false, panel:'auditLogs' },
      { id:'killProcess',      verb:'disrupt',     icon:'⊘',  name:'Kill suspicious process', desc:'CrowdStrike RTR · terminate named process tree (e.g. powershell.exe)',                              risk:'med',  eta:'~30s',    reversible:false, panel:'killProcess' },
      { id:'manageTags',       verb:'hygiene',     icon:'🏷',  name:'Manage tags',             desc:'Add tags like crown-jewel, pci-scope, quarantined · affects future alert priority',                  risk:'low',  eta:'instant', reversible:true, panel:'addToIncident' },
      { id:'goHunt',           verb:'investigate', icon:'⛏',  name:'Investigate entity',     desc:'Load AI-enriched sections for this host (hidden by default to save AI cost)',                       risk:'low',  eta:'instant', reversible:false, panel:'searchLogs' }
    ],
    ip: [
      { id:'openIpPage',       verb:'investigate', icon:'📜', name:'Entity timeline',         desc:'Chronological activity from this IP — logons, users touched, alerts',                                  risk:'low',  eta:'instant', reversible:false, panel:'uebaTimeline' },
      { id:'blockIp',          verb:'contain',     icon:'🚫', name:'Block IP at firewall',    desc:'Palo Alto · push deny rule to perimeter firewall',                                                    risk:'high', eta:'~1m',     reversible:true,  confirm:true, panel:'blockEntity' },
      { id:'blockAsn',         verb:'contain',     icon:'🛑', name:'Block ASN',               desc:'Block entire autonomous system · broader than single IP',                                              risk:'high', eta:'~2m',     reversible:true,  confirm:true, panel:'blockEntity' },
      { id:'addToTiFeed',      verb:'hygiene',     icon:'🔍', name:'Add to threat-intel feed',desc:'Add to internal TI list · proxy & SIEM auto-flag future hits',                                         risk:'low',  eta:'~15s',    reversible:true, panel:'addToIncident' },
      { id:'huntPastLogins',   verb:'investigate', icon:'⛏',  name:'Hunt past logins from IP',desc:'Search sign-in logs · find other victims of this IP across all users',                                risk:'low',  eta:'~1m',     reversible:false, panel:'loginActivity' },
      { id:'manageTags',       verb:'hygiene',     icon:'🏷',  name:'Manage tags',             desc:'Add tags like tor-exit, vpn, known-malicious, allow-listed · affects future alert priority',     risk:'low',  eta:'instant', reversible:true, panel:'addToIncident' },
      { id:'goHunt',           verb:'investigate', icon:'⛏',  name:'Investigate entity',     desc:'Load AI-enriched sections for this IP (hidden by default to save AI cost)',                         risk:'low',  eta:'instant', reversible:false, panel:'searchLogs' }
    ],
    service: [
      { id:'openAppPage',      verb:'investigate', icon:'�', name:'Entity timeline',         desc:'Chronological activity for this service — OAuth consents, sign-ins, config changes, alerts',          risk:'low',  eta:'instant', reversible:false, panel:'uebaTimeline' },
      { id:'revokeOAuth',      verb:'disrupt',     icon:'🔑', name:'Revoke OAuth consent',    desc:'Remove app\u2019s permission to access user data · kills exfil channel',                              risk:'med',  eta:'~30s',    reversible:true, panel:'revokeTokens' },
      { id:'blockApp',         verb:'contain',     icon:'🚫', name:'Block app tenant-wide',   desc:'No user can grant consent to this app again',                                                          risk:'high', eta:'~1m',     reversible:true,  confirm:true, panel:'blockEntity' },
      { id:'manageTags',       verb:'hygiene',     icon:'🏷',  name:'Manage tags',             desc:'Add tags like business-critical, sanctioned, third-party · affects future alert priority',        risk:'low',  eta:'instant', reversible:true, panel:'addToIncident' },
      { id:'goHunt',           verb:'investigate', icon:'⛏',  name:'Investigate entity',     desc:'Load AI-enriched sections for this app (hidden by default to save AI cost)',                        risk:'low',  eta:'instant', reversible:false, panel:'auditLogs' }
    ],
    process: [
      { id:'openProcessTree',  verb:'investigate', icon:'📜', name:'Entity timeline',         desc:'Chronological activity for this process — launches / terminations, hosts observed, alerts',           risk:'low',  eta:'instant', reversible:false, panel:'uebaTimeline' },
      { id:'stopProcess',      verb:'disrupt',     icon:'⊘',  name:'Stop process',            desc:'Terminate on originating host',                                                                        risk:'med',  eta:'~10s',    reversible:false, panel:'killProcess' },
      { id:'quarantineFile',   verb:'contain',     icon:'📥', name:'Quarantine parent file',  desc:'Move file to EDR quarantine across all endpoints where hash is seen',                                risk:'high', eta:'~1m',     reversible:true,  confirm:true, panel:'killProcess' },
      { id:'blockHash',        verb:'contain',     icon:'🧱', name:'Add hash to blocklist',   desc:'Org-wide block · file cannot execute on any managed device',                                          risk:'high', eta:'~30s',    reversible:true,  confirm:true, panel:'blockEntity' },
      { id:'manageTags',       verb:'hygiene',     icon:'🏷',  name:'Manage tags',             desc:'Add tags like signed-binary, lolbin, known-good · affects future alert priority',                  risk:'low',  eta:'instant', reversible:true, panel:'addToIncident' },
      { id:'goHunt',           verb:'investigate', icon:'⛏',  name:'Investigate entity',     desc:'Load AI-enriched sections for this process (hidden by default to save AI cost)',                    risk:'low',  eta:'instant', reversible:false, panel:'searchLogs' }
    ],
    alert: [
      { id:'openAlertPage',    verb:'investigate', icon:'�', name:'Entity timeline',         desc:'Chronological activity for this alert — raw events, triggers, similar alerts',                          risk:'low',  eta:'instant', reversible:false, panel:'uebaTimeline' },
      { id:'runPlaybook',      verb:'disrupt',     icon:'▶',  name:'Run response playbook',   desc:'Execute the SOAR playbook bound to this alert type',                                                  risk:'med',  eta:'~2m',     reversible:false, panel:'runPlaybook' },
      { id:'assignToMe',       verb:'hygiene',     icon:'👋', name:'Assign to',               desc:'Assign this alert to a SOC analyst',                                                                  risk:'low',  eta:'instant', reversible:true, panel:'addToIncident' },
      { id:'closeFalsePositive',verb:'hygiene',    icon:'✓',  name:'Close as false positive', desc:'Suppresses this rule for the source entity for 24h',                                                    risk:'low',  eta:'instant', reversible:true, panel:'closeAlert' },
      { id:'goHunt',           verb:'investigate', icon:'⛏',  name:'Investigate entity',     desc:'Load AI-enriched sections for this alert (hidden by default to save AI cost)',                      risk:'low',  eta:'instant', reversible:false, panel:'searchLogs' }
    ],
    domain: [
      { id:'openDomainPage',   verb:'investigate', icon:'📜', name:'Entity timeline',         desc:'Chronological activity for this domain — DNS lookups, IPs resolved, alerts',                            risk:'low',  eta:'instant', reversible:false, panel:'uebaTimeline' },
      { id:'blockDomain',      verb:'contain',     icon:'🚫', name:'Block domain at proxy',   desc:'Secure web gateway · sinkhole this FQDN org-wide',                                                    risk:'high', eta:'~1m',     reversible:true,  confirm:true, panel:'blockEntity' },
      { id:'sinkholeDns',      verb:'disrupt',     icon:'🕳',  name:'DNS sinkhole',            desc:'Redirect DNS lookups to internal sinkhole IP — kills C2 channel',                                    risk:'high', eta:'~2m',     reversible:true,  confirm:true, panel:'blockEntity' },
      { id:'addDomainToTi',    verb:'hygiene',     icon:'🔍', name:'Add to threat-intel feed',desc:'Add FQDN to internal TI list · proxy & SIEM auto-flag future hits',                                   risk:'low',  eta:'~15s',    reversible:true, panel:'addToIncident' },
      { id:'huntPastDns',      verb:'investigate', icon:'⛏',  name:'Hunt past DNS lookups',   desc:'Find all internal hosts that resolved this domain in last 30 days',                                   risk:'low',  eta:'~1m',     reversible:false, panel:'searchLogs' },
      { id:'manageTags',       verb:'hygiene',     icon:'🏷',  name:'Manage tags',             desc:'Add tags like c2, phishing-infra, allow-listed · affects future alert priority',                   risk:'low',  eta:'instant', reversible:true, panel:'addToIncident' },
      { id:'goHunt',           verb:'investigate', icon:'⛏',  name:'Investigate entity',     desc:'Load AI-enriched sections for this domain (hidden by default to save AI cost)',                     risk:'low',  eta:'instant', reversible:false, panel:'searchLogs' }
    ]
  };

  /* Verb metadata · drives chip color + confirm-modal phrasing */
  const V6_VERBS = {
    contain:     { label:'CONTAIN',     cls:'v6-verb-contain',     blurb:'stops the bleeding · always reversible' },
    disrupt:     { label:'DISRUPT',     cls:'v6-verb-disrupt',     blurb:'breaks the attacker\u2019s current foothold' },
    investigate: { label:'INVESTIGATE', cls:'v6-verb-investigate', blurb:'pivot for more data · no state change' },
    hygiene:     { label:'HYGIENE',     cls:'v6-verb-hygiene',     blurb:'metadata / bookkeeping · no security impact' }
  };

  /* ─── STATE ─────────────────────────────────────────────────────── */
  let v6ChokeOn = false;
  /* Choke-point lifecycle in V6:
       'hidden'    → graph mounted but Start Investigation not run yet
       'ready'     → AI investigation finished; offer "Analyze choke points" CTA
       'analyzing' → loader visible (~1.5s simulated graph analysis)
       'analyzed'  → choke-point pill + dropdown active */
  let v6ChokeState = 'hidden';
  /* Snapshot of graph node count at last analysis — lets us detect newly
     expanded entities and prompt "Analyze again". */
  let v6NodeCountAtAnalyze = 0;

  /* ─── ESCAPE ────────────────────────────────────────────────────── */
  const esc = (s) => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  /* ─── 4.A  ACTIONS PANEL CONTENT (multi-playbook) ──────────────── */
  function buildActionsContent(cut, name, entityId) {
    const m = cut.metrics;
    const playbooks = V6_PLAYBOOKS[entityId] || [];
    const pbHtml = playbooks.map(pb => `
      <div class="v6-pb-card">
        <div class="v6-pb-card-icon">${esc(pb.icon)}</div>
        <div class="v6-pb-card-body">
          <div class="v6-pb-card-title">
            <span>${esc(pb.name)}</span>
            <span class="v6-pb-risk v6-pb-risk-${pb.risk}" title="Blast radius if this action is wrong">Blast radius: ${pb.risk.toUpperCase()}</span>
            ${pb.eta && pb.eta !== 'instant' ? `<span class="v6-pb-eta" title="How long this takes to complete">${esc(pb.eta)}</span>` : ''}
          </div>
          <div class="v6-pb-card-desc">${esc(pb.desc)}</div>
        </div>
        <button class="v6-pb-run" onclick="V6AV.runPlaybook('${esc(entityId)}','${esc(pb.id)}','${esc(pb.icon)} ${esc(pb.name)}')">▶ Run</button>
      </div>`).join('');
    return {
      title: 'Recommended actions — ' + name,
      badge: { text: cut.rankLabel, cls: cut.rank === 1 ? 'ap-tag-crit' : 'ap-tag-high' },
      html: `
        <div class="v6-cut-summary">
          <div class="v6-cut-summary-title">
            <span class="v6-cut-summary-rank ${cut.rank === 2 ? 'r2' : cut.rank === 3 ? 'r3' : ''}">RANK #${cut.rank}</span>
            <span>${esc(cut.icon)} Why this entity</span>
          </div>
          <div style="font-size:11.5px;color:#78350f;line-height:1.5;margin-bottom:10px;">
            ${esc(cut.summary)}
          </div>
          <div class="v6-cut-source">
            <strong>Evidence:</strong> ${esc(cut.source)}
          </div>
        </div>
        <div class="v6-pb-hdr">▶ Available playbooks · ${playbooks.length}</div>
        <div class="v6-pb-list">${pbHtml}</div>

        <div class="v6-impact-card">
          <div class="v6-impact-hdr">📊 Expected impact if you act on this entity</div>
          <div class="v6-impact-row">
            <span class="v6-impact-num prevented">${m.prevented.num}</span>
            <div class="v6-impact-text">
              <div class="v6-impact-label">Alerts prevented</div>
              <div class="v6-impact-sub">over the next 7 days, based on this entity's recent activity</div>
            </div>
          </div>
          <div class="v6-impact-row">
            <span class="v6-impact-num">${m.affects.num}</span>
            <div class="v6-impact-text">
              <div class="v6-impact-label">${esc(m.affects.label)}</div>
              <div class="v6-impact-sub">downstream entities touched by the chosen playbook</div>
            </div>
          </div>
          <div class="v6-impact-row">
            <span class="v6-impact-num effort">${m.effort.num}</span>
            <div class="v6-impact-text">
              <div class="v6-impact-label">${esc(m.effort.label)}</div>
              <div class="v6-impact-sub">analyst effort to confirm and approve</div>
            </div>
          </div>
        </div>`,
      actions: `
        <button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Close</button>
        <button class="ap-btn ap-btn-outline" onclick="V6AV.showWorkflow('${cut.workflowKey}')">⚡ Preview top workflow</button>`
    };
  }

  // Inject our actions content into the existing action panel.
  function openCutActionPanel(entityId) {
    const cut = V6_CUT_DATA[entityId];
    if (!cut) return;
    // The action panel lives inside the entity slider — open the slider first
    // so it is actually visible. Also close any open choke dropdown.
    const chokePanel = document.getElementById('v6ChokePanel');
    if (chokePanel) chokePanel.classList.remove('open');
    if (typeof window.openEntitySlider === 'function') {
      try { window.openEntitySlider(entityId); } catch (e) {}
    }
    const e = (typeof ENTITIES !== "undefined" ? ENTITIES : (window.ENTITIES || {}))[entityId];
    const name = e ? (e.modalTitle.split('·').pop()?.trim() || e.modalTitle) : entityId;

    const panel  = document.getElementById('actionPanel');
    const title  = document.getElementById('apTitle');
    const badge  = document.getElementById('apBadge');
    const body   = document.getElementById('apBody');
    const actions= document.getElementById('apActions');
    if (!panel || !title || !body || !actions) return;

    window.ctxEntityId = entityId;
    const content = buildActionsContent(cut, name, entityId);
    title.textContent = content.title;
    badge.textContent = content.badge.text;
    badge.className = 'ap-badge ' + content.badge.cls;
    badge.style.display = '';
    body.innerHTML = content.html;
    actions.innerHTML = content.actions;
    actions.style.display = 'flex';
    panel.classList.add('visible');
  }

  function runPlaybook(entityId, playbookId, label) {
    if (typeof window.showToast === 'function') {
      window.showToast('▶', `Playbook started → ${label}. Awaiting approval in SOAR queue.`);
    }
  }

  /* ─── 4.A  WRAP populateActionsDropdown TO INJECT V6 ACTIONS ────── */
  function wrapPopulateActionsDropdown() {
    if (typeof window.populateActionsDropdown !== 'function') return;
    if (window.populateActionsDropdown.__v6Wrapped) return;
    const orig = window.populateActionsDropdown;
    window.populateActionsDropdown = function v6PopulateActionsDropdown(type, name) {
      // Replace the V5 dropdown entirely with V6 grouped actions.
      // We still call orig in case it sets state; then we wipe + rebuild.
      orig.call(this, type, name);
      const dd = document.getElementById('edsActionsDd');
      if (!dd) return;
      const eid = window.ctxEntityId;
      if (!eid) return;

      // V6: the slider Actions menu is investigation-only — it offers exactly
      // two pivots, "Entity timeline" and "Investigate entity". All response
      // playbooks (contain / disrupt / hygiene) live in the dedicated actions
      // panel, not in this dropdown.
      const KEEP_ACTIONS = new Set(['Entity timeline', 'Investigate entity']);
      const playbooks = (V6_PLAYBOOKS_BY_TYPE[type] || []).filter(pb => KEEP_ACTIONS.has(pb.name));
      if (!playbooks.length) {
        // Keep V5 default dropdown if we have no per-type playbooks
        return;
      }

      let html = '';
      playbooks.forEach(pb => {
        html += `<div class="dropdown-item v6-dd-act" onclick="V6AV.runEntityAction('${esc(eid)}','${esc(pb.id)}');closeDropdowns()" title="${esc(pb.desc)}">
            <span class="v6-dd-icon">${esc(pb.icon)}</span>
            <span class="v6-dd-name">${esc(pb.name)}</span>
          </div>`;
      });

      dd.innerHTML = html;
    };
    window.populateActionsDropdown.__v6Wrapped = true;
  }

  /* ─── 4.A.2  WRAP openEntitySlider → inject reachability strip ──── */
  function wrapOpenEntitySlider() {
    if (typeof window.openEntitySlider !== 'function') return;
    if (window.openEntitySlider.__v6Wrapped) return;
    const orig = window.openEntitySlider;
    window.openEntitySlider = function v6OpenEntitySlider(entityId) {
      const ret = orig.apply(this, arguments);
      try { injectReachabilityStrip(entityId); } catch (e) { console.warn('[V6AV] reach', e); }
      try { injectSliderActionsButton(entityId); } catch (e) { console.warn('[V6AV] sliderActions', e); }
      // V6: entity overview no longer shows tag chips (Manage tags removed).
      // Defensive: scrub any prior fake log-details mounts from earlier sessions
      document.querySelectorAll('.v6-logdetails-block, .v6-logdetails-card').forEach(n => n.remove());
      try { applyBaselineFilter(entityId); } catch (e) { console.warn('[V6AV] baseline', e); }
      return ret;
    };
    window.openEntitySlider.__v6Wrapped = true;
  }

  /* ─── 4.A.2b  WRAP showEdgeRelation → strip entity-only V6 widgets ───
     The entity slider DOM is reused for the relation view (showEdgeRelation
     just rewrites #edsBody / #edsTitle). When the analyst opens an entity
     first and then clicks an edge, our entity-scoped widgets — Actions ▾,
     reachability card, header tag chips — leak into the relation view
     where they make no sense (a relationship has no "Disable user" /
     "Isolate host" / tag affordance). Strip them on every relation open. */
  function wrapShowEdgeRelation() {
    if (typeof window.showEdgeRelation !== 'function') return;
    if (window.showEdgeRelation.__v6Wrapped) return;
    const orig = window.showEdgeRelation;
    window.showEdgeRelation = function v6ShowEdgeRelation() {
      const ret = orig.apply(this, arguments);
      try {
        const slider = document.getElementById('entitySlider');
        if (slider) {
          // Drop the Actions ▾ dropdown from the slider header
          slider.querySelectorAll('.v6-slider-act-wrap').forEach(n => n.remove());
          // Drop header tag chips (entity-scoped tags)
          slider.querySelectorAll('.v6-header-tag-strip').forEach(n => n.remove());
          // Drop the reachability card (entity-scoped BFS)
          slider.querySelectorAll('.v6-reach-card').forEach(n => n.remove());
        }
      } catch (e) { console.warn('[V6AV] edge-relation scrub', e); }
      return ret;
    };
    window.showEdgeRelation.__v6Wrapped = true;
  }

  /* ─── BASELINE / ENRICHED data gating ────────────────────────────
     Show only the sections shippable on a minimal install by default.
     "Investigate entity" action unlocks the AI-enriched extras for
     just that one entity — cost-saving over enriching every entity. */

  // Per-entity-type whitelist of section keys available on a vanilla
  // AD-sync + Win-Sec install. Sourced from V5/baseline_entity_inventory.md
  // tables (the ✅ baseline rows, excluding rich-path-conditional bonuses
  // and integration-gated extras).
  const V6_BASELINE_SECTIONS = {
    user:    new Set(['riskSummary','usersDetails','loginStatistics','logonActivity','accountLockouts','passwordHistory','groupMembershipChanges','recentAlerts']),
    device:  new Set(['riskSummary','deviceDetails','usersLoggedOn','loginActivity','localAccountLifecycle','recentAlerts']),
    ip:      new Set(['riskSummary','ipDetails','associatedUsers','associatedDevices','recentAlerts']),
    service: new Set(['riskSummary','serviceDetails','serviceInfo','recentAlerts']),
    process: new Set(['riskSummary','processDetails','details','recentAlerts']),
    alert:   new Set(['alertDetails','triggerConditions','details','recentAlerts']),
    domain:  new Set(['riskSummary','ipDetails','associatedUsers','associatedDevices','recentAlerts'])
  };

  /* ─── STAGE 3 GATING · Alert-family pruning within Enriched ─────────
     Once an entity is Investigated, prune the Enriched set further so
     only the sections relevant to the alert family that opened the
     investigation remain visible. Blueprint matrices live in
     V5/entity_constant_vs_dynamic.md §4.
     The analyst can override the pruning per-entity via the
     "+ N more sections" chip; override state is held in
     v6FamilyOverride. */
  const V6_FAMILY_LABELS = {
    impossibleTravel:         'Impossible Travel',
    bruteForce:               'Brute Force / Password Spray',
    accountLockout:           'Account Lockout Anomaly',
    mfaFatigue:               'MFA Fatigue / Bypass',
    oauthConsent:             'OAuth Consent / App Governance',
    suspiciousOauthToken:     'Suspicious OAuth Token',
    newAppConsent:            'New App Consent',
    encodedPowershell:        'Encoded PowerShell / Execution',
    suspiciousServiceInstall: 'Suspicious Service Install',
    c2Connection:             'C2 / Tor Connection',
    torExit:                  'Tor Exit Detected',
    credentialDump:           'SAM / Credential Dump',
    bulkFileDownload:         'Bulk File Download / Sensitive Access',
    sensitiveFileAccess:      'Sensitive File Access',
    dataExfiltration:         'Data Exfiltration',
    mailboxForwarding:        'Mailbox Forwarding to External',
    arpSpoofing:              'ARP Spoofing / LAN MITM',
    portScan:                 'Port-scan / IDS signature',
    internalIpInvestigation:  'Internal IP investigation',
    dnsTunnel:                'DNS Tunnel',
    newlyRegisteredDomain:    'Newly Registered Domain',
    usbExfil:                 'USB Exfil / Data Theft',
    scheduledTaskPersistence: 'Scheduled-Task Persistence',
    gpoTampering:             'GPO Tampering',
    samDatabaseAccess:        'SAM Database Access',
    dllInjection:             'DLL Injection',
    servicePersistence:       'Service Persistence',
    c2FromProcess:            'C2 from process'
  };

  /* Maps an alert.title pattern to a canonical family id. First-match wins. */
  const V6_FAMILY_TITLE_PATTERNS = [
    [/impossible\s*travel/i,                  'impossibleTravel'],
    [/account\s*lockout/i,                    'accountLockout'],
    [/brute\s*force|password\s*spray/i,       'bruteForce'],
    [/mfa.*fatigue|mfa.*bypass/i,             'mfaFatigue'],
    [/oauth.*token|suspicious.*token/i,       'suspiciousOauthToken'],
    [/oauth.*consent|app\s*governance/i,      'oauthConsent'],
    [/new\s*app\s*consent/i,                  'newAppConsent'],
    [/encoded\s*powershell|powershell.*exec/i,'encodedPowershell'],
    [/suspicious\s*service\s*install/i,       'suspiciousServiceInstall'],
    [/scheduled.*task/i,                      'scheduledTaskPersistence'],
    [/gpo\s*tamper/i,                         'gpoTampering'],
    [/usb.*exfil|usb.*data\s*theft/i,         'usbExfil'],
    [/sam.*database|sam.*credential|lsass/i,  'credentialDump'],
    [/dll\s*injection/i,                      'dllInjection'],
    [/arp\s*spoof|lan.*mitm/i,                'arpSpoofing'],
    [/port.*scan|ids\s*signature/i,           'portScan'],
    [/dns.*tunnel/i,                          'dnsTunnel'],
    [/newly\s*registered\s*domain/i,          'newlyRegisteredDomain'],
    [/tor.*exit/i,                            'torExit'],
    [/mailbox.*forward/i,                     'mailboxForwarding'],
    [/bulk\s*file|sensitive\s*file.*download/i,'bulkFileDownload'],
    [/sensitive\s*file/i,                     'sensitiveFileAccess'],
    [/exfil/i,                                'dataExfiltration'],
    [/malicious\s*url|c2|command.*control|beacon/i, 'c2Connection']
  ];

  /* Per entity-type × family → Set of enriched section ids that REMAIN visible.
     Mirrors the V7 design-intent matrices from V5/entity_constant_vs_dynamic.md.
     Sections not listed here are pruned from the Enriched view when the
     entity is investigated under that alert family. */
  const V6_ENRICHED_BY_FAMILY = {
    user: {
      impossibleTravel:         new Set(['resourceFileAccess','networkActivity','recentAppAccess','mailboxForwarding','threatIntelContext']),
      bruteForce:               new Set([]),
      accountLockout:           new Set([]),
      mfaFatigue:               new Set(['recentAppAccess']),
      oauthConsent:             new Set(['resourceFileAccess','recentAppAccess','threatIntelContext']),
      suspiciousOauthToken:     new Set(['resourceFileAccess','recentAppAccess','threatIntelContext']),
      encodedPowershell:        new Set(['processes','serviceTriggered','resourceFileAccess','networkActivity','threatIntelContext']),
      suspiciousServiceInstall: new Set(['processes','serviceTriggered','networkActivity','threatIntelContext']),
      c2Connection:             new Set(['processes','serviceTriggered','networkActivity','threatIntelContext']),
      credentialDump:           new Set(['processes','resourceFileAccess']),
      bulkFileDownload:         new Set(['resourceFileAccess','networkActivity','recentAppAccess','threatIntelContext']),
      dataExfiltration:         new Set(['processes','resourceFileAccess','networkActivity','mailboxForwarding','threatIntelContext']),
      mailboxForwarding:        new Set(['resourceFileAccess','recentAppAccess','mailboxForwarding'])
    },
    service: {
      impossibleTravel:         new Set(['conditionalAccess','signInAudit','adminActivity']),
      suspiciousOauthToken:     new Set(['oauthConsentGrants','signInAudit','processes','serviceTriggered']),
      newAppConsent:            new Set(['oauthConsentGrants','conditionalAccess','adminActivity']),
      bulkFileDownload:         new Set(['signInAudit','fileAccessAnomaly','sensitiveFiles','processes']),
      sensitiveFileAccess:      new Set(['fileAccessAnomaly','sensitiveFiles']),
      suspiciousServiceInstall: new Set(['serviceTimeline','networkConnections','fileDrops','wmiEvents','processes','serviceTriggered']),
      c2Connection:             new Set(['serviceTimeline','networkConnections','processes']),
      dataExfiltration:         new Set(['fileAccessAnomaly','sensitiveFiles','networkConnections','processes'])
    },
    ip: {
      impossibleTravel: new Set(['threatIntelligence','connectionHistory']),
      c2Connection:     new Set(['threatIntelligence','connectionHistory','dnsHistory','idsAlerts','trafficSummary']),
      torExit:          new Set(['threatIntelligence','connectionHistory','idsAlerts']),
      dataExfiltration: new Set(['threatIntelligence','connectionHistory','trafficSummary']),
      arpSpoofing:      new Set(['connectionHistory']),
      internalIpInvestigation: new Set(['connectionHistory','vpnSessions','trafficSummary']),
      portScan:         new Set(['threatIntelligence','connectionHistory','idsAlerts','trafficSummary'])
    },
    domain: {
      c2Connection:          new Set(['threatIntelligence','connectionHistory','dnsHistory','idsAlerts']),
      dataExfiltration:      new Set(['threatIntelligence','connectionHistory','dnsHistory']),
      dnsTunnel:             new Set(['threatIntelligence','dnsHistory','idsAlerts']),
      newlyRegisteredDomain: new Set(['threatIntelligence','dnsHistory'])
    },
    device: {
      encodedPowershell:        new Set(['processesOnHost']),
      suspiciousServiceInstall: new Set(['scheduledTasks','processesOnHost','servicesOnHost']),
      arpSpoofing:              new Set(['processesOnHost']),
      credentialDump:           new Set(['processesOnHost']),
      usbExfil:                 new Set(['usbDeviceEvents']),
      scheduledTaskPersistence: new Set(['scheduledTasks','processesOnHost','servicesOnHost']),
      gpoTampering:             new Set(['gpoApplied'])
    },
    process: {
      encodedPowershell: new Set(['amsiEvents','registryModifications','networkActivity','fileOperations','childProcesses','processDnsQueries']),
      credentialDump:    new Set(['registryModifications','fileOperations']),
      c2Connection:      new Set(['networkActivity','processDnsQueries']),
      dllInjection:      new Set(['networkActivity','dllLoads','namedPipes']),
      servicePersistence:new Set(['registryModifications','fileOperations','childProcesses','serviceTriggered'])
    },
    alert: {} // alert slider is small & always-relevant; no per-family pruning planned
  };

  /* Resolve the active investigation's alert family from currentAlertId. */
  function v6CurrentAlertFamily() {
    const aid = (typeof currentAlertId !== 'undefined') ? currentAlertId
              : (window.currentAlertId || null);
    if (!aid) return null;
    const list = (typeof ALERTS !== 'undefined') ? ALERTS : (window.ALERTS || []);
    const a = list.find(x => x.id === aid);
    if (!a || !a.title) return null;
    for (const [re, fam] of V6_FAMILY_TITLE_PATTERNS) {
      if (re.test(a.title)) return fam;
    }
    return null;
  }

  /* ─── GLOBAL ENTITY-TAG STORE ──────────────────────────────────────
     Persisted in localStorage so tags survive page reload AND apply
     across every alert that touches the same entity.
     Shape: { [entityId]: ['crown-jewel','pci-scope', ...] } */
  const V6_TAG_STORAGE_KEY = 'v6_entity_tags';
  // Seed defaults (used only on first load before user has saved anything)
  const V6_TAG_SEED = {
    'dev-ws045':       ['crown-jewel','prod-asset','pci-scope'],
    'user-m-henderson':['privileged-user','vpn-user'],
    'user-admin':      ['privileged-user'],
    'ip-tor':          ['tor-exit','high-risk'],
    'domain-c2':       ['high-risk']
  };
  function loadTagStore() {
    try {
      const raw = localStorage.getItem(V6_TAG_STORAGE_KEY);
      if (raw) return JSON.parse(raw) || {};
    } catch (_) { /* corrupt JSON · fall through */ }
    return Object.assign({}, V6_TAG_SEED);
  }
  function saveTagStore(store) {
    try { localStorage.setItem(V6_TAG_STORAGE_KEY, JSON.stringify(store)); }
    catch (e) { console.warn('[V6AV] tag save failed', e); }
  }
  let V6_TAGS = loadTagStore();
  function getTagsFor(entityId) {
    return (V6_TAGS[entityId] || []).slice();
  }
  function setTagsFor(entityId, tags) {
    const clean = Array.from(new Set((tags || []).map(t => String(t).trim()).filter(Boolean)));
    if (clean.length) V6_TAGS[entityId] = clean;
    else delete V6_TAGS[entityId];
    saveTagStore(V6_TAGS);
  }
  // A few tags carry semantic weight — used by reachability card to
  // surface "this entity touches a crown-jewel device" callouts.
  const V6_TAG_BADGES = {
    'crown-jewel':     { icon: '\ud83d\udc51', cls: 'v6-tagbadge-crown',   label: 'crown jewel' },
    'pci-scope':       { icon: '\ud83d\udcb3', cls: 'v6-tagbadge-pci',     label: 'PCI scope' },
    'compromised':     { icon: '\u26a0',       cls: 'v6-tagbadge-compromised', label: 'compromised' },
    'quarantined':     { icon: '\ud83d\udd12', cls: 'v6-tagbadge-quarantined', label: 'quarantined' },
    'watchlist':       { icon: '\ud83d\udc41', cls: 'v6-tagbadge-watch',   label: 'watchlist' },
    'privileged-user': { icon: '\u2605',       cls: 'v6-tagbadge-priv',    label: 'privileged' },
    'tor-exit':        { icon: '\ud83e\uddc5', cls: 'v6-tagbadge-tor',     label: 'tor exit' },
    'high-risk':       { icon: '\ud83d\udd25', cls: 'v6-tagbadge-risk',    label: 'high risk' }
  };

  // Per-entity unlock state — once user clicks "Investigate entity",
  // remember it for this session so enriched data stays visible.
  const v6InvestigatedEntities = new Set();

  function applyBaselineFilter(entityId) {
    const e = (typeof ENTITIES !== 'undefined' ? ENTITIES : (window.ENTITIES || {}))[entityId];
    if (!e || !e.sections) return;
    const body = document.getElementById('edsBody');
    if (!body) return;

    // Clean up any prior decoration from a previous slider open
    const oldBadge = document.getElementById('v6BaselineBadge');
    if (oldBadge) oldBadge.remove();

    const investigated = v6InvestigatedEntities.has(entityId);
    const baseline = V6_BASELINE_SECTIONS[e.type];

    // Stage 3 inputs · only meaningful once investigated
    const family = investigated ? v6CurrentAlertFamily() : null;
    const familyMap = family ? (V6_ENRICHED_BY_FAMILY[e.type] || {}) : null;
    const familyAllow = familyMap && familyMap[family] ? familyMap[family] : null;
    const familyLabel = family ? V6_FAMILY_LABELS[family] : null;

    // Show / hide each section based on the three-stage gate
    Object.keys(e.sections).forEach(key => {
      const el = document.getElementById('em-' + key);
      if (!el) return;
      const isBaseline = baseline && baseline.has(key);
      let visible;
      if (!investigated) {
        // Stage 1 — Baseline only
        visible = !baseline || isBaseline;
      } else if (familyAllow) {
        // Stage 3 — Baseline + family-allowed Enriched
        visible = isBaseline || familyAllow.has(key);
      } else {
        // Stage 2 — full Enriched (no family map for this alert)
        visible = true;
      }
      el.style.display = visible ? '' : 'none';
      // Tooltip: explain WHY each visible enriched section is showing
      if (visible && !isBaseline && investigated) {
        el.title = familyLabel
          ? `Showing because alert family = ${familyLabel}.`
          : 'Showing because you Investigated this entity.';
      } else {
        el.removeAttribute('title');
      }
    });

    // Hide tabs whose visible sections are all empty / hidden
    hideEmptyTabs();

    if (investigated) renderInvestigatedBadge(familyLabel, false);
  }

  /* Walk each tab panel · if it has no visible .em-section, hide the
     corresponding tab button so the user never lands on an empty tab. */
  function hideEmptyTabs() {
    const body = document.getElementById('edsBody');
    const tabsHost = document.getElementById('edsTabsHost');
    if (!body || !tabsHost) return;
    const panels = body.querySelectorAll('.eds-tab-panel');
    if (!panels.length) return;

    const tabButtons = tabsHost.querySelectorAll('.eds-tab');
    let firstVisibleIdx = -1;
    let activeStillVisible = false;

    panels.forEach((panel, idx) => {
      const tabId = panel.dataset.tab;
      // Special-case the Recent Alerts tab: it uses a flat body (no .em-section)
      // — check it has any non-empty content.
      let hasVisible;
      if (tabId === 'recentAlerts') {
        const text = panel.textContent.trim();
        hasVisible = text.length > 0 && !/no recent alerts/i.test(text);
      } else {
        hasVisible = Array.from(panel.querySelectorAll('.em-section'))
          .some(s => s.style.display !== 'none');
      }
      const btn = tabButtons[idx];
      if (!btn) return;
      if (hasVisible) {
        btn.style.display = '';
        if (firstVisibleIdx === -1) firstVisibleIdx = idx;
        if (btn.classList.contains('eds-tab-active')) activeStillVisible = true;
      } else {
        btn.style.display = 'none';
        panel.style.display = 'none';
        // If the currently-active tab just got hidden, switch away from it
        if (btn.classList.contains('eds-tab-active')) btn.classList.remove('eds-tab-active');
      }
    });

    // If the active tab was hidden, activate the first visible one
    if (!activeStillVisible && firstVisibleIdx >= 0) {
      const btn = tabButtons[firstVisibleIdx];
      const panel = panels[firstVisibleIdx];
      if (btn) btn.classList.add('eds-tab-active');
      if (panel) panel.style.display = '';
    }
  }

  function renderInvestigatedBadge(familyLabel) {
    const tabsHost = document.getElementById('edsTabsHost');
    if (!tabsHost) return;
    const badge = document.createElement('div');
    badge.id = 'v6BaselineBadge';
    badge.className = 'v6-baseline-badge';
    let txt = '\ud83e\udd16 AI-enriched data loaded for this entity';
    if (familyLabel) txt += ` \u00b7 focused on <b>${familyLabel}</b>`;
    badge.innerHTML = txt;
    tabsHost.appendChild(badge);
  }

  /* Show an "Analyzing entity\u2026" loader over the slider body, then run
     the callback once the simulated analysis completes. */
  function showAnalyzingLoader(entityName, onDone) {
    const slider = document.getElementById('entitySlider');
    if (!slider) { onDone && onDone(); return; }
    // Remove any prior loader
    const old = document.getElementById('v6AnalyzingOverlay');
    if (old) old.remove();
    const overlay = document.createElement('div');
    overlay.id = 'v6AnalyzingOverlay';
    overlay.className = 'v6-analyzing-overlay';
    overlay.innerHTML = `
      <div class="v6-analyzing-card">
        <div class="v6-analyzing-spinner"></div>
        <div class="v6-analyzing-title">Analyzing entity\u2026</div>
        <div class="v6-analyzing-sub">${esc(entityName)} \u00b7 loading AI-enriched data</div>
      </div>`;
    slider.appendChild(overlay);
    setTimeout(() => {
      overlay.remove();
      onDone && onDone();
    }, 1200);
  }

  /* Called from the slider Actions \u25be menu / ctx menu / runEntityAction('goHunt')
     \u2192 shows the analyzing loader, then unlocks enriched sections. */
  function investigateCurrentEntity(entityId) {
    const e = (typeof ENTITIES !== 'undefined' ? ENTITIES : (window.ENTITIES || {}))[entityId];
    if (!e) return;
    const name = e.modalTitle.split('\u00b7').pop()?.trim() || entityId;

    // Already investigated \u2014 just reapply (no loader)
    if (v6InvestigatedEntities.has(entityId)) {
      applyBaselineFilter(entityId);
      return;
    }

    showAnalyzingLoader(name, () => {
      v6InvestigatedEntities.add(entityId);
      applyBaselineFilter(entityId);
      if (typeof window.showToast === 'function') {
        window.showToast('\u2713', `AI-enriched data loaded for ${name}`);
      }
    });
  }

  /* ─── BASELINE SUMMARY CARD ─────────────────────────────────────────
     A uniform header card mounted at the top of EVERY entity's Overview
     tab. Documents \u2014 in one consistent format \u2014 which baseline sections
     are being rendered for this entity type and what data sources power
     them (per V5/baseline_entity_inventory.md). This is the "same format"
     every entity follows: same shell, same key/value rows, same tag chip
     row that surfaces persistent entity tags. */
  const V6_BASELINE_SPEC = {
    user: {
      label: 'User',
      key: 'AD sAMAccountName \u2192 Win-Sec `username`',
      sources: ['AD directory sync', 'Windows Security Event Log (rich-path)'],
      sections: [
        ['riskSummary',            'Anomaly count + AD account-age signals'],
        ['usersDetails',           'APFDiscADUserDetails'],
        ['loginStatistics',        '4624 success / 4625 failure aggregates'],
        ['logonActivity',          '4624 / 4625 timeline'],
        ['accountLockouts',        '4740 lockout events'],
        ['passwordHistory',        '4723 self-service \u222a 4724 admin reset'],
        ['groupMembershipChanges', '4727\u20134729 / 4731\u20134733 / 4754\u20134757'],
        ['recentAlerts',           'Alert profiles using Win-Sec + AD data']
      ]
    },
    device: {
      label: 'Device (host)',
      key: 'AD DNS_NAME \u2192 Win-Sec `hostname` (with reverse-IP fallback)',
      sources: ['AD directory sync', 'Windows Security Event Log (rich-path)'],
      sections: [
        ['riskSummary',          'Derived from baseline events targeting this computer'],
        ['deviceDetails',        'APFDiscADComputerDetails'],
        ['usersLoggedOn',        '4624 distinct usernames on this host'],
        ['loginActivity',        '4624 / 4625 on this host'],
        ['localAccountLifecycle','4720 / 4722 / 4723 / 4724 / 4726 (local SAM)'],
        ['recentAlerts',         'Alert profiles filtered by `hostname`']
      ]
    },
    ip: {
      label: 'IP',
      key: 'Win-Sec `remoteip` field (rich-path)',
      sources: ['Windows Security Event Log (rich-path)', 'Webroot on-demand TI lookup'],
      sections: [
        ['riskSummary',        '4624/4625 ratio + avg per-event `risk_level` (synthesized)'],
        ['ipDetails',          'remoteip + RFC1918 split + Webroot verdict on-demand'],
        ['associatedUsers',    'Distinct username from 4624 \u222a 4625 \u222a 4768 \u222a 4776'],
        ['associatedDevices',  'Distinct hostname/remotehost (internal IPs only)'],
        ['logonActivity',      '4624 / 4625 timeline + `logontype` facets'],
        ['recentAlerts',       'Alert profiles pivoting on `remoteip`']
      ]
    },
    service: {
      label: 'Service / Application',
      key: 'Service principal / app id',
      sources: ['Built-in alert catalog', 'Service config snapshot'],
      sections: [
        ['riskSummary',     'Composite risk for the service'],
        ['serviceDetails',  'App registration + publisher metadata'],
        ['serviceInfo',     'Granted scopes + consent + sign-in count'],
        ['recentAlerts',    'Alert profiles pivoting on app id']
      ]
    },
    process: {
      label: 'Process',
      key: 'Win-Sec `processname` (rich-path 4688 / 4689)',
      sources: ['Windows Security Event Log (rich-path)'],
      sections: [
        ['riskSummary',     '4688 fanout: hosts \u00d7 users \u00d7 elevatedtoken ratio'],
        ['processDetails',  'Latest 4688: processname / pid / commandline / parent'],
        ['details',         'Hashes + signer + elevation metadata'],
        ['recentAlerts',    'Alert profiles pivoting on `processname`']
      ]
    },
    alert: {
      label: 'Alert',
      key: 'Alert id from ITSAlertProfileConfigurations • joined to source event by `LogonId` / `Time`',
      sources: ['Built-in alert catalog (ITSAlertProfileConfigurations)', 'Source Windows Security event that triggered the rule'],
      sections: [
        ['alertDetails',      'Alert Severity · Profile Name · Status + parsed fields from the triggering event'],
        ['triggerConditions', 'Rule expression · matched event ids'],
        ['details',           'Raw `Message` payload + Common Report Name'],
        ['recentAlerts',      'Other alerts on same Target User / Log Source']
      ]
    },
    domain: {
      label: 'Domain',
      key: 'FQDN / AD domain name',
      sources: ['AD directory sync', 'Webroot on-demand WHOIS + verdict'],
      sections: [
        ['riskSummary',       'Webroot verdict + observation density'],
        ['ipDetails',         'WHOIS + registrar + age + related IPs (Webroot)'],
        ['associatedUsers',   'Users that resolved this domain'],
        ['associatedDevices', 'Hosts that resolved this domain'],
        ['recentAlerts',      'Alert profiles pivoting on domain']
      ]
    }
  };

  /* ─── TAG CHIPS into the Risk Summary card ────────────────────────
     The Risk Summary card already shows a chip row (severity + status,
     e.g. "CRITICAL · Compromised Host"). Append the entity's persistent
     tags into that same row so everything reads as one badge cluster
     instead of a separate widget. Falls back to a strip next to the
     type badge when the entity has no Risk Summary section. */
  function injectHeaderTagChips(entityId) {
    const e = (typeof ENTITIES !== 'undefined' ? ENTITIES : (window.ENTITIES || {}))[entityId];
    if (!e) return;

    // Clean prior mounts wherever they may live
    document.querySelectorAll('.v6-header-tag-strip').forEach(s => s.remove());
    document.querySelectorAll('.v6-baseline-card').forEach(c => c.remove());

    const tags = getTagsFor(entityId);
    if (!tags.length) return;

    const chipHtml = tags.map(t => {
      const meta = V6_TAG_BADGES[t];
      return meta
        ? `<span class="v6-tagbadge ${meta.cls}" title="${esc(meta.label)}">${meta.icon} ${esc(meta.label)}</span>`
        : `<span class="v6-tagbadge" title="${esc(t)}">${esc(t)}</span>`;
    }).join('');

    // Preferred mount: append into the Risk Summary card's badge row
    const badgeRow = document.querySelector('#edsBody .em-sc-badges');
    if (badgeRow) {
      const strip = document.createElement('span');
      strip.className = 'v6-header-tag-strip v6-tag-strip-inrisk';
      strip.innerHTML = chipHtml;
      badgeRow.appendChild(strip);
      return;
    }

    // Fallback: alert entities (and any type without a Risk Summary)
    // get a strip next to the type badge in the slider header.
    const typeBadge = document.getElementById('edsTypeBadge');
    if (typeBadge && typeBadge.parentNode) {
      const strip = document.createElement('span');
      strip.className = 'v6-header-tag-strip';
      strip.innerHTML = chipHtml;
      typeBadge.parentNode.insertBefore(strip, typeBadge.nextSibling);
    }
  }

  /* ─── INJECT "Actions ▾" button + dropdown into entity-slider header ───
     Lets the user fire any V6 playbook directly from the slider, without
     having to right-click the node again on the graph. */
  function injectSliderActionsButton(entityId) {
    const slider = document.getElementById('entitySlider');
    if (!slider) return;
    const e = (typeof ENTITIES !== 'undefined' ? ENTITIES : (window.ENTITIES || {}))[entityId];
    if (!e) return;
    // V6: slider Actions menu is investigation-only — only the two pivots.
    const KEEP_ACTIONS = new Set(['Entity timeline', 'Investigate entity']);
    const playbooks = (V6_PLAYBOOKS_BY_TYPE[e.type] || []).filter(pb => KEEP_ACTIONS.has(pb.name));
    if (!playbooks.length) return;

    // Mount point = the right-side action group in the slider header
    // (the one that holds "Hide Details").
    const hideLink = slider.querySelector('.eds-hide-link');
    if (!hideLink) return;
    const headerRight = hideLink.parentElement;
    if (!headerRight) return;

    // Remove any prior injection for a different entity
    const old = headerRight.querySelector('.v6-slider-act-wrap');
    if (old) old.remove();

    // Build dropdown items — always enabled, no investigation gating
    const items = playbooks.map(pb => {
      const color = pb.risk === 'high' ? '#dc2626' : pb.risk === 'med' ? '#ea580c' : '';
      const style = color ? ` style="color:${color};"` : '';
      const onclick = `V6AV.closeSliderActions();V6AV.runEntityAction('${esc(entityId)}','${esc(pb.id)}')`;
      return `<div class="v6-slider-act-item"${style} onclick="${onclick}" title="${esc(pb.desc)}">${esc(pb.icon)} ${esc(pb.name)}</div>`;
    }).join('');

    const wrap = document.createElement('div');
    wrap.className = 'v6-slider-act-wrap';
    wrap.innerHTML = `
      <button type="button" class="v6-slider-act-btn" onclick="V6AV.toggleSliderActions(event)">
        Actions <span class="v6-slider-act-caret">▾</span>
      </button>
      <div class="v6-slider-act-menu" id="v6SliderActMenu">
        ${items}
      </div>`;
    headerRight.insertBefore(wrap, hideLink);
  }

  /* Toggle the slider actions dropdown */
  function toggleSliderActions(evt) {
    if (evt) evt.stopPropagation();
    const menu = document.getElementById('v6SliderActMenu');
    if (!menu) return;
    const open = menu.classList.toggle('open');
    if (open) {
      // Close on outside click
      setTimeout(() => {
        document.addEventListener('click', closeSliderActionsOnce, { once: true });
      }, 0);
    }
  }
  function closeSliderActions() {
    const menu = document.getElementById('v6SliderActMenu');
    if (menu) menu.classList.remove('open');
  }
  function closeSliderActionsOnce() { closeSliderActions(); }

  /* ─── WRAP showGraphCtx → inject V6 actions into graph context menu ── */
  function wrapShowGraphCtx() {
    if (typeof window.showGraphCtx !== 'function') return;
    if (window.showGraphCtx.__v6Wrapped) return;
    const orig = window.showGraphCtx;
    window.showGraphCtx = function v6ShowGraphCtx(evt, entityId) {
      const ret = orig.apply(this, arguments);
      try { injectV6CtxActions(entityId); } catch (e) { console.warn('[V6AV] ctxActions', e); }
      return ret;
    };
    window.showGraphCtx.__v6Wrapped = true;
  }

  // Returns entity-type-specific investigation options that map to
  // existing V6 action panels, using Log360 product terminology.
  function goHuntOptions(type) {
    const byType = {
      user: [
        { key: 'uebaProfile',     icon: '👤', label: 'UEBA Profile' },
        { key: 'logonActivity',   icon: '🔐', label: 'Logon Activity' },
        { key: 'triggeredAlerts', icon: '🚨', label: 'Triggered Alerts' }
      ],
      device: [
        { key: 'vulnerabilities', icon: '🔍', label: 'Vulnerability Scan' },
        { key: 'networkActivity', icon: '🌐', label: 'Network Activity' },
        { key: 'triggeredAlerts', icon: '🚨', label: 'Triggered Alerts' }
      ],
      ip: [
        { key: 'networkActivity', icon: '🌐', label: 'Network Activity' },
        { key: 'triggeredAlerts', icon: '🚨', label: 'Triggered Alerts' }
      ],
      service: [
        { key: 'auditLogs',       icon: '📋', label: 'Audit Logs' },
        { key: 'blastRadius',     icon: '💥', label: 'Blast Radius' },
        { key: 'triggeredAlerts', icon: '🚨', label: 'Triggered Alerts' }
      ],
      process: [
        { key: 'blastRadius',     icon: '💥', label: 'Blast Radius' },
        { key: 'triggeredAlerts', icon: '🚨', label: 'Triggered Alerts' }
      ]
    };
    return byType[type] || [
      { key: 'searchLogs',      icon: '📋', label: 'Search in Logs' },
      { key: 'triggeredAlerts', icon: '🚨', label: 'Triggered Alerts' }
    ];
  }

  function toggleGoHuntMenu(toggleEl) {
    if (!toggleEl) return;
    toggleEl.classList.toggle('expanded');
    const body = toggleEl.nextElementSibling;
    if (body) body.classList.toggle('expanded');
    if (typeof window.reclampCtxMenu === 'function') {
      try { window.reclampCtxMenu(); } catch (_) {}
    }
  }

  function runGoHunt(entityId, huntKey) {
    if (!entityId) return;
    if (typeof hideGraphCtx === 'function') hideGraphCtx();

    // "Triggered Alerts" / "Related Alerts" — expand graph alert nodes directly
    if (huntKey === 'triggeredAlerts' || huntKey === 'relatedAlerts') {
      window.ctxEntityId = entityId;
      if (typeof ctxRelatedAlerts === 'function') {
        ctxRelatedAlerts();
      } else {
        showToast('🚨', 'Triggered alerts expansion is unavailable for this entity');
      }
      return;
    }

    // "Blast Radius" — opens lateral-spread sub-graph (no slider needed)
    if (huntKey === 'blastRadius') {
      window.ctxEntityId = entityId;
      if (typeof ctxBlastRadiusGraph === 'function') ctxBlastRadiusGraph();
      return;
    }

    // All other keys open the entity slider and route to the matching panel
    if (typeof openEntitySlider === 'function') openEntitySlider(entityId);

    const panelMap = {
      uebaProfile:    'uebaTimeline',
      logonActivity:  'loginActivity',
      vulnerabilities:'vulnerabilities',
      networkActivity:'networkActivity',
      auditLogs:      'auditLogs',
      searchLogs:     'searchLogs'
    };
    const panel = panelMap[huntKey];
    if (panel && typeof showActionPanel === 'function') {
      showActionPanel(panel, entityId);
    }
  }

  function injectV6CtxActions(entityId) {
    const ctx = document.getElementById('graphCtxMenu');
    if (!ctx) return;
    const e = (typeof ENTITIES !== 'undefined' ? ENTITIES : (window.ENTITIES || {}))[entityId];
    if (!e) return;
    // V6: graph context menu is investigation-only — only the two pivots
    // ("Entity timeline" + "Investigate entity"). Response playbooks are
    // not surfaced here.
    const KEEP_ACTIONS = new Set(['Entity timeline', 'Investigate entity']);
    const playbooks = (V6_PLAYBOOKS_BY_TYPE[e.type] || []).filter(pb => KEEP_ACTIONS.has(pb.name));
    if (!playbooks.length) return;

    // Don't double-inject if user re-opens menu on same node
    if (ctx.querySelector('.v6-ctx-section')) return;

    // Insert entity-type-aware "Go Hunt" investigation branch.
    const opts = goHuntOptions(e.type);
    const optHtml = opts.map(o =>
      `<div class="ctx-item v6-gohunt-item" onclick="V6AV.runGoHunt('${esc(entityId)}','${o.key}')">${o.icon} ${o.label}</div>`
    ).join('\n        ');
    const goHuntHtml = `<div class="ctx-sep v6-gohunt-sep"></div>
      <div class="ctx-more-toggle v6-gohunt-toggle" onclick="V6AV.toggleGoHuntMenu(this)">
        <span>🧭 Go Hunt</span><span class="ctx-chevron">▸</span>
      </div>
      <div class="ctx-more-body v6-gohunt-body">
        ${optHtml}
      </div>`;
    const afterSearchLogs = ctx.querySelector('.ctx-item[onclick="ctxSearchLogs()"]');
    if (afterSearchLogs) {
      afterSearchLogs.insertAdjacentHTML('afterend', goHuntHtml);
    } else {
      ctx.insertAdjacentHTML('beforeend', goHuntHtml);
    }

    let gated = false;
    try {
      const aid = (typeof currentAlertId !== 'undefined') ? currentAlertId : null;
      if (aid && typeof ALERT_DETAIL !== 'undefined') {
        gated = !!(ALERT_DETAIL[aid] && ALERT_DETAIL[aid].aiInvestigatedRuntime);
      }
    } catch (_) {}

    const items = playbooks;
    if (!items.length) return;

    // Build the V6 rows — always enabled, no investigation gating
    let rows = '';
    items.forEach(pb => {
      const color = pb.risk === 'high' ? '#dc2626' : pb.risk === 'med' ? '#ea580c' : '';
      const style = color ? ` style="color:${color};"` : '';
      const onclick = `hideGraphCtx();V6AV.runEntityAction('${esc(entityId)}','${esc(pb.id)}')`;
      rows += `<div class="ctx-item v6-ctx-section"${style} onclick="${onclick}" title="${esc(pb.desc)}">${esc(pb.icon)} ${esc(pb.name)}</div>`;
    });

    // Append into existing "More actions" body, or create one if missing
    let moreBody = ctx.querySelector('.ctx-more-body');
    if (moreBody) {
      moreBody.insertAdjacentHTML('beforeend', rows);
    } else {
      const wrap = document.createElement('div');
      wrap.innerHTML = `<div class="ctx-sep"></div>
        <div class="ctx-more-toggle" onclick="this.classList.toggle('expanded');this.nextElementSibling.classList.toggle('expanded');if(typeof reclampCtxMenu==='function')reclampCtxMenu()">
          <span>More actions</span><span class="ctx-chevron">▸</span>
        </div>
        <div class="ctx-more-body">${rows}</div>`;
      while (wrap.firstChild) ctx.appendChild(wrap.firstChild);
    }

    // Re-clamp menu size after content added
    if (typeof window.reclampCtxMenu === 'function') {
      try { window.reclampCtxMenu(); } catch (_) {}
    }
  }

  /* ─── ACTIONS BUTTON + DROPDOWN (slider header) ─────────────────── */
  function injectActionsButton(entityId) { /* deprecated — V6 actions now live in graph context menu */ }

  function injectReachabilityStrip(entityId) {
    const slider = document.getElementById('entitySlider');
    if (!slider) return;
    const body = document.getElementById('edsBody');
    if (!body) return;
    // HIDDEN for all entities (per product decision 27 May 2026):
    // Reachability section is suppressed in the entity slider. We still clear
    // any stale card that an earlier render may have left in the DOM, then
    // bail out before constructing a new one.
    body.querySelectorAll('.v6-reach-card').forEach(c => c.remove());
    return;
    // eslint-disable-next-line no-unreachable
    // Mount inside the Overview tab panel (not the slider body root, so it
    // doesn't leak into Activity / Alerts / etc. tabs).
    const overview = body.querySelector('.eds-tab-panel[data-tab="overview"]');
    const host = overview || body;
    // Remove any prior card from anywhere in the slider
    body.querySelectorAll('.v6-reach-card').forEach(c => c.remove());

    /* Gate on AI investigation: before "Start Investigation" is clicked,
       the attack-vector graph is in partial mode and reachability counts
       would be misleading (they'd reflect only the visible subset).
       Show the full reachability card only after AI investigation runs. */
    let det = null;
    try {
      const aid = (typeof currentAlertId !== 'undefined') ? currentAlertId : null;
      if (aid && typeof ALERT_DETAIL !== 'undefined') det = ALERT_DETAIL[aid];
    } catch (_) { /* globals not loaded yet */ }
    if (!det || !det.aiInvestigatedRuntime) return;

    const svg = document.getElementById('graphSvg');
    if (!svg) return;
    const dist = bfsHops(svg, entityId, 3);
    // Group entities by hop distance, capture readable names + ids.
    // Reachability lists only INVESTIGABLE entities — strip alerts (the
    // alert chip is itself an event, not an entity the analyst can act on)
    // and location nodes (geo blobs aren't actionable in a containment
    // workflow). Process / device / user / service / ip / domain remain.
    const ENT_MAP = (typeof ENTITIES !== "undefined" ? ENTITIES : (window.ENTITIES || {}));
    const isExcludedEntity = (id) => {
      const en = ENT_MAP[id];
      if (!en) return /^loc-/i.test(id);   // unknown loc-* nodes from the graph
      if (en.type === 'alert') return true;
      if (en.type === 'location') return true;
      if (/^loc-/i.test(id)) return true;
      return false;
    };
    const buckets = { 1: [], 2: [], 3: [] };
    dist.forEach((d, id) => {
      if (id === entityId || d < 1 || d > 3) return;
      if (isExcludedEntity(id)) return;
      const en = ENT_MAP[id];
      const nm = en ? (en.modalTitle.split('·').pop()?.trim() || id) : id;
      buckets[d].push({ id, name: nm });
    });
    const h1 = buckets[1].length, h2 = buckets[2].length, h3 = buckets[3].length;
    const total = h1 + h2 + h3;
    const e = (typeof ENTITIES !== "undefined" ? ENTITIES : (window.ENTITIES || {}))[entityId];
    const name = e ? (e.modalTitle.split('·').pop()?.trim() || entityId) : entityId;

    /* Render a single pill · if the entity carries semantic tags
       (crown-jewel, pci-scope, compromised, ...) attach inline badges so the
       analyst immediately sees *which* reachable entities are sensitive.
       Each pill ends with a "+ tag" affordance that opens the Manage-tags
       panel for that specific entity (not the slider's parent entity). */
    const renderPill = (n) => {
      const tags = getTagsFor(n.id);
      const badges = tags
        .map(t => V6_TAG_BADGES[t])
        .filter(Boolean)
        .map(b => `<span class="v6-tagbadge ${b.cls}" title="${esc(b.label)}">${b.icon} ${esc(b.label)}</span>`)
        .join('');
      const tagBtn = `<button type="button" class="v6-reach-pill-tag" title="Manage tags for ${esc(n.name)}" onclick="event.stopPropagation();V6AV.runEntityAction('${esc(n.id)}','manageTags')">+ tag</button>`;
      return `<span class="v6-reach-pill${badges ? ' v6-reach-pill-tagged' : ''}">${esc(n.name)}${badges}${tagBtn}</span>`;
    };
    const sample = (arr, max = 4) => {
      if (!arr.length) return '<em style="color:#9ca3af;">none</em>';
      const visible = arr.slice(0, max).map(renderPill).join('');
      if (arr.length <= max) return visible;
      const hiddenFixed = arr.slice(max).map(n => {
        const tags = getTagsFor(n.id);
        const badges = tags.map(t => V6_TAG_BADGES[t]).filter(Boolean)
          .map(b => `<span class="v6-tagbadge ${b.cls}" title="${esc(b.label)}">${b.icon} ${esc(b.label)}</span>`).join('');
        const tagBtn = `<button type="button" class="v6-reach-pill-tag" title="Manage tags for ${esc(n.name)}" onclick="event.stopPropagation();V6AV.runEntityAction('${esc(n.id)}','manageTags')">+ tag</button>`;
        return `<span class="v6-reach-pill v6-reach-pill-extra${badges ? ' v6-reach-pill-tagged' : ''}" hidden>${esc(n.name)}${badges}${tagBtn}</span>`;
      }).join('');
      const more = `<button type="button" class="v6-reach-more" data-extra="${arr.length - max}">+${arr.length - max} more</button>`;
      return visible + hiddenFixed + more;
    };

    /* Build a "Sensitive reachables" callout summarizing tagged entities
       across all hops · so the analyst sees "crown-jewel touched" instantly. */
    const allReach = [].concat(buckets[1], buckets[2], buckets[3]);
    const tagged = allReach
      .map(n => ({ n, tags: getTagsFor(n.id).filter(t => V6_TAG_BADGES[t]) }))
      .filter(x => x.tags.length);
    const callout = tagged.length ? `
      <div class="v6-reach-callout">
        <div class="v6-reach-callout-hdr">\u2728 Sensitive reachables \u00b7 ${tagged.length} tagged entit${tagged.length === 1 ? 'y' : 'ies'} in blast zone</div>
        <div class="v6-reach-callout-list">
          ${tagged.map(x => {
            const badges = x.tags.map(t => V6_TAG_BADGES[t]).map(b =>
              `<span class="v6-tagbadge ${b.cls}">${b.icon} ${esc(b.label)}</span>`).join('');
            return `<div class="v6-reach-callout-row"><strong>${esc(x.n.name)}</strong> ${badges}</div>`;
          }).join('')}
        </div>
      </div>` : '';

    const card = document.createElement('div');
    card.className = 'v6-reach-card';
    card.innerHTML = `
      <div class="v6-reach-card-hdr">
        <span class="v6-reach-card-icon">🧭</span>
        <span class="v6-reach-card-title">Reachability</span>
        <span class="v6-reach-card-total">${total} entities · within 3 hops</span>
      </div>
      <div class="v6-reach-card-explain">
        A <strong>hop</strong> is one jump along a line on the attack-vector graph. From <strong>${esc(name)}</strong>, the entities below sit 1, 2 or 3 jumps away. Acting on this entity (block / disable / isolate) primarily breaks the 1-hop links; 2- and 3-hop entities become unreachable as a side effect.
      </div>
      ${callout}
      <div class="v6-reach-rows">
        <div class="v6-reach-row h1">
          <div class="v6-reach-row-num"><span class="v6-reach-num">${h1}</span></div>
          <div class="v6-reach-row-body">
            <div class="v6-reach-row-title">1 hop away — directly connected</div>
            <div class="v6-reach-row-sub">Reached in <strong>1 jump</strong>. These have an edge straight to ${esc(name)} on the graph.</div>
            <div class="v6-reach-row-list">${sample(buckets[1])}</div>
          </div>
        </div>
        <div class="v6-reach-row h2">
          <div class="v6-reach-row-num"><span class="v6-reach-num">${h2}</span></div>
          <div class="v6-reach-row-body">
            <div class="v6-reach-row-title">2 hops away — one entity in between</div>
            <div class="v6-reach-row-sub">Reached in <strong>2 jumps</strong> (via one of the 1-hop entities above).</div>
            <div class="v6-reach-row-list">${sample(buckets[2])}</div>
          </div>
        </div>
        <div class="v6-reach-row h3">
          <div class="v6-reach-row-num"><span class="v6-reach-num">${h3}</span></div>
          <div class="v6-reach-row-body">
            <div class="v6-reach-row-title">3 hops away — two entities in between</div>
            <div class="v6-reach-row-sub">Reached in <strong>3 jumps</strong>. Outer rim of the blast zone.</div>
            <div class="v6-reach-row-list">${sample(buckets[3])}</div>
          </div>
        </div>
      </div>
    `;
    host.appendChild(card);

    // Expand/collapse "+N more" → reveals the rest of the hidden pills inline
    card.querySelectorAll('.v6-reach-more').forEach(btn => {
      btn.addEventListener('click', () => {
        const row = btn.closest('.v6-reach-row-list');
        if (!row) return;
        const expanded = btn.classList.toggle('open');
        row.querySelectorAll('.v6-reach-pill-extra').forEach(p => { p.hidden = !expanded; });
        btn.textContent = expanded ? 'show less' : `+${btn.dataset.extra} more`;
      });
    });
  }

  /* ─── 4.A.3  PER-ENTITY ACTIONS CARD (mounted in Overview tab) ─── */
  function injectActionsCard(entityId) {
    console.log('[V6AV] injectActionsCard called for', entityId);
    const slider = document.getElementById('entitySlider');
    if (!slider) { console.warn('[V6AV] no #entitySlider'); return; }
    const body = document.getElementById('edsBody');
    if (!body) { console.warn('[V6AV] no #edsBody'); return; }
    const overview = body.querySelector('.eds-tab-panel[data-tab="overview"]');
    const host = overview || body;
    console.log('[V6AV] host =', host === overview ? 'overview panel' : 'edsBody fallback');
    body.querySelectorAll('.v6-actions-card').forEach(c => c.remove());

    // Gate same as reachability: only after Start Investigation completes
    let det = null;
    try {
      const aid = (typeof currentAlertId !== 'undefined') ? currentAlertId : null;
      if (aid && typeof ALERT_DETAIL !== 'undefined') det = ALERT_DETAIL[aid];
    } catch (_) {}
    if (!det || !det.aiInvestigatedRuntime) {
      console.warn('[V6AV] actions card gated: aiInvestigatedRuntime is false');
      return;
    }

    const e = (typeof ENTITIES !== 'undefined' ? ENTITIES : (window.ENTITIES || {}))[entityId];
    if (!e) { console.warn('[V6AV] no entity for', entityId); return; }
    console.log('[V6AV] entity type:', e.type);
    const playbooks = V6_PLAYBOOKS_BY_TYPE[e.type] || [];
    if (!playbooks.length) {
      console.warn('[V6AV] no playbooks for entity type:', e.type, 'entityId:', entityId);
      const empty = document.createElement('div');
      empty.className = 'v6-actions-card';
      empty.innerHTML = `
        <div class="v6-actions-hdr">
          <span class="v6-actions-icon">⚡</span>
          <span class="v6-actions-title">Response actions</span>
          <span class="v6-actions-count">type: ${esc(e.type)}</span>
        </div>
        <div class="v6-actions-explain">No actions defined for entity type <strong>${esc(e.type)}</strong> yet.</div>`;
      host.appendChild(empty);
      return;
    }
    const name = e.modalTitle.split('·').pop()?.trim() || entityId;

    const card = document.createElement('div');
    card.className = 'v6-actions-card';
    card.innerHTML = `
      <div class="v6-actions-hdr">
        <span class="v6-actions-icon">⚡</span>
        <span class="v6-actions-title">Response actions</span>
        <span class="v6-actions-count">${playbooks.length} available</span>
      </div>
      <div class="v6-actions-explain">
        Recommended actions for <strong>${esc(name)}</strong>. Each is tagged with a verb
        — <span class="v6-verb v6-verb-contain">CONTAIN</span> stops the bleeding,
        <span class="v6-verb v6-verb-disrupt">DISRUPT</span> breaks the attacker\u2019s foothold,
        <span class="v6-verb v6-verb-investigate">INVESTIGATE</span> pivots for more data,
        <span class="v6-verb v6-verb-hygiene">HYGIENE</span> is bookkeeping.
      </div>
      <div class="v6-actions-list">
        ${playbooks.map(pb => `
          <div class="v6-act-row" data-verb="${pb.verb}">
            <div class="v6-act-icon">${esc(pb.icon)}</div>
            <div class="v6-act-body">
              <div class="v6-act-title-line">
                <span class="v6-act-name">${esc(pb.name)}</span>
                <span class="v6-verb ${V6_VERBS[pb.verb].cls}">${V6_VERBS[pb.verb].label}</span>
                <span class="v6-act-risk v6-act-risk-${pb.risk}" title="Blast radius if this action is wrong">Blast radius: ${pb.risk.toUpperCase()}</span>
                ${pb.eta && pb.eta !== 'instant' ? `<span class="v6-act-eta" title="How long this takes to complete">Takes ${esc(pb.eta)}</span>` : ''}
                ${pb.reversible ? '<span class="v6-act-rev" title="You can undo this from Action history">↺ Can undo</span>' : ''}
              </div>
              <div class="v6-act-desc">${esc(pb.desc)}</div>
            </div>
            <button class="v6-act-run" data-eid="${esc(entityId)}" data-pid="${esc(pb.id)}">
              ${pb.verb === 'investigate' ? '↗ Open' : '▶ Run'}
            </button>
          </div>
        `).join('')}
      </div>
    `;
    host.appendChild(card);
    // Pin to top of overview panel so it's always visible above other sections.
    if (host.firstChild && host.firstChild !== card) {
      host.insertBefore(card, host.firstChild);
    }
    console.log('[V6AV] actions card appended; in DOM:', !!document.querySelector('.v6-actions-card'));

    // Wire Run buttons
    card.querySelectorAll('.v6-act-run').forEach(btn => {
      btn.addEventListener('click', () => {
        runEntityAction(btn.dataset.eid, btn.dataset.pid);
      });
    });
  }

  /* Resolve action def, optionally show confirm modal, then execute. */
  function runEntityAction(entityId, playbookId) {
    const e = (typeof ENTITIES !== 'undefined' ? ENTITIES : (window.ENTITIES || {}))[entityId];
    if (!e) return;
    const list = V6_PLAYBOOKS_BY_TYPE[e.type] || [];
    const pb = list.find(p => p.id === playbookId);
    if (!pb) return;
    const name = e.modalTitle.split('·').pop()?.trim() || entityId;

    const exec = () => {
      // The "Investigate entity" playbook (id=goHunt) is the dedicated
      // cost-gated entry point — it should unlock the AI-enriched
      // sections in the slider rather than open a generic log panel.
      if (pb.id === 'goHunt') {
        try {
          const gcEl = document.getElementById('graphContainer');
          const sliderOpen = !!(gcEl && gcEl.classList.contains('slider-open'));
          if (typeof window.openEntitySlider === 'function' && !sliderOpen) {
            window.openEntitySlider(entityId);
          }
          setTimeout(() => { investigateCurrentEntity(entityId); }, sliderOpen ? 0 : 80);
        } catch (err) { console.warn('[V6AV] investigate', err); }
        return;
      }
      // If the action maps to an existing V5 action panel, open it
      // (showActionPanel renders its own per-action UI: inputs, confirm, etc.)
      if (pb.panel && typeof window.showActionPanel === 'function') {
        try {
          // The action panel DOM lives inside the entity slider, so the slider
          // must be open first — same pattern V5 ctx-menu uses.
          // NOTE: #actionPanel is static markup that always exists once the
          // graph is mounted, so we must check the slider-open state on
          // #graphContainer instead — otherwise the panel renders into a
          // collapsed slider and stays invisible on the first invocation.
          const gcEl = document.getElementById('graphContainer');
          const sliderOpen = !!(gcEl && gcEl.classList.contains('slider-open'));
          if (typeof window.openEntitySlider === 'function' && !sliderOpen) {
            window.openEntitySlider(entityId);
          }
          // Defer one tick so slider DOM is mounted before panel renders into it.
          // Use a slightly longer delay on the cold path so the slide-in
          // animation has time to start before we mutate inner content.
          setTimeout(() => {
            try {
              window.showActionPanel(pb.panel, entityId);
              // After the generic panel renders, decorate it with the V6 action
              // context so the user can see WHAT the action actually did.
              decorateActionPanel(pb, e, name);
              // Some V6 hygiene actions (manageTags, notifyManager, assignToMe,
              // markCompromised, addToTiFeed, addDomainToTi) were lazily mapped
              // to panel:'addToIncident' for scaffolding only. Override the
              // body so users don't see the wrong "Select incident" UI.
              renderHygieneActionBody(pb, e, name, entityId);
            }
            catch (err) { console.warn('[V6AV] showActionPanel failed', err); executeEntityAction(pb, name); }
          }, sliderOpen ? 0 : 80);
        }
        catch (err) { console.warn('[V6AV] showActionPanel failed', err); executeEntityAction(pb, name); }
      } else {
        executeEntityAction(pb, name);
      }
    };
    if (pb.confirm) {
      showActionConfirm(pb, name, exec);
    } else {
      exec();
    }
  }

  /* Retitle the V5 action panel + prepend a "what this action did" banner so
     the user sees the V6 action context, not just the generic panel name. */
  function decorateActionPanel(pb, entity, entityName) {
    const title = document.getElementById('apTitle');
    const body  = document.getElementById('apBody');
    const badge = document.getElementById('apBadge');
    if (!title || !body) return;

    // Override the title to reflect the V6 action (e.g. "⛏ Go hunt — m.henderson")
    title.textContent = `${pb.icon} ${pb.name} \u2014 ${entityName}`;

    // Pre-filter banner explains what was applied. The "Pre-filter applied"
    // row only makes sense for INVESTIGATE actions (they run a search query
    // scoped to this entity over the last 30d). For hygiene / contain /
    // disrupt actions there is no search — we're mutating state directly —
    // so showing a pre-filter is misleading. Skip the filter row in those
    // cases but keep the verb-chip + description + ETA/risk metadata.
    const filterByType = {
      user:    `user="${entityName}"`,
      device:  `host="${entityName}"`,
      ip:      `src_ip="${entityName}" OR dst_ip="${entityName}"`,
      service: `app="${entityName}"`,
      process: `process_name="${entityName}"`,
      alert:   `alert_id="${entity.id || entityName}"`,
      domain:  `domain="${entityName}" OR fqdn="${entityName}"`
    };
    const filter = filterByType[entity.type] || `entity="${entityName}"`;
    const verbMeta = V6_VERBS[pb.verb] || { label: pb.verb, blurb: '' };
    const showFilter = pb.verb === 'investigate';

    const banner = document.createElement('div');
    banner.className = 'v6-ap-banner';
    banner.innerHTML = `
      <div class="v6-ap-banner-row">
        <span class="v6-verb ${verbMeta.cls || ''}">${verbMeta.label}</span>
        <span class="v6-ap-banner-desc">${esc(pb.desc)}</span>
      </div>
      ${showFilter ? `
      <div class="v6-ap-banner-filter">
        <span class="v6-ap-banner-label">Pre-filter applied:</span>
        <code>${esc(filter)} \u00b7 last 30d</code>
      </div>` : ''}
      <div class="v6-ap-banner-meta">
        ${pb.eta && pb.eta !== 'instant' ? `Takes <strong>${esc(pb.eta)}</strong> \u00b7 ` : ''}
        Blast radius <strong>${esc(pb.risk)}</strong> \u00b7
        ${pb.reversible ? 'can be undone from Action history' : 'cannot be undone'}
      </div>`;
    // Remove any prior banner from a previous action invocation
    const old = body.querySelector('.v6-ap-banner');
    if (old) old.remove();
    body.insertBefore(banner, body.firstChild);

    // Make the badge reflect the verb color
    if (badge && verbMeta.label) {
      badge.textContent = verbMeta.label;
      badge.className = 'ap-badge v6-verb ' + (verbMeta.cls || '');
      badge.style.display = '';
    }
  }

  /* For V6 hygiene actions that piggyback on the addToIncident panel
     scaffolding · replace the body + footer with the correct per-action UI. */
  function renderHygieneActionBody(pb, entity, entityName, entityId) {
    const id = pb.id;
    const hygieneIds = new Set(['manageTags','notifyManager','assignToMe',
      'markCompromised','addToTiFeed','addDomainToTi','collectForensics']);
    if (!hygieneIds.has(id)) return;

    const title   = document.getElementById('apTitle');
    const body    = document.getElementById('apBody');
    const actions = document.getElementById('apActions');
    if (!body || !actions) return;

    // Preserve the V6 banner we just injected
    const banner = body.querySelector('.v6-ap-banner');
    const bannerHtml = banner ? banner.outerHTML : '';

    if (title) title.textContent = `${pb.icon} ${pb.name} \u2014 ${entityName}`;

    let html = '';
    let footer = '';
    const safeName = esc(entityName);

    if (id === 'manageTags') {
      // Load real tags for this entity from the persistent store
      const existing = getTagsFor(entityId);
      const suggested = ['crown-jewel','pci-scope','quarantined','high-risk','watchlist','contractor','prod-asset','privileged-user'];
      // Filter out suggestions already applied
      const suggestList = suggested.filter(t => !existing.includes(t));
      html = `
        <div class="ap-section">
          <div class="ap-section-title">\ud83c\udff7 Current tags on ${safeName}</div>
          <div class="v6-tag-list" id="v6TagList" data-entity-id="${esc(entityId)}">
            ${existing.map(t => `<span class="v6-tag-chip" data-tag="${esc(t)}">${esc(t)} <span class="v6-tag-x" onclick="this.parentElement.remove()">\u00d7</span></span>`).join('') || '<span class="v6-tag-empty">No tags yet.</span>'}
          </div>
          <div class="v6-info-note">Tags are stored globally per entity and persist across alerts. A device tagged <code>crown-jewel</code> will show as a crown-jewel target in every future alert that touches it.</div>
        </div>
        <div class="ap-section">
          <div class="ap-section-title">+ Add tag</div>
          <div class="v6-tag-input-row">
            <input id="v6TagInput" class="v6-tag-input" type="text" placeholder="Type a tag and press Enter\u2026" onkeydown="if(event.key==='Enter'){event.preventDefault();V6AV._addTagFromInput();}" />
            <button class="ap-btn ap-btn-outline" onclick="V6AV._addTagFromInput()">Add</button>
          </div>
          <div class="v6-tag-suggest-label">Suggested:</div>
          <div class="v6-tag-suggest">
            ${suggestList.map(t => `<span class="v6-tag-suggest-chip" data-suggest="${esc(t)}" onclick="V6AV._addTag('${esc(t)}')">${esc(t)}</span>`).join('') || '<span class="v6-tag-empty">All common tags already applied.</span>'}
          </div>
        </div>`;
      footer = `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-primary" onclick="V6AV._saveTagsFromPanel('${esc(entityId)}','${safeName}')">Save tags</button>`;
    }
    else if (id === 'notifyManager') {
      html = `
        <div class="ap-section">
          <div class="ap-section-title">\u2709 Recipients</div>
          <div class="v6-kv-row"><span class="v6-kv-k">Line manager:</span><span class="v6-kv-v">Sarah Chen &lt;sarah.chen@corp.com&gt;</span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">SOC channel:</span><span class="v6-kv-v">#soc-alerts (Teams)</span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">Cc:</span><span class="v6-kv-v">soc-oncall@corp.com</span></div>
        </div>
        <div class="ap-section">
          <div class="ap-section-title">\u270f Message</div>
          <textarea class="v6-notify-textarea" rows="6">High-risk activity detected on ${safeName}. The SOC is investigating impossible-travel logins originating from a Tor exit node. Please confirm whether ${safeName} authorized any travel or new device enrollment in the last 24h.</textarea>
        </div>`;
      footer = `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-primary" onclick="showToast('\u2709','Notification sent to manager + SOC');closeActionPanel();">Send notification</button>`;
    }
    else if (id === 'assignToMe') {
      html = `
        <div class="ap-section">
          <div class="ap-section-title">\ud83d\udc4b Assign this alert</div>
          <div class="v6-kv-row"><span class="v6-kv-k">Entity:</span><span class="v6-kv-v">${safeName}</span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">Status change:</span><span class="v6-kv-v">New \u2192 In progress</span></div>
          <div class="v6-assignee-picker">
            <label class="v6-assignee-label">Search analyst by name or email</label>
            <input type="text" class="v6-assignee-input" placeholder="Type a name, e.g. Sarah"
              oninput="V6AV._filterAssignees(this)"
              onfocus="V6AV._filterAssignees(this)"
              onblur="setTimeout(function(){var d=document.getElementById('v6AssigneeDd');if(d)d.style.display='none'},200)" />
            <div class="v6-assignee-dd" id="v6AssigneeDd"></div>
            <div class="v6-assignee-selected" id="v6AssigneeSelected">
              <span class="v6-assignee-chip v6-assignee-empty">No assignee selected</span>
            </div>
          </div>
          <div class="v6-info-note">Selected analyst will receive all follow-up notifications for this alert. Reassign anytime from the alert header.</div>
        </div>`;
      footer = `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-outline" onclick="V6AV._assignToSelf()">Assign to me</button>
        <button class="ap-btn ap-btn-primary" id="v6AssignBtn" disabled onclick="V6AV._commitAssignee()">Assign</button>`;
    }
    else if (id === 'markCompromised') {
      html = `
        <div class="ap-section">
          <div class="ap-section-title">\u26a0 Mark ${safeName} as compromised</div>
          <div class="v6-info-note v6-info-warn">This raises the entity's UEBA risk score to 100 and tightens monitoring rules. Reversible from the entity profile.</div>
          <div class="v6-kv-row"><span class="v6-kv-k">UEBA risk:</span><span class="v6-kv-v">current 72 \u2192 <strong>100</strong></span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">Tag added:</span><span class="v6-kv-v">compromised, watchlist</span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">Rules tightened:</span><span class="v6-kv-v">+12 detections for this entity</span></div>
        </div>`;
      footer = `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-danger" onclick="showToast('\u26a0','${safeName} marked as compromised');closeActionPanel();">Mark compromised</button>`;
    }
    else if (id === 'addToTiFeed' || id === 'addDomainToTi') {
      const kind = entity.type === 'domain' ? 'FQDN' : (entity.type === 'ip' ? 'IP' : 'indicator');
      html = `
        <div class="ap-section">
          <div class="ap-section-title">\ud83d\udd0d Add ${kind} to internal threat-intel feed</div>
          <div class="v6-kv-row"><span class="v6-kv-k">${kind}:</span><span class="v6-kv-v"><code>${safeName}</code></span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">Feed:</span><span class="v6-kv-v">internal-blocklist (auto-syncs to SIEM + proxy)</span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">Confidence:</span>
            <span class="v6-kv-v">
              <select class="v6-select"><option>High</option><option selected>Medium</option><option>Low</option></select>
            </span>
          </div>
          <div class="v6-kv-row"><span class="v6-kv-k">Expires:</span>
            <span class="v6-kv-v">
              <select class="v6-select"><option>7 days</option><option selected>30 days</option><option>90 days</option><option>Never</option></select>
            </span>
          </div>
          <div class="ap-section-title" style="margin-top:10px;">\u270f Note</div>
          <textarea class="v6-notify-textarea" rows="3">Observed during impossible-travel investigation on ${safeName}.</textarea>
        </div>`;
      footer = `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-primary" onclick="showToast('\ud83d\udd0d','${safeName} added to internal TI feed');closeActionPanel();">Add to feed</button>`;
    }
    else if (id === 'collectForensics') {
      html = `
        <div class="ap-section">
          <div class="ap-section-title">\ud83d\udcbe Forensic package \u2014 ${safeName}</div>
          <div class="v6-info-note">CrowdStrike RTR session opens to the host, runs the bundle below, packages the output as a single <code>.zip</code> in the case folder, and computes a SHA-256 for chain-of-custody. Typical run: ~3 minutes; host stays online.</div>
          <div class="v6-kv-row"><span class="v6-kv-k">Target host:</span><span class="v6-kv-v"><code>${safeName}</code></span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">Operator:</span><span class="v6-kv-v">You (johnson.williams@corp.com)</span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">Case folder:</span><span class="v6-kv-v"><code>/forensics/INC-2026-05-11-001/${esc(entityId || 'entity')}/</code></span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">Output:</span><span class="v6-kv-v">${safeName}_forensic_$(timestamp).zip + .sha256</span></div>
        </div>
        <div class="ap-section">
          <div class="ap-section-title">\u2611 What gets collected</div>
          <div class="v6-forensic-list">
            <label class="v6-forensic-row"><input type="checkbox" checked /> <strong>Memory dump</strong> <span class="v6-forensic-sub">winpmem full RAM image (~4\u20138 GB)</span></label>
            <label class="v6-forensic-row"><input type="checkbox" checked /> <strong>Sysmon export</strong> <span class="v6-forensic-sub">last 24h of channel <code>Microsoft-Windows-Sysmon/Operational</code> as .evtx</span></label>
            <label class="v6-forensic-row"><input type="checkbox" checked /> <strong>Recent file deltas</strong> <span class="v6-forensic-sub">files created or modified in last 24h under <code>C:\\Users\\*</code>, <code>%TEMP%</code>, <code>C:\\ProgramData</code></span></label>
            <label class="v6-forensic-row"><input type="checkbox" checked /> <strong>Network state</strong> <span class="v6-forensic-sub">netstat -ano + arp -a + ipconfig /all + DNS cache</span></label>
            <label class="v6-forensic-row"><input type="checkbox" checked /> <strong>Persistence artifacts</strong> <span class="v6-forensic-sub">scheduled tasks, services, Run keys, WMI subscriptions</span></label>
            <label class="v6-forensic-row"><input type="checkbox" /> <strong>Browser artifacts</strong> <span class="v6-forensic-sub">Edge/Chrome history + cookies + downloads (last 7d)</span></label>
            <label class="v6-forensic-row"><input type="checkbox" /> <strong>Full disk image</strong> <span class="v6-forensic-sub">dd-style raw image (slow \u2014 add ~45m, ~120 GB)</span></label>
          </div>
        </div>
        <div class="ap-section">
          <div class="ap-section-title">\ud83d\udd12 Chain of custody</div>
          <div class="v6-kv-row"><span class="v6-kv-k">Encryption:</span><span class="v6-kv-v">AES-256 (case-folder key)</span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">Hash:</span><span class="v6-kv-v">SHA-256 logged to incident audit trail</span></div>
          <div class="v6-kv-row"><span class="v6-kv-k">Retention:</span>
            <span class="v6-kv-v"><select class="v6-select"><option>30 days</option><option selected>90 days</option><option>1 year</option><option>Legal hold</option></select></span>
          </div>
        </div>`;
      footer = `<button class="ap-btn ap-btn-outline" onclick="closeActionPanel()">Cancel</button>
        <button class="ap-btn ap-btn-primary" onclick="showToast('\ud83d\udcbe','Forensic collection queued for ${safeName} \u00b7 ETA 3m');closeActionPanel();">Start collection</button>`;
    }

    body.innerHTML = bannerHtml + html;
    actions.innerHTML = footer;
    actions.style.display = 'flex';
  }

  /* Helpers for the manageTags mini-panel */
  function _addTag(label) {
    const list = document.getElementById('v6TagList');
    if (!list) return;
    const empty = list.querySelector('.v6-tag-empty');
    if (empty) empty.remove();
    // Skip duplicates
    const existing = Array.from(list.querySelectorAll('.v6-tag-chip'))
      .map(c => c.dataset.tag);
    if (existing.includes(label)) return;
    const chip = document.createElement('span');
    chip.className = 'v6-tag-chip';
    chip.dataset.tag = label;
    chip.innerHTML = `${esc(label)} <span class="v6-tag-x" onclick="this.parentElement.remove()">\u00d7</span>`;
    list.appendChild(chip);
    // Hide the matching suggestion chip so the user can't add it twice
    const sugg = document.querySelector(`.v6-tag-suggest-chip[data-suggest="${label}"]`);
    if (sugg) sugg.remove();
  }
  function _addTagFromInput() {
    const input = document.getElementById('v6TagInput');
    if (!input) return;
    const v = (input.value || '').trim();
    if (!v) return;
    _addTag(v);
    input.value = '';
    input.focus();
  }
  /* Persist the tags currently shown in the panel to the global store. */
  function _saveTagsFromPanel(entityId, entityName) {
    const list = document.getElementById('v6TagList');
    if (!list) return;
    const tags = Array.from(list.querySelectorAll('.v6-tag-chip'))
      .map(c => c.dataset.tag).filter(Boolean);
    setTagsFor(entityId, tags);
    if (typeof window.showToast === 'function') {
      window.showToast('\ud83c\udff7', tags.length
        ? `Tags saved for ${entityName}: ${tags.join(', ')}`
        : `All tags cleared for ${entityName}`);
    }
    // Re-render the reach card so newly-tagged entities surface immediately
    try { injectReachabilityStrip(window.currentEntityId || entityId); } catch (_) {}
    if (typeof window.closeActionPanel === 'function') window.closeActionPanel();
  }

  /* ─── Assignee picker (Assign-to action) ───────────────────────────
     Demo roster of SOC analysts. In a real product this comes from the
     SOC team directory API (Azure AD group, Okta group, etc.). */
  const V6_ASSIGNEES = [
    { name:'Sarah Chen',        email:'sarah.chen@corp.com',        role:'SOC Tier-2',  initial:'SC' },
    { name:'Johnson Williams',  email:'johnson.williams@corp.com',  role:'SOC Tier-2',  initial:'JW' },
    { name:'Raj Patel',         email:'raj.patel@corp.com',         role:'SOC Tier-3',  initial:'RP' },
    { name:'Elena Rodriguez',   email:'elena.rodriguez@corp.com',   role:'SOC Lead',    initial:'ER' },
    { name:'Marcus Thompson',   email:'marcus.thompson@corp.com',   role:'SOC Tier-1',  initial:'MT' },
    { name:'Priya Iyer',        email:'priya.iyer@corp.com',        role:'IR Engineer', initial:'PI' },
    { name:'David Kim',         email:'david.kim@corp.com',         role:'SOC Tier-2',  initial:'DK' },
    { name:'Aisha Okonkwo',     email:'aisha.okonkwo@corp.com',     role:'Threat Hunter', initial:'AO' },
    { name:'Tom Becker',        email:'tom.becker@corp.com',        role:'SOC Manager', initial:'TB' }
  ];
  let _v6PickedAssignee = null;

  function _filterAssignees(inputEl) {
    const dd = document.getElementById('v6AssigneeDd');
    if (!dd) return;
    const q = (inputEl.value || '').trim().toLowerCase();
    const matches = V6_ASSIGNEES.filter(a =>
      !q || a.name.toLowerCase().includes(q) || a.email.toLowerCase().includes(q)
    ).slice(0, 6);
    if (!matches.length) {
      dd.innerHTML = '<div class="v6-assignee-empty-row">No analysts match</div>';
    } else {
      dd.innerHTML = matches.map(a => `
        <div class="v6-assignee-row" onmousedown="V6AV._pickAssignee('${esc(a.email)}')">
          <span class="v6-assignee-avatar">${esc(a.initial)}</span>
          <span class="v6-assignee-meta">
            <span class="v6-assignee-name">${esc(a.name)}</span>
            <span class="v6-assignee-sub">${esc(a.role)} \u00b7 ${esc(a.email)}</span>
          </span>
        </div>
      `).join('');
    }
    dd.style.display = 'block';
  }

  function _pickAssignee(email) {
    const a = V6_ASSIGNEES.find(x => x.email === email);
    if (!a) return;
    _v6PickedAssignee = a;
    const sel = document.getElementById('v6AssigneeSelected');
    if (sel) {
      sel.innerHTML = `
        <span class="v6-assignee-chip">
          <span class="v6-assignee-avatar">${esc(a.initial)}</span>
          <span class="v6-assignee-name">${esc(a.name)}</span>
          <span class="v6-assignee-sub">${esc(a.role)}</span>
          <span class="v6-assignee-x" onclick="V6AV._clearAssignee()">\u00d7</span>
        </span>`;
    }
    const input = document.querySelector('.v6-assignee-input');
    if (input) input.value = a.name;
    const dd = document.getElementById('v6AssigneeDd');
    if (dd) dd.style.display = 'none';
    const btn = document.getElementById('v6AssignBtn');
    if (btn) btn.disabled = false;
  }

  function _clearAssignee() {
    _v6PickedAssignee = null;
    const sel = document.getElementById('v6AssigneeSelected');
    if (sel) sel.innerHTML = '<span class="v6-assignee-chip v6-assignee-empty">No assignee selected</span>';
    const input = document.querySelector('.v6-assignee-input');
    if (input) input.value = '';
    const btn = document.getElementById('v6AssignBtn');
    if (btn) btn.disabled = true;
  }

  function _assignToSelf() {
    _pickAssignee('johnson.williams@corp.com');
    _commitAssignee();
  }

  function _commitAssignee() {
    if (!_v6PickedAssignee) return;
    const a = _v6PickedAssignee;
    if (typeof window.showToast === 'function') {
      window.showToast('\ud83d\udc4b', `Alert assigned to ${a.name} (${a.role})`);
    }
    _v6PickedAssignee = null;
    if (typeof window.closeActionPanel === 'function') window.closeActionPanel();
  }

  function executeEntityAction(pb, entityName) {
    const v = V6_VERBS[pb.verb];
    // Step 1 · "queued" toast
    if (typeof window.showToast === 'function') {
      window.showToast(pb.icon, `${pb.name} \u2192 ${entityName} · queued (${v.label})`);
    }
    // Step 2 · "completed" toast after eta (simulated)
    const delay = /m$/.test(pb.eta) ? 2000 : /s$/.test(pb.eta) ? 1200 : 600;
    setTimeout(() => {
      if (typeof window.showToast === 'function') {
        const verbPast = pb.verb === 'contain' ? 'Contained'
                       : pb.verb === 'disrupt' ? 'Disrupted'
                       : pb.verb === 'investigate' ? 'Pivoted' : 'Updated';
        window.showToast('✓', `${verbPast}: ${pb.name} on ${entityName}${pb.reversible ? ' · reversible from Action history' : ''}`);
      }
    }, delay);
  }

  /* Lightweight confirm modal for high-risk actions */
  function showActionConfirm(pb, entityName, onConfirm) {
    let modal = document.getElementById('v6ActConfirm');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'v6ActConfirm';
      modal.className = 'v6-act-confirm-overlay';
      document.body.appendChild(modal);
    }
    const v = V6_VERBS[pb.verb];
    modal.innerHTML = `
      <div class="v6-act-confirm-card">
        <div class="v6-act-confirm-hdr">
          <span class="v6-act-confirm-icon">${esc(pb.icon)}</span>
          <span class="v6-act-confirm-title">${esc(pb.name)}</span>
          <span class="v6-verb ${v.cls}">${v.label}</span>
        </div>
        <div class="v6-act-confirm-target">Target: <strong>${esc(entityName)}</strong></div>
        <div class="v6-act-confirm-desc">${esc(pb.desc)}</div>
        <ul class="v6-act-confirm-meta">
          <li><strong>Blast radius:</strong> ${pb.risk.toUpperCase()}</li>
          <li><strong>Time to complete:</strong> ${esc(pb.eta)}</li>
          <li><strong>Can undo?:</strong> ${pb.reversible ? 'Yes \u2014 from Action history' : 'No \u2014 effect is permanent'}</li>
        </ul>
        <div class="v6-act-confirm-actions">
          <button class="v6-act-confirm-cancel">Cancel</button>
          <button class="v6-act-confirm-ok">Confirm \u2014 Run ${esc(pb.name)}</button>
        </div>
      </div>
    `;
    modal.classList.add('open');
    modal.querySelector('.v6-act-confirm-cancel').onclick = () => modal.classList.remove('open');
    modal.querySelector('.v6-act-confirm-ok').onclick = () => {
      modal.classList.remove('open');
      onConfirm();
    };
  }

  /* ─── 4.B  CHOKE-POINT WIDGET — mounted next to Malicious/Critical pills ─
     Lifecycle:
       1. Graph mounts → state='hidden' → nothing rendered.
       2. Start Investigation completes → state='ready' → "⚡ Analyze choke
          points" CTA replaces the silent gap.
       3. User clicks → state='analyzing' → animated loader pill (~1.5s).
       4. → state='analyzed' → full pill + dropdown shown, choke nodes
          highlighted on the graph, dropdown auto-opens.
       5. "Analyze again" in the dropdown footer re-runs the loader and
          re-ranks (useful after the user expands new nodes that may shift
          which entity is the true choke point). */
  function currentGraphNodeCount() {
    const svg = document.getElementById('graphSvg');
    return svg ? svg.querySelectorAll('g.graph-node').length : 0;
  }

  function renderV6Bar() {
    const anchorPill = document.getElementById('cmdPillThreatIndicators') || document.getElementById('cmdPillCritCount');
    if (!anchorPill || !anchorPill.parentNode) return;
    const existing = document.getElementById('v6Bar');
    if (existing) existing.remove();

    // State 1: hidden — graph mounted but investigation hasn't run yet.
    if (v6ChokeState === 'hidden') return;

    const wrap = document.createElement('span');
    wrap.id = 'v6Bar';
    wrap.className = 'v6-bar-inline';

    // State 2: ready — show the "Analyze choke points" CTA.
    if (v6ChokeState === 'ready') {
      wrap.innerHTML = `
        <button class="v6-bar-toggle cmd-pill cmd-pill-choke v6-choke-cta"
                id="v6ChokeAnalyzeBtn"
                onclick="V6AV.analyzeChokePoints()"
                title="Identify entities whose removal breaks the most attack paths">
          <span class="cmd-pill-dot" style="background:#7c3aed;"></span>
          <span>⚡ Analyze choke points</span>
        </button>`;
      anchorPill.parentNode.insertBefore(wrap, anchorPill.nextSibling);
      return;
    }

    // State 3: analyzing — show animated loader pill.
    if (v6ChokeState === 'analyzing') {
      wrap.innerHTML = `
        <button class="v6-bar-toggle cmd-pill cmd-pill-choke v6-choke-loading" disabled>
          <span class="v6-choke-spinner"></span>
          <span>Analyzing graph\u2026</span>
        </button>`;
      anchorPill.parentNode.insertBefore(wrap, anchorPill.nextSibling);
      return;
    }

    // State 4: analyzed — full pill + dropdown (existing rich UI).
    const newCount = currentGraphNodeCount();
    const grew = v6NodeCountAtAnalyze > 0 && newCount > v6NodeCountAtAnalyze;
    const newNodes = grew ? (newCount - v6NodeCountAtAnalyze) : 0;
    wrap.innerHTML = `
      <div class="v6-choke-wrap">
        <button class="v6-bar-toggle cmd-pill cmd-pill-choke" id="v6ChokeToggle" onclick="V6AV.toggleChoke()" title="List the entities whose removal breaks the most attack paths">
          <span class="cmd-pill-dot" style="background:#7c3aed;"></span>
          <span class="cmd-pill-num" id="v6ChokeCount">${V6_CHOKE_POINTS.length}</span>
          <span>Choke points</span>
          <span class="cmd-pill-caret">▾</span>
        </button>
        <div class="v6-choke-panel" id="v6ChokePanel">
          <div class="v6-choke-panel-hdr">
            <span>⛓ Choke points — ranked by alerts prevented</span>
            <span class="v6-choke-panel-sub">Click any row to open its response actions</span>
          </div>
          ${grew ? `
            <div class="v6-choke-stale-banner">
              <span>🔄 <strong>${newNodes}</strong> new entit${newNodes === 1 ? 'y' : 'ies'} expanded since last analysis — ranks may have shifted.</span>
              <button class="v6-choke-stale-cta" onclick="V6AV.analyzeChokePoints()">Analyze again</button>
            </div>` : ''}
          ${V6_CHOKE_POINTS.map(eid => {
            const c = V6_CUT_DATA[eid];
            if (!c) return '';
            const e = (typeof ENTITIES !== "undefined" ? ENTITIES : (window.ENTITIES || {}))[eid];
            const name = e ? (e.modalTitle.split('·').pop()?.trim() || eid) : eid;
            const pbCount = (V6_PLAYBOOKS[eid] || []).length;
            return `
              <div class="v6-choke-row" onclick="V6AV.openCutPanel('${eid}')">
                <span class="v6-choke-row-rank r${c.rank}">#${c.rank}</span>
                <span class="v6-choke-row-icon">${esc(c.icon)}</span>
                <div class="v6-choke-row-body">
                  <div class="v6-choke-row-name">${esc(name)}</div>
                  <div class="v6-choke-row-sub">${esc(c.title.split('—')[0].trim())} · prevents <strong>${c.metrics.prevented.num}</strong> alerts/7d · ${pbCount} playbooks</div>
                </div>
                <button class="v6-choke-row-cta" onclick="event.stopPropagation();V6AV.openCutPanel('${eid}')">▶ Actions</button>
              </div>`;
          }).join('')}
          <div class="v6-choke-panel-ftr">
            <button class="v6-choke-ftr-btn" onclick="V6AV.analyzeChokePoints()" title="Re-rank choke points using the current graph (includes any nodes you expanded)">
              🔄 Analyze again
            </button>
          </div>
        </div>
      </div>`;
    anchorPill.parentNode.insertBefore(wrap, anchorPill.nextSibling);
    if (v6ChokeOn) { applyChokePoints(); markChokeToggle(true); }
  }

  /* Kick off the simulated "analyze graph for choke points" pass.
     In a real product this would call a graph-theory job (betweenness
     centrality / min-cut) against the live attack-vector subgraph. */
  function analyzeChokePoints() {
    v6ChokeState = 'analyzing';
    renderV6Bar();
    setTimeout(() => {
      v6ChokeState = 'analyzed';
      v6NodeCountAtAnalyze = currentGraphNodeCount();
      v6ChokeOn = true;
      renderV6Bar();
      applyChokePoints();
      markChokeToggle(true);
      const panel = document.getElementById('v6ChokePanel');
      if (panel) panel.classList.add('open');
      if (typeof window.showToast === 'function') {
        window.showToast('⛓', `Choke-point analysis complete — ${V6_CHOKE_POINTS.length} entities ranked`);
      }
    }, 1500);
  }

  /* ─── 4.D  ADJACENCY / BFS (used by reachability strip) ─────────── */
  function buildAdjacency(svg) {
    const adj = new Map();
    svg.querySelectorAll('line').forEach(line => {
      const s = line.getAttribute('data-source');
      const t = line.getAttribute('data-target');
      if (!s || !t) return;
      if (!adj.has(s)) adj.set(s, new Set());
      if (!adj.has(t)) adj.set(t, new Set());
      adj.get(s).add(t);
      adj.get(t).add(s);
    });
    return adj;
  }

  function bfsHops(svg, startId, maxHops) {
    const adj = buildAdjacency(svg);
    const dist = new Map([[startId, 0]]);
    const queue = [startId];
    while (queue.length) {
      const cur = queue.shift();
      const d = dist.get(cur);
      if (d >= maxHops) continue;
      (adj.get(cur) || new Set()).forEach(n => {
        if (!dist.has(n)) { dist.set(n, d + 1); queue.push(n); }
      });
    }
    return dist;
  }

  /* ─── 4.D  CHOKE POINTS ──────────────────────────────────────────── */
  function applyChokePoints() {
    const svg = document.getElementById('graphSvg');
    if (!svg) return;
    svg.querySelectorAll('[data-v6-choke]').forEach(n => n.removeAttribute('data-v6-choke'));
    let rank = 1;
    V6_CHOKE_POINTS.forEach(eid => {
      const node = svg.querySelector(`g.graph-node[data-entity="${eid}"]`);
      if (node) node.setAttribute('data-v6-choke', String(rank++));
    });
    svg.classList.add('v6-choke-active');
  }
  function clearChokePoints() {
    const svg = document.getElementById('graphSvg');
    if (!svg) return;
    svg.classList.remove('v6-choke-active');
    svg.querySelectorAll('[data-v6-choke]').forEach(n => n.removeAttribute('data-v6-choke'));
  }
  function markChokeToggle(on) {
    const btn = document.getElementById('v6ChokeToggle');
    if (btn) btn.classList.toggle('on', !!on);
  }
  function toggleChoke() {
    v6ChokeOn = !v6ChokeOn;
    const panel = document.getElementById('v6ChokePanel');
    if (v6ChokeOn) {
      applyChokePoints();
      if (panel) panel.classList.add('open');
    } else {
      clearChokePoints();
      if (panel) panel.classList.remove('open');
    }
    markChokeToggle(v6ChokeOn);
  }

  /* ─── 4.D  CONTEXT MENU — V6 leaves the native menu untouched. ──── */
  function wrapContextMenu() { /* no-op: choke-point actions are surfaced via the
     "Choke points" pill in the toolbar and the V6 row in each entity slider. */ }

  /* ─── 4.E  LEGEND EXTENSION ─────────────────────────────────────── */
  function extendLegend() {
    const legend = document.querySelector('.graph-legend');
    if (!legend || legend.querySelector('.v6-legend-risk')) return;
    const wrap = document.createElement('span');
    wrap.className = 'graph-legend-item v6-legend-risk';
    wrap.innerHTML = `<span class="legend-line-risk"></span><span>Risk-weighted</span>`;
    legend.appendChild(wrap);
  }

  /* ─── 4.F  WORKFLOW PREVIEW MODAL ───────────────────────────────── */
  function ensureWorkflowOverlay() {
    let ov = document.getElementById('v6WfOverlay');
    if (ov) return ov;
    ov = document.createElement('div');
    ov.id = 'v6WfOverlay';
    ov.className = 'v6-wf-overlay';
    ov.addEventListener('click', (e) => { if (e.target === ov) closeWorkflow(); });
    document.body.appendChild(ov);
    return ov;
  }

  function showWorkflow(workflowKey) {
    const wf = V6_WORKFLOWS[workflowKey];
    if (!wf) return;
    const ov = ensureWorkflowOverlay();
    ov.innerHTML = `
      <div class="v6-wf-card">
        <div class="v6-wf-hdr">
          <span style="font-size:14px;">⚡</span>
          <span class="v6-wf-hdr-title">${esc(wf.title)}</span>
          <button class="v6-wf-hdr-close" onclick="V6AV.closeWorkflow()">✕</button>
        </div>
        <div class="v6-wf-body">
          <div class="v6-wf-flow">
            ${wf.nodes.map((n, i) => {
              const arrow = i < wf.nodes.length - 1 ? '<div class="v6-wf-arrow">↓</div>' : '';
              if (n.kind === 'branch') {
                return `<div class="v6-wf-branch">${esc(n.label)}</div>${arrow}`;
              }
              return `
                <div class="v6-wf-node v6-wf-node-${esc(n.kind)}">
                  <div class="v6-wf-node-label">${esc(n.label)}</div>
                  ${n.sub ? `<div class="v6-wf-node-sub">${esc(n.sub)}</div>` : ''}
                </div>${arrow}`;
            }).join('')}
          </div>
        </div>
        <div class="v6-wf-footer">
          <span>Preview · workflow is staged, not yet executed</span>
          <a href="#" onclick="event.preventDefault();V6AV.closeWorkflow();V6AV.openWorkflowModule();">Open in Workflows module →</a>
        </div>
      </div>`;
    ov.classList.add('visible');
  }
  function closeWorkflow() {
    const ov = document.getElementById('v6WfOverlay');
    if (ov) ov.classList.remove('visible');
  }
  function openWorkflowModule() {
    if (typeof window.showToast === 'function') {
      window.showToast('⚡', 'Would open: Workflows → New from template');
    }
  }

  /* ─── TAB BADGE ─────────────────────────────────────────────────── */
  // No-op: V6 badge on tab strip removed per UX request.
  // Also strips any stale V6 badge that prior renders left behind.
  function badgeAttackVectorTab() {
    document.querySelectorAll('.v6-build-badge').forEach(b => b.remove());
  }

  /* ─── MOUNT WRAP ────────────────────────────────────────────────── */
  function wrapMount() {
    if (typeof window.mountAttackGraph !== 'function') return;
    if (window.mountAttackGraph.__v6Wrapped) return;
    const orig = window.mountAttackGraph;
    window.mountAttackGraph = function v6MountAttackGraph() {
      const r = orig.apply(this, arguments);
      // The original rewrites panel.innerHTML, so all our injected DOM is gone.
      // Re-inject after a tick to let V5 finish drawing the SVG.
      setTimeout(() => {
        try { renderV6Bar(); }   catch (e) { console.error('[V6AV] bar', e); }
        try { extendLegend(); }  catch (e) { console.error('[V6AV] legend', e); }
        if (v6ChokeOn) applyChokePoints();
      }, 60);
      return r;
    };
    window.mountAttackGraph.__v6Wrapped = true;
  }

  /* ─── BOOT ──────────────────────────────────────────────────────── */
  /* ─── WRAP startInvestigation → refresh open slider after AI completes ── */
  function wrapStartInvestigation() {
    if (typeof window.startInvestigation !== 'function') return;
    if (window.startInvestigation.__v6Wrapped) return;
    const orig = window.startInvestigation;
    window.startInvestigation = function v6StartInvestigation() {
      const r = orig.apply(this, arguments);
      // Original sets aiInvestigatedRuntime=true inside a 1000ms setTimeout.
      // Wait a bit longer, then refresh reachability + actions for any open slider.
      setTimeout(() => {
        try {
          // Promote the choke-point widget from hidden → ready so the
          // "Analyze choke points" CTA appears next to the Critical pill.
          if (v6ChokeState === 'hidden') {
            v6ChokeState = 'ready';
            renderV6Bar();
          }
          const eid = (typeof sliderEntityId !== 'undefined') ? sliderEntityId
                   : (typeof window.sliderEntityId !== 'undefined') ? window.sliderEntityId
                   : null;
          if (eid) {
            injectReachabilityStrip(eid);
          }
        } catch (e) { console.warn('[V6AV] post-investigation refresh', e); }
      }, 1200);
      return r;
    };
    window.startInvestigation.__v6Wrapped = true;
  }

  function boot() {
    wrapMount();
    wrapShowGraphCtx();
    wrapOpenEntitySlider();
    wrapShowEdgeRelation();
    wrapStartInvestigation();
    badgeAttackVectorTab();
    ensureWorkflowOverlay();
    // If attack-vector tab is already mounted at load time:
    if (document.getElementById('graphSvg')) {
      try { renderV6Bar(); extendLegend(); } catch (e) {}
    }
    // Re-badge tabs whenever tabs are re-rendered (defensive).
    const obs = new MutationObserver(() => badgeAttackVectorTab());
    obs.observe(document.body, { childList: true, subtree: true });
    console.log('[V6AV] booted · open Actions menu on any entity to see V6 CUT row');
  }

  /* ─── PUBLIC API ────────────────────────────────────────────────── */
  window.V6AV = {
    openCutPanel: openCutActionPanel,
    runPlaybook,
    toggleChoke,
    analyzeChokePoints,
    showWorkflow,
    closeWorkflow,
    openWorkflowModule,
    runEntityAction,
    toggleGoHuntMenu,
    runGoHunt,
    toggleSliderActions,
    closeSliderActions,
    investigateCurrentEntity,
    _addTag,
    _addTagFromInput,
    _saveTagsFromPanel,
    _filterAssignees,
    _pickAssignee,
    _clearAssignee,
    _assignToSelf,
    _commitAssignee,
    getTagsFor,
    setTagsFor
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
