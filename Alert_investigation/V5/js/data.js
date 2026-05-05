/* ═══ V5 DATA ═══ */
/* Demo alerts list — used by both list view and to seed the detail view */

const ALERTS = [
  {
    id: 'alert-impossible-travel',
    title: 'Impossible Travel Attack',
    severity: 'crit',
    score: 92,
    severityLabel: 'Critical',
    likeCount: '999+',
    likeIcon: '👍',
    timeGenerated: '07 Jun 2017, 05:02:40',
    assignee: { name: 'Johnson Williams', initials: 'JW' },
    status: 'open',
    statusLabel: 'Open',
    remediation: 'btn',
    remediationLabel: 'Run Playbook',
    desc: 'User <span class="ent">corp\\m.henderson</span> (<span class="ent">10.18.1.81</span>) authenticated successfully malicious-site.in (<span class="ent">185.234.217.19</span>) has been requested by <span class="ent">santhosh-8457</span>',
    tools: ['ai', 'log']
  },
  {
    id: 'alert-software-install',
    title: 'Software Install failure',
    severity: 'med',
    score: 55,
    severityLabel: 'Medium',
    likeCount: '52',
    likeIcon: '👎',
    timeGenerated: '07 Jun 2017, 05:02:40',
    assignee: { name: 'Johnson Williams', initials: 'JW' },
    status: 'remediation',
    statusLabel: 'Under Remediation',
    remediation: 'success',
    remediationLabel: 'Success. View Details',
    desc: 'The application <span class="ent">Firefox 109.0.1</span> was failed to install on <span class="ent">zohocorp.com\\santhosh-8457</span> Reason: Unstable network',
    tools: ['log']
  },
  {
    id: 'alert-malicious-url-1',
    title: 'Malicious URL requests',
    severity: 'crit',
    score: 92,
    severityLabel: 'Critical',
    likeCount: '99+',
    likeIcon: '👍',
    timeGenerated: '07 Jun 2017, 05:02:40',
    assignee: { name: 'Unassigned', initials: '?' , unassigned: true },
    status: 'investig',
    statusLabel: 'Under Investigation',
    remediation: 'btn',
    remediationLabel: 'Run Playbook',
    desc: 'Malicious URL <span class="ent">malicious-site.in</span> (<span class="ent">185.234.217.19</span>) has been requested by <span class="ent">santhosh-8457</span> (<span class="ent">10.18.1.81</span>)',
    tools: ['ai', 'log']
  },
  {
    id: 'alert-malicious-url-2',
    title: 'Malicious URL requests',
    severity: 'med',
    score: 55,
    severityLabel: 'Medium',
    likeCount: '999+',
    likeIcon: '👍',
    timeGenerated: '07 Jun 2017, 05:02:40',
    assignee: { name: 'Unassigned', initials: '?', unassigned: true },
    status: 'remediation',
    statusLabel: 'Under Remediation',
    remediation: 'btn',
    remediationLabel: 'Run Playbook',
    desc: 'Malicious URL <span class="ent">malicious-site.in</span> (<span class="ent">185.234.217.19</span>) has been requested by <span class="ent">santhosh-8457</span> (<span class="ent">10.18.1.81</span>)',
    tools: []
  },
  {
    id: 'alert-account-lockout-1',
    title: 'User Account Lockout Notification',
    severity: 'low',
    score: 36,
    severityLabel: 'Low',
    likeCount: '999+',
    likeIcon: '👍',
    timeGenerated: '07 Jun 2017, 05:02:40',
    assignee: { name: 'Johnson Williams', initials: 'JW' },
    status: 'investig',
    statusLabel: 'Under Investigation',
    remediation: 'btn',
    remediationLabel: 'Run Playbook',
    desc: 'User Account <span class="ent">zohocorp\\santhosh-8457</span> (<span class="ent">185.234.217.19</span>) has been locked out due to multiple failed logon attempts triggered from <span class="ent">DAE-WIN2019-1</span> (<span class="ent">10.18.1.81</span>)',
    tools: ['log']
  },
  {
    id: 'alert-account-lockout-2',
    title: 'User Account Lockout Notification',
    severity: 'vlow',
    score: 15,
    severityLabel: 'Very Low',
    likeCount: '999+',
    likeIcon: '👍',
    timeGenerated: '07 Jun 2017, 05:02:40',
    assignee: { name: 'Johnson Williams', initials: 'JW' },
    status: 'fp',
    statusLabel: 'False Positive',
    remediation: 'btn',
    remediationLabel: 'Run Playbook',
    desc: 'User Account <span class="ent">zohocorp\\santhosh-8457</span> (<span class="ent">185.234.217.19</span>) has been locked out due to multiple failed logon attempts triggered from <span class="ent">DAE-WIN2019-1</span> (<span class="ent">10.18.1.81</span>)',
    tools: ['log']
  },
  {
    id: 'alert-malicious-url-3',
    title: 'Malicious URL requests',
    severity: 'crit',
    score: 92,
    severityLabel: 'Critical',
    likeCount: '999+',
    likeIcon: '👍',
    timeGenerated: '07 Jun 2017, 05:02:40',
    assignee: { name: 'Johnson Williams', initials: 'JW' },
    status: 'rem',
    statusLabel: 'Remediated',
    remediation: 'btn',
    remediationLabel: 'Run Playbook',
    desc: 'Malicious URL <span class="ent">malicious-site.in</span> (<span class="ent">185.234.217.19</span>) has been requested by <span class="ent">santhosh-8457</span>',
    tools: []
  },
  {
    id: 'alert-malicious-url-4',
    title: 'Malicious URL requests',
    severity: 'crit',
    score: 92,
    severityLabel: 'Critical',
    likeCount: '999+',
    likeIcon: '👍',
    timeGenerated: '07 Jun 2017, 05:02:40',
    assignee: { name: 'Johnson Williams', initials: 'JW' },
    status: 'bp',
    statusLabel: 'Benign Positive',
    remediation: 'btn',
    remediationLabel: 'Run Playbook',
    desc: 'Malicious URL <span class="ent">malicious-site.in</span> (<span class="ent">185.234.217.19</span>) has been requested by',
    tools: []
  }
];

/* Sidebar insights for list view */
const SIDEBAR_INSIGHTS = {
  alertProfile: [
    { name: 'Mailbox Permission Change Alert', value: 1400, max: 1400 },
    { name: 'Malicious URL requests', value: 600, max: 1400 },
    { name: 'Azure IAM changes', value: 500, max: 1400 },
    { name: 'Brute force attack', value: 400, max: 1400 },
    { name: 'Brute force attack 1', value: 100, max: 1400 }
  ],
  topSuspects: [
    { name: 'Syed-5516', value: 500 },
    { name: 'jaga-windows 2022', value: 500 },
    { name: 'Ravi-5516', value: 500 },
    { name: 'Raj-5516', value: 500 },
    { name: 'mani-5516', value: 500 }
  ],
  logSource: []
};

/* ═══ ALERT DETAIL DATA (Img_2/3/5) ═══ */
const ALERT_DETAIL = {
  'alert-impossible-travel': {
    title: 'Impossible Travel Attack',
    severityLabel: 'High', severityClass: 'high', score: 80,
    aiInvestigated: true,
    assignee: 'Johnson Williams',
    status: 'Open', statusClass: 'open',
    severity: 'Critical', severityPillClass: 'crit',
    createdTime: '07 Jun 2017, 05:02:40',
    sla: '3 Days 5 Hrs',
    tags: [
      { cat: 'MITRE ATT&CK', label: 'Native API (T1106)' },
      { cat: 'MITRE ATT&CK', label: 'Native API (T1106)' },
      { cat: 'MITRE ATT&CK', label: 'Execution (TA0002)' }
    ],
    devices: [
      { name: 'CORP-WS-045', ip: '192.168.1.22' },
      { name: 'CORP-SRV-01', ip: '192.168.1.22' },
      { name: 'CORP-GW-01', ip: '192.168.1.22' }
    ],
    ips: [],
    files: [],

    /* Overview tab */
    summary: 'User <strong>corp\\m.henderson</strong> (<strong>10.18.1.81</strong>) authenticated successfully from external IP <strong>185.220.101.42</strong> (Tor exit node, Romania) at <strong>2026-03-24 03:12:44</strong>, and then again from internal IP <strong>10.18.1.81</strong> on <strong>CORP-NET</strong> at <strong>2026-03-24 03:41:22</strong> — a gap of only <strong>28 minutes</strong> across geographically impossible locations. This simultaneous presence indicates active credential compromise or concurrent session hijacking. Following the anomalous logins, the account performed suspicious OAuth token generation, accessed the mailbox, and downloaded files from sensitive SharePoint directories. Classified as a <strong>True Positive</strong> — no authorized remote access or travel activity exists for this user. Immediate account suspension, token revocation, and session termination are required.',
    insights: [
      { name: 'Williams', sub: 'zohocorp.com', icon: '👤', score: 92, scoreClass: 'crit', text: '<strong>14 malicious urls</strong> requested by this user in last 7 days' },
      { name: 'jaga-453232', sub: '192.53.61.2', icon: '💻', score: 65, scoreClass: 'high', text: '<strong>6 malicious urls</strong> requested from this device in last 7 days' },
      { name: 'www.malicious-url.in', sub: '10.53.61.2', icon: '🔗', score: 55, scoreClass: 'med', text: 'This URL was accessed from <strong>70 Source IPs</strong> in last 7 days' },
      { name: 'www.malicious-url.in', sub: '10.53.61.2', icon: '🔗', score: 20, scoreClass: 'med', text: 'This URL was accessed from <strong>70 Source IPs</strong> in last 7 days' },
      { name: 'www.malicious-url.in', sub: '10.53.61.2', icon: '🔗', score: 20, scoreClass: 'med', text: 'This URL was accessed from <strong>70 Source IPs</strong> in last 7 days' }
    ],
    relatedAlerts: [
      { url: 'www.priatebay.in', sev: 'crit', score: 92, status: 'open', assign: 'Johnson Williams', match: 'Johnson Williams', matchType: 'user' },
      { url: 'www.utorrent.in', sev: 'vlow', score: 15, status: 'open', assign: 'Johnson Williams', match: 'Maya Thompson', matchType: 'user' },
      { url: 'www.maliciousurl.in', sev: 'high', score: 80, status: 'open', assign: 'Johnson Williams', match: 'kito-987654', matchType: 'user' },
      { url: 'www.priate-bay.in', sev: 'high', score: 80, status: 'open', assign: 'Johnson Williams', match: 'jaga-453232', matchType: 'device' },
      { url: 'www.priate-torrent.in', sev: 'med', score: 55, status: 'open', assign: 'Johnson Williams', match: 'Liam Rodriguez', matchType: 'user' },
      { url: 'www.safe-downloads.in', sev: 'low', score: 36, status: 'open', assign: 'Johnson Williams', match: 'nava-321678', matchType: 'user' },
      { url: 'www.securefiles.net', sev: 'med', score: 55, status: 'open', assign: 'Johnson Williams', match: 'Sophia Patel', matchType: 'user' },
      { url: 'www.torrentworld.org', sev: 'crit', score: 94, status: 'open', assign: 'Johnson Williams', match: 'zelo-456123', matchType: 'user' },
      { url: 'www.filereap.net', sev: 'low', score: 30, status: 'open', assign: 'Johnson Williams', match: 'Ethan Clark', matchType: 'user' },
      { url: 'www.shadowdownloads.com', sev: 'high', score: 78, status: 'open', assign: 'Johnson Williams', match: 'mira-789234', matchType: 'user' },
      { url: 'www.quickshare.in', sev: 'med', score: 50, status: 'open', assign: 'Johnson Williams', match: 'Olivia Nguyen', matchType: 'device' }
    ],

    /* Investigation tab */
    investSummary: 'At <span class="ent">2026-03-24 03:12:44</span>, user <span class="ent">corp\\m.henderson</span> authenticated successfully from <span class="ent">185.220.101.42</span> (Romania, Tor exit node) and again from internal IP <span class="ent">10.18.1.81</span> within 28 minutes a physical travel distance that is impossible.This was followed by confirmed <span class="ent">Impossible Travel attack</span> with suspicious OAuth token generation, mailbox access, and SharePoint file downloads on sensitive directories. Classified as a True Positive no authorized remote access or travel activity exists. Immediate account suspension, token revocation, and session termination are required.',
    recommendations: [
      {
        icon: '▶',
        title: 'Run Additional Playbooks',
        desc: 'Related playbooks — Lateral Movement Containment, Pass-the-Hash Mitigation, NTLM Credential Sweep — are available for this alert. Would you like to execute them?',
        actionLabel: 'Run Playbooks'
      },
      {
        icon: '🔧',
        title: 'Tune  Alerts Profile',
        desc: 'Zia has identified potential threshold misalignment for ARP-type alerts on CORP-NET. Adjusting the alert profile may reduce noise without compromising detection coverage.',
        actionLabel: 'Tune Alert Profile'
      }
    ],
    keyFindings: [
      {
        title: 'Alert Detected',
        text: 'Impossible Travel detected for <span class="ent">corp\\m.henderson</span> with logins from a Tor IP in Romania and <span class="ent">CORP-NET</span> within 28 minutes,  confirming a True positive. Likely credential Compromise or session hijacking; suspend account, revoke tokens, and force password reset immediately.'
      },
      {
        title: 'Token Abuse Confirmed',
        text: 'Suspicious OAuth token generation observed shortly after login. The token was used to access <span class="ent">SharePoint</span> file repositories and download sensitive documents.'
      }
    ]
  }
};

/* User Details (Img_5) for entity slider */
const ENTITY_USER_DETAIL = {
  'm.henderson': {
    type: 'User',
    name: 'm.henderson',
    recentAlerts: [
      {
        date: '07 Jun 2017', time: '05:02:40', sev: 'crit', score: 92,
        rows: [
          ['User', 'm.henderson'],
          ['Locking DC', 'DC01.contoso.local'],
          ['Source Computer', 'Unknown'],
          ['Event ID', '4740']
        ]
      },
      {
        date: '07 Jun 2017', time: '05:02:40', sev: 'vlow', score: 15,
        rows: [
          ['User', 'm.henderson'],
          ['Locking DC', 'DC02.contoso.local'],
          ['Source Computer', 'CORP-WS-045'],
          ['Event ID', '4740']
        ]
      }
    ],
    recommendations: [
      {
        title: 'Determine Entry Vector', sev: 'crit', score: 92,
        desc: 'Investigate how m.henderson\u2019s credentials were compromised \u2014 phishing email, brute force, token replay, or session hijack? Review email logs and sign-in risk events for the entry'
      }
    ]
  }
};
