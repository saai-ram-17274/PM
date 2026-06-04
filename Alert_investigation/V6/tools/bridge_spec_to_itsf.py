#!/usr/bin/env python3
"""Bridge itsf_reports_inventory.json (real ITSF report groups) to
device_and_other_entity_spec.md B/E sub-section ids.

Produces two outputs:
  V6/data/spec_to_itsf_join.json  \u2014 per spec logtype, list of matched ITSF
                                     groups + report count + assigned section id
  V6/data/unmatched_groups.json   \u2014 ITSF groups that have no spec section yet
                                     (gap report; drives new B/E ids if needed)

No assumption is made about a group \u2192 section mapping unless that mapping is
explicitly listed in GROUP_TO_SECTION below. Anything not listed flows to the
unmatched output so the user can decide whether to fold it into an existing
section or open a new one.
"""
import json
import os
import re
from collections import OrderedDict, defaultdict

INV = "/home/saairam-17274/Documents/GitHub_repo/PM/Alert_investigation/V6/data/itsf_reports_inventory.json"
OUT_JOIN = "/home/saairam-17274/Documents/GitHub_repo/PM/Alert_investigation/V6/data/spec_to_itsf_join.json"
OUT_GAP  = "/home/saairam-17274/Documents/GitHub_repo/PM/Alert_investigation/V6/data/unmatched_groups.json"

# ---------------------------------------------------------------------------
# 1. spec logtype  \u2192  itsf directory name(s)
# ---------------------------------------------------------------------------
# Derived by inspecting the LOG_TYPE attribute inside each PredefinedReports.xml
# (see V6/data/itsf_reports_inventory.json). Some spec logtypes have NO ITSF
# directory (Win_Archive / Sys_Archive / Syslog / FIM / NAS appliances /
# m365_general / m365_mailtrace / SyslogApp / Gateway_Server / audit / alerts /
# IBM_Maximo / PMP); these are listed with an empty list.
SPEC_TO_ITSF = {
    # Device \u2014 Windows-family
    "Windows":            ["Windows", "WindowsWorkstation", "ActiveDirectory"],
    "Sysmon":             ["Sysmon"],
    "Win_Archive":        ["Windows", "WindowsWorkstation", "ActiveDirectory"],
    "Terminal_Windows":   ["Terminal_Windows"],
    "FIM":                ["Linux"],   # itsf "Linux" dir = Linux_FIM (Windows FIM has no separate dir; surfaced under Windows)
    "Printer_Windows":    ["Printer_Windows"],
    # Device \u2014 Unix-family
    "Unix":               ["UnixLinux"],
    "Syslog":             [],
    "Sys_Archive":        ["UnixLinux"],
    "AS400":              ["IBMAS400"],
    # Device \u2014 Database servers
    "MSSQL":              ["MSSQL"],
    "Oracle":             ["Oracle"],
    "MySQL":              ["MySQL"],
    "PGSQL":              ["PGSQL"],
    "DB2":                ["DB2"],
    # Device \u2014 Web / app / FTP servers
    "ApacheAccessLogs":   ["ApacheAccessLogs"],
    "IIS_W3C_web":        ["IIS_W3C_web"],
    "IIS_W3C_ftp":        ["IIS_W3C_ftp"],
    # Device \u2014 Hypervisor
    "Hypervisor":         ["ESXi", "Hyper-V"],
    "vCenter":            ["vCenter"],
    # Device \u2014 SNMP
    "SNMP":               ["SNMPTrap"],
    # Device \u2014 Network security appliance (16)
    "Cisco":              ["Cisco"],
    "FirePower":          ["FirePower"],
    "PaloAlto":           ["PaloAlto"],
    "Fortinet":           ["Fortinet"],
    "CheckPoint":         ["CheckPoint"],
    "Juniper":            ["Juniper"],
    "SonicWall":          ["SonicWall"],
    "WatchGuard":         ["WatchGuard"],
    "NetScreen":          ["NetScreen"],
    "Barracuda":          ["Barracuda"],
    "pfSense":            ["pfSense"],
    "ForcePoint":         ["ForcePoint"],
    "Sophos":             ["Sophos"],
    "Topsec":             ["Topsec"],
    "Sangfor":            ["Sangfor"],
    "Stormshield":        ["Stormshield"],
    # Device \u2014 Network infrastructure (7)
    "Arista":             ["Arista"],
    "Dell":               ["Dell"],
    "F5":                 ["F5"],
    "H3C":                ["H3C"],
    "HP":                 ["HP"],
    "Huawei":             ["Huawei"],
    "Meraki":             ["Meraki"],
    # Device \u2014 NAS (no ITSF reports xml; uses agent-based file events)
    "EMC Isilon":         ["Linux"],
    "QNAP NAS":           ["Linux"],
    "SynologyNAS":        ["Linux"],
    # Other \u2014 Cloud / SaaS
    "AWS":                       ["AWS"],
    "azure_active_directory":    ["EntraID"],
    "exchange_online":           ["ExchangeOnline"],
    "m365_general":              ["Onedrive", "Teams"],   # Onedrive + Teams roll up into the m365 generic tenant
    "m365_mailtrace":            [],
    "sharepoint_online":         ["Sharepoint"],
    "Salesforce":                ["Salesforce"],
    # Other \u2014 ManageEngine
    "ADAP":               ["ADAP"],
    "ADMP":               ["ADMP"],
    "ADSSP":              ["ADSSP"],
    "OPM":                ["OPM"],
    "PMP":                [],
    "SDP":                ["SDP"],
    "UEM":                ["UEM"],
    "ERP":                ["ERP"],
    # Other \u2014 Enterprise app
    "IBM_Maximo":         [],
    "SAP":                ["SAP"],
    # Other \u2014 EDR
    "McAfee":                       ["McAfee"],
    "Symantec_Endpoint_Protection": ["SymantecEndpointProtection"],
    "Symantec_DLP":                 ["SymantecDLP"],
    "Trend_Micro":                  ["TrendMicro"],
    "FireEye":                      ["FireEye"],
    "MalwareBytes":                 ["Malwarebytes"],
    "CEF_Format":                   ["CEF_Format"],
    # Other \u2014 ThreatAnalytics
    "ThreatAnalytics":    ["ThreatAnalytics"],
    # Other \u2014 Vulnerability findings
    "Qualys":             ["Qualys"],
    "Nessus":             ["Nessus"],
    "Nexpose":            ["Nexpose"],
    "OpenVas":            ["OpenVas"],
    "NMAP":               ["NMAP"],
    # Other \u2014 DHCP
    "DHCP_Linux":         ["DHCP_Linux"],
    "DHCP_Windows":       ["DHCP_Windows"],
    # Other \u2014 wrapper / system metadata
    "SyslogApp":          [],
    "Gateway_Server":     [],
    "audit":              [],
    "alerts":             [],
}

# ---------------------------------------------------------------------------
# 2. itsf group_name  \u2192  spec sub-section id
# ---------------------------------------------------------------------------
# Mapping derived from:
#   (a) group_name keyword
#   (b) per-spec section "what it shows" text in V6/device_and_other_entity_spec.md
# A group can map to multiple sections only when its reports genuinely split
# (e.g. "Account Logon Events" maps to B4 only, even though it also touches B3).
# Conservative: when in doubt, leave unmapped \u2014 the user sees it in the gap report.
#
# Section semantics recap (from spec \u00a73.2/3.3/3.4 and \u00a75.2/5.3):
#   B3 Users Logged On             E3 Processes Started on Host
#   B4 Login Activity              E4 Services Installed on Host
#   B5 Local Account Lifecycle     E5 Scheduled Task Events
#   B7 DB Auth & Privileged Ops    E6 USB Device Events
#   B8 Web 5xx + auth fails        E7 Full DB Query Audit
#   B9 Traffic Flow Summary        E8 URL / Category Breakdown
#   B10 NAS Share Access Summary   E9 Per-flow Firewall Lookup
#   B11 VM / Cluster Inventory     E10 Threat / IPS Event Detail
#                                  E11 VPN Session Detail
#                                  E12 Admin / Config Changes on Appliance
#                                  E13 Switch / Router Interface Events
#                                  E14 SNMP Trap Stream
#                                  E15 NAS / FTP File-level Access Detail
#                                  E16 Hypervisor Management Plane
#                                  E18 File Integrity Events (Windows FIM)
#                                  E19 Print Queue Activity
#   OB3 Recent Activity            OE1 Full Audit Trail
#                                  OE2 Top Targets
#                                  OE3 Configuration Changes
#                                  OE4 Cross-Entity Correlations
#
# Each entry: (regex, section_id, comment)
GROUP_RULES = [
    # --- Login / logon ---
    (r"logon report",                          "B4",  "Windows Logon Reports group"),
    (r"\blogon reports?\b",                    "B4",  ""),
    (r"account logon|account validation",      "B4",  ""),
    (r"credential validation|dc credential|\bad summary\b", "B4", "DC Kerberos/NTLM auth"),
    (r"failed log[io]n|logon failure",         "B4",  ""),
    (r"successful log[io]n|user log[io]n",     "B4",  ""),
    (r"terminal (server|service)|rdp",         "B4",  "session-type 10 logons"),
    (r"user log[io]n.*report|individual user", "B4",  ""),
    (r"logons?/?log\s*off|logon/?logoff|logoff report|local logon", "B4", "logon + logoff session events"),
    (r"kerberos|ldap auditing|\bnps\b|network policy server|domain events", "B4", "Kerberos/LDAP/NPS/DC events"),
    (r"sqlserver logon|sqlserver login|mysql.* logon|mysql.* login", "B4", "DB host logon"),
    (r"ad replication|netlogon|schannel|adfs",     "B4",  "AD replication / DC channel auth / federation"),
    (r"db2.*connection auditing|pgsql logon|pgsql login", "B4", "DB connection auth"),
    # --- Local account / group lifecycle ---
    (r"local account|account management",      "B5",  ""),
    (r"user account changes|user account",     "B5",  ""),
    (r"\buser management\b",                  "B5",  "Windows User Management group"),
    (r"group management|group changes",        "B5",  ""),
    (r"password (change|reset|policy)",        "B5",  ""),
    (r"\bcomputer management\b",              "B5",  "MMC console object lifecycle"),
    # --- C5: AD object lifecycle beyond user/group (Option A: extend B5) ---
    (r"ou management|other ad object|ad object change", "B5", "OU/AD-object lifecycle"),
    (r"ad lds|azuread password|password protection|laps audit", "B5", "AD/LDS account directory"),
    (r"\bou changes?\b|domain object changes?", "B5", "AD object lifecycle"),
    # --- C7: AS400 catch-all (Option A: predominantly auth) ---
    (r"\bas400 reports?\b",                    "B4",  "AS400 catch-all \u2192 auth bucket"),
    # --- Process tracking ---
    (r"process tracking|process create",       "E3",  ""),
    (r"powershell|process audit",              "E3",  ""),
    (r"sysmon process|process events",         "E3",  ""),
    (r"\bsu commands?\b|\bsudo\b",             "E3",  "Unix privilege-escalation commands"),
    # --- Service install / Software inventory (host software state) ---
    (r"service audit|service install|service event",          "E4", ""),
    (r"software install|software updates?|program inventory|library and driver", "E4", "host-side software state changes"),
    # --- Scheduled tasks ---
    (r"scheduled task|task scheduler|task management",        "E5", ""),
    # --- USB / removable media ---
    (r"usb|removable (media|storage|disk|drive)",             "E6", ""),
    # --- File integrity / ACL changes (Option A: fold C4+C10 into E18, cross-platform) ---
    (r"file integrity|\bfim\b|\bfim reports?|file monitoring", "E18", "Windows + Linux FIM"),
    (r"file audit|object access|file system",                  "E18", ""),
    (r"permission changes?|\bacl changes?\b",                  "E18", "object ACL changes \u2192 fold into FIM"),
    # --- Print ---
    (r"print(er|ing|spooler|er events|er activity)",          "E19",""),
    # --- DB ---
    (r"\bgrant|\brevoke|\brole|ddl|privilege",                "B7", "DB privileged ops"),
    (r"db.* (logon|login)|database (logon|login|auth)",       "B7", ""),
    (r"server principal|audit changes|sqlserver.*audit",      "B7", "MSSQL principal/audit changes"),
    (r"oracle auditing (report|server report)",               "B7", "Oracle audit-trail roll-ups"),
    # C11: DB principal/overview rollups \u2192 extend B7
    (r"database principal|principal changes|pgsql overview|\bdb overview\b", "B7", "DB principal & overview rollups"),
    (r"administrative statements|db2.*server reports|database server reports", "B7", "DB admin/server rollups"),
    (r"sqlserver events|sql server events|sql server integrity|sql server authority|sql server permission denied|sqlserver.*trace", "B7", "MSSQL meta/integrity"),
    (r"\bdml\b|\bselect\b|query audit|advanced auditing|general statements", "E7", "DB query audit"),
    # --- Web servers ---
    (r"5xx|server error|error report|status code 5",          "B8", ""),
    (r"401|403|forbidden|unauthorized|auth(entication)? fail","B8", ""),
    (r"top urls?|url access|category|web filter",             "E8", ""),
    (r"top reports?|webserver top|access reports?|iis webserver|webserver advanced", "E8", "Web access aggregations"),
    # --- NSA / Network ---
    (r"traffic|allowed traffic|denied traffic|flow|deny",     "B9", ""),
    (r"accepted connections?|denied connections?|application tracking|common reports?|overview reports?|network audit|fw dhcp", "B9", "NSA generic connection rollups"),
    # C2: Host firewall \u2192 extend B9 (firewall traffic, host or appliance)
    (r"windows firewall|host firewall|host.based firewall",   "B9", "host firewall traffic"),
    (r"firewall.*(policy|admin|config)|admin events",         "E12",""),
    (r"router configuration|switch configuration|config(uration)? report", "E12", "device admin config"),
    (r"iis admin|iis.*admin configuration",                   "E12", "IIS admin config"),
    # C3: Registry / Config / Policy changes \u2192 extend E12 (config/policy lineage)
    (r"registry changes?|registry audit|configuration auditing|\bpolicy changes?\b", "E12", "host registry/config/policy"),
    (r"dns changes?|gpo management",                          "E12", "DNS/GPO config changes"),
    (r"(fw|firewall)?\s*rules? management|(fw|firewall)?\s*policy management|policy management|wmi audit", "E12", "FW rule/policy management + WMI config"),
    (r"network monitor policy",                               "E12", "NSA monitor policy"),
    (r"vpn",                                                  "E11",""),
    (r"ips|intrusion|threat|attack|signature|malware detect", "E10",""),
    (r"security reports?(?! \()|threat prevention",           "E10","PaloAlto/NSA security/threat events"),
    (r"interface (up|down)|port security|link state",         "E13",""),
    (r"router/?switch system|switch.*event|router.*event",    "E13",""),
    # C1+C6+C8+C9: System/health/availability + DNS + Unix services \u2192 extend E13
    (r"\bsystem events?\b|\bsystem reports?\b|eventlog reports?|severity reports?|startup events?|backup and restore", "E13", "host/appliance system events"),
    (r"important events?|\bwindows events?\b|\bunix events?\b|\bsysmon events?\b|\boracle events?\b|\bmysql events?\b|\bpgsql events?\b|\bdb2 events?\b|as/?400 events?|startup shutdown|heartbeat|interface status|health monitoring|trend reports?", "E13", "host/appliance generic events + health"),
    # Catch-all: \"<DeviceFamily> Events\", \"<X> Interface Events\", \"<X> Connection/Port Status\" \u2192 E13
    (r"\bevents?\s*\||\bevents?\s*$|interface events?|connection monitoring|port status",  "E13", "device-family generic events / interface health"),
    (r"fw firewall connections?|firewall connections?",       "B9",  "FW connection rollup"),
    (r"application (crashes?|whitelisting)|application errors?", "E13", "host application health"),
    (r"dns server|dns audit|advanced dns",                    "E13", "DNS server events"),
    (r"unix mail server|unix other events|unix risk|unix nfs", "E13", "Unix service events"),
    (r"risk reports?",                                        "E13", "device risk rollups"),
    (r"wireless|sonicpoint|access point",                     "B9",  "wireless / AP traffic"),
    # --- Hypervisor ---
    (r"vmotion|vm lifecycle|cluster|datastore|snapshot",      "E16",""),
    (r"vmware system event|vcenter system|esxi system|vmware server event|hyper-?v server event", "E16",""),
    (r"\bvm changes?\b|\bhost changes?\b",                    "E16","vCenter VM/host config changes"),
    (r"\bfolder changes?\b|resourcepool changes?|datacenter changes?", "E16","vCenter object changes"),
    # --- SNMP ---
    (r"snmp.*trap|trap",                                      "E14",""),
    # --- Hypervisor (B11 = inventory) ---
    (r"vm (management|inventory)|hyper-?v vm|hosted vms?",    "B11","VM lifecycle / inventory"),
    # --- GPO ---
    (r"gpo (setting )?changes?|gpo applied|group policy",     "E2", "GPO Applied"),
    # --- NAS / FTP / file-share ---
    (r"file access|share access|file ops|file operations",    "B10",""),
    (r"network share aud|file server|cifs|smb share",         "B10","Windows file-share access summary"),
    (r"file.*(create|read|write|delete|rename)|ftp command",  "E15",""),
    (r"iis ftp|ftp server",                                   "E15","FTP commands STOR/RETR/DELE \u2192 file ops"),
    # --- Fallback ---
    (r".*",                                                   None, "fallback \u2014 caller decides"),
]
# Pre-compile
COMPILED = [(re.compile(pat, re.IGNORECASE), sid, com) for pat, sid, com in GROUP_RULES]

def classify_group(group_name: str, display_name: str, slider: str):
    """Return section_id or None. Other-slider groups default to OB3 since the
    Other slider has a single Activity sub-section per spec \u00a75.2."""
    text = f"{group_name} | {display_name or ''}"
    for rx, sid, _ in COMPILED:
        if sid is None:
            break
        if rx.search(text):
            return sid
    # Other slider fallback: every event group rolls up into OB3 (Recent Activity).
    if slider == "other":
        return "OB3"
    return None


def main():
    inv = json.load(open(INV))
    spec_ds = json.load(open("/home/saairam-17274/Documents/GitHub_repo/PM/Alert_investigation/V6/data/entity_section_dataset.json"))
    slider_of = {lt: v["slider"] for lt, v in spec_ds["logtypes"].items()}
    inv_dirs = inv["inventory"]

    join = OrderedDict()
    unmatched = []
    total_groups_seen   = 0
    total_groups_mapped = 0
    total_reports_seen  = 0

    for spec_lt, dirs in SPEC_TO_ITSF.items():
        slider = slider_of.get(spec_lt, "unknown")
        entry = {
            "slider": slider,
            "itsf_dirs": dirs,
            "spec_baseline":  spec_ds["logtypes"].get(spec_lt, {}).get("baseline", []),
            "spec_enriched":  spec_ds["logtypes"].get(spec_lt, {}).get("enriched", []),
            "matched_groups": [],
            "unmapped_groups": [],
            "report_count_total": 0,
            "report_count_by_section": {},
        }
        for d in dirs:
            if d not in inv_dirs:
                continue
            for cat in inv_dirs[d].get("categories", []):
                for g in cat["groups"]:
                    total_groups_seen += 1
                    total_reports_seen += g["report_count"]
                    sid = classify_group(g["group_name"], g.get("display_name", ""), slider)
                    rec = {
                        "itsf_dir":   d,
                        "group_name": g["group_name"],
                        "display":    g.get("display_name"),
                        "report_count": g["report_count"],
                        "section":    sid,
                    }
                    if sid:
                        total_groups_mapped += 1
                        entry["matched_groups"].append(rec)
                        entry["report_count_by_section"][sid] = (
                            entry["report_count_by_section"].get(sid, 0) + g["report_count"])
                    else:
                        entry["unmapped_groups"].append(rec)
                        unmatched.append({"spec_logtype": spec_lt, **rec})
                    entry["report_count_total"] += g["report_count"]
        join[spec_lt] = entry

    join_out = {
        "$schema_version": "1.0",
        "summary": {
            "spec_logtypes": len(join),
            "spec_logtypes_with_reports": sum(1 for v in join.values() if v["report_count_total"] > 0),
            "spec_logtypes_without_reports": sorted(k for k, v in join.items() if v["report_count_total"] == 0),
            "itsf_groups_seen": total_groups_seen,
            "itsf_groups_mapped_to_section": total_groups_mapped,
            "itsf_groups_unmapped": total_groups_seen - total_groups_mapped,
            "itsf_reports_seen": total_reports_seen,
        },
        "spec_to_itsf": join,
    }
    with open(OUT_JOIN, "w", encoding="utf-8") as f:
        json.dump(join_out, f, indent=2, ensure_ascii=False)
    print(f"wrote {OUT_JOIN}")

    # Gap report aggregated by group_name
    gap_by_name = defaultdict(lambda: {"count": 0, "report_count": 0, "log_types": set()})
    for u in unmatched:
        b = gap_by_name[u["group_name"]]
        b["count"] += 1
        b["report_count"] += u["report_count"]
        b["log_types"].add(u["spec_logtype"])
    gap_summary = sorted(
        ({"group_name": k, **{x: (sorted(y) if isinstance(y, set) else y) for x, y in v.items()}}
         for k, v in gap_by_name.items()),
        key=lambda x: x["report_count"], reverse=True,
    )
    with open(OUT_GAP, "w", encoding="utf-8") as f:
        json.dump({
            "$schema_version": "1.0",
            "description": "ITSF report groups that did not match any sub-section id in the spec. Either (a) extend GROUP_RULES in V6/tools/bridge_spec_to_itsf.py, or (b) add a new B/E/OB/OE id to device_and_other_entity_spec.md.",
            "by_group_name": gap_summary,
            "raw": unmatched,
        }, f, indent=2, ensure_ascii=False)
    print(f"wrote {OUT_GAP}")

    # CLI summary
    print(f"\nsummary: {join_out['summary']}")
    print(f"\nspec logtypes WITHOUT any ITSF reports xml:")
    for k in join_out['summary']['spec_logtypes_without_reports']:
        print(f"  - {k}")
    print(f"\nTop 25 unmapped groups by report_count (fix these next):")
    for r in gap_summary[:25]:
        lts = ",".join(r['log_types'])[:50]
        print(f"  {r['report_count']:>4}  {r['group_name']:<55}  [{lts}]")

if __name__ == "__main__":
    main()
