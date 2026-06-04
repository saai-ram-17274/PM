#!/usr/bin/env python3
"""
Enrich data/soc_field_projection.json from PredefinedReports.xml.

For every (logtype, section_id) pair, locate the matching report group(s) in
   REPOS/itsf/product_package/conf/itsf/common/reports/Devices/<LT>/PredefinedReports.xml
collect the FwReportsVsADSFields FIELD_IDs the SOC ships with that group,
intersect them with the logtype's nlq fields, and union them into the
existing role-bucket projection.

Section -> report-group-name keyword map (case-insensitive substring):
  B4  : logon | login | authentication | radius
  B5  : account | user management | group management
  B7  : sql | database
  B8  : web | http
  B9  : traffic | firewall allowed | firewall denied | connection
  B10 : file | folder | share | nas
  B11 : virtual machine | hypervisor | cluster
  E2  : group policy | policy change | object access | gpo
  E3  : process
  E4  : service
  E5  : scheduled task | task scheduler
  E6  : removable | usb | device
  E7  : sql | query | dml | ddl
  E8  : url | web | proxy | uri | browsing
  E10 : threat | attack | intrusion | virus | malware | ips | ids | signature
  E11 : vpn | remote access
  E12 : configuration | policy change | settings
  E13 : severity | system | alert
  E16 : configuration | datacenter | inventory
  E18 : file integrity | file auditing | object access | fim
  E19 : print

Output: data/soc_field_projection_enriched.json — same shape as input.
Also writes data/enrichment_diff.json listing fields added per (lt, sec).
"""
import json, os, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NLQ = Path("/home/saairam-17274/Documents/REPOS/itsf/product_package/conf/itsf/common/ai/nlq/data/nlq_event_field_mapping.json")
REPORTS_BASE = Path("/home/saairam-17274/Documents/REPOS/itsf/product_package/conf/itsf/common/reports/Devices")

SECTION_KEYWORDS = {
    "B3":  ["logon", "login", "authentication", "session", "logoff"],
    "B4":  ["logon", "login", "authentication", "radius"],
    "B5":  ["account", "user management", "group management"],
    "B7":  ["sql", "database"],
    "B8":  ["web", "http"],
    "B9":  ["traffic", "firewall allowed", "firewall denied", "connection", "flow"],
    "B10": ["file", "folder", "share", "nas"],
    "B11": ["virtual machine", "hypervisor", "cluster"],
    "E2":  ["group policy", "policy change", "object access", "gpo"],
    "E3":  ["process"],
    "E4":  ["service"],
    "E5":  ["scheduled task", "task scheduler"],
    "E6":  ["removable", "usb", "device"],
    "E7":  ["sql", "query", "dml", "ddl"],
    "E8":  ["url", "web", "proxy", "uri", "browsing"],
    "E10": ["threat", "attack", "intrusion", "virus", "malware", "ips ", "ids ", "signature"],
    "E11": ["vpn", "remote access"],
    "E12": ["configuration", "policy change", "settings"],
    "E13": ["severity", "system", "alert"],
    "E16": ["configuration", "datacenter", "inventory"],
    "E18": ["file integrity", "file auditing", "object access", "fim"],
    "E19": ["print"],
}

# logtype -> reports subfolder name(s) to try (in priority order)
LT_FOLDER_ALIASES = {
    "Win_Archive": ["Windows", "WindowsWorkstation"],
    "Hypervisor": ["VirtualMachines", "Hypervisor"],
    "AS400": ["IBMAS400"],
    "EMC Isilon": ["EMC", "EMCIsilon"],
    "ApacheAccessLogs": ["Apache"],
    "IIS_W3C_web": ["IIS", "Windows"],
    "IIS_W3C_ftp": ["IIS", "Windows"],
}

CAP = 10  # max fields per (lt, sec) after enrichment

def fr_groups_with_fields(xml: str):
    """yield (group_name, [(field_id, display_name, default_on)])"""
    # split xml by FwReportsGroups boundary
    parts = re.split(r'(<FwReportsGroups [^>]*>)', xml)
    # walk pairs (header, body)
    for i in range(1, len(parts), 2):
        header = parts[i]
        body = parts[i+1] if i+1 < len(parts) else ""
        # truncate body at next group close or next group open (next iter handles)
        body = body.split("</FwReportsGroups>")[0]
        m = re.search(r'GROUP_NAME="([^"]+)"', header)
        gname = m.group(1) if m else ""
        fields = re.findall(
            r'<FwReportsVsADSFields[^>]*FIELD_ID="ADSFields:FIELD_ID:([^"]+)"[^>]*DISPLAY_NAME="([^"]+)"[^>]*DEFAULT_IS_ENABLED="(true|false)"',
            body,
        )
        yield gname, fields

def find_reports_xml(lt: str):
    candidates = LT_FOLDER_ALIASES.get(lt, []) + [lt, lt.replace(" ", ""), lt.replace("_", "")]
    for c in candidates:
        p = REPORTS_BASE / c / "PredefinedReports.xml"
        if p.is_file():
            return p
    return None

def harvest(lt: str, section_id: str, nlq_fields: set) -> dict:
    """Return {field: {display, default_on, group}} restricted to nlq presence."""
    xml_path = find_reports_xml(lt)
    if not xml_path:
        return {}
    kws = SECTION_KEYWORDS.get(section_id, [])
    if not kws:
        return {}
    xml = xml_path.read_text(errors="ignore")
    out = {}
    for gname, fields in fr_groups_with_fields(xml):
        gn = gname.lower()
        if not any(k in gn for k in kws):
            continue
        for fid, disp, en in fields:
            if fid not in nlq_fields:
                continue
            if fid not in out or (en == "true" and out[fid]["default_on"] == "false"):
                out[fid] = {"display": disp, "default_on": en, "group": gname}
    return out

def main():
    nlq = json.loads(NLQ.read_text())
    proj = json.loads((ROOT / "data" / "soc_field_projection.json").read_text())
    enriched = {}
    diff = {}
    for lt, sections in proj.items():
        nlq_fields = set(nlq.get(lt, {}).keys())
        enriched[lt] = {}
        for sec, picked in sections.items():
            harvested = harvest(lt, sec, nlq_fields)
            if not harvested:
                enriched[lt][sec] = picked
                continue
            # union, keeping TIME first then prior order then new ones (default-ON first)
            order = list(picked)
            new_on  = [f for f, m in harvested.items() if m["default_on"] == "true" and f not in order]
            new_off = [f for f, m in harvested.items() if m["default_on"] == "false" and f not in order]
            merged = order + new_on + new_off
            # ensure TIME first
            if "TIME" in merged:
                merged.remove("TIME"); merged.insert(0, "TIME")
            merged = merged[:CAP]
            enriched[lt][sec] = merged
            added = [f for f in merged if f not in picked]
            if added:
                diff.setdefault(lt, {})[sec] = {
                    "before": picked,
                    "after":  merged,
                    "added":  added,
                    "source": f"reports/Devices/{find_reports_xml(lt).parent.name}/PredefinedReports.xml",
                }
    (ROOT / "data" / "soc_field_projection_enriched.json").write_text(
        json.dumps(enriched, indent=2, sort_keys=True) + "\n"
    )
    (ROOT / "data" / "enrichment_diff.json").write_text(
        json.dumps(diff, indent=2, sort_keys=True) + "\n"
    )
    pairs = sum(len(v) for v in enriched.values())
    enriched_pairs = sum(len(v) for v in diff.values())
    added_total = sum(len(d["added"]) for lt in diff.values() for d in lt.values())
    print(f"Logtypes:                 {len(enriched)}")
    print(f"Total (lt, sec) pairs:    {pairs}")
    print(f"Pairs enriched from XML:  {enriched_pairs}")
    print(f"Fields added total:       {added_total}")

if __name__ == "__main__":
    main()
