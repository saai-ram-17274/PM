#!/usr/bin/env python3
"""Parse itsf PredefinedReports.xml inventory \u2192 per-logtype groups + reports.

Source: REPOS/itsf/product_package/conf/itsf/common/reports/**/PredefinedReports.xml
Output: V6/data/itsf_reports_inventory.json
"""
import json
import os
import re
import xml.etree.ElementTree as ET
from collections import OrderedDict

ROOT = "/home/saairam-17274/Documents/REPOS/itsf/product_package/conf/itsf/common/reports"
OUT  = "/home/saairam-17274/Documents/GitHub_repo/PM/Alert_investigation/V6/data/itsf_reports_inventory.json"

# Files that are MITRE tactic groupings or meta-dashboards, not log-type categories.
META_DIRS = {
    "Collection", "CommandAndControl", "CredentialAccess", "DefenseEvasion",
    "Discovery", "Execution", "Exfiltration", "Impact", "InitialAccess",
    "LateralMovement", "Persistence", "PrivilegeEscalation",
    "Dashboard", "dashboard", "DeviceSummary", "workbench",
}

# Strip the DTD line; ElementTree balks on relative SYSTEM DTDs.
DTD_RE = re.compile(r"<!DOCTYPE[^>]*>", re.IGNORECASE)
# Named entities defined in external field_corrections.xml DTDs; strip them.
# Preserve the 5 standard XML entities.
_XML_STANDARD = {"amp", "lt", "gt", "quot", "apos"}
ENTITY_RE = re.compile(r"&([a-zA-Z_][a-zA-Z0-9_]*);")

def _strip_custom_entities(m):
    name = m.group(1)
    return m.group(0) if name in _XML_STANDARD else ""

def parse_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    raw = DTD_RE.sub("", raw, count=1)
    raw = ENTITY_RE.sub(_strip_custom_entities, raw)
    # ElementTree cannot resolve external entities; assume none used in body.
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        return {"_parse_error": str(e)}

    categories = []
    for cat in root.iter("FwReportsCategories"):
        cat_entry = {
            "category_id":   cat.get("CATEGORY_ID"),
            "category_name": cat.get("CATEGORY_NAME"),
            "display_name":  cat.get("DISPLAY_NAME"),
            "module_id":     cat.get("MODULE_ID"),
            "log_types":     [],
            "groups":        [],
        }
        for m in cat.findall("FwReportsCategoriesToDeviceTypeMapping"):
            lt = m.get("LOG_TYPE")
            if lt:
                cat_entry["log_types"].append(lt)
        for g in cat.findall("FwReportsGroups"):
            reports = []
            for r in g.findall("FwReports"):
                criteria = r.get("CRITERIA", "")
                event_ids = sorted(set(re.findall(r"'EVENTID'[^']*'value':'([^']+)'", criteria)
                                       + re.findall(r"'value':'([\d, ]+)','key':'EVENTID'", criteria)))
                # Flatten comma-separated EVENTID values into a single sorted set.
                flat_ids = sorted({x.strip() for s in event_ids for x in s.split(",") if x.strip()})
                reports.append({
                    "report_name":  r.get("REPORT_NAME"),
                    "unique_key":   r.get("UNIQUE_KEY"),
                    "display_name": r.get("DISPLAY_NAME"),
                    "event_ids":    flat_ids,
                })
            cat_entry["groups"].append({
                "group_name":   g.get("GROUP_NAME"),
                "display_name": g.get("DISPLAY_NAME"),
                "priority":     g.get("PRIORITY"),
                "report_count": len(reports),
                "reports":      reports,
            })
        categories.append(cat_entry)
    return {"categories": categories}

def main():
    inventory = OrderedDict()
    meta_files = []
    for dirpath, _dirnames, filenames in os.walk(ROOT):
        if "PredefinedReports.xml" not in filenames:
            continue
        rel = os.path.relpath(dirpath, ROOT)
        leaf = os.path.basename(dirpath)
        path = os.path.join(dirpath, "PredefinedReports.xml")
        parsed = parse_file(path)
        record = {
            "file": os.path.relpath(path, "/home/saairam-17274/Documents/REPOS/itsf"),
            **parsed,
        }
        if leaf in META_DIRS:
            meta_files.append({"dir": rel, **record})
            continue
        inventory[leaf] = record

    # Summary: per dir, total group count + total report count + log_types covered
    summary = []
    for leaf, rec in inventory.items():
        if "categories" not in rec:
            summary.append({"dir": leaf, "_error": rec.get("_parse_error")})
            continue
        g_total = sum(len(c["groups"]) for c in rec["categories"])
        r_total = sum(len(g["reports"]) for c in rec["categories"] for g in c["groups"])
        lts     = sorted({lt for c in rec["categories"] for lt in c["log_types"]})
        summary.append({
            "dir": leaf, "log_types": lts,
            "group_count": g_total, "report_count": r_total,
        })

    out = {
        "$schema_version": "1.0",
        "source_root": ROOT,
        "meta_dirs_skipped": sorted(META_DIRS),
        "summary": summary,
        "meta_files_inventory": meta_files,
        "inventory": inventory,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"wrote {OUT}")
    print(f"logtype_dirs={len(inventory)} meta_dirs={len(meta_files)}")
    # Quick per-dir summary, sorted by report count desc
    rows = sorted(summary, key=lambda r: r.get("report_count", 0), reverse=True)
    print(f"\n{'dir':<30} {'groups':>7} {'reports':>8}  log_types")
    for r in rows:
        if "_error" in r:
            print(f"{r['dir']:<30} {'ERR':>7} {'':>8}  {r['_error']}")
        else:
            lts = ",".join(r["log_types"])[:40]
            print(f"{r['dir']:<30} {r['group_count']:>7} {r['report_count']:>8}  {lts}")

if __name__ == "__main__":
    main()
