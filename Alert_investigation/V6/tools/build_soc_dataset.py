#!/usr/bin/env python3
"""
build_soc_dataset.py

For every spec logtype, compute the Baseline (B*) and Enriched (E*) sub-sections
that a SOC analyst will actually see — derived from the ITSF report tree we
inventoried, not from guesses.

Inputs
------
- V6/data/entity_section_dataset.json   (spec catalog + always-on implicits)
- V6/data/spec_to_itsf_join.json        (per-logtype matched_groups, each tagged
                                         with section_id and report_count)

Output
------
- V6/data/soc_per_logtype_dataset.json

Schema (per logtype)
--------------------
{
  "slider": "device" | "other",
  "sub_class": "<spec sub-class>",
  "itsf_dirs": [...],
  "itsf_group_count": int,
  "itsf_report_count": int,
  "baseline": [
    { "section_id": "B4", "name": "Login Activity",
      "report_count": 47, "group_count": 9, "always_on": false,
      "groups": ["Windows Logon Reports", "..."] },
    ...
  ],
  "enriched": [ ... same shape ... ]
}

Conventions
-----------
* Always-on per spec section 4.x:
  - Device: B1, B2, B6 (baseline); E1, E2 (enriched)
  - Other:  OB1, OB2, OB4 (baseline); OE1-OE4 always available, OE3 marked
    always-on. We only inject these as "always_on:true" rows with zero
    report_count so the UI can render the placeholder bands.
* Sections are sorted by spec id order (B1..B11 then E1..E19), not by volume.
* "groups" lists the distinct ITSF group_names that fed the section, in
  descending report-count order, truncated to 12 entries for readability.
"""
from __future__ import annotations
import json, os
from collections import defaultdict, OrderedDict

ROOT = "/home/saairam-17274/Documents/GitHub_repo/PM/Alert_investigation/V6"
SPEC = os.path.join(ROOT, "data/entity_section_dataset.json")
JOIN = os.path.join(ROOT, "data/spec_to_itsf_join.json")
OUT  = os.path.join(ROOT, "data/soc_per_logtype_dataset.json")

DEVICE_ALWAYS_ON_B = ["B1", "B2", "B6"]
DEVICE_ALWAYS_ON_E = ["E1", "E2"]
OTHER_ALWAYS_ON_B  = ["OB1", "OB2", "OB4"]
OTHER_ALWAYS_ON_E  = ["OE3"]  # config-changes default

# --- Per-logtype overrides for the 13 logtypes that have no ITSF reports xml ---
# Three categories:
#   "extra_always_on": list of section ids to add as always-on placeholders
#                      (used when the logtype is real but has no canonical
#                      report tree, e.g. Syslog as a generic network device).
#   "out_of_scope":    true \u2192 wrapper / metadata feed; renders only the
#                      mandatory always-on shell, with a status flag for the UI.
#   "needs_sourcing":  true \u2192 logtype is in spec but ITSF reports must come
#                      from a non-XML source (PMP, IBM_Maximo, m365_mailtrace).
LOGTYPE_OVERRIDES = {
    # Generic syslog \u2192 network device (B4 auth + B9 traffic baseline, E10/E12/E13 enriched)
    "Syslog": {
        "extra_always_on": ["B4", "B9", "E10", "E12", "E13"],
        "note":            "Generic syslog rendered with the network-device panel shape; sections will populate as vendor-specific log types are parsed downstream.",
    },
    # Wrappers / metadata \u2192 mandatory shell only
    "audit":          {"out_of_scope": True, "note": "Log360 self-audit (platform metadata) \u2014 no first-party report tree."},
    "alerts":         {"out_of_scope": True, "note": "Internal alert-metadata feed \u2014 no first-party report tree."},
    "SyslogApp":      {"out_of_scope": True, "note": "Generic syslog wrapper \u2014 pass-through with no reports of its own."},
    "Gateway_Server": {"out_of_scope": True, "note": "CASB / cloud gateway wrapper \u2014 no first-party report tree."},
    # Missing XML \u2014 sections defined in spec but no ITSF source yet
    "PMP":             {"needs_sourcing": True, "note": "PasswordManager Pro \u2014 report definitions live in PMP product, not ITSF reports xml."},
    "IBM_Maximo":      {"needs_sourcing": True, "note": "Maximo asset-management audit \u2014 needs separate source."},
    "m365_mailtrace":  {"needs_sourcing": True, "note": "Message-trace records \u2014 not in current ITSF M365 report tree."},
}

def sec_sort_key(sid: str):
    """B1 < B2 < ... < B11 < E1 < ... < E19; OB1 < ... < OE4."""
    if not sid:
        return (9, 99)
    prefix_order = {"B": 0, "E": 1, "OB": 2, "OE": 3}
    # pull the leading alpha and trailing digits
    i = 0
    while i < len(sid) and sid[i].isalpha():
        i += 1
    alpha, num = sid[:i], sid[i:]
    return (prefix_order.get(alpha, 9), int(num) if num.isdigit() else 99)


def main():
    spec = json.load(open(SPEC))
    join = json.load(open(JOIN))

    cat_device = spec["section_catalog"]["device"]
    cat_other  = spec["section_catalog"]["other"]
    dev_b_names = {k: v["name"] for k, v in cat_device["baseline"].items()}
    dev_e_names = {k: v["name"] for k, v in cat_device["enriched"].items()}
    oth_b_names = {k: v["name"] for k, v in cat_other["baseline"].items()}
    oth_e_names = {k: v["name"] for k, v in cat_other["enriched"].items()}
    dev_b_tabs = {k: v["tab"] for k, v in cat_device["baseline"].items()}
    dev_e_tabs = {k: v["tab"] for k, v in cat_device["enriched"].items()}
    oth_b_tabs = {k: v["tab"] for k, v in cat_other["baseline"].items()}
    oth_e_tabs = {k: v["tab"] for k, v in cat_other["enriched"].items()}

    logtypes_spec = spec["logtypes"]

    out = OrderedDict()
    out["$schema_version"] = "1.0"
    out["description"] = (
        "Per-logtype SOC-analyst view: Baseline (B*) and Enriched (E*) "
        "sub-sections derived from the ITSF PredefinedReports.xml inventory "
        "(V6/data/spec_to_itsf_join.json). Each row records the section id, "
        "human-readable name, tab placement, the ITSF report_count + group_count "
        "that fed it, and the top contributing group_names. always_on=true rows "
        "come from spec section 4.x and have report_count=0."
    )
    out["provenance"] = {
        "spec_catalog":        "data/entity_section_dataset.json",
        "itsf_bridge":         "data/spec_to_itsf_join.json",
        "itsf_inventory":      "data/itsf_reports_inventory.json",
        "itsf_source_tree":    "REPOS/itsf/product_package/conf/itsf/common/reports/",
    }
    out["totals"] = {
        "logtypes": len(logtypes_spec),
        "logtypes_with_evidence": 0,
        "logtypes_no_itsf_xml":   [],
    }
    out["logtypes"] = OrderedDict()

    no_xml = []

    for lt, spec_row in logtypes_spec.items():
        slider   = spec_row["slider"]
        subcls   = spec_row.get("sub_class", "")
        bridge   = join["spec_to_itsf"].get(lt, {})
        groups   = bridge.get("matched_groups", []) or []
        itsf_dirs = bridge.get("itsf_dirs", []) or []

        # Bucket the ITSF groups by section_id
        agg = defaultdict(lambda: {"report_count": 0, "group_count": 0, "groups": []})
        for g in groups:
            sid = g.get("section")
            if not sid:
                continue
            agg[sid]["report_count"] += int(g.get("report_count", 0))
            agg[sid]["group_count"]  += 1
            agg[sid]["groups"].append((int(g.get("report_count", 0)), g["group_name"]))

        # Split B vs E (for both device and other sliders we honour real evidence)
        baseline_rows, enriched_rows = [], []

        def row_for(sid, evidence, slider):
            if slider == "device":
                name = dev_b_names.get(sid) or dev_e_names.get(sid) or sid
                tab  = dev_b_tabs.get(sid)  or dev_e_tabs.get(sid)  or "Activity"
            else:
                # Other slider: prefer OB/OE catalog; if id is a device B/E
                # (cloud apps with rich auth/admin data), force the Other
                # "Activity" tab so it renders alongside OB3 instead of inventing
                # device-only tabs (Host/Device Activity) that the Other entity
                # has no concept of.
                name = oth_b_names.get(sid) or oth_e_names.get(sid) \
                       or dev_b_names.get(sid) or dev_e_names.get(sid) or sid
                if sid in oth_b_tabs or sid in oth_e_tabs:
                    tab = oth_b_tabs.get(sid) or oth_e_tabs.get(sid)
                else:
                    tab = "Activity"
            top_groups = [name for _, name in sorted(evidence["groups"], reverse=True)][:12]
            return {
                "section_id":   sid,
                "name":         name,
                "tab":          tab,
                "report_count": evidence["report_count"],
                "group_count":  evidence["group_count"],
                "always_on":    False,
                "top_groups":   top_groups,
            }

        for sid, ev in agg.items():
            row = row_for(sid, ev, slider)
            (baseline_rows if sid.startswith("B") or sid.startswith("OB") else enriched_rows).append(row)

        # Inject always-on placeholders that aren't already present
        present_ids = {r["section_id"] for r in baseline_rows + enriched_rows}
        always_b = list(DEVICE_ALWAYS_ON_B if slider == "device" else OTHER_ALWAYS_ON_B)
        always_e = list(DEVICE_ALWAYS_ON_E if slider == "device" else OTHER_ALWAYS_ON_E)

        # Per-logtype extra always-on (e.g. Syslog as network device)
        override = LOGTYPE_OVERRIDES.get(lt, {})
        for sid in override.get("extra_always_on", []):
            if sid.startswith("B") or sid.startswith("OB"):
                always_b.append(sid)
            else:
                always_e.append(sid)
        # de-dup preserving order
        seen = set(); always_b = [s for s in always_b if not (s in seen or seen.add(s))]
        seen = set(); always_e = [s for s in always_e if not (s in seen or seen.add(s))]
        for sid in always_b:
            if sid in present_ids:
                continue
            name_map = dev_b_names if slider == "device" else oth_b_names
            tab_map  = dev_b_tabs  if slider == "device" else oth_b_tabs
            baseline_rows.append({
                "section_id":   sid,
                "name":         name_map.get(sid, sid),
                "tab":          tab_map.get(sid, "Overview"),
                "report_count": 0,
                "group_count":  0,
                "always_on":    True,
                "top_groups":   [],
            })
        for sid in always_e:
            if sid in present_ids:
                continue
            name_map = dev_e_names if slider == "device" else oth_e_names
            tab_map  = dev_e_tabs  if slider == "device" else oth_e_tabs
            enriched_rows.append({
                "section_id":   sid,
                "name":         name_map.get(sid, sid),
                "tab":          tab_map.get(sid, "Overview"),
                "report_count": 0,
                "group_count":  0,
                "always_on":    True,
                "top_groups":   [],
            })

        # Sort: spec-id order
        baseline_rows.sort(key=lambda r: sec_sort_key(r["section_id"]))
        enriched_rows.sort(key=lambda r: sec_sort_key(r["section_id"]))

        total_reports = sum(g.get("report_count", 0) for g in groups)
        total_groups  = len(groups)
        if not itsf_dirs or total_groups == 0:
            no_xml.append(lt)

        out["logtypes"][lt] = {
            "slider":            slider,
            "sub_class":         subcls,
            "itsf_dirs":         itsf_dirs,
            "itsf_group_count":  total_groups,
            "itsf_report_count": total_reports,
            "baseline":          baseline_rows,
            "enriched":          enriched_rows,
            "status":            (
                "out_of_scope"   if override.get("out_of_scope")   else
                "needs_sourcing" if override.get("needs_sourcing") else
                "ok"
            ),
            "override_note":     override.get("note", ""),
        }

    out["totals"]["logtypes_with_evidence"] = sum(
        1 for v in out["logtypes"].values() if v["itsf_group_count"] > 0
    )
    out["totals"]["logtypes_no_itsf_xml"] = no_xml

    with open(OUT, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"wrote {OUT}")
    print(f"logtypes total:         {out['totals']['logtypes']}")
    print(f"with ITSF evidence:     {out['totals']['logtypes_with_evidence']}")
    print(f"without ITSF xml ({len(no_xml)}): {no_xml}")


if __name__ == "__main__":
    main()
