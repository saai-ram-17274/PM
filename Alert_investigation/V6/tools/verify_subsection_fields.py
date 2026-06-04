#!/usr/bin/env python3
"""
verify_subsection_fields.py

For every sub-section that this doc renders for each log-type, check whether the
columns the spec doc *claims* to display actually exist in
nlq_event_field_mapping.json for that log-type. Emits a verified / missing /
candidate-substitutes table per (logtype, section).

The "claims" dict below is a verbatim transcription of the column lists in
device_and_other_entity_spec.md §3.2 / §3.3 / §3.4 / §5.2 / §5.3.

The "feeds" dict below is the evidence-grounded baseline+enriched mapping from
data/soc_per_logtype_dataset.json (B/E ids per logtype, non-always-on rows
only). It is computed at runtime, not hard-coded.
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NLQ = Path("/home/saairam-17274/Documents/REPOS/itsf/product_package/conf/itsf/common/ai/nlq/data/nlq_event_field_mapping.json")
SOC = ROOT / "data" / "soc_per_logtype_dataset.json"

# Columns the spec claims to render for each sub-section, verbatim from
# device_and_other_entity_spec.md (one tuple per section id).
CLAIMS = {
    "B1":  ["Total Logons","Successful Logons","Failed Logons","Logon-failure ratio","Lockouts","Unique source IPs","Privileged-account events"],
    "B2":  ["Hostname","FQDN","OS","Build","Domain","OU","Owner","Role","Status","LAPS-managed","Last boot","Last logon","Last seen","Asset source"],
    "B3":  ["USERNAME","LOGON_ID","LOGON_TYPE","session start","session end","duration"],
    "B4":  ["TIME","USERNAME","LOGON_TYPE","SOURCE_IP","SOURCE_HOST","RESULT","FAILURE_REASON"],
    "B5":  ["TIME","ACTOR","TARGET_USER","ACTION","GROUP_NAME","RESULT"],
    "B6":  ["TIME","ALERT_NAME","SEVERITY","RULE","CORRELATION_ID","STATUS"],
    "B7":  ["TIME","USERNAME","SOURCE_IP","DBNAME","ACTION","OBJECTNAME","RESULT"],
    "B8":  ["TIME","CLIENT_IP","METHOD","URL","STATUS","BYTES","USERAGENT"],
    "B9":  ["SOURCE_IP","DEST_IP","SOURCE_PORT","DEST_PORT","PROTOCOL","ACTION","RULENAME","BYTES"],
    "B10": ["USERNAME","SHAREPATH","FILENAME","ACTION","ACCESSES","RESULT"],
    "B11": ["VMNAME","GUEST_OS","POWER_STATE","CLUSTERNAME","last vMotion","snapshot count"],
    "E1":  ["agent_state","agent_version","last_heartbeat","missed_heartbeat","log_lag","av_status"],
    "E2":  ["GPO_NAME","SCOPE","LINK_OU","version","last_applied","result"],
    "E3":  ["TIME","PROCESSNAME","PARENT_PROCESS","COMMANDLINE","USERNAME","INTEGRITY_LEVEL","HASH","SIGNER"],
    "E4":  ["TIME","SERVICE_NAME","SERVICE_FILE_NAME","SERVICE_TYPE","START_TYPE","ACCOUNT","RESULT"],
    "E5":  ["TIME","TASK_NAME","ACTOR","COMMAND","TRIGGER","RUN_AS"],
    "E6":  ["TIME","USERNAME","DEVICE_NAME","DEVICE_ID","VENDOR","PRODUCT_ID","SERIAL","CLASS"],
    "E7":  ["TIME","USERNAME","SOURCE_IP","DBNAME","ACTION","OBJECTNAME","QUERY","ROWS_AFFECTED","RESULT"],
    "E8":  ["TIME","CLIENT_IP","USERNAME","URL","CATEGORY","ACTION","BYTES","USERAGENT","REFERER"],
    "E9":  ["TIME","SRC_IP","SRC_PORT","DST_IP","DST_PORT","PROTO","RULE","ACTION","BYTES_IN","BYTES_OUT","DURATION","USERNAME"],
    "E10": ["TIME","SRC_IP","DST_IP","SIGNATURE","THREAT_NAME","CATEGORY","SEVERITY","ACTION","CVE"],
    "E11": ["TIME","USERNAME","CLIENT_IP","ASSIGNED_IP","GROUP","AUTH_METHOD","MFA_USED","DURATION","BYTES","RESULT"],
    "E12": ["TIME","ADMIN_USER","SOURCE_IP","OBJECT","CHANGE_TYPE","OLD_VALUE","NEW_VALUE","RESULT"],
    "E13": ["TIME","COMPONENT","EVENT","SEVERITY","MESSAGE"],
    "E14": ["TIME","IPADDRESS","OID","TRAP_TYPE","SEVERITY","VARBINDS","MESSAGE"],
    "E15": ["TIME","USERNAME","SOURCE_IP","SHAREPATH","FILENAME","ACCESSES","RESULT"],
    "E16": ["TIME","USERNAME","SOURCE_IP","EVENT_TYPE","TARGET_VM_OR_CLUSTER","RESULT"],
    "E18": ["TIME","FILENAME","ACTION","USERNAME","PROCESSNAME","SHA256_BEFORE","SHA256_AFTER"],
    "E19": ["TIME","USERNAME","DOCUMENT_NAME","PRINTER_NAME","PAGES","BYTES","RESULT"],
    "OB1": ["entity-specific widgets — see spec §5.5"],
    "OB2": ["entity name","entity type","parent host","owner","first-seen","last-seen","ingest source","ingest health"],
    "OB3": ["TIME","actor","operation","target","result"],
    "OB4": ["TIME","ALERT_NAME","SEVERITY","RULE","CORRELATION_ID","STATUS"],
    "OE1": ["full audit timeline — same fields as OB3 + secondary event types"],
    "OE2": ["target","event_count"],
    "OE3": ["TIME","ADMIN_USER","OBJECT","CHANGE_TYPE","OLD_VALUE","NEW_VALUE","RESULT"],
    "OE4": ["entity","edge_type","edge_count"],
}

# Synonyms — claim-name (uppercased) → list of regex patterns to test against
# real field names (case-insensitive). Order matters: first match wins.
SYNONYMS = {
    "TIME":              [r"^(LOGGED_TIME|RECEIVED_TIME|TIMESTAMP|EVENT_TIME|TIME)$"],
    "USERNAME":          [r"^USERNAME$", r"^USER_NAME$", r"^USER$", r"^ACCOUNT_NAME$", r"^ACTOR$", r"^TARGET_USERNAME$", r"^TARGET_USER$"],
    "ACTOR":             [r"^USERNAME$", r"^USER_NAME$", r"^SUBJECT_USERNAME$", r"^ACCOUNT_NAME$"],
    "TARGET_USER":       [r"^TARGET_USERNAME$", r"^TARGET_USER$", r"^TARGETUSER$", r"^USERNAME$"],
    "DOMAIN":            [r"^DOMAIN$", r"^DOMAIN_NAME$"],
    "SOURCE_IP":         [r"^SOURCE_IP$", r"^SRC_IP$", r"^REMOTEIP$", r"^CLIENT_IP$", r"^IPADDRESS$"],
    "CLIENT_IP":         [r"^CLIENT_IP$", r"^SOURCE_IP$", r"^REMOTEIP$", r"^SRC_IP$"],
    "SRC_IP":            [r"^SRC_IP$", r"^SOURCE_IP$", r"^REMOTEIP$"],
    "DEST_IP":           [r"^DEST_IP$", r"^DST_IP$", r"^DESTINATION_IP$", r"^TARGETIP$"],
    "DST_IP":            [r"^DST_IP$", r"^DEST_IP$", r"^DESTINATION_IP$"],
    "SOURCE_PORT":       [r"^SOURCE_PORT$", r"^SRC_PORT$"],
    "DEST_PORT":         [r"^DEST_PORT$", r"^DST_PORT$", r"^DESTINATION_PORT$"],
    "SRC_PORT":          [r"^SRC_PORT$", r"^SOURCE_PORT$"],
    "DST_PORT":          [r"^DST_PORT$", r"^DEST_PORT$"],
    "PROTOCOL":          [r"^PROTOCOL$", r"^PROTO$"],
    "PROTO":             [r"^PROTOCOL$", r"^PROTO$"],
    "ACTION":            [r"^ACTION$", r"^OPERATION$", r"^EVENTACTION$", r"^IENAME$"],
    "RESULT":            [r"^RESULT$", r"^STATUS$", r"^OUTCOME$"],
    "STATUS":            [r"^STATUS$", r"^RESULT$", r"^HTTP_STATUS$"],
    "RULENAME":          [r"^RULENAME$", r"^RULE$", r"^RULE_NAME$", r"^POLICY_NAME$"],
    "RULE":              [r"^RULE$", r"^RULENAME$", r"^RULE_NAME$"],
    "BYTES":             [r"^BYTES$", r"^BYTES_SENT$", r"^BYTES_RECEIVED$", r"^TOTAL_BYTES$", r"^DURATION$"],
    "URL":               [r"^URL$", r"^REQUEST_URL$", r"^FILENAME$"],
    "METHOD":            [r"^METHOD$", r"^HTTP_METHOD$", r"^OPERATION$"],
    "USERAGENT":         [r"^USERAGENT$", r"^USER_AGENT$"],
    "REFERER":           [r"^REFERER$", r"^REFERRER$"],
    "CATEGORY":          [r"^CATEGORY$", r"^URL_CATEGORY$"],
    "LOGON_TYPE":        [r"^LOGONTYPE$", r"^LOGON_TYPE$"],
    "LOGON_ID":          [r"^LOGON_ID$", r"^LOGONID$"],
    "FAILURE_REASON":    [r"^FAILURE_REASON$", r"^SUB_STATUS$", r"^SUBSTATUS$", r"^FAILUREREASON$"],
    "SOURCE_HOST":       [r"^SOURCE_HOST$", r"^WORKSTATION$", r"^WORKSTATIONNAME$", r"^SOURCEHOST$"],
    "DBNAME":            [r"^DBNAME$", r"^DATABASE_NAME$", r"^DATABASE$"],
    "OBJECTNAME":        [r"^OBJECTNAME$", r"^OBJECT_NAME$", r"^OBJECT$"],
    "GROUP_NAME":        [r"^GROUP_NAME$", r"^GROUPNAME$", r"^TARGET_GROUP$"],
    "PROCESSNAME":       [r"^PROCESSNAME$", r"^PROCESS_NAME$", r"^IMAGE$"],
    "PARENT_PROCESS":    [r"^PARENT_PROCESS$", r"^PARENT_IMAGE$", r"^PARENTPROCESSNAME$"],
    "COMMANDLINE":       [r"^COMMANDLINE$", r"^COMMAND_LINE$", r"^COMMAND$"],
    "INTEGRITY_LEVEL":   [r"^INTEGRITY_LEVEL$", r"^INTEGRITYLEVEL$"],
    "HASH":              [r"^HASH$", r"^SHA256$", r"^MD5$", r"^HASHES$"],
    "SIGNER":            [r"^SIGNER$", r"^SIGNED$", r"^SIGNATURE_STATUS$"],
    "SERVICE_NAME":      [r"^SERVICE_NAME$", r"^SERVICENAME$"],
    "SERVICE_FILE_NAME": [r"^SERVICE_FILE_NAME$", r"^SERVICE_FILENAME$", r"^IMAGE_PATH$"],
    "SERVICE_TYPE":      [r"^SERVICE_TYPE$", r"^SERVICETYPE$"],
    "START_TYPE":        [r"^START_TYPE$", r"^STARTTYPE$", r"^SERVICE_START_TYPE$"],
    "ACCOUNT":           [r"^ACCOUNT$", r"^USERNAME$", r"^SERVICE_ACCOUNT$"],
    "TASK_NAME":         [r"^TASKNAME$", r"^TASK_NAME$"],
    "COMMAND":           [r"^COMMAND$", r"^COMMANDLINE$"],
    "TRIGGER":           [r"^TRIGGER$", r"^SCHEDULE$"],
    "RUN_AS":            [r"^RUN_AS$", r"^RUNAS$", r"^ACCOUNT$"],
    "DEVICE_NAME":       [r"^DEVICE_NAME$", r"^DEVICENAME$", r"^DEVICE$"],
    "DEVICE_ID":         [r"^DEVICE_ID$", r"^DEVICEID$"],
    "VENDOR":            [r"^VENDOR$", r"^VENDORNAME$", r"^VENDOR_NAME$"],
    "PRODUCT_ID":        [r"^PRODUCT_ID$", r"^PRODUCTID$", r"^PRODUCT_NAME$"],
    "SERIAL":            [r"^SERIAL$", r"^SERIALNUMBER$", r"^SERIAL_NUMBER$"],
    "CLASS":             [r"^CLASS$", r"^DEVICE_CLASS$", r"^CLASS_NAME$"],
    "QUERY":             [r"^QUERY$", r"^SQLTEXT$", r"^SQL_TEXT$", r"^STATEMENT$"],
    "ROWS_AFFECTED":     [r"^ROWS_AFFECTED$", r"^ROWCOUNT$"],
    "SIGNATURE":         [r"^SIGNATURE$", r"^SIGID$", r"^SIGNATURE_ID$"],
    "THREAT_NAME":       [r"^THREAT_NAME$", r"^THREATNAME$", r"^VIRUSNAME$", r"^MALWARE_NAME$"],
    "SEVERITY":          [r"^SEVERITY$", r"^SEVERITY_LEVEL$", r"^PRIORITY$"],
    "CVE":               [r"^CVE$", r"^CVE_ID$", r"^CVENUMBER$"],
    "ASSIGNED_IP":       [r"^ASSIGNED_IP$", r"^ASSIGNEDIP$", r"^VPN_IP$"],
    "GROUP":             [r"^GROUP$", r"^GROUP_NAME$", r"^GROUPNAME$"],
    "AUTH_METHOD":       [r"^AUTH_METHOD$", r"^AUTHMETHOD$", r"^AUTHENTICATION_METHOD$"],
    "MFA_USED":          [r"^MFA_USED$", r"^MFA$"],
    "DURATION":          [r"^DURATION$", r"^SESSION_DURATION$"],
    "ADMIN_USER":        [r"^ADMIN_USER$", r"^ADMINUSER$", r"^USERNAME$"],
    "OBJECT":            [r"^OBJECT$", r"^OBJECTNAME$", r"^OBJECT_NAME$", r"^TARGET$"],
    "CHANGE_TYPE":       [r"^CHANGE_TYPE$", r"^OPERATION$", r"^ACTION$", r"^IENAME$"],
    "OLD_VALUE":         [r"^OLD_VALUE$", r"^OLDVALUE$", r"^OLD$"],
    "NEW_VALUE":         [r"^NEW_VALUE$", r"^NEWVALUE$", r"^NEW$"],
    "COMPONENT":         [r"^COMPONENT$", r"^SUBSYSTEM$", r"^MODULE$", r"^SOURCE$"],
    "EVENT":             [r"^EVENT$", r"^IENAME$", r"^EVENT_NAME$", r"^EVENTID$"],
    "MESSAGE":           [r"^MESSAGE$", r"^DESCRIPTION$", r"^DETAIL$"],
    "IPADDRESS":         [r"^IPADDRESS$", r"^IP_ADDRESS$", r"^SOURCE_IP$"],
    "OID":               [r"^OID$", r"^TRAP_OID$"],
    "TRAP_TYPE":         [r"^TRAP_TYPE$", r"^TRAPTYPE$"],
    "VARBINDS":          [r"^VARBINDS$", r"^VARBIND$"],
    "FILENAME":          [r"^FILENAME$", r"^FILE_NAME$", r"^OBJECTNAME$"],
    "SHAREPATH":         [r"^SHAREPATH$", r"^SHARENAME$", r"^SHARE_NAME$"],
    "ACCESSES":          [r"^ACCESSES$", r"^ACCESS_MASK$", r"^ACCESSMASK$"],
    "EVENT_TYPE":        [r"^EVENT_TYPE$", r"^EVENTTYPE$", r"^IENAME$"],
    "TARGET_VM_OR_CLUSTER":[r"^VMNAME$", r"^CLUSTERNAME$", r"^TARGET$", r"^OBJECTNAME$"],
    "SHA256_BEFORE":     [r"^SHA256_BEFORE$", r"^OLD_HASH$"],
    "SHA256_AFTER":      [r"^SHA256_AFTER$", r"^NEW_HASH$", r"^SHA256$"],
    "DOCUMENT_NAME":     [r"^DOCUMENT_NAME$", r"^DOCUMENTNAME$", r"^FILENAME$"],
    "PRINTER_NAME":      [r"^PRINTER_NAME$", r"^PRINTERNAME$"],
    "PAGES":             [r"^PAGES$", r"^PAGE_COUNT$"],
    "VMNAME":            [r"^VMNAME$", r"^VM_NAME$"],
    "GUEST_OS":          [r"^GUEST_OS$", r"^GUESTOS$", r"^OS$"],
    "POWER_STATE":       [r"^POWER_STATE$", r"^POWERSTATE$", r"^STATE$"],
    "CLUSTERNAME":       [r"^CLUSTERNAME$", r"^CLUSTER_NAME$"],
    "ALERT_NAME":        [r"^ALERT_NAME$", r"^ALERTNAME$", r"^RULENAME$"],
    "CORRELATION_ID":    [r"^CORRELATION_ID$", r"^CORRELATIONID$"],
}

def resolve(claim: str, fields: set[str]) -> tuple[str|None, list[str]]:
    """Return (matched_field, candidates). matched_field is the first nlq field
    that matches a synonym pattern for `claim`. candidates is the full list of
    substring-near-match field names (helpful for manual review)."""
    up = claim.upper().replace(" ", "_").replace("-", "_")
    for pat in SYNONYMS.get(up, [f"^{re.escape(up)}$"]):
        for f in fields:
            if re.fullmatch(pat, f, re.IGNORECASE):
                return f, []
    # Substring fallback for candidates only (NOT a match)
    base = re.split(r"[_\s]", up)[0]
    cands = sorted([f for f in fields if base and base.lower() in f.lower()])[:5]
    return None, cands


def main():
    nlq = json.load(open(NLQ))
    soc = json.load(open(SOC))

    rows = []  # (logtype, section_id, section_name, claim, matched_field, candidates)
    for lt, lt_obj in soc["logtypes"].items():
        if lt not in nlq:
            continue
        fields = set(nlq[lt].keys())
        # Collect non-always-on baseline + enriched section ids
        feeds = []
        for r in lt_obj.get("baseline", []) + lt_obj.get("enriched", []):
            if not r.get("always_on") and r["section_id"] in CLAIMS:
                feeds.append((r["section_id"], r["name"]))
        for sid, sname in feeds:
            for claim in CLAIMS.get(sid, []):
                # widgets / narrative claims — skip resolve
                if any(tok in claim for tok in ("—", "see ", "ratio", "%", "count of", "secondary", "widget")):
                    rows.append((lt, sid, sname, claim, "[narrative]", []))
                    continue
                matched, cands = resolve(claim, fields)
                rows.append((lt, sid, sname, claim, matched or "MISSING", cands))

    # Aggregate counts
    total = sum(1 for r in rows if r[4] != "[narrative]")
    missing = sum(1 for r in rows if r[4] == "MISSING")
    print(f"Total field-claims checked: {total}")
    print(f"  matched: {total - missing}")
    print(f"  missing: {missing}")
    print()

    # Per-section miss-rate summary
    from collections import defaultdict
    sect_total = defaultdict(int); sect_miss = defaultdict(int)
    for lt, sid, sname, claim, matched, cands in rows:
        if matched == "[narrative]": continue
        sect_total[sid] += 1
        if matched == "MISSING": sect_miss[sid] += 1
    print(f"{'sect':<5} {'miss/total':<12} {'pct':<5}  name")
    for sid in sorted(sect_total, key=lambda x: (-sect_miss[x]/sect_total[x], x)):
        pct = 100.0 * sect_miss[sid] / sect_total[sid]
        # find a representative name
        name = next((s for (l,s_,n,c,m,c2) in rows for s in [n] if s_ == sid), "?")
        print(f"  {sid:<3} {sect_miss[sid]:>3}/{sect_total[sid]:<3}   {pct:5.1f}%  {name}")

    # Dump full table
    out = ROOT / "data" / "subsection_field_audit.json"
    j = []
    for lt, sid, sname, claim, matched, cands in rows:
        j.append({"logtype": lt, "section_id": sid, "section_name": sname,
                  "claim": claim, "matched": matched, "candidates": cands})
    out.write_text(json.dumps(j, indent=2))
    print(f"\nWrote {out}")

if __name__ == "__main__":
    main()
