#!/usr/bin/env python3
"""
build_field_projection.py

For every (logtype, section_id) pair in soc_per_logtype_dataset.json, derive a
5–8-field SOC-useful shortlist drawn ONLY from fields that actually exist on
that log-type in nlq_event_field_mapping.json. Output:
  data/soc_field_projection.json   -> { logtype: { section_id: [fields...] } }

Role-bucket strategy: each sub-section declares a priority-ordered list of
"role" patterns (TIME, actor, source, target, action, outcome, threat…). For
each logtype that feeds a section, iterate buckets in order; for each bucket
pick the first nlq field that regex-matches, cap at 8 distinct fields. Skip
buckets with no match — never invent.
"""
from __future__ import annotations
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NLQ  = Path("/home/saairam-17274/Documents/REPOS/itsf/product_package/conf/itsf/common/ai/nlq/data/nlq_event_field_mapping.json")
SOC  = ROOT / "data" / "soc_per_logtype_dataset.json"
OUT  = ROOT / "data" / "soc_field_projection.json"

# Role buckets used across sections. Patterns are regex (case-insensitive),
# matched against the full nlq field name with re.fullmatch.
BUCKETS = {
    "TIME":          r"^(LOGGED_TIME|RECEIVED_TIME|EVENT_TIME|TIMESTAMP|TIME|EVENT_DATETIME|DETECTION_TIME)$",
    "USER":          r"^(USERNAME|USER_NAME|USER|ACCOUNT_NAME|ACCOUNTNAME|SUBJECT_USERNAME|EVENTUSER|LOGON_USER|TUSERNAME)$",
    "TARGET_USER":   r"^(TARGET_USERNAME|TARGET_USER|TARGETUSER|TARGET_ACCOUNTNAME|TARGET_ACCOUNT)$",
    "ADMIN_USER":    r"^(ADMIN|ADMIN_USER|ADMINUSER|ADMIN_NAME)$",
    "SRC_IP":        r"^(SOURCE_IP|SRC_IP|REMOTEIP|CLIENT_IP|IPADDRESS|IP_ADDRESS|SRCIP|SOURCEIP)$",
    "SRC_HOST":      r"^(SOURCE_HOST|SOURCEHOST|WORKSTATION|WORKSTATIONNAME|SRCHOST|HOSTNAME)$",
    "SRC_PORT":      r"^(SOURCE_PORT|SRC_PORT|SOURCEPORT|SRCPORT)$",
    "DST_IP":        r"^(DEST_IP|DST_IP|DESTINATION_IP|TARGETIP|DESTIP|DESTINATIONIP)$",
    "DST_PORT":      r"^(DEST_PORT|DST_PORT|DESTINATION_PORT|DESTPORT)$",
    "PROTOCOL":      r"^(PROTOCOL|PROTO)$",
    "ACTION":        r"^(ACTION|OPERATION|EVENTACTION|IENAME|EVENTNAME|EVENT_NAME|ACTIVITY)$",
    "RESULT":        r"^(RESULT|STATUS|OUTCOME|EVENT_RESULT|HTTP_STATUS|STATUSCODE)$",
    "FAIL_REASON":   r"^(FAILURE_REASON|FAILUREREASON|SUB_STATUS|SUBSTATUS|REASON|FAILREASON|ERROR)$",
    "LOGON_TYPE":    r"^(LOGONTYPE|LOGON_TYPE)$",
    "LOGON_ID":      r"^(LOGON_ID|LOGONID)$",
    "DOMAIN":        r"^(DOMAIN|DOMAIN_NAME|DOMAINNAME|TARGET_DOMAIN)$",
    "EVENT_ID":      r"^(EVENTID|EVENT_ID|EID|EVENT_TYPE_ID)$",
    "SEVERITY":      r"^(SEVERITY|SEVERITY_LEVEL|PRIORITY|RISK_LEVEL|RISKLEVEL)$",
    "MESSAGE":       r"^(MESSAGE|DESCRIPTION|DETAIL|EVENT_DESCRIPTION|MSG)$",
    "RULE":          r"^(RULENAME|RULE|RULE_NAME|POLICY|POLICYNAME|POLICY_NAME)$",
    "GROUP":         r"^(GROUP|GROUP_NAME|GROUPNAME|TARGET_GROUP|TARGETGROUP|MEMBERGROUP)$",
    "OBJECT":        r"^(OBJECTNAME|OBJECT_NAME|OBJECT|TARGET|TARGETNAME|TARGET_NAME)$",
    "OBJECT_TYPE":   r"^(OBJECTTYPE|OBJECT_TYPE|TARGET_TYPE)$",
    "FILE":          r"^(FILENAME|FILE_NAME|FILE|FILEPATH|FILE_PATH|FILEPATHNAME|OBJECTNAME)$",
    "SHARE":         r"^(SHAREPATH|SHARENAME|SHARE_NAME|SHARE)$",
    "ACCESS":        r"^(ACCESSES|ACCESS_MASK|ACCESSMASK|ACCESS|PRIVILEGE|PRIVILEGES)$",
    "PROCESS":       r"^(PROCESSNAME|PROCESS_NAME|IMAGE|PROCESS)$",
    "PARENT_PROC":   r"^(PARENT_PROCESS|PARENT_IMAGE|PARENTPROCESSNAME|PARENTPROCESS)$",
    "CMDLINE":       r"^(COMMANDLINE|COMMAND_LINE|COMMAND)$",
    "INTEGRITY":     r"^(INTEGRITY_LEVEL|INTEGRITYLEVEL)$",
    "HASH":          r"^(HASH|HASHES|SHA256|MD5|SHA1|FILEHASH)$",
    "SIGNER":        r"^(SIGNER|SIGNATURE_STATUS|SIGNED|SIGNATURESTATUS)$",
    "SERVICE":       r"^(SERVICE_NAME|SERVICENAME|SERVICE)$",
    "SVC_IMAGE":     r"^(SERVICE_FILE_NAME|SERVICE_FILENAME|IMAGE_PATH|IMAGEPATH|SERVICEFILE)$",
    "START_TYPE":    r"^(START_TYPE|STARTTYPE|SERVICE_START_TYPE)$",
    "ACCOUNT":       r"^(SERVICE_ACCOUNT|SERVICEACCOUNT|ACCOUNT|RUN_AS|RUNAS|RUN_AS_USER)$",
    "TASK":          r"^(TASKNAME|TASK_NAME|TASK)$",
    "TRIGGER":       r"^(TRIGGER|SCHEDULE|TASKTRIGGER)$",
    "VENDOR":        r"^(VENDOR|VENDORNAME|VENDOR_NAME)$",
    "PRODUCT":       r"^(PRODUCT|PRODUCTNAME|PRODUCT_NAME|PRODUCT_ID|PRODUCTID|MODEL)$",
    "SERIAL":        r"^(SERIAL|SERIAL_NUMBER|SERIALNUMBER)$",
    "DEVICE_CLASS":  r"^(DEVICE_CLASS|DEVICECLASS|CLASS|CLASS_NAME)$",
    "DEVICE":        r"^(DEVICE|DEVICENAME|DEVICE_NAME|DEVICE_ID|DEVICEID)$",
    "DBNAME":        r"^(DBNAME|DATABASE|DATABASENAME|DATABASE_NAME|DB)$",
    "SCHEMA":        r"^(SCHEMA|SCHEMANAME|SCHEMA_NAME)$",
    "QUERY":         r"^(QUERY|SQLTEXT|SQL_TEXT|STATEMENT|SQLSTATEMENT)$",
    "ROWS":          r"^(ROWS_AFFECTED|ROWCOUNT|ROWS|AFFECTED_ROWS)$",
    "URL":           r"^(URL|REQUEST_URL|URI|REQUESTURI|REQUESTURL)$",
    "URL_CAT":       r"^(CATEGORY|URL_CATEGORY|CATEGORYNAME|WEB_CATEGORY)$",
    "METHOD":        r"^(METHOD|HTTP_METHOD|REQUEST_METHOD|HTTPMETHOD)$",
    "BYTES":         r"^(BYTES|TOTAL_BYTES|BYTES_TOTAL|BYTESCOUNT)$",
    "BYTES_IN":      r"^(BYTES_IN|BYTESIN|BYTES_RECEIVED|RECEIVED_BYTES)$",
    "BYTES_OUT":     r"^(BYTES_OUT|BYTESOUT|BYTES_SENT|SENT_BYTES)$",
    "UA":            r"^(USERAGENT|USER_AGENT|UA|CSUSERAGENT|HTTP_USER_AGENT)$",
    "REFERER":       r"^(REFERER|REFERRER|CSREFERER|HTTP_REFERER)$",
    "SIGNATURE":     r"^(SIGNATURE|SIGID|SIGNATURE_ID|SIGNATURE_NAME|SIGNATURENAME)$",
    "THREAT":        r"^(THREAT_NAME|THREATNAME|VIRUSNAME|VIRUS_NAME|MALWARENAME|MALWARE_NAME|THREAT|INTELLIGENCE)$",
    "ATTACK_CAT":    r"^(THREAT_CATEGORY|ATTACK_CATEGORY|CATEGORY|ATTACK_TYPE|THREAT_TYPE)$",
    "CVE":           r"^(CVE|CVE_ID|CVENUMBER|CVE_NUMBER)$",
    "ASSIGNED_IP":   r"^(ASSIGNED_IP|ASSIGNEDIP|VPN_IP|VPNIP|TUNNEL_IP)$",
    "VPN_GROUP":     r"^(GROUP_POLICY|GROUPPOLICY|VPN_GROUP|TUNNELGROUP|TUNNEL_GROUP)$",
    "AUTH_METHOD":   r"^(AUTH_METHOD|AUTHMETHOD|AUTHENTICATION_METHOD|AUTHTYPE)$",
    "DURATION":      r"^(DURATION|SESSION_DURATION|ELAPSED|ELAPSED_TIME|SESSIONDURATION)$",
    "CHG_TYPE":      r"^(CHANGE_TYPE|CHANGETYPE|MODIFICATION_TYPE)$",
    "OLD_VAL":       r"^(OLD_VALUE|OLDVALUE|PREVIOUS_VALUE|OLD)$",
    "NEW_VAL":       r"^(NEW_VALUE|NEWVALUE|UPDATED_VALUE|NEW)$",
    "VM":            r"^(VMNAME|VM_NAME|VM|VIRTUALMACHINE|VIRTUAL_MACHINE)$",
    "CLUSTER":       r"^(CLUSTERNAME|CLUSTER_NAME|CLUSTER|DATACENTERNAME|DATACENTER)$",
    "POWER":         r"^(POWER_STATE|POWERSTATE|STATE|POWER|VMPOWERSTATE)$",
    "GUEST_OS":      r"^(GUEST_OS|GUESTOS|OS|OSNAME|OS_NAME|GUEST_OS_NAME)$",
    "DOC":           r"^(DOCUMENT_NAME|DOCUMENTNAME|DOCUMENT|DOCNAME|JOBTITLE|JOB_TITLE|JOBNAME)$",
    "PRINTER":       r"^(PRINTER_NAME|PRINTERNAME|PRINTER|PRINTERPATH)$",
    "PAGES":         r"^(PAGES|PAGE_COUNT|PAGECOUNT|TOTAL_PAGES)$",
    "OID":           r"^(OID|TRAP_OID|TRAPOID)$",
    "TRAP":          r"^(TRAP_TYPE|TRAPTYPE|TRAP)$",
    "VARBINDS":      r"^(VARBINDS|VARBIND|VARBIND_LIST)$",
    "MAC":           r"^(MACADDRESS|MAC|MAC_ADDRESS|HARDWARE_ADDRESS)$",
    "SCOPE":         r"^(LEASESCOPE|SCOPE|DHCP_SCOPE|SCOPEID|SUBNET)$",
    "GPO":           r"^(GPO|GPONAME|GPO_NAME)$",
    "RECEIVER":      r"^(RECIPIENT|RECEIVER|RECIPIENTS|TO|TARGET)$",
    "SENDER":        r"^(SENDER|FROM|FROMUSER|MAIL_FROM)$",
    "MAILSUBJECT":   r"^(SUBJECT|MAIL_SUBJECT|SUBJECT_LINE)$",
    "INTERFACE":     r"^(INTERFACE|INTERFACE_NAME|IFNAME|IF_NAME|PORT|PORTNAME)$",
}

# Per-section role priority — first 8 matches become the projection.
SECTIONS = {
    "B3":  ["TIME","USER","LOGON_ID","LOGON_TYPE","SRC_IP","SRC_HOST","DOMAIN","DURATION","EVENT_ID"],
    "B4":  ["TIME","USER","DOMAIN","SRC_IP","SRC_HOST","LOGON_TYPE","RESULT","FAIL_REASON","EVENT_ID"],
    "B5":  ["TIME","USER","TARGET_USER","ACTION","GROUP","DOMAIN","RESULT","EVENT_ID"],
    "B7":  ["TIME","USER","SRC_IP","DBNAME","ACTION","OBJECT","SCHEMA","RESULT"],
    "B8":  ["TIME","SRC_IP","USER","METHOD","URL","RESULT","BYTES","UA"],
    "B9":  ["TIME","SRC_IP","SRC_PORT","DST_IP","DST_PORT","PROTOCOL","ACTION","RULE","BYTES"],
    "B10": ["TIME","USER","SRC_IP","SHARE","FILE","ACCESS","ACTION","RESULT"],
    "B11": ["TIME","VM","CLUSTER","POWER","GUEST_OS","USER","ACTION"],
    "E2":  ["TIME","GPO","USER","OBJECT","RESULT","ACTION"],
    "E3":  ["TIME","PROCESS","PARENT_PROC","CMDLINE","USER","INTEGRITY","HASH","SIGNER"],
    "E4":  ["TIME","SERVICE","SVC_IMAGE","START_TYPE","ACCOUNT","RESULT","EVENT_ID"],
    "E5":  ["TIME","TASK","USER","ACTION","CMDLINE","TRIGGER","ACCOUNT"],
    "E6":  ["TIME","USER","VENDOR","PRODUCT","DEVICE","SERIAL","DEVICE_CLASS","ACTION"],
    "E7":  ["TIME","USER","SRC_IP","DBNAME","ACTION","OBJECT","QUERY","ROWS","RESULT"],
    "E8":  ["TIME","SRC_IP","USER","URL","URL_CAT","METHOD","ACTION","BYTES","UA","REFERER"],
    "E9":  ["TIME","SRC_IP","SRC_PORT","DST_IP","DST_PORT","PROTOCOL","RULE","ACTION","BYTES_IN","BYTES_OUT","DURATION","USER"],
    "E10": ["TIME","SRC_IP","DST_IP","SIGNATURE","THREAT","ATTACK_CAT","SEVERITY","ACTION","CVE","RULE"],
    "E11": ["TIME","USER","SRC_IP","ASSIGNED_IP","VPN_GROUP","AUTH_METHOD","DURATION","BYTES","RESULT"],
    "E12": ["TIME","ADMIN_USER","USER","SRC_IP","OBJECT","CHG_TYPE","OLD_VAL","NEW_VAL","RESULT"],
    "E13": ["TIME","SRC_HOST","EVENT_ID","SEVERITY","SERVICE","ACTION","MESSAGE"],
    "E14": ["TIME","SRC_IP","OID","TRAP","SEVERITY","MESSAGE"],
    "E15": ["TIME","USER","SRC_IP","SHARE","FILE","ACCESS","ACTION","RESULT"],
    "E16": ["TIME","USER","SRC_IP","VM","CLUSTER","ACTION","OBJECT","RESULT"],
    "E18": ["TIME","FILE","ACTION","USER","PROCESS","HASH","OLD_VAL","NEW_VAL"],
    "E19": ["TIME","USER","DOC","PRINTER","PAGES","BYTES","RESULT"],
    # Other slider
    "OB3": ["TIME","USER","SRC_IP","ACTION","OBJECT","RESULT","SEVERITY","MESSAGE"],
}

def project(fields: set[str], role_order: list[str], cap: int = 8) -> list[str]:
    picked, seen = [], set()
    for role in role_order:
        pat = BUCKETS.get(role)
        if not pat: continue
        for f in sorted(fields):
            if re.fullmatch(pat, f, re.IGNORECASE) and f not in seen:
                picked.append(f); seen.add(f)
                break
        if len(picked) >= cap: break
    return picked

def main():
    nlq = json.load(open(NLQ))
    soc = json.load(open(SOC))
    out = {}
    for lt, obj in soc["logtypes"].items():
        if lt not in nlq: continue
        fields = set(nlq[lt].keys())
        per_section = {}
        for r in obj.get("baseline", []) + obj.get("enriched", []):
            if r.get("always_on"): continue
            sid = r["section_id"]
            order = SECTIONS.get(sid)
            if not order: continue
            picked = project(fields, order)
            per_section[sid] = picked
        # B3 (Users Logged On) is not enumerated in soc_per_logtype_dataset.json,
        # but it is the session-view sibling of B4 sourced from the same auth
        # event stream. Synthesise B3 for every logtype that has B4 — the
        # projection will be empty for logtypes whose nlq mapping lacks LOGON_ID
        # / LOGON_TYPE (those logtypes simply do not render B3 at the UI layer).
        if "B4" in per_section and "B3" not in per_section:
            per_section["B3"] = project(fields, SECTIONS["B3"])
        if per_section:
            out[lt] = per_section
    OUT.write_text(json.dumps(out, indent=2))
    # Summary
    total = sum(len(s) for lt in out.values() for s in lt.values())
    empty = sum(1 for lt in out.values() for sid, fs in lt.items() if not fs)
    pairs = sum(len(d) for d in out.values())
    print(f"Logtypes with projection: {len(out)}")
    print(f"(logtype, section) pairs: {pairs}")
    print(f"Total fields picked:      {total}")
    print(f"Empty pairs (no field matched any role): {empty}")
    print(f"Wrote {OUT}")

if __name__ == "__main__":
    main()
