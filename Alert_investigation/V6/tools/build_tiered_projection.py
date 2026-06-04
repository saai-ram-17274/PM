#!/usr/bin/env python3
"""
Build two-tier field projection for §7 of device_and_other_entity_spec.md.

Tier 1 (Top-level): 4-6 fields shown by default — answers "who, what, when, where" at a glance.
Tier 2 (Sub-level / Show More): 5-12 additional fields for deeper investigation.

Reads:
  - nlq_event_field_mapping.json (authoritative field registry per log-type)
  - data/soc_field_projection_enriched.json (current §7 fields, max 10)

Outputs:
  - data/soc_field_tiered_projection.json  (per logtype/section: {top: [...], sub: [...]})
  - Markdown table suitable for §7

Rules per section type define which field roles are "top" priority.
Additional sub-level fields are pulled from the nlq mapping that weren't in the
current projection but are relevant to the section's SOC purpose.
"""

import json
import sys
from pathlib import Path
from collections import OrderedDict

BASE = Path(__file__).resolve().parent.parent
NLQ_PATH = Path("/home/saairam-17274/Documents/REPOS/itsf/product_package/conf/itsf/common/ai/nlq/data/nlq_event_field_mapping.json")
ENRICHED_PATH = BASE / "data" / "soc_field_projection_enriched.json"
OUTPUT_PATH = BASE / "data" / "soc_field_tiered_projection.json"

# --- Per-section-type tiering rules ---
# Each rule: { "top_priority": [...], "sub_candidates": [...] }
# top_priority: ordered list of field name patterns. First N matches (up to 5-6) become top.
# sub_candidates: additional field name patterns to pull from nlq if available.

SECTION_RULES = {
    "B3": {
        "top_priority": [
            "TIME", "USERNAME", "ACCOUNT_NAME", "LOGONTYPE", "REMOTEIP", "SOURCE_IP", "IPADDRESS", "HOSTNAME"
        ],
        "sub_candidates": [
            "LOGONID", "DOMAIN", "EVENTID", "SESSIONTYPE", "WORKSTATION_NAME",
            "PROCESSNAME", "DURATION", "SEVERITY", "AUTHENTICATION", "REMOTEHOST",
            "MODE", "HOSTID", "DOMAINNAME", "PRIVATE_IP", "SOURCE_PORT"
        ],
        "top_max": 5
    },
    "B4": {
        "top_priority": [
            "TIME", "ACCOUNT_NAME", "USERNAME", "REMOTEIP", "SOURCE_IP", "IPADDRESS",
            "RESULT", "STATUS", "FAILUREREASON", "REASON", "HOSTNAME"
        ],
        "sub_candidates": [
            "LOGONTYPE", "DOMAIN", "EVENTID", "PROCESSNAME", "REMOTEHOST",
            "WORKSTATION_NAME", "ENCRYPTIONTYPE", "ERRORCODE", "MODE",
            "HOSTID", "DOMAINNAME", "SEVERITY", "AUTHENTICATION", "SOURCE_PORT",
            "DESCRIPTION", "MESSAGE"
        ],
        "top_max": 5
    },
    "B5": {
        "top_priority": [
            "TIME", "USERNAME", "ACCOUNT_NAME", "TARGETUSER", "ACTION", "IENAME", "RESULT", "STATUS"
        ],
        "sub_candidates": [
            "GROUPNAME", "GROUP", "DOMAIN", "EVENTID", "HOSTNAME", "MACHINENAME",
            "TARGETDOMAIN", "SAMACCOUNTNAME", "MEMBERSID", "DISPLAYNAME",
            "USERPRINCIPALNAME", "SOURCE_IP", "OBJECT", "DESCRIPTION", "NOTES",
            "ACCOUNT_TYPE", "TYPE", "ROLE", "DOMAINNAME", "CONF_OBJECT"
        ],
        "top_max": 5
    },
    "E2": {
        "top_priority": [
            "TIME", "USERNAME", "ACCOUNT_NAME", "OBJECT", "ACTION", "HOSTNAME"
        ],
        "sub_candidates": [
            "DN", "OBJECTNAME", "GUID", "RESULT", "IENAME", "DISPLAYNAME",
            "ACCESSES", "OBJECTTYPE", "CATEGORY", "SUBCATEGORY", "EVENTID", "CHANGES", "PREVVAL"
        ],
        "top_max": 5
    },
    "E3": {
        "top_priority": [
            "TIME", "PROCESSNAME", "COMMANDLINE", "USERNAME", "ACCOUNT_NAME", "PARENTPROCESSNAME"
        ],
        "sub_candidates": [
            "HOSTNAME", "DOMAIN", "PROCESSID", "PARENTPROCESSID",
            "PARENTPROCESSCOMMANDLINE", "LOGONID", "SERVICENAME", "EVENTID",
            "INTEGRITYLEVEL", "HASHES", "SIGNATURESTATUS", "SEVERITY",
            "ORIGINALFILENAME", "PRODUCT_NAME", "CWD", "SIGNED"
        ],
        "top_max": 5
    },
    "E4": {
        "top_priority": [
            "TIME", "SERVICENAME", "SERVICEACCOUNT", "RESULT", "STATUS", "HOSTNAME"
        ],
        "sub_candidates": [
            "SERVICETYPE", "OBJECTNAME", "EVENTID", "USERNAME", "MESSAGE",
            "DOMAIN", "SERVICESTARTTYPE", "PROCESSID", "PROCESSNAME"
        ],
        "top_max": 5
    },
    "E5": {
        "top_priority": [
            "TIME", "USERNAME", "ACCOUNT_NAME", "ACTION", "IENAME", "COMMANDLINE"
        ],
        "sub_candidates": [
            "SERVICEACCOUNT", "HOSTNAME", "EVENTID", "TASKCONTENTNEW",
            "TASKCATEGORY", "DOMAIN", "PROCESSNAME"
        ],
        "top_max": 5
    },
    "E6": {
        "top_priority": [
            "TIME", "USERNAME", "ACCOUNT_NAME", "VENDORNAME", "ACTION", "IENAME", "HOSTNAME"
        ],
        "sub_candidates": [
            "OBJECTNAME", "DOMAIN", "EVENTID", "LOGONID", "MESSAGE",
            "DEVICETYPE", "PHYTYPE", "PROCESSNAME"
        ],
        "top_max": 5
    },
    "B7": {
        "top_priority": [
            "TIME", "DATABASENAME", "IENAME", "ACTION", "STATUS", "STATUSCODE"
        ],
        "sub_candidates": [
            "OBJECTNAME", "SCHEMANAME", "USERNAME", "USERID", "STATEMENT",
            "INSTANCENAME", "PRIVILEGE", "WORKSTATION_NAME", "OBJECTTYPE",
            "REMOTEIP", "IPADDRESS", "OPERATION", "RESULT", "TARGET"
        ],
        "top_max": 5
    },
    "E7": {
        "top_priority": [
            "TIME", "DATABASENAME", "IENAME", "ACTION", "STATEMENT", "STATUS", "STATUSCODE"
        ],
        "sub_candidates": [
            "OBJECTNAME", "SCHEMANAME", "USERNAME", "USERID",
            "INSTANCENAME", "ROWS_MODIFIED", "ROWS_RETURNED", "WORKSTATION_NAME",
            "PROCESSID", "OBJECTTYPE", "COMMAND_TAG", "TRANSACTIONID"
        ],
        "top_max": 5
    },
    "B8": {
        "top_priority": [
            "TIME", "IPADDRESS", "SOURCE_IP", "USERNAME", "HTTPMETHOD", "USERAGENT"
        ],
        "sub_candidates": [
            "HOSTNAME", "HTTPSTATUS", "RESPONSE_TYPE", "REQUEST",
            "RECEIVED_BYTES", "SENT_BYTES", "TIMETAKEN_I", "referrer",
            "URL_SITE", "PROTOCOL_APP", "RISK_LEVEL", "DESCRIPTION"
        ],
        "top_max": 5
    },
    "B9": {
        "top_priority": [
            "TIME", "SOURCE_IP", "REMOTEIP", "IPADDRESS", "DEST_IP", "TARGETIP", "DEST_PORT", "ACTION", "IENAME", "PROTOCOL", "PROTOCOL_TR"
        ],
        "sub_candidates": [
            "SOURCE_PORT", "SOURCEPORT", "RULENAME", "POLICY", "POLICY_NAME",
            "HOSTNAME", "USERNAME", "URL_SITE", "DURATION",
            "RECEIVED_BYTES", "SENT_BYTES", "HOSTID", "SOURCE_ZONE", "DEST_ZONE",
            "SOURCE_INTERFACE", "DEST_INTERFACE", "APPLICATION", "PROTOCOL_APP",
            "MESSAGE", "DIRECTION"
        ],
        "top_max": 6
    },
    "B10": {
        "top_priority": [
            "TIME", "USERNAME", "ACCOUNT_NAME", "SHARENAME", "ACCESSES", "ACTION", "RESULT"
        ],
        "sub_candidates": [
            "FILENAME", "OBJECTNAME", "REMOTEIP", "HOSTNAME", "SHAREPATH",
            "IENAME", "REMOTEHOST", "RELATIVETARGETNAME", "FILETYPE",
            "PROCESSNAME", "DOMAIN"
        ],
        "top_max": 5
    },
    "B11": {
        "top_priority": [
            "TIME", "VMNAME", "USERNAME", "IENAME", "STATUS"
        ],
        "sub_candidates": [
            "HOSTNAME", "REMOTEHOST", "MESSAGE", "HOSTID", "SEVERITY",
            "RESULT", "DOMAIN", "LOGONTYPE"
        ],
        "top_max": 5
    },
    "E8": {
        "top_priority": [
            "TIME", "USERNAME", "IPADDRESS", "REMOTEIP", "SOURCE_IP", "CATEGORY", "IENAME", "ACTION"
        ],
        "sub_candidates": [
            "USERAGENT", "URL_SITE", "URL_ARG", "HOSTNAME", "referrer",
            "DESCRIPTION", "RESPONSE_TYPE", "REQUEST_TYPE", "RISK_LEVEL",
            "OPERATION", "MESSAGE"
        ],
        "top_max": 5
    },
    "E10": {
        "top_priority": [
            "TIME", "SOURCE_IP", "REMOTEIP", "IPADDRESS", "DEST_IP", "TARGETIP", "DESTINATION_IP", "SEVERITY", "ACTION", "IENAME"
        ],
        "sub_candidates": [
            "CATEGORY", "RULENAME", "POLICY", "POLICY_NAME", "INTELLIGENCE",
            "RISK_LEVEL", "HOSTNAME", "SIGNATURE_ID", "IDS_NAME", "ATTACK",
            "MESSAGE", "VIRUS_NAME", "DEST_PORT", "SOURCE_PORT", "EVENTID",
            "PRIORITY", "DESCRIPTION", "CLASSIFICATION", "THREAT_ID"
        ],
        "top_max": 5
    },
    "E11": {
        "top_priority": [
            "TIME", "USERNAME", "SOURCE_IP", "DURATION", "RESULT", "STATUS"
        ],
        "sub_candidates": [
            "HOSTNAME", "MESSAGE", "REMOTEHOST", "PRIVATE_IP", "HOSTID",
            "REASON", "VPN_NAME", "REMOTE_IP", "SOURCEHOST", "IENAME",
            "DESCRIPTION", "TYPE"
        ],
        "top_max": 5
    },
    "E12": {
        "top_priority": [
            "TIME", "USERNAME", "ACCOUNT_NAME", "SOURCE_IP", "REMOTEIP", "IPADDRESS", "OBJECT", "TARGET"
        ],
        "sub_candidates": [
            "OLDVALUE", "NEWVALUE", "RESULT", "STATUS", "HOSTNAME",
            "INTERFACE", "COMMAND", "COMMANDEXECUTED", "CATEGORY", "ACCESSRIGHT",
            "DESCRIPTION", "TARGETUSER", "IENAME", "MESSAGE", "OPERATION",
            "ADMIN_STATUS", "OPERATOR_STATUS", "PROCESS", "PATH", "VLAN_ID",
            "EVENTID", "CONF_OBJECT", "CONF_ATTR", "POLICY_NAME"
        ],
        "top_max": 5
    },
    "E13": {
        "top_priority": [
            "TIME", "HOSTNAME", "SEVERITY", "PRIORITY", "RISK_LEVEL", "MESSAGE", "IENAME"
        ],
        "sub_candidates": [
            "SERVICENAME", "SERVICE_NAME", "ACTION", "EVENTID",
            "USERNAME", "DESCRIPTION", "REMOTEHOST", "DOMAIN", "SOURCE",
            "HOSTID", "NOTES", "COUNT", "NEW_STATUS", "STATUS", "REASON",
            "TYPE", "FACILITY", "SOURCE_IP", "COMMANDEXECUTED", "MODULE"
        ],
        "top_max": 5
    },
    "E14": {
        "top_priority": [
            "TIME", "HOSTNAME", "SEVERITY", "MESSAGE"
        ],
        "sub_candidates": [
            "SOURCE", "FACILITY", "IENAME", "HOSTID", "TYPE"
        ],
        "top_max": 4
    },
    "E15": {
        "top_priority": [
            "TIME", "USERNAME", "FILENAME", "FILE_NAME", "IENAME", "ACTION", "RESULT"
        ],
        "sub_candidates": [
            "HOSTNAME", "SHAREPATH", "SHARENAME", "DOMAIN", "REMOTEIP",
            "OBJECTNAME", "PROCESSNAME", "MESSAGE", "SEVERITY"
        ],
        "top_max": 5
    },
    "E16": {
        "top_priority": [
            "TIME", "USERNAME", "EVENTNAME", "TARGET", "DATACENTER"
        ],
        "sub_candidates": [
            "REMOTEIP", "HOSTNAME", "OLDVALUE", "NEWVALUE", "DATASTORE",
            "DISK", "SOURCEHOST", "DESTINATIONHOST", "RESOURCEPOOL",
            "NETWORK", "FILE", "SEVERITY", "STATE", "ERRORMESSAGE"
        ],
        "top_max": 5
    },
    "E18": {
        "top_priority": [
            "TIME", "FILENAME", "OBJECTNAME", "NAME", "FILE",
            "ACTION", "IENAME", "CHANGETYPE",
            "USERNAME", "ACCOUNT_NAME"
        ],
        "sub_candidates": [
            "PROCESSNAME", "OLDVALUE", "NEWVALUE", "HOSTNAME", "FILETYPE",
            "HASHES", "LOCATION", "PLATFORM", "FILESIZE", "ACCESSMASK",
            "SHAREPATH", "PREVVAL", "OPERATIONID", "CHANGETYPE", "SEVERITY",
            "OPERATION", "MESSAGE"
        ],
        "top_max": 5
    },
    "E19": {
        "top_priority": [
            "TIME", "DOCNAME", "PRINTER", "OWNEDBY"
        ],
        "sub_candidates": [
            "SIZE", "PAGESPRINTED", "PORT", "SPOOLERTIME", "HOSTNAME",
            "DOCID", "OWNEDON", "SEVERITY", "MESSAGE", "TYPE"
        ],
        "top_max": 4
    },
    "OB3": {
        "top_priority": [
            "TIME", "USERNAME", "ACTION", "OPERATION", "IENAME", "SEVERITY", "RESULT"
        ],
        "sub_candidates": [
            "IPADDRESS", "SOURCE_IP", "REMOTEIP", "MESSAGE", "DESCRIPTION",
            "OBJECT", "TARGET", "RISK_LEVEL", "STATUS", "OBJECTNAME",
            "HOSTNAME", "CATEGORY", "EVENTID", "USERAGENT"
        ],
        "top_max": 5
    },
}

# --- Per-log-type OB3 overrides ---
# OB3 serves many different entity classes; a single generic rule can't handle
# vuln scanners vs EDR vs DLP vs cloud SaaS vs network scanners.
OB3_OVERRIDES = {
    # Vulnerability scanners — findings-centric
    "Nessus": {
        "top_priority": ["TIME", "VULNNAME", "SEVERITYLEVEL", "CVE", "PORT", "RISKFACTOR"],
        "sub_candidates": ["HOSTNAME", "OS", "PROTOCOL", "EXPLOITAVAIL", "SERVICENAME",
                           "HOSTIP", "PLUGINID", "GROUP", "DESCRIPTION", "MESSAGE"],
        "top_max": 6
    },
    "Qualys": {
        "top_priority": ["TIME", "VULNNAME", "SEVERITYLEVEL", "CVE", "RESULT", "RISKFACTOR"],
        "sub_candidates": ["HOSTNAME", "OS", "PORT", "PROTOCOL", "EXPLOITS", "MALWARE",
                           "STATUS", "HOSTIP", "QUALYSTYPE", "GROUP", "MESSAGE"],
        "top_max": 6
    },
    "Nexpose": {
        "top_priority": ["TIME", "VULNNAME", "SEVERITYLEVEL", "RISKSCORE", "STATUS", "PORT"],
        "sub_candidates": ["HOSTNAME", "OS", "RISKFACTOR", "PROTOCOL", "SERVICENAME",
                           "EXPLOITS", "VULNSTATUS", "KEY", "MESSAGE"],
        "top_max": 6
    },
    "OpenVas": {
        "top_priority": ["TIME", "MESSAGE"],
        "sub_candidates": [],
        "top_max": 2
    },
    "NMAP": {
        "top_priority": ["TIME", "PORT", "SERVICENAME", "STATUS", "PROTOCOL"],
        "sub_candidates": ["HOSTNAME", "REASON", "MESSAGE"],
        "top_max": 5
    },
    # EDR / Endpoint AV — threat-centric
    "FireEye": {
        "top_priority": ["TIME", "MALWARETYPE", "ACTION", "SEVERITY", "DESTINATION_IP", "SNAME"],
        "sub_candidates": ["HOSTNAME", "FILEHASH", "FILETYPE", "ALERTTYPE", "CNCHOST",
                           "OBJURL", "PORT", "LOCATION", "OS", "REMOTEHOST", "MESSAGE"],
        "top_max": 6
    },
    "McAfee": {
        "top_priority": ["TIME", "VIRUS_NAME", "ACTION", "SEVERITY", "FILENAME", "USERNAME"],
        "sub_candidates": ["HOSTNAME", "ENDPOINT_IP", "ENDPOINT_NAME", "CATEGORY",
                           "PRIMARY_ACTION", "SECONDARY_ACTION", "RISK_NAME",
                           "VIRUS_FILENAME", "SCAN_TIME", "OS_NAME", "MESSAGE"],
        "top_max": 6
    },
    "Symantec_Endpoint_Protection": {
        "top_priority": ["TIME", "RISK_NAME", "ACTION", "USERNAME", "REMOTEIP", "IENAME"],
        "sub_candidates": ["HOSTNAME", "DESCRIPTION", "ATTACK", "APPLICATION", "STATUS",
                           "ACTUAL_ACTION", "DOMAIN", "CATEGORY_ID", "LOCATION",
                           "APPLICATION_HASH", "POLICY_NAME", "OBJECT", "MESSAGE",
                           "SOURCE", "DEST_IP", "DEST_PORT", "OPERATION"],
        "top_max": 6
    },
    "MalwareBytes": {
        "top_priority": ["TIME", "RISK_NAME", "ACTION", "USERNAME", "SEVERITY", "FILENAME"],
        "sub_candidates": ["HOSTNAME", "SOURCE_IP", "STATUS", "CATEGORY", "RISK_CATEGORY",
                           "FILEPATH", "OBJECT_SCANNED", "APPLICATION", "PARENT_PROCESS",
                           "URL_SITE", "DESCRIPTION", "IENAME", "MESSAGE"],
        "top_max": 6
    },
    # DLP — policy/data-centric
    "Symantec_DLP": {
        "top_priority": ["TIME", "POLICY", "SEVERITY", "FILENAME", "BLOCKED", "SENDER"],
        "sub_candidates": ["HOSTNAME", "DATAOWNER", "PATH", "PARENT_PATH", "SUBJECT",
                           "RECIPENTS", "PROTOCOL", "INCIDENT_ID", "RULES",
                           "ENDPOINT_DEVICE", "DESTINATION_IP", "ATTACHMENT_NAME", "MESSAGE"],
        "top_max": 6
    },
    # Cloud / SaaS — operation-centric
    "azure_active_directory": {
        "top_priority": ["TIME", "USERNAME", "OPERATION", "RESULT", "IPADDRESS", "APPLICATIONNAME"],
        "sub_candidates": ["FAILUREREASON", "ERRORCODE", "CITY", "COUNTRY", "STATUS",
                           "RISK_LEVEL", "CALLER", "SOURCE", "HOSTNAME", "LOCATION",
                           "LOGON_TYPE_TEXT", "MESSAGE"],
        "top_max": 6
    },
    "AWS": {
        "top_priority": ["TIME", "USERNAME", "LOG_EVENT_NAME", "EVENTSOURCE", "IPADDRESS", "ERRORCODE"],
        "sub_candidates": ["HOSTNAME", "CALLER", "SOURCE_REGION", "USERAGENT", "EVENT_TYPE",
                           "ERRORMESSAGE", "REQUESTPARAMETERS", "BUCKETNAME", "ROLE",
                           "POLICY_NAME", "GROUPNAME", "MESSAGE", "SEVERITY"],
        "top_max": 6
    },
    "m365_general": {
        "top_priority": ["TIME", "CALLER", "OPERATION", "RESULT", "IPADDRESS", "TARGET"],
        "sub_candidates": ["HOSTNAME", "SERVICENAME", "AUDITTYPE", "ROLE",
                           "DESCRIPTION", "MODIFIED_PROPERTIES_GD", "MESSAGE"],
        "top_max": 6
    },
    "sharepoint_online": {
        "top_priority": ["TIME", "CALLER", "OPERATION", "RESULT", "IPADDRESS", "TARGET"],
        "sub_candidates": ["HOSTNAME", "SERVICENAME", "AUDITTYPE", "ROLE",
                           "DESCRIPTION", "MODIFIED_PROPERTIES_GD", "MESSAGE"],
        "top_max": 6
    },
    "exchange_online": {
        "top_priority": ["TIME", "CALLER", "OPERATION", "RESULT", "IPADDRESS", "TARGET"],
        "sub_candidates": ["HOSTNAME", "SERVICENAME", "AUDITTYPE", "ROLE",
                           "DESCRIPTION", "MODIFIED_PROPERTIES_GD", "MESSAGE"],
        "top_max": 6
    },
    "Salesforce": {
        "top_priority": ["TIME", "USERNAME", "ACTION", "OBJECT", "IPADDRESS", "STATUS"],
        "sub_candidates": ["SEVERITY", "OBJECTNAME", "CATEGORY", "DESCRIPTION",
                           "ENTITYNAME", "TRANSACTION", "EVENT_TYPE", "HOSTNAME", "MESSAGE"],
        "top_max": 6
    },
    # ME product audit — admin-activity-centric
    "ADAP": {
        "top_priority": ["TIME", "USERNAME", "ACTION", "IENAME", "IPADDRESS"],
        "sub_candidates": ["DESCRIPTION", "MESSAGE", "HOSTNAME", "CATEGORY", "SEVERITY"],
        "top_max": 5
    },
    "ADMP": {
        "top_priority": ["TIME", "USERNAME", "ACTION", "IENAME", "IPADDRESS"],
        "sub_candidates": ["DESCRIPTION", "MESSAGE", "HOSTNAME", "CATEGORY", "SEVERITY"],
        "top_max": 5
    },
    "ADSSP": {
        "top_priority": ["TIME", "USERNAME", "ACTION", "IENAME", "IPADDRESS"],
        "sub_candidates": ["DESCRIPTION", "MESSAGE", "HOSTNAME", "CATEGORY", "SEVERITY"],
        "top_max": 5
    },
    "OPM": {
        "top_priority": ["TIME", "USERNAME", "ACTION", "IENAME", "SEVERITY"],
        "sub_candidates": ["DESCRIPTION", "MESSAGE", "HOSTNAME", "IPADDRESS"],
        "top_max": 5
    },
    "SDP": {
        "top_priority": ["TIME", "USERNAME", "ACTION", "IENAME", "IPADDRESS"],
        "sub_candidates": ["DESCRIPTION", "MESSAGE", "HOSTNAME", "CATEGORY"],
        "top_max": 5
    },
    "UEM": {
        "top_priority": ["TIME", "USERNAME", "ACTION", "IENAME", "HOSTNAME"],
        "sub_candidates": ["DESCRIPTION", "MESSAGE", "SEVERITY", "IPADDRESS", "STATUS"],
        "top_max": 5
    },
    "ERP": {
        "top_priority": ["TIME", "USERNAME", "ACTION", "OPERATION", "IENAME"],
        "sub_candidates": ["DESCRIPTION", "MESSAGE", "HOSTNAME", "SEVERITY", "STATUS"],
        "top_max": 5
    },
    # Generic CEF — best-effort
    "CEF_Format": {
        "top_priority": ["TIME", "ACTION", "IENAME", "SOURCE_IP", "DEST_IP", "SEVERITYLEVEL"],
        "sub_candidates": ["HOSTNAME", "PRODUCT_NAME", "DEST_USER", "FILENAME",
                           "DESCRIPTION", "PROTOCOL_APP", "DEST_PORT", "REMOTEHOST", "MESSAGE"],
        "top_max": 6
    },
    # DHCP — lease-centric
    "DHCP_Windows": {
        "top_priority": ["TIME", "DESCRIPTION", "MESSAGE"],
        "sub_candidates": ["HOSTNAME"],
        "top_max": 3
    },
    "DHCP_Linux": {
        "top_priority": ["TIME", "DESCRIPTION", "MESSAGE"],
        "sub_candidates": ["HOSTNAME"],
        "top_max": 3
    },
}


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def get_nlq_fields(nlq_data, logtype):
    """Get the set of field names for a logtype from the nlq mapping."""
    if logtype in nlq_data:
        return set(nlq_data[logtype].keys()) - {"LOGTYPE"}  # exclude LOGTYPE meta-field
    return set()


def tier_fields(current_fields, nlq_fields, section, logtype=None):
    """
    Split fields into top-level and sub-level for a given section.
    
    current_fields: list of fields currently in the projection (max 10)
    nlq_fields: set of ALL fields available for this logtype in nlq
    section: section id (e.g., "B3", "E10")
    logtype: log-type name (used for OB3 per-log-type overrides)
    """
    # Check for per-log-type OB3 override
    if section == "OB3" and logtype and logtype in OB3_OVERRIDES:
        rule = OB3_OVERRIDES[logtype]
    else:
        rule = SECTION_RULES.get(section)
    if not rule:
        # No rule defined - use first 4 as top, rest as sub
        return current_fields[:4], current_fields[4:]
    
    top_priority = rule["top_priority"]
    sub_candidates = rule["sub_candidates"]
    top_max = rule.get("top_max", 5)
    
    # Field synonyms — picking one from a group excludes the others from top
    SYNONYMS = {
        "USERNAME": {"ACCOUNT_NAME", "USERID", "LOGIN_NAME"},
        "ACCOUNT_NAME": {"USERNAME", "USERID", "LOGIN_NAME"},
        "SOURCE_IP": {"REMOTEIP", "IPADDRESS", "REMOTE_IP", "CLIENTIP"},
        "REMOTEIP": {"SOURCE_IP", "IPADDRESS", "REMOTE_IP", "CLIENTIP"},
        "IPADDRESS": {"SOURCE_IP", "REMOTEIP", "REMOTE_IP", "CLIENTIP"},
        "DEST_IP": {"TARGETIP", "DESTINATION_IP"},
        "TARGETIP": {"DEST_IP", "DESTINATION_IP"},
        "DESTINATION_IP": {"DEST_IP", "TARGETIP"},
        "RESULT": {"STATUS"},
        "STATUS": {"RESULT"},
        "SEVERITY": {"PRIORITY", "RISK_LEVEL", "COMMON_SEVERITY"},
        "PRIORITY": {"SEVERITY", "RISK_LEVEL"},
        "RISK_LEVEL": {"SEVERITY", "PRIORITY"},
        "IENAME": {"ACTION"},
        "FILENAME": {"OBJECTNAME", "NAME", "FILE"},
        "OBJECTNAME": {"FILENAME", "NAME", "FILE"},
        "NAME": {"FILENAME", "OBJECTNAME", "FILE"},
        "FILE": {"FILENAME", "OBJECTNAME", "NAME"},
    }
    
    # All available fields = current + additional from nlq that match sub_candidates
    all_available = set(current_fields) | nlq_fields
    
    # Build top-level: pick from top_priority that exist in available fields
    top = []
    excluded_from_top = set()
    for field in top_priority:
        if field in excluded_from_top:
            continue
        if field in all_available and field not in top:
            top.append(field)
            # Exclude synonyms from top
            if field in SYNONYMS:
                excluded_from_top.update(SYNONYMS[field])
            if len(top) >= top_max:
                break
    
    # If we didn't reach top_max, fill from current_fields in order
    for field in current_fields:
        if field not in top and field not in excluded_from_top and len(top) < top_max:
            top.append(field)
    
    # Build sub-level: current fields not in top + additional from nlq per sub_candidates
    sub = []
    # First: remaining current fields not in top
    for field in current_fields:
        if field not in top and field not in sub:
            sub.append(field)
    
    # Then: additional fields from nlq that match sub_candidates and aren't already used
    used = set(top) | set(sub)
    for field in sub_candidates:
        if field in nlq_fields and field not in used:
            sub.append(field)
            used.add(field)
            if len(sub) >= 12:  # cap sub-level at 12
                break
    
    return top, sub


def main():
    nlq_data = load_json(NLQ_PATH)
    enriched_data = load_json(ENRICHED_PATH)
    
    output = OrderedDict()
    
    # Stats
    total_pairs = 0
    total_top_fields = 0
    total_sub_fields = 0
    
    for logtype in sorted(enriched_data.keys()):
        nlq_fields = get_nlq_fields(nlq_data, logtype)
        output[logtype] = OrderedDict()
        
        for section in sorted(enriched_data[logtype].keys(), key=lambda s: (
            0 if s.startswith("B") else 1 if s.startswith("E") else 2,
            int(''.join(c for c in s if c.isdigit()) or '0')
        )):
            current_fields = enriched_data[logtype][section]
            top, sub = tier_fields(current_fields, nlq_fields, section, logtype)
            
            output[logtype][section] = {
                "top": top,
                "sub": sub
            }
            
            total_pairs += 1
            total_top_fields += len(top)
            total_sub_fields += len(sub)
    
    # Write JSON output
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"Generated tiered projection for {total_pairs} (log-type, section) pairs")
    print(f"Total top-level fields: {total_top_fields} (avg {total_top_fields/total_pairs:.1f})")
    print(f"Total sub-level fields: {total_sub_fields} (avg {total_sub_fields/total_pairs:.1f})")
    print(f"Output: {OUTPUT_PATH}")
    
    # Generate markdown table
    md_lines = []
    md_lines.append("| Log-type | Section | Top-level fields (default) | Sub-level fields (Show More) |")
    md_lines.append("|---|---|---|---|")
    
    for logtype in sorted(output.keys()):
        first = True
        for section in output[logtype]:
            entry = output[logtype][section]
            lt_col = logtype if first else "↳"
            first = False
            top_str = ", ".join(f"`{f}`" for f in entry["top"])
            sub_str = ", ".join(f"`{f}`" for f in entry["sub"]) if entry["sub"] else "—"
            md_lines.append(f"| {lt_col} | **{section}** | {top_str} | {sub_str} |")
    
    md_path = BASE / "data" / "soc_field_tiered_projection.md"
    with open(md_path, "w") as f:
        f.write("\n".join(md_lines))
    
    print(f"Markdown table: {md_path}")


if __name__ == "__main__":
    main()
