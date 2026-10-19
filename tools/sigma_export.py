"""Export a generated detection rule as real Sigma and convert it with pySigma.

Each step of our rule becomes a Sigma base rule on Windows/Sysmon telemetry, and the sequence
becomes a Sigma correlation rule (temporal_ordered, grouped, with a timespan). pySigma then
converts it to a Splunk search and Elastic (Lucene) queries. Splunk's backend supports unordered
`temporal` correlation, so the Splunk version checks that all steps occur but not their order.
"""
from __future__ import annotations

import uuid

import yaml

from tools.enrichment import is_external

PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
NS = uuid.UUID("6f1b9a52-7c1e-4b7e-9a51-2f6d1c0e8b11")


def _step_sigma(step: dict, iocs: dict[str, list[str]]) -> tuple[dict, dict]:
    """(logsource, detection) for one rule step, on standard Windows/Sysmon fields."""
    name, ext = step["rule_name"], step.get("src_external")
    win = lambda svc: {"product": "windows", "service": svc}
    if name == "Failed login":
        det = {"selection": {"EventID": 4625}}
    elif name == "Successful login":
        det = {"selection": {"EventID": 4624, "LogonType": 10}}
    elif name == "Remote logon":
        det = {"selection": {"EventID": 4624, "LogonType": 3}}
    elif name == "New admin account created":
        det = {"selection": {"EventID": 4732, "TargetUserName": "Administrators"}}
    elif name == "Remote service created":
        return win("system"), {"selection": {"EventID": 7045}, "condition": "selection"}
    elif name == "Credential dumping detected":
        return {"product": "windows", "category": "process_access"}, {
            "selection": {"TargetImage|endswith": "\\lsass.exe", "GrantedAccess": ["0x1010", "0x1410", "0x1fffff"]},
            "condition": "selection"}
    elif name == "Suspicious file download":
        return {"product": "windows", "category": "file_event"}, {
            "selection": {"TargetFilename|contains": "\\Downloads\\", "TargetFilename|endswith": ".exe"},
            "condition": "selection"}
    elif name == "Phishing link clicked":
        return {"category": "proxy"}, {"selection": {"c-uri|contains": iocs["domains"] or ["login"]}, "condition": "selection"}
    elif name == "Beaconing detected":
        return {"product": "windows", "category": "dns_query"}, {
            "selection": {"QueryName|endswith": iocs["domains"] or [".invalid"]}, "condition": "selection"}
    else:
        return {"category": "firewall"}, {"selection": {"rule_name": name}, "condition": "selection"}
    if ext:
        det["filter_internal"] = {"IpAddress|cidr": PRIVATE}
        det["condition"] = "selection and not filter_internal"
    else:
        det["condition"] = "selection"
    return win("security"), det


def to_sigma(rule: dict, alerts: list[dict]) -> dict:
    """Sigma YAML (base rules + correlation) plus pySigma conversions for Splunk and Elastic."""
    iocs = {"domains": sorted({a["domain"] for a in alerts if a["domain"]}),
            "ips": sorted({a["src_ip"] for a in alerts if a["src_ip"] and is_external(a["src_ip"])})}
    docs, names = [], []
    for n, step in enumerate(rule["detection"]["steps"], start=1):
        logsource, detection = _step_sigma(step, iocs)
        name = f"{rule['id'].lower().replace('-', '_')}_step{n}"
        names.append(name)
        docs.append({"title": f"{rule['title']} — step {n}: {step['rule_name']}",
                     "id": str(uuid.uuid5(NS, name)), "name": name, "status": "experimental",
                     "logsource": logsource, "detection": detection, "level": "low",
                     "tags": [t for t in rule["tags"] if t.startswith("attack.t")]})
    group = {"host": "Computer", "user": "TargetUserName"}[rule["detection"]["group_by"]]
    correlation = {"title": rule["title"], "id": str(uuid.uuid5(NS, rule["id"])), "status": "experimental",
                   "correlation": {"type": "temporal_ordered", "rules": names, "group-by": [group],
                                   "timespan": f"{rule['detection']['timeframe_min']}m"},
                   "level": rule["level"]}
    if len(names) > 1:
        docs.append(correlation)
    sigma_yaml = yaml.safe_dump_all(docs, sort_keys=False, allow_unicode=True)

    out = {"sigma": sigma_yaml, "splunk": "", "elastic": [], "errors": []}
    try:
        from sigma.backends.elasticsearch import LuceneBackend
        from sigma.backends.splunk import SplunkBackend
        from sigma.collection import SigmaCollection

        base = SigmaCollection.from_yaml(yaml.safe_dump_all(docs[:len(names)], sort_keys=False))
        out["elastic"] = LuceneBackend().convert(base)
        if len(names) > 1:
            unordered = dict(correlation, correlation={**correlation["correlation"], "type": "temporal"})
            splunk_yaml = yaml.safe_dump_all(docs[:len(names)] + [unordered], sort_keys=False)
            out["splunk"] = SplunkBackend().convert(SigmaCollection.from_yaml(splunk_yaml))[0]
        else:
            out["splunk"] = SplunkBackend().convert(base)[0]
    except Exception as exc:   # pySigma missing or a conversion error: keep the Sigma YAML
        out["errors"].append(f"{type(exc).__name__}: {exc}")
    return out
