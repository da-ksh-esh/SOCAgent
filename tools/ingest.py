"""Load alerts from the native JSON schema or from Windows Security / Sysmon event logs.

Windows events are expected as JSON objects with the field names used by Windows event exports and
the OTRF Security-Datasets (EventID, Channel, Computer, TargetUserName, IpAddress, LogonType,
TargetImage, GrantedAccess, Hashes, ServiceName, QueryName, TargetFilename, Hash, Contents, ...).
They are mapped to SIEM-style alerts so the same agents can triage them:

  4625                         -> Failed login
  4624 LogonType 10/2          -> Successful login        4624 LogonType 3 -> Remote logon
  4732 (added to Administrators) -> New admin account created
  7045 (service installed)     -> Remote service created
  Sysmon 10 on lsass.exe       -> Credential dumping detected
  Sysmon 15 .exe download      -> Suspicious file download
  Sysmon 22, >=3 queries for one domain from one host -> Beaconing detected
  Sysmon 1 / 4688 vssadmin delete shadows -> Shadow copies deleted
Events that match none of these are ignored.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime

from tools.enrichment import is_external

REQUIRED = ["id", "ts", "source", "host", "rule_name"]
RAW_SEVERITY = {"Failed login": "low", "Successful login": "low", "Remote logon": "low",
                "New admin account created": "high", "Remote service created": "medium",
                "Credential dumping detected": "high", "Suspicious file download": "medium",
                "Beaconing detected": "high", "Shadow copies deleted": "high"}
SOURCE = {"Failed login": "auth", "Successful login": "auth", "Remote logon": "auth",
          "New admin account created": "auth", "Remote service created": "edr",
          "Credential dumping detected": "edr", "Suspicious file download": "edr",
          "Beaconing detected": "dns", "Shadow copies deleted": "edr"}


def detect_format(records) -> str:
    if not isinstance(records, list) or not records or not isinstance(records[0], dict):
        raise ValueError("expected a JSON list of objects")
    if any(k in records[0] for k in ("EventID", "EventId", "event_id")):
        return "windows"
    if all(k in records[0] for k in REQUIRED):
        return "native"
    raise ValueError("unrecognised format: need the native alert schema or Windows/Sysmon events with EventID")


def _ts(r: dict) -> str:
    raw = str(r.get("@timestamp") or r.get("TimeCreated") or r.get("UtcTime") or r.get("EventTime"))
    raw = raw.replace("Z", "").replace(" ", "T")[:19]
    return datetime.fromisoformat(raw).strftime("%Y-%m-%dT%H:%M:%S")


def _host(r: dict) -> str:
    return str(r.get("Computer") or r.get("Hostname") or "UNKNOWN").split(".")[0].upper()


def _user(r: dict) -> str:
    u = r.get("TargetUserName") or r.get("User") or r.get("SubjectUserName") or ""
    return str(u).split("\\")[-1].lower() if u not in ("-", "SYSTEM", "NT AUTHORITY\\SYSTEM") else ""


def _sha256(r: dict) -> str:
    m = re.search(r"SHA256=([0-9A-Fa-f]{64})", str(r.get("Hashes") or r.get("Hash") or ""))
    return m.group(1).lower() if m else ""


def _ip(value) -> str:
    v = str(value or "")
    return "" if v in ("-", "::1", "127.0.0.1") else v


def windows_to_alerts(events: list[dict], host_ips: dict[str, str] | None = None) -> list[dict]:
    host_ips = host_ips or {}
    out = []

    def add(r: dict, rule: str, message: str, **fields) -> None:
        host = _host(r)
        out.append({"id": "", "ts": _ts(r), "source": SOURCE[rule], "host": host, "user": fields.get("user", _user(r)),
                    "src_ip": fields.get("src_ip", ""), "dst_ip": fields.get("dst_ip", host_ips.get(host, "")),
                    "domain": fields.get("domain", ""), "hash": fields.get("hash", ""), "rule_name": rule,
                    "raw_severity": RAW_SEVERITY[rule], "message": message})

    dns: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in events:
        eid = int(r.get("EventID") or r.get("EventId") or r.get("event_id") or 0)
        channel = str(r.get("Channel", ""))
        sysmon = "Sysmon" in channel
        if eid == 4625:
            add(r, "Failed login", f"Failed logon for '{_user(r)}' (type {r.get('LogonType', '?')})", src_ip=_ip(r.get("IpAddress")))
        elif eid == 4624:
            lt, ip = int(r.get("LogonType") or 0), _ip(r.get("IpAddress"))
            if lt == 3:
                add(r, "Remote logon", f"Network logon (type 3) for '{_user(r)}' from {ip or 'local'}", src_ip=ip)
            elif lt in (2, 10, 11):
                add(r, "Successful login", f"Logon (type {lt}) for '{_user(r)}' from {ip or 'console'}", src_ip=ip)
        elif eid == 4732 and "admin" in str(r.get("TargetUserName", "")).lower():
            add(r, "New admin account created", f"{r.get('MemberName', 'account')} added to {r.get('TargetUserName')}",
                user=str(r.get("SubjectUserName", "")).lower())
        elif eid == 7045:
            add(r, "Remote service created", f"Service {r.get('ServiceName')} installed ({r.get('ImagePath', '')})")
        elif sysmon and eid == 10 and str(r.get("TargetImage", "")).lower().endswith("lsass.exe"):
            add(r, "Credential dumping detected", f"{r.get('SourceImage')} opened lsass.exe ({r.get('GrantedAccess')})",
                hash=_sha256(r))
        elif sysmon and eid == 15 and str(r.get("TargetFilename", "")).lower().endswith(".exe"):
            url = re.search(r"HostUrl=https?://([^/\s]+)", str(r.get("Contents", "")))
            add(r, "Suspicious file download", f"{r.get('TargetFilename')} downloaded", hash=_sha256(r),
                domain=url.group(1).lower() if url else "")
        elif (sysmon and eid == 1 or eid == 4688) and re.search(r"vssadmin.*delete\s+shadows", str(r.get("CommandLine", "")), re.I):
            add(r, "Shadow copies deleted", str(r.get("CommandLine")))
        elif sysmon and eid == 22 and r.get("QueryName"):
            dns[(_host(r), str(r["QueryName"]).lower())].append(r)
    for (host, domain), queries in dns.items():
        if len(queries) >= 3:    # periodic callbacks to one domain look like beaconing
            for r in queries:
                add(r, "Beaconing detected", f"DNS query for {domain} ({len(queries)} from {host})", domain=domain)
    out.sort(key=lambda a: (a["ts"], a["host"]))
    for i, a in enumerate(out, start=1):
        a["id"] = f"WIN-{i:04d}"
    return out


def load_alerts(records: list[dict], host_ips: dict[str, str] | None = None) -> tuple[list[dict], str]:
    """(alerts, format) from either supported format."""
    fmt = detect_format(records)
    if fmt == "native":
        for a in records:
            for k in ("user", "src_ip", "dst_ip", "domain", "hash", "message"):
                a.setdefault(k, "")
            a.setdefault("raw_severity", "low")
        return records, fmt
    return windows_to_alerts(records, host_ips), fmt


__all__ = ["detect_format", "windows_to_alerts", "load_alerts", "is_external"]
