"""MITRE ATT&CK mapping. Each SIEM rule that can support a kill-chain stage maps to one technique."""
from __future__ import annotations

# SIEM rule name -> (technique id, technique name, tactic)
RULE_TECHNIQUE = {
    "Port scan detected": ("T1046", "Network Service Discovery", "Discovery"),
    "Phishing link clicked": ("T1566.002", "Phishing: Spearphishing Link", "Initial Access"),
    "Successful login": ("T1078", "Valid Accounts", "Initial Access"),
    "Suspicious file download": ("T1204.002", "User Execution: Malicious File", "Execution"),
    "Remote service created": ("T1569.002", "System Services: Service Execution", "Execution"),
    "New admin account created": ("T1136.001", "Create Account: Local Account", "Persistence"),
    "Failed login": ("T1110", "Brute Force", "Credential Access"),
    "Credential dumping detected": ("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
    "Remote logon": ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "Beaconing detected": ("T1071.001", "Application Layer Protocol: Web", "Command and Control"),
    "Large outbound transfer": ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
    "Shadow copies deleted": ("T1490", "Inhibit System Recovery", "Impact"),
    "Mass file encryption": ("T1486", "Data Encrypted for Impact", "Impact"),
}

TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Credential Access", "Discovery",
                "Lateral Movement", "Command and Control", "Exfiltration", "Impact"]


def techniques(stages: dict[str, list[str]], alerts_by_id: dict[str, dict]) -> list[dict]:
    """ATT&CK techniques evidenced by the alerts behind each correlated stage."""
    out, seen = [], set()
    for stage, ids in stages.items():
        for aid in ids:
            rule = alerts_by_id[aid]["rule_name"]
            if rule in RULE_TECHNIQUE and RULE_TECHNIQUE[rule][0] not in seen:
                tid, name, tactic = RULE_TECHNIQUE[rule]
                seen.add(tid)
                out.append({"stage": stage, "id": tid, "name": name, "tactic": tactic})
    return out


def catalogue() -> list[dict]:
    """All techniques this PoC can detect (for the coverage grid)."""
    return [{"id": t, "name": n, "tactic": tac} for t, n, tac in RULE_TECHNIQUE.values()]
