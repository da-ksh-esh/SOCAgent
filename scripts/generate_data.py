"""Generate the synthetic SOC dataset (seeded, reproducible, variable noise).

    python scripts/generate_data.py                 # seed 42, ~150 alerts -> data/
    python scripts/generate_data.py --seed 7 --alerts 600

Writes into data/:
  alerts.json          SIEM alerts: four scripted attack chains hidden in benign noise
  threat_intel.json    indicator (IP / domain / hash) -> reputation
  assets.json          host -> owner, role, criticality, ip
  user_baselines.json  user -> usual hosts and working hours
  attack_logs.json     replayed attack samples for detection-rule tests
  benign_logs.json     benign samples for detection-rule tests (must stay silent)
  ground_truth.json    which alert IDs belong to which chain (evaluation only)

generate_dataset(seed, n_alerts) returns (alerts, ground_truth) in memory for the benchmark.
Each seed varies the attacked hosts, users, indicators, timings and chain lengths.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

BASE_DAY = datetime(2026, 10, 14)
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

ASSETS = {
    "SRV-DC01": {"owner": "IT Infrastructure", "role": "Domain controller", "criticality": "crown_jewel", "ip": "10.0.1.10"},
    "SRV-DB01": {"owner": "Data Platform", "role": "Customer database", "criticality": "crown_jewel", "ip": "10.0.1.20"},
    "SRV-APP01": {"owner": "App Engineering", "role": "Internal application server", "criticality": "high", "ip": "10.0.1.30"},
    "SRV-WEB01": {"owner": "App Engineering", "role": "Public web server", "criticality": "high", "ip": "10.0.1.40"},
    "SRV-BKP01": {"owner": "IT Infrastructure", "role": "Backup server", "criticality": "high", "ip": "10.0.1.50"},
    "FIN-WS01": {"owner": "Finance", "role": "Finance workstation", "criticality": "high", "ip": "10.0.3.11"},
    "FIN-WS03": {"owner": "Finance", "role": "Finance workstation", "criticality": "high", "ip": "10.0.3.13"},
    "WS-MKT07": {"owner": "Marketing", "role": "User workstation", "criticality": "medium", "ip": "10.0.4.17"},
    "WS-HR02": {"owner": "Human Resources", "role": "User workstation", "criticality": "medium", "ip": "10.0.4.22"},
    "WS-ENG11": {"owner": "Engineering", "role": "User workstation", "criticality": "low", "ip": "10.0.5.11"},
    "WS-ENG12": {"owner": "Engineering", "role": "User workstation", "criticality": "low", "ip": "10.0.5.12"},
    "WS-ENG13": {"owner": "Engineering", "role": "User workstation", "criticality": "low", "ip": "10.0.5.13"},
    "WS-ENG14": {"owner": "Engineering", "role": "User workstation", "criticality": "low", "ip": "10.0.5.14"},
    "WS-SALES04": {"owner": "Sales", "role": "User workstation", "criticality": "low", "ip": "10.0.6.4"},
    "SCN-01": {"owner": "Security", "role": "Vulnerability scanner", "criticality": "low", "ip": "10.0.0.5"},
}
SERVERS = [h for h in ASSETS if h.startswith("SRV-")]
JUMP_HOST_IP = "10.0.9.5"   # IT admin jump box (not monitored, so not an asset)

USERS = {
    "administrator": {"usual_hosts": ["SRV-APP01", "SRV-WEB01", "SRV-DC01"], "work_hours": [8, 19]},
    "it_admin": {"usual_hosts": SERVERS, "work_hours": [7, 21]},
    "priya.s": {"usual_hosts": ["WS-MKT07"], "work_hours": [8, 20]},
    "rahul.k": {"usual_hosts": ["FIN-WS03"], "work_hours": [9, 19]},
    "anita.m": {"usual_hosts": ["FIN-WS01"], "work_hours": [9, 19]},
    "vikram.r": {"usual_hosts": ["WS-HR02"], "work_hours": [9, 19]},
    "arjun.p": {"usual_hosts": ["WS-ENG11"], "work_hours": [9, 21]},
    "neha.k": {"usual_hosts": ["WS-ENG12"], "work_hours": [9, 21]},
    "sameer.d": {"usual_hosts": ["WS-ENG13"], "work_hours": [9, 21]},
    "kavya.n": {"usual_hosts": ["WS-ENG14"], "work_hours": [9, 21]},
    "rohan.b": {"usual_hosts": ["WS-SALES04"], "work_hours": [8, 20]},
    "svc_backup": {"usual_hosts": ["SRV-BKP01"], "work_hours": [0, 24]},
    "svc_scanner": {"usual_hosts": ["SCN-01"], "work_hours": [0, 24]},
}
WORKSTATION_USERS = {u: b["usual_hosts"][0] for u, b in USERS.items()
                     if b["usual_hosts"][0].startswith(("WS-", "FIN-"))}


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# Indicator pools: each seed picks from these, and the threat-intel feed knows all of them.
BRUTE_FORCE_IPS = ["185.220.101.45", "45.155.205.233"]
PHISH_DOMAINS = ["secure-login-update.com", "docs-review-share.net"]
C2_DOMAINS = ["cdn-sync-update.net", "telemetry-edge-cdn.org"]
MALWARE_HASHES = [sha256("invoice_viewer.exe"), sha256("statement_viewer.exe")]
DUMPER_HASHES = [sha256("procdump64_lsass"), sha256("mimikatz_x64")]
EXFIL_IPS = ["45.95.168.12", "193.29.13.92"]
SIGNED_INSTALLER_HASH = sha256("zoom_installer_signed.msi")

THREAT_INTEL = {
    **{ip: {"reputation": "malicious", "note": "Known brute-force source (Tor exit / botnet)"} for ip in BRUTE_FORCE_IPS},
    **{d: {"reputation": "malicious", "note": "Credential phishing domain, registered days ago"} for d in PHISH_DOMAINS},
    **{d: {"reputation": "malicious", "note": "Command-and-control domain (commodity RAT)"} for d in C2_DOMAINS},
    **{h: {"reputation": "malicious", "note": "Remote access trojan dropper"} for h in MALWARE_HASHES},
    **{h: {"reputation": "malicious", "note": "Credential dumping tool"} for h in DUMPER_HASHES},
    **{ip: {"reputation": "suspicious", "note": "Bulletproof hosting range, seen in data-theft cases"} for ip in EXFIL_IPS},
    "10.0.0.5": {"reputation": "benign", "note": "Internal vulnerability scanner (allow-listed)"},
    "52.95.110.1": {"reputation": "benign", "note": "Corporate cloud backup endpoint"},
    "updates.microsoft.com": {"reputation": "benign", "note": "Vendor update service"},
    SIGNED_INSTALLER_HASH: {"reputation": "benign", "note": "Signed vendor installer"},
}

RAW_SEVERITY = {
    "Failed login": "low", "Successful login": "low", "VPN login": "low", "Remote logon": "low",
    "New admin account created": "high", "Phishing link clicked": "medium",
    "Suspicious file download": "medium", "Beaconing detected": "high",
    "Large outbound transfer": "medium", "Port scan detected": "low", "Patch installed": "low",
    "Credential dumping detected": "high", "Remote service created": "medium",
}
SOURCE = {
    "Failed login": "auth", "Successful login": "auth", "VPN login": "auth", "Remote logon": "auth",
    "New admin account created": "auth", "Phishing link clicked": "dns",
    "Suspicious file download": "edr", "Beaconing detected": "dns",
    "Large outbound transfer": "firewall", "Port scan detected": "firewall", "Patch installed": "edr",
    "Credential dumping detected": "edr", "Remote service created": "edr",
}


def alert(ts: datetime, rule: str, host: str, user: str = "", src_ip: str = "", dst_ip: str = "",
          domain: str = "", file_hash: str = "", message: str = "") -> dict:
    return {
        "id": "", "ts": ts.strftime("%Y-%m-%dT%H:%M:%S"), "source": SOURCE[rule], "host": host,
        "user": user, "src_ip": src_ip, "dst_ip": dst_ip or ASSETS.get(host, {}).get("ip", ""),
        "domain": domain, "hash": file_hash, "rule_name": rule,
        "raw_severity": RAW_SEVERITY[rule], "message": message,
    }


def at(day: datetime, hour: int, minute: int) -> datetime:
    return day.replace(hour=hour, minute=minute, second=0)


# ---------------------------------------------------------------- attack chains

def chain_a(day, host="SRV-APP01", attacker=BRUTE_FORCE_IPS[0], failures=9, hour=2, minute=5) -> list[dict]:
    """A: brute force -> successful login -> new admin account (on a server)."""
    start = at(day, hour, minute)
    out = [alert(start + timedelta(seconds=40 * i), "Failed login", host, "administrator", attacker,
                 message=f"Failed RDP logon for 'administrator' from {attacker}") for i in range(failures)]
    t = start + timedelta(seconds=40 * failures + 60)
    out.append(alert(t, "Successful login", host, "administrator", attacker,
                     message=f"Successful RDP logon for 'administrator' from {attacker}"))
    out.append(alert(t + timedelta(minutes=3), "New admin account created", host, "administrator", attacker,
                     message="Local account 'svc_update' created and added to Administrators"))
    return out


def chain_b(day, user="priya.s", phish=PHISH_DOMAINS[0], c2=C2_DOMAINS[0], file_hash=MALWARE_HASHES[0],
            beacons=6, hour=14, minute=5) -> list[dict]:
    """B: phishing click -> malware download -> outbound beaconing."""
    host = WORKSTATION_USERS[user]
    start = at(day, hour, minute)
    out = [
        alert(start, "Phishing link clicked", host, user, domain=phish,
              message=f"User opened link to {phish} from email 'Invoice overdue'"),
        alert(start + timedelta(minutes=2), "Suspicious file download", host, user, domain=phish,
              file_hash=file_hash, message=f"Executable downloaded from {phish}"),
    ]
    for i in range(beacons):
        out.append(alert(start + timedelta(minutes=10 + 5 * i), "Beaconing detected", host, user, domain=c2,
                         message=f"Periodic DNS/HTTPS callback to {c2} (interval 300s)"))
    return out


def chain_c(day, user="rahul.k", dest=EXFIL_IPS[0], transfers=3, hour=1, minute=32) -> list[dict]:
    """C: unusual large data transfer from a finance host to an external IP, off hours."""
    host = WORKSTATION_USERS[user]
    start = at(day, hour, minute)
    return [alert(start + timedelta(minutes=9 * i), "Large outbound transfer", host, user, ASSETS[host]["ip"], dest,
                  message=f"{1.6 + 0.7 * i:.1f} GB uploaded over HTTPS to {dest}") for i in range(transfers)]


def chain_d(day, user="neha.k", hop1="SRV-DB01", hop2="SRV-DC01", dumper=DUMPER_HASHES[0],
            hour=22, minute=10) -> list[dict]:
    """D: credential dumping on a workstation -> lateral movement to a server -> domain controller."""
    ws = WORKSTATION_USERS[user]
    start = at(day, hour, minute)
    return [
        alert(start, "Credential dumping detected", ws, user, ASSETS[ws]["ip"], file_hash=dumper,
              message="lsass.exe memory read by an unsigned process"),
        alert(start + timedelta(minutes=12), "Remote logon", hop1, user, ASSETS[ws]["ip"],
              message=f"Network logon (type 3, NTLM) for '{user}' from {ws}"),
        alert(start + timedelta(minutes=15), "Remote service created", hop1, user, ASSETS[ws]["ip"],
              message="Service PSEXESVC installed remotely"),
        alert(start + timedelta(minutes=24), "Remote logon", hop2, user, ASSETS[hop1]["ip"],
              message=f"Network logon (type 3, NTLM) for '{user}' from {hop1}"),
    ]


CHAIN_META = {
    "A": {"name": "Brute force -> login -> new admin account", "expected_band": "high"},
    "B": {"name": "Phishing click -> malware download -> C2 beaconing", "expected_band": "high"},
    "C": {"name": "Off-hours bulk data transfer from finance host", "expected_band": "medium"},
    "D": {"name": "Credential dumping -> lateral movement to domain controller", "expected_band": "high"},
}


def random_chains(rng: random.Random, day: datetime) -> dict[str, list[dict]]:
    """One variant of every chain; the default seed reproduces the original demo dataset."""
    return {
        "A": chain_a(day, host=rng.choice(["SRV-APP01", "SRV-WEB01"]), attacker=rng.choice(BRUTE_FORCE_IPS),
                     failures=rng.randint(6, 10), hour=rng.randint(1, 4), minute=rng.randint(0, 40)),
        "B": chain_b(day, user=rng.choice(["priya.s", "rohan.b", "vikram.r"]), phish=rng.choice(PHISH_DOMAINS),
                     c2=rng.choice(C2_DOMAINS), file_hash=rng.choice(MALWARE_HASHES), beacons=rng.randint(4, 7),
                     hour=rng.randint(10, 16), minute=rng.randint(0, 40)),
        "C": chain_c(day, user=rng.choice(["rahul.k", "anita.m"]), dest=rng.choice(EXFIL_IPS),
                     transfers=rng.randint(2, 4), hour=rng.randint(0, 4), minute=rng.randint(0, 50)),
        "D": chain_d(day, user=rng.choice(["neha.k", "arjun.p", "sameer.d"]), hop1=rng.choice(["SRV-DB01", "SRV-BKP01"]),
                     dumper=rng.choice(DUMPER_HASHES), hour=rng.randint(21, 22), minute=rng.randint(0, 30)),
    }


# ---------------------------------------------------------------- benign noise

def random_time(rng, day, lo=9, hi=18) -> datetime:
    return day.replace(hour=rng.randint(lo, hi - 1), minute=rng.randint(0, 59), second=rng.randint(0, 59))


def ep_typo(rng, day, user=None, failures=None, t=None) -> list[dict]:
    user = user or rng.choice(list(WORKSTATION_USERS))
    host = WORKSTATION_USERS[user]
    t = t or random_time(rng, day)
    ip = ASSETS[host]["ip"]
    n = failures or rng.randint(1, 3)
    out = [alert(t + timedelta(seconds=15 * i), "Failed login", host, user, ip,
                 message=f"Failed logon for '{user}' (bad password)") for i in range(n)]
    out.append(alert(t + timedelta(seconds=15 * n + 20), "Successful login", host, user, ip,
                     message=f"Successful logon for '{user}'"))
    return out


def ep_vpn(rng, day) -> list[dict]:
    user = rng.choice(list(WORKSTATION_USERS))
    host = WORKSTATION_USERS[user]
    t = random_time(rng, day)
    home_ip = f"49.36.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    return [alert(t, "VPN login", host, user, home_ip, message=f"VPN session established for '{user}'"),
            alert(t + timedelta(seconds=30), "Successful login", host, user, f"10.8.0.{rng.randint(2, 250)}",
                  message=f"Successful logon for '{user}' via VPN pool")]


def ep_patch(rng, day) -> list[dict]:
    host = rng.choice(SERVERS)
    t = random_time(rng, day, 9, 18)
    kbs = rng.sample(range(5030000, 5039999), rng.randint(2, 4))
    return [alert(t + timedelta(minutes=2 * i), "Patch installed", host, "it_admin", ASSETS[host]["ip"],
                  domain="updates.microsoft.com", message=f"KB{kb} installed by it_admin (change window)")
            for i, kb in enumerate(kbs)]


def ep_admin_remote(rng, day) -> list[dict]:
    """Hard negative: IT admin logs on to a server from the jump host (one host, no credential theft)."""
    host = rng.choice(SERVERS)
    t = random_time(rng, day, 9, 18)
    return [alert(t, "Remote logon", host, "it_admin", JUMP_HOST_IP,
                  message=f"Network logon (type 3, Kerberos) for 'it_admin' from jump host")]


def ep_scan(rng, day, hour: int) -> list[dict]:
    t = day.replace(hour=hour, minute=0)
    targets = rng.sample(list(ASSETS), rng.randint(5, 8))
    return [alert(t + timedelta(minutes=i), "Port scan detected", "SCN-01", "", "10.0.0.5", ASSETS[h]["ip"],
                  message=f"Scheduled vulnerability scan of {h}") for i, h in enumerate(targets)]


def ep_backup(day, hour=23) -> list[dict]:
    t = day.replace(hour=hour, minute=10)
    return [alert(t + timedelta(minutes=6 * i), "Large outbound transfer", "SRV-BKP01", "svc_backup",
                  ASSETS["SRV-BKP01"]["ip"], "52.95.110.1", message=f"Nightly backup sync, {size} to cloud backup")
            for i, size in enumerate(["14.2 GB", "9.8 GB"])]


def ep_signed_download(day, host="WS-ENG13", user="sameer.d", hour=11) -> list[dict]:
    return [alert(day.replace(hour=hour, minute=20), "Suspicious file download", host, user, domain="zoom.us",
                  file_hash=SIGNED_INSTALLER_HASH, message="EDR flagged MSI download (signed by vendor)")]


def span(episode: list[dict]) -> tuple[str, datetime, datetime]:
    return episode[0]["host"], datetime.fromisoformat(episode[0]["ts"]), datetime.fromisoformat(episode[-1]["ts"])


def overlaps(episode: list[dict], taken: dict) -> bool:
    """True if any alert of the episode lands within 2h of anything already placed on the same host."""
    for a in episode:
        t = datetime.fromisoformat(a["ts"])
        if any(s - timedelta(hours=2) < t < e + timedelta(hours=2) for s, e in taken.get(a["host"], [])):
            return True
    return False


def reserve(episode: list[dict], taken: dict) -> None:
    by_host: dict[str, list[datetime]] = {}
    for a in episode:
        by_host.setdefault(a["host"], []).append(datetime.fromisoformat(a["ts"]))
    for host, times in by_host.items():
        taken.setdefault(host, []).append((min(times), max(times)))


def generate_dataset(seed: int = 42, n_alerts: int = 150) -> tuple[list[dict], dict]:
    """Alerts and ground truth for one seed. Noise fills the dataset up to n_alerts."""
    rng = random.Random(seed)
    day = BASE_DAY
    chains = random_chains(rng, day) if seed != 42 else {
        "A": chain_a(day), "B": chain_b(day), "C": chain_c(day), "D": chain_d(day)}
    taken: dict = {}   # attack windows only: noise keeps 2h away from attacks but may cluster with other noise
    for episode in chains.values():
        reserve(episode, taken)

    noise: list[dict] = []
    fixed_makers = [
        lambda h: ep_backup(day, h), lambda h: ep_signed_download(day, hour=h),
        lambda h: ep_typo(rng, day, "vikram.r", 6, day.replace(hour=h, minute=4)),
        lambda h: ep_typo(rng, day, "neha.k", 5, day.replace(hour=h, minute=40)),
    ]
    for make, hours in zip(fixed_makers, [(23, 20, 19), (11, 13, 15), (10, 12, 17), (16, 13, 11)]):
        for h in hours:   # hard negatives: try a few hours until one does not touch an attack
            episode = make(h)
            if not overlaps(episode, taken):
                noise += episode
                break
    for hour in (3, 15):
        noise += ep_scan(rng, day, hour)

    attack_count = sum(len(c) for c in chains.values())
    makers = [ep_typo, ep_typo, ep_vpn, ep_patch, ep_admin_remote]
    attempts = 0
    while attack_count + len(noise) < n_alerts and attempts < 50 * n_alerts:
        attempts += 1
        episode = rng.choice(makers)(rng, day)
        if not overlaps(episode, taken):
            noise += episode

    for name, chain in chains.items():
        for a in chain:
            a["_chain"] = name
    alerts = sorted(noise + [a for c in chains.values() for a in c], key=lambda a: (a["ts"], a["host"]))
    for i, a in enumerate(alerts, start=1):
        a["id"] = f"ALT-{i:04d}"
    truth = {
        "seed": seed,
        "chains": {k: {**v, "alert_ids": [a["id"] for a in alerts if a.get("_chain") == k]} for k, v in CHAIN_META.items()},
        "benign_alert_ids": [a["id"] for a in alerts if "_chain" not in a],
    }
    for a in alerts:
        a.pop("_chain", None)
    return alerts, truth


def build_rule_test_logs(rng: random.Random) -> tuple[dict, list[dict]]:
    """Fresh samples (different day, hosts and indicators) so rules must generalise."""
    day = BASE_DAY + timedelta(days=7)
    attack = {
        "brute_force": chain_a(day, host="SRV-WEB01", attacker="91.240.118.30", failures=7),
        "phishing_c2": chain_b(day, user="rohan.b", phish="docs-share-review.com", c2="telemetry-cdn-sync.org",
                               file_hash=sha256("shipping_label.exe"), beacons=4),
        "lateral_movement": chain_d(day, user="kavya.n", hop1="SRV-APP01", hop2="SRV-DC01",
                                    dumper=sha256("nanodump"), hour=20),
    }
    benign: list[dict] = []
    benign += ep_typo(rng, day, "anita.m", 2)
    benign += ep_typo(rng, day, "vikram.r", 6, day.replace(hour=10))   # internal lockout
    benign += ep_vpn(rng, day) + ep_patch(rng, day) + ep_scan(rng, day, 3)
    benign += ep_backup(day) + ep_signed_download(day)
    benign += ep_admin_remote(rng, day) + ep_admin_remote(rng, day)     # admin remote logons, two servers
    for i, a in enumerate(benign, start=1):
        a["id"] = f"BEN-{i:04d}"
    for key, logs in attack.items():
        for i, a in enumerate(logs, start=1):
            a["id"] = f"ATK-{key[:2].upper()}-{i:03d}"
    return attack, benign


def windows_sample() -> list[dict]:
    """A small Windows Security + Sysmon event log (OTRF Security-Datasets field names)."""
    day = BASE_DAY + timedelta(days=1)
    ev = []

    def e(ts, eid, computer, channel="Security", **fields):
        ev.append({"@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "EventID": eid,
                   "Channel": "Microsoft-Windows-Sysmon/Operational" if channel == "Sysmon" else channel,
                   "Computer": f"{computer}.corp.local", **fields})

    t = day.replace(hour=3, minute=12)                                   # brute force on the web server
    for i in range(8):
        e(t + timedelta(seconds=30 * i), 4625, "SRV-WEB01", TargetUserName="administrator",
          IpAddress=BRUTE_FORCE_IPS[1], LogonType=10, Status="0xc000006a")
    e(t + timedelta(minutes=5), 4624, "SRV-WEB01", TargetUserName="administrator", IpAddress=BRUTE_FORCE_IPS[1], LogonType=10)
    e(t + timedelta(minutes=8), 4732, "SRV-WEB01", TargetUserName="Administrators", SubjectUserName="administrator",
      MemberName="CN=svc_sync,CN=Users,DC=corp,DC=local")

    t = day.replace(hour=22, minute=5)                                   # credential dumping + lateral movement
    e(t, 10, "WS-ENG11", "Sysmon", SourceImage=r"C:\Users\arjun.p\AppData\Local\Temp\pd64.exe",
      TargetImage=r"C:\Windows\system32\lsass.exe", GrantedAccess="0x1410", User="CORP\\arjun.p",
      Hashes=f"SHA1=0,MD5=0,SHA256={DUMPER_HASHES[1].upper()}")
    e(t + timedelta(minutes=11), 4624, "SRV-BKP01", TargetUserName="arjun.p", IpAddress=ASSETS["WS-ENG11"]["ip"], LogonType=3)
    e(t + timedelta(minutes=13), 7045, "SRV-BKP01", "System", ServiceName="PSEXESVC",
      ImagePath=r"%SystemRoot%\PSEXESVC.exe", TargetUserName="arjun.p", IpAddress=ASSETS["WS-ENG11"]["ip"])
    e(t + timedelta(minutes=21), 4624, "SRV-DC01", TargetUserName="arjun.p", IpAddress=ASSETS["SRV-BKP01"]["ip"], LogonType=3)

    t = day.replace(hour=13, minute=40)                                  # malware download + beaconing
    e(t, 15, "WS-MKT07", "Sysmon", User="CORP\\priya.s", TargetFilename=r"C:\Users\priya.s\Downloads\invoice_viewer.exe",
      Hash=f"SHA256={MALWARE_HASHES[0].upper()}", Contents=f"[ZoneTransfer] ZoneId=3 HostUrl=https://{PHISH_DOMAINS[0]}/inv")
    for i in range(5):
        e(t + timedelta(minutes=8 + 5 * i), 22, "WS-MKT07", "Sysmon", User="CORP\\priya.s", QueryName=C2_DOMAINS[0])

    t = day.replace(hour=10, minute=2)                                   # benign: typo, admin logon, updates
    e(t, 4625, "WS-HR02", TargetUserName="vikram.r", IpAddress="-", LogonType=2)
    e(t + timedelta(seconds=20), 4624, "WS-HR02", TargetUserName="vikram.r", IpAddress="-", LogonType=2)
    e(day.replace(hour=11, minute=15), 4624, "SRV-DB01", TargetUserName="it_admin", IpAddress=JUMP_HOST_IP, LogonType=3)
    e(day.replace(hour=11, minute=30), 22, "SRV-DB01", "Sysmon", User="NT AUTHORITY\\SYSTEM", QueryName="updates.microsoft.com")
    return sorted(ev, key=lambda x: x["@timestamp"])


def write_reference_data() -> None:
    """Constant reference files (intel, assets, baselines, rule-test logs, Windows sample)."""
    DATA_DIR.mkdir(exist_ok=True)
    (DATA_DIR / "samples").mkdir(exist_ok=True)
    (DATA_DIR / "samples" / "windows_sysmon_sample.json").write_text(json.dumps(windows_sample(), indent=2), encoding="utf-8")
    attack_logs, benign_logs = build_rule_test_logs(random.Random(1234))
    files = {"threat_intel.json": THREAT_INTEL, "assets.json": ASSETS, "user_baselines.json": USERS,
             "attack_logs.json": attack_logs, "benign_logs.json": benign_logs}
    for name, payload in files.items():
        (DATA_DIR / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main(seed: int = 42, n_alerts: int = 150) -> None:
    write_reference_data()
    alerts, truth = generate_dataset(seed, n_alerts)
    (DATA_DIR / "alerts.json").write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    (DATA_DIR / "ground_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    attack = sum(len(c["alert_ids"]) for c in truth["chains"].values())
    print(f"Wrote {len(alerts)} alerts ({attack} attack, {len(truth['benign_alert_ids'])} benign, seed {seed}) to {DATA_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--alerts", type=int, default=150)
    args = parser.parse_args()
    main(args.seed, args.alerts)
