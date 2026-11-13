import re
from collections import defaultdict

UFW_BLOCK_RE = re.compile(r"\[UFW BLOCK\].*?SRC=(\d+\.\d+\.\d+\.\d+).*?DPT=(\d+)")


def analyze_firewall_log(filepath: str, port_threshold: int = 5) -> list:
    ports_by_ip = defaultdict(set)
    alerts = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = UFW_BLOCK_RE.search(line)
            if match:
                ip, dpt = match.groups()
                ports_by_ip[ip].add(int(dpt))

    for ip, ports in ports_by_ip.items():
        if len(ports) >= port_threshold:
            sorted_ports = sorted(ports)
            preview = ", ".join(str(p) for p in sorted_ports[:8])
            alerts.append({
                "severity": "MEDIUM",
                "category": "Network Port Scan / Service Enumeration",
                "mitre_id": "T1046",
                "source_ip": ip,
                "details": f"Blocked connection probes across {len(ports)} distinct ports ({preview}).",
                "remediation": f"Drop all traffic from {ip} at perimeter firewall (`sudo ufw insert 1 deny from {ip}`)."
            })

    return alerts
