import re
from collections import defaultdict

FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)")


def analyze_ssh_log(filepath: str, threshold: int = 5) -> list:
    failed_by_ip = defaultdict(list)
    alerts = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            fail_match = FAILED_RE.search(line)
            if fail_match:
                user, ip = fail_match.groups()
                failed_by_ip[ip].append((line_num, user))
                continue

            acc_match = ACCEPTED_RE.search(line)
            if acc_match:
                user, ip = acc_match.groups()
                if len(failed_by_ip[ip]) >= threshold:
                    alerts.append({
                        "severity": "CRITICAL",
                        "category": "SSH Account Compromise After Brute Force",
                        "mitre_id": "T1110.001",
                        "source_ip": ip,
                        "details": f"Successful login for '{user}' after {len(failed_by_ip[ip])} failed attempts (line {line_num}).",
                        "remediation": f"Immediately block {ip}, reset credentials for '{user}', and enforce SSH key-only authentication."
                    })

    for ip, attempts in failed_by_ip.items():
        if len(attempts) >= threshold:
            users = sorted({u for _, u in attempts})
            alerts.append({
                "severity": "HIGH",
                "category": "SSH Brute-Force / Credential Stuffing",
                "mitre_id": "T1110",
                "source_ip": ip,
                "details": f"{len(attempts)} failed SSH login attempts targeting users: {', '.join(users[:5])}.",
                "remediation": f"Block {ip} via UFW/iptables (`sudo ufw deny from {ip}`) and enable Fail2Ban."
            })

    return alerts
