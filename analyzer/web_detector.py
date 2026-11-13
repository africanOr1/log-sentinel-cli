import re
from urllib.parse import unquote

LOG_RE = re.compile(r'^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]+" (\d{3}) \d+ "[^"]*" "([^"]*)"')

RULES = [
    {
        "category": "SQL Injection (SQLi) Probe",
        "mitre_id": "T1190",
        "severity": "HIGH",
        "pattern": re.compile(r"(\bunion\b.*\bselect\b|'\s*or\s*'1'='1|'\s*or\s*1=1|--|;\s*drop\s+table)", re.IGNORECASE),
        "remediation": "Ensure parameterized queries/prepared statements are enforced and block offending IP at WAF."
    },
    {
        "category": "Cross-Site Scripting (XSS) Probe",
        "mitre_id": "T1059.007",
        "severity": "MEDIUM",
        "pattern": re.compile(r"(<script>|javascript:|onerror=|onload=|alert\()", re.IGNORECASE),
        "remediation": "Enforce strict output encoding and Content-Security-Policy (CSP) headers."
    },
    {
        "category": "Directory / Path Traversal Attempt",
        "mitre_id": "T1083",
        "severity": "HIGH",
        "pattern": re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini)", re.IGNORECASE),
        "remediation": "Sanitize file path inputs and restrict web server filesystem permissions."
    }
]

SCANNER_RE = re.compile(r"(sqlmap|nikto|gobuster|dirbuster|nmap|wfuzz|nuclei)", re.IGNORECASE)


def analyze_web_log(filepath: str) -> list:
    alerts = []
    seen_events = set()

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = LOG_RE.search(line)
            if not match:
                continue
            ip, timestamp, method, raw_path, status, user_agent = match.groups()
            decoded_path = unquote(raw_path)

            scanner_match = SCANNER_RE.search(user_agent)
            if scanner_match:
                key = (ip, "SCANNER", scanner_match.group(1).lower())
                if key not in seen_events:
                    seen_events.add(key)
                    alerts.append({
                        "severity": "MEDIUM",
                        "category": "Automated Vulnerability Scanner Detected",
                        "mitre_id": "T1595.002",
                        "source_ip": ip,
                        "details": f"Scanner User-Agent '{scanner_match.group(1)}' detected probing {decoded_path}.",
                        "remediation": f"Rate-limit or block {ip} and review exposed endpoints."
                    })

            for rule in RULES:
                if rule["pattern"].search(decoded_path):
                    key = (ip, rule["category"], decoded_path)
                    if key not in seen_events:
                        seen_events.add(key)
                        alerts.append({
                            "severity": rule["severity"],
                            "category": rule["category"],
                            "mitre_id": rule["mitre_id"],
                            "source_ip": ip,
                            "details": f"{method} request to '{decoded_path}' (HTTP {status}).",
                            "remediation": rule["remediation"]
                        })

    return alerts
