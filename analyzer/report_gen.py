import json
from datetime import datetime, timezone


def export_reports(alerts: list, md_path: str = "incident_report.md", json_path: str = "incident_report.json") -> None:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    payload = {
        "tool": "LogSentinel CLI v1.1",
        "generated_at": generated_at,
        "total_alerts": len(alerts),
        "alerts": alerts
    }
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(payload, jf, indent=2)

    lines = [
        "# LogSentinel Security Incident Report",
        f"**Generated:** {generated_at}  ",
        f"**Total Alerts Flagged:** {len(alerts)}",
        "",
        "## Executive Summary",
        "| Severity | MITRE ATT&CK | Category | Source IP | Details |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ]

    for a in alerts:
        lines.append(f"| **{a['severity']}** | `{a['mitre_id']}` | {a['category']} | `{a['source_ip']}` | {a['details']} |")

    lines.extend(["", "## Recommended Remediation Actions"])
    for idx, a in enumerate(alerts, 1):
        lines.append(f"{idx}. **[{a['severity']}] {a['category']} (`{a['source_ip']}`):** {a['remediation']}")

    with open(md_path, "w", encoding="utf-8") as mf:
        mf.write("\n".join(lines) + "\n")
