#!/usr/bin/env python3
import argparse
import os
import sys

from analyzer.ssh_detector import analyze_ssh_log
from analyzer.web_detector import analyze_web_log
from analyzer.firewall_detector import analyze_firewall_log
from analyzer.report_gen import export_reports

BANNER = """
============================================================
  LOGSENTINEL CLI v1.1 - Blue-Team Threat & Log Analyzer
  Authorized Defensive Monitoring & Incident Triage Only
============================================================
"""


def main():
    parser = argparse.ArgumentParser(description="LogSentinel CLI - Detect attacks from server logs.")
    parser.add_argument("--demo", action="store_true", help="Run analysis on built-in simulated attack logs")
    parser.add_argument("--auth-log", type=str, help="Path to Linux SSH auth.log file")
    parser.add_argument("--web-log", type=str, help="Path to Apache/Nginx access.log file")
    parser.add_argument("--fw-log", type=str, help="Path to UFW firewall log file")
    parser.add_argument("--threshold", type=int, default=5, help="Threshold for brute-force / port scan alerts (default: 5)")
    parser.add_argument("--export", action="store_true", help="Export incident_report.md and incident_report.json")
    args = parser.parse_args()

    print(BANNER.strip())

    base_dir = os.path.dirname(os.path.abspath(__file__))
    if args.demo:
        args.auth_log = os.path.join(base_dir, "sample_logs", "sample_auth.log")
        args.web_log = os.path.join(base_dir, "sample_logs", "sample_access.log")
        args.fw_log = os.path.join(base_dir, "sample_logs", "sample_ufw.log")

    if not any([args.auth_log, args.web_log, args.fw_log]):
        parser.print_help()
        sys.exit(1)

    all_alerts = []

    if args.auth_log and os.path.exists(args.auth_log):
        print(f"[*] Scanning SSH log: {args.auth_log}")
        all_alerts.extend(analyze_ssh_log(args.auth_log, threshold=args.threshold))

    if args.web_log and os.path.exists(args.web_log):
        print(f"[*] Scanning Web log: {args.web_log}")
        all_alerts.extend(analyze_web_log(args.web_log))

    if args.fw_log and os.path.exists(args.fw_log):
        print(f"[*] Scanning Firewall log: {args.fw_log}")
        all_alerts.extend(analyze_firewall_log(args.fw_log, port_threshold=args.threshold))

    print(f"\n[+] Analysis Complete: {len(all_alerts)} threat(s) detected.\n")

    for alert in all_alerts:
        print(f"[{alert['severity']}] ({alert['mitre_id']}) {alert['category']}")
        print(f"    Source IP   : {alert['source_ip']}")
        print(f"    Details     : {alert['details']}")
        print(f"    Remediation : {alert['remediation']}\n")

    if args.export:
        export_reports(all_alerts)
        print("[+] Reports exported: incident_report.md, incident_report.json")


if __name__ == "__main__":
    main()
