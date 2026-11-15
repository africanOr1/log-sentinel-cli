# LogSentinel CLI v1.1

![Tests](https://github.com/africanOr1/log-sentinel-cli/actions/workflows/tests.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-zero-success)

A lightweight, zero-dependency **Blue-Team SOC Log Analyzer & Threat Detector** built in Python. LogSentinel parses Linux authentication logs (`auth.log`), web server logs (`access.log`), and UFW firewall logs (`ufw.log`) to detect active attacks, map alerts to **MITRE ATT&CK** techniques, and export structured incident reports.

## Key Features
* **SSH Brute-Force & Compromise Detection (`T1110`):** Detects high-frequency failed login bursts and flags accounts that succeed immediately after a brute-force wave.
* **Web Attack & Scanner Detection (`T1190`, `T1059.007`, `T1083`):** Spots SQL Injection (SQLi), Cross-Site Scripting (XSS), Directory Traversal, and automated scanners (`sqlmap`, `Nikto`, `Gobuster`).
* **Firewall Port Scan Detection (`T1046`):** Identifies vertical port scanning and network service enumeration across blocked UFW packets.
* **Zero-Friction Demo Mode:** Includes simulated attack logs so you can test the tool immediately without external setup.
* **Automated Incident Reporting:** Exports findings into `incident_report.md` and `incident_report.json` with recommended remediation steps.

## Quickstart

Clone the repository and run the built-in simulation:

```bash
git clone https://github.com/africanOr1/log-sentinel-cli.git
cd log-sentinel-cli
python3 sentinel.py --demo --export
```

### Custom Log Analysis

```bash
python3 sentinel.py --auth-log /var/log/auth.log --web-log /var/log/nginx/access.log --fw-log /var/log/ufw.log --threshold 5 --export
```

### Running Unit Tests

```bash
python3 -m unittest discover -s tests -v
```

## Project Structure

```text
log-sentinel-cli/
├── .github/workflows/tests.yml   # Automated CI test pipeline
├── analyzer/
│   ├── __init__.py
│   ├── ssh_detector.py           # SSH brute-force & compromise rules
│   ├── web_detector.py           # SQLi, XSS, LFI, and scanner rules
│   ├── firewall_detector.py
