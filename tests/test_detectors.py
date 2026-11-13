import os
import unittest

from analyzer.ssh_detector import analyze_ssh_log
from analyzer.web_detector import analyze_web_log
from analyzer.firewall_detector import analyze_firewall_log


class TestDetectors(unittest.TestCase):
    def setUp(self):
        self.base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_ssh_detection(self):
        path = os.path.join(self.base, "sample_logs", "sample_auth.log")
        alerts = analyze_ssh_log(path, threshold=5)
        categories = [a["category"] for a in alerts]
        self.assertIn("SSH Brute-Force / Credential Stuffing", categories)
        self.assertIn("SSH Account Compromise After Brute Force", categories)

    def test_web_detection(self):
        path = os.path.join(self.base, "sample_logs", "sample_access.log")
        alerts = analyze_web_log(path)
        categories = [a["category"] for a in alerts]
        self.assertIn("SQL Injection (SQLi) Probe", categories)
        self.assertIn("Cross-Site Scripting (XSS) Probe", categories)
        self.assertIn("Directory / Path Traversal Attempt", categories)
        self.assertIn("Automated Vulnerability Scanner Detected", categories)

    def test_firewall_detection(self):
        path = os.path.join(self.base, "sample_logs", "sample_ufw.log")
        alerts = analyze_firewall_log(path, port_threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["mitre_id"], "T1046")


if __name__ == "__main__":
    unittest.main()
