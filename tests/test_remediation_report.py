"""
Unit tests for Post-Remediation HTML and JSON Audit Report.
"""

import unittest
from agents.remediator_agent.agent import RemediatorAgent
from agents.remediator_agent.reporter import RemediationReporter


class TestRemediationReport(unittest.TestCase):

    def setUp(self):
        self.agent = RemediatorAgent()
        self.sample_result = {
            "workspace_path": "/tmp/test_workspace",
            "files_modified": ["src/Controllers/UsersController.cs", "config/airgap_proxy.json", "AIRGAP_SECURITY_AUDIT.md"],
            "summary": "Remediated 1 finding and configured air-gap gateway proxy",
            "bug_fixes": [
                {
                    "finding_id": "SQLI-001",
                    "rule_id": "csharp-sql-injection",
                    "severity": "HIGH",
                    "cwe_id": "CWE-89",
                    "file_path": "src/Controllers/UsersController.cs",
                    "line_number": 12,
                    "summary": "Parameterized SQL query",
                    "explanation": "Sanitized query using SqlParameter",
                    "provider": "rule-based-security-fixer",
                    "diff": "--- a/src/Controllers/UsersController.cs\n+++ b/src/Controllers/UsersController.cs\n@@ -12,1 +12,1 @@\n-rawSql\n+safeSql",
                }
            ],
            "proxy_config": {
                "airgap_mode": True,
                "proxy_host": "proxy.airgap.internal:8080",
                "blocked_external_egress": ["api.external-cloud.com"],
            },
        }

    def test_render_html_report_contains_key_elements(self):
        html_rep = RemediationReporter.render_html_report(self.sample_result)
        self.assertIn("<!DOCTYPE html>", html_rep)
        self.assertIn("Autonomous API Defense for Air-Gapped Systems", html_rep)
        self.assertIn("SQLI-001", html_rep)
        self.assertIn("csharp-sql-injection", html_rep)
        self.assertIn("CWE-89", html_rep)
        self.assertIn("REMEDIATED", html_rep)
        self.assertIn("AIR-GAP COMPLIANCE VERIFIED", html_rep)
        self.assertIn("window.print()", html_rep)

    def test_agent_get_report_content(self):
        self.agent.last_result = self.sample_result
        html_rep, ctype = self.agent.get_report_content("html")
        self.assertIn("text/html", ctype)
        self.assertIn("SQLI-001", html_rep)

        json_rep, jtype = self.agent.get_report_content("json")
        self.assertIn("application/json", jtype)
        self.assertIn("completed", json_rep)


if __name__ == "__main__":
    unittest.main()
