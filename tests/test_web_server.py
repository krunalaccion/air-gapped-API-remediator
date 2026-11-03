"""
Unit tests for web server API endpoints and Air-Gapped API Remediator logic.
"""

import json
import tempfile
import unittest
from pathlib import Path

from agents.scanner_agent.agent import ScannerAgent
from agents.remediator_agent.agent import RemediatorAgent


class TestAirGappedScannerAndRemediator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_airgap_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scan_workspace_detects_egress(self):
        # Create a file with external API call
        src_dir = self.temp_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        py_file = src_dir / "client.py"
        py_file.write_text('response = requests.get("https://api.external-cloud.com/v1/telemetry")\n')

        scanner = ScannerAgent()
        findings = scanner.scan_workspace(self.temp_dir)
        self.assertTrue(len(findings) >= 1)
        egress_finding = next((f for f in findings if "external-cloud.com" in f["description"]), None)
        self.assertIsNotNone(egress_finding)
        self.assertEqual(egress_finding["severity"], "HIGH")
        self.assertEqual(egress_finding["file"], "src/client.py")

    def test_scan_workspace_defaults_when_clean(self):
        # Clean directory
        scanner = ScannerAgent()
        findings = scanner.scan_workspace(self.temp_dir)
        # Should return placeholder findings for airgap remediator
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["id"], "AIRGAP-001")

    def test_airgap_agent_remediate(self):
        agent = RemediatorAgent()
        result = agent.remediate(self.temp_dir)
        self.assertIn("config/airgap_proxy.json", result["files_modified"])
        self.assertIn("AIRGAP_SECURITY_AUDIT.md", result["files_modified"])
        self.assertTrue((self.temp_dir / "config" / "airgap_proxy.json").exists())
        self.assertTrue((self.temp_dir / "AIRGAP_SECURITY_AUDIT.md").exists())


if __name__ == "__main__":
    unittest.main()
