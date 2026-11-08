import unittest
from pathlib import Path
from agents.scanner_agent.external_scanners import (
    SemgrepScanner,
    TrivyScanner,
    get_scanner_tools_status,
)
from agents.scanner_agent.pipeline import SecureScanPipeline


class TestExternalScanners(unittest.TestCase):
    def test_tools_status_schema(self):
        tools = get_scanner_tools_status()
        self.assertIn("semgrep", tools)
        self.assertIn("trivy", tools)
        self.assertIn("available", tools["semgrep"])
        self.assertIn("available", tools["trivy"])

    def test_semgrep_graceful_handling_when_not_installed(self):
        scanner = SemgrepScanner(binary_path="/nonexistent/semgrep")
        self.assertFalse(scanner.is_available)
        findings, status = scanner.scan(Path("."))
        self.assertEqual(len(findings), 0)
        self.assertEqual(status.status_code, "SKIPPED")
        self.assertIn("not installed", status.skipped_reason.lower())

    def test_trivy_graceful_handling_when_not_installed(self):
        scanner = TrivyScanner(binary_path="/nonexistent/trivy")
        self.assertFalse(scanner.is_available)
        findings, status = scanner.scan(Path("."))
        self.assertEqual(len(findings), 0)
        self.assertEqual(status.status_code, "SKIPPED")
        self.assertIn("not installed", status.skipped_reason.lower())

    def test_pipeline_engine_selection(self):
        pipeline = SecureScanPipeline()
        # Scan CustomerApi with engine="all"
        target_dir = Path("repos/CustomerApi")
        if target_dir.exists():
            bundle = pipeline.run_scan(target_dir, scanner_engine="all")
            # Should have statuses recorded for scanners
            scanner_names = [s.scanner_name for s in bundle.scanner_statuses]
            self.assertTrue(any("Semgrep" in n for n in scanner_names))
            self.assertTrue(any("Trivy" in n for n in scanner_names))
            self.assertTrue(any("Lexical" in n for n in scanner_names))

            # Verify HTML report accurately displays threat counts in KPI cards
            html_rep = pipeline.render_html_report(bundle)
            self.assertIn("Audit Verdict", html_rep)
            self.assertIn("Critical &amp; High Risk", html_rep)
            if len(bundle.findings) > 0:
                self.assertNotIn("<span>0</span>\n          <span style=\"font-size: 13px; font-weight: 600; color: #dc2626;\">threats</span>", html_rep)


if __name__ == "__main__":
    unittest.main()

