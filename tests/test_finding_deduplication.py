"""
Unit tests for vulnerability finding deduplication across internal inspectors,
external scanners (Semgrep, Trivy), and the remediation pipeline.
"""

import json
import tempfile
import unittest
from pathlib import Path

from agents.scanner_agent.deduplicator import (
    is_duplicate_finding,
    deduplicate_findings,
    clean_duplicate_finding_files,
    normalize_file_path,
    paths_match,
    normalize_snippet,
    cwes_compatible,
)
from agents.scanner_agent.models import (
    RawSecurityFinding,
    FindingSeverity,
    FindingClassification,
)
from agents.scanner_agent.pipeline import SecureScanPipeline
from agents.remediator_agent.agent import RemediatorAgent


class TestFindingDeduplication(unittest.TestCase):

    def setUp(self):
        self.sample_airgap_001 = {
            "finding_id": "AIRGAP-001",
            "rule_id": "airgap-external-egress",
            "severity": "MEDIUM",
            "file_path": "src/ERMS.API/appsettings.json",
            "line_number": 27,
            "message": "Outbound egress to Slack webhook violates air-gap perimeter policy.",
            "code_snippet": '"WebhookUrl": "https://webhooks.example.com/services/org/channel/placeholder",',
            "cwe_id": "CWE-918",
        }
        self.sample_semgrep_002 = {
            "finding_id": "SEMGREP-002",
            "rule_id": "airgap.network.unwhitelisted-external-egress",
            "severity": "HIGH",
            "file_path": "src/ERMS.API/appsettings.json",
            "line_number": 27,
            "message": "Direct outbound internet connection detected in isolated perimeter.",
            "code_snippet": '"WebhookUrl": "https://webhooks.example.com/services/org/channel/placeholder",',
            "cwe_id": "CWE-918",
        }

        self.sample_crypto_0003 = {
            "finding_id": "CRYPTO-0003",
            "rule_id": "csharp.crypto.weak-algorithm",
            "severity": "MEDIUM",
            "file_path": "src/ERMS.Infrastructure/Cryptography/LegacyCryptoService.cs",
            "line_number": 13,
            "message": "Weak/deprecated cryptographic algorithm detected: MD5.Create.",
            "code_snippet": "using var md5 = MD5.Create();",
            "cwe_id": "CWE-328",
        }
        self.sample_semgrep_003 = {
            "finding_id": "SEMGREP-003",
            "rule_id": "airgap.generic.crypto.weak-algorithm",
            "severity": "MEDIUM",
            "file_path": "src/ERMS.Infrastructure/Cryptography/LegacyCryptoService.cs",
            "line_number": 13,
            "message": "Deprecated or broken cryptographic algorithm used (DES, MD5, SHA1).",
            "code_snippet": "using var md5 = MD5.Create();",
            "cwe_id": "CWE-327",
        }

        self.sample_config_0002 = {
            "finding_id": "CONFIG-0002",
            "rule_id": "aspnet.config.allowed-hosts-wildcard",
            "severity": "LOW",
            "file_path": "src/ERMS.API/appsettings.json",
            "line_number": 1,
            "message": 'AllowedHosts is set to "*".',
            "code_snippet": '"AllowedHosts": "*"',
            "cwe_id": "CWE-16",
        }
        self.sample_config_0003 = {
            "finding_id": "CONFIG-0003",
            "rule_id": "aspnet.config.connectionstring-plaintext-password",
            "severity": "HIGH",
            "file_path": "src/ERMS.API/appsettings.json",
            "line_number": 1,
            "message": "Plaintext password detected in ConnectionStrings.",
            "code_snippet": '"DefaultConnection": "Server=localhost,1433;Database=ERMS_DB;User Id=sa;Password=secret"',
            "cwe_id": "CWE-798",
        }

        self.sample_crypto_0005 = {
            "finding_id": "CRYPTO-0005",
            "rule_id": "csharp.crypto.weak-algorithm",
            "severity": "HIGH",
            "file_path": "src/ERMS.Infrastructure/Cryptography/LegacyCryptoService.cs",
            "line_number": 41,
            "message": "Weak/deprecated cryptographic algorithm detected: DES.Create.",
            "code_snippet": "using var des = DES.Create();",
            "cwe_id": "CWE-327",
        }
        self.sample_crypto_0006 = {
            "finding_id": "CRYPTO-0006",
            "rule_id": "csharp.crypto.weak-algorithm",
            "severity": "HIGH",
            "file_path": "src/ERMS.Infrastructure/Cryptography/LegacyCryptoService.cs",
            "line_number": 56,
            "message": "Weak/deprecated cryptographic algorithm detected: DES.Create.",
            "code_snippet": "using var des = DES.Create();",
            "cwe_id": "CWE-327",
        }

    def test_duplicate_egress_detection(self):
        self.assertTrue(is_duplicate_finding(self.sample_airgap_001, self.sample_semgrep_002))
        self.assertTrue(is_duplicate_finding(self.sample_semgrep_002, self.sample_airgap_001))

    def test_duplicate_crypto_detection_with_differing_cwes(self):
        # CRYPTO-0003 uses CWE-328 (Hash), SEMGREP-003 uses CWE-327 (Broken Crypto)
        self.assertTrue(cwes_compatible("CWE-327", "CWE-328"))
        self.assertTrue(is_duplicate_finding(self.sample_crypto_0003, self.sample_semgrep_003))

    def test_distinct_vulnerabilities_not_flagged_as_duplicates(self):
        # Different issues on line 1 of appsettings.json
        self.assertFalse(is_duplicate_finding(self.sample_config_0002, self.sample_config_0003))
        # Different methods in LegacyCryptoService (lines 41 vs 56)
        self.assertFalse(is_duplicate_finding(self.sample_crypto_0005, self.sample_crypto_0006))

    def test_path_matching_cross_repository(self):
        self.assertTrue(paths_match("LargeRepo/src/ERMS.API/appsettings.json", "src/ERMS.API/appsettings.json"))
        self.assertTrue(paths_match("src/ERMS.API/appsettings.json", "LargeRepo/src/ERMS.API/appsettings.json"))
        self.assertTrue(paths_match("./src/ERMS.API/appsettings.json", "src\\ERMS.API\\appsettings.json"))
        self.assertFalse(paths_match("src/ERMS.API/appsettings.json", "src/ERMS.API/launchSettings.json"))

    def test_deduplicate_findings_list_and_severity_promotion(self):
        findings = [
            self.sample_airgap_001,   # MEDIUM severity
            self.sample_semgrep_002,  # HIGH severity, duplicate
            self.sample_crypto_0003,  # MEDIUM severity
            self.sample_semgrep_003,  # MEDIUM severity, duplicate
            self.sample_config_0002,  # Unique
            self.sample_config_0003,  # Unique
        ]
        deduped = deduplicate_findings(findings)
        self.assertEqual(len(deduped), 4)

        # Confirm AIRGAP-001 severity was promoted from MEDIUM to HIGH
        airgap_finding = next(f for f in deduped if f["finding_id"] == "AIRGAP-001")
        self.assertEqual(airgap_finding["severity"], "HIGH")

        # Confirm SEMGREP-002 and SEMGREP-003 were removed/ignored
        ids = [f["finding_id"] for f in deduped]
        self.assertNotIn("SEMGREP-002", ids)
        self.assertNotIn("SEMGREP-003", ids)

    def test_clean_duplicate_finding_files_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            f1 = tmp_path / "airgap-001.json"
            f1.write_text(json.dumps(self.sample_airgap_001, indent=2), encoding="utf-8")

            f2 = tmp_path / "semgrep-002.json"
            f2.write_text(json.dumps(self.sample_semgrep_002, indent=2), encoding="utf-8")

            f3 = tmp_path / "config-0002.json"
            f3.write_text(json.dumps(self.sample_config_0002, indent=2), encoding="utf-8")

            self.assertEqual(len(list(tmp_path.glob("*.json"))), 3)

            removed = clean_duplicate_finding_files(tmp_path)
            self.assertEqual(removed, ["semgrep-002.json"])

            remaining = [p.name for p in sorted(tmp_path.glob("*.json"))]
            self.assertEqual(remaining, ["airgap-001.json", "config-0002.json"])
            self.assertFalse(f2.exists())
            self.assertTrue(f1.exists())

    def test_pipeline_merge_findings_deduplication(self):
        f_builtin = RawSecurityFinding(
            finding_id="CRYPTO-0001",
            scanner_source="CSharpLexicalAnalyzer",
            rule_id="csharp.crypto.weak-algorithm",
            severity=FindingSeverity.MEDIUM,
            classification=FindingClassification.VERIFIED,
            file_path="src/ERMS.Infrastructure/Cryptography/LegacyCryptoService.cs",
            line_start=13,
            line_end=13,
            code_snippet="using var md5 = MD5.Create();",
            raw_evidence="Weak MD5",
            cwe_id="CWE-328",
        )
        f_semgrep = RawSecurityFinding(
            finding_id="SEMGREP-001",
            scanner_source="SemgrepScanner",
            rule_id="airgap.generic.crypto.weak-algorithm",
            severity=FindingSeverity.HIGH,
            classification=FindingClassification.VERIFIED,
            file_path="src/ERMS.Infrastructure/Cryptography/LegacyCryptoService.cs",
            line_start=13,
            line_end=13,
            code_snippet="using var md5 = MD5.Create();",
            raw_evidence="Deprecated MD5",
            cwe_id="CWE-327",
        )

        merged = SecureScanPipeline._merge_findings([f_builtin], [f_semgrep])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].finding_id, "CRYPTO-0001")
        # Elevated severity to HIGH from duplicate Semgrep finding
        self.assertEqual(merged[0].severity, FindingSeverity.HIGH)

    def test_remediator_loads_and_cleans_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            f_dir = tmp_path / "findings"
            f_dir.mkdir(parents=True, exist_ok=True)

            (f_dir / "airgap-001.json").write_text(json.dumps(self.sample_airgap_001), encoding="utf-8")
            (f_dir / "semgrep-002.json").write_text(json.dumps(self.sample_semgrep_002), encoding="utf-8")
            (f_dir / "config-0002.json").write_text(json.dumps(self.sample_config_0002), encoding="utf-8")

            remediator = RemediatorAgent(scanner_findings_dir=f_dir)
            loaded = remediator.load_scanner_findings()

            self.assertEqual(len(loaded), 2)
            loaded_ids = [item["finding_id"] for item in loaded]
            self.assertIn("AIRGAP-001", loaded_ids)
            self.assertIn("CONFIG-0002", loaded_ids)
            self.assertNotIn("SEMGREP-002", loaded_ids)

            # Confirm duplicate file semgrep-002.json was unlinked on disk
            self.assertFalse((f_dir / "semgrep-002.json").exists())
            self.assertTrue((f_dir / "airgap-001.json").exists())


if __name__ == "__main__":
    unittest.main()
