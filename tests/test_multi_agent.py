"""
Unit tests for the Multi-Agent architecture, specialized agents, and common server.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from agents.base import BaseAgent, AgentRegistry
from agents.scanner_agent.agent import ScannerAgent
from agents.remediator_agent.agent import RemediatorAgent
from agents.git_agent.agent import GitSubAgent
from agents.git_agent.config import GitAgentConfig, ProviderType
from orchestrator.pipeline import MultiAgentPipeline


class DummyCustomAgent(BaseAgent):
    """Example of an additional custom agent added by user to the multi-agent system."""

    def __init__(self):
        super().__init__(
            name="PolicyComplianceAgent",
            role="Perimeter Rule Checker",
            description="Checks regulatory airgap compliance rules."
        )

    def run(self, context):
        return {"policy_check": "PASS", "agent": self.name}


class TestMultiAgentArchitecture(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_multi_agent_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_agent_registry_and_extensibility(self):
        AgentRegistry.clear()

        scanner = ScannerAgent()
        remediator = RemediatorAgent()
        custom_agent = DummyCustomAgent()

        AgentRegistry.register("scanner", scanner)
        AgentRegistry.register("remediator", remediator)
        AgentRegistry.register("policy", custom_agent)

        agents = AgentRegistry.list_agents()
        self.assertEqual(len(agents), 3)

        agent_names = {a["name"] for a in agents}
        self.assertIn("ScannerAgent", agent_names)
        self.assertIn("RemediatorAgent", agent_names)
        self.assertIn("PolicyComplianceAgent", agent_names)

        # Test fetching specific agent
        retrieved = AgentRegistry.get("policy")
        self.assertIsNotNone(retrieved)
        res = retrieved.run({})
        self.assertEqual(res["policy_check"], "PASS")

    def test_scanner_agent_detection(self):
        src_dir = self.temp_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        py_file = src_dir / "network.py"
        py_file.write_text('url = "https://api.external-cloud.com/v1/telemetry"\n')

        scanner = ScannerAgent()
        result = scanner.run({"workspace_path": str(self.temp_dir)})
        self.assertEqual(result["status"], "completed")
        self.assertGreaterEqual(result["total_findings"], 1)

        findings = result["findings"]
        egress_finding = next((f for f in findings if "external-cloud.com" in f["description"]), None)
        self.assertIsNotNone(egress_finding)
        self.assertEqual(egress_finding["severity"], "HIGH")

    def test_remediator_agent_fixes(self):
        remediator = RemediatorAgent()
        result = remediator.run({"workspace_path": str(self.temp_dir)})

        self.assertEqual(result["status"], "completed")
        self.assertIn("config/airgap_proxy.json", result["files_modified"])
        self.assertIn("AIRGAP_SECURITY_AUDIT.md", result["files_modified"])

        # Check files were written
        self.assertTrue((self.temp_dir / "config" / "airgap_proxy.json").exists())
        self.assertTrue((self.temp_dir / "AIRGAP_SECURITY_AUDIT.md").exists())

        # Verify proxy config content
        proxy_content = json.loads((self.temp_dir / "config" / "airgap_proxy.json").read_text())
        self.assertTrue(proxy_content["airgap_mode"])
        self.assertEqual(proxy_content["proxy_host"], "proxy.airgap.internal")


if __name__ == "__main__":
    unittest.main()

