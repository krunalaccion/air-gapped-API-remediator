"""
Unit tests for the Multi-Agent architecture, specialized agents, and common server.
"""

import json
import subprocess
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

    def test_multi_agent_pipeline_local_repo(self):
        # Create a local git repo
        local_repo = self.temp_dir / "pipeline_local_repo"
        local_repo.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init"], cwd=str(local_repo), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(local_repo), check=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=str(local_repo), check=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=str(local_repo), check=True)
        (local_repo / "main.py").write_text("import requests\nresp = requests.get('https://api.external-cloud.com/v1')\n")
        subprocess.run(["git", "add", "."], cwd=str(local_repo), check=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-m", "init"], cwd=str(local_repo), check=True)
        subprocess.run(["git", "branch", "-M", "main"], cwd=str(local_repo), check=True)

        config = GitAgentConfig(
            repo_url=str(local_repo),
            feature_branch_name="airgap/remediate-apis",
        )
        self.assertEqual(config.provider, ProviderType.LOCAL)

        pipeline = MultiAgentPipeline(git_config=config)
        res = pipeline.run_remediation_pipeline()

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["git_result"]["status"], "success")
        self.assertTrue(res["git_result"]["pr_url"].startswith("file://"))

        # Verify commit exists on branch
        out = subprocess.run(["git", "log", "-1", "--pretty=%s"], cwd=str(local_repo), capture_output=True, text=True, check=True).stdout
        self.assertIn("fix(airgap)", out)
        # Verify airgap proxy file generated
        self.assertTrue((local_repo / "config" / "airgap_proxy.json").exists())


if __name__ == "__main__":
    unittest.main()

