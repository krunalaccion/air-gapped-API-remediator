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

    def test_remediator_agent_bug_fixer_finding(self):
        remediator = RemediatorAgent(
            repos_root=self.temp_dir / "repos",
            reports_dir=self.temp_dir / "reports",
        )
        ws_dir = self.temp_dir / "ws"
        ws_dir.mkdir(parents=True, exist_ok=True)

        result = remediator.fix_finding(
            workspace_path=ws_dir,
            provider="mock",
        )
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["applied"])
        self.assertIn("Controllers/UsersController.cs", result["files_modified"])
        self.assertTrue((ws_dir / "Controllers" / "UsersController.cs").exists())
        patched = (ws_dir / "Controllers" / "UsersController.cs").read_text(encoding="utf-8")
        self.assertIn("Parameters.AddWithValue", patched)

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
        # Verify CustomerApi files were NOT injected into the local repository
        self.assertFalse((local_repo / "Controllers").exists())
        self.assertFalse((local_repo / "Controllers" / "UsersController.cs").exists())
        self.assertFalse((local_repo / "reports" / "SQLI-001_report.json").exists())

    def test_local_llm_client_ollama_and_local(self):
        from agents.remediator_agent.llm_client import CloudLLMClient
        from agents.remediator_agent.models import Finding

        client_ollama = CloudLLMClient(provider="ollama", model="qwen2.5-coder:3b")
        self.assertEqual(client_ollama.provider, "ollama")
        self.assertEqual(client_ollama.model, "qwen2.5-coder:3b")

        client_local = CloudLLMClient(provider="local", model="qwen2.5-coder-7b-instruct", base_url="http://localhost:1234/v1")
        self.assertEqual(client_local.provider, "local")
        self.assertEqual(client_local.base_url, "http://localhost:1234/v1")

        # Verify offline fallback when local endpoint is unreachable
        finding = Finding(
            finding_id="SQLI-001",
            rule_id="csharp-sql-injection",
            severity="HIGH",
            file_path="Controllers/UsersController.cs",
            line_number=12,
            message="SQLi",
            code_snippet='var query = $"SELECT * FROM Users WHERE Id = \'{userId}\'";',
            repository="CustomerApi",
        )
        sample_code = (
            'var query = $"SELECT * FROM Users WHERE Id = \'{userId}\'";\n'
            'var cmd = new SqlCommand(query, conn);\n'
        )
        proposal = client_ollama.generate_fix(finding, sample_code, sample_code)
        self.assertIsNotNone(proposal)
        self.assertIn("Parameters.AddWithValue", proposal.fixed_file_content)
        self.assertIn("@userId", proposal.fixed_file_content)

        # Verify RemediatorAgent initialization with llm_provider, model, base_url
        remediator = RemediatorAgent(
            llm_provider="ollama",
            model="qwen2.5-coder:3b",
            base_url="http://127.0.0.1:11434",
        )
        self.assertEqual(remediator.llm_provider, "ollama")
        self.assertEqual(remediator.model, "qwen2.5-coder:3b")
        self.assertEqual(remediator.base_url, "http://127.0.0.1:11434")

    def test_llm_client_timeout_and_secret_remediation(self):
        import os
        from unittest.mock import patch
        from agents.remediator_agent.llm_client import CloudLLMClient
        from agents.remediator_agent.fixer_agent import Finding

        # 1. Verify default timeout is 180 seconds
        client_default = CloudLLMClient(provider="mock")
        self.assertEqual(client_default.timeout, 180)

        # 2. Verify custom timeout override
        client_custom = CloudLLMClient(provider="mock", timeout=60)
        self.assertEqual(client_custom.timeout, 60)

        # 3. Verify environment variable LLM_TIMEOUT override
        with patch.dict(os.environ, {"LLM_TIMEOUT": "240"}):
            client_env = CloudLLMClient(provider="mock")
            self.assertEqual(client_env.timeout, 240)

        # 4. Verify C# hardcoded JwtSecret with redacted snippet is properly remediated
        secret_finding = Finding(
            finding_id="SECRET-0001",
            rule_id="csharp.secret.hardcoded-credential",
            severity="CRITICAL",
            file_path="src/ERMS.Shared/Constants/SecurityConstants.cs",
            line_number=5,
            message="Hardcoded credential assigned to variable 'JwtSecret'.",
            code_snippet='string JwtSecret = "***REDACTED***";',
            repository="LargeRepo",
            cwe_id="CWE-798",
        )
        csharp_code = (
            "namespace ERMS.Shared.Constants\n"
            "{\n"
            "    public static class SecurityConstants\n"
            "    {\n"
            '        public const string JwtSecret = "mysupersecretjwtsigningkey1234567890";\n'
            "    }\n"
            "}\n"
        )
        proposal_secret = client_default.generate_fix(secret_finding, csharp_code, csharp_code)
        self.assertIsNotNone(proposal_secret)
        self.assertNotIn("mysupersecretjwtsigningkey1234567890", proposal_secret.fixed_file_content)
        self.assertIn("Environment.GetEnvironmentVariable", proposal_secret.fixed_file_content)
        self.assertIn("JwtSecret", proposal_secret.fixed_file_content)

        # 5. Verify C# hardcoded ApiKey property assignment (SEMGREP-001) is properly remediated
        apikey_finding = Finding(
            finding_id="SEMGREP-001",
            rule_id="airgap.generic.secrets.hardcoded-credentials",
            severity="HIGH",
            file_path="src/ERMS.Persistence/Seed/DatabaseSeeder.cs",
            line_number=8,
            message="Hardcoded secret detected in source code.",
            code_snippet='ApiKey = "xoxb-test-api-key-sample",',
            repository="LargeRepo",
            cwe_id="CWE-798",
        )
        seeder_code = (
            "        {\n"
            '            Name = "Enterprise Slack Webhook",\n'
            '            BaseUrl = "http://proxy.airgap.internal:8080/services/TEST",\n'
            '            ApiKey = "xoxb-test-api-key-sample",\n'
            "            IsActive = true\n"
            "        }\n"
        )
        proposal_apikey = client_default.generate_fix(apikey_finding, seeder_code, seeder_code)
        self.assertIsNotNone(proposal_apikey)
        self.assertNotIn("xoxb-test-api-key-sample", proposal_apikey.fixed_file_content)
        self.assertIn("Environment.GetEnvironmentVariable", proposal_apikey.fixed_file_content)
        self.assertIn("ApiKey", proposal_apikey.fixed_file_content)

    def test_local_ai_error_message_and_allowed_hosts_fallback(self):
        from agents.remediator_agent.llm_client import CloudLLMClient
        from agents.remediator_agent.models import Finding

        client = CloudLLMClient(provider="mock")

        # 1. Verify error message uses local AI phrasing (no cloud API keys)
        unknown_finding = Finding(
            finding_id="UNKNOWN-001",
            rule_id="custom.unsupported.rule",
            severity="HIGH",
            file_path="src/Unknown.cs",
            line_number=10,
            message="Unsupported rule",
            code_snippet="doSomethingUnsupported();",
            repository="TestRepo",
        )
        with self.assertRaises(RuntimeError) as ctx:
            client.generate_fix(unknown_finding, "doSomethingUnsupported();", "doSomethingUnsupported();")
        
        err_msg = str(ctx.exception)
        self.assertIn("No local AI model available (ensure Ollama is running)", err_msg)
        self.assertIn("custom.unsupported.rule", err_msg)
        self.assertNotIn("GEMINI_API_KEY", err_msg)
        self.assertNotIn("OPENAI_API_KEY", err_msg)
        self.assertNotIn("ANTHROPIC_API_KEY", err_msg)
        self.assertNotIn("Cloud API key", err_msg)

        # 2. Verify aspnet.config.allowed-hosts-wildcard is properly remediated
        hosts_finding = Finding(
            finding_id="CONFIG-001",
            rule_id="aspnet.config.allowed-hosts-wildcard",
            severity="LOW",
            file_path="appsettings.json",
            line_number=1,
            message="AllowedHosts is set to *.",
            code_snippet='"AllowedHosts": "*"',
            repository="CustomerApi",
        )
        appsettings_json = (
            "{\n"
            '  "Logging": {\n'
            '    "LogLevel": {\n'
            '      "Default": "Information"\n'
            "    }\n"
            "  },\n"
            '  "AllowedHosts": "*"\n'
            "}\n"
        )
        proposal = client.generate_fix(hosts_finding, appsettings_json, appsettings_json)
        self.assertIsNotNone(proposal)
        self.assertIn('"AllowedHosts": "localhost;*.airgap.internal"', proposal.fixed_file_content)
        self.assertNotIn('"AllowedHosts": "*"', proposal.fixed_file_content)

    def test_shared_llm_client_memoizes_offline_fallback_across_findings(self):
        import tempfile
        from unittest.mock import patch
        from agents.remediator_agent.agent import RemediatorAgent

        tmp_dir = Path(tempfile.mkdtemp(prefix="test_shared_llm_"))
        (tmp_dir / "file1.cs").write_text('var q = $"SELECT * FROM Users WHERE Id = \'{id}\'";\n', encoding="utf-8")
        (tmp_dir / "file2.cs").write_text('var q = $"SELECT * FROM Orders WHERE Id = \'{id}\'";\n', encoding="utf-8")

        remediator = RemediatorAgent(
            reports_dir=tmp_dir / "reports",
            llm_provider="ollama",
            model="gemma4:12b",
        )
        call_count = 0

        def failing_ollama_call(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise RuntimeError("Connection timed out")

        finding1 = {
            "finding_id": "SQLI-001",
            "rule_id": "csharp-sql-injection",
            "severity": "HIGH",
            "file_path": "file1.cs",
            "line_number": 1,
            "message": "SQLi",
            "code_snippet": 'var q = $"SELECT * FROM Users WHERE Id = \'{id}\'";',
            "repository": "TempRepo",
        }
        finding2 = {
            "finding_id": "SQLI-002",
            "rule_id": "csharp-sql-injection",
            "severity": "HIGH",
            "file_path": "file2.cs",
            "line_number": 1,
            "message": "SQLi",
            "code_snippet": 'var q = $"SELECT * FROM Orders WHERE Id = \'{id}\'";',
            "repository": "TempRepo",
        }

        with patch.object(remediator, "load_scanner_findings", return_value=[finding1, finding2]), \
             patch("agents.remediator_agent.llm_client.CloudLLMClient._call_ollama", side_effect=failing_ollama_call):
            res = remediator.remediate(workspace_path=tmp_dir)
            self.assertEqual(len(res["bug_fixes"]), 2)
            # Verified: _call_ollama is called once and falls back immediately for finding 2!
            self.assertEqual(call_count, 1)

    def test_compress_source_context_short_file(self):
        from agents.remediator_agent.llm_client import CloudLLMClient
        short_file = "\n".join([f"line_{i}" for i in range(1, 30)])
        compressed = CloudLLMClient._compress_source_context(short_file, target_line=15)
        self.assertEqual(compressed, short_file)

    def test_compress_source_context_large_file(self):
        from agents.remediator_agent.llm_client import CloudLLMClient
        large_file = "\n".join([f"line_{i} = {i};" for i in range(1, 200)])
        compressed = CloudLLMClient._compress_source_context(large_file, target_line=100)
        self.assertIn("line_1 = 1;", compressed)
        self.assertIn("Omitted", compressed)
        self.assertIn("line_100 = 100;", compressed)
        # Should not include lines way far away (e.g. line 45)
        self.assertNotIn("line_45 = 45;", compressed)

    def test_apply_snippet_replacement(self):
        from agents.remediator_agent.llm_client import _apply_snippet_replacement
        content = "public void DoSomething() {\n    var q = \"SELECT * FROM Users\";\n    return q;\n}"
        orig = 'var q = "SELECT * FROM Users";'
        repl = 'var q = "SELECT * FROM Users WHERE active = 1";'
        updated = _apply_snippet_replacement(content, orig, repl)
        self.assertIsNotNone(updated)
        self.assertIn('active = 1', updated)
        self.assertNotIn('"SELECT * FROM Users";\n', updated)


if __name__ == "__main__":
    unittest.main()
