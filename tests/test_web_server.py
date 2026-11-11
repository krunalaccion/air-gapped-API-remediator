"""
Unit tests for web server API endpoints and Air-Gapped API Remediator logic.
"""

import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from agents.scanner_agent.agent import ScannerAgent
from agents.remediator_agent.agent import RemediatorAgent
from web_server import MultiAgentAPIHandler


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

    def _call_post(self, path: str, payload: dict) -> tuple[int, dict]:
        handler = MultiAgentAPIHandler.__new__(MultiAgentAPIHandler)
        body = json.dumps(payload).encode("utf-8")
        handler.rfile = io.BytesIO(body)
        handler.wfile = io.BytesIO()
        handler.headers = {"Content-Length": str(len(body))}
        handler.path = path
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()

        handler.do_POST()
        status_code = handler.send_response.call_args[0][0] if handler.send_response.call_args else 200
        response_data = json.loads(handler.wfile.getvalue().decode("utf-8")) if handler.wfile.getvalue() else {}
        return status_code, response_data

    def test_validate_path_git_repo(self):
        # Create a git repo
        git_dir = self.temp_dir / "valid_git_repo"
        git_dir.mkdir()
        subprocess.run(["git", "init"], cwd=str(git_dir), check=True, capture_output=True)

        status, data = self._call_post("/api/validate-path", {"path": str(git_dir)})
        self.assertEqual(status, 200)
        self.assertTrue(data.get("valid"))
        self.assertTrue(data.get("has_git"))
        self.assertEqual(data.get("path"), str(git_dir.resolve()))

    def test_validate_path_non_git_repo_returns_error(self):
        # Directory without .git
        non_git = self.temp_dir / "non_git_folder"
        non_git.mkdir()

        status, data = self._call_post("/api/validate-path", {"path": str(non_git)})
        self.assertEqual(status, 400)
        self.assertFalse(data.get("valid"))
        self.assertFalse(data.get("has_git"))
        self.assertIn("is not a Git repository", data.get("error", ""))
        self.assertIn("missing '.git' directory", data.get("error", ""))

    def test_validate_path_non_existent(self):
        non_existent = self.temp_dir / "does_not_exist"
        status, data = self._call_post("/api/validate-path", {"path": str(non_existent)})
        self.assertEqual(status, 400)
        self.assertFalse(data.get("valid"))
        self.assertIn("does not exist", data.get("error", ""))

    def test_api_prepare_non_git_repo_returns_error(self):
        # Local path without .git must be rejected by /api/prepare
        non_git = self.temp_dir / "not_a_repo"
        non_git.mkdir()

        status, data = self._call_post("/api/prepare", {"repo_url": str(non_git)})
        self.assertEqual(status, 400)
        self.assertIn("error", data)
        self.assertIn("is not a Git repository", data["error"])
        self.assertIn("Missing '.git' directory", data["error"])

    def test_api_fs_list_directories(self):
        # Create a git subfolder and a non-git subfolder
        git_sub = self.temp_dir / "repo_a"
        git_sub.mkdir()
        subprocess.run(["git", "init"], cwd=str(git_sub), check=True, capture_output=True)

        regular_sub = self.temp_dir / "docs"
        regular_sub.mkdir()

        status, data = self._call_post("/api/fs/list", {"path": str(self.temp_dir)})
        self.assertEqual(status, 200)
        folders = {f["name"]: f for f in data.get("folders", [])}

        self.assertIn("repo_a", folders)
        self.assertTrue(folders["repo_a"]["has_git"])

        self.assertIn("docs", folders)
        self.assertFalse(folders["docs"]["has_git"])

        # Check quick access shortcuts
        quick_access = data.get("quick_access", [])
        self.assertTrue(len(quick_access) >= 2)
        labels = [q["label"] for q in quick_access]
        self.assertTrue(any("Home" in l for l in labels))

    def test_index_html_integrity_and_folder_modal(self):
        from web_server import get_web_dir
        html_path = get_web_dir() / "index.html"
        self.assertTrue(html_path.exists())
        content = html_path.read_text(encoding="utf-8")

        # Verify key elements for remote repository URL pipeline & security theme
        self.assertIn('id="repoUrl"', content)
        self.assertIn('id="threatLevelBadge"', content)
        self.assertIn('id="kpiVulnCard"', content)
        self.assertIn('setPortalTheme', content)
        self.assertIn('id="buildTestResultsContainer"', content)
        self.assertIn('handleRerunBuildTest', content)
        self.assertIn('renderBuildAndTestUI', content)
        self.assertIn('.hidden {', content)
        self.assertIn('display: none !important;', content)
        self.assertIn('div.textContent = `[${time}] [${agentName}] ${msg}`;', content)


    def _call_get(self, path: str) -> tuple[int, dict]:
        handler = MultiAgentAPIHandler.__new__(MultiAgentAPIHandler)
        handler.rfile = io.BytesIO(b"")
        handler.wfile = io.BytesIO()
        handler.headers = {}
        handler.path = path
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()

        handler.do_GET()
        status_code = handler.send_response.call_args[0][0] if handler.send_response.call_args else 200
        response_data = json.loads(handler.wfile.getvalue().decode("utf-8")) if handler.wfile.getvalue() else {}
        return status_code, response_data

    def test_api_local_pr_endpoint(self):
        import web_server
        # Prepare workspace on a local git repo
        local_repo = self.temp_dir / "my_local_test_repo"
        local_repo.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=str(local_repo), check=True, capture_output=True)
        (local_repo / "README.md").write_text("# Test Repo\n")
        subprocess.run(["git", "add", "."], cwd=str(local_repo), check=True, capture_output=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "init"], cwd=str(local_repo), check=True, capture_output=True)

        # Call /api/prepare
        status, prep_data = self._call_post("/api/prepare", {"repo_url": str(local_repo)})
        self.assertEqual(status, 200)

        # Call /api/create-pr
        status, pr_data = self._call_post("/api/create-pr", {
            "title": "Local Test PR",
            "description": "Testing local pull request retrieval",
        })
        self.assertEqual(status, 200)
        self.assertEqual(pr_data.get("provider"), "local")
        self.assertIn("PR-1.md", pr_data.get("pr_file_path", ""))
        self.assertIn("Local Test PR", pr_data.get("pr_content", ""))

        # Call GET /api/local-pr
        status, get_data = self._call_get("/api/local-pr")
        self.assertEqual(status, 200)
        self.assertIn("content", get_data)
        self.assertIn("Local Test PR", get_data["content"])
        self.assertEqual(get_data.get("filename"), "PR-1.md")

    def test_scanner_does_not_scan_customer_api_on_external_repo(self):
        ext_repo = self.temp_dir / "external_python_repo"
        ext_repo.mkdir()
        (ext_repo / "server.py").write_text("import requests\nresp = requests.get('https://api.external-cloud.com/v1')\n")
        subprocess.run(["git", "init"], cwd=str(ext_repo), check=True, capture_output=True)

        scanner = ScannerAgent()
        scan_res = scanner.run({"workspace_path": str(ext_repo)})

        self.assertFalse(scan_res["securescan"]["executed"])
        files_scanned = [f.get("file") or f.get("file_path") for f in scan_res["findings"]]
        self.assertNotIn("Controllers/UsersController.cs", files_scanned)
        finding_ids = [f.get("id") or f.get("finding_id") for f in scan_res["findings"]]
        self.assertNotIn("SQLI-001", finding_ids)

        # Remediate external repo and ensure UsersController.cs is NEVER injected
        remediator = RemediatorAgent()
        rem_res = remediator.remediate(workspace_path=ext_repo)
        self.assertFalse((ext_repo / "Controllers").exists())
        self.assertFalse((ext_repo / "Controllers" / "UsersController.cs").exists())
        self.assertFalse((ext_repo / "reports" / "SQLI-001_report.json").exists())

    def test_build_tester_engine_python_with_tests(self):
        from agents.git_agent.build_tester import run_build_and_tests
        py_repo = self.temp_dir / "py_math_project"
        py_repo.mkdir()
        (py_repo / "calculator.py").write_text("def mul(a, b):\n    return a * b\n")
        tests_dir = py_repo / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_calc.py").write_text(
            "import unittest\nfrom calculator import mul\n\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_mul(self):\n"
            "        self.assertEqual(mul(3, 4), 12)\n"
        )

        res = run_build_and_tests(py_repo)
        self.assertTrue(res["executed"])
        self.assertEqual(res["ecosystem"], "python")
        self.assertEqual(res["build"]["status"], "passed")
        self.assertEqual(res["tests"]["status"], "passed")
        self.assertTrue(res["tests"]["tests_found"])
        self.assertEqual(res["tests"]["passed"], 1)
        self.assertEqual(res["tests"]["failed"], 0)

    def test_api_prepare_runs_build_and_tests(self):
        # Prepare workspace on a python repo and ensure build_and_test is returned
        test_repo = self.temp_dir / "my_py_repo"
        test_repo.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=str(test_repo), check=True, capture_output=True)
        (test_repo / "app.py").write_text("x = 42\n")
        subprocess.run(["git", "add", "."], cwd=str(test_repo), check=True, capture_output=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "init"], cwd=str(test_repo), check=True, capture_output=True)

        status, prep_data = self._call_post("/api/prepare", {"repo_url": str(test_repo)})
        self.assertEqual(status, 200)
        self.assertEqual(prep_data["context"]["repo_name"], "my_py_repo")
        self.assertIn("build_and_test", prep_data)
        bt = prep_data["build_and_test"]
        self.assertTrue(bt["executed"])
        self.assertEqual(bt["ecosystem"], "python")
        self.assertEqual(bt["build"]["status"], "passed")

        # Telemetry should also report repo_name
        t_status, telem_data = self._call_get("/api/telemetry")
        self.assertEqual(t_status, 200)
        self.assertEqual(telem_data["git"]["repo_name"], "my_py_repo")

        # Test manual POST /api/build-test endpoint
        b_status, b_data = self._call_post("/api/build-test", {})
        self.assertEqual(b_status, 200)
        self.assertTrue(b_data["executed"])
        self.assertEqual(b_data["ecosystem"], "python")

    def test_api_prepare_skip_build_test_and_subsequent_execution(self):
        # Prepare repo with skip_build_test flag for staged UI loading
        test_repo = self.temp_dir / "staged_py_repo"
        test_repo.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=str(test_repo), check=True, capture_output=True)
        (test_repo / "main.py").write_text("print('hello world')\n")
        subprocess.run(["git", "add", "."], cwd=str(test_repo), check=True, capture_output=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "init"], cwd=str(test_repo), check=True, capture_output=True)

        status, prep_data = self._call_post("/api/prepare", {
            "repo_url": str(test_repo),
            "skip_build_test": True,
        })
        self.assertEqual(status, 200)
        bt = prep_data.get("build_and_test", {})
        self.assertEqual(bt.get("status"), "pending")
        self.assertFalse(bt.get("executed"))

        # Subsequent call to /api/build-test executes the verification
        b_status, b_data = self._call_post("/api/build-test", {})
        self.assertEqual(b_status, 200)
        self.assertTrue(b_data.get("executed"))
        self.assertEqual(b_data.get("ecosystem"), "python")
        self.assertEqual(b_data.get("build", {}).get("status"), "passed")

    def test_step3_repeated_runs_accumulate_threats_and_generate_dossier_commit_and_pr(self):
        import web_server
        # Prepare a local repository with external egress
        repo_dir = self.temp_dir / "threat_accum_repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=str(repo_dir), check=True, capture_output=True)
        (repo_dir / "app.py").write_text('import requests\nrequests.get("https://api.external-cloud.com/v1/telemetry")\n')
        subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "init"], cwd=str(repo_dir), check=True, capture_output=True)

        # Step 1: Prepare
        p_status, p_data = self._call_post("/api/prepare", {"repo_url": str(repo_dir)})
        self.assertEqual(p_status, 200)

        # Step 2: Scan
        s_status, s_data = self._call_post("/api/scan", {"workspace_path": str(repo_dir)})
        self.assertEqual(s_status, 200)
        initial_findings = s_data.get("findings", [])
        self.assertTrue(len(initial_findings) >= 1)

        # Step 3: Run Fix (Run 1)
        f_status1, f_data1 = self._call_post("/api/fix", {"workspace_path": str(repo_dir)})
        self.assertEqual(f_status1, 200)
        threats_run1 = f_data1.get("all_threats", [])
        self.assertTrue(len(threats_run1) >= 1)
        self.assertIn("fix(airgap)", f_data1.get("commit_message", ""))
        self.assertIn("Remediated Security Threats", f_data1.get("commit_message", ""))

        # Step 3: Run Fix again (Run 2) - must retain all threats and not wipe them
        f_status2, f_data2 = self._call_post("/api/fix", {"workspace_path": str(repo_dir)})
        self.assertEqual(f_status2, 200)
        threats_run2 = f_data2.get("all_threats", [])
        self.assertTrue(len(threats_run2) >= len(threats_run1), "Threats must not decrease or wipe on repeated step 3 runs")
        self.assertIn("fix(airgap)", f_data2.get("commit_message", ""))
        self.assertIn("Remediated Security Threats", f_data2.get("commit_message", ""))
        self.assertIn("Security Posture", f_data2.get("pr_body", ""))
        self.assertIn("SecOps Compliance", f_data2.get("pr_body", ""))

        # Step 4: Commit & Push with default / empty commit message
        c_status, c_data = self._call_post("/api/commit-push", {})
        self.assertEqual(c_status, 200)

        # Verify the actual git commit in the repository contains the full breakdown
        active_agent = web_server.ACTIVE_GIT_AGENT
        self.assertIsNotNone(active_agent)
        log_res = subprocess.run(
            ["git", "log", "-1", "--pretty=%B"],
            cwd=str(active_agent.get_workspace_path()),
            capture_output=True,
            text=True,
            check=True,
        )
        commit_body = log_res.stdout
        self.assertIn("fix(airgap)", commit_body)
        self.assertIn("Remediated Security Threats & Remediation Actions:", commit_body)
        self.assertIn("Modified Files & Compliance Manifests:", commit_body)

        # Step 4: Create PR with default / empty description
        pr_status, pr_data = self._call_post("/api/create-pr", {})
        self.assertEqual(pr_status, 200)
        pr_content = pr_data.get("pr_content", "")
        self.assertIn("[SecOps Compliance]", pr_data.get("title", ""))
        self.assertIn("Remediated Vulnerabilities & Security Findings Evidence", pr_content)
        self.assertIn("Modified Source Code & Artifacts", pr_content)
        self.assertIn("Air-Gap & Perimeter Security Compliance Checklist", pr_content)

    def test_index_html_contains_build_test_loader_elements(self):
        from web_server import get_web_dir
        html_path = get_web_dir() / "index.html"
        content = html_path.read_text(encoding="utf-8")
        self.assertIn('id="buildTestLoader"', content)
        self.assertIn('showBuildTestLoader', content)
        self.assertIn('hideBuildTestLoader', content)
        self.assertIn('accumulatedThreatFindings', content)
        self.assertIn('accumulatedRemediations', content)
        self.assertIn('generateCommitMessageSummary', content)

    def test_step3_realtime_progress_endpoint(self):
        # 1. Test initial GET /api/fix/progress
        status, prog = self._call_get("/api/fix/progress")
        self.assertEqual(status, 200)
        self.assertIn("status", prog)
        self.assertIn("percent", prog)
        self.assertIn("items", prog)
        self.assertIn("completed_targets", prog)
        self.assertIn("total_targets", prog)

        # 2. Test progress tracking after remediation
        test_repo = self.temp_dir / "progress_test_repo"
        test_repo.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=str(test_repo), check=True, capture_output=True)
        (test_repo / "server.py").write_text('import requests\nrequests.get("https://api.external-cloud.com/v1/metrics")\n')
        subprocess.run(["git", "add", "."], cwd=str(test_repo), check=True, capture_output=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "init"], cwd=str(test_repo), check=True, capture_output=True)

        self._call_post("/api/prepare", {"repo_url": str(test_repo)})
        self._call_post("/api/scan", {"workspace_path": str(test_repo)})
        f_status, f_res = self._call_post("/api/fix", {"workspace_path": str(test_repo)})
        self.assertEqual(f_status, 200)

        p_status, post_prog = self._call_get("/api/fix/progress")
        self.assertEqual(p_status, 200)
        self.assertEqual(post_prog["status"], "COMPLETED")
        self.assertEqual(post_prog["percent"], 100)
        self.assertTrue(len(post_prog["items"]) >= 3)
        item_ids = [itm["id"] for itm in post_prog["items"]]
        self.assertIn("AIRGAP-PROXY-001", item_ids)
        self.assertIn("AIRGAP-AUDIT-001", item_ids)
        self.assertIn("POST-SCAN-VERIFY", item_ids)

        # Check telemetry also includes progress
        t_status, telem = self._call_get("/api/telemetry")
        self.assertEqual(t_status, 200)
        self.assertIn("progress", telem.get("remediator", {}))

    def test_index_html_step3_realtime_progress_and_button_lock_elements(self):
        from web_server import get_web_dir
        html_path = get_web_dir() / "index.html"
        content = html_path.read_text(encoding="utf-8")
        self.assertIn('id="step3LiveFixProgress"', content)
        self.assertIn('id="fixProgressIterationBadge"', content)
        self.assertIn('showStep3FixProgress', content)
        self.assertIn('updateStep3FixProgress', content)
        self.assertIn('hideStep3FixProgress', content)
        self.assertIn('setGlobalActionLock', content)
        self.assertIn('function apiGet', content)
        self.assertIn('function apiPost', content)
        self.assertIn('btnFix', content)
        self.assertIn('btnScan', content)
        self.assertIn('btnPrepare', content)

    def test_csharp_deserialization_cwe502_comment_handling(self):
        from agents.scanner_agent.inspectors import CSharpLexicalAnalyzer
        from agents.remediator_agent.llm_client import CloudLLMClient
        from agents.remediator_agent.models import Finding

        analyzer = CSharpLexicalAnalyzer()

        # 1. Vulnerable code with comment should be detected
        vuln_code = (
            "namespace TestNamespace {\n"
            "    public class TestSerializer {\n"
            "        private static readonly JsonSerializerSettings UnsafeSettings = new() {\n"
            "            TypeNameHandling = TypeNameHandling.Auto, // or TypeNameHandling.Auto if type safety is not a concern\n"
            "            Formatting = Formatting.Indented\n"
            "        };\n"
            "    }\n"
            "}\n"
        )
        vuln_file = self.temp_dir / "VulnSerializer.cs"
        vuln_file.write_text(vuln_code, encoding="utf-8")
        findings = analyzer.analyze_file(vuln_file)
        deserial_findings = [f for f in findings if f.cwe_id == "CWE-502" or "deserial" in f.rule_id]
        self.assertEqual(len(deserial_findings), 1)
        self.assertEqual(deserial_findings[0].line_start, 4)

        # 2. Compliant code with comment should NOT be flagged as vulnerable
        safe_code = (
            "namespace TestNamespace {\n"
            "    public class TestSerializer {\n"
            "        private static readonly JsonSerializerSettings SafeSettings = new() {\n"
            "            TypeNameHandling = TypeNameHandling.None, // or TypeNameHandling.Auto if type safety is not a concern\n"
            "            Formatting = Formatting.Indented\n"
            "        };\n"
            "    }\n"
            "}\n"
        )
        safe_file = self.temp_dir / "SafeSerializer.cs"
        safe_file.write_text(safe_code, encoding="utf-8")
        safe_findings = analyzer.analyze_file(safe_file)
        safe_deserial = [f for f in safe_findings if f.cwe_id == "CWE-502" or "deserial" in f.rule_id]
        self.assertEqual(len(safe_deserial), 0)

        # 3. Deterministic Remediator fix replaces TypeNameHandling and sanitizes comment
        finding = Finding(
            finding_id="DESERIAL-0001",
            rule_id="csharp.deserialization.unsafe-api",
            severity="HIGH",
            file_path="src/EmployeePortal.Integrations/Serialization/LegacyJsonSerializer.cs",
            line_number=4,
            message="Unsafe deserialization API or TypeNameHandling configuration detected.",
            code_snippet="TypeNameHandling = TypeNameHandling.Auto, // or TypeNameHandling.Auto if type safety is not a concern",
            repository="test_repo",
            cwe_id="CWE-502",
        )
        client = CloudLLMClient(provider="mock")
        proposal = client.generate_fix(finding, vuln_code, vuln_code)
        self.assertIn("TypeNameHandling = TypeNameHandling.None", proposal.fixed_file_content)
        self.assertNotIn("TypeNameHandling.Auto", proposal.fixed_file_content)

        # 4. Running inspector on the fixed code yields 0 findings
        fixed_file = self.temp_dir / "FixedSerializer.cs"
        fixed_file.write_text(proposal.fixed_file_content, encoding="utf-8")
        fixed_findings = analyzer.analyze_file(fixed_file)
        fixed_deserial = [f for f in fixed_findings if f.cwe_id == "CWE-502" or "deserial" in f.rule_id]
        self.assertEqual(len(fixed_deserial), 0)

    def test_iterative_remediation_pipeline_execution(self):
        from orchestrator.pipeline import MultiAgentPipeline
        from agents.git_agent.config import GitAgentConfig, ProviderType

        local_repo = self.temp_dir / "pipeline_iter_repo"
        local_repo.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=str(local_repo), check=True, capture_output=True)
        (local_repo / "server.py").write_text('import requests\nrequests.get("https://api.external-cloud.com/v1/metrics")\n')
        subprocess.run(["git", "add", "."], cwd=str(local_repo), check=True, capture_output=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "init"], cwd=str(local_repo), check=True, capture_output=True)

        config = GitAgentConfig(
            repo_url=str(local_repo),
            provider=ProviderType.LOCAL,
            feature_branch_name="remediation/iterative-test",
        )
        pipeline = MultiAgentPipeline(git_config=config)
        res = pipeline.run_remediation_pipeline()

        self.assertEqual(res["status"], "success")
        self.assertIn("iterations_run", res)
        self.assertIn("max_iterations", res)
        self.assertEqual(res["max_iterations"], 5)
        self.assertTrue(1 <= res["iterations_run"] <= 5)
        self.assertTrue(res["resolved_all"])
        self.assertEqual(res["git_result"]["status"], "success")

    def test_hsts_cwe319_remediation_and_inspection(self):
        from agents.scanner_agent.inspectors import AspNetContextInspector, ProjectProfile
        from agents.remediator_agent.llm_client import CloudLLMClient
        from agents.remediator_agent.models import Finding
        from agents.remediator_agent.fixer_agent import BugFixerAgent

        program_code = (
            "var builder = WebApplication.CreateBuilder(args);\n"
            "var app = builder.Build();\n\n"
            "if (!app.Environment.IsDevelopment())\n"
            "{\n"
            "    app.UseExceptionHandler(\"/Error\", createScopeForErrors: true);\n"
            "}\n\n"
            "app.UseStaticFiles();\n"
            "app.UseAntiforgery();\n\n"
            "app.MapRazorComponents<App>()\n"
            "    .AddInteractiveServerRenderMode();\n\n"
            "app.Run();\n"
        )
        test_dir = self.temp_dir / "HstsProject"
        test_dir.mkdir(parents=True, exist_ok=True)
        prog_file = test_dir / "Program.cs"
        prog_file.write_text(program_code, encoding="utf-8")

        # 1. Inspect initial Program.cs -> should find HSTS-0001
        profile = ProjectProfile(project_root=test_dir, source_files=[prog_file])
        inspector = AspNetContextInspector()
        findings = inspector.inspect_project(profile)
        hsts_findings = [f for f in findings if f.cwe_id == "CWE-319" or "hsts" in f.rule_id]
        self.assertEqual(len(hsts_findings), 1)
        self.assertEqual(hsts_findings[0].code_snippet, "app.UseHsts() not found in Program.cs")

        # 2. Fix finding via BugFixerAgent
        finding = Finding(
            finding_id="HSTS-0001",
            rule_id="aspnet.headers.hsts-missing-heuristic",
            severity="MEDIUM",
            file_path="Program.cs",
            line_number=1,
            message="app.UseHsts() is omitted in middleware pipeline.",
            code_snippet="app.UseHsts() not found in Program.cs",
            repository="HstsProject",
            cwe_id="CWE-319",
        )
        fixer = BugFixerAgent(repos_root=test_dir, reports_dir=test_dir / "reports")
        report = fixer.process_finding(finding)
        self.assertTrue(report.applied)

        # 3. Verify file content now contains app.UseHsts()
        remediated_content = prog_file.read_text(encoding="utf-8")
        self.assertIn("app.UseHsts()", remediated_content)
        self.assertIn("app.UseHttpsRedirection()", remediated_content)
        self.assertIn("app.Run()", remediated_content)

        # 4. Re-inspect -> 0 findings
        post_findings = inspector.inspect_project(profile)
        post_hsts = [f for f in post_findings if f.cwe_id == "CWE-319" or "hsts" in f.rule_id]
        self.assertEqual(len(post_hsts), 0)

    def test_launchsettings_json_cwe918_schemastore_and_external_proxy(self):
        from agents.remediator_agent.llm_client import CloudLLMClient
        from agents.remediator_agent.models import Finding
        from agents.remediator_agent.fixer_agent import BugFixerAgent
        from agents.scanner_agent.agent import ScannerAgent

        test_dir = self.temp_dir / "LaunchSettingsTest"
        props_dir = test_dir / "Properties"
        props_dir.mkdir(parents=True, exist_ok=True)

        # Case A: External schemastore.org URL
        launch_api = (
            "{\n"
            '  "$schema": "https://json.schemastore.org/launchsettings.json",\n'
            '  "profiles": {\n'
            '    "http": {\n'
            '      "commandName": "Project",\n'
            '      "applicationUrl": "http://localhost:5180"\n'
            "    }\n"
            "  }\n"
            "}\n"
        )
        api_file = props_dir / "launchSettings.json"
        api_file.write_text(launch_api, encoding="utf-8")

        finding_api = Finding(
            finding_id="SEMGREP-001",
            rule_id="airgap.network.unwhitelisted-external-egress",
            severity="HIGH",
            file_path="Properties/launchSettings.json",
            line_number=2,
            message="Direct outbound internet connection detected in isolated perimeter. (CWE-918)",
            code_snippet='"$schema": "https://json.schemastore.org/launchsettings.json"',
            repository="LaunchSettingsTest",
            cwe_id="CWE-918",
        )
        fixer = BugFixerAgent(repos_root=test_dir, reports_dir=test_dir / "reports")
        rep_api = fixer.process_finding(finding_api)
        self.assertTrue(rep_api.applied)

        fixed_api_content = api_file.read_text(encoding="utf-8")
        self.assertIn("http://proxy.airgap.internal:8080/launchsettings.json", fixed_api_content)
        self.assertNotIn("https://json.schemastore.org", fixed_api_content)
        self.assertNotIn("```", fixed_api_content)

        # Case B: External proxy with corrupted markdown fences
        launch_web = (
            "```\n"
            "{\n"
            '  "$schema": "https://internal-proxy.example.com/launchsettings.json",\n'
            '  "profiles": {\n'
            '    "http": {\n'
            '      "commandName": "Project",\n'
            '      "applicationUrl": "http://localhost:5181"\n'
            "    }\n"
            "  }\n"
            "}\n"
            "```\n"
        )
        web_file = props_dir / "launchSettings.Web.json"
        web_file.write_text(launch_web, encoding="utf-8")

        finding_web = Finding(
            finding_id="SEMGREP-002",
            rule_id="airgap.network.unwhitelisted-external-egress",
            severity="HIGH",
            file_path="Properties/launchSettings.Web.json",
            line_number=3,
            message="Direct outbound internet connection detected in isolated perimeter. (CWE-918)",
            code_snippet='"$schema": "https://internal-proxy.example.com/launchsettings.json"',
            repository="LaunchSettingsTest",
            cwe_id="CWE-918",
        )
        rep_web = fixer.process_finding(finding_web)
        self.assertTrue(rep_web.applied)

        fixed_web_content = web_file.read_text(encoding="utf-8")
        self.assertIn("http://proxy.airgap.internal:8080/launchsettings.json", fixed_web_content)
        self.assertNotIn("internal-proxy.example.com", fixed_web_content)
        self.assertNotIn("```", fixed_web_content)
        # Verify valid JSON
        data = json.loads(fixed_web_content)
        self.assertEqual(data["$schema"], "http://proxy.airgap.internal:8080/launchsettings.json")

    def test_employee_portal_exact_reported_findings_remediation(self):
        from agents.remediator_agent.agent import RemediatorAgent
        from agents.scanner_agent.agent import ScannerAgent

        ep_dir = self.temp_dir / "EmployeePortalTestRepo"
        ep_dir.mkdir(parents=True, exist_ok=True)

        web_dir = ep_dir / "src" / "EmployeePortal.Web"
        api_dir = ep_dir / "src" / "EmployeePortal.API"
        web_props = web_dir / "Properties"
        api_props = api_dir / "Properties"
        web_props.mkdir(parents=True, exist_ok=True)
        api_props.mkdir(parents=True, exist_ok=True)

        # Create dummy .csproj files so ProjectInspector recognizes the C# projects
        csproj_xml = '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>'
        (web_dir / "EmployeePortal.Web.csproj").write_text(csproj_xml, encoding="utf-8")
        (api_dir / "EmployeePortal.API.csproj").write_text(csproj_xml, encoding="utf-8")

        # 1. Program.cs without app.UseHsts()
        program_cs = (
            "using EmployeePortal.Web.Components;\n"
            "using EmployeePortal.Web.Services;\n\n"
            "var builder = WebApplication.CreateBuilder(args);\n\n"
            "builder.Services.AddRazorComponents()\n"
            "    .AddInteractiveServerComponents();\n\n"
            "builder.Services.AddScoped<PortalUserSessionService>();\n\n"
            'var apiBaseUrl = builder.Configuration["PortalApi:BaseUrl"] ?? "http://localhost:5180";\n'
            "var app = builder.Build();\n\n"
            "if (!app.Environment.IsDevelopment())\n"
            "{\n"
            '    app.UseExceptionHandler("/Error", createScopeForErrors: true);\n'
            "}\n\n"
            "app.UseStaticFiles();\n"
            "app.UseAntiforgery();\n\n"
            "app.MapRazorComponents<App>()\n"
            "    .AddInteractiveServerRenderMode();\n\n"
            "app.Run();\n"
        )
        (web_dir / "Program.cs").write_text(program_cs, encoding="utf-8")

        # 2. API launchSettings.json with schemastore.org
        api_launch = (
            "{\n"
            '  "$schema": "https://json.schemastore.org/launchsettings.json",\n'
            '  "profiles": {\n'
            '    "http": {\n'
            '      "commandName": "Project",\n'
            '      "applicationUrl": "http://localhost:5180"\n'
            "    }\n"
            "  }\n"
            "}\n"
        )
        (api_props / "launchSettings.json").write_text(api_launch, encoding="utf-8")

        # 3. Web launchSettings.json with internal-proxy.example.com
        web_launch = (
            "{\n"
            '  "$schema": "https://internal-proxy.example.com/launchsettings.json",\n'
            '  "profiles": {\n'
            '    "http": {\n'
            '      "commandName": "Project",\n'
            '      "applicationUrl": "http://localhost:5181"\n'
            "    }\n"
            "  }\n"
            "}\n"
        )
        (web_props / "launchSettings.json").write_text(web_launch, encoding="utf-8")

        # 4. Web appsettings.json with wildcard AllowedHosts
        web_appsettings = (
            "{\n"
            '  "Logging": { "LogLevel": { "Default": "Information" } },\n'
            '  "AllowedHosts": "*",\n'
            '  "PortalApi": { "BaseUrl": "http://localhost:5180" }\n'
            "}\n"
        )
        (web_dir / "appsettings.json").write_text(web_appsettings, encoding="utf-8")

        # 5. API appsettings.json with wildcard AllowedHosts and plaintext database password
        api_appsettings = (
            "{\n"
            '  "Logging": { "LogLevel": { "Default": "Information" } },\n'
            '  "AllowedHosts": "*",\n'
            '  "ConnectionStrings": {\n'
            '    "DefaultConnection": "Server=sql-sandbox.dummy-hr-portal.local,1433;Database=EmployeeDb;User Id=sa;Password=DummyP@ssw0rd123!;TrustServerCertificate=True;"\n'
            '  }\n'
            "}\n"
        )
        (api_dir / "appsettings.json").write_text(api_appsettings, encoding="utf-8")

        # Initial Scan
        scanner = ScannerAgent(findings_dir=ep_dir / "findings")
        scan_res = scanner.run({"workspace_path": str(ep_dir)})
        findings = scan_res.get("findings", [])
        self.assertTrue(len(findings) >= 2)

        # Run RemediatorAgent
        remediator = RemediatorAgent(
            repos_root=ep_dir,
            reports_dir=ep_dir / "reports",
            scanner_findings_dir=ep_dir / "findings",
        )
        fix_res = remediator.remediate(workspace_path=ep_dir, provider="mock")
        self.assertTrue(len(fix_res["bug_fixes"]) > 0)
        self.assertTrue(len(fix_res["files_modified"]) > 0)

        # Post-scan verification
        post_res = scanner.run({"workspace_path": str(ep_dir), "is_post_scan": True})
        residual_findings = post_res.get("findings", [])

        # Verify all target files were remediated
        web_prog_fixed = (web_dir / "Program.cs").read_text(encoding="utf-8")
        self.assertIn("app.UseHsts()", web_prog_fixed)
        self.assertIn("app.UseHttpsRedirection()", web_prog_fixed)

        api_launch_fixed = (api_props / "launchSettings.json").read_text(encoding="utf-8")
        self.assertIn("http://proxy.airgap.internal:8080/launchsettings.json", api_launch_fixed)
        self.assertNotIn("json.schemastore.org", api_launch_fixed)

        web_launch_fixed = (web_props / "launchSettings.json").read_text(encoding="utf-8")
        self.assertIn("http://proxy.airgap.internal:8080/launchsettings.json", web_launch_fixed)
        self.assertNotIn("internal-proxy.example.com", web_launch_fixed)

        web_cfg_fixed = (web_dir / "appsettings.json").read_text(encoding="utf-8")
        self.assertIn('"AllowedHosts": "localhost;*.airgap.internal"', web_cfg_fixed)
        self.assertNotIn('"AllowedHosts": "*"', web_cfg_fixed)

        api_cfg_fixed = (api_dir / "appsettings.json").read_text(encoding="utf-8")
        self.assertIn('"AllowedHosts": "localhost;*.airgap.internal"', api_cfg_fixed)
        self.assertNotIn('"AllowedHosts": "*"', api_cfg_fixed)
        self.assertIn("Integrated Security=True;", api_cfg_fixed)
        self.assertNotIn("DummyP@ssw0rd123!", api_cfg_fixed)

        # Residual egress / HSTS / config findings must be 0
        target_residual = [
            rf for rf in residual_findings
            if "hsts" in rf.get("rule_id", "").lower()
            or "launchsettings" in rf.get("file", "").lower()
            or "allowed-hosts" in rf.get("rule_id", "").lower()
            or "connectionstring" in rf.get("rule_id", "").lower()
        ]
        self.assertEqual(len(target_residual), 0)

    def test_validate_path_allow_non_git(self):
        non_git = self.temp_dir / "plain_project_1"
        non_git.mkdir()
        status, data = self._call_post("/api/validate-path", {"path": str(non_git), "allow_non_git": True})
        self.assertEqual(status, 200)
        self.assertTrue(data.get("valid"))
        self.assertFalse(data.get("has_git"))
        self.assertTrue(data.get("can_auto_init"))

    def test_validate_path_auto_init(self):
        non_git = self.temp_dir / "plain_project_2"
        non_git.mkdir()
        status, data = self._call_post("/api/validate-path", {"path": str(non_git), "auto_init": True})
        self.assertEqual(status, 200)
        self.assertTrue(data.get("valid"))
        self.assertTrue(data.get("has_git"))
        self.assertTrue((non_git / ".git").exists())

    def test_prepare_and_fix_unlinked_local_project(self):
        # Create a plain local project without git or remote
        proj_dir = self.temp_dir / "unlinked_local_app"
        proj_dir.mkdir()
        (proj_dir / "telemetry.py").write_text(
            'import requests\n\ndef send():\n    return requests.post("https://api.mixpanel.com/track", data={})\n',
            encoding="utf-8",
        )

        # 1. Prepare with auto_init: True
        status, prep_data = self._call_post("/api/prepare", {
            "repo_url": str(proj_dir),
            "feature_branch": "remediation/local-fix-test",
            "auto_init": True,
            "skip_build_test": True,
        })
        self.assertEqual(status, 200)
        self.assertEqual(prep_data["context"]["provider"], "local")
        self.assertTrue((proj_dir / ".git").exists())

        # 2. Scan workspace
        status, scan_data = self._call_post("/api/scan", {
            "workspace_path": str(proj_dir),
            "scanner_engine": "all",
        })
        self.assertEqual(status, 200)
        self.assertGreater(scan_data.get("total_findings", 0), 0)

        # 3. Fix issues
        status, fix_data = self._call_post("/api/fix", {
            "workspace_path": str(proj_dir),
        })
        self.assertEqual(status, 200)
        self.assertGreater(len(fix_data.get("files_modified", [])), 0)

        # 4. Commit and push (remains safely local for unlinked repo)
        status, commit_data = self._call_post("/api/commit-push", {
            "commit_message": "fix(airgap): remediate mixpanel telemetry in unlinked project",
        })
        self.assertEqual(status, 200)
        self.assertIn("commit_hash", commit_data)

        # 5. Create local PR manifest
        status, pr_data = self._call_post("/api/create-pr", {
            "title": "Remediate Mixpanel Telemetry",
            "description": "Auto-remediation for unlinked project",
        })
        self.assertEqual(status, 200)
        self.assertEqual(pr_data.get("provider"), "local")
        self.assertTrue(Path(pr_data["pr_file_path"]).exists())
        self.assertIn("Remediate Mixpanel Telemetry", pr_data.get("title", ""))

    def test_reset_all_removes_folder_name_and_references(self):
        # 1. Prepare a local project workspace
        proj_dir = self.temp_dir / "my_secret_project"
        proj_dir.mkdir()
        (proj_dir / "app.py").write_text("print('hello')\n")
        status, prep_data = self._call_post("/api/prepare", {
            "repo_url": str(proj_dir),
            "feature_branch": "remediation/test-branch",
            "auto_init": True,
            "skip_build_test": True,
        })
        self.assertEqual(status, 200)

        # 2. Call reset-all
        status, reset_data = self._call_post("/api/reset-all", {})
        self.assertEqual(status, 200)
        self.assertEqual(reset_data.get("status"), "success")
        self.assertEqual(reset_data.get("workspace_path"), "")
        self.assertEqual(reset_data.get("repo_name"), "")
        self.assertEqual(reset_data.get("status_summary", {}).get("branch"), "none")

        # 3. Verify telemetry contains zero references to the folder or git workspace
        telem = reset_data.get("telemetry", {})
        self.assertFalse(telem.get("git", {}).get("prepared"))
        self.assertEqual(telem.get("git", {}).get("repo_name"), "")
        self.assertIsNone(telem.get("git", {}).get("context"))
        self.assertEqual(telem.get("active_workspace_path"), "")
        self.assertEqual(telem.get("workspace_files"), [])

    def test_bug_fixer_reset_removes_folder_name_and_references(self):
        # 1. Prepare a local project workspace
        proj_dir = self.temp_dir / "another_local_app"
        proj_dir.mkdir()
        (proj_dir / "index.js").write_text("console.log('hi');\n")
        status, prep_data = self._call_post("/api/prepare", {
            "repo_url": str(proj_dir),
            "feature_branch": "remediation/branch-2",
            "auto_init": True,
            "skip_build_test": True,
        })
        self.assertEqual(status, 200)

        # 2. Call bug-fixer/reset
        status, reset_data = self._call_post("/api/bug-fixer/reset", {})
        self.assertEqual(status, 200)
        self.assertEqual(reset_data.get("status"), "success")
        self.assertEqual(reset_data.get("workspace_path"), "")
        self.assertEqual(reset_data.get("repo_name"), "")
        self.assertEqual(reset_data.get("status_summary", {}).get("branch"), "none")

        # 3. Verify telemetry contains zero references to the folder or git workspace
        telem = reset_data.get("telemetry", {})
        self.assertFalse(telem.get("git", {}).get("prepared"))
        self.assertEqual(telem.get("git", {}).get("repo_name"), "")
        self.assertIsNone(telem.get("git", {}).get("context"))
        self.assertEqual(telem.get("active_workspace_path"), "")
        self.assertEqual(telem.get("workspace_files"), [])

    def test_local_folder_with_remote_origin_commit_and_push_api(self):
        # Create a bare remote and a local clone on disk
        bare_remote = self.temp_dir / "origin_remote.git"
        local_clone = self.temp_dir / "local_selected_folder"
        subprocess.run(["git", "init", "--bare", str(bare_remote)], check=True, capture_output=True)
        seed = self.temp_dir / "seed_repo"
        subprocess.run(["git", "clone", str(bare_remote), str(seed)], check=True, capture_output=True)
        (seed / "app.py").write_text("import requests\nrequests.get('https://api.external-cloud.com/v1')\n")
        subprocess.run(["git", "add", "."], cwd=str(seed), check=True, capture_output=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "init"], cwd=str(seed), check=True, capture_output=True)
        subprocess.run(["git", "branch", "-M", "main"], cwd=str(seed), check=True, capture_output=True)
        subprocess.run(["git", "push", "-u", "origin", "main"], cwd=str(seed), check=True, capture_output=True)
        subprocess.run(["git", "symbolic-ref", "HEAD", "refs/heads/main"], cwd=str(bare_remote), check=True, capture_output=True)
        subprocess.run(["git", "clone", str(bare_remote), str(local_clone)], check=True, capture_output=True)

        # Prepare using local folder path + optional auth token
        p_st, p_data = self._call_post("/api/prepare", {
            "repo_url": str(local_clone),
            "token": "ghp_localDemoToken1234",
            "feature_branch": "remediation/push-from-local",
        })
        self.assertEqual(p_st, 200)
        self.assertTrue(p_data.get("has_remote"))

        # Make a remediation edit and commit+push via /api/commit-push
        (local_clone / "app.py").write_text("import requests\nrequests.get('http://proxy.airgap.internal:8080/v1')\n")
        c_st, c_data = self._call_post("/api/commit-push", {
            "commit_message": "fix(airgap): remediate egress from local folder",
        })
        self.assertEqual(c_st, 200)
        self.assertTrue(c_data.get("pushed"))
        self.assertEqual(c_data.get("push_status"), "pushed")

        # Verify branch exists in bare remote
        remote_branches = subprocess.run(
            ["git", "branch", "--list", "remediation/push-from-local"],
            cwd=str(bare_remote),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertIn("remediation/push-from-local", remote_branches)


class NodeJsScannerAndRemediatorTest(unittest.TestCase):
    """Regression suite for multi-language Node.js/Express SAST scanning and offline deterministic remediation."""

    @staticmethod
    def _create_vulnerable_node_project(proj_dir: Path) -> None:
        (proj_dir / "src" / "controllers").mkdir(parents=True)
        (proj_dir / "src" / "middleware").mkdir(parents=True)
        (proj_dir / "src" / "utils").mkdir(parents=True)

        (proj_dir / "package.json").write_text(json.dumps({
            "name": "vulnerable-express-api",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.19.2",
                "jsonwebtoken": "^9.0.2",
                "sqlite3": "^5.1.7",
                "cors": "^2.8.5"
            }
        }, indent=2))
        (proj_dir / "package-lock.json").write_text(json.dumps({
            "name": "vulnerable-express-api",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/express": {
                    "version": "4.19.2",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.19.2.tgz"
                },
                "node_modules/tarball": {
                    "version": "1.0.0",
                    "resolved": "https://external.cdn.example/tarball-1.0.0.tgz"
                }
            }
        }, indent=2))

        (proj_dir / "src" / "app.js").write_text(
            "const express = require('express');\n"
            "const cors = require('cors');\n"
            "const app = express();\n"
            "app.use(cors({\n"
            "  origin: '*',\n"
            "  credentials: true\n"
            "}));\n"
            "module.exports = app;\n"
        )

        (proj_dir / "src" / "middleware" / "auth.js").write_text(
            "const jwt = require('jsonwebtoken');\n"
            "const JWT_SECRET = process.env.JWT_SECRET || 'hardcoded-test-jwt-secret-key';\n"
            "function authenticateToken(req, res, next) {\n"
            "  // debug bypass header\n"
            "  if (req.headers['x-debug-mode'] === 'true') {\n"
            "    req.user = { id: 1, role: 'admin' };\n"
            "    return next();\n"
            "  }\n"
            "  const token = (req.headers['authorization'] || '').split(' ')[1];\n"
            "  jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] }, (err, decoded) => {\n"
            "    if (err) return res.status(403).json({ error: 'Invalid token' });\n"
            "    req.user = decoded;\n"
            "    next();\n"
            "  });\n"
            "}\n"
            "function requireRole(...roles) {\n"
            "  return (req, res, next) => {\n"
            "    const overrideRole = req.headers['x-role-override'];\n"
            "    const currentRole = overrideRole || (req.user && req.user.role);\n"
            "    if (!roles.includes(currentRole)) return res.status(403).json({ error: 'Denied' });\n"
            "    next();\n"
            "  };\n"
            "}\n"
            "module.exports = { authenticateToken, requireRole, JWT_SECRET };\n"
        )

        (proj_dir / "src" / "middleware" / "errorHandler.js").write_text(
            "function errorHandler(err, req, res, next) {\n"
            "  res.status(err.status || 500).json({\n"
            "    status: 'error',\n"
            "    message: err.message,\n"
            "    stack: err.stack,\n"
            "    internalQuery: err.query || null,\n"
            "    processEnv: process.env.NODE_ENV\n"
            "  });\n"
            "}\n"
            "module.exports = errorHandler;\n"
        )

        (proj_dir / "src" / "utils" / "objectUtils.js").write_text(
            "function deepMerge(target, source) {\n"
            "  for (const key in source) {\n"
            "    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {\n"
            "      if (!target[key]) target[key] = {};\n"
            "      deepMerge(target[key], source[key]);\n"
            "    } else {\n"
            "      target[key] = source[key];\n"
            "    }\n"
            "  }\n"
            "  return target;\n"
            "}\n"
            "module.exports = { deepMerge };\n"
        )

        (proj_dir / "src" / "controllers" / "authController.js").write_text(
            "const { rawQuery, safeQuery } = require('../config/database');\n"
            "async function login(req, res, next) {\n"
            "  try {\n"
            "    const { username, password } = req.body;\n"
            "    console.log(`[LOGIN] Attempting login for ${username} / password=${password}`);\n"
            "    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;\n\n"
            "    const users = await rawQuery(query);\n"
            "    if (!users.length) return res.status(401).json({ error: 'Invalid credentials' });\n"
            "    const user = users[0];\n"
            "    return res.json({\n"
            "      user: {\n"
            "        id: user.id,\n"
            "        username: user.username,\n"
            "        ssn: user.ssn,\n"
            "        resetToken: user.password_reset_token,\n"
            "      }\n"
            "    });\n"
            "  } catch (err) { next(err); }\n"
            "}\n"
            "async function register(req, res, next) {\n"
            "  try {\n"
            "    const { username, password, email, role } = req.body;\n"
            "    const assignedRole = 'user';\n"
            "    const query = `INSERT INTO users (username, password, email, role, ssn) VALUES (?, ?, ?, ?, ?)`;\n"
            "    await safeQuery(query, [username, password, email, assignedRole, '000-00-0000']);\n"
            "    res.status(201).json({ status: 'created' });\n"
            "  } catch (err) { next(err); }\n"
            "}\n"
            "module.exports = { login, register };\n"
        )

        (proj_dir / "src" / "controllers" / "productController.js").write_text(
            "const path = require('path');\n"
            "const { rawQuery, safeQuery } = require('../config/database');\n"
            "async function searchProducts(req, res, next) {\n"
            "  try {\n"
            "    const searchTerm = req.query.q || '';\n"
            "    const sql = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%' OR description LIKE '%${searchTerm}%'`;\n"
            "    console.log('[SEARCH]', sql);\n\n"
            "    const products = await rawQuery(sql);\n"
            "    res.json({ results: products });\n"
            "  } catch (err) {\n"
            "    err.query = `SELECT * FROM products WHERE name LIKE '%${req.query.q}%'`;\n"
            "    next(err);\n"
            "  }\n"
            "}\n"
            "function downloadProductReport(req, res) {\n"
            "  const filename = req.query.file;\n"
            "  const reportsDir = path.resolve(__dirname, '../../reports');\n"
            "  const filePath = path.join(reportsDir, filename);\n"
            "  res.sendFile(filePath);\n"
            "}\n"
            "module.exports = { searchProducts, downloadProductReport };\n"
        )

        (proj_dir / "src" / "controllers" / "systemController.js").write_text(
            "const { exec } = require('child_process');\n"
            "function pingHost(req, res) {\n"
            "  const host = req.query.host;\n"
            "  const command = `ping -c 1 ${host}`;\n"
            "  exec(command, (error, stdout) => {\n"
            "    if (error) return res.status(500).json({ error: error.message });\n"
            "    res.json({ command, stdout });\n"
            "  });\n"
            "}\n"
            "function calculateExpression(req, res) {\n"
            "  const { expression } = req.body;\n"
            "  const result = eval(expression);\n"
            "  res.json({ expression, result });\n"
            "}\n"
            "module.exports = { pingHost, calculateExpression };\n"
        )

        (proj_dir / "src" / "controllers" / "userController.js").write_text(
            "const { safeQuery } = require('../config/database');\n"
            "async function getUserProfile(req, res, next) {\n"
            "  try {\n"
            "    const targetUserId = req.params.id;\n"
            "    const rows = await safeQuery('SELECT * FROM users WHERE id = ?', [targetUserId]);\n"
            "    const user = rows[0];\n"
            "    res.json({ id: user.id, ssn: user.ssn, resetToken: user.password_reset_token });\n"
            "  } catch (err) { next(err); }\n"
            "}\n"
            "module.exports = { getUserProfile };\n"
        )

        (proj_dir / "src" / "controllers" / "webhookController.js").write_text(
            "const http = require('http');\n"
            "const https = require('https');\n"
            "function testWebhook(req, res, next) {\n"
            "  const targetUrl = req.body.url || req.query.url;\n"
            "  try {\n"
            "    const parsed = new URL(targetUrl);\n"
            "    const client = parsed.protocol === 'https:' ? https : http;\n"
            "    const clientReq = client.get(targetUrl, (clientRes) => {\n"
            "      res.json({ statusCode: clientRes.statusCode });\n"
            "    });\n"
            "    clientReq.on('error', (err) => res.status(502).json({ error: err.message }));\n"
            "  } catch (err) { next(err); }\n"
            "}\n"
            "function handleRedirect(req, res) {\n"
            "  const target = req.query.to;\n"
            "  res.redirect(target);\n"
            "}\n"
            "module.exports = { testWebhook, handleRedirect };\n"
        )

    def test_nodejs_express_scanner_detects_all_15_owasp_vulns_and_ignores_lockfiles(self):
        from agents.scanner_agent.agent import ScannerAgent

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            proj_dir = tmp_path / "node_api"
            findings_dir = tmp_path / "findings"
            findings_dir.mkdir()
            self._create_vulnerable_node_project(proj_dir)

            scanner = ScannerAgent(findings_dir=findings_dir)
            result = scanner.run({"workspace_path": str(proj_dir), "scanner_engine": "all"})

            self.assertEqual(result["status"], "completed")
            self.assertTrue(result["securescan"]["executed"])
            self.assertEqual(result["securescan"]["project_topology"], "Node.js / Express REST API")
            self.assertIn("Node.js (Express ^4.19.2)", result["securescan"]["target_frameworks"])

            findings = result["findings"]
            lockfile_findings = [
                f for f in findings
                if "package-lock.json" in (f.get("file_path") or "")
                or "registry.npmjs.org" in (f.get("code_snippet") or "")
            ]
            self.assertEqual(lockfile_findings, [])

            expected_pairs = [
                ("CWE-89", "authController.js"),
                ("CWE-89", "productController.js"),
                ("CWE-78", "systemController.js"),
                ("CWE-95", "systemController.js"),
                ("CWE-639", "userController.js"),
                ("CWE-22", "productController.js"),
                ("CWE-287", "auth.js"),
                ("CWE-798", "auth.js"),
                ("CWE-256", "authController.js"),
                ("CWE-359", "userController.js"),
                ("CWE-209", "errorHandler.js"),
                ("CWE-942", "app.js"),
                ("CWE-1321", "objectUtils.js"),
                ("CWE-918", "webhookController.js"),
                ("CWE-601", "webhookController.js"),
            ]
            for cwe, fname in expected_pairs:
                self.assertTrue(
                    any((f.get("cwe_id") or "").upper() == cwe and fname in (f.get("file_path") or "") for f in findings),
                    f"Expected finding ({cwe}, {fname}) not detected",
                )

    def test_nodejs_express_remediator_auto_fallback_achieves_zero_residual_findings(self):
        from agents.scanner_agent.agent import ScannerAgent
        from agents.remediator_agent.agent import RemediatorAgent

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            proj_dir = tmp_path / "node_api"
            findings_dir = tmp_path / "findings"
            reports_dir = tmp_path / "reports"
            repos_root = tmp_path / "repos_root"
            findings_dir.mkdir()
            reports_dir.mkdir()
            repos_root.mkdir()
            self._create_vulnerable_node_project(proj_dir)

            scanner = ScannerAgent(findings_dir=findings_dir)
            init_res = scanner.run({"workspace_path": str(proj_dir), "scanner_engine": "all"})
            self.assertGreaterEqual(len(init_res["findings"]), 15)

            remediator = RemediatorAgent(
                repos_root=repos_root,
                reports_dir=reports_dir,
                scanner_findings_dir=findings_dir,
            )
            rem_res = remediator.remediate(proj_dir, provider="auto-fallback")
            self.assertEqual(len(rem_res.get("failed_fixes", [])), 0)
            self.assertGreaterEqual(len(rem_res.get("bug_fixes", [])), 15)

            auth_ctrl = (proj_dir / "src" / "controllers" / "authController.js").read_text()
            self.assertIn("safeQuery(", auth_ctrl)
            self.assertIn("crypto.scryptSync", auth_ctrl)
            self.assertNotIn("user.ssn", auth_ctrl)

            auth_mw = (proj_dir / "src" / "middleware" / "auth.js").read_text()
            self.assertNotIn("hardcoded-test-jwt-secret-key", auth_mw)
            self.assertNotIn("req.headers['x-debug-mode']", auth_mw)
            self.assertNotIn("'none'", auth_mw)

            sys_ctrl = (proj_dir / "src" / "controllers" / "systemController.js").read_text()
            self.assertIn("execFile(", sys_ctrl)
            self.assertNotIn("eval(", sys_ctrl)

            obj_utils = (proj_dir / "src" / "utils" / "objectUtils.js").read_text()
            self.assertIn("'__proto__'", obj_utils)
            self.assertIn("'prototype'", obj_utils)

            webhook_ctrl = (proj_dir / "src" / "controllers" / "webhookController.js").read_text()
            self.assertIn("startsWith('127.')", webhook_ctrl)
            self.assertIn("allowedDomains.includes", webhook_ctrl)

            app_js = (proj_dir / "src" / "app.js").read_text()
            self.assertNotIn("origin: '*'", app_js)
            self.assertIn("app.disable('x-powered-by')", app_js)

            post_res = scanner.run({"workspace_path": str(proj_dir), "scanner_engine": "all", "is_post_scan": True})
            residual = post_res.get("post_scan_findings", post_res.get("findings", []))
            self.assertEqual(residual, [])


class TestLocalLLMModelDiscovery(unittest.TestCase):
    """Tests for local Ollama/OpenAI model discovery endpoint and UI dropdown wiring."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_ollama_models_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _call_get(self, path: str) -> tuple[int, dict]:
        handler = MultiAgentAPIHandler.__new__(MultiAgentAPIHandler)
        handler.rfile = io.BytesIO()
        handler.wfile = io.BytesIO()
        handler.headers = {}
        handler.path = path
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.do_GET()
        status_code = handler.send_response.call_args[0][0] if handler.send_response.call_args else 200
        response_data = json.loads(handler.wfile.getvalue().decode("utf-8")) if handler.wfile.getvalue() else {}
        return status_code, response_data

    def test_discover_ollama_via_api(self):
        from unittest.mock import patch
        from agents.remediator_agent.llm_client import discover_local_llm_models

        fake_tags = {
            "models": [
                {
                    "name": "llama3.2:latest",
                    "size": 2 * (1024 ** 3),
                    "modified_at": "2026-01-10T10:00:00Z",
                    "details": {
                        "parameter_size": "3.2B",
                        "family": "llama",
                        "quantization_level": "Q4_K_M",
                    },
                },
                {
                    "name": "qwen2.5-coder:3b",
                    "size": int(1.9 * (1024 ** 3)),
                    "modified_at": "2026-01-11T10:00:00Z",
                    "details": {
                        "parameter_size": "3.1B",
                        "family": "qwen2",
                        "quantization_level": "Q4_K_M",
                    },
                },
            ]
        }

        class FakeResp:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return json.dumps(fake_tags).encode("utf-8")

        with patch("urllib.request.urlopen", return_value=FakeResp()) as mock_open:
            res = discover_local_llm_models(provider="ollama", base_url="http://127.0.0.1:11434/v1")

        self.assertTrue(mock_open.called)
        self.assertEqual(res["base_url"], "http://127.0.0.1:11434")
        self.assertTrue(res["daemon_running"])
        self.assertEqual(res["source"], "ollama_api")
        self.assertEqual(res["model_names"], ["llama3.2:latest", "qwen2.5-coder:3b"])
        self.assertEqual(res["default_model"], "qwen2.5-coder:3b")
        self.assertEqual(res["models"][0]["size_label"], "2.0 GB")
        self.assertEqual(res["models"][0]["parameter_size"], "3.2B")

    def test_discover_ollama_manifest_fallback_when_daemon_offline(self):
        from unittest.mock import patch
        from agents.remediator_agent.llm_client import discover_local_llm_models

        manifest_base = self.temp_dir / "manifests" / "registry.ollama.ai" / "library"
        (manifest_base / "llama3.2").mkdir(parents=True, exist_ok=True)
        (manifest_base / "qwen2.5-coder").mkdir(parents=True, exist_ok=True)
        (manifest_base / "llama3.2" / "latest").write_text(
            json.dumps({"config": {"size": 1024}, "layers": [{"size": 500 * 1024 * 1024}]}),
            encoding="utf-8",
        )
        (manifest_base / "qwen2.5-coder" / "3b").write_text(
            json.dumps({"config": {"size": 2048}, "layers": [{"size": 2 * (1024 ** 3)}]}),
            encoding="utf-8",
        )

        with patch("agents.remediator_agent.llm_client._discover_ollama_via_api", return_value=([], "connection refused")), \
             patch("agents.remediator_agent.llm_client._discover_ollama_via_cli", return_value=([], "ollama daemon stopped")):
            res = discover_local_llm_models(provider="ollama", models_dir=self.temp_dir)

        self.assertFalse(res["daemon_running"])
        self.assertEqual(res["source"], "local_manifests")
        self.assertIn("llama3.2:latest", res["model_names"])
        self.assertIn("qwen2.5-coder:3b", res["model_names"])
        self.assertEqual(res["default_model"], "qwen2.5-coder:3b")
        qwen_entry = next(m for m in res["models"] if m["name"] == "qwen2.5-coder:3b")
        self.assertEqual(qwen_entry["size_label"], "2.0 GB")

    def test_discover_openai_compat_models(self):
        from unittest.mock import patch
        from agents.remediator_agent.llm_client import discover_local_llm_models

        class FakeResp:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return json.dumps({
                    "data": [{"id": "deepseek-coder-v2-lite", "owned_by": "lm-studio"}]
                }).encode("utf-8")

        with patch("urllib.request.urlopen", return_value=FakeResp()):
            res = discover_local_llm_models(provider="local", base_url="http://localhost:1234/v1")

        self.assertEqual(res["provider"], "local")
        self.assertTrue(res["daemon_running"])
        self.assertEqual(res["source"], "openai_compat_api")
        self.assertEqual(res["model_names"], ["deepseek-coder-v2-lite"])
        self.assertEqual(res["default_model"], "deepseek-coder-v2-lite")

    def test_api_llm_models_endpoint(self):
        from unittest.mock import patch

        sample = {
            "provider": "ollama",
            "base_url": "http://127.0.0.1:11434",
            "daemon_running": True,
            "source": "ollama_api",
            "models": [{"name": "codellama:7b", "size_label": "3.8 GB"}],
            "model_names": ["codellama:7b"],
            "default_model": "codellama:7b",
            "error": None,
        }
        with patch("web_server.discover_local_llm_models", return_value=sample) as mock_disc:
            status, data = self._call_get("/api/llm/models?provider=ollama&base_url=http%3A%2F%2F127.0.0.1%3A11434")
            self.assertEqual(status, 200)
            self.assertEqual(data["model_names"], ["codellama:7b"])
            mock_disc.assert_called_once_with(provider="ollama", base_url="http://127.0.0.1:11434")

            status2, data2 = self._call_get("/api/ollama/models")
            self.assertEqual(status2, 200)
            self.assertEqual(data2["model_names"], ["codellama:7b"])

    def test_ui_contains_local_model_dropdowns(self):
        root = Path(__file__).resolve().parent.parent
        index_html = (root / "web" / "index.html").read_text(encoding="utf-8")
        scheduler_html = (root / "web" / "scheduler.html").read_text(encoding="utf-8")
        self.assertIn('id="llmModelSelect"', index_html)
        self.assertIn("loadLocalLlmModels", index_html)
        self.assertIn("/api/llm/models", index_html)
        self.assertIn('id="schedLlmModelSelect"', scheduler_html)
        self.assertIn("loadSchedLlmModels", scheduler_html)
        self.assertIn("/api/llm/models", scheduler_html)


if __name__ == "__main__":
    unittest.main()
