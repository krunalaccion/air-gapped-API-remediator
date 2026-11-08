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



if __name__ == "__main__":
    unittest.main()
