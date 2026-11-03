"""
Unit tests for GitAgentMCPServer protocol handling and tools.
"""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from agents.git_agent.mcp_server import GitAgentMCPServer
from agents.git_agent.agent import GitSubAgent, WorkspaceContext
from agents.git_agent.providers.base import PullRequestResult


class TestGitAgentMCPServer(unittest.TestCase):

    def setUp(self):
        self.server = GitAgentMCPServer()

    def test_initialize(self):
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        resp = self.server.process_message(msg)
        self.assertEqual(resp["id"], 1)
        self.assertEqual(resp["result"]["serverInfo"]["name"], "git-agent-mcp")
        self.assertIn("tools", resp["result"]["capabilities"])

    def test_ping(self):
        msg = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
        resp = self.server.process_message(msg)
        self.assertEqual(resp["id"], 2)
        self.assertEqual(resp["result"], {})

    def test_tools_list(self):
        msg = {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
        resp = self.server.process_message(msg)
        tools = resp["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("git_prepare_repo", tool_names)
        self.assertIn("git_status", tool_names)
        self.assertIn("git_diff", tool_names)
        self.assertIn("git_read_file", tool_names)
        self.assertIn("git_write_file", tool_names)
        self.assertIn("git_commit_and_push", tool_names)
        self.assertIn("git_create_pull_request", tool_names)
        self.assertIn("git_finalize_audit", tool_names)

    def test_tools_call_read_write_file(self):
        temp_dir = Path(tempfile.mkdtemp(prefix="test_mcp_fs_"))
        try:
            # Mock agent workspace
            mock_agent = MagicMock()
            mock_agent.get_workspace_path.return_value = temp_dir
            self.server.agent = mock_agent

            # 1. Write file
            write_msg = {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "git_write_file",
                    "arguments": {
                        "relative_path": "src/patch.py",
                        "content": "SECRET_KEY = 'environment_var'",
                    },
                },
            }
            resp = self.server.process_message(write_msg)
            self.assertFalse(resp["result"].get("isError", False))
            self.assertTrue((temp_dir / "src" / "patch.py").exists())

            # 2. Read file
            read_msg = {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "git_read_file",
                    "arguments": {
                        "relative_path": "src/patch.py",
                    },
                },
            }
            resp = self.server.process_message(read_msg)
            content = resp["result"]["content"][0]["text"]
            self.assertEqual(content, "SECRET_KEY = 'environment_var'")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tools_call_local_repo_full_workflow(self):
        temp_dir = Path(tempfile.mkdtemp(prefix="test_mcp_local_"))
        try:
            # Init git repository
            subprocess.run(["git", "init"], cwd=str(temp_dir), check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "MCPUser"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "config", "user.email", "mcp@test.local"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=str(temp_dir), check=True)
            (temp_dir / "index.js").write_text("console.log('original');\n")
            subprocess.run(["git", "add", "."], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-m", "init"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "branch", "-M", "main"], cwd=str(temp_dir), check=True)

            # 1. Prepare local repo via MCP
            prep_msg = {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "git_prepare_repo",
                    "arguments": {
                        "repo_url": str(temp_dir),
                        "feature_branch": "mcp-patch-branch",
                    },
                },
            }
            resp = self.server.process_message(prep_msg)
            self.assertFalse(resp["result"].get("isError", False))
            self.assertIn("Repository prepared successfully", resp["result"]["content"][0]["text"])

            # 2. Write file via MCP
            write_msg = {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "git_write_file",
                    "arguments": {
                        "relative_path": "index.js",
                        "content": "console.log('secured');\n",
                    },
                },
            }
            resp = self.server.process_message(write_msg)
            self.assertFalse(resp["result"].get("isError", False))

            # 3. Status via MCP
            stat_msg = {"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "git_status", "arguments": {}}}
            resp = self.server.process_message(stat_msg)
            stat = json.loads(resp["result"]["content"][0]["text"])
            self.assertIn("index.js", stat["modified"])

            # 4. Finalize audit via MCP
            fin_msg = {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": "git_finalize_audit",
                    "arguments": {
                        "commit_message": "fix: update index.js",
                        "pr_title": "Local Patch PR",
                    },
                },
            }
            resp = self.server.process_message(fin_msg)
            res_data = json.loads(resp["result"]["content"][0]["text"])
            self.assertEqual(res_data["status"], "success")
            self.assertTrue(res_data["pr_url"].startswith("file://"))

            # Verify commit made locally
            out = subprocess.run(["git", "log", "-1", "--pretty=%s"], cwd=str(temp_dir), capture_output=True, text=True, check=True).stdout
            self.assertEqual(out.strip(), "fix: update index.js")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

