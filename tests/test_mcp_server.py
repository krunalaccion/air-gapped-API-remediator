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

from git_agent.mcp_server import GitAgentMCPServer
from git_agent.agent import GitSubAgent, WorkspaceContext
from git_agent.providers.base import PullRequestResult


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


if __name__ == "__main__":
    unittest.main()

