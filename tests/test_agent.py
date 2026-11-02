"""
Unit and integration tests for GitSubAgent and multi-agent lifecycle.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from git_agent.agent import GitSubAgent
from git_agent.config import GitAgentConfig, ProviderType
from git_agent.providers.base import PullRequestResult


class TestGitSubAgent(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_agent_env_"))
        self.remote_dir = self.temp_dir / "remote.git"
        self.local_dir = self.temp_dir / "local_clone"

        # Initialize bare remote repo
        subprocess.run(["git", "init", "--bare", str(self.remote_dir)], check=True, capture_output=True)

        # Seed initial commit
        seed = self.temp_dir / "seed"
        subprocess.run(["git", "clone", str(self.remote_dir), str(seed)], check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Seeder"], cwd=str(seed), check=True)
        subprocess.run(["git", "config", "user.email", "seed@test.local"], cwd=str(seed), check=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=str(seed), check=True)
        (seed / "app.py").write_text("print('insecure code')\n")
        subprocess.run(["git", "add", "app.py"], cwd=str(seed), check=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-m", "Initial commit"], cwd=str(seed), check=True)
        subprocess.run(["git", "branch", "-M", "main"], cwd=str(seed), check=True)
        subprocess.run(["git", "push", "-u", "origin", "main"], cwd=str(seed), check=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_subagent_lifecycle(self):
        config = GitAgentConfig(
            repo_url=str(self.remote_dir),
            provider=ProviderType.GITHUB,
            workspace_dir=str(self.local_dir),
            feature_branch_name="agent/fix-cve-2026",
            author_name="SecurityAgent",
            author_email="secagent@test.local",
        )
        agent = GitSubAgent(config)

        # Mock the provider PR creation so network is not touched
        agent.provider = MagicMock()
        agent.provider.get_default_branch.return_value = "main"
        agent.provider.create_pull_request.return_value = PullRequestResult(
            id="12345",
            number=99,
            url="https://github.com/mock/repo/pull/99",
            title="Fix Insecure Code",
            head_branch="agent/fix-cve-2026",
            base_branch="main",
            provider="github",
        )

        # 1. Step 1: Prepare workspace
        ctx = agent.prepare_workspace()
        self.assertEqual(ctx.base_branch, "main")
        self.assertEqual(ctx.feature_branch, "agent/fix-cve-2026")
        self.assertTrue((ctx.repo_path / "app.py").exists())

        # 2. Downstream Agent simulates vulnerability remediation
        (ctx.repo_path / "app.py").write_text("print('sanitized secure code')\n")
        (ctx.repo_path / "VULN_PATCH.md").write_text("Remediated SQL injection flaw.")

        # 3. Step 2: Finalize workspace & open PR
        res = agent.finalize_workspace(
            commit_message="fix(sec): sanitize input in app.py",
            pr_title="Fix Insecure Code",
            pr_body="Detailed remediation notes.",
        )

        self.assertEqual(res.status, "success")
        self.assertIsNotNone(res.commit_hash)
        self.assertEqual(res.pr.number, 99)
        self.assertEqual(res.pr.url, "https://github.com/mock/repo/pull/99")
        agent.provider.create_pull_request.assert_called_once()


if __name__ == "__main__":
    unittest.main()
