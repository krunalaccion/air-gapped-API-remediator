"""
Unit and integration tests for GitSubAgent and multi-agent lifecycle.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from agents.git_agent.agent import GitSubAgent
from agents.git_agent.config import GitAgentConfig, ProviderType
from agents.git_agent.providers.base import PullRequestResult


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

    def test_local_repo_subagent_lifecycle_in_place(self):
        # Create a local git repo
        local_repo = self.temp_dir / "my_local_workdir"
        local_repo.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init"], cwd=str(local_repo), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "LocalDev"], cwd=str(local_repo), check=True)
        subprocess.run(["git", "config", "user.email", "local@dev.local"], cwd=str(local_repo), check=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=str(local_repo), check=True)
        (local_repo / "server.py").write_text("API_KEY = 'hardcoded_secret'\n")
        subprocess.run(["git", "add", "server.py"], cwd=str(local_repo), check=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-m", "Initial local commit"], cwd=str(local_repo), check=True)
        subprocess.run(["git", "branch", "-M", "main"], cwd=str(local_repo), check=True)

        # Configure GitSubAgent directly on local repo
        config = GitAgentConfig(
            repo_url=str(local_repo),
            feature_branch_name="security/rotate-secret",
        )
        self.assertEqual(config.provider, ProviderType.LOCAL)
        self.assertEqual(config.workspace_dir, str(local_repo.resolve()))

        agent = GitSubAgent(config)

        # 1. Prepare workspace
        ctx = agent.prepare_workspace()
        self.assertEqual(ctx.base_branch, "main")
        self.assertEqual(ctx.feature_branch, "security/rotate-secret")
        self.assertEqual(str(ctx.repo_path), str(local_repo.resolve()))
        self.assertEqual(ctx.provider, "local")

        # 2. Modify files (simulate patch)
        (local_repo / "server.py").write_text("API_KEY = os.getenv('API_KEY')\n")
        (local_repo / "AUDIT.md").write_text("Rotated hardcoded key.\n")

        # 3. Finalize workspace
        res = agent.finalize_workspace(
            commit_message="fix(security): load API_KEY from environment",
            pr_title="Rotate Hardcoded Secrets",
            pr_body="Replaced hardcoded key with environment variable.",
        )

        self.assertEqual(res.status, "success")
        self.assertIsNotNone(res.commit_hash)
        self.assertEqual(res.pr.provider, "local")
        self.assertEqual(res.pr.number, 1)
        self.assertTrue(res.pr.url.startswith("file://"))

        # Verify git commit in local repository
        out = subprocess.run(
            ["git", "log", "-1", "--pretty=%B"],
            cwd=str(local_repo),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertIn("fix(security): load API_KEY from environment", out)

        # Verify PR record file exists in .git/local_prs
        self.assertTrue((local_repo / ".git" / "local_prs" / "PR-1.md").exists())

    def test_local_repo_without_git_throws_error(self):
        # Create non-git folder
        non_git_dir = self.temp_dir / "plain_folder_without_git"
        non_git_dir.mkdir(parents=True, exist_ok=True)
        (non_git_dir / "notes.txt").write_text("just files, no git")

        config = GitAgentConfig(repo_url=str(non_git_dir))
        agent = GitSubAgent(config)

        # Calling prepare_workspace must throw error
        with self.assertRaises(ValueError) as ctx:
            agent.prepare_workspace()

        self.assertIn("is not a Git repository", str(ctx.exception))
        self.assertIn("missing '.git' directory", str(ctx.exception))

    def test_local_repo_with_remote_origin_pushes_and_authenticates(self):
        # Local clone backed by a bare remote 'origin' (created in setUp at self.remote_dir)
        subprocess.run(["git", "clone", str(self.remote_dir), str(self.local_dir)], check=True, capture_output=True)

        config = GitAgentConfig(
            repo_url=str(self.local_dir),
            feature_branch_name="remediation/local-push-test",
        )
        self.assertEqual(config.provider, ProviderType.LOCAL)
        self.assertTrue(config.is_local)

        agent = GitSubAgent(config)
        ctx = agent.prepare_workspace()
        (ctx.repo_path / "app.py").write_text("print('fixed locally and pushed')\n")

        res = agent.finalize_workspace(
            commit_message="fix: remediate and push from local folder",
            pr_title="Local Push PR",
            pr_body="Pushed from local folder to origin.",
        )
        self.assertEqual(res.status, "success")

        # Confirm the branch was pushed to the bare remote
        remote_branches = subprocess.run(
            ["git", "branch", "--list", "remediation/local-push-test"],
            cwd=str(self.remote_dir),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertIn("remediation/local-push-test", remote_branches)

        # Verify authenticated URL injection when origin is an HTTPS GitHub URL
        subprocess.run(
            ["git", "remote", "set-url", "origin", "https://github.com/example-org/sample-app.git"],
            cwd=str(self.local_dir),
            check=True,
            capture_output=True,
        )
        with unittest.mock.patch.object(agent.workspace, "push") as mock_push:
            push_res = agent.push_branch(branch="remediation/local-push-test", token="ghp_testSecretToken999")
            self.assertTrue(push_res["pushed"])
            self.assertEqual(push_res["remote_url"], "https://github.com/example-org/sample-app.git")
            mock_push.assert_called_once_with(
                branch="remediation/local-push-test",
                remote="origin",
                force=False,
                push_url="https://x-access-token:ghp_testSecretToken999@github.com/example-org/sample-app.git",
            )


if __name__ == "__main__":
    unittest.main()
