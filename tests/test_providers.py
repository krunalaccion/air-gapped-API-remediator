"""
Unit tests for GitHub and GitLab providers.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from agents.git_agent.config import GitAgentConfig, ProviderType
from agents.git_agent.providers.github import GitHubProvider
from agents.git_agent.providers.gitlab import GitLabProvider
from agents.git_agent.providers.local import LocalProvider
from agents.git_agent.providers import get_provider


class TestProviders(unittest.TestCase):

    def test_github_parsing_https(self):
        cfg = GitAgentConfig(repo_url="https://github.com/my-org/core-service.git", token="tok")
        provider = GitHubProvider(cfg)
        self.assertEqual(provider.owner, "my-org")
        self.assertEqual(provider.repo, "core-service")

    def test_github_parsing_ssh(self):
        cfg = GitAgentConfig(repo_url="git@github.com:my-org/core-service.git", token="tok")
        provider = GitHubProvider(cfg)
        self.assertEqual(provider.owner, "my-org")
        self.assertEqual(provider.repo, "core-service")

    def test_github_parsing_shorthand(self):
        cfg = GitAgentConfig(repo_url="my-org/core-service", token="tok")
        provider = GitHubProvider(cfg)
        self.assertEqual(provider.owner, "my-org")
        self.assertEqual(provider.repo, "core-service")

    def test_gitlab_parsing_nested_subgroups(self):
        cfg = GitAgentConfig(
            repo_url="https://gitlab.com/group/subgroup/deep/project.git",
            token="tok",
        )
        provider = GitLabProvider(cfg)
        self.assertEqual(provider.project_path, "group/subgroup/deep/project")
        self.assertEqual(provider.project_id, "group%2Fsubgroup%2Fdeep%2Fproject")

    def test_gitlab_parsing_ssh(self):
        cfg = GitAgentConfig(
            repo_url="git@gitlab.com:enterprise/team/service.git",
            token="tok",
        )
        provider = GitLabProvider(cfg)
        self.assertEqual(provider.project_path, "enterprise/team/service")

    @patch.object(GitHubProvider, "_make_request")
    def test_github_create_pull_request(self, mock_req):
        mock_req.return_value = {
            "id": 987654,
            "number": 42,
            "html_url": "https://github.com/owner/repo/pull/42",
            "title": "Fix security vulnerability",
            "draft": False,
        }

        cfg = GitAgentConfig(repo_url="https://github.com/owner/repo.git", token="ghp_test")
        provider = GitHubProvider(cfg)

        pr = provider.create_pull_request(
            head_branch="patch-vuln-1",
            base_branch="main",
            title="Fix security vulnerability",
            description="Details of fix",
        )

        self.assertEqual(pr.number, 42)
        self.assertEqual(pr.url, "https://github.com/owner/repo/pull/42")
        self.assertEqual(pr.head_branch, "patch-vuln-1")
        self.assertEqual(pr.base_branch, "main")
        self.assertEqual(pr.provider, "github")

    @patch.object(GitLabProvider, "_make_request")
    def test_gitlab_create_merge_request(self, mock_req):
        mock_req.return_value = {
            "id": 111,
            "iid": 12,
            "web_url": "https://gitlab.com/group/project/-/merge_requests/12",
            "title": "Resolve CVE-2026",
        }

        cfg = GitAgentConfig(repo_url="https://gitlab.com/group/project.git", token="glpat_test")
        provider = GitLabProvider(cfg)

        mr = provider.create_pull_request(
            head_branch="patch-cve",
            base_branch="main",
            title="Resolve CVE-2026",
            description="Patched vulnerability",
        )

        self.assertEqual(mr.number, 12)
        self.assertEqual(mr.url, "https://gitlab.com/group/project/-/merge_requests/12")
        self.assertEqual(mr.provider, "gitlab")

    def test_local_provider_get_provider(self):
        cfg = GitAgentConfig(repo_url="/Users/dev/my-repo")
        provider = get_provider(cfg)
        self.assertIsInstance(provider, LocalProvider)

    def test_local_provider_workflow(self):
        temp_dir = Path(tempfile.mkdtemp(prefix="test_local_provider_"))
        try:
            # Initialize a git repo
            subprocess.run(["git", "init"], cwd=str(temp_dir), check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=str(temp_dir), check=True)
            (temp_dir / "file.txt").write_text("Hello\n")
            subprocess.run(["git", "add", "."], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-m", "init"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "branch", "-M", "main"], cwd=str(temp_dir), check=True)

            cfg = GitAgentConfig(repo_url=str(temp_dir))
            provider = LocalProvider(cfg)

            # 1. Verify access
            self.assertTrue(provider.verify_access())

            # 2. Default branch
            self.assertEqual(provider.get_default_branch(), "main")

            # 3. Create pull request
            pr = provider.create_pull_request(
                head_branch="feature/audit-fix",
                base_branch="main",
                title="Fix Local Flaw",
                description="Remediation for local security issue.",
                draft=False,
            )

            self.assertEqual(pr.provider, "local")
            self.assertEqual(pr.number, 1)
            self.assertEqual(pr.head_branch, "feature/audit-fix")
            self.assertEqual(pr.base_branch, "main")
            self.assertTrue(pr.url.startswith("file://"))

            # Check that files were created
            pr_md_file = temp_dir / ".git" / "local_prs" / "PR-1.md"
            self.assertTrue(pr_md_file.exists())
            self.assertIn("Fix Local Flaw", pr_md_file.read_text())

            # Create second PR to check incrementing number
            pr2 = provider.create_pull_request(
                head_branch="feature/audit-fix-2",
                base_branch="main",
                title="Fix Second Issue",
                description="Another fix.",
            )
            self.assertEqual(pr2.number, 2)
            self.assertTrue((temp_dir / ".git" / "local_prs" / "PR-2.md").exists())
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_local_provider_verify_access_invalid(self):
        cfg = GitAgentConfig(repo_url="/non/existent/path/for/repo")
        provider = LocalProvider(cfg)
        self.assertFalse(provider.verify_access())

    def test_local_provider_check_is_git_repository_throws_error(self):
        # 1. Non-existent path
        cfg1 = GitAgentConfig(repo_url="/non/existent/path/here")
        p1 = LocalProvider(cfg1)
        with self.assertRaises(FileNotFoundError):
            p1.check_is_git_repository()

        # 2. Existing folder without .git
        temp_dir = Path(tempfile.mkdtemp(prefix="non_git_folder_"))
        try:
            (temp_dir / "somefile.txt").write_text("not a git repo")
            cfg2 = GitAgentConfig(repo_url=str(temp_dir))
            p2 = LocalProvider(cfg2)
            with self.assertRaises(ValueError) as ctx:
                p2.check_is_git_repository()
            self.assertIn("is not a Git repository", str(ctx.exception))
            self.assertIn("missing '.git' directory", str(ctx.exception))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

