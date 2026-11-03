"""
Unit tests for GitHub and GitLab providers.
"""

import unittest
from unittest.mock import patch, MagicMock
from agents.git_agent.config import GitAgentConfig, ProviderType
from agents.git_agent.providers.github import GitHubProvider
from agents.git_agent.providers.gitlab import GitLabProvider
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


if __name__ == "__main__":
    unittest.main()

