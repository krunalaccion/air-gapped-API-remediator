"""
Unit tests for GitAgentConfig and provider resolution.
"""

import os
import unittest
from git_agent.config import GitAgentConfig, ProviderType


class TestGitAgentConfig(unittest.TestCase):

    def test_auto_detect_github(self):
        cfg = GitAgentConfig(repo_url="https://github.com/my-org/security-repo.git")
        self.assertEqual(cfg.provider, ProviderType.GITHUB)
        self.assertEqual(cfg.api_base_url, "https://api.github.com")

    def test_auto_detect_gitlab(self):
        cfg = GitAgentConfig(repo_url="https://gitlab.com/group/subgroup/project.git")
        self.assertEqual(cfg.provider, ProviderType.GITLAB)
        self.assertEqual(cfg.api_base_url, "https://gitlab.com/api/v4")

    def test_authenticated_clone_url_github(self):
        cfg = GitAgentConfig(
            repo_url="https://github.com/octocat/Hello-World.git",
            token="ghp_secretToken12345",
        )
        auth_url = cfg.authenticated_clone_url
        self.assertIn("x-access-token:ghp_secretToken12345@github.com", auth_url)

    def test_authenticated_clone_url_gitlab(self):
        cfg = GitAgentConfig(
            repo_url="https://gitlab.com/mygroup/myproject.git",
            token="glpat-secretToken12345",
        )
        auth_url = cfg.authenticated_clone_url
        self.assertIn("oauth2:glpat-secretToken12345@gitlab.com", auth_url)

    def test_token_masking(self):
        cfg = GitAgentConfig(
            repo_url="https://github.com/owner/repo.git",
            token="ghp_abcdef1234567890",
        )
        masked = cfg.mask_token()
        self.assertEqual(masked, "ghp_...7890")
        self.assertNotIn("abcdef123456", masked)

    def test_sanitized_repo_url(self):
        cfg = GitAgentConfig(
            repo_url="https://user:password@github.com/owner/repo.git"
        )
        self.assertEqual(cfg.sanitized_repo_url, "https://github.com/owner/repo.git")

    def test_from_dict(self):
        data = {
            "repo_url": "https://gitlab.com/corp/app.git",
            "token": "token123",
            "base_branch": "develop",
            "feature_branch_name": "feat-1",
            "author_name": "AuditBot",
            "draft_pr": True,
        }
        cfg = GitAgentConfig.from_dict(data)
        self.assertEqual(cfg.provider, ProviderType.GITLAB)
        self.assertEqual(cfg.base_branch, "develop")
        self.assertEqual(cfg.author_name, "AuditBot")
        self.assertTrue(cfg.draft_pr)


if __name__ == "__main__":
    unittest.main()
