"""
Unit tests for GitAgentConfig and provider resolution.
"""

import os
import unittest
from agents.git_agent.config import GitAgentConfig, ProviderType


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

    def test_auto_detect_local_paths(self):
        # Absolute path
        cfg1 = GitAgentConfig(repo_url="/Users/test/my-project")
        self.assertEqual(cfg1.provider, ProviderType.LOCAL)
        self.assertTrue(cfg1.is_local)

        # Relative path
        cfg2 = GitAgentConfig(repo_url="./my-project")
        self.assertEqual(cfg2.provider, ProviderType.LOCAL)
        self.assertTrue(cfg2.is_local)

        # Current directory
        cfg3 = GitAgentConfig(repo_url=".")
        self.assertEqual(cfg3.provider, ProviderType.LOCAL)
        self.assertTrue(cfg3.is_local)

        # File URL
        cfg4 = GitAgentConfig(repo_url="file:///tmp/repo")
        self.assertEqual(cfg4.provider, ProviderType.LOCAL)
        self.assertTrue(cfg4.is_local)

        # Explicit provider=local
        cfg5 = GitAgentConfig(repo_url="my-custom-repo", provider=ProviderType.LOCAL)
        self.assertEqual(cfg5.provider, ProviderType.LOCAL)
        self.assertTrue(cfg5.is_local)

    def test_authenticated_clone_url_local(self):
        cfg = GitAgentConfig(
            repo_url="/tmp/my-local-repo",
            token="ghp_some_token",
        )
        # Local paths should never embed tokens or https
        auth_url = cfg.authenticated_clone_url
        self.assertNotIn("ghp_some_token", auth_url)
        self.assertNotIn("https://", auth_url)
        self.assertTrue(auth_url.endswith("my-local-repo"))

    def test_sanitized_repo_url_local(self):
        cfg = GitAgentConfig(repo_url="file:///tmp/my-repo")
        sanitized = cfg.sanitized_repo_url
        self.assertTrue(sanitized.endswith("my-repo"))
        self.assertNotIn("file://", sanitized)

    def test_from_dict_local(self):
        data = {
            "repo_url": "/Users/local/code",
            "provider": "local",
            "base_branch": "main",
        }
        cfg = GitAgentConfig.from_dict(data)
        self.assertEqual(cfg.provider, ProviderType.LOCAL)
        self.assertEqual(cfg.base_branch, "main")
        self.assertTrue(cfg.is_local)

    def test_build_authenticated_remote_url_for_local_repo_with_origin(self):
        cfg = GitAgentConfig(
            repo_url="/tmp/my-local-repo",
            token="ghp_localPushToken1234",
            username="secbot",
        )
        # GitHub HTTPS origin
        gh_url = cfg.build_authenticated_remote_url("https://github.com/org/app.git")
        self.assertEqual(gh_url, "https://x-access-token:ghp_localPushToken1234@github.com/org/app.git")

        # GitHub SSH origin converted to HTTPS when token supplied
        gh_ssh = cfg.build_authenticated_remote_url("git@github.com:org/app.git")
        self.assertEqual(gh_ssh, "https://x-access-token:ghp_localPushToken1234@github.com/org/app.git")

        # GitLab HTTPS origin
        gl_url = cfg.build_authenticated_remote_url("https://gitlab.com/team/app.git", token="glpat-abc999")
        self.assertEqual(gl_url, "https://oauth2:glpat-abc999@gitlab.com/team/app.git")

        # Generic HTTPS origin uses custom username + token
        gen_url = cfg.build_authenticated_remote_url("https://git.corp.local/team/app.git")
        self.assertEqual(gen_url, "https://secbot:ghp_localPushToken1234@git.corp.local/team/app.git")

        # Local bare remote remains untouched
        self.assertEqual(cfg.build_authenticated_remote_url("/tmp/bare_remote.git"), "/tmp/bare_remote.git")


if __name__ == "__main__":
    unittest.main()

