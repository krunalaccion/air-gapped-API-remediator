"""
Configuration management for the Git SubAgent.
Supports loading from environment variables, dictionaries, and config files.
"""

from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse


class ProviderType(str, Enum):
    GITHUB = "github"
    GITLAB = "gitlab"
    GENERIC = "generic"


@dataclass
class GitAgentConfig:
    """Configurable options for Git Agent operations."""

    repo_url: str
    token: Optional[str] = None
    provider: ProviderType = ProviderType.GENERIC
    api_base_url: Optional[str] = None

    # Branch settings
    base_branch: Optional[str] = None  # None or "auto" triggers auto-detection of default branch (main/master)
    feature_branch_name: Optional[str] = None
    feature_branch_prefix: str = "agent/vuln-audit-"

    # Workspace directory
    workspace_dir: Optional[str] = None  # None creates an isolated temporary directory

    # Author info for commits
    author_name: str = "Git SubAgent"
    author_email: str = "git-agent@subagent.local"

    # Pull Request defaults
    default_pr_title: str = "Automated Security Vulnerability Fixes"
    default_pr_body: str = (
        "## Summary of Changes\n\n"
        "This Pull/Merge Request was automatically created by the Git SubAgent following "
        "a security audit and vulnerability remediation scan.\n\n"
        "Please review the changes carefully before merging."
    )
    draft_pr: bool = False

    # Extra metadata
    extra_headers: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        # Auto-detect provider if generic or not explicitly provided
        if self.provider == ProviderType.GENERIC:
            self.provider = self._detect_provider_from_url(self.repo_url)

        # Auto-load token from environment if not explicitly passed
        if not self.token:
            self.token = self._resolve_env_token()

        # Set default API base URL if not provided
        if not self.api_base_url:
            self.api_base_url = self._default_api_base()

    def _detect_provider_from_url(self, url: str) -> ProviderType:
        """Infer provider from repository URL host."""
        lower_url = url.lower()
        if "gitlab" in lower_url:
            return ProviderType.GITLAB
        if "github" in lower_url:
            return ProviderType.GITHUB
        return ProviderType.GENERIC

    def _resolve_env_token(self) -> Optional[str]:
        """Attempt to read token from environment variables matching provider."""
        if self.provider == ProviderType.GITHUB:
            return (
                os.getenv("GITHUB_TOKEN")
                or os.getenv("GH_TOKEN")
                or os.getenv("GIT_AGENT_TOKEN")
            )
        elif self.provider == ProviderType.GITLAB:
            return (
                os.getenv("GITLAB_TOKEN")
                or os.getenv("GL_TOKEN")
                or os.getenv("GIT_AGENT_TOKEN")
            )
        return os.getenv("GIT_AGENT_TOKEN") or os.getenv("GIT_TOKEN")

    def _default_api_base(self) -> str:
        """Return the default API endpoint for the detected provider."""
        if self.provider == ProviderType.GITHUB:
            # Check for GitHub Enterprise URL
            parsed = urlparse(self.repo_url)
            host = parsed.netloc.split("@")[-1].split(":")[0]
            if host and host not in ("github.com", ""):
                return f"https://{host}/api/v3"
            return "https://api.github.com"

        elif self.provider == ProviderType.GITLAB:
            parsed = urlparse(self.repo_url)
            host = parsed.netloc.split("@")[-1].split(":")[0]
            if host and host not in ("gitlab.com", ""):
                return f"https://{host}/api/v4"
            return "https://gitlab.com/api/v4"

        return ""

    @property
    def authenticated_clone_url(self) -> str:
        """
        Builds a safe clone URL with credentials embedded for git commands,
        or returns the standard URL if no token is available.
        """
        if not self.token:
            return self.repo_url

        url = self.repo_url.strip()

        # Convert SSH to HTTPS if needed (e.g. git@github.com:owner/repo.git -> https://github.com/owner/repo.git)
        ssh_pattern = r"^git@([^:]+):(.+)$"
        ssh_match = re.match(ssh_pattern, url)
        if ssh_match:
            host, path = ssh_match.groups()
            url = f"https://{host}/{path}"

        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"

        parsed = urlparse(url)
        host = parsed.netloc.split("@")[-1]  # strip any existing userinfo

        if self.provider == ProviderType.GITHUB:
            # GitHub supports x-access-token or token as username
            return f"https://x-access-token:{self.token}@{host}{parsed.path}"
        elif self.provider == ProviderType.GITLAB:
            # GitLab supports oauth2 or personal access token via oauth2 user
            return f"https://oauth2:{self.token}@{host}{parsed.path}"
        else:
            return f"https://gitagent:{self.token}@{host}{parsed.path}"

    @property
    def sanitized_repo_url(self) -> str:
        """Returns repo URL without tokens or credentials for safe logging."""
        url = self.repo_url
        # Strip user:password or tokens from http urls
        parsed = urlparse(url)
        if parsed.netloc and "@" in parsed.netloc:
            host = parsed.netloc.split("@")[-1]
            return parsed._replace(netloc=host).geturl()
        return url

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GitAgentConfig:
        """Instantiate config from dictionary (e.g. parsed JSON or YAML)."""
        provider = data.get("provider")
        if isinstance(provider, str):
            try:
                provider = ProviderType(provider.lower())
            except ValueError:
                provider = ProviderType.GENERIC

        return cls(
            repo_url=data["repo_url"],
            token=data.get("token"),
            provider=provider or ProviderType.GENERIC,
            api_base_url=data.get("api_base_url"),
            base_branch=data.get("base_branch"),
            feature_branch_name=data.get("feature_branch_name"),
            feature_branch_prefix=data.get("feature_branch_prefix", "agent/vuln-audit-"),
            workspace_dir=data.get("workspace_dir"),
            author_name=data.get("author_name", "Git SubAgent"),
            author_email=data.get("author_email", "git-agent@subagent.local"),
            default_pr_title=data.get("default_pr_title", "Automated Security Vulnerability Fixes"),
            default_pr_body=data.get(
                "default_pr_body",
                "Automated Pull/Merge Request generated by Git SubAgent."
            ),
            draft_pr=bool(data.get("draft_pr", False)),
            extra_headers=data.get("extra_headers", {}),
        )

    def mask_token(self) -> str:
        """Returns masked token string for safe display."""
        if not self.token:
            return "<none>"
        if len(self.token) <= 8:
            return "***"
        return f"{self.token[:4]}...{self.token[-4:]}"
