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
    LOCAL = "local"
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

    @property
    def is_local(self) -> bool:
        """Indicates whether this repository is on the local filesystem."""
        return self.provider == ProviderType.LOCAL or self._is_local_path(self.repo_url)

    @staticmethod
    def _is_local_path(url: str) -> bool:
        """Check if URL or path string represents a local filesystem location."""
        if not url:
            return False
        clean = url.strip()
        if clean.startswith("file://"):
            return True
        if clean.startswith(("/", "~", "./", "../")) or clean == ".":
            return True
        # Windows drive letter (e.g. C:\ or C:/)
        if re.match(r"^[a-zA-Z]:[\\/]", clean):
            return True
        # Check if the path exists on disk
        try:
            expanded = os.path.expanduser(clean)
            if Path(expanded).exists():
                return True
        except Exception:
            pass
        return False

    def __post_init__(self):
        # Auto-detect provider if generic or not explicitly provided
        if self.provider == ProviderType.GENERIC:
            self.provider = self._detect_provider_from_url(self.repo_url)

        # For local repos, default workspace_dir to repo_url if it contains a git working tree
        if self.provider == ProviderType.LOCAL and not self.workspace_dir:
            try:
                clean = self.repo_url.strip()
                if clean.startswith("file://"):
                    clean = clean[7:]
                local_path = Path(os.path.expanduser(clean)).resolve()
                if local_path.exists() and (local_path / ".git").exists():
                    self.workspace_dir = str(local_path)
            except Exception:
                pass

        # Auto-load token from environment if not explicitly passed (skip for local repos)
        if not self.token and self.provider != ProviderType.LOCAL:
            self.token = self._resolve_env_token()

        # Set default API base URL if not provided
        if not self.api_base_url:
            self.api_base_url = self._default_api_base()

    def _detect_provider_from_url(self, url: str) -> ProviderType:
        """Infer provider from repository URL host or filesystem path."""
        if not url:
            return ProviderType.GENERIC
        lower_url = url.strip().lower()
        if lower_url == "local":
            return ProviderType.LOCAL
        if self._is_local_path(url):
            return ProviderType.LOCAL
        if "gitlab" in lower_url:
            return ProviderType.GITLAB
        if "github" in lower_url:
            return ProviderType.GITHUB
        return ProviderType.GENERIC

    def _resolve_env_token(self) -> Optional[str]:
        """
        Attempt to read token from:
        1. Environment variables
        2. Local .env file
        3. ~/.gemini/config/mcp_config.json
        """
        # 1. Environment variables
        if self.provider == ProviderType.GITHUB:
            tok = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
            if tok:
                return tok
        elif self.provider == ProviderType.GITLAB:
            tok = os.getenv("GITLAB_TOKEN") or os.getenv("GL_TOKEN")
            if tok:
                return tok

        tok = os.getenv("GIT_AGENT_TOKEN") or os.getenv("GIT_TOKEN")
        if tok:
            return tok

        # 2. Check local .env file
        for env_path in (Path(".env"), Path(__file__).parent.parent / ".env"):
            if env_path.exists():
                try:
                    for line in env_path.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, val = line.split("=", 1)
                            key = key.strip()
                            val = val.strip().strip('"\'')
                            if self.provider == ProviderType.GITHUB and key in ("GITHUB_TOKEN", "GH_TOKEN"):
                                return val
                            if self.provider == ProviderType.GITLAB and key in ("GITLAB_TOKEN", "GL_TOKEN"):
                                return val
                            if key in ("GIT_AGENT_TOKEN", "GIT_TOKEN"):
                                return val
                except Exception:
                    pass

        # 3. Check ~/.gemini/config/mcp_config.json
        mcp_cfg_path = Path.home() / ".gemini" / "config" / "mcp_config.json"
        if mcp_cfg_path.exists():
            try:
                import json
                data = json.loads(mcp_cfg_path.read_text(encoding="utf-8"))
                for srv in data.get("mcpServers", {}).values():
                    env_dict = srv.get("env", {})
                    if self.provider == ProviderType.GITHUB:
                        t = env_dict.get("GITHUB_TOKEN") or env_dict.get("GH_TOKEN")
                        if t and not t.startswith("ghp_your"):
                            return t
                    elif self.provider == ProviderType.GITLAB:
                        t = env_dict.get("GITLAB_TOKEN") or env_dict.get("GL_TOKEN")
                        if t and not t.startswith("glpat-your"):
                            return t
            except Exception:
                pass

        return None

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

        elif self.provider == ProviderType.LOCAL:
            return ""

        return ""

    @property
    def authenticated_clone_url(self) -> str:
        """
        Builds a safe clone URL with credentials embedded for git commands,
        or returns the standard URL if no token is available or if repository is local.
        """
        if self.is_local:
            clean = self.repo_url.strip()
            if clean.startswith("file://"):
                clean = clean[7:]
            return str(Path(os.path.expanduser(clean)).resolve())

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
        if self.is_local:
            clean = self.repo_url.strip()
            if clean.startswith("file://"):
                clean = clean[7:]
            return str(Path(os.path.expanduser(clean)).resolve())
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

