"""
GitHub repository provider implementation for Git SubAgent.
Uses GitHub REST API (v3) to query repo metadata, default branch, and create Pull Requests.
"""

from __future__ import annotations
import json
import re
from typing import Optional, Dict, Any, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from git_agent.config import GitAgentConfig
from git_agent.providers.base import GitProvider, PullRequestResult


class GitHubProvider(GitProvider):
    """Provider for GitHub.com and GitHub Enterprise."""

    def __init__(self, config: GitAgentConfig):
        self.config = config
        self.api_base = (config.api_base_url or "https://api.github.com").rstrip("/")
        self.owner, self.repo = self._parse_owner_repo(config.repo_url)

    def _parse_owner_repo(self, url: str) -> Tuple[str, str]:
        """Extracts owner and repo name from various GitHub URL formats."""
        url = url.strip()

        # Handle simple "owner/repo" shorthand
        if re.match(r"^[\w.-]+/[\w.-]+$", url):
            owner, repo = url.split("/")
            return owner, repo.removesuffix(".git")

        # Handle SSH format: git@github.com:owner/repo.git
        ssh_match = re.match(r"^git@[^:]+:([^/]+)/(.+?)(?:\.git)?$", url)
        if ssh_match:
            return ssh_match.group(1), ssh_match.group(2)

        # Handle HTTP/HTTPS URLs
        parsed = urlparse(url)
        path = parsed.path.strip("/")
        parts = path.split("/")
        if len(parts) >= 2:
            owner = parts[0]
            repo = parts[1].removesuffix(".git")
            return owner, repo

        raise ValueError(f"Could not parse GitHub owner/repo from URL: '{url}'")

    def _make_request(
        self,
        endpoint: str,
        method: str = "GET",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Perform an authenticated HTTP request against GitHub REST API."""
        url = f"{self.api_base}/{endpoint.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "GitAgent-SubAgent",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"

        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = Request(url, data=data, headers=headers, method=method)

        try:
            with urlopen(req, timeout=30) as resp:
                resp_data = resp.read().decode("utf-8")
                return json.loads(resp_data) if resp_data else {}
        except HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            try:
                err_json = json.loads(err_body)
                msg = err_json.get("message", err_body)
            except Exception:
                msg = err_body
            raise RuntimeError(
                f"GitHub API Error [{e.code} {e.reason}] for {method} {url}: {msg}"
            ) from e
        except URLError as e:
            raise RuntimeError(f"Network error connecting to GitHub API: {e.reason}") from e

    def verify_access(self) -> bool:
        """Verify repository exists and is accessible."""
        try:
            repo_info = self._make_request(f"repos/{self.owner}/{self.repo}")
            return "name" in repo_info
        except Exception:
            return False

    def get_default_branch(self) -> str:
        """Fetch the default branch ('main' or 'master') from the repository."""
        repo_info = self._make_request(f"repos/{self.owner}/{self.repo}")
        return repo_info.get("default_branch", "main")

    def create_pull_request(
        self,
        head_branch: str,
        base_branch: str,
        title: str,
        description: str,
        draft: bool = False,
    ) -> PullRequestResult:
        """Create a Pull Request on GitHub."""
        payload = {
            "title": title,
            "body": description,
            "head": head_branch,
            "base": base_branch,
            "draft": draft,
        }

        resp = self._make_request(
            f"repos/{self.owner}/{self.repo}/pulls",
            method="POST",
            payload=payload,
        )

        return PullRequestResult(
            id=str(resp.get("id")),
            number=resp.get("number", 0),
            url=resp.get("html_url", ""),
            title=resp.get("title", title),
            head_branch=head_branch,
            base_branch=base_branch,
            provider="github",
            draft=resp.get("draft", draft),
            raw_response=resp,
        )
