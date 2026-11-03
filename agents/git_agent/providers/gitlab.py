"""
GitLab repository provider implementation for Git SubAgent.
Uses GitLab REST API (v4) to query project metadata, default branch, and create Merge Requests.
"""

from __future__ import annotations
import json
import re
from typing import Optional, Dict, Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

try:
    from ..config import GitAgentConfig
    from .base import GitProvider, PullRequestResult
except (ImportError, ValueError):
    from agents.git_agent.config import GitAgentConfig
    from agents.git_agent.providers.base import GitProvider, PullRequestResult


class GitLabProvider(GitProvider):
    """Provider for GitLab.com and self-hosted GitLab instances."""

    def __init__(self, config: GitAgentConfig):
        self.config = config
        self.api_base = (config.api_base_url or "https://gitlab.com/api/v4").rstrip("/")
        self.project_path = self._parse_project_path(config.repo_url)
        # URL-encode the project namespace/path for GitLab API v4: e.g. group/subgroup/project -> group%2Fsubgroup%2Fproject
        self.project_id = quote(self.project_path, safe="")

    def _parse_project_path(self, url: str) -> str:
        """Extracts namespaced project path (e.g., 'group/project' or 'group/subgroup/repo') from URL."""
        url = url.strip()

        # Handle numeric project ID or direct path
        if url.isdigit():
            return url

        # Handle SSH format: git@gitlab.com:group/subgroup/repo.git
        ssh_match = re.match(r"^git@[^:]+:(.+?)(?:\.git)?$", url)
        if ssh_match:
            return ssh_match.group(1).strip("/")

        # Handle HTTP/HTTPS URLs
        parsed = urlparse(url)
        path = parsed.path.strip("/")
        if path.endswith(".git"):
            path = path[:-4]

        if path:
            return path

        raise ValueError(f"Could not parse GitLab project path from URL: '{url}'")

    def _make_request(
        self,
        endpoint: str,
        method: str = "GET",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Perform an authenticated HTTP request against GitLab REST API."""
        url = f"{self.api_base}/{endpoint.lstrip('/')}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "GitAgent-SubAgent",
        }

        if self.config.token:
            headers["PRIVATE-TOKEN"] = self.config.token

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
                f"GitLab API Error [{e.code} {e.reason}] for {method} {url}: {msg}"
            ) from e
        except URLError as e:
            raise RuntimeError(f"Network error connecting to GitLab API: {e.reason}") from e

    def verify_access(self) -> bool:
        """Verify project exists and is accessible."""
        try:
            proj_info = self._make_request(f"projects/{self.project_id}")
            return "name" in proj_info
        except Exception:
            return False

    def get_default_branch(self) -> str:
        """Fetch default branch from GitLab project metadata."""
        proj_info = self._make_request(f"projects/{self.project_id}")
        return proj_info.get("default_branch", "main")

    def create_pull_request(
        self,
        head_branch: str,
        base_branch: str,
        title: str,
        description: str,
        draft: bool = False,
    ) -> PullRequestResult:
        """Create a Merge Request on GitLab."""
        mr_title = f"Draft: {title}" if draft and not title.startswith("Draft:") else title

        payload = {
            "source_branch": head_branch,
            "target_branch": base_branch,
            "title": mr_title,
            "description": description,
        }

        resp = self._make_request(
            f"projects/{self.project_id}/merge_requests",
            method="POST",
            payload=payload,
        )

        return PullRequestResult(
            id=str(resp.get("id")),
            number=resp.get("iid", 0),  # In GitLab, 'iid' is the project-scoped MR number
            url=resp.get("web_url", ""),
            title=resp.get("title", title),
            head_branch=head_branch,
            base_branch=base_branch,
            provider="gitlab",
            draft=draft,
            raw_response=resp,
        )

