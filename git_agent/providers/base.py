"""
Base interface and data models for Git repository hosting providers (GitHub, GitLab).
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class PullRequestResult:
    """Standardized result returned when a PR/MR is created."""
    id: str
    number: int
    url: str
    title: str
    head_branch: str
    base_branch: str
    provider: str
    draft: bool = False
    raw_response: Optional[Dict[str, Any]] = None

    def __str__(self) -> str:
        return f"[{self.provider.upper()}] PR/MR #{self.number}: {self.title} -> {self.url}"


class GitProvider(ABC):
    """Abstract provider interface for repository platform operations."""

    @abstractmethod
    def get_default_branch(self) -> str:
        """
        Query provider API to determine repository's default branch (e.g., 'main' or 'master').
        """
        pass

    @abstractmethod
    def create_pull_request(
        self,
        head_branch: str,
        base_branch: str,
        title: str,
        description: str,
        draft: bool = False,
    ) -> PullRequestResult:
        """
        Create a Pull Request (GitHub) or Merge Request (GitLab).
        """
        pass

    @abstractmethod
    def verify_access(self) -> bool:
        """
        Verify that repository is accessible with current credentials.
        """
        pass
