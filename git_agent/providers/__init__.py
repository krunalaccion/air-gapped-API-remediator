"""
Repository hosting providers for Git SubAgent.
"""

from typing import Union
from git_agent.config import GitAgentConfig, ProviderType
from git_agent.providers.base import GitProvider, PullRequestResult
from git_agent.providers.github import GitHubProvider
from git_agent.providers.gitlab import GitLabProvider


def get_provider(config: GitAgentConfig) -> GitProvider:
    """Factory to instantiate the appropriate provider for the configuration."""
    if config.provider == ProviderType.GITHUB:
        return GitHubProvider(config)
    elif config.provider == ProviderType.GITLAB:
        return GitLabProvider(config)
    else:
        # Fall back to URL inspection or GitHub default
        lower_url = config.repo_url.lower()
        if "gitlab" in lower_url:
            return GitLabProvider(config)
        elif "github" in lower_url:
            return GitHubProvider(config)
        raise ValueError(
            f"Unsupported or unrecognized git provider for URL: '{config.sanitized_repo_url}'. "
            f"Please specify provider='github' or provider='gitlab' in GitAgentConfig."
        )


__all__ = [
    "GitProvider",
    "PullRequestResult",
    "GitHubProvider",
    "GitLabProvider",
    "get_provider",
]

