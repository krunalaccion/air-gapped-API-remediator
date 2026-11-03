"""
Repository hosting providers for Git SubAgent.
"""

from typing import Union
try:
    from ..config import GitAgentConfig, ProviderType
    from .base import GitProvider, PullRequestResult
    from .github import GitHubProvider
    from .gitlab import GitLabProvider
    from .local import LocalProvider
except (ImportError, ValueError):
    from agents.git_agent.config import GitAgentConfig, ProviderType
    from agents.git_agent.providers.base import GitProvider, PullRequestResult
    from agents.git_agent.providers.github import GitHubProvider
    from agents.git_agent.providers.gitlab import GitLabProvider
    from agents.git_agent.providers.local import LocalProvider


def get_provider(config: GitAgentConfig) -> GitProvider:
    """Factory to instantiate the appropriate provider for the configuration."""
    if config.provider == ProviderType.GITHUB:
        return GitHubProvider(config)
    elif config.provider == ProviderType.GITLAB:
        return GitLabProvider(config)
    elif config.provider == ProviderType.LOCAL:
        return LocalProvider(config)
    else:
        # Fall back to URL inspection or GitHub default
        lower_url = config.repo_url.lower()
        if getattr(config, "is_local", False):
            return LocalProvider(config)
        elif "gitlab" in lower_url:
            return GitLabProvider(config)
        elif "github" in lower_url:
            return GitHubProvider(config)
        raise ValueError(
            f"Unsupported or unrecognized git provider for URL: '{config.sanitized_repo_url}'. "
            f"Please specify provider='github', provider='gitlab', or provider='local' in GitAgentConfig."
        )


__all__ = [
    "GitProvider",
    "PullRequestResult",
    "GitHubProvider",
    "GitLabProvider",
    "LocalProvider",
    "get_provider",
]

