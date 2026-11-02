"""
Configurable Git SubAgent & MCP Server.
"""

from git_agent.config import GitAgentConfig, ProviderType
from git_agent.agent import GitSubAgent, WorkspaceContext, FinalizeResult
from git_agent.providers import GitProvider, PullRequestResult, GitHubProvider, GitLabProvider, get_provider
from git_agent.workspace import GitWorkspace, GitCommandError
from git_agent.mcp_server import GitAgentMCPServer

__version__ = "0.1.0"

__all__ = [
    "GitAgentConfig",
    "ProviderType",
    "GitSubAgent",
    "WorkspaceContext",
    "FinalizeResult",
    "GitProvider",
    "PullRequestResult",
    "GitHubProvider",
    "GitLabProvider",
    "get_provider",
    "GitWorkspace",
    "GitCommandError",
    "GitAgentMCPServer",
]
