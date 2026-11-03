"""
Configurable Git SubAgent & MCP Server.
"""

try:
    from .config import GitAgentConfig, ProviderType
    from .agent import GitSubAgent, WorkspaceContext, FinalizeResult
    from .providers import GitProvider, PullRequestResult, GitHubProvider, GitLabProvider, get_provider
    from .workspace import GitWorkspace, GitCommandError
    from .mcp_server import GitAgentMCPServer
except (ImportError, ValueError):
    from agents.git_agent.config import GitAgentConfig, ProviderType
    from agents.git_agent.agent import GitSubAgent, WorkspaceContext, FinalizeResult
    from agents.git_agent.providers import GitProvider, PullRequestResult, GitHubProvider, GitLabProvider, get_provider
    from agents.git_agent.workspace import GitWorkspace, GitCommandError
    from agents.git_agent.mcp_server import GitAgentMCPServer

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

