"""
Integration adapters for multi-agent architectures and frameworks.
"""

from git_agent.integrations.multi_agent_pipeline import (
    MultiAgentOrchestrator,
    MockVulnerabilityScannerAgent,
)
from git_agent.integrations.langgraph_subagent import create_git_subagent_tools

__all__ = [
    "MultiAgentOrchestrator",
    "MockVulnerabilityScannerAgent",
    "create_git_subagent_tools",
]

