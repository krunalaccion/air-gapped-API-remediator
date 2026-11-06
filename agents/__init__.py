"""
Multi-Agent System Package.
Provides specialized subagents for repository management, security scanning,
and air-gapped API & bug remediation, coordinated via a unified orchestrator and web UI.
"""

from agents.base import BaseAgent, AgentRegistry
from agents.git_agent.agent import GitSubAgent, WorkspaceContext, FinalizeResult
from agents.scanner_agent.agent import ScannerAgent
from agents.remediator_agent import (
    RemediatorAgent,
    BugFixerAgent,
    CloudLLMClient,
    Finding,
    FixProposal,
    FixReport,
    RepositoryTools,
    DEFAULT_SQLI_FINDING,
)

# Auto-register core agents in central registry
AgentRegistry.register("scanner", ScannerAgent())
AgentRegistry.register("remediator", RemediatorAgent())

__all__ = [
    "BaseAgent",
    "AgentRegistry",
    "GitSubAgent",
    "WorkspaceContext",
    "FinalizeResult",
    "ScannerAgent",
    "RemediatorAgent",
    "BugFixerAgent",
    "CloudLLMClient",
    "Finding",
    "FixProposal",
    "FixReport",
    "RepositoryTools",
    "DEFAULT_SQLI_FINDING",
]
