"""
Remediator Agent package.
Includes both Air-Gap RemediatorAgent and Automated BugFixerAgent (`fixer_agent.py`, `llm_client.py`, `models.py`, `tools.py`).
"""

from agents.remediator_agent.agent import RemediatorAgent, DEFAULT_SQLI_FINDING
from agents.remediator_agent.fixer_agent import BugFixerAgent
from agents.remediator_agent.llm_client import CloudLLMClient
from agents.remediator_agent.models import Finding, FixProposal, FixReport
from agents.remediator_agent.tools import RepositoryTools

__all__ = [
    "RemediatorAgent",
    "BugFixerAgent",
    "CloudLLMClient",
    "Finding",
    "FixProposal",
    "FixReport",
    "RepositoryTools",
    "DEFAULT_SQLI_FINDING",
]
