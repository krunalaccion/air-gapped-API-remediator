"""
LangGraph / Tool-Calling Multi-Agent integration adapter for GitSubAgent.
Provides tool wrappers and state helpers for injecting GitSubAgent into LangGraph graphs or ReAct agent loops.
"""

from __future__ import annotations
from typing import Dict, Any, Optional, List
from git_agent.agent import GitSubAgent
from git_agent.config import GitAgentConfig


def create_git_subagent_tools(config: GitAgentConfig) -> List[Any]:
    """
    Returns a collection of tool functions ready for LangChain / LangGraph bind_tools().
    """
    subagent = GitSubAgent(config)

    def git_prepare_workspace(feature_branch: Optional[str] = None) -> str:
        """
        Clones the configured repository, pulls main/master, and creates a feature branch
        for vulnerability scanning and remediation. Returns local repo path.
        """
        ctx = subagent.prepare_workspace(feature_branch=feature_branch)
        return f"Workspace prepared at: {ctx.repo_path} on branch: {ctx.feature_branch}"

    def git_check_status() -> str:
        """
        Checks the status of files modified or created during vulnerability analysis.
        """
        status = subagent.get_status()
        return str(status)

    def git_finalize_and_open_pr(
        commit_message: str,
        pr_title: str,
        pr_description: str,
    ) -> str:
        """
        Commits all security fixes, pushes the branch to GitHub/GitLab, and creates a Pull Request.
        """
        res = subagent.finalize_workspace(
            commit_message=commit_message,
            pr_title=pr_title,
            pr_body=pr_description,
        )
        return f"PR Status: {res.status}. PR URL: {res.pr.url if res.pr else 'None'}"

    return [
        git_prepare_workspace,
        git_check_status,
        git_finalize_and_open_pr,
    ]

