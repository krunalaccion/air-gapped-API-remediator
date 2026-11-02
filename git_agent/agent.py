"""
GitSubAgent - Configurable subagent designed for injection into multi-agent systems.
Manages repository lifecycle: cloning, branching for audits, committing fixes, and raising PR/MRs.
"""

from __future__ import annotations
import datetime
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any

from git_agent.config import GitAgentConfig, ProviderType
from git_agent.providers import get_provider, GitProvider, PullRequestResult
from git_agent.workspace import GitWorkspace

logger = logging.getLogger("git_agent.subagent")


@dataclass
class WorkspaceContext:
    """Context object returned when a workspace is prepared for downstream agents."""
    repo_path: Path
    base_branch: str
    feature_branch: str
    provider: str
    repo_url: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo_path": str(self.repo_path),
            "base_branch": self.base_branch,
            "feature_branch": self.feature_branch,
            "provider": self.provider,
            "repo_url": self.repo_url,
            "metadata": self.metadata,
        }


@dataclass
class FinalizeResult:
    """Result returned after committing changes and creating a PR/MR."""
    status: str  # "success", "no_changes", or "error"
    commit_hash: Optional[str] = None
    pr: Optional[PullRequestResult] = None
    message: str = ""
    diff_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "commit_hash": self.commit_hash,
            "pr_url": self.pr.url if self.pr else None,
            "pr_number": self.pr.number if self.pr else None,
            "pr_title": self.pr.title if self.pr else None,
            "head_branch": self.pr.head_branch if self.pr else None,
            "base_branch": self.pr.base_branch if self.pr else None,
            "message": self.message,
            "diff_summary": self.diff_summary,
        }


class GitSubAgent:
    """
    Subagent for multi-agent architectures.
    
    Typical Multi-Agent Lifecycle:
      1. Main Orchestrator invokes: `context = git_subagent.prepare_workspace()`
      2. Vulnerability / Audit Agent scans `context.repo_path` and writes patches/fixes.
      3. Main Orchestrator invokes: `result = git_subagent.finalize_workspace(commit_message=..., pr_title=...)`
    """

    def __init__(self, config: GitAgentConfig):
        self.config = config
        self.provider: Optional[GitProvider] = None
        self._init_provider()

        self.workspace = GitWorkspace(
            workspace_dir=config.workspace_dir,
            author_name=config.author_name,
            author_email=config.author_email,
            token_to_scrub=config.token,
        )
        self.context: Optional[WorkspaceContext] = None

    def _init_provider(self) -> None:
        """Initialize repository provider (GitHub / GitLab)."""
        try:
            self.provider = get_provider(self.config)
        except Exception as e:
            logger.warning("Could not initialize provider: %s. PR operations will require explicit provider.", e)
            self.provider = None

    @classmethod
    def from_url_and_token(
        cls,
        repo_url: str,
        token: Optional[str] = None,
        base_branch: Optional[str] = None,
        feature_branch_name: Optional[str] = None,
        workspace_dir: Optional[str] = None,
        **kwargs,
    ) -> GitSubAgent:
        """Convenience constructor from basic repository parameters."""
        config = GitAgentConfig(
            repo_url=repo_url,
            token=token,
            base_branch=base_branch,
            feature_branch_name=feature_branch_name,
            workspace_dir=workspace_dir,
            **kwargs,
        )
        return cls(config)

    def prepare_workspace(
        self,
        feature_branch: Optional[str] = None,
        base_branch: Optional[str] = None,
    ) -> WorkspaceContext:
        """
        Step 1: Clones repository, pulls base branch (main/master), and creates feature branch.
        Prepares the repository for vulnerability scanning or modifications.
        """
        logger.info("Preparing workspace for repo: %s", self.config.sanitized_repo_url)

        # 1. Clone repository
        clone_url = self.config.authenticated_clone_url
        self.workspace.clone(clone_url)

        # 2. Determine base branch (configured, from provider API, or from remote git)
        target_base = base_branch or self.config.base_branch
        if not target_base or target_base.lower() == "auto":
            if self.provider:
                try:
                    target_base = self.provider.get_default_branch()
                    logger.info("Provider detected default branch: %s", target_base)
                except Exception as e:
                    logger.warning("Provider default branch lookup failed: %s; inspecting git remote", e)
                    target_base = self.workspace.detect_default_branch()
            else:
                target_base = self.workspace.detect_default_branch()

        if not target_base:
            target_base = "main"

        # 3. Checkout and pull base branch
        logger.info("Checking out and pulling base branch: %s", target_base)
        self.workspace.checkout_and_pull_base(target_base)

        # 4. Generate and checkout feature branch
        target_feature = feature_branch or self.config.feature_branch_name
        if not target_feature:
            ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            target_feature = f"{self.config.feature_branch_prefix}{ts}"

        logger.info("Creating and switching to feature branch: %s", target_feature)
        self.workspace.create_feature_branch(target_feature)

        # 5. Build WorkspaceContext
        self.context = WorkspaceContext(
            repo_path=self.workspace.workspace_dir,
            base_branch=target_base,
            feature_branch=target_feature,
            provider=self.config.provider.value,
            repo_url=self.config.sanitized_repo_url,
            metadata={
                "author_name": self.config.author_name,
                "author_email": self.config.author_email,
            },
        )
        return self.context

    def get_workspace_path(self) -> Path:
        """Returns the local Path where files are checked out."""
        return self.workspace.workspace_dir

    def get_status(self) -> Dict[str, Any]:
        """Inspects status of files in the workspace."""
        return self.workspace.status()

    def get_diff(self, staged: bool = False) -> str:
        """Returns git diff of changes made by other agents."""
        return self.workspace.diff(staged=staged)

    def finalize_workspace(
        self,
        commit_message: Optional[str] = None,
        pr_title: Optional[str] = None,
        pr_body: Optional[str] = None,
        files: Optional[List[str]] = None,
        draft: Optional[bool] = None,
    ) -> FinalizeResult:
        """
        Step 2: Commits changes made by vulnerability scanners or downstream agents,
        pushes feature branch, and opens a Pull Request or Merge Request.
        """
        if not self.context:
            raise RuntimeError("Workspace has not been prepared yet. Call prepare_workspace() first.")

        # 1. Check for changes
        if not self.workspace.has_changes():
            logger.info("No modifications detected in workspace.")
            return FinalizeResult(
                status="no_changes",
                message="No file changes found in workspace. Commit and PR skipped.",
            )

        # 2. Get diff summary
        diff_summary = self.workspace.diff()[:2000]  # First 2000 chars

        # 3. Stage changes
        logger.info("Staging changes in workspace")
        self.workspace.add(files)

        # 4. Commit changes
        msg = commit_message or "fix(security): resolve vulnerabilities detected during audit"
        logger.info("Committing changes with message: %s", msg)
        commit_hash = self.workspace.commit(
            message=msg,
            author_name=self.config.author_name,
            author_email=self.config.author_email,
        )

        # 5. Push to remote
        logger.info("Pushing feature branch '%s' to remote", self.context.feature_branch)
        self.workspace.push(
            branch=self.context.feature_branch,
            push_url=self.config.authenticated_clone_url,
        )

        # 6. Raise Pull Request / Merge Request
        if not self.provider:
            raise RuntimeError(
                "No provider configured (e.g. GitHub or GitLab). Cannot create Pull Request automatically."
            )

        title = pr_title or self.config.default_pr_title
        body = pr_body or self.config.default_pr_body
        is_draft = draft if draft is not None else self.config.draft_pr

        logger.info(
            "Creating %s PR/MR: head='%s', base='%s', title='%s'",
            self.config.provider.value,
            self.context.feature_branch,
            self.context.base_branch,
            title,
        )

        pr_result = self.provider.create_pull_request(
            head_branch=self.context.feature_branch,
            base_branch=self.context.base_branch,
            title=title,
            description=body,
            draft=is_draft,
        )

        logger.info("PR/MR created successfully: %s", pr_result.url)

        return FinalizeResult(
            status="success",
            commit_hash=commit_hash,
            pr=pr_result,
            message=f"Successfully committed {commit_hash[:7]} and opened PR #{pr_result.number}: {pr_result.url}",
            diff_summary=diff_summary,
        )

    def cleanup(self) -> None:
        """Clean up temporary workspace if needed."""
        self.workspace.cleanup()
