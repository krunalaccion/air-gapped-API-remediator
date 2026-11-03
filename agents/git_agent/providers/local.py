"""
Local filesystem Git repository provider for offline and local repositories.
Supports local default branch detection, repository validation, and local review/PR generation.
"""

from __future__ import annotations
import datetime
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List

try:
    from ..config import GitAgentConfig
    from .base import GitProvider, PullRequestResult
except (ImportError, ValueError):
    from agents.git_agent.config import GitAgentConfig
    from agents.git_agent.providers.base import GitProvider, PullRequestResult

logger = logging.getLogger("git_agent.providers.local")


class LocalProvider(GitProvider):
    """
    Provider for local repositories on disk without requiring remote API access.
    Generates local pull request reviews and tracking manifests in .git/local_prs.
    """

    def __init__(self, config: GitAgentConfig):
        self.config = config
        clean_url = config.repo_url.strip()
        if clean_url.startswith("file://"):
            clean_url = clean_url[7:]
        self.repo_path = Path(os.path.expanduser(clean_url)).resolve()

    def _run_git(self, args: List[str], cwd: Optional[Path] = None) -> tuple[int, str, str]:
        """Execute git command in the repo directory."""
        target_dir = cwd or self.repo_path
        if not target_dir.exists():
            return 1, "", f"Directory does not exist: {target_dir}"
        cmd = ["git"] + args
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(target_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        except Exception as e:
            return 1, "", str(e)

    def verify_access(self) -> bool:
        """Verify that the local repository path exists and is a valid git repository."""
        if not self.repo_path.exists():
            return False
        # Normal repository with .git directory
        if (self.repo_path / ".git").exists():
            return True
        # Bare repository (HEAD and objects directory present)
        if (self.repo_path / "HEAD").exists() and (self.repo_path / "objects").exists():
            return True
        # Check via git rev-parse
        code, out, _ = self._run_git(["rev-parse", "--is-inside-work-tree"])
        if code == 0 and out.lower() == "true":
            return True
        code, out, _ = self._run_git(["rev-parse", "--is-bare-repository"])
        if code == 0 and out.lower() == "true":
            return True
        return False

    def get_default_branch(self) -> str:
        """
        Determine default branch (e.g. 'main' or 'master') of the local repository.
        """
        if self.config.base_branch and self.config.base_branch.lower() != "auto":
            return self.config.base_branch

        if not self.verify_access():
            return "main"

        # 1. Try origin/HEAD if a remote exists
        code, out, _ = self._run_git(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
        if code == 0 and out:
            # e.g., 'origin/main' -> 'main'
            return out.split("/")[-1]

        # 2. Check if local 'main' branch exists
        code, out, _ = self._run_git(["show-ref", "--verify", "--quiet", "refs/heads/main"])
        if code == 0:
            return "main"

        # 3. Check if local 'master' branch exists
        code, out, _ = self._run_git(["show-ref", "--verify", "--quiet", "refs/heads/master"])
        if code == 0:
            return "master"

        # 4. Check current active branch
        code, out, _ = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"])
        if code == 0 and out and out != "HEAD":
            return out

        # 5. Check git config init.defaultBranch
        code, out, _ = self._run_git(["config", "init.defaultBranch"])
        if code == 0 and out:
            return out

        return "main"

    def create_pull_request(
        self,
        head_branch: str,
        base_branch: str,
        title: str,
        description: str,
        draft: bool = False,
    ) -> PullRequestResult:
        """
        Create a local Pull Request review record and markdown summary.
        Stored under .git/local_prs/ (or .local_prs/ if bare or .git inaccessible).
        """
        # Determine destination directory for local PR records
        target_base = self.repo_path
        if (target_base / ".git").is_dir():
            prs_dir = target_base / ".git" / "local_prs"
        else:
            prs_dir = target_base / ".local_prs"

        try:
            prs_dir.mkdir(parents=True, exist_ok=True)
            existing_prs = list(prs_dir.glob("PR-*.json"))
            pr_number = len(existing_prs) + 1
        except Exception:
            pr_number = 1
            prs_dir = Path("/tmp") / f"local_prs_{int(datetime.datetime.now().timestamp())}"
            prs_dir.mkdir(parents=True, exist_ok=True)

        pr_id = f"local-pr-{pr_number}"
        pr_file_md = prs_dir / f"PR-{pr_number}.md"
        pr_file_json = prs_dir / f"PR-{pr_number}.json"
        now_iso = datetime.datetime.now().isoformat()

        # Build markdown report
        md_content = (
            f"# Local Pull Request #{pr_number}: {title}\n\n"
            f"- **Repository**: `{self.repo_path}`\n"
            f"- **Head Branch**: `{head_branch}`\n"
            f"- **Base Branch**: `{base_branch}`\n"
            f"- **Status**: {'Draft' if draft else 'Open'}\n"
            f"- **Provider**: Local Git Repository\n"
            f"- **Created At**: {now_iso}\n\n"
            f"## Description\n\n"
            f"{description}\n"
        )

        # Write markdown and json records
        try:
            pr_file_md.write_text(md_content, encoding="utf-8")
            raw_meta = {
                "id": pr_id,
                "number": pr_number,
                "title": title,
                "description": description,
                "head_branch": head_branch,
                "base_branch": base_branch,
                "draft": draft,
                "created_at": now_iso,
                "repo_path": str(self.repo_path),
                "md_file": str(pr_file_md.resolve()),
            }
            pr_file_json.write_text(json.dumps(raw_meta, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning("Could not write local PR files to %s: %s", prs_dir, e)
            raw_meta = {
                "id": pr_id,
                "number": pr_number,
                "title": title,
                "description": description,
                "head_branch": head_branch,
                "base_branch": base_branch,
                "draft": draft,
                "created_at": now_iso,
                "repo_path": str(self.repo_path),
            }

        url = f"file://{pr_file_md.resolve()}"

        return PullRequestResult(
            id=pr_id,
            number=pr_number,
            url=url,
            title=title,
            head_branch=head_branch,
            base_branch=base_branch,
            provider="local",
            draft=draft,
            raw_response=raw_meta,
        )
