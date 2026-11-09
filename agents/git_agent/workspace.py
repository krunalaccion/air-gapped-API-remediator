"""
Git Workspace Manager for handling local repository operations:
cloning, branching, staging, committing, and pushing changes.
"""

from __future__ import annotations
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Tuple

logger = logging.getLogger("git_agent.workspace")


class GitCommandError(RuntimeError):
    """Exception raised when a git command fails."""
    def __init__(self, command: str, exit_code: int, stdout: str, stderr: str):
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"Git command failed [exit {exit_code}]: {command}\n"
            f"STDOUT: {stdout.strip()}\n"
            f"STDERR: {stderr.strip()}"
        )


class GitWorkspace:
    """Manages the local filesystem workspace and git CLI execution."""

    def __init__(
        self,
        workspace_dir: Optional[str] = None,
        author_name: str = "Git SubAgent",
        author_email: str = "git-agent@subagent.local",
        token_to_scrub: Optional[str] = None,
    ):
        self._is_temp = workspace_dir is None
        self.workspace_dir = Path(workspace_dir or tempfile.mkdtemp(prefix="git_agent_workspace_")).resolve()
        self.author_name = author_name
        self.author_email = author_email
        self.token_to_scrub = token_to_scrub
        self.current_feature_branch: Optional[str] = None
        self.base_branch: Optional[str] = None

    def _scrub(self, text: str) -> str:
        """Strip sensitive credentials from output strings."""
        if not self.token_to_scrub or not text:
            return text
        return text.replace(self.token_to_scrub, "********")

    def run_git(
        self,
        args: List[str],
        cwd: Optional[Path] = None,
        check: bool = True,
        env: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute a git command safely in the workspace directory.
        Returns (exit_code, stdout, stderr).
        """
        target_cwd = cwd or self.workspace_dir
        cmd = ["git"] + args
        cmd_str = self._scrub(" ".join(cmd))

        git_env = os.environ.copy()
        git_env["GIT_TERMINAL_PROMPT"] = "0"  # Prevent git from hanging waiting for interactive auth
        # Inject author and committer purely via environment variables to avoid modifying any git config
        if self.author_name:
            git_env["GIT_AUTHOR_NAME"] = self.author_name
            git_env["GIT_COMMITTER_NAME"] = self.author_name
        if self.author_email:
            git_env["GIT_AUTHOR_EMAIL"] = self.author_email
            git_env["GIT_COMMITTER_EMAIL"] = self.author_email

        if env:
            git_env.update(env)

        logger.debug("Executing git command: %s in %s", cmd_str, target_cwd)

        proc = subprocess.run(
            cmd,
            cwd=str(target_cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=git_env,
        )

        stdout = self._scrub(proc.stdout)
        stderr = self._scrub(proc.stderr)

        if check and proc.returncode != 0:
            raise GitCommandError(
                command=cmd_str,
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
            )

        return proc.returncode, stdout, stderr

    def clone(self, clone_url: str, depth: Optional[int] = None) -> None:
        """Clone repository into the workspace directory without modifying any git configs."""
        if (self.workspace_dir / ".git").exists():
            logger.info("Workspace %s is already a git repository", self.workspace_dir)
            code, remotes_out, _ = self.run_git(["remote"], check=False)
            if "origin" in [r.strip() for r in remotes_out.splitlines()]:
                logger.info("Fetching latest changes from origin")
                self.run_git(["-c", "credential.helper=", "fetch", "origin"], check=False)
            return

        # Ensure parent directory exists
        self.workspace_dir.parent.mkdir(parents=True, exist_ok=True)

        args = ["-c", "credential.helper=", "clone"]
        if depth:
            args.extend(["--depth", str(depth)])
        args.extend([clone_url, str(self.workspace_dir)])

        # Run clone in parent directory
        self.run_git(args, cwd=self.workspace_dir.parent)

    def configure_author(self) -> None:
        """No-op: author and credentials are configured ephemerally per command/env to avoid modifying git configs."""
        pass

    def detect_default_branch(self) -> str:
        """Detect default branch ('main' or 'master') from remote HEAD, remote branches, or local branches."""
        # 1. Try reading origin/HEAD
        code, out, _ = self.run_git(["symbolic-ref", "refs/remotes/origin/HEAD"], check=False)
        if code == 0 and out.strip():
            ref = out.strip()
            # e.g., 'refs/remotes/origin/main' -> 'main'
            return ref.split("/")[-1]

        # 2. Check if 'main' or 'master' exists in remotes
        code, out, _ = self.run_git(["branch", "-r"], check=False)
        if code == 0:
            remotes = [b.strip() for b in out.splitlines()]
            if "origin/main" in remotes:
                return "main"
            if "origin/master" in remotes:
                return "master"

        # 3. Check if 'main' or 'master' exists in local branches
        code, out, _ = self.run_git(["branch"], check=False)
        if code == 0:
            local_branches = [b.strip().lstrip("* ") for b in out.splitlines()]
            if "main" in local_branches:
                return "main"
            if "master" in local_branches:
                return "master"

        # 4. Fallback to current branch or 'main'
        curr = self.get_current_branch()
        return curr if curr and curr != "HEAD" else "main"

    def checkout_and_pull_base(self, base_branch: str) -> str:
        """
        Checkout base branch and pull latest changes from remote.
        Gracefully resolves remote tracking branch or falls back to detected default branch (e.g. master/main).
        Returns the resolved base branch name.
        """
        # 1. Try direct checkout
        code, _, _ = self.run_git(["checkout", base_branch], check=False)
        if code != 0:
            # 2. Try checking out tracking branch from remote
            code, _, _ = self.run_git(["checkout", "-b", base_branch, f"origin/{base_branch}"], check=False)

        if code != 0:
            # 3. Fallback: requested 'main' but repo default might be 'master' (or vice-versa)
            fallback = self.detect_default_branch()
            logger.warning(
                "Requested base branch '%s' not found. Falling back to default branch '%s'",
                base_branch,
                fallback,
            )
            code, _, _ = self.run_git(["checkout", fallback], check=False)
            if code == 0:
                base_branch = fallback
            else:
                curr = self.get_current_branch()
                if curr and curr != "HEAD":
                    base_branch = curr

        self.base_branch = base_branch
        # Pull latest changes if remote 'origin' exists
        code, remotes_out, _ = self.run_git(["remote"], check=False)
        if "origin" in [r.strip() for r in remotes_out.splitlines()]:
            self.run_git(["pull", "origin", self.base_branch], check=False)
        return self.base_branch

    def create_feature_branch(self, branch_name: str) -> str:
        """Create and checkout a new feature branch."""
        # Check if branch already exists locally
        code, _, _ = self.run_git(["checkout", "-b", branch_name], check=False)
        if code != 0:
            # If already exists, switch to it
            self.run_git(["checkout", branch_name])

        self.current_feature_branch = branch_name
        return branch_name

    def get_current_branch(self) -> str:
        """Return the currently checked-out branch name."""
        code, out, _ = self.run_git(["rev-parse", "--abbrev-ref", "HEAD"], check=False)
        if code == 0 and out.strip() and out.strip() != "HEAD":
            return out.strip()
        code, out, _ = self.run_git(["symbolic-ref", "--short", "HEAD"], check=False)
        if code == 0 and out.strip():
            return out.strip()
        return self.current_feature_branch or self.base_branch or "main"

    def status(self) -> Dict[str, List[str]]:
        """
        Return parsed git status containing staged, modified, untracked, and deleted files.
        """
        _, out, _ = self.run_git(["status", "--porcelain"])
        staged: List[str] = []
        modified: List[str] = []
        untracked: List[str] = []
        deleted: List[str] = []

        for line in out.splitlines():
            if not line:
                continue
            index_status = line[0]
            work_tree_status = line[1]
            path = line[3:].strip()

            if index_status in ("M", "A", "R", "C"):
                staged.append(path)
            elif index_status == "D":
                deleted.append(path)

            if work_tree_status == "M":
                modified.append(path)
            elif work_tree_status == "D":
                deleted.append(path)
            elif index_status == "?" and work_tree_status == "?":
                untracked.append(path)

        return {
            "branch": [self.get_current_branch()],
            "staged": staged,
            "modified": modified,
            "untracked": untracked,
            "deleted": deleted,
        }

    def has_changes(self) -> bool:
        """Check if there are any changes (modified, untracked, or staged)."""
        stat = self.status()
        return bool(stat["staged"] or stat["modified"] or stat["untracked"] or stat["deleted"])

    def diff(self, staged: bool = False) -> str:
        """Return git diff for unstaged or staged changes."""
        args = ["diff", "--cached"] if staged else ["diff"]
        _, out, _ = self.run_git(args)
        return out

    def add(self, files: Optional[List[str]] = None) -> None:
        """Stage specific files or all changes."""
        if files:
            self.run_git(["add", "--"] + files)
        else:
            self.run_git(["add", "-A"])

    def commit(
        self,
        message: str,
        author_name: Optional[str] = None,
        author_email: Optional[str] = None,
    ) -> str:
        """
        Commit staged changes and return commit hash.
        """
        base_args = ["-c", "commit.gpgsign=false", "commit"]
        if author_name and author_email:
            args = base_args + [
                f"--author={author_name} <{author_email}>",
                "-m",
                message,
            ]
        else:
            args = base_args + ["-m", message]

        self.run_git(args)
        _, hash_out, _ = self.run_git(["rev-parse", "HEAD"])
        return hash_out.strip()

    def push(
        self,
        branch: Optional[str] = None,
        remote: str = "origin",
        force: bool = False,
        push_url: Optional[str] = None,
    ) -> None:
        """
        Push current branch or specified branch to remote.
        If push_url is provided, pushes directly to the authenticated URL without modifying git configs.
        Gracefully handles local repositories where push destination is the workspace itself or no remote exists.
        """
        target_branch = branch or self.current_feature_branch or self.get_current_branch()

        # If push_url is given, check if it points to self (same directory)
        if push_url:
            try:
                if Path(push_url).resolve() == self.workspace_dir.resolve():
                    logger.info("Push destination is local workspace; branch '%s' is already local", target_branch)
                    return
            except Exception:
                pass

        target_destination = push_url if push_url else remote
        # If target destination is a simple remote name (like 'origin'), check if that remote exists
        if not push_url or not (push_url.startswith("http://") or push_url.startswith("https://") or push_url.startswith("git@") or "/" in push_url):
            code, remotes_out, _ = self.run_git(["remote"], check=False)
            remotes = [r.strip() for r in remotes_out.splitlines()]
            if target_destination not in remotes:
                logger.info(
                    "No remote '%s' configured; changes remain safely committed to local branch '%s'",
                    target_destination,
                    target_branch,
                )
                return

        # If push_url is a local directory path and equals workspace_dir
        try:
            dest_path = Path(target_destination).resolve()
            if dest_path == self.workspace_dir.resolve():
                logger.info("Push destination is local workspace; branch '%s' is already local", target_branch)
                return
        except Exception:
            pass

        # Pass credential.helper= to ensure only the token in the URL is used
        args = ["-c", "credential.helper=", "push", "-u", target_destination, target_branch]
        if force:
            args.append("--force")

        self.run_git(args)

    def cleanup(self) -> None:
        """Remove temporary directory if created as temporary."""
        if self._is_temp and self.workspace_dir.exists():
            shutil.rmtree(self.workspace_dir, ignore_errors=True)
