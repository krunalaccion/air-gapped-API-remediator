"""
Integration tests for GitWorkspace using a local bare repository as the remote.
Tests cloning, branching, modifying, diffing, committing, and pushing.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from agents.git_agent.workspace import GitWorkspace


class TestGitWorkspace(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory containing a bare repo (acting as 'origin')
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_git_env_"))
        self.remote_dir = self.temp_dir / "remote_repo.git"
        self.workspace_dir = self.temp_dir / "local_repo"

        # 1. Initialize bare repo
        subprocess.run(["git", "init", "--bare", str(self.remote_dir)], check=True, capture_output=True)

        # 2. Seed the bare repo with an initial commit on 'main'
        seed_dir = self.temp_dir / "seed"
        subprocess.run(["git", "clone", str(self.remote_dir), str(seed_dir)], check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(seed_dir), check=True)
        subprocess.run(["git", "config", "user.email", "tester@test.com"], cwd=str(seed_dir), check=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=str(seed_dir), check=True)

        (seed_dir / "README.md").write_text("# Hello World\nInitial repo content.\n")
        subprocess.run(["git", "add", "README.md"], cwd=str(seed_dir), check=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-m", "Initial commit"], cwd=str(seed_dir), check=True)
        # Ensure default branch is main
        subprocess.run(["git", "branch", "-M", "main"], cwd=str(seed_dir), check=True)
        subprocess.run(["git", "push", "-u", "origin", "main"], cwd=str(seed_dir), check=True)
        # Update bare remote's HEAD to point to main
        subprocess.run(["git", "symbolic-ref", "HEAD", "refs/heads/main"], cwd=str(self.remote_dir), check=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_clone_and_branch_workflow(self):
        ws = GitWorkspace(workspace_dir=str(self.workspace_dir))

        # 1. Clone
        ws.clone(str(self.remote_dir))
        self.assertTrue((self.workspace_dir / ".git").exists())
        self.assertTrue((self.workspace_dir / "README.md").exists())

        # 2. Detect default branch
        default_br = ws.detect_default_branch()
        self.assertEqual(default_br, "main")

        # 3. Checkout base
        ws.checkout_and_pull_base("main")
        self.assertEqual(ws.get_current_branch(), "main")

        # 4. Create feature branch
        ws.create_feature_branch("security-patch-1")
        self.assertEqual(ws.get_current_branch(), "security-patch-1")

        # 5. Check no changes initially
        self.assertFalse(ws.has_changes())

        # 6. Simulate security fix (modify README and create FIX.txt)
        (self.workspace_dir / "README.md").write_text("# Hello World\nSecured repo content.\n")
        (self.workspace_dir / "FIX.txt").write_text("Vulnerability resolved.")

        self.assertTrue(ws.has_changes())
        stat = ws.status()
        self.assertIn("README.md", stat["modified"])
        self.assertIn("FIX.txt", stat["untracked"])

        # 7. Check diff
        diff_text = ws.diff()
        self.assertIn("-Initial repo content.", diff_text)
        self.assertIn("+Secured repo content.", diff_text)

        # 8. Add and commit
        ws.add()
        commit_hash = ws.commit("fix: resolve security flaw")
        self.assertTrue(len(commit_hash) >= 7)
        self.assertFalse(ws.has_changes())

        # 9. Push feature branch to remote
        ws.push(branch="security-patch-1")

        # 10. Verify remote has the new branch
        out = subprocess.run(
            ["git", "branch", "-r"],
            cwd=str(self.workspace_dir),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertIn("origin/security-patch-1", out)


if __name__ == "__main__":
    unittest.main()
