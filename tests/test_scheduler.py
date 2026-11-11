"""
Unit and integration tests for the Background Batch Repository Scheduler
and its REST API endpoints + web page (/scheduler).
"""

import datetime as dt
import io
import json
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from orchestrator.scheduler import (
    BatchScheduler,
    CronExpression,
    compute_next_run_at,
    discover_repositories,
    local_now,
    validate_schedule_payload,
)
from web_server import MultiAgentAPIHandler, get_web_dir


def _init_git_repo(repo_dir: Path, files: dict[str, str], branch: str = "main") -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", branch], cwd=str(repo_dir), check=True, capture_output=True)
    for rel, content in files.items():
        fpath = repo_dir / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-c", "commit.gpgsign=false",
            "-c", "user.name=Test",
            "-c", "user.email=test@test.local",
            "commit", "-m", "chore: initial commit",
        ],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )


class TestBatchSchedulerEngine(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_sched_"))
        self.repos_parent = self.temp_dir / "workspace_folder"
        self.repos_parent.mkdir(parents=True, exist_ok=True)
        self.data_dir = self.temp_dir / "scheduler_data"
        self.scheduler = None

    def tearDown(self):
        if self.scheduler:
            self.scheduler.stop(timeout=3.0)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cron_parser_and_schedule_calculations(self):
        cron = CronExpression("*/15 2 * * 1-5")
        # Saturday 2026-11-07 10:00 -> next Monday 2026-11-09 02:00
        tz = local_now().tzinfo
        sat = dt.datetime(2026, 11, 7, 10, 0, tzinfo=tz)
        nxt = cron.next_after(sat)
        self.assertEqual(nxt.year, 2026)
        self.assertEqual(nxt.month, 11)
        self.assertEqual(nxt.day, 9)
        self.assertEqual(nxt.hour, 2)
        self.assertEqual(nxt.minute, 0)

        with self.assertRaises(ValueError):
            CronExpression("invalid cron")

        # Daily rollover
        daily_sched = {"enabled": True, "schedule_type": "daily", "time_of_day": "08:30"}
        before = dt.datetime(2026, 11, 10, 9, 0, tzinfo=tz)
        nxt_daily = dt.datetime.fromisoformat(compute_next_run_at(daily_sched, after=before))
        self.assertEqual(nxt_daily.day, 11)
        self.assertEqual(nxt_daily.hour, 8)
        self.assertEqual(nxt_daily.minute, 30)

        # Weekly
        weekly_sched = {"enabled": True, "schedule_type": "weekly", "days_of_week": ["wed"], "time_of_day": "03:00"}
        tue = dt.datetime(2026, 11, 10, 10, 0, tzinfo=tz)  # Tuesday
        nxt_weekly = dt.datetime.fromisoformat(compute_next_run_at(weekly_sched, after=tue))
        self.assertEqual(nxt_weekly.weekday(), 2)  # Wednesday
        self.assertEqual(nxt_weekly.hour, 3)

    def test_discover_repositories_and_self_protection(self):
        repo_a = self.repos_parent / "alpha_service"
        repo_b = self.repos_parent / "beta_service"
        nested_parent = self.repos_parent / "team_group"
        nested_repo = nested_parent / "gamma_service"
        plain_dir = self.repos_parent / "plain_project"
        protected_dir = self.repos_parent / "protected_agent_root"

        _init_git_repo(repo_a, {"app.py": "print('a')\n"})
        _init_git_repo(repo_b, {"app.py": "print('b')\n"})
        _init_git_repo(nested_repo, {"app.py": "print('gamma')\n"})
        _init_git_repo(protected_dir, {"app.py": "print('agent')\n"})
        plain_dir.mkdir(parents=True, exist_ok=True)
        (plain_dir / "main.py").write_text("print('plain')\n", encoding="utf-8")

        # Non-recursive, git-only
        res = discover_repositories(
            self.repos_parent,
            include_non_git=False,
            recursive=False,
            app_root_dir=protected_dir,
        )
        names = [r["name"] for r in res["repos"]]
        self.assertEqual(names, ["alpha_service", "beta_service"])
        self.assertNotIn("protected_agent_root", names)

        # Recursive + include non-git
        res_rec = discover_repositories(
            self.repos_parent,
            include_non_git=True,
            recursive=True,
            app_root_dir=protected_dir,
        )
        rel_paths = [r["relative_path"] for r in res_rec["repos"]]
        self.assertEqual(
            rel_paths,
            ["alpha_service", "beta_service", "plain_project", "team_group/gamma_service"],
        )

    def test_sequential_background_execution_across_multiple_repos(self):
        repo1 = self.repos_parent / "01_py_egress"
        repo2 = self.repos_parent / "02_node_api"
        repo3 = self.repos_parent / "03_clean_repo"

        _init_git_repo(
            repo1,
            {"client.py": 'import requests\nrequests.get("https://api.external-cloud.com/v1/telemetry")\n'},
        )
        _init_git_repo(
            repo2,
            {
                "package.json": json.dumps({"name": "node-app", "dependencies": {"express": "^4.19.2"}}),
                "src/app.js": (
                    "const express = require('express');\n"
                    "const cors = require('cors');\n"
                    "const app = express();\n"
                    "app.use(cors({ origin: '*', credentials: true }));\n"
                    "module.exports = app;\n"
                ),
            },
        )
        _init_git_repo(repo3, {"README.md": "# Clean Repo\n"})

        self.scheduler = BatchScheduler(
            data_dir=self.data_dir,
            app_root_dir=self.temp_dir / "dummy_agent_root",
            auto_start=True,
            poll_interval_seconds=0.2,
        )

        created = self.scheduler.create_schedule({
            "name": "Multi-Repo Batch Audit",
            "folder_path": str(self.repos_parent),
            "schedule_type": "interval",
            "interval_minutes": 30,
            "scanner_engine": "all",
            "llm_provider": "auto-fallback",
            "base_branch": "auto",
            "feature_branch": "remediation/scheduled-audit",
            "run_build_test": False,
            "auto_commit": True,
            "auto_pr": True,
            "run_immediately": True,
        })
        run_id = created["triggered_run"]["run_id"]

        # Wait up to 30 seconds for background worker to process all 3 repos one by one
        deadline = time.time() + 30.0
        detail = None
        while time.time() < deadline:
            detail = self.scheduler.get_run_detail(run_id)
            if detail and detail.get("status") in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "CANCELLED"):
                break
            time.sleep(0.2)

        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], "COMPLETED")
        self.assertEqual(detail["total_repos"], 3)
        self.assertEqual(detail["completed_repos"], 3)
        self.assertEqual(detail["succeeded_repos"], 3)
        self.assertEqual(detail["failed_repos"], 0)
        self.assertEqual(detail["progress_percent"], 100)

        repos = detail["repos"]
        self.assertEqual([r["name"] for r in repos], ["01_py_egress", "02_node_api", "03_clean_repo"])

        # Verify strict sequential one-by-one execution timestamps
        t0_end = dt.datetime.fromisoformat(repos[0]["finished_at"])
        t1_start = dt.datetime.fromisoformat(repos[1]["started_at"])
        t1_end = dt.datetime.fromisoformat(repos[1]["finished_at"])
        t2_start = dt.datetime.fromisoformat(repos[2]["started_at"])
        self.assertLessEqual(t0_end, t1_start)
        self.assertLessEqual(t1_end, t2_start)

        # Verify repo1 & repo2 were actually remediated, committed, and given local PRs
        self.assertGreaterEqual(repos[0]["initial_findings_count"], 1)
        self.assertEqual(repos[0]["post_findings_count"], 0)
        self.assertTrue(repos[0]["resolved_all"])
        self.assertIsNotNone(repos[0]["commit_hash"])
        self.assertTrue(Path(repos[0]["pr_file_path"]).exists())
        self.assertTrue(Path(repos[0]["remediation_report_path"]).exists())
        self.assertTrue(Path(repos[0]["scan_report_path"]).exists())

        self.assertGreaterEqual(repos[1]["initial_findings_count"], 1)
        self.assertEqual(repos[1]["post_findings_count"], 0)
        self.assertTrue(repos[1]["resolved_all"])
        self.assertIsNotNone(repos[1]["commit_hash"])

        # Verify reports can be served via get_repo_report and never pollute with CustomerApi
        html_rep, ctype = self.scheduler.get_repo_report(run_id, "0", "remediation")
        self.assertIn("text/html", ctype)
        self.assertIn("REMEDIATION", html_rep.upper())
        scan_rep, s_ctype = self.scheduler.get_repo_report(run_id, "0", "scan")
        self.assertIn("text/html", s_ctype)
        self.assertIn("01_py_egress", scan_rep)
        self.assertNotIn("CustomerApi", scan_rep)

    def test_automatic_due_schedule_fires_in_background_and_persists_across_restart(self):
        repo = self.repos_parent / "auto_repo"
        _init_git_repo(repo, {"app.py": 'import requests\nrequests.get("https://api.external-cloud.com/ping")\n'})

        self.scheduler = BatchScheduler(
            data_dir=self.data_dir,
            app_root_dir=self.temp_dir / "dummy_agent_root",
            auto_start=True,
            poll_interval_seconds=0.2,
        )

        # Schedule "once" 1 second ago so the background ticker fires it automatically
        past_iso = (local_now() - dt.timedelta(seconds=1)).isoformat()
        res = self.scheduler.create_schedule({
            "name": "One-Shot Background Trigger",
            "folder_path": str(self.repos_parent),
            "schedule_type": "once",
            "run_at": past_iso,
            "llm_provider": "auto-fallback",
            "run_build_test": False,
        })
        sched_id = res["schedule"]["id"]

        deadline = time.time() + 25.0
        sched_state = None
        while time.time() < deadline:
            sched_state = self.scheduler.get_schedule(sched_id)
            if sched_state and sched_state.get("last_run_status") == "COMPLETED":
                break
            time.sleep(0.2)

        self.assertIsNotNone(sched_state)
        self.assertEqual(sched_state["last_run_status"], "COMPLETED")
        self.assertFalse(sched_state["enabled"])  # Once schedule disables after triggering

        # Stop and reload a fresh BatchScheduler from disk to confirm persistence
        self.scheduler.stop(timeout=3.0)
        reloaded = BatchScheduler(
            data_dir=self.data_dir,
            app_root_dir=self.temp_dir / "dummy_agent_root",
            auto_start=False,
        )
        self.assertEqual(len(reloaded.list_schedules()), 1)
        self.assertEqual(len(reloaded.list_runs()), 1)
        self.assertEqual(reloaded.list_runs()[0]["status"], "COMPLETED")

    def test_scheduler_continues_after_repo_failure(self):
        bad_repo = self.repos_parent / "01_broken_git"
        bad_repo.mkdir(parents=True)
        # Create fake .git folder that causes git commands to fail
        (bad_repo / ".git").write_text("not a valid git dir", encoding="utf-8")

        good_repo = self.repos_parent / "02_good_repo"
        _init_git_repo(good_repo, {"svc.py": 'import requests\nrequests.post("https://api.external-cloud.com/send")\n'})

        self.scheduler = BatchScheduler(
            data_dir=self.data_dir,
            app_root_dir=self.temp_dir / "dummy_agent_root",
            auto_start=True,
            poll_interval_seconds=0.2,
        )
        res = self.scheduler.create_schedule({
            "name": "Resilience Test",
            "folder_path": str(self.repos_parent),
            "schedule_type": "interval",
            "interval_minutes": 15,
            "llm_provider": "auto-fallback",
            "run_build_test": False,
            "run_immediately": True,
        })
        run_id = res["triggered_run"]["run_id"]

        deadline = time.time() + 25.0
        detail = None
        while time.time() < deadline:
            detail = self.scheduler.get_run_detail(run_id)
            if detail and detail.get("status") in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"):
                break
            time.sleep(0.2)

        self.assertEqual(detail["status"], "COMPLETED_WITH_ERRORS")
        self.assertEqual(detail["failed_repos"], 1)
        self.assertEqual(detail["succeeded_repos"], 1)
        self.assertEqual(detail["repos"][0]["status"], "FAILED")
        self.assertEqual(detail["repos"][1]["status"], "COMPLETED")

    def test_fast_cancellation_during_slow_llm_call(self):
        from agents.remediator_agent.llm_client import CloudLLMClient

        repo = self.repos_parent / "01_slow_llm_repo"
        _init_git_repo(
            repo,
            {
                "svc1.py": 'import requests\nrequests.get("https://api.external-cloud.com/1")\n',
                "svc2.py": 'import requests\nrequests.get("https://api.external-cloud.com/2")\n',
            },
        )
        repo2 = self.repos_parent / "02_second_repo"
        _init_git_repo(repo2, {"app.py": "print('ok')\n"})

        entered_llm = []

        def slow_http_post(*args, **kwargs):
            entered_llm.append(True)
            time.sleep(8.0)
            return {"message": {"content": "{}"}}

        self.scheduler = BatchScheduler(
            data_dir=self.data_dir,
            app_root_dir=self.temp_dir / "dummy_agent_root",
            auto_start=True,
            poll_interval_seconds=0.2,
        )

        with patch.object(CloudLLMClient, "_http_post", side_effect=slow_http_post):
            res = self.scheduler.create_schedule({
                "name": "Fast Cancel Test",
                "folder_path": str(self.repos_parent),
                "schedule_type": "interval",
                "interval_minutes": 15,
                "llm_provider": "ollama",
                "run_build_test": False,
                "run_immediately": True,
            })
            run_id = res["triggered_run"]["run_id"]

            # Wait until worker enters slow LLM call in REMEDIATE
            wait_deadline = time.time() + 10.0
            while time.time() < wait_deadline and not entered_llm:
                time.sleep(0.05)
            self.assertTrue(entered_llm, "Worker did not enter LLM call in time")

            # Verify post_findings_count is None while remediation hasn't completed post-scan yet
            mid_detail = self.scheduler.get_run_detail(run_id)
            self.assertIsNone(mid_detail["repos"][0]["post_findings_count"])

            cancel_started = time.monotonic()
            can_res = self.scheduler.cancel_run(run_id)
            self.assertEqual(can_res["status"], "CANCELLING")

            # Should cancel far faster than the 8s sleep
            done_deadline = time.time() + 3.0
            detail = None
            while time.time() < done_deadline:
                detail = self.scheduler.get_run_detail(run_id)
                if detail and detail.get("status") == "CANCELLED":
                    break
                time.sleep(0.05)

            elapsed = time.monotonic() - cancel_started
            self.assertIsNotNone(detail)
            self.assertEqual(detail["status"], "CANCELLED")
            self.assertLess(elapsed, 2.0, f"Cancel took too long: {elapsed:.2f}s")
            self.assertEqual(detail["repos"][0]["status"], "CANCELLED")
            self.assertEqual(detail["repos"][1]["status"], "CANCELLED")

    def test_live_modified_files_progress_during_remediation(self):
        from agents.remediator_agent.agent import RemediatorAgent

        repo = self.repos_parent / "live_mod_repo"
        _init_git_repo(
            repo,
            {
                "a.py": 'import requests\nrequests.get("https://api.external-cloud.com/a")\n',
                "b.py": 'import requests\nrequests.get("https://api.external-cloud.com/b")\n',
            },
        )

        observed_mid_modified = []
        orig_fix_finding = RemediatorAgent.fix_finding

        def instrumented_fix(self_rem, *args, **kwargs):
            res = orig_fix_finding(self_rem, *args, **kwargs)
            # Slow slightly on second finding so we can inspect persisted run_detail mid-iteration
            time.sleep(0.1)
            return res

        self.scheduler = BatchScheduler(
            data_dir=self.data_dir,
            app_root_dir=self.temp_dir / "dummy_agent_root",
            auto_start=True,
            poll_interval_seconds=0.2,
        )

        with patch.object(RemediatorAgent, "fix_finding", instrumented_fix):
            res = self.scheduler.create_schedule({
                "name": "Live Modified Progress",
                "folder_path": str(self.repos_parent),
                "schedule_type": "interval",
                "interval_minutes": 15,
                "llm_provider": "auto-fallback",
                "run_build_test": False,
                "run_immediately": True,
            })
            run_id = res["triggered_run"]["run_id"]

            deadline = time.time() + 15.0
            while time.time() < deadline:
                detail = self.scheduler.get_run_detail(run_id)
                if detail and detail.get("repos"):
                    r0 = detail["repos"][0]
                    if r0.get("status") == "RUNNING" and len(r0.get("files_modified") or []) > 0:
                        observed_mid_modified.append(list(r0["files_modified"]))
                if detail and detail.get("status") == "COMPLETED":
                    break
                time.sleep(0.05)

        self.assertTrue(len(observed_mid_modified) > 0, "Expected non-empty files_modified while RUNNING")
        self.assertEqual(detail["status"], "COMPLETED")
        self.assertGreaterEqual(len(detail["repos"][0]["files_modified"]), 2)

    def test_scheduler_always_branches_from_main_or_master(self):
        # Repo 1: has 'main', currently left dirty on an old 'remediation/airgap-api-compliance' branch
        repo_main = self.repos_parent / "01_repo_with_main"
        _init_git_repo(repo_main, {"app.py": 'import requests\nrequests.get("https://api.external-cloud.com/v1")\n'}, branch="main")
        # Create an old remediation branch with stale file and dirty edit
        subprocess.run(["git", "checkout", "-b", "remediation/airgap-api-compliance"], cwd=str(repo_main), check=True, capture_output=True)
        (repo_main / "stale_marker.txt").write_text("stale\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo_main), check=True, capture_output=True)
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "old remediation"],
            cwd=str(repo_main),
            check=True,
            capture_output=True,
        )
        # Add an uncommitted leftover change on old remediation branch
        (repo_main / "app.py").write_text("# dirty aborted edit\n", encoding="utf-8")
        # Advance 'main' with a new file so we verify the fresh remediation branch starts from 'main'
        subprocess.run(["git", "checkout", "-f", "main"], cwd=str(repo_main), check=True, capture_output=True)
        (repo_main / "new_on_main.py").write_text('import requests\nrequests.get("https://api.external-cloud.com/new")\n', encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo_main), check=True, capture_output=True)
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "advance main"],
            cwd=str(repo_main),
            check=True,
            capture_output=True,
        )
        # Switch back to dirty old remediation branch before scheduler runs
        subprocess.run(["git", "checkout", "remediation/airgap-api-compliance"], cwd=str(repo_main), check=True, capture_output=True)
        (repo_main / "uncommitted_aborted.tmp").write_text("dirty\n", encoding="utf-8")

        # Repo 2: has 'master' only, currently checked out on 'feature/wip'
        repo_master = self.repos_parent / "02_repo_with_master"
        _init_git_repo(repo_master, {"svc.py": 'import requests\nrequests.post("https://api.external-cloud.com/m")\n'}, branch="master")
        subprocess.run(["git", "checkout", "-b", "feature/wip"], cwd=str(repo_master), check=True, capture_output=True)
        (repo_master / "wip_only.txt").write_text("wip\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo_master), check=True, capture_output=True)
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "wip"],
            cwd=str(repo_master),
            check=True,
            capture_output=True,
        )

        # Repo 3: has ONLY 'develop' (neither main nor master) -> must fail clearly rather than running on develop
        repo_develop = self.repos_parent / "03_repo_develop_only"
        _init_git_repo(repo_develop, {"dev.py": "print('dev')\n"}, branch="develop")

        self.scheduler = BatchScheduler(
            data_dir=self.data_dir,
            app_root_dir=self.temp_dir / "dummy_agent_root",
            auto_start=True,
            poll_interval_seconds=0.2,
        )
        res = self.scheduler.create_schedule({
            "name": "Strict Main/Master Test",
            "folder_path": str(self.repos_parent),
            "schedule_type": "interval",
            "interval_minutes": 15,
            "llm_provider": "auto-fallback",
            "base_branch": "auto",
            "feature_branch": "remediation/airgap-api-compliance",
            "run_build_test": False,
            "run_immediately": True,
        })
        run_id = res["triggered_run"]["run_id"]

        deadline = time.time() + 30.0
        detail = None
        while time.time() < deadline:
            detail = self.scheduler.get_run_detail(run_id)
            if detail and detail.get("status") in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"):
                break
            time.sleep(0.2)

        self.assertEqual(detail["status"], "COMPLETED_WITH_ERRORS")
        repos = detail["repos"]

        # Repo 1 ran from 'main', reset remediation branch onto 'main' (has new_on_main.py, lacks stale_marker.txt)
        self.assertEqual(repos[0]["status"], "COMPLETED")
        self.assertEqual(repos[0]["base_branch"], "main")
        self.assertEqual(repos[0]["feature_branch"], "remediation/airgap-api-compliance")
        self.assertTrue((repo_main / "new_on_main.py").exists())
        self.assertFalse((repo_main / "stale_marker.txt").exists())
        self.assertFalse((repo_main / "uncommitted_aborted.tmp").exists())
        self.assertEqual(repos[0]["post_findings_count"], 0)

        # Repo 2 ran from 'master', not 'feature/wip' (lacks wip_only.txt)
        self.assertEqual(repos[1]["status"], "COMPLETED")
        self.assertEqual(repos[1]["base_branch"], "master")
        self.assertFalse((repo_master / "wip_only.txt").exists())
        self.assertEqual(repos[1]["post_findings_count"], 0)

        # Repo 3 rejected because neither 'main' nor 'master' exists
        self.assertEqual(repos[2]["status"], "FAILED")
        self.assertIn("main", repos[2]["error"].lower())
        self.assertIn("master", repos[2]["error"].lower())

    def test_scheduler_emails_reports_after_each_repo_and_respects_toggle(self):
        repo_a = self.repos_parent / "01_email_repo_a"
        repo_b = self.repos_parent / "02_email_repo_b"
        _init_git_repo(repo_a, {"app.py": 'import requests\nrequests.get("https://api.external-cloud.com/a")\n'})
        _init_git_repo(repo_b, {"README.md": "# Clean Service\n"})

        from orchestrator.email_notifier import EmailReportNotifier

        notifier = EmailReportNotifier(app_root_dir=self.temp_dir / "dummy_agent_root")
        notifier.update_config({"recipient_emails": "default-secops@example.com", "smtp_host": ""})

        self.scheduler = BatchScheduler(
            data_dir=self.data_dir,
            app_root_dir=self.temp_dir / "dummy_agent_root",
            auto_start=True,
            poll_interval_seconds=0.2,
            email_notifier=notifier,
        )

        # Spy on send_remediation_report_email while keeping real outbox behavior
        calls = []
        orig_send = notifier.send_remediation_report_email

        def spy_send(**kwargs):
            calls.append(kwargs)
            return orig_send(**kwargs)

        with patch.object(notifier, "send_remediation_report_email", side_effect=spy_send):
            created = self.scheduler.create_schedule({
                "name": "Batch With Per-Repo Email",
                "folder_path": str(self.repos_parent),
                "schedule_type": "interval",
                "interval_minutes": 60,
                "llm_provider": "auto-fallback",
                "run_build_test": False,
                "send_email": True,
                "email_recipients": "team-lead@example.com, secops@example.com",
                "run_immediately": True,
            })
            run_id = created["triggered_run"]["run_id"]

            deadline = time.time() + 30.0
            detail = None
            while time.time() < deadline:
                detail = self.scheduler.get_run_detail(run_id)
                if detail and detail.get("status") in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"):
                    break
                time.sleep(0.2)

        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], "COMPLETED")
        self.assertEqual(len(calls), 2)
        self.assertEqual([c["repo_name"] for c in calls], ["01_email_repo_a", "02_email_repo_b"])
        for c in calls:
            self.assertEqual(c["trigger_source"], "scheduler_repo_completed")
            self.assertEqual(c["override_recipients"], "team-lead@example.com, secops@example.com")
            self.assertTrue(c["remediation_html"])
            self.assertTrue(c["scan_html"])
            self.assertTrue(c["remediation_json"])

        for repo_res in detail["repos"]:
            self.assertEqual(repo_res["email_status"], "saved_to_outbox")
            self.assertEqual(repo_res["email_recipients"], ["team-lead@example.com", "secops@example.com"])
            self.assertTrue(repo_res["email_outbox_file"])

        # Now verify send_email=False skips emailing and email errors do not fail repo completion
        calls.clear()
        with patch.object(notifier, "send_remediation_report_email", side_effect=spy_send):
            created_skip = self.scheduler.create_schedule({
                "name": "Batch Email Disabled",
                "folder_path": str(self.repos_parent),
                "schedule_type": "interval",
                "interval_minutes": 60,
                "llm_provider": "auto-fallback",
                "run_build_test": False,
                "send_email": False,
                "run_immediately": True,
            })
            run_id_skip = created_skip["triggered_run"]["run_id"]

            deadline = time.time() + 30.0
            detail_skip = None
            while time.time() < deadline:
                detail_skip = self.scheduler.get_run_detail(run_id_skip)
                if detail_skip and detail_skip.get("status") in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"):
                    break
                time.sleep(0.2)

        self.assertEqual(detail_skip["status"], "COMPLETED")
        self.assertEqual(len(calls), 0)
        for repo_res in detail_skip["repos"]:
            self.assertEqual(repo_res["email_status"], "skipped")

        # Verify email exception does not fail the batch run
        with patch.object(notifier, "send_remediation_report_email", side_effect=RuntimeError("SMTP unreachable")):
            created_err = self.scheduler.create_schedule({
                "name": "Batch Email Error Resilience",
                "folder_path": str(self.repos_parent),
                "schedule_type": "interval",
                "interval_minutes": 60,
                "llm_provider": "auto-fallback",
                "run_build_test": False,
                "send_email": True,
                "run_immediately": True,
            })
            run_id_err = created_err["triggered_run"]["run_id"]

            deadline = time.time() + 30.0
            detail_err = None
            while time.time() < deadline:
                detail_err = self.scheduler.get_run_detail(run_id_err)
                if detail_err and detail_err.get("status") in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"):
                    break
                time.sleep(0.2)

        self.assertEqual(detail_err["status"], "COMPLETED")
        for repo_res in detail_err["repos"]:
            self.assertEqual(repo_res["email_status"], "error")
            self.assertIn("SMTP unreachable", repo_res["email_message"])

    def test_scheduler_pushes_local_folder_repos_with_masked_auth(self):
        # Create a bare remote and clone it into the scheduled local folder
        bare_remote = self.temp_dir / "bare_origin.git"
        subprocess.run(["git", "init", "--bare", str(bare_remote)], check=True, capture_output=True)
        seed = self.temp_dir / "seed"
        subprocess.run(["git", "clone", str(bare_remote), str(seed)], check=True, capture_output=True)
        (seed / "client.py").write_text('import requests\nrequests.get("https://api.external-cloud.com/push")\n')
        subprocess.run(["git", "add", "-A"], cwd=str(seed), check=True, capture_output=True)
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "init"],
            cwd=str(seed), check=True, capture_output=True,
        )
        subprocess.run(["git", "branch", "-M", "main"], cwd=str(seed), check=True, capture_output=True)
        subprocess.run(["git", "push", "-u", "origin", "main"], cwd=str(seed), check=True, capture_output=True)
        subprocess.run(["git", "symbolic-ref", "HEAD", "refs/heads/main"], cwd=str(bare_remote), check=True, capture_output=True)

        local_clone = self.repos_parent / "local_with_remote"
        subprocess.run(["git", "clone", str(bare_remote), str(local_clone)], check=True, capture_output=True)

        self.scheduler = BatchScheduler(
            data_dir=self.data_dir,
            app_root_dir=self.temp_dir / "dummy_agent_root",
            auto_start=True,
            poll_interval_seconds=0.2,
        )

        created = self.scheduler.create_schedule({
            "name": "Local Folder Push With Auth",
            "folder_path": str(self.repos_parent),
            "schedule_type": "interval",
            "interval_minutes": 60,
            "llm_provider": "auto-fallback",
            "feature_branch": "remediation/sched-push-branch",
            "run_build_test": False,
            "auto_commit": True,
            "auto_push": True,
            "auto_pr": True,
            "git_token": "ghp_superSecretSchedToken1234",
            "git_username": "secops-bot",
            "send_email": False,
            "run_immediately": True,
        })

        # Token must be masked in public schedule view and run snapshot
        pub_sched = created["schedule"]
        self.assertTrue(pub_sched["has_git_token"])
        self.assertEqual(pub_sched["git_token"], "********")
        self.assertEqual(pub_sched["git_username"], "secops-bot")
        self.assertTrue(pub_sched["auto_push"])

        run_id = created["triggered_run"]["run_id"]
        deadline = time.time() + 30.0
        detail = None
        while time.time() < deadline:
            detail = self.scheduler.get_run_detail(run_id)
            if detail and detail.get("status") in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"):
                break
            time.sleep(0.2)

        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], "COMPLETED")
        self.assertEqual(detail["schedule_snapshot"]["git_token"], "********")
        repo_res = detail["repos"][0]
        self.assertEqual(repo_res["push_status"], "pushed")
        self.assertIn("bare_origin.git", repo_res["remote_url"])

        # Verify the branch actually reached the remote repository
        remote_branches = subprocess.run(
            ["git", "branch", "--list", "remediation/sched-push-branch"],
            cwd=str(bare_remote),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertIn("remediation/sched-push-branch", remote_branches)

        # Updating schedule with masked placeholder preserves secret; clearing removes it
        sched_id = pub_sched["id"]
        upd_preserve = self.scheduler.update_schedule(sched_id, {"name": "Renamed", "git_token": "********"})
        self.assertTrue(upd_preserve["has_git_token"])
        self.assertEqual(self.scheduler._schedules[sched_id]["git_token"], "ghp_superSecretSchedToken1234")

        upd_clear = self.scheduler.update_schedule(sched_id, {"git_token": ""})
        self.assertFalse(upd_clear["has_git_token"])
        self.assertEqual(upd_clear["git_token"], "")


class TestSchedulerWebAPI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_sched_api_"))
        self.repos_parent = self.temp_dir / "repos_root"
        self.repos_parent.mkdir(parents=True)
        _init_git_repo(self.repos_parent / "repo_one", {"app.py": 'import requests\nrequests.get("https://api.external-cloud.com/a")\n'})
        self.test_scheduler = BatchScheduler(
            data_dir=self.temp_dir / "sched_data",
            app_root_dir=self.temp_dir / "agent_root",
            auto_start=False,
        )

    def tearDown(self):
        self.test_scheduler.stop(timeout=3.0)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @staticmethod
    def _call_get_raw(path: str) -> tuple[int, bytes]:
        handler = MultiAgentAPIHandler.__new__(MultiAgentAPIHandler)
        handler.rfile = io.BytesIO(b"")
        handler.wfile = io.BytesIO()
        handler.headers = {}
        handler.path = path
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.do_GET()
        status_code = handler.send_response.call_args[0][0] if handler.send_response.call_args else 200
        return status_code, handler.wfile.getvalue()

    @staticmethod
    def _call_post(path: str, payload: dict) -> tuple[int, dict]:
        handler = MultiAgentAPIHandler.__new__(MultiAgentAPIHandler)
        body = json.dumps(payload).encode("utf-8")
        handler.rfile = io.BytesIO(body)
        handler.wfile = io.BytesIO()
        handler.headers = {"Content-Length": str(len(body))}
        handler.path = path
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.do_POST()
        status_code = handler.send_response.call_args[0][0] if handler.send_response.call_args else 200
        data = json.loads(handler.wfile.getvalue().decode("utf-8")) if handler.wfile.getvalue() else {}
        return status_code, data

    def test_scheduler_html_and_navigation_links(self):
        sched_html = get_web_dir() / "scheduler.html"
        self.assertTrue(sched_html.exists())
        status, body = self._call_get_raw("/scheduler")
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn('id="schedFolderPath"', text)
        self.assertIn('id="btnSchedulerEmailSettings"', text)
        self.assertIn('id="schedSendEmail"', text)
        self.assertIn('id="schedEmailRecipients"', text)
        self.assertIn('id="schedAutoPush"', text)
        self.assertIn('id="schedGitToken"', text)
        self.assertIn('id="schedGitUsername"', text)
        self.assertIn('id="emailReportModal"', text)
        self.assertIn("discoverReposNow", text)
        self.assertIn("submitScheduleForm", text)
        self.assertIn('id="detailReposList"', text)

        index_text = (get_web_dir() / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="/scheduler"', index_text)
        self.assertIn('id="navBatchScheduler"', index_text)
        self.assertIn('id="step4GitToken"', index_text)
        self.assertIn('id="step4GitUsername"', index_text)
        self.assertIn("syncGitAuthInputs", index_text)
        # Top-right Email Reports button removed from single repo pipeline page
        self.assertNotIn('id="btnEmailSettingsHeader"', index_text)
        # Send Report Now buttons are hidden until remediation step completes
        self.assertRegex(index_text, r'id="btnSendReportStep3"[^>]*class="hidden\b|class="hidden\b[^"]*"[^>]*id="btnSendReportStep3"')
        self.assertRegex(index_text, r'id="btnModalSendEmailNow"[^>]*class="hidden\b|class="hidden\b[^"]*"[^>]*id="btnModalSendEmailNow"')
        self.assertIn("updateSendReportButtonsVisibility", index_text)

    def test_scheduler_rest_crud_and_discovery(self):
        with patch("web_server.BATCH_SCHEDULER", self.test_scheduler):
            # Discover
            st, disc = self._call_post("/api/scheduler/discover", {"folder_path": str(self.repos_parent)})
            self.assertEqual(st, 200)
            self.assertEqual(disc["total_repos"], 1)
            self.assertEqual(disc["repos"][0]["name"], "repo_one")

            # Invalid schedule rejected
            st_bad, err_bad = self._call_post("/api/scheduler/schedules", {
                "name": "Bad",
                "folder_path": str(self.repos_parent),
                "schedule_type": "cron",
                "cron_expression": "not-a-cron",
            })
            self.assertEqual(st_bad, 400)
            self.assertIn("error", err_bad)

            # Invalid base_branch rejected (scheduler enforces auto/main/master)
            st_bad_br, err_bad_br = self._call_post("/api/scheduler/schedules", {
                "name": "Bad Branch",
                "folder_path": str(self.repos_parent),
                "schedule_type": "daily",
                "time_of_day": "02:30",
                "base_branch": "develop",
            })
            self.assertEqual(st_bad_br, 400)
            self.assertIn("main", err_bad_br.get("error", ""))

            # Invalid email_recipients rejected
            st_bad_em, err_bad_em = self._call_post("/api/scheduler/schedules", {
                "name": "Bad Email",
                "folder_path": str(self.repos_parent),
                "schedule_type": "daily",
                "time_of_day": "02:30",
                "email_recipients": "not-an-email",
            })
            self.assertEqual(st_bad_em, 400)
            self.assertIn("email", err_bad_em.get("error", "").lower())

            # Create schedule with email & git auth settings
            st_c, created = self._call_post("/api/scheduler/schedules", {
                "name": "Nightly Scan",
                "folder_path": str(self.repos_parent),
                "schedule_type": "daily",
                "time_of_day": "02:30",
                "auto_push": True,
                "git_token": "ghp_apiTokenMaskedTest999",
                "git_username": "audit-bot",
                "send_email": True,
                "email_recipients": "secops@example.com, audit@example.com",
            })
            self.assertEqual(st_c, 201)
            self.assertTrue(created["schedule"]["send_email"])
            self.assertTrue(created["schedule"]["auto_push"])
            self.assertTrue(created["schedule"]["has_git_token"])
            self.assertEqual(created["schedule"]["git_token"], "********")
            self.assertEqual(created["schedule"]["git_username"], "audit-bot")
            self.assertEqual(created["schedule"]["email_recipients"], "secops@example.com, audit@example.com")
            sched_id = created["schedule"]["id"]

            # Overview
            st_ov, raw_ov = self._call_get_raw("/api/scheduler/overview")
            self.assertEqual(st_ov, 200)
            ov = json.loads(raw_ov.decode("utf-8"))
            self.assertEqual(len(ov["schedules"]), 1)

            # Toggle pause
            st_t, tog = self._call_post("/api/scheduler/schedules/toggle", {"id": sched_id})
            self.assertEqual(st_t, 200)
            self.assertFalse(tog["schedule"]["enabled"])

            # Update schedule
            st_u, upd = self._call_post("/api/scheduler/schedules/update", {
                "id": sched_id,
                "name": "Updated Cron Scan",
                "schedule_type": "cron",
                "cron_expression": "0 3 * * 1-5",
            })
            self.assertEqual(st_u, 200)
            self.assertEqual(upd["schedule"]["name"], "Updated Cron Scan")

            # Run now & inspect queued run
            st_r, run_res = self._call_post("/api/scheduler/schedules/run-now", {"id": sched_id})
            self.assertEqual(st_r, 202)
            run_id = run_res["run"]["run_id"]

            # Cancel queued run
            st_can, can_res = self._call_post("/api/scheduler/runs/cancel", {"run_id": run_id})
            self.assertEqual(st_can, 200)
            self.assertEqual(can_res["status"], "CANCELLED")

            # Delete schedule
            st_d, del_res = self._call_post("/api/scheduler/schedules/delete", {"id": sched_id})
            self.assertEqual(st_d, 200)
            self.assertTrue(del_res["deleted"])


if __name__ == "__main__":
    unittest.main()

