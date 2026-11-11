"""
Multi-Agent Orchestrator Pipeline.
Coordinates GitSubAgent, ScannerAgent, RemediatorAgent (including BugFixerAgent), and any dynamically registered agents.
Provides unified workflows for air-gapped API scanning, SAST/bug remediation, and automated PR delivery.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from agents.base import AgentRegistry
from agents.git_agent.agent import GitSubAgent, WorkspaceContext, FinalizeResult
from agents.git_agent.config import GitAgentConfig
from agents.scanner_agent.agent import ScannerAgent
from agents.remediator_agent.agent import RemediatorAgent
from orchestrator.email_notifier import EmailReportNotifier

logger = logging.getLogger("orchestrator.pipeline")


class MultiAgentPipeline:
    """
    Coordinates execution of multi-agent tasks across the repository lifecycle:
    1. GitSubAgent: clones & provisions feature branch
    2. ScannerAgent: scans for external API egress & security violations
    3. RemediatorAgent: generates internal proxy routing, audit manifests & runs BugFixerAgent patches
    4. GitSubAgent: commits remediations & creates Pull Request
    """

    def __init__(
        self,
        git_config: GitAgentConfig,
        scanner: Optional[ScannerAgent] = None,
        remediator: Optional[RemediatorAgent] = None,
    ):
        self.git_agent = GitSubAgent(git_config)
        self.scanner = scanner or ScannerAgent()
        self.remediator = remediator or RemediatorAgent()

        # Register in central registry
        AgentRegistry.register("git", self.git_agent)
        AgentRegistry.register("scanner", self.scanner)
        AgentRegistry.register("remediator", self.remediator)

    def run_remediation_pipeline(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes end-to-end Air-Gapped API & Bug Remediator pipeline:
        1. Setup: GitSubAgent prepares repository & creates feature branch.
        2. Scan: ScannerAgent detects external outbound egress & air-gap violations.
        3. Fix: RemediatorAgent applies proxy configs, offline mocks, and BugFixerAgent SAST patches.
        4. Finalize: GitSubAgent commits changes and raises Pull Request.
        """
        logger.info("=== STEP 1: GitSubAgent Prepares Remediation Workspace ===")
        ctx: WorkspaceContext = self.git_agent.prepare_workspace()
        logger.info("Workspace ready at %s on branch '%s'", ctx.repo_path, ctx.feature_branch)

        build_test_result = {}
        try:
            build_test_result = self.git_agent.build_and_test()
            logger.info("Build & Unit Test Verification completed: %s", build_test_result.get("summary"))
        except Exception as bt_exc:
            logger.warning("Build & test execution failed: %s", bt_exc)
            build_test_result = {"executed": False, "error": str(bt_exc)}

        logger.info("=== STEP 2: ScannerAgent Scans for Egress Violations ===")
        scan_result = self.scanner.run({"workspace_path": str(ctx.repo_path)})
        findings = scan_result.get("findings", [])
        logger.info("Scan completed. Detected %d airgap policy findings.", len(findings))

        logger.info("=== STEP 3: RemediatorAgent Applies Air-Gap & BugFixer Remediations (Iterative Loop) ===")
        max_iterations = 5
        iteration = 0
        fix_result = {}
        post_scan = {}
        files_modified: List[str] = []

        while iteration < max_iterations:
            iteration += 1
            logger.info("[Iterative Remediation] Starting iteration %d of %d for workspace: %s", iteration, max_iterations, ctx.repo_path)
            fix_result = self.remediator.run({
                "workspace_path": str(ctx.repo_path),
                "provider": provider,
                "model": model,
                "base_url": base_url,
            })
            for mod_f in fix_result.get("files_modified", []):
                if mod_f not in files_modified:
                    files_modified.append(mod_f)

            # Verification scan to confirm residual threats
            post_scan = self.scanner.run({
                "workspace_path": str(ctx.repo_path),
                "is_post_scan": True,
            })
            residual_findings = post_scan.get("findings") if post_scan.get("findings") is not None else (post_scan.get("bug_findings") or [])
            residual_count = len(residual_findings)
            logger.info("[Iterative Remediation] Iteration %d/%d completed. Residual threats detected: %d", iteration, max_iterations, residual_count)

            if residual_count == 0:
                logger.info("[Iterative Remediation] All threats resolved successfully in iteration %d!", iteration)
                break
            elif iteration < max_iterations:
                logger.info("[Iterative Remediation] Re-ingesting %d residual threats for iteration %d/%d", residual_count, iteration + 1, max_iterations)
                self.scanner.findings_dir.mkdir(parents=True, exist_ok=True)
                for existing_f in list(self.scanner.findings_dir.glob("*.json")):
                    try:
                        existing_f.unlink()
                    except OSError:
                        pass
                for rf in residual_findings:
                    rf_id = (rf.get("finding_id") or rf.get("id") or "FINDING").lower().replace("_", "-")
                    f_file = self.scanner.findings_dir / f"{rf_id}.json"
                    try:
                        f_file.write_text(json.dumps(rf, indent=2), encoding="utf-8")
                    except Exception:
                        pass

        # Standalone bug_fixer pass for compatibility and audit parity
        bug_fix_result = self.remediator.fix_finding(
            workspace_path=ctx.repo_path,
            provider=provider,
            model=model,
            base_url=base_url,
        )
        for bf_file in bug_fix_result.get("files_modified", []):
            if bf_file not in files_modified:
                files_modified.append(bf_file)
        logger.info("Applied fixes to files: %s", files_modified)

        logger.info("=== STEP 4 & 5: GitSubAgent Commits & Raises Pull Request ===")
        repo_name = ctx.repo_name or "repository"
        all_threats = list(self.remediator.accumulated_threats.values())
        if not all_threats:
            all_threats = fix_result.get("all_threats") or []
        all_modified = sorted(list(self.remediator.accumulated_modified_files.union(set(files_modified))))

        commit_msg = self.remediator.generate_commit_message(
            repo_name=repo_name,
            threats=all_threats,
            modified_files=all_modified,
        )
        pr_title = self.remediator.generate_pr_title(
            repo_name=repo_name,
            threat_count=len(all_threats),
        )
        pr_body = self.remediator.generate_pr_body(
            repo_name=repo_name,
            threats=all_threats,
            modified_files=all_modified,
            branch=ctx.feature_branch,
            base_branch=ctx.base_branch,
        )

        finalize_result = self.git_agent.finalize_workspace(
            commit_message=commit_msg,
            pr_title=pr_title,
            pr_body=pr_body,
        )

        resolved_all = (len(post_scan.get("findings") if post_scan.get("findings") is not None else (post_scan.get("bug_findings") or [])) == 0)

        email_notification = None
        try:
            app_root = Path(__file__).resolve().parent.parent
            notifier = EmailReportNotifier(app_root_dir=app_root)
            cfg = notifier.get_public_config()
            if cfg.get("enabled", True) and cfg.get("auto_send_after_remediation", True):
                rem_html, _ = self.remediator.get_report_content(fmt="html", workspace_path=str(ctx.repo_path))
                rem_json, _ = self.remediator.get_report_content(fmt="json", workspace_path=str(ctx.repo_path))
                scan_html, _ = self.scanner.get_report_content("html")
                email_notification = notifier.send_remediation_report_email(
                    repo_name=repo_name,
                    workspace_path=str(ctx.repo_path),
                    branch=ctx.feature_branch,
                    base_branch=ctx.base_branch,
                    scan_result=scan_result,
                    remediation_result=fix_result,
                    post_scan_result=post_scan,
                    pr_data=finalize_result.to_dict().get("pull_request"),
                    remediation_html=rem_html,
                    remediation_json=rem_json,
                    scan_html=scan_html,
                    trigger_source="pipeline_completed",
                )
        except Exception as email_exc:
            logger.warning("Could not send pipeline completion email report: %s", email_exc)

        return {
            "status": "success",
            "context": ctx.to_dict(),
            "build_and_test": build_test_result,
            "scan": scan_result,
            "remediation": fix_result,
            "post_scan": post_scan,
            "iterations_run": iteration,
            "max_iterations": max_iterations,
            "resolved_all": resolved_all,
            "bug_fixer": bug_fix_result,
            "git_result": finalize_result.to_dict(),
            "email_notification": email_notification,
        }
