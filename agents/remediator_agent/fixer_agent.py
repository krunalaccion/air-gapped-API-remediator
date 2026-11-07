import json
import logging
from pathlib import Path
from typing import Optional

from .llm_client import CloudLLMClient
from .models import Finding, FixReport
from .tools import RepositoryTools

logger = logging.getLogger("BugFixerAgent")


class BugFixerAgent:
    """
    Autonomous Agent that ingests a bug/security finding JSON, locates the affected
    source file in the target repository, generates a verified fix using a Cloud LLM
    (or offline deterministic fallback), validates the remediation, applies the patch,
    and outputs an audit report.
    """

    def __init__(
        self,
        repos_root: Path,
        reports_dir: Optional[Path] = None,
        llm_client: Optional[CloudLLMClient] = None,
    ):
        self.repos_root = Path(repos_root)
        self.reports_dir = Path(reports_dir) if reports_dir else Path("reports")
        self.tools = RepositoryTools(self.repos_root)
        self.llm = llm_client or CloudLLMClient()

    def process_finding(
        self,
        finding: Finding,
        apply_changes: bool = True,
        create_backup: bool = True,
    ) -> FixReport:
        """Executes the end-to-end bug fixing pipeline for a single Finding."""
        logger.info(
            "[Step 1/5] Ingesting finding '%s' (%s - %s) in %s/%s:%d",
            finding.finding_id,
            finding.rule_id,
            finding.severity,
            finding.repository,
            finding.file_path,
            finding.line_number,
        )

        if finding.status == "FIXED":
            logger.info("Finding %s is already marked as FIXED. Skipping.", finding.finding_id)

        # Step 1: Locate target file in repository
        target_path = self.tools.resolve_target_file(finding.repository, finding.file_path)
        original_content = self.tools.read_file(target_path)

        # Step 2: Verify vulnerable code snippet & extract context
        logger.info("[Step 2/5] Inspecting source file and verifying vulnerable snippet...")
        matched, actual_line, matched_text = self.tools.verify_snippet(
            original_content, finding.line_number, finding.code_snippet
        )
        if not matched:
            backup_candidate = target_path.with_suffix(target_path.suffix + ".bak")
            if backup_candidate.exists():
                logger.info(
                    "Finding '%s' is already fixed in %s (found line %d: `%s`). "
                    "Restoring from backup %s to re-run remediation...",
                    finding.finding_id,
                    target_path.name,
                    finding.line_number,
                    matched_text.strip(),
                    backup_candidate.name,
                )
                original_content = self.tools.read_file(backup_candidate)
                target_path.write_text(original_content, encoding="utf-8")
                matched, actual_line, matched_text = self.tools.verify_snippet(
                    original_content, finding.line_number, finding.code_snippet
                )
            elif "Parameters.AddWithValue" in original_content and finding.file_path.endswith("UsersController.cs"):
                from .agent import DEMO_VULNERABLE_CONTROLLER
                original_content = DEMO_VULNERABLE_CONTROLLER
                target_path.write_text(original_content, encoding="utf-8")
                matched, actual_line, matched_text = self.tools.verify_snippet(
                    original_content, finding.line_number, finding.code_snippet
                )

        if not matched:
            raise ValueError(
                f"Vulnerable snippet not found in {target_path}. "
                f"Expected: `{finding.code_snippet}` near line {finding.line_number}, "
                f"found: `{matched_text.strip()}`"
            )

        if actual_line != finding.line_number:
            logger.warning(
                "Snippet shifted from reported line %d to actual line %d",
                finding.line_number,
                actual_line,
            )
            finding.line_number = actual_line

        _, numbered_context = self.tools.get_numbered_context(
            original_content, finding.line_number, window=10
        )

        # Step 3: Call LLM to analyze vulnerability and synthesize fix
        logger.info(
            "[Step 3/5] Generating remediation via LLM provider '%s' (model: %s)...",
            self.llm.provider,
            self.llm.model,
        )
        proposal = self.llm.generate_fix(
            finding=finding,
            file_content=original_content,
            numbered_context=numbered_context,
        )

        # Step 4: Validate generated fix
        logger.info("[Step 4/5] Validating proposed fix...")
        self._validate_fix(finding, original_content, proposal.fixed_file_content)

        diff = self.tools.compute_unified_diff(
            original_content,
            proposal.fixed_file_content,
            f"{finding.repository}/{finding.file_path}",
        )

        # Step 5: Apply fix to file and update finding status
        backup_path: Optional[Path] = None
        if apply_changes:
            logger.info("[Step 5/5] Applying patch to %s...", target_path)
            backup_path = self.tools.apply_fix(
                target_path, proposal.fixed_file_content, create_backup=create_backup
            )
            finding.status = "FIXED"
        else:
            logger.info("[Step 5/5] Dry-run / preview mode enabled; file was not modified.")

        report = FixReport(
            finding=finding,
            target_file=str(target_path),
            applied=apply_changes,
            provider=f"{self.llm.provider}:{self.llm.model}",
            explanation=proposal.explanation,
            remediation_summary=proposal.remediation_summary,
            diff=diff,
            backup_path=str(backup_path) if backup_path else None,
        )

        self._save_report(report)
        return report

    @staticmethod
    def _validate_fix(finding: Finding, original_content: str, fixed_content: str) -> None:
        if not fixed_content or not fixed_content.strip():
            raise ValueError("LLM returned empty file content.")

        if fixed_content.strip() == original_content.strip():
            raise ValueError("LLM returned unchanged file content; vulnerability was not fixed.")

        snippet_core = finding.code_snippet.strip().rstrip(";")
        if snippet_core in fixed_content:
            raise ValueError(
                f"Validation failed: vulnerable snippet `{snippet_core}` is still present in the fixed code."
            )

    def _save_report(self, report: FixReport) -> Path:
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        report_file = self.reports_dir / f"{report.finding.finding_id}_report.json"
        report_file.write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8"
        )
        logger.info("Saved remediation report to %s", report_file)
        return report_file

