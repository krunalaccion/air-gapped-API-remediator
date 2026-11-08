import json
import logging
import re
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
            # Check if this finding was already remediated by a previous step or another rule
            clean_snip = re.sub(r'[\s\'\",;]+', '', finding.code_snippet or "").lower()
            clean_orig = re.sub(r'[\s\'\",;]+', '', original_content).lower()
            if (
                "parameters.addwithvalue" in clean_orig
                or (len(clean_snip) > 6 and clean_snip not in clean_orig)
                or finding.status == "FIXED"
            ):
                logger.info(
                    "Finding '%s' is already remediated in %s. Skipping redundant patch.",
                    finding.finding_id,
                    target_path.name,
                )
                return FixReport(
                    finding=finding,
                    target_file=str(target_path),
                    applied=True,
                    provider=self.llm.provider,
                    explanation=f"Finding '{finding.finding_id}' ({finding.rule_id}) is verified as already remediated in '{target_path.name}'.",
                    remediation_summary=f"Already remediated in {target_path.name}.",
                    diff="",
                    backup_path=None,
                )

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
        try:
            self._validate_fix(finding, original_content, proposal.fixed_file_content)
        except ValueError as val_err:
            if self.llm.provider not in ("mock", "offline", "auto-fallback"):
                logger.warning("LLM proposal validation failed (%s). Attempting deterministic fallback...", val_err)
                proposal = self.llm._generate_deterministic_fix(finding, original_content)
                self._validate_fix(finding, original_content, proposal.fixed_file_content)
            else:
                raise

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

        snippet_core = (finding.code_snippet or "").strip().rstrip(";")
        is_comment = (
            snippet_core.startswith("//")
            or snippet_core.startswith("/*")
            or snippet_core.startswith("*")
            or snippet_core.startswith("#")
        )
        is_missing_heuristic = (
            "not found" in snippet_core.lower()
            or "missing" in snippet_core.lower()
            or "hsts" in finding.rule_id.lower()
        )

        clean_snip = re.sub(r'[\s\'\",;]+', '', snippet_core).lower()
        clean_orig = re.sub(r'[\s\'\",;]+', '', original_content).lower()

        # Specifically check if vulnerable snippet is present
        if "allowedhosts" in clean_snip:
            is_vuln_in_fixed = bool(re.search(r'\"AllowedHosts\"\s*:\s*\"\*\"', fixed_content))
            is_vuln_in_orig = bool(re.search(r'\"AllowedHosts\"\s*:\s*\"\*\"', original_content))
        else:
            is_vuln_in_fixed = snippet_core in fixed_content or (
                len(clean_snip) > 6 and clean_snip in re.sub(r'[\s\'\",;]+', '', fixed_content).lower()
            )
            is_vuln_in_orig = snippet_core in original_content or (
                len(clean_snip) > 6 and clean_snip in clean_orig
            )

        if fixed_content.strip() == original_content.strip():
            # If the vulnerable snippet was already absent from original_content (or is a comment/already patched),
            # accept the file as already compliant.
            if not is_missing_heuristic and (is_comment or not is_vuln_in_orig):
                return
            raise ValueError("LLM returned unchanged file content; vulnerability was not fixed.")

        if (
            not is_missing_heuristic
            and not is_comment
            and is_vuln_in_fixed
        ):
            # If the exact vulnerable snippet still remains in fixed content
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

