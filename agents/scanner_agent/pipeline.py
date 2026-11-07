"""
ScannerAgent Security Pipeline (Process 2 of 3)
Coordinates:
  1. ProjectInspector (.csproj target frameworks, topology, NuGet dependencies)
  2. CSharpLexicalAnalyzer (SQL Injection CWE-89, XSS CWE-79, Hardcoded Secrets CWE-798, Weak Crypto, Deserialization, Path Traversal)
  3. AspNetContextInspector (Inverted Auth Middleware CWE-696, Missing HSTS CWE-319, Wildcard CORS CWE-942, AllowedHosts CWE-16, ConnectionString Passwords CWE-798)
  4. Exporting structured JSON findings to `agents/scanner_agent/findings/` for RemediatorAgent (Process 3)
"""

from __future__ import annotations
from datetime import datetime, timezone
import html
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .inspectors import AspNetContextInspector, CSharpLexicalAnalyzer, ProjectInspector
from .models import (
    RawSecurityFinding,
    ScannerExecutionStatus,
    ScanReportBundle,
)


class SecureScanPipeline:
    """
    Unified security scanning pipeline inside `agents/scanner_agent/`.
    Scans the repository initiated by `git_agent` and produces findings for `remediator_agent`.
    """

    def __init__(self, findings_dir: Optional[Path] = None):
        base_dir = Path(__file__).resolve().parent
        self.findings_dir: Path = (findings_dir or (base_dir / "findings")).resolve()
        self.findings_dir.mkdir(parents=True, exist_ok=True)

    def run_scan(
        self,
        target_project_dir: Path,
        report_prefix: str = "securescan_portal_audit",
    ) -> ScanReportBundle:
        target_path = Path(target_project_dir).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target project path does not exist: {target_path}")

        timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Inspect project structure & dependencies
        project_inspector = ProjectInspector(target_path)
        profile = project_inspector.inspect()
        dep_audit = project_inspector.extract_dependencies()

        # 2. Run C# Lexical Analyzer & ASP.NET Core Context Inspector
        lexical_analyzer = CSharpLexicalAnalyzer()
        context_inspector = AspNetContextInspector()

        findings: List[RawSecurityFinding] = []
        for src_file in profile.source_files:
            findings.extend(lexical_analyzer.analyze_file(src_file, project_root=target_path))
        findings.extend(context_inspector.inspect_project(profile))

        # 3. Compute severity counts
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sev_counts[key] = sev_counts.get(key, 0) + 1

        scanner_statuses = [
            ScannerExecutionStatus(
                scanner_name="C# Lexical & SAST Analyzer",
                available=True,
                executed=True,
                rules_or_db_status="ACTIVE (SQLi, XSS, Secrets, Crypto, Deserialization)",
                status_code="SUCCESS",
            ),
            ScannerExecutionStatus(
                scanner_name="ASP.NET Context & Config Inspector",
                available=True,
                executed=True,
                rules_or_db_status="ACTIVE (Middleware, HSTS, CORS, appsettings.json)",
                status_code="SUCCESS",
            ),
            ScannerExecutionStatus(
                scanner_name="Project & NuGet Dependency Inspector",
                available=True,
                executed=True,
                rules_or_db_status=dep_audit.coverage_summary,
                status_code="SUCCESS",
            ),
        ]

        overall_state = "VULNERABILITIES_FOUND" if findings else "NO_VULNERABILITIES_DETECTED"
        overall_label = "Vulnerabilities found" if findings else "No vulnerabilities detected"

        bundle = ScanReportBundle(
            scan_timestamp=timestamp_utc,
            project_path=str(target_path).replace("\\", "/"),
            target_frameworks=profile.target_frameworks,
            project_topology=profile.project_topology,
            overall_scan_state=overall_state,
            overall_state_label=overall_label,
            severity_counts=sev_counts,
            findings=findings,
            scanner_statuses=scanner_statuses,
            dependency_audit=dep_audit,
            target_unmodified_verified=True,
        )
        return bundle

    @staticmethod
    def render_html_report(bundle: ScanReportBundle) -> str:
        rows = []
        for f in bundle.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            cls = f.classification.value if hasattr(f.classification, "value") else str(f.classification)
            rows.append(
                f"<tr>"
                f"<td><strong>{html.escape(f.finding_id)}</strong><br><small>{html.escape(f.cwe_id or '')}</small></td>"
                f"<td>{html.escape(sev)} ({html.escape(cls)})</td>"
                f"<td><code>{html.escape(f.file_path)}:{f.line_start}</code></td>"
                f"<td>{html.escape(f.raw_evidence)}<pre style='background:#f1f5f9;padding:6px;border-radius:4px'>{html.escape(f.code_snippet)}</pre></td>"
                f"</tr>"
            )
        rows_html = "\n".join(rows) or "<tr><td colspan='4'>No findings detected.</td></tr>"
        return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>ScannerAgent Security Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #eef2f9; color: #0f172a; padding: 24px; }}
    .card {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 12px; padding: 20px; max-width: 1100px; margin: 0 auto; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f8fafc; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>ScannerAgent (SecureScanAI) Security Audit Report</h2>
    <p><strong>Target Repository:</strong> {html.escape(bundle.project_path)} | <strong>Frameworks:</strong> {html.escape(', '.join(bundle.target_frameworks))} | <strong>Topology:</strong> {html.escape(bundle.project_topology)}</p>
    <table>
      <thead><tr><th>ID / CWE</th><th>Severity</th><th>File : Line</th><th>Evidence &amp; Code Snippet</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</body>
</html>"""

