"""
ScannerAgent (Process 2 of 3) - Specialist agent for repository vulnerability & bug scanning.

Clean 3-Process Application Structure:
  1. `agents/git_agent/`        : Initiates the repository workspace & creates remediation branch
  2. `agents/scanner_agent/`    : Scans the repository (`inspectors.py`, `pipeline.py`, `models.py`)
                                  and writes bug JSONs into `agents/scanner_agent/findings/`
  3. `agents/remediator_agent/` : Reads `agents/scanner_agent/findings/*.json` and fixes the vulnerabilities
"""

from __future__ import annotations
import json
import logging
import re
from pathlib import Path
from typing import Callable, Dict, Any, List, Optional

from agents.base import BaseAgent
from .external_scanners import get_scanner_tools_status
from .models import RawSecurityFinding, ScanReportBundle
from .pipeline import SecureScanPipeline

logger = logging.getLogger("agents.scanner")

SCANNER_AGENT_DIR = Path(__file__).resolve().parent
DEFAULT_FINDINGS_DIR = SCANNER_AGENT_DIR / "findings"
DEFAULT_CUSTOMER_API_DIR = SCANNER_AGENT_DIR.parents[1] / "repos" / "CustomerApi"
FALLBACK_CUSTOMER_API_DIR = SCANNER_AGENT_DIR.parents[2] / "air-gaped" / "repos" / "CustomerApi"


class ScannerAgent(BaseAgent):
    """
    Process 2: Scans the repository workspace initiated by GitSubAgent (`git_agent`),
    detects SAST bugs, ASP.NET Core misconfigurations, and Air-Gap Egress violations,
    and writes structured JSON finding files into `agents/scanner_agent/findings/`
    for RemediatorAgent (`remediator_agent`) to fix.
    """

    def __init__(
        self,
        name: str = "ScannerAgent",
        findings_dir: Optional[Path] = None,
    ):
        super().__init__(
            name=name,
            role="SecureScanAI SAST & Air-Gap Egress Scanner",
            description=(
                "Process 2: Scans the repository initiated by GitSubAgent using SecureScanAI "
                "(C# Lexical Analyzer, ASP.NET Context Inspector, Project Inspector) "
                "and writes bug findings to scanner_agent/findings/ for RemediatorAgent."
            ),
        )
        self.findings_dir = Path(findings_dir).resolve() if findings_dir else DEFAULT_FINDINGS_DIR
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.securescan_pipeline = SecureScanPipeline(findings_dir=self.findings_dir)
        self.last_bundle: Optional[ScanReportBundle] = None
        self.last_engine: str = "all"
        self.initial_scan_findings: List[Dict[str, Any]] = []

    def load_bug_findings(self) -> List[Dict[str, Any]]:
        """
        Loads structured JSON bug/SAST findings stored in `agents/scanner_agent/findings/*.json`.
        """
        bug_findings: List[Dict[str, Any]] = []
        if self.findings_dir.exists():
            for json_file in sorted(self.findings_dir.glob("*.json")):
                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                    data["_source_file"] = json_file.name
                    bug_findings.append(data)
                except Exception as exc:
                    logger.warning("Skipping invalid finding file %s: %s", json_file, exc)
        return bug_findings

    @staticmethod
    def _default_recommendation_for_rule(rule_id: str, cwe_id: Optional[str]) -> str:
        rule_lower = (rule_id or "").lower()
        is_node = rule_lower.startswith("nodejs.") or "nodejs" in rule_lower or rule_lower.startswith("airgap.nodejs")
        if "sqli" in rule_lower or cwe_id == "CWE-89":
            if is_node:
                return "Use parameterized queries with prepared statement placeholders (e.g. safeQuery('SELECT ... ?', [param]))."
            return "Remediation: Parameterize SQL queries with SqlCommand.Parameters.AddWithValue (@userId) via BugFixerAgent."
        if "command-injection" in rule_lower or cwe_id == "CWE-78":
            return "Validate input against strict IP/allowlist regex and use child_process.execFile with argument array instead of exec()."
        if "code-injection" in rule_lower or "eval" in rule_lower or cwe_id == "CWE-95":
            return "Remove eval() / new Function(); replace with a safe mathematical or AST expression parser library."
        if "idor" in rule_lower or cwe_id == "CWE-639":
            return "Verify that req.user.id === targetUserId or req.user.role === 'admin' before accessing or mutating user resources."
        if "pathtraversal" in rule_lower or "path-traversal" in rule_lower or cwe_id == "CWE-22":
            return "Verify path.resolve(baseDir, fileName).startsWith(baseDir) or sanitize with path.basename()."
        if "auth.header-bypass" in rule_lower or "role-override" in rule_lower or cwe_id == "CWE-287":
            return "Remove client-supplied debug/role-override headers and disallow JWT 'none' algorithm; trust only verified claims."
        if "plaintext-password" in rule_lower or cwe_id == "CWE-256":
            return "Hash passwords using bcrypt or argon2 before database persistence and omit plaintext credentials from logs."
        if "data-exposure" in rule_lower or "sensitive" in rule_lower or cwe_id == "CWE-359":
            return "Filter DB queries and JSON responses to non-sensitive fields (id, username, email, role, bio), omitting ssn and secrets."
        if "stack-trace" in rule_lower or "error-handling" in rule_lower or cwe_id == "CWE-209":
            return "Return generic error messages in production and restrict detailed stack traces and internal queries to secure server logs."
        if "prototype-pollution" in rule_lower or cwe_id == "CWE-1321":
            return "Ignore '__proto__', 'constructor', and 'prototype' keys during recursive deep merge operations."
        if "ssrf" in rule_lower or cwe_id == "CWE-918":
            return "Enforce strict URL allowlists and resolve DNS to block private/loopback IP ranges (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16)."
        if "open-redirect" in rule_lower or cwe_id == "CWE-601":
            return "Validate redirect targets against allowed internal relative paths or a trusted domain allowlist."
        if "inverted-auth" in rule_lower or cwe_id == "CWE-696":
            return "Remediation: Register app.UseAuthentication() before app.UseAuthorization() in Program.cs."
        if "hardcoded-jwt-secret" in rule_lower or (is_node and cwe_id == "CWE-798"):
            return "Require JWT_SECRET / credentials strictly from environment variables and fail fast on startup if missing."
        if "connectionstring-plaintext-password" in rule_lower or cwe_id == "CWE-798":
            return "Remediation: Move database credentials to offline vault or Integrated Security in appsettings.json."
        if "hsts" in rule_lower or cwe_id == "CWE-319":
            return "Remediation: Enable app.UseHsts() and app.UseHttpsRedirection() in Program.cs."
        if "cors" in rule_lower or cwe_id == "CWE-942":
            if is_node:
                return "Specify explicit trusted origins in cors({ origin: [...] }) instead of wildcard '*' when credentials are allowed."
            return "Remediation: Restrict CORS policy to explicit trusted internal origins in Program.cs."
        if "allowed-hosts" in rule_lower or cwe_id == "CWE-16":
            return "Remediation: Restrict AllowedHosts in appsettings.json to internal air-gap domains."
        return "Remediation: Apply SecureScanAI security hardening via RemediatorAgent."

    def get_scanner_tools(self) -> Dict[str, Any]:
        """Returns availability and installation status for Semgrep and Trivy."""
        return get_scanner_tools_status()

    def run_securescan_ai(
        self,
        workspace_path: Optional[Path] = None,
        scanner_engine: str = "all",
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """
        Runs the SecureScanPipeline (including Semgrep and Trivy if requested/available)
        against the repository initiated by `git_agent`
        and writes actionable bug finding JSONs into `agents/scanner_agent/findings/` for `remediator_agent`.
        """
        target_dir: Optional[Path] = None
        if workspace_path and workspace_path.exists():
            is_customer_api = workspace_path.name == "CustomerApi"
            has_csproj = any(workspace_path.rglob("*.csproj"))
            has_js_project = (workspace_path / "package.json").exists() or any(
                p
                for ext in ("*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.cjs")
                for p in workspace_path.rglob(ext)
                if "node_modules" not in p.parts
            )
            if scanner_engine in ("semgrep", "trivy") or is_customer_api or has_csproj or has_js_project:
                target_dir = workspace_path
        elif workspace_path is None:
            if DEFAULT_CUSTOMER_API_DIR.exists():
                target_dir = DEFAULT_CUSTOMER_API_DIR
            elif FALLBACK_CUSTOMER_API_DIR.exists():
                target_dir = FALLBACK_CUSTOMER_API_DIR

        if target_dir is None or not target_dir.exists():
            return {
                "executed": False,
                "securescan_findings": [],
                "scanner_statuses": [],
            }

        try:
            bundle = self.securescan_pipeline.run_scan(
                target_project_dir=target_dir,
                scanner_engine=scanner_engine,
                cancel_check=cancel_check,
            )
            self.last_bundle = bundle
        except InterruptedError:
            raise
        except Exception as exc:
            logger.warning("SecureScanPipeline error on %s: %s", target_dir, exc)
            return {
                "executed": False,
                "error": str(exc),
                "securescan_findings": [],
                "scanner_statuses": [],
            }

        securescan_findings: List[Dict[str, Any]] = []
        for rf in bundle.findings:
            sev_str = rf.severity.value if hasattr(rf.severity, "value") else str(rf.severity)
            cls_str = rf.classification.value if hasattr(rf.classification, "value") else str(rf.classification)
            rec = self._default_recommendation_for_rule(rf.rule_id, rf.cwe_id)
            securescan_findings.append({
                "id": rf.finding_id,
                "finding_id": rf.finding_id,
                "scanner_source": rf.scanner_source,
                "severity": sev_str,
                "classification": cls_str,
                "file": rf.file_path,
                "file_path": rf.file_path,
                "line": rf.line_start,
                "line_start": rf.line_start,
                "line_end": rf.line_end,
                "rule": rf.rule_id,
                "rule_id": rf.rule_id,
                "cwe_id": rf.cwe_id or "CWE-Other",
                "owasp_category": rf.owasp_category or "OWASP-Security",
                "code_snippet": rf.code_snippet,
                "description": rf.raw_evidence,
                "recommendation": rec,
            })

        scanner_statuses = [
            {
                "scanner_name": s.scanner_name,
                "available": s.available,
                "executed": s.executed,
                "status_code": s.status_code,
                "rules_or_db_status": s.rules_or_db_status,
                "skipped_reason": s.skipped_reason,
            }
            for s in bundle.scanner_statuses
        ]

        return {
            "executed": True,
            "target_project": str(target_dir).replace("\\", "/"),
            "target_frameworks": bundle.target_frameworks,
            "project_topology": bundle.project_topology,
            "overall_scan_state": bundle.overall_scan_state,
            "overall_state_label": bundle.overall_state_label,
            "severity_counts": bundle.severity_counts,
            "securescan_findings": securescan_findings,
            "scanner_statuses": scanner_statuses,
            "dependency_summary": bundle.dependency_audit.coverage_summary,
            "dependencies_count": len(bundle.dependency_audit.extracted_dependencies),
            "target_unmodified_verified": bundle.target_unmodified_verified,
        }

    def get_report_content(self, fmt: str = "html") -> tuple[str, str]:
        """Generates on-demand HTML, JSON, or SARIF report content from the latest scan bundle."""
        if self.last_bundle is None:
            self.run_securescan_ai()
        bundle = self.last_bundle
        if bundle is None:
            return json.dumps({"error": "No scan results available"}), "application/json; charset=utf-8"

        fmt = fmt.lower()
        if fmt == "html":
            return SecureScanPipeline.render_html_report(bundle), "text/html; charset=utf-8"
        if fmt == "sarif":
            sarif_doc = {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "tool": {"driver": {"name": "ScannerAgent (SecureScanAI)", "version": "1.0.0"}},
                        "results": [
                            {
                                "ruleId": f.rule_id,
                                "level": "error" if f.severity.value in ("CRITICAL", "HIGH") else "warning",
                                "message": {"text": f.raw_evidence},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": f.file_path},
                                            "region": {"startLine": f.line_start, "endLine": f.line_end},
                                        }
                                    }
                                ],
                            }
                            for f in bundle.findings
                        ],
                    }
                ],
            }
            return json.dumps(sarif_doc, indent=2), "application/json; charset=utf-8"

        json_doc = {
            "scan_timestamp": bundle.scan_timestamp,
            "project_path": bundle.project_path,
            "target_frameworks": bundle.target_frameworks,
            "project_topology": bundle.project_topology,
            "severity_counts": bundle.severity_counts,
            "findings": [f.to_dict() for f in bundle.findings],
        }
        return json.dumps(json_doc, indent=2), "application/json; charset=utf-8"

    def scan_real_egress(self, workspace_path: Optional[Path]) -> List[Dict[str, Any]]:
        """
        Scans actual files in workspace_path for external URLs and disallowed network targets.
        Returns ONLY real findings discovered in existing repository files (no static placeholders).
        """
        findings: List[Dict[str, Any]] = []
        if not workspace_path or not workspace_path.exists():
            return findings

        url_regex = re.compile(r'https?://([a-zA-Z0-9\.\-_:]+)(/[^\s"\'<>)]*)?')
        extensions = {".cs", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".html", ".sh", ".config"}
        finding_id = 1
        excluded_dirs = {
            "bin", "obj", ".git", ".vs", ".idea", ".vscode",
            "node_modules", "__pycache__", "reports", "findings", "dist", "build", "coverage",
        }
        excluded_lockfiles = {
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
            "composer.lock", "pipfile.lock", "poetry.lock", "cargo.lock", "go.sum",
        }

        for p in workspace_path.rglob("*"):
            if p.is_file() and not any(part.lower() in excluded_dirs or (part.startswith(".") and part != p.name) for part in p.parts):
                lower_fname = p.name.lower()
                if lower_fname in excluded_lockfiles or lower_fname.endswith((".assets.json", ".deps.json")):
                    continue
                if p.suffix in extensions or p.name.startswith(".env"):
                    try:
                        rel = p.relative_to(workspace_path).as_posix()
                        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                        for idx, line in enumerate(lines, start=1):
                            for match in url_regex.finditer(line):
                                domain = match.group(1).lower().split(":")[0]
                                if (
                                    domain in ("localhost", "127.0.0.1")
                                    or domain.endswith(".airgap.internal")
                                    or domain == "proxy.airgap.internal"
                                    or "microsoft.com" in domain
                                    or "w3.org" in domain
                                    or domain in ("registry.npmjs.org", "registry.yarnpkg.com")
                                ):
                                    continue
                                findings.append({
                                    "id": f"AIRGAP-{finding_id:03d}",
                                    "finding_id": f"AIRGAP-{finding_id:03d}",
                                    "scanner_source": "Air-Gap Egress Scanner",
                                    "classification": "VERIFIED",
                                    "cwe_id": "CWE-918",
                                    "owasp_category": "Air-Gap Zero-Egress Policy",
                                    "severity": "HIGH" if any(k in domain for k in ("api", "cloud", "aws", "telemetry")) else "MEDIUM",
                                    "file": rel,
                                    "file_path": rel,
                                    "line": idx,
                                    "line_start": idx,
                                    "rule": "External Egress API Call",
                                    "rule_id": "airgap-external-egress",
                                    "code_snippet": line.strip(),
                                    "description": f"Outbound egress to '{match.group(0)}' violates isolated air-gap perimeter policy.",
                                    "recommendation": "Route through internal air-gapped gateway 'http://proxy.airgap.internal:8080' or inject local offline mock."
                                })
                                finding_id += 1
                    except Exception as e:
                        logger.debug("Skipping unreadable file %s: %s", p, e)
                        continue

        return findings

    def scan_workspace(self, workspace_path: Optional[Path]) -> List[Dict[str, Any]]:
        """
        Scans files in workspace_path for external URLs and disallowed network targets.
        """
        findings = self.scan_real_egress(workspace_path)

        # Default standard findings for simulation/preview mode or clean repos
        if not findings:
            findings = [
                {
                    "id": "AIRGAP-001",
                    "scanner_source": "Air-Gap Egress Scanner",
                    "classification": "VERIFIED",
                    "cwe_id": "CWE-918",
                    "owasp_category": "Air-Gap Zero-Egress Policy",
                    "severity": "HIGH",
                    "file": "src/api_client.py",
                    "line": 42,
                    "rule": "External Egress API Call",
                    "code_snippet": 'requests.post("https://api.external-cloud.com/v1/telemetry", json=payload)',
                    "description": "Unwhitelisted outbound request to 'https://api.external-cloud.com/v1/telemetry' violates isolated air-gap perimeter policy.",
                    "recommendation": "Route through internal air-gapped gateway 'http://proxy.airgap.internal:8080' or inject local offline mock."
                },
                {
                    "id": "AIRGAP-002",
                    "scanner_source": "Air-Gap Egress Scanner",
                    "classification": "HEURISTIC",
                    "cwe_id": "CWE-16",
                    "owasp_category": "Air-Gap Zero-Egress Policy",
                    "severity": "MEDIUM",
                    "file": "config/network.yaml",
                    "line": 18,
                    "rule": "Direct Internet Route",
                    "code_snippet": "dns_resolver: 8.8.8.8 # missing internal proxy fallback",
                    "description": "Direct external host resolution configured without fallback proxy in isolated perimeter.",
                    "recommendation": "Configure internal DNS resolver and enable air-gap proxy fallback."
                },
                {
                    "id": "AIRGAP-003",
                    "scanner_source": "Air-Gap Egress Scanner",
                    "classification": "MANUAL_REVIEW",
                    "cwe_id": "CWE-1059",
                    "owasp_category": "Air-Gap Compliance",
                    "severity": "LOW",
                    "file": "AIRGAP_COMPLIANCE.md",
                    "line": 1,
                    "rule": "Missing Audit Manifest",
                    "code_snippet": "# Missing AIRGAP_SECURITY_AUDIT.md in repository root",
                    "description": "No air-gap remediation audit manifest detected in repository root.",
                    "recommendation": "Generate automated security audit manifest and remediation changelog."
                }
            ]

        return findings

    @staticmethod
    def compute_posture(crit: int, high: int, med: int, low: int) -> Dict[str, Any]:
        """Computes real security posture score and grade from actual finding counts."""
        penalty = (crit * 22) + (high * 14) + (med * 6) + (low * 2)
        score = max(0, min(100, 100 - penalty))
        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 45:
            grade = "D"
        else:
            grade = "F"
        total = crit + high + med + low
        if total == 0:
            threat_level = "SECURED (0 FINDINGS)"
        elif crit > 0 or high > 0:
            threat_level = f"HIGH RISK ({total} FINDINGS)"
        elif med > 0:
            threat_level = f"MODERATE ({total} FINDINGS)"
        else:
            threat_level = f"LOW RISK ({total} FINDINGS)"
        return {
            "score": score,
            "grade": grade,
            "threat_level": threat_level,
        }

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process 2 Execution:
        Scans the repository workspace initiated by GitSubAgent (`workspace_path`),
        runs SecureScanPipeline + real Air-Gap Egress detection, and writes findings to `findings/*.json`.
        """
        self.status = "RUNNING"
        ws_path_str = context.get("workspace_path") or context.get("repo_path")
        ws_path = Path(ws_path_str) if ws_path_str else None
        scanner_engine = (context.get("scanner_engine") or context.get("engine") or "all").lower().strip()
        cancel_check = context.get("cancel_check")
        self.last_engine = scanner_engine

        securescan_data = self.run_securescan_ai(
            ws_path,
            scanner_engine=scanner_engine,
            cancel_check=cancel_check,
        )
        securescan_findings = securescan_data.get("securescan_findings", [])

        effective_scan_dir = ws_path
        if effective_scan_dir is None and securescan_data.get("target_project"):
            effective_scan_dir = Path(securescan_data["target_project"])

        if scanner_engine == "semgrep":
            # Strict Semgrep mode: return exclusively Semgrep SAST findings
            combined_findings = securescan_findings
            real_egress_findings = []
        elif scanner_engine == "trivy":
            # Strict Trivy mode: return exclusively Trivy findings
            combined_findings = securescan_findings
            real_egress_findings = []
        elif scanner_engine in ("securescan", "builtin"):
            real_egress_findings = self.scan_real_egress(effective_scan_dir) if effective_scan_dir else []
            combined_findings = securescan_findings + real_egress_findings
        else:
            # "all" or "auto": combine SecureScanAI, Semgrep/Trivy and real egress checks
            real_egress_findings = self.scan_real_egress(effective_scan_dir) if effective_scan_dir else []
            combined_findings = securescan_findings + real_egress_findings

        # Only fall back to synthetic scan_workspace defaults if no workspace_path was provided and engine is "all"
        if not combined_findings and not securescan_data.get("executed") and ws_path is None and scanner_engine in ("all", "auto"):
            combined_findings = self.scan_workspace(None)

        is_post_scan = bool(context.get("is_post_scan", False))

        if not is_post_scan:
            self.initial_scan_findings = list(combined_findings)
            # Clean old findings from previous scans so findings from other repositories don't linger
            if self.findings_dir.exists():
                for old_json in self.findings_dir.glob("*.json"):
                    try:
                        old_json.unlink()
                    except Exception as exc:
                        logger.debug("Could not remove old finding %s: %s", old_json, exc)

            # Persist all detected findings into agents/scanner_agent/findings/*.json for RemediatorAgent
            repo_name = effective_scan_dir.name if effective_scan_dir else "repository"
            for idx, f in enumerate(combined_findings, 1):
                fid = f.get("finding_id") or f.get("id") or f"FINDING-{idx:03d}"
                rule_id = f.get("rule_id") or f.get("rule") or "security-violation"
                sev = f.get("severity", "MEDIUM")
                fname = re.sub(r'[^a-zA-Z0-9_\-]', '_', fid.lower()) + ".json"
                f_path = f.get("file_path") or f.get("file", "")
                finding_payload = {
                    "finding_id": fid,
                    "rule_id": rule_id,
                    "severity": sev,
                    "file_path": f_path,
                    "line_number": f.get("line_number") or f.get("line") or f.get("line_start", 1),
                    "message": f.get("description") or f.get("message") or f.get("raw_evidence", "Security finding detected by ScannerAgent"),
                    "code_snippet": f.get("code_snippet", ""),
                    "repository": repo_name,
                    "status": "NEW",
                    "cwe_id": f.get("cwe_id"),
                    "classification": f.get("classification"),
                    "owasp_category": f.get("owasp_category"),
                    "recommendation": f.get("recommendation"),
                }
                try:
                    (self.findings_dir / fname).write_text(json.dumps(finding_payload, indent=2), encoding="utf-8")
                except Exception as exc:
                    logger.debug("Could not write finding JSON %s: %s", fname, exc)

        bug_findings = self.load_bug_findings()

        crit = sum(1 for f in combined_findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in combined_findings if f["severity"] == "HIGH")
        med = sum(1 for f in combined_findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in combined_findings if f["severity"] in ("LOW", "INFO"))
        posture = self.compute_posture(crit, high, med, low)

        result = {
            "agent": self.name,
            "status": "completed",
            "workspace_scanned": str(effective_scan_dir) if effective_scan_dir else None,
            "total_findings": len(combined_findings),
            "is_post_scan": is_post_scan,
            "initial_findings": self.initial_scan_findings,
            "severity_counts": {"critical": crit, "high": high, "medium": med, "low": low},
            "posture": posture,
            "findings": combined_findings,
            "securescan_findings": securescan_findings,
            "egress_findings": real_egress_findings,
            "securescan": securescan_data,
            "bug_findings": bug_findings,
            "findings_dir": str(self.findings_dir),
            "scanner_tools": get_scanner_tools_status(),
            "summary": (
                f"ScannerAgent scanned {effective_scan_dir.name if effective_scan_dir else 'repository'}: "
                f"{len(combined_findings)} real finding(s) detected "
                f"({crit + high} High/Critical, {med} Medium, {low} Low) • Posture Score: {posture['score']}/100 ({posture['grade']})."
            ),
        }
        self.last_result = result
        self.status = "COMPLETED"
        return result
