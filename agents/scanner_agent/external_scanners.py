"""
External Scanner Integrations for ScannerAgent:
- SemgrepScanner: Runs Semgrep SAST engine via CLI (`semgrep scan --json`)
- TrivyScanner: Runs Trivy Vulnerability, Misconfiguration & Secret scanner via CLI (`trivy fs --format json`)

Both scanners cleanly map their native findings into `RawSecurityFinding` objects
and register their status in `ScannerExecutionStatus`.
"""

from __future__ import annotations
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    FindingClassification,
    FindingSeverity,
    RawSecurityFinding,
    ScannerExecutionStatus,
)

logger = logging.getLogger("agents.scanner.external")

COMMON_BIN_DIRS = [
    Path("/opt/homebrew/bin"),
    Path("/usr/local/bin"),
    Path.home() / ".local" / "bin",
    Path.home() / "Library" / "Python" / "3.9" / "bin",
    Path.home() / "Library" / "Python" / "3.10" / "bin",
    Path.home() / "Library" / "Python" / "3.11" / "bin",
    Path.home() / "Library" / "Python" / "3.12" / "bin",
    Path.home() / ".cargo" / "bin",
]

_SCANNER_TOOLS_CACHE: Optional[Dict[str, Dict[str, Any]]] = None


def _get_safe_scanner_env() -> Dict[str, str]:
    """Returns an isolated environment dict preventing external telemetry or home-directory permission errors."""
    env = dict(os.environ)
    env["HOME"] = "/tmp"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_USER_LOG_FILE"] = "/tmp/semgrep.log"
    # Ensure homebrew and local bin are always searchable in PATH
    existing_path = env.get("PATH", "")
    env["PATH"] = f"/opt/homebrew/bin:/usr/local/bin:{existing_path}"
    return env


def find_binary(name: str) -> Optional[str]:
    """Finds an executable in standard PATH or common macOS/Linux installation paths."""
    found = shutil.which(name)
    if found:
        return found
    for d in COMMON_BIN_DIRS:
        candidate = d / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def get_scanner_tools_status(force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
    """Returns availability and version info for installed external scanners (cached to avoid blocking telemetry)."""
    global _SCANNER_TOOLS_CACHE
    if _SCANNER_TOOLS_CACHE is not None and not force_refresh:
        return _SCANNER_TOOLS_CACHE

    tools: Dict[str, Dict[str, Any]] = {}
    safe_env = _get_safe_scanner_env()

    semgrep_bin = find_binary("semgrep")
    if semgrep_bin:
        version_str = "Installed"
        try:
            p = subprocess.run([semgrep_bin, "--version"], capture_output=True, text=True, timeout=1.0, env=safe_env)
            if p.returncode == 0 and p.stdout.strip():
                version_str = p.stdout.strip().splitlines()[0]
        except Exception:
            pass
        tools["semgrep"] = {
            "available": True,
            "binary_path": semgrep_bin,
            "version": version_str,
            "install_cmd": None,
        }
    else:
        tools["semgrep"] = {
            "available": False,
            "binary_path": None,
            "version": None,
            "install_cmd": "brew install semgrep   # or: pip install semgrep",
        }

    trivy_bin = find_binary("trivy")
    if trivy_bin:
        version_str = "Installed"
        try:
            p = subprocess.run([trivy_bin, "--version"], capture_output=True, text=True, timeout=1.0, env=safe_env)
            if p.returncode == 0 and p.stdout.strip():
                version_str = p.stdout.strip().splitlines()[0]
        except Exception:
            pass
        tools["trivy"] = {
            "available": True,
            "binary_path": trivy_bin,
            "version": version_str,
            "install_cmd": None,
        }
    else:
        tools["trivy"] = {
            "available": False,
            "binary_path": None,
            "version": None,
            "install_cmd": "brew install trivy",
        }

    _SCANNER_TOOLS_CACHE = tools
    return tools


class SemgrepScanner:
    """
    Adapter for Semgrep SAST CLI (`semgrep scan --json`).
    Translates Semgrep results into `RawSecurityFinding` items.
    """

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or find_binary("semgrep")

    @property
    def is_available(self) -> bool:
        return bool(self.binary_path and Path(self.binary_path).is_file() and os.access(self.binary_path, os.X_OK))

    def scan(
        self,
        target_dir: Path,
        config: str = "auto",
        timeout: int = 120,
    ) -> Tuple[List[RawSecurityFinding], ScannerExecutionStatus]:
        findings: List[RawSecurityFinding] = []
        target_path = Path(target_dir).resolve()

        if not self.is_available:
            status = ScannerExecutionStatus(
                scanner_name="Semgrep SAST Scanner",
                available=False,
                executed=False,
                skipped_reason="semgrep CLI not installed in PATH (run 'brew install semgrep' or 'pip install semgrep')",
                rules_or_db_status="NOT INSTALLED",
                status_code="SKIPPED",
            )
            return findings, status

        # Prefer local air-gapped rule directory so Semgrep never dials out
        rules_dir = Path(__file__).resolve().parent / "rules" / "semgrep"
        effective_config = config
        if config in ("auto", "offline", "airgap", "local") or not config:
            if rules_dir.exists():
                effective_config = str(rules_dir)
            else:
                effective_config = "auto"

        cmd = [
            self.binary_path,
            "scan",
            "--config",
            effective_config,
            "--exclude",
            "bin",
            "--exclude",
            "obj",
            "--exclude",
            "reports",
            "--exclude",
            ".git",
            "--exclude",
            "node_modules",
            "--exclude",
            "*.assets.json",
            "--exclude",
            "*.deps.json",
            "--metrics=off",
            "--disable-version-check",
            "--json",
            "--quiet",
            str(target_path),
        ]

        logger.info("Running Semgrep scan on %s: %s", target_path, " ".join(cmd))
        safe_env = _get_safe_scanner_env()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(target_path),
                env=safe_env,
            )
        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out after %ds", timeout)
            status = ScannerExecutionStatus(
                scanner_name="Semgrep SAST Scanner",
                available=True,
                executed=False,
                skipped_reason=f"Scan timed out after {timeout} seconds",
                rules_or_db_status="TIMEOUT",
                status_code="FAILED",
            )
            return findings, status
        except Exception as exc:
            logger.error("Failed to execute Semgrep: %s", exc)
            status = ScannerExecutionStatus(
                scanner_name="Semgrep SAST Scanner",
                available=True,
                executed=False,
                skipped_reason=str(exc),
                rules_or_db_status="EXEC_ERROR",
                status_code="FAILED",
            )
            return findings, status

        # Parse JSON output
        try:
            data = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError as err:
            logger.warning("Failed to decode Semgrep JSON: %s (stdout: %s)", err, proc.stdout[:300])
            status = ScannerExecutionStatus(
                scanner_name="Semgrep SAST Scanner",
                available=True,
                executed=False,
                skipped_reason=f"Failed to parse Semgrep JSON output: {err}",
                rules_or_db_status="PARSE_ERROR",
                status_code="FAILED",
            )
            return findings, status

        raw_results = data.get("results", [])
        for idx, res in enumerate(raw_results, 1):
            check_id = res.get("check_id") or "semgrep.rule"
            if "airgap." in check_id:
                check_id = "airgap." + check_id.split("airgap.", 1)[1]
            extra = res.get("extra", {})
            metadata = extra.get("metadata", {})
            raw_sev = (extra.get("severity") or "WARNING").upper()

            # Map Semgrep severity
            if raw_sev in ("ERROR", "CRITICAL"):
                sev = FindingSeverity.HIGH
            elif raw_sev in ("WARNING", "MEDIUM"):
                sev = FindingSeverity.MEDIUM
            else:
                sev = FindingSeverity.LOW

            # Extract CWE & OWASP
            cwe_list = metadata.get("cwe", [])
            cwe_id = cwe_list[0].split(":")[0].strip() if cwe_list else "CWE-Security"
            owasp_list = metadata.get("owasp", [])
            owasp_cat = owasp_list[0] if owasp_list else "A03:2021-Injection"

            file_p = res.get("path") or "source.cs"
            # Normalize relative path
            try:
                rel_path = Path(file_p).resolve().relative_to(target_path).as_posix()
            except Exception:
                rel_path = str(file_p).replace("\\", "/")

            start_line = res.get("start", {}).get("line") or 1
            end_line = res.get("end", {}).get("line") or start_line
            code_snip = extra.get("lines") or ""
            if not code_snip or code_snip == "requires login":
                try:
                    src_file = (target_path / rel_path).resolve()
                    if src_file.exists() and src_file.is_file():
                        file_lines = src_file.read_text(encoding="utf-8", errors="replace").splitlines()
                        s_idx = max(0, start_line - 1)
                        e_idx = min(len(file_lines), end_line)
                        code_snip = "\n".join(file_lines[s_idx:e_idx]).strip()
                except Exception:
                    pass

            findings.append(
                RawSecurityFinding(
                    finding_id=f"SEMGREP-{idx:03d}",
                    scanner_source="Semgrep SAST",
                    rule_id=check_id,
                    severity=sev,
                    classification=FindingClassification.VERIFIED,
                    file_path=rel_path,
                    line_start=start_line,
                    line_end=end_line,
                    code_snippet=code_snip.strip(),
                    raw_evidence=extra.get("message") or f"Semgrep rule violation: {check_id}",
                    cwe_id=cwe_id,
                    owasp_category=owasp_cat,
                    metadata={"semgrep_metadata": metadata},
                )
            )

        status = ScannerExecutionStatus(
            scanner_name="Semgrep SAST Scanner",
            available=True,
            executed=True,
            rules_or_db_status=f"ACTIVE (Found {len(findings)} issues via config '{config}')",
            status_code="SUCCESS",
        )
        return findings, status


class TrivyScanner:
    """
    Adapter for Trivy Vulnerability, Misconfiguration & Secret Scanner (`trivy fs --format json`).
    Translates Trivy results into `RawSecurityFinding` items.
    """

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or find_binary("trivy")

    @property
    def is_available(self) -> bool:
        return bool(self.binary_path and Path(self.binary_path).is_file() and os.access(self.binary_path, os.X_OK))

    def scan(
        self,
        target_dir: Path,
        security_checks: str = "vuln,config,secret",
        timeout: int = 120,
    ) -> Tuple[List[RawSecurityFinding], ScannerExecutionStatus]:
        findings: List[RawSecurityFinding] = []
        target_path = Path(target_dir).resolve()

        if not self.is_available:
            status = ScannerExecutionStatus(
                scanner_name="Trivy Security Scanner",
                available=False,
                executed=False,
                skipped_reason="trivy CLI not installed in PATH (run 'brew install trivy')",
                rules_or_db_status="NOT INSTALLED",
                status_code="SKIPPED",
            )
            return findings, status

        cmd = [
            self.binary_path,
            "fs",
            "--offline-scan",
            "--skip-db-update",
            "--skip-check-update",
            "--format",
            "json",
            "--security-checks",
            security_checks,
            "--skip-dirs",
            "bin,obj,reports,.git,node_modules",
            "--quiet",
            str(target_path),
        ]

        logger.info("Running Trivy scan on %s: %s", target_path, " ".join(cmd))
        safe_env = _get_safe_scanner_env()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(target_path),
                env=safe_env,
            )
            # If offline DB check failed because local cache was never initialized, fall back to config/secret checks
            if proc.returncode != 0 and ("DB error" in proc.stderr or "--skip-db-update" in proc.stderr):
                logger.info("Retrying Trivy with offline config & secret inspection...")
                fallback_cmd = [
                    self.binary_path,
                    "fs",
                    "--format",
                    "json",
                    "--security-checks",
                    "config,secret",
                    "--skip-dirs",
                    "bin,obj,reports,.git,node_modules",
                    "--quiet",
                    str(target_path),
                ]
                proc = subprocess.run(
                    fallback_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=str(target_path),
                    env=safe_env,
                )
        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timed out after %ds", timeout)
            status = ScannerExecutionStatus(
                scanner_name="Trivy Security Scanner",
                available=True,
                executed=False,
                skipped_reason=f"Scan timed out after {timeout} seconds",
                rules_or_db_status="TIMEOUT",
                status_code="FAILED",
            )
            return findings, status
        except Exception as exc:
            logger.error("Failed to execute Trivy: %s", exc)
            status = ScannerExecutionStatus(
                scanner_name="Trivy Security Scanner",
                available=True,
                executed=False,
                skipped_reason=str(exc),
                rules_or_db_status="EXEC_ERROR",
                status_code="FAILED",
            )
            return findings, status

        try:
            data = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError as err:
            logger.warning("Failed to decode Trivy JSON: %s (stdout: %s)", err, proc.stdout[:300])
            status = ScannerExecutionStatus(
                scanner_name="Trivy Security Scanner",
                available=True,
                executed=False,
                skipped_reason=f"Failed to parse Trivy JSON output: {err}",
                rules_or_db_status="PARSE_ERROR",
                status_code="FAILED",
            )
            return findings, status

        finding_counter = 1
        results = data.get("Results", [])
        for res_block in results:
            target_file = res_block.get("Target") or "manifest"
            try:
                rel_path = Path(target_file).resolve().relative_to(target_path).as_posix()
            except Exception:
                rel_path = str(target_file).replace("\\", "/")

            # 1. Package Vulnerabilities (CVEs)
            for v in res_block.get("Vulnerabilities", []):
                vid = v.get("VulnerabilityID") or f"TRIVY-{finding_counter:03d}"
                pkg_name = v.get("PkgName") or "package"
                inst_ver = v.get("InstalledVersion") or ""
                fix_ver = v.get("FixedVersion") or "upgrade available"
                raw_sev = (v.get("Severity") or "MEDIUM").upper()

                sev = FindingSeverity.MEDIUM
                if raw_sev == "CRITICAL":
                    sev = FindingSeverity.CRITICAL
                elif raw_sev == "HIGH":
                    sev = FindingSeverity.HIGH
                elif raw_sev in ("LOW", "INFO"):
                    sev = FindingSeverity.LOW

                findings.append(
                    RawSecurityFinding(
                        finding_id=f"TRIVY-VULN-{finding_counter:03d}",
                        scanner_source="Trivy SCA",
                        rule_id=f"trivy.vuln.{vid.lower()}",
                        severity=sev,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=1,
                        line_end=1,
                        code_snippet=f"{pkg_name}@{inst_ver} (Fixed in {fix_ver})",
                        raw_evidence=f"{vid}: {v.get('Title') or v.get('Description', 'Vulnerable package dependency detected')}",
                        cwe_id=(v.get("CweIDs") or ["CWE-1395"])[0] if v.get("CweIDs") else "CWE-1395",
                        owasp_category="A06:2021-Vulnerable and Outdated Components",
                        metadata={"pkg_name": pkg_name, "installed": inst_ver, "fixed": fix_ver, "cve": vid},
                    )
                )
                finding_counter += 1

            # 2. Misconfigurations
            for m in res_block.get("Misconfigurations", []):
                mid = m.get("ID") or f"MISCONFIG-{finding_counter:03d}"
                raw_sev = (m.get("Severity") or "MEDIUM").upper()
                sev = FindingSeverity.HIGH if raw_sev in ("CRITICAL", "HIGH") else FindingSeverity.MEDIUM
                lines_info = m.get("Lines") or {}
                l_start = lines_info.get("Start") or 1
                l_end = lines_info.get("End") or l_start

                findings.append(
                    RawSecurityFinding(
                        finding_id=f"TRIVY-CFG-{finding_counter:03d}",
                        scanner_source="Trivy Config",
                        rule_id=f"trivy.config.{mid.lower()}",
                        severity=sev,
                        classification=FindingClassification.HEURISTIC,
                        file_path=rel_path,
                        line_start=l_start,
                        line_end=l_end,
                        code_snippet=m.get("Resolution") or "Review security configuration.",
                        raw_evidence=f"{mid}: {m.get('Title') or m.get('Description', 'Configuration vulnerability detected')}",
                        cwe_id="CWE-16",
                        owasp_category="A05:2021-Security Misconfiguration",
                    )
                )
                finding_counter += 1

            # 3. Hardcoded Secrets
            for s in res_block.get("Secrets", []):
                sid = s.get("RuleID") or f"SECRET-{finding_counter:03d}"
                raw_sev = (s.get("Severity") or "CRITICAL").upper()
                sev = FindingSeverity.CRITICAL if raw_sev in ("CRITICAL", "HIGH") else FindingSeverity.HIGH
                l_start = s.get("StartLine") or 1
                l_end = s.get("EndLine") or l_start
                code_lines = s.get("Code", {}).get("Lines", [])
                code_content = code_lines[0].get("Content", "") if code_lines else ""

                findings.append(
                    RawSecurityFinding(
                        finding_id=f"TRIVY-SEC-{finding_counter:03d}",
                        scanner_source="Trivy Secret",
                        rule_id=f"trivy.secret.{sid.lower()}",
                        severity=sev,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=l_start,
                        line_end=l_end,
                        code_snippet=code_content.strip(),
                        raw_evidence=f"{sid}: {s.get('Title', 'Hardcoded secret detected by Trivy')}",
                        cwe_id="CWE-798",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                    )
                )
                finding_counter += 1

        status = ScannerExecutionStatus(
            scanner_name="Trivy Security Scanner",
            available=True,
            executed=True,
            rules_or_db_status=f"ACTIVE (Found {len(findings)} CVEs/misconfigs)",
            status_code="SUCCESS",
        )
        return findings, status

