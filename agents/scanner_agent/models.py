"""
Data models for ScannerAgent (Process 2: SAST, C# Lexical, ASP.NET Context & Air-Gap Egress Scanning).
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingClassification(str, Enum):
    VERIFIED = "VERIFIED"
    HEURISTIC = "HEURISTIC"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(frozen=True)
class RawSecurityFinding:
    """Immutable security finding discovered by ScannerAgent."""
    finding_id: str
    scanner_source: str
    rule_id: str
    severity: FindingSeverity
    classification: FindingClassification
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    raw_evidence: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value if isinstance(self.severity, Enum) else str(self.severity)
        data["classification"] = (
            self.classification.value if isinstance(self.classification, Enum) else str(self.classification)
        )
        return data


@dataclass
class ScannerExecutionStatus:
    """Execution status of an individual scanner module."""
    scanner_name: str
    available: bool = True
    executed: bool = True
    skipped_reason: Optional[str] = None
    rules_or_db_status: str = "ACTIVE"
    status_code: str = "SUCCESS"


@dataclass
class DependencyRecord:
    """Extracted .NET NuGet package dependency record."""
    package_name: str
    version: Optional[str] = None
    manifest_path: str = ""
    manifest_type: str = ""
    dependency_type: str = "Direct"
    target_framework: Optional[str] = None


@dataclass
class DependencyManifestAudit:
    """Summary of project dependency manifests."""
    found_manifests: List[str] = field(default_factory=list)
    extracted_dependencies: List[DependencyRecord] = field(default_factory=list)
    coverage_summary: str = "NO MANIFESTS AUDITED"


@dataclass
class ScanReportBundle:
    """Consolidated scan result bundle produced by SecureScanPipeline."""
    scan_timestamp: str
    project_path: str
    target_frameworks: List[str]
    project_topology: str
    overall_scan_state: str
    overall_state_label: str
    severity_counts: Dict[str, int]
    findings: List[RawSecurityFinding]
    scanner_statuses: List[ScannerExecutionStatus]
    dependency_audit: DependencyManifestAudit
    target_unmodified_verified: bool = True
    html_report_path: Optional[Path] = None
    json_report_path: Optional[Path] = None
    sarif_report_path: Optional[Path] = None

