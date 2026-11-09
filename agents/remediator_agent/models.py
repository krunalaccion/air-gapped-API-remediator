from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class Finding:
    """Represents an incoming security/bug finding from a scanner or external source."""
    finding_id: str
    rule_id: str
    severity: str
    file_path: str
    line_number: int
    message: str
    code_snippet: str
    repository: str
    status: str = "NEW"
    cwe_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        finding_id = str(data.get("finding_id") or data.get("id") or "FINDING")
        rule_id = str(data.get("rule_id") or data.get("rule") or "security-violation")
        severity = str(data.get("severity") or "MEDIUM").upper()
        file_path = str(data.get("file_path") or data.get("file") or "")
        line_num = int(data.get("line_number") or data.get("line_start") or data.get("line") or 1)
        message = str(data.get("message") or data.get("description") or data.get("raw_evidence") or "Security finding")
        code_snippet = str(data.get("code_snippet") or "")
        repository = str(data.get("repository") or "repository")
        status = str(data.get("status", "NEW")).upper()
        cwe_id = str(data.get("cwe_id", "")) if data.get("cwe_id") else None

        return cls(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=severity,
            file_path=file_path,
            line_number=line_num,
            message=message,
            code_snippet=code_snippet,
            repository=repository,
            status=status,
            cwe_id=cwe_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FixProposal:
    """Represents the LLM-generated remediation proposal."""
    explanation: str
    fixed_file_content: str
    remediation_summary: str
    confidence: str = "HIGH"


@dataclass
class FixReport:
    """Final execution report produced by the BugFixerAgent."""
    finding: Finding
    target_file: str
    applied: bool
    provider: str
    explanation: str
    remediation_summary: str
    diff: str
    backup_path: Optional[str] = None
    error: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding": self.finding.to_dict(),
            "target_file": self.target_file,
            "applied": self.applied,
            "provider": self.provider,
            "explanation": self.explanation,
            "remediation_summary": self.remediation_summary,
            "diff": self.diff,
            "backup_path": self.backup_path,
            "error": self.error,
            "timestamp": self.timestamp,
        }

