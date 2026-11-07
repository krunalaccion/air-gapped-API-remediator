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

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        required_fields = [
            "finding_id",
            "rule_id",
            "severity",
            "file_path",
            "line_number",
            "message",
            "code_snippet",
            "repository",
        ]
        missing = [f for f in required_fields if f not in data]
        if missing:
            raise ValueError(f"Missing required finding fields: {', '.join(missing)}")

        return cls(
            finding_id=str(data["finding_id"]),
            rule_id=str(data["rule_id"]),
            severity=str(data["severity"]).upper(),
            file_path=str(data["file_path"]),
            line_number=int(data["line_number"]),
            message=str(data["message"]),
            code_snippet=str(data["code_snippet"]),
            repository=str(data["repository"]),
            status=str(data.get("status", "NEW")).upper(),
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

