"""
Scanner Agent Package (Process 2 of 3):
- `agent.py`      : ScannerAgent (BaseAgent implementation)
- `pipeline.py`   : SecureScanPipeline
- `inspectors.py` : ProjectInspector, CSharpLexicalAnalyzer, AspNetContextInspector
- `models.py`     : RawSecurityFinding, FindingSeverity, FindingClassification, ScanReportBundle
- `findings/`     : JSON bug findings (`sqli_001.json`) consumed by `remediator_agent`
"""

from .agent import ScannerAgent
from .inspectors import AspNetContextInspector, CSharpLexicalAnalyzer, ProjectInspector, ProjectProfile
from .models import (
    DependencyManifestAudit,
    DependencyRecord,
    FindingClassification,
    FindingSeverity,
    RawSecurityFinding,
    ScannerExecutionStatus,
    ScanReportBundle,
)
from .pipeline import SecureScanPipeline

__all__ = [
    "ScannerAgent",
    "SecureScanPipeline",
    "ProjectInspector",
    "ProjectProfile",
    "CSharpLexicalAnalyzer",
    "AspNetContextInspector",
    "RawSecurityFinding",
    "FindingSeverity",
    "FindingClassification",
    "ScannerExecutionStatus",
    "DependencyRecord",
    "DependencyManifestAudit",
    "ScanReportBundle",
]
