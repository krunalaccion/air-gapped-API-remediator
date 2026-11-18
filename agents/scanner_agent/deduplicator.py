"""
Deduplication utility for security findings across internal inspectors and external scanners (Semgrep, Trivy).

Detects overlapping and identical vulnerability findings based on:
1. Target file path normalization (handling cross-repo and relative path differences).
2. Code snippet normalization and exact / substring matching.
3. Matching or overlapping line ranges combined with compatible CWE categories.
4. Egress URL and rule-family semantic equivalence.

Supports ignoring and removing duplicate vulnerability records in memory and on disk.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, TypeVar

logger = logging.getLogger("mcp_server")

T = TypeVar("T")

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

EQUIVALENT_CWES = [
    {"CWE-327", "CWE-328"},  # Broken / weak crypto & weak hashing
    {"CWE-918", "CWE-1059", "CWE-20"},  # External egress, SSRF, Air-gap policy
    {"CWE-798", "CWE-259", "CWE-321"},  # Hardcoded credentials, secrets, tokens
    {"CWE-89", "CWE-564"},  # SQL Injection
    {"CWE-79", "CWE-80"},  # Cross-Site Scripting (XSS)
    {"CWE-502"},  # Insecure Deserialization
    {"CWE-319", "CWE-200"},  # Cleartext communication / missing HSTS
]


def normalize_file_path(path: Optional[str]) -> str:
    """Normalizes file path for cross-scanner comparison."""
    if not path:
        return ""
    p = str(path).replace("\\", "/").strip()
    p = re.sub(r"^\.?/+", "", p)
    return p.lower()


def paths_match(p1: Optional[str], p2: Optional[str]) -> bool:
    """Returns True if two file paths point to the same file."""
    norm1 = normalize_file_path(p1)
    norm2 = normalize_file_path(p2)
    if not norm1 or not norm2:
        return False
    if norm1 == norm2:
        return True
    return norm1.endswith("/" + norm2) or norm2.endswith("/" + norm1)


def normalize_snippet(snip: Optional[str]) -> str:
    """Strips comments, whitespace, quotes, and punctuation for semantic snippet comparison."""
    if not snip:
        return ""
    s = re.sub(r"//.*$|/\*.*?\*/", "", str(snip), flags=re.MULTILINE)
    return re.sub(r"[\s\'\",;`]+", "", s).lower()


def severity_rank(sev: Any) -> int:
    """Returns numeric rank for a finding severity."""
    val = sev.value if hasattr(sev, "value") else str(sev)
    return SEVERITY_ORDER.get(str(val).upper(), 0)


def cwes_compatible(cwe1: Optional[str], cwe2: Optional[str]) -> bool:
    """Returns True if two CWE identifiers represent the same vulnerability category."""
    c1 = (cwe1 or "").upper().strip()
    c2 = (cwe2 or "").upper().strip()
    if not c1 or not c2:
        return False
    if c1 == c2:
        return True
    for eq_set in EQUIVALENT_CWES:
        if c1 in eq_set and c2 in eq_set:
            return True
    return False


def get_rule_category(rule_id: Optional[str], cwe_id: Optional[str] = None) -> str:
    """Classifies a rule or CWE into a broad semantic vulnerability family."""
    r = (rule_id or "").lower()
    c = (cwe_id or "").upper()
    if any(k in r for k in ("egress", "network", "airgap", "url", "unwhitelisted")) or c in ("CWE-918", "CWE-1059"):
        return "egress"
    if any(k in r for k in ("crypto", "weak-algorithm", "hash", "md5", "sha1", "des")) or c in ("CWE-327", "CWE-328"):
        return "crypto"
    if any(k in r for k in ("secret", "credential", "hardcoded", "token", "apikey", "password")) or c in ("CWE-798", "CWE-259", "CWE-321"):
        return "secret"
    if any(k in r for k in ("sqli", "sql-injection", "sql")) or c == "CWE-89":
        return "sqli"
    if any(k in r for k in ("hsts", "header")) or c == "CWE-319":
        return "hsts"
    if any(k in r for k in ("deserial", "typenamehandling")) or c == "CWE-502":
        return "deserial"
    if any(k in r for k in ("xss", "cross-site")) or c == "CWE-79":
        return "xss"
    return r


def is_duplicate_finding(f1: Any, f2: Any) -> bool:
    """
    Returns True if finding f2 is a duplicate of finding f1.
    Accepts both dictionary payloads and RawSecurityFinding instances.
    """
    p1 = f1.file_path if hasattr(f1, "file_path") else (f1.get("file_path") or f1.get("file"))
    p2 = f2.file_path if hasattr(f2, "file_path") else (f2.get("file_path") or f2.get("file"))

    if not paths_match(p1, p2):
        return False

    l1_start = f1.line_start if hasattr(f1, "line_start") else (f1.get("line_start") or f1.get("line_number") or f1.get("line") or 1)
    l1_end = f1.line_end if hasattr(f1, "line_end") else (f1.get("line_end") or l1_start)
    l2_start = f2.line_start if hasattr(f2, "line_start") else (f2.get("line_start") or f2.get("line_number") or f2.get("line") or 1)
    l2_end = f2.line_end if hasattr(f2, "line_end") else (f2.get("line_end") or l2_start)

    snip1 = normalize_snippet(f1.code_snippet if hasattr(f1, "code_snippet") else f1.get("code_snippet"))
    snip2 = normalize_snippet(f2.code_snippet if hasattr(f2, "code_snippet") else f2.get("code_snippet"))

    cwe1 = f1.cwe_id if hasattr(f1, "cwe_id") else f1.get("cwe_id")
    cwe2 = f2.cwe_id if hasattr(f2, "cwe_id") else f2.get("cwe_id")

    rule1 = f1.rule_id if hasattr(f1, "rule_id") else (f1.get("rule_id") or f1.get("rule") or "")
    rule2 = f2.rule_id if hasattr(f2, "rule_id") else (f2.get("rule_id") or f2.get("rule") or "")

    cat1 = get_rule_category(rule1, cwe1)
    cat2 = get_rule_category(rule2, cwe2)

    # 1. Exact normalized snippet match
    if snip1 and snip2 and len(snip1) >= 6:
        if snip1 == snip2:
            if abs(l1_start - l2_start) <= 5 or (l1_start <= 1 and l2_start <= 1):
                return True

    # 2. Substring snippet match
    if snip1 and snip2 and min(len(snip1), len(snip2)) >= 8:
        if (snip1 in snip2 or snip2 in snip1) and abs(l1_start - l2_start) <= 3:
            return True

    # 3. Same line or overlapping line range with compatible category or CWE
    lines_overlap = max(l1_start, l2_start) <= min(l1_end, l2_end) + 2
    if lines_overlap and (l1_start > 1 or l2_start > 1):
        if cwes_compatible(cwe1, cwe2):
            return True
        if cat1 and cat2 and cat1 == cat2:
            return True

    # 4. Same line (line == 1) with matching category and matching snippet keywords
    if l1_start == l2_start == 1 and cat1 and cat2 and cat1 == cat2:
        if snip1 and snip2 and (snip1 in snip2 or snip2 in snip1):
            return True

    return False


def deduplicate_findings(
    findings: List[T],
    remove_files: bool = False,
    findings_dir: Optional[Path] = None,
) -> List[T]:
    """
    Filters out duplicate vulnerabilities from a list of findings.
    If remove_files is True, deletes any duplicate finding JSON files found on disk.
    """
    deduped: List[T] = []

    for inc in findings:
        dup_found = False
        for cur in deduped:
            if is_duplicate_finding(cur, inc):
                dup_found = True
                inc_id = inc.finding_id if hasattr(inc, "finding_id") else inc.get("finding_id", "FINDING")
                cur_id = cur.finding_id if hasattr(cur, "finding_id") else cur.get("finding_id", "FINDING")
                logger.info(
                    "Duplicate vulnerability detected: %s is a duplicate of %s (file: %s). Ignoring duplicate.",
                    inc_id,
                    cur_id,
                    getattr(inc, "file_path", inc.get("file_path") if isinstance(inc, dict) else "unknown"),
                )

                # Promote canonical finding severity if duplicate has higher severity
                inc_sev = inc.severity if hasattr(inc, "severity") else (inc.get("severity") if isinstance(inc, dict) else None)
                cur_sev = cur.severity if hasattr(cur, "severity") else (cur.get("severity") if isinstance(cur, dict) else None)
                if severity_rank(inc_sev) > severity_rank(cur_sev):
                    if hasattr(cur, "severity"):
                        try:
                            cur.severity = inc.severity
                        except Exception:
                            import dataclasses
                            if dataclasses.is_dataclass(cur):
                                cur_idx = deduped.index(cur)
                                deduped[cur_idx] = dataclasses.replace(cur, severity=inc.severity)
                    elif isinstance(cur, dict):
                        cur["severity"] = inc.get("severity")

                # Remove duplicate file from disk if requested
                if remove_files and findings_dir and findings_dir.exists():
                    f_candidates = []
                    inc_file = inc.get("_source_file") if isinstance(inc, dict) else None
                    if inc_file:
                        f_candidates.append(findings_dir / inc_file)
                    if inc_id:
                        fname_clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", inc_id.lower()) + ".json"
                        f_candidates.append(findings_dir / fname_clean)
                        # Also check without hyphens/underscores if any
                        f_candidates.append(findings_dir / f"{inc_id.lower().replace('_', '-')}.json")
                    for f_cand in f_candidates:
                        if f_cand.exists():
                            try:
                                f_cand.unlink()
                                logger.info("Removed duplicate vulnerability finding file from disk: %s", f_cand.name)
                            except Exception as exc:
                                logger.warning("Could not delete duplicate finding file %s: %s", f_cand, exc)
                break

        if not dup_found:
            deduped.append(inc)

    return deduped


def clean_duplicate_finding_files(findings_dir: Path) -> List[str]:
    """
    Scans a directory of finding JSON files, identifies duplicates, and unlinks them.
    Returns list of removed filenames.
    """
    import json

    removed_files: List[str] = []
    if not findings_dir or not findings_dir.exists():
        return removed_files

    json_files = sorted(findings_dir.glob("*.json"))
    loaded: List[tuple[Path, Dict[str, Any]]] = []
    for jf in json_files:
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
            data["_source_file"] = jf.name
            loaded.append((jf, data))
        except Exception:
            continue

    accepted: List[tuple[Path, Dict[str, Any]]] = []
    for jf, data in loaded:
        is_dup = False
        for acc_path, acc_data in accepted:
            if is_duplicate_finding(acc_data, data):
                is_dup = True
                try:
                    jf.unlink()
                    logger.info("Removed duplicate finding file %s (duplicate of %s)", jf.name, acc_data.get("finding_id"))
                    removed_files.append(jf.name)
                except Exception as exc:
                    logger.warning("Could not remove duplicate finding file %s: %s", jf.name, exc)
                break
        if not is_dup:
            accepted.append((jf, data))

    return removed_files
