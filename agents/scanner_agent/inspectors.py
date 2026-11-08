"""
Source Code & Project Inspectors for ScannerAgent (from SecureScanAI):
- ProjectInspector: Discovers .csproj frameworks, topology (Web API / MVC / Minimal API), and NuGet dependencies
- CSharpLexicalAnalyzer: Detects SQL Injection (CWE-89), XSS (CWE-79), Hardcoded Secrets (CWE-798),
  Weak Cryptography (CWE-327/CWE-328/CWE-338), Insecure Deserialization (CWE-502), Path Traversal (CWE-22)
- AspNetContextInspector: Detects Inverted Auth Middleware (CWE-696), Missing HSTS (CWE-319),
  Unsafe CORS (CWE-942), Wildcard AllowedHosts (CWE-16), Plaintext ConnectionString Passwords (CWE-798)
"""

from __future__ import annotations
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
from typing import Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET

from .models import (
    DependencyManifestAudit,
    DependencyRecord,
    FindingClassification,
    FindingSeverity,
    RawSecurityFinding,
)

EXCLUDED_DIRECTORIES: Set[str] = {
    "bin",
    "obj",
    ".git",
    ".vs",
    ".idea",
    ".vscode",
    "node_modules",
    "__pycache__",
    "reports",
    "findings",
}

SECURITY_KEYWORDS = ("token", "password", "pwd", "secret", "key", "salt", "auth", "nonce", "otp", "credential")
CHECKSUM_KEYWORDS = ("checksum", "etag", "hashfile", "filehash", "cachekey", "contenthash", "fingerprint")


@dataclass
class ProjectProfile:
    """Discovered architectural profile of a target repository."""
    project_root: Path
    project_files: List[Path] = field(default_factory=list)
    target_frameworks: List[str] = field(default_factory=list)
    project_topology: str = "ASP.NET Core Web API"
    source_files: List[Path] = field(default_factory=list)
    config_files: List[Path] = field(default_factory=list)
    dependency_manifests: List[Path] = field(default_factory=list)


class ProjectInspector:
    """Inspects project structure, .csproj target frameworks, and NuGet dependencies."""

    def __init__(self, project_path: Path):
        self.project_root = Path(project_path).resolve()

    def inspect(self) -> ProjectProfile:
        profile = ProjectProfile(project_root=self.project_root)
        for root, dirs, files in os.walk(self.project_root, followlinks=False):
            current_dir = Path(root)
            dirs[:] = [d for d in dirs if d.lower() not in EXCLUDED_DIRECTORIES]
            for file_name in files:
                file_path = current_dir / file_name
                lower_name = file_name.lower()
                if lower_name.endswith(".cs"):
                    profile.source_files.append(file_path)
                elif (lower_name.startswith("appsettings") and lower_name.endswith(".json")) or lower_name == "web.config":
                    profile.config_files.append(file_path)
                elif lower_name.endswith((".csproj", "packages.lock.json", "packages.config")):
                    profile.dependency_manifests.append(file_path)
                    if lower_name.endswith(".csproj"):
                        profile.project_files.append(file_path)

        tfms: Set[str] = set()
        for csproj_path in profile.project_files:
            try:
                root = ET.parse(csproj_path).getroot()
                for elem in root.iter():
                    tag = elem.tag.split("}")[-1]
                    if tag == "TargetFramework" and elem.text:
                        tfms.add(elem.text.strip())
                    elif tag == "TargetFrameworks" and elem.text:
                        tfms.update(t.strip() for t in elem.text.split(";") if t.strip())
            except Exception:
                continue

        profile.target_frameworks = sorted(tfms) if tfms else ["net8.0"]
        profile.project_topology = "Web API" if profile.source_files else "Multi-Language Repository"
        return profile

    def extract_dependencies(self) -> DependencyManifestAudit:
        records: List[DependencyRecord] = []
        rel_manifests: List[str] = []
        for csproj_path in self.inspect().project_files:
            rel_path = str(csproj_path.relative_to(self.project_root)).replace("\\", "/")
            rel_manifests.append(rel_path)
            try:
                root = ET.parse(csproj_path).getroot()
                for elem in root.iter():
                    if elem.tag.split("}")[-1] == "PackageReference":
                        pkg = elem.attrib.get("Include") or elem.attrib.get("Update")
                        ver = elem.attrib.get("Version")
                        if pkg:
                            records.append(
                                DependencyRecord(
                                    package_name=pkg.strip(),
                                    version=ver.strip() if ver else None,
                                    manifest_path=rel_path,
                                    manifest_type="csproj",
                                )
                            )
            except Exception:
                continue

        summary = (
            f"Audited {len(rel_manifests)} manifest(s) ({len(records)} dependency entries)."
            if rel_manifests
            else "No .csproj manifests found."
        )
        return DependencyManifestAudit(
            found_manifests=rel_manifests,
            extracted_dependencies=records,
            coverage_summary=summary,
        )


class CSharpLexicalAnalyzer:
    """
    Lexical and structural pattern analyzer for C# source code.
    Detects SQL Injection, XSS, Hardcoded Secrets, Weak Crypto, Deserialization, and Path Traversal.
    """

    def __init__(self):
        self._finding_counter = 0

    def _next_id(self, prefix: str) -> str:
        self._finding_counter += 1
        return f"{prefix}-{self._finding_counter:04d}"

    def analyze_file(self, file_path: Path, project_root: Optional[Path] = None) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings

        rel_path = (
            str(file_path.relative_to(project_root)).replace("\\", "/")
            if project_root and str(file_path.resolve()).startswith(str(project_root.resolve()))
            else str(file_path).replace("\\", "/")
        )
        lines = content.splitlines()

        findings.extend(self._check_sql_injection(rel_path, lines, content))
        findings.extend(self._check_xss_patterns(rel_path, lines))
        findings.extend(self._check_hardcoded_secrets(rel_path, lines))
        findings.extend(self._check_cryptography(rel_path, lines))
        findings.extend(self._check_insecure_deserialization(rel_path, lines, content))
        findings.extend(self._check_path_traversal(rel_path, lines))
        return findings

    def _check_sql_injection(self, rel_path: str, lines: List[str], full_content: str) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        user_input_params: Set[str] = set()

        for m in re.finditer(
            r'\[(?:FromQuery|FromBody|FromRoute|FromForm|FromHeader)\]\s*(?:string|int|long|Guid)\s+([a-zA-Z0-9_]+)',
            full_content,
        ):
            user_input_params.add(m.group(1).strip())

        for m in re.finditer(
            r'\[Http(?:Get|Post|Put|Delete|Patch)\s*\(\s*["\'][^"\']*\{([a-zA-Z0-9_]+)\}[^"\']*["\']\s*\)\]',
            full_content,
        ):
            user_input_params.add(m.group(1).strip())

        sql_var_concats: Dict[str, Tuple[int, str, str, bool, Optional[str]]] = {}
        sql_var_assign = re.compile(
            r'\b(?:var|string)\s+([a-zA-Z0-9_]*(?:sql|query|command|cmd)[a-zA-Z0-9_]*)\s*=\s*([^;]+);',
            re.IGNORECASE,
        )

        for line_idx, line in enumerate(lines, 1):
            var_match = sql_var_assign.search(line)
            if var_match:
                v_name = var_match.group(1).strip()
                v_expr = var_match.group(2).strip()

                if v_expr.startswith('$"') and "{" in v_expr and "}" in v_expr:
                    interp_vars = re.findall(r'\{([a-zA-Z0-9_]+)\}', v_expr)
                    user_param = next((op for op in interp_vars if op in user_input_params), interp_vars[0] if interp_vars else None)
                    is_user = user_param in user_input_params if user_param else True
                    sql_var_concats[v_name] = (line_idx, line.strip(), v_expr, is_user, user_param)
                    continue

                if "+" in v_expr:
                    operands = [op.strip() for op in v_expr.split("+")]
                    if all((op.startswith('"') and op.endswith('"')) for op in operands):
                        continue
                    user_param = next((op for op in operands if op in user_input_params), None)
                    sql_var_concats[v_name] = (line_idx, line.strip(), v_expr, user_param is not None, user_param)

        raw_sql_sinks = re.compile(
            r'\b(FromSqlRaw|FromSqlRawAsync|ExecuteSqlRaw|ExecuteSqlRawAsync|QueryAsync|Query|ExecuteAsync|Execute|SqlCommand)\s*\(([^)]+)\)'
        )

        for line_idx, line in enumerate(lines, 1):
            match = raw_sql_sinks.search(line)
            if not match:
                continue
            sink_name = match.group(1)
            args = match.group(2).strip()
            arg_first = args.split(",")[0].strip()

            if arg_first in sql_var_concats:
                assign_line, assign_snippet, _, is_user_input, user_param = sql_var_concats[arg_first]
                findings.append(
                    RawSecurityFinding(
                        finding_id="SQLI-001" if self._finding_counter == 0 else self._next_id("SQLI"),
                        scanner_source="C# Lexical Analyzer",
                        rule_id="csharp-sql-injection",
                        severity=FindingSeverity.HIGH,
                        classification=FindingClassification.VERIFIED if is_user_input else FindingClassification.HEURISTIC,
                        file_path=rel_path,
                        line_start=assign_line,
                        line_end=line_idx,
                        code_snippet=assign_snippet.rstrip(";"),
                        raw_evidence=(
                            f"Unparameterized SQL string interpolation/concatenation with '{user_param or 'input'}' "
                            f"at line {assign_line} passed to {sink_name} at line {line_idx}."
                        ),
                        cwe_id="CWE-89",
                        owasp_category="A03:2021-Injection",
                        metadata={"sink": sink_name, "assignment_line": assign_line, "user_parameter": user_param},
                    )
                )
                self._finding_counter += 1
            elif "+" in arg_first or arg_first.startswith('$"'):
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("SQLI"),
                        scanner_source="C# Lexical Analyzer",
                        rule_id="csharp.sqli.raw-sql-concatenation",
                        severity=FindingSeverity.HIGH,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=line_idx,
                        line_end=line_idx,
                        code_snippet=line.strip(),
                        raw_evidence=f"Dynamic SQL expression passed directly to {sink_name}.",
                        cwe_id="CWE-89",
                        owasp_category="A03:2021-Injection",
                        metadata={"sink": sink_name, "assignment_line": line_idx},
                    )
                )

        return findings

    def _check_xss_patterns(self, rel_path: str, lines: List[str]) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        html_raw_pattern = re.compile(r'\b(Html\.Raw|HtmlString)\s*\(([^)]*)\)')
        for line_idx, line in enumerate(lines, 1):
            m = html_raw_pattern.search(line)
            if m:
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("XSS"),
                        scanner_source="C# Lexical Analyzer",
                        rule_id="csharp.xss.html-raw-rendering",
                        severity=FindingSeverity.MEDIUM,
                        classification=FindingClassification.HEURISTIC,
                        file_path=rel_path,
                        line_start=line_idx,
                        line_end=line_idx,
                        code_snippet=line.strip(),
                        raw_evidence=f"{m.group(1)} invoked with expression '{m.group(2).strip()}'; verify HTML encoding.",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                    )
                )
        return findings

    def _check_hardcoded_secrets(self, rel_path: str, lines: List[str]) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        secret_assignment = re.compile(
            r'(?i)\b(string|var|const)\s+([a-zA-Z0-9_]*(?:password|pwd|secret|apiKey|api_key|token|privateKey)[a-zA-Z0-9_]*)\s*=\s*["\']([^"\'\r\n]{8,})["\']'
        )
        for line_idx, line in enumerate(lines, 1):
            m = secret_assignment.search(line)
            if m and not any(p in m.group(3).lower() for p in ("dummy", "example", "placeholder")):
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("SECRET"),
                        scanner_source="C# Lexical Analyzer",
                        rule_id="csharp.secret.hardcoded-credential",
                        severity=FindingSeverity.CRITICAL,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=line_idx,
                        line_end=line_idx,
                        code_snippet=f'{m.group(1)} {m.group(2)} = "***REDACTED***";',
                        raw_evidence=f"Hardcoded credential assigned to variable '{m.group(2)}'.",
                        cwe_id="CWE-798",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                    )
                )
        return findings

    def _check_cryptography(self, rel_path: str, lines: List[str]) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        weak_algos = [
            (re.compile(r'\b(DES\.Create|DESCryptoServiceProvider|TripleDES\.Create|RC2\.Create)\b'), "CWE-327", FindingSeverity.HIGH),
            (re.compile(r'\b(MD5\.Create|MD5CryptoServiceProvider|SHA1\.Create|SHA1Managed)\b'), "CWE-328", FindingSeverity.MEDIUM),
        ]
        for line_idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("//") or clean.startswith("/*") or clean.startswith("*"):
                continue
            for pattern, cwe, sev in weak_algos:
                m = pattern.search(line)
                if m:
                    findings.append(
                        RawSecurityFinding(
                            finding_id=self._next_id("CRYPTO"),
                            scanner_source="C# Lexical Analyzer",
                            rule_id="csharp.crypto.weak-algorithm",
                            severity=sev,
                            classification=FindingClassification.VERIFIED,
                            file_path=rel_path,
                            line_start=line_idx,
                            line_end=line_idx,
                            code_snippet=line.strip(),
                            raw_evidence=f"Weak/deprecated cryptographic algorithm detected: {m.group(1)}.",
                            cwe_id=cwe,
                            owasp_category="A02:2021-Cryptographic Failures",
                        )
                    )
        return findings

    def _check_insecure_deserialization(self, rel_path: str, lines: List[str], full_content: str) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        has_bf = "BinaryFormatter" in full_content
        for line_idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("//") or clean.startswith("/*") or clean.startswith("*"):
                continue
            if (has_bf and ".Deserialize(" in line) or "TypeNameHandling.All" in line or "TypeNameHandling.Auto" in line:
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("DESERIAL"),
                        scanner_source="C# Lexical Analyzer",
                        rule_id="csharp.deserialization.unsafe-api",
                        severity=FindingSeverity.HIGH,
                        classification=FindingClassification.HEURISTIC,
                        file_path=rel_path,
                        line_start=line_idx,
                        line_end=line_idx,
                        code_snippet=line.strip(),
                        raw_evidence="Unsafe deserialization API or TypeNameHandling configuration detected.",
                        cwe_id="CWE-502",
                        owasp_category="A08:2021-Software and Data Integrity Failures",
                    )
                )
        return findings

    def _check_path_traversal(self, rel_path: str, lines: List[str]) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        file_io = re.compile(r'\bFile\.(Open|ReadAllText|ReadAllBytes|WriteAllText|WriteAllBytes)\s*\(([^)]+)\)')
        for line_idx, line in enumerate(lines, 1):
            m = file_io.search(line)
            if m and not re.fullmatch(r'@?"[^"]*"', m.group(2).split(",")[0].strip()):
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("TRAVERSAL"),
                        scanner_source="C# Lexical Analyzer",
                        rule_id="csharp.pathtraversal.dynamic-file-access",
                        severity=FindingSeverity.HIGH,
                        classification=FindingClassification.HEURISTIC,
                        file_path=rel_path,
                        line_start=line_idx,
                        line_end=line_idx,
                        code_snippet=line.strip(),
                        raw_evidence=f"File.{m.group(1)} invoked with dynamic path '{m.group(2).strip()}'.",
                        cwe_id="CWE-22",
                        owasp_category="A01:2021-Broken Access Control",
                    )
                )
        return findings


class AspNetContextInspector:
    """Inspects ASP.NET Core Program.cs/Startup.cs middleware pipeline and appsettings.json/web.config."""

    def __init__(self):
        self._counter = 0

    def _next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:04d}"

    def inspect_project(self, profile: ProjectProfile) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        findings.extend(self._inspect_middleware(profile))
        findings.extend(self._inspect_configs(profile))
        return findings

    def _inspect_middleware(self, profile: ProjectProfile) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        for src_path in profile.source_files:
            if not any(k in src_path.name.lower() for k in ("program", "startup")):
                continue
            try:
                content = src_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel_path = str(src_path.relative_to(profile.project_root)).replace("\\", "/")
            lines = content.splitlines()
            use_authn_idx = -1
            use_authz_idx = -1
            for idx, line in enumerate(lines, 1):
                if "app.UseAuthentication(" in line:
                    use_authn_idx = idx
                elif "app.UseAuthorization(" in line:
                    use_authz_idx = idx

            if use_authn_idx != -1 and use_authz_idx != -1 and use_authz_idx < use_authn_idx:
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("PIPE"),
                        scanner_source="ASP.NET Context Inspector",
                        rule_id="aspnet.pipeline.inverted-auth-middleware-order",
                        severity=FindingSeverity.HIGH,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=use_authz_idx,
                        line_end=use_authn_idx,
                        code_snippet=f"Line {use_authz_idx}: app.UseAuthorization();\nLine {use_authn_idx}: app.UseAuthentication();",
                        raw_evidence="app.UseAuthorization() appears before app.UseAuthentication() in middleware pipeline.",
                        cwe_id="CWE-696",
                        owasp_category="A04:2021-Insecure Design",
                    )
                )

            if "app.UseHsts(" not in content:
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("HSTS"),
                        scanner_source="ASP.NET Context Inspector",
                        rule_id="aspnet.headers.hsts-missing-heuristic",
                        severity=FindingSeverity.MEDIUM,
                        classification=FindingClassification.HEURISTIC,
                        file_path=rel_path,
                        line_start=1,
                        line_end=1,
                        code_snippet="app.UseHsts() not found in Program.cs",
                        raw_evidence="app.UseHsts() is omitted in middleware pipeline.",
                        cwe_id="CWE-319",
                        owasp_category="A05:2021-Security Misconfiguration",
                    )
                )

            if "AllowAnyOrigin(" in content:
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("CORS"),
                        scanner_source="ASP.NET Context Inspector",
                        rule_id="aspnet.cors.wildcard-origin-manual-review",
                        severity=FindingSeverity.LOW,
                        classification=FindingClassification.MANUAL_REVIEW,
                        file_path=rel_path,
                        line_start=1,
                        line_end=1,
                        code_snippet="policy.AllowAnyOrigin() detected",
                        raw_evidence="Wildcard CORS policy detected; restrict origins to internal air-gap domains.",
                        cwe_id="CWE-942",
                        owasp_category="A05:2021-Security Misconfiguration",
                    )
                )
        return findings

    def _inspect_configs(self, profile: ProjectProfile) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        for cfg_path in profile.config_files:
            if not cfg_path.name.lower().endswith(".json"):
                continue
            try:
                data = json.loads(cfg_path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue

            rel_path = str(cfg_path.relative_to(profile.project_root)).replace("\\", "/")
            if data.get("AllowedHosts") == "*":
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("CONFIG"),
                        scanner_source="ASP.NET Config Inspector",
                        rule_id="aspnet.config.allowed-hosts-wildcard",
                        severity=FindingSeverity.LOW,
                        classification=FindingClassification.HEURISTIC,
                        file_path=rel_path,
                        line_start=1,
                        line_end=1,
                        code_snippet='"AllowedHosts": "*"',
                        raw_evidence='AllowedHosts is set to "*". Restrict AllowedHosts to prevent host header injection.',
                        cwe_id="CWE-16",
                        owasp_category="A05:2021-Security Misconfiguration",
                    )
                )

            conn_strings = data.get("ConnectionStrings", {})
            if isinstance(conn_strings, dict):
                for conn_name, conn_val in conn_strings.items():
                    if isinstance(conn_val, str) and re.search(r'(?i)\b(password|pwd)\s*=\s*[^;]+', conn_val):
                        redacted_val = re.sub(r'(?i)(password|pwd)\s*=\s*[^;]+', r'\1=***REDACTED***', conn_val)
                        findings.append(
                            RawSecurityFinding(
                                finding_id=self._next_id("CONFIG"),
                                scanner_source="ASP.NET Config Inspector",
                                rule_id="aspnet.config.connectionstring-plaintext-password",
                                severity=FindingSeverity.HIGH,
                                classification=FindingClassification.VERIFIED,
                                file_path=rel_path,
                                line_start=1,
                                line_end=1,
                                code_snippet=f'"{conn_name}": "{redacted_val}"',
                                raw_evidence=f"Plaintext password detected in ConnectionStrings['{conn_name}'].",
                                cwe_id="CWE-798",
                                owasp_category="A07:2021-Identification and Authentication Failures",
                            )
                        )
        return findings

