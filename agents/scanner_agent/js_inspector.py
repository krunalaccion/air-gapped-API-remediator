"""
JavaScript / TypeScript / Node.js Express Lexical & Structural SAST Analyzer.
Detects OWASP Top 10 & CWE vulnerabilities across Node.js REST APIs:
  - SQL Injection (CWE-89)
  - OS Command Injection (CWE-78)
  - Dynamic Code Evaluation / eval() (CWE-95)
  - Insecure Direct Object Reference / IDOR (CWE-639)
  - Path Traversal / Arbitrary File Read (CWE-22)
  - Header-Based Auth Bypass & Weak JWT 'none' Alg (CWE-287)
  - Hardcoded Secrets & Fallback JWT Keys (CWE-798)
  - Plaintext Password Storage (CWE-256)
  - Sensitive PII & Secret Exposure (CWE-359)
  - Stack Trace & Query Information Leakage (CWE-209)
  - Overly Permissive CORS Policy (CWE-942)
  - Prototype Pollution via Unsafe Merge (CWE-1321)
  - Server-Side Request Forgery / SSRF (CWE-918)
  - Unvalidated Open Redirect (CWE-601)
"""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Dict, List, Optional, Set, Tuple

from .models import (
    FindingClassification,
    FindingSeverity,
    RawSecurityFinding,
)


@dataclass
class JSFunctionBlock:
    """Represents a parsed JavaScript/TypeScript function body with 1-based line numbers."""
    name: str
    params: str
    start_line: int
    end_line: int
    raw_lines: List[Tuple[int, str]]
    code_lines: List[Tuple[int, str]]

    @property
    def code_text(self) -> str:
        return "\n".join(line for _, line in self.code_lines)


def strip_js_comments_preserving_lines(content: str) -> List[str]:
    """
    Strips JS/TS single-line (//) and multi-line (/* ... */) comments while preserving
    string literals (including https:// URLs) and exact 1-based line alignment.
    """
    out: List[str] = []
    n = len(content)
    i = 0
    in_quote: Optional[str] = None
    in_line_comment = False
    in_block_comment = False

    while i < n:
        ch = content[i]
        nxt = content[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                out.append("  ")
                i += 2
            elif ch == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" ")
                i += 1
            continue

        if in_quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(nxt)
                i += 2
                continue
            if ch == in_quote:
                in_quote = None
            i += 1
            continue

        if ch in ("'", '"', "`"):
            in_quote = ch
            out.append(ch)
            i += 1
        elif ch == "/" and nxt == "/":
            in_line_comment = True
            out.append("  ")
            i += 2
        elif ch == "/" and nxt == "*":
            in_block_comment = True
            out.append("  ")
            i += 2
        else:
            out.append(ch)
            i += 1

    return "".join(out).splitlines()


def extract_js_functions(raw_lines: List[str], code_lines: List[str]) -> List[JSFunctionBlock]:
    """Extracts named and arrow JS functions with brace-counted spans."""
    functions: List[JSFunctionBlock] = []
    func_decl_re = re.compile(
        r'^\s*(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*\{'
        r'|^\s*(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>\s*\{'
    )

    total = len(code_lines)
    idx = 0
    while idx < total:
        line = code_lines[idx]
        m = func_decl_re.search(line)
        if not m:
            idx += 1
            continue

        fn_name = m.group(1) or m.group(3) or "anonymous"
        params = (m.group(2) if m.group(1) else m.group(4)) or ""
        start_idx = idx
        brace_depth = 0
        started = False
        end_idx = idx

        # Strip quoted contents simply for balanced brace tracking
        for cur in range(idx, total):
            cleaned = re.sub(r"'[^']*'|\"[^\"]*\"", "", code_lines[cur])
            opens = cleaned.count("{")
            closes = cleaned.count("}")
            if opens > 0:
                started = True
            brace_depth += opens - closes
            end_idx = cur
            if started and brace_depth <= 0:
                break

        functions.append(
            JSFunctionBlock(
                name=fn_name,
                params=params,
                start_line=start_idx + 1,
                end_line=end_idx + 1,
                raw_lines=[(i + 1, raw_lines[i]) for i in range(start_idx, end_idx + 1)],
                code_lines=[(i + 1, code_lines[i]) for i in range(start_idx, end_idx + 1)],
            )
        )
        idx = end_idx + 1

    return functions


class JavaScriptLexicalAnalyzer:
    """
    Lexical and structural security analyzer for Node.js / Express / JS / TS source files.
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
        raw_lines = content.splitlines()
        code_lines = strip_js_comments_preserving_lines(content)
        functions = extract_js_functions(raw_lines, code_lines)

        findings.extend(self._check_sql_injection(rel_path, raw_lines, code_lines))
        findings.extend(self._check_command_injection(rel_path, raw_lines, code_lines))
        findings.extend(self._check_code_injection(rel_path, raw_lines, code_lines))
        findings.extend(self._check_idor(rel_path, functions))
        findings.extend(self._check_path_traversal(rel_path, functions))
        findings.extend(self._check_auth_bypass(rel_path, raw_lines, code_lines, functions))
        findings.extend(self._check_hardcoded_secrets(rel_path, raw_lines, code_lines))
        findings.extend(self._check_plaintext_passwords(rel_path, functions))
        findings.extend(self._check_sensitive_pii_exposure(rel_path, functions))
        findings.extend(self._check_error_leakage(rel_path, raw_lines, code_lines, functions))
        findings.extend(self._check_permissive_cors(rel_path, raw_lines, code_lines))
        findings.extend(self._check_prototype_pollution(rel_path, functions))
        findings.extend(self._check_ssrf(rel_path, functions))
        findings.extend(self._check_open_redirect(rel_path, functions))
        return findings

    def _check_sql_injection(
        self, rel_path: str, raw_lines: List[str], code_lines: List[str]
    ) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        sql_assign_re = re.compile(
            r'\b(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*([^;]+);?'
        )
        sql_kw_re = re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE)\b', re.IGNORECASE)
        sql_sink_re = re.compile(
            r'\b(?:rawQuery|db\.(?:all|run|get|exec)|(?:sequelize|pool|client|conn|connection)\.query|knex\.raw)\s*\(([^)]+)\)'
        )

        dynamic_sql_vars: Dict[str, Tuple[int, str, str]] = {}
        reported_lines: Set[int] = set()

        for idx, line in enumerate(code_lines, start=1):
            stripped = line.strip()
            if not stripped or re.match(r'^err\.\w+\s*=', stripped):
                continue

            m_assign = sql_assign_re.search(line)
            if m_assign:
                v_name = m_assign.group(1)
                v_expr = m_assign.group(2).strip()
                has_sql = bool(sql_kw_re.search(v_expr))
                has_interp = ("`" in v_expr and "${" in v_expr) or (
                    "+" in v_expr and any(q in v_expr for q in ("'", '"'))
                )
                if has_sql and has_interp:
                    dynamic_sql_vars[v_name] = (idx, raw_lines[idx - 1].strip(), v_expr)

            m_sink = sql_sink_re.search(line)
            if not m_sink:
                continue

            arg_first = m_sink.group(1).split(",")[0].strip()
            if arg_first in dynamic_sql_vars:
                assign_line, snippet, sql_expr = dynamic_sql_vars[arg_first]
                reported_lines.add(assign_line)
                is_auth_or_destructive = bool(
                    re.search(r'\b(users|password|passwd|auth|login)\b', sql_expr, re.IGNORECASE)
                )
                sev = FindingSeverity.CRITICAL if is_auth_or_destructive else FindingSeverity.HIGH
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("JS-SQLI"),
                        scanner_source="JavaScript SAST Analyzer",
                        rule_id="nodejs.sqli.raw-query-interpolation",
                        severity=sev,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=assign_line,
                        line_end=idx,
                        code_snippet=snippet,
                        raw_evidence=(
                            f"SQL Injection: Unparameterized SQL query interpolated at line {assign_line} "
                            f"and executed via {m_sink.group(0).split('(')[0]}() at line {idx}."
                        ),
                        cwe_id="CWE-89",
                        owasp_category="A03:2021-Injection",
                    )
                )
            elif sql_kw_re.search(arg_first) and (
                "${" in arg_first or ("+" in arg_first and any(q in arg_first for q in ("'", '"')))
            ):
                reported_lines.add(idx)
                is_auth = bool(re.search(r'\b(users|password|auth|login)\b', arg_first, re.IGNORECASE))
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("JS-SQLI"),
                        scanner_source="JavaScript SAST Analyzer",
                        rule_id="nodejs.sqli.raw-query-interpolation",
                        severity=FindingSeverity.CRITICAL if is_auth else FindingSeverity.HIGH,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=raw_lines[idx - 1].strip(),
                        raw_evidence=f"SQL Injection: Dynamic SQL expression passed directly to query sink at line {idx}.",
                        cwe_id="CWE-89",
                        owasp_category="A03:2021-Injection",
                    )
                )

        return findings

    def _check_command_injection(
        self, rel_path: str, raw_lines: List[str], code_lines: List[str]
    ) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        cmd_assign_re = re.compile(r'\b(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*([^;]+);?')
        exec_sink_re = re.compile(r'\b(?:child_process\.)?(exec|execSync)\s*\(([^,)]+)')

        dynamic_vars: Dict[str, Tuple[int, str]] = {}
        for idx, line in enumerate(code_lines, start=1):
            m_assign = cmd_assign_re.search(line)
            if m_assign:
                var_name = m_assign.group(1)
                expr = m_assign.group(2)
                if ("`" in expr and "${" in expr) or (
                    "+" in expr and any(q in expr for q in ("'", '"'))
                ):
                    dynamic_vars[var_name] = (idx, raw_lines[idx - 1].strip())

            m_exec = exec_sink_re.search(line)
            if not m_exec:
                continue

            arg_expr = m_exec.group(2).strip()
            if arg_expr in dynamic_vars:
                assign_line, snippet = dynamic_vars[arg_expr]
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("JS-CMDI"),
                        scanner_source="JavaScript SAST Analyzer",
                        rule_id="nodejs.command-injection.child-process-exec",
                        severity=FindingSeverity.CRITICAL,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=assign_line,
                        line_end=idx,
                        code_snippet=raw_lines[idx - 1].strip(),
                        raw_evidence=(
                            f"OS Command Injection: Untrusted input interpolated into shell command "
                            f"'{arg_expr}' at line {assign_line} and executed via {m_exec.group(1)}() at line {idx}."
                        ),
                        cwe_id="CWE-78",
                        owasp_category="A03:2021-Injection",
                    )
                )
            elif not re.fullmatch(r'[\'"`][^\'"`${}]+[\'"`]', arg_expr):
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("JS-CMDI"),
                        scanner_source="JavaScript SAST Analyzer",
                        rule_id="nodejs.command-injection.child-process-exec",
                        severity=FindingSeverity.CRITICAL,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=raw_lines[idx - 1].strip(),
                        raw_evidence=f"OS Command Injection: Dynamic expression passed to child_process.{m_exec.group(1)}().",
                        cwe_id="CWE-78",
                        owasp_category="A03:2021-Injection",
                    )
                )

        return findings

    def _check_code_injection(
        self, rel_path: str, raw_lines: List[str], code_lines: List[str]
    ) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        eval_re = re.compile(r'\b(eval|vm\.runInThisContext|vm\.runInNewContext)\s*\(([^)]+)\)|\bnew\s+Function\s*\(([^)]+)\)')

        for idx, line in enumerate(code_lines, start=1):
            m = eval_re.search(line)
            if not m:
                continue
            arg = (m.group(2) or m.group(3) or "").strip()
            if re.fullmatch(r'[\'"][^\'"]*[\'"]', arg):
                continue
            findings.append(
                RawSecurityFinding(
                    finding_id=self._next_id("JS-EVAL"),
                    scanner_source="JavaScript SAST Analyzer",
                    rule_id="nodejs.code-injection.eval-usage",
                    severity=FindingSeverity.CRITICAL,
                    classification=FindingClassification.VERIFIED,
                    file_path=rel_path,
                    line_start=idx,
                    line_end=idx,
                    code_snippet=raw_lines[idx - 1].strip(),
                    raw_evidence=f"Dynamic Code Evaluation via {m.group(1) or 'new Function'}({arg}) allows arbitrary JS execution.",
                    cwe_id="CWE-95",
                    owasp_category="A03:2021-Injection",
                )
            )
        return findings

    def _check_idor(self, rel_path: str, functions: List[JSFunctionBlock]) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        for fn in functions:
            if not re.search(r'\breq\b', fn.params):
                continue
            body = fn.code_text
            if "req.params." not in body:
                continue
            # Check if DB query uses the route parameter
            has_db_lookup = bool(
                re.search(r'\b(?:safeQuery|rawQuery|db\.\w+|findById|findByPk|findOne)\s*\(', body)
                and re.search(r'\bWHERE\b|\bfindBy', body, re.IGNORECASE)
            )
            if not has_db_lookup:
                continue
            # Check for object ownership or role check referencing req.user / req.auth
            has_authz_check = bool(
                re.search(r'req\.(?:user|auth)\.(?:id|userId|sub|role)\b|isAdmin|checkOwnership', body)
            )
            if not has_authz_check:
                param_line = next(
                    (ln for ln, txt in fn.code_lines if "req.params." in txt),
                    fn.start_line,
                )
                snippet = next(
                    (txt.strip() for ln, txt in fn.raw_lines if ln == param_line),
                    fn.raw_lines[0][1].strip(),
                )
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("JS-IDOR"),
                        scanner_source="JavaScript SAST Analyzer",
                        rule_id="nodejs.access-control.idor-missing-ownership-check",
                        severity=FindingSeverity.HIGH,
                        classification=FindingClassification.HEURISTIC,
                        file_path=rel_path,
                        line_start=fn.start_line,
                        line_end=fn.end_line,
                        code_snippet=snippet,
                        raw_evidence=(
                            f"Insecure Direct Object Reference (IDOR) in '{fn.name}': "
                            f"accesses/modifies resource by route parameter without verifying req.user ownership or admin role."
                        ),
                        cwe_id="CWE-639",
                        owasp_category="A01:2021-Broken Access Control",
                    )
                )
        return findings

    def _check_path_traversal(self, rel_path: str, functions: List[JSFunctionBlock]) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        path_join_re = re.compile(r'path\.(?:join|resolve)\s*\(([^)]+)\)')
        fs_or_send_re = re.compile(r'\b(?:res\.sendFile|res\.download|fs\.(?:readFile|readFileSync|createReadStream|existsSync))\s*\(')

        for fn in functions:
            body = fn.code_text
            if not fs_or_send_re.search(body):
                continue
            has_containment_guard = bool(
                re.search(r'\.startsWith\s*\(|path\.basename\s*\(|normalizeAndVerify', body)
            )
            if has_containment_guard:
                continue

            for ln, line_text in fn.code_lines:
                m = path_join_re.search(line_text)
                if not m:
                    continue
                args = m.group(1)
                # Ignore safe server setup calls like path.resolve(__dirname, '../../database.sqlite')
                parts = [p.strip() for p in args.split(",")]
                has_dynamic_input = any(
                    p != "__dirname"
                    and not re.fullmatch(r'[\'"][^\'"]*[\'"]', p)
                    for p in parts
                )
                if not has_dynamic_input:
                    continue
                snippet = next((txt.strip() for raw_ln, txt in fn.raw_lines if raw_ln == ln), line_text.strip())
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("JS-TRAVERSAL"),
                        scanner_source="JavaScript SAST Analyzer",
                        rule_id="nodejs.path-traversal.unsanitized-file-access",
                        severity=FindingSeverity.HIGH,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=ln,
                        line_end=fn.end_line,
                        code_snippet=snippet,
                        raw_evidence=(
                            f"Path Traversal in '{fn.name}': dynamic path combined via path.join/resolve at line {ln} "
                            f"without verifying directory containment (.startsWith / path.basename)."
                        ),
                        cwe_id="CWE-22",
                        owasp_category="A01:2021-Broken Access Control",
                    )
                )
                break
        return findings

    def _check_auth_bypass(
        self,
        rel_path: str,
        raw_lines: List[str],
        code_lines: List[str],
        functions: List[JSFunctionBlock],
    ) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        bypass_header_re = re.compile(
            r"""req\.headers\s*\[\s*['"](x-debug-mode|x-role-override|x-auth-bypass|x-admin-override|x-impersonate)['"]\s*\]""",
            re.IGNORECASE,
        )
        jwt_none_re = re.compile(r"""jwt\.verify\s*\([^)]*['"]none['"]""")

        matched_lines: List[int] = []
        matched_headers: List[str] = []
        has_jwt_none = False

        for idx, line in enumerate(code_lines, start=1):
            hm = bypass_header_re.search(line)
            if hm:
                matched_lines.append(idx)
                matched_headers.append(hm.group(1))
            if jwt_none_re.search(line):
                matched_lines.append(idx)
                has_jwt_none = True

        if matched_lines:
            start_ln = min(matched_lines)
            end_ln = max(matched_lines)
            details = []
            if matched_headers:
                details.append(f"trusts client-supplied header(s): {', '.join(sorted(set(matched_headers)))}")
            if has_jwt_none:
                details.append("allows insecure JWT 'none' signature algorithm")
            findings.append(
                RawSecurityFinding(
                    finding_id=self._next_id("JS-AUTH"),
                    scanner_source="JavaScript SAST Analyzer",
                    rule_id="nodejs.auth.header-bypass-and-role-override",
                    severity=FindingSeverity.CRITICAL,
                    classification=FindingClassification.VERIFIED,
                    file_path=rel_path,
                    line_start=start_ln,
                    line_end=end_ln,
                    code_snippet=raw_lines[start_ln - 1].strip(),
                    raw_evidence=f"Authentication & Privilege Bypass: middleware {' and '.join(details)}.",
                    cwe_id="CWE-287",
                    owasp_category="A01:2021-Broken Access Control",
                )
            )
        return findings

    def _check_hardcoded_secrets(
        self, rel_path: str, raw_lines: List[str], code_lines: List[str]
    ) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        # Detect variable secret declarations including env-var fallback `process.env.X || 'secret'`
        secret_assign_re = re.compile(
            r"""\b(?:const|let|var)\s+([A-Za-z0-9_]*(?:JWT_SECRET|SECRET|API_KEY|PRIVATE_KEY|AUTH_TOKEN|ACCESS_TOKEN|PASSWORD)[A-Za-z0-9_]*)\s*=\s*(?:process\.env\.[A-Za-z0-9_]+\s*\|\|\s*)?['"]([^'"\r\n]{8,})['"]""",
            re.IGNORECASE,
        )

        for idx, line in enumerate(code_lines, start=1):
            m = secret_assign_re.search(line)
            if not m:
                continue
            val = m.group(2)
            if "${" in val or any(p in val.lower() for p in ("example", "placeholder", "your_")):
                continue
            findings.append(
                RawSecurityFinding(
                    finding_id=self._next_id("JS-SECRET"),
                    scanner_source="JavaScript SAST Analyzer",
                    rule_id="nodejs.secret.hardcoded-jwt-secret",
                    severity=FindingSeverity.HIGH,
                    classification=FindingClassification.VERIFIED,
                    file_path=rel_path,
                    line_start=idx,
                    line_end=idx,
                    code_snippet=raw_lines[idx - 1].strip(),
                    raw_evidence=f"Hardcoded secret fallback assigned to '{m.group(1)}' in source code.",
                    cwe_id="CWE-798",
                    owasp_category="A02:2021-Cryptographic Failures",
                )
            )
        return findings

    def _check_plaintext_passwords(self, rel_path: str, functions: List[JSFunctionBlock]) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        insert_pw_re = re.compile(r'\bINSERT\s+INTO\s+\w*\s*\([^)]*\bpassword\b', re.IGNORECASE)
        hash_call_re = re.compile(r'\b(?:bcrypt|bcryptjs|argon2)\.(?:hash|hashSync)\b|\b(?:scrypt|scryptSync|pbkdf2|pbkdf2Sync)\b')

        for fn in functions:
            body = fn.code_text
            if not insert_pw_re.search(body):
                continue
            # Require dynamic password variable / request handler input rather than static DB schema seeding
            if not (re.search(r'\breq\b', fn.params) or re.search(r'\bpassword\b', fn.params)):
                continue
            if hash_call_re.search(body):
                continue

            insert_ln = next(
                (ln for ln, txt in fn.code_lines if insert_pw_re.search(txt)),
                fn.start_line,
            )
            snippet = next(
                (txt.strip() for ln, txt in fn.raw_lines if ln == insert_ln),
                fn.raw_lines[0][1].strip(),
            )
            findings.append(
                RawSecurityFinding(
                    finding_id=self._next_id("JS-CRYPTO"),
                    scanner_source="JavaScript SAST Analyzer",
                    rule_id="nodejs.crypto.plaintext-password-storage",
                    severity=FindingSeverity.HIGH,
                    classification=FindingClassification.VERIFIED,
                    file_path=rel_path,
                    line_start=fn.start_line,
                    line_end=fn.end_line,
                    code_snippet=snippet,
                    raw_evidence=f"Plaintext password storage in '{fn.name}': password persisted without bcrypt/argon2 cryptographic hashing.",
                    cwe_id="CWE-256",
                    owasp_category="A02:2021-Cryptographic Failures",
                )
            )
        return findings

    def _check_sensitive_pii_exposure(self, rel_path: str, functions: List[JSFunctionBlock]) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        select_all_users_re = re.compile(r'\bSELECT\s+\*\s+FROM\s+users\b', re.IGNORECASE)
        explicit_pii_re = re.compile(r'\b(?:ssn|password_reset_token|resetToken)\s*:\s*user\.', re.IGNORECASE)

        for fn in functions:
            body = fn.code_text
            if "res.json" not in body:
                continue

            has_explicit_pii = bool(explicit_pii_re.search(body))
            has_wildcard_users = bool(select_all_users_re.search(body))
            # Check if code filters out password/ssn before returning
            has_projection = bool(
                re.search(r'\bconst\s*\{\s*password\b|\bdelete\s+\w+\.(?:password|ssn)\b', body)
            )

            if has_explicit_pii:
                ln = next((l for l, t in fn.code_lines if explicit_pii_re.search(t)), fn.start_line)
                snippet = next((t.strip() for rl, t in fn.raw_lines if rl == ln), fn.raw_lines[0][1].strip())
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("JS-PII"),
                        scanner_source="JavaScript SAST Analyzer",
                        rule_id="nodejs.data-exposure.sensitive-user-fields",
                        severity=FindingSeverity.MEDIUM,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=ln,
                        line_end=ln + 1,
                        code_snippet=snippet,
                        raw_evidence=f"Sensitive PII/Token Exposure in '{fn.name}': serializes ssn / password_reset_token in HTTP JSON response.",
                        cwe_id="CWE-359",
                        owasp_category="A02:2021-Cryptographic Failures",
                    )
                )
            elif has_wildcard_users and not has_projection and "WHERE" not in body:
                ln = next((l for l, t in fn.code_lines if select_all_users_re.search(t)), fn.start_line)
                snippet = next((t.strip() for rl, t in fn.raw_lines if rl == ln), fn.raw_lines[0][1].strip())
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("JS-PII"),
                        scanner_source="JavaScript SAST Analyzer",
                        rule_id="nodejs.data-exposure.sensitive-user-fields",
                        severity=FindingSeverity.MEDIUM,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=ln,
                        line_end=fn.end_line,
                        code_snippet=snippet,
                        raw_evidence=(
                            f"Sensitive PII and Secret Exposure in '{fn.name}': "
                            f"returns full user database records (including ssn, password, password_reset_token) without field filtering."
                        ),
                        cwe_id="CWE-359",
                        owasp_category="A02:2021-Cryptographic Failures",
                    )
                )
        return findings

    def _check_error_leakage(
        self,
        rel_path: str,
        raw_lines: List[str],
        code_lines: List[str],
        functions: List[JSFunctionBlock],
    ) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        leak_re = re.compile(r'\b(?:stack\s*:\s*err(?:or)?\.stack|internalQuery\s*:\s*err(?:or)?\.query)\b')

        for fn in functions:
            body = fn.code_text
            if not leak_re.search(body):
                continue
            has_prod_guard = bool(re.search(r"NODE_ENV\s*!==?\s*['\"]production['\"]|NODE_ENV\s*===?\s*['\"]development['\"]", body))
            if has_prod_guard:
                continue

            ln = next((l for l, t in fn.code_lines if leak_re.search(t)), fn.start_line)
            snippet = next((t.strip() for rl, t in fn.raw_lines if rl == ln), raw_lines[ln - 1].strip())
            findings.append(
                RawSecurityFinding(
                    finding_id=self._next_id("JS-ERR"),
                    scanner_source="JavaScript SAST Analyzer",
                    rule_id="nodejs.error-handling.stack-trace-leakage",
                    severity=FindingSeverity.MEDIUM,
                    classification=FindingClassification.VERIFIED,
                    file_path=rel_path,
                    line_start=fn.start_line,
                    line_end=fn.end_line,
                    code_snippet=snippet,
                    raw_evidence=(
                        f"Stack Trace & Query Information Leakage in '{fn.name}': "
                        f"exposes internal stack traces / SQL queries to API clients."
                    ),
                    cwe_id="CWE-209",
                    owasp_category="A05:2021-Security Misconfiguration",
                )
            )
        return findings

    def _check_permissive_cors(
        self, rel_path: str, raw_lines: List[str], code_lines: List[str]
    ) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        full_code = "\n".join(code_lines)

        # Match app.use(cors({ ... origin: '*' ... })) across multiple lines
        for m in re.finditer(r'cors\s*\(\s*\{([^}]+)\}\s*\)', full_code, re.DOTALL):
            block = m.group(1)
            om = re.search(r"""origin\s*:\s*(['"]\*['"]|true)""", block)
            if om:
                start_ln = full_code[: m.start()].count("\n") + 1
                origin_ln = full_code[: m.start(1) + om.start()].count("\n") + 1
                end_ln = full_code[: m.end()].count("\n") + 1
                snippet = raw_lines[origin_ln - 1].strip()
                has_creds = bool(re.search(r'credentials\s*:\s*true', block))
                findings.append(
                    RawSecurityFinding(
                        finding_id=self._next_id("JS-CORS"),
                        scanner_source="JavaScript SAST Analyzer",
                        rule_id="nodejs.cors.wildcard-origin-policy",
                        severity=FindingSeverity.MEDIUM,
                        classification=FindingClassification.VERIFIED,
                        file_path=rel_path,
                        line_start=start_ln,
                        line_end=end_ln,
                        code_snippet=snippet,
                        raw_evidence=(
                            "Overly Permissive CORS Policy: wildcard origin '*'"
                            + (" combined with credentials: true." if has_creds else " allows arbitrary cross-origin access.")
                        ),
                        cwe_id="CWE-942",
                        owasp_category="A05:2021-Security Misconfiguration",
                    )
                )
        return findings

    def _check_prototype_pollution(self, rel_path: str, functions: List[JSFunctionBlock]) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        key_loop_re = re.compile(r'for\s*\(\s*(?:const|let|var)?\s*([a-zA-Z0-9_$]+)\s+(?:of\s+Object\.keys\(|in\s+)')

        for fn in functions:
            body = fn.code_text
            m_loop = key_loop_re.search(body)
            if not m_loop:
                continue
            key_var = m_loop.group(1)
            assign_re = re.compile(rf'\[\s*{re.escape(key_var)}\s*\]\s*=')
            if not assign_re.search(body):
                continue

            has_proto_guard = "__proto__" in body or ("constructor" in body and "prototype" in body)
            if has_proto_guard:
                continue

            assign_ln = next((ln for ln, t in fn.code_lines if assign_re.search(t)), fn.start_line)
            snippet = next((t.strip() for rl, t in fn.raw_lines if rl == assign_ln), fn.raw_lines[0][1].strip())
            findings.append(
                RawSecurityFinding(
                    finding_id=self._next_id("JS-PROTO"),
                    scanner_source="JavaScript SAST Analyzer",
                    rule_id="nodejs.integrity.prototype-pollution-merge",
                    severity=FindingSeverity.HIGH,
                    classification=FindingClassification.VERIFIED,
                    file_path=rel_path,
                    line_start=fn.start_line,
                    line_end=fn.end_line,
                    code_snippet=snippet,
                    raw_evidence=(
                        f"Prototype Pollution via unsafe recursive merge in '{fn.name}': "
                        f"assigns property '{key_var}' without filtering '__proto__', 'constructor', or 'prototype'."
                    ),
                    cwe_id="CWE-1321",
                    owasp_category="A08:2021-Software and Data Integrity Failures",
                )
            )
        return findings

    def _check_ssrf(self, rel_path: str, functions: List[JSFunctionBlock]) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        url_input_re = re.compile(r'\b(?:req\.(?:body|query|params)\.\w+|new\s+URL\s*\()')
        http_client_re = re.compile(r'\b(?:http|https|client)\.(?:get|request)\s*\(([^,)]+)|\b(?:fetch|axios)\s*\(([^,)]+)')

        for fn in functions:
            if not re.search(r'\breq\b', fn.params):
                continue
            body = fn.code_text
            if not url_input_re.search(body):
                continue
            m_client = http_client_re.search(body)
            if not m_client:
                continue

            has_ssrf_guard = bool(
                re.search(r'127\.0\.0\.|169\.254\.|10\.0\.0\.|192\.168\.|isPrivateIP|allowedDomains|allowedHosts|dns\.lookup', body)
            )
            if has_ssrf_guard:
                continue

            call_ln = next((ln for ln, t in fn.code_lines if http_client_re.search(t)), fn.start_line)
            snippet = next((t.strip() for rl, t in fn.raw_lines if rl == call_ln), fn.raw_lines[0][1].strip())
            findings.append(
                RawSecurityFinding(
                    finding_id=self._next_id("JS-SSRF"),
                    scanner_source="JavaScript SAST Analyzer",
                    rule_id="nodejs.ssrf.unvalidated-outbound-request",
                    severity=FindingSeverity.HIGH,
                    classification=FindingClassification.VERIFIED,
                    file_path=rel_path,
                    line_start=fn.start_line,
                    line_end=fn.end_line,
                    code_snippet=snippet,
                    raw_evidence=(
                        f"Server-Side Request Forgery (SSRF) in '{fn.name}': "
                        f"fetches user-supplied URL without private/loopback IP filtering or allowlist."
                    ),
                    cwe_id="CWE-918",
                    owasp_category="A10:2021-Server-Side Request Forgery",
                )
            )
        return findings

    def _check_open_redirect(self, rel_path: str, functions: List[JSFunctionBlock]) -> List[RawSecurityFinding]:
        findings: List[RawSecurityFinding] = []
        redirect_re = re.compile(r'\bres\.redirect\s*\(([^)]+)\)')

        for fn in functions:
            if not re.search(r'\breq\b', fn.params):
                continue
            body = fn.code_text
            m_red = redirect_re.search(body)
            if not m_red:
                continue

            target_expr = m_red.group(1).strip()
            # Ignore constant literals like res.redirect('/dashboard')
            if re.fullmatch(r'[\'"][^\'"]*[\'"]', target_expr):
                continue
            has_allowlist = bool(
                re.search(r"startsWith\s*\(\s*['\"]/['\"]|allowedRedirects|allowedDomains|whitelist|allowlist", body)
            )
            if has_allowlist:
                continue

            red_ln = next((ln for ln, t in fn.code_lines if redirect_re.search(t)), fn.start_line)
            snippet = next((t.strip() for rl, t in fn.raw_lines if rl == red_ln), fn.raw_lines[0][1].strip())
            findings.append(
                RawSecurityFinding(
                    finding_id=self._next_id("JS-REDIRECT"),
                    scanner_source="JavaScript SAST Analyzer",
                    rule_id="nodejs.access-control.open-redirect",
                    severity=FindingSeverity.MEDIUM,
                    classification=FindingClassification.VERIFIED,
                    file_path=rel_path,
                    line_start=fn.start_line,
                    line_end=fn.end_line,
                    code_snippet=snippet,
                    raw_evidence=(
                        f"Unvalidated Open Redirect in '{fn.name}': "
                        f"res.redirect({target_expr}) redirects using unvalidated request input."
                    ),
                    cwe_id="CWE-601",
                    owasp_category="A01:2021-Broken Access Control",
                )
            )
        return findings
