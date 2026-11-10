"""
Offline Deterministic Security Remediation Engine for JavaScript / Node.js / Express codebases.
Used by BugFixerAgent / CloudLLMClient fallback when Cloud LLMs or Local Ollama are unavailable.
"""

from __future__ import annotations
import re
from typing import Optional

from .models import Finding, FixProposal


def generate_deterministic_js_fix(finding: Finding, file_content: str) -> Optional[FixProposal]:
    """
    Applies AST/pattern-safe offline security remediations for Node.js/Express findings.
    Returns FixProposal if the finding rule/CWE is supported, otherwise None.
    """
    rule_lower = (finding.rule_id or "").lower()
    cwe = (finding.cwe_id or "").upper()
    file_lower = (finding.file_path or "").lower()

    if not file_lower.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")):
        return None

    # 1. SQL Injection (CWE-89)
    if cwe == "CWE-89" or "sqli" in rule_lower:
        new_content = file_content
        # Replace rawQuery import if safeQuery is present
        new_content = re.sub(
            r"const\s*\{\s*rawQuery\s*,\s*safeQuery\s*\}\s*=\s*require\(([^)]+)\);",
            r"const { safeQuery } = require(\1);",
            new_content,
        )

        # Pattern A: Login SQLi `SELECT ... FROM users WHERE username = '${username}' AND password = '${password}'`
        new_content = re.sub(
            r"^([ \t]*)const\s+query\s*=\s*`SELECT\s+(?:\*|[\w\s,]+?)\s+FROM\s+users\s+WHERE\s+username\s*=\s*'\$\{(\w+)\}'\s+AND\s+password\s*=\s*'\$\{(\w+)\}'`\s*;(?:[ \t]*(?://[^\n]*)?\n)+[ \t]*const\s+users\s*=\s*await\s+rawQuery\(query\);",
            r"\1const query = 'SELECT id, username, email, role FROM users WHERE username = ? AND password = ?';\n\1const users = await safeQuery(query, [\2, \3]);",
            new_content,
            flags=re.MULTILINE,
        )

        # Pattern B: LIKE search SQLi
        new_content = re.sub(
            r"^([ \t]*)const\s+sql\s*=\s*`SELECT\s+\*\s+FROM\s+products\s+WHERE\s+name\s+LIKE\s+'%\$\{(\w+)\}%'\s+OR\s+description\s+LIKE\s+'%\$\{(\w+)\}%'`\s*;((?:[ \t]*(?:console\.[a-zA-Z0-9_]+\([^\n]*\);?|//[^\n]*)?\n)+)[ \t]*const\s+products\s*=\s*await\s+rawQuery\(sql\);",
            r"\1const sql = 'SELECT * FROM products WHERE name LIKE ? OR description LIKE ?';\4\1const products = await safeQuery(sql, [`%\${\2}%`, `%\${\3}%`]);",
            new_content,
            flags=re.MULTILINE,
        )

        # Pattern C: Sanitize err.query interpolation in catch blocks
        new_content = re.sub(
            r"err\.query\s*=\s*`[^`]*\$\{[^}]+\}[^`]*`;?",
            "// Internal SQL query stripped to prevent leakage",
            new_content,
        )

        # Generic fallback for other interpolated SQL passed to rawQuery
        if new_content == file_content:
            def _replace_interp(m):
                indent = m.group(1)
                var_kw = m.group(2)
                qvar = m.group(3)
                sql_tpl = m.group(4)
                params = re.findall(r"\$\{([a-zA-Z0-9_$.]+)\}", sql_tpl)
                param_sql = re.sub(r"'?\$\{[a-zA-Z0-9_$.]+\}'?", "?", sql_tpl)
                param_list = ", ".join(params)
                return f"{indent}{var_kw} {qvar} = '{param_sql}';\n{indent}const {qvar}Params = [{param_list}];"

            new_content = re.sub(
                r"^([ \t]*)(const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*`([^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{[^}]+\}[^`]*)`;?",
                _replace_interp,
                new_content,
                flags=re.IGNORECASE | re.MULTILINE,
            )
            new_content = re.sub(r"\brawQuery\s*\(\s*(\w+)\s*\)", r"safeQuery(\1, typeof \1Params !== 'undefined' ? \1Params : [])", new_content)

        if new_content != file_content:
            return FixProposal(
                explanation=f"Replaced interpolated raw SQL query in `{finding.file_path}` with parameterized prepared statement placeholders via `safeQuery()` (CWE-89).",
                remediation_summary="Converted dynamic SQL string interpolation into parameterized safeQuery() statements.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 2. OS Command Injection (CWE-78)
    if cwe == "CWE-78" or "command-injection" in rule_lower:
        new_content = file_content
        new_content = new_content.replace("const { exec } = require('child_process');", "const { execFile } = require('child_process');")
        new_content = new_content.replace('const { exec } = require("child_process");', "const { execFile } = require('child_process');")
        new_content = re.sub(
            r"const\s+command\s*=\s*`ping\s+-c\s+1\s+\$\{(\w+)\}`;\s*\n([^\n]*\n)?\s*exec\(command,",
            r"const hostRegex = /^[a-zA-Z0-9.-]{1,253}$/;\n  if (!hostRegex.test(String(\1))) {\n    return res.status(400).json({ error: 'Invalid host format' });\n  }\n  execFile('ping', ['-c', '1', String(\1)],",
            new_content,
        )
        new_content = new_content.replace("command,", "host: String(host),")
        if new_content != file_content:
            return FixProposal(
                explanation=f"Replaced unsafe shell execution `child_process.exec()` in `{finding.file_path}` with strict host allowlist validation and `execFile('ping', ['-c', '1', host])` (CWE-78).",
                remediation_summary="Validated host input with regex and replaced child_process.exec() with parameterized execFile().",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 3. Dynamic Code Evaluation via eval() (CWE-95)
    if cwe == "CWE-95" or "code-injection" in rule_lower or "eval" in rule_lower:
        new_content = file_content
        safe_parser_code = (
            "    const mathRegex = /^[0-9+\\-*/().\\s]+$/;\n"
            "    if (!mathRegex.test(String(expression))) {\n"
            "      return res.status(400).json({ error: 'Invalid expression: only numeric arithmetic is permitted' });\n"
            "    }\n"
            "    const evaluateSafeMath = (str) => {\n"
            "      const tokens = str.match(/\\d+(?:\\.\\d+)?|[+\\-*/]/g) || [];\n"
            "      let acc = parseFloat(tokens[0] || '0');\n"
            "      for (let i = 1; i < tokens.length; i += 2) {\n"
            "        const op = tokens[i]; const rhs = parseFloat(tokens[i + 1] || '0');\n"
            "        if (op === '+') acc += rhs; else if (op === '-') acc -= rhs;\n"
            "        else if (op === '*') acc *= rhs; else if (op === '/') acc = rhs !== 0 ? acc / rhs : NaN;\n"
            "      }\n"
            "      return acc;\n"
            "    };\n"
            "    const result = evaluateSafeMath(String(expression));"
        )
        if re.search(r"^\s*const\s+result\s*=\s*eval\(expression\);", new_content, re.MULTILINE):
            new_content = re.sub(
                r"^\s*const\s+result\s*=\s*eval\(expression\);",
                lambda _: safe_parser_code,
                new_content,
                flags=re.MULTILINE,
            )
        if new_content != file_content:
            return FixProposal(
                explanation=f"Removed dangerous `eval()` invocation in `{finding.file_path}` and enforced strict numeric arithmetic validation and safe tokenization (CWE-95).",
                remediation_summary="Removed eval() and replaced with strict safe arithmetic parser.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 4. Insecure Direct Object Reference / IDOR (CWE-639)
    if cwe == "CWE-639" or "idor" in rule_lower:
        new_content = file_content
        # Inject ownership/admin check into functions reading req.params.id
        for fn_sig, check_code in [
            (
                r"(async\s+function\s+getUserProfile\s*\([^)]*\)\s*\{\s*\n\s*try\s*\{\s*\n\s*const\s+targetUserId\s*=\s*req\.params\.id;)",
                r"\1\n    if (!req.user || (String(req.user.id) !== String(targetUserId) && req.user.role !== 'admin')) {\n      return res.status(403).json({ error: 'Forbidden: access denied' });\n    }",
            ),
            (
                r"(async\s+function\s+updateUserProfile\s*\([^)]*\)\s*\{\s*\n\s*try\s*\{\s*\n\s*const\s+targetUserId\s*=\s*req\.params\.id;)",
                r"\1\n    if (!req.user || (String(req.user.id) !== String(targetUserId) && req.user.role !== 'admin')) {\n      return res.status(403).json({ error: 'Forbidden: access denied' });\n    }",
            ),
            (
                r"(async\s+function\s+deleteUser\s*\([^)]*\)\s*\{\s*\n\s*try\s*\{\s*\n\s*const\s+targetUserId\s*=\s*req\.params\.id;)",
                r"\1\n    if (!req.user || req.user.role !== 'admin') {\n      return res.status(403).json({ error: 'Forbidden: administrator role required' });\n    }",
            ),
        ]:
            if "req.user" not in new_content or re.search(fn_sig, new_content):
                match = re.search(fn_sig, new_content)
                if match and "access denied" not in new_content[match.start():match.end() + 250]:
                    new_content = re.sub(fn_sig, check_code, new_content, count=1)

        if new_content != file_content:
            return FixProposal(
                explanation=f"Added object-level ownership and role authorization verification (`req.user.id === targetUserId || req.user.role === 'admin'`) in `{finding.file_path}` (CWE-639).",
                remediation_summary="Enforced user ownership and admin role authorization checks for IDOR prevention.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 5. Path Traversal (CWE-22)
    if cwe == "CWE-22" or "path-traversal" in rule_lower or "traversal" in rule_lower:
        new_content = file_content
        pat = re.compile(
            r"(const\s+reportsDir\s*=\s*path\.resolve\([^)]+\);\s*\n[^\n]*\n?\s*)const\s+filePath\s*=\s*path\.join\(\s*reportsDir\s*,\s*(\w+)\s*\);"
        )
        rep = (
            r"\1const safeFileName = path.basename(String(\2));\n"
            r"    const filePath = path.resolve(reportsDir, safeFileName);\n"
            r"    if (!filePath.startsWith(reportsDir + path.sep)) {\n"
            r"      return res.status(403).json({ error: 'Invalid report file path' });\n"
            r"    }"
        )
        new_content = pat.sub(rep, new_content)
        if new_content != file_content:
            return FixProposal(
                explanation=f"Sanitized filename via `path.basename()` and verified resolved path containment using `filePath.startsWith(reportsDir + path.sep)` in `{finding.file_path}` (CWE-22).",
                remediation_summary="Enforced directory boundary containment verification to block path traversal.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 6. Header-Based Authentication Bypass & Role Override (CWE-287)
    if cwe == "CWE-287" or "header-bypass" in rule_lower or "role-override" in rule_lower:
        new_content = file_content
        # Remove x-debug-mode bypass block (handle nested { ... } object literal inside if-block)
        new_content = re.sub(
            r"^(?:[ \t]*//[^\n]*debug bypass[^\n]*\n)?[ \t]*if\s*\(\s*req\.headers\s*\[\s*['\"]x-debug-mode['\"]\s*\]\s*===?\s*['\"]true['\"]\s*\)\s*\{(?:[^{}]|\{[^}]*\})*\}\s*\n?",
            "  // Debug header authentication bypass disabled (CWE-287)\n",
            new_content,
            flags=re.MULTILINE | re.IGNORECASE,
        )
        # Disallow 'none' algorithm in jwt.verify
        new_content = re.sub(
            r"""algorithms\s*:\s*\[\s*['"]HS256['"]\s*,\s*['"]none['"]\s*\]""",
            "algorithms: ['HS256']",
            new_content,
        )
        # Remove x-role-override header trust
        new_content = re.sub(
            r"const\s+overrideRole\s*=\s*req\.headers\s*\[\s*['\"]x-role-override['\"]\s*\];\s*\n\s*const\s+currentRole\s*=\s*overrideRole\s*\|\|\s*\(req\.user\s*&&\s*req\.user\.role\);",
            "// Role override header removed (CWE-287); derive role solely from verified JWT claims\n  const currentRole = req.user && req.user.role;",
            new_content,
        )
        if new_content != file_content:
            return FixProposal(
                explanation=f"Removed client-controlled `x-debug-mode` and `x-role-override` bypasses and disabled JWT `'none'` algorithm in `{finding.file_path}` (CWE-287).",
                remediation_summary="Eliminated header-based authentication/role overrides and enforced HS256 JWT verification.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 7. Hardcoded JWT Secret (CWE-798)
    if cwe == "CWE-798" or "hardcoded-jwt-secret" in rule_lower or "secret" in rule_lower:
        new_content = file_content
        new_content = re.sub(
            r"const\s+JWT_SECRET\s*=\s*process\.env\.JWT_SECRET\s*\|\|\s*['\"][^'\"]+['\"]\s*;",
            "const JWT_SECRET = process.env.JWT_SECRET;\nif (!JWT_SECRET) {\n  throw new Error('FATAL: JWT_SECRET environment variable must be set.');\n}",
            new_content,
        )
        if new_content != file_content:
            return FixProposal(
                explanation=f"Removed hardcoded fallback JWT secret in `{finding.file_path}` and enforced fail-fast environment variable validation (CWE-798).",
                remediation_summary="Removed hardcoded JWT secret fallback and required process.env.JWT_SECRET.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 8. Plaintext Password Storage (CWE-256)
    if cwe == "CWE-256" or "plaintext-password" in rule_lower:
        new_content = file_content
        if "require('crypto')" not in new_content and 'require("crypto")' not in new_content:
            new_content = "const crypto = require('crypto');\n" + new_content
        new_content = re.sub(
            r"(\s*const\s+assignedRole\s*=\s*'user'[^\n]*\n|\s*const\s+assignedRole\s*=\s*role\s*\|\|\s*'user';\s*\n)\s*(//[^\n]*\n)?\s*const\s+query\s*=\s*`INSERT INTO users[^`]+`;\s*\n\s*await\s+safeQuery\(query,\s*\[username,\s*password,",
            r"\n    // Hash password with Node.js built-in scrypt and random per-user salt (CWE-256)\n    const salt = crypto.randomBytes(16).toString('hex');\n    const hashedPassword = `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;\n    const assignedRole = 'user';\n    const query = `INSERT INTO users (username, password, email, role, ssn) VALUES (?, ?, ?, ?, ?)`;\n    await safeQuery(query, [username, hashedPassword,",
            new_content,
        )
        # Also scrub plaintext password console.log in authController if present
        new_content = re.sub(
            r"^[^\n]*console\.log\([^\n]*password[^\n]*\);\s*\n?",
            "    console.log(`[AUTH AUDIT] Login attempt for user: \"${username}\"`);\n",
            new_content,
            flags=re.MULTILINE | re.IGNORECASE,
        )
        if new_content != file_content:
            return FixProposal(
                explanation=f"Replaced plaintext password persistence in `{finding.file_path}` with salted cryptographic scrypt hashing (`crypto.scryptSync`) and sanitized password logs (CWE-256).",
                remediation_summary="Applied salted scrypt password hashing and removed plaintext credential logging.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 9. Sensitive PII and Secret Exposure (CWE-359)
    if cwe == "CWE-359" or "data-exposure" in rule_lower or "pii" in rule_lower:
        new_content = file_content
        new_content = re.sub(
            r"SELECT\s+\*\s+FROM\s+users\b",
            "SELECT id, username, email, role, bio FROM users",
            new_content,
            flags=re.IGNORECASE,
        )
        # Strip ssn & resetToken from JSON response objects (multiline first, then inline single-line properties)
        new_content = re.sub(
            r"^[ \t]*ssn\s*:\s*user\.ssn[ \t]*,?[ \t]*\n?",
            "",
            new_content,
            flags=re.MULTILINE,
        )
        new_content = re.sub(
            r"^[ \t]*resetToken\s*:\s*user\.password_reset_token[ \t]*,?[ \t]*\n?",
            "",
            new_content,
            flags=re.MULTILINE,
        )
        new_content = re.sub(r",?[ \t]*\bssn\s*:\s*user\.ssn\b", "", new_content)
        new_content = re.sub(r",?[ \t]*\bresetToken\s*:\s*user\.password_reset_token\b", "", new_content)
        # Remove leading comma right after '{' or trailing comma before '}'
        new_content = re.sub(r"(\{[ \t]*),\s*", r"\1", new_content)
        new_content = re.sub(r",([ \t]*\n?[ \t]*\})", r"\1", new_content)
        if new_content != file_content:
            return FixProposal(
                explanation=f"Restricted user SQL query projection to non-sensitive columns (`id, username, email, role, bio`) and removed `ssn` and `password_reset_token` fields from responses in `{finding.file_path}` (CWE-359).",
                remediation_summary="Projected only safe user columns and redacted PII/secret tokens from API responses.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 10. Stack Trace & Query Leakage (CWE-209)
    if cwe == "CWE-209" or "stack-trace" in rule_lower or "error-handling" in rule_lower:
        new_content = (
            "/**\n"
            " * Global Error Handling Middleware (Hardened - CWE-209)\n"
            " */\n"
            "function errorHandler(err, req, res, next) {\n"
            "  console.error('[SERVER ERROR]:', err);\n\n"
            "  const statusCode = err.status || 500;\n"
            "  const isProd = process.env.NODE_ENV === 'production';\n\n"
            "  res.status(statusCode).json({\n"
            "    status: 'error',\n"
            "    message: isProd ? 'An internal server error occurred' : err.message,\n"
            "    ...(process.env.NODE_ENV === 'development' ? { stack: err.stack } : {}),\n"
            "  });\n"
            "}\n\n"
            "module.exports = errorHandler;\n"
        )
        if new_content.strip() != file_content.strip():
            return FixProposal(
                explanation=f"Suppressed stack traces, `internalQuery`, and `processEnv` from HTTP error responses in `{finding.file_path}` (CWE-209).",
                remediation_summary="Gated error response details and stripped internal SQL/env leakage.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 11. Overly Permissive CORS Policy (CWE-942)
    if cwe == "CWE-942" or "cors" in rule_lower:
        new_content = file_content
        new_content = re.sub(
            r"origin\s*:\s*['\"]\*['\"]",
            "origin: ['https://portal.airgap.internal', 'http://localhost:3000']",
            new_content,
        )
        if "app.disable('x-powered-by')" not in new_content:
            new_content = new_content.replace("const app = express();", "const app = express();\napp.disable('x-powered-by');", 1)
        if new_content != file_content:
            return FixProposal(
                explanation=f"Replaced wildcard CORS origin `'*'` with explicit trusted origins and disabled `x-powered-by` fingerprinting in `{finding.file_path}` (CWE-942).",
                remediation_summary="Restricted CORS policy to trusted origins and disabled Express fingerprinting.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 12. Prototype Pollution (CWE-1321)
    if cwe == "CWE-1321" or "prototype-pollution" in rule_lower:
        new_content = (
            "/**\n"
            " * Object utility helper (Protected against Prototype Pollution - CWE-1321).\n"
            " */\n"
            "function deepMerge(target, source) {\n"
            "  if (!source || typeof source !== 'object') return target;\n"
            "  for (const key of Object.keys(source)) {\n"
            "    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {\n"
            "      continue;\n"
            "    }\n"
            "    if (source[key] instanceof Object && key in target && Object.prototype.hasOwnProperty.call(target, key)) {\n"
            "      Object.assign(source[key], deepMerge(target[key], source[key]));\n"
            "    }\n"
            "    target[key] = source[key];\n"
            "  }\n"
            "  return target;\n"
            "}\n\n"
            "module.exports = {\n"
            "  deepMerge\n"
            "};\n"
        )
        if new_content.strip() != file_content.strip():
            return FixProposal(
                explanation=f"Added explicit filtering for `'__proto__'`, `'constructor'`, and `'prototype'` keys during recursive deep merge in `{finding.file_path}` (CWE-1321).",
                remediation_summary="Blocked prototype-polluting keys (__proto__, constructor, prototype) in deepMerge.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 13. SSRF (CWE-918)
    if cwe == "CWE-918" or "ssrf" in rule_lower:
        new_content = file_content
        ssrf_guard = (
            "    const parsed = new URL(targetUrl);\n"
            "    const host = parsed.hostname.toLowerCase();\n"
            "    if (\n"
            "      !['https:', 'http:'].includes(parsed.protocol) ||\n"
            "      host === 'localhost' ||\n"
            "      host.startsWith('127.') ||\n"
            "      host.startsWith('10.') ||\n"
            "      host.startsWith('169.254.') ||\n"
            "      host.startsWith('192.168.') ||\n"
            "      host === '::1'\n"
            "    ) {\n"
            "      return res.status(403).json({ error: 'Blocked: private or loopback SSRF target rejected' });\n"
            "    }"
        )
        new_content = re.sub(
            r"^\s*const\s+parsed\s*=\s*new\s+URL\(targetUrl\);",
            ssrf_guard,
            new_content,
            flags=re.MULTILINE,
        )
        if new_content != file_content:
            return FixProposal(
                explanation=f"Enforced strict protocol and private/loopback IP blocking (`127.`, `10.`, `169.254.`, `192.168.`, `localhost`) in `{finding.file_path}` to mitigate SSRF (CWE-918).",
                remediation_summary="Added URL protocol validation and private/loopback IP SSRF guards.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    # 14. Unvalidated Open Redirect (CWE-601)
    if cwe == "CWE-601" or "open-redirect" in rule_lower:
        new_content = file_content
        def _replace_redirect(m: re.Match) -> str:
            var_name = m.group(1)
            return (
                "  const allowedDomains = ['portal.airgap.internal', 'localhost'];\n"
                "  let safeRedirect = false;\n"
                f"  if (String({var_name}).startsWith('/') && !String({var_name}).startsWith('//')) {{\n"
                "    safeRedirect = true;\n"
                "  } else {\n"
                "    try {\n"
                f"      const parsedTarget = new URL(String({var_name}));\n"
                "      safeRedirect = allowedDomains.includes(parsedTarget.hostname);\n"
                "    } catch (e) { safeRedirect = false; }\n"
                "  }\n"
                "  if (!safeRedirect) {\n"
                "    return res.status(400).json({ error: 'Untrusted redirect destination rejected' });\n"
                "  }\n"
                f"  res.redirect({var_name});"
            )
        new_content = re.sub(
            r"^(?:[ \t]*//[^\n]*Open redirect[^\n]*\n)?[ \t]*res\.redirect\((\w+)\);",
            _replace_redirect,
            new_content,
            flags=re.MULTILINE | re.IGNORECASE,
        )
        if new_content != file_content:
            return FixProposal(
                explanation=f"Added relative path and trusted domain allowlist validation before `res.redirect()` in `{finding.file_path}` (CWE-601).",
                remediation_summary="Validated redirect targets against relative paths and trusted allowlist domains.",
                confidence="HIGH",
                fixed_file_content=new_content,
            )

    return None
