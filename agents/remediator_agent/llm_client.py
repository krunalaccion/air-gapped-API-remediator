import json
import logging
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
import urllib.error
from typing import Callable, Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from .js_fixer import generate_deterministic_js_fix
from .models import Finding, FixProposal

logger = logging.getLogger("agents.remediator_agent.llm_client")


SYSTEM_PROMPT = """You are an expert Application Security Engineer and Automated Code Remediation Agent.
Your task is to fix security vulnerabilities and bugs reported by static analysis (SAST) tools.

Rules:
1. Eliminate the vulnerability completely using language-idiomatic security best practices (e.g., parameterized SQL queries with SqlParameter / AddWithValue instead of string interpolation or concatenation).
2. Preserve existing functionality, method signatures, namespaces, formatting, and unrelated code.
3. Return ONLY a valid JSON object matching this exact schema (no markdown fences outside JSON):
{
  "explanation": "Clear explanation of why the original code was vulnerable and how the fix resolves it.",
  "remediation_summary": "One-line summary of the fix applied.",
  "confidence": "HIGH | MEDIUM | LOW",
  "original_snippet": "The exact vulnerable code snippet or lines from the original file to be replaced.",
  "replacement_snippet": "The safe, remediated replacement code to substitute in place of original_snippet.",
  "fixed_file_content": "Alternatively, the full source file content if replacing the entire file."
}
"""


def _apply_snippet_replacement(
    original_content: str, original_snippet: str, replacement_snippet: str
) -> Optional[str]:
    """Surgically substitutes the vulnerable original snippet with the replacement snippet."""
    if not original_snippet or replacement_snippet is None:
        return None
    orig_clean = original_snippet.strip()
    repl_clean = replacement_snippet.strip()

    # 1. Exact match
    if orig_clean in original_content:
        return original_content.replace(orig_clean, repl_clean, 1)

    # 2. Stripped trailing semicolon or whitespace
    orig_no_semi = orig_clean.rstrip(";")
    if orig_no_semi and orig_no_semi in original_content:
        return original_content.replace(orig_no_semi, repl_clean.rstrip(";"), 1)

    # 3. Line-by-line whitespace-insensitive search preserving indentation
    orig_lines = [l.strip() for l in orig_clean.splitlines() if l.strip()]
    if orig_lines:
        content_lines = original_content.splitlines()
        for i in range(len(content_lines) - len(orig_lines) + 1):
            window = [content_lines[i + j].strip() for j in range(len(orig_lines))]
            if window == orig_lines:
                leading_ws = len(content_lines[i]) - len(content_lines[i].lstrip())
                indent = content_lines[i][:leading_ws]
                repl_lines = [f"{indent}{l}" if l.strip() else l for l in repl_clean.splitlines()]
                new_lines = content_lines[:i] + repl_lines + content_lines[i + len(orig_lines):]
                return "\n".join(new_lines)
    return None


class CloudLLMClient:
    """
    Multi-provider Cloud LLM client supporting OpenAI, Gemini, Anthropic,
    OpenAI-compatible endpoints (Azure/Ollama/vLLM), and offline rule-based fallback.
    """

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
        timeout: Optional[int] = None,
    ):
        self.provider = (provider or os.getenv("LLM_PROVIDER") or self._detect_provider()).lower()
        self.model = model or os.getenv("LLM_MODEL") or self._default_model(self.provider)
        self.api_key = api_key or self._resolve_api_key(self.provider)
        self.base_url = base_url or os.getenv("LLM_BASE_URL")
        self.cancel_check = cancel_check
        self.timeout = int(timeout or os.getenv("LLM_TIMEOUT", "180"))
        self._offline_fallback_active = False

    @staticmethod
    def _detect_provider() -> str:
        if os.getenv("OLLAMA_URL") or os.getenv("OLLAMA_HOST") or os.getenv("LOCAL_LLM"):
            return "ollama"
        if os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"):
            return "gemini"
        if os.getenv("OPENAI_API_KEY"):
            return "openai"
        if os.getenv("ANTHROPIC_API_KEY"):
            return "anthropic"
        return "auto-fallback"

    @staticmethod
    def _default_model(provider: str) -> str:
        defaults = {
            "gemini": "gemini-2.5-flash",
            "openai": "gpt-4o",
            "anthropic": "claude-3-5-sonnet-latest",
            "ollama": os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b"),
            "local": os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b"),
            "auto-fallback": "rule-based-security-fixer",
            "mock": "rule-based-security-fixer",
        }
        return defaults.get(provider, "qwen2.5-coder:3b" if provider in ("ollama", "local") else "gpt-4o")

    @staticmethod
    def _resolve_api_key(provider: str) -> Optional[str]:
        if provider == "gemini":
            return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if provider == "openai":
            return os.getenv("OPENAI_API_KEY")
        if provider == "anthropic":
            return os.getenv("ANTHROPIC_API_KEY")
        if provider in ("ollama", "local"):
            return os.getenv("OLLAMA_API_KEY") or os.getenv("LLM_API_KEY")
        return os.getenv("LLM_API_KEY")

    def generate_fix(
        self,
        finding: Finding,
        file_content: str,
        numbered_context: str,
    ) -> FixProposal:
        """Calls the configured Cloud/Local LLM to generate a FixProposal for the finding."""
        if self.cancel_check and self.cancel_check():
            raise InterruptedError("Cancelled during LLM remediation")
        snippet_core = (finding.code_snippet or "").strip().rstrip(";")
        is_comment = (
            snippet_core.startswith("//")
            or snippet_core.startswith("/*")
            or snippet_core.startswith("*")
            or snippet_core.startswith("#")
        )
        is_missing_heuristic = (
            "not found" in snippet_core.lower()
            or "missing" in snippet_core.lower()
            or "hsts" in finding.rule_id.lower()
        )
        # Deterministic handler for JSON config files (launchSettings.json, appsettings.json, etc.)
        # and ASP.NET Core HSTS / middleware to guarantee clean syntax and immediate remediation
        if (
            finding.file_path.lower().endswith(".json")
            or "launchsettings" in finding.file_path.lower()
            or "appsettings" in finding.file_path.lower()
            or "hsts" in finding.rule_id.lower()
            or "hsts" in finding.finding_id.lower()
            or "allowed-hosts" in finding.rule_id.lower()
            or "connectionstring" in finding.rule_id.lower()
        ):
            try:
                proposal = self._generate_deterministic_fix(finding, file_content)
                if proposal and proposal.fixed_file_content.strip() != file_content.strip():
                    return proposal
            except Exception:
                pass

        # Deterministic fast-path for JavaScript / TypeScript / Node.js security findings
        if finding.file_path.lower().endswith((".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")):
            try:
                js_proposal = generate_deterministic_js_fix(finding, file_content)
                if js_proposal and js_proposal.fixed_file_content.strip() != file_content.strip():
                    return js_proposal
            except Exception:
                pass

        # Check if the code was already remediated
        clean_snip = re.sub(r'[\s\'\",;]+', '', snippet_core).lower()
        clean_orig = re.sub(r'[\s\'\",;]+', '', file_content).lower()

        is_literal_present = (
            snippet_core in file_content
            or (len(clean_snip) > 6 and clean_snip in clean_orig)
        )

        is_secret_finding = (
            "connectionstring" in finding.rule_id.lower()
            or "cwe-798" in (finding.cwe_id or "").lower()
            or "secret" in finding.rule_id.lower()
            or "credential" in finding.rule_id.lower()
            or "***redacted***" in clean_snip
        )
        if "allowedhosts" in clean_snip:
            is_vuln_in_orig = bool(re.search(r'\"AllowedHosts\"\s*:\s*\"\*\"', file_content))
        elif is_literal_present and not ("***redacted***" in clean_snip):
            is_vuln_in_orig = True
        elif (finding.cwe_id or "").upper() == "CWE-89" and finding.file_path.lower().endswith((".js", ".ts", ".mjs", ".cjs")):
            is_vuln_in_orig = bool(
                re.search(r"\brawQuery\s*\(|(?i:SELECT|INSERT|UPDATE|DELETE)\b[^\n`;]*\$\{", file_content)
            )
        elif is_secret_finding:
            has_conn_cred = bool(re.search(r'(?i)\b(password|pwd)\s*=\s*[^;]+', file_content))
            has_code_cred = bool(re.search(
                r'(?i)\b(?:string|var|const|let)?\s*[a-zA-Z0-9_]*(?:password|pwd|secret|apiKey|api_key|token|privateKey|jwtSecret|bearer)[a-zA-Z0-9_]*\s*[:=]\s*(?:process\.env\.[A-Z0-9_]+\s*\|\|\s*)?["\']([^"\'\r\n]{8,})["\']',
                file_content,
            ))
            snip_var_m = re.search(
                r'(?i)\b(?:string|var|const|let)\s+(?P<var>[a-zA-Z0-9_]+)\s*[:=]|(?P<var2>[a-zA-Z0-9_]*(?:password|pwd|secret|apiKey|api_key|token|privateKey|jwtSecret|bearer)[a-zA-Z0-9_]*)\s*[:=]',
                finding.code_snippet or "",
            )
            has_snip_var = False
            if snip_var_m:
                v_name = snip_var_m.group("var") or snip_var_m.group("var2")
                if v_name and v_name.lower() not in ("string", "var", "const", "let"):
                    has_snip_var = bool(re.search(
                        rf'(?i)\b{re.escape(v_name)}\s*[:=]\s*(?:process\.env\.[A-Z0-9_]+\s*\|\|\s*)?["\']([^"\'\r\n]{{8,}})["\']',
                        file_content,
                    ))
            is_vuln_in_orig = has_conn_cred or has_code_cred or has_snip_var
        else:
            is_vuln_in_orig = is_literal_present
        if not is_missing_heuristic and (is_comment or not is_vuln_in_orig):
            return FixProposal(
                explanation=f"Finding '{finding.finding_id}' ({finding.rule_id}) is verified as already remediated in '{finding.file_path}'.",
                remediation_summary=f"Already remediated in {finding.file_path}.",
                confidence="HIGH",
                fixed_file_content=file_content,
            )

        # If previous call in this batch failed due to offline/unresponsive LLM, use deterministic fixer immediately
        if getattr(self, "_offline_fallback_active", False):
            return self._generate_deterministic_fix(finding, file_content)

        user_prompt = self._build_user_prompt(finding, file_content, numbered_context)

        try:
            if self.provider in ("ollama", "local"):
                raw_response = self._call_ollama(user_prompt)
                return self._parse_response(raw_response, original_file_content=file_content)
            elif self.provider == "gemini":
                raw_response = self._call_gemini(user_prompt)
                return self._parse_response(raw_response, original_file_content=file_content)
            elif self.provider == "openai":
                raw_response = self._call_openai(user_prompt)
                return self._parse_response(raw_response, original_file_content=file_content)
            elif self.provider == "anthropic":
                raw_response = self._call_anthropic(user_prompt)
                return self._parse_response(raw_response, original_file_content=file_content)
            elif self.provider in ("mock", "offline", "auto-fallback"):
                return self._generate_deterministic_fix(finding, file_content)
            else:
                raise ValueError(f"Unsupported LLM provider: '{self.provider}'")
        except InterruptedError:
            raise
        except Exception as exc:
            # Fall back to deterministic fixer if LLM call fails (e.g. offline / air-gapped test or no network)
            if self.provider not in ("mock", "offline", "auto-fallback"):
                logger.warning("LLM provider '%s' failed (%s); falling back to deterministic security fixer.", self.provider, exc)
                self._offline_fallback_active = True
                return self._generate_deterministic_fix(finding, file_content)
            raise

    @classmethod
    def _compress_source_context(
        cls, file_content: str, target_line: int, head_lines: int = 25, window_lines: int = 35
    ) -> str:
        """
        Compresses large source files to minimize LLM reading/prefill time.
        Preserves the file header (imports, namespaces) and a focused window around the vulnerable line,
        omitting hundreds of unrelated lines. Returns full content unchanged if <= 80 lines.
        """
        lines = file_content.splitlines()
        total = len(lines)
        if total <= 80:
            return file_content

        target_idx = max(1, min(total, target_line))
        win_start = max(1, target_idx - window_lines)
        win_end = min(total, target_idx + window_lines)

        output_parts: List[str] = []
        if win_start > head_lines + 5:
            output_parts.extend(lines[:head_lines])
            omitted = win_start - head_lines - 1
            output_parts.append(f"\n// ... [Omitted {omitted} lines of unrelated methods to compress context] ...\n")
            output_parts.extend(lines[win_start - 1 : win_end])
        else:
            output_parts.extend(lines[:win_end])

        if win_end < total:
            omitted_tail = total - win_end
            output_parts.append(f"\n// ... [Omitted {omitted_tail} lines of remaining code to compress context] ...\n")

        return "\n".join(output_parts)

    @classmethod
    def _build_user_prompt(
        cls, finding: Finding, file_content: str, numbered_context: str
    ) -> str:
        compressed_content = cls._compress_source_context(file_content, finding.line_number)
        return f"""Fix the following security finding in the source file.

### Finding Metadata
- Finding ID: {finding.finding_id}
- Rule ID: {finding.rule_id}
- Severity: {finding.severity}
- Repository: {finding.repository}
- File Path: {finding.file_path}
- Vulnerable Line Number: {finding.line_number}
- Scanner Message: {finding.message}
- Vulnerable Snippet: `{finding.code_snippet}`

### Code Context (Around Line {finding.line_number})
```
{numbered_context}
```

### Relevant Source Code (Compressed Context)
```
{compressed_content}
```

Return the JSON object containing `explanation`, `remediation_summary`, `confidence`, and either:
1. `original_snippet` and `replacement_snippet` (fast surgical patch of the vulnerable lines), OR
2. `fixed_file_content` (the complete remediated file content)."""

    def _call_openai(self, user_prompt: str) -> str:
        if not self.api_key:
            raise RuntimeError(
                "OPENAI_API_KEY environment variable is required when using provider='openai'."
            )
        url = (self.base_url or "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
        payload = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        data = self._post_json(url, payload, headers)
        return data["choices"][0]["message"]["content"]

    def _call_gemini(self, user_prompt: str) -> str:
        if not self.api_key:
            raise RuntimeError(
                "GEMINI_API_KEY (or GOOGLE_API_KEY) environment variable is required when using provider='gemini'."
            )
        base = (
            self.base_url
            or f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        )
        url = f"{base}?key={self.api_key}"
        payload = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }
        headers = {"Content-Type": "application/json"}
        data = self._post_json(url, payload, headers)
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _call_anthropic(self, user_prompt: str) -> str:
        if not self.api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY environment variable is required when using provider='anthropic'."
            )
        url = (self.base_url or "https://api.anthropic.com/v1").rstrip("/") + "/messages"
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "temperature": 0.1,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        data = self._post_json(url, payload, headers)
        return data["content"][0]["text"]

    def _call_ollama(self, user_prompt: str) -> str:
        base = (
            self.base_url
            or os.getenv("OLLAMA_URL")
            or os.getenv("OLLAMA_HOST")
            or os.getenv("LOCAL_LLM_URL")
            or "http://127.0.0.1:11434"
        ).rstrip("/")

        # OpenAI-compatible /v1 endpoint (used by LM Studio, vLLM, LocalAI, or Ollama /v1)
        if base.endswith("/v1"):
            url = f"{base}/chat/completions"
            payload = {
                "model": self.model,
                "response_format": {"type": "json_object"},
                "temperature": 0.1,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            }
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            data = self._post_json(url, payload, headers)
            return data["choices"][0]["message"]["content"]

        # Native Ollama /api/chat with format="json"
        url = f"{base}/api/chat"
        num_ctx = int(os.getenv("OLLAMA_NUM_CTX", "8192"))
        keep_alive = os.getenv("OLLAMA_KEEP_ALIVE", "30m")
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "keep_alive": keep_alive,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "options": {
                "temperature": 0.1,
                "num_ctx": num_ctx,
            },
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = self._post_json(url, payload, headers)
        return data.get("message", {}).get("content", "")

    def _post_json(
        self, url: str, payload: Dict[str, Any], headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """Executes _http_post with fast cancellation polling if cancel_check is supplied."""
        if not self.cancel_check:
            return self._http_post(url, payload, headers, timeout=self.timeout)

        result_box: Dict[str, Any] = {}
        error_box: Dict[str, BaseException] = {}
        done_ev = threading.Event()

        def _worker() -> None:
            try:
                result_box["data"] = self._http_post(url, payload, headers, timeout=self.timeout)
            except BaseException as exc:
                error_box["err"] = exc
            finally:
                done_ev.set()

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        while not done_ev.wait(0.1):
            if self.cancel_check():
                raise InterruptedError("Cancelled during LLM HTTP request")
        if "err" in error_box:
            raise error_box["err"]
        return result_box["data"]

    @staticmethod
    def _http_post(
        url: str, payload: Dict[str, Any], headers: Dict[str, str], timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """POST JSON payload with exponential backoff retry on transient HTTP 429/5xx errors."""
        encoded = json.dumps(payload).encode("utf-8")
        eff_timeout = int(timeout or os.getenv("LLM_TIMEOUT", "180"))
        max_retries = max(0, int(os.getenv("LLM_MAX_RETRIES", "2")))
        base_backoff = float(os.getenv("LLM_RETRY_BACKOFF_SEC", "0.5"))
        retryable_codes = {429, 502, 503, 504}

        for attempt in range(max_retries + 1):
            req = urllib.request.Request(
                url,
                data=encoded,
                headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=eff_timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                try:
                    body = exc.read().decode("utf-8", errors="replace")
                finally:
                    exc.close()
                if exc.code in retryable_codes and attempt < max_retries:
                    delay = base_backoff * (2 ** attempt)
                    logger.warning(
                        "Transient LLM HTTP %d error; retrying in %.2fs (attempt %d/%d)",
                        exc.code,
                        delay,
                        attempt + 1,
                        max_retries,
                    )
                    time.sleep(delay)
                    continue
                raise RuntimeError(f"LLM API HTTP {exc.code} error: {body}") from exc
            except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
                raise RuntimeError(f"Network error calling LLM API: {exc}") from exc

    @classmethod
    def _parse_response(
        cls, raw_text: str, original_file_content: Optional[str] = None
    ) -> FixProposal:
        cleaned = raw_text.strip()
        # Robust JSON extraction: check for markdown code blocks or outermost braces
        fence_match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", cleaned)
        if fence_match:
            cleaned = fence_match.group(1).strip()
        elif not (cleaned.startswith("{") and cleaned.endswith("}")):
            first_brace = cleaned.find("{")
            last_brace = cleaned.rfind("}")
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                cleaned = cleaned[first_brace : last_brace + 1].strip()

        data = json.loads(cleaned)

        # 1. Fast surgical snippet replacement if provided
        fixed_content = ""
        orig_snip = data.get("original_snippet")
        repl_snip = data.get("replacement_snippet")
        if original_file_content and orig_snip and repl_snip is not None:
            patched = _apply_snippet_replacement(original_file_content, str(orig_snip), str(repl_snip))
            if patched:
                fixed_content = patched

        # 2. Fall back to full fixed_file_content if surgical replacement not provided
        if not fixed_content:
            fixed_content = data.get("fixed_file_content", "")
            clean_fixed = fixed_content.strip()
            if clean_fixed.startswith("```"):
                fence_m = re.match(r"^```[a-zA-Z0-9_\-]*\s*\n([\s\S]*?)\n```\s*$", clean_fixed)
                if fence_m:
                    clean_fixed = fence_m.group(1)
                else:
                    lines = [l for l in clean_fixed.splitlines() if not l.strip().startswith("```")]
                    clean_fixed = "\n".join(lines)
                fixed_content = clean_fixed

        return FixProposal(
            explanation=data.get("explanation", "Remediated security finding."),
            fixed_file_content=fixed_content,
            remediation_summary=data.get(
                "remediation_summary", "Applied automated security fix."
            ),
            confidence=data.get("confidence", "HIGH"),
        )

    @staticmethod
    def _generate_deterministic_fix(
        finding: Finding, file_content: str
    ) -> FixProposal:
        """
        Built-in C# SQL Injection, ASP.NET Core Middleware, and Config remediator
        used when running in offline/mock mode (or when no local AI model is available).
        """
        rule_lower = finding.rule_id.lower()

        # 0. JavaScript / Node.js / Express Deterministic Fixes
        js_proposal = generate_deterministic_js_fix(finding, file_content)
        if js_proposal is not None:
            return js_proposal

        # 1. C# SQL Injection (CWE-89)
        if "sql" in rule_lower or "SELECT " in finding.code_snippet:
            new_content = file_content
            # Pattern 1: var/string q = $"SELECT ... WHERE ... '{val}'" or "{val}"
            p1 = re.compile(
                r'(?P<indent>[ \t]*)(?:var|string)\s+(?P<qvar>\w+)\s*=\s*\$"(?P<sql_prefix>SELECT\s+.*?\s+WHERE\s+[\w\.]+\s*=\s*)\'\{(?P<param>[\w\.]+)\}\'"\s*;?'
            )
            p2 = re.compile(
                r'(?P<indent>[ \t]*)(?:var|string)\s+(?P<qvar>\w+)\s*=\s*\$"(?P<sql_prefix>SELECT\s+.*?\s+WHERE\s+[\w\.]+\s*=\s*)\{(?P<param>[\w\.]+)\}"\s*;?'
            )
            for pat in [p1, p2]:
                m = pat.search(new_content)
                if m:
                    indent = m.group("indent")
                    qvar = m.group("qvar")
                    sql_prefix = m.group("sql_prefix")
                    param = m.group("param")
                    clean_param = param.split(".")[-1]
                    param_tag = f"@{clean_param}"
                    fixed_line = f'{indent}const string {qvar} = "{sql_prefix}{param_tag}";'
                    new_content = pat.sub(fixed_line, new_content, count=1)

                    cmd_pat = re.compile(
                        rf'(?P<cindent>[ \t]*)(?:using\s+)?(?:var|SqlCommand)\s+(?P<cmdvar>\w+)\s*=\s*(?:await\s+)?new\s+SqlCommand\(\s*{re.escape(qvar)}\s*,\s*\w+\s*\)\s*;'
                    )
                    cmd_match = cmd_pat.search(new_content)
                    if cmd_match and f'Parameters.AddWithValue("{param_tag}"' not in new_content:
                        cindent = cmd_match.group("cindent")
                        cmdvar = cmd_match.group("cmdvar")
                        replacement = f'{cmd_match.group(0)}\n{cindent}{cmdvar}.Parameters.AddWithValue("{param_tag}", {param});'
                        new_content = cmd_pat.sub(replacement, new_content, count=1)
                    break

            # Fallback: simple string replacement if matching finding.code_snippet directly
            if new_content == file_content and finding.code_snippet:
                snip = finding.code_snippet.strip().rstrip(";")
                if "SELECT " in snip and ("{" in snip or " + " in snip):
                    param_match = re.search(r'\{([\w\.]+)\}', snip) or re.search(r'\+\s*([\w\.]+)', snip)
                    if param_match:
                        raw_param = param_match.group(1)
                        clean_param = raw_param.split(".")[-1]
                        param_tag = f"@{clean_param}"
                        safe_sql = re.sub(r'\'?\{[\w\.]+\}\'?', param_tag, snip)
                        safe_sql = re.sub(r'\+\s*[\w\.]+', param_tag, safe_sql)
                        safe_sql = safe_sql.replace('$"', '"')
                        new_content = new_content.replace(snip, safe_sql)

            if new_content != file_content:
                return FixProposal(
                    explanation=f"Replaced dynamic SQL string interpolation in `{finding.file_path}` with constant parameterized query and bound parameters safely via SqlCommand.Parameters.AddWithValue (CWE-89).",
                    remediation_summary="Replaced dynamic SQL string interpolation with parameterized SqlCommand query.",
                    confidence="HIGH",
                    fixed_file_content=new_content,
                )

        # 2. C# Weak Cryptography (CWE-327 / CWE-328)
        if (
            "crypto" in rule_lower
            or "weak-algorithm" in rule_lower
            or any(k in rule_lower for k in ("des", "rc2", "md5", "sha1"))
            or any(k in finding.code_snippet for k in ("DES.Create", "MD5.Create", "SHA1.Create", "RC2.Create", "TripleDES.Create"))
        ):
            new_content = file_content
            new_content = re.sub(r'\b(DES|TripleDES|RC2|Rijndael)\.Create\(\)', 'Aes.Create()', new_content)
            new_content = re.sub(r'\bnew\s+DESCryptoServiceProvider\(\)', 'Aes.Create()', new_content)
            new_content = re.sub(r'\bnew\s+RC2CryptoServiceProvider\(\)', 'Aes.Create()', new_content)
            new_content = re.sub(r'\bnew\s+TripleDESCryptoServiceProvider\(\)', 'Aes.Create()', new_content)
            new_content = re.sub(r'\b(MD5|SHA1)\.Create\(\)', 'SHA256.Create()', new_content)
            new_content = re.sub(r'\bnew\s+MD5CryptoServiceProvider\(\)', 'SHA256.Create()', new_content)
            new_content = re.sub(r'\bnew\s+SHA1CryptoServiceProvider\(\)', 'SHA256.Create()', new_content)

            if new_content != file_content:
                return FixProposal(
                    explanation=f"Replaced broken/obsolete cryptographic algorithm in `{finding.file_path}` with modern AES / SHA-256 primitives (CWE-327/CWE-328).",
                    remediation_summary="Replaced weak cryptographic algorithm with modern AES / SHA256.",
                    confidence="HIGH",
                    fixed_file_content=new_content,
                )

        # 3. C# Unsafe Deserialization (CWE-502)
        if (
            "deserial" in rule_lower
            or "unsafe-api" in rule_lower
            or "typenamehandling" in finding.code_snippet.lower()
            or "binaryformatter" in finding.code_snippet.lower()
            or "cwe-502" in (finding.cwe_id or "").lower()
            or "deserial" in finding.finding_id.lower()
        ):
            new_content = file_content
            # Replace TypeNameHandling with TypeNameHandling.None
            new_content = re.sub(
                r'TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)',
                'TypeNameHandling = TypeNameHandling.None',
                new_content,
            )
            new_content = re.sub(
                r'TypeNameHandling\.(All|Auto|Objects|Arrays)',
                'TypeNameHandling.None',
                new_content,
            )
            # Remove any confusing comments that mention TypeNameHandling.Auto / All
            new_content = re.sub(
                r'//[^\n]*TypeNameHandling\.(Auto|All|Objects|Arrays)[^\n]*',
                '// TypeNameHandling secured to TypeNameHandling.None (CWE-502)',
                new_content,
            )
            if "BinaryFormatter" in new_content:
                new_content = re.sub(r'new\s+BinaryFormatter\(\)', '/* BinaryFormatter removed: insecure */', new_content)
                new_content = re.sub(
                    r'(?P<var>\w+)\.Deserialize\((?P<stream>[^\)]+)\)',
                    r'System.Text.Json.JsonSerializer.Deserialize<object>(\g<stream>)',
                    new_content
                )

            if new_content != file_content:
                return FixProposal(
                    explanation="Disabled dangerous polymorphic type name handling (TypeNameHandling.None) and replaced insecure BinaryFormatter with safe typed deserializer (CWE-502).",
                    remediation_summary="Disabled unsafe TypeNameHandling (TypeNameHandling.None) and secured deserialization.",
                    confidence="HIGH",
                    fixed_file_content=new_content,
                )
            elif "TypeNameHandling.None" in file_content:
                cleaned = re.sub(
                    r'//[^\n]*TypeNameHandling\.(Auto|All|Objects|Arrays)[^\n]*',
                    '// TypeNameHandling secured to TypeNameHandling.None (CWE-502)',
                    file_content,
                )
                return FixProposal(
                    explanation="Verified TypeNameHandling is configured to TypeNameHandling.None and sanitized misleading configuration comments (CWE-502).",
                    remediation_summary="Sanitized TypeNameHandling configuration to TypeNameHandling.None.",
                    confidence="HIGH",
                    fixed_file_content=cleaned,
                )

        # 4. ASP.NET Core Middleware Pipeline & HSTS / CORS in Program.cs (CWE-696 / CWE-319 / CWE-942)
        if "inverted-auth" in rule_lower or "hsts" in rule_lower or "cors" in rule_lower or finding.file_path.lower().endswith("program.cs"):
            new_content = file_content
            # Uncomment commented HSTS or HTTPS redirection calls
            new_content = re.sub(r'(?m)^([ \t]*)//[ \t]*app\.UseHsts\(\);?', r'\1app.UseHsts();', new_content)
            new_content = re.sub(r'(?m)^([ \t]*)//[ \t]*app\.UseHttpsRedirection\(\);?', r'\1app.UseHttpsRedirection();', new_content)

            # Restrict wildcard CORS
            new_content = re.sub(
                r'policy\.AllowAnyOrigin\(\)\.AllowAnyHeader\(\)\.AllowAnyMethod\(\);',
                'policy.WithOrigins("https://portal.airgap.internal").AllowAnyHeader().AllowAnyMethod();',
                new_content
            )

            # Fix inverted auth middleware order
            if "app.UseAuthorization();\napp.UseAuthentication();" in new_content:
                new_content = new_content.replace(
                    "app.UseAuthorization();\napp.UseAuthentication();",
                    "app.UseAuthentication();\napp.UseAuthorization();",
                )
            elif "app.UseAuthorization();\r\napp.UseAuthentication();" in new_content:
                new_content = new_content.replace(
                    "app.UseAuthorization();\r\napp.UseAuthentication();",
                    "app.UseAuthentication();\r\napp.UseAuthorization();",
                )

            # Ensure app.UseHsts() is present in middleware pipeline
            if "app.UseHsts(" not in new_content:
                dev_env_match = re.search(r'if\s*\(\s*!app\.Environment\.IsDevelopment\(\)\s*\)\s*\{', new_content)
                if dev_env_match:
                    insert_pos = dev_env_match.end()
                    exc_match = re.search(r'app\.UseExceptionHandler\([^;]+;\s*', new_content[insert_pos:])
                    if exc_match:
                        exc_end = insert_pos + exc_match.end()
                        new_content = new_content[:exc_end] + "\n    app.UseHsts();" + new_content[exc_end:]
                    else:
                        new_content = new_content[:insert_pos] + "\n    app.UseHsts();" + new_content[insert_pos:]
                elif "app.UseHttpsRedirection();" in new_content:
                    new_content = new_content.replace(
                        "app.UseHttpsRedirection();",
                        "app.UseHsts();\napp.UseHttpsRedirection();",
                        1
                    )
                elif "app.UseStaticFiles();" in new_content:
                    new_content = new_content.replace(
                        "app.UseStaticFiles();",
                        "app.UseHsts();\napp.UseHttpsRedirection();\napp.UseStaticFiles();",
                        1
                    )
                elif "app.UseRouting();" in new_content:
                    new_content = new_content.replace(
                        "app.UseRouting();",
                        "app.UseHsts();\napp.UseHttpsRedirection();\napp.UseRouting();",
                        1
                    )
                elif "app.UseAuthentication();" in new_content:
                    new_content = new_content.replace(
                        "app.UseAuthentication();",
                        "app.UseHsts();\napp.UseHttpsRedirection();\napp.UseAuthentication();",
                        1
                    )
                elif "var app = builder.Build();" in new_content:
                    new_content = new_content.replace(
                        "var app = builder.Build();",
                        "var app = builder.Build();\n\nif (!app.Environment.IsDevelopment())\n{\n    app.UseHsts();\n}\napp.UseHttpsRedirection();",
                        1
                    )
                elif "app.Run();" in new_content:
                    new_content = new_content.replace(
                        "app.Run();",
                        "app.UseHsts();\napp.UseHttpsRedirection();\n\napp.Run();",
                        1
                    )

            # Ensure app.UseHttpsRedirection() is present
            if "app.UseHttpsRedirection(" not in new_content:
                if "app.UseStaticFiles();" in new_content:
                    new_content = new_content.replace(
                        "app.UseStaticFiles();",
                        "app.UseHttpsRedirection();\napp.UseStaticFiles();",
                        1
                    )
                elif "app.UseRouting();" in new_content:
                    new_content = new_content.replace(
                        "app.UseRouting();",
                        "app.UseHttpsRedirection();\napp.UseRouting();",
                        1
                    )
                elif "app.Run();" in new_content:
                    new_content = new_content.replace(
                        "app.Run();",
                        "app.UseHttpsRedirection();\napp.Run();",
                        1
                    )

            if new_content != file_content:
                return FixProposal(
                    explanation=(
                        "Secured ASP.NET Core middleware pipeline in Program.cs: enabled HTTP Strict Transport "
                        "Security (HSTS - CWE-319), enforced HTTPS redirection, and ensured correct middleware ordering."
                    ),
                    remediation_summary="Enabled app.UseHsts() and app.UseHttpsRedirection() in Program.cs.",
                    confidence="HIGH",
                    fixed_file_content=new_content,
                )

        # 5. JSON Configuration files (launchSettings.json, appsettings.json, etc.) - CWE-918 / CWE-798 / CWE-16
        if (
            finding.file_path.lower().endswith(".json")
            or "launchsettings" in finding.file_path.lower()
            or "appsettings" in finding.file_path.lower()
            or "connectionstring" in rule_lower
            or "allowed-hosts" in rule_lower
        ):
            try:
                clean_json_str = file_content.strip()
                if clean_json_str.startswith("```"):
                    lines = [l for l in clean_json_str.splitlines() if not l.strip().startswith("```")]
                    clean_json_str = "\n".join(lines).strip()

                cfg_data = json.loads(clean_json_str)
                modified = False

                # 5a. Fix $schema if pointing to external URL
                if "$schema" in cfg_data and isinstance(cfg_data["$schema"], str):
                    schema_val = cfg_data["$schema"]
                    if not (
                        "localhost" in schema_val
                        or "127.0.0.1" in schema_val
                        or "airgap.internal" in schema_val
                    ):
                        schema_name = Path(schema_val.split("?")[0]).name or "launchsettings.json"
                        cfg_data["$schema"] = f"http://proxy.airgap.internal:8080/{schema_name}"
                        modified = True

                # 5b. Fix AllowedHosts
                for ah_key in ("AllowedHosts", "allowedHosts", "ALLOWEDHOSTS"):
                    if ah_key in cfg_data and isinstance(cfg_data[ah_key], str) and "*" in cfg_data[ah_key]:
                        cfg_data[ah_key] = "localhost;*.airgap.internal"
                        modified = True

                # 5c. Fix ConnectionStrings passwords
                if isinstance(cfg_data.get("ConnectionStrings"), dict):
                    for k, v in cfg_data["ConnectionStrings"].items():
                        if isinstance(v, str) and re.search(r"(?i)(Password|Pwd)\s*=", v):
                            cfg_data["ConnectionStrings"][k] = re.sub(
                                r"(?i)(Password|Pwd)\s*=\s*[^;]+;?",
                                "Integrated Security=True;",
                                v,
                            )
                            modified = True

                # 5d. Fix TelemetryEndpoint
                if "TelemetryEndpoint" in cfg_data and "airgap.internal" not in str(cfg_data["TelemetryEndpoint"]):
                    cfg_data["TelemetryEndpoint"] = "http://proxy.airgap.internal:8080/v1/telemetry"
                    modified = True

                # 5e. Recursively sanitize any other external URLs in JSON
                def _sanitize_json_urls(obj):
                    nonlocal modified
                    if isinstance(obj, dict):
                        for k, v in list(obj.items()):
                            if isinstance(v, str) and ("http://" in v or "https://" in v):
                                if "localhost" not in v and "127.0.0.1" not in v and "airgap.internal" not in v:
                                    path_match = re.search(r'https?://[^/\s"\']+(/[^\s"\']*)?', v)
                                    path_suffix = path_match.group(1) if (path_match and path_match.group(1)) else ""
                                    obj[k] = f"http://proxy.airgap.internal:8080{path_suffix}"
                                    modified = True
                            elif isinstance(v, (dict, list)):
                                _sanitize_json_urls(v)
                    elif isinstance(obj, list):
                        for item in obj:
                            _sanitize_json_urls(item)

                _sanitize_json_urls(cfg_data)

                new_json = json.dumps(cfg_data, indent=2) + "\n"
                if modified or new_json.strip() != file_content.strip():
                    return FixProposal(
                        explanation=(
                            f"Remediated security issues in `{Path(finding.file_path).name}`: routed external schemas and "
                            f"egress URLs to internal air-gap proxy gateway 'http://proxy.airgap.internal:8080' (CWE-918) "
                            f"and secured configuration settings."
                        ),
                        remediation_summary=f"Proxied external URLs and schema to http://proxy.airgap.internal:8080 in {Path(finding.file_path).name}.",
                        confidence="HIGH",
                        fixed_file_content=new_json,
                    )
            except Exception as ex:
                logger.debug("Failed deterministic JSON config fix: %s", ex)

            # Fallback for AllowedHosts wildcard if json.loads failed (e.g. comments in JSON) or format differed
            if (
                "allowed-hosts" in rule_lower
                or "allowedhosts" in rule_lower
                or "aspnet.config.allowed-hosts" in rule_lower
            ) and re.search(r'\"(?i:AllowedHosts)\"\s*:\s*\"[^\"]*\*\"', file_content):
                new_content = re.sub(
                    r'\"(?i:AllowedHosts)\"\s*:\s*\"[^\"]*\*\"',
                    '"AllowedHosts": "localhost;*.airgap.internal"',
                    file_content,
                )
                if new_content.strip() != file_content.strip():
                    return FixProposal(
                        explanation=(
                            f"Restricted wildcard AllowedHosts in `{Path(finding.file_path).name}` to approved "
                            "internal air-gap domains (CWE-16)."
                        ),
                        remediation_summary=f"Hardened AllowedHosts from wildcard '*' to approved internal endpoints in {Path(finding.file_path).name}.",
                        confidence="HIGH",
                        fixed_file_content=new_content,
                    )

        # 6. Air-Gap External Outbound Network Egress (CWE-918 / airgap-external-egress)
        if (
            "airgap" in rule_lower
            or "egress" in rule_lower
            or getattr(finding, "cwe_id", None) == "CWE-918"
            or "http://" in (finding.code_snippet or "")
            or "https://" in (finding.code_snippet or "")
            or "8.8.8.8" in (finding.code_snippet or "")
            or "1.1.1.1" in (finding.code_snippet or "")
        ):
            new_content = file_content
            replaced = False

            # Replace any external HTTP / HTTPS URLs with internal airgap proxy route
            url_pattern = re.compile(r'https?://(?P<host>[a-zA-Z0-9\.\-_:]+)(?P<path>/[^\s"\'<>\)]*)?')
            for m in list(url_pattern.finditer(new_content)):
                domain = m.group("host").lower().split(":")[0]
                if (
                    domain in ("localhost", "127.0.0.1")
                    or domain.endswith(".airgap.internal")
                    or domain == "proxy.airgap.internal"
                ):
                    continue

                full_url = m.group(0)
                path_part = m.group("path") or ""
                proxy_url = f"http://proxy.airgap.internal:8080{path_part}"
                new_content = new_content.replace(full_url, proxy_url)
                replaced = True

            # Replace public DNS resolvers
            if "8.8.8.8" in new_content:
                new_content = new_content.replace("8.8.8.8", "127.0.0.1 # internal airgap proxy fallback")
                replaced = True
            if "1.1.1.1" in new_content:
                new_content = new_content.replace("1.1.1.1", "127.0.0.1 # internal airgap proxy fallback")
                replaced = True

            if replaced and new_content.strip() != file_content.strip():
                return FixProposal(
                    explanation=(
                        f"Detected unwhitelisted outbound network call in `{finding.file_path}` violating "
                        f"air-gap zero-egress perimeter policy (CWE-918). Rerouted outbound traffic through "
                        f"internal proxy gateway 'http://proxy.airgap.internal:8080'."
                    ),
                    remediation_summary="Rerouted outbound request to internal airgap proxy gateway 'http://proxy.airgap.internal:8080'.",
                    confidence="HIGH",
                    fixed_file_content=new_content,
                )

        # 7. Hardcoded Secrets and Credentials in Source Code (CWE-798 / csharp.secret.hardcoded-credential / airgap.generic.secrets.hardcoded-credentials)
        if (
            "secret" in rule_lower
            or "credential" in rule_lower
            or getattr(finding, "cwe_id", None) == "CWE-798"
            or "***redacted***" in (finding.code_snippet or "").lower()
        ):
            new_content = file_content
            replaced = False

            # Extract variable name from snippet if available
            snip_clean = (finding.code_snippet or "").strip()
            target_var = None
            snip_m = re.search(
                r'(?i)\b(?:string|var|const|let)\s+(?P<var>[a-zA-Z0-9_]+)\s*[:=]|(?P<var2>[a-zA-Z0-9_]*(?:password|pwd|secret|apiKey|api_key|token|privateKey|jwtSecret|bearer)[a-zA-Z0-9_]*)\s*[:=]',
                snip_clean,
            )
            if snip_m:
                cand = snip_m.group("var") or snip_m.group("var2")
                if cand and cand.lower() not in ("string", "var", "const", "let"):
                    target_var = cand

            # 7a. C# const / static readonly / field declaration
            p1 = re.compile(
                r'(?P<indent>[ \t]*)(?P<mods>(?:(?:public|private|internal|protected|static|readonly)\s+)*)(?P<const>const\s+)?(?P<type>string|var)\s+(?P<var>[a-zA-Z0-9_]+)\s*=\s*["\'](?P<val>[^"\'\r\n]{8,})["\'](?P<semi>;)',
                re.IGNORECASE,
            )
            def _repl_field(m: re.Match) -> str:
                nonlocal replaced
                v = m.group("var")
                is_secret_name = any(k in v.lower() for k in ("secret", "password", "pwd", "token", "key", "credential", "apikey", "jwt"))
                if target_var:
                    if v.lower() != target_var.lower():
                        return m.group(0)
                elif not is_secret_name:
                    return m.group(0)

                indent = m.group("indent")
                mods = m.group("mods") or "public "
                if m.group("const"):
                    mods = mods.replace("const", "").strip()
                    if "static" not in mods:
                        mods = f"{mods} static".strip()
                    if "readonly" not in mods:
                        mods = f"{mods} readonly".strip()
                    mods = f"{mods} "
                env_name = re.sub(r'[^a-zA-Z0-9_]', '_', v).upper()
                replaced = True
                return f'{indent}{mods}string {v} = Environment.GetEnvironmentVariable("{env_name}") ?? "placeholder-{v.lower()}-token";'

            new_content = p1.sub(_repl_field, new_content)

            # 7b. Object initializer or property assignment (e.g. ApiKey = "xoxb-...")
            p2 = re.compile(
                r'(?P<indent>[ \t]*)(?P<prop>[a-zA-Z0-9_]+)\s*=\s*["\'](?P<val>[^"\'\r\n]{8,})["\'](?P<comma>[,;])',
                re.IGNORECASE,
            )
            def _repl_prop(m: re.Match) -> str:
                nonlocal replaced
                prop = m.group("prop")
                is_secret_name = any(k in prop.lower() for k in ("secret", "password", "pwd", "token", "key", "credential", "apikey", "jwt"))
                if target_var:
                    if prop.lower() != target_var.lower():
                        return m.group(0)
                elif not is_secret_name:
                    return m.group(0)

                indent = m.group("indent")
                comma = m.group("comma")
                env_name = re.sub(r'[^a-zA-Z0-9_]', '_', prop).upper()
                replaced = True
                return f'{indent}{prop} = Environment.GetEnvironmentVariable("{env_name}") ?? "placeholder-{prop.lower()}-token"{comma}'

            new_content = p2.sub(_repl_prop, new_content)

            # 7c. Python secret assignment (e.g. API_KEY = "...")
            if finding.file_path.lower().endswith(".py"):
                p3 = re.compile(
                    r'(?P<indent>[ \t]*)(?P<var>[a-zA-Z0-9_]*(?:PASSWORD|PWD|SECRET|API_KEY|TOKEN|KEY|CREDENTIAL)[a-zA-Z0-9_]*)\s*=\s*["\'](?P<val>[^"\'\r\n]{8,})["\']',
                    re.IGNORECASE,
                )
                def _repl_py(m: re.Match) -> str:
                    nonlocal replaced
                    v = m.group("var")
                    indent = m.group("indent")
                    replaced = True
                    return f'{indent}{v} = os.getenv("{v.upper()}", "placeholder-{v.lower()}-token")'
                new_content = p3.sub(_repl_py, new_content)

            if replaced and new_content.strip() != file_content.strip():
                return FixProposal(
                    explanation=(
                        f"Remediated hardcoded credential in `{finding.file_path}` (CWE-798). "
                        "Replaced plaintext secret with environment variable lookup and secure fallback."
                    ),
                    remediation_summary=f"Replaced hardcoded credential with environment variable lookup in {finding.file_path}.",
                    confidence="HIGH",
                    fixed_file_content=new_content,
                )

        raise RuntimeError(
            f"No local AI model available (ensure Ollama is running) and rule '{finding.rule_id}' has no offline fallback."
        )


def _format_model_size(size_bytes: Optional[int]) -> str:
    """Format byte count into human-readable MB/GB label."""
    if not size_bytes or size_bytes <= 0:
        return ""
    gb = size_bytes / (1024 ** 3)
    if gb >= 1.0:
        return f"{gb:.1f} GB"
    mb = size_bytes / (1024 ** 2)
    return f"{mb:.0f} MB"


def _normalize_ollama_root(base_url: Optional[str]) -> str:
    raw = (
        base_url
        or os.getenv("OLLAMA_URL")
        or os.getenv("OLLAMA_HOST")
        or os.getenv("LOCAL_LLM_URL")
        or "http://127.0.0.1:11434"
    ).strip().rstrip("/")
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = f"http://{raw}"
    if raw.endswith("/v1"):
        raw = raw[:-3].rstrip("/")
    return raw


def _is_local_host_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "")


def _discover_ollama_via_api(ollama_root: str, timeout: float = 2.5) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    tags_url = f"{ollama_root}/api/tags"
    req = urllib.request.Request(tags_url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        models: List[Dict[str, Any]] = []
        for entry in data.get("models") or []:
            name = (entry.get("name") or entry.get("model") or "").strip()
            if not name:
                continue
            size_val = entry.get("size")
            size_bytes = int(size_val) if isinstance(size_val, (int, float)) and size_val > 0 else None
            details = entry.get("details") or {}
            models.append({
                "name": name,
                "size_bytes": size_bytes,
                "size_label": _format_model_size(size_bytes),
                "parameter_size": details.get("parameter_size") or "",
                "family": details.get("family") or "",
                "quantization": details.get("quantization_level") or "",
                "modified_at": entry.get("modified_at") or "",
                "source": "ollama_api",
            })
        return models, None
    except Exception as exc:
        return [], str(exc)


def _discover_ollama_via_cli(timeout: float = 3.0) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    ollama_bin = shutil.which("ollama")
    if not ollama_bin:
        return [], "ollama CLI not found"
    try:
        proc = subprocess.run(
            [ollama_bin, "list"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip() or f"ollama list exited with {proc.returncode}"
            return [], err
        models: List[Dict[str, Any]] = []
        for line in proc.stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.upper().startswith("NAME"):
                continue
            cols = re.split(r"\s{2,}", stripped)
            name = cols[0].strip() if cols else ""
            if not name:
                continue
            size_label = cols[2].strip() if len(cols) >= 3 and cols[2].strip() != "-" else ""
            models.append({
                "name": name,
                "size_bytes": None,
                "size_label": size_label,
                "parameter_size": "",
                "family": "",
                "quantization": "",
                "modified_at": cols[3].strip() if len(cols) >= 4 else "",
                "source": "ollama_cli",
            })
        return models, None
    except Exception as exc:
        return [], str(exc)


def _discover_ollama_via_manifests(models_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    base_dir = models_dir or Path(os.getenv("OLLAMA_MODELS") or (Path.home() / ".ollama" / "models"))
    manifests_dir = base_dir / "manifests"
    if not manifests_dir.exists() or not manifests_dir.is_dir():
        return []

    models: List[Dict[str, Any]] = []
    for manifest_file in sorted(manifests_dir.rglob("*")):
        if not manifest_file.is_file() or manifest_file.name.startswith("."):
            continue
        try:
            rel_parts = manifest_file.relative_to(manifests_dir).parts
        except ValueError:
            continue
        if len(rel_parts) == 4 and rel_parts[0] == "registry.ollama.ai":
            _, namespace, model_name, tag = rel_parts
            full_name = f"{model_name}:{tag}" if namespace == "library" else f"{namespace}/{model_name}:{tag}"
        elif len(rel_parts) >= 3:
            tag = rel_parts[-1]
            model_name = rel_parts[-2]
            namespace = rel_parts[-3]
            registry = rel_parts[0] if len(rel_parts) >= 4 else ""
            if registry == "registry.ollama.ai" and namespace == "library":
                full_name = f"{model_name}:{tag}"
            elif registry and registry != "registry.ollama.ai":
                full_name = f"{registry}/{namespace}/{model_name}:{tag}"
            else:
                full_name = f"{namespace}/{model_name}:{tag}"
        elif len(rel_parts) == 2:
            full_name = f"{rel_parts[0]}:{rel_parts[1]}"
        else:
            continue

        size_bytes: Optional[int] = None
        try:
            raw_json = json.loads(manifest_file.read_text(encoding="utf-8"))
            total_sz = 0
            cfg_obj = raw_json.get("config")
            if isinstance(cfg_obj, dict) and isinstance(cfg_obj.get("size"), int):
                total_sz += cfg_obj["size"]
            for layer in raw_json.get("layers") or []:
                if isinstance(layer, dict) and isinstance(layer.get("size"), int):
                    total_sz += layer["size"]
            if total_sz > 0:
                size_bytes = total_sz
        except Exception:
            pass

        models.append({
            "name": full_name,
            "size_bytes": size_bytes,
            "size_label": _format_model_size(size_bytes),
            "parameter_size": "",
            "family": "",
            "quantization": "",
            "modified_at": "",
            "source": "local_manifests",
        })
    return models


def _discover_openai_compat_models(base_url: Optional[str], timeout: float = 2.5) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    raw = (base_url or os.getenv("LOCAL_LLM_URL") or "http://localhost:1234/v1").strip().rstrip("/")
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = f"http://{raw}"
    models_url = f"{raw}/models" if raw.endswith("/v1") else f"{raw}/v1/models"
    req = urllib.request.Request(models_url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        models: List[Dict[str, Any]] = []
        for entry in data.get("data") or []:
            mid = (entry.get("id") or "").strip()
            if mid:
                models.append({
                    "name": mid,
                    "size_bytes": None,
                    "size_label": "",
                    "parameter_size": "",
                    "family": entry.get("owned_by") or "",
                    "quantization": "",
                    "modified_at": "",
                    "source": "openai_compat_api",
                })
        return models, None
    except Exception as exc:
        return [], str(exc)


def discover_local_llm_models(
    provider: str = "ollama",
    base_url: Optional[str] = None,
    timeout: float = 2.5,
    models_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Discover locally installed/available LLM models for the selected local provider.
    For Ollama, queries `{base_url}/api/tags` first, falling back to `ollama list` CLI
    and `~/.ollama/models/manifests` on disk when the daemon is stopped.
    """
    prov = (provider or "ollama").strip().lower()
    if prov == "local":
        eff_base = (base_url or os.getenv("LOCAL_LLM_URL") or "http://localhost:1234/v1").strip().rstrip("/")
        models, err = _discover_openai_compat_models(eff_base, timeout=timeout)
        names = [m["name"] for m in models]
        return {
            "provider": "local",
            "base_url": eff_base,
            "daemon_running": err is None,
            "source": "openai_compat_api" if err is None else "unavailable",
            "models": models,
            "model_names": names,
            "default_model": names[0] if names else "qwen2.5-coder-7b-instruct",
            "error": err,
        }

    ollama_root = _normalize_ollama_root(base_url)
    models, api_err = _discover_ollama_via_api(ollama_root, timeout=timeout)
    daemon_running = api_err is None
    source = "ollama_api" if daemon_running else "unavailable"
    error_msg: Optional[str] = None

    if not daemon_running and _is_local_host_url(ollama_root):
        cli_models, cli_err = _discover_ollama_via_cli(timeout=timeout)
        if cli_err is None:
            models = cli_models
            daemon_running = True
            source = "ollama_cli"
        else:
            disk_models = _discover_ollama_via_manifests(models_dir=models_dir)
            if disk_models:
                models = disk_models
                source = "local_manifests"
                error_msg = "Ollama server is offline; showing models found in local manifest cache."
            else:
                error_msg = api_err or cli_err
    elif api_err:
        error_msg = api_err

    # Deduplicate while preserving discovery order
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for m in models:
        name = m.get("name", "")
        if name and name not in seen:
            seen.add(name)
            deduped.append(m)

    names = [m["name"] for m in deduped]
    preferred_env = os.getenv("OLLAMA_MODEL") or "qwen2.5-coder:3b"
    default_model = preferred_env if preferred_env in names else (names[0] if names else preferred_env)

    return {
        "provider": "ollama",
        "base_url": ollama_root,
        "daemon_running": daemon_running,
        "source": source,
        "models": deduped,
        "model_names": names,
        "default_model": default_model,
        "error": error_msg,
    }


_PRELOAD_LOCK = threading.Lock()
_INFLIGHT_PRELOADS: set = set()


def preload_local_llm_model(
    provider: Optional[str] = "ollama",
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    keep_alive: Optional[str] = None,
    timeout: float = 120.0,
) -> Dict[str, Any]:
    """
    Loads the selected local LLM model into memory (RAM/VRAM) immediately so it is hot
    when remediation begins.

    - Native Ollama: POST {base_url}/api/generate with an empty prompt and keep_alive
      (official Ollama warm-load API that loads weights + KV-cache without generating tokens).
    - OpenAI-compatible local server (/v1): minimal max_tokens=1 chat completion warm-up.
    """
    prov = (provider or os.getenv("LLM_PROVIDER") or "ollama").strip().lower()
    if prov not in ("ollama", "local"):
        return {
            "loaded": False,
            "skipped": True,
            "provider": prov,
            "model": model or "",
            "reason": f"Provider '{prov}' does not require local memory preloading.",
        }

    eff_model = (
        (model or "").strip()
        or os.getenv("LLM_MODEL")
        or CloudLLMClient._default_model(prov)
    )
    eff_keep_alive = keep_alive or os.getenv("OLLAMA_KEEP_ALIVE", "30m")
    num_ctx = int(os.getenv("OLLAMA_NUM_CTX", "8192"))

    if prov == "local" or (base_url and base_url.strip().rstrip("/").endswith("/v1")):
        eff_base = (
            (base_url or "").strip()
            or os.getenv("LOCAL_LLM_URL")
            or ("http://localhost:1234/v1" if prov == "local" else "http://127.0.0.1:11434/v1")
        ).rstrip("/")
        url = f"{eff_base}/chat/completions"
        payload: Dict[str, Any] = {
            "model": eff_model,
            "messages": [{"role": "user", "content": "ready"}],
            "max_tokens": 1,
            "temperature": 0.0,
        }
    else:
        eff_base = _normalize_ollama_root(base_url)
        url = f"{eff_base}/api/generate"
        payload = {
            "model": eff_model,
            "prompt": "",
            "stream": False,
            "keep_alive": eff_keep_alive,
            "options": {
                "num_ctx": num_ctx,
            },
        }

    headers = {"Content-Type": "application/json"}
    api_key = os.getenv("OLLAMA_API_KEY") or os.getenv("LLM_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    started = time.monotonic()
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
        elapsed_ms = round((time.monotonic() - started) * 1000.0, 1)
        logger.info(
            "Preloaded local LLM model '%s' into memory via %s in %.1fms (keep_alive=%s, num_ctx=%d)",
            eff_model,
            eff_base,
            elapsed_ms,
            eff_keep_alive,
            num_ctx,
        )
        return {
            "loaded": True,
            "provider": prov,
            "model": eff_model,
            "base_url": eff_base,
            "keep_alive": eff_keep_alive,
            "num_ctx": num_ctx,
            "elapsed_ms": elapsed_ms,
            "error": None,
        }
    except Exception as exc:
        elapsed_ms = round((time.monotonic() - started) * 1000.0, 1)
        logger.warning(
            "Could not preload local LLM model '%s' via %s (%s)",
            eff_model,
            eff_base,
            exc,
        )
        return {
            "loaded": False,
            "provider": prov,
            "model": eff_model,
            "base_url": eff_base,
            "keep_alive": eff_keep_alive,
            "num_ctx": num_ctx,
            "elapsed_ms": elapsed_ms,
            "error": str(exc),
        }


def preload_local_llm_model_async(
    provider: Optional[str] = "ollama",
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    keep_alive: Optional[str] = None,
    timeout: float = 120.0,
    on_complete: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Optional[threading.Thread]:
    """
    Starts loading the selected local LLM model into memory on a background daemon thread
    so process startup (git prepare, build, scan) proceeds in parallel while weights load.
    Deduplicates concurrent in-flight preload requests for the exact same target model.
    """
    prov = (provider or os.getenv("LLM_PROVIDER") or "ollama").strip().lower()
    if prov not in ("ollama", "local"):
        return None

    eff_model = (
        (model or "").strip()
        or os.getenv("LLM_MODEL")
        or CloudLLMClient._default_model(prov)
    )
    eff_base = (base_url or "").strip().rstrip("/")
    key = (prov, eff_model, eff_base)

    with _PRELOAD_LOCK:
        if key in _INFLIGHT_PRELOADS:
            return None
        _INFLIGHT_PRELOADS.add(key)

    def _worker() -> None:
        try:
            result = preload_local_llm_model(
                provider=prov,
                model=eff_model,
                base_url=eff_base or None,
                keep_alive=keep_alive,
                timeout=timeout,
            )
            if on_complete:
                try:
                    on_complete(result)
                except Exception:
                    pass
        finally:
            with _PRELOAD_LOCK:
                _INFLIGHT_PRELOADS.discard(key)

    t = threading.Thread(
        target=_worker,
        name=f"llm-preload-{eff_model}",
        daemon=True,
    )
    t.start()
    return t
