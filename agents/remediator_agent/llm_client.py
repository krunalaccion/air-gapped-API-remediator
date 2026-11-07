import json
import os
import re
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from .models import Finding, FixProposal


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
  "fixed_file_content": "The complete, full remediated source file content ready to be saved."
}
"""


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
    ):
        self.provider = (provider or os.getenv("LLM_PROVIDER") or self._detect_provider()).lower()
        self.model = model or os.getenv("LLM_MODEL") or self._default_model(self.provider)
        self.api_key = api_key or self._resolve_api_key(self.provider)
        self.base_url = base_url or os.getenv("LLM_BASE_URL")

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
        user_prompt = self._build_user_prompt(finding, file_content, numbered_context)

        try:
            if self.provider in ("ollama", "local"):
                raw_response = self._call_ollama(user_prompt)
                return self._parse_response(raw_response)
            elif self.provider == "gemini":
                raw_response = self._call_gemini(user_prompt)
                return self._parse_response(raw_response)
            elif self.provider == "openai":
                raw_response = self._call_openai(user_prompt)
                return self._parse_response(raw_response)
            elif self.provider == "anthropic":
                raw_response = self._call_anthropic(user_prompt)
                return self._parse_response(raw_response)
            elif self.provider in ("mock", "offline", "auto-fallback"):
                return self._generate_deterministic_fix(finding, file_content)
            else:
                raise ValueError(f"Unsupported LLM provider: '{self.provider}'")
        except Exception as exc:
            # Fall back to deterministic fixer if LLM call fails (e.g. offline / air-gapped test or no network)
            if self.provider not in ("mock", "offline", "auto-fallback"):
                return self._generate_deterministic_fix(finding, file_content)
            raise

    @staticmethod
    def _build_user_prompt(
        finding: Finding, file_content: str, numbered_context: str
    ) -> str:
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

### Complete Original Source File
```
{file_content}
```

Return the JSON object containing `explanation`, `remediation_summary`, `confidence`, and `fixed_file_content`."""

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
        data = self._http_post(url, payload, headers)
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
        data = self._http_post(url, payload, headers)
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
        data = self._http_post(url, payload, headers)
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
            data = self._http_post(url, payload, headers)
            return data["choices"][0]["message"]["content"]

        # Native Ollama /api/chat with format="json"
        url = f"{base}/api/chat"
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "options": {"temperature": 0.1},
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = self._http_post(url, payload, headers)
        return data.get("message", {}).get("content", "")

    @staticmethod
    def _http_post(
        url: str, payload: Dict[str, Any], headers: Dict[str, str]
    ) -> Dict[str, Any]:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM API HTTP {exc.code} error: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Network error calling LLM API: {exc.reason}") from exc

    @staticmethod
    def _parse_response(raw_text: str) -> FixProposal:
        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)

        data = json.loads(cleaned)
        return FixProposal(
            explanation=data.get("explanation", "Remediated security finding."),
            fixed_file_content=data["fixed_file_content"],
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
        used when running in offline/mock mode (or when no Cloud API key is set yet).
        """
        rule_lower = finding.rule_id.lower()

        # 1. C# SQL Injection (CWE-89)
        if "sql" in rule_lower or "SELECT " in finding.code_snippet:
            pattern = re.compile(
                r'(?P<indent>[ \t]*)var\s+(?P<qvar>\w+)\s*=\s*\$"(?P<sql_prefix>SELECT\s+.*?\s+WHERE\s+\w+\s*=\s*)\'\{(?P<param>\w+)\}\'"\s*;?'
            )
            match = pattern.search(file_content)
            if match:
                indent = match.group("indent")
                qvar = match.group("qvar")
                sql_prefix = match.group("sql_prefix")
                param = match.group("param")
                param_tag = f"@{param}"

                fixed_query_line = f'{indent}const string {qvar} = "{sql_prefix}{param_tag}";'
                new_content = pattern.sub(fixed_query_line, file_content, count=1)

                cmd_pattern = re.compile(
                    rf'(?P<cindent>[ \t]*)(?:using\s+)?var\s+(?P<cmdvar>\w+)\s*=\s*new\s+SqlCommand\(\s*{re.escape(qvar)}\s*,\s*\w+\s*\)\s*;'
                )
                cmd_match = cmd_pattern.search(new_content)
                if cmd_match and f'Parameters.AddWithValue("{param_tag}"' not in new_content:
                    cindent = cmd_match.group("cindent")
                    cmdvar = cmd_match.group("cmdvar")
                    replacement = (
                        f"{cmd_match.group(0)}\n"
                        f'{cindent}{cmdvar}.Parameters.AddWithValue("{param_tag}", {param});'
                    )
                    new_content = cmd_pattern.sub(replacement, new_content, count=1)

                return FixProposal(
                    explanation=(
                        f"The query on line {finding.line_number} used C# string interpolation "
                        f"(`$\"... '{{userId}}'...\"`) to concatenate user-controlled input (`{param}`) "
                        f"directly into a SQL command, enabling SQL Injection (CWE-89). "
                        f"Replaced string interpolation with a constant parameterized SQL query (`{param_tag}`) "
                        f"and bound the parameter safely via `SqlCommand.Parameters.AddWithValue`."
                    ),
                    remediation_summary=(
                        f"Replaced interpolated SQL string with parameterized query using @{param}."
                    ),
                    confidence="HIGH",
                    fixed_file_content=new_content,
                )

        # 2. ASP.NET Core Middleware Pipeline & HSTS / CORS in Program.cs (CWE-696 / CWE-319 / CWE-942)
        if "inverted-auth" in rule_lower or "hsts" in rule_lower or "cors" in rule_lower or finding.file_path.lower().endswith("program.cs"):
            new_content = file_content
            new_content = new_content.replace(
                "policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();",
                'policy.WithOrigins("https://portal.airgap.internal").AllowAnyHeader().AllowAnyMethod();',
            )
            if "app.UseAuthorization();\napp.UseAuthentication();" in new_content:
                new_content = new_content.replace(
                    "app.UseAuthorization();\napp.UseAuthentication();",
                    "app.UseHsts();\napp.UseHttpsRedirection();\napp.UseAuthentication();\napp.UseAuthorization();",
                )
            elif "app.UseAuthorization();\r\napp.UseAuthentication();" in new_content:
                new_content = new_content.replace(
                    "app.UseAuthorization();\r\napp.UseAuthentication();",
                    "app.UseHsts();\r\napp.UseHttpsRedirection();\r\napp.UseAuthentication();\r\napp.UseAuthorization();",
                )
            if new_content != file_content:
                return FixProposal(
                    explanation=(
                        "Fixed inverted ASP.NET Core authentication/authorization middleware order (CWE-696) "
                        "by registering app.UseAuthentication() before app.UseAuthorization(), enabled HSTS/HTTPS "
                        "enforcement (CWE-319), and scoped CORS origins to internal air-gap domains (CWE-942)."
                    ),
                    remediation_summary="Reordered UseAuthentication before UseAuthorization, enabled UseHsts, and restricted CORS.",
                    confidence="HIGH",
                    fixed_file_content=new_content,
                )

        # 3. ASP.NET Core appsettings.json Plaintext Password & Wildcard AllowedHosts (CWE-798 / CWE-16)
        if "connectionstring" in rule_lower or "allowed-hosts" in rule_lower or finding.file_path.lower().endswith("appsettings.json"):
            try:
                cfg_data = json.loads(file_content)
                cfg_data["AllowedHosts"] = "*.airgap.internal;localhost"
                if isinstance(cfg_data.get("ConnectionStrings"), dict):
                    for k, v in cfg_data["ConnectionStrings"].items():
                        if isinstance(v, str):
                            cfg_data["ConnectionStrings"][k] = re.sub(
                                r"(?i)(Password|Pwd)\s*=\s*[^;]+;?",
                                "Integrated Security=True;",
                                v,
                            )
                if "TelemetryEndpoint" in cfg_data:
                    cfg_data["TelemetryEndpoint"] = "http://proxy.airgap.internal:8080/v1/telemetry"
                new_content = json.dumps(cfg_data, indent=2) + "\n"
                if new_content.strip() != file_content.strip():
                    return FixProposal(
                        explanation=(
                            "Removed hardcoded plaintext database password from ConnectionStrings (CWE-798), "
                            "restricted wildcard AllowedHosts to internal air-gap domains (CWE-16), and routed "
                            "TelemetryEndpoint through the internal air-gap proxy gateway."
                        ),
                        remediation_summary="Removed plaintext ConnectionString password and restricted AllowedHosts in appsettings.json.",
                        confidence="HIGH",
                        fixed_file_content=new_content,
                    )
            except Exception:
                pass

        # 4. Air-Gap External Outbound Network Egress (CWE-918 / airgap-external-egress)
        if (
            "airgap" in rule_lower
            or "egress" in rule_lower
            or finding.cwe_id == "CWE-918"
            or "http://" in finding.code_snippet
            or "https://" in finding.code_snippet
            or "8.8.8.8" in finding.code_snippet
            or "1.1.1.1" in finding.code_snippet
        ):
            new_content = file_content
            replaced = False

            # Replace any external HTTP / HTTPS URLs with internal airgap proxy route
            url_pattern = re.compile(r'https?://(?P<host>[a-zA-Z0-9\.\-_:]+)(?P<path>/[^\s"\'<>\)]*)?')
            for m in list(url_pattern.finditer(new_content)):
                domain = m.group("host").lower()
                if (
                    domain in ("localhost", "127.0.0.1")
                    or domain.endswith(".airgap.internal")
                    or "schemastore.org" in domain
                    or "microsoft.com" in domain
                    or "w3.org" in domain
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

        raise RuntimeError(
            "No Cloud API key configured (set GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY) "
            f"and rule '{finding.rule_id}' has no offline fallback."
        )
