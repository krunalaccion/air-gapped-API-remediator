"""
Common Web Server and REST API for the Multi-Agent System.
Serves the unified Web UI and provides endpoints for all specialized agents:
- GitSubAgent (Repository lifecycle, branching, commits, PRs)
- ScannerAgent (Code, egress, and air-gap policy auditing)
- RemediatorAgent (Proxy routing, automated patching, compliance manifests, and BugFixerAgent SAST remediation)
- MultiAgentPipeline (End-to-end multi-agent orchestration)
"""

from __future__ import annotations
import http.server
import json
import logging
import os
import socketserver
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Dict, Any, Optional, List

from agents.base import AgentRegistry
from agents.git_agent.config import GitAgentConfig, ProviderType
from agents.git_agent.agent import GitSubAgent
from agents.scanner_agent.agent import ScannerAgent
from agents.remediator_agent.agent import RemediatorAgent, DEFAULT_SQLI_FINDING
from agents.remediator_agent.llm_client import discover_local_llm_models
from orchestrator.pipeline import MultiAgentPipeline
from orchestrator.scheduler import BatchScheduler, discover_repositories
from orchestrator.email_notifier import EmailReportNotifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("multi_agent.web_server")

# Active agent instances for the web session
ACTIVE_GIT_AGENT: Optional[GitSubAgent] = None
SCANNER_AGENT: ScannerAgent = ScannerAgent()
REMEDIATOR_AGENT: RemediatorAgent = RemediatorAgent()
LATEST_PR: Optional[Dict[str, Any]] = None

APP_ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_LOCAL_REPO = (APP_ROOT_DIR / "repos" / "CustomerApi").resolve()
EMAIL_NOTIFIER: EmailReportNotifier = EmailReportNotifier(app_root_dir=APP_ROOT_DIR)
BATCH_SCHEDULER: BatchScheduler = BatchScheduler(
    data_dir=APP_ROOT_DIR / "scheduler_data",
    app_root_dir=APP_ROOT_DIR,
    auto_start=False,
    email_notifier=EMAIL_NOTIFIER,
)


def _ensure_default_local_repo_ready(reset_files: bool = False) -> None:
    """Ensures repos/CustomerApi is a valid Git repository with both master and main branches."""
    try:
        DEFAULT_LOCAL_REPO.mkdir(parents=True, exist_ok=True)
        if reset_files or not (DEFAULT_LOCAL_REPO / "Controllers" / "UsersController.cs").exists():
            REMEDIATOR_AGENT.reset_demo(workspace_path=DEFAULT_LOCAL_REPO)
        if not (DEFAULT_LOCAL_REPO / ".git").exists():
            subprocess.run(["git", "init", "-b", "master"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
            subprocess.run(["git", "config", "user.name", "Git SubAgent"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
            subprocess.run(["git", "config", "user.email", "git-agent@subagent.local"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
            subprocess.run(["git", "add", "-A"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
            subprocess.run(["git", "commit", "-m", "chore: initial vulnerable CustomerApi repository"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
        elif reset_files:
            subprocess.run(["git", "add", "-A"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
            subprocess.run(["git", "commit", "-m", "chore: reset CustomerApi to pre-remediation baseline"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
        # Ensure both master and main refs point to the baseline commit so either base_branch works seamlessly
        subprocess.run(["git", "branch", "-f", "master", "HEAD"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
        subprocess.run(["git", "branch", "-f", "main", "HEAD"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
    except Exception as exc:
        logger.debug("Could not initialize default local repo: %s", exc)


def _init_local_git_repo(
    path: Path,
    base_branch: str = "main",
    author_name: str = "Git SubAgent",
    author_email: str = "git-agent@subagent.local",
) -> bool:
    """Initializes a local directory as a Git repository with baseline commit and main/master branches."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        init_branch = base_branch if base_branch and base_branch.lower() != "auto" else "main"
        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = author_name
        env["GIT_COMMITTER_NAME"] = author_name
        env["GIT_AUTHOR_EMAIL"] = author_email
        env["GIT_COMMITTER_EMAIL"] = author_email
        env["GIT_TERMINAL_PROMPT"] = "0"

        subprocess.run(["git", "init", "-b", init_branch], cwd=str(path), capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", author_name], cwd=str(path), capture_output=True)
        subprocess.run(["git", "config", "user.email", author_email], cwd=str(path), capture_output=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=str(path), capture_output=True)
        subprocess.run(["git", "add", "-A"], cwd=str(path), capture_output=True)
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "chore: initial baseline repository snapshot"],
            cwd=str(path),
            env=env,
            capture_output=True,
            check=True,
        )
        subprocess.run(["git", "branch", "-f", "master", "HEAD"], cwd=str(path), capture_output=True)
        subprocess.run(["git", "branch", "-f", "main", "HEAD"], cwd=str(path), capture_output=True)
        return True
    except Exception as exc:
        logger.warning("Could not auto-initialize git repository at %s: %s", path, exc)
        return False


_ensure_default_local_repo_ready(reset_files=False)

# Register core agents
AgentRegistry.register(
    "git",
    GitSubAgent(GitAgentConfig(repo_url="", provider=ProviderType.GENERIC)),
)
AgentRegistry.register("scanner", SCANNER_AGENT)
AgentRegistry.register("remediator", REMEDIATOR_AGENT)


def _normalize_local_repo_path(raw_path: str | Path) -> Path:
    """Normalizes local repository path and resolves common path aliases or nested working dirs."""
    if not raw_path:
        return Path(raw_path) if isinstance(raw_path, Path) else Path(".")
    raw_str = str(raw_path).replace("file://", "").strip()
    p = Path(raw_str).expanduser()
    if p.is_absolute() and p.exists():
        return p.resolve()
    # Resolve relative to APP_ROOT_DIR first if it exists there
    candidate_app = (APP_ROOT_DIR / raw_str).resolve()
    if candidate_app.exists():
        return candidate_app
    resolved = p.resolve()
    if resolved.exists():
        return resolved
    # Fallback 1: If path includes GitAgent/EnterpriseEmployeePortal, try without GitAgent/
    if "GitAgent" in resolved.parts:
        parts = [part for part in resolved.parts if part != "GitAgent"]
        alt1 = Path(*parts)
        if alt1.exists():
            return alt1
    # Fallback 2: Check in parent directory of APP_ROOT_DIR
    alt2 = (APP_ROOT_DIR.parent / resolved.name).resolve()
    if alt2.exists():
        return alt2
    # Fallback 3: Check inside APP_ROOT_DIR / "repos" / resolved.name
    alt3 = (APP_ROOT_DIR / "repos" / resolved.name).resolve()
    if alt3.exists():
        return alt3
    return resolved


def _resolve_active_workspace() -> Optional[Path]:
    """Returns the active GitSubAgent workspace path or None if not prepared."""
    if ACTIVE_GIT_AGENT and ACTIVE_GIT_AGENT.context:
        try:
            ws = ACTIVE_GIT_AGENT.get_workspace_path()
            if ws and ws.exists() and ws.resolve() != APP_ROOT_DIR:
                return ws
        except Exception:
            pass
    return None


def _build_telemetry_payload() -> Dict[str, Any]:
    """Builds a 100% real-time telemetry snapshot from the active agents and repository."""
    ws_dir = _resolve_active_workspace()
    git_prepared = bool(ACTIVE_GIT_AGENT and ACTIVE_GIT_AGENT.context and ws_dir)
    git_status = None
    git_context = None
    git_diff = ""
    git_author = "Git SubAgent <git-agent@subagent.local>"
    git_repo_name = ""
    git_remote_url = None
    git_has_token = False

    if git_prepared and ACTIVE_GIT_AGENT:
        try:
            git_status = ACTIVE_GIT_AGENT.get_status()
            git_context = ACTIVE_GIT_AGENT.context.to_dict() if ACTIVE_GIT_AGENT.context else None
            git_diff = ACTIVE_GIT_AGENT.get_diff()
            git_author = f"{ACTIVE_GIT_AGENT.config.author_name} <{ACTIVE_GIT_AGENT.config.author_email}>"
            git_repo_name = ACTIVE_GIT_AGENT.config.repo_name
            git_remote_url = ACTIVE_GIT_AGENT.get_sanitized_remote_url()
            git_has_token = bool(ACTIVE_GIT_AGENT.config.token)
        except Exception as exc:
            logger.debug("Telemetry git status check error: %s", exc)
        if not git_repo_name and ACTIVE_GIT_AGENT.context:
            git_repo_name = getattr(ACTIVE_GIT_AGENT.context, "repo_name", "")

    agents_list = AgentRegistry.list_agents()
    if SCANNER_AGENT.last_result or git_prepared:
        bug_findings = SCANNER_AGENT.load_bug_findings()
    else:
        bug_findings = []
    remediator_reports = REMEDIATOR_AGENT.list_reports(ws_dir) if (git_prepared and REMEDIATOR_AGENT.last_result) else []

    discovered_files = set()
    workspace_files: List[Dict[str, Any]] = []
    if git_prepared and ws_dir and ws_dir.exists():
        for p in ws_dir.rglob("*"):
            if p.is_file() and not any(part.startswith(".") for part in p.parts if part != p.name):
                if p.suffix in {".cs", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".md", ".sh", ".config"}:
                    try:
                        rel = str(p.relative_to(ws_dir)).replace("\\", "/")
                        discovered_files.add(rel)
                    except ValueError:
                        pass
        for rel in sorted(discovered_files):
            f_path = ws_dir / rel
            if f_path.exists() and f_path.is_file():
                workspace_files.append({
                    "relative_path": rel,
                    "exists": True,
                    "size_bytes": f_path.stat().st_size,
                })

    return {
        "default_repo_path": "",
        "active_workspace_path": str(ws_dir) if (git_prepared and ws_dir) else "",
        "agents": agents_list,
        "agents_total": len(agents_list),
        "git": {
            "prepared": git_prepared,
            "repo_name": git_repo_name,
            "context": git_context,
            "status": git_status,
            "diff": git_diff,
            "author": git_author,
            "remote_url": git_remote_url,
            "has_remote": bool(git_remote_url),
            "has_token": git_has_token,
        },
        "scanner": {
            "status": SCANNER_AGENT.status if (git_prepared or SCANNER_AGENT.last_result) else "IDLE",
            "last_result": SCANNER_AGENT.last_result,
            "bug_findings": bug_findings,
            "findings_dir": str(SCANNER_AGENT.findings_dir),
            "tools": SCANNER_AGENT.get_scanner_tools(),
        },
        "remediator": {
            "status": REMEDIATOR_AGENT.status if git_prepared else "IDLE",
            "last_result": REMEDIATOR_AGENT.last_result if git_prepared else None,
            "reports_count": len(remediator_reports),
            "progress": REMEDIATOR_AGENT.get_progress(),
        },
        "workspace_files": workspace_files,
        "latest_pr": LATEST_PR,
        "build_and_test": ACTIVE_GIT_AGENT.last_build_test_result if (git_prepared and ACTIVE_GIT_AGENT and hasattr(ACTIVE_GIT_AGENT, "last_build_test_result")) else None,
        "email": EMAIL_NOTIFIER.get_public_config(),
    }


def _dispatch_current_remediation_email(
    *,
    ws_path: Optional[Path] = None,
    remediation_result: Optional[Dict[str, Any]] = None,
    post_scan_result: Optional[Dict[str, Any]] = None,
    override_recipients: Optional[Any] = None,
    custom_subject: Optional[str] = None,
    custom_note: Optional[str] = None,
    trigger_source: str = "remediation_completed",
) -> Dict[str, Any]:
    """Gathers active workspace reports and sends the remediation summary email."""
    resolved_ws = ws_path or _resolve_active_workspace() or DEFAULT_LOCAL_REPO
    repo_name = (
        ACTIVE_GIT_AGENT.context.repo_name
        if (ACTIVE_GIT_AGENT and ACTIVE_GIT_AGENT.context and ACTIVE_GIT_AGENT.context.repo_name)
        else (resolved_ws.name if resolved_ws else "repository")
    )
    branch = (
        ACTIVE_GIT_AGENT.context.feature_branch
        if (ACTIVE_GIT_AGENT and ACTIVE_GIT_AGENT.context and ACTIVE_GIT_AGENT.context.feature_branch)
        else "remediation/airgap-api-compliance"
    )
    base_branch = (
        ACTIVE_GIT_AGENT.context.base_branch
        if (ACTIVE_GIT_AGENT and ACTIVE_GIT_AGENT.context and ACTIVE_GIT_AGENT.context.base_branch)
        else "main"
    )

    rem_res = remediation_result or REMEDIATOR_AGENT.last_result or {}
    post_scan = post_scan_result or getattr(REMEDIATOR_AGENT, "last_post_scan", None) or rem_res.get("post_scan") or {}
    scan_res = SCANNER_AGENT.last_result or {}

    rem_html, _ = REMEDIATOR_AGENT.get_report_content(fmt="html", workspace_path=str(resolved_ws) if resolved_ws else None)
    rem_json, _ = REMEDIATOR_AGENT.get_report_content(fmt="json", workspace_path=str(resolved_ws) if resolved_ws else None)
    scan_html, _ = SCANNER_AGENT.get_report_content("html")

    return EMAIL_NOTIFIER.send_remediation_report_email(
        repo_name=repo_name,
        workspace_path=str(resolved_ws) if resolved_ws else "",
        branch=branch,
        base_branch=base_branch,
        scan_result=scan_res,
        remediation_result=rem_res,
        post_scan_result=post_scan,
        pr_data=LATEST_PR,
        remediation_html=rem_html,
        remediation_json=rem_json,
        scan_html=scan_html,
        override_recipients=override_recipients,
        custom_subject=custom_subject,
        custom_note=custom_note,
        trigger_source=trigger_source,
    )


def get_web_dir() -> Path:
    """Finds the common web directory containing index.html."""
    return Path(__file__).parent / "web"


class MultiAgentAPIHandler(http.server.SimpleHTTPRequestHandler):
    """Unified HTTP Request Handler serving the common Multi-Agent Dashboard and JSON API."""

    def _send_json(self, data: Dict[str, Any], status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        global ACTIVE_GIT_AGENT
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/telemetry":
            """Return complete live telemetry snapshot for the portal UI."""
            self._send_json(_build_telemetry_payload())
            return

        elif path == "/api/agents":
            """List all registered agents and their current statuses."""
            agents_list = AgentRegistry.list_agents()
            self._send_json({
                "agents": agents_list,
                "total": len(agents_list),
            })
            return

        elif path in ("/api/fix/progress", "/api/remediator/progress"):
            """Return real-time status of files being fixed by RemediatorAgent in Step 3."""
            self._send_json(REMEDIATOR_AGENT.get_progress())
            return

        elif path == "/api/bug-fixer/reports":
            """List all saved BugFixerAgent remediation reports from RemediatorAgent."""
            git_prepared = bool(ACTIVE_GIT_AGENT and ACTIVE_GIT_AGENT.context)
            reports = REMEDIATOR_AGENT.list_reports(_resolve_active_workspace()) if (git_prepared and REMEDIATOR_AGENT.last_result) else []
            self._send_json({
                "count": len(reports),
                "reports": reports,
                "default_finding": None,
            })
            return

        elif path == "/api/securescan/report":
            """Serve the latest SecureScanAI HTML, JSON, or SARIF report."""
            parsed_query = urllib.parse.parse_qs(parsed.query)
            fmt = (parsed_query.get("format", ["html"])[0] or "html").lower()
            content_str, content_type = SCANNER_AGENT.get_report_content(fmt)
            if not content_str:
                self._send_json({"error": f"No SecureScanAI {fmt.upper()} report generated yet. Run a scan first."}, status=404)
                return

            content = content_str.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        elif path in ("/api/remediator/report", "/reports/REMEDIATION_AUDIT_REPORT.html", "/REMEDIATION_AUDIT_REPORT.html"):
            """Serve the latest RemediatorAgent Post-Remediation HTML or JSON report."""
            parsed_query = urllib.parse.parse_qs(parsed.query)
            fmt = (parsed_query.get("format", ["html"])[0] or "html").lower()
            ws_path = _resolve_active_workspace()
            content_str, content_type = REMEDIATOR_AGENT.get_report_content(fmt=fmt, workspace_path=str(ws_path) if ws_path else None)
            content = content_str.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        elif path == "/api/scanner/tools":
            self._send_json(SCANNER_AGENT.get_scanner_tools())
            return

        elif path == "/api/email/config":
            self._send_json(EMAIL_NOTIFIER.get_public_config())
            return

        elif path == "/api/email/outbox":
            self._send_json({"outbox": EMAIL_NOTIFIER.list_outbox(limit=25)})
            return

        elif path in ("/api/llm/models", "/api/ollama/models"):
            """Discover locally installed LLM models (Ollama daemon, CLI, manifests, or OpenAI-compatible)."""
            parsed_query = urllib.parse.parse_qs(parsed.query)
            provider = (parsed_query.get("provider", ["ollama"])[0] or "ollama").strip().lower()
            base_url = (parsed_query.get("base_url", [""])[0] or "").strip() or None
            self._send_json(discover_local_llm_models(provider=provider, base_url=base_url))
            return

        elif path == "/api/status":
            if not ACTIVE_GIT_AGENT:
                self._send_json({"error": "No active repository prepared"}, status=400)
                return
            stat = ACTIVE_GIT_AGENT.get_status()
            ctx = ACTIVE_GIT_AGENT.context
            self._send_json({
                "status": stat,
                "context": ctx.to_dict() if ctx else None,
            })
            return

        elif path == "/api/diff":
            if not ACTIVE_GIT_AGENT:
                self._send_json({"error": "No active repository prepared"}, status=400)
                return
            diff = ACTIVE_GIT_AGENT.get_diff()
            self._send_json({"diff": diff})
            return

        elif path == "/api/local-pr":
            if not ACTIVE_GIT_AGENT:
                self._send_json({"error": "No active repository prepared"}, status=400)
                return
            repo_path = ACTIVE_GIT_AGENT.get_workspace_path()
            prs_dir = repo_path / ".git" / "local_prs"
            if not prs_dir.exists():
                prs_dir = repo_path / ".local_prs"

            parsed_query = urllib.parse.parse_qs(parsed.query)
            pr_num = parsed_query.get("number", [None])[0]
            if pr_num:
                md_path = prs_dir / f"PR-{pr_num}.md"
            else:
                prs = sorted(prs_dir.glob("PR-*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
                md_path = prs[0] if prs else None

            if not md_path or not md_path.exists():
                self._send_json({"error": "No local PR report found"}, status=404)
                return

            self._send_json({
                "file_path": str(md_path.resolve()),
                "filename": md_path.name,
                "content": md_path.read_text(encoding="utf-8"),
            })
            return

        # Batch Scheduler GET endpoints
        elif path == "/api/scheduler/overview":
            self._send_json(BATCH_SCHEDULER.get_overview())
            return

        elif path == "/api/scheduler/schedules":
            self._send_json({"schedules": BATCH_SCHEDULER.list_schedules()})
            return

        elif path == "/api/scheduler/runs":
            parsed_query = urllib.parse.parse_qs(parsed.query)
            limit = int(parsed_query.get("limit", ["50"])[0] or 50)
            self._send_json({"runs": BATCH_SCHEDULER.list_runs(limit=limit)})
            return

        elif path == "/api/scheduler/runs/detail":
            parsed_query = urllib.parse.parse_qs(parsed.query)
            run_id = (parsed_query.get("run_id", [""])[0] or "").strip()
            detail = BATCH_SCHEDULER.get_run_detail(run_id) if run_id else None
            if not detail:
                self._send_json({"error": f"Run '{run_id}' not found"}, status=404)
                return
            self._send_json(detail)
            return

        elif path == "/api/scheduler/runs/report":
            parsed_query = urllib.parse.parse_qs(parsed.query)
            run_id = (parsed_query.get("run_id", [""])[0] or "").strip()
            repo_key = (parsed_query.get("repo", [""])[0] or "").strip()
            report_type = (parsed_query.get("type", ["remediation"])[0] or "remediation").strip()
            content_str, content_type = BATCH_SCHEDULER.get_repo_report(
                run_id=run_id,
                repo_key=repo_key,
                report_type=report_type,
            )
            if not content_str:
                self._send_json({"error": "Requested batch report not found."}, status=404)
                return
            content = content_str.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        elif path == "/api/scheduler/runs/pr":
            parsed_query = urllib.parse.parse_qs(parsed.query)
            run_id = (parsed_query.get("run_id", [""])[0] or "").strip()
            repo_key = (parsed_query.get("repo", [""])[0] or "").strip()
            detail = BATCH_SCHEDULER.get_run_detail(run_id) if run_id else None
            if not detail:
                self._send_json({"error": "Run not found"}, status=404)
                return
            target_repo = None
            for idx, r in enumerate(detail.get("repos") or []):
                if str(idx) == repo_key or r.get("name") == repo_key or r.get("relative_path") == repo_key:
                    target_repo = r
                    break
            if not target_repo or not target_repo.get("pr_file_path"):
                self._send_json({"error": "No local PR file found for this repository in this run."}, status=404)
                return
            pr_path = Path(target_repo["pr_file_path"]).resolve()
            repo_root = Path(target_repo["path"]).resolve()
            if not str(pr_path).startswith(str(repo_root) + os.sep) or not pr_path.exists():
                self._send_json({"error": "Local PR file no longer exists on disk."}, status=404)
                return
            self._send_json({
                "file_path": str(pr_path),
                "filename": pr_path.name,
                "content": pr_path.read_text(encoding="utf-8"),
            })
            return

        elif path == "/" or path == "/index.html":
            html_file = get_web_dir() / "index.html"
            if html_file.exists():
                content = html_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        elif path in ("/scheduler", "/scheduler.html"):
            html_file = get_web_dir() / "scheduler.html"
            if html_file.exists():
                content = html_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        # Static Web Assets (Favicons & Apple Touch Icons for Safari, Chrome, Firefox, Edge)
        elif (
            path.startswith("/favicon")
            or path.startswith("/apple-touch-icon")
            or path.startswith("/safari-pinned-tab")
        ):
            target_name = path.lstrip("/").split("?")[0]
            asset_file = get_web_dir() / target_name
            if not asset_file.exists():
                asset_file = Path(__file__).parent / target_name
            if not asset_file.exists():
                if "apple-touch-icon" in target_name:
                    asset_file = get_web_dir() / "apple-touch-icon.png"
                elif target_name.endswith(".ico"):
                    asset_file = get_web_dir() / "favicon.ico"
                elif target_name.endswith(".svg"):
                    asset_file = get_web_dir() / "favicon.svg"
                else:
                    asset_file = get_web_dir() / "favicon.png"

            if asset_file.exists():
                content = asset_file.read_bytes()
                mime = "image/png"
                if target_name.endswith(".ico"):
                    mime = "image/x-icon"
                elif target_name.endswith(".svg"):
                    mime = "image/svg+xml"
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-cache, must-revalidate")
                self.end_headers()
                self.wfile.write(content)
                return

        super().do_GET()

    def do_POST(self):
        global ACTIVE_GIT_AGENT, SCANNER_AGENT, REMEDIATOR_AGENT, LATEST_PR
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            payload = json.loads(post_data) if post_data else {}
        except Exception:
            payload = {}

        try:
            # 1. Prepare Workspace (GitSubAgent)
            if path == "/api/prepare":
                repo_url = payload.get("repo_url")
                if not repo_url:
                    self._send_json({"error": "repo_url is required"}, status=400)
                    return

                # Normalize local path if specified
                norm_cand = _normalize_local_repo_path(repo_url)
                is_local_hint = (
                    repo_url.startswith("/")
                    or repo_url.startswith("~")
                    or repo_url.startswith("./")
                    or repo_url.startswith("../")
                    or repo_url.startswith("file://")
                    or repo_url == "."
                    or (len(repo_url) > 2 and repo_url[1] == ":")
                    or norm_cand.exists()
                )
                if is_local_hint:
                    if norm_cand.exists():
                        repo_url = str(norm_cand)

                token = payload.get("token") or payload.get("git_token") or os.getenv("GITHUB_TOKEN") or os.getenv("GITLAB_TOKEN")
                username = payload.get("username") or payload.get("git_username")
                provider_str = payload.get("provider")
                if provider_str:
                    try:
                        provider = ProviderType(provider_str.lower())
                    except ValueError:
                        provider = ProviderType.GENERIC
                elif is_local_hint:
                    provider = ProviderType.LOCAL
                else:
                    provider = ProviderType.GENERIC

                auto_init = bool(payload.get("auto_init", False))

                config = GitAgentConfig(
                    repo_url=repo_url,
                    token=token,
                    username=username,
                    provider=provider,
                    base_branch=payload.get("base_branch"),
                    feature_branch_name=payload.get("feature_branch"),
                    workspace_dir=payload.get("workspace_dir"),
                    author_name=payload.get("author_name", "Git SubAgent"),
                    author_email=payload.get("author_email", "git-agent@subagent.local"),
                    auto_init=auto_init,
                )

                # Validation & Self-Protection: if target is local, verify it exists and never mutate APP_ROOT_DIR itself
                if config.is_local or config.provider == ProviderType.LOCAL:
                    clean_path = Path(config.sanitized_repo_url).resolve()
                    if clean_path == APP_ROOT_DIR:
                        self._send_json({
                            "error": "Cannot use the agent root directory as target repository. Please select or clone your project repository."
                        }, status=400)
                        return
                    elif clean_path == DEFAULT_LOCAL_REPO:
                        _ensure_default_local_repo_ready(reset_files=False)

                    if not clean_path.exists():
                        self._send_json({"error": f"Selected path does not exist: '{clean_path}'"}, status=400)
                        return
                    has_git = (clean_path / ".git").exists() or (clean_path / "HEAD").exists()
                    if not has_git:
                        code = subprocess.run(
                            ["git", "rev-parse", "--is-inside-work-tree"],
                            cwd=str(clean_path),
                            capture_output=True,
                        ).returncode
                        if code != 0:
                            if auto_init and clean_path.is_dir():
                                _init_local_git_repo(
                                    clean_path,
                                    base_branch=payload.get("base_branch") or "main",
                                    author_name=config.author_name,
                                    author_email=config.author_email,
                                )
                                has_git = True
                            else:
                                self._send_json({
                                    "error": f"Selected path '{clean_path}' is not a Git repository. Missing '.git' directory."
                                }, status=400)
                                return

                    # Clean up demo artifacts that may have been previously injected into non-CustomerApi repo
                    if clean_path.name != "CustomerApi":
                        injected_c = clean_path / "Controllers" / "UsersController.cs"
                        if injected_c.exists():
                            try:
                                c_txt = injected_c.read_text(encoding="utf-8", errors="ignore")
                                if "namespace CustomerApi" in c_txt or "CustomerApi" in c_txt:
                                    injected_c.unlink()
                                    if injected_c.parent.exists() and not any(injected_c.parent.iterdir()):
                                        injected_c.parent.rmdir()
                            except Exception:
                                pass
                        injected_r = clean_path / "reports" / "SQLI-001_report.json"
                        if injected_r.exists():
                            try:
                                injected_r.unlink()
                            except Exception:
                                pass

                ACTIVE_GIT_AGENT = GitSubAgent(config)
                AgentRegistry.register("git", ACTIVE_GIT_AGENT)
                # Reset previous scan & remediation results for the new repository session
                SCANNER_AGENT.last_result = None
                SCANNER_AGENT.status = "IDLE"
                REMEDIATOR_AGENT.last_result = None
                REMEDIATOR_AGENT.status = "IDLE"
                REMEDIATOR_AGENT.accumulated_threats.clear()
                REMEDIATOR_AGENT.accumulated_modified_files.clear()
                REMEDIATOR_AGENT.accumulated_bug_fixes.clear()
                LATEST_PR = None
                if SCANNER_AGENT.findings_dir.exists():
                    for old_f in SCANNER_AGENT.findings_dir.glob("*.json"):
                        try:
                            old_f.unlink()
                        except Exception:
                            pass
                if REMEDIATOR_AGENT.reports_dir.exists():
                    for old_r in REMEDIATOR_AGENT.reports_dir.glob("*_report.json"):
                        try:
                            old_r.unlink()
                        except Exception:
                            pass
                try:
                    ctx = ACTIVE_GIT_AGENT.prepare_workspace(auto_init=auto_init)
                except Exception as clone_exc:
                    logger.error("Failed to prepare repository (%s): %s", config.sanitized_repo_url, clone_exc)
                    ACTIVE_GIT_AGENT = None
                    self._send_json({"error": f"Failed to prepare repository: {clone_exc}"}, status=400)
                    return

                # Build the code and run unit tests if any (can be skipped for staged UI execution)
                skip_build_test = bool(payload.get("skip_build_test", False))
                build_test_res = {}
                if skip_build_test:
                    build_test_res = {
                        "executed": False,
                        "status": "pending",
                        "ecosystem": "pending",
                        "ecosystem_name": "Pending Execution",
                        "build": {"status": "pending", "summary": "Build pending"},
                        "tests": {"status": "pending", "tests_found": False, "summary": "Tests pending"},
                        "summary": "Build and unit test verification suite queued",
                    }
                else:
                    try:
                        build_test_res = ACTIVE_GIT_AGENT.build_and_test()
                    except Exception as bt_exc:
                        logger.warning("Build/test runner failed: %s", bt_exc)
                        build_test_res = {
                            "executed": False,
                            "error": str(bt_exc),
                            "ecosystem": "unknown",
                            "ecosystem_name": "Unknown",
                            "build": {"status": "skipped", "summary": f"Build runner error: {bt_exc}"},
                            "tests": {"status": "skipped", "tests_found": False, "summary": "Tests not run"},
                            "summary": f"Build runner error: {bt_exc}",
                        }

                remote_url = ACTIVE_GIT_AGENT.get_sanitized_remote_url()
                self._send_json({
                    "message": "Repository prepared successfully",
                    "context": ctx.to_dict(),
                    "remote_url": remote_url,
                    "has_remote": bool(remote_url),
                    "status": ACTIVE_GIT_AGENT.get_status(),
                    "build_and_test": build_test_res,
                })
                return

            # 2. Scan Code (ScannerAgent)
            elif path == "/api/scan":
                prepared_ws = _resolve_active_workspace()
                explicit_ws = (payload.get("workspace_path") or payload.get("repo_url") or "").strip()
                ws_path = None

                if explicit_ws:
                    candidate_p = _normalize_local_repo_path(explicit_ws)
                    if candidate_p.exists() and candidate_p != APP_ROOT_DIR:
                        ws_path = candidate_p

                # If no valid explicit directory was found or it was a remote URL, prioritize Step 01 prepared workspace
                if not ws_path:
                    ws_path = prepared_ws
                elif prepared_ws and ws_path == DEFAULT_LOCAL_REPO and prepared_ws != DEFAULT_LOCAL_REPO:
                    # Do not let fallback CustomerApi default override user's active workspace
                    ws_path = prepared_ws

                if not ws_path:
                    self._send_json({"error": "Repository not prepared yet. Complete Step 01 to initialize workspace."}, status=400)
                    return

                # If active git agent does not match the workspace being scanned, align it
                if ws_path and (not ACTIVE_GIT_AGENT or not ACTIVE_GIT_AGENT.context or ACTIVE_GIT_AGENT.get_workspace_path().resolve() != ws_path.resolve()):
                    if (ws_path / ".git").exists():
                        cfg = GitAgentConfig(
                            repo_url=str(ws_path),
                            provider=ProviderType.LOCAL,
                            base_branch="master",
                            feature_branch_name="remediation/airgap-api-compliance",
                        )
                        ACTIVE_GIT_AGENT = GitSubAgent(cfg)
                        AgentRegistry.register("git", ACTIVE_GIT_AGENT)
                        try:
                            ACTIVE_GIT_AGENT.prepare_workspace()
                        except Exception as prep_e:
                            logger.debug("Auto-sync workspace for %s: %s", ws_path, prep_e)

                REMEDIATOR_AGENT.last_result = None
                REMEDIATOR_AGENT.status = "IDLE"
                engine = payload.get("scanner_engine") or payload.get("engine") or "all"
                result = SCANNER_AGENT.run({"workspace_path": str(ws_path), "scanner_engine": engine})
                result["mode"] = "live" if ACTIVE_GIT_AGENT else "preview"
                self._send_json(result)
                return

            # 3. Fix Code (RemediatorAgent + BugFixerAgent on scanner_agent/findings/*.json)
            # Iterative remediation loop: runs until all threats are resolved or up to 5 times
            elif path == "/api/fix":
                prepared_ws = _resolve_active_workspace()
                explicit_ws = (payload.get("workspace_path") or payload.get("repo_url") or "").strip()
                ws_path = None

                if explicit_ws:
                    candidate_p = _normalize_local_repo_path(explicit_ws)
                    if candidate_p.exists() and candidate_p != APP_ROOT_DIR:
                        ws_path = candidate_p

                if not ws_path:
                    ws_path = prepared_ws
                elif prepared_ws and ws_path == DEFAULT_LOCAL_REPO and prepared_ws != DEFAULT_LOCAL_REPO:
                    ws_path = prepared_ws

                if not ws_path:
                    self._send_json({"error": "Repository not prepared yet. Complete Step 01 to initialize workspace."}, status=400)
                    return

                max_iterations = int(payload.get("max_iterations") or 5)
                max_iterations = max(1, min(max_iterations, 5))
                iteration = 0
                result = {}
                post_scan = {}

                while iteration < max_iterations:
                    iteration += 1
                    logger.info("[Iterative Remediation] Starting iteration %d of %d for workspace: %s", iteration, max_iterations, ws_path)
                    REMEDIATOR_AGENT.current_progress["iteration"] = iteration
                    REMEDIATOR_AGENT.current_progress["max_iterations"] = max_iterations
                    REMEDIATOR_AGENT.current_progress["status"] = "RUNNING"
                    REMEDIATOR_AGENT.current_progress["phase"] = f"Iteration {iteration}/{max_iterations}"
                    REMEDIATOR_AGENT.current_progress["message"] = f"Iteration {iteration}/{max_iterations}: Applying security patches..."

                    result = REMEDIATOR_AGENT.run({
                        "workspace_path": str(ws_path),
                        "provider": payload.get("provider"),
                        "model": payload.get("model"),
                        "base_url": payload.get("base_url"),
                    })
                    result["mode"] = "live" if ACTIVE_GIT_AGENT else "preview"

                    # Update real-time progress for the post-remediation verification scan
                    for itm in REMEDIATOR_AGENT.current_progress.get("items", []):
                        if itm.get("id") == "POST-SCAN-VERIFY":
                            itm["status"] = "fixing"
                            itm["action"] = f"Executing verification scan (Iteration {iteration}/{max_iterations})..."
                            break
                    REMEDIATOR_AGENT.current_progress["current_file"] = "AST Security Post-Scan"
                    REMEDIATOR_AGENT.current_progress["phase"] = f"Verification Scan {iteration}/{max_iterations}"
                    REMEDIATOR_AGENT.current_progress["message"] = f"Iteration {iteration}/{max_iterations}: Running verification scan to verify threats..."
                    REMEDIATOR_AGENT.current_progress["percent"] = 90

                    # Re-run scanner on the patched workspace using the active scanner engine to reflect real post-remediation findings & posture
                    scan_engine = payload.get("scanner_engine") or getattr(SCANNER_AGENT, "last_engine", "all")
                    post_scan = SCANNER_AGENT.run({"workspace_path": str(ws_path), "scanner_engine": scan_engine, "is_post_scan": True})
                    result["post_scan"] = post_scan
                    REMEDIATOR_AGENT.last_post_scan = post_scan
                    REMEDIATOR_AGENT.last_workspace_path = str(ws_path)

                    residual_findings = post_scan.get("findings") if post_scan.get("findings") is not None else (post_scan.get("bug_findings") or [])
                    residual_count = len(residual_findings)
                    logger.info("[Iterative Remediation] Iteration %d/%d completed. Residual threats detected: %d", iteration, max_iterations, residual_count)

                    if residual_count == 0:
                        logger.info("[Iterative Remediation] All threats resolved successfully in iteration %d!", iteration)
                        break
                    elif iteration < max_iterations:
                        logger.info("[Iterative Remediation] Re-ingesting %d residual threats for iteration %d/%d", residual_count, iteration + 1, max_iterations)
                        # Save only active residual findings to findings_dir for the next iteration pass
                        SCANNER_AGENT.findings_dir.mkdir(parents=True, exist_ok=True)
                        for existing_f in list(SCANNER_AGENT.findings_dir.glob("*.json")):
                            try:
                                existing_f.unlink()
                            except OSError:
                                pass
                        for rf in residual_findings:
                            rf_id = (rf.get("finding_id") or rf.get("id") or "FINDING").lower().replace("_", "-")
                            f_file = SCANNER_AGENT.findings_dir / f"{rf_id}.json"
                            try:
                                f_file.write_text(json.dumps(rf, indent=2), encoding="utf-8")
                            except Exception:
                                pass

                # Finalize real-time progress
                resolved_all = (len(post_scan.get("findings") if post_scan.get("findings") is not None else (post_scan.get("bug_findings") or [])) == 0)
                for itm in REMEDIATOR_AGENT.current_progress.get("items", []):
                    if itm.get("id") == "POST-SCAN-VERIFY":
                        itm["status"] = "remediated"
                        itm["action"] = f"Verified: {len(post_scan.get('findings') or [])} residual threats detected"
                        break
                REMEDIATOR_AGENT.current_progress["completed_targets"] = len(REMEDIATOR_AGENT.current_progress.get("items", []))
                REMEDIATOR_AGENT.current_progress["percent"] = 100
                REMEDIATOR_AGENT.current_progress["status"] = "COMPLETED"
                REMEDIATOR_AGENT.current_progress["phase"] = "Completed"
                REMEDIATOR_AGENT.current_progress["iteration"] = iteration
                REMEDIATOR_AGENT.current_progress["max_iterations"] = max_iterations
                REMEDIATOR_AGENT.current_progress["resolved_all"] = resolved_all
                REMEDIATOR_AGENT.current_progress["message"] = (
                    f"All threats resolved in {iteration} iteration(s) (100/100 Grade A+)."
                    if resolved_all else
                    f"Completed {iteration} iterations. Remaining threats: {len(post_scan.get('findings') or [])}."
                )
                REMEDIATOR_AGENT.current_progress["current_file"] = None

                result["iterations_run"] = iteration
                result["max_iterations"] = max_iterations
                result["resolved_all"] = resolved_all

                # Refresh the saved HTML audit report with post_scan posture
                try:
                    html_rep = REMEDIATOR_AGENT.render_html_report(workspace_path=str(ws_path))
                    REMEDIATOR_AGENT.reports_dir.mkdir(parents=True, exist_ok=True)
                    (REMEDIATOR_AGENT.reports_dir / "REMEDIATION_AUDIT_REPORT.html").write_text(html_rep, encoding="utf-8")
                except Exception:
                    pass

                if ACTIVE_GIT_AGENT:
                    result["status_summary"] = ACTIVE_GIT_AGENT.get_status()
                    result["diff"] = ACTIVE_GIT_AGENT.get_diff() or result.get("bug_diff", "")
                else:
                    result["diff"] = result.get("bug_diff", "")

                # Automatically send remediation report email if enabled or requested
                try:
                    if payload.get("recipient_emails") is not None:
                        EMAIL_NOTIFIER.update_config({"recipient_emails": payload.get("recipient_emails")})
                    if "auto_send_email" in payload:
                        EMAIL_NOTIFIER.update_config({"auto_send_after_remediation": payload.get("auto_send_email")})
                    email_cfg = EMAIL_NOTIFIER.get_public_config()
                    should_send = bool(
                        payload.get("send_email")
                        or (email_cfg.get("enabled", True) and email_cfg.get("auto_send_after_remediation", True))
                    )
                    if should_send:
                        result["email_notification"] = _dispatch_current_remediation_email(
                            ws_path=ws_path,
                            remediation_result=result,
                            post_scan_result=post_scan,
                            override_recipients=payload.get("recipient_emails"),
                            trigger_source="step3_remediation_completed",
                        )
                except Exception as email_exc:
                    logger.warning("Auto-email report after remediation failed: %s", email_exc)
                    result["email_notification"] = {"status": "error", "message": str(email_exc)}

                self._send_json(result)
                return

            # 3B. RemediatorAgent (BugFixerAgent) - Fix SAST/Bug Finding
            elif path == "/api/bug-fixer/fix":
                ws_path = _resolve_active_workspace()
                if not ws_path:
                    self._send_json({"error": "Repository not prepared yet. Complete Step 01 to initialize workspace."}, status=400)
                    return
                finding_data = payload.get("finding") or dict(DEFAULT_SQLI_FINDING)
                preview = bool(payload.get("preview", False))
                provider = payload.get("provider") or None
                model = payload.get("model") or None

                result = REMEDIATOR_AGENT.fix_finding(
                    finding_payload=finding_data,
                    workspace_path=ws_path,
                    preview=preview,
                    provider=provider,
                    model=model,
                )
                result["mode"] = "live" if ACTIVE_GIT_AGENT else "standalone"
                if ACTIVE_GIT_AGENT:
                    result["status_summary"] = ACTIVE_GIT_AGENT.get_status()
                    result["git_diff"] = ACTIVE_GIT_AGENT.get_diff()
                self._send_json(result)
                return

            # 3C. Reset Demo Vulnerable Repository & All Steps State
            elif path in ("/api/bug-fixer/reset", "/api/reset-all"):
                ws_path = _resolve_active_workspace() or DEFAULT_LOCAL_REPO
                if ws_path.name == "CustomerApi" or ws_path.resolve() == DEFAULT_LOCAL_REPO:
                    result = REMEDIATOR_AGENT.reset_demo(workspace_path=ws_path)
                    _ensure_default_local_repo_ready(reset_files=True)
                else:
                    result = REMEDIATOR_AGENT.reset_demo(workspace_path=None)
                SCANNER_AGENT.last_result = None
                SCANNER_AGENT.last_bundle = None
                SCANNER_AGENT.status = "IDLE"
                REMEDIATOR_AGENT.last_result = None
                REMEDIATOR_AGENT.status = "IDLE"
                REMEDIATOR_AGENT.accumulated_threats.clear()
                REMEDIATOR_AGENT.accumulated_modified_files.clear()
                REMEDIATOR_AGENT.accumulated_bug_fixes.clear()
                LATEST_PR = None
                if SCANNER_AGENT.findings_dir.exists():
                    for old_f in SCANNER_AGENT.findings_dir.glob("*.json"):
                        try:
                            old_f.unlink()
                        except Exception:
                            pass
                if REMEDIATOR_AGENT.reports_dir.exists():
                    for old_r in REMEDIATOR_AGENT.reports_dir.glob("*_report.json"):
                        try:
                            old_r.unlink()
                        except Exception:
                            pass
                if REMEDIATOR_AGENT.reports_dir.exists():
                    for old_r in REMEDIATOR_AGENT.reports_dir.glob("*_report.json"):
                        try:
                            old_r.unlink()
                        except Exception:
                            pass
                if ACTIVE_GIT_AGENT:
                    try:
                        ACTIVE_GIT_AGENT.cleanup()
                    except Exception:
                        pass
                ACTIVE_GIT_AGENT = None
                AgentRegistry.register(
                    "git",
                    GitSubAgent(GitAgentConfig(repo_url="", provider=ProviderType.GENERIC)),
                )
                result = {
                    "status": "success",
                    "message": "Reset all pipeline steps, workspace references, and findings cache",
                    "workspace_path": "",
                    "repo_name": "",
                    "status_summary": {
                        "branch": "none",
                        "clean": True,
                        "modified_files": [],
                        "untracked_files": [],
                    },
                    "git_diff": "",
                }
                result["telemetry"] = _build_telemetry_payload()
                self._send_json(result)
                return

            # 4A. Read real file from active workspace or default repo
            elif path == "/api/read-file":
                rel_path = (payload.get("relative_path") or "").strip()
                if not rel_path:
                    self._send_json({"error": "relative_path is required"}, status=400)
                    return

                ws_dir = _resolve_active_workspace()
                if not ws_dir and SCANNER_AGENT.last_result and SCANNER_AGENT.last_result.get("workspace_scanned"):
                    cand = _normalize_local_repo_path(SCANNER_AGENT.last_result["workspace_scanned"])
                    if cand.exists() and cand != APP_ROOT_DIR:
                        ws_dir = cand

                if not ws_dir:
                    self._send_json({"error": "No repository prepared yet. Complete Step 01 to initialize workspace."}, status=400)
                    return

                clean_rel = rel_path.lstrip("/\\")
                if ws_dir and clean_rel.startswith(ws_dir.name + "/"):
                    clean_rel = clean_rel[len(ws_dir.name) + 1:]
                target_file = (ws_dir / clean_rel).resolve()
                if not str(target_file).startswith(str(ws_dir.resolve())):
                    self._send_json({"error": "Forbidden path outside workspace"}, status=403)
                    return

                if not target_file.exists() or not target_file.is_file():
                    self._send_json({
                        "relative_path": rel_path,
                        "exists": False,
                        "full_path": str(target_file),
                        "content": "",
                        "message": f"File '{rel_path}' has not been generated in workspace '{ws_dir.name}' yet.",
                    })
                    return

                content = target_file.read_text(encoding="utf-8", errors="replace")
                self._send_json({
                    "relative_path": rel_path,
                    "exists": True,
                    "full_path": str(target_file),
                    "size_bytes": target_file.stat().st_size,
                    "content": content,
                })
                return

            # 4. Save custom patch / write file
            elif path == "/api/write-file":
                ws_dir = _resolve_active_workspace()
                if not ws_dir:
                    self._send_json({"error": "No repository prepared yet. Complete Step 01 to initialize workspace."}, status=400)
                    return
                rel_path = payload.get("relative_path")
                content = payload.get("content", "")
                if not rel_path:
                    self._send_json({"error": "relative_path is required"}, status=400)
                    return

                target_file = (ws_dir / rel_path).resolve()
                if not str(target_file).startswith(str(ws_dir.resolve())):
                    self._send_json({"error": "Forbidden path outside workspace"}, status=403)
                    return

                target_file.parent.mkdir(parents=True, exist_ok=True)
                target_file.write_text(content, encoding="utf-8")
                self._send_json({
                    "message": f"Saved {rel_path}",
                    "status": ACTIVE_GIT_AGENT.get_status() if ACTIVE_GIT_AGENT else None,
                    "diff": ACTIVE_GIT_AGENT.get_diff() if ACTIVE_GIT_AGENT else "",
                })
                return

            # 5. Commit & Push (GitSubAgent)
            elif path == "/api/commit-push":
                if not ACTIVE_GIT_AGENT:
                    self._send_json({"error": "Please call /api/prepare first"}, status=400)
                    return

                commit_msg = payload.get("commit_message")
                repo_name = ACTIVE_GIT_AGENT.context.repo_name if (ACTIVE_GIT_AGENT and ACTIVE_GIT_AGENT.context) else "repository"
                cur_threats = list(REMEDIATOR_AGENT.accumulated_threats.values())
                cur_files = list(REMEDIATOR_AGENT.accumulated_modified_files)

                # Ensure commit_msg contains detailed threat and remediation information irrespective of run count
                if cur_threats:
                    full_template = REMEDIATOR_AGENT.generate_commit_message(
                        repo_name=repo_name,
                        threats=cur_threats,
                        modified_files=cur_files,
                    )
                    if not commit_msg or not commit_msg.strip():
                        commit_msg = full_template
                    elif "\n" not in commit_msg.strip() or "Remediated Security Threats" not in commit_msg:
                        # Append detailed threat breakdown to user-provided subject
                        lines = full_template.split("\n\n", 1)
                        body_part = lines[1] if len(lines) > 1 else ""
                        commit_msg = f"{commit_msg.strip()}\n\n{body_part}"
                elif not commit_msg:
                    commit_msg = "fix(airgap): remediate external API endpoints"

                files = payload.get("files")
                cur_br = ACTIVE_GIT_AGENT.workspace.current_feature_branch or ACTIVE_GIT_AGENT.workspace.get_current_branch()
                req_token = payload.get("token") or payload.get("git_token")
                req_username = payload.get("username") if "username" in payload else payload.get("git_username")
                force_push = bool(payload.get("force", False))

                commit_hash: Optional[str] = None
                had_changes = ACTIVE_GIT_AGENT.workspace.has_changes()
                if had_changes:
                    ACTIVE_GIT_AGENT.workspace.add(files)
                    commit_hash = ACTIVE_GIT_AGENT.workspace.commit(commit_msg)

                try:
                    push_res = ACTIVE_GIT_AGENT.push_branch(
                        branch=cur_br,
                        force=force_push,
                        token=req_token,
                        username=req_username,
                    )
                except Exception as push_exc:
                    err_prefix = f"Committed {commit_hash[:7]}, but push to remote failed" if commit_hash else "Push to remote failed"
                    self._send_json({
                        "error": f"{err_prefix}: {push_exc}",
                        "commit_hash": commit_hash,
                        "branch": cur_br,
                    }, status=400)
                    return

                remote_label = push_res.get("remote_url") or "origin"
                if had_changes:
                    msg_text = (
                        f"Committed {commit_hash[:7]} and pushed branch '{cur_br}' to {remote_label}"
                        if push_res.get("pushed")
                        else f"Committed {commit_hash[:7]} and updated local branch '{cur_br}'"
                    )
                    self._send_json({
                        "message": msg_text,
                        "commit_hash": commit_hash,
                        "branch": cur_br,
                        "pushed": push_res.get("pushed", False),
                        "push_status": push_res.get("status"),
                        "remote_url": push_res.get("remote_url"),
                    })
                else:
                    msg_text = (
                        f"Working tree clean. Pushed branch '{cur_br}' to {remote_label}."
                        if push_res.get("pushed")
                        else f"Working tree clean. Updated local branch '{cur_br}'."
                    )
                    self._send_json({
                        "message": msg_text,
                        "branch": cur_br,
                        "pushed": push_res.get("pushed", False),
                        "push_status": push_res.get("status"),
                        "remote_url": push_res.get("remote_url"),
                    })
                return

            # 6. Raise Pull Request (GitSubAgent)
            elif path == "/api/create-pr":
                if not ACTIVE_GIT_AGENT:
                    self._send_json({"error": "Please call /api/prepare first"}, status=400)
                    return

                repo_name = ACTIVE_GIT_AGENT.context.repo_name if (ACTIVE_GIT_AGENT and ACTIVE_GIT_AGENT.context) else "repository"
                cur_threats = list(REMEDIATOR_AGENT.accumulated_threats.values())
                cur_files = list(REMEDIATOR_AGENT.accumulated_modified_files)

                title = payload.get("title")
                if not title:
                    title = REMEDIATOR_AGENT.generate_pr_title(repo_name=repo_name, threat_count=len(cur_threats))

                desc = payload.get("description")
                if not desc or desc.strip() in ("", "Automated Pull Request from Multi-Agent System"):
                    desc = REMEDIATOR_AGENT.generate_pr_body(
                        repo_name=repo_name,
                        threats=cur_threats,
                        modified_files=cur_files,
                        branch=ACTIVE_GIT_AGENT.workspace.current_feature_branch or "remediation/airgap-api-compliance",
                        base_branch=ACTIVE_GIT_AGENT.workspace.base_branch or "main",
                    )
                elif cur_threats and "Remediated Vulnerabilities" not in desc:
                    body_ext = REMEDIATOR_AGENT.generate_pr_body(
                        repo_name=repo_name,
                        threats=cur_threats,
                        modified_files=cur_files,
                        branch=ACTIVE_GIT_AGENT.workspace.current_feature_branch or "remediation/airgap-api-compliance",
                        base_branch=ACTIVE_GIT_AGENT.workspace.base_branch or "main",
                    )
                    desc = f"{desc.strip()}\n\n{body_ext}"

                draft = bool(payload.get("draft", False))
                req_token = payload.get("token") or payload.get("git_token")
                req_username = payload.get("username") if "username" in payload else payload.get("git_username")
                if req_token:
                    ACTIVE_GIT_AGENT.config.token = req_token
                    ACTIVE_GIT_AGENT.workspace.token_to_scrub = req_token
                if req_username is not None:
                    ACTIVE_GIT_AGENT.config.username = req_username

                use_remote_pr = (
                    not ACTIVE_GIT_AGENT.config.is_local
                    or bool(ACTIVE_GIT_AGENT.last_push_result and ACTIVE_GIT_AGENT.last_push_result.get("pushed"))
                )
                pr_provider = ACTIVE_GIT_AGENT.resolve_pr_provider() if use_remote_pr else ACTIVE_GIT_AGENT.provider
                if not pr_provider:
                    self._send_json({"error": "No git provider configured (GitHub/GitLab/Local)"}, status=400)
                    return

                pr = pr_provider.create_pull_request(
                    head_branch=ACTIVE_GIT_AGENT.workspace.current_feature_branch,
                    base_branch=ACTIVE_GIT_AGENT.workspace.base_branch or "main",
                    title=title,
                    description=desc,
                    draft=draft,
                )
                pr_label = "Pull Request" if pr.provider != "local" else "Local Pull Request"
                file_path = ""
                md_content = ""
                if pr.provider == "local" and pr.raw_response and "md_file" in pr.raw_response:
                    file_path = pr.raw_response["md_file"]
                    try:
                        md_content = Path(file_path).read_text(encoding="utf-8")
                    except Exception:
                        pass

                pr_data = {
                    "message": f"{pr_label} created successfully",
                    "pr_number": pr.number,
                    "pr_url": pr.url,
                    "pr_file_path": file_path,
                    "pr_content": md_content,
                    "title": pr.title,
                    "provider": pr.provider,
                }
                LATEST_PR = pr_data
                try:
                    email_cfg = EMAIL_NOTIFIER.get_public_config()
                    if payload.get("send_email") or (email_cfg.get("enabled", True) and email_cfg.get("auto_send_after_pr", False)):
                        pr_data["email_notification"] = _dispatch_current_remediation_email(
                            override_recipients=payload.get("recipient_emails"),
                            trigger_source="step5_pr_created",
                        )
                except Exception as pr_email_exc:
                    logger.warning("Auto-email report after PR creation failed: %s", pr_email_exc)
                self._send_json(pr_data)
                return

            # 6B. Email Configuration & Manual Report Dispatch
            elif path == "/api/email/config":
                updated_cfg = EMAIL_NOTIFIER.update_config(payload)
                self._send_json({
                    "message": "Email report configuration saved",
                    "config": updated_cfg,
                })
                return

            elif path == "/api/email/send-report":
                if any(k in payload for k in ("webhook_url", "smtp_host", "smtp_port", "smtp_username", "smtp_password", "sender_email", "recipient_emails", "use_tls", "use_ssl", "auto_send_after_remediation", "auto_send_after_pr", "attach_remediation_pdf", "attach_scan_pdf", "attach_remediation_html", "attach_scan_html", "attach_remediation_json")):
                    EMAIL_NOTIFIER.update_config(payload)
                email_res = _dispatch_current_remediation_email(
                    override_recipients=payload.get("recipient_emails"),
                    custom_subject=payload.get("subject"),
                    custom_note=payload.get("custom_note"),
                    trigger_source=payload.get("trigger_source") or "manual_ui_dispatch",
                )
                self._send_json(email_res)
                return

            # 7. End-to-end Pipeline Execution
            elif path == "/api/pipeline/run":
                if not ACTIVE_GIT_AGENT:
                    self._send_json({"error": "Please configure repository with /api/prepare first"}, status=400)
                    return

                pipeline = MultiAgentPipeline(
                    git_config=ACTIVE_GIT_AGENT.config,
                    scanner=SCANNER_AGENT,
                    remediator=REMEDIATOR_AGENT,
                )
                res = pipeline.run_remediation_pipeline()
                self._send_json(res)
                return

            # 7b. Run Workspace Build and Unit Tests
            elif path == "/api/build-test":
                if not ACTIVE_GIT_AGENT:
                    self._send_json({"error": "Please call /api/prepare first"}, status=400)
                    return
                try:
                    build_test_res = ACTIVE_GIT_AGENT.build_and_test()
                except Exception as bt_exc:
                    logger.warning("Build/test runner failed: %s", bt_exc)
                    build_test_res = {
                        "executed": False,
                        "error": str(bt_exc),
                        "ecosystem": "unknown",
                        "ecosystem_name": "Unknown",
                        "build": {"status": "skipped", "summary": f"Build runner error: {bt_exc}"},
                        "tests": {"status": "skipped", "tests_found": False, "summary": "Tests not run"},
                        "summary": f"Build runner error: {bt_exc}",
                    }
                self._send_json(build_test_res)
                return

            # 8. Validate Local Repository Path (Check if directory has .git)
            elif path == "/api/validate-path":
                raw_path = payload.get("path", "").strip()
                if not raw_path:
                    self._send_json({"valid": False, "error": "Path cannot be empty"}, status=400)
                    return

                clean = raw_path.replace("file://", "")
                target_path = _normalize_local_repo_path(clean)

                if not target_path.exists():
                    self._send_json({
                        "valid": False,
                        "exists": False,
                        "has_git": False,
                        "path": str(target_path),
                        "error": f"Path does not exist: {target_path}",
                    }, status=400)
                    return

                if not target_path.is_dir():
                    self._send_json({
                        "valid": False,
                        "exists": True,
                        "is_dir": False,
                        "has_git": False,
                        "path": str(target_path),
                        "error": f"Path is not a directory: {target_path}",
                    }, status=400)
                    return

                has_git = (target_path / ".git").exists() or (target_path / "HEAD").exists()
                if not has_git:
                    code = subprocess.run(
                        ["git", "rev-parse", "--is-inside-work-tree"],
                        cwd=str(target_path),
                        capture_output=True,
                    ).returncode
                    has_git = (code == 0)

                auto_init = bool(payload.get("auto_init", False))
                allow_non_git = bool(payload.get("allow_non_git", False))

                if not has_git:
                    if auto_init and target_path.is_dir():
                        _init_local_git_repo(target_path)
                        has_git = True
                    elif allow_non_git and target_path.is_dir():
                        self._send_json({
                            "valid": True,
                            "exists": True,
                            "is_dir": True,
                            "has_git": False,
                            "can_auto_init": True,
                            "path": str(target_path),
                            "message": f"Local project directory detected at {target_path} (Git can be auto-initialized).",
                        })
                        return
                    else:
                        self._send_json({
                            "valid": False,
                            "exists": True,
                            "is_dir": True,
                            "has_git": False,
                            "can_auto_init": True,
                            "path": str(target_path),
                            "error": f"Selected path '{target_path}' is not a Git repository (missing '.git' directory).",
                        }, status=400)
                        return

                self._send_json({
                    "valid": True,
                    "exists": True,
                    "is_dir": True,
                    "has_git": True,
                    "can_auto_init": False,
                    "path": str(target_path),
                    "message": f"Valid Git repository detected at {target_path}",
                })
                return

            # 9. List Folders for Interactive Directory Browser
            elif path == "/api/fs/list":
                raw_path = payload.get("path", "").strip()
                if raw_path:
                    clean = raw_path.replace("file://", "")
                    current_dir = Path(os.path.expanduser(clean)).resolve()
                else:
                    current_dir = (APP_ROOT_DIR / "repos").resolve() if (APP_ROOT_DIR / "repos").exists() else Path.cwd().resolve()

                if not current_dir.exists() or not current_dir.is_dir():
                    current_dir = Path.home().resolve()

                folders = []
                try:
                    for entry in sorted(current_dir.iterdir(), key=lambda p: p.name.lower()):
                        if entry.is_dir() and not entry.name.startswith("."):
                            has_git = (entry / ".git").exists() or (entry / "HEAD").exists()
                            folders.append({
                                "name": entry.name,
                                "path": str(entry.resolve()),
                                "has_git": has_git,
                            })
                except Exception as e:
                    logger.warning("Could not list directories in %s: %s", current_dir, e)

                parent_dir = str(current_dir.parent.resolve()) if current_dir != current_dir.parent else None
                current_has_git = (current_dir / ".git").exists() or (current_dir / "HEAD").exists()

                home = Path.home().resolve()
                quick_access = [
                    {"label": "🏠 Home", "path": str(home)},
                ]
                for rel in ["Projects", "Documents", "Desktop", "Downloads"]:
                    candidate = home / rel
                    if candidate.exists() and candidate.is_dir():
                        quick_access.append({"label": rel, "path": str(candidate.resolve())})

                self._send_json({
                    "current_path": str(current_dir),
                    "current_has_git": current_has_git,
                    "parent_path": parent_dir,
                    "folders": folders,
                    "quick_access": quick_access,
                })
                return

            # 10. Batch Scheduler Endpoints (Discover, Schedules CRUD, Background Execution)
            elif path == "/api/scheduler/discover":
                raw_folder = (payload.get("folder_path") or "").strip()
                if not raw_folder:
                    self._send_json({"error": "folder_path is required"}, status=400)
                    return
                target_folder = _normalize_local_repo_path(raw_folder)
                try:
                    result = discover_repositories(
                        folder_path=target_folder,
                        include_non_git=bool(payload.get("include_non_git", False)),
                        recursive=bool(payload.get("recursive", False)),
                        app_root_dir=APP_ROOT_DIR,
                    )
                    self._send_json(result)
                except (ValueError, FileNotFoundError, NotADirectoryError) as exc:
                    self._send_json({"error": str(exc)}, status=400)
                return

            elif path == "/api/scheduler/schedules":
                sched_payload = dict(payload)
                if sched_payload.get("folder_path"):
                    sched_payload["folder_path"] = str(_normalize_local_repo_path(sched_payload["folder_path"]))
                try:
                    created = BATCH_SCHEDULER.create_schedule(sched_payload)
                    self._send_json(created, status=201)
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=400)
                return

            elif path == "/api/scheduler/schedules/update":
                schedule_id = (payload.get("id") or payload.get("schedule_id") or "").strip()
                if not schedule_id:
                    self._send_json({"error": "id is required"}, status=400)
                    return
                sched_payload = dict(payload)
                if sched_payload.get("folder_path"):
                    sched_payload["folder_path"] = str(_normalize_local_repo_path(sched_payload["folder_path"]))
                try:
                    updated = BATCH_SCHEDULER.update_schedule(schedule_id, sched_payload)
                    self._send_json({"schedule": updated})
                except KeyError as exc:
                    self._send_json({"error": str(exc)}, status=404)
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=400)
                return

            elif path == "/api/scheduler/schedules/toggle":
                schedule_id = (payload.get("id") or payload.get("schedule_id") or "").strip()
                if not schedule_id:
                    self._send_json({"error": "id is required"}, status=400)
                    return
                try:
                    enabled_val = payload["enabled"] if "enabled" in payload else None
                    updated = BATCH_SCHEDULER.toggle_schedule(schedule_id, enabled=enabled_val)
                    self._send_json({"schedule": updated})
                except KeyError as exc:
                    self._send_json({"error": str(exc)}, status=404)
                return

            elif path == "/api/scheduler/schedules/delete":
                schedule_id = (payload.get("id") or payload.get("schedule_id") or "").strip()
                if not schedule_id:
                    self._send_json({"error": "id is required"}, status=400)
                    return
                deleted = BATCH_SCHEDULER.delete_schedule(schedule_id)
                if not deleted:
                    self._send_json({"error": f"Schedule '{schedule_id}' not found"}, status=404)
                    return
                self._send_json({"deleted": True, "id": schedule_id})
                return

            elif path == "/api/scheduler/schedules/run-now":
                schedule_id = (payload.get("id") or payload.get("schedule_id") or "").strip()
                if not schedule_id:
                    self._send_json({"error": "id is required"}, status=400)
                    return
                try:
                    run_info = BATCH_SCHEDULER.trigger_schedule_now(schedule_id, trigger_source="manual")
                    self._send_json({"message": "Batch run queued in background", "run": run_info}, status=202)
                except KeyError as exc:
                    self._send_json({"error": str(exc)}, status=404)
                return

            elif path == "/api/scheduler/runs/cancel":
                run_id = (payload.get("run_id") or payload.get("id") or "").strip()
                if not run_id:
                    self._send_json({"error": "run_id is required"}, status=400)
                    return
                try:
                    res = BATCH_SCHEDULER.cancel_run(run_id)
                    self._send_json(res)
                except KeyError as exc:
                    self._send_json({"error": str(exc)}, status=404)
                return

            elif path == "/api/scheduler/runs/clear":
                removed = BATCH_SCHEDULER.clear_finished_runs()
                self._send_json({"cleared": removed})
                return

            self._send_json({"error": f"Unknown endpoint: {path}"}, status=404)

        except Exception as e:
            logger.error("API error on %s: %s", path, e, exc_info=True)
            self._send_json({"error": str(e)}, status=500)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server so requests (e.g. folder browsing, status polling) never block each other."""
    daemon_threads = True
    allow_reuse_address = True


def run_server(port: int = 8080):
    """Start the Common Multi-Agent UI Dashboard HTTP Server."""
    web_dir = get_web_dir()
    os.chdir(str(web_dir.parent))
    BATCH_SCHEDULER.start()
    with ThreadedTCPServer(("", port), MultiAgentAPIHandler) as httpd:
        print(f"\n=======================================================")
        print(f"🤖 Multi-Agent Control Center running at:")
        print(f"👉 Single Repo UI:    http://localhost:{port}")
        print(f"🗓️  Batch Scheduler:   http://localhost:{port}/scheduler")
        print(f"📁 Serving common UI from: {web_dir}")
        print(f"=======================================================\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Multi-Agent UI server.")
        finally:
            BATCH_SCHEDULER.stop()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
