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
import signal
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Dict, Any, Optional, List

from agents.base import AgentRegistry
from agents.git_agent import __version__ as APP_VERSION
from agents.git_agent.config import GitAgentConfig, ProviderType
from agents.git_agent.agent import GitSubAgent
from agents.scanner_agent.agent import ScannerAgent
from agents.remediator_agent.agent import RemediatorAgent
from agents.remediator_agent.llm_client import discover_local_llm_models
from orchestrator.scheduler import BatchScheduler
from orchestrator.email_notifier import EmailReportNotifier
from orchestrator.routes import (
    handle_get_git_routes,
    handle_post_git_routes,
    handle_get_scan_fix_routes,
    handle_post_scan_fix_routes,
    handle_get_scheduler_routes,
    handle_post_scheduler_routes,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("multi_agent.web_server")

SERVER_START_TIME: float = time.monotonic()
_STATE_LOCK = threading.RLock()

# Active agent instances for the web session (lazily initialized to avoid import-time disk I/O)
ACTIVE_GIT_AGENT: Optional[GitSubAgent] = None
SCANNER_AGENT: Optional[ScannerAgent] = None
REMEDIATOR_AGENT: Optional[RemediatorAgent] = None
LATEST_PR: Optional[Dict[str, Any]] = None

APP_ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_LOCAL_REPO = (APP_ROOT_DIR / "repos" / "CustomerApi").resolve()
EMAIL_NOTIFIER: Optional[EmailReportNotifier] = None
BATCH_SCHEDULER: Optional[BatchScheduler] = None


def get_scanner_agent() -> ScannerAgent:
    """Return the singleton ScannerAgent, initializing and registering it lazily."""
    global SCANNER_AGENT
    with _STATE_LOCK:
        if SCANNER_AGENT is None:
            SCANNER_AGENT = ScannerAgent()
            AgentRegistry.register("scanner", SCANNER_AGENT)
        return SCANNER_AGENT


def get_remediator_agent() -> RemediatorAgent:
    """Return the singleton RemediatorAgent, initializing and registering it lazily."""
    global REMEDIATOR_AGENT
    with _STATE_LOCK:
        if REMEDIATOR_AGENT is None:
            REMEDIATOR_AGENT = RemediatorAgent()
            AgentRegistry.register("remediator", REMEDIATOR_AGENT)
        return REMEDIATOR_AGENT


def get_email_notifier() -> EmailReportNotifier:
    """Return the singleton EmailReportNotifier, initializing it lazily."""
    global EMAIL_NOTIFIER
    with _STATE_LOCK:
        if EMAIL_NOTIFIER is None:
            EMAIL_NOTIFIER = EmailReportNotifier(app_root_dir=APP_ROOT_DIR)
        return EMAIL_NOTIFIER


def get_batch_scheduler() -> BatchScheduler:
    """Return the singleton BatchScheduler, initializing it lazily."""
    global BATCH_SCHEDULER
    with _STATE_LOCK:
        if BATCH_SCHEDULER is None:
            BATCH_SCHEDULER = BatchScheduler(
                data_dir=APP_ROOT_DIR / "scheduler_data",
                app_root_dir=APP_ROOT_DIR,
                auto_start=False,
                email_notifier=get_email_notifier(),
            )
        return BATCH_SCHEDULER


def _ensure_agents_registered() -> None:
    """Ensure default git, scanner, and remediator agents are registered in AgentRegistry."""
    if AgentRegistry.get("git") is None:
        AgentRegistry.register(
            "git",
            ACTIVE_GIT_AGENT or GitSubAgent(GitAgentConfig(repo_url="", provider=ProviderType.GENERIC)),
        )
    get_scanner_agent()
    get_remediator_agent()


def _reset_pipeline_state(reset_git_agent: bool = False) -> None:
    """Reset scanner/remediator caches, finding files, and optionally the active Git agent."""
    global ACTIVE_GIT_AGENT, LATEST_PR
    scanner = get_scanner_agent()
    remediator = get_remediator_agent()

    scanner.last_result = None
    scanner.last_bundle = None
    scanner.status = "IDLE"
    remediator.last_result = None
    remediator.status = "IDLE"
    remediator.accumulated_threats.clear()
    remediator.accumulated_modified_files.clear()
    remediator.accumulated_bug_fixes.clear()
    LATEST_PR = None

    if scanner.findings_dir.exists():
        for old_f in scanner.findings_dir.glob("*.json"):
            try:
                old_f.unlink()
            except Exception:
                pass
    if remediator.reports_dir.exists():
        for old_r in remediator.reports_dir.glob("*_report.json"):
            try:
                old_r.unlink()
            except Exception:
                pass

    if reset_git_agent:
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


def _ensure_default_local_repo_ready(reset_files: bool = False) -> None:
    """Ensures repos/CustomerApi is a valid Git repository with both master and main branches."""
    try:
        DEFAULT_LOCAL_REPO.mkdir(parents=True, exist_ok=True)
        if reset_files or not (DEFAULT_LOCAL_REPO / "Controllers" / "UsersController.cs").exists():
            get_remediator_agent().reset_demo(workspace_path=DEFAULT_LOCAL_REPO)
        if not (DEFAULT_LOCAL_REPO / ".git").exists():
            subprocess.run(["git", "init", "-b", "master"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
            subprocess.run(["git", "config", "user.name", "Git SubAgent"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
            subprocess.run(["git", "config", "user.email", "git-agent@subagent.local"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
            subprocess.run(["git", "add", "-A"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
            subprocess.run(["git", "commit", "-m", "chore: initial vulnerable CustomerApi repository"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
        elif reset_files:
            subprocess.run(["git", "add", "-A"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
            subprocess.run(["git", "commit", "-m", "chore: reset CustomerApi to pre-remediation baseline"], cwd=str(DEFAULT_LOCAL_REPO), capture_output=True)
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


def _normalize_local_repo_path(raw_path: str | Path) -> Path:
    """Normalizes local repository path and resolves common path aliases or nested working dirs."""
    if not raw_path:
        return Path(raw_path) if isinstance(raw_path, Path) else Path(".")
    raw_str = str(raw_path).replace("file://", "").strip()
    p = Path(raw_str).expanduser()
    if p.is_absolute() and p.exists():
        return p.resolve()
    candidate_app = (APP_ROOT_DIR / raw_str).resolve()
    if candidate_app.exists():
        return candidate_app
    resolved = p.resolve()
    if resolved.exists():
        return resolved
    if "GitAgent" in resolved.parts:
        parts = [part for part in resolved.parts if part != "GitAgent"]
        alt1 = Path(*parts)
        if alt1.exists():
            return alt1
    alt2 = (APP_ROOT_DIR.parent / resolved.name).resolve()
    if alt2.exists():
        return alt2
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

    _ensure_agents_registered()
    scanner = get_scanner_agent()
    remediator = get_remediator_agent()
    notifier = get_email_notifier()

    agents_list = AgentRegistry.list_agents()
    if scanner.last_result or git_prepared:
        bug_findings = scanner.load_bug_findings()
    else:
        bug_findings = []
    remediator_reports = remediator.list_reports(ws_dir) if (git_prepared and remediator.last_result) else []

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
            "status": scanner.status if (git_prepared or scanner.last_result) else "IDLE",
            "last_result": scanner.last_result,
            "bug_findings": bug_findings,
            "findings_dir": str(scanner.findings_dir),
            "tools": scanner.get_scanner_tools(),
        },
        "remediator": {
            "status": remediator.status if git_prepared else "IDLE",
            "last_result": remediator.last_result if git_prepared else None,
            "reports_count": len(remediator_reports),
            "progress": remediator.get_progress(),
        },
        "workspace_files": workspace_files,
        "latest_pr": LATEST_PR,
        "build_and_test": ACTIVE_GIT_AGENT.last_build_test_result if (git_prepared and ACTIVE_GIT_AGENT and hasattr(ACTIVE_GIT_AGENT, "last_build_test_result")) else None,
        "email": notifier.get_public_config(),
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

    scanner = get_scanner_agent()
    remediator = get_remediator_agent()
    notifier = get_email_notifier()

    rem_res = remediation_result or remediator.last_result or {}
    post_scan = post_scan_result or getattr(remediator, "last_post_scan", None) or rem_res.get("post_scan") or {}
    scan_res = scanner.last_result or {}

    rem_html, _ = remediator.get_report_content(fmt="html", workspace_path=str(resolved_ws) if resolved_ws else None)
    rem_json, _ = remediator.get_report_content(fmt="json", workspace_path=str(resolved_ws) if resolved_ws else None)
    scan_html, _ = scanner.get_report_content("html")

    return notifier.send_remediation_report_email(
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

    def log_message(self, format: str, *args: Any) -> None:
        """Route HTTP access logs through the structured module logger."""
        client_addr = getattr(self, "client_address", ("-", 0))
        logger.debug("HTTP %s - %s", client_addr[0], format % args)

    def _send_json(self, data: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def _serve_static_ui_or_asset(self, path: str) -> bool:
        if path in ("/", "/index.html"):
            html_file = get_web_dir() / "index.html"
            if html_file.exists():
                content = html_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return True

        if path in ("/scheduler", "/scheduler.html"):
            html_file = get_web_dir() / "scheduler.html"
            if html_file.exists():
                content = html_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return True

        if (
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
                return True

        return False

    def do_GET(self) -> None:
        started_at = time.monotonic()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        ws = sys.modules[__name__]

        try:
            if path == "/api/health":
                _ensure_agents_registered()
                agents_list = AgentRegistry.list_agents()
                self._send_json({
                    "status": "ok",
                    "version": APP_VERSION,
                    "uptime_seconds": round(time.monotonic() - SERVER_START_TIME, 2),
                    "agents_total": len(agents_list),
                })
                return

            if path == "/api/telemetry":
                self._send_json(_build_telemetry_payload())
                return

            if path == "/api/agents":
                _ensure_agents_registered()
                agents_list = AgentRegistry.list_agents()
                self._send_json({
                    "agents": agents_list,
                    "total": len(agents_list),
                })
                return

            if path == "/api/email/config":
                self._send_json(get_email_notifier().get_public_config())
                return

            if path == "/api/email/outbox":
                self._send_json({"outbox": get_email_notifier().list_outbox(limit=25)})
                return

            if path in ("/api/llm/models", "/api/ollama/models"):
                parsed_query = urllib.parse.parse_qs(parsed.query)
                provider = (parsed_query.get("provider", ["ollama"])[0] or "ollama").strip().lower()
                base_url = (parsed_query.get("base_url", [""])[0] or "").strip() or None
                self._send_json(discover_local_llm_models(provider=provider, base_url=base_url))
                return

            if (
                handle_get_git_routes(self, path, parsed, ws)
                or handle_get_scan_fix_routes(self, path, parsed, ws)
                or handle_get_scheduler_routes(self, path, parsed, ws)
                or self._serve_static_ui_or_asset(path)
            ):
                return

            super().do_GET()
        finally:
            if path.startswith("/api/"):
                elapsed_ms = (time.monotonic() - started_at) * 1000.0
                logger.debug("GET %s completed in %.1fms", path, elapsed_ms)

    def do_POST(self) -> None:
        started_at = time.monotonic()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        ws = sys.modules[__name__]

        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            payload = json.loads(post_data) if post_data else {}
        except Exception:
            payload = {}

        try:
            if (
                handle_post_git_routes(self, path, payload, ws)
                or handle_post_scan_fix_routes(self, path, payload, ws)
                or handle_post_scheduler_routes(self, path, payload, ws)
            ):
                return

            if path == "/api/email/config":
                updated_cfg = get_email_notifier().update_config(payload)
                self._send_json({
                    "message": "Email report configuration saved",
                    "config": updated_cfg,
                })
                return

            if path == "/api/email/send-report":
                notifier = get_email_notifier()
                email_keys = (
                    "webhook_url", "smtp_host", "smtp_port", "smtp_username", "smtp_password",
                    "sender_email", "recipient_emails", "use_tls", "use_ssl",
                    "auto_send_after_remediation", "auto_send_after_pr",
                    "attach_remediation_pdf", "attach_scan_pdf",
                    "attach_remediation_html", "attach_scan_html", "attach_remediation_json",
                )
                if any(k in payload for k in email_keys):
                    notifier.update_config(payload)
                email_res = _dispatch_current_remediation_email(
                    override_recipients=payload.get("recipient_emails"),
                    custom_subject=payload.get("subject"),
                    custom_note=payload.get("custom_note"),
                    trigger_source=payload.get("trigger_source") or "manual_ui_dispatch",
                )
                self._send_json(email_res)
                return

            self._send_json({"error": f"Unknown endpoint: {path}"}, status=404)

        except Exception as e:
            logger.error("API error on %s: %s", path, e, exc_info=True)
            self._send_json({"error": str(e)}, status=500)
        finally:
            elapsed_ms = (time.monotonic() - started_at) * 1000.0
            logger.info("POST %s completed in %.1fms", path, elapsed_ms)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server so requests (e.g. folder browsing, status polling) never block each other."""
    daemon_threads = True
    allow_reuse_address = True


def run_server(port: int = 8080) -> None:
    """Start the Common Multi-Agent UI Dashboard HTTP Server."""
    web_dir = get_web_dir()
    os.chdir(str(web_dir.parent))
    _ensure_agents_registered()
    _ensure_default_local_repo_ready(reset_files=False)
    scheduler = get_batch_scheduler()
    scheduler.start()

    with ThreadedTCPServer(("", port), MultiAgentAPIHandler) as httpd:
        if threading.current_thread() is threading.main_thread():
            def _handle_sigterm(signum: int, _frame: Any) -> None:
                logger.info("Received signal %s; shutting down server gracefully...", signum)
                threading.Thread(target=httpd.shutdown, daemon=True).start()

            signal.signal(signal.SIGTERM, _handle_sigterm)

        print(f"\n=======================================================")
        print(f"🤖 Multi-Agent Control Center v{APP_VERSION} running at:")
        print(f"👉 Single Repo UI:    http://localhost:{port}")
        print(f"🗓️  Batch Scheduler:   http://localhost:{port}/scheduler")
        print(f"🩺 Health Check:      http://localhost:{port}/api/health")
        print(f"📁 Serving common UI from: {web_dir}")
        print(f"=======================================================\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Multi-Agent UI server.")
        finally:
            scheduler.stop()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
