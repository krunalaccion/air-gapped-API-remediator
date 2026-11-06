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
from typing import Dict, Any, Optional

from agents.base import AgentRegistry
from agents.git_agent.config import GitAgentConfig, ProviderType
from agents.git_agent.agent import GitSubAgent
from agents.scanner_agent.agent import ScannerAgent
from agents.remediator_agent.agent import RemediatorAgent, DEFAULT_SQLI_FINDING
from orchestrator.pipeline import MultiAgentPipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("multi_agent.web_server")

# Active agent instances for the web session
ACTIVE_GIT_AGENT: Optional[GitSubAgent] = None
SCANNER_AGENT: ScannerAgent = ScannerAgent()
REMEDIATOR_AGENT: RemediatorAgent = RemediatorAgent()
LATEST_PR: Optional[Dict[str, Any]] = None

DEFAULT_LOCAL_REPO = (Path(__file__).resolve().parent / "repos" / "CustomerApi").resolve()

# Register core agents
AgentRegistry.register(
    "git",
    GitSubAgent(GitAgentConfig(repo_url=str(DEFAULT_LOCAL_REPO), provider=ProviderType.LOCAL)),
)
AgentRegistry.register("scanner", SCANNER_AGENT)
AgentRegistry.register("remediator", REMEDIATOR_AGENT)


def _resolve_active_workspace() -> Path:
    """Returns the active GitSubAgent workspace path or the default CustomerApi repo."""
    if ACTIVE_GIT_AGENT and ACTIVE_GIT_AGENT.context:
        try:
            ws = ACTIVE_GIT_AGENT.get_workspace_path()
            if ws and ws.exists():
                return ws
        except Exception:
            pass
    return DEFAULT_LOCAL_REPO


def _build_telemetry_payload() -> Dict[str, Any]:
    """Builds a 100% real-time telemetry snapshot from the active agents and repository."""
    ws_dir = _resolve_active_workspace()
    git_prepared = bool(ACTIVE_GIT_AGENT and ACTIVE_GIT_AGENT.context)
    git_status = None
    git_context = None
    git_diff = ""
    git_author = "Git SubAgent <git-agent@subagent.local>"

    if git_prepared and ACTIVE_GIT_AGENT:
        try:
            git_status = ACTIVE_GIT_AGENT.get_status()
            git_context = ACTIVE_GIT_AGENT.context.to_dict() if ACTIVE_GIT_AGENT.context else None
            git_diff = ACTIVE_GIT_AGENT.get_diff()
            git_author = f"{ACTIVE_GIT_AGENT.config.author_name} <{ACTIVE_GIT_AGENT.config.author_email}>"
        except Exception as exc:
            logger.debug("Telemetry git status check error: %s", exc)

    agents_list = AgentRegistry.list_agents()
    bug_findings = SCANNER_AGENT.load_bug_findings()
    remediator_reports = REMEDIATOR_AGENT.list_reports()

    tracked_rel_paths = [
        "Controllers/UsersController.cs",
        "Program.cs",
        "appsettings.json",
        "CustomerApi.csproj",
        "AIRGAP_SECURITY_AUDIT.md",
        "config/airgap_proxy.json",
    ]
    workspace_files: List[Dict[str, Any]] = []
    if ws_dir and ws_dir.exists():
        for rel in tracked_rel_paths:
            f_path = ws_dir / rel
            workspace_files.append({
                "relative_path": rel,
                "exists": f_path.exists(),
                "size_bytes": f_path.stat().st_size if f_path.exists() else 0,
            })

    return {
        "default_repo_path": str(DEFAULT_LOCAL_REPO),
        "active_workspace_path": str(ws_dir),
        "agents": agents_list,
        "agents_total": len(agents_list),
        "git": {
            "prepared": git_prepared,
            "context": git_context,
            "status": git_status,
            "diff": git_diff,
            "author": git_author,
        },
        "scanner": {
            "status": SCANNER_AGENT.status,
            "last_result": SCANNER_AGENT.last_result,
            "bug_findings": bug_findings,
            "findings_dir": str(SCANNER_AGENT.findings_dir),
        },
        "remediator": {
            "status": REMEDIATOR_AGENT.status,
            "last_result": REMEDIATOR_AGENT.last_result,
            "reports_count": len(remediator_reports),
        },
        "workspace_files": workspace_files,
        "latest_pr": LATEST_PR,
    }


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

        elif path == "/api/bug-fixer/reports":
            """List all saved BugFixerAgent remediation reports from RemediatorAgent."""
            reports = REMEDIATOR_AGENT.list_reports()
            self._send_json({
                "count": len(reports),
                "reports": reports,
                "default_finding": DEFAULT_SQLI_FINDING,
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

        elif path == "/api/status":
            global ACTIVE_GIT_AGENT
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

                token = payload.get("token") or os.getenv("GITHUB_TOKEN") or os.getenv("GITLAB_TOKEN")
                provider_str = payload.get("provider")
                if provider_str:
                    try:
                        provider = ProviderType(provider_str.lower())
                    except ValueError:
                        provider = ProviderType.GENERIC
                else:
                    provider = ProviderType.GENERIC

                config = GitAgentConfig(
                    repo_url=repo_url,
                    token=token,
                    provider=provider,
                    base_branch=payload.get("base_branch"),
                    feature_branch_name=payload.get("feature_branch"),
                    workspace_dir=payload.get("workspace_dir"),
                    author_name=payload.get("author_name", "Git SubAgent"),
                    author_email=payload.get("author_email", "git-agent@subagent.local"),
                )

                # Validation: if target is a local repository, verify it exists and has git
                if config.is_local or config.provider == ProviderType.LOCAL:
                    clean_path = Path(config.sanitized_repo_url)
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
                            self._send_json({
                                "error": f"Selected path '{clean_path}' is not a Git repository. Missing '.git' directory."
                            }, status=400)
                            return

                ACTIVE_GIT_AGENT = GitSubAgent(config)
                AgentRegistry.register("git", ACTIVE_GIT_AGENT)
                try:
                    ctx = ACTIVE_GIT_AGENT.prepare_workspace()
                except Exception as clone_exc:
                    # Offline / air-gapped fallback to local CustomerApi Git repository when remote clone is unreachable
                    local_fallback = Path(__file__).resolve().parent / "repos" / "CustomerApi"
                    if not config.is_local and local_fallback.exists() and (local_fallback / ".git").exists():
                        logger.info("Remote clone unreachable in air-gap mode (%s); initializing local repository %s", clone_exc, local_fallback)
                        fallback_cfg = GitAgentConfig(
                            repo_url=str(local_fallback),
                            provider=ProviderType.LOCAL,
                            base_branch=payload.get("base_branch") or "master",
                            feature_branch_name=payload.get("feature_branch"),
                            author_name=payload.get("author_name", "Git SubAgent"),
                            author_email=payload.get("author_email", "git-agent@subagent.local"),
                        )
                        ACTIVE_GIT_AGENT = GitSubAgent(fallback_cfg)
                        AgentRegistry.register("git", ACTIVE_GIT_AGENT)
                        ctx = ACTIVE_GIT_AGENT.prepare_workspace()
                    else:
                        raise

                self._send_json({
                    "message": "Repository prepared successfully",
                    "context": ctx.to_dict(),
                    "status": ACTIVE_GIT_AGENT.get_status(),
                })
                return

            # 2. Scan Code (ScannerAgent)
            elif path == "/api/scan":
                ws_path = ACTIVE_GIT_AGENT.get_workspace_path() if ACTIVE_GIT_AGENT else None
                result = SCANNER_AGENT.run({"workspace_path": str(ws_path) if ws_path else None})
                result["mode"] = "live" if ACTIVE_GIT_AGENT else "preview"
                self._send_json(result)
                return

            # 3. Fix Code (RemediatorAgent + BugFixerAgent on scanner_agent/findings/*.json)
            elif path == "/api/fix":
                ws_path = ACTIVE_GIT_AGENT.get_workspace_path() if ACTIVE_GIT_AGENT else None
                result = REMEDIATOR_AGENT.run({
                    "workspace_path": str(ws_path) if ws_path else None,
                    "provider": payload.get("provider"),
                    "model": payload.get("model"),
                })
                result["mode"] = "live" if ACTIVE_GIT_AGENT else "preview"
                # Re-run scanner on the patched workspace to reflect real post-remediation findings & posture
                post_scan = SCANNER_AGENT.run({"workspace_path": str(ws_path) if ws_path else None})
                result["post_scan"] = post_scan
                if ACTIVE_GIT_AGENT:
                    result["status_summary"] = ACTIVE_GIT_AGENT.get_status()
                    result["diff"] = ACTIVE_GIT_AGENT.get_diff() or result.get("bug_diff", "")
                else:
                    result["diff"] = result.get("bug_diff", "")
                self._send_json(result)
                return

            # 3B. RemediatorAgent (BugFixerAgent) - Fix SAST/Bug Finding
            elif path == "/api/bug-fixer/fix":
                ws_path = ACTIVE_GIT_AGENT.get_workspace_path() if ACTIVE_GIT_AGENT else None
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

            # 3C. RemediatorAgent (BugFixerAgent) - Reset Demo Vulnerable Controller
            elif path == "/api/bug-fixer/reset":
                ws_path = ACTIVE_GIT_AGENT.get_workspace_path() if ACTIVE_GIT_AGENT else None
                result = REMEDIATOR_AGENT.reset_demo(workspace_path=ws_path)
                post_scan = SCANNER_AGENT.run({"workspace_path": str(ws_path) if ws_path else None})
                result["post_scan"] = post_scan
                if ACTIVE_GIT_AGENT:
                    result["status_summary"] = ACTIVE_GIT_AGENT.get_status()
                    result["git_diff"] = ACTIVE_GIT_AGENT.get_diff()
                self._send_json(result)
                return

            # 4A. Read real file from active workspace or default repo
            elif path == "/api/read-file":
                rel_path = (payload.get("relative_path") or "").strip()
                if not rel_path:
                    self._send_json({"error": "relative_path is required"}, status=400)
                    return

                ws_dir = _resolve_active_workspace()
                target_file = (ws_dir / rel_path).resolve()
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
                if not ACTIVE_GIT_AGENT:
                    self._send_json({"error": "Please call /api/prepare first"}, status=400)
                    return

                rel_path = payload.get("relative_path")
                content = payload.get("content", "")
                if not rel_path:
                    self._send_json({"error": "relative_path is required"}, status=400)
                    return

                ws_dir = ACTIVE_GIT_AGENT.get_workspace_path()
                target_file = (ws_dir / rel_path).resolve()
                if not str(target_file).startswith(str(ws_dir.resolve())):
                    self._send_json({"error": "Forbidden path outside workspace"}, status=403)
                    return

                target_file.parent.mkdir(parents=True, exist_ok=True)
                target_file.write_text(content, encoding="utf-8")
                self._send_json({
                    "message": f"Saved {rel_path}",
                    "status": ACTIVE_GIT_AGENT.get_status(),
                    "diff": ACTIVE_GIT_AGENT.get_diff(),
                })
                return

            # 5. Commit & Push (GitSubAgent)
            elif path == "/api/commit-push":
                if not ACTIVE_GIT_AGENT:
                    self._send_json({"error": "Please call /api/prepare first"}, status=400)
                    return

                commit_msg = payload.get("commit_message", "fix(airgap): remediate external API endpoints")
                files = payload.get("files")
                cur_br = ACTIVE_GIT_AGENT.workspace.current_feature_branch or ACTIVE_GIT_AGENT.workspace.get_current_branch()
                dest_label = "remote branch" if not ACTIVE_GIT_AGENT.config.is_local else "local branch"

                if ACTIVE_GIT_AGENT.workspace.has_changes():
                    ACTIVE_GIT_AGENT.workspace.add(files)
                    commit_hash = ACTIVE_GIT_AGENT.workspace.commit(commit_msg)
                    ACTIVE_GIT_AGENT.workspace.push(push_url=ACTIVE_GIT_AGENT.config.authenticated_clone_url)
                    self._send_json({
                        "message": f"Committed {commit_hash[:7]} and updated {dest_label} '{cur_br}'",
                        "commit_hash": commit_hash,
                        "branch": cur_br,
                    })
                else:
                    ACTIVE_GIT_AGENT.workspace.push(push_url=ACTIVE_GIT_AGENT.config.authenticated_clone_url)
                    self._send_json({
                        "message": f"Working tree clean. Updated {dest_label} '{cur_br}'.",
                        "branch": cur_br,
                    })
                return

            # 6. Raise Pull Request (GitSubAgent)
            elif path == "/api/create-pr":
                if not ACTIVE_GIT_AGENT:
                    self._send_json({"error": "Please call /api/prepare first"}, status=400)
                    return

                title = payload.get("title", "[Air-Gapped Remediation] Security & SAST Compliance Remediation")
                desc = payload.get("description", "Automated Pull Request from Multi-Agent System")
                draft = bool(payload.get("draft", False))

                if not ACTIVE_GIT_AGENT.provider:
                    self._send_json({"error": "No git provider configured (GitHub/GitLab/Local)"}, status=400)
                    return

                pr = ACTIVE_GIT_AGENT.provider.create_pull_request(
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
                self._send_json(pr_data)
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

            # 8. Validate Local Repository Path (Check if directory has .git)
            elif path == "/api/validate-path":
                raw_path = payload.get("path", "").strip()
                if not raw_path:
                    self._send_json({"valid": False, "error": "Path cannot be empty"}, status=400)
                    return

                clean = raw_path.replace("file://", "")
                target_path = Path(os.path.expanduser(clean)).resolve()

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

                if not has_git:
                    self._send_json({
                        "valid": False,
                        "exists": True,
                        "is_dir": True,
                        "has_git": False,
                        "path": str(target_path),
                        "error": f"Selected path '{target_path}' is not a Git repository (missing '.git' directory).",
                    }, status=400)
                    return

                self._send_json({
                    "valid": True,
                    "exists": True,
                    "is_dir": True,
                    "has_git": True,
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
                    current_dir = Path.cwd().resolve()

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

                # Quick access locations for fast navigation (especially on macOS)
                home = Path.home().resolve()
                quick_access = [
                    {"label": "🏠 Home", "path": str(home)},
                    {"label": "📁 Workspace", "path": str(Path.cwd().resolve())},
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
    with ThreadedTCPServer(("", port), MultiAgentAPIHandler) as httpd:
        print(f"\n=======================================================")
        print(f"🤖 Multi-Agent Control Center running at:")
        print(f"👉 http://localhost:{port}")
        print(f"📁 Serving common UI from: {web_dir}")
        print(f"=======================================================\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Multi-Agent UI server.")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
