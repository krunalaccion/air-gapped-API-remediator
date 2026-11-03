"""
Common Web Server and REST API for the Multi-Agent System.
Serves the unified Web UI and provides endpoints for all specialized agents:
- GitSubAgent (Repository lifecycle, branching, commits, PRs)
- ScannerAgent (Code, egress, and air-gap policy auditing)
- RemediatorAgent (Proxy routing, automated patching, compliance manifests)
- MultiAgentPipeline (End-to-end multi-agent orchestration)
"""

from __future__ import annotations
import http.server
import json
import logging
import os
import socketserver
import sys
import urllib.parse
from pathlib import Path
from typing import Dict, Any, Optional

from agents.base import AgentRegistry
from agents.git_agent.config import GitAgentConfig, ProviderType
from agents.git_agent.agent import GitSubAgent
from agents.scanner_agent.agent import ScannerAgent
from agents.remediator_agent.agent import RemediatorAgent
from orchestrator.pipeline import MultiAgentPipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("multi_agent.web_server")

# Active agent instances for the web session
ACTIVE_GIT_AGENT: Optional[GitSubAgent] = None
SCANNER_AGENT: ScannerAgent = ScannerAgent()
REMEDIATOR_AGENT: RemediatorAgent = RemediatorAgent()

# Register core agents
AgentRegistry.register("git", GitSubAgent(GitAgentConfig(repo_url="https://github.com/placeholder/repo.git")))
AgentRegistry.register("scanner", SCANNER_AGENT)
AgentRegistry.register("remediator", REMEDIATOR_AGENT)


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

        if path == "/api/agents":
            """List all registered agents and their current statuses."""
            agents_list = AgentRegistry.list_agents()
            self._send_json({
                "agents": agents_list,
                "total": len(agents_list),
            })
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
        global ACTIVE_GIT_AGENT, SCANNER_AGENT, REMEDIATOR_AGENT
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
                provider = ProviderType(provider_str.lower()) if provider_str else ProviderType.GENERIC

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
                ACTIVE_GIT_AGENT = GitSubAgent(config)
                AgentRegistry.register("git", ACTIVE_GIT_AGENT)
                ctx = ACTIVE_GIT_AGENT.prepare_workspace()

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

            # 3. Fix Code (RemediatorAgent)
            elif path == "/api/fix":
                ws_path = ACTIVE_GIT_AGENT.get_workspace_path() if ACTIVE_GIT_AGENT else None
                result = REMEDIATOR_AGENT.run({"workspace_path": str(ws_path) if ws_path else None})
                result["mode"] = "live" if ACTIVE_GIT_AGENT else "preview"
                if ACTIVE_GIT_AGENT:
                    result["status_summary"] = ACTIVE_GIT_AGENT.get_status()
                    result["diff"] = ACTIVE_GIT_AGENT.get_diff()
                self._send_json(result)
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

                if ACTIVE_GIT_AGENT.workspace.has_changes():
                    ACTIVE_GIT_AGENT.workspace.add(files)
                    commit_hash = ACTIVE_GIT_AGENT.workspace.commit(commit_msg)
                    ACTIVE_GIT_AGENT.workspace.push(push_url=ACTIVE_GIT_AGENT.config.authenticated_clone_url)
                    self._send_json({
                        "message": f"Committed {commit_hash[:7]} and pushed to remote branch '{cur_br}'",
                        "commit_hash": commit_hash,
                        "branch": cur_br,
                    })
                else:
                    ACTIVE_GIT_AGENT.workspace.push(push_url=ACTIVE_GIT_AGENT.config.authenticated_clone_url)
                    self._send_json({
                        "message": f"Working tree clean. Pushed branch '{cur_br}' to remote.",
                        "branch": cur_br,
                    })
                return

            # 6. Raise Pull Request (GitSubAgent)
            elif path == "/api/create-pr":
                if not ACTIVE_GIT_AGENT:
                    self._send_json({"error": "Please call /api/prepare first"}, status=400)
                    return

                title = payload.get("title", "[Air-Gapped Remediation] Replace external API egress with offline services")
                desc = payload.get("description", "Automated Pull Request from Multi-Agent System")
                draft = bool(payload.get("draft", False))

                if not ACTIVE_GIT_AGENT.provider:
                    self._send_json({"error": "No git provider configured (GitHub/GitLab)"}, status=400)
                    return

                pr = ACTIVE_GIT_AGENT.provider.create_pull_request(
                    head_branch=ACTIVE_GIT_AGENT.workspace.current_feature_branch,
                    base_branch=ACTIVE_GIT_AGENT.workspace.base_branch or "main",
                    title=title,
                    description=desc,
                    draft=draft,
                )
                self._send_json({
                    "message": "Pull Request created successfully",
                    "pr_number": pr.number,
                    "pr_url": pr.url,
                    "title": pr.title,
                })
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

            self._send_json({"error": f"Unknown endpoint: {path}"}, status=404)

        except Exception as e:
            logger.error("API error on %s: %s", path, e, exc_info=True)
            self._send_json({"error": str(e)}, status=500)


def run_server(port: int = 8080):
    """Start the Common Multi-Agent UI Dashboard HTTP Server."""
    web_dir = get_web_dir()
    os.chdir(str(web_dir.parent))
    with socketserver.TCPServer(("", port), MultiAgentAPIHandler) as httpd:
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

