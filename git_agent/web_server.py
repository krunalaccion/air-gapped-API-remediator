"""
Embedded Web Server and REST API for GitSubAgent.
Provides a local web-based graphical user interface (GUI) with zero external dependencies.
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

from git_agent.config import GitAgentConfig, ProviderType
from git_agent.agent import GitSubAgent

logger = logging.getLogger("git_agent.web")

# Active agent state for the web session
ACTIVE_AGENT: Optional[GitSubAgent] = None


class GitAgentAPIHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP Request Handler serving the Dashboard GUI and JSON API endpoints."""

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

        if path == "/api/status":
            global ACTIVE_AGENT
            if not ACTIVE_AGENT:
                self._send_json({"error": "No active repository prepared"}, status=400)
                return
            stat = ACTIVE_AGENT.get_status()
            ctx = ACTIVE_AGENT.context
            self._send_json({
                "status": stat,
                "context": ctx.to_dict() if ctx else None,
            })
            return

        elif path == "/api/diff":
            if not ACTIVE_AGENT:
                self._send_json({"error": "No active repository prepared"}, status=400)
                return
            diff = ACTIVE_AGENT.get_diff()
            self._send_json({"diff": diff})
            return

        elif path == "/" or path == "/index.html":
            html_path = Path(__file__).parent / "web" / "index.html"
            if html_path.exists():
                content = html_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        super().do_GET()

    def do_POST(self):
        global ACTIVE_AGENT
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            payload = json.loads(post_data) if post_data else {}
        except Exception:
            payload = {}

        try:
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
                ACTIVE_AGENT = GitSubAgent(config)
                ctx = ACTIVE_AGENT.prepare_workspace()
                self._send_json({
                    "message": "Repository prepared successfully",
                    "context": ctx.to_dict(),
                    "status": ACTIVE_AGENT.get_status(),
                })
                return

            if not ACTIVE_AGENT:
                self._send_json({"error": "Please call /api/prepare first"}, status=400)
                return

            if path == "/api/write-file":
                rel_path = payload.get("relative_path")
                content = payload.get("content", "")
                if not rel_path:
                    self._send_json({"error": "relative_path is required"}, status=400)
                    return

                ws_dir = ACTIVE_AGENT.get_workspace_path()
                target_file = (ws_dir / rel_path).resolve()
                if not str(target_file).startswith(str(ws_dir.resolve())):
                    self._send_json({"error": "Forbidden path outside workspace"}, status=403)
                    return

                target_file.parent.mkdir(parents=True, exist_ok=True)
                target_file.write_text(content, encoding="utf-8")
                self._send_json({
                    "message": f"Saved {rel_path}",
                    "status": ACTIVE_AGENT.get_status(),
                    "diff": ACTIVE_AGENT.get_diff(),
                })
                return

            elif path == "/api/commit-push":
                commit_msg = payload.get("commit_message", "chore: apply audit updates")
                files = payload.get("files")
                cur_br = ACTIVE_AGENT.workspace.current_feature_branch or ACTIVE_AGENT.workspace.get_current_branch()

                if ACTIVE_AGENT.workspace.has_changes():
                    ACTIVE_AGENT.workspace.add(files)
                    commit_hash = ACTIVE_AGENT.workspace.commit(commit_msg)
                    ACTIVE_AGENT.workspace.push(push_url=ACTIVE_AGENT.config.authenticated_clone_url)
                    self._send_json({
                        "message": f"Committed {commit_hash[:7]} and pushed to remote",
                        "commit_hash": commit_hash,
                        "branch": cur_br,
                    })
                else:
                    ACTIVE_AGENT.workspace.push(push_url=ACTIVE_AGENT.config.authenticated_clone_url)
                    self._send_json({
                        "message": f"Working tree clean. Pushed branch '{cur_br}' to remote.",
                        "branch": cur_br,
                    })
                return

            elif path == "/api/create-pr":
                title = payload.get("title", "Automated Security Remediation")
                desc = payload.get("description", "Automated Pull Request from GitAgent")
                draft = bool(payload.get("draft", False))

                if not ACTIVE_AGENT.provider:
                    self._send_json({"error": "No git provider configured (GitHub/GitLab)"}, status=400)
                    return

                pr = ACTIVE_AGENT.provider.create_pull_request(
                    head_branch=ACTIVE_AGENT.workspace.current_feature_branch,
                    base_branch=ACTIVE_AGENT.workspace.base_branch or "main",
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

            elif path == "/api/finalize":
                res = ACTIVE_AGENT.finalize_workspace(
                    commit_message=payload.get("commit_message"),
                    pr_title=payload.get("pr_title"),
                    pr_body=payload.get("pr_body"),
                    draft=payload.get("draft"),
                )
                self._send_json(res.to_dict())
                return

            self._send_json({"error": f"Unknown endpoint: {path}"}, status=404)

        except Exception as e:
            logger.error("API error on %s: %s", path, e, exc_info=True)
            self._send_json({"error": str(e)}, status=500)


def run_server(port: int = 8080):
    """Start local GUI HTTP server."""
    web_dir = Path(__file__).parent / "web"
    os.chdir(str(web_dir.parent))  # Serve from package root
    with socketserver.TCPServer(("", port), GitAgentAPIHandler) as httpd:
        print(f"\n=======================================================")
        print(f"🚀 GitAgent UI Dashboard running at:")
        print(f"👉 http://localhost:{port}")
        print(f"=======================================================\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down UI server.")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)

