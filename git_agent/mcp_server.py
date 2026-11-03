"""
Model Context Protocol (MCP) Server for Git SubAgent.
Implements the JSON-RPC 2.0 stdio transport conforming to MCP specification (2024-11-05).
Exposes tools for repository cloning, branch management, vulnerability remediation committing, and PR creation.
"""

from __future__ import annotations
import json
import logging
import os
import sys
import traceback
from pathlib import Path
from typing import Dict, Any, Optional

from git_agent.config import GitAgentConfig, ProviderType
from git_agent.agent import GitSubAgent, WorkspaceContext, FinalizeResult

# Setup logging to stderr so stdout remains purely for JSON-RPC messages
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [mcp_server] %(message)s",
)
logger = logging.getLogger("git_agent.mcp")


class GitAgentMCPServer:
    """MCP Server exposing Git SubAgent tools over stdio."""

    def __init__(self):
        self.agent: Optional[GitSubAgent] = None
        self.tools = self._build_tool_definitions()

    def _build_tool_definitions(self) -> list:
        return [
            {
                "name": "git_prepare_repo",
                "description": (
                    "Clones a GitHub/GitLab repository, pulls the latest main/master branch, "
                    "and creates a feature branch ready for vulnerability scanning or modifications."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_url": {
                            "type": "string",
                            "description": "Repository URL (e.g. 'https://github.com/owner/repo.git' or 'https://gitlab.com/group/project')",
                        },
                        "token": {
                            "type": "string",
                            "description": "Personal Access Token for GitHub (GITHUB_TOKEN) or GitLab (GITLAB_TOKEN). Can also be set in environment.",
                        },
                        "provider": {
                            "type": "string",
                            "enum": ["github", "gitlab", "generic"],
                            "description": "Hosting provider. Auto-detected from URL if omitted.",
                        },
                        "base_branch": {
                            "type": "string",
                            "description": "Base branch to branch off of (e.g. 'main' or 'master'). Auto-detected if omitted.",
                        },
                        "feature_branch": {
                            "type": "string",
                            "description": "Name for the new feature branch. Auto-generated timestamped branch if omitted.",
                        },
                        "workspace_dir": {
                            "type": "string",
                            "description": "Local directory path to clone into. Isolated temporary directory if omitted.",
                        },
                        "author_name": {
                            "type": "string",
                            "description": "Git commit author name.",
                        },
                        "author_email": {
                            "type": "string",
                            "description": "Git commit author email.",
                        },
                    },
                    "required": ["repo_url"],
                },
            },
            {
                "name": "git_status",
                "description": "Returns current git status of the active repository workspace (branch, modified, staged, untracked files).",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "git_diff",
                "description": "Returns the git diff of changes currently made in the workspace.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "staged": {
                            "type": "boolean",
                            "description": "If true, show diff of staged changes. If false, show working tree diff.",
                        }
                    },
                },
            },
            {
                "name": "git_read_file",
                "description": "Reads contents of a file inside the checked-out workspace to inspect for vulnerabilities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "relative_path": {
                            "type": "string",
                            "description": "Relative path to the file inside the repository workspace.",
                        }
                    },
                    "required": ["relative_path"],
                },
            },
            {
                "name": "git_write_file",
                "description": "Writes or updates a file inside the repository workspace (e.g. applying a vulnerability fix or patch).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "relative_path": {
                            "type": "string",
                            "description": "Relative path to the file inside the repository workspace.",
                        },
                        "content": {
                            "type": "string",
                            "description": "Full new content of the file.",
                        },
                    },
                    "required": ["relative_path", "content"],
                },
            },
            {
                "name": "git_commit_and_push",
                "description": "Stages workspace changes, commits them with author attribution, and pushes the feature branch to remote.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "commit_message": {
                            "type": "string",
                            "description": "Commit message describing the changes or security fixes applied.",
                        },
                        "files": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of relative file paths to stage. Stages all changes if omitted.",
                        },
                    },
                    "required": ["commit_message"],
                },
            },
            {
                "name": "git_create_pull_request",
                "description": "Opens a Pull Request (GitHub) or Merge Request (GitLab) for the pushed feature branch.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "PR / Merge Request title.",
                        },
                        "description": {
                            "type": "string",
                            "description": "PR / Merge Request markdown description.",
                        },
                        "draft": {
                            "type": "boolean",
                            "description": "Whether to open the PR as a draft.",
                        },
                    },
                    "required": ["title", "description"],
                },
            },
            {
                "name": "git_finalize_audit",
                "description": (
                    "End-to-end workflow: Stages all modifications, commits with message, "
                    "pushes feature branch, and automatically opens a Pull/Merge Request for review."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "commit_message": {
                            "type": "string",
                            "description": "Git commit message for the fixes applied.",
                        },
                        "pr_title": {
                            "type": "string",
                            "description": "Title of the Pull/Merge Request.",
                        },
                        "pr_body": {
                            "type": "string",
                            "description": "Description / vulnerability report body for the Pull/Merge Request.",
                        },
                        "draft": {
                            "type": "boolean",
                            "description": "Whether to create PR as draft (default: false).",
                        },
                    },
                },
            },
        ]

    def handle_tool_call(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch tool calls to subagent methods."""
        try:
            if name == "git_prepare_repo":
                repo_url = args["repo_url"]
                token = args.get("token")
                provider_str = args.get("provider")
                provider = ProviderType(provider_str.lower()) if provider_str else ProviderType.GENERIC

                config = GitAgentConfig(
                    repo_url=repo_url,
                    token=token,
                    provider=provider,
                    base_branch=args.get("base_branch"),
                    feature_branch_name=args.get("feature_branch"),
                    workspace_dir=args.get("workspace_dir"),
                    author_name=args.get("author_name", "Git SubAgent"),
                    author_email=args.get("author_email", "git-agent@subagent.local"),
                )
                self.agent = GitSubAgent(config)
                ctx = self.agent.prepare_workspace()
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"Repository prepared successfully.\n"
                                f"Workspace directory: {ctx.repo_path}\n"
                                f"Base branch: {ctx.base_branch}\n"
                                f"Active feature branch: {ctx.feature_branch}\n"
                                f"Provider: {ctx.provider}"
                            ),
                        }
                    ]
                }

            if not self.agent:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": "Error: No active workspace found. Please call 'git_prepare_repo' first.",
                        }
                    ],
                    "isError": True,
                }

            if name == "git_status":
                status = self.agent.get_status()
                return {
                    "content": [
                        {"type": "text", "text": json.dumps(status, indent=2)}
                    ]
                }

            elif name == "git_diff":
                staged = bool(args.get("staged", False))
                diff = self.agent.get_diff(staged=staged)
                return {
                    "content": [
                        {"type": "text", "text": diff if diff else "(no changes)"}
                    ]
                }

            elif name == "git_read_file":
                rel_path = args["relative_path"]
                workspace_base = Path(self.agent.get_workspace_path()).resolve()
                full_path = (workspace_base / rel_path).resolve()
                try:
                    full_path.relative_to(workspace_base)
                except ValueError:
                    raise ValueError("Access outside workspace directory is forbidden.")
                if not full_path.exists():
                    raise FileNotFoundError(f"File not found: {rel_path}")
                content = full_path.read_text(encoding="utf-8", errors="replace")
                return {
                    "content": [{"type": "text", "text": content}]
                }

            elif name == "git_write_file":
                rel_path = args["relative_path"]
                content = args["content"]
                workspace_base = Path(self.agent.get_workspace_path()).resolve()
                full_path = (workspace_base / rel_path).resolve()
                try:
                    full_path.relative_to(workspace_base)
                except ValueError:
                    raise ValueError("Access outside workspace directory is forbidden.")
                full_path.parent.mkdir(parents=True, exist_ok=True)
                full_path.write_text(content, encoding="utf-8")
                return {
                    "content": [
                        {"type": "text", "text": f"Successfully updated file: {rel_path}"}
                    ]
                }

            elif name == "git_commit_and_push":
                msg = args["commit_message"]
                files = args.get("files")
                current_br = self.agent.workspace.current_feature_branch or self.agent.workspace.get_current_branch()
                if self.agent.workspace.has_changes():
                    self.agent.workspace.add(files)
                    commit_hash = self.agent.workspace.commit(msg)
                    self.agent.workspace.push(push_url=self.agent.config.authenticated_clone_url)
                    return {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Committed {commit_hash[:7]} ('{msg}') and pushed branch '{current_br}' to remote.",
                            }
                        ]
                    }
                else:
                    self.agent.workspace.push(push_url=self.agent.config.authenticated_clone_url)
                    return {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Working tree clean (no new changes to commit). Pushed branch '{current_br}' to remote.",
                            }
                        ]
                    }

            elif name == "git_create_pull_request":
                title = args["title"]
                description = args["description"]
                draft = bool(args.get("draft", False))
                if not self.agent.provider:
                    raise RuntimeError("No provider configured (e.g. GitHub or GitLab).")

                pr = self.agent.provider.create_pull_request(
                    head_branch=self.agent.workspace.current_feature_branch,
                    base_branch=self.agent.workspace.base_branch or "main",
                    title=title,
                    description=description,
                    draft=draft,
                )
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Pull Request opened successfully: #{pr.number} - {pr.url}",
                        }
                    ]
                }

            elif name == "git_finalize_audit":
                result: FinalizeResult = self.agent.finalize_workspace(
                    commit_message=args.get("commit_message"),
                    pr_title=args.get("pr_title"),
                    pr_body=args.get("pr_body"),
                    draft=args.get("draft"),
                )
                return {
                    "content": [
                        {"type": "text", "text": json.dumps(result.to_dict(), indent=2)}
                    ]
                }

            else:
                return {
                    "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                    "isError": True,
                }

        except Exception as e:
            logger.error("Error executing tool '%s': %s", name, e, exc_info=True)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Tool execution failed: {str(e)}\n{traceback.format_exc()}",
                    }
                ],
                "isError": True,
            }

    def process_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process incoming JSON-RPC 2.0 message and generate response."""
        msg_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {},
                    },
                    "serverInfo": {
                        "name": "git-agent-mcp",
                        "version": "0.1.0",
                    },
                },
            }

        elif method == "notifications/initialized":
            # Client acknowledges initialization; no response needed
            return None

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": self.tools},
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            result = self.handle_tool_call(tool_name, tool_args)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result,
            }

        else:
            if msg_id is not None:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method '{method}' not found",
                    },
                }
            return None

    def run_stdio(self) -> None:
        """Run stdio loop reading NDJSON lines and outputting responses."""
        logger.info("GitAgent MCP Server running on stdio...")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                response = self.process_message(request)
                if response is not None:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
            except json.JSONDecodeError as e:
                logger.error("JSON decode error: %s on line: %s", e, line)
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
            except Exception as e:
                logger.error("Unexpected error in stdio loop: %s", e, exc_info=True)


def main():
    server = GitAgentMCPServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
