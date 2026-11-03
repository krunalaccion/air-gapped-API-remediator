"""
Command-line interface for Git SubAgent.
Allows testing, manual execution, and script automation of git preparation, committing, and PR creation.
"""

from __future__ import annotations
import argparse
import json
import logging
import sys
from pathlib import Path

from git_agent.config import GitAgentConfig, ProviderType
from git_agent.agent import GitSubAgent
from git_agent.mcp_server import GitAgentMCPServer


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def cmd_prepare(args: argparse.Namespace):
    """Clone repo, pull base branch, and create feature branch."""
    config = GitAgentConfig(
        repo_url=args.repo_url,
        token=args.token,
        provider=ProviderType(args.provider) if args.provider else ProviderType.GENERIC,
        base_branch=args.base_branch,
        feature_branch_name=args.feature_branch,
        workspace_dir=args.workspace_dir,
    )
    agent = GitSubAgent(config)
    ctx = agent.prepare_workspace()
    print("\n--- Workspace Ready ---")
    print(f"Directory:      {ctx.repo_path}")
    print(f"Base Branch:    {ctx.base_branch}")
    print(f"Feature Branch: {ctx.feature_branch}")
    print(f"Provider:       {ctx.provider}")
    print(f"Repo URL:       {ctx.repo_url}")


def cmd_mcp(args: argparse.Namespace):
    """Start the MCP server over stdio."""
    server = GitAgentMCPServer()
    server.run_stdio()


def cmd_ui(args: argparse.Namespace):
    """Start the GitAgent Web Dashboard."""
    from git_agent.web_server import run_server
    run_server(port=args.port)


def main():
    parser = argparse.ArgumentParser(
        prog="git-agent",
        description="Configurable Git SubAgent & MCP Server for automated branching and PR workflows.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Prepare command
    prep_p = subparsers.add_parser("prepare", help="Clone repo, pull base branch, create feature branch")
    prep_p.add_argument("--repo-url", "-r", required=True, help="Repository URL (GitHub or GitLab)")
    prep_p.add_argument("--token", "-t", help="Personal Access Token")
    prep_p.add_argument("--provider", "-p", choices=["github", "gitlab", "generic"], help="Repository provider")
    prep_p.add_argument("--base-branch", "-b", help="Base branch (main/master)")
    prep_p.add_argument("--feature-branch", "-f", help="New feature branch name")
    prep_p.add_argument("--workspace-dir", "-w", help="Workspace directory destination")
    prep_p.set_defaults(func=cmd_prepare)

    # MCP Server command
    mcp_p = subparsers.add_parser("mcp", help="Start the MCP Server on stdio")
    mcp_p.set_defaults(func=cmd_mcp)

    # Web UI command
    ui_p = subparsers.add_parser("ui", help="Start the GitAgent Graphical Web Dashboard")
    ui_p.add_argument("--port", type=int, default=8080, help="Port to run web server on (default: 8080)")
    ui_p.set_defaults(func=cmd_ui)

    args = parser.parse_args()
    setup_logging(args.verbose)
    args.func(args)


if __name__ == "__main__":
    main()

