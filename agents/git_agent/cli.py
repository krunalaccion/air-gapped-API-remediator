"""
Command-line interface for Git SubAgent.
Allows testing, manual execution, and script automation of git preparation, committing, and PR creation.
"""

from __future__ import annotations
import argparse
import logging
from pathlib import Path

DIFF_PREVIEW_MAX_LINES = 20

try:
    from .config import GitAgentConfig, ProviderType
    from .agent import GitSubAgent
    from .mcp_server import GitAgentMCPServer
except (ImportError, ValueError):
    from agents.git_agent.config import GitAgentConfig, ProviderType
    from agents.git_agent.agent import GitSubAgent
    from agents.git_agent.mcp_server import GitAgentMCPServer


def setup_logging(verbose: bool = False) -> None:
    """Configure root logging level and format for CLI execution."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def cmd_prepare(args: argparse.Namespace) -> None:
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


def cmd_mcp(args: argparse.Namespace) -> None:
    """Start the MCP server over stdio."""
    server = GitAgentMCPServer()
    server.run_stdio()


def cmd_ui(args: argparse.Namespace) -> None:
    """Start the Multi-Agent Web Dashboard."""
    from web_server import run_server
    run_server(port=args.port)


def cmd_scan(args: argparse.Namespace) -> None:
    """Run ScannerAgent against a local workspace path."""
    from agents.scanner_agent.agent import ScannerAgent
    scanner = ScannerAgent()
    scan_path = Path(args.path).resolve()
    print(f"\n🔍 [ScannerAgent] Scanning workspace: {scan_path}")
    result = scanner.run({"workspace_path": str(scan_path)})

    print("\n--- Scan Results ---")
    print(f"Target:         {result.get('workspace_scanned')}")
    print(f"Total Findings: {result.get('total_findings', 0)}")
    print(f"Posture:        {result.get('posture', 'UNKNOWN')}")
    counts = result.get("severity_counts", {})
    print(f"Severities:     Critical={counts.get('critical', 0)} High={counts.get('high', 0)} Medium={counts.get('medium', 0)} Low={counts.get('low', 0)}")

    findings = result.get("findings", [])
    if findings:
        print("\nFindings Details:")
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "MEDIUM")
            rule = f.get("rule_id", "security-issue")
            fpath = f.get("file_path", "")
            line = f.get("line_number", 1)
            msg = f.get("description") or f.get("message", "")
            print(f"  {idx}. [{sev}] {rule} in {fpath}:{line} -> {msg}")
    else:
        print("\n✅ Zero security or egress violations detected.")


def cmd_remediate(args: argparse.Namespace) -> None:
    """Run RemediatorAgent directly against a repository workspace."""
    from agents.remediator_agent.agent import RemediatorAgent
    target_path = Path(args.path).resolve()
    print(f"\n🛠️  [RemediatorAgent] Remediating workspace: {target_path}")
    print(f"Engine: Provider={args.llm or 'auto'}, Model={args.model or 'default'}, URL={args.base_url or 'default'}")

    remediator = RemediatorAgent(
        llm_provider=args.llm,
        model=args.model,
        base_url=args.base_url,
    )
    result = remediator.run({
        "workspace_path": str(target_path),
        "provider": args.llm,
        "model": args.model,
        "base_url": args.base_url,
    })

    print("\n--- Remediation Complete ---")
    print(f"Status:         {result.get('status')}")
    print(f"Files Modified: {', '.join(result.get('files_modified', []))}")
    print(f"Summary:        {result.get('summary')}")

    file_diffs = result.get("file_diffs", {})
    if file_diffs:
        print("\nApplied Patches:")
        for fpath, diff in file_diffs.items():
            print(f"\n--- {fpath} ---")
            lines = diff.splitlines()
            print("\n".join(lines[:DIFF_PREVIEW_MAX_LINES]))
            if len(lines) > DIFF_PREVIEW_MAX_LINES:
                print(f"  ... (+ {len(lines) - DIFF_PREVIEW_MAX_LINES} more lines)")


def cmd_pipeline(args: argparse.Namespace) -> None:
    """Run complete end-to-end multi-agent pipeline (Git prep -> Scan -> Remediate -> PR)."""
    from agents.git_agent.config import GitAgentConfig, ProviderType
    from agents.remediator_agent.agent import RemediatorAgent
    from agents.scanner_agent.agent import ScannerAgent
    from orchestrator.pipeline import MultiAgentPipeline

    print("\n🚀 Executing Complete Autonomous Multi-Agent Pipeline (Headless CLI)")
    print(f"Target Repo: {args.repo_url}")
    print(f"LLM Engine:  Provider={args.llm or 'auto'}, Model={args.model or 'default'}")

    config = GitAgentConfig(
        repo_url=args.repo_url,
        token=args.token,
        provider=ProviderType(args.provider) if args.provider else ProviderType.GENERIC,
        base_branch=args.base_branch,
        feature_branch_name=args.feature_branch,
        workspace_dir=args.workspace_dir,
    )
    scanner = ScannerAgent()
    remediator = RemediatorAgent(
        llm_provider=args.llm,
        model=args.model,
        base_url=args.base_url,
    )
    pipeline = MultiAgentPipeline(git_config=config, scanner=scanner, remediator=remediator)
    res = pipeline.run_remediation_pipeline(
        provider=args.llm,
        model=args.model,
        base_url=args.base_url,
    )

    print("\n=======================================================")
    print("✅ Pipeline Successfully Completed")
    print(f"Repository:     {res.get('context', {}).get('repo_path')}")
    print(f"Feature Branch: {res.get('context', {}).get('feature_branch')}")
    print(f"PR Link:        {res.get('git_result', {}).get('pr_url')}")
    print("=======================================================")


def main() -> None:
    """Parse CLI arguments and dispatch the selected subcommand."""
    parser = argparse.ArgumentParser(
        prog="airgap-remediator",
        description="Autonomous Air-Gapped Security Scanner & Remediation Agent.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Prepare command
    prep_p = subparsers.add_parser("prepare", help="Clone repo or prepare local repo, pull/detect base branch, create feature branch")
    prep_p.add_argument("--repo-url", "-r", required=True, help="Repository URL (GitHub, GitLab, or local filesystem path)")
    prep_p.add_argument("--token", "-t", help="Personal Access Token (optional for local repositories)")
    prep_p.add_argument("--provider", "-p", choices=["github", "gitlab", "local", "generic"], help="Repository provider")
    prep_p.add_argument("--base-branch", "-b", help="Base branch (main/master)")
    prep_p.add_argument("--feature-branch", "-f", help="New feature branch name")
    prep_p.add_argument("--workspace-dir", "-w", help="Workspace directory destination")
    prep_p.set_defaults(func=cmd_prepare)

    # Scan command
    scan_p = subparsers.add_parser("scan", help="Scan a repository for SAST bugs, insecure configs, and external egress")
    scan_p.add_argument("--path", "-p", required=True, help="Path to local repository workspace to scan")
    scan_p.set_defaults(func=cmd_scan)

    # Remediate command
    rem_p = subparsers.add_parser("remediate", help="Run RemediatorAgent to patch vulnerabilities using Local or Cloud LLMs")
    rem_p.add_argument("--path", "-p", required=True, help="Path to local repository workspace")
    rem_p.add_argument("--llm", choices=["ollama", "local", "gemini", "openai", "claude", "rule-based"], help="LLM Provider")
    rem_p.add_argument("--model", "-m", help="Model name (e.g., qwen2.5-coder:3b)")
    rem_p.add_argument("--base-url", "-u", help="Local LLM endpoint (e.g. http://127.0.0.1:11434)")
    rem_p.set_defaults(func=cmd_remediate)

    # Full Pipeline command
    pipe_p = subparsers.add_parser("pipeline", help="Run full pipeline: Git Prepare -> Scan -> Remediate -> PR")
    pipe_p.add_argument("--repo-url", "-r", required=True, help="Repository URL or local directory")
    pipe_p.add_argument("--token", "-t", help="Access token (optional for local repos)")
    pipe_p.add_argument("--provider", "-p", choices=["github", "gitlab", "local", "generic"], help="Provider type")
    pipe_p.add_argument("--base-branch", "-b", help="Base branch")
    pipe_p.add_argument("--feature-branch", "-f", help="Feature branch name")
    pipe_p.add_argument("--workspace-dir", "-w", help="Workspace destination directory")
    pipe_p.add_argument("--llm", choices=["ollama", "local", "gemini", "openai", "claude", "rule-based"], help="LLM Provider")
    pipe_p.add_argument("--model", "-m", help="Model name (e.g. qwen2.5-coder:3b)")
    pipe_p.add_argument("--base-url", "-u", help="Local LLM endpoint")
    pipe_p.set_defaults(func=cmd_pipeline)

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

