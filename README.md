# Configurable Git SubAgent & MCP Server

A modular, production-ready Git subagent designed to be injected into multi-agent systems (e.g. for vulnerability scanning, automated remediation, code reviews, and dependency updates) or run as a standalone **Model Context Protocol (MCP)** server.

---

## 🌟 Key Features

- **Multi-Platform Support**: Works seamlessly with **GitHub** and **GitLab** (including GitHub Enterprise and self-hosted GitLab).
- **Configurable Credentials & URLs**: HTTPS and SSH URLs, Personal Access Tokens (PAT), OAuth tokens, environment variables (`GITHUB_TOKEN`, `GITLAB_TOKEN`, `GIT_AGENT_TOKEN`).
- **Automated Branch Lifecycle**: Auto-detects remote base branch (`main` or `master`), pulls latest changes, and provisions dedicated feature branches (e.g., `agent/vuln-audit-20261102-113000`).
- **Designed for Subagent Injection**: Clean, programmatic lifecycle hooks (`prepare_workspace()`, `finalize_workspace()`) so parent multi-agent orchestrators can easily pass the cloned repository to specialized auditing agents (e.g. Semgrep, Bandit, LLM security reviewers).
- **Automated Pull & Merge Requests**: Commits remediation work with customizable author attribution and raises GitHub Pull Requests or GitLab Merge Requests via official REST APIs.
- **Model Context Protocol (MCP) Server**: Full JSON-RPC 2.0 stdio server compliant with the MCP specification (2024-11-05), enabling any MCP-compatible AI agent or host (Claude Desktop, Cursor, Antigravity) to control Git operations as native tools.
- **Credential Safety & Security**: Tokens are automatically masked in logs, scrubbed from stdout/stderr, and kept out of persistent git remotes.

---

## 📐 Architecture & Multi-Agent Flow

```
                     ┌─────────────────────────────────────────┐
                     │        Multi-Agent Orchestrator         │
                     └────────────┬─────────────────────────────┘
                                  │
          1. prepare_workspace()  │  3. finalize_workspace()
          (Clone base & branch)   │  (Commit & Open PR/MR)
                                  ▼
                     ┌─────────────────────────┐
                     │       GitSubAgent       │
                     └────────────┬────────────┘
                                  │
                                  │ Cloned Repo Path
                                  ▼
                     ┌─────────────────────────┐
                     │   Vulnerability Agent   │
                     │  (Audit, Patch & Fix)   │
                     └─────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Requirements

- Python 3.9+
- Standard `git` CLI (version 2.x+)
- Zero mandatory external Python dependencies (pure Python standard library for core git and REST operations).

### 2. Configuration Options

Set credentials via environment variables, `.env`, or configuration files:

```bash
# GitHub
export GITHUB_TOKEN="ghp_yourPersonalAccessTokenHere"

# GitLab
export GITLAB_TOKEN="glpat-yourPersonalAccessTokenHere"

# Or general token
export GIT_AGENT_TOKEN="your-token"
```

You can also use a YAML or JSON configuration file (see `git_agent_config.example.yaml`):

```yaml
repo_url: "https://github.com/my-org/my-service.git"
token: "ghp_xxxxxxxxxxxxxxxxxxxx"
provider: "github" # or "gitlab"
base_branch: "main" # or "auto"
feature_branch_prefix: "agent/security-audit-"
author_name: "Security Remediation SubAgent"
author_email: "secagent@automation.local"
default_pr_title: "[Security] Automated vulnerability audit fixes"
draft_pr: false
```

---

## 🤖 Injecting as a Subagent in a Multi-Agent System

Here is how you inject `GitSubAgent` into your parent multi-agent system:

```python
from agents.git_agent import GitSubAgent, GitAgentConfig, ProviderType

# 1. Configure the subagent
config = GitAgentConfig(
    repo_url="https://github.com/my-org/web-service.git",
    token="ghp_xxxxxxxxxxxx",
    feature_branch_prefix="sec-audit/",
)
git_subagent = GitSubAgent(config)

# ====================================================================
# PHASE 1: Workspace Preparation
# ====================================================================
# Clones repo, pulls main/master, and creates a new feature branch
context = git_subagent.prepare_workspace()
print(f"Workspace Path: {context.repo_path}")
print(f"Base Branch:    {context.base_branch}")
print(f"Feature Branch: {context.feature_branch}")

# ====================================================================
# PHASE 2: Downstream Specialist Agent (e.g. Vulnerability Scanner)
# ====================================================================
# The specialist agent works directly in `context.repo_path`
# (e.g., runs Semgrep/Trivy, patches insecure code, writes reports)
with open(context.repo_path / "SECURITY_AUDIT.md", "w") as f:
    f.write("# Security Audit Complete\nPatched SQL injection vulnerability.")

# ====================================================================
# PHASE 3: Workspace Finalization & PR Creation
# ====================================================================
# Commits all changes, pushes feature branch, and raises PR/MR
result = git_subagent.finalize_workspace(
    commit_message="fix(sec): patch SQL injection and update audit report",
    pr_title="[Security] Automated Vulnerability Remediation",
    pr_body="Automated PR generated after security scanning detected vulnerabilities.",
)

print(f"Status:   {result.status}")
print(f"Commit:   {result.commit_hash}")
print(f"PR URL:   {result.pr.url}")
print(f"PR #:     {result.pr.number}")
```

See [orchestrator/pipeline.py](file:///Users/krunaldharamshi/Projects/GitAgent/orchestrator/pipeline.py) for a runnable end-to-end multi-agent pipeline example.

---

## 🌐 Common Multi-Agent Web Dashboard

Start the common Multi-Agent Control Center:

```bash
python3 web_server.py 8080
```

---

## 🔌 Running as an MCP Server

The Git SubAgent includes a Model Context Protocol (MCP) server running over JSON-RPC stdio.

### Start the MCP Server

```bash
python3 -m agents.git_agent.mcp_server
# or using the CLI command:
git-agent mcp
```

### Adding to Claude Desktop / Cursor / Antigravity

In your MCP settings (e.g. `claude_desktop_config.json` or Antigravity MCP settings):

```json
{
  "mcpServers": {
    "git-agent": {
      "command": "python3",
      "args": ["-m", "agents.git_agent.mcp_server"],
      "cwd": "/path/to/GitAgent",
      "env": {
        "GITHUB_TOKEN": "ghp_yourTokenHere",
        "GITLAB_TOKEN": "glpat-yourTokenHere"
      }
    }
  }
}
```

### Available MCP Tools

| Tool Name | Description | Key Arguments |
| :--- | :--- | :--- |
| `git_prepare_repo` | Clones repo, pulls `main`/`master`, and creates feature branch | `repo_url`, `token`, `provider`, `base_branch`, `feature_branch` |
| `git_status` | Inspects workspace file status (modified, staged, untracked) | _(none)_ |
| `git_diff` | Returns `git diff` of working tree or staged changes | `staged` (bool) |
| `git_read_file` | Reads file from checked-out workspace for vulnerability scan | `relative_path` |
| `git_write_file` | Writes/patches file in workspace with security remediations | `relative_path`, `content` |
| `git_commit_and_push` | Stages files, commits changes, and pushes branch to remote | `commit_message`, `files` |
| `git_create_pull_request` | Opens a Pull Request (GitHub) or Merge Request (GitLab) | `title`, `description`, `draft` |
| `git_finalize_audit` | **One-step workflow**: commit all, push, and open PR/MR | `commit_message`, `pr_title`, `pr_body`, `draft` |

---

## 🛠️ CLI Usage

```bash
# Prepare repository and feature branch
python3 -m agents.git_agent.cli prepare \
  --repo-url "https://github.com/my-org/service.git" \
  --token "ghp_xxxx" \
  --feature-branch "audit/cve-2026-001"

# Run MCP server
python3 -m agents.git_agent.cli mcp
```

---

## 🧪 Running Tests

Execute the full automated test suite:

```bash
python3 -m unittest discover -s tests
```

