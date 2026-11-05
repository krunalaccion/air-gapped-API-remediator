# Air-Gapped API Security Vulnerability Remediator
### Autonomous Multi-Agent Control Center & Git SubAgent System

A production-ready, autonomous multi-agent remediation system designed to audit, isolate, and remediate unauthorized outbound API egress within **air-gapped** or **zero-trust isolated network perimeters**. Coordinates **GitSubAgent**, **ScannerAgent**, and **RemediatorAgent** across a 5-stage automated pipeline, and provides both a unified Web Control Center and an official **Model Context Protocol (MCP)** server.

> 📖 **Full System Documentation**: For the complete architectural specification, multi-agent fleet contracts, and exhaustive REST API reference, see [AIR_GAPPED_API_SECURITY_REMEDIATOR.md](file:///Users/krunaldharamshi/Projects/GitAgent/AIR_GAPPED_API_SECURITY_REMEDIATOR.md).  
> 🧪 **QA Test Specification & Verification Guide**: For the complete QA test matrix, step-by-step test procedures, test data generation, and acceptance sign-off criteria, see [QA_DOCUMENTATION.md](file:///Users/krunaldharamshi/Projects/GitAgent/QA_DOCUMENTATION.md) (or open [QA_DOCUMENTATION.html](file:///Users/krunaldharamshi/Projects/GitAgent/QA_DOCUMENTATION.html) to print/export as PDF).

---

## 🌟 Key Capabilities & Features

- **Automated Air-Gap Egress Auditing**: Recursively scans codebases (`.py`, `.js`, `.ts`, `.json`, `.yaml`, `.yml`, `.env`, etc.) for hardcoded outbound HTTP/HTTPS calls, cloud SDK endpoints, and external telemetry (`ScannerAgent`).
- **Automated Proxy Routing & Offline Mocking**: Injects compliant internal gateway proxy configurations (`config/airgap_proxy.json`) redirecting egress to `proxy.airgap.internal:8080` and enables offline mock fallback interceptors (`RemediatorAgent`).
- **Automated Compliance Verification**: Produces formal isolation audit logs (`AIRGAP_SECURITY_AUDIT.md`) tracking remediated rules (`AIRGAP-001`, `AIRGAP-002`, `AIRGAP-003`) and compliance verification checklists.
- **Offline & Local Git Repository Mode**: Full in-place or cloned workflows for local git repos without requiring internet or remote API access, generating local PR review manifests (`.git/local_prs/PR-*.md`).
- **Multi-Platform Support**: Works seamlessly with **Local Folders**, **GitHub**, and **GitLab** (including self-hosted enterprise instances).
- **Interactive Web Control Center**: Real-time browser dashboard (`http://localhost:8080`) featuring dynamic agent discovery, 5-stage pipeline visualizer, folder picker modal, git validation, finding tables, patch editor, diff viewer, and inline PR review viewer.
- **Model Context Protocol (MCP) Server**: Full JSON-RPC 2.0 stdio server compliant with the MCP specification (2024-11-05), allowing Cursor, Claude Desktop, or Antigravity to operate the Git subagent directly.
- **Zero Mandatory External Dependencies**: Operates purely on the standard Python library (3.9+) — ideal for air-gapped enclaves without public internet access.
- **Credential Safety & Security**: Tokens are automatically masked in logs, scrubbed from stdout/stderr, and kept out of persistent git remotes.

---

## 📐 Architecture & Multi-Agent Flow

```
                      ┌─────────────────────────────────────────┐
                      │    Multi-Agent Control Center / API     │
                      │       http://localhost:8080             │
                      └────────────────────┬────────────────────┘
                                           │
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │   MultiAgentPipeline (Orchestrator)     │
                      └─────┬───────────────────┬───────────┬───┘
                            │                   │           │
     1. prepare_workspace() │   2. run() scan   │           │ 3. run() fix
     4. finalize_workspace()│                   │           │
                            ▼                   ▼           ▼
                      ┌───────────┐       ┌───────────┐┌───────────┐
                      │GitSubAgent│       │ScannerAgnt││Remediator │
                      └─────┬─────┘       └───────────┘└───────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
  ┌───────────────────────┐   ┌───────────────────────┐
  │  Remote Git Provider  │   │  Local Git Provider   │
  │  (GitHub / GitLab)    │   │ (Offline Filesystem)  │
  │  - Remote Pull/Merge  │   │ - Local PR Manifest   │
  │    Request API        │   │   (.git/local_prs/)   │
  └───────────────────────┘   └───────────────────────┘
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
| `git_prepare_repo` | Clones repo or opens local repo, pulls/detects `main`/`master`, and creates feature branch | `repo_url`, `token`, `provider` (`github`, `gitlab`, `local`), `base_branch`, `feature_branch` |
| `git_status` | Inspects workspace file status (modified, staged, untracked) | _(none)_ |
| `git_diff` | Returns `git diff` of working tree or staged changes | `staged` (bool) |
| `git_read_file` | Reads file from checked-out workspace for vulnerability scan | `relative_path` |
| `git_write_file` | Writes/patches file in workspace with security remediations | `relative_path`, `content` |
| `git_commit_and_push` | Stages files, commits changes, and pushes/updates branch | `commit_message`, `files` |
| `git_create_pull_request` | Opens a Pull Request (GitHub), Merge Request (GitLab), or Local Review PR | `title`, `description`, `draft` |
| `git_finalize_audit` | **One-step workflow**: commit all, push/update, and open PR/MR/Local PR | `commit_message`, `pr_title`, `pr_body`, `draft` |

---

## 🛠️ CLI Usage

```bash
# 1. Prepare remote repository (GitHub/GitLab)
python3 -m agents.git_agent.cli prepare \
  --repo-url "https://github.com/my-org/service.git" \
  --token "ghp_xxxx" \
  --feature-branch "audit/cve-2026-001"

# 2. Prepare local git repository directly in-place
python3 -m agents.git_agent.cli prepare \
  --repo-url "/path/to/my-local-repo" \
  --feature-branch "audit/local-scan"

# 3. Run MCP server
python3 -m agents.git_agent.cli mcp
```

---

## 🧪 Running Tests

Execute the full automated test suite:

```bash
python3 -m unittest discover -s tests
```

