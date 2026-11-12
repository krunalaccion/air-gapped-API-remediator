# Air-Gapped API Security Vulnerability Remediator
### Autonomous Multi-Agent Defense & Git SubAgent System for Air-Gapped Systems

A production-ready, autonomous multi-agent security remediation system designed to audit, isolate, and remediate unauthorized outbound API egress and SAST vulnerabilities within **air-gapped**, **zero-trust**, or **isolated network perimeters**. Coordinates **GitSubAgent**, **ScannerAgent**, **RemediatorAgent**, **BugFixerAgent**, and **BuildTester** across a 5-stage automated pipeline, providing both a unified Web Control Center and an official **Model Context Protocol (MCP)** server.

> 📖 **Full System Architecture Reference**: For deep architectural specifications, multi-agent fleet contracts, and exhaustive REST API specifications, see [AIR_GAPPED_API_SECURITY_REMEDIATOR.md](file:///Users/krunaldharamshi/Projects/GitAgent/AIR_GAPPED_API_SECURITY_REMEDIATOR.md).  
> 🧪 **QA Test Specification & Verification Guide**: For the complete QA test matrix, step-by-step test procedures, test data generation, and acceptance sign-off criteria, see [QA_DOCUMENTATION.md](file:///Users/krunaldharamshi/Projects/GitAgent/QA_DOCUMENTATION.md).

---

## 🌟 Key Capabilities & Features

- **Hybrid SAST & Air-Gap Egress Scanning (`ScannerAgent`)**:
  - Recursively audits source code (`.cs`, `.py`, `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.json`, `.yaml`, `.yml`, `.env`, `.config`, etc.) for unauthorized outbound HTTP/HTTPS calls, cloud SDK endpoints, and external telemetry (`AIRGAP-001`, `AIRGAP-002`, `AIRGAP-003`), automatically excluding dependency lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, etc.) and registry domains.
  - Multi-language heuristic SAST engines across **C#/.NET** and **Node.js / Express (`JavaScriptLexicalAnalyzer`)**: SQL Injection (`CWE-89`), OS Command Injection (`CWE-78`), Dynamic Code Evaluation (`CWE-95`), IDOR (`CWE-639`), Path Traversal (`CWE-22`), Auth Bypass (`CWE-287`), Hardcoded Secrets (`CWE-798`), Plaintext Passwords (`CWE-256`), Sensitive PII Exposure (`CWE-359`), Stack Trace Leakage (`CWE-209`), Permissive CORS (`CWE-942`), Prototype Pollution (`CWE-1321`), SSRF (`CWE-918`), Open Redirect (`CWE-601`), Insecure Deserialization (`DESERIAL-004`), and Deprecated Cryptography (`CRYPTO-007/008/009`).
  - Built-in integration with external industry scanners: offline **Semgrep** (`airgap_rules.yaml`, `nodejs_rules.yaml`) and **Trivy** CLI detection with automatic fallbacks (`/api/scanner/tools`).
  - Interactive **Security Scanner HTML/JSON Audit Report** generation (`/api/securescan/report?format=html`) with verified threat counts and compliance verdicts.

- **Autonomous Code Patching & Remediation Studio (`RemediatorAgent` & `BugFixerAgent`)**:
  - Dual-mode remediation: 100% offline deterministic rule-based fixers (`.NET/C#`, **Node.js/Express** via `js_fixer.py`, Python, Config/JSON — `AIR-GAP OFFLINE`) or local AI engines (**Local Ollama**, **Local OpenAI-compatible LLMs** such as LM Studio or vLLM).
  - Automatic **Local LLM / Ollama Model Discovery** (`/api/llm/models`): queries running Ollama (`/api/tags`), CLI (`ollama list`), local disk manifests (`~/.ollama/models/manifests`), or OpenAI-compatible `/v1/models` endpoints and populates an interactive model selector dropdown (`#llmModelSelect` / `#schedLlmModelSelect`) with model size/parameter metadata and custom-name fallback.
  - Remediates all detected security flaws and egress calls in C#, Python, and JS/TS codebases with zero residual threats verified on post-scan.
  - Injects compliant internal proxy routing (`config/airgap_proxy.json`) redirecting egress to `proxy.airgap.internal:8080` with offline mock fallbacks.
  - Interactive Web Studio with Queued Targets, Side-by-Side (Split) Diff, Unified Diff, and live code editing.
  - Automatic post-remediation verification scans updating posture scores (e.g. 100/100 A+).
  - Formal **Remediation & Compliance Dossier** (`REMEDIATION_AUDIT_REPORT.html`, `/api/remediator/report?format=html`) and **Send Report Now** email dispatch strictly gated until Step 03 completion.

- **Background Batch Folder Scheduler (`BatchScheduler` & `/scheduler`)**:
  - Scans an entire local directory (shallow or recursive, optionally auto-initializing non-Git folders) and runs **GitSubAgent -> ScannerAgent -> RemediatorAgent -> Commit/Push -> PR -> Email** sequentially across every repository.
  - Supports **Interval**, **Daily**, **Weekly**, **Cron** (`@daily`, `@hourly`, standard 5-field cron), and **One-Time** schedules persisted in `scheduler_data/`, with live progress telemetry and fast cooperative run cancellation (`/api/scheduler/runs/cancel`).
  - Automatically resolves clean base branches (`auto` -> `main` / `master`) before branching, supports **per-schedule remote push & Git auth** (`auto_push`, `git_token`, `git_username` with masked UI storage), and dispatches per-repository email reports immediately after each repository completes scan + remediation.

- **Email Report Notification Service (`EmailReportNotifier`)**:
  - Builds HTML and plain-text security remediation summaries, converts HTML audit reports into **PDF attachments** (`REMEDIATION_AUDIT_REPORT.pdf`, `SECURESCAN_REPORT.pdf`) alongside optional JSON payloads using [`orchestrator/pdf_renderer.py`](file:///Users/krunaldharamshi/Projects/GitAgent/orchestrator/pdf_renderer.py), and archives every dispatched message as an `.eml` file under `reports/email_outbox/`.
  - Supports both standard **SMTP (`STARTTLS`/`SSL`)** and **HTTPS Webhook (`EMAIL_WEBHOOK_URL`)** delivery over port 443 for firewall-restricted environments.
  - In the Single Repo Pipeline, email delivery buttons appear only after Step 03 remediation succeeds; in the Batch Scheduler, emails fire automatically per repository when enabled on the schedule.

- **Automated Ecosystem Build & Unit Test Verification (`BuildTester`)**:
  - Automatically identifies target repository ecosystem (.NET, Python, Node.js / TypeScript, Go, Rust, Java/Maven/Gradle).
  - Executes build compilation and unit test discovery on workspace isolation (Step 01) and on-demand (`/api/build-test`).
  - Emits real-time build and test execution results directly into the UI.

- **Repository Isolation & True Identity Tracking (`GitSubAgent`)**:
  - Clones or mounts repositories into ephemeral, quarantined quarantine workspaces without modifying original baseline files until approved.
  - Automatically detects and displays the main repository name (e.g., `CustomerApi`, `EnterpriseEmployeePortal`) rather than temporary path strings.
  - Resolves perimeter isolation status (`ISOLATED`).

- **Offline & Local Project Mode (`LocalProvider`) + Local Folder Remote Push**:
  - Full remediation support for local repositories **without any linked remote** (no GitHub/GitLab origin).
  - Auto-initializes plain directories into Git repositories on-demand (`auto_init: true`) with baseline commits and isolated feature branches.
  - Zero-internet operation for local filesystem projects (`repos/CustomerApi` or `/path/to/project`), creating file-based offline PR review manifests (`.git/local_prs/PR-*.md`).
  - **Remote Push & Auth for Local Folders**: When a local folder has a configured remote (`origin`), both the Single Repo Pipeline (optional Git Auth fields in Step 01 / Step 04) and Batch Scheduler (`auto_push`, `git_token`, `git_username`) support pushing remediation branches and creating remote GitHub/GitLab PRs using ephemeral masked credentials.

- **Remote Enterprise Git Providers (`GitHubProvider`, `GitLabProvider`)**:
  - Works with GitHub, GitLab (including self-hosted enterprise enclaves).
  - Raises automated Pull Requests / Merge Requests with draft options and security dossiers.
  - Safe credential management: tokens are masked in logs, scrubbed from process outputs, and kept out of persistent remote configurations.

- **Interactive Web Control Center (`web/index.html`, `web/scheduler.html`, `web_server.py` & `orchestrator/routes/`)**:
  - Single Repo Pipeline (`/`) with real-time Liveline visualizer tracking all 5 stages, plus dedicated Batch Folder Scheduler (`/scheduler`) with live active-run status indicator.
  - Dark Mode and Light Mode support with persistent user preferences.
  - Multi-browser and high-resolution touch icon support (Apple Touch Icons, standard SVG/PNG favicons).
  - Live repository file tree with real-time modified file pills, installed Ollama/local model dropdowns, and syntax viewing.
  - Modal filesystem picker with bookmarks and one-click demo loader (`repos/CustomerApi`).
  - Dynamic perimeter mode badges: Remote Git, Local Git (Unlinked), and Local Project (Auto-Init).

- **Model Context Protocol (MCP) Server**:
  - Full JSON-RPC 2.0 stdio server compliant with the MCP specification (2024-11-05).
  - Compatible with Claude Desktop, Cursor, and Google Antigravity.

- **Zero Mandatory External Dependencies**:
  - Core orchestrator, Git subagent, REST server, and rule-based remediator run entirely on standard Python 3.9+ without mandatory third-party `pip` packages.

---

## 📐 Architecture & Multi-Agent Flow

```
                      ┌──────────────────────────────────────────────┐
                      │    Multi-Agent Control Center (Web & REST)   │
                      │       / (Pipeline) & /scheduler (Batch)      │
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │ MultiAgentPipeline & BatchScheduler (Orch.)  │
                      └──────┬───────────────┬───────────────┬───────┘
                             │               │               │
                             │ Stage 1, 4, 5 │       Stage 2 │       Stage 3
                             ▼               ▼               ▼
                      ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
                      │ GitSubAgent │ │ScannerAgent │ │ Remediator  │
                      └──────┬──────┘ └──────┬──────┘ │ + Ollama/FX │
                             │               │        └──────┬──────┘
                             │               ▼               │
                             │       ┌──────────────┐        │
                             │       │ExternalScans │        │
                             │       │Semgrep/Trivy │        │
                             │       └──────────────┘        │
                             ▼                               ▼
                      ┌─────────────┐                 ┌──────────────┐
                      │ BuildTester │                 │ Reports &    │
                      │ (.NET/Py/JS)│                 │ EmailNotifier│
                      └─────────────┘                 └──────────────┘
                             │
               ┌─────────────┴─────────────┐
               ▼                           ▼
   ┌───────────────────────┐   ┌───────────────────────┐
   │  Remote Git Provider  │   │  Local Git Provider   │
   │  (GitHub / GitLab)    │   │ (Offline / Pushed)    │
   │  - Remote Pull/Merge  │   │ - Local PR Manifest   │
   │    Request API        │   │   (.git/local_prs/)   │
   └───────────────────────┘   └───────────────────────┘
```

### The 5-Stage Automated Liveline Workflow

1. **Step 01: Repository Isolation & Environment Initialization (`GitSubAgent` & `BuildTester`)**
   - Clones or checks out repository into an isolated quarantine workspace.
   - Detects default branch, creates dedicated remediation feature branch (`remediation/airgap-api-compliance`).
   - Runs automated ecosystem build and unit test discovery suite.
2. **Step 02: Security Scanner (`ScannerAgent`)**
   - Ingests workspace, executes deep regex/heuristic SAST and egress checks.
   - Runs Semgrep and Trivy tools if installed.
   - Generates interactive **Security Audit Report** (`/api/securescan/report?format=html`).
3. **Step 03: Autonomous Code Patching & Remediation (`RemediatorAgent` & `BugFixerAgent`)**
   - Queues findings from Step 02 in the interactive remediation studio.
   - Applies AST-accurate patches using rule-based or local AI LLM backends (Local Ollama, LM Studio / vLLM, Air-Gap Offline Rule Engine).
   - Injects proxy routes and mock interceptors for air-gap isolation.
   - Executes verification post-scan, confirms score (100/100 A+), and generates the **Remediation & Compliance Dossier**.
4. **Step 04: Patch Verification & Git Commit (`GitSubAgent`)**
   - Reviews working tree changes, diff statistics (+/- lines), and staged files.
   - Formulates automated, conventional-commit messages.
5. **Step 05: SecOps Compliance PR & Audit Evidence (`GitSubAgent`)**
   - Pushes branch to remote (GitHub/GitLab) or generates offline local PR manifest (`.git/local_prs/PR-*.md`).
   - Embeds complete compliance audit summary, security posture score, and verification checklist.

---

## 🚀 Quick Start

### 1. Prerequisites

- **Python**: Version 3.9 or higher (standard library only for core functionality).
- **Git**: Git CLI v2.x+ installed and available on `$PATH`.
- **Operating System**: macOS, Linux (Ubuntu, RHEL, Debian), or Windows.
- **Optional Tools**:
  - `ollama` (for local open-weights LLM inference, e.g., `qwen2.5-coder:3b`)
  - `semgrep`, `trivy` (for multi-engine scanner augmentation)
  - `dotnet`, `pytest`, `npm` (for automated build/test execution)

### 2. Configuration & Credentials

Set credentials via environment variables:

```bash
# GitHub Token
export GITHUB_TOKEN="ghp_yourPersonalAccessTokenHere"

# GitLab Token
export GITLAB_TOKEN="glpat-yourPersonalAccessTokenHere"

# General Token fallback
export GIT_AGENT_TOKEN="your-token"
```

Or configure using `git_agent_config.example.yaml`:

```yaml
repo_url: "https://github.com/my-org/my-service.git"
token: "ghp_xxxxxxxxxxxxxxxxxxxx"
provider: "github" # or "gitlab" / "local"
base_branch: "main" # or "master"
feature_branch_prefix: "remediation/airgap-compliance-"
author_name: "Security Remediation SubAgent"
author_email: "secagent@automation.local"
default_pr_title: "[Security] Automated vulnerability audit fixes"
draft_pr: false
```

### 3. Start the Web Control Center

Start the multi-agent control center server:

```bash
python3 web_server.py 8080
```

Open your browser to **`http://localhost:8080`**.

---

## 📡 Complete REST API Specification

The multi-threaded server (`web_server.py`) exposes REST endpoints across the Single Repo Pipeline, Local LLM Discovery, Email Notification Service, and Background Batch Scheduler:

| Method | Endpoint | Description | Request Payload / Params |
| :--- | :--- | :--- | :--- |
| `GET` | `/` or `/index.html` | Serves the Single Repo Multi-Agent Control Center UI | _(none)_ |
| `GET` | `/scheduler` or `/scheduler.html` | Serves the Background Batch Folder Scheduler UI | _(none)_ |
| `GET` | `/api/health` | Returns service health status, version, uptime, and registered agent count | _(none)_ |
| `GET` | `/api/telemetry` | Returns real-time state of all agents, workspace files, git status, PRs, and build status | _(none)_ |
| `GET` | `/api/agents` | Lists registered specialist agents and their operational status | _(none)_ |
| `GET` | `/api/scanner/tools` | Detects availability of external scanner CLIs (**Semgrep**, **Trivy**) | _(none)_ |
| `GET` | `/api/securescan/report` | Returns interactive HTML, JSON, or SARIF security scan audit report | `?format=html\|json\|sarif` |
| `GET` | `/api/llm/models` | Lists locally installed Ollama / OpenAI-compatible models (`/api/ollama/models` alias) | `?provider=ollama\|local&base_url=...` |
| `GET` | `/api/fix/progress` | Returns real-time file remediation progress during Step 03 | _(none)_ |
| `GET` | `/api/remediator/report` | Serves post-remediation **Remediation & Compliance Dossier** in HTML/JSON | `?format=html\|json` |
| `GET` | `/api/email/config` | Returns public email/SMTP/webhook notification config (masks password) | _(none)_ |
| `POST` | `/api/email/config` | Updates and persists email, SMTP, or webhook notification settings | `{"enabled", "smtp_host", "webhook_url", ...}` |
| `POST` | `/api/email/send-report` | Sends security remediation report email immediately with PDF/JSON attachments | `{"recipient_emails", "subject", "custom_note"}` |
| `GET` | `/api/email/outbox` | Lists recently archived `.eml` report messages in `reports/email_outbox/` | _(none)_ |
| `POST` | `/api/fs/list` | Lists subdirectories and quick-access bookmarks for repository selection | `{"path": "/path/to/dir"}` |
| `POST` | `/api/validate-path` | Validates if a filesystem directory exists, checks `.git` presence, and supports auto-init | `{"path": "/path/to/repo", "allow_non_git": true, "auto_init": false}` |
| `POST` | `/api/prepare` | Clones/mounts repository (or local folder with optional remote auth), provisions feature branch, runs build/test | `{"repo_url", "token", "username", "base_branch", "feature_branch", "auto_init"}` |
| `POST` | `/api/scan` | Runs SAST and air-gap egress scanner across workspace files | `{"workspace_path", "repo_url", "scanner_engine"}` |
| `POST` | `/api/fix` | Executes `RemediatorAgent` / `BugFixerAgent`, applies patches, and runs post-scan verification | `{"workspace_path", "provider", "model", "base_url"}` |
| `POST` | `/api/read-file` | Reads file content from active workspace | `{"relative_path": "src/app.py"}` |
| `POST` | `/api/write-file` | Saves custom code changes to workspace | `{"relative_path": "...", "content": "..."}` |
| `POST` | `/api/commit-push` | Stages modified files, creates conventional commit, and pushes branch (supports local-folder auth) | `{"commit_message", "files", "token", "username", "force"}` |
| `POST` | `/api/create-pr` | Creates remote GitHub PR, GitLab MR, or offline Local PR manifest | `{"title": "...", "description": "...", "draft": false}` |
| `POST` | `/api/build-test` | Runs automated compilation and test execution on active workspace | `{"workspace_path": "..."}` |
| `POST` | `/api/pipeline/run` | Executes 1-click end-to-end 5-stage remediation pipeline | _(none)_ |
| `POST` | `/api/bug-fixer/reset` | Resets workspace state, cleans findings cache, and re-initializes pipeline (`/api/reset-all` alias) | _(none)_ |
| `GET` | `/api/local-pr` | Retrieves Markdown content of generated offline Local PR review manifest | `?path=/path/to/PR-1.md` |
| `GET` | `/api/scheduler/overview` | Returns active run status, queue depth, schedules, and recent batch runs | _(none)_ |
| `POST` | `/api/scheduler/discover` | Scans a local folder for Git (and optional non-Git) repositories | `{"folder_path", "include_non_git", "recursive"}` |
| `GET` / `POST` | `/api/scheduler/schedules` | Lists all batch schedules (`GET`) or creates a new folder schedule (`POST`) | Schedule config JSON (cron/interval/auth/email) |
| `POST` | `/api/scheduler/schedules/update` | Updates an existing schedule (preserves masked `git_token` unless changed) | `{"id", ...}` |
| `POST` | `/api/scheduler/schedules/toggle` | Enables or disables a saved batch schedule | `{"id", "enabled"}` |
| `POST` | `/api/scheduler/schedules/delete` | Deletes a saved batch schedule | `{"id"}` |
| `POST` | `/api/scheduler/schedules/run-now` | Queues an immediate background batch run for a schedule | `{"id"}` |
| `GET` | `/api/scheduler/runs/detail` | Returns per-repo remediation status, push/PR links, and email dispatch results for a run | `?run_id=...` |
| `GET` | `/api/scheduler/runs/report` | Serves per-repo HTML or JSON scan/remediation report from a batch run | `?run_id=...&repo=...&type=remediation\|scanner` |
| `GET` | `/api/scheduler/runs/pr` | Retrieves generated Local PR Markdown for a repo within a batch run | `?run_id=...&repo=...` |
| `POST` | `/api/scheduler/runs/cancel` | Requests fast cooperative cancellation of an active or queued batch run | `{"run_id"}` |
| `POST` | `/api/scheduler/runs/clear` | Clears completed/failed/cancelled batch run history records | _(none)_ |

---

## 🤖 Python Subagent SDK Usage

You can embed `GitSubAgent`, `ScannerAgent`, and `RemediatorAgent` directly into Python multi-agent orchestration frameworks (LangGraph, AutoGen, CrewAI, or Google Antigravity):

```python
from agents.git_agent import GitSubAgent, GitAgentConfig, ProviderType
from agents.scanner_agent import ScannerAgent
from agents.remediator_agent import RemediatorAgent

# 1. Initialize Git SubAgent
config = GitAgentConfig(
    repo_url="/path/to/my-local-repo",
    provider=ProviderType.LOCAL,
    feature_branch_name="remediation/airgap-api-compliance",
)
git_agent = GitSubAgent(config)

# Phase 1: Isolate repository and create quarantine feature branch
ctx = git_agent.prepare_workspace()
print(f"Isolated Workspace: {ctx.repo_path} (Branch: {ctx.feature_branch})")

# Run automated build & test suite
build_res = git_agent.build_and_test()
print(f"Ecosystem: {build_res.get('ecosystem_name')} - Build: {build_res.get('build', {}).get('status')}")

# Phase 2: Execute Deep Security Scanner
scanner = ScannerAgent()
scan_results = scanner.run({"workspace_path": str(ctx.repo_path), "scanner_engine": "all"})
print(f"Scan Complete: {scan_results['total_findings']} vulnerabilities detected.")

# Phase 3: Autonomous Remediation (Air-Gap Offline or AI LLM)
remediator = RemediatorAgent()
fix_results = remediator.run({
    "workspace_path": str(ctx.repo_path),
    "provider": "ollama",
    "model": "qwen2.5-coder:3b",
})
print(f"Remediated: {len(fix_results.get('files_modified', []))} files modified.")

# Phase 4 & 5: Commit & Raise Local / Remote PR
final_result = git_agent.finalize_workspace(
    commit_message="fix(security): remediate SAST vulnerabilities and egress endpoints",
    pr_title="[Security] Air-Gap Egress & SAST Compliance Fixes",
    pr_body="Automated Pull Request generated by Air-Gapped API Security Remediator.",
)
print(f"PR Created: {final_result.pr.url}")
```

---

## 🔌 Model Context Protocol (MCP) Server

The system includes a production-grade Model Context Protocol (MCP) server communicating over JSON-RPC 2.0 stdio.

### Starting the Server

```bash
python3 -m agents.git_agent.mcp_server
```

Or via CLI:

```bash
python3 -m agents.git_agent.cli mcp
```

### Adding to Claude Desktop / Cursor / Antigravity

In your MCP configuration file (`claude_desktop_config.json` or Antigravity MCP settings):

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
| `git_prepare_repo` | Clones repo or opens local repo, detects default branch, provisions feature branch, and runs build verification | `repo_url`, `token`, `provider` (`github`, `gitlab`, `local`), `base_branch`, `feature_branch` |
| `git_status` | Inspects workspace file status (modified, staged, untracked) | _(none)_ |
| `git_diff` | Returns unified `git diff` of working tree or staged changes | `staged` (bool) |
| `git_read_file` | Reads source code from checked-out workspace for vulnerability analysis | `relative_path` |
| `git_write_file` | Writes/patches file in workspace with security remediations | `relative_path`, `content` |
| `git_commit_and_push` | Stages files, commits changes, and pushes/updates branch | `commit_message`, `files` |
| `git_create_pull_request` | Opens a Pull Request (GitHub), Merge Request (GitLab), or Local PR Manifest | `title`, `description`, `draft` |
| `git_finalize_audit` | **One-step workflow**: stages changes, commits, pushes, and creates PR/MR | `commit_message`, `pr_title`, `pr_body`, `draft` |

---

## 🛠️ CLI Usage

```bash
# 1. Prepare remote repository (GitHub/GitLab)
python3 -m agents.git_agent.cli prepare \
  --repo-url "https://github.com/my-org/service.git" \
  --token "ghp_xxxx" \
  --feature-branch "remediation/airgap-compliance"

# 2. Prepare local git repository in-place
python3 -m agents.git_agent.cli prepare \
  --repo-url "/path/to/my-local-repo" \
  --feature-branch "remediation/local-audit"

# 3. Launch MCP JSON-RPC Server
python3 -m agents.git_agent.cli mcp
```

---

## 🧪 Automated Testing & Verification

The codebase includes an exhaustive test suite covering all agent lifecycles, configuration handling, external scanner adapters, MCP JSON-RPC communication, multi-agent pipeline orchestration, git providers, report generators, and REST API handlers.

Run all automated unit and integration tests:

```bash
python3 -m unittest discover -s tests
```

Output:
```
----------------------------------------------------------------------
Ran 102 tests in 34.1s

OK
```

All **102 unit and integration tests** across **11 test modules** pass cleanly with a 100% pass rate.

---

## 🐳 Docker & Makefile Support

Run the application in a container or via `Makefile` shortcuts:

```bash
# Using Makefile
make install       # pip install .
make test          # Run full unittest suite
make run           # Start web server on port 8080

# Using Docker Compose
docker compose up --build
```

---

## 🔧 Troubleshooting & FAQ

| Issue | Likely Cause | Resolution |
| :--- | :--- | :--- |
| `Address already in use` on port `8080` | Another process is bound to `8080` | Pass an alternate port: `python3 web_server.py 8090` |
| Ollama models not listed or LLM fails | Ollama daemon is not running or offline | Start Ollama (`ollama serve`) or select `auto-fallback` / offline deterministic fixer |
| `git push` or PR creation rejected | Missing/expired PAT or insufficient repo scopes | Export `GITHUB_TOKEN` (with `repo` scope) or `GITLAB_TOKEN` (with `api` scope), or use Local PR mode |
| Email notifications not sent | Credentials still set to template placeholders | Copy `.env.example` to `.env`, set `EMAIL_ENABLED=true`, and configure SMTP or `EMAIL_WEBHOOK_URL` |
| Semgrep / Trivy shows unavailable | Optional scanner CLIs not installed on `$PATH` | Built-in C#, JS/TS, and air-gap egress scanners run automatically with zero external tools |

---

## 📄 License

Provided for internal security engineering and hackathon evaluation. See repository maintainers for distribution terms.
