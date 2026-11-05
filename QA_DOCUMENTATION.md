# QA Test Specification & Verification Manual
## Air-Gapped API Security Vulnerability Remediator

---

### Document Control Information

| Attribute | Details |
| :--- | :--- |
| **Document ID** | `QA-SPEC-AIRGAP-2026-V1` |
| **Document Title** | Air-Gapped API Security Vulnerability Remediator QA Test Plan & Verification Manual |
| **System Under Test (SUT)** | Multi-Agent Control Center (`GitSubAgent`, `ScannerAgent`, `RemediatorAgent`, `MultiAgentPipeline`) |
| **Version** | `1.0.0` |
| **Target Release** | Production / Air-Gap Enclave Certified |
| **Document Classification** | Engineering & Quality Assurance |
| **QA Lead / Author** | QA Engineering Team |
| **Sign-Off Status** | Pending Execution |

---

## 1. Executive Summary & Test Scope

### 1.1 Purpose
This document provides the exhaustive Quality Assurance (QA) verification protocol for the **Air-Gapped API Security Vulnerability Remediator**. It defines the test strategy, environment prerequisites, test data setup, detailed test cases (functional, negative, boundary, security), execution steps, expected outcomes, and sign-off criteria.

### 1.2 System Under Test (SUT) Scope
The test scope validates the 4 core sub-systems:
1. **Agent Fleet & Registry**: [`BaseAgent`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/base.py#L15) contract, dynamic registration, status tracking, and discovery via [`AgentRegistry`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/base.py#L53).
2. **ScannerAgent**: Static regex analysis detecting external outbound HTTP/HTTPS URLs across 10+ file types, rule categorization (`AIRGAP-001`, `AIRGAP-002`, `AIRGAP-003`), severity scoring (`HIGH`, `MEDIUM`, `LOW`), and internal domain whitelisting (`*.airgap.internal`, `localhost`, `127.0.0.1`).
3. **RemediatorAgent**: Automated creation of internal proxy configurations ([`config/airgap_proxy.json`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/remediator_agent/agent.py#L58)) and audit documentation ([`AIRGAP_SECURITY_AUDIT.md`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/remediator_agent/agent.py#L37)).
4. **GitSubAgent & Providers**: Remote repository workflows (GitHub/GitLab) and completely offline **Local Filesystem Repositories** ([`LocalProvider`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/git_agent/providers/local.py#L25)), atomic commits, token masking, and local PR manifest generation (`.git/local_prs/PR-*.md`).
5. **Multi-Agent Control Center Web Server & GUI**: Unified threaded HTTP server ([`web_server.py`](file:///Users/krunaldharamshi/Projects/GitAgent/web_server.py)), 14 REST API routes, directory navigation, real-time `.git` validation, and interactive UI ([`web/index.html`](file:///Users/krunaldharamshi/Projects/GitAgent/web/index.html)).
6. **Model Context Protocol (MCP) Server**: Stdio JSON-RPC 2.0 interface ([`agents/git_agent/mcp_server.py`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/git_agent/mcp_server.py)) for LLM hosts.

---

## 2. Test Environment Setup & Prerequisites

### 2.1 Hardware & Software Requirements
- **Operating System**: macOS, Linux (Ubuntu 20.04+, RHEL 8+), or Windows 10/11
- **Python Runtime**: Python 3.9 or higher (standard library only)
- **Git Binary**: Git CLI v2.x+ installed and accessible via `$PATH`
- **Zero External Dependencies**: Verification that no third-party `pip` packages (`requests`, `pydantic`, etc.) are mandatory for standard runtime execution.
- **Web Browser**: Chrome, Firefox, Safari, or Edge for GUI testing.

### 2.2 Setting Up the QA Test Environment
```bash
# 1. Clone or navigate to the repository root
cd /path/to/GitAgent

# 2. Verify Python version (must be >= 3.9)
python3 --version

# 3. Verify Git CLI is available
git --version

# 4. Run automated unit test suite to establish clean baseline
python3 -m unittest discover -s tests
```

### 2.3 Starting the Test Server
```bash
# Start server on default port 8080 (or custom port like 8085)
python3 web_server.py 8080
```
Verify the server prints:
```
=======================================================
🤖 Multi-Agent Control Center running at:
👉 http://localhost:8080
📁 Serving common UI from: .../web
=======================================================
```

### 2.4 Generating QA Test Repositories (Test Data Bed)

#### Test Bed A: Vulnerable Local Git Repository with Egress Violations
Execute this shell snippet to generate a sample vulnerable repository for offline testing:
```bash
mkdir -p /tmp/qa_airgap_vulnerable_repo
cd /tmp/qa_airgap_vulnerable_repo
git init
git config user.name "QA Tester"
git config user.email "qa@airgap.test"
git config commit.gpgsign false

# 1. Create file triggering Rule AIRGAP-001 (HIGH: api/cloud/aws/telemetry)
mkdir -p src
cat << 'EOF' > src/telemetry_client.py
import requests

def send_metrics():
    # HIGH severity egress
    url = "https://api.external-cloud.com/v1/telemetry"
    return requests.post(url, json={"status": "active"})
EOF

# 2. Create file triggering Rule AIRGAP-002 (MEDIUM: non-whitelisted domain)
mkdir -p config
cat << 'EOF' > config/remote_endpoints.yaml
endpoints:
  billing_service: "https://payments.thirdparty-vendor.com/v2/checkout"
  allowed_internal: "http://service.airgap.internal:8080/health"
  allowed_local: "http://127.0.0.1:5000/metrics"
EOF

# 3. Initial commit
git add .
git commit -m "feat: initial service implementation with external endpoints"
git branch -M main
```

#### Test Bed B: Non-Git Directory (Negative Testing)
```bash
mkdir -p /tmp/qa_plain_directory
echo "Not a git repo" > /tmp/qa_plain_directory/sample.txt
```

---

## 3. QA Test Execution Matrix

| Test ID | Module / Category | Test Case Title | Severity | Type |
| :--- | :--- | :--- | :--- | :--- |
| **TC-001** | Agent Fleet | Dynamic Agent Registry Discovery (`/api/agents`) | High | Functional |
| **TC-002** | Path Validation | Real-Time Git Repository Validation - Valid Repo | High | Functional |
| **TC-003** | Path Validation | Real-Time Git Repository Validation - Non-Git Directory | High | Negative |
| **TC-004** | Path Validation | Real-Time Git Repository Validation - Non-Existent Path | Medium | Negative |
| **TC-005** | Filesystem Explorer | Directory Listing & Quick Bookmarks (`/api/fs/list`) | Medium | Functional |
| **TC-006** | Repo Setup | Local Repository Preparation & Feature Branch Creation | Critical | Functional |
| **TC-007** | Repo Setup | Remote Repository Preparation with Token Masking | Critical | Security / Functional |
| **TC-008** | Egress Scanner | High Severity Egress Detection (`AIRGAP-001`) | Critical | Security / Functional |
| **TC-009** | Egress Scanner | Medium Severity Internet Route Detection (`AIRGAP-002`) | High | Security / Functional |
| **TC-010** | Egress Scanner | Internal Air-Gap Whitelist Verification (`*.airgap.internal`) | Critical | Security / Functional |
| **TC-011** | Egress Scanner | Clean Workspace Simulation / Preview Mode Fallbacks | Medium | Functional |
| **TC-012** | Remediator | Gateway Proxy Interceptor Generation (`airgap_proxy.json`)| Critical | Functional |
| **TC-013** | Remediator | Compliance Audit Manifest Generation (`AIRGAP_SECURITY_AUDIT.md`) | High | Functional |
| **TC-014** | Workspace Editor | Custom In-Browser File Modification (`/api/write-file`) | High | Functional |
| **TC-015** | Security Boundary | Workspace Sandbox Path Traversal Defense (`../`) | Critical | Security / Negative |
| **TC-016** | Git Lifecycle | File Staging & Atomic Commits (`/api/commit-push`) | High | Functional |
| **TC-017** | Git Lifecycle | Commit Attempt on Clean Working Tree | Low | Boundary |
| **TC-018** | PR Delivery | Offline Local PR Review Manifest Creation (`PR-1.md`) | Critical | Functional |
| **TC-019** | PR Delivery | Local PR Markdown Content Retrieval (`/api/local-pr`) | High | Functional |
| **TC-020** | Pipeline | 1-Click End-to-End Multi-Agent Pipeline Execution | Critical | Integration |
| **TC-021** | Web UI Dashboard | Browser Dashboard Layout, Badges & Interactive Controls | High | UI / UX |
| **TC-022** | MCP Protocol | Model Context Protocol JSON-RPC 2.0 stdio Interface | High | Integration |
| **TC-023** | Security | Token Scrubbing & Credential Masking in Terminal Logs | Critical | Security |
| **TC-024** | Regression | Full Automated Regression Test Suite Execution | Critical | Automated Unit Test |

---

## 4. Detailed Test Cases & Step-by-Step Procedures

---

### TC-001: Dynamic Agent Registry Discovery (`/api/agents`)
- **Objective**: Verify that all core specialist agents are properly registered in `AgentRegistry` and discoverable via REST.
- **Pre-Conditions**: Web server running on `http://localhost:8080`.
- **Test Steps**:
  1. Send `GET http://localhost:8080/api/agents`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Response JSON contains `total: 3` (or greater if custom agents are loaded).
  - Array contains items with `id: "git"`, `id: "scanner"`, and `id: "remediator"`.
  - Each agent has `status: "READY"`.
- **Verification Command**:
  ```bash
  curl -s http://localhost:8080/api/agents | grep -E "GitSubAgent|ScannerAgent|RemediatorAgent"
  ```
- **Pass / Fail Criteria**: Pass if all 3 agents return with complete metadata.

---

### TC-002: Real-Time Git Repository Validation - Valid Local Repo
- **Objective**: Verify that `/api/validate-path` correctly confirms a valid local git repository.
- **Pre-Conditions**: Test Bed A created at `/tmp/qa_airgap_vulnerable_repo`.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/validate-path` with payload:
     ```json
     {"path": "/tmp/qa_airgap_vulnerable_repo"}
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - JSON payload:
    ```json
    {
      "valid": true,
      "exists": true,
      "is_dir": true,
      "has_git": true,
      "path": "/tmp/qa_airgap_vulnerable_repo",
      "message": "Valid Git repository detected at /tmp/qa_airgap_vulnerable_repo"
    }
    ```
- **Pass / Fail Criteria**: Pass if `valid: true` and `has_git: true`.

---

### TC-003: Real-Time Git Repository Validation - Non-Git Directory (Negative)
- **Objective**: Ensure the system rejects standard directories lacking `.git`.
- **Pre-Conditions**: Test Bed B created at `/tmp/qa_plain_directory`.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/validate-path` with payload:
     ```json
     {"path": "/tmp/qa_plain_directory"}
     ```
- **Expected Outcome**:
  - HTTP Status: `400 Bad Request`
  - JSON payload:
    ```json
    {
      "valid": false,
      "exists": true,
      "is_dir": true,
      "has_git": false,
      "path": "/tmp/qa_plain_directory",
      "error": "Selected path '/tmp/qa_plain_directory' is not a Git repository (missing '.git' directory)."
    }
    ```
- **Pass / Fail Criteria**: Pass if HTTP 400 is returned with explicit error message.

---

### TC-004: Real-Time Git Repository Validation - Non-Existent Path (Negative)
- **Objective**: Validate behavior when an invalid or non-existent path is submitted.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/validate-path` with payload:
     ```json
     {"path": "/tmp/does_not_exist_9999"}
     ```
- **Expected Outcome**:
  - HTTP Status: `400 Bad Request`
  - JSON: `valid: false`, `exists: false`, error string indicating path does not exist.
- **Pass / Fail Criteria**: Pass if HTTP 400 and `exists: false`.

---

### TC-005: Filesystem Explorer & Quick Bookmarks (`/api/fs/list`)
- **Objective**: Verify that `/api/fs/list` returns subdirectory listings and quick navigation bookmarks for macOS/Linux.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/fs/list` with payload `{"path": "/tmp"}`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Returns `current_path`, `folders` list, and `quick_access` array containing bookmarks (e.g. Home, Workspace, Projects, Documents).
  - Each item in `folders` has `name`, `path`, and boolean `has_git`.
- **Pass / Fail Criteria**: Pass if folders are enumerated and `.git` repos are flagged with `has_git: true`.

---

### TC-006: Local Repository Preparation & Feature Branching
- **Objective**: Ensure `GitSubAgent` correctly binds to a local repository and checks out an isolated feature branch.
- **Pre-Conditions**: Test Bed A ready at `/tmp/qa_airgap_vulnerable_repo`.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/prepare` with payload:
     ```json
     {
       "repo_url": "/tmp/qa_airgap_vulnerable_repo",
       "feature_branch": "airgap/qa-remediation-pass-1",
       "provider": "local"
     }
     ```
  2. In terminal, inspect `/tmp/qa_airgap_vulnerable_repo`:
     ```bash
     cd /tmp/qa_airgap_vulnerable_repo && git branch --show-current
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Response includes `context.repo_path` and `context.feature_branch: "airgap/qa-remediation-pass-1"`.
  - Current git branch on disk switches to `airgap/qa-remediation-pass-1`.
- **Pass / Fail Criteria**: Pass if branch on disk matches `airgap/qa-remediation-pass-1`.

---

### TC-007: Remote Repository Preparation with Token Masking
- **Objective**: Validate remote repository handling and ensure credentials are never exposed in plaintext logs.
- **Pre-Conditions**: Valid GitHub PAT or mock remote.
- **Test Steps**:
  1. Prepare a remote repo with a token:
     ```bash
     curl -s -X POST http://localhost:8080/api/prepare \
       -H "Content-Type: application/json" \
       -d '{"repo_url": "https://github.com/mock-org/service.git", "token": "ghp_SECRET_TOKEN_12345"}'
     ```
  2. Inspect server terminal logs.
- **Expected Outcome**:
  - The token string `ghp_SECRET_TOKEN_12345` is scrubbed/masked as `ghp_***` or removed.
  - Subprocess execution strips token parameters.
- **Pass / Fail Criteria**: Pass if token is masked across all outputs.

---

### TC-008: Egress Vulnerability Detection (`AIRGAP-001` - High Severity)
- **Objective**: Verify that `ScannerAgent` detects outbound API calls containing `api`, `cloud`, `aws`, or `telemetry`.
- **Pre-Conditions**: Workspace prepared on Test Bed A.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/scan` with payload `{}`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - `status: "completed"`
  - `findings` list contains a finding for `src/telemetry_client.py`:
    - `id: "AIRGAP-001"`
    - `severity: "HIGH"`
    - `rule: "External Egress API Call"`
    - `description` references `https://api.external-cloud.com/v1/telemetry`
    - `recommendation` directs to `http://proxy.airgap.internal:8080`.
- **Pass / Fail Criteria**: Pass if `AIRGAP-001` is classified as `HIGH` severity.

---

### TC-009: Outbound Route Detection (`AIRGAP-002` - Medium Severity)
- **Objective**: Verify detection of direct internet route in config files.
- **Pre-Conditions**: Workspace prepared on Test Bed A.
- **Test Steps**:
  1. Examine findings from `/api/scan`.
- **Expected Outcome**:
  - `findings` list contains an entry for `config/remote_endpoints.yaml`:
    - `rule: "External Egress API Call"` or `Direct Internet Route`
    - Identifies `https://payments.thirdparty-vendor.com/v2/checkout`
- **Pass / Fail Criteria**: Pass if non-whitelisted URL in config file is flagged.

---

### TC-010: Internal Air-Gap Whitelist Verification
- **Objective**: Ensure internal airgap endpoints and localhost are NOT flagged as violations.
- **Pre-Conditions**: Test Bed A contains `http://service.airgap.internal:8080/health` and `http://127.0.0.1:5000/metrics`.
- **Test Steps**:
  1. Search findings from `/api/scan` for `service.airgap.internal` or `127.0.0.1`.
- **Expected Outcome**:
  - Neither `service.airgap.internal` nor `127.0.0.1` appear in the `findings` list.
- **Pass / Fail Criteria**: Pass if zero whitelisted endpoints appear in findings.

---

### TC-011: Clean Workspace Preview Mode Fallbacks
- **Objective**: Verify that scanning an uninitialized workspace returns preview simulation findings so the UI remains interactive.
- **Pre-Conditions**: Restart web server without calling `/api/prepare`.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/scan`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Returns fallback findings (`AIRGAP-001`, `AIRGAP-002`, `AIRGAP-003`).
  - `mode: "preview"`.
- **Pass / Fail Criteria**: Pass if HTTP 200 with preview mode flag.

---

### TC-012: Gateway Proxy Interceptor Generation (`config/airgap_proxy.json`)
- **Objective**: Verify `RemediatorAgent` generates a valid proxy configuration file.
- **Pre-Conditions**: Repository prepared on Test Bed A.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/fix` with payload `{}`.
  2. Verify file on disk at `/tmp/qa_airgap_vulnerable_repo/config/airgap_proxy.json`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - File exists and contains valid JSON:
    - `airgap_mode: true`
    - `proxy_host: "proxy.airgap.internal"`
    - `proxy_port: 8080`
    - `allowed_internal_domains` contains `"*.airgap.internal"`, `"localhost"`, `"127.0.0.1"`
    - `mock_responses_enabled: true`
    - `remediation_status: "COMPLIANT"`
- **Pass / Fail Criteria**: Pass if JSON schema and keys match specification.

---

### TC-013: Compliance Audit Manifest Generation (`AIRGAP_SECURITY_AUDIT.md`)
- **Objective**: Verify `RemediatorAgent` writes the formal security audit log.
- **Pre-Conditions**: Test Bed A fixed via `/api/fix`.
- **Test Steps**:
  1. Read `/tmp/qa_airgap_vulnerable_repo/AIRGAP_SECURITY_AUDIT.md`.
- **Expected Outcome**:
  - File exists at repository root.
  - Contains executive summary, rule remediation entries (`AIRGAP-001`, `AIRGAP-002`, `AIRGAP-003`), and 4-point verification checklist.
- **Pass / Fail Criteria**: Pass if file exists and contains checklist items.

---

### TC-014: Custom In-Browser File Modification (`/api/write-file`)
- **Objective**: Test manual patch injection through the control center.
- **Pre-Conditions**: Workspace prepared on Test Bed A.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/write-file` with payload:
     ```json
     {
       "relative_path": "src/telemetry_client.py",
       "content": "# Remediated\nimport os\nPROXY = os.getenv('AIRGAP_PROXY', 'http://proxy.airgap.internal:8080')\n"
     }
     ```
  2. Read `/tmp/qa_airgap_vulnerable_repo/src/telemetry_client.py`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - File content on disk matches the new content.
  - Response contains updated git status and non-empty `diff`.
- **Pass / Fail Criteria**: Pass if file is written accurately and diff is returned.

---

### TC-015: Sandbox Path Traversal Defense (`../`) (Security Negative)
- **Objective**: Ensure `/api/write-file` strictly rejects attempts to write outside the workspace.
- **Pre-Conditions**: Workspace prepared on Test Bed A.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/write-file` with payload:
     ```json
     {
       "relative_path": "../../../tmp/escaped_file.txt",
       "content": "Malicious payload"
     }
     ```
- **Expected Outcome**:
  - HTTP Status: `403 Forbidden`
  - Response: `{"error": "Forbidden path outside workspace"}`
  - No file is created at `/tmp/escaped_file.txt`.
- **Pass / Fail Criteria**: Pass if HTTP 403 is returned and filesystem escape is blocked.

---

### TC-016: File Staging & Atomic Commits (`/api/commit-push`)
- **Objective**: Validate staging of uncommitted remediations and commit authoring.
- **Pre-Conditions**: Uncommitted changes present from TC-012, TC-013, TC-014.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/commit-push` with payload:
     ```json
     {
       "commit_message": "fix(airgap): redirect outbound egress to internal proxy"
     }
     ```
  2. Inspect git log on disk:
     ```bash
     cd /tmp/qa_airgap_vulnerable_repo && git log -1 --pretty=format:"%s | %an <%ae>"
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Response contains `commit_hash` and updated branch name.
  - Git log confirms commit message matches and author attribution is set.
- **Pass / Fail Criteria**: Pass if commit exists in git history with working tree clean.

---

### TC-017: Commit Attempt on Clean Working Tree (Boundary)
- **Objective**: Verify behavior when `/api/commit-push` is triggered with zero uncommitted changes.
- **Pre-Conditions**: Working tree is clean following TC-016.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/commit-push` with payload:
     ```json
     {"commit_message": "test redundant commit"}
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Response message indicates: `Working tree clean. Updated local branch...`
  - No empty commit is created.
- **Pass / Fail Criteria**: Pass if handled gracefully without throwing an error.

---

### TC-018: Offline Local PR Review Manifest Creation (`PR-1.md`)
- **Objective**: Verify `LocalProvider` generates a local PR review markdown manifest.
- **Pre-Conditions**: Commits authored on feature branch in Test Bed A.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/create-pr` with payload:
     ```json
     {
       "title": "[Security Audit] Air-Gap Egress Remediation",
       "description": "Automated patch removing direct public internet egress."
     }
     ```
  2. Check `/tmp/qa_airgap_vulnerable_repo/.git/local_prs/PR-1.md`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - `provider: "local"`
  - `pr_number: 1`
  - `pr_url` format: `file:///tmp/qa_airgap_vulnerable_repo/.git/local_prs/PR-1.md`
  - The markdown file exists on disk and includes commit hashes, branch comparisons (`airgap/qa-remediation-pass-1` -> `main`), and diff summary.
- **Pass / Fail Criteria**: Pass if `PR-1.md` is generated on disk with valid review content.

---

### TC-019: Local PR Markdown Content Retrieval (`/api/local-pr`)
- **Objective**: Test retrieval of the local PR manifest via REST for UI rendering.
- **Pre-Conditions**: `PR-1.md` created in TC-018.
- **Test Steps**:
  1. Send `GET http://localhost:8080/api/local-pr`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - JSON payload contains `filename: "PR-1.md"`, `file_path`, and full Markdown `content`.
- **Pass / Fail Criteria**: Pass if Markdown content is retrieved accurately.

---

### TC-020: 1-Click End-to-End Multi-Agent Pipeline Execution
- **Objective**: Execute the complete 5-stage automated pipeline through a single API invocation.
- **Pre-Conditions**:
  - Fresh local test repository prepared at `/tmp/qa_pipeline_test`.
  - Prepare repo via `/api/prepare`.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/pipeline/run` with payload `{}`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Response object contains keys: `status: "success"`, `context`, `scan`, `remediation`, `git_result`.
  - `config/airgap_proxy.json` and `AIRGAP_SECURITY_AUDIT.md` exist and are committed.
  - PR manifest `PR-1.md` is generated.
- **Pass / Fail Criteria**: Pass if status is `"success"` and all 5 stages complete.

---

### TC-021: Web UI Dashboard Functional Validation
- **Objective**: Verify browser UI rendering and interactions at `http://localhost:8080`.
- **Test Steps**:
  1. Open `http://localhost:8080` in a web browser.
  2. Verify:
     - Header shows: `Multi-Agent Control Center`, `Multi-Agent Model`, `Air-Gap Perimeter`.
     - Connected Agent Fleet shows 3 cards (`GitSubAgent`, `ScannerAgent`, `RemediatorAgent`).
     - Click **"📁 Select Folder"** button; verify directory browser modal opens.
     - Select a folder and confirm real-time validation pill shows green checkmark.
     - Click **"⚡ Run End-to-End Pipeline"**; verify progress tags update from `READY` → `RUNNING` → `COMPLETED`.
     - Click **"View Diff"**; verify diff viewer displays working tree changes.
     - Click **"📄 View Local PR Review"**; verify modal displays rendered markdown.
- **Expected Outcome**: UI is completely responsive without unhandled JavaScript exceptions in Developer Console.
- **Pass / Fail Criteria**: Pass if all visual elements render and modal interactions operate cleanly.

---

### TC-022: Model Context Protocol (MCP) Server stdio Interface
- **Objective**: Validate MCP server protocol compliance over JSON-RPC 2.0 stdio.
- **Test Steps**:
  1. Run the MCP server in a subprocess and send an `initialize` JSON-RPC message:
     ```bash
     echo '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}' | python3 -m agents.git_agent.mcp_server
     ```
  2. Send `tools/list` message:
     ```bash
     echo '{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}' | python3 -m agents.git_agent.mcp_server
     ```
- **Expected Outcome**:
  - Response 1 returns `protocolVersion: "2024-11-05"`.
  - Response 2 lists the 8 MCP tools (`git_prepare_repo`, `git_status`, `git_diff`, `git_read_file`, `git_write_file`, `git_commit_and_push`, `git_create_pull_request`, `git_finalize_audit`).
- **Pass / Fail Criteria**: Pass if JSON-RPC 2.0 schema is strictly respected.

---

### TC-023: Credential Masking in Terminal Output
- **Objective**: Confirm that tokens are scrubbed from standard error and exception traces.
- **Test Steps**:
  1. Trigger an intentional git failure using a fake token URL.
  2. Check stdout and stderr logs.
- **Expected Outcome**:
  - Raw token strings do NOT appear in plain text.
- **Pass / Fail Criteria**: Pass if zero raw token occurrences exist in logged streams.

---

### TC-024: Full Automated Regression Test Suite
- **Objective**: Execute all 45 automated unit tests across the codebase.
- **Test Steps**:
  ```bash
  python3 -m unittest discover -s tests
  ```
- **Expected Outcome**:
  - Test runner executes 45 tests.
  - Final status: `OK`.
  - Exit code: `0`.
- **Pass / Fail Criteria**: Pass if 45/45 tests pass with 0 failures and 0 errors.

---

## 5. QA Verification Checklist & Sign-Off Sheet

| Checklist Item | Target Standard | Status | Verified By |
| :--- | :--- | :--- | :--- |
| **Zero Runtime Pip Dependencies** | Standard Library only | `[ ] PASS / [ ] FAIL` | ____________ |
| **All 45 Unit Tests Passing** | 100% Pass Rate | `[ ] PASS / [ ] FAIL` | ____________ |
| **Egress URL Detection Accuracy** | Detects HTTP/HTTPS egress | `[ ] PASS / [ ] FAIL` | ____________ |
| **Internal Whitelist Filter** | `*.airgap.internal` whitelisted | `[ ] PASS / [ ] FAIL` | ____________ |
| **Local Git In-Place Operation** | Zero internet required | `[ ] PASS / [ ] FAIL` | ____________ |
| **Path Traversal Security Check** | Blocked with HTTP 403 | `[ ] PASS / [ ] FAIL` | ____________ |
| **Local PR Manifest Generation** | Created in `.git/local_prs/` | `[ ] PASS / [ ] FAIL` | ____________ |
| **Web UI Dashboard Accessibility** | Compatible with modern browsers | `[ ] PASS / [ ] FAIL` | ____________ |
| **MCP Server Tool Compliance** | Conforms to MCP 2024-11-05 | `[ ] PASS / [ ] FAIL` | ____________ |

### QA Approvals & Sign-Off

```
Lead QA Engineer: _________________________    Date: ______________  Status: [ APPROVED ]
Security Auditor: _________________________    Date: ______________  Status: [ APPROVED ]
Engineering Lead: _________________________    Date: ______________  Status: [ APPROVED ]
```

