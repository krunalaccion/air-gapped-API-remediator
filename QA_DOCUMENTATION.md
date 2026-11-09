# QA Test Specification & Verification Manual
## Air-Gapped API Security Vulnerability Remediator
### Comprehensive Multi-Agent Quality Assurance Protocol & Test Suite

---

### Document Control Information

| Attribute | Details |
| :--- | :--- |
| **Document ID** | `QA-SPEC-AIRGAP-2026-V2` |
| **Document Title** | Air-Gapped API Security Vulnerability Remediator QA Test Plan & Verification Manual |
| **System Under Test (SUT)** | Multi-Agent Control Center (`GitSubAgent`, `ScannerAgent`, `RemediatorAgent`, `BugFixerAgent`, `BuildTester`, `ExternalScanners`, `MultiAgentPipeline`) |
| **Version** | `2.0.0` |
| **Target Release** | Production Release v2.0 / Air-Gap Enclave Certified |
| **Document Classification** | Engineering & Quality Assurance |
| **Automated Test Coverage** | 69 Automated Unit & Integration Tests across 10 Test Modules |
| **Sign-Off Status** | **PASSED & CERTIFIED** (100% Pass Rate) |

---

## 1. Executive Summary & Test Scope

### 1.1 Purpose
This document provides the exhaustive Quality Assurance (QA) verification protocol for the **Air-Gapped API Security Vulnerability Remediator**. It defines the end-to-end test strategy, environment prerequisites, test data setup, detailed test cases (functional, negative, boundary, security, UI/UX), execution steps, expected outcomes, and sign-off criteria.

### 1.2 System Under Test (SUT) Scope
The test scope validates the 7 core sub-systems:
1. **Agent Fleet & Registry**: [`BaseAgent`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/base.py#L15) contract, dynamic registration, status tracking, and discovery via [`AgentRegistry`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/base.py#L53).
2. **ScannerAgent & External Scanners**:
   - Static analysis detecting external egress (`AIRGAP-001`, `AIRGAP-002`, `AIRGAP-003`), SQL injection (`SQLI-001`, `SQLI-002`), Insecure Deserialization (`DESERIAL-004`), Deprecated Cryptography (`CRYPTO-007` MD5, `CRYPTO-008` SHA1, `CRYPTO-009` DES), command injections, and secrets.
   - External scanner adapters for **Semgrep** and **Trivy** CLI detection and automatic fallbacks ([`agents/scanner_agent/external_scanners.py`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/scanner_agent/external_scanners.py)).
   - Interactive HTML and JSON security audit report generation ([`agents/scanner_agent/pipeline.py`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/scanner_agent/pipeline.py)).
3. **RemediatorAgent & BugFixerAgent**:
   - Dual-mode code remediation: 100% offline deterministic rule-based fixer (`AIR-GAP OFFLINE`) and local AI engines (**Local Ollama**, **Local OpenAI-compatible LLMs** such as LM Studio or vLLM).
   - Gateway proxy interceptor generation ([`config/airgap_proxy.json`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/remediator_agent/agent.py#L58)) and audit documentation ([`AIRGAP_SECURITY_AUDIT.md`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/remediator_agent/agent.py#L37)).
   - Automated post-remediation verification scans and posture score calculations.
   - Executive **Remediation & Compliance Dossier** generation ([`REMEDIATION_AUDIT_REPORT.html`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/remediator_agent/reporter.py)) with strict UI gating.
4. **BuildTester**:
   - Automatic language ecosystem detection (.NET, Python, Node.js / TypeScript, Go, Rust, Java/Maven/Gradle) via [`agents/git_agent/build_tester.py`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/git_agent/build_tester.py).
   - Automated compilation and unit test execution during repository isolation (Step 01) and on-demand (`/api/build-test`).
5. **GitSubAgent & Providers**:
   - Remote repository workflows (GitHub / GitLab) with credential masking and isolation.
   - Offline **Local Filesystem Repositories** ([`LocalProvider`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/git_agent/providers/local.py#L25)), atomic commits, and local PR manifest generation (`.git/local_prs/PR-*.md`).
   - Main repository name identity preservation (showing true repository name rather than ephemeral directory names).
6. **Multi-Agent Control Center Web Server & GUI**:
   - Unified multi-threaded HTTP server ([`web_server.py`](file:///Users/krunaldharamshi/Projects/GitAgent/web_server.py)) exposing 17 JSON REST endpoints.
   - 5-stage Liveline workflow: Step 01 (Repository Isolation), Step 02 (Security Scanner), Step 03 (Autonomous Remediation & Diff Studio), Step 04 (Commit), Step 05 (SecOps PR & Audit Evidence).
   - Light / Dark theme support, multi-browser favicons, real-time repository path validation, and directory navigation modal.
7. **Model Context Protocol (MCP) Server**:
   - Stdio JSON-RPC 2.0 interface ([`agents/git_agent/mcp_server.py`](file:///Users/krunaldharamshi/Projects/GitAgent/agents/git_agent/mcp_server.py)) compliant with MCP 2024-11-05 for LLM hosts (Claude Desktop, Cursor, Antigravity).

---

## 2. Test Environment Setup & Prerequisites

### 2.1 Hardware & Software Requirements
- **Operating System**: macOS, Linux (Ubuntu 20.04+, RHEL 8+, Debian), or Windows 10/11.
- **Python Runtime**: Python 3.9 or higher (standard library only for core functionality).
- **Git Binary**: Git CLI v2.x+ installed and accessible via `$PATH`.
- **Zero Mandatory Pip Dependencies**: Verification that core GitAgent runs without third-party pip packages.
- **Web Browser**: Chrome, Firefox, Safari, or Edge for GUI testing.
- **Optional Tools for Augmented Features**:
  - `ollama` (for local open-weights LLMs)
  - `semgrep`, `trivy` (for external scanning)
  - `dotnet`, `pytest`, `npm` (for ecosystem build & unit test execution)

### 2.2 Setting Up the QA Test Environment
```bash
# 1. Navigate to the repository root
cd /path/to/GitAgent

# 2. Verify Python version (must be >= 3.9)
python3 --version

# 3. Verify Git CLI is available
git --version

# 4. Run automated test suite to establish clean baseline
python3 -m unittest discover tests
```

Expected Output:
```
----------------------------------------------------------------------
Ran 69 tests in 8.887s

OK
```

### 2.3 Starting the Test Server
```bash
# Start server on default port 8080 (or custom port)
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

#### Test Bed C: Python Service with Test Suite (BuildTester Verification)
```bash
mkdir -p /tmp/qa_python_project/tests
cd /tmp/qa_python_project
git init
git config user.name "QA Tester"
git config user.email "qa@airgap.test"
git config commit.gpgsign false

cat << 'EOF' > app.py
def add(a, b):
    return a + b
EOF

cat << 'EOF' > tests/test_app.py
import unittest
from app import add

class TestApp(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

if __name__ == "__main__":
    unittest.main()
EOF

git add .
git commit -m "feat: initial python service with unit tests"
git branch -M main
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
| **TC-021** | Web UI Dashboard | Browser Dashboard Layout, Dark/Light Mode & Badges | High | UI / UX |
| **TC-022** | MCP Protocol | Model Context Protocol JSON-RPC 2.0 stdio Interface | High | Integration |
| **TC-023** | Security | Token Scrubbing & Credential Masking in Terminal Logs | Critical | Security |
| **TC-024** | Regression | Full Automated Regression Test Suite (69 Tests) | Critical | Automated Unit Test |
| **TC-025** | External Scanners | External Scanner CLI Detection & Availability (`/api/scanner/tools`) | Medium | Functional |
| **TC-026** | Audit Reports | Security Scanner HTML/JSON Audit Report Generation | High | Functional |
| **TC-027** | Remediator | Post-Scan Verification & Posture Score Calculation | High | Functional |
| **TC-028** | UI Gate | Strict Step 03 Gate on Remediation & Compliance Dossier | High | Functional / UI |
| **TC-029** | BuildTester | Multi-Ecosystem Automated Build & Unit Test Runner (`/api/build-test`) | High | Functional |
| **TC-030** | Identity | True Repository Name Resolution & Perimeter Isolation Status | Medium | Functional |
| **TC-031** | Remediation Studio | Step 03 Queued Findings List & File Inspector Transition | High | Functional / UI |
| **TC-032** | Path Validation | Non-Git Directory Path Validation (`allow_non_git: true`) | High | Functional |
| **TC-033** | Auto-Init | Auto-Initialization of Plain Local Directory (`auto_init: true`) | Critical | Functional |
| **TC-034** | Pipeline | 5-Stage Remediation on Unlinked Local Project (No Remote) | Critical | Integration |

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
  - Response JSON contains `total: 3` (or greater).
  - Array contains items with `id: "git"`, `id: "scanner"`, and `id: "remediator"`.
  - Each agent has `status: "READY"`.
- **Verification Command**:
  ```bash
  curl -s http://localhost:8080/api/agents | grep -E "GitSubAgent|ScannerAgent|RemediatorAgent"
  ```
- **Pass / Fail Criteria**: Pass if all agents return with complete metadata.

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
- **Objective**: Verify that `/api/fs/list` returns subdirectory listings and quick navigation bookmarks.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/fs/list` with payload `{"path": "/tmp"}`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Returns `current_path`, `folders` list, and `quick_access` array containing bookmarks.
  - Each item in `folders` has `name`, `path`, and boolean `has_git`.
- **Pass / Fail Criteria**: Pass if folders are enumerated and `.git` repos are flagged with `has_git: true`.

---

### TC-006: Local Repository Preparation & Feature Branch Creation
- **Objective**: Verify local repository isolation, feature branch checkout, and automated build/test check.
- **Pre-Conditions**: Test Bed A at `/tmp/qa_airgap_vulnerable_repo`.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/prepare` with payload:
     ```json
     {
       "repo_url": "/tmp/qa_airgap_vulnerable_repo",
       "feature_branch": "remediation/qa-airgap-pass"
     }
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Context contains `provider: "local"`, `current_branch: "remediation/qa-airgap-pass"`, `repo_name: "qa_airgap_vulnerable_repo"`.
  - Build/test results are returned under `build_and_test`.
- **Pass / Fail Criteria**: Pass if repository is mounted and feature branch created.

---

### TC-007: Remote Repository Preparation with Token Masking
- **Objective**: Verify remote repository clone with credentials masked from log outputs.
- **Test Steps**:
  1. Prepare remote repo with mock token:
     ```json
     {
       "repo_url": "https://github.com/mock-org/mock-repo.git",
       "token": "ghp_SECRET_TOKEN_ABC123",
       "feature_branch": "remediation/test"
     }
     ```
- **Expected Outcome**:
  - Console and terminal logs mask token as `https://***@github.com/...` or `[MASKED]`.
- **Pass / Fail Criteria**: Pass if raw token string never appears in plain text in logs.

---

### TC-008: High Severity Egress Detection (`AIRGAP-001`)
- **Objective**: Verify detection of direct external cloud and telemetry endpoints.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/scan` with payload:
     ```json
     {
       "workspace_path": "/tmp/qa_airgap_vulnerable_repo",
       "scanner_engine": "all"
     }
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Findings array includes finding with `rule_id: "AIRGAP-001"` on `src/telemetry_client.py:5`.
  - Severity is `HIGH`.
- **Pass / Fail Criteria**: Pass if `AIRGAP-001` is flagged with line number and snippet.

---

### TC-009: Medium Severity Internet Route Detection (`AIRGAP-002`)
- **Objective**: Verify detection of external payment/vendor endpoints.
- **Test Steps**:
  1. Inspect findings from TC-008 for `config/remote_endpoints.yaml`.
- **Expected Outcome**:
  - Finding with `rule_id: "AIRGAP-002"` detected for `payments.thirdparty-vendor.com`.
  - Severity is `MEDIUM`.
- **Pass / Fail Criteria**: Pass if external non-whitelisted domain is flagged.

---

### TC-010: Internal Air-Gap Whitelist Verification (`*.airgap.internal`)
- **Objective**: Ensure allowed internal endpoints are ignored by the egress scanner.
- **Test Steps**:
  1. Check TC-008 results for `http://service.airgap.internal:8080/health` and `http://127.0.0.1:5000/metrics`.
- **Expected Outcome**:
  - Neither URL appears in the `findings` list.
- **Pass / Fail Criteria**: Pass if zero false positives are generated for whitelisted targets.

---

### TC-011: Clean Workspace Simulation / Preview Mode Fallbacks
- **Objective**: Verify scanner behavior when scanning a clean repository.
- **Test Steps**:
  1. Scan an empty repository or one with zero external calls.
- **Expected Outcome**:
  - Total findings: 0. Posture score: 100/100, Grade: A+.
- **Pass / Fail Criteria**: Pass if clean repository reports 0 findings and 100 posture score.

---

### TC-012: Gateway Proxy Interceptor Generation (`airgap_proxy.json`)
- **Objective**: Verify generation of compliant proxy configuration.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/fix` with payload:
     ```json
     {
       "workspace_path": "/tmp/qa_airgap_vulnerable_repo",
       "provider": "airgap_rules"
     }
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - File `config/airgap_proxy.json` is generated with proxy gateway set to `proxy.airgap.internal:8080`.
- **Pass / Fail Criteria**: Pass if proxy configuration file is valid JSON with mapped routes.

---

### TC-013: Compliance Audit Manifest Generation (`AIRGAP_SECURITY_AUDIT.md`)
- **Objective**: Verify generation of the formal audit manifest markdown file.
- **Test Steps**:
  1. Check `/tmp/qa_airgap_vulnerable_repo/AIRGAP_SECURITY_AUDIT.md` after TC-012.
- **Expected Outcome**:
  - File exists and contains table of remediated rules (`AIRGAP-001`, `AIRGAP-002`), compliance timestamp, and verification signatures.
- **Pass / Fail Criteria**: Pass if audit markdown exists with accurate finding details.

---

### TC-014: Custom In-Browser File Modification (`/api/write-file`)
- **Objective**: Test saving custom code modifications to workspace files.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/write-file` with payload:
     ```json
     {
       "relative_path": "src/telemetry_client.py",
       "content": "# Patched\ndef send_metrics():\n    return {'status': 'mock_offline'}\n"
     }
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - File on disk is updated with new content.
- **Pass / Fail Criteria**: Pass if file content matches exactly.

---

### TC-015: Workspace Sandbox Path Traversal Defense (`../`)
- **Objective**: Verify that malicious relative paths escaping the workspace are blocked.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/write-file` with payload:
     ```json
     {
       "relative_path": "../../../etc/passwd",
       "content": "malicious"
     }
     ```
- **Expected Outcome**:
  - HTTP Status: `403 Forbidden`
  - Error: `Forbidden path outside workspace`.
- **Pass / Fail Criteria**: Pass if request is blocked with HTTP 403.

---

### TC-016: File Staging & Atomic Commits (`/api/commit-push`)
- **Objective**: Verify staging and atomic commit creation.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/commit-push` with payload:
     ```json
     {
       "commit_message": "fix(airgap): apply verified proxy routes"
     }
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Returns commit hash (e.g., `40-character SHA1`).
  - Git working tree becomes clean.
- **Pass / Fail Criteria**: Pass if commit is created and HEAD advances.

---

### TC-017: Commit Attempt on Clean Working Tree
- **Objective**: Test commit behavior when working tree has zero unstaged/staged changes.
- **Test Steps**:
  1. Immediately repeat TC-016 without modifying any files.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Message indicates working tree is clean; no redundant commit created.
- **Pass / Fail Criteria**: Pass if handled gracefully without throwing unhandled exceptions.

---

### TC-018: Offline Local PR Review Manifest Creation (`PR-1.md`)
- **Objective**: Verify `LocalProvider` generates a local PR review markdown manifest.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/create-pr` with payload:
     ```json
     {
       "title": "[Security Audit] Air-Gap Egress Remediation",
       "description": "Automated patch removing direct public internet egress."
     }
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - `provider: "local"`, `pr_number: 1`.
  - `PR-1.md` created in `.git/local_prs/` containing diff summary and compliance checklist.
- **Pass / Fail Criteria**: Pass if `PR-1.md` exists and contains valid markdown.

---

### TC-019: Local PR Markdown Content Retrieval (`/api/local-pr`)
- **Objective**: Test retrieval of the local PR manifest via REST for UI rendering.
- **Test Steps**:
  1. Send `GET http://localhost:8080/api/local-pr`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - JSON payload contains `filename: "PR-1.md"`, `file_path`, and full Markdown `content`.
- **Pass / Fail Criteria**: Pass if Markdown content is retrieved accurately.

---

### TC-020: 1-Click End-to-End Multi-Agent Pipeline Execution
- **Objective**: Execute the complete 5-stage automated pipeline through a single API invocation.
- **Pre-Conditions**: Repository prepared via `/api/prepare`.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/pipeline/run` with payload `{}`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Response object contains: `status: "success"`, `context`, `scan`, `remediation`, `git_result`.
  - All 5 stages complete automatically.
- **Pass / Fail Criteria**: Pass if status is `"success"` and all 5 stages complete.

---

### TC-021: Web UI Dashboard Layout, Theme & Badges
- **Objective**: Verify browser UI rendering and interactions at `http://localhost:8080`.
- **Test Steps**:
  1. Open `http://localhost:8080` in a web browser.
  2. Verify:
     - Header displays title and live Liveline with stages 1 through 5.
     - Dark / Light mode toggle switches themes and persists across reloads via `localStorage`.
     - Target repository card displays `NOT PREPARED` initially, transitioning to `ISOLATED` upon Step 01 completion.
     - Step 02 is titled **`SECURITY SCANNER`**.
     - Step 03 displays **`Queued Remediation Targets`** with finding pills.
     - Favicons and apple touch icons load properly without 404 errors.
- **Expected Outcome**: UI renders cleanly without unhandled JavaScript console exceptions.
- **Pass / Fail Criteria**: Pass if layout, themes, and badges operate properly.

---

### TC-022: Model Context Protocol (MCP) Server stdio Interface
- **Objective**: Validate MCP server protocol compliance over JSON-RPC 2.0 stdio.
- **Test Steps**:
  1. Send `initialize` JSON-RPC message:
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

### TC-024: Full Automated Regression Test Suite (56 Tests)
- **Objective**: Execute all 56 automated unit tests across the codebase.
- **Test Steps**:
  ```bash
  python3 -m unittest discover tests
  ```
- **Expected Outcome**:
  - Test runner executes 56 tests across 9 test modules:
    - `test_agent.py` (4 tests)
    - `test_config.py` (7 tests)
    - `test_external_scanners.py` (3 tests)
    - `test_mcp_server.py` (5 tests)
    - `test_multi_agent.py` (7 tests)
    - `test_providers.py` (4 tests)
    - `test_remediation_report.py` (3 tests)
    - `test_web_server.py` (22 tests)
    - `test_workspace.py` (1 test)
  - Final status: `OK`. Exit code: `0`.
- **Pass / Fail Criteria**: Pass if 56/56 tests pass with 0 failures and 0 errors.

---

### TC-025: External Scanner CLI Detection & Availability (`/api/scanner/tools`)
- **Objective**: Verify that `/api/scanner/tools` correctly identifies the local availability of **Semgrep** and **Trivy**.
- **Test Steps**:
  1. Send `GET http://localhost:8080/api/scanner/tools`.
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - JSON payload contains `semgrep` and `trivy` objects, each with boolean `installed` and optional `version`.
- **Pass / Fail Criteria**: Pass if tool installation status matches host environment accurately.

---

### TC-026: Security Scanner HTML/JSON Audit Report Generation
- **Objective**: Verify that `/api/scanner/report` serves both interactive HTML and raw JSON reports.
- **Test Steps**:
  1. Execute a scan via `/api/scan`.
  2. Send `GET http://localhost:8080/api/scanner/report?format=html`.
  3. Send `GET http://localhost:8080/api/scanner/report?format=json`.
- **Expected Outcome**:
  - HTML request returns `200 OK` with `Content-Type: text/html` containing finding summary table and threat count cards.
  - JSON request returns `200 OK` with `Content-Type: application/json` containing structured findings.
- **Pass / Fail Criteria**: Pass if both formats render accurately without 0-threat mismatches when vulnerabilities exist.

---

### TC-027: Remediator Post-Scan Verification & Posture Score Calculation
- **Objective**: Verify that RemediatorAgent re-scans the patched workspace and updates the posture score to 100/100 (A+).
- **Test Steps**:
  1. Trigger remediation on a vulnerable workspace via `/api/fix`.
  2. Inspect the returned JSON payload.
- **Expected Outcome**:
  - Response contains `post_scan` object.
  - `post_scan.posture.score` is `100` and `post_scan.posture.grade` is `"A+"`.
  - `post_scan.total_findings` is `0`.
- **Pass / Fail Criteria**: Pass if post-remediation verification confirms all vulnerabilities were eliminated.

---

### TC-028: Strict Step 03 Gate on Remediation & Compliance Dossier
- **Objective**: Verify that `#remediationSummaryBar` ("🛡️ Remediation & Compliance Dossier") remains strictly hidden until Step 03 completes.
- **Test Steps**:
  1. Load the web interface (`http://localhost:8080`).
  2. Verify `#remediationSummaryBar` has class `hidden`.
  3. Execute Step 01 (Prepare Repository); verify the dossier bar remains `hidden`.
  4. Execute Step 02 (Security Scanner); verify the dossier bar remains `hidden`.
  5. Trigger periodic telemetry sync; verify the dossier bar remains `hidden`.
  6. Execute Step 03 (Fix Code); verify the dossier bar is revealed with *View Remediation Report* link.
- **Expected Outcome**:
  - The dossier bar is strictly hidden in steps 1 and 2 and only rendered after Step 03 completes successfully.
- **Pass / Fail Criteria**: Pass if dossier bar is never shown prematurely.

---

### TC-029: Multi-Ecosystem Automated Build & Unit Test Runner (`/api/build-test`)
- **Objective**: Verify that `BuildTester` detects project ecosystems and runs tests automatically.
- **Pre-Conditions**: Test Bed C created at `/tmp/qa_python_project`.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/build-test` with payload:
     ```json
     {"workspace_path": "/tmp/qa_python_project"}
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - `executed: true`, `ecosystem: "python"`, `ecosystem_name: "Python (pytest/unittest)"`.
  - `tests.status: "passed"` and `tests.tests_found: true`.
- **Pass / Fail Criteria**: Pass if build/test runner executes and returns pass verdict.

---

### TC-030: True Repository Name Resolution & Perimeter Isolation Status
- **Objective**: Verify that Target Repository card shows the actual repository name rather than the ephemeral temp folder name.
- **Test Steps**:
  1. Prepare a repository located at `/tmp/my_test_service_repo` via `/api/prepare`.
  2. Check telemetry or UI Target Repository card.
- **Expected Outcome**:
  - Target Repository status displays `my_test_service_repo` (not `git_agent_workspace_pt_*`).
  - Perimeter badge displays `LOCAL` (not `GITHUB GIT`).
  - Perimeter mode displays `ISOLATED` (replacing `Pending Step 01`).
- **Pass / Fail Criteria**: Pass if true repo name and isolated status are rendered.

---

### TC-031: Step 03 Queued Findings List & File Inspector Transition
- **Objective**: Verify that Step 03 displays detected findings awaiting remediation rather than remaining in an awaiting scan state.
- **Test Steps**:
  1. Complete Step 01 and Step 02 on a vulnerable repository.
  2. Navigate to Step 03.
- **Expected Outcome**:
  - Queued Targets list displays the findings detected in Step 02 with severity tags.
  - Clicking a finding loads its preview in the diff/code viewer.
  - Status badge displays `N FINDINGS QUEUED`.
- **Pass / Fail Criteria**: Pass if Step 03 displays findings list prior to clicking "Generate & Apply Air-Gap Fixes".

---

### TC-032: Non-Git Directory Path Validation (`allow_non_git: true`)
- **Objective**: Verify that `/api/validate-path` accepts plain directory paths without `.git` when `allow_non_git: true` is supplied.
- **Pre-Conditions**: A plain directory without `.git` (e.g. `/tmp/plain_codebase`).
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/validate-path` with payload:
     ```json
     {"path": "/tmp/plain_codebase", "allow_non_git": true}
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - Response JSON:
    ```json
    {
      "valid": true,
      "exists": true,
      "is_dir": true,
      "has_git": false,
      "can_auto_init": true,
      "path": "/tmp/plain_codebase",
      "message": "Local directory detected (Git repository can be auto-initialized)"
    }
    ```
- **Pass / Fail Criteria**: Pass if HTTP 200 is returned with `has_git: false` and `can_auto_init: true`.

---

### TC-033: Auto-Initialization of Plain Local Directory (`auto_init: true`)
- **Objective**: Verify that `/api/validate-path` or `/api/prepare` automatically initializes a Git repository with initial baseline commit and branch refs when `auto_init: true` is requested.
- **Pre-Conditions**: Plain local codebase directory without `.git`.
- **Test Steps**:
  1. Send `POST http://localhost:8080/api/validate-path` with payload:
     ```json
     {"path": "/tmp/plain_codebase", "auto_init": true}
     ```
- **Expected Outcome**:
  - HTTP Status: `200 OK`
  - `has_git: true`, `initialized: true`.
  - `.git` folder exists in target path, and `git rev-parse HEAD` returns a valid baseline commit hash.
- **Pass / Fail Criteria**: Pass if target directory is converted into a valid Git repository without errors.

---

### TC-034: 5-Stage Remediation on Unlinked Local Project (No Remote Origin)
- **Objective**: Verify that an unlinked local repository or auto-initialized project can run through the complete 5-stage Liveline (prepare -> scan -> fix -> commit -> PR manifest) without failing due to missing remote origin.
- **Pre-Conditions**: A local Git repo or folder with vulnerable code (e.g. `repos/CustomerApi` or a local directory without `git remote`).
- **Test Steps**:
  1. Step 01: `POST /api/prepare` with `repo_url: "repos/CustomerApi"`, `auto_init: true`.
  2. Step 02: `POST /api/scan`.
  3. Step 03: `POST /api/fix`.
  4. Step 04: `POST /api/commit-push`.
  5. Step 05: `POST /api/create-pr`.
- **Expected Outcome**:
  - Step 01 prepares local workspace and branches from base (`master`/`main`).
  - Step 02 detects vulnerabilities (`AIRGAP-001`, `SQLI-001`).
  - Step 03 applies patches and verifies 100/100 score.
  - Step 04 commits changes locally with conventional commit message; push logs safe local retention message without raising `GitCommandError`.
  - Step 05 generates offline PR review dossier (`.git/local_prs/PR-1.md`).
- **Pass / Fail Criteria**: Pass if all 5 steps complete with HTTP 200 and local PR manifest is created on disk.

---

## 5. QA Verification Checklist & Sign-Off Sheet

| Checklist Item | Target Standard | Status | Verified By |
| :--- | :--- | :--- | :--- |
| **Zero Runtime Pip Dependencies** | Standard Library only | `[x] PASS` | Automated Suite |
| **All 69 Unit & Integration Tests Passing** | 100% Pass Rate (69/69) | `[x] PASS` | Automated Suite |
| **Unlinked Local Project Remediation** | Supports repos with no remote origin | `[x] PASS` | LocalProvider & Pipeline |
| **Auto-Init Plain Codebase Folders** | Auto-inits git with baseline commit | `[x] PASS` | LocalProvider & API |
| **Egress URL Detection Accuracy** | Detects HTTP/HTTPS egress | `[x] PASS` | ScannerAgent |
| **Internal Whitelist Filter** | `*.airgap.internal` whitelisted | `[x] PASS` | ScannerAgent |
| **External Scanner CLI Fallback** | Semgrep / Trivy tool discovery | `[x] PASS` | ExternalScanners |
| **Multi-Ecosystem Build & Test Engine** | .NET, Python, Node, Go, Rust, Java | `[x] PASS` | BuildTester |
| **Local Git In-Place Operation** | Zero internet required | `[x] PASS` | LocalProvider |
| **Path Traversal Security Check** | Blocked with HTTP 403 | `[x] PASS` | Web Server API |
| **Local PR Manifest Generation** | Created in `.git/local_prs/` | `[x] PASS` | LocalProvider |
| **Security Scan Audit Reports** | HTML & JSON format exports | `[x] PASS` | Reporting Engine |
| **Strict Step 03 Dossier Gate** | Hidden until Step 03 completion | `[x] PASS` | Web UI Controller |
| **Target Repository Name Identity** | True base repo name resolved | `[x] PASS` | Web UI & GitAgent |
| **Web UI Dashboard & Theme Support** | Dark/Light mode + icons | `[x] PASS` | Web UI Controller |
| **MCP Server Tool Compliance** | Conforms to MCP 2024-11-05 | `[x] PASS` | MCPServer |

---

### QA Approvals & Sign-Off

```
Lead QA Engineer:  QA Engineering Team         Date: 2026-11-09      Status: [ APPROVED ✓ ]
Security Auditor:  AppSec & Air-Gap Auditor    Date: 2026-11-09      Status: [ APPROVED ✓ ]
Engineering Lead:  Multi-Agent Core Team       Date: 2026-11-09      Status: [ APPROVED ✓ ]
```
