"""
Build and Unit Test Execution Engine for Isolated Quarantine Workspaces.
Automatically detects repository project ecosystem, compiles/builds code,
and executes unit test suites if present.
"""

from __future__ import annotations
import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("git_agent.build_tester")


def _find_binary(name: str, fallback_paths: Optional[List[Path]] = None) -> Optional[str]:
    """Finds an executable binary in PATH or specified fallback locations."""
    found = shutil.which(name)
    if found:
        return found
    if fallback_paths:
        for p in fallback_paths:
            if p.exists() and (os.access(p, os.X_OK) or p.is_file()):
                return str(p)
    return None


def _find_dotnet_binary() -> Optional[str]:
    """Locates the dotnet CLI binary."""
    fallbacks = [
        Path("/usr/local/share/dotnet/dotnet"),
        Path("/opt/homebrew/bin/dotnet"),
        Path("/usr/bin/dotnet"),
        Path.home() / ".dotnet" / "dotnet",
        Path("C:/Program Files/dotnet/dotnet.exe"),
    ]
    return _find_binary("dotnet", fallbacks)


def _check_dotnet_has_sdk(dotnet_bin: str) -> bool:
    """Verifies whether the dotnet host has any .NET SDKs installed."""
    try:
        proc = subprocess.run([dotnet_bin, "--list-sdks"], capture_output=True, text=True, timeout=5)
        return proc.returncode == 0 and bool(proc.stdout.strip())
    except Exception:
        return False


def _run_command(cmd: List[str], cwd: Path, timeout: int = 60) -> Tuple[int, str, str, float]:
    """Executes a command and returns (exit_code, stdout, stderr, duration_seconds)."""
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration = round(time.time() - start, 2)
        return proc.returncode, proc.stdout or "", proc.stderr or "", duration
    except subprocess.TimeoutExpired as te:
        duration = round(time.time() - start, 2)
        out = te.stdout.decode("utf-8", errors="replace") if isinstance(te.stdout, bytes) else (te.stdout or "")
        err = te.stderr.decode("utf-8", errors="replace") if isinstance(te.stderr, bytes) else (te.stderr or "")
        return -1, out, err + f"\n[TIMEOUT] Command timed out after {timeout} seconds", duration
    except Exception as exc:
        duration = round(time.time() - start, 2)
        return -1, "", str(exc), duration


def _parse_python_test_output(output: str) -> Dict[str, int]:
    """Parses test counts from pytest or unittest output."""
    res = {"passed": 0, "failed": 0, "skipped": 0}
    # pytest style: 5 passed, 1 skipped, 2 failed
    p_match = re.search(r"(\d+)\s+passed", output)
    f_match = re.search(r"(\d+)\s+failed", output)
    s_match = re.search(r"(\d+)\s+skipped", output)
    if p_match:
        res["passed"] = int(p_match.group(1))
    if f_match:
        res["failed"] = int(f_match.group(1))
    if s_match:
        res["skipped"] = int(s_match.group(1))

    # unittest style: Ran 12 tests in 0.05s
    ran_match = re.search(r"Ran\s+(\d+)\s+tests?", output)
    if ran_match:
        total = int(ran_match.group(1))
        fail_match = re.search(r"failures=(\d+)", output)
        err_match = re.search(r"errors=(\d+)", output)
        skip_match = re.search(r"skipped=(\d+)", output)
        fails = (int(fail_match.group(1)) if fail_match else 0) + (int(err_match.group(1)) if err_match else 0)
        skips = int(skip_match.group(1)) if skip_match else 0
        res["failed"] = max(res["failed"], fails)
        res["skipped"] = max(res["skipped"], skips)
        res["passed"] = max(res["passed"], max(0, total - fails - skips))
    return res


def _parse_dotnet_test_output(output: str) -> Dict[str, int]:
    """Parses test counts from dotnet test output."""
    res = {"passed": 0, "failed": 0, "skipped": 0}
    # Format: Passed: 5, Failed: 0, Skipped: 0, Total: 5
    m_pass = re.search(r"Passed:\s*(\d+)", output, re.IGNORECASE)
    m_fail = re.search(r"Failed:\s*(\d+)", output, re.IGNORECASE)
    m_skip = re.search(r"Skipped:\s*(\d+)", output, re.IGNORECASE)
    if m_pass:
        res["passed"] = int(m_pass.group(1))
    if m_fail:
        res["failed"] = int(m_fail.group(1))
    if m_skip:
        res["skipped"] = int(m_skip.group(1))
    return res


def run_build_and_tests(workspace_path: Path | str, timeout: int = 60) -> Dict[str, Any]:
    """
    Analyzes the workspace directory, determines the project ecosystem,
    executes build commands, and runs any discovered unit tests.
    """
    ws = Path(workspace_path).resolve()
    if not ws.exists() or not ws.is_dir():
        return {
            "executed": False,
            "error": f"Workspace directory does not exist: {ws}",
            "ecosystem": "unknown",
            "ecosystem_name": "Unknown",
            "build": {"status": "skipped", "summary": "Workspace path does not exist"},
            "tests": {"status": "skipped", "tests_found": False, "summary": "Workspace path does not exist"},
            "summary": "Workspace not found",
        }

    # 1. Detect ecosystem
    sln_files = list(ws.glob("*.sln")) + list(ws.glob("*/*.sln"))
    csproj_files = [f for f in ws.glob("**/*.csproj") if "node_modules" not in str(f)]
    pkg_json = ws / "package.json"
    py_files = [f for f in ws.glob("**/*.py") if not any(x in str(f) for x in [".venv", "venv", "__pycache__"])]
    go_mod = ws / "go.mod"
    cargo_toml = ws / "Cargo.toml"
    pom_xml = ws / "pom.xml"
    build_gradle = ws / "build.gradle"
    makefile = ws / "Makefile"

    # =========================================================================
    # Ecosystem 1: .NET / C#
    # =========================================================================
    if sln_files or csproj_files:
        dotnet_bin = _find_dotnet_binary()
        project_label = sln_files[0].name if sln_files else csproj_files[0].name
        target_path = sln_files[0] if sln_files else csproj_files[0]

        build_res: Dict[str, Any] = {
            "executed": True,
            "command": f"dotnet build {project_label}",
            "status": "pending",
            "summary": "",
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "duration_sec": 0.0,
        }
        test_res: Dict[str, Any] = {
            "executed": False,
            "tests_found": False,
            "command": "",
            "status": "pending",
            "summary": "",
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "duration_sec": 0.0,
        }

        if not dotnet_bin:
            build_res["status"] = "skipped"
            build_res["summary"] = "dotnet CLI not installed on host machine"
            test_res["status"] = "skipped"
            test_res["summary"] = "dotnet CLI not installed on host machine"
            return {
                "executed": True,
                "ecosystem": "dotnet",
                "ecosystem_name": ".NET (C#)",
                "target_project": project_label,
                "build": build_res,
                "tests": test_res,
                "summary": f".NET project detected ({project_label}) • dotnet CLI not found",
            }

        has_sdk = _check_dotnet_has_sdk(dotnet_bin)
        if not has_sdk:
            build_res["status"] = "skipped"
            build_res["summary"] = "No .NET SDKs installed on system"
            test_res["status"] = "skipped"
            test_res["summary"] = "No .NET SDKs installed on system"
            return {
                "executed": True,
                "ecosystem": "dotnet",
                "ecosystem_name": ".NET (C#)",
                "target_project": project_label,
                "build": build_res,
                "tests": test_res,
                "summary": f".NET project detected ({project_label}) • SDK not installed",
            }

        # Run dotnet build
        code, out, err, dur = _run_command([dotnet_bin, "build", "--nologo", str(target_path)], cwd=ws, timeout=timeout)
        build_res["exit_code"] = code
        build_res["stdout"] = out
        build_res["stderr"] = err
        build_res["duration_sec"] = dur
        if code == 0:
            build_res["status"] = "passed"
            build_res["summary"] = f"Build succeeded in {dur}s"
        else:
            build_res["status"] = "failed"
            build_res["summary"] = f"Build failed with exit code {code}"

        # Look for unit test projects
        test_projects = [
            cp for cp in csproj_files
            if any(term in cp.name.lower() for term in ["test", "tests", "spec", "specs"])
        ]
        if test_projects or "test" in target_path.name.lower():
            test_target = test_projects[0] if test_projects else target_path
            test_res["executed"] = True
            test_res["tests_found"] = True
            test_res["command"] = f"dotnet test {test_target.name}"
            t_code, t_out, t_err, t_dur = _run_command(
                [dotnet_bin, "test", "--nologo", str(test_target)], cwd=ws, timeout=timeout
            )
            test_res["exit_code"] = t_code
            test_res["stdout"] = t_out
            test_res["stderr"] = t_err
            test_res["duration_sec"] = t_dur
            counts = _parse_dotnet_test_output(t_out)
            test_res["passed"] = counts["passed"]
            test_res["failed"] = counts["failed"]
            test_res["skipped"] = counts["skipped"]
            if t_code == 0:
                test_res["status"] = "passed"
                test_res["summary"] = f"{counts['passed']} test(s) passed in {t_dur}s"
            else:
                test_res["status"] = "failed"
                test_res["summary"] = f"Tests failed: {counts['failed']} failure(s) in {t_dur}s"
        else:
            test_res["executed"] = False
            test_res["tests_found"] = False
            test_res["status"] = "no_tests_found"
            test_res["summary"] = "No test project (*.Tests.csproj) detected"

        summary = f"Build: {build_res['status'].upper()} • Tests: {test_res['status'].upper()}"
        return {
            "executed": True,
            "ecosystem": "dotnet",
            "ecosystem_name": ".NET (C#)",
            "target_project": project_label,
            "build": build_res,
            "tests": test_res,
            "summary": summary,
        }

    # =========================================================
    # Ecosystem 2: Node.js / TypeScript (npm)
    # =========================================================
    if pkg_json.exists():
        npm_bin = _find_binary("npm", [Path("/usr/local/bin/npm"), Path("/opt/homebrew/bin/npm")])
        scripts = {}
        try:
            pkg_data = json.loads(pkg_json.read_text(encoding="utf-8"))
            scripts = pkg_data.get("scripts", {})
        except Exception:
            pass

        build_res = {
            "executed": False,
            "command": "",
            "status": "not_required",
            "summary": "No 'build' script defined in package.json",
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "duration_sec": 0.0,
        }
        test_res = {
            "executed": False,
            "tests_found": False,
            "command": "",
            "status": "no_tests_found",
            "summary": "No 'test' script defined in package.json",
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "duration_sec": 0.0,
        }

        if npm_bin and "build" in scripts:
            build_res["executed"] = True
            build_res["command"] = "npm run build"
            code, out, err, dur = _run_command([npm_bin, "run", "build"], cwd=ws, timeout=timeout)
            build_res["exit_code"] = code
            build_res["stdout"] = out
            build_res["stderr"] = err
            build_res["duration_sec"] = dur
            build_res["status"] = "passed" if code == 0 else "failed"
            build_res["summary"] = f"npm build {'succeeded' if code == 0 else 'failed'} in {dur}s"

        if npm_bin and "test" in scripts:
            t_cmd = scripts["test"]
            if "no test specified" not in t_cmd.lower():
                test_res["executed"] = True
                test_res["tests_found"] = True
                test_res["command"] = "npm test"
                code, out, err, dur = _run_command([npm_bin, "test"], cwd=ws, timeout=timeout)
                test_res["exit_code"] = code
                test_res["stdout"] = out
                test_res["stderr"] = err
                test_res["duration_sec"] = dur
                test_res["status"] = "passed" if code == 0 else "failed"
                test_res["summary"] = f"npm test {'passed' if code == 0 else 'failed'} in {dur}s"

        return {
            "executed": True,
            "ecosystem": "nodejs",
            "ecosystem_name": "Node.js (npm)",
            "target_project": "package.json",
            "build": build_res,
            "tests": test_res,
            "summary": f"Build: {build_res['status'].upper()} • Tests: {test_res['status'].upper()}",
        }

    # =========================================================
    # Ecosystem 3: Python
    # =========================================================
    if py_files or (ws / "requirements.txt").exists() or (ws / "pyproject.toml").exists():
        python_bin = _find_binary("python3", [Path("/usr/bin/python3"), Path("/usr/local/bin/python3")]) or "python3"

        # Compilation / Syntax Check
        c_code, c_out, c_err, c_dur = _run_command([python_bin, "-m", "compileall", "-q", "."], cwd=ws, timeout=timeout)
        build_res = {
            "executed": True,
            "command": "python3 -m compileall -q .",
            "status": "passed" if c_code == 0 else "failed",
            "summary": f"Python syntax check {'passed (0 errors)' if c_code == 0 else 'failed'} in {c_dur}s",
            "stdout": c_out,
            "stderr": c_err,
            "exit_code": c_code,
            "duration_sec": c_dur,
        }

        # Look for test files
        test_files = [
            f for f in ws.glob("**/*.py")
            if (f.name.startswith("test_") or f.name.endswith("_test.py"))
            and not any(x in str(f) for x in [".venv", "venv", "__pycache__"])
        ]
        test_dir = ws / "tests" if (ws / "tests").is_dir() else (ws / "test" if (ws / "test").is_dir() else None)

        test_res = {
            "executed": False,
            "tests_found": bool(test_files or test_dir),
            "command": "",
            "status": "no_tests_found",
            "summary": "No unit test files (test_*.py) detected",
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "duration_sec": 0.0,
        }

        if test_files or test_dir:
            test_res["executed"] = True
            # Prefer pytest if available, else unittest discover
            pytest_bin = _find_binary("pytest")
            test_cmd = [python_bin, "-m", "pytest", "-q"] if pytest_bin else [python_bin, "-m", "unittest", "discover", "-s", test_dir.name if test_dir else "."]
            test_res["command"] = " ".join(test_cmd)

            t_code, t_out, t_err, t_dur = _run_command(test_cmd, cwd=ws, timeout=timeout)
            test_res["exit_code"] = t_code
            test_res["stdout"] = t_out
            test_res["stderr"] = t_err
            test_res["duration_sec"] = t_dur

            counts = _parse_python_test_output(t_out + "\n" + t_err)
            test_res["passed"] = counts["passed"]
            test_res["failed"] = counts["failed"]
            test_res["skipped"] = counts["skipped"]
            if t_code == 0:
                test_res["status"] = "passed"
                test_res["summary"] = f"{counts['passed']} test(s) passed in {t_dur}s"
            else:
                test_res["status"] = "failed"
                test_res["summary"] = f"Tests failed with exit code {t_code} in {t_dur}s"

        return {
            "executed": True,
            "ecosystem": "python",
            "ecosystem_name": "Python",
            "target_project": f"{len(py_files)} Python file(s)",
            "build": build_res,
            "tests": test_res,
            "summary": f"Build: {build_res['status'].upper()} • Tests: {test_res['status'].upper()}",
        }

    # =========================================================
    # Fallback / Generic
    # =========================================================
    return {
        "executed": True,
        "ecosystem": "generic",
        "ecosystem_name": "Generic Repository",
        "target_project": ws.name,
        "build": {
            "executed": False,
            "status": "not_required",
            "summary": "No build configuration detected (.NET, Node, Python, etc.)",
            "command": "",
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "duration_sec": 0.0,
        },
        "tests": {
            "executed": False,
            "tests_found": False,
            "status": "no_tests_found",
            "summary": "No automated test suite detected",
            "command": "",
            "exit_code": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "duration_sec": 0.0,
        },
        "summary": "No build or test configurations detected",
    }

