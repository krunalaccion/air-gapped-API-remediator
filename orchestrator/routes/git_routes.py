"""
Git, workspace file, path validation, and filesystem browser route handlers.
"""

from __future__ import annotations

import logging
import os
import subprocess
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Optional

from agents.base import AgentRegistry
from agents.git_agent.agent import GitSubAgent
from agents.git_agent.config import GitAgentConfig, ProviderType

logger = logging.getLogger("multi_agent.web_server.git_routes")


def handle_get_git_routes(handler: Any, path: str, parsed: urllib.parse.ParseResult, ws: Any) -> bool:
    """Handle Git-related GET endpoints. Returns True if the path was matched."""
    if path == "/api/status":
        if not ws.ACTIVE_GIT_AGENT:
            handler._send_json({"error": "No active repository prepared"}, status=400)
            return True
        stat = ws.ACTIVE_GIT_AGENT.get_status()
        ctx = ws.ACTIVE_GIT_AGENT.context
        handler._send_json({
            "status": stat,
            "context": ctx.to_dict() if ctx else None,
        })
        return True

    if path == "/api/diff":
        if not ws.ACTIVE_GIT_AGENT:
            handler._send_json({"error": "No active repository prepared"}, status=400)
            return True
        diff = ws.ACTIVE_GIT_AGENT.get_diff()
        handler._send_json({"diff": diff})
        return True

    if path == "/api/local-pr":
        if not ws.ACTIVE_GIT_AGENT:
            handler._send_json({"error": "No active repository prepared"}, status=400)
            return True
        repo_path = ws.ACTIVE_GIT_AGENT.get_workspace_path()
        prs_dir = repo_path / ".git" / "local_prs"
        if not prs_dir.exists():
            prs_dir = repo_path / ".local_prs"

        parsed_query = urllib.parse.parse_qs(parsed.query)
        pr_num = parsed_query.get("number", [None])[0]
        if pr_num:
            md_path = prs_dir / f"PR-{pr_num}.md"
        else:
            prs = sorted(prs_dir.glob("PR-*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
            md_path = prs[0] if prs else None

        if not md_path or not md_path.exists():
            handler._send_json({"error": "No local PR report found"}, status=404)
            return True

        handler._send_json({
            "file_path": str(md_path.resolve()),
            "filename": md_path.name,
            "content": md_path.read_text(encoding="utf-8"),
        })
        return True

    return False


def _handle_prepare(handler: Any, payload: Dict[str, Any], ws: Any) -> None:
    repo_url = payload.get("repo_url")
    if not repo_url:
        handler._send_json({"error": "repo_url is required"}, status=400)
        return

    norm_cand = ws._normalize_local_repo_path(repo_url)
    is_local_hint = (
        repo_url.startswith("/")
        or repo_url.startswith("~")
        or repo_url.startswith("./")
        or repo_url.startswith("../")
        or repo_url.startswith("file://")
        or repo_url == "."
        or (len(repo_url) > 2 and repo_url[1] == ":")
        or norm_cand.exists()
    )
    if is_local_hint and norm_cand.exists():
        repo_url = str(norm_cand)

    token = payload.get("token") or payload.get("git_token") or os.getenv("GITHUB_TOKEN") or os.getenv("GITLAB_TOKEN")
    username = payload.get("username") or payload.get("git_username")
    provider_str = payload.get("provider")
    if provider_str:
        try:
            provider = ProviderType(provider_str.lower())
        except ValueError:
            provider = ProviderType.GENERIC
    elif is_local_hint:
        provider = ProviderType.LOCAL
    else:
        provider = ProviderType.GENERIC

    auto_init = bool(payload.get("auto_init", False))

    config = GitAgentConfig(
        repo_url=repo_url,
        token=token,
        username=username,
        provider=provider,
        base_branch=payload.get("base_branch"),
        feature_branch_name=payload.get("feature_branch"),
        workspace_dir=payload.get("workspace_dir"),
        author_name=payload.get("author_name", "Git SubAgent"),
        author_email=payload.get("author_email", "git-agent@subagent.local"),
        auto_init=auto_init,
    )

    if config.is_local or config.provider == ProviderType.LOCAL:
        clean_path = Path(config.sanitized_repo_url).resolve()
        if clean_path == ws.APP_ROOT_DIR:
            handler._send_json({
                "error": "Cannot use the agent root directory as target repository. Please select or clone your project repository."
            }, status=400)
            return
        elif clean_path == ws.DEFAULT_LOCAL_REPO:
            ws._ensure_default_local_repo_ready(reset_files=False)

        if not clean_path.exists():
            handler._send_json({"error": f"Selected path does not exist: '{clean_path}'"}, status=400)
            return
        has_git = (clean_path / ".git").exists() or (clean_path / "HEAD").exists()
        if not has_git:
            code = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(clean_path),
                capture_output=True,
            ).returncode
            if code != 0:
                if auto_init and clean_path.is_dir():
                    ws._init_local_git_repo(
                        clean_path,
                        base_branch=payload.get("base_branch") or "main",
                        author_name=config.author_name,
                        author_email=config.author_email,
                    )
                    has_git = True
                else:
                    handler._send_json({
                        "error": f"Selected path '{clean_path}' is not a Git repository. Missing '.git' directory."
                    }, status=400)
                    return

        if clean_path.name != "CustomerApi":
            injected_c = clean_path / "Controllers" / "UsersController.cs"
            if injected_c.exists():
                try:
                    c_txt = injected_c.read_text(encoding="utf-8", errors="ignore")
                    if "namespace CustomerApi" in c_txt or "CustomerApi" in c_txt:
                        injected_c.unlink()
                        if injected_c.parent.exists() and not any(injected_c.parent.iterdir()):
                            injected_c.parent.rmdir()
                except Exception:
                    pass
            injected_r = clean_path / "reports" / "SQLI-001_report.json"
            if injected_r.exists():
                try:
                    injected_r.unlink()
                except Exception:
                    pass

    ws.ACTIVE_GIT_AGENT = GitSubAgent(config)
    AgentRegistry.register("git", ws.ACTIVE_GIT_AGENT)
    ws._reset_pipeline_state(reset_git_agent=False)

    try:
        ctx = ws.ACTIVE_GIT_AGENT.prepare_workspace(auto_init=auto_init)
    except Exception as clone_exc:
        logger.error("Failed to prepare repository (%s): %s", config.sanitized_repo_url, clone_exc)
        ws.ACTIVE_GIT_AGENT = None
        handler._send_json({"error": f"Failed to prepare repository: {clone_exc}"}, status=400)
        return

    skip_build_test = bool(payload.get("skip_build_test", False))
    if skip_build_test:
        build_test_res = {
            "executed": False,
            "status": "pending",
            "ecosystem": "pending",
            "ecosystem_name": "Pending Execution",
            "build": {"status": "pending", "summary": "Build pending"},
            "tests": {"status": "pending", "tests_found": False, "summary": "Tests pending"},
            "summary": "Build and unit test verification suite queued",
        }
    else:
        try:
            build_test_res = ws.ACTIVE_GIT_AGENT.build_and_test()
        except Exception as bt_exc:
            logger.warning("Build/test runner failed: %s", bt_exc)
            build_test_res = {
                "executed": False,
                "error": str(bt_exc),
                "ecosystem": "unknown",
                "ecosystem_name": "Unknown",
                "build": {"status": "skipped", "summary": f"Build runner error: {bt_exc}"},
                "tests": {"status": "skipped", "tests_found": False, "summary": "Tests not run"},
                "summary": f"Build runner error: {bt_exc}",
            }

    remote_url = ws.ACTIVE_GIT_AGENT.get_sanitized_remote_url()
    handler._send_json({
        "message": "Repository prepared successfully",
        "context": ctx.to_dict(),
        "remote_url": remote_url,
        "has_remote": bool(remote_url),
        "status": ws.ACTIVE_GIT_AGENT.get_status(),
        "build_and_test": build_test_res,
    })


def _handle_read_file(handler: Any, payload: Dict[str, Any], ws: Any) -> None:
    rel_path = (payload.get("relative_path") or "").strip()
    if not rel_path:
        handler._send_json({"error": "relative_path is required"}, status=400)
        return

    scanner = ws.get_scanner_agent()
    ws_dir = ws._resolve_active_workspace()
    if not ws_dir and scanner.last_result and scanner.last_result.get("workspace_scanned"):
        cand = ws._normalize_local_repo_path(scanner.last_result["workspace_scanned"])
        if cand.exists() and cand != ws.APP_ROOT_DIR:
            ws_dir = cand

    if not ws_dir:
        handler._send_json({"error": "No repository prepared yet. Complete Step 01 to initialize workspace."}, status=400)
        return

    clean_rel = rel_path.lstrip("/\\")
    if ws_dir and clean_rel.startswith(ws_dir.name + "/"):
        clean_rel = clean_rel[len(ws_dir.name) + 1:]
    target_file = (ws_dir / clean_rel).resolve()
    if not str(target_file).startswith(str(ws_dir.resolve())):
        handler._send_json({"error": "Forbidden path outside workspace"}, status=403)
        return

    if not target_file.exists() or not target_file.is_file():
        handler._send_json({
            "relative_path": rel_path,
            "exists": False,
            "full_path": str(target_file),
            "content": "",
            "message": f"File '{rel_path}' has not been generated in workspace '{ws_dir.name}' yet.",
        })
        return

    content = target_file.read_text(encoding="utf-8", errors="replace")
    handler._send_json({
        "relative_path": rel_path,
        "exists": True,
        "full_path": str(target_file),
        "size_bytes": target_file.stat().st_size,
        "content": content,
    })


def _handle_write_file(handler: Any, payload: Dict[str, Any], ws: Any) -> None:
    ws_dir = ws._resolve_active_workspace()
    if not ws_dir:
        handler._send_json({"error": "No repository prepared yet. Complete Step 01 to initialize workspace."}, status=400)
        return
    rel_path = payload.get("relative_path")
    content = payload.get("content", "")
    if not rel_path:
        handler._send_json({"error": "relative_path is required"}, status=400)
        return

    target_file = (ws_dir / rel_path).resolve()
    if not str(target_file).startswith(str(ws_dir.resolve())):
        handler._send_json({"error": "Forbidden path outside workspace"}, status=403)
        return

    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text(content, encoding="utf-8")
    handler._send_json({
        "message": f"Saved {rel_path}",
        "status": ws.ACTIVE_GIT_AGENT.get_status() if ws.ACTIVE_GIT_AGENT else None,
        "diff": ws.ACTIVE_GIT_AGENT.get_diff() if ws.ACTIVE_GIT_AGENT else "",
    })


def _handle_commit_push(handler: Any, payload: Dict[str, Any], ws: Any) -> None:
    if not ws.ACTIVE_GIT_AGENT:
        handler._send_json({"error": "Please call /api/prepare first"}, status=400)
        return

    remediator = ws.get_remediator_agent()
    commit_msg = payload.get("commit_message")
    repo_name = ws.ACTIVE_GIT_AGENT.context.repo_name if (ws.ACTIVE_GIT_AGENT and ws.ACTIVE_GIT_AGENT.context) else "repository"
    cur_threats = list(remediator.accumulated_threats.values())
    cur_files = list(remediator.accumulated_modified_files)

    if cur_threats:
        full_template = remediator.generate_commit_message(
            repo_name=repo_name,
            threats=cur_threats,
            modified_files=cur_files,
        )
        if not commit_msg or not commit_msg.strip():
            commit_msg = full_template
        elif "\n" not in commit_msg.strip() or "Remediated Security Threats" not in commit_msg:
            lines = full_template.split("\n\n", 1)
            body_part = lines[1] if len(lines) > 1 else ""
            commit_msg = f"{commit_msg.strip()}\n\n{body_part}"
    elif not commit_msg:
        commit_msg = "fix(airgap): remediate external API endpoints"

    files = payload.get("files")
    cur_br = ws.ACTIVE_GIT_AGENT.workspace.current_feature_branch or ws.ACTIVE_GIT_AGENT.workspace.get_current_branch()
    req_token = payload.get("token") or payload.get("git_token")
    req_username = payload.get("username") if "username" in payload else payload.get("git_username")
    force_push = bool(payload.get("force", False))

    commit_hash: Optional[str] = None
    had_changes = ws.ACTIVE_GIT_AGENT.workspace.has_changes()
    if had_changes:
        ws.ACTIVE_GIT_AGENT.workspace.add(files)
        commit_hash = ws.ACTIVE_GIT_AGENT.workspace.commit(commit_msg)

    try:
        push_res = ws.ACTIVE_GIT_AGENT.push_branch(
            branch=cur_br,
            force=force_push,
            token=req_token,
            username=req_username,
        )
    except Exception as push_exc:
        err_prefix = f"Committed {commit_hash[:7]}, but push to remote failed" if commit_hash else "Push to remote failed"
        handler._send_json({
            "error": f"{err_prefix}: {push_exc}",
            "commit_hash": commit_hash,
            "branch": cur_br,
        }, status=400)
        return

    remote_label = push_res.get("remote_url") or "origin"
    if had_changes:
        msg_text = (
            f"Committed {commit_hash[:7]} and pushed branch '{cur_br}' to {remote_label}"
            if push_res.get("pushed")
            else f"Committed {commit_hash[:7]} and updated local branch '{cur_br}'"
        )
        handler._send_json({
            "message": msg_text,
            "commit_hash": commit_hash,
            "branch": cur_br,
            "pushed": push_res.get("pushed", False),
            "push_status": push_res.get("status"),
            "remote_url": push_res.get("remote_url"),
        })
    else:
        msg_text = (
            f"Working tree clean. Pushed branch '{cur_br}' to {remote_label}."
            if push_res.get("pushed")
            else f"Working tree clean. Updated local branch '{cur_br}'."
        )
        handler._send_json({
            "message": msg_text,
            "branch": cur_br,
            "pushed": push_res.get("pushed", False),
            "push_status": push_res.get("status"),
            "remote_url": push_res.get("remote_url"),
        })


def _handle_create_pr(handler: Any, payload: Dict[str, Any], ws: Any) -> None:
    if not ws.ACTIVE_GIT_AGENT:
        handler._send_json({"error": "Please call /api/prepare first"}, status=400)
        return

    remediator = ws.get_remediator_agent()
    notifier = ws.get_email_notifier()
    repo_name = ws.ACTIVE_GIT_AGENT.context.repo_name if (ws.ACTIVE_GIT_AGENT and ws.ACTIVE_GIT_AGENT.context) else "repository"
    cur_threats = list(remediator.accumulated_threats.values())
    cur_files = list(remediator.accumulated_modified_files)

    title = payload.get("title")
    if not title:
        title = remediator.generate_pr_title(repo_name=repo_name, threat_count=len(cur_threats))

    desc = payload.get("description")
    if not desc or desc.strip() in ("", "Automated Pull Request from Multi-Agent System"):
        desc = remediator.generate_pr_body(
            repo_name=repo_name,
            threats=cur_threats,
            modified_files=cur_files,
            branch=ws.ACTIVE_GIT_AGENT.workspace.current_feature_branch or "remediation/airgap-api-compliance",
            base_branch=ws.ACTIVE_GIT_AGENT.workspace.base_branch or "main",
        )
    elif cur_threats and "Remediated Vulnerabilities" not in desc:
        body_ext = remediator.generate_pr_body(
            repo_name=repo_name,
            threats=cur_threats,
            modified_files=cur_files,
            branch=ws.ACTIVE_GIT_AGENT.workspace.current_feature_branch or "remediation/airgap-api-compliance",
            base_branch=ws.ACTIVE_GIT_AGENT.workspace.base_branch or "main",
        )
        desc = f"{desc.strip()}\n\n{body_ext}"

    draft = bool(payload.get("draft", False))
    req_token = payload.get("token") or payload.get("git_token")
    req_username = payload.get("username") if "username" in payload else payload.get("git_username")
    if req_token:
        ws.ACTIVE_GIT_AGENT.config.token = req_token
        ws.ACTIVE_GIT_AGENT.workspace.token_to_scrub = req_token
    if req_username is not None:
        ws.ACTIVE_GIT_AGENT.config.username = req_username

    use_remote_pr = (
        not ws.ACTIVE_GIT_AGENT.config.is_local
        or bool(ws.ACTIVE_GIT_AGENT.last_push_result and ws.ACTIVE_GIT_AGENT.last_push_result.get("pushed"))
    )
    pr_provider = ws.ACTIVE_GIT_AGENT.resolve_pr_provider() if use_remote_pr else ws.ACTIVE_GIT_AGENT.provider
    if not pr_provider:
        handler._send_json({"error": "No git provider configured (GitHub/GitLab/Local)"}, status=400)
        return

    pr = pr_provider.create_pull_request(
        head_branch=ws.ACTIVE_GIT_AGENT.workspace.current_feature_branch,
        base_branch=ws.ACTIVE_GIT_AGENT.workspace.base_branch or "main",
        title=title,
        description=desc,
        draft=draft,
    )
    pr_label = "Pull Request" if pr.provider != "local" else "Local Pull Request"
    file_path = ""
    md_content = ""
    if pr.provider == "local" and pr.raw_response and "md_file" in pr.raw_response:
        file_path = pr.raw_response["md_file"]
        try:
            md_content = Path(file_path).read_text(encoding="utf-8")
        except Exception:
            pass

    pr_data: Dict[str, Any] = {
        "message": f"{pr_label} created successfully",
        "pr_number": pr.number,
        "pr_url": pr.url,
        "pr_file_path": file_path,
        "pr_content": md_content,
        "title": pr.title,
        "provider": pr.provider,
    }
    ws.LATEST_PR = pr_data
    try:
        email_cfg = notifier.get_public_config()
        if payload.get("send_email") or (email_cfg.get("enabled", True) and email_cfg.get("auto_send_after_pr", False)):
            pr_data["email_notification"] = ws._dispatch_current_remediation_email(
                override_recipients=payload.get("recipient_emails"),
                trigger_source="step5_pr_created",
            )
    except Exception as pr_email_exc:
        logger.warning("Auto-email report after PR creation failed: %s", pr_email_exc)
    handler._send_json(pr_data)


def _handle_build_test(handler: Any, ws: Any) -> None:
    if not ws.ACTIVE_GIT_AGENT:
        handler._send_json({"error": "Please call /api/prepare first"}, status=400)
        return
    try:
        build_test_res = ws.ACTIVE_GIT_AGENT.build_and_test()
    except Exception as bt_exc:
        logger.warning("Build/test runner failed: %s", bt_exc)
        build_test_res = {
            "executed": False,
            "error": str(bt_exc),
            "ecosystem": "unknown",
            "ecosystem_name": "Unknown",
            "build": {"status": "skipped", "summary": f"Build runner error: {bt_exc}"},
            "tests": {"status": "skipped", "tests_found": False, "summary": "Tests not run"},
            "summary": f"Build runner error: {bt_exc}",
        }
    handler._send_json(build_test_res)


def _handle_validate_path(handler: Any, payload: Dict[str, Any], ws: Any) -> None:
    raw_path = payload.get("path", "").strip()
    if not raw_path:
        handler._send_json({"valid": False, "error": "Path cannot be empty"}, status=400)
        return

    clean = raw_path.replace("file://", "")
    target_path = ws._normalize_local_repo_path(clean)

    if not target_path.exists():
        handler._send_json({
            "valid": False,
            "exists": False,
            "has_git": False,
            "path": str(target_path),
            "error": f"Path does not exist: {target_path}",
        }, status=400)
        return

    if not target_path.is_dir():
        handler._send_json({
            "valid": False,
            "exists": True,
            "is_dir": False,
            "has_git": False,
            "path": str(target_path),
            "error": f"Path is not a directory: {target_path}",
        }, status=400)
        return

    has_git = (target_path / ".git").exists() or (target_path / "HEAD").exists()
    if not has_git:
        code = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(target_path),
            capture_output=True,
        ).returncode
        has_git = (code == 0)

    auto_init = bool(payload.get("auto_init", False))
    allow_non_git = bool(payload.get("allow_non_git", False))

    if not has_git:
        if auto_init and target_path.is_dir():
            ws._init_local_git_repo(target_path)
            has_git = True
        elif allow_non_git and target_path.is_dir():
            handler._send_json({
                "valid": True,
                "exists": True,
                "is_dir": True,
                "has_git": False,
                "can_auto_init": True,
                "path": str(target_path),
                "message": f"Local project directory detected at {target_path} (Git can be auto-initialized).",
            })
            return
        else:
            handler._send_json({
                "valid": False,
                "exists": True,
                "is_dir": True,
                "has_git": False,
                "can_auto_init": True,
                "path": str(target_path),
                "error": f"Selected path '{target_path}' is not a Git repository (missing '.git' directory).",
            }, status=400)
            return

    handler._send_json({
        "valid": True,
        "exists": True,
        "is_dir": True,
        "has_git": True,
        "can_auto_init": False,
        "path": str(target_path),
        "message": f"Valid Git repository detected at {target_path}",
    })


def _handle_fs_list(handler: Any, payload: Dict[str, Any], ws: Any) -> None:
    raw_path = payload.get("path", "").strip()
    if raw_path:
        clean = raw_path.replace("file://", "")
        current_dir = Path(os.path.expanduser(clean)).resolve()
    else:
        current_dir = (ws.APP_ROOT_DIR / "repos").resolve() if (ws.APP_ROOT_DIR / "repos").exists() else Path.cwd().resolve()

    if not current_dir.exists() or not current_dir.is_dir():
        current_dir = Path.home().resolve()

    folders = []
    try:
        for entry in sorted(current_dir.iterdir(), key=lambda p: p.name.lower()):
            if entry.is_dir() and not entry.name.startswith("."):
                has_git = (entry / ".git").exists() or (entry / "HEAD").exists()
                folders.append({
                    "name": entry.name,
                    "path": str(entry.resolve()),
                    "has_git": has_git,
                })
    except Exception as e:
        logger.warning("Could not list directories in %s: %s", current_dir, e)

    parent_dir = str(current_dir.parent.resolve()) if current_dir != current_dir.parent else None
    current_has_git = (current_dir / ".git").exists() or (current_dir / "HEAD").exists()

    home = Path.home().resolve()
    quick_access = [{"label": "🏠 Home", "path": str(home)}]
    repos_dir = (ws.APP_ROOT_DIR / "repos").resolve()
    if repos_dir.exists() and repos_dir.is_dir():
        quick_access.append({"label": "📁 App Repos", "path": str(repos_dir)})
    elif ws.APP_ROOT_DIR.exists() and ws.APP_ROOT_DIR.is_dir():
        quick_access.append({"label": "📁 Workspace", "path": str(ws.APP_ROOT_DIR.resolve())})
    for rel in ["Projects", "Documents", "Desktop", "Downloads"]:
        candidate = home / rel
        if candidate.exists() and candidate.is_dir():
            quick_access.append({"label": rel, "path": str(candidate.resolve())})

    handler._send_json({
        "current_path": str(current_dir),
        "current_has_git": current_has_git,
        "parent_path": parent_dir,
        "folders": folders,
        "quick_access": quick_access,
    })


def handle_post_git_routes(handler: Any, path: str, payload: Dict[str, Any], ws: Any) -> bool:
    """Handle Git, workspace file, and filesystem POST endpoints. Returns True if matched."""
    routes = {
        "/api/prepare": lambda: _handle_prepare(handler, payload, ws),
        "/api/read-file": lambda: _handle_read_file(handler, payload, ws),
        "/api/write-file": lambda: _handle_write_file(handler, payload, ws),
        "/api/commit-push": lambda: _handle_commit_push(handler, payload, ws),
        "/api/create-pr": lambda: _handle_create_pr(handler, payload, ws),
        "/api/build-test": lambda: _handle_build_test(handler, ws),
        "/api/validate-path": lambda: _handle_validate_path(handler, payload, ws),
        "/api/fs/list": lambda: _handle_fs_list(handler, payload, ws),
    }
    action = routes.get(path)
    if action is None:
        return False
    action()
    return True

