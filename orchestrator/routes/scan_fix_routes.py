"""
Scanner, Remediator, BugFixer, Reset, and Pipeline route handlers.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Optional

from agents.base import AgentRegistry
from agents.git_agent.agent import GitSubAgent
from agents.git_agent.config import GitAgentConfig, ProviderType
from agents.remediator_agent.agent import DEFAULT_SQLI_FINDING
from orchestrator.pipeline import MultiAgentPipeline

logger = logging.getLogger("multi_agent.web_server.scan_fix_routes")


def _resolve_requested_workspace(payload: Dict[str, Any], ws: Any) -> Optional[Path]:
    prepared_ws = ws._resolve_active_workspace()
    explicit_ws = (payload.get("workspace_path") or payload.get("repo_url") or "").strip()
    ws_path: Optional[Path] = None

    if explicit_ws:
        candidate_p = ws._normalize_local_repo_path(explicit_ws)
        if candidate_p.exists() and candidate_p != ws.APP_ROOT_DIR:
            ws_path = candidate_p

    if not ws_path:
        ws_path = prepared_ws
    elif prepared_ws and ws_path == ws.DEFAULT_LOCAL_REPO and prepared_ws != ws.DEFAULT_LOCAL_REPO:
        ws_path = prepared_ws

    return ws_path


def handle_get_scan_fix_routes(handler: Any, path: str, parsed: urllib.parse.ParseResult, ws: Any) -> bool:
    """Handle Scanner/Remediator GET endpoints. Returns True if matched."""
    if path in ("/api/fix/progress", "/api/remediator/progress"):
        handler._send_json(ws.get_remediator_agent().get_progress())
        return True

    if path == "/api/bug-fixer/reports":
        remediator = ws.get_remediator_agent()
        git_prepared = bool(ws.ACTIVE_GIT_AGENT and ws.ACTIVE_GIT_AGENT.context)
        reports = remediator.list_reports(ws._resolve_active_workspace()) if (git_prepared and remediator.last_result) else []
        handler._send_json({
            "count": len(reports),
            "reports": reports,
            "default_finding": None,
        })
        return True

    if path == "/api/securescan/report":
        parsed_query = urllib.parse.parse_qs(parsed.query)
        fmt = (parsed_query.get("format", ["html"])[0] or "html").lower()
        content_str, content_type = ws.get_scanner_agent().get_report_content(fmt)
        if not content_str:
            handler._send_json({"error": f"No SecureScanAI {fmt.upper()} report generated yet. Run a scan first."}, status=404)
            return True

        content = content_str.encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(content)))
        handler.end_headers()
        handler.wfile.write(content)
        return True

    if path in ("/api/remediator/report", "/reports/REMEDIATION_AUDIT_REPORT.html", "/REMEDIATION_AUDIT_REPORT.html"):
        parsed_query = urllib.parse.parse_qs(parsed.query)
        fmt = (parsed_query.get("format", ["html"])[0] or "html").lower()
        ws_path = ws._resolve_active_workspace()
        content_str, content_type = ws.get_remediator_agent().get_report_content(
            fmt=fmt,
            workspace_path=str(ws_path) if ws_path else None,
        )
        content = content_str.encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(content)))
        handler.end_headers()
        handler.wfile.write(content)
        return True

    if path == "/api/scanner/tools":
        handler._send_json(ws.get_scanner_agent().get_scanner_tools())
        return True

    return False


def _handle_scan(handler: Any, payload: Dict[str, Any], ws: Any) -> None:
    ws_path = _resolve_requested_workspace(payload, ws)
    if not ws_path:
        handler._send_json({"error": "Repository not prepared yet. Complete Step 01 to initialize workspace."}, status=400)
        return

    if ws_path and (not ws.ACTIVE_GIT_AGENT or not ws.ACTIVE_GIT_AGENT.context or ws.ACTIVE_GIT_AGENT.get_workspace_path().resolve() != ws_path.resolve()):
        if (ws_path / ".git").exists():
            cfg = GitAgentConfig(
                repo_url=str(ws_path),
                provider=ProviderType.LOCAL,
                base_branch="master",
                feature_branch_name="remediation/airgap-api-compliance",
            )
            ws.ACTIVE_GIT_AGENT = GitSubAgent(cfg)
            AgentRegistry.register("git", ws.ACTIVE_GIT_AGENT)
            try:
                ws.ACTIVE_GIT_AGENT.prepare_workspace()
            except Exception as prep_e:
                logger.debug("Auto-sync workspace for %s: %s", ws_path, prep_e)

    scanner = ws.get_scanner_agent()
    remediator = ws.get_remediator_agent()
    remediator.last_result = None
    remediator.status = "IDLE"
    engine = payload.get("scanner_engine") or payload.get("engine") or "all"
    result = scanner.run({"workspace_path": str(ws_path), "scanner_engine": engine})
    result["mode"] = "live" if ws.ACTIVE_GIT_AGENT else "preview"
    handler._send_json(result)


def _handle_fix(handler: Any, payload: Dict[str, Any], ws: Any) -> None:
    ws_path = _resolve_requested_workspace(payload, ws)
    if not ws_path:
        handler._send_json({"error": "Repository not prepared yet. Complete Step 01 to initialize workspace."}, status=400)
        return

    scanner = ws.get_scanner_agent()
    remediator = ws.get_remediator_agent()
    notifier = ws.get_email_notifier()

    max_iterations = int(payload.get("max_iterations") or 5)
    max_iterations = max(1, min(max_iterations, 5))
    iteration = 0
    result: Dict[str, Any] = {}
    post_scan: Dict[str, Any] = {}

    while iteration < max_iterations:
        iteration += 1
        logger.info("[Iterative Remediation] Starting iteration %d of %d for workspace: %s", iteration, max_iterations, ws_path)
        remediator.current_progress["iteration"] = iteration
        remediator.current_progress["max_iterations"] = max_iterations
        remediator.current_progress["status"] = "RUNNING"
        remediator.current_progress["phase"] = f"Iteration {iteration}/{max_iterations}"
        remediator.current_progress["message"] = f"Iteration {iteration}/{max_iterations}: Applying security patches..."

        result = remediator.run({
            "workspace_path": str(ws_path),
            "provider": payload.get("provider"),
            "model": payload.get("model"),
            "base_url": payload.get("base_url"),
        })
        result["mode"] = "live" if ws.ACTIVE_GIT_AGENT else "preview"

        for itm in remediator.current_progress.get("items", []):
            if itm.get("id") == "POST-SCAN-VERIFY":
                itm["status"] = "fixing"
                itm["action"] = f"Executing verification scan (Iteration {iteration}/{max_iterations})..."
                break
        remediator.current_progress["current_file"] = "AST Security Post-Scan"
        remediator.current_progress["phase"] = f"Verification Scan {iteration}/{max_iterations}"
        remediator.current_progress["message"] = f"Iteration {iteration}/{max_iterations}: Running verification scan to verify threats..."
        remediator.current_progress["percent"] = 90

        scan_engine = payload.get("scanner_engine") or getattr(scanner, "last_engine", "all")
        post_scan = scanner.run({"workspace_path": str(ws_path), "scanner_engine": scan_engine, "is_post_scan": True})
        result["post_scan"] = post_scan
        remediator.last_post_scan = post_scan
        remediator.last_workspace_path = str(ws_path)

        residual_findings = post_scan.get("findings") if post_scan.get("findings") is not None else (post_scan.get("bug_findings") or [])
        residual_count = len(residual_findings)
        logger.info("[Iterative Remediation] Iteration %d/%d completed. Residual threats detected: %d", iteration, max_iterations, residual_count)

        if residual_count == 0:
            logger.info("[Iterative Remediation] All threats resolved successfully in iteration %d!", iteration)
            break
        elif iteration < max_iterations:
            logger.info("[Iterative Remediation] Re-ingesting %d residual threats for iteration %d/%d", residual_count, iteration + 1, max_iterations)
            scanner.findings_dir.mkdir(parents=True, exist_ok=True)
            for existing_f in list(scanner.findings_dir.glob("*.json")):
                try:
                    existing_f.unlink()
                except OSError:
                    pass
            for rf in residual_findings:
                rf_id = (rf.get("finding_id") or rf.get("id") or "FINDING").lower().replace("_", "-")
                f_file = scanner.findings_dir / f"{rf_id}.json"
                try:
                    f_file.write_text(json.dumps(rf, indent=2), encoding="utf-8")
                except Exception:
                    pass

    resolved_all = len(post_scan.get("findings") if post_scan.get("findings") is not None else (post_scan.get("bug_findings") or [])) == 0
    for itm in remediator.current_progress.get("items", []):
        if itm.get("id") == "POST-SCAN-VERIFY":
            itm["status"] = "remediated"
            itm["action"] = f"Verified: {len(post_scan.get('findings') or [])} residual threats detected"
            break
    remediator.current_progress["completed_targets"] = len(remediator.current_progress.get("items", []))
    remediator.current_progress["percent"] = 100
    remediator.current_progress["status"] = "COMPLETED"
    remediator.current_progress["phase"] = "Completed"
    remediator.current_progress["iteration"] = iteration
    remediator.current_progress["max_iterations"] = max_iterations
    remediator.current_progress["resolved_all"] = resolved_all
    remediator.current_progress["message"] = (
        f"All threats resolved in {iteration} iteration(s) (100/100 Grade A+)."
        if resolved_all else
        f"Completed {iteration} iterations. Remaining threats: {len(post_scan.get('findings') or [])}."
    )
    remediator.current_progress["current_file"] = None

    result["iterations_run"] = iteration
    result["max_iterations"] = max_iterations
    result["resolved_all"] = resolved_all

    try:
        html_rep = remediator.render_html_report(workspace_path=str(ws_path))
        remediator.reports_dir.mkdir(parents=True, exist_ok=True)
        (remediator.reports_dir / "REMEDIATION_AUDIT_REPORT.html").write_text(html_rep, encoding="utf-8")
    except Exception:
        pass

    if ws.ACTIVE_GIT_AGENT:
        result["status_summary"] = ws.ACTIVE_GIT_AGENT.get_status()
        result["diff"] = ws.ACTIVE_GIT_AGENT.get_diff() or result.get("bug_diff", "")
    else:
        result["diff"] = result.get("bug_diff", "")

    try:
        if payload.get("recipient_emails") is not None:
            notifier.update_config({"recipient_emails": payload.get("recipient_emails")})
        if "auto_send_email" in payload:
            notifier.update_config({"auto_send_after_remediation": payload.get("auto_send_email")})
        email_cfg = notifier.get_public_config()
        should_send = bool(
            payload.get("send_email")
            or (email_cfg.get("enabled", True) and email_cfg.get("auto_send_after_remediation", True))
        )
        if should_send:
            result["email_notification"] = ws._dispatch_current_remediation_email(
                ws_path=ws_path,
                remediation_result=result,
                post_scan_result=post_scan,
                override_recipients=payload.get("recipient_emails"),
                trigger_source="step3_remediation_completed",
            )
    except Exception as email_exc:
        logger.warning("Auto-email report after remediation failed: %s", email_exc)
        result["email_notification"] = {"status": "error", "message": str(email_exc)}

    handler._send_json(result)


def _handle_bug_fixer_fix(handler: Any, payload: Dict[str, Any], ws: Any) -> None:
    ws_path = ws._resolve_active_workspace()
    if not ws_path:
        handler._send_json({"error": "Repository not prepared yet. Complete Step 01 to initialize workspace."}, status=400)
        return
    finding_data = payload.get("finding") or dict(DEFAULT_SQLI_FINDING)
    preview = bool(payload.get("preview", False))
    provider = payload.get("provider") or None
    model = payload.get("model") or None

    result = ws.get_remediator_agent().fix_finding(
        finding_payload=finding_data,
        workspace_path=ws_path,
        preview=preview,
        provider=provider,
        model=model,
    )
    result["mode"] = "live" if ws.ACTIVE_GIT_AGENT else "standalone"
    if ws.ACTIVE_GIT_AGENT:
        result["status_summary"] = ws.ACTIVE_GIT_AGENT.get_status()
        result["git_diff"] = ws.ACTIVE_GIT_AGENT.get_diff()
    handler._send_json(result)


def _handle_reset_all(handler: Any, ws: Any) -> None:
    remediator = ws.get_remediator_agent()
    ws_path = ws._resolve_active_workspace() or ws.DEFAULT_LOCAL_REPO
    if ws_path.name == "CustomerApi" or ws_path.resolve() == ws.DEFAULT_LOCAL_REPO:
        remediator.reset_demo(workspace_path=ws_path)
        ws._ensure_default_local_repo_ready(reset_files=True)
    else:
        remediator.reset_demo(workspace_path=None)

    ws._reset_pipeline_state(reset_git_agent=True)

    result = {
        "status": "success",
        "message": "Reset all pipeline steps, workspace references, and findings cache",
        "workspace_path": "",
        "repo_name": "",
        "status_summary": {
            "branch": "none",
            "clean": True,
            "modified_files": [],
            "untracked_files": [],
        },
        "git_diff": "",
        "telemetry": ws._build_telemetry_payload(),
    }
    handler._send_json(result)


def _handle_pipeline_run(handler: Any, ws: Any) -> None:
    if not ws.ACTIVE_GIT_AGENT:
        handler._send_json({"error": "Please configure repository with /api/prepare first"}, status=400)
        return

    pipeline = MultiAgentPipeline(
        git_config=ws.ACTIVE_GIT_AGENT.config,
        scanner=ws.get_scanner_agent(),
        remediator=ws.get_remediator_agent(),
    )
    res = pipeline.run_remediation_pipeline()
    handler._send_json(res)


def handle_post_scan_fix_routes(handler: Any, path: str, payload: Dict[str, Any], ws: Any) -> bool:
    """Handle Scanner/Remediator/Pipeline POST endpoints. Returns True if matched."""
    routes = {
        "/api/scan": lambda: _handle_scan(handler, payload, ws),
        "/api/fix": lambda: _handle_fix(handler, payload, ws),
        "/api/bug-fixer/fix": lambda: _handle_bug_fixer_fix(handler, payload, ws),
        "/api/bug-fixer/reset": lambda: _handle_reset_all(handler, ws),
        "/api/reset-all": lambda: _handle_reset_all(handler, ws),
        "/api/pipeline/run": lambda: _handle_pipeline_run(handler, ws),
    }
    action = routes.get(path)
    if action is None:
        return False
    action()
    return True

