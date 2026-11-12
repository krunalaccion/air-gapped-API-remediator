"""
Batch Scheduler route handlers.
"""

from __future__ import annotations

import os
import urllib.parse
from pathlib import Path
from typing import Any, Dict

from orchestrator.scheduler import discover_repositories


def handle_get_scheduler_routes(handler: Any, path: str, parsed: urllib.parse.ParseResult, ws: Any) -> bool:
    """Handle Batch Scheduler GET endpoints. Returns True if matched."""
    scheduler = ws.get_batch_scheduler()

    if path == "/api/scheduler/overview":
        handler._send_json(scheduler.get_overview())
        return True

    if path == "/api/scheduler/schedules":
        handler._send_json({"schedules": scheduler.list_schedules()})
        return True

    if path == "/api/scheduler/runs":
        parsed_query = urllib.parse.parse_qs(parsed.query)
        limit = int(parsed_query.get("limit", ["50"])[0] or 50)
        handler._send_json({"runs": scheduler.list_runs(limit=limit)})
        return True

    if path == "/api/scheduler/runs/detail":
        parsed_query = urllib.parse.parse_qs(parsed.query)
        run_id = (parsed_query.get("run_id", [""])[0] or "").strip()
        detail = scheduler.get_run_detail(run_id) if run_id else None
        if not detail:
            handler._send_json({"error": f"Run '{run_id}' not found"}, status=404)
            return True
        handler._send_json(detail)
        return True

    if path == "/api/scheduler/runs/report":
        parsed_query = urllib.parse.parse_qs(parsed.query)
        run_id = (parsed_query.get("run_id", [""])[0] or "").strip()
        repo_key = (parsed_query.get("repo", [""])[0] or "").strip()
        report_type = (parsed_query.get("type", ["remediation"])[0] or "remediation").strip()
        content_str, content_type = scheduler.get_repo_report(
            run_id=run_id,
            repo_key=repo_key,
            report_type=report_type,
        )
        if not content_str:
            handler._send_json({"error": "Requested batch report not found."}, status=404)
            return True
        content = content_str.encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(content)))
        handler.end_headers()
        handler.wfile.write(content)
        return True

    if path == "/api/scheduler/runs/pr":
        parsed_query = urllib.parse.parse_qs(parsed.query)
        run_id = (parsed_query.get("run_id", [""])[0] or "").strip()
        repo_key = (parsed_query.get("repo", [""])[0] or "").strip()
        detail = scheduler.get_run_detail(run_id) if run_id else None
        if not detail:
            handler._send_json({"error": "Run not found"}, status=404)
            return True
        target_repo = None
        for idx, r in enumerate(detail.get("repos") or []):
            if str(idx) == repo_key or r.get("name") == repo_key or r.get("relative_path") == repo_key:
                target_repo = r
                break
        if not target_repo or not target_repo.get("pr_file_path"):
            handler._send_json({"error": "No local PR file found for this repository in this run."}, status=404)
            return True
        pr_path = Path(target_repo["pr_file_path"]).resolve()
        repo_root = Path(target_repo["path"]).resolve()
        if not str(pr_path).startswith(str(repo_root) + os.sep) or not pr_path.exists():
            handler._send_json({"error": "Local PR file no longer exists on disk."}, status=404)
            return True
        handler._send_json({
            "file_path": str(pr_path),
            "filename": pr_path.name,
            "content": pr_path.read_text(encoding="utf-8"),
        })
        return True

    return False


def handle_post_scheduler_routes(handler: Any, path: str, payload: Dict[str, Any], ws: Any) -> bool:
    """Handle Batch Scheduler POST endpoints. Returns True if matched."""
    scheduler = ws.get_batch_scheduler()

    if path == "/api/scheduler/discover":
        raw_folder = (payload.get("folder_path") or "").strip()
        if not raw_folder:
            handler._send_json({"error": "folder_path is required"}, status=400)
            return True
        target_folder = ws._normalize_local_repo_path(raw_folder)
        try:
            result = discover_repositories(
                folder_path=target_folder,
                include_non_git=bool(payload.get("include_non_git", False)),
                recursive=bool(payload.get("recursive", False)),
                app_root_dir=ws.APP_ROOT_DIR,
            )
            handler._send_json(result)
        except (ValueError, FileNotFoundError, NotADirectoryError) as exc:
            handler._send_json({"error": str(exc)}, status=400)
        return True

    if path == "/api/scheduler/schedules":
        sched_payload = dict(payload)
        if sched_payload.get("folder_path"):
            sched_payload["folder_path"] = str(ws._normalize_local_repo_path(sched_payload["folder_path"]))
        try:
            created = scheduler.create_schedule(sched_payload)
            handler._send_json(created, status=201)
        except ValueError as exc:
            handler._send_json({"error": str(exc)}, status=400)
        return True

    if path == "/api/scheduler/schedules/update":
        schedule_id = (payload.get("id") or payload.get("schedule_id") or "").strip()
        if not schedule_id:
            handler._send_json({"error": "id is required"}, status=400)
            return True
        sched_payload = dict(payload)
        if sched_payload.get("folder_path"):
            sched_payload["folder_path"] = str(ws._normalize_local_repo_path(sched_payload["folder_path"]))
        try:
            updated = scheduler.update_schedule(schedule_id, sched_payload)
            handler._send_json({"schedule": updated})
        except KeyError as exc:
            handler._send_json({"error": str(exc)}, status=404)
        except ValueError as exc:
            handler._send_json({"error": str(exc)}, status=400)
        return True

    if path == "/api/scheduler/schedules/toggle":
        schedule_id = (payload.get("id") or payload.get("schedule_id") or "").strip()
        if not schedule_id:
            handler._send_json({"error": "id is required"}, status=400)
            return True
        try:
            enabled_val = payload["enabled"] if "enabled" in payload else None
            updated = scheduler.toggle_schedule(schedule_id, enabled=enabled_val)
            handler._send_json({"schedule": updated})
        except KeyError as exc:
            handler._send_json({"error": str(exc)}, status=404)
        return True

    if path == "/api/scheduler/schedules/delete":
        schedule_id = (payload.get("id") or payload.get("schedule_id") or "").strip()
        if not schedule_id:
            handler._send_json({"error": "id is required"}, status=400)
            return True
        deleted = scheduler.delete_schedule(schedule_id)
        if not deleted:
            handler._send_json({"error": f"Schedule '{schedule_id}' not found"}, status=404)
            return True
        handler._send_json({"deleted": True, "id": schedule_id})
        return True

    if path == "/api/scheduler/schedules/run-now":
        schedule_id = (payload.get("id") or payload.get("schedule_id") or "").strip()
        if not schedule_id:
            handler._send_json({"error": "id is required"}, status=400)
            return True
        try:
            run_info = scheduler.trigger_schedule_now(schedule_id, trigger_source="manual")
            handler._send_json({"message": "Batch run queued in background", "run": run_info}, status=202)
        except KeyError as exc:
            handler._send_json({"error": str(exc)}, status=404)
        return True

    if path == "/api/scheduler/runs/cancel":
        run_id = (payload.get("run_id") or payload.get("id") or "").strip()
        if not run_id:
            handler._send_json({"error": "run_id is required"}, status=400)
            return True
        try:
            res = scheduler.cancel_run(run_id)
            handler._send_json(res)
        except KeyError as exc:
            handler._send_json({"error": str(exc)}, status=404)
        return True

    if path == "/api/scheduler/runs/clear":
        removed = scheduler.clear_finished_runs()
        handler._send_json({"cleared": removed})
        return True

    return False

