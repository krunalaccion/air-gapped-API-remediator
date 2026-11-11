"""
Background Batch Repository Scheduler for Multi-Agent Air-Gapped Security Remediation.

Discovers all repositories inside a specified local folder and executes the full
GitSubAgent -> ScannerAgent -> RemediatorAgent -> Commit -> Pull Request pipeline
sequentially (one by one) in a persistent background worker queue according to a schedule.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import queue
import re
import shutil
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from agents.git_agent.agent import GitSubAgent
from agents.git_agent.config import GitAgentConfig, ProviderType
from agents.remediator_agent.agent import RemediatorAgent
from agents.scanner_agent.agent import ScannerAgent
from agents.scanner_agent.models import (
    DependencyManifestAudit,
    FindingClassification,
    FindingSeverity,
    RawSecurityFinding,
    ScanReportBundle,
    ScannerExecutionStatus,
)
from agents.scanner_agent.pipeline import SecureScanPipeline
from orchestrator.email_notifier import EmailReportNotifier, _split_emails

logger = logging.getLogger("orchestrator.scheduler")

IGNORED_DISCOVERY_DIRS: Set[str] = {
    ".git",
    "node_modules",
    "bin",
    "obj",
    "__pycache__",
    "venv",
    ".venv",
    "dist",
    "build",
    "coverage",
    "reports",
    "findings",
    "scheduler_data",
    ".git_agent_workspaces",
}

CRON_MACROS: Dict[str, str] = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
    "@monthly": "0 0 1 * *",
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
}

MONTH_NAMES: Dict[str, int] = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

DOW_NAMES: Dict[str, int] = {
    "sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

DAY_LABEL_TO_PY_WEEKDAY: Dict[str, int] = {
    "mon": 0, "monday": 0, "0": 0,
    "tue": 1, "tuesday": 1, "1": 1,
    "wed": 2, "wednesday": 2, "2": 2,
    "thu": 3, "thursday": 3, "3": 3,
    "fri": 4, "friday": 4, "4": 4,
    "sat": 5, "saturday": 5, "5": 5,
    "sun": 6, "sunday": 6, "6": 6,
}


def local_now() -> dt.datetime:
    """Returns current timezone-aware local datetime."""
    return dt.datetime.now().astimezone()


def parse_iso_aware(value: Optional[str]) -> Optional[dt.datetime]:
    """Parses an ISO datetime string into a timezone-aware local datetime."""
    if not value:
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        local_tz = local_now().tzinfo
        parsed = parsed.replace(tzinfo=local_tz)
    return parsed


def _slugify(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", name or "repo").strip("_")
    return cleaned or "repo"


def _atomic_write_json(target_path: Path, data: Any) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.with_suffix(f"{target_path.suffix}.tmp.{os.getpid()}.{threading.get_ident()}")
    tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp_path, target_path)


class CronExpression:
    """Zero-dependency 5-field POSIX cron parser and next-run calculator."""

    def __init__(self, expression: str):
        raw = (expression or "").strip()
        if raw.lower() in CRON_MACROS:
            raw = CRON_MACROS[raw.lower()]
        parts = raw.split()
        if len(parts) != 5:
            raise ValueError("Cron expression must have exactly 5 fields: 'minute hour dom month dow'")

        self.expression = raw
        self.minutes, _ = self._parse_field(parts[0], 0, 59)
        self.hours, _ = self._parse_field(parts[1], 0, 23)
        self.doms, self.dom_wildcard = self._parse_field(parts[2], 1, 31)
        self.months, _ = self._parse_field(parts[3], 1, 12, names=MONTH_NAMES)
        raw_dows, self.dow_wildcard = self._parse_field(parts[4], 0, 7, names=DOW_NAMES)
        # Convert cron day-of-week (0/7=Sun, 1=Mon..6=Sat) to Python weekday (0=Mon..6=Sun)
        self.py_weekdays: Set[int] = {((d - 1) % 7) for d in raw_dows}

    @staticmethod
    def _parse_token(token: str, min_val: int, max_val: int, names: Optional[Dict[str, int]]) -> int:
        low = token.strip().lower()
        if names and low in names:
            return names[low]
        val = int(low)
        if val < min_val or val > max_val:
            raise ValueError(f"Cron value '{token}' out of range [{min_val}, {max_val}]")
        return val

    @classmethod
    def _parse_field(
        cls,
        field_str: str,
        min_val: int,
        max_val: int,
        names: Optional[Dict[str, int]] = None,
    ) -> Tuple[Set[int], bool]:
        field_str = field_str.strip()
        if field_str == "*":
            return set(range(min_val, max_val + 1)), True

        values: Set[int] = set()
        for chunk in field_str.split(","):
            chunk = chunk.strip()
            if not chunk:
                raise ValueError(f"Empty segment in cron field '{field_str}'")

            step = 1
            if "/" in chunk:
                range_part, step_part = chunk.split("/", 1)
                step = int(step_part)
                if step <= 0:
                    raise ValueError(f"Cron step must be > 0 in '{chunk}'")
            else:
                range_part = chunk

            if range_part == "*":
                start, end = min_val, max_val
            elif "-" in range_part:
                s_raw, e_raw = range_part.split("-", 1)
                start = cls._parse_token(s_raw, min_val, max_val, names)
                end = cls._parse_token(e_raw, min_val, max_val, names)
                if start > end:
                    raise ValueError(f"Cron range start > end in '{chunk}'")
            else:
                single = cls._parse_token(range_part, min_val, max_val, names)
                if "/" in chunk:
                    start, end = single, max_val
                else:
                    values.add(single)
                    continue

            values.update(range(start, end + 1, step))

        if not values:
            raise ValueError(f"Cron field '{field_str}' matched no values")
        return values, False

    def _day_matches(self, candidate: dt.datetime) -> bool:
        dom_match = candidate.day in self.doms
        dow_match = candidate.weekday() in self.py_weekdays
        if self.dom_wildcard and self.dow_wildcard:
            return True
        if self.dom_wildcard:
            return dow_match
        if self.dow_wildcard:
            return dom_match
        return dom_match or dow_match

    def next_after(self, after: dt.datetime) -> dt.datetime:
        """Finds the next matching datetime strictly after `after`."""
        cur = after.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
        limit = cur + dt.timedelta(days=366 * 4)

        while cur <= limit:
            if cur.month not in self.months:
                # Jump to 1st of next month at 00:00
                if cur.month == 12:
                    cur = cur.replace(year=cur.year + 1, month=1, day=1, hour=0, minute=0)
                else:
                    cur = cur.replace(month=cur.month + 1, day=1, hour=0, minute=0)
                continue

            if not self._day_matches(cur):
                cur = (cur + dt.timedelta(days=1)).replace(hour=0, minute=0)
                continue

            if cur.hour not in self.hours:
                next_hours = [h for h in sorted(self.hours) if h > cur.hour]
                if next_hours:
                    cur = cur.replace(hour=next_hours[0], minute=0)
                else:
                    cur = (cur + dt.timedelta(days=1)).replace(hour=0, minute=0)
                continue

            if cur.minute not in self.minutes:
                next_mins = [m for m in sorted(self.minutes) if m > cur.minute]
                if next_mins:
                    cur = cur.replace(minute=next_mins[0])
                else:
                    cur = (cur + dt.timedelta(hours=1)).replace(minute=0)
                continue

            return cur

        raise ValueError(f"Cron expression '{self.expression}' has no match within 4 years")


def normalize_days_of_week(days: Any) -> List[int]:
    """Normalizes weekday values (ints or names) into sorted Python weekday ints (0=Mon..6=Sun)."""
    if not days:
        return []
    result: Set[int] = set()
    for item in days:
        key = str(item).strip().lower()
        if key in DAY_LABEL_TO_PY_WEEKDAY:
            result.add(DAY_LABEL_TO_PY_WEEKDAY[key])
        else:
            raise ValueError(f"Invalid day of week: '{item}'")
    return sorted(result)


def compute_next_run_at(
    schedule: Dict[str, Any],
    after: Optional[dt.datetime] = None,
) -> Optional[str]:
    """Computes the next ISO-8601 fire timestamp for a schedule dictionary."""
    if not schedule.get("enabled", True):
        return None

    now = after or local_now()
    stype = (schedule.get("schedule_type") or "interval").strip().lower()

    if stype == "interval":
        mins = int(schedule.get("interval_minutes") or 60)
        mins = max(1, mins)
        next_dt = now + dt.timedelta(minutes=mins)
        return next_dt.isoformat()

    if stype == "daily":
        t_str = (schedule.get("time_of_day") or "02:00").strip()
        hour, minute = [int(x) for x in t_str.split(":", 1)]
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += dt.timedelta(days=1)
        return candidate.isoformat()

    if stype == "weekly":
        days = normalize_days_of_week(schedule.get("days_of_week") or [0])
        t_str = (schedule.get("time_of_day") or "02:00").strip()
        hour, minute = [int(x) for x in t_str.split(":", 1)]
        for offset in range(0, 8):
            candidate = (now + dt.timedelta(days=offset)).replace(
                hour=hour, minute=minute, second=0, microsecond=0
            )
            if candidate.weekday() in days and candidate > now:
                return candidate.isoformat()
        return None

    if stype == "cron":
        expr = schedule.get("cron_expression") or "0 * * * *"
        cron = CronExpression(expr)
        return cron.next_after(now).isoformat()

    if stype == "once":
        run_at = parse_iso_aware(schedule.get("run_at"))
        if run_at is None:
            return None
        if schedule.get("last_run_at") and run_at <= now:
            return None
        return run_at.isoformat()

    raise ValueError(f"Unsupported schedule_type: '{stype}'")


def _is_git_repo_dir(path: Path) -> bool:
    """Returns True if `path` itself is the root of a Git repository."""
    if not path.is_dir():
        return False
    if (path / ".git").exists():
        return True
    if (path / "HEAD").exists() and (path / "objects").exists():
        return True
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return Path(proc.stdout.strip()).resolve() == path.resolve()
    except Exception:
        pass
    return False


def _git_repo_metadata(path: Path) -> Tuple[str, str]:
    """Reads current branch and origin remote URL (if configured) from a git repo."""
    branch = ""
    remote_url = ""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            branch = proc.stdout.strip()
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            remote_url = proc.stdout.strip()
    except Exception:
        pass
    return branch, remote_url


def _resolve_main_or_master_branch(
    path: Path,
    preferred: Optional[str] = None,
) -> Optional[str]:
    """
    Strictly resolves the base branch to 'main' or 'master' (checking local refs first,
    then remote origin tracking refs). Returns None if neither branch exists.
    """
    pref = (preferred or "auto").strip().lower()
    candidates = ["master", "main"] if pref == "master" else ["main", "master"]

    for ref_prefix in ("refs/heads/", "refs/remotes/origin/"):
        for cand in candidates:
            try:
                proc = subprocess.run(
                    ["git", "show-ref", "--verify", "--quiet", f"{ref_prefix}{cand}"],
                    cwd=str(path),
                    capture_output=True,
                    timeout=5,
                )
                if proc.returncode == 0:
                    return cand
            except Exception:
                pass
    return None


def _has_non_empty_project_files(path: Path) -> bool:
    """Checks if a directory contains at least one non-hidden file."""
    try:
        for entry in path.iterdir():
            if not entry.name.startswith(".") and entry.name not in IGNORED_DISCOVERY_DIRS:
                return True
    except Exception:
        return False
    return False


def discover_repositories(
    folder_path: str | Path,
    include_non_git: bool = False,
    recursive: bool = False,
    app_root_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Discovers all repositories inside a local folder path.
    Excludes the agent's own root directory to prevent self-mutation.
    """
    raw_str = str(folder_path or "").replace("file://", "").strip()
    if not raw_str:
        raise ValueError("folder_path is required")

    root_dir = Path(os.path.expanduser(raw_str)).resolve()
    if not root_dir.exists():
        raise FileNotFoundError(f"Folder path does not exist: '{root_dir}'")
    if not root_dir.is_dir():
        raise NotADirectoryError(f"Path is not a directory: '{root_dir}'")

    protected_root = app_root_dir.resolve() if app_root_dir else None
    repos: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []

    def _scan_dir(current_dir: Path, depth: int) -> None:
        try:
            entries = sorted(current_dir.iterdir(), key=lambda p: p.name.lower())
        except OSError as exc:
            skipped.append({"path": str(current_dir), "reason": f"Unreadable directory: {exc}"})
            return

        for entry in entries:
            if not entry.is_dir():
                continue
            if entry.name.startswith(".") or entry.name in IGNORED_DISCOVERY_DIRS:
                continue

            resolved_entry = entry.resolve()
            if protected_root and resolved_entry == protected_root:
                skipped.append({
                    "path": str(resolved_entry),
                    "name": entry.name,
                    "reason": "Protected AirGap Remediator root directory",
                })
                continue

            rel_name = resolved_entry.relative_to(root_dir).as_posix()
            if _is_git_repo_dir(resolved_entry):
                branch, remote_url = _git_repo_metadata(resolved_entry)
                base_br = _resolve_main_or_master_branch(resolved_entry)
                repos.append({
                    "name": entry.name,
                    "relative_path": rel_name,
                    "path": str(resolved_entry),
                    "has_git": True,
                    "auto_init_required": False,
                    "current_branch": branch or "main",
                    "base_branch": base_br,
                    "remote_url": GitAgentConfig.sanitize_url(remote_url) if remote_url else "",
                })
                # Stop descending once a repository boundary is found
                continue

            if recursive and depth < 4:
                before_count = len(repos)
                _scan_dir(resolved_entry, depth + 1)
                # If no nested git repos were inside and include_non_git is enabled, consider folder itself
                if len(repos) == before_count and include_non_git and _has_non_empty_project_files(resolved_entry):
                    repos.append({
                        "name": entry.name,
                        "relative_path": rel_name,
                        "path": str(resolved_entry),
                        "has_git": False,
                        "auto_init_required": True,
                        "current_branch": "uninitialized",
                        "remote_url": "",
                    })
            elif include_non_git and _has_non_empty_project_files(resolved_entry):
                repos.append({
                    "name": entry.name,
                    "relative_path": rel_name,
                    "path": str(resolved_entry),
                    "has_git": False,
                    "auto_init_required": True,
                    "current_branch": "uninitialized",
                    "remote_url": "",
                })
            else:
                skipped.append({
                    "path": str(resolved_entry),
                    "name": entry.name,
                    "reason": "Not a Git repository (missing .git)",
                })

    _scan_dir(root_dir, 0)

    return {
        "folder_path": str(root_dir),
        "folder_is_git_repo": _is_git_repo_dir(root_dir),
        "total_repos": len(repos),
        "repos": repos,
        "skipped": skipped,
    }


def validate_schedule_payload(
    payload: Dict[str, Any],
    app_root_dir: Optional[Path] = None,
) -> Tuple[bool, Optional[str]]:
    """Validates schedule creation/update payload and returns (ok, error_message)."""
    folder_path = (payload.get("folder_path") or "").strip()
    if not folder_path:
        return False, "Target local folder path is required."

    cleaned = folder_path.replace("file://", "").strip()
    resolved = Path(os.path.expanduser(cleaned)).resolve()
    if not resolved.exists():
        return False, f"Folder path does not exist: '{resolved}'"
    if not resolved.is_dir():
        return False, f"Folder path is not a directory: '{resolved}'"
    if app_root_dir and resolved == app_root_dir.resolve():
        return False, "Cannot schedule the AirGap Remediator root directory itself. Select a folder containing target repositories."

    stype = (payload.get("schedule_type") or "interval").strip().lower()
    if stype not in ("interval", "daily", "weekly", "cron", "once"):
        return False, f"Unsupported schedule_type '{stype}'. Choose interval, daily, weekly, cron, or once."

    if stype == "interval":
        try:
            mins = int(payload.get("interval_minutes") or 0)
            if mins < 1:
                return False, "Interval must be at least 1 minute."
        except (TypeError, ValueError):
            return False, "Interval minutes must be a valid integer."

    elif stype in ("daily", "weekly"):
        t_str = (payload.get("time_of_day") or "").strip()
        if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", t_str):
            return False, "Time of day must be in 24-hour HH:MM format (e.g. 02:30)."
        if stype == "weekly":
            try:
                days = normalize_days_of_week(payload.get("days_of_week") or [])
                if not days:
                    return False, "Select at least one day of the week for weekly schedules."
            except ValueError as exc:
                return False, str(exc)

    elif stype == "cron":
        expr = (payload.get("cron_expression") or "").strip()
        try:
            CronExpression(expr)
        except Exception as exc:
            return False, f"Invalid cron expression: {exc}"

    elif stype == "once":
        try:
            run_at = parse_iso_aware(payload.get("run_at"))
            if run_at is None:
                return False, "One-time schedules require a valid 'run_at' date/time."
        except Exception as exc:
            return False, f"Invalid 'run_at' datetime: {exc}"

    raw_base = (payload.get("base_branch") or "auto").strip().lower()
    if raw_base not in ("", "auto", "main", "master"):
        return False, "Scheduler base_branch must be 'auto', 'main', or 'master'."

    raw_recipients = payload.get("email_recipients") if "email_recipients" in payload else payload.get("recipient_emails")
    if raw_recipients is not None and str(raw_recipients).strip():
        if not _split_emails(raw_recipients):
            return False, "Please provide valid recipient email address(es) separated by commas, or leave blank to use Email Settings defaults."

    return True, None


def describe_schedule(schedule: Dict[str, Any]) -> str:
    """Generates a human-readable summary string for a schedule."""
    stype = (schedule.get("schedule_type") or "interval").lower()
    if stype == "interval":
        mins = int(schedule.get("interval_minutes") or 60)
        if mins >= 60 and mins % 60 == 0:
            hrs = mins // 60
            return f"Every {hrs} hour{'s' if hrs != 1 else ''}"
        return f"Every {mins} minute{'s' if mins != 1 else ''}"
    if stype == "daily":
        return f"Daily at {schedule.get('time_of_day', '02:00')}"
    if stype == "weekly":
        names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        days = normalize_days_of_week(schedule.get("days_of_week") or [0])
        day_str = ", ".join(names[d] for d in days)
        return f"Weekly ({day_str}) at {schedule.get('time_of_day', '02:00')}"
    if stype == "cron":
        return f"Cron: {schedule.get('cron_expression', '0 * * * *')}"
    if stype == "once":
        return f"Once at {schedule.get('run_at', '')}"
    return stype


class BatchScheduler:
    """
    Persistent background scheduler and sequential batch executor.
    Processes all repositories inside a configured local folder one by one in a background thread.
    """

    MAX_RUN_HISTORY = 100
    MAX_LOGS_PER_RUN = 500

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        app_root_dir: Optional[Path] = None,
        auto_start: bool = False,
        poll_interval_seconds: float = 1.0,
        email_notifier: Optional[EmailReportNotifier] = None,
    ):
        self.app_root_dir = (app_root_dir or Path(__file__).resolve().parents[1]).resolve()
        self.data_dir = (data_dir or (self.app_root_dir / "scheduler_data")).resolve()
        self.email_notifier = email_notifier or EmailReportNotifier(app_root_dir=self.app_root_dir)
        self.runs_dir = self.data_dir / "runs"
        self.schedules_file = self.data_dir / "schedules.json"
        self.runs_index_file = self.data_dir / "runs.json"
        self.poll_interval_seconds = max(0.2, float(poll_interval_seconds))

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._job_queue: queue.Queue[str] = queue.Queue()
        self._ticker_thread: Optional[threading.Thread] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._active_run_id: Optional[str] = None
        self._cancel_flags: Dict[str, threading.Event] = {}
        self._run_auth_cache: Dict[str, Tuple[Optional[str], Optional[str]]] = {}

        self._schedules: Dict[str, Dict[str, Any]] = {}
        self._runs: Dict[str, Dict[str, Any]] = {}

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self._load_state()

        if auto_start:
            self.start()

    def _load_state(self) -> None:
        with self._lock:
            if self.schedules_file.exists():
                try:
                    raw_scheds = json.loads(self.schedules_file.read_text(encoding="utf-8"))
                    if isinstance(raw_scheds, list):
                        for item in raw_scheds:
                            sid = item.get("id")
                            if sid:
                                # Recompute missed next_run_at cleanly on startup for enabled schedules
                                if item.get("enabled", True) and item.get("schedule_type") != "once":
                                    try:
                                        nxt = parse_iso_aware(item.get("next_run_at"))
                                        if nxt is None or nxt < local_now() - dt.timedelta(minutes=5):
                                            item["next_run_at"] = compute_next_run_at(item)
                                    except Exception:
                                        item["next_run_at"] = compute_next_run_at(item)
                                self._schedules[sid] = item
                except Exception as exc:
                    logger.warning("Failed to load schedules.json: %s", exc)

            if self.runs_index_file.exists():
                try:
                    raw_runs = json.loads(self.runs_index_file.read_text(encoding="utf-8"))
                    if isinstance(raw_runs, list):
                        for r in raw_runs:
                            rid = r.get("run_id")
                            if not rid:
                                continue
                            # Recover runs left RUNNING/QUEUED/CANCELLING before a server restart
                            if r.get("status") in ("RUNNING", "QUEUED", "CANCELLING"):
                                r["status"] = "INTERRUPTED"
                                r["finished_at"] = r.get("finished_at") or local_now().isoformat()
                                r["error"] = r.get("error") or "Server restarted while run was in progress."
                                detail_path = self.runs_dir / rid / "run_detail.json"
                                if detail_path.exists():
                                    try:
                                        detail = json.loads(detail_path.read_text(encoding="utf-8"))
                                        detail["status"] = "INTERRUPTED"
                                        detail["finished_at"] = r["finished_at"]
                                        detail["error"] = r["error"]
                                        _atomic_write_json(detail_path, detail)
                                    except Exception:
                                        pass
                            self._runs[rid] = r
                except Exception as exc:
                    logger.warning("Failed to load runs.json: %s", exc)

            self._persist_schedules_locked()
            self._persist_runs_locked()

    def _persist_schedules_locked(self) -> None:
        ordered = sorted(
            self._schedules.values(),
            key=lambda s: s.get("created_at", ""),
            reverse=True,
        )
        _atomic_write_json(self.schedules_file, ordered)

    @staticmethod
    def _run_summary_view(run_data: Dict[str, Any]) -> Dict[str, Any]:
        """Builds a compact summary object for runs.json and list endpoints."""
        return {
            "run_id": run_data["run_id"],
            "schedule_id": run_data.get("schedule_id"),
            "schedule_name": run_data.get("schedule_name"),
            "trigger_source": run_data.get("trigger_source", "scheduled"),
            "folder_path": run_data.get("folder_path"),
            "status": run_data.get("status", "QUEUED"),
            "created_at": run_data.get("created_at"),
            "started_at": run_data.get("started_at"),
            "finished_at": run_data.get("finished_at"),
            "total_repos": run_data.get("total_repos", 0),
            "completed_repos": run_data.get("completed_repos", 0),
            "succeeded_repos": run_data.get("succeeded_repos", 0),
            "failed_repos": run_data.get("failed_repos", 0),
            "skipped_repos": run_data.get("skipped_repos", 0),
            "total_initial_findings": run_data.get("total_initial_findings", 0),
            "total_post_findings": run_data.get("total_post_findings", 0),
            "total_remediated": run_data.get("total_remediated", 0),
            "current_repo_name": run_data.get("current_repo_name"),
            "current_step": run_data.get("current_step"),
            "progress_percent": run_data.get("progress_percent", 0),
            "error": run_data.get("error"),
        }

    def _persist_runs_locked(self) -> None:
        ordered = sorted(
            self._runs.values(),
            key=lambda r: r.get("created_at", ""),
            reverse=True,
        )[: self.MAX_RUN_HISTORY]
        self._runs = {r["run_id"]: r for r in ordered}
        summaries = [self._run_summary_view(r) for r in ordered]
        _atomic_write_json(self.runs_index_file, summaries)

    def _persist_run_detail(self, run_data: Dict[str, Any]) -> None:
        with self._lock:
            rid = run_data["run_id"]
            ev = self._cancel_flags.get(rid)
            if ev and ev.is_set() and run_data.get("status") == "RUNNING":
                run_data["status"] = "CANCELLING"
            self._runs[rid] = self._run_summary_view(run_data)
            detail_path = self.runs_dir / rid / "run_detail.json"
            _atomic_write_json(detail_path, run_data)
            self._persist_runs_locked()

    def start(self) -> None:
        """Starts the background scheduler ticker and worker threads."""
        with self._lock:
            if self.is_running():
                return
            self._stop_event.clear()
            self._ticker_thread = threading.Thread(
                target=self._ticker_loop,
                name="BatchScheduler-Ticker",
                daemon=True,
            )
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="BatchScheduler-Worker",
                daemon=True,
            )
            self._ticker_thread.start()
            self._worker_thread.start()
            logger.info("Background BatchScheduler started (data_dir=%s)", self.data_dir)

    def stop(self, timeout: float = 5.0) -> None:
        """Signals background threads to stop cleanly and cancels active run."""
        self._stop_event.set()
        with self._lock:
            for ev in self._cancel_flags.values():
                ev.set()
        if self._ticker_thread and self._ticker_thread.is_alive():
            self._ticker_thread.join(timeout=timeout)
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
        self._ticker_thread = None
        self._worker_thread = None

    def is_running(self) -> bool:
        return bool(
            not self._stop_event.is_set()
            and self._ticker_thread
            and self._ticker_thread.is_alive()
            and self._worker_thread
            and self._worker_thread.is_alive()
        )

    # ------------------------------------------------------------------
    # Schedule CRUD
    # ------------------------------------------------------------------
    @staticmethod
    def _public_schedule_view(sched: Dict[str, Any]) -> Dict[str, Any]:
        """Returns a copy of a schedule dict with git_token masked for safe API/UI exposure."""
        view = dict(sched)
        raw_tok = view.get("git_token") or ""
        has_tok = bool(str(raw_tok).strip())
        view["has_git_token"] = has_tok
        view["git_token"] = "********" if has_tok else ""
        return view

    def list_schedules(self) -> List[Dict[str, Any]]:
        with self._lock:
            return sorted(
                [self._public_schedule_view(s) for s in self._schedules.values()],
                key=lambda s: s.get("created_at", ""),
                reverse=True,
            )

    def get_schedule(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            item = self._schedules.get(schedule_id)
            return self._public_schedule_view(item) if item else None

    def _build_schedule_record(
        self,
        payload: Dict[str, Any],
        existing: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now = local_now()
        now_iso = now.isoformat()
        stype = (payload.get("schedule_type") or (existing or {}).get("schedule_type") or "interval").strip().lower()
        enabled = bool(payload["enabled"]) if "enabled" in payload else bool((existing or {}).get("enabled", True))

        raw_folder = (payload.get("folder_path") or (existing or {}).get("folder_path") or "").replace("file://", "").strip()
        resolved_folder = str(Path(os.path.expanduser(raw_folder)).resolve())

        days_of_week = (
            normalize_days_of_week(payload["days_of_week"])
            if "days_of_week" in payload
            else (existing or {}).get("days_of_week", [0])
        )

        raw_base = (payload.get("base_branch") if "base_branch" in payload else (existing or {}).get("base_branch")) or "auto"
        norm_base = str(raw_base).strip().lower()
        if norm_base not in ("auto", "main", "master"):
            norm_base = "auto"

        raw_rec = (
            payload.get("email_recipients")
            if "email_recipients" in payload
            else (
                payload.get("recipient_emails")
                if "recipient_emails" in payload
                else (existing or {}).get("email_recipients", "")
            )
        )
        norm_rec = ", ".join(_split_emails(raw_rec)) if raw_rec else ""

        if payload.get("clear_git_token"):
            resolved_git_token = ""
        elif "git_token" in payload or "token" in payload:
            raw_tok = payload.get("git_token") if "git_token" in payload else payload.get("token")
            tok_str = str(raw_tok or "").strip()
            if tok_str == "********" and existing:
                resolved_git_token = str(existing.get("git_token") or "")
            else:
                resolved_git_token = tok_str
        else:
            resolved_git_token = str((existing or {}).get("git_token") or "")

        if "git_username" in payload or "username" in payload:
            raw_uname = payload.get("git_username") if "git_username" in payload else payload.get("username")
            resolved_git_username = str(raw_uname or "").strip()
        else:
            resolved_git_username = str((existing or {}).get("git_username") or "")

        record: Dict[str, Any] = {
            "id": (existing or {}).get("id") or f"sched-{uuid.uuid4().hex[:8]}",
            "name": (payload.get("name") or (existing or {}).get("name") or f"Batch Audit ({Path(resolved_folder).name})").strip(),
            "folder_path": resolved_folder,
            "enabled": enabled,
            "schedule_type": stype,
            "interval_minutes": int(payload.get("interval_minutes") or (existing or {}).get("interval_minutes") or 60),
            "time_of_day": (payload.get("time_of_day") or (existing or {}).get("time_of_day") or "02:00").strip(),
            "days_of_week": days_of_week,
            "cron_expression": (payload.get("cron_expression") or (existing or {}).get("cron_expression") or "0 2 * * *").strip(),
            "run_at": payload.get("run_at") if "run_at" in payload else (existing or {}).get("run_at"),
            "scanner_engine": (payload.get("scanner_engine") or (existing or {}).get("scanner_engine") or "all").strip().lower(),
            "llm_provider": (payload.get("llm_provider") or (existing or {}).get("llm_provider") or "ollama").strip().lower(),
            "llm_model": (payload.get("llm_model") if "llm_model" in payload else (existing or {}).get("llm_model")) or None,
            "llm_base_url": (payload.get("llm_base_url") if "llm_base_url" in payload else (existing or {}).get("llm_base_url")) or None,
            "base_branch": norm_base,
            "feature_branch": (payload.get("feature_branch") if "feature_branch" in payload else (existing or {}).get("feature_branch")) or "remediation/airgap-api-compliance",
            "timestamp_branch": bool(payload["timestamp_branch"]) if "timestamp_branch" in payload else bool((existing or {}).get("timestamp_branch", False)),
            "include_non_git": bool(payload["include_non_git"]) if "include_non_git" in payload else bool((existing or {}).get("include_non_git", False)),
            "recursive": bool(payload["recursive"]) if "recursive" in payload else bool((existing or {}).get("recursive", False)),
            "run_build_test": bool(payload["run_build_test"]) if "run_build_test" in payload else bool((existing or {}).get("run_build_test", True)),
            "auto_commit": bool(payload["auto_commit"]) if "auto_commit" in payload else bool((existing or {}).get("auto_commit", True)),
            "auto_push": bool(payload["auto_push"]) if "auto_push" in payload else bool((existing or {}).get("auto_push", True)),
            "auto_pr": bool(payload["auto_pr"]) if "auto_pr" in payload else bool((existing or {}).get("auto_pr", True)),
            "git_token": resolved_git_token,
            "git_username": resolved_git_username,
            "send_email": bool(payload["send_email"]) if "send_email" in payload else bool((existing or {}).get("send_email", True)),
            "email_recipients": norm_rec,
            "max_iterations": max(1, min(int(payload.get("max_iterations") or (existing or {}).get("max_iterations") or 5), 5)),
            "created_at": (existing or {}).get("created_at") or now_iso,
            "updated_at": now_iso,
            "last_run_id": (existing or {}).get("last_run_id"),
            "last_run_at": (existing or {}).get("last_run_at"),
            "last_run_status": (existing or {}).get("last_run_status"),
        }
        record["description"] = describe_schedule(record)
        record["next_run_at"] = compute_next_run_at(record, after=now)
        return record

    def create_schedule(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ok, err = validate_schedule_payload(payload, app_root_dir=self.app_root_dir)
        if not ok:
            raise ValueError(err or "Invalid schedule configuration")

        record = self._build_schedule_record(payload)
        with self._lock:
            self._schedules[record["id"]] = record
            self._persist_schedules_locked()

        run_info = None
        if payload.get("run_immediately"):
            run_info = self.trigger_schedule_now(record["id"], trigger_source="immediate")
            record = self.get_schedule(record["id"]) or self._public_schedule_view(record)
        else:
            record = self._public_schedule_view(record)

        return {"schedule": record, "triggered_run": run_info}

    def update_schedule(self, schedule_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            existing = self._schedules.get(schedule_id)
            if not existing:
                raise KeyError(f"Schedule '{schedule_id}' not found")
            merged = dict(existing)
            merged.update(payload)
            ok, err = validate_schedule_payload(merged, app_root_dir=self.app_root_dir)
            if not ok:
                raise ValueError(err or "Invalid schedule configuration")
            updated = self._build_schedule_record(merged, existing=existing)
            self._schedules[schedule_id] = updated
            self._persist_schedules_locked()
            return self._public_schedule_view(updated)

    def toggle_schedule(self, schedule_id: str, enabled: Optional[bool] = None) -> Dict[str, Any]:
        with self._lock:
            existing = self._schedules.get(schedule_id)
            if not existing:
                raise KeyError(f"Schedule '{schedule_id}' not found")
            new_state = (not bool(existing.get("enabled", True))) if enabled is None else bool(enabled)
            existing["enabled"] = new_state
            existing["updated_at"] = local_now().isoformat()
            existing["next_run_at"] = compute_next_run_at(existing) if new_state else None
            self._persist_schedules_locked()
            return self._public_schedule_view(existing)

    def delete_schedule(self, schedule_id: str) -> bool:
        with self._lock:
            if schedule_id not in self._schedules:
                return False
            del self._schedules[schedule_id]
            self._persist_schedules_locked()
            return True

    # ------------------------------------------------------------------
    # Run Enqueueing, Inspection & Cancellation
    # ------------------------------------------------------------------
    def _has_pending_or_active_run_for_schedule_locked(self, schedule_id: str) -> bool:
        return any(
            r.get("schedule_id") == schedule_id and r.get("status") in ("QUEUED", "RUNNING")
            for r in self._runs.values()
        )

    def trigger_schedule_now(
        self,
        schedule_id: str,
        trigger_source: str = "manual",
    ) -> Dict[str, Any]:
        with self._lock:
            sched = self._schedules.get(schedule_id)
            if not sched:
                raise KeyError(f"Schedule '{schedule_id}' not found")
            sched_snapshot = dict(sched)

        return self._enqueue_batch_run(sched_snapshot, trigger_source=trigger_source)

    def _enqueue_batch_run(
        self,
        schedule_snapshot: Dict[str, Any],
        trigger_source: str = "scheduled",
    ) -> Dict[str, Any]:
        now_iso = local_now().isoformat()
        run_id = f"run-{local_now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        public_snapshot = self._public_schedule_view(schedule_snapshot)
        raw_tok = schedule_snapshot.get("git_token") or ""
        raw_uname = schedule_snapshot.get("git_username") or ""
        with self._lock:
            self._run_auth_cache[run_id] = (raw_tok or None, raw_uname or None)
        run_data: Dict[str, Any] = {
            "run_id": run_id,
            "schedule_id": public_snapshot.get("id"),
            "schedule_name": public_snapshot.get("name"),
            "trigger_source": trigger_source,
            "folder_path": public_snapshot.get("folder_path"),
            "schedule_snapshot": public_snapshot,
            "status": "QUEUED",
            "created_at": now_iso,
            "started_at": None,
            "finished_at": None,
            "total_repos": 0,
            "completed_repos": 0,
            "succeeded_repos": 0,
            "failed_repos": 0,
            "skipped_repos": 0,
            "total_initial_findings": 0,
            "total_post_findings": 0,
            "total_remediated": 0,
            "current_repo_name": None,
            "current_step": "QUEUED",
            "progress_percent": 0,
            "repos": [],
            "skipped": [],
            "logs": [
                {
                    "timestamp": now_iso,
                    "level": "info",
                    "repo": "Scheduler",
                    "message": f"Queued background batch run ({trigger_source}) for folder: {schedule_snapshot.get('folder_path')}",
                }
            ],
            "error": None,
        }

        with self._lock:
            self._cancel_flags[run_id] = threading.Event()
            (self.runs_dir / run_id).mkdir(parents=True, exist_ok=True)
            self._persist_run_detail(run_data)
            self._job_queue.put(run_id)

        return self._run_summary_view(run_data)

    def list_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            ordered = sorted(
                self._runs.values(),
                key=lambda r: r.get("created_at", ""),
                reverse=True,
            )
            return [dict(r) for r in ordered[:limit]]

    @staticmethod
    def _is_valid_id(identifier: str) -> bool:
        return bool(identifier and re.fullmatch(r"[a-zA-Z0-9_-]+", identifier))

    def get_run_detail(self, run_id: str) -> Optional[Dict[str, Any]]:
        if not self._is_valid_id(run_id):
            return None
        detail_path = (self.runs_dir / run_id / "run_detail.json").resolve()
        with self._lock:
            if detail_path.exists():
                try:
                    return json.loads(detail_path.read_text(encoding="utf-8"))
                except Exception:
                    pass
            summary = self._runs.get(run_id)
            return dict(summary) if summary else None

    def cancel_run(self, run_id: str) -> Dict[str, Any]:
        with self._lock:
            detail = self.get_run_detail(run_id)
            if not detail:
                raise KeyError(f"Run '{run_id}' not found")
            status = detail.get("status")
            if status not in ("QUEUED", "RUNNING", "CANCELLING"):
                return {"run_id": run_id, "status": status, "message": f"Run is already {status}"}

            ev = self._cancel_flags.get(run_id)
            if ev is None:
                ev = threading.Event()
                self._cancel_flags[run_id] = ev
            ev.set()

            if status == "QUEUED":
                detail["status"] = "CANCELLED"
                detail["finished_at"] = local_now().isoformat()
                detail["current_step"] = "CANCELLED"
                detail["logs"].append({
                    "timestamp": detail["finished_at"],
                    "level": "warn",
                    "repo": "Scheduler",
                    "message": "Queued run cancelled by user before execution started.",
                })
                self._persist_run_detail(detail)
                return {"run_id": run_id, "status": "CANCELLED", "message": "Queued run cancelled."}

            detail["status"] = "CANCELLING"
            detail["current_step"] = "CANCELLING"
            for r in detail.get("repos") or []:
                if r.get("status") == "RUNNING":
                    r["step_detail"] = "Cancelling active operation..."
            detail["logs"].append({
                "timestamp": local_now().isoformat(),
                "level": "warn",
                "repo": "Scheduler",
                "message": "Cancellation requested; aborting active step immediately...",
            })
            self._persist_run_detail(detail)
            return {"run_id": run_id, "status": "CANCELLING", "message": "Cancellation requested."}

    def clear_finished_runs(self) -> int:
        removed = 0
        with self._lock:
            to_delete = [
                rid for rid, r in self._runs.items()
                if r.get("status") not in ("QUEUED", "RUNNING", "CANCELLING")
            ]
            for rid in to_delete:
                del self._runs[rid]
                run_folder = self.runs_dir / rid
                if run_folder.exists():
                    shutil.rmtree(run_folder, ignore_errors=True)
                self._cancel_flags.pop(rid, None)
                removed += 1
            self._persist_runs_locked()
        return removed

    def get_repo_report(
        self,
        run_id: str,
        repo_key: str,
        report_type: str = "remediation",
    ) -> Tuple[Optional[str], str]:
        detail = self.get_run_detail(run_id)
        if not detail:
            return None, "application/json; charset=utf-8"

        target_repo = None
        for idx, r in enumerate(detail.get("repos") or []):
            if str(idx) == str(repo_key) or r.get("name") == repo_key or r.get("relative_path") == repo_key:
                target_repo = r
                break

        if not target_repo:
            return None, "application/json; charset=utf-8"

        rtype = (report_type or "remediation").lower()
        key = "scan_report_path" if rtype == "scan" else "remediation_report_path"
        raw_path = target_repo.get(key)
        if not raw_path:
            return None, "application/json; charset=utf-8"

        resolved = Path(raw_path).resolve()
        run_root = (self.runs_dir / run_id).resolve()
        if not str(resolved).startswith(str(run_root) + os.sep) or not resolved.exists():
            return None, "application/json; charset=utf-8"

        return resolved.read_text(encoding="utf-8", errors="replace"), "text/html; charset=utf-8"

    def get_overview(self) -> Dict[str, Any]:
        with self._lock:
            schedules = self.list_schedules()
            runs = self.list_runs(limit=30)
            active_run = None
            if self._active_run_id:
                active_run = self.get_run_detail(self._active_run_id)
            elif runs and runs[0].get("status") in ("RUNNING", "QUEUED", "CANCELLING"):
                active_run = self.get_run_detail(runs[0]["run_id"])

            queued_count = sum(1 for r in self._runs.values() if r.get("status") == "QUEUED")
            now = local_now()
            return {
                "scheduler_running": self.is_running(),
                "active_run_id": self._active_run_id,
                "queued_runs": queued_count,
                "schedules": schedules,
                "runs": runs,
                "active_run": active_run,
                "server_time_local": now.isoformat(),
                "server_time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            }

    # ------------------------------------------------------------------
    # Background Loops & Execution Engine
    # ------------------------------------------------------------------
    def _ticker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._check_due_schedules()
            except Exception as exc:
                logger.error("Scheduler ticker error: %s", exc, exc_info=True)
            self._stop_event.wait(self.poll_interval_seconds)

    def _check_due_schedules(self) -> None:
        now = local_now()
        to_trigger: List[Dict[str, Any]] = []

        with self._lock:
            changed = False
            for sid, sched in self._schedules.items():
                if not sched.get("enabled", True):
                    continue
                next_at = parse_iso_aware(sched.get("next_run_at"))
                if next_at is None:
                    try:
                        sched["next_run_at"] = compute_next_run_at(sched, after=now)
                        changed = True
                    except Exception:
                        pass
                    continue

                if next_at <= now:
                    if self._has_pending_or_active_run_for_schedule_locked(sid):
                        continue

                    to_trigger.append(dict(sched))
                    if (sched.get("schedule_type") or "").lower() == "once":
                        sched["enabled"] = False
                        sched["next_run_at"] = None
                    else:
                        sched["next_run_at"] = compute_next_run_at(sched, after=now)
                    sched["updated_at"] = now.isoformat()
                    changed = True

            if changed:
                self._persist_schedules_locked()

        for sched_snapshot in to_trigger:
            logger.info("Schedule '%s' (%s) triggered at %s", sched_snapshot.get("name"), sched_snapshot.get("id"), now.isoformat())
            self._enqueue_batch_run(sched_snapshot, trigger_source="scheduled")

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                run_id = self._job_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                detail = self.get_run_detail(run_id)
                if not detail or detail.get("status") == "CANCELLED":
                    continue
                cancel_ev = self._cancel_flags.get(run_id)
                if cancel_ev and cancel_ev.is_set():
                    continue
                self._execute_batch_run(run_id)
            except Exception as exc:
                logger.error("Worker error executing run %s: %s", run_id, exc, exc_info=True)
            finally:
                with self._lock:
                    if self._active_run_id == run_id:
                        self._active_run_id = None
                self._job_queue.task_done()

    def _append_log(self, run_data: Dict[str, Any], level: str, repo_label: str, message: str) -> None:
        entry = {
            "timestamp": local_now().isoformat(),
            "level": level,
            "repo": repo_label,
            "message": message,
        }
        logs = run_data.setdefault("logs", [])
        logs.append(entry)
        if len(logs) > self.MAX_LOGS_PER_RUN:
            del logs[: len(logs) - self.MAX_LOGS_PER_RUN]

    def _update_schedule_last_run(self, schedule_id: Optional[str], run_id: str, status: str) -> None:
        if not schedule_id:
            return
        with self._lock:
            sched = self._schedules.get(schedule_id)
            if sched:
                sched["last_run_id"] = run_id
                sched["last_run_at"] = local_now().isoformat()
                sched["last_run_status"] = status
                self._persist_schedules_locked()

    def _execute_batch_run(self, run_id: str) -> None:
        run_data = self.get_run_detail(run_id)
        if not run_data:
            return

        cancel_ev = self._cancel_flags.setdefault(run_id, threading.Event())
        sched = dict(run_data.get("schedule_snapshot") or {})
        with self._lock:
            cached_auth = self._run_auth_cache.pop(run_id, None)
            live_sched = self._schedules.get(run_data.get("schedule_id") or "")
        if cached_auth and (cached_auth[0] or cached_auth[1]):
            if cached_auth[0]:
                sched["git_token"] = cached_auth[0]
            if cached_auth[1]:
                sched["git_username"] = cached_auth[1]
        elif live_sched:
            if live_sched.get("git_token"):
                sched["git_token"] = live_sched["git_token"]
            if live_sched.get("git_username"):
                sched["git_username"] = live_sched["git_username"]
        if sched.get("git_token") == "********":
            sched["git_token"] = (live_sched or {}).get("git_token") or ""
        folder_path = run_data.get("folder_path") or sched.get("folder_path") or ""

        with self._lock:
            self._active_run_id = run_id

        run_data["status"] = "RUNNING"
        run_data["started_at"] = local_now().isoformat()
        run_data["current_step"] = "DISCOVERING"
        self._append_log(run_data, "info", "Scheduler", f"Starting sequential batch run on folder: {folder_path}")
        self._update_schedule_last_run(run_data.get("schedule_id"), run_id, "RUNNING")
        self._persist_run_detail(run_data)

        try:
            discovery = discover_repositories(
                folder_path=folder_path,
                include_non_git=bool(sched.get("include_non_git", False)),
                recursive=bool(sched.get("recursive", False)),
                app_root_dir=self.app_root_dir,
            )
        except Exception as disc_exc:
            run_data["status"] = "FAILED"
            run_data["error"] = str(disc_exc)
            run_data["finished_at"] = local_now().isoformat()
            run_data["current_step"] = "FAILED"
            self._append_log(run_data, "error", "Scheduler", f"Repository discovery failed: {disc_exc}")
            self._persist_run_detail(run_data)
            self._update_schedule_last_run(run_data.get("schedule_id"), run_id, "FAILED")
            return

        discovered = discovery.get("repos") or []
        run_data["skipped"] = discovery.get("skipped") or []
        run_data["skipped_repos"] = len(run_data["skipped"])
        run_data["total_repos"] = len(discovered)
        run_data["repos"] = [
            {
                "index": idx,
                "name": repo["name"],
                "relative_path": repo["relative_path"],
                "path": repo["path"],
                "has_git": repo["has_git"],
                "status": "PENDING",
                "current_step": "QUEUED",
                "step_detail": "Waiting in sequential queue",
                "started_at": None,
                "finished_at": None,
                "base_branch": None,
                "feature_branch": None,
                "build_test_status": None,
                "initial_findings_count": 0,
                "initial_posture_score": None,
                "initial_posture_grade": None,
                "post_findings_count": None,
                "post_posture_score": None,
                "post_posture_grade": None,
                "remediated_count": 0,
                "iterations_run": 0,
                "resolved_all": False,
                "files_modified": [],
                "commit_hash": None,
                "commit_status": None,
                "remote_url": repo.get("remote_url") or None,
                "push_status": None,
                "pr_number": None,
                "pr_url": None,
                "pr_file_path": None,
                "scan_report_path": None,
                "remediation_report_path": None,
                "email_status": None,
                "email_message": None,
                "email_recipients": [],
                "email_outbox_file": None,
                "email_notification": None,
                "error": None,
            }
            for idx, repo in enumerate(discovered)
        ]

        if not discovered:
            run_data["status"] = "COMPLETED"
            run_data["finished_at"] = local_now().isoformat()
            run_data["current_step"] = "COMPLETED"
            run_data["progress_percent"] = 100
            self._append_log(run_data, "warn", "Scheduler", f"No repositories found inside '{folder_path}'.")
            self._persist_run_detail(run_data)
            self._update_schedule_last_run(run_data.get("schedule_id"), run_id, "COMPLETED")
            return

        self._append_log(
            run_data,
            "info",
            "Scheduler",
            f"Discovered {len(discovered)} repository(s) to process sequentially: {', '.join(r['name'] for r in discovered)}",
        )
        self._persist_run_detail(run_data)

        # Process every repository strictly one by one
        for idx, repo_item in enumerate(run_data["repos"]):
            if self._stop_event.is_set() or cancel_ev.is_set():
                for rem in run_data["repos"][idx:]:
                    rem["status"] = "CANCELLED"
                    rem["current_step"] = "CANCELLED"
                    rem["step_detail"] = "Cancelled before starting"
                run_data["status"] = "CANCELLED"
                run_data["finished_at"] = local_now().isoformat()
                run_data["current_step"] = "CANCELLED"
                run_data["current_repo_name"] = None
                self._append_log(run_data, "warn", "Scheduler", "Batch run cancelled; remaining repositories skipped.")
                self._persist_run_detail(run_data)
                self._update_schedule_last_run(run_data.get("schedule_id"), run_id, "CANCELLED")
                return

            run_data["current_repo_name"] = repo_item["name"]
            self._process_single_repo(run_data, repo_item, sched, cancel_ev)

            # Update run-level rollups after each repository completes
            run_data["completed_repos"] = sum(
                1 for r in run_data["repos"] if r["status"] in ("COMPLETED", "NO_CHANGES", "FAILED")
            )
            run_data["succeeded_repos"] = sum(
                1 for r in run_data["repos"] if r["status"] in ("COMPLETED", "NO_CHANGES")
            )
            run_data["failed_repos"] = sum(1 for r in run_data["repos"] if r["status"] == "FAILED")
            run_data["total_initial_findings"] = sum((r.get("initial_findings_count") or 0) for r in run_data["repos"])
            run_data["total_post_findings"] = sum((r.get("post_findings_count") or 0) for r in run_data["repos"])
            run_data["total_remediated"] = sum((r.get("remediated_count") or 0) for r in run_data["repos"])
            run_data["progress_percent"] = int((run_data["completed_repos"] / len(run_data["repos"])) * 100)
            self._persist_run_detail(run_data)

            if repo_item.get("status") == "CANCELLED" or cancel_ev.is_set() or self._stop_event.is_set():
                for rem in run_data["repos"][idx + 1 :]:
                    rem["status"] = "CANCELLED"
                    rem["current_step"] = "CANCELLED"
                    rem["step_detail"] = "Cancelled before starting"
                run_data["status"] = "CANCELLED"
                run_data["finished_at"] = local_now().isoformat()
                run_data["current_step"] = "CANCELLED"
                run_data["current_repo_name"] = None
                self._append_log(run_data, "warn", "Scheduler", "Batch run cancelled; stopped immediately.")
                self._persist_run_detail(run_data)
                self._update_schedule_last_run(run_data.get("schedule_id"), run_id, "CANCELLED")
                return

        final_status = "COMPLETED"
        if run_data["failed_repos"] == len(run_data["repos"]):
            final_status = "FAILED"
        elif run_data["failed_repos"] > 0:
            final_status = "COMPLETED_WITH_ERRORS"

        run_data["status"] = final_status
        run_data["finished_at"] = local_now().isoformat()
        run_data["current_step"] = "COMPLETED"
        run_data["current_repo_name"] = None
        run_data["progress_percent"] = 100
        self._append_log(
            run_data,
            "success" if final_status == "COMPLETED" else "warn",
            "Scheduler",
            (
                f"Batch finished ({final_status}): {run_data['succeeded_repos']}/{run_data['total_repos']} repo(s) succeeded, "
                f"{run_data['failed_repos']} failed, {run_data['total_remediated']} issue(s) remediated."
            ),
        )
        self._persist_run_detail(run_data)
        self._update_schedule_last_run(run_data.get("schedule_id"), run_id, final_status)

    @staticmethod
    def _ensure_unborn_head_committed(repo_path: Path, author_name: str, author_email: str) -> None:
        """If a local .git repo has 0 commits (unborn HEAD), creates an initial commit so branching works."""
        if not (repo_path / ".git").exists():
            return
        head_check = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=str(repo_path),
            capture_output=True,
        )
        if head_check.returncode == 0:
            return

        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = author_name
        env["GIT_COMMITTER_NAME"] = author_name
        env["GIT_AUTHOR_EMAIL"] = author_email
        env["GIT_COMMITTER_EMAIL"] = author_email
        env["GIT_TERMINAL_PROMPT"] = "0"
        subprocess.run(["git", "add", "-A"], cwd=str(repo_path), capture_output=True, env=env)
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "chore: initial baseline repository snapshot"],
            cwd=str(repo_path),
            capture_output=True,
            env=env,
        )
        # Ensure main/master branch refs exist for strict main/master scheduling
        if not _resolve_main_or_master_branch(repo_path):
            subprocess.run(["git", "branch", "-f", "main", "HEAD"], cwd=str(repo_path), capture_output=True, env=env)

    @staticmethod
    def _prepare_clean_main_or_master(
        repo_path: Path,
        preferred_base: Optional[str],
        feature_branch: str,
        feature_prefix: str = "remediation/",
        git_token: Optional[str] = None,
        git_username: Optional[str] = None,
    ) -> Tuple[str, Optional[str]]:
        """
        Prepares a local Git repository so it switches cleanly to 'main' or 'master'.
        Returns (resolved_base_branch, optional_cleanup_log_message).
        Raises ValueError if neither 'main' nor 'master' exists.
        """
        git_env = os.environ.copy()
        git_env["GIT_TERMINAL_PROMPT"] = "0"

        # Fetch origin (best-effort; air-gapped repos without reachable origin continue cleanly)
        rem_proc = subprocess.run(
            ["git", "remote"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            env=git_env,
        )
        if rem_proc.returncode == 0 and "origin" in [r.strip() for r in rem_proc.stdout.splitlines()]:
            try:
                url_proc = subprocess.run(
                    ["git", "remote", "get-url", "origin"],
                    cwd=str(repo_path),
                    capture_output=True,
                    text=True,
                    env=git_env,
                )
                origin_url = url_proc.stdout.strip() if url_proc.returncode == 0 else ""
                auth_fetch_url = ""
                if origin_url and git_token:
                    helper_cfg = GitAgentConfig(
                        repo_url=str(repo_path),
                        token=git_token,
                        username=git_username,
                        provider=ProviderType.LOCAL,
                    )
                    auth_fetch_url = helper_cfg.build_authenticated_remote_url(origin_url)
                if auth_fetch_url and "@" in auth_fetch_url.split("://", 1)[-1].split("/", 1)[0]:
                    fetch_cmd = ["git", "-c", "credential.helper=", "fetch", auth_fetch_url, "+refs/heads/*:refs/remotes/origin/*"]
                else:
                    fetch_cmd = ["git", "fetch", "origin"]
                subprocess.run(
                    fetch_cmd,
                    cwd=str(repo_path),
                    capture_output=True,
                    text=True,
                    env=git_env,
                    timeout=10,
                )
            except subprocess.TimeoutExpired:
                pass

        curr_proc = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            env=git_env,
        )
        curr_branch = curr_proc.stdout.strip() if curr_proc.returncode == 0 else "HEAD"

        resolved_base = _resolve_main_or_master_branch(repo_path, preferred=preferred_base)
        if not resolved_base:
            raise ValueError(
                f"Repository '{repo_path.name}' does not have a 'main' or 'master' branch (current branch: '{curr_branch}')."
            )

        status_proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            env=git_env,
        )
        cleanup_note: Optional[str] = None
        if status_proc.returncode == 0 and status_proc.stdout.strip():
            is_rem_branch = (
                curr_branch == feature_branch
                or curr_branch.startswith(feature_prefix)
                or curr_branch.startswith("remediation/")
                or curr_branch.startswith("agent/")
            )
            if is_rem_branch:
                subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=str(repo_path), capture_output=True, env=git_env)
                subprocess.run(["git", "clean", "-fd"], cwd=str(repo_path), capture_output=True, env=git_env)
                cleanup_note = (
                    f"Cleaned leftover uncommitted changes on branch '{curr_branch}' before switching to '{resolved_base}'."
                )
            else:
                subprocess.run(
                    ["git", "stash", "push", "-u", "-m", "airgap-scheduler-autostash"],
                    cwd=str(repo_path),
                    capture_output=True,
                    env=git_env,
                )
                cleanup_note = (
                    f"Auto-stashed uncommitted changes on '{curr_branch}' before checking out '{resolved_base}'."
                )

        return resolved_base, cleanup_note

    def _process_single_repo(
        self,
        run_data: Dict[str, Any],
        repo_item: Dict[str, Any],
        sched: Dict[str, Any],
        cancel_ev: threading.Event,
    ) -> None:
        repo_name = repo_item["name"]
        repo_path = Path(repo_item["path"]).resolve()
        run_id = run_data["run_id"]
        repo_slug = f"{repo_item['index'] + 1:02d}_{_slugify(repo_name)}"
        repo_artifacts_dir = self.runs_dir / run_id / repo_slug
        findings_dir = repo_artifacts_dir / "findings"
        reports_dir = repo_artifacts_dir / "reports"
        scratch_repos_root = repo_artifacts_dir / "_scratch_repos"
        findings_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)
        scratch_repos_root.mkdir(parents=True, exist_ok=True)

        repo_item["status"] = "RUNNING"
        repo_item["started_at"] = local_now().isoformat()

        def set_step(step: str, detail: str) -> None:
            repo_item["current_step"] = step
            repo_item["step_detail"] = detail
            run_data["current_step"] = f"{repo_name}: {step}"
            self._persist_run_detail(run_data)

        try:
            # ----------------------------------------------------------
            # Step 1: Git Workspace Prep
            # ----------------------------------------------------------
            set_step("PREPARE", "Preparing local repository and remediation branch...")
            self._append_log(run_data, "info", repo_name, f"Step 1/5: Preparing workspace at {repo_path}")

            pref_base = (sched.get("base_branch") or "auto").strip().lower()
            if pref_base not in ("auto", "main", "master"):
                pref_base = "auto"

            feature_branch = sched.get("feature_branch") or "remediation/airgap-api-compliance"
            if sched.get("timestamp_branch"):
                ts_suffix = local_now().strftime("%Y%m%d-%H%M%S")
                feature_branch = f"{feature_branch.rstrip('/')}-{ts_suffix}"

            auto_init = bool(sched.get("include_non_git", False) or repo_item.get("auto_init_required", False))
            if repo_path.name == "CustomerApi" and not (repo_path / ".git").exists():
                auto_init = True

            sched_token = (sched.get("git_token") or "").strip()
            if sched_token == "********":
                sched_token = ""
            sched_username = (sched.get("git_username") or "").strip() or None

            is_existing_git = (repo_path / ".git").exists() or _is_git_repo_dir(repo_path)
            if is_existing_git:
                self._ensure_unborn_head_committed(repo_path, "Git SubAgent", "git-agent@subagent.local")
                resolved_base, cleanup_note = self._prepare_clean_main_or_master(
                    repo_path=repo_path,
                    preferred_base=pref_base,
                    feature_branch=feature_branch,
                    git_token=sched_token or None,
                    git_username=sched_username,
                )
                if cleanup_note:
                    self._append_log(run_data, "info", repo_name, cleanup_note)
            else:
                resolved_base = "master" if pref_base == "master" else "main"

            git_config = GitAgentConfig(
                repo_url=str(repo_path),
                token=sched_token or None,
                username=sched_username,
                provider=ProviderType.LOCAL,
                base_branch=resolved_base,
                feature_branch_name=feature_branch,
                workspace_dir=str(repo_path),
                auto_init=auto_init,
            )
            git_agent = GitSubAgent(git_config)
            ctx = git_agent.prepare_workspace(auto_init=auto_init, reset_feature_branch=True)
            repo_item["has_git"] = True
            repo_item["base_branch"] = ctx.base_branch
            repo_item["feature_branch"] = ctx.feature_branch
            repo_item["remote_url"] = git_agent.get_sanitized_remote_url() or repo_item.get("remote_url")
            self._append_log(
                run_data,
                "success",
                repo_name,
                f"Workspace ready on branch '{ctx.feature_branch}' (base: '{ctx.base_branch}')",
            )

            # Optional Build & Unit Test verification
            if sched.get("run_build_test", True):
                set_step("BUILD_TEST", "Compiling and running baseline unit tests...")
                try:
                    bt_res = git_agent.build_and_test()
                    build_st = (bt_res.get("build") or {}).get("status", "skipped")
                    test_st = (bt_res.get("tests") or {}).get("status", "skipped")
                    repo_item["build_test_status"] = f"build:{build_st} tests:{test_st}"
                    self._append_log(run_data, "info", repo_name, f"Build & Test: {bt_res.get('summary', repo_item['build_test_status'])}")
                except Exception as bt_exc:
                    repo_item["build_test_status"] = f"error: {bt_exc}"
                    self._append_log(run_data, "warn", repo_name, f"Build & Test warning: {bt_exc}")

            if cancel_ev.is_set() or self._stop_event.is_set():
                raise InterruptedError("Cancelled during workspace setup")

            # ----------------------------------------------------------
            # Step 2: Security Scan (Isolated ScannerAgent)
            # ----------------------------------------------------------
            def is_cancelled() -> bool:
                return cancel_ev.is_set() or self._stop_event.is_set()

            scanner_engine = sched.get("scanner_engine") or "all"
            set_step("SCAN", f"Running security scan ({scanner_engine})...")
            self._append_log(run_data, "info", repo_name, f"Step 2/5: Scanning repository with engine '{scanner_engine}'")

            scanner = ScannerAgent(findings_dir=findings_dir)
            scan_res = scanner.run({
                "workspace_path": str(ctx.repo_path),
                "scanner_engine": scanner_engine,
                "cancel_check": is_cancelled,
            })
            initial_count = int(scan_res.get("total_findings", 0))
            init_posture = scan_res.get("posture") or {}
            repo_item["initial_findings_count"] = initial_count
            repo_item["initial_posture_score"] = init_posture.get("score")
            repo_item["initial_posture_grade"] = init_posture.get("grade")

            scan_html: Optional[str] = None
            try:
                if scanner.last_bundle is not None:
                    scan_html, _ = scanner.get_report_content("html")
                else:
                    raw_findings = []
                    for f_idx, fd in enumerate(scan_res.get("findings") or [], 1):
                        sev_val = (fd.get("severity") or "MEDIUM").upper()
                        cls_val = (fd.get("classification") or "VERIFIED").upper()
                        try:
                            sev_enum = FindingSeverity(sev_val)
                        except ValueError:
                            sev_enum = FindingSeverity.MEDIUM
                        try:
                            cls_enum = FindingClassification(cls_val)
                        except ValueError:
                            cls_enum = FindingClassification.VERIFIED
                        raw_findings.append(RawSecurityFinding(
                            finding_id=fd.get("finding_id") or fd.get("id") or f"FINDING-{f_idx:03d}",
                            scanner_source=fd.get("scanner_source") or "Air-Gap Egress Scanner",
                            rule_id=fd.get("rule_id") or fd.get("rule") or "security-policy",
                            severity=sev_enum,
                            classification=cls_enum,
                            file_path=fd.get("file_path") or fd.get("file") or "",
                            line_start=int(fd.get("line_start") or fd.get("line") or 1),
                            line_end=int(fd.get("line_end") or fd.get("line") or 1),
                            code_snippet=fd.get("code_snippet") or "",
                            raw_evidence=fd.get("description") or fd.get("message") or "",
                            cwe_id=fd.get("cwe_id"),
                            owasp_category=fd.get("owasp_category"),
                        ))
                    sev_counts = dict(scan_res.get("severity_counts") or {})
                    bundle = ScanReportBundle(
                        scan_timestamp=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        project_path=str(ctx.repo_path).replace("\\", "/"),
                        target_frameworks=["Local Repository"],
                        project_topology="Air-Gapped Workspace",
                        overall_scan_state="VULNERABILITIES_FOUND" if raw_findings else "NO_VULNERABILITIES_DETECTED",
                        overall_state_label="Vulnerabilities found" if raw_findings else "No vulnerabilities detected",
                        severity_counts=sev_counts,
                        findings=raw_findings,
                        scanner_statuses=[ScannerExecutionStatus(scanner_name="Air-Gap Egress & Policy Scanner")],
                        dependency_audit=DependencyManifestAudit(),
                        target_unmodified_verified=True,
                    )
                    scan_html = SecureScanPipeline.render_html_report(bundle)
                scan_html_path = repo_artifacts_dir / "SECURESCAN_REPORT.html"
                scan_html_path.write_text(scan_html, encoding="utf-8")
                repo_item["scan_report_path"] = str(scan_html_path)
            except Exception as rep_exc:
                logger.debug("Could not write scan HTML report for %s: %s", repo_name, rep_exc)

            self._append_log(
                run_data,
                "warn" if initial_count > 0 else "success",
                repo_name,
                f"Scan complete: {initial_count} finding(s) detected • Posture {init_posture.get('score', '--')}/100 ({init_posture.get('grade', '--')})",
            )

            if cancel_ev.is_set() or self._stop_event.is_set():
                raise InterruptedError("Cancelled after scan")

            # ----------------------------------------------------------
            # Step 3: Iterative Remediation (Isolated RemediatorAgent)
            # ----------------------------------------------------------
            max_iterations = max(1, min(int(sched.get("max_iterations") or 5), 5))
            llm_provider = sched.get("llm_provider") or "ollama"
            llm_model = sched.get("llm_model") or None
            llm_base_url = sched.get("llm_base_url") or None

            remediator = RemediatorAgent(
                repos_root=scratch_repos_root,
                reports_dir=reports_dir,
                scanner_findings_dir=findings_dir,
                llm_provider=llm_provider,
                model=llm_model,
                base_url=llm_base_url,
            )

            iteration = 0
            rem_res: Dict[str, Any] = {}
            post_scan: Dict[str, Any] = scan_res
            all_modified_files: List[str] = []

            while iteration < max_iterations:
                if is_cancelled():
                    raise InterruptedError("Cancelled during remediation")

                iteration += 1
                set_step("REMEDIATE", f"Iteration {iteration}/{max_iterations}: Applying patches & air-gap policies...")
                self._append_log(
                    run_data,
                    "info",
                    repo_name,
                    f"Step 3/5: Remediation iteration {iteration}/{max_iterations} (provider={llm_provider})",
                )

                def _on_remediation_progress(prog: Dict[str, Any]) -> None:
                    live_files = sorted(
                        list(set(all_modified_files).union(set(prog.get("files_modified") or [])))
                    )
                    repo_item["files_modified"] = live_files
                    repo_item["remediated_count"] = int(prog.get("remediated_count") or len(remediator.accumulated_threats))
                    repo_item["step_detail"] = f"Iteration {iteration}/{max_iterations}: {prog.get('message', 'Patching...')}"
                    run_data["total_remediated"] = sum(r.get("remediated_count", 0) for r in run_data["repos"])
                    self._persist_run_detail(run_data)

                rem_res = remediator.run({
                    "workspace_path": str(ctx.repo_path),
                    "provider": llm_provider,
                    "model": llm_model,
                    "base_url": llm_base_url,
                    "progress_callback": _on_remediation_progress,
                    "cancel_check": is_cancelled,
                })
                for mod_f in rem_res.get("files_modified", []):
                    if mod_f not in all_modified_files:
                        all_modified_files.append(mod_f)
                repo_item["files_modified"] = sorted(
                    list(remediator.accumulated_modified_files.union(set(all_modified_files)))
                )
                repo_item["iterations_run"] = iteration

                if is_cancelled():
                    raise InterruptedError("Cancelled before verification post-scan")

                set_step("REMEDIATE", f"Iteration {iteration}/{max_iterations}: Running verification post-scan...")
                post_scan = scanner.run({
                    "workspace_path": str(ctx.repo_path),
                    "scanner_engine": scanner_engine,
                    "is_post_scan": True,
                    "cancel_check": is_cancelled,
                })
                remediator.last_post_scan = post_scan
                remediator.last_workspace_path = str(ctx.repo_path)

                residual_findings = (
                    post_scan.get("findings")
                    if post_scan.get("findings") is not None
                    else (post_scan.get("bug_findings") or [])
                )
                residual_count = len(residual_findings)
                repo_item["post_findings_count"] = residual_count
                repo_item["remediated_count"] = max(0, initial_count - residual_count) if initial_count > 0 else len(remediator.accumulated_threats)
                run_data["total_remediated"] = sum(r.get("remediated_count", 0) for r in run_data["repos"])
                self._persist_run_detail(run_data)

                if residual_count == 0:
                    break

                if iteration < max_iterations:
                    findings_dir.mkdir(parents=True, exist_ok=True)
                    for old_f in list(findings_dir.glob("*.json")):
                        try:
                            old_f.unlink()
                        except OSError:
                            pass
                    for rf in residual_findings:
                        rf_id = (rf.get("finding_id") or rf.get("id") or "FINDING").lower().replace("_", "-")
                        f_file = findings_dir / f"{re.sub(r'[^a-zA-Z0-9_-]', '_', rf_id)}.json"
                        try:
                            f_file.write_text(json.dumps(rf, indent=2), encoding="utf-8")
                        except Exception:
                            pass

            post_findings = (
                post_scan.get("findings")
                if post_scan.get("findings") is not None
                else (post_scan.get("bug_findings") or [])
            )
            post_count = len(post_findings)
            post_posture = post_scan.get("posture") or {}
            repo_item["post_findings_count"] = post_count
            repo_item["post_posture_score"] = post_posture.get("score")
            repo_item["post_posture_grade"] = post_posture.get("grade")
            repo_item["iterations_run"] = iteration
            repo_item["resolved_all"] = (post_count == 0)
            repo_item["files_modified"] = sorted(
                list(remediator.accumulated_modified_files.union(set(all_modified_files)))
            )
            repo_item["remediated_count"] = max(0, initial_count - post_count) if initial_count > 0 else len(remediator.accumulated_threats)

            rem_html: Optional[str] = None
            rem_json: Optional[str] = None
            try:
                rem_html = remediator.render_html_report(workspace_path=str(ctx.repo_path))
                rem_html_path = repo_artifacts_dir / "REMEDIATION_AUDIT_REPORT.html"
                rem_html_path.write_text(rem_html, encoding="utf-8")
                repo_item["remediation_report_path"] = str(rem_html_path)
            except Exception as html_exc:
                logger.debug("Could not write remediation HTML report for %s: %s", repo_name, html_exc)

            try:
                rem_json, _ = remediator.get_report_content(fmt="json", workspace_path=str(ctx.repo_path))
                rem_json_path = repo_artifacts_dir / "REMEDIATION_AUDIT_REPORT.json"
                rem_json_path.write_text(rem_json, encoding="utf-8")
            except Exception as json_exc:
                logger.debug("Could not write remediation JSON report for %s: %s", repo_name, json_exc)

            self._append_log(
                run_data,
                "success" if post_count == 0 else "warn",
                repo_name,
                f"Remediation finished in {iteration} iteration(s): residual={post_count}, score={post_posture.get('score', '--')}/100 ({post_posture.get('grade', '--')})",
            )

            # ----------------------------------------------------------
            # Step 4 & 5: Git Commit, Push & Pull Request
            # ----------------------------------------------------------
            auto_commit = bool(sched.get("auto_commit", True))
            auto_push = bool(sched.get("auto_push", True))
            auto_pr = bool(sched.get("auto_pr", True))
            pr_title: Optional[str] = None

            if auto_commit:
                set_step("COMMIT", "Staging and committing remediations to local branch...")
                if git_agent.workspace.has_changes():
                    all_threats = list(remediator.accumulated_threats.values()) or (rem_res.get("all_threats") or [])
                    commit_msg = remediator.generate_commit_message(
                        repo_name=ctx.repo_name,
                        threats=all_threats,
                        modified_files=repo_item["files_modified"],
                    )
                    pr_title = remediator.generate_pr_title(
                        repo_name=ctx.repo_name,
                        threat_count=len(all_threats),
                    )
                    pr_body = remediator.generate_pr_body(
                        repo_name=ctx.repo_name,
                        threats=all_threats,
                        modified_files=repo_item["files_modified"],
                        branch=ctx.feature_branch,
                        base_branch=ctx.base_branch,
                    )

                    git_agent.workspace.add()
                    commit_hash = git_agent.workspace.commit(
                        message=commit_msg,
                        author_name=git_config.author_name,
                        author_email=git_config.author_email,
                    )
                    repo_item["commit_hash"] = commit_hash
                    repo_item["commit_status"] = "committed"
                    self._append_log(run_data, "success", repo_name, f"Committed {commit_hash[:7]} to branch '{ctx.feature_branch}'")

                    pushed_remote = False
                    if auto_push:
                        set_step("PUSH", "Pushing remediation branch to remote repository...")
                        push_res = git_agent.push_branch(branch=ctx.feature_branch)
                        pushed_remote = bool(push_res.get("pushed"))
                        repo_item["push_status"] = push_res.get("status")
                        repo_item["remote_url"] = push_res.get("remote_url") or repo_item.get("remote_url")
                        if pushed_remote:
                            self._append_log(
                                run_data,
                                "success",
                                repo_name,
                                f"Pushed branch '{ctx.feature_branch}' to {push_res.get('remote_url') or 'origin'}",
                            )
                        else:
                            self._append_log(
                                run_data,
                                "info",
                                repo_name,
                                f"No remote 'origin' configured; branch '{ctx.feature_branch}' kept locally.",
                            )
                    else:
                        repo_item["push_status"] = "skipped_by_policy"

                    if auto_pr:
                        set_step("PR", "Creating pull request dossier...")
                        pr_provider = git_agent.resolve_pr_provider() if pushed_remote else git_agent.provider
                        try:
                            pr_res = pr_provider.create_pull_request(
                                head_branch=ctx.feature_branch,
                                base_branch=ctx.base_branch,
                                title=pr_title,
                                description=pr_body,
                                draft=git_config.draft_pr,
                            )
                        except Exception as remote_pr_exc:
                            if pr_provider is not git_agent.provider and git_agent.provider is not None:
                                self._append_log(
                                    run_data,
                                    "warn",
                                    repo_name,
                                    f"Remote PR creation failed ({remote_pr_exc}); falling back to local PR record.",
                                )
                                pr_res = git_agent.provider.create_pull_request(
                                    head_branch=ctx.feature_branch,
                                    base_branch=ctx.base_branch,
                                    title=pr_title,
                                    description=pr_body,
                                    draft=git_config.draft_pr,
                                )
                            else:
                                raise
                        repo_item["commit_status"] = "success"
                        repo_item["pr_number"] = pr_res.number
                        repo_item["pr_url"] = pr_res.url
                        if pr_res.raw_response:
                            repo_item["pr_file_path"] = pr_res.raw_response.get("md_file")
                        self._append_log(
                            run_data,
                            "success",
                            repo_name,
                            f"Created {pr_res.provider} PR #{pr_res.number}: {pr_res.url}",
                        )
                else:
                    repo_item["commit_status"] = "no_changes"
                    repo_item["push_status"] = "skipped_no_changes"
                    self._append_log(run_data, "info", repo_name, "Working tree clean (already compliant); commit & PR skipped.")
            else:
                repo_item["commit_status"] = "skipped_by_policy"
                repo_item["push_status"] = "skipped_by_policy"
                self._append_log(run_data, "info", repo_name, "Auto-commit disabled; patches left unstaged in workspace.")

            if not is_cancelled():
                self._dispatch_repo_email(
                    run_data=run_data,
                    repo_item=repo_item,
                    sched=sched,
                    ctx=ctx,
                    scan_res=scan_res,
                    rem_res=rem_res,
                    post_scan=post_scan,
                    remediator=remediator,
                    iteration=iteration,
                    scan_html=scan_html,
                    rem_html=rem_html,
                    rem_json=rem_json,
                    pr_title=pr_title,
                    set_step=set_step,
                )

            repo_item["status"] = "NO_CHANGES" if repo_item["commit_status"] == "no_changes" else "COMPLETED"
            repo_item["current_step"] = "DONE"
            repo_item["step_detail"] = (
                f"Completed ({post_count} residual • {post_posture.get('score', 100)}/100 {post_posture.get('grade', 'A+')})"
            )

        except InterruptedError as cancel_exc:
            repo_item["status"] = "CANCELLED"
            repo_item["current_step"] = "CANCELLED"
            repo_item["step_detail"] = str(cancel_exc)
            repo_item["error"] = str(cancel_exc)
            self._append_log(run_data, "warn", repo_name, f"Cancelled: {cancel_exc}")
        except Exception as exc:
            logger.error("Batch run failed on repo %s: %s", repo_name, exc, exc_info=True)
            err_str = str(exc)
            tok_to_mask = (sched.get("git_token") or "").strip()
            if tok_to_mask and tok_to_mask != "********":
                err_str = err_str.replace(tok_to_mask, "********")
            repo_item["status"] = "FAILED"
            repo_item["current_step"] = "FAILED"
            repo_item["step_detail"] = err_str
            repo_item["error"] = err_str
            self._append_log(run_data, "error", repo_name, f"Failed: {err_str}")
        finally:
            repo_item["finished_at"] = local_now().isoformat()
            if scratch_repos_root.exists():
                shutil.rmtree(scratch_repos_root, ignore_errors=True)
            self._persist_run_detail(run_data)

    def _dispatch_repo_email(
        self,
        *,
        run_data: Dict[str, Any],
        repo_item: Dict[str, Any],
        sched: Dict[str, Any],
        ctx: Any,
        scan_res: Dict[str, Any],
        rem_res: Dict[str, Any],
        post_scan: Dict[str, Any],
        remediator: RemediatorAgent,
        iteration: int,
        scan_html: Optional[str],
        rem_html: Optional[str],
        rem_json: Optional[str],
        pr_title: Optional[str],
        set_step: Any,
    ) -> None:
        """Emails scan and remediation audit reports once a scheduled repo completes."""
        repo_name = repo_item["name"]
        send_email_enabled = bool(sched.get("send_email", True))
        if not send_email_enabled or not self.email_notifier:
            repo_item["email_status"] = "skipped"
            return

        email_cfg = self.email_notifier.get_public_config()
        if not email_cfg.get("enabled", True):
            repo_item["email_status"] = "skipped"
            return

        set_step("EMAIL", "Dispatching scan & remediation audit reports via email...")
        try:
            all_threats = list(remediator.accumulated_threats.values()) or (rem_res.get("all_threats") or [])
            email_rem_result = dict(rem_res) if isinstance(rem_res, dict) else {}
            email_rem_result["all_threats"] = all_threats
            email_rem_result["files_modified"] = list(repo_item.get("files_modified") or [])
            email_rem_result["iterations_run"] = iteration

            pr_data = None
            if repo_item.get("pr_url") or repo_item.get("pr_file_path"):
                pr_data = {
                    "pr_number": repo_item.get("pr_number"),
                    "pr_url": repo_item.get("pr_url"),
                    "pr_file_path": repo_item.get("pr_file_path"),
                    "title": pr_title or f"[SecOps Compliance] Remediation for {repo_name}",
                }

            effective_rem_html = rem_html
            if not effective_rem_html and repo_item.get("remediation_report_path"):
                rep_p = Path(repo_item["remediation_report_path"])
                if rep_p.exists():
                    effective_rem_html = rep_p.read_text(encoding="utf-8", errors="replace")

            effective_scan_html = scan_html
            if not effective_scan_html and repo_item.get("scan_report_path"):
                scan_p = Path(repo_item["scan_report_path"])
                if scan_p.exists():
                    effective_scan_html = scan_p.read_text(encoding="utf-8", errors="replace")

            email_res = self.email_notifier.send_remediation_report_email(
                repo_name=repo_name,
                workspace_path=str(ctx.repo_path),
                branch=ctx.feature_branch,
                base_branch=ctx.base_branch,
                scan_result=scan_res,
                remediation_result=email_rem_result,
                post_scan_result=post_scan,
                pr_data=pr_data,
                remediation_html=effective_rem_html,
                remediation_json=rem_json,
                scan_html=effective_scan_html,
                override_recipients=sched.get("email_recipients") or None,
                custom_note=f"Automated scheduled batch run '{run_data.get('schedule_name') or 'Batch Audit'}' (run {run_data.get('run_id')}).",
                trigger_source="scheduler_repo_completed",
            )
            repo_item["email_notification"] = email_res
            repo_item["email_status"] = email_res.get("status")
            repo_item["email_message"] = email_res.get("message")
            repo_item["email_recipients"] = email_res.get("recipients") or []
            repo_item["email_outbox_file"] = email_res.get("outbox_filename") or email_res.get("outbox_file")

            status_val = email_res.get("status")
            log_level = "success" if status_val == "sent" else ("warn" if status_val == "error" else "info")
            self._append_log(
                run_data,
                log_level,
                repo_name,
                email_res.get("message") or f"Report email status: {status_val}",
            )
        except Exception as email_exc:
            logger.warning("Email dispatch failed for scheduled repo %s: %s", repo_name, email_exc)
            repo_item["email_status"] = "error"
            repo_item["email_message"] = str(email_exc)
            repo_item["email_notification"] = {"status": "error", "message": str(email_exc)}
            self._append_log(run_data, "warn", repo_name, f"Email report warning: {email_exc}")
