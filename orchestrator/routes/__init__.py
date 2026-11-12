"""
Modular route handlers for the Multi-Agent Web Server.
"""

from orchestrator.routes.git_routes import (
    handle_get_git_routes,
    handle_post_git_routes,
)
from orchestrator.routes.scan_fix_routes import (
    handle_get_scan_fix_routes,
    handle_post_scan_fix_routes,
)
from orchestrator.routes.scheduler_routes import (
    handle_get_scheduler_routes,
    handle_post_scheduler_routes,
)

__all__ = [
    "handle_get_git_routes",
    "handle_post_git_routes",
    "handle_get_scan_fix_routes",
    "handle_post_scan_fix_routes",
    "handle_get_scheduler_routes",
    "handle_post_scheduler_routes",
]

