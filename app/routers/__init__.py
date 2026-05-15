"""Router package exports.

Submodules are imported lazily by callers to avoid validation/UI circular imports.
"""

__all__ = [
    "api_admin",
    "api_auth",
    "api_homepage",
    "api_metrics",
    "api_notifications",
    "api_tags",
    "api_tasks",
    "api_users",
    "ui",
]
