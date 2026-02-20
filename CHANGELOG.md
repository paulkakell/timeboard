# Changelog

## 00.03.01

- Fix: Correct broken module imports in API routers that prevented the container from starting (Portainer deployments crashed with `ModuleNotFoundError: No module named 'app.database'`).
  - `app/routers/api_admin.py` now imports `get_db` from `app.db` and `list_log_files` from `app.logging_setup`.
  - `app/routers/api_notifications.py` now imports `get_db` from `app.db`.

Compatibility: Backward compatible.

## 00.03.02

- Fix: Database schema upgrade banner now behaves like a one-time notification (shown once after an actual upgrade, then cleared) instead of reappearing on every page load.
- Fix: Discord webhook notifications now send Discord-friendly Markdown (not HTML), disable @mention parsing by default, and accept common legacy config keys (e.g. `url`).
- Fix: Dashboard filters are now stateful across navigation within a session until explicitly reset.
- Additive: Notification payloads now include `due_date_display` (stable UTC string) for downstream webhook/API consumers.
- Fix/Security: Outbound notification URLs are now restricted to `http://` and `https://` schemes.

Compatibility: Backward compatible.
