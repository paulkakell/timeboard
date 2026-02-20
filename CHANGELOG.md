# Changelog

## 00.03.01

- Fix: Correct broken module imports in API routers that prevented the container from starting (Portainer deployments crashed with `ModuleNotFoundError: No module named 'app.database'`).
  - `app/routers/api_admin.py` now imports `get_db` from `app.db` and `list_log_files` from `app.logging_setup`.
  - `app/routers/api_notifications.py` now imports `get_db` from `app.db`.

Compatibility: Backward compatible.
