# Changelog


## 00.05.00

- Additive: Asynchronous delivery for all non-browser notification services (email, gotify, ntfy, discord, webhook, generic_api, wns) so task create/update/complete no longer blocks on network calls.
- Additive: Notification delivery status and error fields are now persisted on `notification_events` and returned by the notifications events API to aid troubleshooting.
- Fix: Outbound notification HTTP failures now include safe URL context (query stripped) and response snippets, and async worker failures are logged with event/service/user context.

Compatibility: Backward compatible (DB migration is additive).

Refs: Issue N/A, Commit N/A


## 00.04.01

- Additive: Dashboard page size default is now 10 (options now include 10, 25, 50, 100, 200).

Compatibility: Backward compatible.

## 00.04.00

- Fix: Discord webhook notifications now use an embed so the task name is a clickable link to the task entry (when an absolute URL is available via `app.base_url` or a task's `url`).
- Additive: Profile → Notifications: clicking a generated `notify:…` routing tag now copies it to the clipboard.
- Additive: `TIMEBOARD_BASE_URL` environment variable can override `app.base_url` (useful for generating absolute links in external notifications).

Compatibility: Backward compatible.

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
