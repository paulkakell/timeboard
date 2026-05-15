# Changelog

## 00.13.01

- Fix/Security: Set a private runtime umask and repair existing SQLite database, WAL, SHM, and journal file permissions to owner-only (`0600`) so installation-specific credentials and secrets are not world-readable.
- Fix/Security: Add a Docker entrypoint that works whether the container starts as root or as a non-root user; root startup now honors `PUID`/`PGID`, optionally repairs `/data` ownership, and drops privileges before launching the app.
- Fix/Security: Apply owner-only permissions to generated and repaired `settings.yml` files.
- Fix/Compatibility: Keep settings validation compatible with both Pydantic v2 (`model_validate`) and older Pydantic v1 (`parse_obj`) runtime images.
- Tests: Add regression coverage for first-run private umask behavior, upgraded database permission repair, SQLite sidecar permission repair, SQLite URL parsing, generated settings-file permissions, and Admin Validation passing after permission repair.

Compatibility: Backward compatible. No database schema changes. Existing installations with mode `0644` database files are repaired on startup when the service account can chmod the mounted files. Set `TIMEBOARDAPP_CHOWN_DATA=false` only when host/orchestrator ownership is managed outside the container.

Refs: Issue Admin Validation warning 010 database file world-accessible, Commit N/A

## 00.13.00

- Additive: Add Profile → Metrics with per-user task status, due bucket, completion-rate, overdue-time, and notification metrics.
- Additive: Add metrics API endpoints for current-user, per-user, all-user, deployment, Prometheus text exposition, InfluxDB line protocol, and endpoint catalog reporting.
- Additive: Add GetHomepage.dev Custom API integration endpoints for user summary, deployment summary, and dynamic-list user rows.
- Additive/Security: Expand Admin → Validation to inventory every documented API endpoint, optionally exercise every documented endpoint over loopback HTTP, scan for orphaned release artifacts, check installation-specific weak credentials/secrets, and validate configuration for every allowed notification channel.
- Fix: Reorder `/api/users/me` before `/api/users/{user_id}` so FastAPI resolves the static current-user endpoint correctly.
- Fix/Maintenance: Remove obsolete duplicate static icon artifacts from earlier releases and collapse duplicate notification helper code.
- Tests: Add regression coverage for metrics APIs, Homepage payloads, endpoint inventory, all-channel notification validation, and orphan artifact scanning.

Compatibility: Backward compatible. No database schema changes. New API endpoints are additive. Existing API paths are unchanged except for the `/api/users/me` path-order bug fix.

Refs: Issue Admin validation robustness / metrics / Homepage integration, Commit N/A

## 00.12.03

- Fix/Security: Auto-repair legacy placeholder or short session/JWT secrets in existing `settings.yml` files and ignore weak secret environment overrides so Admin -> Validation no longer fails runtime secret strength on upgraded deployments.
- Fix/Security: Add application-level browser security headers (`X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, and HTTPS-only `Strict-Transport-Security`) instead of relying solely on reverse-proxy configuration.
- Fix: Make username lookup, username authentication, API token user resolution, and username duplicate checks case-insensitive while preserving stored username casing.
- Additive/Dependency: Add `pip-audit` to runtime requirements so Admin -> Validation can confirm CVE tooling is available in the container.
- Tests: Add regression coverage for placeholder secret repair, weak env-secret override handling, case-insensitive username authentication/duplicate denial, and emitted browser security headers.

Compatibility: Backward compatible (no DB schema changes). Existing active sessions and API tokens may be invalidated once legacy placeholder secrets are automatically rotated.

Refs: Issue Admin -> Validation 2 warnings / 2 failures, Commit N/A

## 00.12.02

- Fix: Update UI template rendering calls to use the request-first `TemplateResponse` signature so the dashboard and other server-rendered pages launch correctly on newer Starlette/FastAPI deployments.
- Tests: Add regression coverage that flags any UI template render call that omits `request` as the first argument.

Compatibility: Backward compatible (no DB schema changes).

Refs: Issue docker deploy Internal Server Error / TemplateResponse TypeError, Commit N/A


## 00.12.01

- Fix: Restore the TimeboardApp configuration loader module so `python -m app.run` can import `get_settings` during Docker startup.
- Fix/Security: Preserve first-run settings generation with randomized session/JWT secrets and keep the deployment entrypoint on the supported `TIMEBOARDAPP_SETTINGS` path.
- Tests: Add regression coverage for startup configuration import and first-run settings-file creation.
- Dependency/Tests: Add `httpx` to development requirements because FastAPI/Starlette TestClient requires it during regression tests.

Compatibility: Backward compatible (no DB schema changes).

Refs: Issue deployment ImportError get_settings, Commit N/A

## 00.12.00

- Additive: Add a per-user Profile setting for a frozen past-due tag shortcut bar. When enabled, the top bar dynamically lists tags assigned to active past-due tasks and opens a new dashboard tab filtered to the selected tag.
- Additive: Add Admin → Validation for in-app full feature validation and security-oriented runtime checks in a running Docker environment. The suite writes redacted, pasteable logs under the validation log directory and is also available through `python -m app.cli validate`.
- Fix/Security: First-run settings generation now replaces sample session/JWT secret placeholders with random secrets instead of copying placeholder values into a new runtime settings file.
- Additive/Tests: Add regression coverage for the past-due tag data source, per-user preference persistence, validation log redaction, and validation fixture cleanup.

Compatibility: Backward compatible (no DB schema changes; the new user setting uses existing `users.ui_prefs_json`).

Refs: Issue N/A, Commit N/A


## 00.11.00

- Additive/Branding: Rebrand product name to TimeboardApp across the codebase (UI, docs, config defaults, notification headers/user-agent).
- Additive: When demo mode is enabled (`demo.enabled: true`), the login page displays a demo warning and the demo admin username/password.
- Fix: Docker Compose now defaults to publishing the app on `http://localhost:8888` without requiring `PORT` to be set.
- Additive: Add a companion static website under `/web` (intended for deployment at `timeboardapp.com`) that documents features, architecture, and deployment.
- Fix/Docs: Add `timeboardapp.com` links in the README and UI footer.
- Fix/Legal: Change license to MIT.
- Maintenance: Update requirements to explicitly include direct dependencies.

Compatibility: Backward compatible (no DB schema changes).

Refs: Issue N/A, Commit N/A


## 00.10.00

- Additive: Demo mode in settings.yml (`demo.enabled`) to run TimeboardApp as a safe public demo.
- Additive: Robust seeded demo dataset themed as "Dunder Mifflin Paper Company, Inc".
  - Seeds users with manager/subordinate hierarchy, assigned tasks, task follows, nested subtasks, recurrence patterns, and in-app notifications.
- Additive: Automatic demo reset job (`demo.reset_interval_minutes`) that purges + rebuilds the demo dataset on a schedule.
- Fix/Security: Outbound notification integrations (email/webhooks/API/discord/gotify/ntfy/WNS) are blocked when `demo.disable_external_apis` is enabled.

Compatibility: Backward compatible (no DB schema changes).

Refs: Issue N/A, Commit N/A


## 00.09.00

- Additive: Global task search (navbar) that searches across task fields and tags.
- Additive: Task cloning, including full subtask trees.
- Additive: Nested subtasks (unlimited depth) via parent/child tasks.
  - Recurrent parent tasks rebuild their full child task tree on recurrence.
  - Safeguard: completing/deleting a parent task with open subtasks prompts to cascade-close or cancel.
- Additive: In-app notifications with navbar bell + unread badge.
  - Viewing notifications clears the "new" badge state.
  - Uncleared notifications persist indefinitely; cleared notifications are purged using the same retention policy as archived tasks.
- Additive: Hierarchical users (manager/subordinate).
  - Admin can set each user's manager.
  - Managers can assign tasks to subordinates.
  - Managers can follow subordinate tasks to receive in-app notifications on update/complete/delete.
  - Manager dashboard can optionally include tasks they assigned to subordinates.
- Additive: Admin user deletion supports optional reassignment of completed tasks.

Compatibility: Backward compatible (DB migration is additive: new nullable columns and new tables).

Refs: Issue N/A, Commit N/A


## 00.08.00

- Additive: Calendar view now includes checkbox filters for the color-coded time-left buckets and for Completed/Deleted tasks.
  - Completed and Deleted are hidden by default.
  - Calendar filter + view selection (Month/Week/Day/Year) are persisted per-user.
- Additive: Dashboard now auto-linkifies URLs found in task descriptions.
- Fix: Dashboard pagination is now preserved when completing, deleting, or updating tasks (no longer resets to page 1).

Compatibility: Backward compatible (DB migration is additive: new nullable `users.ui_prefs_json`).

Refs: Issue N/A, Commit N/A


## 00.07.01

- Fix: Clarify the login-page password reset link text (now labeled "Reset password").
- Fix/Docs: Document the supported admin password recovery command (`python -m app.cli reset-admin`) for deployments without email reset.

Compatibility: Backward compatible.

Refs: Issue N/A, Commit N/A


## 00.07.00

- Additive: First-run installs now seed a small set of demo tasks/tags for the initial admin account (only when the SQLite DB file did not exist before startup).
- Additive: Admin → Database now includes a "Purge All" action to permanently delete tasks, tags, and notification-related data (user accounts + admin settings are preserved). A pre-purge JSON backup is written to `/data/backups`.
- Fix: Gotify notifications now authenticate using the `X-Gotify-Key` header instead of `?token=...` query params (improves compatibility with reverse proxies/WAFs and avoids leaking tokens in URLs).

Compatibility: Backward compatible.

Refs: Issue N/A, Commit N/A


## 00.06.00

- Additive: Email can now be delivered via SendGrid API (v3) as an alternative to SMTP. Configurable in Admin → Email and via the Admin email settings API.
- Fix: Admin email settings API now supports partial updates consistently (mirrors the logging/WNS admin endpoints behavior).

Compatibility: Backward compatible.

Refs: Issue N/A, Commit N/A


## 00.05.01

- Fix: Email (SMTP) delivery failures now include host/port/timeout context (and a Docker/localhost hint) in logs and notification event delivery errors to make configuration and networking issues easier to diagnose.

Compatibility: Backward compatible.

Refs: Issue N/A, Commit N/A


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
- Additive: `TIMEBOARDAPP_BASE_URL` environment variable can override `app.base_url` (useful for generating absolute links in external notifications).

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
