# TimeboardApp

A lightweight, dockerized task board that supports recurrence intervals shorter than a day.

Current version: **00.13.00**

Website:
- https://timeboardapp.com

Repository:
- https://github.com/paulkakell/timeboardapp

## Key features

- Recurrence options:
  - **Post-Completion Interval**: schedule next due time as `completion_time + interval` (e.g., every `8h` after completion).
  - **Multi-Slot Daily Scheduling**: schedule next due time at the next time slot in a daily list (e.g., `08:00, 15:00, 23:00`).
  - **Fixed Clock Scheduling**: schedule next due time on a fixed interval anchored to the previous due date (e.g., `1d` anchored to `10:00` every day), regardless of completion time.

- Mobile-friendly and desktop-friendly web UI (auto-detects mobile devices; footer link to switch to desktop).
- Light/Dark/System themes.
- Task Type filtering and sorting.
- Calendar view with color-coded due-state filtering (per-user, persisted).
- Optional per-user frozen past-due tag shortcut bar from **Profile**.
- Profile metrics dashboard for per-user task completion, due-time, overdue-time, and notification metrics.
- Archived view for completed/deleted tasks (restore archived tasks back to active).
- Admin user management:
  - create/delete users
  - promote/demote users between Admin and User
  - dashboard "Views" menu (My Tasks, All Tasks, per-user views)
  - export/import database JSON
  - full feature and security validation from **Admin → Validation**
- Email features (when SMTP is configured in the admin UI):
  - hourly overdue reminders
  - password reset via email ("Reset password" link)
  - login using username or email address
- Per-user notification services (each service entry generates a routing tag; tasks with that tag send notifications on create/update/past due/complete/archive):
  - Browser notifications (SSE)
  - Email
  - Windows Push Notification Services (WNS)
  - Gotify
  - ntfy
  - Discord (webhook)
  - Generic webhook
  - Generic API
  - Non-browser deliveries are dispatched asynchronously; delivery status/errors are recorded on `notification_events` and returned by `/api/notifications/events`.
- Application logging to `/data/logs` (daily files) with configurable log level + retention via the admin UI.
- SQLite database.
- Full OpenAPI-documented API (Swagger UI at `/docs`).
- Metrics APIs for user-level and deployment-level reporting, including JSON, Prometheus text, and InfluxDB line protocol exports.
- Homepage integration endpoints for GetHomepage.dev Custom API widgets.
- Configurable via `settings.yml` on a Docker volume.
- Archived task purge job (default 15 days, per-user override).
- Application + database versioning (stored in `app_meta`). On startup, older/unversioned databases are automatically upgraded to the current schema.

## Quick start (Docker Compose)

```bash
docker compose up --build
```

Optionally, copy `.env.example` to `.env` and adjust defaults (host port, data directory, network name).

Open the UI at:

- http://localhost:8888

If demo mode is enabled (`demo.enabled: true`), the login page shows demo credentials and a reset warning.

Note: if you set `PORT`, Docker Compose maps the UI to `http://localhost:${PORT}` instead of `:8888`.


On first run, TimeboardApp creates an `admin` account and prints the password in the container logs.

```bash
docker compose logs -f timeboardapp
```

On first run (fresh database file), TimeboardApp also seeds a small set of demo tasks/tags under the initial admin account.
You can remove all seeded/user data via **Admin → Database → Purge All**.

## Resetting a forgotten admin password

If email is enabled and the admin account has an email address on file, use the **Reset password** link on the login page.

If email is not enabled (or the account has no email address), you can reset the admin password from the server/host with direct access to the SQLite database.

Docker Compose:

```bash
# Prints a new random password to stdout
docker compose exec timeboardapp python -m app.cli reset-admin

# Or set a specific password (won't print unless you add --print)
docker compose exec timeboardapp python -m app.cli reset-admin --password "NewStrongPasswordHere" --print
```

Bare metal (same machine as the app):

```bash
export TIMEBOARDAPP_SETTINGS=/path/to/settings.yml
python -m app.cli reset-admin
```

After resetting, sign in as `admin` with the new password and change it in **Profile → Password**.

## Configuration

TimeboardApp loads settings from:

- `TIMEBOARDAPP_SETTINGS` (default: `/data/settings.yml`)

On first run, if the settings file does not exist, TimeboardApp copies `settings.sample.yml` into place and replaces sample session/JWT secret placeholders with random runtime secrets. On upgrade, existing `settings.yml` files that still contain placeholder, blank, or too-short signing secrets are repaired with new random values on startup. Weak secret environment overrides such as `CHANGE_ME_*` are ignored so they cannot force an insecure runtime configuration.

Secret rotation invalidates existing browser sessions and API tokens; affected users must sign in again.

Common settings:

- `app.timezone`: used for displaying and interpreting date/time inputs.
- `app.base_url`: public URL prefix when behind a reverse proxy or served from a subpath (can also be set via `TIMEBOARDAPP_BASE_URL`).
- `security.session_secret`: used to sign UI session cookies.
- `security.jwt_secret`: used to sign API JWT tokens.
- `database.path`: SQLite DB file path (default `/data/timeboardapp.db`).
- `purge.default_days`: default purge window for archived tasks.
- `purge.interval_minutes`: how often the purge job runs.
- `demo.enabled`: when true, TimeboardApp runs as a self-resetting demo instance.
- `demo.reset_interval_minutes`: how often the demo dataset is wiped + rebuilt.
- `demo.disable_external_apis`: blocks outbound notifications/webhooks/email in demo mode.
- `email.*`: legacy seed values (copied into the database on first run if no DB settings exist). Runtime configuration is managed in the admin UI (SMTP or SendGrid).

Docker note (SMTP): if TimeboardApp is running in a container, setting the SMTP host to `localhost` / `127.0.0.1` will try to connect to the container itself.
Use a hostname/IP reachable from inside the container (for example: an SMTP container service name on the same docker-compose network, or `host.docker.internal`
when using Docker Desktop).


## Profile shortcuts

Each user can enable **Profile → Dashboard shortcuts → Show frozen past-due tag bar**. When enabled, a sticky top bar dynamically lists tags assigned to that user's active past-due tasks. Selecting a tag opens a new dashboard browser tab filtered to that tag.

## Validation and security testing

Admins can open **Admin → Validation** and run the full validation suite against the running environment. The suite creates isolated temporary users/tasks/services, checks major feature paths, verifies every documented API endpoint when a loopback `--base-url` is supplied, performs installation-specific credential/secret checks, scans for known orphaned release artifacts, validates all allowed notification channel configurations, writes a redacted log, and removes the temporary records. It does not send external email or webhook traffic.

Docker CLI equivalent:

```bash
docker compose exec timeboardapp python -m app.cli validate --base-url http://127.0.0.1:8888
```

By default, validation logs are written under `/data/validation`. The runtime image includes `pip-audit` so validation can confirm CVE tooling availability; outbound network access is still required for full vulnerability lookups. Live API endpoint exercise is restricted to loopback URLs (`localhost`, `127.0.0.1`, or `::1`) to avoid server-side request forgery risk. Copy the full output log into ChatGPT with the codebase when you want issues resolved.

## API usage

Swagger UI:

- `/docs`

Get a token:

```bash
curl -X POST http://localhost:8888/api/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=YOUR_PASSWORD"
```

List tasks:

```bash
curl "http://localhost:8888/api/tasks?sort=due_date" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Filtering and sorting:

- `tag`: filter by a tag name
- `task_type`: filter by task type
- `status`: `active` or `archived` (completed + deleted)
- `sort`: `due_date`, `task_type`, `name`, `archived_at`

Restore an archived task:

```bash
curl -X POST http://localhost:8888/api/tasks/123/restore \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Admin: update a user (email/role):

```bash
curl -X PATCH http://localhost:8888/api/users/2 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_admin": true, "email": "user@example.com"}'
```


Create a notification service (returns a generated routing tag):

```bash
curl -X POST http://localhost:8888/api/notifications/services \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "service_type": "ntfy",
    "name": "Phone",
    "enabled": true,
    "config": { "server_url": "https://ntfy.sh", "topic": "my-topic" }
  }'
```

List notification services:

```bash
curl http://localhost:8888/api/notifications/services \
  -H "Authorization: Bearer YOUR_TOKEN"
```

List notification events:

```bash
curl http://localhost:8888/api/notifications/events?limit=50 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Metrics API and exports

Authenticated users can retrieve their own metrics:

```bash
curl http://localhost:8888/api/metrics/me \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Admins can retrieve deployment-level and all-user metrics, plus scraper-friendly exports:

```bash
curl http://localhost:8888/api/metrics/deployment \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"

curl http://localhost:8888/api/metrics/prometheus \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"

curl http://localhost:8888/api/metrics/influx \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

Metrics endpoints:

| Method | Path | Scope | Format |
| --- | --- | --- | --- |
| GET | `/api/metrics/catalog` | Authenticated user | JSON endpoint catalog |
| GET | `/api/metrics/me` | Authenticated user | JSON current-user metrics |
| GET | `/api/metrics/users` | Admin | JSON metrics for all users |
| GET | `/api/metrics/users/{user_id}` | Admin or same user | JSON metrics for one user |
| GET | `/api/metrics/deployment` | Admin | JSON deployment metrics |
| GET | `/api/metrics/prometheus` | Admin | Prometheus text exposition |
| GET | `/api/metrics/influx` | Admin | InfluxDB line protocol |

The metrics payloads include task status counts, due buckets, 7-day/30-day creation/completion/deletion counts, on-time/late completion statistics, overdue-time totals, notification service counts, notification event counts, and runtime uptime where applicable.

### Homepage Custom API integration

TimeboardApp exposes compact JSON endpoints intended for GetHomepage.dev Custom API widgets:

| Method | Path | Scope | Purpose |
| --- | --- | --- | --- |
| GET | `/api/homepage/summary` | Authenticated user | Current-user widget fields such as `active`, `past_due`, `completed_7d`, and `overdue_hours` |
| GET | `/api/homepage/deployment` | Admin | Deployment widget fields such as users, admins, active tasks, overdue tasks, notification failures, and uptime |
| GET | `/api/homepage/users` | Admin | Dynamic-list-friendly user rows |

Example Homepage service block:

```yaml
- TimeboardApp:
    icon: mdi-clipboard-check
    href: https://timeboard.example.com
    widget:
      type: customapi
      url: https://timeboard.example.com/api/homepage/summary
      headers:
        Authorization: Bearer YOUR_TOKEN
      mappings:
        - field: active
          label: Active
          format: number
        - field: past_due
          label: Past due
          format: number
        - field: completion_rate_30d
          label: On time
          format: percent
```

Admin: update email settings (admin only):

```bash
curl -X PUT http://localhost:8888/api/admin/email \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "provider": "smtp",
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "smtp_username": "user@example.com",
    "smtp_password": "YOUR_PASSWORD",
    "smtp_from": "TimeboardApp <timeboardapp@example.com>",
    "use_tls": true
  }'

```

Admin: update SendGrid settings (admin only):

```bash
curl -X PUT http://localhost:8888/api/admin/email \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "provider": "sendgrid",
    "sendgrid_api_key": "YOUR_SENDGRID_API_KEY",
    "smtp_from": "TimeboardApp <timeboardapp@example.com>"
  }'
```

## Task fields

Required:

- Task Name
- Task Type
- Recurrence type (None/Post-Completion/Multi-Slot Daily/Fixed Clock)

Optional:

- Due Date (if omitted, creation time is used as due date)
- Description
- Tags
- URL

## Notes

- Deleting a task archives it as `deleted` with a timestamp and does not spawn a recurrence.
- Completing a task archives it as `completed` with a timestamp, and spawns a new active task if recurrence is configured.
- Admin users default to viewing only their own tasks; use the Views menu for All Tasks or a specific user.
- Dashboard filters (tag/type/sort/page size/view) are sticky within a session until you click Reset.
- Deleting a user permanently deletes all associated tasks.

## Development checks

Unit tests:

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

Security scan (Bandit):

```bash
bandit -r app
```


### Tasks API summary endpoint

Authenticated API clients can call `GET /api/tasks/summary` to retrieve per-user totals derived from the bearer token. The response includes these counters: `archived`, `past_due`, `all_upcoming_due`, `due_in_0_8h`, `due_in_8_24h`, and `due_in_over_24h`.

