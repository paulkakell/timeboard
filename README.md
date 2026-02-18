# Timeboard (Taskboard)

A lightweight, dockerized task board that supports recurrence intervals shorter than a day.

Current version: **0.1.0**

Repository:
- https://github.com/paulkakell/timeboard

## Key features

- Recurrence options:
  - **Post-Completion Interval**: schedule next due time as `completion_time + interval` (e.g., every `8h` after completion).
  - **Multi-Slot Daily Scheduling**: schedule next due time at the next time slot in a daily list (e.g., `08:00, 15:00, 23:00`).
  - **Fixed Clock Scheduling**: schedule next due time on a fixed interval anchored to the previous due date (e.g., `1d` anchored to `10:00` every day), regardless of completion time.

- Mobile-friendly and desktop-friendly web UI (auto-detects mobile devices; footer link to switch to desktop).
- Light/Dark/System themes.
- Task Type filtering and sorting.
- Archived view for completed/deleted tasks (restore archived tasks back to active).
- Admin user management:
  - create/delete users
  - promote/demote users between Admin and User
  - dashboard "Views" menu (My Tasks, All Tasks, per-user views)
  - export/import database JSON
- Optional email features (when SMTP is configured):
  - hourly overdue reminders
  - password reset via email ("Forgot Email?" link)
  - login using username or email address
- SQLite database.
- Full OpenAPI-documented API (Swagger UI at `/docs`).
- Configurable via `settings.yml` on a Docker volume.
- Archived task purge job (default 15 days, per-user override).
- Application + database versioning (stored in `app_meta`). On startup, older/unversioned databases are automatically upgraded to the current schema.

## Quick start (Docker Compose)

```bash
docker compose up --build
```

Open the UI at:

- http://localhost:8888

On first run, Timeboard creates an `admin` account and prints the password in the container logs.

```bash
docker logs -f timeboard
```

## Configuration

Timeboard loads settings from:

- `TIMEBOARD_SETTINGS` (default: `/data/settings.yml`)

On first run, if the settings file does not exist, Timeboard copies `settings.sample.yml` into place.

Common settings:

- `app.timezone`: used for displaying and interpreting date/time inputs.
- `app.base_url`: public URL prefix when behind a reverse proxy or served from a subpath.
- `security.session_secret`: used to sign UI session cookies.
- `security.jwt_secret`: used to sign API JWT tokens.
- `database.path`: SQLite DB file path (default `/data/timeboard.db`).
- `purge.default_days`: default purge window for archived tasks.
- `purge.interval_minutes`: how often the purge job runs.
- `email.*`: SMTP and reminder settings.

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
