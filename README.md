# Timeboard (Taskboard)

A lightweight, dockerized task board that supports recurrence intervals shorter than a day.

## Key features

- Recurrence options:
  - **Post-Completion Interval**: schedule next due time as `completion_time + interval` (e.g., every `8h` after completion).
  - **Multi-Slot Daily Scheduling**: schedule next due time at the next time slot in a daily list (e.g., `08:00, 15:00, 23:00`).
  - **Fixed Clock Scheduling**: schedule next due time on a fixed interval anchored to the previous due date (e.g., `1d` anchored to `10:00` every day), regardless of completion time.

- Mobile-friendly and desktop-friendly web UI.
- Light/Dark/System themes.
- Admin user management (create/delete users).
- SQLite database.
- Full OpenAPI-documented API (Swagger UI at `/docs`).
- Configurable via `settings.yml` on a Docker volume.
- Archived task purge job (default 15 days, per-user override).

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

On first run, if `/data/settings.yml` does not exist, Timeboard copies `settings.sample.yml` into place.

Common settings:

- `app.timezone`: used for displaying and interpreting date/time inputs.
- `security.session_secret`: used to sign UI session cookies.
- `security.jwt_secret`: used to sign API JWT tokens.
- `database.path`: SQLite DB file path (default `/data/timeboard.db`).
- `purge.default_days`: default purge window for archived tasks.
- `purge.interval_minutes`: how often the purge job runs.

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
curl http://localhost:8888/api/tasks \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Task fields

Required:

- Task Name
- Task Type
- Due Date
- Recurrence type (None/Post-Completion/Multi-Slot Daily/Fixed Clock)

Optional:

- Description
- Tags
- URL

## Notes

- Deleting a task archives it as `deleted` with a timestamp and does not spawn a recurrence.
- Completing a task archives it as `completed` with a timestamp, and spawns a new active task if recurrence is configured.
- Admin users can view tasks for all users.
- Deleting a user permanently deletes all associated tasks.
