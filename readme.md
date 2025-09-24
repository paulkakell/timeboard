# Timeboard
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Self-hosted, mobile friendly task dashboard with flexible recurrence, boolean search, and time-left tracking. Single container. FastAPI backend. SQLite persistence. Vanilla HTML and JS frontend. Works with Portainer and GHCR.

---

## Features

- Task fields: Name, Type, Subtype, URL, Description, Tags, Recurrence
- Recurrence modes:
  1. One-time at a specific date and time
  2. After completion every X minutes, hours, days, or months
  3. At fixed times via a cron expression
  4. At a defined set of cron expressions
- Dashboard:
  - Search with boolean filters over all fields
  - Sortable columns
  - Complete button advances or deletes per recurrence
  - Open button launches the task URL in a new tab
  - Time-left column shows months, days, hours, minutes
  - Color gradient background for time-left from red to green, text from yellow to black
- Responsive layout for mobile and desktop
- Data stored in a Docker volume

---

## Architecture

- Backend: FastAPI, Uvicorn, SQLAlchemy, croniter, Pydantic
- Database: SQLite at `/data/timeboard.db`
- Frontend: Static HTML, CSS, JS served by FastAPI
- Container: Python 3.12 slim, single service

Folder layout:
```
timeboard/
├─ docker-compose.yml
├─ Dockerfile
├─ requirements.txt
└─ app/
   ├─ main.py
   ├─ db.py
   ├─ models.py
   └─ static/
      ├─ index.html
      ├─ app.js
      └─ styles.css
```

---

## Quick start

Local with Docker:
```bash
docker compose up -d
# open http://localhost:8080
```

Portainer with GHCR image:
```yaml
version: "3.9"
services:
  timeboard:
    image: ghcr.io/OWNER/REPO:latest
    environment:
      - TZ=America/Denver
    ports:
      - "8080:8000"
    volumes:
      - timeboard_data:/data
    restart: unless-stopped
volumes:
  timeboard_data: {}
```

Portainer with repository build:
- Stacks → Add stack → Repository
- Repository URL: your GitHub repo
- Compose path: `docker-compose.yml`

---

## CI publish to GHCR

GitHub Actions workflow `.github/workflows/publish.yml`:
- Triggers on pushes to `main` and tags `v*`
- Logs in to `ghcr.io` with `secrets.GITHUB_TOKEN`
- Builds `linux/amd64` and `linux/arm64`
- Pushes tags: `latest`, short SHA, and release tag

Resulting images:
- `ghcr.io/OWNER/REPO:latest`
- `ghcr.io/OWNER/REPO:<short-sha>`
- `ghcr.io/OWNER/REPO:vX.Y.Z`

---

## API

Base URL: `/api`

### List tasks
`GET /api/tasks`

Response:
```json
[
  {
    "id": 1,
    "name": "Pay water bill",
    "type": "Finance",
    "subtype": "Utility",
    "url": "https://pay.example.com",
    "description": "Account 1234",
    "tags": ["bills","home"],
    "recurrence_mode": "none",
    "recurrence_params": {},
    "due_at": "2025-10-01T18:00:00Z",
    "last_completed_at": null,
    "next_due_at": "2025-10-01T18:00:00Z",
    "time_left_ms": 123456789
  }
]
```

### Create task
`POST /api/tasks`

Body for one-time task:
```json
{
  "name": "Pay water bill",
  "type": "Finance",
  "subtype": "Utility",
  "url": "https://pay.example.com",
  "description": "Account 1234",
  "tags": ["bills","home"],
  "recurrence_mode": "none",
  "due_at": "2025-10-01T18:00:00Z"
}
```

Body for after-completion recurrence:
```json
{
  "name": "Stretch",
  "recurrence_mode": "after",
  "after_interval_value": 6,
  "after_interval_unit": "hours",
  "tags": ["health"]
}
```

Body for daily at noon:
```json
{
  "name": "Daily review",
  "recurrence_mode": "cron",
  "cron": "0 12 * * *",
  "tags": ["work"]
}
```

Body for specific set of times:
```json
{
  "name": "Posting cadence",
  "recurrence_mode": "set",
  "cron_set": [
    "0 16 * * 1,3,5",
    "0 20 * * 1,3,5",
    "0 0 * * 2,4,6"
  ],
  "tags": ["content"]
}
```

### Update task
`PUT /api/tasks/{task_id}`

Body uses the same fields as `POST /api/tasks`.

### Complete task
`POST /api/tasks/{task_id}/complete`

Behavior:
- `none`: deletes the task
- `after`: sets `next_due_at` to now plus the configured interval
- `cron`: advances to the next scheduled time after now
- `set`: advances to the next among the set after now

### Delete task
`DELETE /api/tasks/{task_id}`

---

## UI

Open the app in a browser. The dashboard shows a search bar and a task table with these columns:
- Complete button
- Open button
- Time left
- Name
- Type
- Subtype
- Task instructions
- Tags
- Recurrence
- Actions: Edit, Delete

### Create or edit tasks
- Click New task to open the modal form
- Fill fields
- Pick a recurrence mode
  - One-time: set `Due at` in ISO UTC, for example `2025-10-01T18:00:00Z`
  - After completion: set interval value and unit
  - Fixed time: enter a cron string, for example `0 12 * * *`
  - Specific times: enter one cron per line
- Save to create or update
- Use Delete in the modal to remove a task

### Search
- Free text matches all fields
- Field filters: `name:bill`, `type:finance`, `subtype:utility`, `tag:home`
- Combine terms with `AND` or `OR`
- Sorting: click a column header

### Time-left colors
- Background blends from `#FF000D` at zero to `#00FF00` at the longest duration on screen
- Text blends from `#FFFF00` at zero to `#000000` at the longest duration

---

## Persistence and backups

- Volume `timeboard_data` holds `/data/timeboard.db`
- Back up the Docker volume with your normal host backup process

---

## Configuration

- Timezone via `TZ` environment variable
- Container listens on port `8000`, mapped to `8080` in the examples

---

## Troubleshooting

- Portainer cannot pull from GHCR
  - Make the package public or add a `ghcr.io` registry in Portainer with a PAT that has `packages:read`
- Build workflow created no package
  - Ensure workflow has `packages: write`
  - Force lowercase image name when computing tags
  - Confirm `push: true` in the build step
- Wrong image path
  - Use `ghcr.io/owner/repo:tag`, all lowercase

---

## License

MIT. See `LICENSE`.
