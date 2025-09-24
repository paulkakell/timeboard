# Timeboard
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Task dashboard with recurrence and 24h due times.

## Run
```bash
docker build -t timeboard:dev .
docker run -p 8000:8000 -e TIMEBOARD_TZ="America/Denver" -e RELEASE_VERSION="v0.2.0" -e REPOSITORY_URL="https://github.com/you/timeboard" -v $(pwd)/data:/data timeboard:dev
```

Open http://localhost:8000

## Features
- Dashboard and New Task are separate pages in navigation.
- Due at uses the configured time zone `TIMEBOARD_TZ` and 24h format `YYYY-MM-DD HH:MM:SS`. Example: `2025-10-01 22:00:00`.
- Recurrence supports minutes, hours, days, weeks, months, years.
- Cron and Set modes accept a time zone. Defaults to `TIMEBOARD_TZ`.
- Release version and repo link appear bottom left.

## API
- GET `/api/meta`
- GET `/api/tasks`
- POST `/api/tasks`
- PUT `/api/tasks/{id}`
- POST `/api/tasks/{id}/advance`
- DELETE `/api/tasks/{id}`

See code for request bodies.

## License
MIT
