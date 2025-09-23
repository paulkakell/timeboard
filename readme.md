# Timeboard

Timeboard is a lightweight, self-hosted web application for managing time-based tasks with recurrence logic.
It runs as a single Docker container with a FastAPI backend, SQLite persistence, and a responsive HTML/JS frontend.
Designed for use with Portainer and Nginx Proxy Manager.

---

## Features

- Add tasks with:
  - Name, Type, Subtype
  - Clickable URL
  - Description
  - Tags
  - Recurrence schedule
- Recurrence options:
  1. One-time at a specific date/time
  2. Repeat every X minutes/hours/days/months after completion
  3. Repeat at fixed times (cron expression, e.g. “every day at noon”)
  4. Repeat on a set of scheduled times (cron array)
- Dashboard view:
  - Search bar with boolean queries (`name:bill AND tag:home`)
  - Sortable columns
  - Buttons for “Complete” and “Open URL”
  - Time left displayed in months/days/hours/minutes
  - Color gradient from red→green depending on remaining time
- Mobile-friendly responsive layout
- Data stored in a persistent Docker volume

---

## Quick Start

Clone the repository:

```bash
git clone https://github.com/YOUR_USER/timeboard.git
cd timeboard
