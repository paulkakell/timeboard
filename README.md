# TimeboardApp

A lightweight, dockerized task board that supports recurrence intervals shorter than a day.

Current version: **00.13.00**

Website:
- https://timeboardapp.com

Repository:
- https://github.com/paulkakell/timeboardapp

Container image:
- `ghcr.io/paulkakell/timeboardapp`

## Key features

- Recurrence options:
  - **Post-Completion Interval**: schedule the next due time as `completion_time + interval`, such as every `8h` after completion.
  - **Multi-Slot Daily Scheduling**: schedule the next due time at the next time slot in a daily list, such as `08:00, 15:00, 23:00`.
  - **Fixed Clock Scheduling**: schedule the next due time on a fixed interval anchored to the previous due date.
- Mobile-friendly and desktop-friendly web UI.
- Light, dark, and system themes.
- Task type filtering, sorting, cloning, nested subtasks, and global search.
- Calendar view with color-coded due-state filtering and persisted per-user preferences.
- Optional frozen past-due tag shortcuts from **Profile**.
- Archived view for completed and deleted tasks.
- Admin user management, data export/import, backups, logs, and in-app validation.
- Session authentication for the UI and JWT authentication for the API.
- Per-user notification services: browser, email, WNS, Gotify, ntfy, Discord, generic webhook, and generic API.
- SQLite persistence under `/data`.
- Application and database versioning with automatic additive schema upgrades.

## Container delivery

GitHub Actions validates every pull request and builds the release container. A successful push to `main` publishes a multi-architecture image to GitHub Container Registry for `linux/amd64` and `linux/arm64`.

Published tags are:

- `00.13.00`: the release version used by the default Compose file.
- `sha-<commit>`: an immutable commit-oriented rollback and audit tag.
- `latest`: the most recent successful `main` build.

Images include OCI source, revision, and version labels, plus BuildKit provenance and an SBOM. The release version is read from `app/version.py`, and a Git tag such as `v00.13.00` must match it.

New GHCR packages may initially be private. Either make the package public in GitHub package settings or authenticate the deployment host before pulling:

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
```

Use a token that has only the package-read permission required by the deployment host.

## Quick start with Docker Compose

The Compose deployment pulls a versioned GHCR image; it does not build the application locally.

```bash
cp .env.example .env

docker compose pull
docker compose up -d
```

Open the UI at:

- `http://localhost:8888`

If `PORT` is changed, use the configured host port instead. The application always listens on container port `8888`.

On first run, TimeboardApp creates an `admin` account and prints the generated password in the container logs:

```bash
docker compose logs -f app
```

If demo mode is enabled with `demo.enabled: true`, the login page displays the demo credentials and reset warning.

## Running production and demo stacks on one host

Each stack must use a separate data directory, host port, and `CONTAINER_NAME`. The container name is also registered as the unique proxy-facing Docker network alias.

Production example:

```dotenv
TIMEBOARDAPP_IMAGE=ghcr.io/paulkakell/timeboardapp
TIMEBOARDAPP_TAG=00.13.00
PORT=3010
CONFIG_DATA=/srv/timeboardapp/production
CONTAINER_NAME=timeboardapp
INTERNAL_NETWORK=net_internal
EXTERNAL_NETWORK=net_external
```

Demo example:

```dotenv
TIMEBOARDAPP_IMAGE=ghcr.io/paulkakell/timeboardapp
TIMEBOARDAPP_TAG=00.13.00
PORT=3011
CONFIG_DATA=/srv/timeboardapp/demo
CONTAINER_NAME=timeboardapp-demo
INTERNAL_NETWORK=net_internal
EXTERNAL_NETWORK=net_external
```

For Nginx Proxy Manager on the same external Docker network, use the unique aliases and the container port:

```text
timeboard.bitterhost.com  -> timeboardapp:8888
demo.timeboardapp.com     -> timeboardapp-demo:8888
```

The Compose service is intentionally named `app`. Do not configure a reverse proxy to use `app` when multiple TimeboardApp stacks share a network, because that service alias exists in every stack.

If Nginx Proxy Manager instead reaches the Docker host through published ports, route production to host port `3010` and demo to host port `3011`.

## Upgrading from a source-built Compose stack

Version `00.13.00` changes the Compose service name to `app` and replaces `build: .` with the GHCR image. Preserve the existing `/data` directory, but remove the old service before starting the new one so Docker does not retain an orphan container with the same configured container name.

```bash
# Back up the persistent data directory first.
docker compose down --remove-orphans
docker compose pull
docker compose up -d
```

Review startup logs and run **Admin → Validation** after deployment.

For future upgrades, set `TIMEBOARDAPP_TAG` to the required release, then run:

```bash
docker compose pull
docker compose up -d
```

For an exact rollback, pin `TIMEBOARDAPP_TAG` to a previously published release or `sha-<commit>` tag. No database rollback is required for `00.13.00` because it contains no schema changes.

## Resetting a forgotten admin password

If email is enabled and the admin account has an email address, use the **Reset password** link on the login page.

Without email reset, run:

```bash
# Print a new random password.
docker compose exec app python -m app.cli reset-admin

# Or set a specific password.
docker compose exec app python -m app.cli reset-admin \
  --password "NewStrongPasswordHere" --print
```

Bare metal:

```bash
export TIMEBOARDAPP_SETTINGS=/path/to/settings.yml
python -m app.cli reset-admin
```

After resetting, sign in as `admin` and change the password under **Profile → Password**.

## Configuration

TimeboardApp loads settings from `TIMEBOARDAPP_SETTINGS`, which defaults to `/data/settings.yml`.

On first run, the sample configuration is copied into place and placeholder signing secrets are replaced with random values. Existing deployments with placeholder, blank, identical, or too-short session/JWT secrets are repaired on startup. Secret rotation invalidates existing sessions and API tokens.

Common settings:

- `app.timezone`: display and input timezone.
- `app.base_url`: public URL for generated external links; may also be set with `TIMEBOARDAPP_BASE_URL`.
- `security.session_secret`: UI session signing key.
- `security.jwt_secret`: API JWT signing key.
- `database.path`: SQLite database path, default `/data/timeboardapp.db`.
- `purge.default_days`: default archive retention period.
- `purge.interval_minutes`: archived-data purge interval.
- `demo.enabled`: enables the self-resetting public demo mode.
- `demo.reset_interval_minutes`: demo reset interval.
- `demo.disable_external_apis`: disables outbound integrations in demo mode.
- `email.*`: first-run seed values; runtime email configuration is managed from the Admin UI.

Docker Compose variables:

- `TIMEBOARDAPP_IMAGE`: image repository, default `ghcr.io/paulkakell/timeboardapp`.
- `TIMEBOARDAPP_TAG`: version or SHA tag, default `00.13.00`.
- `PORT`: published host port.
- `CONFIG_DATA`: host path mounted at `/data`.
- `CONTAINER_NAME`: unique container name and proxy network alias.
- `INTERNAL_NETWORK` and `EXTERNAL_NETWORK`: external Docker network names.

If SMTP is configured from inside a container, `localhost` refers to the TimeboardApp container itself. Use an SMTP service name or host address reachable from that container.

## Validation and security testing

Admins can run the full validation suite from **Admin → Validation**. It creates isolated temporary records, tests major feature and security paths, writes a redacted validation log, and removes its fixtures.

Docker CLI equivalent:

```bash
docker compose exec app python -m app.cli validate \
  --base-url http://127.0.0.1:8888
```

The CI workflow also runs:

```bash
pytest -q
python -m compileall -q app tests
bandit -r app -ll -q
python -m pip check
pip-audit -r /tmp/timeboardapp-requirements.txt
docker compose config
docker build --pull --tag timeboardapp:ci .
```

A live container health check must pass before GHCR publishing begins.

## API usage

Swagger UI is available at `/docs`.

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

Filtering and sorting parameters include `tag`, `task_type`, `status`, and `sort`.

Restore an archived task:

```bash
curl -X POST http://localhost:8888/api/tasks/123/restore \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Authenticated clients can call `GET /api/tasks/summary` for per-user archived, past-due, and upcoming counters.

## Development

Install dependencies and run tests:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
pytest -q
bandit -r app
```

The production Compose file intentionally pulls GHCR. Developers who need a local image can build it explicitly without changing the deployment file:

```bash
docker build -t timeboardapp:dev .
```

## Notes

- Completing a recurring task archives it and creates the next active occurrence.
- Deleting a task archives it without creating a recurrence.
- Dashboard filters remain sticky within a browser session until reset.
- Deleting a user permanently deletes that user’s associated tasks.
