# Validation Report - TimeboardApp 00.13.00

Run date: 2026-05-15

## Release classification

Version changed from `00.12.03` to `00.13.00` using the project format `<Release Version>.<Feature Update>.<Bug Fix>`. This is a feature update release with additive APIs and UI functionality. No database schema changes were introduced.

## Change summary

### Additive

- Added Profile → Metrics page.
- Added `/api/metrics/*` endpoints for current-user, per-user, all-user, deployment, Prometheus, InfluxDB, and catalog exports.
- Added `/api/homepage/*` endpoints for GetHomepage.dev Custom API widgets.
- Added metrics builders/renderers in `app/metrics.py`.
- Added expanded Admin Validation checks for endpoint inventory, live endpoint exercise, installation-specific security, orphan artifacts, and all notification channel configuration coverage.
- Added regression tests for metrics, Homepage, endpoint inventory, and current-user route ordering.

### Fixes

- Fixed `/api/users/me` path ordering so it is not captured by `/{user_id}`.
- Removed obsolete duplicate static icon files no longer referenced by the current manifest/templates.
- Removed duplicate notification `_truncate` helper.
- Changed router package exports to lazy submodule references to avoid circular imports.

### Breaking changes

None.

## Requested feature coverage

### 1. Admin Validation robustness

Covered.

- Every documented API endpoint is inventoried from API routers and compared to OpenAPI.
- When a loopback base URL is supplied, every documented API endpoint is exercised over HTTP.
- Orphaned release artifacts are scanned by known obsolete path list and duplicate top-level function detection.
- Installation-specific security now checks admin presence, common weak passwords, weak/placeholder configured secrets, enabled integrations with missing/weak secrets, weak secret environment overrides, and database file exposure.
- All allowed notification channels are configured and updated during validation without external sends: browser, discord, email, generic_api, gotify, ntfy, webhook, and wns.

### 2. Profile menu metrics option

Covered.

- Profile dropdown includes Metrics.
- Profile page includes a Metrics card.
- `/profile/metrics` renders user-level metrics for task status, due buckets, completion timing, overdue time, notification services/events, and API export pointers.

### 3. Docker/container metrics endpoint listing

Covered.

- `GET /api/metrics/catalog` returns a machine-readable endpoint catalog.
- README and static API docs include the metrics endpoint table.
- Prometheus and InfluxDB line protocol endpoints are available for metrics servers.

### 4. Homepage integration

Covered.

- `GET /api/homepage/summary` returns compact current-user widget fields.
- `GET /api/homepage/deployment` returns compact admin deployment widget fields.
- `GET /api/homepage/users` returns dynamic-list-friendly user summary rows.
- README and static API docs include a Custom API widget example.

## Automated tests

Command:

```bash
python -m pytest -q
```

Result:

```text
54 passed, 555 warnings in 7.45s
```

Warnings are deprecation warnings from Python/FastAPI/Pydantic/SQLAlchemy datetime and model configuration paths already present in the project. They are not regressions from this feature set.

New or updated tests:

- `tests/test_metrics_homepage.py`
- `tests/test_api_users_me.py`
- `tests/test_admin_validation.py`

## Admin Validation live run

Command:

```bash
TIMEBOARDAPP_SETTINGS=/mnt/data/timeboard_validation_settings.yml \
python -m app.cli validate --base-url http://127.0.0.1:8899 \
  --output /mnt/data/timeboard_admin_validation_00.13.00.log --no-write-log
```

Result:

```text
Summary: PASS=22, WARN=1, FAIL=0, SKIP=1
Live loopback validation exercised 41 documented API endpoints.
```

Warning:

```text
database file is world-accessible (mode 644)
```

This warning was caused by the temporary sandbox validation database file. It does not indicate an application code failure. Production deployments should set restrictive permissions on the SQLite database volume.

Skip:

```text
Email delivery is disabled or unconfigured; external SMTP/SendGrid delivery was not attempted.
```

This is expected. Validation intentionally does not send external email or webhook traffic.

## Static analysis and linting

Command:

```bash
python -m compileall -q app tests
```

Result: passed.

Bandit medium/high scan:

```bash
python -m bandit -q -r app -ll
```

Result: no medium/high findings. Full Bandit scan reports low-severity findings only, primarily existing broad `try/except` best-effort handling and demo/validation placeholder strings.

No Ruff or mypy configuration is included in `requirements-dev.txt`; no project-specific Ruff/mypy run was available.

## Security review

Reviewed and validated:

- Authentication: bearer token and current-user endpoints remain covered; `/api/users/me` route ordering fixed and tested.
- Authorization: deployment, all-user, Prometheus, InfluxDB, Homepage deployment, and Homepage users endpoints require admin access. Per-user metrics require admin or same user.
- Input validation: endpoint payloads continue to use existing Pydantic schemas where applicable. Metrics/Homepage endpoints are read-only.
- Secrets handling: Admin Validation checks runtime secrets, weak env overrides, integration secrets, and database file exposure. Validation logs redact token/password/secret/API-key patterns.
- SSRF control: live validation HTTP checks are restricted to loopback hosts only.
- Logging: validation logs are redacted; notification and admin logs remain structured through existing logging paths.

## Dependency validation

- `python -m pip install -q -r requirements.txt -r requirements-dev.txt`: passed.
- `python -m pip check`: failed because the sandbox Python environment contains an unrelated global `moviepy`/`pillow` conflict. `moviepy` and `pillow` are not declared TimeboardApp dependencies.
- `python -m pip_audit -r requirements.txt -r requirements-dev.txt`: attempted but failed due sandbox DNS resolution failure for `pypi.org`.

No dependency versions were changed in this release.

## Build validation

- Python compilation passed.
- Docker build was not executed because Docker is not installed in the sandbox environment.
- Application startup was validated by running Uvicorn on `127.0.0.1:8899` and executing live Admin Validation against it.

## Configuration validation

- No new required environment variables.
- Metrics and Homepage endpoints use existing JWT authentication.
- `app.state.started_at_utc` is set at application startup for runtime uptime metrics.
- Existing `settings.yml` format remains compatible.

## Database migration review

No schema changes. No migration scripts were added. Rollback does not require a database downgrade.

## Performance check

No dedicated load-test harness exists in the repository. Metrics builders perform aggregate SQL queries and bounded per-user/user-list queries. The added tests seed representative task and notification records and verify endpoint behavior. For large installations, scrape intervals for all-user exports should be tuned to deployment size.

## Logging and observability

- Added JSON metrics, Prometheus text exposition, InfluxDB line protocol, and Homepage Custom API payloads.
- Existing `/data/logs` behavior remains unchanged.
- Admin Validation logs continue to be written under `/data/validation` by default and redact secrets.

## Documentation update

Updated:

- `README.md`
- `CHANGELOG.md`
- `docs/docs/api.html`
- `docs/docs/security.html`
- `docs/docs/index.html`
- `docs/docs/architecture.html`
- `RELEASE_NOTES_00.13.00.md`
- `VALIDATION_REPORT_00.13.00.md`

## Backward compatibility

Backward compatible. New endpoints and UI routes are additive. Existing APIs, CLI flags, config fields, and data formats remain stable. The `/api/users/me` fix restores intended behavior and does not remove any endpoint.

## Rollback plan

Redeploy the prior `00.12.03` artifact/image and keep the existing SQLite database/settings volume. Because no schema changes were introduced, no database downgrade is required. Take a database backup before rollback.

## Release artifacts

- `timeboard_v00.13.00.zip`
- `RELEASE_NOTES_00.13.00.md`
- `VALIDATION_REPORT_00.13.00.md`
- `timeboard_admin_validation_00.13.00.log`

## Commit notes

```text
Add metrics exports, Homepage Custom API integration, and stronger Admin Validation

- Bump TimeboardApp version to 00.13.00.
- Add Profile → Metrics UI for per-user task, completion, overdue-time, and notification metrics.
- Add metrics API endpoints for current user, per-user, all users, deployment, Prometheus text, InfluxDB line protocol, and endpoint catalog exports.
- Add Homepage Custom API endpoints for user summary, deployment summary, and dynamic-list user rows.
- Expand Admin Validation with documented API inventory/OpenAPI comparison, loopback exercise of every documented API endpoint, orphan artifact scanning, installation-specific credential/secret checks, and all-channel notification configuration validation.
- Fix /api/users/me route ordering before /api/users/{user_id}.
- Remove obsolete duplicate static icon artifacts and duplicate notification helper code.
- Add regression tests for metrics, Homepage payloads, endpoint inventory, /api/users/me route ordering, all-channel notification validation, and orphan artifact scanning.
- Update README, static docs, changelog, release notes, and validation report.
```
