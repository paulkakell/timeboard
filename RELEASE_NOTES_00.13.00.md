# Release Notes - TimeboardApp 00.13.00

Release date: 2026-05-15

## Summary

00.13.00 is an additive feature and validation-hardening release. It adds user and deployment metrics, GetHomepage.dev Custom API integration endpoints, a Profile metrics page, and a broader Admin Validation suite that can inventory and exercise every documented API endpoint in a live loopback deployment.

## Version strategy

Version changed from `00.12.03` to `00.13.00` using the project format `<Release Version>.<Feature Update>.<Bug Fix>`.

This is a feature update release with no database schema change.

## Added

- Profile → Metrics page for current-user task, completion, overdue-time, and notification metrics.
- Metrics API endpoints:
  - `GET /api/metrics/catalog`
  - `GET /api/metrics/me`
  - `GET /api/metrics/users`
  - `GET /api/metrics/users/{user_id}`
  - `GET /api/metrics/deployment`
  - `GET /api/metrics/prometheus`
  - `GET /api/metrics/influx`
- Homepage Custom API endpoints:
  - `GET /api/homepage/summary`
  - `GET /api/homepage/deployment`
  - `GET /api/homepage/users`
- Deployment and per-user metrics include task status totals, due buckets, recent create/complete/delete counters, completion timing, overdue-time totals, notification service/event counts, and runtime uptime.
- Admin Validation endpoint inventory and OpenAPI comparison for all API routers.
- Optional live loopback exercise for all documented API endpoints when a loopback `--base-url` is provided.
- Installation-specific security check for missing admin users, weak common-password candidates, weak configured integration secrets, weak secret environment overrides, and world-accessible database files.
- Orphan artifact scan for known obsolete static assets and duplicate top-level function definitions.
- All allowed notification channel types are now configured during validation without sending external traffic.

## Fixed

- Reordered `/api/users/me` before `/api/users/{user_id}` so FastAPI resolves the static current-user route before the dynamic integer route.
- Removed obsolete duplicate root-level static icon assets from prior releases.
- Collapsed a duplicate notification helper implementation.
- Made router package imports lazy to avoid validation/UI circular imports.

## Compatibility

- Backward compatible.
- No database migration or schema change.
- Existing API paths remain stable.
- New endpoints are additive.
- Existing user sessions and API tokens are not invalidated by this release.

## Security notes

Admin Validation now includes a stronger installation-specific review. In the validation run for this package, one warning was reported for the temporary validation database file being world-accessible (`0644`). This was a temporary file created in the sandbox validation environment, not an application code failure. Production operators should ensure the SQLite database volume is readable only by the intended service account.

## Test and validation status

- `python -m pytest -q`: 54 passed.
- `python -m compileall -q app tests`: passed.
- Live Admin Validation with `--base-url http://127.0.0.1:8899`: 22 PASS, 1 WARN, 0 FAIL, 1 SKIP.
- Live endpoint exercise: 41 documented API method/path combinations exercised.
- Bandit medium/high scan: no medium/high findings. Full Bandit scan reports only existing low-severity best-effort exception-handling and demo/test placeholder findings.
- `pip-audit`: attempted, but unavailable in the sandbox because DNS resolution for `pypi.org` failed.
- Docker build: not executed in the sandbox because Docker is not installed.

## Rollback

Rollback to `00.12.03` by redeploying the prior image/artifact and retaining the existing SQLite database and settings volume. No schema migration was introduced in `00.13.00`, so rollback does not require a database downgrade. Back up the database before rollback as normal operational practice.

## Artifacts

- Source package: `timeboard_v00.13.00.zip`
- Release notes: `RELEASE_NOTES_00.13.00.md`
- Validation report: `VALIDATION_REPORT_00.13.00.md`
- Live Admin Validation log: `timeboard_admin_validation_00.13.00.log`

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
