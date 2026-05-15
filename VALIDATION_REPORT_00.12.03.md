# Validation Report - TimeboardApp 00.12.03

Date: 2026-05-15
Release type: bug-fix / security hardening
Issue reference: Admin → Validation report `20260515T062741Z-1b264364`
Commit hash: N/A in sandbox

## Version increment

Version changed from `00.12.02` to `00.12.03` using the project format `<Release Version>.<Feature Update>.<Bug Fix>`. This is a bug-fix/security-hardening release with no database schema change.

## Root cause

The uploaded Admin → Validation log showed four issues:

1. `pip-audit` was not installed in the runtime image, so the dependency/CVE tooling check warned.
2. Runtime settings still used placeholder/short `session_secret` and `jwt_secret` values.
3. The app relied on a reverse proxy for browser security headers instead of setting them directly.
4. Username authentication was exact-case, while validation expects case-insensitive username login.

A secondary issue was found while validating the fix: the dependency inventory check compared requirement names literally and did not normalize distribution names such as `pip-audit` / `pip_audit`.

## Changes validated

- Added `pip-audit>=2.7` to `requirements.txt`.
- Normalized dependency names in Admin → Validation with PEP-503-style normalization.
- Added runtime secret repair for placeholder, blank, identical, or too-short `settings.yml` signing secrets.
- Ignored weak secret environment overrides so placeholders cannot override strong file secrets.
- Added browser security headers through FastAPI middleware.
- Made username authentication, username lookup, API token subject resolution, and duplicate-username checks case-insensitive while preserving stored casing.
- Added regression tests covering secret repair, weak env override handling, case-insensitive auth/duplicates, security headers, and dependency-name normalization.
- Updated version, README, static docs, changelog, release notes, and validation report.

## Automated tests

Commands:

```bash
python -m venv /mnt/data/timeboard_001203_venv
source /mnt/data/timeboard_001203_venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m compileall -q app tests
pytest -q
```

Result: `50 passed, 475 warnings in 17.47s`.

Warnings observed were pre-existing Pydantic class-based config warnings, `datetime.utcnow()` deprecation warnings, SQLAlchemy/Python sqlite datetime adapter warnings, and FastAPI lifespan deprecation warnings from importing the app in the security-header regression test. No test failures were observed.

## Admin validation smoke test

A live local server was started with an intentionally placeholder-bearing settings file to verify runtime secret repair and Admin → Validation behavior.

Command:

```bash
TIMEBOARDAPP_SETTINGS=/mnt/data/timeboard_validation_001203_settings.yml python -m app.run
TIMEBOARDAPP_SETTINGS=/mnt/data/timeboard_validation_001203_settings.yml \
  python -m app.cli validate \
  --base-url http://127.0.0.1:19003 \
  --output /mnt/data/timeboard_admin_validation_001203.log
```

Result:

```text
Summary: PASS=19, WARN=0, FAIL=0, SKIP=1
```

The one `SKIP` was `Email delivery mode` because email was disabled/unconfigured in the isolated validation settings. The four reported checks now pass:

- Dependency inventory and optional CVE tooling: `PASS`
- Runtime secret strength: `PASS`
- Browser security header source check: `PASS`
- Authentication, profile prefs, and password reset: `PASS`

## Static analysis and linting

Commands:

```bash
python -m compileall -q app tests
python -m bandit -r app -ll -q
```

Results:

- Python compilation passed.
- Bandit medium/high severity scan passed.
- Bandit emitted existing comment/nosec parser warnings but did not report a blocking medium/high finding.

## Security review

Reviewed authentication, authorization, input validation, logging, dependency behavior, and secrets handling.

- Authentication: username matching is now case-insensitive; email login was already normalized. Password verification behavior was unchanged.
- Authorization: no privilege checks, route guards, manager hierarchy logic, or ownership checks were weakened.
- Input validation: username uniqueness checks now reject case-variant duplicates. Existing email normalization behavior remains unchanged.
- Secrets: placeholder or short runtime signing secrets are replaced with high-entropy token-safe values. Weak env overrides are ignored. This prevents legacy config from forcing insecure session/JWT signing.
- Logging: validation output continues to redact known secrets. The secret repair code does not log generated secrets.
- Browser hardening: the app now sets frame-denial, CSP, MIME-sniffing, referrer-policy, and HTTPS-only HSTS headers.
- Dependency tooling: `pip-audit` is now present in runtime requirements so Admin → Validation can verify the tool is available.

SAST result: Bandit medium/high severity scan passed.

Dependency CVE lookup:

```bash
pip-audit -r requirements.txt -r requirements-dev.txt
```

Result: attempted, but the sandbox could not resolve `pypi.org`, so the online vulnerability lookup did not complete. `pip-audit` installation and CLI availability were validated (`pip-audit 2.10.0`), and `pip check` reported no broken requirements.

## Dependency validation

Commands:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pip check
pip-audit --version
```

Results:

- Clean virtual environment dependency installation passed.
- `pip check`: `No broken requirements found.`
- `pip-audit --version`: `pip-audit 2.10.0`.
- No lock file rebuild was required because this project does not include a lock file.

## Build validation

Docker is not available in the sandbox, so a Docker image build could not be executed here. Runtime build/startup was validated by starting the app with Uvicorn through `python -m app.run`, reaching `/healthz`, and running the live CLI validation suite against `http://127.0.0.1:19003`.

Result: app startup, health check, and Admin validation path passed.

## Configuration validation

- `TIMEBOARDAPP_SETTINGS` remained the supported settings path override.
- `TIMEBOARDAPP_BASE_URL`, `TIMEBOARDAPP_PORT`, and `PORT` behavior was unchanged.
- Strong `TIMEBOARDAPP_SESSION_SECRET` and `TIMEBOARDAPP_JWT_SECRET` overrides remain supported.
- Weak placeholder/short secret overrides are now ignored for safety.
- Existing `settings.yml` files with weak signing secrets are repaired on startup and persisted when writable.
- A temp settings file with `CHANGE_ME_SESSION_SECRET` and `CHANGE_ME_JWT_SECRET` was repaired during live validation.

## Database migration review

No schema changes were introduced. No migration scripts were required. Existing `ensure_db_schema` behavior still updates `app_meta.db_version` and `app_meta.app_version` to the current app version on startup.

Forward compatibility: no new columns/tables are required.

Backward compatibility: rollback to `00.12.02` does not require database rollback. Keep repaired secrets rather than restoring placeholder secrets.

## Performance check

The changes add constant-time header assignment per response, case-insensitive username lookups in existing auth/user flows, and startup-time settings secret repair only when weak values are detected. No task query, scheduler loop, notification dispatch, import/export, or recurrence hot path was changed.

Full test runtime in the clean virtual environment was 17.47 seconds. No load test was required for these validation/security fixes.

## Logging and observability

No structured logging format, log retention, admin log viewer, or metrics/alerting behavior was changed. Validation log redaction was retained. Generated runtime secrets are not printed or stored in validation logs.

## Documentation update

Updated:

- `README.md` current version and configuration/validation guidance.
- `CHANGELOG.md` entry for `00.12.03`.
- `docs/docs/configuration.html` for secret repair and weak env override behavior.
- `docs/docs/security.html` for secret requirements, repair side effects, and browser security headers.
- `RELEASE_NOTES_00.12.03.md`.
- `VALIDATION_REPORT_00.12.03.md`.

No API reference examples required changes because no API request/response format changed.

## Backward compatibility review

Backward compatible. No route, CLI, schema, task data, notification payload, config field, or API response format was removed.

One operational side effect is intentional: deployments still using placeholder/weak signing secrets will rotate to secure values, invalidating active browser sessions and JWTs. Users must sign in again.

## Rollback plan

If deployment fails, redeploy the prior `00.12.02` source/image artifact. No database rollback is required.

Preserve the existing `/data` volume before rollback. If this release repaired weak secrets, keep the repaired `settings.yml` values; do not restore `CHANGE_ME_*` placeholders. If an emergency rollback must also restore prior sessions/tokens, restore the previous settings file from backup, but this reintroduces weak-secret risk and is not recommended.

## Release artifacts

- Source package: `timeboard_v00.12.03.zip`
- Release notes: `RELEASE_NOTES_00.12.03.md`
- Validation report: `VALIDATION_REPORT_00.12.03.md`
- Live validation log: `timeboard_admin_validation_001203.log`

## Commit notes

```text
Resolve Admin Validation warnings and failures for 00.12.03

- Add pip-audit to runtime requirements and normalize dependency inventory names.
- Auto-repair placeholder/short settings.yml session and JWT secrets; ignore weak env secret overrides.
- Add browser security header middleware for X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy, and HTTPS-only HSTS.
- Make username auth, username lookup, API token subject resolution, and username duplicate checks case-insensitive.
- Add regression tests for secret repair, weak env overrides, security headers, case-insensitive auth/duplicates, and dependency-name normalization.
- Bump TimeboardApp version to 00.12.03 and update README, static docs, changelog, release notes, and validation report.

Compatibility: backward compatible; no DB schema changes. Weak-secret repair invalidates existing sessions/tokens by design.
Refs: Admin -> Validation report 20260515T062741Z-1b264364; commit N/A.
```
