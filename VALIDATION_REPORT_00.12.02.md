# Validation Report - TimeboardApp 00.12.02

Date: 2026-05-15
Release type: bug-fix

## Root cause

The deployed web UI failed while rendering the dashboard because `templates.TemplateResponse(...)` was still using the older template-name-first argument order. The runtime interpreted the context dictionary as the template name, causing Jinja2 template caching to raise `TypeError: unhashable type: 'dict'`.

## Changes validated

- Updated all UI `templates.TemplateResponse(...)` invocations in `app/routers/ui.py` to the request-first signature: `TemplateResponse(request, template_name, context, ...)`.
- Confirmed all 54 UI template response calls now pass `request` as the first argument.
- Added `tests/test_ui_template_response_signature.py` regression coverage to prevent old-style UI template response calls from returning.
- Updated version from `00.12.01` to `00.12.02`.
- Updated README version, CHANGELOG, and release notes.

## Automated tests

Commands:

```bash
python -m venv /mnt/data/timeboard_clean_venv
source /mnt/data/timeboard_clean_venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
TIMEBOARDAPP_SETTINGS=/mnt/data/timeboard_clean_test_settings.yml pytest -q
```

Result: `44 passed, 447 warnings in 5.76s`.

Warnings were pre-existing Pydantic class-based config and `datetime.utcnow()` deprecation warnings; no test failures were observed.

Additional route smoke test:

```bash
TIMEBOARDAPP_SETTINGS=/mnt/data/timeboard_dashboard_smoke_settings.yml python - <<'PY'
from fastapi.testclient import TestClient
from app.main import app
from app.db import SessionLocal
from app.models import User
from app.auth import hash_password

with TestClient(app) as client:
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == 'admin').first()
        assert admin is not None
        admin.hashed_password = hash_password('DashboardSmoke123!')
        db.add(admin)
        db.commit()
    finally:
        db.close()

    login = client.post('/login', data={'username': 'admin', 'password': 'DashboardSmoke123!'}, follow_redirects=False)
    assert login.status_code in (302, 303)
    dashboard = client.get('/dashboard')
    assert dashboard.status_code == 200
    assert 'text/html' in dashboard.headers.get('content-type', '')
PY
```

Result: `POST /login 303 /dashboard`; `GET /dashboard 200 text/html; charset=utf-8`.

## Static analysis and linting

Commands:

```bash
python -m compileall -q app tests
python -m bandit -r app -ll -q
```

Results:

- Python compilation passed.
- Bandit medium/high severity scan passed.
- A low-severity Bandit scan of `app/routers/ui.py` still reports pre-existing broad `try/except/pass`, `try/except/continue`, and blank-secret-clear patterns. These were not introduced by this release and were not changed to keep the fix limited to the rendering error.

## Security review

Reviewed the changed code path for authentication, authorization, input validation, logging, dependency, and secrets impacts.

- Authentication and authorization flows were not changed.
- Input validation was not changed.
- Logging behavior was not changed.
- Secrets handling was not changed.
- No dependency versions were changed.
- The fix passes `request` explicitly into server-rendered template responses and does not expose additional data.

SAST result: Bandit medium/high severity scan passed.

Dependency vulnerability scan:

```bash
python -m pip install pip-audit
python -m pip_audit -r requirements.txt -r requirements-dev.txt
```

Result: `pip-audit` installation succeeded, but the vulnerability lookup could not complete because the sandbox could not resolve `pypi.org`. No dependency changes were made in this release.

## Dependency validation

Commands:

```bash
python -m venv /mnt/data/timeboard_clean_venv
source /mnt/data/timeboard_clean_venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
pip check
python - <<'PY'
import fastapi, starlette
print('fastapi', fastapi.__version__)
print('starlette', starlette.__version__)
PY
```

Results:

- Clean virtual environment dependency installation passed.
- `pip check`: `No broken requirements found.`
- Validation environment versions: FastAPI `0.136.1`, Starlette `1.0.0`.
- No lock file rebuild was required because this project does not include a lock file and no requirements were changed.

## Build and startup validation

Docker build could not be run in the sandbox because Docker is not installed. A Python/Uvicorn startup smoke test was run instead:

```bash
TIMEBOARDAPP_SETTINGS=/mnt/data/timeboard_uvicorn_smoke2_settings.yml timeout 5 python -m app.run
```

Result: startup reached `Application startup complete` and `Uvicorn running on http://127.0.0.1:19002`; the process was intentionally stopped by timeout.

## Configuration validation

- No environment variables, config files, feature flags, or defaults were changed.
- Smoke tests used explicit temporary `TIMEBOARDAPP_SETTINGS` files and isolated SQLite database paths.
- Existing `TIMEBOARDAPP_SETTINGS` behavior is preserved.

## Database migration review

No schema changes. No migration scripts changed. No forward or backward database compatibility concerns were introduced. No rollback migration is required.

## Performance check

The change only corrects template response call ordering. It does not touch database queries, task logic, scheduler logic, network I/O, or persistence paths. No load test was required. Full test runtime in a clean environment was 5.76 seconds.

## Logging and observability

No logging, metrics, alerting, or observability code was changed. The startup and route smoke tests confirmed existing structured startup logs still emit normally.

## Documentation update

- Updated `README.md` current version to `00.12.02`.
- Updated `CHANGELOG.md` with the bug fix, compatibility, tests, issue reference, and commit placeholder.
- Added `RELEASE_NOTES_00.12.02.md`.
- Added this validation report.

No API documentation, architecture diagrams, or user-guide behavior examples changed because this release does not add or alter user-facing functionality.

## Backward compatibility review

Backward compatible. No API routes, CLI flags, configuration fields, database schema, or data formats changed.

## Rollback plan

If deployment fails, redeploy the prior `00.12.01` source/image artifact. No database rollback is required because this release does not change schema or persistent data. Preserve the existing `/data` volume before rollback.

## Release artifacts

- Source package: `timeboard_v00.12.02.zip`
- Release notes: `RELEASE_NOTES_00.12.02.md`
- Validation report: `VALIDATION_REPORT_00.12.02.md`

## Commit notes

```text
Fix UI TemplateResponse argument order for Starlette/FastAPI deployments

- Update app/routers/ui.py TemplateResponse calls to pass request as the first argument.
- Add regression test enforcing request-first UI template response calls.
- Bump TimeboardApp version to 00.12.02.
- Update changelog, README version, release notes, and validation report.

Compatibility: backward compatible; no DB schema changes.
Refs: docker deploy Internal Server Error / TemplateResponse TypeError; commit N/A.
```
