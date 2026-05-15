# Release Notes - TimeboardApp 00.12.01

Release type: Bug fix

## Summary

This release fixes a deployment startup failure where `app.run` attempted to import `get_settings` from `app.config`, but the exported `app/config.py` no longer contained the configuration loader. The corrected package restores the configuration loader and adds regression coverage for the import path and first-run settings-file creation. The development dependency list now includes `httpx`, which is required by FastAPI/Starlette TestClient.

## Compatibility

Backward compatible. No database schema changes, API changes, CLI flag changes, or configuration format changes.

## Validation

- Full pytest suite: 43 passed.
- Static analysis: Python compilation passed; Bandit medium/high scan passed.
- Dependency validation: `pip check` passed; `pip-audit` was attempted but could not complete because the sandbox could not resolve `pypi.org`.
- Build validation: Python startup smoke test reached Uvicorn successfully. Docker build could not be run in the sandbox because Docker is not installed.

## Rollback

Revert to version 00.12.00 only if this fix introduces an unexpected regression. Keep the existing `/data` volume in place; no migration rollback is required because this release has no schema changes.
