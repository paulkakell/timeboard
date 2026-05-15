# Release Notes - TimeboardApp 00.13.01

Release date: 2026-05-15

## Summary

00.13.01 is a security bug-fix release for the Admin Validation warning:

```text
010. [WARN] [SECURITY] Installation-specific credentials and secrets
     database file is world-accessible (mode 644)
```

The database can contain password hashes, reset tokens, notification configuration, and integration secrets. A SQLite file created as `0644` is readable by any local account or container process that can reach the mounted `/data` path. This release makes first-run database creation private and repairs upgraded installations that already have permissive database file modes.

## Version strategy

Version changed from `00.13.00` to `00.13.01` using the project format `<Release Version>.<Feature Update>.<Bug Fix>`.

This is a bug-fix/security release with no database schema change.

## Fixed

- Set a private runtime umask (`0077`) before SQLite can create the database file.
- Repair existing SQLite database permissions to `0600` on startup when the service account can chmod the mounted file.
- Repair SQLite sidecar files that can contain database content: `-wal`, `-shm`, and `-journal`.
- Add a Docker entrypoint that works when the container starts as root or as an explicit non-root user.
- When the container starts as root, honor `PUID`/`PGID`, optionally repair `/data` ownership, then drop privileges before launching the app.
- Apply owner-only permissions to generated and repaired `settings.yml` files.
- Keep settings validation compatible with both Pydantic v2 (`model_validate`) and older Pydantic v1 (`parse_obj`) runtime images.
- Update Admin Validation’s database exposure check to also consider SQLite sidecar files.

## Added

- `app/permissions.py` with shared permission helpers for private umask, SQLite path parsing, first-run permission defaults, and upgrade repair.
- `docker-entrypoint.py` for Docker startup ownership/umask/privilege handling.
- Regression tests for first-run private creation, upgraded database permission repair, sidecar repair, SQLite URL parsing, generated settings-file permissions, and Admin Validation passing after repair.
- Documentation for `PUID`, `PGID`, and `TIMEBOARDAPP_CHOWN_DATA`.

## Compatibility

- Backward compatible.
- No database migration or schema change.
- Existing API paths, CLI flags, config keys, and data formats remain stable.
- Existing installations with `0644` database files are repaired automatically on startup when file ownership permits chmod.
- If the host or orchestrator intentionally manages volume ownership, set `TIMEBOARDAPP_CHOWN_DATA=false`. The app still applies the private umask and best-effort database chmod repair.
- Secret rotation is not performed by this release unless the existing `00.12.03` weak-secret repair logic detects placeholder or short signing secrets.

## Security notes

The warning occurs because SQLite creates files using the process umask. With a common Docker/default umask of `0022`, a new database file can become `0644`. This release fixes both sides of the problem: the entrypoint and app set `0077` for new files, and startup calls repair logic for existing database files before Admin Validation runs.

The Docker entrypoint uses `os.lchown` during ownership repair so symlinks under `/data` are not followed during chown traversal.

## Test and validation status

Completed in the sandbox:

- `python -m compileall -q app tests docker-entrypoint.py`: passed.
- `python -m pytest tests/test_startup_config_regression.py tests/test_permissions.py -q`: 8 passed.
- `PUID=0 PGID=0 python docker-entrypoint.py python -c '...'`: confirmed the entrypoint preserves the private `0077` umask before exec.
- Manual source pattern scan for `eval`, `exec`, `pickle`, unsafe YAML loading, subprocess usage, and `os.system`: no new executable high-risk patterns; matches were only scanner rule definitions in `app/validation.py`.

Not completed in the sandbox:

- Full `python -m pytest -q`: attempted, but collection was blocked because the sandbox lacks `SQLAlchemy` and other runtime dependencies.
- Dependency installation: attempted with `python -m pip install -r requirements.txt -r requirements-dev.txt`, but DNS resolution to PyPI failed.
- Bandit and pip-audit: not available in the sandbox and could not be installed because of the same DNS limitation.
- Docker image build: not executed because Docker is not installed in the sandbox.
- Live Admin Validation: not executed because the missing runtime dependencies prevented starting the application locally.

## Rollback

Rollback to `00.13.00` by redeploying the prior image/artifact and retaining the existing SQLite database and settings volume. No schema migration was introduced in `00.13.01`, so rollback does not require a database downgrade.

Operational note: rollback removes the automatic permission repair. If rollback is required, keep the safer file modes that this release applied (`chmod 600 /data/*.db /data/*.db-wal /data/*.db-shm /data/*.db-journal` as applicable) or repair them manually on the host.

## Artifacts

- Source package: `timeboard_v00.13.01.zip`
- Release notes: `RELEASE_NOTES_00.13.01.md`
- Validation report: `VALIDATION_REPORT_00.13.01.md`

## Commit notes

```text
Fix SQLite database file permissions and Docker startup user handling

- Bump TimeboardApp version to 00.13.01.
- Add shared runtime permission helpers for private umask, SQLite database path parsing, and database/settings chmod repair.
- Apply private umask before SQLite database creation and repair existing database/WAL/SHM/journal files to 0600 on startup.
- Add Docker entrypoint that handles root and non-root starts, honors PUID/PGID, optionally repairs /data ownership, and drops privileges.
- Update Admin Validation database exposure checks to include SQLite sidecar files.
- Apply 0600 permissions to generated and repaired settings.yml files.
- Add Pydantic v1/v2 settings validation compatibility.
- Add regression tests for first-run permissions, upgrade repair, sidecar repair, SQLite URL parsing, generated settings permissions, and Admin Validation passing after repair.
- Update README, static docs, changelog, release notes, and validation report.
```
