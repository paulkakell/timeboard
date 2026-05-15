# Validation Report - TimeboardApp 00.13.01

Run date: 2026-05-15

## Release classification

Version changed from `00.13.00` to `00.13.01` using the project format `<Release Version>.<Feature Update>.<Bug Fix>`. This is a security bug-fix release. No database schema changes were introduced.

## Change summary

### Fixes

- Fixed first-run SQLite database creation so default file permissions are private instead of world-readable.
- Fixed upgraded installations by repairing existing SQLite database permissions on startup.
- Fixed SQLite WAL/SHM/journal sidecar exposure by repairing those files to `0600` when present.
- Fixed Docker startup behavior so root-start containers can chown `/data`, drop privileges to `PUID`/`PGID`, and still preserve private file creation defaults.
- Fixed generated/repaired `settings.yml` permissions to `0600`.
- Fixed settings validation compatibility across Pydantic v1 and v2 runtimes.

### Additive

- Added shared runtime permission helper module: `app/permissions.py`.
- Added Docker entrypoint: `docker-entrypoint.py`.
- Added `TIMEBOARDAPP_CHOWN_DATA` environment control for operators that manage volume ownership externally.
- Added permission-focused regression tests.
- Added docs for runtime file permissions and Docker UID/GID behavior.

### Breaking changes

None.

## Requested issue coverage

### Admin Validation warning 010

Covered.

The original warning:

```text
010. [WARN] [SECURITY] Installation-specific credentials and secrets
     database file is world-accessible (mode 644)
```

Root cause: SQLite database file creation inherited a permissive process umask, commonly `0022`, resulting in `0644` database files. Since the database contains credential-adjacent and secret-bearing data, the file must not be world-readable.

Implemented controls:

- `docker-entrypoint.py` sets `umask 0077` before executing the app command.
- `app/db.py` applies the private umask and prepares database permission repair before SQLAlchemy opens SQLite.
- `app/main.py` repairs database permissions before and after table creation and after schema migration.
- `app/permissions.py` repairs the database plus `-wal`, `-shm`, and `-journal` sidecars to `0600`.
- Admin Validation now checks SQLite sidecar files in addition to the main database file.

### Build process root/user behavior

Covered.

- Root start: entrypoint creates managed data directories, optionally chowns them to `PUID`/`PGID`, drops privileges, and execs the app.
- Non-root start: entrypoint cannot chown, but still applies `umask 0077`; app startup still performs best-effort chmod repair when the user owns the mounted files.
- Operator override: `TIMEBOARDAPP_CHOWN_DATA=false` disables entrypoint ownership repair when external orchestration owns that policy.

### Backward compatibility

Covered.

Existing installations with database mode `0644` are repaired on startup when chmod is permitted. No schema changes, API changes, or data format changes were introduced.

## Automated tests

Commands completed:

```bash
python -m compileall -q app tests docker-entrypoint.py
python -m pytest tests/test_startup_config_regression.py tests/test_permissions.py -q
```

Result:

```text
8 passed
```

New or updated tests:

- `tests/test_permissions.py`
- `tests/test_admin_validation.py`
- `tests/test_startup_config_regression.py` coverage remains passing with the new settings-file permission behavior.

Full-suite command attempted:

```bash
python -m pytest -q
```

Sandbox result:

```text
13 collection errors: ModuleNotFoundError: No module named 'sqlalchemy'
```

Dependency installation was attempted:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
```

Sandbox result:

```text
DNS resolution for pypi.org failed; dependencies could not be installed.
```

## Static analysis and linting

Command completed:

```bash
python -m compileall -q app tests docker-entrypoint.py
```

Result: passed.

Additional manual pattern scan checked for `eval`, `exec`, `pickle`, unsafe YAML loading, subprocess usage, and `os.system`. No new executable high-risk patterns were introduced. The only `eval`/`exec` matches are existing scanner-rule strings in `app/validation.py`.

Bandit was not available in the sandbox and could not be installed because dependency installation was blocked by DNS.

## Security review

Reviewed areas:

- Authentication/authorization: no authentication or authorization logic was changed.
- Input validation: no request payload parsing or user-input processing changed.
- Secrets handling: improved by applying `0600` to generated/repaired `settings.yml` and SQLite files that can contain credential or integration secret data.
- Logging behavior: permission repair logs only paths and modes; it does not log secrets.
- Symlink handling: Docker ownership repair uses `os.lchown` so symlinks under `/data` are not followed during chown traversal.
- SSRF/network: unchanged.
- Dependency risk: no libraries were added or upgraded.

## Dependency validation

No dependency versions were changed. Dependency installation and `pip-audit` could not be completed in the sandbox because DNS resolution to PyPI failed.

## Build validation

Dockerfile was updated to copy and use `docker-entrypoint.py`:

```dockerfile
ENTRYPOINT ["python", "/app/docker-entrypoint.py"]
CMD ["python", "-m", "app.run"]
```

Docker build was not executed because Docker is not installed in the sandbox. The entrypoint was syntax-compiled and manually exec-tested with `PUID=0 PGID=0` to confirm the private umask is active before command execution.

## Configuration validation

Updated configuration/docs:

- `.env.example`: added `TIMEBOARDAPP_CHOWN_DATA=true` and clarified `PUID`/`PGID` behavior.
- `docker-compose.yml`: passes `TIMEBOARDAPP_CHOWN_DATA` into the container.
- README and static docs: document private file permissions and root/non-root Docker startup behavior.

No required configuration changes for existing users. Defaults remain backward compatible.

## Database migration review

No schema migration was introduced. `app_meta.db_version` will advance to `00.13.01` through existing version metadata logic, but no tables or columns are added, removed, or modified.

Rollback to `00.13.00` does not require a database downgrade.

## Performance check

The app-side permission repair checks a fixed, small set of files: database, `-wal`, `-shm`, and `-journal`. Runtime impact is negligible.

The Docker entrypoint can recursively chown `/data` when started as root and `TIMEBOARDAPP_CHOWN_DATA=true`. This is intentional for upgrade compatibility. Operators with very large `/data` trees and externally managed ownership can set `TIMEBOARDAPP_CHOWN_DATA=false`.

No load test was run because the change does not touch request-path query logic or core task-processing algorithms.

## Logging and observability

Startup logs permission repair failures and successful file mode changes. Logs contain paths and octal modes only. Admin Validation continues to report unresolved world-readable database files if chmod is not permitted.

## Documentation update

Updated:

- `README.md`
- `.env.example`
- `docker-compose.yml`
- `docs/docs/configuration.html`
- `docs/docs/deployment.html`
- `docs/docs/security.html`
- `docs/docs/architecture.html`
- `CHANGELOG.md`
- `RELEASE_NOTES_00.13.01.md`
- `VALIDATION_REPORT_00.13.01.md`

## Backward compatibility review

Stable:

- API routes: unchanged.
- CLI commands/flags: unchanged.
- Settings schema: unchanged.
- Database schema: unchanged.
- Backup/import formats: unchanged.

New optional environment variable:

- `TIMEBOARDAPP_CHOWN_DATA` defaults to `true`; setting it to `false` disables entrypoint ownership repair only.

## Rollback plan

Redeploy `00.13.00` using the prior image/artifact and retain the existing `/data` volume. No database downgrade is needed. Keep any safer file permissions applied by `00.13.01`; do not restore `0644` database permissions.

Manual permission rollback safety command, if needed for a retained deployment:

```bash
chmod 600 /data/*.db /data/*.db-wal /data/*.db-shm /data/*.db-journal 2>/dev/null || true
```

## Release artifacts

- `timeboard_v00.13.01.zip`
- `RELEASE_NOTES_00.13.01.md`
- `VALIDATION_REPORT_00.13.01.md`

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
