# TimeboardApp 00.13.00 Validation Report

Date: 2026-07-12  
Pull request: #29  
Branch: `agent/ghcr-container-publishing`  
Validated implementation commit: `1a0230416093d92a77c5ab37418ff4fb1106a135`  
GitHub Actions workflow run: `29182277561` (`CI and GHCR Image`, run 63)

## Release decision

**Result: PASS for review and merge.**

The implementation passed the complete pull-request validation gate: release-version checks, 57 automated tests, Python compilation, Bandit static security analysis, installed-dependency validation, vulnerability auditing, Docker Compose rendering, a clean Docker image build, and a live container health check.

The GHCR publish job was correctly skipped on the pull request. It is configured to run only after the same validation job succeeds on a push to `main` or a matching version tag.

## Change classification

- **Additive:** GitHub Actions now publishes versioned multi-architecture images to GHCR with OCI labels, provenance, and an SBOM.
- **Fix:** Docker Compose no longer builds locally and no longer attempts to interpolate a service-map key. Unique `CONTAINER_NAME` aliases isolate production and demo proxy routing.
- **Security fix:** PyJWT replaces `python-jose[cryptography]`, removing the transitive `ecdsa` package affected by `PYSEC-2026-1325` / `CVE-2024-23342`.
- **Operationally breaking:** The Compose service identifier changes to `app`. Commands and automation using `docker compose exec timeboardapp` or `docker compose logs timeboardapp` must use `app`. Application APIs, data, settings, and JWT formats remain backward compatible.

## 1. Version increment

- Previous version: `00.12.03`
- Release version: `00.13.00`
- Strategy: increment the feature-update segment and reset the bug-fix segment because this release adds a new registry delivery model and changes deployment topology.
- Expected release tag: `v00.13.00`
- Workflow enforcement: a Git tag must exactly match `app/version.py`.

Status: **PASS**

## 2. Changelog

`CHANGELOG.md` records:

- GHCR publication and image tags
- multi-architecture targets
- provenance and SBOM generation
- Compose service/alias correction
- replacement of local builds
- JWT dependency remediation
- tests and documentation
- operational compatibility impact
- issue/advisory references and PR #29

Status: **PASS**

## 3. Automated tests

Command:

```text
pytest -q --tb=short --junitxml=pytest-results.xml
```

Result:

```text
57 passed, 15 warnings in 7.55s
```

New regression coverage includes:

- release version consistency
- GHCR image path and removal of Compose `build:`
- unique production/demo proxy aliases
- required CI and publish gates
- existing HS256 token compatibility after the JWT backend change
- rejection of malformed JWTs
- prevention of `python-jose` or direct `ecdsa` dependency reintroduction

The 15 warnings are pre-existing deprecation warnings involving Python `crypt`, Starlette TestClient/httpx integration, Pydantic class-based configuration, and FastAPI `on_event`. They do not indicate failures in this release, but should be scheduled for a future compatibility cleanup before the respective removals.

Status: **PASS**

## 4. Static analysis and linting

Commands:

```text
python -m compileall -q app tests
bandit -r app -ll -q
```

Results:

- Python application and test modules compiled successfully.
- Bandit reported no medium- or high-severity findings.
- No structural or security warning blocked the release.

Status: **PASS**

## 5. Security review

### Authentication and token handling

- JWT signing remains HS256 with the existing configured secret.
- Decoding retains a fixed `algorithms=["HS256"]` allow-list and does not trust the token-provided algorithm.
- Existing HS256 token format compatibility is covered by a fixed pre-release token fixture.
- Malformed tokens continue to produce HTTP 401.
- Authorization helpers and admin checks are unchanged.

### Dependency vulnerability remediation

The first audit detected:

```text
ecdsa 0.19.2  PYSEC-2026-1325
```

The advisory is also identified as `CVE-2024-23342` and concerns a Minerva timing attack in python-ecdsa. The advisory provides no fixed version. TimeboardApp does not use ECDSA; the package was installed only through `python-jose[cryptography]`.

Remediation:

- removed `python-jose[cryptography]`
- added `PyJWT>=2.10,<3.0`
- migrated the two HS256 encode/decode calls
- added compatibility, invalid-token, and dependency-selection tests

Final audit result:

```text
No known vulnerabilities found
```

### Secrets and CI permissions

- Validation job permission: `contents: read`.
- Publish job permissions: `contents: read`, `packages: write`.
- GHCR login uses the ephemeral repository `GITHUB_TOKEN` only in the publish job.
- `.dockerignore` excludes environment files, databases, logs, backups, validation output, and repository metadata.
- Container smoke-test failure logging redacts the generated initial-admin password.
- Deployment documentation recommends a package-read-only token when the GHCR package is private.

### Input validation and logging

No request input schemas, authorization rules, or user-controlled logging paths changed. Application security headers and structured operational logging remain unchanged.

Status: **PASS**

## 6. Dependency validation

Commands:

```text
python -m pip check
pip-audit -r /tmp/timeboardapp-requirements.txt
```

Results:

- Installed dependency graph is consistent.
- Final vulnerability audit reports no known vulnerabilities.
- PyJWT is constrained to the compatible major version range `>=2.10,<3.0`.
- No lock file exists in the repository, so no lock-file rebuild was applicable.

Status: **PASS**

## 7. Build validation

Command:

```text
docker build --pull --tag timeboardapp:ci .
```

Result:

- Fresh image build completed successfully on the GitHub-hosted Ubuntu runner.
- Build used the repository Dockerfile and production requirements.
- `.dockerignore` reduced the build context and excluded local runtime state.

Live smoke test:

- Started `timeboardapp:ci` on an isolated host port.
- Polled `GET /healthz`.
- Verified `status == "ok"`.
- Verified returned version equals `00.13.00`.

Status: **PASS**

## 8. Configuration validation

Command:

```text
docker compose config
```

Validated behavior:

- image defaults to `ghcr.io/paulkakell/timeboardapp:00.13.00`
- no local Compose build is present
- service identifier is `app`
- `CONTAINER_NAME` supplies the unique alias on both configured external networks
- host port, data directory, image repository, image tag, timezone, UID/GID, and network names remain configurable
- production and demo examples use distinct aliases, ports, data directories, and base URLs

Status: **PASS**

## 9. Database migration review

- No model or schema changes.
- No migration scripts added or modified.
- Existing `/data/timeboardapp.db` files remain compatible.
- No database rollback is required.
- Backup of each `/data` directory is still required before deployment as an operational safeguard.

Status: **NOT APPLICABLE / PASS**

## 10. Performance check

The change affects container delivery, Compose naming, CI, and HS256 library selection. It does not alter task queries, recurrence logic, notification I/O, or database access patterns.

- Full regression suite completed in 7.55 seconds on the hosted runner.
- Image startup and health response completed within the smoke-test readiness window.
- A load test was not required because no core request/query/I/O path changed.

Status: **PASS for scope**

## 11. Logging and observability

- Existing application file/stdout logging behavior is unchanged.
- `/healthz` remains the deployment readiness check and now verifies release version during CI.
- Published images receive OCI source, revision, and version labels.
- GitHub Actions emits the published image digest and platform list in the job summary.
- Failure diagnostics for pytest and pip-audit are retained as short-lived workflow artifacts.
- Existing application metrics/alerts are not modified by this release.

Status: **PASS**

## 12. Documentation update

Updated artifacts:

- `README.md`
- `CHANGELOG.md`
- `docs/docs/getting-started.html`
- `docs/docs/deployment.html`
- `docs/docs/architecture.html`
- `RELEASE_NOTES_00.13.00.md`
- `.env.example`

Documented use cases include:

- public and private GHCR pulls
- production and demo on one host
- Nginx Proxy Manager routing through unique aliases or host ports
- initial migration from local builds
- routine upgrades
- release/SHA rollback
- service-name command changes
- validation and security gates

Status: **PASS**

## 13. Backward compatibility review

Stable:

- HTTP APIs and payloads
- UI behavior
- CLI flags and commands inside the container
- `settings.yml`
- database schema and data
- HS256 bearer-token format
- `/data` volume layout

Changed:

- Compose service identifier: `timeboardapp`/dynamic key to `app`
- deployment source: local build to versioned GHCR image
- Compose commands must reference service `app`
- reverse proxies must target unique aliases (`timeboardapp`, `timeboardapp-demo`) rather than shared service alias `app`

Status: **PASS with documented operational breaking change**

## 14. Rollback plan

Before deployment:

1. Back up production and demo data directories.
2. Preserve or retag the previous locally built image for the initial migration.
3. Record the currently deployed Compose configuration.

Rollback after GHCR adoption:

1. Set `TIMEBOARDAPP_TAG` to a prior release or exact `sha-<commit>` tag.
2. Run `docker compose pull`.
3. Run `docker compose up -d`.
4. Verify `/healthz`, login, and Admin → Validation.

Initial-migration rollback:

1. Restore the prior Compose file.
2. Restore/restart the retained local image.
3. Keep the same `/data` directory; no schema downgrade is required.

Status: **PASS**

## 15. Release notes and artifacts

Release notes: `RELEASE_NOTES_00.13.00.md`

Expected post-merge artifacts:

```text
ghcr.io/paulkakell/timeboardapp:00.13.00
ghcr.io/paulkakell/timeboardapp:sha-<commit>
ghcr.io/paulkakell/timeboardapp:latest
```

Expected platforms:

```text
linux/amd64
linux/arm64
```

The pull-request workflow intentionally does not publish registry artifacts. Publication occurs only after merge/push validation succeeds.

Status: **PASS / publication pending merge**

## 16. Commit notes

Copy/paste commit notes:

```text
feat(release): publish TimeboardApp images to GHCR

- bump release version to 00.13.00
- validate tests, security, dependencies, Compose, image build, and health before publishing
- publish amd64/arm64 GHCR images with version, SHA, and latest tags
- make Compose pull ghcr.io/paulkakell/timeboardapp instead of building locally
- use stable service name app with unique CONTAINER_NAME proxy aliases
- replace python-jose with PyJWT and remove vulnerable python-ecdsa dependency
- preserve existing HS256 token compatibility and invalid-token behavior
- add provenance, SBOM, release notes, deployment docs, and rollback guidance
```

## Remaining non-blocking follow-up

The test run reports deprecation warnings for Passlib/Python `crypt`, Starlette TestClient integration, Pydantic V2 class-based configuration, and FastAPI startup/shutdown events. These are not introduced by this release and do not block 00.13.00, but should be addressed before upgrading to Python 3.13, Pydantic 3, or a FastAPI/Starlette version that removes the deprecated interfaces.
