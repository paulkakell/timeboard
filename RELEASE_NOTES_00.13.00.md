# Release Notes - TimeboardApp 00.13.00

Date: 2026-07-12  
Release type: feature update / deployment fix

## Summary

TimeboardApp containers are now built and validated by GitHub Actions and published to GitHub Container Registry instead of being built by each deployment host. The default Compose deployment pulls the versioned image `ghcr.io/paulkakell/timeboardapp:00.13.00`.

This release also corrects the production/demo Docker DNS collision. Compose map keys are not a reliable place for environment-variable interpolation, so the service now has the stable name `app`. Each stack’s unique `CONTAINER_NAME` value is registered as its proxy-facing network alias, allowing production and demo to coexist on the same Nginx Proxy Manager network without both advertising `timeboardapp`.

## Published artifacts

After the release is merged and the `main` workflow succeeds, GHCR publishes:

- `ghcr.io/paulkakell/timeboardapp:00.13.00`
- `ghcr.io/paulkakell/timeboardapp:sha-<commit>`
- `ghcr.io/paulkakell/timeboardapp:latest`

Architectures:

- `linux/amd64`
- `linux/arm64`

Supply-chain metadata:

- OCI source, revision, and version labels
- BuildKit provenance
- Software bill of materials (SBOM)

The release tag must use the application version format and match `v00.13.00`.

## Changes

- Replaced the local-only Docker workflow with tests, static analysis, dependency validation, Compose validation, image build validation, and a live `/healthz` smoke test.
- Added GHCR authentication through the repository-scoped `GITHUB_TOKEN`.
- Added multi-architecture Buildx publishing with version, SHA, and `latest` tags.
- Replaced Compose `build: .` with the version-pinned GHCR image.
- Replaced the attempted variable service-map key with the stable Compose service name `app`.
- Added unique network aliases based on `CONTAINER_NAME` for both external networks.
- Added `.dockerignore` rules to prevent local data, environment files, tests, reports, and repository metadata from entering the build context.
- Added regression tests for the release version, GHCR path, Compose topology, validation gates, architectures, provenance, and SBOM settings.
- Updated README and static deployment, getting-started, and architecture documentation.

## Compatibility

The application runtime is backward compatible:

- No database schema changes
- No migrations
- No API changes
- No CLI option changes
- No `settings.yml` format changes
- Existing `/data` directories remain compatible

Operational compatibility note: the Compose service name is now `app`. Commands such as:

```bash
docker compose exec timeboardapp ...
docker compose logs timeboardapp
```

must become:

```bash
docker compose exec app ...
docker compose logs app
```

## Production and demo routing

Recommended aliases on a shared proxy network:

```text
timeboard.bitterhost.com  -> timeboardapp:8888
demo.timeboardapp.com     -> timeboardapp-demo:8888
```

Do not use `app` as an Nginx Proxy Manager upstream when both stacks share the network.

## Upgrade procedure

1. Back up the production and demo data directories.
2. Preserve or retag the existing locally built image until validation is complete.
3. Set the production and demo `.env` files to `TIMEBOARDAPP_TAG=00.13.00`.
4. Ensure each stack has a unique `CONTAINER_NAME`, `CONFIG_DATA`, and `PORT`.
5. For the first service-name migration, run:

```bash
docker compose down --remove-orphans
docker compose pull
docker compose up -d
```

6. Review `docker compose logs -f app`.
7. Verify `/healthz`, login, API access, notifications, backups, and Admin → Validation.

If the GHCR package remains private, authenticate the deployment host with a package-read token before `docker compose pull`.

## Rollback

For deployments already using GHCR, set `TIMEBOARDAPP_TAG` to the previous release or exact `sha-<commit>` tag and recreate the service.

For the initial migration from the source-built deployment, retain the old local image until the new release is accepted. Restore the previous Compose file and local image if rollback is required.

No database rollback is necessary because version 00.13.00 does not alter the schema or persistent data format.

## Security review

- Publish permission is isolated to the GHCR job with `packages: write`; validation uses `contents: read` only.
- The GitHub token is passed only to the verified GHCR login step and is not written to the image or repository.
- The deployment host should use a package-read token rather than a broad personal token.
- `.dockerignore` excludes `.env`, persistent databases, logs, backups, and validation output.
- Dependency auditing and Bandit medium/high checks gate image publishing.
- The image still follows the existing runtime user model; changing container privileges is outside this release and should be assessed separately before a future hardening change.

## Validation gates

The release workflow requires all of the following before publication:

```text
pytest -q
python -m compileall -q app tests
bandit -r app -ll -q
python -m pip check
pip-audit
Docker Compose configuration validation
Docker image build
Live container /healthz smoke test
```

The associated validation report records the workflow result and commit status.
