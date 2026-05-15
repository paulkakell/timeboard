# Release Notes - TimeboardApp 00.12.03

Date: 2026-05-15
Release type: bug-fix / security hardening

## Summary

This release resolves the four Admin → Validation issues reported from `timeboardapp-validation-20260515T062741Z-1b264364.log`: two warnings and two failures. The validation suite now passes the affected checks for dependency tooling, runtime secret strength, browser security headers, and case-insensitive username authentication.

## Changes

- Fixed runtime secret validation failures by repairing legacy `settings.yml` files that still contain placeholder, blank, identical, or too-short signing secrets.
- Weak secret environment overrides such as `CHANGE_ME_*`, `test-*`, or values shorter than 32 characters are ignored so they cannot force insecure runtime signing.
- Added application-level browser security headers: `X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, and HTTPS-only `Strict-Transport-Security`.
- Fixed username authentication to match usernames case-insensitively while preserving stored display casing.
- Extended case-insensitive behavior to username lookup, API bearer-token user resolution, and username duplicate checks.
- Added `pip-audit` to runtime requirements and normalized Python distribution-name checks so Admin → Validation recognizes packages whose metadata uses underscore/dot variants.
- Updated the application version from `00.12.02` to `00.12.03`.
- Updated README, static configuration/security docs, changelog, release notes, and validation report.

## Compatibility

Backward compatible. No database schema changes, API route changes, CLI flag changes, or data-format changes are included.

Operational note: if an existing deployment still has placeholder or weak `security.session_secret` / `security.jwt_secret` values, this release rotates them automatically. That invalidates existing browser sessions and API tokens; users must sign in again. This is intentional and limited to insecure legacy secret values.

## Deployment notes

Deploy this package in place of `00.12.02`. Existing database and `/data` volumes can be retained.

After deployment, run Admin → Validation again. Expected result for the four reported issues:

- Dependency inventory and optional CVE tooling: `PASS`
- Runtime secret strength: `PASS`
- Browser security header source check: `PASS`
- Authentication, profile prefs, and password reset: `PASS`

If email delivery is disabled, the validation suite may still show `SKIP` for the email delivery mode check. That is expected and unrelated to the reported failures/warnings.

## Rollback

Rollback to `00.12.02` by redeploying the prior source/image artifact if this release introduces an unexpected regression. No database rollback is required because there are no schema changes.

If secrets were auto-repaired and you roll back, keep the repaired `settings.yml` secrets. Restoring old placeholder secrets is not recommended. Existing sessions/tokens that were invalidated by secret rotation cannot be restored without restoring the old insecure secrets.
