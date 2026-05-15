# Release Notes - TimeboardApp 00.12.02

Date: 2026-05-15
Release type: bug-fix

## Summary

This release fixes a post-deploy Internal Server Error that occurred when launching the web UI. The deployed runtime expected Starlette/FastAPI template rendering calls to pass the request object first, but TimeboardApp still used the older template-name-first call style in the UI router.

## Changes

- Updated all `templates.TemplateResponse(...)` calls in `app/routers/ui.py` to use the request-first signature: `TemplateResponse(request, template_name, context, ...)`.
- Added regression coverage to ensure UI template responses continue using the request-first signature.
- Updated the application version from `00.12.01` to `00.12.02`.

## Compatibility

Backward compatible. No database schema changes, migrations, API changes, CLI changes, configuration changes, or data-format changes are included.

## Deployment notes

Deploy this package in place of `00.12.01`. Existing settings and database volumes can be retained.

## Rollback

Rollback to `00.12.01` by redeploying the prior source/image artifact if this release introduces an unexpected regression. No database rollback is required because this release does not change schema or persistent data.
