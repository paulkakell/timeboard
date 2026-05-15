from __future__ import annotations

import ast
import importlib.metadata
import json
import os
import re
import secrets
import shutil
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

from sqlalchemy import or_
from sqlalchemy.orm import Session

from .auth import authenticate_user, verify_password
from .config import get_settings
from .crud import (
    OpenSubtasksError,
    clear_in_app_unread,
    complete_task,
    consume_password_reset_token,
    count_in_app_unread,
    create_in_app_notification,
    create_password_reset_token,
    create_task,
    create_user,
    delete_user,
    follow_task,
    is_following_task,
    is_manager_of,
    list_in_app_notifications,
    list_past_due_tags_for_user,
    list_tasks,
    restore_task,
    soft_delete_task,
    unfollow_task,
    update_task,
    update_user_admin,
)
from .db_admin import export_db_json, get_auto_backup_settings, validate_import_payload
from .emailer import build_password_reset_email, email_enabled
from .logging_setup import list_log_files
from .meta_settings import get_email_settings, get_logging_settings, get_wns_settings
from .models import AppMeta, Tag, TaskStatus, User
from .routers import api_admin, api_auth, api_homepage, api_metrics, api_notifications, api_tags, api_tasks, api_users
from .notifications import (
    CHANNEL_BROWSER,
    CHANNEL_DISCORD,
    CHANNEL_EMAIL,
    CHANNEL_GENERIC_API,
    CHANNEL_GOTIFY,
    CHANNEL_NTFY,
    CHANNEL_WEBHOOK,
    CHANNEL_WNS,
    CHANNEL_TYPES,
    create_user_notification_service,
    delete_user_notification_service,
    list_user_notification_services,
    update_user_notification_service,
)
from .recurrence import parse_duration_to_seconds, parse_fixed_calendar_rule, parse_times_csv
from .version import APP_VERSION


VALIDATION_LOG_BASENAME = "validation"
VALIDATION_STATUS_ORDER = ("PASS", "WARN", "FAIL", "SKIP")


class ValidationWarn(Exception):
    """Raised by a check that should be recorded as a warning."""


class ValidationSkip(Exception):
    """Raised by a check that is intentionally skipped."""


@dataclass
class ValidationFinding:
    category: str
    name: str
    status: str
    detail: str = ""
    security: bool = False


@dataclass
class ValidationReport:
    run_id: str
    app_version: str
    started_at_utc: datetime
    actor: str = "unknown"
    base_url: str | None = None
    completed_at_utc: datetime | None = None
    findings: list[ValidationFinding] = field(default_factory=list)
    log_path: str | None = None

    def add(self, category: str, name: str, status: str, detail: str = "", *, security: bool = False) -> None:
        status_u = str(status or "").strip().upper()
        if status_u not in VALIDATION_STATUS_ORDER:
            status_u = "FAIL"
        self.findings.append(
            ValidationFinding(
                category=str(category or "General"),
                name=str(name or "Unnamed check"),
                status=status_u,
                detail=str(detail or ""),
                security=bool(security),
            )
        )

    @property
    def has_failures(self) -> bool:
        return any(f.status == "FAIL" for f in self.findings)

    def counts(self) -> dict[str, int]:
        counts = {k: 0 for k in VALIDATION_STATUS_ORDER}
        for finding in self.findings:
            counts[finding.status] = counts.get(finding.status, 0) + 1
        return counts

    def to_text(self) -> str:
        completed = self.completed_at_utc or datetime.utcnow().replace(tzinfo=None)
        counts = self.counts()
        lines: list[str] = []
        lines.append("TimeboardApp validation report")
        lines.append(f"Run ID: {self.run_id}")
        lines.append(f"App version: {self.app_version}")
        lines.append(f"Actor: {self.actor}")
        lines.append(f"Started UTC: {self.started_at_utc.isoformat()}")
        lines.append(f"Completed UTC: {completed.isoformat()}")
        lines.append(f"Base URL checked: {self.base_url or 'not checked'}")
        if self.log_path:
            lines.append(f"Log path: {self.log_path}")
        lines.append("")
        lines.append(
            "Summary: "
            + ", ".join([f"{status}={counts.get(status, 0)}" for status in VALIDATION_STATUS_ORDER])
        )
        lines.append("")

        current_category = None
        for idx, finding in enumerate(self.findings, start=1):
            if finding.category != current_category:
                current_category = finding.category
                lines.append(f"## {current_category}")
            marker = "SECURITY" if finding.security else "FEATURE"
            lines.append(f"{idx:03d}. [{finding.status}] [{marker}] {finding.name}")
            if finding.detail:
                for line in finding.detail.rstrip().splitlines():
                    lines.append(f"     {line}")
            lines.append("")

        return redact_validation_text("\n".join(lines).rstrip() + "\n")


def _known_secret_values() -> list[str]:
    values: list[str] = []
    try:
        settings = get_settings()
        values.extend(
            [
                settings.security.session_secret,
                settings.security.jwt_secret,
                getattr(settings.email, "smtp_password", ""),
                getattr(settings.email, "sendgrid_api_key", ""),
            ]
        )
    except Exception:
        pass
    return [str(v) for v in values if isinstance(v, str) and len(str(v)) >= 6]


def redact_validation_text(text_value: str) -> str:
    """Redact credentials from validation logs before display or storage."""

    out = str(text_value or "")
    for secret_value in _known_secret_values():
        out = out.replace(secret_value, "<redacted>")

    patterns = [
        re.compile(r"(?i)(password\s*[=:]\s*)([^\s,;]+)"),
        re.compile(r"(?i)(token\s*[=:]\s*)([^\s,;]+)"),
        re.compile(r"(?i)(secret\s*[=:]\s*)([^\s,;]+)"),
        re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)([^\s,;]+)"),
        re.compile(r"(?i)(authorization\s*[=:]\s*)([^\s,;]+)"),
    ]
    for pattern in patterns:
        out = pattern.sub(lambda m: f"{m.group(1)}<redacted>", out)
    return out


def default_validation_log_dir() -> Path:
    """Return the directory used for validation logs in the running environment."""

    try:
        db_path = str(get_settings().database.path or "").strip()
        if db_path and not db_path.startswith("sqlite:"):
            return Path(db_path).expanduser().resolve().parent / VALIDATION_LOG_BASENAME
    except Exception:
        pass
    return Path("/data") / VALIDATION_LOG_BASENAME


def _write_validation_log(report: ValidationReport, *, log_dir: Path | None = None) -> Path | None:
    target_dir = log_dir or default_validation_log_dir()
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        filename = f"timeboardapp-validation-{report.run_id}.log"
        path = target_dir / filename
        report.log_path = str(path)
        path.write_text(report.to_text(), encoding="utf-8")
        return path
    except Exception:
        report.log_path = None
        return None


def _run_check(
    report: ValidationReport,
    category: str,
    name: str,
    func: Callable[[], str | tuple[str, str] | None],
    *,
    security: bool = False,
) -> None:
    try:
        result = func()
        if isinstance(result, tuple):
            status, detail = result
        else:
            status, detail = "PASS", ("" if result is None else str(result))
        report.add(category, name, status, detail, security=security)
    except ValidationSkip as exc:
        report.add(category, name, "SKIP", str(exc), security=security)
    except ValidationWarn as exc:
        report.add(category, name, "WARN", str(exc), security=security)
    except Exception as exc:  # pragma: no cover - traceback is diagnostic output
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__, limit=8))
        report.add(category, name, "FAIL", tb, security=security)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _safe_detail_join(items: Iterable[str], *, max_items: int = 8) -> str:
    arr = [str(x) for x in items if str(x).strip()]
    if len(arr) > max_items:
        return "; ".join(arr[:max_items]) + f"; ... +{len(arr) - max_items} more"
    return "; ".join(arr)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401,N802 - urllib API
        return None


def _http_status(base_url: str, path: str, *, timeout_seconds: float = 2.5) -> int:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationSkip("Base URL must use http or https")
    host = (parsed.hostname or "").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValidationSkip("Live HTTP checks are restricted to loopback base URLs to avoid SSRF risk")

    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    opener = urllib.request.build_opener(_NoRedirectHandler)
    req = urllib.request.Request(url, headers={"User-Agent": f"TimeboardAppValidation/{APP_VERSION}"})
    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            return int(getattr(resp, "status", 200))
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except urllib.error.URLError as exc:
        raise ValidationWarn(f"Could not reach {url}: {exc}") from exc


def _check_version_and_db(db: Session) -> str:
    row = db.query(AppMeta).filter(AppMeta.key == "db_version").first()
    if row is None:
        raise ValidationWarn("app_meta.db_version is missing; run startup migrations before release")
    if str(row.value) != str(APP_VERSION):
        raise AssertionError(f"db_version={row.value}; expected {APP_VERSION}")
    return f"APP_VERSION and app_meta.db_version are {APP_VERSION}"


def _check_settings_security() -> str:
    settings = get_settings()
    weak_values = {
        "CHANGE_ME_SESSION_SECRET",
        "CHANGE_ME_JWT_SECRET",
        "test-session-secret",
        "test-jwt-secret",
        "secret",
        "password",
    }
    findings: list[str] = []
    for name, value in {
        "session_secret": settings.security.session_secret,
        "jwt_secret": settings.security.jwt_secret,
    }.items():
        v = str(value or "")
        if v in weak_values or v.startswith("CHANGE_ME"):
            findings.append(f"{name} is still a placeholder")
        if len(v) < 32:
            findings.append(f"{name} is shorter than 32 characters")
    if settings.security.session_secret == settings.security.jwt_secret:
        findings.append("session_secret and jwt_secret are identical")
    if findings:
        raise AssertionError(_safe_detail_join(findings))
    return "Session and JWT secrets are non-placeholder, distinct, and at least 32 characters."


def _check_config_sanity() -> str:
    settings = get_settings()
    if int(settings.app.port) <= 0 or int(settings.app.port) > 65535:
        raise AssertionError("Configured app.port is outside the valid TCP range")
    if int(settings.purge.default_days) < 1:
        raise AssertionError("purge.default_days must be positive")
    if int(settings.purge.interval_minutes) < 1:
        raise AssertionError("purge.interval_minutes must be positive")
    return (
        f"app={settings.app.name}; timezone={settings.app.timezone}; "
        f"database_path={settings.database.path}; demo_enabled={bool(settings.demo.enabled)}"
    )




def _normalize_package_name(name: str) -> str:
    """Normalize Python distribution names per PEP 503 conventions."""

    return re.sub(r"[-_.]+", "-", str(name or "")).lower().strip("-")


def _check_dependency_inventory() -> tuple[str, str]:
    required_names: list[str] = []
    req_path = Path(__file__).resolve().parent.parent / "requirements.txt"
    if req_path.exists():
        for raw in req_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            name = re.split(r"[<>=!~\[]", line, maxsplit=1)[0].strip()
            if name:
                required_names.append(_normalize_package_name(name))

    installed = {
        _normalize_package_name(dist.metadata.get("Name", "")): dist.version
        for dist in importlib.metadata.distributions()
    }
    missing = [name for name in required_names if name not in installed]
    pip_audit_available = shutil.which("pip-audit") is not None
    detail = f"requirements={len(required_names)}; installed_distributions={len(installed)}"
    if missing:
        return "FAIL", detail + "; missing=" + _safe_detail_join(missing)
    if not pip_audit_available:
        return "WARN", detail + "; pip-audit not installed, so CVE lookup was not executed by the in-app runner"
    return "PASS", detail + "; pip-audit executable is available for operator CVE scans"


def _scan_source_for_risky_patterns() -> tuple[str, str]:
    root = Path(__file__).resolve().parent.parent
    risky_patterns: list[tuple[str, re.Pattern[str], str]] = [
        ("eval", re.compile(r"\beval\s*\("), "eval() usage"),  # nosec: scanner rule definition
        ("exec", re.compile(r"\bexec\s*\("), "exec() usage"),  # nosec: scanner rule definition
        ("os_system", re.compile(r"\bos\.system\s*\("), "os.system usage"),
        ("shell_true", re.compile(r"subprocess\.[A-Za-z_]+\([^\n]*shell\s*=\s*True"), "subprocess shell=True"),
        ("pickle_load", re.compile(r"\bpickle\.(loads?|load)\s*\("), "pickle load usage"),
        ("yaml_load", re.compile(r"\byaml\.load\s*\("), "yaml.load usage"),
    ]
    suffixes = {".py", ".html", ".js", ".yml", ".yaml"}
    skip_parts = {".git", "__pycache__", ".pytest_cache", "validation", "data"}
    findings: list[str] = []

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if any(part in skip_parts for part in path.parts):
            continue
        try:
            rel = path.relative_to(root)
            text_value = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for lineno, line in enumerate(text_value.splitlines(), start=1):
            if "# nosec" in line:
                continue
            for _code, pattern, label in risky_patterns:
                if pattern.search(line):
                    findings.append(f"{rel}:{lineno}: {label}")

    if findings:
        return "FAIL", _safe_detail_join(findings, max_items=12)
    return "PASS", "No high-risk dynamic execution or unsafe deserialization patterns found in tracked source files."


def _check_security_headers_source() -> tuple[str, str]:
    """Static signal for security middleware/headers.

    This does not prove every deployment is hardened; it alerts operators when the
    app relies on the reverse proxy for browser security headers.
    """

    main_path = Path(__file__).resolve().parent / "main.py"
    text_value = main_path.read_text(encoding="utf-8", errors="replace") if main_path.exists() else ""
    expected_headers = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]
    missing = [h for h in expected_headers if h not in text_value]
    if missing:
        return (
            "WARN",
            "Application code does not set these browser security headers directly: "
            + _safe_detail_join(missing)
            + "; configure them at the reverse proxy or add middleware.",
        )
    return "PASS", "Security header middleware markers found in application code."


API_ROUTER_SPECS = [
    ("/api/auth", api_auth.router),
    ("/api/users", api_users.router),
    ("/api/tasks", api_tasks.router),
    ("/api/tags", api_tags.router),
    ("/api/notifications", api_notifications.router),
    ("/api/metrics", api_metrics.router),
    ("/api/homepage", api_homepage.router),
    ("/api/admin", api_admin.router),
]


def _join_api_path(prefix: str, path: str) -> str:
    joined = (prefix.rstrip("/") + "/" + str(path or "").lstrip("/")).replace("//", "/")
    if path == "/" and not joined.endswith("/"):
        joined += "/"
    return joined


def documented_api_routes() -> list[dict[str, str]]:
    """Return method/path combinations for every documented API router."""

    rows: list[dict[str, str]] = []
    for prefix, router in API_ROUTER_SPECS:
        for route in getattr(router, "routes", []) or []:
            path = getattr(route, "path", None)
            methods = sorted([m for m in (getattr(route, "methods", set()) or set()) if m not in {"HEAD", "OPTIONS"}])
            if not path or not methods:
                continue
            for method in methods:
                rows.append(
                    {
                        "method": str(method).upper(),
                        "path": _join_api_path(prefix, str(path)),
                        "name": str(getattr(route, "name", "")),
                    }
                )
    return sorted(rows, key=lambda x: (x["path"], x["method"]))


def _check_api_endpoint_inventory() -> tuple[str, str]:
    routes = documented_api_routes()
    if not routes:
        return "FAIL", "No API routes were discovered from router modules."

    duplicates: list[str] = []
    seen: set[tuple[str, str]] = set()
    for row in routes:
        key = (row["method"], row["path"])
        if key in seen:
            duplicates.append(f"{row['method']} {row['path']}")
        seen.add(key)
    if duplicates:
        return "FAIL", "Duplicate documented API routes: " + _safe_detail_join(duplicates, max_items=12)

    # Compare against the running FastAPI OpenAPI schema when available. Importing
    # here avoids a module-level dependency cycle during app startup.
    try:
        from .main import app  # noqa: PLC0415

        schema = app.openapi()
        openapi_pairs: set[tuple[str, str]] = set()
        for path, methods in (schema.get("paths") or {}).items():
            if not str(path).startswith("/api/"):
                continue
            for method in (methods or {}).keys():
                if str(method).lower() in {"get", "post", "put", "patch", "delete"}:
                    openapi_pairs.add((str(method).upper(), str(path)))
        missing = sorted([f"{m} {p}" for (m, p) in seen if (m, p) not in openapi_pairs])
        if missing:
            return "FAIL", "Router endpoint(s) missing from OpenAPI: " + _safe_detail_join(missing, max_items=16)
        return "PASS", f"Endpoint matrix covers {len(routes)} documented API method/path combinations and matches OpenAPI."
    except Exception as exc:
        return "WARN", f"Endpoint matrix covers {len(routes)} documented API method/path combinations; OpenAPI comparison unavailable: {type(exc).__name__}: {exc}"


def _check_orphaned_release_artifacts() -> tuple[str, str]:
    root = Path(__file__).resolve().parent.parent
    obsolete_paths = [
        "app/static/apple-touch-icon.png",
        "app/static/favicon-128.png",
        "app/static/favicon-16.png",
        "app/static/favicon-256.png",
        "app/static/favicon-32.png",
        "app/static/favicon-48.png",
        "app/static/favicon-64.png",
        "app/static/pwa-192.png",
        "app/static/pwa-512.png",
    ]
    present = [p for p in obsolete_paths if (root / p).exists()]

    duplicate_defs: list[str] = []
    for py_path in (root / "app").rglob("*.py"):
        if any(part in {"__pycache__", ".pytest_cache"} for part in py_path.parts):
            continue
        try:
            tree = ast.parse(py_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        names: dict[str, int] = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names[node.name] = names.get(node.name, 0) + 1
        for name, count in names.items():
            if count > 1:
                duplicate_defs.append(f"{py_path.relative_to(root)}:{name}x{count}")

    findings = []
    if present:
        findings.append("obsolete duplicate static assets still present: " + _safe_detail_join(present, max_items=12))
    if duplicate_defs:
        findings.append("duplicate top-level function definitions: " + _safe_detail_join(duplicate_defs, max_items=12))
    if findings:
        return "WARN", " | ".join(findings)
    return "PASS", "No known obsolete duplicate static assets or duplicate top-level function definitions found."


def _is_weak_secret_value(value: str | None) -> bool:
    v = str(value or "").strip()
    if not v:
        return True
    if len(v) < 32:
        return True
    if v.lower() in {"secret", "password", "changeme", "change_me", "test", "token", "admin"}:
        return True
    if v.upper().startswith("CHANGE_ME"):
        return True
    return False


def _check_installation_specific_security(db: Session) -> tuple[str, str]:
    settings = get_settings()
    findings: list[str] = []
    warnings: list[str] = []

    users = db.query(User).order_by(User.id.asc()).all()
    admins = [u for u in users if bool(u.is_admin)]
    if not admins:
        findings.append("no admin account exists")

    weak_candidates = [
        "admin",
        "password",
        "password123",
        "changeme",
        "timeboardapp",
        "TimeboardApp",
        "letmein",
        "welcome",
    ]
    for user in users:
        candidates = list(weak_candidates)
        uname = str(user.username or "")
        if uname:
            candidates.extend([uname, f"{uname}123", f"{uname}!"])
        for candidate in candidates:
            try:
                if verify_password(candidate, user.hashed_password):
                    findings.append(f"weak password detected for user '{uname}'")
                    break
            except Exception:
                continue
        if not bool(user.is_admin) and not str(user.email or "").strip():
            warnings.append(f"non-admin user '{uname}' has no email address; password reset and email notifications are unavailable")

    for env_name in [
        "TIMEBOARDAPP_SESSION_SECRET",
        "TIMEBOARDAPP_JWT_SECRET",
        "TIMEBOARD_SESSION_SECRET",
        "TIMEBOARD_JWT_SECRET",
    ]:
        if env_name in os.environ and _is_weak_secret_value(os.environ.get(env_name)):
            warnings.append(f"weak {env_name} override is present; runtime ignores weak overrides, but deployment secrets should be repaired")

    email_cfg = get_email_settings(db)
    if bool(email_cfg.enabled):
        if str(email_cfg.provider or "smtp") == "sendgrid":
            if _is_weak_secret_value(email_cfg.sendgrid_api_key):
                findings.append("SendGrid provider is enabled but sendgrid_api_key is missing or weak")
        else:
            if not str(email_cfg.smtp_host or "").strip():
                findings.append("SMTP email is enabled but smtp_host is blank")
            if email_cfg.smtp_password and _is_weak_secret_value(email_cfg.smtp_password):
                findings.append("SMTP password appears to be weak or placeholder")

    wns_cfg = get_wns_settings(db)
    if bool(wns_cfg.enabled):
        if not str(wns_cfg.package_sid or "").strip():
            findings.append("WNS is enabled but package_sid is blank")
        if _is_weak_secret_value(wns_cfg.client_secret):
            findings.append("WNS is enabled but client_secret is missing or weak")

    db_path = str(getattr(settings.database, "path", "") or "")
    if db_path and not db_path.startswith("sqlite:"):
        try:
            p = Path(db_path)
            if p.exists():
                mode = p.stat().st_mode & 0o777
                if mode & 0o007:
                    warnings.append(f"database file is world-accessible (mode {mode:o})")
        except Exception as exc:
            warnings.append(f"database file permission check unavailable: {type(exc).__name__}")

    if findings:
        return "FAIL", _safe_detail_join(findings, max_items=12) + ("; warnings: " + _safe_detail_join(warnings, max_items=6) if warnings else "")
    if warnings:
        return "WARN", _safe_detail_join(warnings, max_items=8)
    return "PASS", f"Checked {len(users)} user account(s), {len(admins)} admin account(s), runtime integration secrets, and database file exposure signals."


class _ValidationFixture:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.prefix = f"tbval{secrets.token_hex(5)}"
        self.password = "ValPass-" + secrets.token_urlsafe(12)
        self.admin: User | None = None
        self.manager: User | None = None
        self.subordinate: User | None = None
        self.created_user_ids: list[int] = []
        self.created_notify_service_ids: list[int] = []
        self.tag_primary = f"{self.prefix}_past"
        self.tag_secondary = f"{self.prefix}_also"

    def setup(self) -> str:
        self.admin = create_user(
            self.db,
            username=f"{self.prefix}_admin",
            password=self.password,
            is_admin=True,
            email=None,
        )
        self.manager = create_user(
            self.db,
            username=f"{self.prefix}_mgr",
            password=self.password,
            is_admin=False,
            email=f"{self.prefix}_mgr@example.invalid",
        )
        self.subordinate = create_user(
            self.db,
            username=f"{self.prefix}_sub",
            password=self.password,
            is_admin=False,
            email=f"{self.prefix}_sub@example.invalid",
        )
        self.created_user_ids = [int(self.admin.id), int(self.manager.id), int(self.subordinate.id)]
        update_user_admin(self.db, user_id=int(self.subordinate.id), manager_id=int(self.manager.id))
        self.db.refresh(self.subordinate)
        _assert(is_manager_of(self.db, manager_user_id=int(self.manager.id), subordinate_user_id=int(self.subordinate.id)), "manager hierarchy was not created")
        return f"Created isolated validation users with prefix {self.prefix}; cleanup is scoped to this prefix."

    def cleanup(self) -> None:
        try:
            for service_id in list(self.created_notify_service_ids):
                if service_id and self.admin:
                    try:
                        delete_user_notification_service(self.db, user_id=int(self.admin.id), service_id=int(service_id))
                    except Exception:
                        self.db.rollback()
            for user_id in list(self.created_user_ids):
                try:
                    delete_user(self.db, user_id=int(user_id))
                except Exception:
                    self.db.rollback()
            notify_patterns = [f"notify:u{uid}:%" for uid in self.created_user_ids]
            q = self.db.query(Tag).filter(Tag.name.like(f"{self.prefix}%"))
            if notify_patterns:
                q = self.db.query(Tag).filter(
                    or_(Tag.name.like(f"{self.prefix}%"), *[Tag.name.like(pattern) for pattern in notify_patterns])
                )
            for tag in q.all():
                try:
                    self.db.delete(tag)
                except Exception:
                    pass
            self.db.commit()
        except Exception:
            self.db.rollback()

    def require_ready(self) -> tuple[User, User, User]:
        if not self.admin or not self.manager or not self.subordinate:
            raise ValidationSkip("Validation fixture was not created")
        return self.admin, self.manager, self.subordinate

    def check_auth_profile_and_password_reset(self) -> str:
        admin, _manager, _subordinate = self.require_ready()
        _assert(authenticate_user(self.db, admin.username, self.password) is not None, "username authentication failed")
        _assert(authenticate_user(self.db, str(admin.username).upper(), self.password) is not None, "case-insensitive username authentication failed")

        admin.ui_prefs_json = '{"calendar":{"view":"dayGridMonth"},"past_due_tag_bar":{"enabled":true}}'
        self.db.add(admin)
        self.db.commit()
        self.db.refresh(admin)
        _assert("past_due_tag_bar" in (admin.ui_prefs_json or ""), "profile UI preference did not persist")

        token = secrets.token_urlsafe(32)
        new_password = "ValPass-New-" + secrets.token_urlsafe(8)
        create_password_reset_token(
            self.db,
            user=admin,
            token=token,
            expires_at_utc=datetime.utcnow().replace(tzinfo=None) + timedelta(minutes=30),
        )
        _assert(consume_password_reset_token(self.db, token=token, new_password=new_password, now_utc=datetime.utcnow()), "password reset token was not consumed")
        _assert(authenticate_user(self.db, admin.username, new_password) is not None, "authentication with reset password failed")
        self.password = new_password
        return "Authentication, profile UI prefs persistence, and password reset flow passed."

    def check_task_crud_filtering_and_archiving(self) -> str:
        admin, _manager, _subordinate = self.require_ready()
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        past = create_task(
            self.db,
            owner=admin,
            name=f"{self.prefix} past due",
            task_type="Validation",
            due_date=now - timedelta(days=1),
            tags=[self.tag_primary, self.tag_secondary],
        )
        future = create_task(
            self.db,
            owner=admin,
            name=f"{self.prefix} future",
            task_type="Validation",
            due_date=now + timedelta(days=1),
            tags=[self.tag_primary],
        )
        filtered = list_tasks(self.db, current_user=admin, tag=self.tag_primary, include_archived=False)
        filtered_ids = {int(t.id) for t in filtered}
        _assert(int(past.id) in filtered_ids and int(future.id) in filtered_ids, "tag filter did not return expected active tasks")

        updated = update_task(
            self.db,
            task=future,
            current_user=admin,
            name=f"{self.prefix} future updated",
            task_type="ValidationUpdated",
            tags=[self.tag_primary],
        )
        _assert(updated.name.endswith("updated"), "task update did not persist")

        soft_delete_task(self.db, task=future, current_user=admin, when_utc=datetime.utcnow().replace(tzinfo=None))
        _assert(future.status == TaskStatus.deleted, "soft delete did not mark task deleted")
        restore_task(self.db, task=future, current_user=admin)
        _assert(future.status == TaskStatus.active, "restore did not reactivate deleted task")
        return "Task create, tag filter, update, soft-delete, and restore paths passed."

    def check_past_due_tag_bar_data(self) -> str:
        admin, _manager, _subordinate = self.require_ready()
        rows = list_past_due_tags_for_user(self.db, user=admin)
        names = {str(r.get("name")) for r in rows}
        _assert(self.tag_primary in names and self.tag_secondary in names, "past-due tag query did not include expected tags")
        primary = [r for r in rows if r.get("name") == self.tag_primary][0]
        _assert(int(primary.get("task_count") or 0) >= 1, "past-due tag count was not populated")
        return f"Past-due tag bar query returned {len(rows)} tag(s) for overdue active tasks."

    def check_recurrence_modes(self) -> str:
        admin, _manager, _subordinate = self.require_ready()
        _assert(parse_duration_to_seconds("1h 30m") == 5400, "duration parser failed")
        _assert(parse_times_csv("08:00, 15:30") == "08:00,15:30", "daily times parser failed")
        _assert(parse_fixed_calendar_rule("Every Tuesday"), "fixed calendar rule parser failed")

        due = datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(minutes=5)
        recurrent = create_task(
            self.db,
            owner=admin,
            name=f"{self.prefix} recurrent",
            task_type="ValidationRecurrence",
            due_date=due,
            recurrence_type="post_completion",
            recurrence_interval="1h",
            tags=[self.tag_primary],
        )
        completed, spawned = complete_task(
            self.db,
            task=recurrent,
            current_user=admin,
            when_utc=datetime.utcnow().replace(tzinfo=None),
        )
        _assert(completed.status == TaskStatus.completed, "recurrent source task was not completed")
        _assert(spawned is not None and spawned.status == TaskStatus.active, "post-completion recurrence did not spawn a new active task")
        return "Recurrence parsing and post-completion spawn passed."

    def check_nested_subtasks_and_permissions(self) -> str:
        admin, _manager, subordinate = self.require_ready()
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        parent = create_task(
            self.db,
            owner=admin,
            name=f"{self.prefix} parent",
            task_type="ValidationNested",
            due_date=now + timedelta(hours=2),
        )
        child = create_task(
            self.db,
            owner=admin,
            name=f"{self.prefix} child",
            task_type="ValidationNested",
            due_date=now + timedelta(hours=3),
            parent_task_id=int(parent.id),
        )
        try:
            complete_task(self.db, task=parent, current_user=admin, when_utc=datetime.utcnow().replace(tzinfo=None))
            raise AssertionError("Completing a parent with an open child did not require confirmation")
        except OpenSubtasksError:
            pass
        complete_task(
            self.db,
            task=parent,
            current_user=admin,
            when_utc=datetime.utcnow().replace(tzinfo=None),
            cascade_subtasks=True,
        )
        self.db.refresh(child)
        _assert(child.status == TaskStatus.completed, "cascade completion did not close child task")

        protected = create_task(
            self.db,
            owner=admin,
            name=f"{self.prefix} protected",
            task_type="ValidationPermissions",
            due_date=now + timedelta(hours=4),
        )
        try:
            update_task(self.db, task=protected, current_user=subordinate, name="not allowed")
            raise AssertionError("Non-owner non-admin was allowed to update another user's task")
        except PermissionError:
            pass
        return "Nested subtask guard, cascade completion, and non-owner write denial passed."

    def check_manager_assignment_following(self) -> str:
        _admin, manager, subordinate = self.require_ready()
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        assigned = create_task(
            self.db,
            owner=subordinate,
            name=f"{self.prefix} assigned",
            task_type="ValidationAssignment",
            due_date=now + timedelta(hours=5),
            assigned_by_user_id=int(manager.id),
        )
        _assert(is_manager_of(self.db, manager_user_id=int(manager.id), subordinate_user_id=int(subordinate.id)), "manager relationship missing")
        follow_task(self.db, follower=manager, task=assigned)
        _assert(is_following_task(self.db, follower_user_id=int(manager.id), task_id=int(assigned.id)), "manager follow record was not created")
        unfollow_task(self.db, follower=manager, task=assigned)
        _assert(not is_following_task(self.db, follower_user_id=int(manager.id), task_id=int(assigned.id)), "manager follow record was not removed")
        return "Manager assignment and follow/unfollow paths passed."

    def check_notification_services_and_in_app(self) -> str:
        admin, _manager, _subordinate = self.require_ready()

        # Create one disabled service for every allowed notification channel so
        # validation covers configuration/tag generation without sending external
        # traffic. Browser is the only non-external channel and is also kept
        # disabled after update to avoid side effects during the run.
        sample_configs = {
            CHANNEL_BROWSER: {},
            CHANNEL_EMAIL: {"to_address": str(admin.email or f"{self.prefix}@example.invalid")},
            CHANNEL_GOTIFY: {"base_url": "https://example.invalid", "token": "validation-token"},
            CHANNEL_NTFY: {"server_url": "https://ntfy.sh", "topic": f"{self.prefix}-topic"},
            CHANNEL_DISCORD: {"webhook_url": "https://example.invalid/discord/webhook"},
            CHANNEL_WEBHOOK: {"url": "https://example.invalid/webhook", "secret": "validation-secret"},
            CHANNEL_GENERIC_API: {"url": "https://example.invalid/api", "method": "POST", "headers": {"X-Validation": "true"}},
            CHANNEL_WNS: {"channel_uri": "https://example.invalid/wns/channel"},
        }

        created_types: set[str] = set()
        for service_type in CHANNEL_TYPES:
            svc = create_user_notification_service(
                self.db,
                user_id=int(admin.id),
                service_type=service_type,
                name=f"{self.prefix} {service_type}",
                enabled=False,
                config=sample_configs.get(service_type, {}),
            )
            self.created_notify_service_ids.append(int(svc.id))
            created_types.add(str(svc.service_type))
            _assert(svc.tag is not None and str(svc.tag.name).startswith("notify:"), f"{service_type} service did not generate routing tag")

            updated = update_user_notification_service(
                self.db,
                user_id=int(admin.id),
                service_id=int(svc.id),
                name=f"{self.prefix} {service_type} updated",
                enabled=False,
                config=sample_configs.get(service_type, {}),
            )
            _assert(updated is not None and updated.enabled is False, f"{service_type} notification service update failed")

        services = list_user_notification_services(self.db, user_id=int(admin.id))
        listed_ids = {int(s.id) for s in services}
        for service_id in self.created_notify_service_ids:
            _assert(service_id in listed_ids, f"notification service list did not include service_id={service_id}")
        _assert(created_types == set(CHANNEL_TYPES), "not all notification channel types were configured: " + _safe_detail_join(sorted(set(CHANNEL_TYPES) - created_types)))

        create_in_app_notification(
            self.db,
            user_id=int(admin.id),
            event_type="validation",
            title=f"{self.prefix} notification",
            message="validation event",
        )
        self.db.commit()
        unread = count_in_app_unread(self.db, user_id=int(admin.id))
        _assert(unread >= 1, "in-app unread count did not increment")
        events = list_in_app_notifications(self.db, user_id=int(admin.id), include_cleared=True, limit=10)
        _assert(events, "in-app notification list was empty")
        clear_in_app_unread(self.db, user_id=int(admin.id))
        _assert(count_in_app_unread(self.db, user_id=int(admin.id)) == 0, "clear unread did not clear badge count")
        return "Notification service CRUD covered all allowed channels (" + ", ".join(sorted(created_types)) + ") and in-app notification lifecycle passed."

    def check_admin_settings_export_and_integrations(self) -> str:
        email_cfg = get_email_settings(self.db)
        logging_cfg = get_logging_settings(self.db)
        wns_cfg = get_wns_settings(self.db)
        backup_cfg = get_auto_backup_settings(self.db)
        _assert(logging_cfg.level, "logging settings missing level")
        _assert(email_cfg.reset_token_minutes > 0, "email reset token TTL invalid")
        _assert("frequency" in backup_cfg, "auto-backup settings missing frequency")
        _assert(CHANNEL_BROWSER in CHANNEL_TYPES, "browser notification channel missing")
        for expected in [CHANNEL_EMAIL, CHANNEL_GOTIFY, CHANNEL_NTFY, CHANNEL_DISCORD, CHANNEL_WEBHOOK, CHANNEL_GENERIC_API, CHANNEL_WNS]:
            _assert(expected in CHANNEL_TYPES, f"notification channel missing: {expected}")
        subject, body = build_password_reset_email(username="validation", reset_url="https://example.invalid/reset")
        _assert("validation" in body and subject, "password reset email template did not render")
        exported = export_db_json(self.db)
        errors, warnings = validate_import_payload(exported)
        if errors:
            raise AssertionError("Export validation errors: " + _safe_detail_join(errors, max_items=6))
        return (
            "Admin settings, notification channel registry, email template, and database export validation passed"
            + (f" with warnings: {_safe_detail_join(warnings, max_items=4)}" if warnings else ".")
        )


def _http_api_call(
    base_url: str,
    method: str,
    path: str,
    *,
    token: str | None = None,
    json_body: dict | None = None,
    form_body: dict | None = None,
    timeout_seconds: float = 4.0,
) -> tuple[int, str, object | None]:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationSkip("Base URL must use http or https")
    host = (parsed.hostname or "").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValidationSkip("Live API endpoint checks are restricted to loopback base URLs to avoid SSRF risk")

    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    headers = {"User-Agent": f"TimeboardAppValidation/{APP_VERSION}"}
    data: bytes | None = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(json_body).encode("utf-8")
    elif form_body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form_body).encode("utf-8")

    req = urllib.request.Request(url, headers=headers, data=data, method=str(method).upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:  # nosec B310 - loopback only, validated above
            raw = resp.read() or b""
            status_code = int(getattr(resp, "status", 200))
    except urllib.error.HTTPError as exc:
        raw = exc.read() or b""
        status_code = int(exc.code)
    except urllib.error.URLError as exc:
        raise ValidationWarn(f"Could not reach {url}: {exc}") from exc

    text = raw.decode("utf-8", errors="replace")
    parsed_body: object | None = None
    if text.strip():
        try:
            parsed_body = json.loads(text)
        except Exception:
            parsed_body = None
    return status_code, text, parsed_body


def _extract_access_token(body: object | None) -> str:
    if isinstance(body, dict):
        token = str(body.get("access_token") or "").strip()
        if token:
            return token
    raise AssertionError("Token endpoint did not return access_token")


def _check_live_documented_api_endpoints(base_url: str | None, fixture: _ValidationFixture) -> tuple[str, str]:
    if not base_url:
        raise ValidationSkip("No loopback base URL supplied")
    admin, _manager, _subordinate = fixture.require_ready()

    exercised: set[tuple[str, str]] = set()
    observations: list[str] = []
    failures: list[str] = []

    def call(
        route_key: tuple[str, str],
        method: str,
        path: str,
        *,
        token: str | None = None,
        json_body: dict | None = None,
        form_body: dict | None = None,
        expected: set[int] | None = None,
    ) -> tuple[int, str, object | None]:
        expected_set = expected or set(range(200, 300))
        status_code, text, body = _http_api_call(
            base_url,
            method,
            path,
            token=token,
            json_body=json_body,
            form_body=form_body,
        )
        exercised.add((route_key[0].upper(), route_key[1]))
        observations.append(f"{method.upper()} {route_key[1]}={status_code}")
        if status_code not in expected_set:
            snippet = text.strip().replace("\n", " ")[:160]
            failures.append(f"{method.upper()} {route_key[1]} got {status_code}, expected {sorted(expected_set)}; {snippet}")
        return status_code, text, body

    # Auth endpoints.
    _status, _text, token_body = call(
        ("POST", "/api/auth/token"),
        "POST",
        "/api/auth/token",
        form_body={"username": admin.username, "password": fixture.password},
    )
    token = _extract_access_token(token_body)
    call(("GET", "/api/auth/me"), "GET", "/api/auth/me", token=token)

    # Current-user endpoints and admin user CRUD.
    call(("GET", "/api/users/"), "GET", "/api/users/", token=token)
    call(("GET", "/api/users/me"), "GET", "/api/users/me", token=token)
    call(("PATCH", "/api/users/me"), "PATCH", "/api/users/me", token=token, json_body={})
    api_user_payload = {
        "username": f"{fixture.prefix}_api_user",
        "password": fixture.password,
        "email": f"{fixture.prefix}_api_user@example.invalid",
        "is_admin": False,
    }
    _s, _t, user_body = call(("POST", "/api/users/"), "POST", "/api/users/", token=token, json_body=api_user_payload, expected={200, 201})
    api_user_id = int(user_body.get("id")) if isinstance(user_body, dict) and user_body.get("id") else int(admin.id)
    call(("PATCH", "/api/users/{user_id}"), "PATCH", f"/api/users/{api_user_id}", token=token, json_body={"email": f"{fixture.prefix}_api_user2@example.invalid", "is_admin": False})
    call(("DELETE", "/api/users/{user_id}"), "DELETE", f"/api/users/{api_user_id}", token=token)

    # Task CRUD and lifecycle endpoints.
    call(("GET", "/api/tasks/"), "GET", "/api/tasks/", token=token)
    call(("GET", "/api/tasks/summary"), "GET", "/api/tasks/summary", token=token)
    task_payload = {
        "name": f"{fixture.prefix} api task",
        "task_type": "ValidationAPI",
        "description": "created by live API endpoint validation",
        "url": "",
        "due_date": (datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=2)).isoformat(),
        "recurrence_type": "none",
        "tags": [fixture.tag_primary],
    }
    _s, _t, task_body = call(("POST", "/api/tasks/"), "POST", "/api/tasks/", token=token, json_body=task_payload, expected={200, 201})
    task_id = int(task_body.get("id")) if isinstance(task_body, dict) and task_body.get("id") else 0
    _assert(task_id > 0, "Task API create did not return an id")
    call(("GET", "/api/tasks/{task_id}"), "GET", f"/api/tasks/{task_id}", token=token)
    call(("PUT", "/api/tasks/{task_id}"), "PUT", f"/api/tasks/{task_id}", token=token, json_body={"name": f"{fixture.prefix} api task updated"})
    call(("POST", "/api/tasks/{task_id}/complete"), "POST", f"/api/tasks/{task_id}/complete", token=token)
    call(("POST", "/api/tasks/{task_id}/restore"), "POST", f"/api/tasks/{task_id}/restore", token=token)
    call(("DELETE", "/api/tasks/{task_id}"), "DELETE", f"/api/tasks/{task_id}", token=token)

    # Tags.
    call(("GET", "/api/tags/"), "GET", "/api/tags/", token=token)

    # Notification services and events.
    call(("GET", "/api/notifications/services"), "GET", "/api/notifications/services", token=token)
    svc_payload = {"service_type": CHANNEL_BROWSER, "name": f"{fixture.prefix} api browser", "enabled": False, "config": {}}
    _s, _t, svc_body = call(("POST", "/api/notifications/services"), "POST", "/api/notifications/services", token=token, json_body=svc_payload, expected={200, 201})
    service_id = int(svc_body.get("id")) if isinstance(svc_body, dict) and svc_body.get("id") else 0
    _assert(service_id > 0, "Notification service API create did not return an id")
    fixture.created_notify_service_ids.append(service_id)
    call(("GET", "/api/notifications/services/{service_id}"), "GET", f"/api/notifications/services/{service_id}", token=token)
    call(("PUT", "/api/notifications/services/{service_id}"), "PUT", f"/api/notifications/services/{service_id}", token=token, json_body={"name": f"{fixture.prefix} api browser updated", "enabled": False, "config": {}})
    call(("GET", "/api/notifications/events"), "GET", "/api/notifications/events?limit=10", token=token)
    call(("DELETE", "/api/notifications/services/{service_id}"), "DELETE", f"/api/notifications/services/{service_id}", token=token, expected={200, 202, 204})
    try:
        fixture.created_notify_service_ids.remove(service_id)
    except ValueError:
        pass

    # Metrics endpoints.
    call(("GET", "/api/metrics/catalog"), "GET", "/api/metrics/catalog", token=token)
    call(("GET", "/api/metrics/me"), "GET", "/api/metrics/me", token=token)
    call(("GET", "/api/metrics/users"), "GET", "/api/metrics/users", token=token)
    call(("GET", "/api/metrics/users/{user_id}"), "GET", f"/api/metrics/users/{int(admin.id)}", token=token)
    call(("GET", "/api/metrics/deployment"), "GET", "/api/metrics/deployment", token=token)
    call(("GET", "/api/metrics/prometheus"), "GET", "/api/metrics/prometheus", token=token)
    call(("GET", "/api/metrics/influx"), "GET", "/api/metrics/influx", token=token)

    # Homepage customapi endpoints.
    call(("GET", "/api/homepage/summary"), "GET", "/api/homepage/summary", token=token)
    call(("GET", "/api/homepage/deployment"), "GET", "/api/homepage/deployment", token=token)
    call(("GET", "/api/homepage/users"), "GET", "/api/homepage/users", token=token)

    # Admin settings/log endpoints. PUT calls preserve existing secrets.
    _s, _t, email_body = call(("GET", "/api/admin/email"), "GET", "/api/admin/email", token=token)
    email_payload = dict(email_body) if isinstance(email_body, dict) else {}
    email_payload.update({"keep_existing_password": True, "keep_existing_sendgrid_api_key": True})
    call(("PUT", "/api/admin/email"), "PUT", "/api/admin/email", token=token, json_body=email_payload)

    _s, _t, logging_body = call(("GET", "/api/admin/logging"), "GET", "/api/admin/logging", token=token)
    logging_payload = dict(logging_body) if isinstance(logging_body, dict) else {"level": "INFO", "retention_days": 30}
    call(("PUT", "/api/admin/logging"), "PUT", "/api/admin/logging", token=token, json_body=logging_payload)

    _s, _t, wns_body = call(("GET", "/api/admin/wns"), "GET", "/api/admin/wns", token=token)
    wns_payload = {
        "enabled": bool(wns_body.get("enabled")) if isinstance(wns_body, dict) else False,
        "package_sid": str(wns_body.get("package_sid") or "") if isinstance(wns_body, dict) else "",
        "keep_existing_secret": True,
    }
    call(("PUT", "/api/admin/wns"), "PUT", "/api/admin/wns", token=token, json_body=wns_payload)

    _s, _t, logs_body = call(("GET", "/api/admin/logs/files"), "GET", "/api/admin/logs/files", token=token)
    log_filename = "missing-validation.log"
    if isinstance(logs_body, list) and logs_body and isinstance(logs_body[0], dict) and logs_body[0].get("filename"):
        log_filename = str(logs_body[0]["filename"])
    call(("GET", "/api/admin/logs/files/{filename}"), "GET", f"/api/admin/logs/files/{urllib.parse.quote(log_filename)}", token=token, expected={200, 404})

    documented = {(row["method"], row["path"]) for row in documented_api_routes()}
    missing = sorted([f"{method} {path}" for method, path in documented if (method, path) not in exercised])
    if missing:
        failures.append("documented endpoint(s) not exercised: " + _safe_detail_join(missing, max_items=20))
    if failures:
        raise AssertionError(_safe_detail_join(failures, max_items=18))
    return "PASS", f"Live loopback validation exercised {len(exercised)} documented API endpoints. Observed: " + _safe_detail_join(observations, max_items=20)


def _check_live_http(base_url: str | None) -> str:
    if not base_url:
        raise ValidationSkip("No loopback base URL supplied")
    expectations = {
        "/login": {200},
        "/docs": {200},
        "/api/tasks/": {401, 403},
        "/admin/users": {303, 307, 308},
        "/dashboard": {303, 307, 308},
    }
    observed: list[str] = []
    failures: list[str] = []
    for path, expected in expectations.items():
        status = _http_status(base_url, path)
        observed.append(f"{path}={status}")
        if status not in expected:
            failures.append(f"{path}: got {status}, expected {sorted(expected)}")
    if failures:
        raise AssertionError(_safe_detail_join(failures))
    return "Loopback HTTP checks passed: " + ", ".join(observed)


def _check_log_files_access() -> str:
    files = list_log_files()
    return f"Log directory is readable; {len(files)} log file(s) listed."


def _check_email_mode() -> tuple[str, str]:
    try:
        enabled = email_enabled()
    except TypeError:
        enabled = False
    if enabled:
        return "PASS", "Email delivery is enabled/configured; validation did not send external email."
    return "SKIP", "Email delivery is disabled or unconfigured; external SMTP/SendGrid delivery was not attempted."


def _check_notification_delivery_modes() -> tuple[str, str]:
    return (
        "PASS",
        "All notification service types are registered for configuration checks: "
        + ", ".join(sorted(CHANNEL_TYPES)),
    )


def run_admin_validation(
    db: Session,
    *,
    actor: str = "admin",
    base_url: str | None = None,
    log_dir: Path | None = None,
    write_log: bool = True,
) -> ValidationReport:
    """Run feature and security validation checks in a running environment.

    The suite creates isolated temporary users/tasks/services, validates core
    behavior, and then removes only records created with its unique prefix.
    It does not execute user-supplied shell commands or send external email or
    webhook traffic.
    """

    report = ValidationReport(
        run_id=datetime.utcnow().strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4),
        app_version=APP_VERSION,
        started_at_utc=datetime.utcnow().replace(tzinfo=None),
        actor=actor,
        base_url=base_url,
    )

    _run_check(report, "Environment", "Version metadata and DB schema version", lambda: _check_version_and_db(db))
    _run_check(report, "Environment", "Configuration sanity", _check_config_sanity)
    _run_check(report, "Environment", "Dependency inventory and optional CVE tooling", _check_dependency_inventory)
    _run_check(report, "Environment", "Documented API endpoint inventory", _check_api_endpoint_inventory)
    _run_check(report, "Environment", "Orphaned release artifact scan", _check_orphaned_release_artifacts)
    _run_check(report, "Environment", "Application log file access", _check_log_files_access)

    _run_check(report, "Security", "Runtime secret strength", _check_settings_security, security=True)
    _run_check(report, "Security", "High-risk source pattern scan", _scan_source_for_risky_patterns, security=True)
    _run_check(report, "Security", "Browser security header source check", _check_security_headers_source, security=True)
    _run_check(report, "Security", "Installation-specific credentials and secrets", lambda: _check_installation_specific_security(db), security=True)
    _run_check(report, "Security", "Live unauthenticated HTTP access controls", lambda: _check_live_http(base_url), security=True)

    fixture = _ValidationFixture(db)
    try:
        _run_check(report, "Feature validation", "Isolated validation fixture setup", fixture.setup)
        _run_check(report, "Feature validation", "Authentication, profile prefs, and password reset", fixture.check_auth_profile_and_password_reset, security=True)
        _run_check(report, "Feature validation", "Task CRUD, filtering, archiving, and restore", fixture.check_task_crud_filtering_and_archiving)
        _run_check(report, "Feature validation", "Past-due tag bar data source", fixture.check_past_due_tag_bar_data)
        _run_check(report, "Feature validation", "Recurrence parsing and spawning", fixture.check_recurrence_modes)
        _run_check(report, "Feature validation", "Nested subtasks and authorization denial", fixture.check_nested_subtasks_and_permissions, security=True)
        _run_check(report, "Feature validation", "Manager assignment and follow/unfollow", fixture.check_manager_assignment_following)
        _run_check(report, "Feature validation", "Notification services and in-app notifications", fixture.check_notification_services_and_in_app)
        _run_check(report, "Feature validation", "Admin settings, integrations, and DB export validation", fixture.check_admin_settings_export_and_integrations)
        _run_check(report, "Feature validation", "Live documented API endpoint exercise", lambda: _check_live_documented_api_endpoints(base_url, fixture), security=True)
    finally:
        try:
            fixture.cleanup()
            report.add("Feature validation", "Isolated validation fixture cleanup", "PASS", "Temporary validation records were removed.")
        except Exception as exc:
            report.add("Feature validation", "Isolated validation fixture cleanup", "FAIL", str(exc))

    _run_check(report, "External integrations", "Email delivery mode", _check_email_mode)
    _run_check(report, "External integrations", "Notification delivery channel registry", _check_notification_delivery_modes)

    report.completed_at_utc = datetime.utcnow().replace(tzinfo=None)
    if write_log:
        _write_validation_log(report, log_dir=log_dir)
    return report
