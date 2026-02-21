import io
import json


class _DummyResp:
    def __init__(self, status: int = 202, body: bytes = b""):
        self.status = int(status)
        self._body = body

    def read(self):
        return self._body

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _get_header(req, key: str) -> str | None:
    try:
        v = req.get_header(key)
        if v:
            return v
    except Exception:
        pass
    try:
        for k, v in req.header_items():
            if str(k).lower() == str(key).lower():
                return v
    except Exception:
        pass
    # Some headers are stored in a separate mapping.
    try:
        for store in (getattr(req, "headers", None), getattr(req, "unredirected_hdrs", None)):
            if isinstance(store, dict):
                for k, v in store.items():
                    if str(k).lower() == str(key).lower():
                        return v
    except Exception:
        pass
    return None


def test_email_enabled_sendgrid_requires_api_key(monkeypatch):
    from app import emailer
    from app.meta_settings import EmailConfig

    cfg_missing = EmailConfig(enabled=True, provider="sendgrid", sendgrid_api_key="")
    monkeypatch.setattr(emailer, "_load_email_config", lambda db=None: cfg_missing)
    assert emailer.email_enabled() is False

    cfg_ok = EmailConfig(enabled=True, provider="sendgrid", sendgrid_api_key="SG.TEST")
    monkeypatch.setattr(emailer, "_load_email_config", lambda db=None: cfg_ok)
    assert emailer.email_enabled() is True


def test_send_email_sendgrid_builds_expected_request(monkeypatch):
    from app import emailer
    from app.meta_settings import EmailConfig

    cfg = EmailConfig(
        enabled=True,
        provider="sendgrid",
        sendgrid_api_key="SG.TEST",
        smtp_from="Timeboard <timeboard@example.com>",
    )
    monkeypatch.setattr(emailer, "_load_email_config", lambda db=None: cfg)

    # Ensure SMTP path is not used.
    monkeypatch.setattr(emailer, "_smtp_connect", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("smtp")))

    captured = {}

    def _fake_urlopen(req, timeout=None):
        captured["req"] = req
        captured["timeout"] = timeout
        return _DummyResp(status=202)

    monkeypatch.setattr(emailer.request, "urlopen", _fake_urlopen)

    emailer.send_email(
        to_address="User One <u1@example.com>, u2@example.com",
        subject="Subject",
        body_text="Hello",
        body_html="<b>Hello</b>",
    )

    req = captured.get("req")
    assert req is not None
    assert getattr(req, "full_url", "") == emailer.SENDGRID_SEND_ENDPOINT
    assert _get_header(req, "Authorization") == "Bearer SG.TEST"
    assert _get_header(req, "Content-Type") == "application/json"

    payload = json.loads(req.data.decode("utf-8"))
    assert payload["subject"] == "Subject"
    assert payload["from"]["email"] == "timeboard@example.com"
    assert payload["from"]["name"] == "Timeboard"
    assert len(payload["personalizations"][0]["to"]) == 2
    assert payload["personalizations"][0]["to"][0]["email"] == "u1@example.com"
    assert payload["personalizations"][0]["to"][0]["name"] == "User One"
    assert payload["personalizations"][0]["to"][1]["email"] == "u2@example.com"
    assert any(c.get("type") == "text/plain" for c in payload["content"])
    assert any(c.get("type") == "text/html" for c in payload["content"])


def test_send_email_sendgrid_http_error_does_not_leak_api_key(monkeypatch):
    from urllib.error import HTTPError

    from app import emailer
    from app.meta_settings import EmailConfig

    cfg = EmailConfig(enabled=True, provider="sendgrid", sendgrid_api_key="SG.SECRET")
    monkeypatch.setattr(emailer, "_load_email_config", lambda db=None: cfg)

    def _fake_urlopen(req, timeout=None):
        raise HTTPError(
            url=emailer.SENDGRID_SEND_ENDPOINT,
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=io.BytesIO(b'{"errors":[{"message":"invalid api key"}]}'),
        )

    monkeypatch.setattr(emailer.request, "urlopen", _fake_urlopen)

    try:
        emailer.send_email(to_address="u@example.com", subject="S", body_text="B")
        assert False, "expected send_email to raise"
    except RuntimeError as e:
        s = str(e)
        assert "401" in s
        assert "invalid api key" in s
        assert "SG.SECRET" not in s
