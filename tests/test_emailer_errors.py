import socket


def test_safe_smtp_host_strips_common_wrappers():
    from app.emailer import _safe_smtp_host_for_logs

    assert _safe_smtp_host_for_logs("smtp.example.com") == "smtp.example.com"
    assert _safe_smtp_host_for_logs("smtp.example.com:587") == "smtp.example.com"
    assert _safe_smtp_host_for_logs("smtp://smtp.example.com:587") == "smtp.example.com"
    assert _safe_smtp_host_for_logs("user:pw@smtp.example.com") == "smtp.example.com"
    assert _safe_smtp_host_for_logs("smtp.example.com/path?q=1") == "smtp.example.com"
    assert _safe_smtp_host_for_logs("[::1]") == "::1"


def test_smtp_connect_timeout_message_includes_host_port(monkeypatch):
    from app.emailer import _smtp_connect
    from app.meta_settings import EmailConfig

    def _raise_timeout(*args, **kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr("app.emailer.smtplib.SMTP", _raise_timeout)

    cfg = EmailConfig(enabled=True, smtp_host="smtp.example.com", smtp_port=587, use_tls=True)
    try:
        _smtp_connect(cfg)
        assert False, "expected _smtp_connect to raise"
    except RuntimeError as e:
        s = str(e)
        assert "smtp.example.com:587" in s
        assert "timed out" in s


def test_smtp_connect_timeout_message_includes_localhost_docker_hint(monkeypatch):
    from app.emailer import _smtp_connect
    from app.meta_settings import EmailConfig

    def _raise_timeout(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr("app.emailer.smtplib.SMTP", _raise_timeout)

    cfg = EmailConfig(enabled=True, smtp_host="localhost", smtp_port=25, use_tls=False)
    try:
        _smtp_connect(cfg)
        assert False, "expected _smtp_connect to raise"
    except RuntimeError as e:
        assert "Docker note" in str(e)
