import json


def test_gotify_send_uses_header_token(monkeypatch):
    from app import notifications

    captured = {}

    def fake_http_request(*, url, headers, data, method="POST", timeout=10):
        captured["url"] = url
        captured["headers"] = headers
        captured["data"] = data
        return 200, ""

    monkeypatch.setattr(notifications, "_http_request", fake_http_request)

    notifications._send_gotify(
        config={"base_url": "https://gotify.example.com", "token": "abc123", "priority": 5},
        title="T",
        message="M",
    )

    assert captured["url"] == "https://gotify.example.com/message"
    assert captured["headers"].get("X-Gotify-Key") == "abc123"
    assert "token=" not in captured["url"]

    payload = json.loads(captured["data"].decode("utf-8"))
    assert payload["title"] == "T"
    assert payload["message"] == "M"


def test_gotify_priority_is_clamped(monkeypatch):
    from app import notifications

    captured = {}

    def fake_http_request(*, url, headers, data, method="POST", timeout=10):
        captured["data"] = data
        return 200, ""

    monkeypatch.setattr(notifications, "_http_request", fake_http_request)

    notifications._send_gotify(
        config={"base_url": "https://gotify.example.com", "token": "abc123", "priority": 999},
        title="T",
        message="M",
    )
    payload = json.loads(captured["data"].decode("utf-8"))
    assert payload["priority"] == 10
