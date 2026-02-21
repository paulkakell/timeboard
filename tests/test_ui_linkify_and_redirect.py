from app.routers.ui import _safe_next_url, linkify_urls


def test_linkify_urls_basic_http_and_trailing_punct():
    html = str(linkify_urls("See https://example.com/test."))
    assert '<a href="https://example.com/test"' in html
    assert ">https://example.com/test</a>" in html
    # Trailing period should not be part of the link.
    assert html.endswith(".")


def test_linkify_urls_www_prefix_adds_https_href():
    html = str(linkify_urls("Visit www.example.com/path"))
    assert '<a href="https://www.example.com/path"' in html
    assert ">www.example.com/path</a>" in html


def test_linkify_urls_escapes_html():
    html = str(linkify_urls("<script>alert(1)</script> https://example.com"))
    # Script tags must be escaped, not rendered.
    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert '<a href="https://example.com"' in html


def test_safe_next_url_blocks_external_and_allows_internal():
    assert _safe_next_url("http://evil.com", default="/dashboard") == "/dashboard"
    assert _safe_next_url("https://evil.com", default="/dashboard") == "/dashboard"
    assert _safe_next_url("//evil.com", default="/dashboard") == "/dashboard"
    assert _safe_next_url("/dashboard?page=2&tag=x", default="/dashboard") == "/dashboard?page=2&tag=x"
    assert _safe_next_url("  /calendar  ", default="/dashboard") == "/calendar"
