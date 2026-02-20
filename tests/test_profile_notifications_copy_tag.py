from pathlib import Path


def test_profile_notifications_tag_is_click_to_copy():
    tpl = Path(__file__).resolve().parent.parent / 'app' / 'templates' / 'profile_notifications.html'
    text = tpl.read_text(encoding='utf-8')
    assert 'data-copy-text' in text
    assert 'copy-to-clipboard' in text
