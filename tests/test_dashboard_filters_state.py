from app.routers.ui import _merge_stateful_dashboard_filters


def test_merge_stateful_dashboard_filters_defaults_admin():
    effective, new_state = _merge_stateful_dashboard_filters(
        query_params={},
        existing_state=None,
        is_admin=True,
        current_user_id=5,
    )

    assert effective["tag"] is None
    assert effective["task_type"] is None
    assert effective["sort"] == "due_date"
    assert effective["page_size"] == 10
    assert effective["user_id"] == 5

    assert new_state["sort"] == "due_date"
    assert new_state["page_size"] == 10
    assert new_state["user_id"] == 5


def test_merge_stateful_dashboard_filters_uses_existing_when_query_missing():
    existing = {
        "tag": "finance",
        "task_type": "TypeA",
        "sort": "name",
        "page_size": 100,
        "user_id": 0,
    }
    effective, new_state = _merge_stateful_dashboard_filters(
        query_params={},
        existing_state=existing,
        is_admin=True,
        current_user_id=5,
    )
    assert effective["tag"] == "finance"
    assert effective["task_type"] == "TypeA"
    assert effective["sort"] == "name"
    assert effective["page_size"] == 100
    assert effective["user_id"] == 0
    assert new_state["user_id"] == 0


def test_merge_stateful_dashboard_filters_overrides_only_present_params():
    existing = {"tag": "old", "sort": "name", "page_size": 100, "user_id": 5}
    effective, new_state = _merge_stateful_dashboard_filters(
        query_params={"tag": "new", "page_size": "50"},
        existing_state=existing,
        is_admin=True,
        current_user_id=5,
    )
    assert effective["tag"] == "new"
    assert effective["page_size"] == 50
    # sort wasn't in the query, so it remains from the session
    assert effective["sort"] == "name"
    assert new_state["sort"] == "name"


def test_merge_stateful_dashboard_filters_blank_clears_tag():
    existing = {"tag": "finance", "page_size": 25, "user_id": 5}
    effective, new_state = _merge_stateful_dashboard_filters(
        query_params={"tag": ""},
        existing_state=existing,
        is_admin=True,
        current_user_id=5,
    )
    assert effective["tag"] is None
    assert new_state["tag"] is None
