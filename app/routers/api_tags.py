from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..auth import get_current_user_api
from ..crud import get_user, list_tags_for_user
from ..db import get_db
from ..schemas import TagOut


router = APIRouter()


@router.get("/", response_model=list[TagOut])
def api_list_tags(
    user_id: int | None = Query(default=None, description="Admin-only: list tags for a specific user"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user_api),
):
    if current_user.is_admin and user_id:
        u = get_user(db, int(user_id))
        if not u:
            return []
        return list_tags_for_user(db, user=u)
    return list_tags_for_user(db, user=current_user)
