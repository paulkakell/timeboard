from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .crud import create_task
from .models import RecurrenceType, Task, User


logger = logging.getLogger("timeboard.demo_data")


def seed_demo_data(db: Session, *, owner: User) -> dict[str, int]:
    """Populate a small set of demo tasks/tags for first-run installs.

    This is intentionally conservative:
      - Only seeds when the database has no tasks.
      - Does not emit notification events.

    Returns counts for logging/UI.
    """

    # Avoid duplicate seeding if this is called more than once.
    try:
        existing_tasks = int(db.query(Task).count() or 0)
    except Exception:
        existing_tasks = 0
    if existing_tasks > 0:
        return {"seeded": 0, "skipped": 1, "tasks_created": 0}

    now = datetime.now(timezone.utc)

    demo_tasks: list[dict] = [
        {
            "name": "Welcome to Timeboard",
            "task_type": "Getting Started",
            "due_date": now + timedelta(hours=2),
            "description": (
                "This is demo data created on first run.\n\n"
                "Tips:\n"
                "- Add tags (comma-separated) to group tasks\n"
                "- Try the recurrence options (None / Post-Completion / Multi-Slot Daily / Fixed Clock)\n"
                "- Visit /help for notification routing and examples"
            ),
            "tags": ["demo", "tips"],
        },
        {
            "name": "Example: Post-completion recurrence (every 8h after completion)",
            "task_type": "Demo",
            "due_date": now + timedelta(hours=4),
            "recurrence_type": RecurrenceType.post_completion.value,
            "recurrence_interval": "8h",
            "tags": ["demo", "recurring"],
        },
        {
            "name": "Example: Multi-slot daily (09:00, 13:00, 18:00)",
            "task_type": "Demo",
            "due_date": now + timedelta(hours=1),
            "recurrence_type": RecurrenceType.multi_slot_daily.value,
            "recurrence_times": "09:00, 13:00, 18:00",
            "tags": ["demo", "recurring"],
        },
        {
            "name": "Example: Fixed clock schedule (Every Tuesday)",
            "task_type": "Demo",
            "due_date": now + timedelta(days=1),
            "recurrence_type": RecurrenceType.fixed_clock.value,
            "recurrence_interval": "Every Tuesday",
            "tags": ["demo", "recurring"],
        },
        {
            "name": "Example: Fixed clock schedule (10th of every month)",
            "task_type": "Demo",
            "due_date": now + timedelta(days=7),
            "recurrence_type": RecurrenceType.fixed_clock.value,
            "recurrence_interval": "10th of every month",
            "tags": ["demo", "recurring"],
        },
    ]

    created = 0
    for spec in demo_tasks:
        try:
            create_task(
                db,
                owner=owner,
                name=str(spec.get("name") or ""),
                task_type=str(spec.get("task_type") or "General"),
                due_date=spec.get("due_date"),
                description=spec.get("description"),
                url=spec.get("url"),
                recurrence_type=str(spec.get("recurrence_type") or RecurrenceType.none.value),
                recurrence_interval=spec.get("recurrence_interval"),
                recurrence_times=spec.get("recurrence_times"),
                tags=spec.get("tags"),
                send_notifications=False,
            )
            created += 1
        except Exception:
            logger.exception("Failed to create demo task: %s", spec.get("name"))

    return {"seeded": 1, "skipped": 0, "tasks_created": int(created)}
