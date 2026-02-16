from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import Iterable, List, Optional

from .models import RecurrenceType, Task
from .utils.time_utils import from_local_to_utc_naive, get_app_tz, now_utc, to_local


_DURATION_RE = re.compile(
    r"(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>weeks?|w|days?|d|hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s)\b",
    re.IGNORECASE,
)


class RecurrenceError(ValueError):
    pass


def parse_duration_to_seconds(text: str) -> int:
    """Parse a human duration like '8h', '1 day 2 hours', '90m' into seconds."""
    if not text or not str(text).strip():
        raise RecurrenceError("Interval is required")

    total_seconds = 0.0
    matches = list(_DURATION_RE.finditer(text.strip()))
    if not matches:
        raise RecurrenceError(
            "Invalid interval. Examples: '8h', '30m', '1d 2h', '90s', '2 weeks'"
        )

    for m in matches:
        val = float(m.group("value"))
        unit = m.group("unit").lower()
        if unit in {"week", "weeks", "w"}:
            total_seconds += val * 7 * 24 * 3600
        elif unit in {"day", "days", "d"}:
            total_seconds += val * 24 * 3600
        elif unit in {"hour", "hours", "hr", "hrs", "h"}:
            total_seconds += val * 3600
        elif unit in {"minute", "minutes", "min", "mins", "m"}:
            total_seconds += val * 60
        elif unit in {"second", "seconds", "sec", "secs", "s"}:
            total_seconds += val
        else:
            raise RecurrenceError(f"Unsupported unit: {unit}")

    seconds_int = int(round(total_seconds))
    if seconds_int <= 0:
        raise RecurrenceError("Interval must be greater than 0")
    return seconds_int


_TIME_PATTERNS = [
    "%H:%M",
    "%H:%M:%S",
    "%I:%M%p",
    "%I:%M %p",
    "%I%p",
    "%I %p",
]


def _parse_one_time(token: str) -> time:
    tok = token.strip().lower()
    tok = tok.replace(".", "")
    tok = re.sub(r"\s+", " ", tok)
    # normalize am/pm spacing
    tok = tok.replace("am", " am").replace("pm", " pm")
    tok = re.sub(r"\s+", " ", tok).strip()

    # Try strict formats.
    for fmt in _TIME_PATTERNS:
        try:
            dt = datetime.strptime(tok.replace(" ", ""), fmt) if "%p" in fmt and " " not in fmt else datetime.strptime(tok, fmt)
            return dt.time().replace(second=0, microsecond=0)
        except ValueError:
            continue

    # Last-resort: accept '8:00am' without space.
    try:
        dt = datetime.strptime(tok.replace(" ", ""), "%I:%M%p")
        return dt.time().replace(second=0, microsecond=0)
    except ValueError as e:
        raise RecurrenceError(f"Invalid time value: '{token}'") from e


def parse_times_csv(text: str) -> str:
    """Parse a comma-separated time list into canonical 'HH:MM,HH:MM' 24h format."""
    if not text or not str(text).strip():
        raise RecurrenceError("Times list is required")

    parts = [p.strip() for p in str(text).split(",") if p.strip()]
    if not parts:
        raise RecurrenceError("Times list is required")

    times: List[time] = []
    for p in parts:
        times.append(_parse_one_time(p))

    # Deduplicate + sort
    uniq = sorted({(t.hour, t.minute) for t in times})
    canonical = ",".join([f"{h:02d}:{m:02d}" for h, m in uniq])
    return canonical


def parse_times_canonical(canonical: str) -> list[time]:
    if not canonical:
        return []
    result: list[time] = []
    for token in canonical.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            dt = datetime.strptime(token, "%H:%M")
            result.append(dt.time())
        except ValueError as e:
            raise RecurrenceError(f"Invalid canonical time: '{token}'") from e
    result.sort(key=lambda t: (t.hour, t.minute))
    return result


def compute_next_due_utc(task: Task, completed_at_utc: datetime) -> Optional[datetime]:
    """Compute the next due date for a task that was just completed.

    Returns a naive UTC datetime or None if no recurrence.
    """
    rtype = RecurrenceType(task.recurrence_type)

    if rtype == RecurrenceType.none:
        return None

    if rtype == RecurrenceType.post_completion:
        if not task.recurrence_interval_seconds:
            raise RecurrenceError("Post-completion interval is required")
        return completed_at_utc + timedelta(seconds=int(task.recurrence_interval_seconds))

    if rtype == RecurrenceType.fixed_clock:
        if not task.recurrence_interval_seconds:
            raise RecurrenceError("Fixed-clock interval is required")
        interval = timedelta(seconds=int(task.recurrence_interval_seconds))

        # Next occurrence is anchored to the due date sequence, not completion time.
        candidate = task.due_date_utc + interval
        ref = completed_at_utc
        while candidate <= ref:
            candidate = candidate + interval
        return candidate

    if rtype == RecurrenceType.multi_slot_daily:
        if not task.recurrence_times:
            raise RecurrenceError("Daily time slots are required")

        tz = get_app_tz()
        slots = parse_times_canonical(task.recurrence_times)
        if not slots:
            raise RecurrenceError("Daily time slots are required")

        # Anchor on the task's scheduled due date (not completion time), then catch up until > completion.
        anchor_local = to_local(task.due_date_utc)

        def next_after(anchor: datetime) -> datetime:
            d = anchor.date()
            t = anchor.time().replace(second=0, microsecond=0)
            later = [s for s in slots if (s.hour, s.minute) > (t.hour, t.minute)]
            if later:
                chosen = later[0]
                candidate_local = datetime.combine(d, chosen, tzinfo=tz)
            else:
                candidate_local = datetime.combine(d + timedelta(days=1), slots[0], tzinfo=tz)
            return candidate_local

        candidate_local = next_after(anchor_local)
        # Convert to UTC naive
        from datetime import timezone as _tz
        candidate_utc = candidate_local.astimezone(_tz.utc).replace(tzinfo=None)

        ref = completed_at_utc
        # Catch up if the next slot is still in the past (e.g., completion occurred days later)
        while candidate_utc <= ref:
            anchor_local = candidate_local
            candidate_local = next_after(anchor_local)
            candidate_utc = candidate_local.astimezone(_tz.utc).replace(tzinfo=None)

        return candidate_utc

    raise RecurrenceError(f"Unsupported recurrence type: {task.recurrence_type}")
