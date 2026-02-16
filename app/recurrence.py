from __future__ import annotations

import calendar
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


# ---------------------- Fixed calendar scheduling (fixed_clock extension) ----------------------


_WEEKDAY_TOKEN_TO_INT: dict[str, int] = {
    "mon": 0,
    "monday": 0,
    "tue": 1,
    "tues": 1,
    "tuesday": 1,
    "wed": 2,
    "wednesday": 2,
    "thu": 3,
    "thur": 3,
    "thurs": 3,
    "thursday": 3,
    "fri": 4,
    "friday": 4,
    "sat": 5,
    "saturday": 5,
    "sun": 6,
    "sunday": 6,
}

_INT_TO_WEEKDAY_CODE: dict[int, str] = {
    0: "MO",
    1: "TU",
    2: "WE",
    3: "TH",
    4: "FR",
    5: "SA",
    6: "SU",
}
_WEEKDAY_CODE_TO_INT: dict[str, int] = {v: k for k, v in _INT_TO_WEEKDAY_CODE.items()}
_INT_TO_WEEKDAY_NAME: dict[int, str] = {
    0: "Monday",
    1: "Tuesday",
    2: "Wednesday",
    3: "Thursday",
    4: "Friday",
    5: "Saturday",
    6: "Sunday",
}

_MONTH_TOKEN_TO_INT: dict[str, int] = {
    "jan": 1,
    "january": 1,
    "feb": 2,
    "february": 2,
    "mar": 3,
    "march": 3,
    "apr": 4,
    "april": 4,
    "may": 5,
    "jun": 6,
    "june": 6,
    "jul": 7,
    "july": 7,
    "aug": 8,
    "august": 8,
    "sep": 9,
    "sept": 9,
    "september": 9,
    "oct": 10,
    "october": 10,
    "nov": 11,
    "november": 11,
    "dec": 12,
    "december": 12,
}
_INT_TO_MONTH_NAME: dict[int, str] = {
    1: "January",
    2: "February",
    3: "March",
    4: "April",
    5: "May",
    6: "June",
    7: "July",
    8: "August",
    9: "September",
    10: "October",
    11: "November",
    12: "December",
}

_ORDINAL_TOKEN_TO_POS: dict[str, int] = {
    "first": 1,
    "1st": 1,
    "second": 2,
    "2nd": 2,
    "third": 3,
    "3rd": 3,
    "fourth": 4,
    "4th": 4,
    "last": -1,
}


@dataclass(frozen=True)
class FixedCalendarRule:
    """Subset of RFC 5545 RRULE for fixed calendar scheduling.

    Stored canonically in Task.recurrence_times for RecurrenceType.fixed_clock.
    """

    freq: str  # WEEKLY | MONTHLY | YEARLY
    byday: tuple[int, ...] = ()  # weekday ints (0=Mon)
    bymonthday: int | None = None
    bysetpos: int | None = None
    bymonth: int | None = None


def _last_day_of_month(year: int, month: int) -> int:
    return int(calendar.monthrange(year, month)[1])


def _add_months(year: int, month: int, delta_months: int) -> tuple[int, int]:
    """Add months to (year, month). Month is 1-12."""
    idx = (year * 12) + (month - 1) + int(delta_months)
    new_year = idx // 12
    new_month = (idx % 12) + 1
    return int(new_year), int(new_month)


def _ordinal_suffix(n: int) -> str:
    if 10 <= (n % 100) <= 20:
        return "th"
    return {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")


def _looks_like_fixed_rule_canonical(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    u = t.upper()
    return u.startswith("RRULE:") or "FREQ=" in u


def fixed_calendar_rule_to_canonical(rule: FixedCalendarRule) -> str:
    freq = rule.freq.upper().strip()
    if freq == "WEEKLY":
        if not rule.byday:
            raise RecurrenceError("Weekly rule requires BYDAY")
        days = ",".join([_INT_TO_WEEKDAY_CODE[d] for d in sorted(set(rule.byday))])
        return f"FREQ=WEEKLY;BYDAY={days}"

    if freq == "MONTHLY":
        if rule.bymonthday is not None:
            if rule.bymonthday < 1 or rule.bymonthday > 31:
                raise RecurrenceError("Monthly BYMONTHDAY must be between 1 and 31")
            return f"FREQ=MONTHLY;BYMONTHDAY={int(rule.bymonthday)}"
        if rule.bysetpos is None or not rule.byday:
            raise RecurrenceError("Monthly rule requires BYMONTHDAY or (BYSETPOS + BYDAY)")
        if len(rule.byday) != 1:
            raise RecurrenceError("Monthly BYSETPOS rules support exactly one weekday")
        pos = int(rule.bysetpos)
        if pos not in {1, 2, 3, 4, -1}:
            raise RecurrenceError("Monthly BYSETPOS must be First/Second/Third/Fourth/Last")
        return f"FREQ=MONTHLY;BYSETPOS={pos};BYDAY={_INT_TO_WEEKDAY_CODE[rule.byday[0]]}"

    if freq == "YEARLY":
        if rule.bymonth is None or rule.bymonthday is None:
            raise RecurrenceError("Yearly rule requires BYMONTH and BYMONTHDAY")
        m = int(rule.bymonth)
        d = int(rule.bymonthday)
        if m < 1 or m > 12:
            raise RecurrenceError("Yearly BYMONTH must be between 1 and 12")
        if d < 1 or d > 31:
            raise RecurrenceError("Yearly BYMONTHDAY must be between 1 and 31")
        return f"FREQ=YEARLY;BYMONTH={m};BYMONTHDAY={d}"

    raise RecurrenceError(f"Unsupported fixed schedule frequency: {rule.freq}")


def parse_fixed_calendar_rule_canonical(text: str) -> FixedCalendarRule:
    """Parse a canonical fixed-calendar rule.

    Supported canonical forms (subset of RRULE):
      - FREQ=WEEKLY;BYDAY=MO,WE,FR
      - FREQ=MONTHLY;BYMONTHDAY=10
      - FREQ=MONTHLY;BYSETPOS=1;BYDAY=MO
      - FREQ=YEARLY;BYMONTH=1;BYMONTHDAY=5

    A leading 'RRULE:' prefix is accepted.
    """
    if not text or not str(text).strip():
        raise RecurrenceError("Fixed schedule rule is required")

    raw = str(text).strip()
    if raw.upper().startswith("RRULE:"):
        raw = raw.split(":", 1)[1].strip()

    parts = [p.strip() for p in raw.split(";") if p.strip()]
    kv: dict[str, str] = {}
    for p in parts:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        kv[k.strip().upper()] = v.strip()

    freq = kv.get("FREQ", "").upper().strip()
    if freq not in {"WEEKLY", "MONTHLY", "YEARLY"}:
        raise RecurrenceError("Fixed schedule rule must include FREQ=WEEKLY|MONTHLY|YEARLY")

    if freq == "WEEKLY":
        byday_raw = kv.get("BYDAY")
        if not byday_raw:
            raise RecurrenceError("Weekly fixed schedule requires BYDAY")
        codes = [c.strip().upper() for c in byday_raw.split(",") if c.strip()]
        days: list[int] = []
        for c in codes:
            if c not in _WEEKDAY_CODE_TO_INT:
                raise RecurrenceError(f"Invalid BYDAY weekday code: {c}")
            days.append(_WEEKDAY_CODE_TO_INT[c])
        if not days:
            raise RecurrenceError("Weekly fixed schedule requires at least one BYDAY")
        return FixedCalendarRule(freq="WEEKLY", byday=tuple(sorted(set(days))))

    if freq == "MONTHLY":
        if "BYMONTHDAY" in kv:
            try:
                md = int(kv["BYMONTHDAY"])
            except ValueError as e:
                raise RecurrenceError("MONTHLY BYMONTHDAY must be an integer") from e
            if md < 1 or md > 31:
                raise RecurrenceError("MONTHLY BYMONTHDAY must be between 1 and 31")
            return FixedCalendarRule(freq="MONTHLY", bymonthday=md)

        byday_raw = kv.get("BYDAY")
        bysetpos_raw = kv.get("BYSETPOS")
        if not byday_raw or not bysetpos_raw:
            raise RecurrenceError("MONTHLY fixed schedule requires BYMONTHDAY or (BYSETPOS + BYDAY)")

        codes = [c.strip().upper() for c in byday_raw.split(",") if c.strip()]
        if len(codes) != 1:
            raise RecurrenceError("MONTHLY BYSETPOS rules support exactly one weekday")
        code = codes[0]
        if code not in _WEEKDAY_CODE_TO_INT:
            raise RecurrenceError(f"Invalid BYDAY weekday code: {code}")
        try:
            pos = int(bysetpos_raw)
        except ValueError as e:
            raise RecurrenceError("MONTHLY BYSETPOS must be an integer") from e
        if pos not in {1, 2, 3, 4, -1}:
            raise RecurrenceError("MONTHLY BYSETPOS must be 1-4 or -1 (last)")
        return FixedCalendarRule(freq="MONTHLY", byday=(int(_WEEKDAY_CODE_TO_INT[code]),), bysetpos=pos)

    # YEARLY
    bymonth_raw = kv.get("BYMONTH")
    bymonthday_raw = kv.get("BYMONTHDAY")
    if not bymonth_raw or not bymonthday_raw:
        raise RecurrenceError("YEARLY fixed schedule requires BYMONTH and BYMONTHDAY")
    try:
        m = int(bymonth_raw)
        d = int(bymonthday_raw)
    except ValueError as e:
        raise RecurrenceError("YEARLY BYMONTH and BYMONTHDAY must be integers") from e
    if m < 1 or m > 12:
        raise RecurrenceError("YEARLY BYMONTH must be between 1 and 12")
    if d < 1 or d > 31:
        raise RecurrenceError("YEARLY BYMONTHDAY must be between 1 and 31")
    return FixedCalendarRule(freq="YEARLY", bymonth=m, bymonthday=d)


def parse_fixed_calendar_rule(text: str) -> str:
    """Parse a fixed-calendar rule string into canonical form.

    This extends RecurrenceType.fixed_clock beyond pure durations.

    Accepted examples:
      - Every Tuesday
      - Monday, Wednesday, Friday
      - 10th of every month
      - First Monday
      - The 5th of January

    Canonical form is a subset of RFC 5545 RRULE:
      - FREQ=WEEKLY;BYDAY=TU
      - FREQ=MONTHLY;BYMONTHDAY=10
      - FREQ=MONTHLY;BYSETPOS=1;BYDAY=MO
      - FREQ=YEARLY;BYMONTH=1;BYMONTHDAY=5
    """
    if not text or not str(text).strip():
        raise RecurrenceError("Fixed schedule rule is required")

    raw = str(text).strip()

    # Allow canonical RRULE-like strings directly.
    if _looks_like_fixed_rule_canonical(raw):
        rule = parse_fixed_calendar_rule_canonical(raw)
        return fixed_calendar_rule_to_canonical(rule)

    norm = raw.lower().strip()
    norm = norm.replace(",", " ")
    norm = re.sub(r"\s+", " ", norm)

    tokens = re.findall(r"[a-z]+|\d{1,2}(?:st|nd|rd|th)?", norm)

    month: int | None = None
    for tok in tokens:
        if tok in _MONTH_TOKEN_TO_INT:
            month = _MONTH_TOKEN_TO_INT[tok]
            break

    weekdays: list[int] = sorted({int(_WEEKDAY_TOKEN_TO_INT[t]) for t in tokens if t in _WEEKDAY_TOKEN_TO_INT})

    pos: int | None = None
    for tok in tokens:
        if tok in _ORDINAL_TOKEN_TO_POS:
            pos = int(_ORDINAL_TOKEN_TO_POS[tok])
            break

    day_num: int | None = None
    for tok in tokens:
        m = re.match(r"^(\d{1,2})", tok)
        if not m:
            continue
        n = int(m.group(1))
        if 1 <= n <= 31:
            day_num = n
            break

    # YEARLY: month name + day number
    if month is not None:
        if day_num is None:
            raise RecurrenceError("Yearly rule requires a day of month (example: 'January 5')")
        return f"FREQ=YEARLY;BYMONTH={month};BYMONTHDAY={day_num}"

    # MONTHLY (nth weekday): e.g. 'First Monday'
    if pos is not None and weekdays:
        if len(weekdays) != 1:
            raise RecurrenceError("Monthly ordinal rule must specify exactly one weekday (example: 'First Monday')")
        if pos not in {1, 2, 3, 4, -1}:
            raise RecurrenceError("Monthly ordinal must be First/Second/Third/Fourth/Last")
        wd_code = _INT_TO_WEEKDAY_CODE[int(weekdays[0])]
        return f"FREQ=MONTHLY;BYSETPOS={pos};BYDAY={wd_code}"

    # MONTHLY (day of month): e.g. '10th of every month'
    is_monthly_hint = ("month" in norm) or ("monthly" in norm)
    if day_num is not None and (is_monthly_hint or re.fullmatch(r"\d{1,2}(st|nd|rd|th)", norm) is not None):
        return f"FREQ=MONTHLY;BYMONTHDAY={day_num}"

    # WEEKLY: any weekday tokens
    if weekdays:
        codes = ",".join([_INT_TO_WEEKDAY_CODE[int(w)] for w in weekdays])
        return f"FREQ=WEEKLY;BYDAY={codes}"

    raise RecurrenceError(
        "Invalid fixed schedule. Examples: 'Every Tuesday', 'Mon, Wed, Fri', '10th of every month', 'First Monday', 'January 5'"
    )


def fixed_calendar_rule_to_human(text: str) -> str:
    """Render a canonical fixed-calendar rule as a short human string."""
    rule = parse_fixed_calendar_rule_canonical(text)
    freq = rule.freq.upper()

    if freq == "WEEKLY":
        days = [
            _INT_TO_WEEKDAY_NAME[int(d)]
            for d in sorted(set(rule.byday))
            if int(d) in _INT_TO_WEEKDAY_NAME
        ]
        if len(days) == 1:
            return f"Every {days[0]}"
        return "Every " + ", ".join(days)

    if freq == "MONTHLY":
        if rule.bymonthday is not None:
            d = int(rule.bymonthday)
            return f"{d}{_ordinal_suffix(d)} of every month"

        # nth weekday
        if rule.bysetpos is None or not rule.byday:
            return "Monthly"

        pos = int(rule.bysetpos)
        wd = _INT_TO_WEEKDAY_NAME.get(int(rule.byday[0]), "")
        if pos == -1:
            return f"Last {wd} of every month".strip()
        label = {1: "First", 2: "Second", 3: "Third", 4: "Fourth"}.get(pos, str(pos))
        return f"{label} {wd} of every month".strip()

    if freq == "YEARLY":
        if rule.bymonth is None or rule.bymonthday is None:
            return "Yearly"
        m = _INT_TO_MONTH_NAME.get(int(rule.bymonth), str(rule.bymonth))
        d = int(rule.bymonthday)
        return f"Every {m} {d}{_ordinal_suffix(d)}"

    return str(text)


def _next_weekly_after(anchor_local: datetime, *, byday: tuple[int, ...], tz) -> datetime:
    if not byday:
        raise RecurrenceError("Weekly fixed schedule requires BYDAY")

    days = sorted(set(int(d) for d in byday))
    d0 = anchor_local.date()
    w0 = int(d0.weekday())
    t0 = anchor_local.time().replace(second=0, microsecond=0)

    for wd in days:
        if wd > w0:
            return datetime.combine(d0 + timedelta(days=int(wd - w0)), t0, tzinfo=tz)

    # Wrap to next week
    delta = (7 - w0) + days[0]
    return datetime.combine(d0 + timedelta(days=int(delta)), t0, tzinfo=tz)


def _nth_weekday_of_month(year: int, month: int, weekday: int, pos: int) -> date:
    """Return the date for the nth (1-4) weekday in a month, or last (-1)."""
    weekday = int(weekday)
    pos = int(pos)

    first_wd, days_in_month = calendar.monthrange(year, month)

    if pos == -1:
        last = date(year, month, int(days_in_month))
        offset = (int(last.weekday()) - weekday) % 7
        return date(year, month, int(days_in_month - offset))

    if pos not in {1, 2, 3, 4}:
        raise RecurrenceError("Monthly BYSETPOS must be 1-4 or -1 (last)")

    first_occ = 1 + ((weekday - int(first_wd)) % 7)
    day = first_occ + (7 * (pos - 1))
    if day > int(days_in_month):
        # This shouldn't happen for 1-4, but keep it safe.
        raise RecurrenceError("Monthly ordinal does not occur in this month")
    return date(year, month, int(day))


def _next_monthly_after(anchor_local: datetime, *, rule: FixedCalendarRule, tz) -> datetime:
    t0 = anchor_local.time().replace(second=0, microsecond=0)
    y, m = int(anchor_local.year), int(anchor_local.month)

    def candidate_for(year: int, month: int) -> datetime:
        if rule.bymonthday is not None:
            day = min(int(rule.bymonthday), _last_day_of_month(year, month))
            return datetime.combine(date(year, month, day), t0, tzinfo=tz)

        if rule.bysetpos is None or not rule.byday:
            raise RecurrenceError("MONTHLY fixed schedule requires BYMONTHDAY or (BYSETPOS + BYDAY)")
        if len(rule.byday) != 1:
            raise RecurrenceError("MONTHLY BYSETPOS rules support exactly one weekday")
        d = _nth_weekday_of_month(year, month, int(rule.byday[0]), int(rule.bysetpos))
        return datetime.combine(d, t0, tzinfo=tz)

    cand = candidate_for(y, m)
    if cand <= anchor_local:
        y2, m2 = _add_months(y, m, 1)
        cand = candidate_for(y2, m2)
    return cand


def _next_yearly_after(anchor_local: datetime, *, rule: FixedCalendarRule, tz) -> datetime:
    if rule.bymonth is None or rule.bymonthday is None:
        raise RecurrenceError("YEARLY fixed schedule requires BYMONTH and BYMONTHDAY")

    t0 = anchor_local.time().replace(second=0, microsecond=0)
    month = int(rule.bymonth)
    day = int(rule.bymonthday)

    def candidate_for(year: int) -> datetime:
        d = min(day, _last_day_of_month(year, month))
        return datetime.combine(date(year, month, d), t0, tzinfo=tz)

    y = int(anchor_local.year)
    cand = candidate_for(y)
    if cand <= anchor_local:
        cand = candidate_for(y + 1)
    return cand


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
        # Two modes:
        # 1) Legacy interval mode (recurrence_interval_seconds)
        # 2) Fixed calendar rule mode (stored in recurrence_times)

        if task.recurrence_interval_seconds:
            interval = timedelta(seconds=int(task.recurrence_interval_seconds))

            # Next occurrence is anchored to the due date sequence, not completion time.
            candidate = task.due_date_utc + interval
            ref = completed_at_utc
            while candidate <= ref:
                candidate = candidate + interval
            return candidate

        if task.recurrence_times and _looks_like_fixed_rule_canonical(task.recurrence_times):
            rule = parse_fixed_calendar_rule_canonical(task.recurrence_times)
            tz = get_app_tz()

            # Anchor on the task's scheduled due date (not completion time), then catch up until > completion.
            anchor_local = to_local(task.due_date_utc)

            def next_after(anchor: datetime) -> datetime:
                freq = rule.freq.upper()
                if freq == "WEEKLY":
                    return _next_weekly_after(anchor, byday=rule.byday, tz=tz)
                if freq == "MONTHLY":
                    return _next_monthly_after(anchor, rule=rule, tz=tz)
                if freq == "YEARLY":
                    return _next_yearly_after(anchor, rule=rule, tz=tz)
                raise RecurrenceError(f"Unsupported fixed schedule frequency: {rule.freq}")

            candidate_local = next_after(anchor_local)
            from datetime import timezone as _tz
            candidate_utc = candidate_local.astimezone(_tz.utc).replace(tzinfo=None)

            ref = completed_at_utc
            while candidate_utc <= ref:
                anchor_local = candidate_local
                candidate_local = next_after(anchor_local)
                candidate_utc = candidate_local.astimezone(_tz.utc).replace(tzinfo=None)

            return candidate_utc

        raise RecurrenceError(
            "Fixed-clock scheduling requires an interval (e.g. '8h') or a fixed calendar rule (e.g. 'Every Tuesday')"
        )

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
