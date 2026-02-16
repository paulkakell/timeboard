from __future__ import annotations


def humanize_timedelta(seconds: float) -> str:
    sec = int(abs(seconds))
    days, rem = divmod(sec, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)

    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes or not parts:
        parts.append(f"{minutes}m")

    s = " ".join(parts)
    if seconds < 0:
        return f"Past due by {s}"
    return s


def time_left_class(seconds: float) -> str:
    if seconds < 0:
        return "tl-past"
    if seconds <= 8 * 3600:
        return "tl-0-8"
    if seconds <= 24 * 3600:
        return "tl-8-24"
    return "tl-24p"


def seconds_to_duration_str(seconds: int) -> str:
    """Convert seconds to a compact duration string like '1w 2d 3h 15m'."""
    sec = int(seconds)
    if sec <= 0:
        return "0s"

    parts: list[str] = []

    weeks, sec = divmod(sec, 7 * 24 * 3600)
    days, sec = divmod(sec, 24 * 3600)
    hours, sec = divmod(sec, 3600)
    minutes, sec = divmod(sec, 60)

    if weeks:
        parts.append(f"{weeks}w")
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if sec and not parts:
        parts.append(f"{sec}s")

    return " ".join(parts) if parts else "0s"
