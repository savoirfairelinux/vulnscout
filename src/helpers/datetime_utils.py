# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from datetime import datetime, timezone


def ensure_utc_iso(dt) -> str | None:
    """Return an ISO 8601 string that always carries the UTC offset.

    SQLite does not preserve timezone info, so datetimes read back from
    the database are naive even though they were stored as UTC.  This
    helper re-attaches ``+00:00`` when the offset is missing so that
    consumers (e.g. JavaScript ``new Date()``) can interpret the value
    correctly.
    """
    if dt is None:
        return None
    if not hasattr(dt, "isoformat"):
        return str(dt)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


_DATETIME_MIN_UTC = datetime.min.replace(tzinfo=timezone.utc)


def normalize_timestamp_for_sort(ts) -> datetime:
    """Normalise a timestamp (str, datetime, or None) to a UTC datetime for sorting.

    Returns ``datetime.min`` (UTC) when *ts* is ``None`` or unparseable so that
    items without a timestamp sort to the end of a descending list.
    """
    if ts is None:
        return _DATETIME_MIN_UTC
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            return _DATETIME_MIN_UTC
    if hasattr(ts, 'tzinfo') and ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts
