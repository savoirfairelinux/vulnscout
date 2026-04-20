# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from datetime import timezone


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
