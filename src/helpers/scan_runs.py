# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tool-scan lifecycle shared by synchronous CLI scans and queued jobs."""

import uuid
from contextlib import contextmanager
from typing import Callable, Iterator

from ..extensions import db
from ..models.scan import Scan


@contextmanager
def tool_scan(
    variant_id: uuid.UUID, source: str, run_id: str | None = None, *,
    failure_cleanups: list[Callable[[], None]] | None = None,
) -> Iterator[Scan]:
    """Persist a scan step, removing it if its producer fails or is interrupted.

    On failure, rollback removes staged data, producer callbacks clean up their
    exclusively new committed records, and deleting the scan removes its
    observations. Pre-existing/shared findings and assessments are retained.
    """
    scan = Scan.create(
        description="empty description",
        variant_id=variant_id,
        scan_type="tool",
        scan_source=source,
        run_id=run_id,
    )
    scan_id = scan.id
    try:
        yield scan
        db.session.commit()
    except BaseException:
        db.session.rollback()
        for cleanup in failure_cleanups or ():
            cleanup()
        persisted_scan = db.session.get(Scan, scan_id)
        if persisted_scan is not None:
            db.session.delete(persisted_scan)
            db.session.commit()
        raise
