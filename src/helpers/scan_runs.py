# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tool-scan lifecycle shared by synchronous CLI scans and queued jobs."""

import uuid
from contextlib import contextmanager
from typing import Iterator

from ..extensions import db
from ..models.scan import Scan


@contextmanager
def tool_scan(variant_id: uuid.UUID, source: str, run_id: str | None = None) -> Iterator[Scan]:
    """Persist a scan step, removing it if its producer fails or is interrupted.

    Producers can commit findings in chunks. Removing a failed step also removes
    its observations, without deleting shared findings or assessments.
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
    except BaseException:
        db.session.rollback()
        persisted_scan = db.session.get(Scan, scan_id)
        if persisted_scan is not None:
            db.session.delete(persisted_scan)
            db.session.commit()
        raise
