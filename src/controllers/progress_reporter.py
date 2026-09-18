# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Progress sink for enrichment code that may or may not run as a queued operation.

Boot enrichment and SBOM-upload enrichment pass a
:class:`~src.controllers.job_context.JobContext`, so their progress reaches the
SSE stream. The CLI passes nothing and the calls become no-ops.
"""

from __future__ import annotations

from typing import Protocol


class ProgressReporter(Protocol):
    def report(self, current: int, total: int, message: str) -> None:
        ...

    def log(self, line: str) -> None:
        ...

    def is_cancelled(self) -> bool:
        ...


class NullReporter:
    """Discards everything; used when enrichment runs outside the queue."""

    def report(self, current: int, total: int, message: str) -> None:
        return None

    def log(self, line: str) -> None:
        return None

    def is_cancelled(self) -> bool:
        return False


NULL_REPORTER: ProgressReporter = NullReporter()
