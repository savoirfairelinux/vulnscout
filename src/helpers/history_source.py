# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Attribution of vulnerability-data writes for the history log.

The history listener runs at flush time, far from the code that set the
values, so writers declare where their data comes from by wrapping their work
in :func:`history_source`. It works both as a context manager and as a
decorator, and nests: the innermost source wins.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

# Writes made outside any tagged block come from SBOM/scan document ingestion.
DEFAULT_SOURCE = "sbom"
# Lets a job that shells out to ``flask`` commands attribute their writes.
SOURCE_ENV_VAR = "VULNSCOUT_HISTORY_SOURCE"
# Operation IDs of refresh runs; their queue ID identifies the run.
REFRESH_OPERATION_PREFIX = "refresh:"

_current_source: ContextVar[str] = ContextVar(
    "vulnerability_history_source",
    default=os.environ.get(SOURCE_ENV_VAR) or DEFAULT_SOURCE,
)
_current_operation: ContextVar[tuple[str | None, str | None]] = ContextVar(
    "vulnerability_history_operation", default=(None, None),
)


def current_history_source() -> str:
    """Return the source that history rows flushed right now are attributed to."""
    return _current_source.get()


def current_history_operation() -> tuple[str | None, str | None]:
    return _current_operation.get()


@contextmanager
def history_operation(queue_id: str | None, operation_id: str | None) -> Iterator[None]:
    token = _current_operation.set((queue_id, operation_id))
    try:
        yield
    finally:
        _current_operation.reset(token)


@contextmanager
def history_source(source: str | None) -> Iterator[None]:
    """Attribute every vulnerability-data write flushed in this block to *source*.

    ``None`` keeps the enclosing source, so callers can pass an optional value
    straight through.
    """
    if not source:
        yield
        return
    token = _current_source.set(source)
    try:
        yield
    finally:
        _current_source.reset(token)


@contextmanager
def refresh_history(source: str, run_id: str | None = None) -> Iterator[None]:
    """Attribute writes to one refresh run of *source*.

    The run is *run_id*, else the enclosing queue, else a new one per entry.
    """
    run = run_id or _current_operation.get()[0]
    if run is None:
        from ..controllers.operation_registry import new_queue_id  # avoids an import cycle
        run = new_queue_id()
    with history_source(source), history_operation(run, f"{REFRESH_OPERATION_PREFIX}{source}"):
        yield
