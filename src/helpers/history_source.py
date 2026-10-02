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
