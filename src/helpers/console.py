# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Shared terminal color policy for CLI output and server logs."""

import os
import sys
from typing import IO


def color_enabled(*, err: bool = False, stream: IO[str] | None = None) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if stream is None:
        stream = sys.stderr if err else sys.stdout
    if stream is sys.stdout or stream is sys.stderr:
        hint = os.environ.get(
            "_VULNSCOUT_COLOR_STDERR" if stream is sys.stderr else "_VULNSCOUT_COLOR_STDOUT"
        )
        if hint in ("0", "1"):
            return hint == "1"
    return stream.isatty()
