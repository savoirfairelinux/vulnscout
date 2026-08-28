# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import sys
from typing import IO

from .env_vars import get_bool_env


def verbose(*objects: object, sep: str = ' ', end: str = '\n', file: IO[str] | None = None, flush: bool = True) -> None:
    if get_bool_env("VERBOSE_MODE"):
        print(*objects, sep=sep, end=end, file=file, flush=flush)


def warn(*objects: object, sep: str = ' ', end: str = '\n', flush: bool = True) -> None:
    """Report a problem on stderr regardless of ``VERBOSE_MODE``.

    ``verbose`` is silent unless the user opted in, which is the wrong channel
    for something that silently discards data. Use this whenever a failure
    would otherwise leave no trace.
    """
    print(*objects, sep=sep, end=end, file=sys.stderr, flush=flush)
