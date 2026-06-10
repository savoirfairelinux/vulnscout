# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from typing import IO

from .env_vars import get_bool_env


def verbose(*objects: object, sep: str = ' ', end: str = '\n', file: IO[str] | None = None, flush: bool = True) -> None:
    if get_bool_env("VERBOSE_MODE"):
        print(*objects, sep=sep, end=end, file=file, flush=flush)
