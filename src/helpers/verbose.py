# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from .env_vars import get_bool_env


def verbose(*objects, sep=' ', end='\n', file=None, flush=True):
    if get_bool_env("VERBOSE_MODE"):
        print(*objects, sep=sep, end=end, file=file, flush=flush)
