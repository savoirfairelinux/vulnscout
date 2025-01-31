# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os


def verbose(*objects, sep=' ', end='\n', file=None, flush=True):
    if os.getenv("VERBOSE_MODE", "false") == "true":
        print(*objects, sep=sep, end=end, file=file, flush=flush)
