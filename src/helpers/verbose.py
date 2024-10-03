# -*- coding: utf-8 -*-
import os


def verbose(*objects, sep=' ', end='\n', file=None, flush=True):
    if os.getenv("VERBOSE_MODE", "false") == "true":
        print(*objects, sep=sep, end=end, file=file, flush=flush)
