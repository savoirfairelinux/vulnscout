# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import logging


def setup_logging():
    """Setup logging configuration for NVD operations."""
    log_file = os.getenv("NVD_LOGFILE", "/cache/vulnscout/nvd.log")
    verbose_logging = os.getenv("NVD_VERBOSE_LOGGING", "false").lower() == "true"

    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        print("[Patch-Finder] Warning: Log directory does not exist, falling back to console logging.")
        handlers = [logging.StreamHandler()]
    else:
        handlers = [logging.FileHandler(log_file)]

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers
    )

    return verbose_logging


def log_and_print(message, verbose_logging=True, force_print=False):
    """Log a message and optionally print it to console."""
    logging.info(message)
    if verbose_logging or force_print:
        print(f"[Patch-Finder] {message}", flush=True)
