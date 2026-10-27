# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Terminal-aware defaults without overriding deployment logging configuration."""

import logging
import sys
from typing import TextIO, cast

import click
from flask import has_request_context, request
from flask.logging import has_level_handler, wsgi_errors_stream

from .console import color_enabled


class ConsoleFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
        self.request_formatter = logging.Formatter("%(message)s")

    def format(self, record: logging.LogRecord) -> str:
        text = (
            self.request_formatter.format(record)
            if record.name == "werkzeug" else super().format(record)
        )
        stream = request.environ["wsgi.errors"] if has_request_context() else sys.stderr
        if not color_enabled(stream=stream):
            return click.unstyle(text)
        if record.levelno >= logging.ERROR:
            return click.style(text, fg="red", bold=record.levelno >= logging.CRITICAL)
        if record.levelno >= logging.WARNING:
            return click.style(text, fg="yellow")
        if record.levelno >= logging.INFO:
            return click.style(text, fg="cyan")
        return click.style(text, fg="bright_black", dim=True)


def configure_console_logging() -> None:
    for name in ("src", "werkzeug"):
        logger = logging.getLogger(name)
        if not has_level_handler(logger):
            handler = logging.StreamHandler(cast(TextIO, wsgi_errors_stream))
            handler.setFormatter(ConsoleFormatter())
            logger.addHandler(handler)
