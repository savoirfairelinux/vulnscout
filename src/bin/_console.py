# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Presentation for the custom CLI commands, not application logging."""

from __future__ import annotations

import io
import re
import sys
from typing import IO, Any, Literal

import click

from ..helpers.env_vars import get_bool_env
from ..helpers.console import color_enabled

Role = Literal["info", "success", "warning", "error"]
COLORS: dict[Role, str] = {
    "info": "cyan", "success": "green", "warning": "yellow", "error": "red",
}


def style(message: str, role: Role = "info", *, bold: bool = False) -> str:
    return click.style(message, fg=COLORS[role], bold=True if bold else None)


def echo(message: object = None, *, role: Role = "info", err: bool = False, nl: bool = True) -> None:
    text = "" if message is None else str(message)
    enabled = click.get_current_context(silent=True) is not None and color_enabled(err=err)
    click.echo(style(text, role) if enabled else text, err=err, nl=nl, color=enabled)


def print_message(
    *objects: object, role: Role = "info", sep: str = " ", end: str = "\n",
    file: IO[str] | None = None, flush: bool = False,
) -> None:
    stream = sys.stdout if file is None else file
    text = sep.join(str(obj) for obj in objects)
    if (stream is sys.stdout or stream is sys.stderr) and click.get_current_context(silent=True) is not None:
        if color_enabled(err=stream is sys.stderr):
            text = style(text, role)
    print(text, end=end, file=stream, flush=flush)


def verbose(
    *objects: object, sep: str = " ", end: str = "\n",
    file: IO[str] | None = None, flush: bool = True,
) -> None:
    if get_bool_env("VERBOSE_MODE"):
        print_message(*objects, sep=sep, end=end, file=file, flush=flush)


def warn(*objects: object, sep: str = " ", end: str = "\n", flush: bool = True) -> None:
    print_message(*objects, role="warning", sep=sep, end=end, file=sys.stderr, flush=flush)


def help_text(text: str) -> str:
    lines = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\n")
        if body and (not body.startswith(" ") or body.endswith(":")):
            line = style(body, bold=True) + line[len(body):]
        else:
            line = re.sub(r"(?<!\S)--?[\w-]+", lambda match: style(match[0], bold=True), line)
        lines.append(line)
    return "".join(lines)


class _CommandError(click.ClickException):
    def __init__(self, original: click.ClickException) -> None:
        super().__init__(original.message)
        self.original = original
        setattr(self, "exit_code", original.exit_code)

    def show(self, file: IO[str] | None = None) -> None:
        buffer = io.StringIO()
        self.original.show(file=buffer)
        stream = sys.stderr if file is None else file
        enabled = stream is sys.stderr and color_enabled(err=True)
        text = buffer.getvalue()
        click.echo(style(text, "error") if enabled else text, file=stream, nl=False, color=enabled)


class Command(click.Command):
    """Keep custom help and Click-generated failures on the same color policy."""

    def get_help(self, ctx: click.Context) -> str:
        text = super().get_help(ctx)
        return help_text(text) if color_enabled() else text

    def make_context(
        self, info_name: str | None, args: list[str],
        parent: click.Context | None = None, **extra: Any,
    ) -> click.Context:
        extra["color"] = color_enabled()
        try:
            return super().make_context(info_name, args, parent=parent, **extra)
        except click.ClickException as exc:
            raise _CommandError(exc) from exc

    def invoke(self, ctx: click.Context) -> Any:
        # Click's help callback uses ctx.color, whereas messages resolve each
        # destination independently (including container transport hints).
        ctx.color = color_enabled()
        try:
            return super().invoke(ctx)
        except click.ClickException as exc:
            raise _CommandError(exc) from exc
