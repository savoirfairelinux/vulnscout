# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Console logging preserves records and non-console consumers."""

import io
import logging
import os
import subprocess
import sys

import click
from flask import Flask
import pytest

from src.helpers.console import color_enabled
from src.helpers.logging import ConsoleFormatter, configure_console_logging


@pytest.fixture(autouse=True)
def color_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("_VULNSCOUT_COLOR_STDERR", "1")


def record(level=logging.INFO, name="src.controllers.example", message="Message %s", args=("value",)):
    return logging.LogRecord(name, level, __file__, 1, message, args, None)


@pytest.mark.parametrize(("level", "style"), [
    (logging.DEBUG, {"fg": "bright_black", "dim": True}),
    (logging.INFO, {"fg": "cyan"}),
    (logging.WARNING, {"fg": "yellow"}),
    (logging.ERROR, {"fg": "red", "bold": False}),
    (logging.CRITICAL, {"fg": "red", "bold": True}),
])
def test_log_palette_and_plain_equivalence(monkeypatch, level, style):
    formatter = ConsoleFormatter()
    entry = record(level)
    colored = formatter.format(entry)
    monkeypatch.setenv("NO_COLOR", "1")
    plain = formatter.format(entry)
    assert colored == click.style(plain, **style)
    assert "Message value" in plain
    assert "\x1b[" not in plain
    assert entry.msg == "Message %s"
    assert entry.args == ("value",)
    assert entry.levelname == logging.getLevelName(level)


@pytest.mark.parametrize("env", [
    {"NO_COLOR": "1"}, {"TERM": "dumb"}, {"_VULNSCOUT_COLOR_STDERR": "0"},
])
def test_opt_out_strips_werkzeug_status_colors(monkeypatch, env):
    message = '"\x1b[33mGET /missing HTTP/1.1\x1b[0m" 404 -'
    entry = record(name="werkzeug", message=message, args=())
    colored = ConsoleFormatter().format(entry)
    assert message in colored
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert ConsoleFormatter().format(entry) == '"GET /missing HTTP/1.1" 404 -'
    assert entry.msg == message


def test_redirected_stderr_is_plain(monkeypatch):
    monkeypatch.delenv("_VULNSCOUT_COLOR_STDERR")
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    assert "\x1b[" not in ConsoleFormatter().format(record())


def test_wsgi_error_file_ignores_terminal_hint():
    app = Flask(__name__)
    stream = io.StringIO()
    with app.test_request_context(environ_overrides={"wsgi.errors": stream}):
        assert "\x1b[" not in ConsoleFormatter().format(record())
        assert not color_enabled(stream=stream)


def test_traceback_and_other_formatters_are_unchanged(monkeypatch):
    try:
        raise ValueError("Example failure")
    except ValueError:
        entry = record(logging.ERROR)
        entry.exc_info = sys.exc_info()
    formatter = ConsoleFormatter()
    colored = formatter.format(entry)
    assert "Traceback (most recent call last):" in colored
    assert "ValueError: Example failure" in colored
    assert "\x1b[" not in logging.Formatter().format(entry)
    monkeypatch.setenv("NO_COLOR", "1")
    assert click.unstyle(colored) == formatter.format(entry)


@pytest.fixture
def isolated_loggers():
    loggers = [logging.getLogger(name) for name in ("", "src", "werkzeug", "src.bin.webapp")]
    original = [(logger, logger.handlers[:], logger.level, logger.propagate) for logger in loggers]
    for logger in loggers:
        logger.handlers = []
        logger.setLevel(logging.WARNING if logger is logging.getLogger() else logging.NOTSET)
        logger.propagate = True
    try:
        yield loggers
    finally:
        for logger, handlers, level, propagate in original:
            logger.handlers = handlers
            logger.setLevel(level)
            logger.propagate = propagate


def test_setup_is_idempotent_and_covers_flask_and_module_logs(isolated_loggers, monkeypatch):
    logging.getLogger().handlers = []
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)
    configure_console_logging()
    configure_console_logging()
    app = Flask("src.bin.webapp")
    app.logger.warning("App warning")
    logging.getLogger("src.controllers.example").error("Controller error")
    werkzeug = logging.getLogger("werkzeug")
    werkzeug.setLevel(logging.INFO)
    werkzeug.info('"GET / HTTP/1.1" 200 -')
    assert not app.logger.handlers
    assert len(logging.getLogger("src").handlers) == 1
    assert len(werkzeug.handlers) == 1
    assert stream.getvalue().count("App warning") == 1
    assert stream.getvalue().count("Controller error") == 1
    assert stream.getvalue().count('"GET / HTTP/1.1" 200 -') == 1
    assert "\x1b[33m" in stream.getvalue()
    assert "\x1b[31m" in stream.getvalue()
    assert "\x1b[36m" in stream.getvalue()
    assert logging.getLogger("src").level == logging.NOTSET


@pytest.mark.parametrize("name", ["", "src", "werkzeug"])
def test_existing_handlers_are_not_reconfigured(isolated_loggers, name):
    logging.getLogger().handlers = []
    logger = logging.getLogger(name)
    handler = logging.StreamHandler(io.StringIO())
    formatter = logging.Formatter("custom: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    configure_console_logging()
    assert logger.handlers == [handler]
    assert handler.formatter is formatter
    if name == "":
        assert not logging.getLogger("src").handlers
        assert not logging.getLogger("werkzeug").handlers


@pytest.mark.parametrize("hint", ["0", "1"])
def test_real_werkzeug_server_requests_and_wsgi_errors(hint):
    code = """
import io
import logging
import threading
import urllib.error
import urllib.request
from flask import Flask
from werkzeug.serving import make_server
from src.helpers.logging import configure_console_logging

configure_console_logging()
app = Flask("src.bin.webapp")
@app.get("/")
def index():
    app.logger.warning("Request warning")
    return "OK"

server = make_server("127.0.0.1", 0, app)
thread = threading.Thread(target=server.serve_forever)
thread.start()
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/") as response:
        assert response.read() == b"OK"
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/missing")
    except urllib.error.HTTPError as error:
        assert error.code == 404
    stream = io.StringIO()
    with app.test_request_context(environ_overrides={"wsgi.errors": stream}):
        app.logger.error("WSGI error")
    assert "WSGI error" in stream.getvalue()
    assert "\\x1b[" not in stream.getvalue()
finally:
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()
"""
    env = dict(os.environ, _VULNSCOUT_COLOR_STDERR=hint)
    result = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr.count("Request warning") == 1
    assert result.stderr.count('"GET / HTTP/1.1" 200 -') == 1
    assert click.unstyle(result.stderr).count('"GET /missing HTTP/1.1" 404 -') == 1
    assert ("\x1b[" in result.stderr) == (hint == "1")
