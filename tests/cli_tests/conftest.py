# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Fixtures shared by the CLI tests."""

import pytest

from src.bin import _ai_queue_client, _ai_runner


def _refused(method, path, body, timeout):
    raise _ai_queue_client.ServerUnavailable("Connection refused")


@pytest.fixture(autouse=True)
def no_web_server(monkeypatch):
    """The AI commands find no `vulnscout serve` and run in-process, whatever listens on the default port."""
    monkeypatch.setattr(_ai_runner, "queue_client", lambda: _ai_queue_client.QueueClient(_refused))
