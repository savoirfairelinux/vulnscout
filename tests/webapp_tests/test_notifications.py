# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for src/routes/notifications.py — covering all branches."""

import pytest
import json
import os
from src.bin.webapp import create_app


@pytest.fixture()
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        with application.app_context():
            from src.extensions import db as _db
            _db.create_all()
            yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


class TestNotificationsRoute:
    def test_no_file_returns_empty_list(self, client, monkeypatch):
        """When the notification file does not exist, return []."""
        monkeypatch.setattr("src.routes.notifications.NOTIFICATION_FILE", "/nonexistent.json")
        resp = client.get("/api/notifications")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_file_with_list(self, client, tmp_path, monkeypatch):
        """When the file contains a JSON list, return it as-is."""
        notif_file = tmp_path / "notif.json"
        notif_file.write_text(json.dumps([{"level": "warning", "title": "test"}]))
        monkeypatch.setattr("src.routes.notifications.NOTIFICATION_FILE", str(notif_file))
        resp = client.get("/api/notifications")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["level"] == "warning"

    def test_file_with_dict_normalised_to_list(self, client, tmp_path, monkeypatch):
        """When the file contains a single dict, wrap it in a list."""
        notif_file = tmp_path / "notif.json"
        notif_file.write_text(json.dumps({"level": "info", "title": "single"}))
        monkeypatch.setattr("src.routes.notifications.NOTIFICATION_FILE", str(notif_file))
        resp = client.get("/api/notifications")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["title"] == "single"

    def test_invalid_json_returns_empty_list(self, client, tmp_path, monkeypatch):
        """When the file contains invalid JSON, return []."""
        notif_file = tmp_path / "notif.json"
        notif_file.write_text("not valid json{{{")
        monkeypatch.setattr("src.routes.notifications.NOTIFICATION_FILE", str(notif_file))
        resp = client.get("/api/notifications")
        assert resp.status_code == 200
        assert resp.get_json() == []
