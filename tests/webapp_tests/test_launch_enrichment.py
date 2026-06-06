# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the revised _launch_enrichment in webapp.py."""

import os
import pytest
from unittest.mock import patch, MagicMock
from src.bin.webapp import create_app
from tests.webapp_tests import write_demo_files, setup_demo_db


@pytest.fixture()
def init_files(tmp_path):
    files = {
        "status": tmp_path / "status.txt",
        "packages": tmp_path / "packages-merged.json",
        "vulnerabilities": tmp_path / "vulnerabilities-merged.json",
        "assessments": tmp_path / "assessments-merged.json",
        "openvex": tmp_path / "openvex.json",
        "time_estimates": tmp_path / "time_estimates.json",
    }
    write_demo_files(files)
    return files


@pytest.fixture()
def app(init_files):
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": init_files["openvex"],
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture(autouse=True)
def reset_trackers():
    from src.controllers.nvd_progress import NVDProgressTracker
    from src.controllers.epss_progress import EPSSProgressTracker
    NVDProgressTracker.complete()
    EPSSProgressTracker.complete()
    yield
    NVDProgressTracker.complete()
    EPSSProgressTracker.complete()


class TestLaunchEnrichment:

    def test_epss_thread_spawned_when_enabled_and_cves_exist(self, app, monkeypatch):
        """A thread is spawned for EPSS when INITIAL_REFRESH_EPSS=true and CVEs are in the DB."""
        monkeypatch.setenv("INITIAL_REFRESH_EPSS", "true")
        monkeypatch.setenv("INITIAL_REFRESH_NVD", "false")

        from src.bin.webapp import _launch_enrichment
        with patch("src.bin.webapp.threading.Thread") as MockThread, \
             patch("src.bin.webapp.EPSSProgressTracker") as MockEPSS, \
             patch("src.bin.webapp.NVDProgressTracker"):
            MockThread.return_value = MagicMock()
            MockEPSS.start_if_idle.return_value = True

            with app.app_context():
                _launch_enrichment(app)

        assert MockThread.return_value.start.call_count == 1

    def test_nvd_thread_spawned_when_enabled_and_cves_exist(self, app, monkeypatch):
        """A thread is spawned for NVD when INITIAL_REFRESH_NVD=true and CVEs are in the DB."""
        monkeypatch.setenv("INITIAL_REFRESH_EPSS", "false")
        monkeypatch.setenv("INITIAL_REFRESH_NVD", "true")

        from src.bin.webapp import _launch_enrichment
        with patch("src.bin.webapp.threading.Thread") as MockThread, \
             patch("src.bin.webapp.NVDProgressTracker") as MockNVD, \
             patch("src.bin.webapp.EPSSProgressTracker"):
            MockThread.return_value = MagicMock()
            MockNVD.start_if_idle.return_value = True

            with app.app_context():
                _launch_enrichment(app)

        assert MockThread.return_value.start.call_count == 1

    def test_no_thread_spawned_when_both_disabled(self, app, monkeypatch):
        """No threads are spawned when both flags are false."""
        monkeypatch.setenv("INITIAL_REFRESH_EPSS", "false")
        monkeypatch.setenv("INITIAL_REFRESH_NVD", "false")

        from src.bin.webapp import _launch_enrichment
        with patch("src.bin.webapp.threading.Thread") as MockThread:
            with app.app_context():
                _launch_enrichment(app)

        MockThread.assert_not_called()

    def test_no_thread_spawned_when_epss_already_running(self, app, monkeypatch):
        """No EPSS thread is spawned when EPSSProgressTracker is already in progress."""
        monkeypatch.setenv("INITIAL_REFRESH_EPSS", "true")
        monkeypatch.setenv("INITIAL_REFRESH_NVD", "false")

        from src.bin.webapp import _launch_enrichment
        with patch("src.bin.webapp.threading.Thread") as MockThread, \
             patch("src.bin.webapp.EPSSProgressTracker") as MockEPSS:
            MockEPSS.start_if_idle.return_value = False

            with app.app_context():
                _launch_enrichment(app)

        MockThread.assert_not_called()

    def test_no_thread_spawned_when_no_cves_in_db(self, app, monkeypatch):
        """No threads are spawned when the DB has no CVE-format vulnerabilities."""
        monkeypatch.setenv("INITIAL_REFRESH_EPSS", "true")
        monkeypatch.setenv("INITIAL_REFRESH_NVD", "false")

        from src.bin.webapp import _launch_enrichment
        from src.extensions import db

        with patch("src.bin.webapp.threading.Thread") as MockThread, \
             patch("src.bin.webapp.EPSSProgressTracker"):
            with app.app_context():
                with patch("src.bin.webapp.db") as mock_db:
                    mock_db.select = db.select
                    mock_db.session.execute.return_value.scalars.return_value.all.return_value = []
                    _launch_enrichment(app)

        MockThread.assert_not_called()

    def test_no_thread_spawned_when_nvd_already_running(self, app, monkeypatch):
        """No NVD thread is spawned when NVDProgressTracker is already in progress."""
        monkeypatch.setenv("INITIAL_REFRESH_EPSS", "false")
        monkeypatch.setenv("INITIAL_REFRESH_NVD", "true")

        from src.bin.webapp import _launch_enrichment
        with patch("src.bin.webapp.threading.Thread") as MockThread, \
             patch("src.bin.webapp.NVDProgressTracker") as MockNVD, \
             patch("src.bin.webapp.EPSSProgressTracker"):
            MockNVD.start_if_idle.return_value = False

            with app.app_context():
                _launch_enrichment(app)

        MockThread.assert_not_called()
