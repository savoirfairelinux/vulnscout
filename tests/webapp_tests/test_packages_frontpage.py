# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Coverage tests for src/controllers/packages.py and src/routes/frontpage.py.

Targets packages.py lines: 52, 61, 170, 218.
Targets frontpage.py lines: 13, 20.
"""

import os
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Shared DB app fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        from src.bin.webapp import create_app
        from src.extensions import db as _db
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


# ===========================================================================
# PackagesController._preload_cache — exception branches (lines 52, 61)
# ===========================================================================

class TestPackagesControllerPreloadExceptions:
    def test_package_fetch_exception_is_caught(self, app):
        """Line 52: when Package.get_all() raises, the exception is caught
        and _cache stays empty (no re-raise)."""
        from src.controllers.packages import PackagesController
        from src.models.package import Package

        with patch.object(Package, "get_all", side_effect=RuntimeError("DB gone")):
            ctrl = PackagesController()

        assert ctrl._cache == {}

    def test_finding_fetch_exception_is_caught(self, app):
        """Line 61: when Finding.get_all() raises, the exception is caught."""
        from src.controllers.packages import PackagesController
        from src.models.finding import Finding

        with patch.object(Finding, "get_all", side_effect=RuntimeError("FK broken")):
            ctrl = PackagesController()

        # Controller constructed without error
        assert ctrl._finding_cache == {}


# ===========================================================================
# PackagesController.get() — scoped: package not in allowed set (line 170)
# ===========================================================================

class TestPackagesControllerScopedGet:
    def test_get_returns_none_when_package_out_of_scope(self, app):
        """Line 170: when a package exists in DB but its id is not in
        scope.package_ids, get() returns None."""
        import uuid
        from src.controllers.packages import PackagesController
        from src.helpers.export_scope import ExportScope
        from src.models.package import Package

        pkg = Package.create("scoped-out-pkg", "0.0.1")
        from src.extensions import db as _db
        _db.session.commit()

        # Scope with an empty package_ids set — nothing is in scope
        scope = ExportScope(package_ids=set(), variant_ids=set())
        ctrl = PackagesController(scope=scope)
        ctrl._cache.clear()  # ensure DB fallback path is used

        result = ctrl.get(pkg.string_id)
        assert result is None


# ===========================================================================
# PackagesController.__contains__ — scoped out (line 218)
# ===========================================================================

class TestPackagesControllerScopedContains:
    def test_contains_returns_false_when_package_out_of_scope(self, app):
        """Line 218: __contains__ returns False when the package exists in DB
        but its UUID is not in the active export scope."""
        import uuid
        from src.controllers.packages import PackagesController
        from src.helpers.export_scope import ExportScope
        from src.models.package import Package

        pkg = Package.create("scoped-out-pkg2", "1.2.3")
        from src.extensions import db as _db
        _db.session.commit()

        scope = ExportScope(package_ids=set(), variant_ids=set())
        ctrl = PackagesController(scope=scope)
        ctrl._cache.clear()

        assert pkg.string_id not in ctrl


# ===========================================================================
# routes/frontpage.py — lines 13 and 20 (static_folder is None → 500)
# ===========================================================================

class TestFrontpageStaticFolderNone:
    def test_index_returns_500_when_static_folder_none(self, app, client):
        """Line 13: GET / returns 500 when static_folder is None."""
        original = app.static_folder
        app.static_folder = None
        try:
            resp = client.get("/")
            assert resp.status_code == 500
            data = resp.get_json()
            assert "error" in data
        finally:
            app.static_folder = original

    def test_static_file_returns_500_when_static_folder_none(self, app, client):
        """Line 20: GET /<path> returns 500 when static_folder is None."""
        original = app.static_folder
        app.static_folder = None
        try:
            resp = client.get("/some/deep/path.js")
            assert resp.status_code == 500
            data = resp.get_json()
            assert "error" in data
        finally:
            app.static_folder = original
