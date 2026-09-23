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


# ===========================================================================
# routes/frontpage.py — SPA client-route fallback
#
# The frontend router (react-router) owns paths like /sbom and /vulnerabilities
# client-side. A hard refresh or direct link on one of those paths hits Flask
# first, so the catch-all route must serve index.html for any path that isn't
# an actual file on disk, letting the SPA's router take over from there.
# ===========================================================================

class TestFrontpageSpaFallback:
    @pytest.fixture()
    def static_dir(self, app, tmp_path):
        """Point the app at a throwaway static folder containing just an
        index.html and one real asset, so fallback vs. direct-serve behavior
        can be told apart without depending on a built frontend bundle."""
        folder = tmp_path / "static"
        folder.mkdir()
        (folder / "index.html").write_bytes(b"<!doctype html><html><body>index</body></html>")
        (folder / "vulnscout_logo.png").write_bytes(b"fake-logo-bytes")
        original = app.static_folder
        app.static_folder = str(folder)
        try:
            yield folder
        finally:
            app.static_folder = original

    def test_unknown_client_route_serves_index_html(self, app, client, static_dir):
        """GET /sbom (a client-side route, not a real file) serves index.html
        instead of 404ing, so a hard refresh on a deep link still works."""
        resp = client.get("/sbom")
        assert resp.status_code == 200
        assert resp.data == (b"<!doctype html><html><body>index</body></html>")

    def test_nested_unknown_client_route_serves_index_html(self, app, client, static_dir):
        """A deeper unknown path (e.g. a future nested route) also falls
        back to index.html rather than 404ing."""
        resp = client.get("/settings/projects")
        assert resp.status_code == 200
        assert resp.data == (b"<!doctype html><html><body>index</body></html>")

    def test_existing_static_file_is_served_directly(self, app, client, static_dir):
        """A path that matches a real file in the static folder is served
        as-is, not overridden by the SPA fallback."""
        resp = client.get("/vulnscout_logo.png")
        assert resp.status_code == 200
        assert resp.data == b"fake-logo-bytes"
