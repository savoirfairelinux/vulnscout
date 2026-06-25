# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Coverage tests for src/routes/config.py.

Targets: lines 26, 56-58, 119, 127, 141-148, 193, 204-205.
"""

import os
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Fixtures
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


# ---------------------------------------------------------------------------
# _mask_nvd_api_key — line 26 (key <= 8 chars → all stars)
# ---------------------------------------------------------------------------

class TestMaskNvdApiKey:
    def test_short_key_fully_masked(self, client, monkeypatch):
        """Line 26: a key of 8 or fewer chars is replaced with '*' * len(key)."""
        monkeypatch.setenv("NVD_API_KEY", "short12")   # 7 chars → all stars
        resp = client.get("/api/config/nvd-api-key")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["masked_key"] == "*" * 7
        assert "*" in data["masked_key"]


# ---------------------------------------------------------------------------
# _write_config_key — lines 56-58 (exception → return False)
# ---------------------------------------------------------------------------

class TestWriteConfigKeyException:
    def test_patch_config_write_failure_returns_500(self, client, tmp_path):
        """Lines 56-58: when _write_config_key raises internally, returns 500."""
        import builtins

        original_open = builtins.open

        def _fail_open(path, *args, **kwargs):
            if "config.env" in str(path):
                raise OSError("disk full")
            return original_open(path, *args, **kwargs)

        with patch("src.routes.config._config_file_path",
                   return_value=str(tmp_path / "config.env")):
            with patch("builtins.open", side_effect=_fail_open):
                resp = client.patch("/api/config",
                                    json={"author_name": "test-author"})
        # The write failure should propagate to a 500 response
        assert resp.status_code == 500
        data = resp.get_json()
        assert "error" in data


# ---------------------------------------------------------------------------
# PATCH /api/config — line 119 (None value is treated as empty string)
# ---------------------------------------------------------------------------

class TestPatchConfigNullValue:
    def test_patch_config_null_value_clears_key(self, client, tmp_path):
        """Line 119: when a config value is None it is normalized to '' (clear)."""
        with patch("src.routes.config._write_config_key", return_value=True):
            resp = client.patch("/api/config", json={"author_name": None})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# PATCH /api/config — line 127 (invalid email format)
# ---------------------------------------------------------------------------

class TestPatchConfigInvalidEmail:
    def test_invalid_email_returns_400(self, client):
        """Line 127: a malformed contact_email is rejected with 400."""
        resp = client.patch("/api/config",
                            json={"contact_email": "not-an-email"})
        assert resp.status_code == 400
        data = resp.get_json()
        assert "email" in data["error"].lower()


# ---------------------------------------------------------------------------
# PATCH /api/config — lines 141-148 (rollback when second write fails)
# ---------------------------------------------------------------------------

class TestPatchConfigRollback:
    def test_second_write_failure_rolls_back_first(self, client, tmp_path):
        """Lines 141-148: if a write fails mid-loop, already-written keys are
        rolled back and a 500 is returned."""
        call_count = {"n": 0}

        def _fail_second(*args, **kwargs):
            call_count["n"] += 1
            return call_count["n"] < 2  # first call succeeds, second fails

        with patch("src.routes.config._write_config_key",
                   side_effect=_fail_second):
            resp = client.patch("/api/config", json={
                "author_name": "Alice",
                "product_name": "TestProd",
            })
        assert resp.status_code == 500
        data = resp.get_json()
        assert "error" in data


# ---------------------------------------------------------------------------
# PUT /api/config/nvd-api-key — line 193 (network error → 503)
# ---------------------------------------------------------------------------

class TestSetNvdApiKeyNetworkError:
    def test_network_error_returns_503(self, client):
        """Line 193: when the NVD probe call raises, a 503 is returned."""
        from src.controllers.nvd_db import NVD_DB
        with patch.object(NVD_DB, "api_probe_cve",
                          side_effect=ConnectionError("no network")):
            resp = client.put("/api/config/nvd-api-key",
                              json={"api_key": "test-key-1234"})
        assert resp.status_code == 503
        data = resp.get_json()
        assert "error" in data


# ---------------------------------------------------------------------------
# PUT /api/config/nvd-api-key — lines 204-205 (non-integer ratelimit header)
# ---------------------------------------------------------------------------

class TestSetNvdApiKeyRatelimitHeaderNotInt:
    def test_non_integer_ratelimit_header_is_ignored(self, client, tmp_path):
        """Lines 204-205: when x-ratelimit-limit is not an integer, the
        ValueError is caught and the key is saved anyway."""
        from src.controllers.nvd_db import NVD_DB
        with patch.object(NVD_DB, "api_probe_cve",
                          return_value=(200, {}, {"x-ratelimit-limit": "not-an-int"})):
            with patch("src.routes.config._write_config_key", return_value=True):
                resp = client.put("/api/config/nvd-api-key",
                                  json={"api_key": "valid-key-5678"})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# PATCH /api/config — line 147 (rollback restores a non-None prev_val)
# ---------------------------------------------------------------------------

class TestPatchConfigRollbackNonNullEnvRestore:
    def test_second_write_failure_restores_non_null_prev_val(self, client):
        """Line 147: when the second write fails and snapshot has a non-None
        value for the already-written key, it is restored via os.environ.
        allowed_keys processes 'product_name' first, so PRODUCT_NAME must be
        pre-set so snapshot has a non-None value to trigger the else branch."""
        import os
        call_count = {"n": 0}

        def _fail_second(*args, **kwargs):
            call_count["n"] += 1
            return call_count["n"] < 2  # first succeeds, second fails

        old_product = os.environ.get("PRODUCT_NAME")
        old_author = os.environ.get("AUTHOR_NAME")
        os.environ["PRODUCT_NAME"] = "OriginalProd"
        os.environ["AUTHOR_NAME"] = "OriginalAuthor"
        try:
            with patch("src.routes.config._write_config_key",
                       side_effect=_fail_second):
                resp = client.patch("/api/config", json={
                    "product_name": "NewProd",
                    "author_name": "NewAuthor",
                })
        finally:
            if old_product is None:
                os.environ.pop("PRODUCT_NAME", None)
            else:
                os.environ["PRODUCT_NAME"] = old_product
            if old_author is None:
                os.environ.pop("AUTHOR_NAME", None)
            else:
                os.environ["AUTHOR_NAME"] = old_author
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# PUT /api/config/nvd-api-key — line 193 (invalid API key via message header)
# ---------------------------------------------------------------------------

class TestSetNvdApiKeyInvalidMessageHeader:
    def test_invalid_key_message_header_returns_400(self, client):
        """Line 193: when the NVD probe response 'message' header contains
        'invalid api', the key is rejected with 400."""
        from src.controllers.nvd_db import NVD_DB
        with patch.object(NVD_DB, "api_probe_cve",
                          return_value=(200, {}, {"message": "Invalid API key"})):
            resp = client.put("/api/config/nvd-api-key",
                              json={"api_key": "bad-key-9999"})
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data


# ---------------------------------------------------------------------------
# GET /api/version — webapp.py line 131
# ---------------------------------------------------------------------------

class TestApiVersion:
    def test_version_endpoint_returns_json(self, client):
        """Line 131 (webapp.py): GET /api/version returns a JSON version field."""
        resp = client.get("/api/version")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "version" in data
