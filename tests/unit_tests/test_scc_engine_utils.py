# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unit tests for src/controllers/scc_engine.py.

The tests cover all helper functions and the SccEngine class methods without
requiring real advisory git clones.  Heavy external dependencies (VulnDbManager,
GitDatabase, init_*) are replaced with lightweight fakes via monkeypatching.
"""

from __future__ import annotations

import os
import pathlib
from unittest.mock import MagicMock, patch, call

import pytest

from sbom_cve_check.vuln.comp_id import CompId
from sbom_cve_check.vuln.vex import VexStatus


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

class TestTruthy:

    def test_true_values(self):
        from src.controllers.scc_engine import _truthy
        for val in ("1", "true", "TRUE", "yes", "YES", "on", "ON", "  true  "):
            assert _truthy(val) is True, f"Expected True for {val!r}"

    def test_false_values(self):
        from src.controllers.scc_engine import _truthy
        for val in ("0", "false", "no", "off", "", None, "anything-else"):
            assert _truthy(val) is False, f"Expected False for {val!r}"


class TestDatabasesDir:

    def test_uses_env_var_when_set(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SBOM_CVE_CHECK_DATABASES_DIR", str(tmp_path))
        monkeypatch.delenv("VULNSCOUT_CACHE_DIR", raising=False)
        from src.controllers import scc_engine as mod
        result = mod._databases_dir()
        assert result == tmp_path.expanduser().resolve()

    def test_uses_vulnscout_cache_dir_when_env_set(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SBOM_CVE_CHECK_DATABASES_DIR", raising=False)
        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
        from src.controllers import scc_engine as mod
        result = mod._databases_dir()
        assert result == tmp_path.joinpath("local_databases").resolve()

    def test_falls_back_to_cache_vulnscout(self, monkeypatch):
        monkeypatch.delenv("SBOM_CVE_CHECK_DATABASES_DIR", raising=False)
        monkeypatch.delenv("VULNSCOUT_CACHE_DIR", raising=False)
        from src.controllers import scc_engine as mod
        result = mod._databases_dir()
        assert str(result).endswith("/cache/vulnscout/local_databases")

    def test_blank_env_var_falls_back(self, monkeypatch):
        monkeypatch.setenv("SBOM_CVE_CHECK_DATABASES_DIR", "   ")
        monkeypatch.delenv("VULNSCOUT_CACHE_DIR", raising=False)
        from src.controllers import scc_engine as mod
        result = mod._databases_dir()
        assert "local_databases" in str(result)


class TestTrustGitDirectories:

    def test_sets_git_config_env_vars(self, monkeypatch):
        # Remove any existing GIT_CONFIG_* vars.
        for key in list(os.environ.keys()):
            if key.startswith("GIT_CONFIG"):
                monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("GIT_CONFIG_COUNT", "0")

        from src.controllers import scc_engine as mod
        paths = [pathlib.Path("/a"), pathlib.Path("/b")]
        mod._trust_git_directories(paths)

        assert os.environ["GIT_CONFIG_COUNT"] == "2"
        assert os.environ["GIT_CONFIG_KEY_0"] == "safe.directory"
        assert os.environ["GIT_CONFIG_VALUE_0"] == "/a"
        assert os.environ["GIT_CONFIG_KEY_1"] == "safe.directory"
        assert os.environ["GIT_CONFIG_VALUE_1"] == "/b"

    def test_preserves_existing_count(self, monkeypatch):
        for key in list(os.environ.keys()):
            if key.startswith("GIT_CONFIG"):
                monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("GIT_CONFIG_COUNT", "3")

        from src.controllers import scc_engine as mod
        mod._trust_git_directories([pathlib.Path("/x")])

        assert os.environ["GIT_CONFIG_COUNT"] == "4"
        assert os.environ["GIT_CONFIG_KEY_3"] == "safe.directory"
        assert os.environ["GIT_CONFIG_VALUE_3"] == "/x"

    def test_invalid_count_treated_as_zero(self, monkeypatch):
        for key in list(os.environ.keys()):
            if key.startswith("GIT_CONFIG"):
                monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("GIT_CONFIG_COUNT", "notanumber")

        from src.controllers import scc_engine as mod
        mod._trust_git_directories([pathlib.Path("/y")])

        assert os.environ["GIT_CONFIG_KEY_0"] == "safe.directory"

    def test_empty_list_keeps_count(self, monkeypatch):
        for key in list(os.environ.keys()):
            if key.startswith("GIT_CONFIG"):
                monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("GIT_CONFIG_COUNT", "2")

        from src.controllers import scc_engine as mod
        mod._trust_git_directories([])

        assert os.environ["GIT_CONFIG_COUNT"] == "2"


class TestInstallCpeParserCaches:

    def test_is_idempotent(self, monkeypatch):
        """Calling the function twice must not crash and must set the flag."""
        import src.controllers.scc_engine as mod
        # Reset the flag so the first call runs the full install path.
        monkeypatch.setattr(mod, "_PURE_CACHES_INSTALLED", False)
        mod._install_cpe_parse_caches()
        assert mod._PURE_CACHES_INSTALLED is True
        # Second call: flag is True, should be a no-op.
        mod._install_cpe_parse_caches()
        assert mod._PURE_CACHES_INSTALLED is True

    def test_already_installed_returns_early(self, monkeypatch):
        import src.controllers.scc_engine as mod
        monkeypatch.setattr(mod, "_PURE_CACHES_INSTALLED", True)
        # Should return without importing or reassigning anything.
        mod._install_cpe_parse_caches()
        assert mod._PURE_CACHES_INSTALLED is True

    def test_wrapper_string_arg_uses_cache(self, monkeypatch):
        """After cache installation, calling Cpe23.parse with a string hits
        the cached branch (lines 70-71 inside the wrapper)."""
        import src.controllers.scc_engine as mod
        from sbom_cve_check.vuln.cpe import Cpe23

        monkeypatch.setattr(mod, "_PURE_CACHES_INSTALLED", False)
        mod._install_cpe_parse_caches()

        cpe_str = "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
        result = Cpe23.parse(cpe_str)
        # Cached second call — still returns a valid result.
        result2 = Cpe23.parse(cpe_str)
        assert result == result2

    def test_wrapper_none_arg_uses_cache(self, monkeypatch):
        """Calling the wrapper with None hits the cached branch."""
        import src.controllers.scc_engine as mod
        from sbom_cve_check.vuln.cpe import Cpe23

        monkeypatch.setattr(mod, "_PURE_CACHES_INSTALLED", False)
        mod._install_cpe_parse_caches()
        # None passes through the string/None branch (line 71).
        result = Cpe23.parse(None)
        assert result is None

    def test_wrapper_non_string_arg_passes_through(self, monkeypatch):
        """Calling the wrapper with a Cpe23 instance hits the pass-through
        branch (line 72: ``return func(arg)``) before the original function
        handles it (which may itself raise)."""
        import src.controllers.scc_engine as mod
        from sbom_cve_check.vuln.cpe import Cpe23

        monkeypatch.setattr(mod, "_PURE_CACHES_INSTALLED", False)
        mod._install_cpe_parse_caches()

        # Parse a string to get a real Cpe23 instance.
        cpe_str = "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
        cpe_obj = Cpe23.parse(cpe_str)
        # Call parse with the Cpe23 object → non-str, non-None → line 72
        # (``return func(arg)``).  The original Cpe23.parse doesn't accept a
        # Cpe23 instance so it raises; we just need line 72 to execute.
        with pytest.raises(Exception):
            Cpe23.parse(cpe_obj)


# ---------------------------------------------------------------------------
# SccEngine – constructed with mocked dependencies
# ---------------------------------------------------------------------------

def _make_mock_engine(tmp_path, auto_update=False):
    """Return a SccEngine with all external I/O mocked out."""
    nvd_dir = tmp_path / "nvd-fkie"
    nvd_dir.mkdir()
    cvelist_dir = tmp_path / "cvelist"
    cvelist_dir.mkdir()

    mock_mgr = MagicMock()
    mock_mgr._databases = {}

    with patch("src.controllers.scc_engine.VulnDbManager", return_value=mock_mgr), \
         patch("src.controllers.scc_engine.init_global_databases_lock"), \
         patch("src.controllers.scc_engine.GitDatabase"), \
         patch("src.controllers.scc_engine.init_products_database"), \
         patch("src.controllers.scc_engine.init_cna_database"), \
         patch("src.controllers.scc_engine._install_cpe_parse_caches"):
        from src.controllers.scc_engine import SccEngine
        engine = SccEngine(tmp_path, 1, auto_update)

    engine._manager = mock_mgr
    return engine


class TestSccEngineInit:

    def test_creates_manager_and_indexes(self, tmp_path):
        engine = _make_mock_engine(tmp_path)
        # create_index must have been called once.
        engine._manager.create_index.assert_called_once()

    def test_raises_when_dir_missing_and_no_auto_update(self, tmp_path):
        # Neither nvd-fkie nor cvelist directories exist.
        mock_mgr = MagicMock()
        with patch("src.controllers.scc_engine.VulnDbManager", return_value=mock_mgr), \
             patch("src.controllers.scc_engine.init_global_databases_lock"), \
             patch("src.controllers.scc_engine.GitDatabase"), \
             patch("src.controllers.scc_engine.init_products_database"), \
             patch("src.controllers.scc_engine.init_cna_database"), \
             patch("src.controllers.scc_engine._install_cpe_parse_caches"):
            from src.controllers.scc_engine import SccEngine
            with pytest.raises(RuntimeError, match="nvd-fkie"):
                SccEngine(tmp_path, 1, auto_update=False)

    def test_no_error_when_auto_update_even_if_dirs_missing(self, tmp_path):
        mock_mgr = MagicMock()
        mock_mgr._databases = {}
        with patch("src.controllers.scc_engine.VulnDbManager", return_value=mock_mgr), \
             patch("src.controllers.scc_engine.init_global_databases_lock"), \
             patch("src.controllers.scc_engine.GitDatabase"), \
             patch("src.controllers.scc_engine.init_products_database"), \
             patch("src.controllers.scc_engine.init_cna_database"), \
             patch("src.controllers.scc_engine._install_cpe_parse_caches"):
            from src.controllers.scc_engine import SccEngine
            engine = SccEngine(tmp_path, 1, auto_update=True)
        assert engine is not None

    def test_caches_initialised(self, tmp_path):
        engine = _make_mock_engine(tmp_path)
        assert isinstance(engine._applicable_cache, dict)
        assert isinstance(engine._verdict_cache, dict)

    def test_sets_databases_dir(self, tmp_path):
        engine = _make_mock_engine(tmp_path)
        assert engine._databases_dir == tmp_path


class TestInstallGetVulnCaches:

    def test_wraps_get_vuln_with_lru_cache(self, tmp_path):
        engine = _make_mock_engine(tmp_path)

        class _FakeDb:
            calls = 0

            def get_vuln(self, cve_id):
                self.calls += 1
                return {"id": cve_id}

        db = _FakeDb()
        engine._manager._databases = {"nvd": [db]}
        engine._install_get_vuln_caches()

        # After wrapping, repeated calls with the same arg should hit the cache.
        assert getattr(db.get_vuln, "__wrapped__", None) is not None

    def test_skips_already_wrapped(self, tmp_path):
        engine = _make_mock_engine(tmp_path)

        db = MagicMock()
        # Mark as already wrapped.
        db.get_vuln.__wrapped__ = db.get_vuln
        engine._manager._databases = {"nvd": [db]}
        engine._install_get_vuln_caches()

        # Should not wrap again.
        assert db.get_vuln.__wrapped__ is db.get_vuln

    def test_no_databases_attr_is_safe(self, tmp_path):
        engine = _make_mock_engine(tmp_path)
        engine._manager._databases = None
        # Must not raise.
        engine._install_get_vuln_caches()


class TestVexStatusStr:

    @pytest.fixture(autouse=True)
    def _get_cls(self):
        from src.controllers.scc_engine import SccEngine
        self.SccEngine = SccEngine

    def _computed(self, status):
        c = MagicMock()
        c.vex_assessment.status = status
        return c

    def test_affected(self):
        assert self.SccEngine._vex_status_str(self._computed(VexStatus.AFFECTED)) == "affected"

    def test_not_affected(self):
        assert self.SccEngine._vex_status_str(self._computed(VexStatus.NOT_AFFECTED)) == "not_affected"

    def test_fixed(self):
        assert self.SccEngine._vex_status_str(self._computed(VexStatus.FIXED)) == "fixed"

    def test_under_investigation_for_unknown(self):
        assert self.SccEngine._vex_status_str(
            self._computed(VexStatus.UNDER_INVESTIGATION)
        ) == "under_investigation"

    def test_unknown_falls_back_to_under_investigation(self):
        assert self.SccEngine._vex_status_str(
            self._computed(VexStatus.UNKNOWN)
        ) == "under_investigation"


class TestApplicableVulns:

    def _make_bare_engine(self, tmp_path):
        """Bypass __init__ entirely to isolate applicable_vulns logic."""
        from src.controllers.scc_engine import SccEngine
        engine = object.__new__(SccEngine)
        engine._manager = MagicMock()
        engine._applicable_cache = {}
        engine._verdict_cache = {}
        return engine

    def test_none_comp_build_yields_nothing(self, tmp_path):
        engine = self._make_bare_engine(tmp_path)
        pkg = MagicMock()
        pkg.name = ""
        pkg.version = ""
        pkg.cpe = []
        pkg.purl = []

        with patch("src.controllers.scc_engine.build_comp_build", return_value=None):
            results = list(engine.applicable_vulns(pkg))
        assert results == []

    def test_cache_miss_calls_get_applicable_vulns(self, tmp_path):
        engine = self._make_bare_engine(tmp_path)
        engine._manager._index_comp_vuln = {"openssl": []}

        mock_comp = MagicMock()
        mock_comp._vuln_db_entries = ("entry",)
        mock_comp.identifier = "CVE-2023-0001"
        engine._manager.get_applicable_vulns.return_value = [mock_comp]

        mock_build = MagicMock()
        mock_build.version = "1.1.1"
        mock_build.ids_for_matching.return_value = [CompId(name="openssl")]

        with patch("src.controllers.scc_engine.build_comp_build", return_value=mock_build), \
             patch("src.controllers.scc_engine.ComputedVulnInfo") as MockCVI:
            fake_cvi = MagicMock()
            fake_cvi.vex_assessment.status = VexStatus.AFFECTED
            fake_cvi.identifier = "CVE-2023-0001"
            MockCVI.return_value = fake_cvi

            pkg = MagicMock()
            results = list(engine.applicable_vulns(pkg))

        assert len(results) == 1
        engine._manager.get_applicable_vulns.assert_called_once()

    def test_cache_hit_skips_get_applicable_vulns(self, tmp_path):
        engine = self._make_bare_engine(tmp_path)
        engine._manager._index_comp_vuln = {"openssl": []}

        mock_build = MagicMock()
        mock_build.version = "1.1.1"
        mock_build.ids_for_matching.return_value = [CompId(name="openssl")]

        key = (frozenset({CompId(name="openssl")}), "1.1.1")
        engine._applicable_cache[key] = [("entry",)]

        with patch("src.controllers.scc_engine.build_comp_build", return_value=mock_build), \
             patch("src.controllers.scc_engine.ComputedVulnInfo") as MockCVI:
            fake_cvi = MagicMock()
            fake_cvi.vex_assessment.status = VexStatus.NOT_AFFECTED
            fake_cvi.identifier = "CVE-2023-0001"
            MockCVI.return_value = fake_cvi

            pkg = MagicMock()
            results = list(engine.applicable_vulns(pkg))

        engine._manager.get_applicable_vulns.assert_not_called()
        assert len(results) == 1

    def test_verdict_cached_on_second_pkg(self, tmp_path):
        engine = self._make_bare_engine(tmp_path)
        engine._manager._index_comp_vuln = {"openssl": []}

        mock_build = MagicMock()
        mock_build.version = "1.1.1"
        mock_build.ids_for_matching.return_value = [CompId(name="openssl")]

        key = (frozenset({CompId(name="openssl")}), "1.1.1")
        engine._applicable_cache[key] = [("entry",)]
        engine._verdict_cache[key] = {"CVE-2023-0001": "fixed"}

        with patch("src.controllers.scc_engine.build_comp_build", return_value=mock_build), \
             patch("src.controllers.scc_engine.ComputedVulnInfo") as MockCVI:
            fake_cvi = MagicMock()
            fake_cvi.identifier = "CVE-2023-0001"
            MockCVI.return_value = fake_cvi

            pkg = MagicMock()
            results = list(engine.applicable_vulns(pkg))

        # Status comes from the verdict cache, not _vex_status_str.
        assert results[0][1] == "fixed"

    def test_cache_overflow_clears_both_caches(self, tmp_path):
        engine = self._make_bare_engine(tmp_path)
        engine._manager._index_comp_vuln = {"openssl": []}
        # Fill caches past the 50 000-entry limit.
        engine._applicable_cache = {i: [] for i in range(50_001)}
        engine._verdict_cache = {i: {} for i in range(50_001)}

        mock_comp = MagicMock()
        mock_comp._vuln_db_entries = ()
        engine._manager.get_applicable_vulns.return_value = [mock_comp]

        mock_build = MagicMock()
        mock_build.version = "2.0"
        mock_build.ids_for_matching.return_value = [CompId(name="openssl")]

        with patch("src.controllers.scc_engine.build_comp_build", return_value=mock_build), \
             patch("src.controllers.scc_engine.ComputedVulnInfo"):
            pkg = MagicMock()
            list(engine.applicable_vulns(pkg))

        # Both caches cleared then one new entry added.
        assert len(engine._applicable_cache) == 1
        assert len(engine._verdict_cache) <= 1

    def test_ids_not_in_index_excluded_from_key(self, tmp_path):
        """Identifiers whose name is absent from the index are excluded from the
        cache key, so packages sharing the same indexed ids share the cache."""
        engine = self._make_bare_engine(tmp_path)
        # Only "curl" is in the index; "libcurl" is not.
        engine._manager._index_comp_vuln = {"curl": []}

        mock_build = MagicMock()
        mock_build.version = "8.0"
        mock_build.ids_for_matching.return_value = [
            CompId(name="curl"),
            CompId(name="libcurl"),  # not in index → excluded
        ]
        engine._manager.get_applicable_vulns.return_value = []

        with patch("src.controllers.scc_engine.build_comp_build", return_value=mock_build):
            pkg = MagicMock()
            list(engine.applicable_vulns(pkg))

        key = list(engine._applicable_cache.keys())[0]
        key_names = {c.name for c in key[0]}
        assert "curl" in key_names
        assert "libcurl" not in key_names


# ---------------------------------------------------------------------------
# get_engine / reset_engine
# ---------------------------------------------------------------------------

class TestGetAndResetEngine:

    @pytest.fixture(autouse=True)
    def _reset(self):
        """Ensure the module-level engine cache is clean before and after each test."""
        import src.controllers.scc_engine as mod
        mod._ENGINE = None
        yield
        mod._ENGINE = None

    def test_get_engine_creates_once(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOM_CVE_CHECK_DATABASES_DIR", str(tmp_path))
        monkeypatch.delenv("SBOM_CVE_CHECK_GIT_FETCH_DEPTH", raising=False)
        monkeypatch.delenv("SBOM_CVE_CHECK_AUTO_UPDATE", raising=False)

        nvd = tmp_path / "nvd-fkie"
        nvd.mkdir()
        cvelist = tmp_path / "cvelist"
        cvelist.mkdir()

        mock_mgr = MagicMock()
        mock_mgr._databases = {}

        with patch("src.controllers.scc_engine.VulnDbManager", return_value=mock_mgr), \
             patch("src.controllers.scc_engine.init_global_databases_lock"), \
             patch("src.controllers.scc_engine.GitDatabase"), \
             patch("src.controllers.scc_engine.init_products_database"), \
             patch("src.controllers.scc_engine.init_cna_database"), \
             patch("src.controllers.scc_engine._install_cpe_parse_caches"):
            from src.controllers.scc_engine import get_engine
            e1 = get_engine()
            e2 = get_engine()

        assert e1 is e2  # cached — not rebuilt on second call

    def test_get_engine_respects_fetch_depth_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOM_CVE_CHECK_DATABASES_DIR", str(tmp_path))
        monkeypatch.setenv("SBOM_CVE_CHECK_GIT_FETCH_DEPTH", "5")
        monkeypatch.delenv("SBOM_CVE_CHECK_AUTO_UPDATE", raising=False)

        nvd = tmp_path / "nvd-fkie"
        nvd.mkdir()
        cvelist = tmp_path / "cvelist"
        cvelist.mkdir()

        captured = {}
        mock_mgr = MagicMock()
        mock_mgr._databases = {}

        original_init = None

        def fake_init(self, databases_dir, fetch_depth, auto_update):
            captured["fetch_depth"] = fetch_depth
            self._databases_dir = databases_dir
            self._manager = mock_mgr
            self._applicable_cache = {}
            self._verdict_cache = {}
            self._auto_update = auto_update

        with patch("src.controllers.scc_engine.VulnDbManager", return_value=mock_mgr), \
             patch("src.controllers.scc_engine.init_global_databases_lock"), \
             patch("src.controllers.scc_engine.GitDatabase"), \
             patch("src.controllers.scc_engine.init_products_database"), \
             patch("src.controllers.scc_engine.init_cna_database"), \
             patch("src.controllers.scc_engine._install_cpe_parse_caches"), \
             patch("src.controllers.scc_engine.SccEngine.__init__", fake_init):
            from src.controllers.scc_engine import get_engine
            get_engine()

        assert captured["fetch_depth"] == 5

    def test_get_engine_invalid_depth_defaults_to_1(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOM_CVE_CHECK_DATABASES_DIR", str(tmp_path))
        monkeypatch.setenv("SBOM_CVE_CHECK_GIT_FETCH_DEPTH", "notanint")
        monkeypatch.delenv("SBOM_CVE_CHECK_AUTO_UPDATE", raising=False)

        nvd = tmp_path / "nvd-fkie"
        nvd.mkdir()
        cvelist = tmp_path / "cvelist"
        cvelist.mkdir()

        captured = {}
        mock_mgr = MagicMock()
        mock_mgr._databases = {}

        def fake_init(self, databases_dir, fetch_depth, auto_update):
            captured["fetch_depth"] = fetch_depth
            self._databases_dir = databases_dir
            self._manager = mock_mgr
            self._applicable_cache = {}
            self._verdict_cache = {}
            self._auto_update = auto_update

        with patch("src.controllers.scc_engine.VulnDbManager", return_value=mock_mgr), \
             patch("src.controllers.scc_engine.init_global_databases_lock"), \
             patch("src.controllers.scc_engine.GitDatabase"), \
             patch("src.controllers.scc_engine.init_products_database"), \
             patch("src.controllers.scc_engine.init_cna_database"), \
             patch("src.controllers.scc_engine._install_cpe_parse_caches"), \
             patch("src.controllers.scc_engine.SccEngine.__init__", fake_init):
            from src.controllers.scc_engine import get_engine
            get_engine()

        assert captured["fetch_depth"] == 1

    def test_reset_engine_clears_cache(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOM_CVE_CHECK_DATABASES_DIR", str(tmp_path))
        monkeypatch.delenv("SBOM_CVE_CHECK_GIT_FETCH_DEPTH", raising=False)
        monkeypatch.delenv("SBOM_CVE_CHECK_AUTO_UPDATE", raising=False)

        nvd = tmp_path / "nvd-fkie"
        nvd.mkdir()
        cvelist = tmp_path / "cvelist"
        cvelist.mkdir()

        mock_mgr = MagicMock()
        mock_mgr._databases = {}

        with patch("src.controllers.scc_engine.VulnDbManager", return_value=mock_mgr), \
             patch("src.controllers.scc_engine.init_global_databases_lock"), \
             patch("src.controllers.scc_engine.GitDatabase"), \
             patch("src.controllers.scc_engine.init_products_database"), \
             patch("src.controllers.scc_engine.init_cna_database"), \
             patch("src.controllers.scc_engine._install_cpe_parse_caches"):
            from src.controllers.scc_engine import get_engine, reset_engine
            e = get_engine()
            assert e is not None

            reset_engine()
            import src.controllers.scc_engine as mod
            assert mod._ENGINE is None


class _FakeGitDb:
    """Minimal stand-in for sbom_cve_check's GitDatabase used in refresh tests."""

    def __init__(self, commits):
        # ``commits`` is the sequence of values returned by successive
        # get_date_last_commit() calls (before/after each update).
        self._commits = list(commits)
        self._idx = 0
        self.update_calls = []
        self.raise_on_update = False

    def get_date_last_commit(self):
        value = self._commits[min(self._idx, len(self._commits) - 1)]
        self._idx += 1
        return value

    def update(self, force_update):
        self.update_calls.append(force_update)
        if self.raise_on_update:
            raise RuntimeError("network down")


def _attach_git_dbs(engine, git_dbs):
    """Wire fake git databases into the engine's manager."""
    wrappers = []
    for git_db in git_dbs:
        wrapper = MagicMock()
        wrapper.git_database = git_db
        wrappers.append(wrapper)
    engine._manager._databases = {0: wrappers}
    return engine


class TestRefreshDatabases:

    def test_noop_when_auto_update_disabled(self, tmp_path):
        engine = _make_mock_engine(tmp_path, auto_update=False)
        engine._manager.create_index.reset_mock()
        git_db = _FakeGitDb(["sha-a", "sha-a"])
        _attach_git_dbs(engine, [git_db])

        assert engine.refresh_databases() is False
        # No fetch attempted in offline mode.
        assert git_db.update_calls == []
        engine._manager.create_index.assert_not_called()

    def test_force_fetches_each_db_without_commit_change(self, tmp_path):
        engine = _make_mock_engine(tmp_path, auto_update=True)
        engine._manager.create_index.reset_mock()
        git_a = _FakeGitDb(["sha-a", "sha-a"])
        git_b = _FakeGitDb(["sha-b", "sha-b"])
        _attach_git_dbs(engine, [git_a, git_b])

        changed = engine.refresh_databases()

        assert changed is False
        assert git_a.update_calls == [True]
        assert git_b.update_calls == [True]
        # Unchanged commits → index is not rebuilt.
        engine._manager.create_index.assert_not_called()

    def test_rebuilds_index_and_clears_caches_on_commit_change(self, tmp_path):
        engine = _make_mock_engine(tmp_path, auto_update=True)
        engine._manager.create_index.reset_mock()
        git_db = _FakeGitDb(["sha-old", "sha-new"])
        _attach_git_dbs(engine, [git_db])

        engine._applicable_cache[("k",)] = ["x"]
        engine._verdict_cache[("k",)] = {"CVE-1": "affected"}

        changed = engine.refresh_databases()

        assert changed is True
        engine._manager.create_index.assert_called_once()
        assert engine._applicable_cache == {}
        assert engine._verdict_cache == {}

    def test_swallows_fetch_errors(self, tmp_path):
        engine = _make_mock_engine(tmp_path, auto_update=True)
        engine._manager.create_index.reset_mock()
        git_db = _FakeGitDb(["sha-a", "sha-a"])
        git_db.raise_on_update = True
        _attach_git_dbs(engine, [git_db])

        # A failing fetch must not raise and must not rebuild the index.
        assert engine.refresh_databases() is False
        engine._manager.create_index.assert_not_called()

    def test_no_databases_returns_false_without_fetch(self, tmp_path):
        # _manager._databases is {} (falsy) so _git_databases() returns [] immediately.
        engine = _make_mock_engine(tmp_path, auto_update=True)
        engine._manager.create_index.reset_mock()
        # Do NOT call _attach_git_dbs — leave _databases as the empty dict set by _make_mock_engine.

        changed = engine.refresh_databases()

        assert changed is False
        engine._manager.create_index.assert_not_called()


class TestGetEngineRefresh:

    @pytest.fixture(autouse=True)
    def _reset(self):
        import src.controllers.scc_engine as mod
        mod._ENGINE = None
        yield
        mod._ENGINE = None

    def test_refreshes_on_every_call(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOM_CVE_CHECK_DATABASES_DIR", str(tmp_path))
        monkeypatch.delenv("SBOM_CVE_CHECK_GIT_FETCH_DEPTH", raising=False)
        monkeypatch.delenv("SBOM_CVE_CHECK_AUTO_UPDATE", raising=False)

        (tmp_path / "nvd-fkie").mkdir()
        (tmp_path / "cvelist").mkdir()

        mock_mgr = MagicMock()
        mock_mgr._databases = {}

        with patch("src.controllers.scc_engine.VulnDbManager", return_value=mock_mgr), \
             patch("src.controllers.scc_engine.init_global_databases_lock"), \
             patch("src.controllers.scc_engine.GitDatabase"), \
             patch("src.controllers.scc_engine.init_products_database"), \
             patch("src.controllers.scc_engine.init_cna_database"), \
             patch("src.controllers.scc_engine._install_cpe_parse_caches"), \
             patch("src.controllers.scc_engine.SccEngine.refresh_databases") as refresh:
            from src.controllers.scc_engine import get_engine
            get_engine()
            # First scan: built then refreshed so even the first scan is fresh.
            refresh.assert_called_once()
            get_engine()
            # Cached engine reused → refreshed again before the next scan.
            assert refresh.call_count == 2
