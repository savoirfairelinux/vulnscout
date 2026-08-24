# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Direct coverage for refresh jobs executed by the operation queue."""

from __future__ import annotations

import datetime
import decimal
import urllib.error
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.controllers import refresh_jobs as jobs


def job_context(ids, **options):
    return SimpleNamespace(
        options={"ids": ids, **options},
        report=MagicMock(),
        is_cancelled=lambda: False,
        check_cancelled=MagicMock(),
    )


def test_normalisers_sleep_interval_and_safe_commit(monkeypatch):
    assert jobs.normalise_cve_ids([" cve-2024-0001 ", "CVE-2024-0001", 2, "bad"]) == ["CVE-2024-0001"]
    assert jobs.normalise_ghsa_ids([" ghsa-abcd-1234-5678 ", "GHSA-ABCD-1234-5678", "bad"]) == ["GHSA-ABCD-1234-5678"]
    assert jobs.normalise_cve_ids("CVE-2024-1") == []
    assert jobs.normalise_ghsa_ids("GHSA-ABCD-1234-5678") == []

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    assert jobs._nvd_sleep_interval() == 6.0
    monkeypatch.setenv("NVD_API_KEY", "key")
    assert jobs._nvd_sleep_interval() == 0.6

    session = MagicMock()
    monkeypatch.setattr(jobs.db, "session", session)
    jobs._safe_commit("success")
    session.commit.assert_called_once()
    session.expunge_all.assert_called_once()

    session.reset_mock()
    session.commit.side_effect = RuntimeError("database unavailable")
    jobs._safe_commit("failure")
    session.rollback.assert_called_once()
    session.expunge_all.assert_called_once()


def test_known_ids_and_refresh_helper_edge_cases(monkeypatch):
    class Query:
        def filter(self, _condition):
            return self

        def all(self):
            return [("CVE-2024-0001",)]

    monkeypatch.setattr(jobs, "DB_LOOKUP_CHUNK", 1)
    monkeypatch.setattr(jobs.db, "session", SimpleNamespace(query=lambda _column: Query()))
    assert jobs.known_cve_ids(["CVE-2024-0001", "CVE-2024-0002"]) == ["CVE-2024-0001"]

    record = object()
    monkeypatch.setattr(jobs.db, "session", SimpleNamespace(get=MagicMock(return_value=record)))
    monkeypatch.setattr(jobs, "get_cve_json", lambda _cve_id: {"id": "CVE-2024-0001"})
    monkeypatch.setattr(jobs, "extract_cve_details", lambda _payload: {"id": "CVE-2024-0001"})
    apply_nvd = MagicMock()
    monkeypatch.setattr(jobs, "apply_nvd_update", apply_nvd)
    monkeypatch.setattr(jobs, "apply_cvss_update", MagicMock())
    jobs._refresh_nvd_record("CVE-2024-0001", "local", None)
    apply_nvd.assert_called_once()

    monkeypatch.setattr(jobs.db, "session", SimpleNamespace(get=MagicMock(return_value=None)))
    jobs._apply_epss_score("CVE-2024-0001", "0.1", datetime.datetime.now(datetime.timezone.utc))


def test_deferred_refresh_resolves_new_ids_when_it_starts(monkeypatch):
    ctx = job_context(
        [], source="epss", variant_ids=["variant-a"],
        exclude_ids=["CVE-2024-0001"],
    )
    ctx.op_id = "refresh:epss"
    monkeypatch.setattr(jobs.registry, "get", lambda _op_id: None)
    monkeypatch.setattr(
        jobs, "_scoped_vulnerability_ids",
        lambda _variant_ids: {"CVE-2024-0001", "CVE-2024-0002"},
    )
    monkeypatch.setattr(jobs, "known_cve_ids", lambda ids: ids)
    runner = MagicMock()
    monkeypatch.setitem(jobs.REFRESH_JOBS, "epss", runner)

    jobs.run_deferred_refresh(ctx)

    assert ctx.options["ids"] == ["CVE-2024-0002"]
    runner.assert_called_once_with(ctx)


def test_deferred_refresh_skips_after_failed_scan(monkeypatch):
    ctx = job_context([], source="epss", variant_ids=["variant-a"], exclude_ids=[])
    ctx.op_id = "refresh:epss"
    monkeypatch.setattr(
        jobs.registry, "get",
        lambda _op_id: {"queue_id": "q-1", "position": 2},
    )
    monkeypatch.setattr(
        jobs.registry, "snapshot",
        lambda: [{"queue_id": "q-1", "position": 1, "kind": "scan", "status": "error"}],
    )
    resolve = MagicMock()
    monkeypatch.setattr(jobs, "_scoped_vulnerability_ids", resolve)

    jobs.run_deferred_refresh(ctx)

    resolve.assert_not_called()
    ctx.report.assert_called_once_with(0, 0, "Skipped because an earlier scan did not complete")


def test_refresh_nvd_record_api_and_local_paths(monkeypatch):
    record = object()
    monkeypatch.setattr(jobs.db, "session", SimpleNamespace(get=MagicMock(return_value=record)))
    apply_nvd = MagicMock()
    apply_cvss = MagicMock()
    monkeypatch.setattr(jobs, "apply_nvd_update", apply_nvd)
    monkeypatch.setattr(jobs, "apply_cvss_update", apply_cvss)

    client = MagicMock()
    client.api_get_cve.return_value = (200, {"vulnerabilities": [{"cve": {"id": "CVE-2024-1"}}]})
    monkeypatch.setattr(jobs.NVD_DB, "extract_cve_details", MagicMock(return_value={"id": "CVE-2024-1"}))
    jobs._refresh_nvd_record("CVE-2024-1", "api", client)
    apply_nvd.assert_called_once()
    apply_cvss.assert_called_once()

    apply_nvd.reset_mock()
    client.api_get_cve.return_value = (404, {})
    jobs._refresh_nvd_record("CVE-2024-2", "api", client)
    apply_nvd.assert_not_called()

    monkeypatch.setattr(jobs, "get_cve_json", lambda _cve_id: None)
    jobs._refresh_nvd_record("CVE-2024-3", "local", None)
    apply_nvd.assert_not_called()


def test_run_nvd_refresh_api_and_local_setup_failure(monkeypatch):
    ctx = job_context(["CVE-2024-1", "CVE-2024-2"], mode="api")
    client = MagicMock()
    monkeypatch.setattr(jobs, "NVD_DB", lambda **_kwargs: client)
    monkeypatch.setattr(jobs, "_nvd_sleep_interval", lambda: 0.0)
    refreshed = MagicMock()
    monkeypatch.setattr(jobs, "_refresh_nvd_record", refreshed)
    committed = MagicMock()
    monkeypatch.setattr(jobs, "_safe_commit", committed)
    slept = MagicMock()
    monkeypatch.setattr(jobs.time, "sleep", slept)

    jobs.run_nvd_refresh(ctx)
    assert refreshed.call_count == 2
    slept.assert_called_once_with(0.0)
    assert committed.call_count == 1
    assert ctx.report.call_args_list[-1].args[-1] == "NVD refresh complete"

    monkeypatch.setattr(jobs, "_get_scc_engine", MagicMock(side_effect=ValueError("missing")))
    with pytest.raises(RuntimeError, match="Failed to load local NVD database"):
        jobs.run_nvd_refresh(job_context(["CVE-2024-1"]))


def test_nvd_refresh_handles_item_errors_periodic_commits_and_cancellation(monkeypatch):
    monkeypatch.setattr(jobs, "NVD_DB", lambda **_kwargs: MagicMock())
    monkeypatch.setattr(jobs, "_nvd_sleep_interval", lambda: 0.0)
    monkeypatch.setattr(jobs, "_refresh_nvd_record", MagicMock(side_effect=ValueError("bad record")))
    committed = MagicMock()
    monkeypatch.setattr(jobs, "_safe_commit", committed)
    monkeypatch.setattr(jobs, "NVD_COMMIT_EVERY", 1)
    jobs.run_nvd_refresh(job_context(["CVE-2024-0001"], mode="api"))
    assert committed.call_count == 2

    ctx = job_context(["CVE-2024-0001"], mode="api")
    ctx.is_cancelled = lambda: True
    ctx.check_cancelled.side_effect = RuntimeError("cancelled")
    with pytest.raises(RuntimeError, match="cancelled"):
        jobs.run_nvd_refresh(ctx)


def test_apply_and_run_epss_refresh(monkeypatch):
    record = MagicMock(epss_score=None)
    monkeypatch.setattr(jobs.db, "session", SimpleNamespace(get=MagicMock(return_value=record)))
    now = datetime.datetime.now(datetime.timezone.utc)
    jobs._apply_epss_score("CVE-2024-1", "0.42", now)
    assert record.update_record.call_args.kwargs["epss_score"] == decimal.Decimal("0.42")
    assert record.update_record.call_args.kwargs["epss_data_updated_at"] == now

    record.reset_mock()
    record.epss_score = decimal.Decimal("0.42")
    jobs._apply_epss_score("CVE-2024-1", "0.42", now)
    assert "epss_data_updated_at" not in record.update_record.call_args.kwargs

    client = MagicMock()
    client.api_get_epss_batch.side_effect = [{"CVE-2024-1": {"score": "0.5"}}, RuntimeError("offline")]
    monkeypatch.setattr(jobs, "EPSS_DB", lambda: client)
    applied = MagicMock()
    monkeypatch.setattr(jobs, "_apply_epss_score", applied)
    committed = MagicMock()
    monkeypatch.setattr(jobs, "_safe_commit", committed)
    monkeypatch.setattr(jobs, "EPSS_BATCH_SIZE", 1)
    ctx = job_context(["CVE-2024-1", "CVE-2024-2"])
    jobs.run_epss_refresh(ctx)
    applied.assert_called_once()
    assert committed.call_count == 1
    assert ctx.report.call_args_list[-1].args[-1] == "EPSS refresh complete"


def test_epss_refresh_handles_update_errors_and_cancellation(monkeypatch):
    client = MagicMock()
    client.api_get_epss_batch.return_value = {"CVE-2024-0001": {"score": "0.5"}}
    monkeypatch.setattr(jobs, "EPSS_DB", lambda: client)
    monkeypatch.setattr(jobs, "_apply_epss_score", MagicMock(side_effect=ValueError("bad score")))
    monkeypatch.setattr(jobs, "_safe_commit", MagicMock())
    jobs.run_epss_refresh(job_context(["CVE-2024-0001"]))

    ctx = job_context(["CVE-2024-0001"])
    ctx.is_cancelled = lambda: True
    ctx.check_cancelled.side_effect = RuntimeError("cancelled")
    with pytest.raises(RuntimeError, match="cancelled"):
        jobs.run_epss_refresh(ctx)


def test_apply_and_run_ghsa_refresh(monkeypatch):
    record = MagicMock(publish_date=None)
    monkeypatch.setattr(jobs.db, "session", SimpleNamespace(get=MagicMock(return_value=record)))
    monkeypatch.setattr(jobs.VulnerabilitiesController, "_fetch_ghsa_published", lambda _id: "2024-01-02T00:00:00Z")
    now = datetime.datetime.now(datetime.timezone.utc)
    jobs._apply_ghsa_published("GHSA-ABCD-1234", now)
    assert record.update_record.call_args.kwargs["publish_date"] == datetime.date(2024, 1, 2)

    monkeypatch.setattr(jobs, "_apply_ghsa_published", MagicMock(side_effect=[None, ValueError("bad")]))
    monkeypatch.setattr(jobs, "_safe_commit", MagicMock())
    monkeypatch.setattr(jobs.time, "sleep", MagicMock())
    ctx = job_context(["GHSA-ABCD-1234", "GHSA-ABCD-5678"])
    jobs.run_ghsa_refresh(ctx)
    assert "1 failed" in ctx.report.call_args_list[-1].args[-1]

    error = urllib.error.HTTPError("url", 429, "rate limited", {}, None)
    monkeypatch.setattr(jobs, "_apply_ghsa_published", MagicMock(side_effect=error))
    with pytest.raises(RuntimeError, match="rate limit"):
        jobs.run_ghsa_refresh(job_context(["GHSA-ABCD-1234"]))


def test_ghsa_helper_handles_missing_invalid_and_absent_records(monkeypatch):
    now = datetime.datetime.now(datetime.timezone.utc)
    monkeypatch.setattr(jobs.VulnerabilitiesController, "_fetch_ghsa_published", lambda _id: None)
    jobs._apply_ghsa_published("GHSA-ABCD-1234-5678", now)

    record = MagicMock(publish_date=None)
    monkeypatch.setattr(jobs.db, "session", SimpleNamespace(get=MagicMock(return_value=record)))
    monkeypatch.setattr(jobs.VulnerabilitiesController, "_fetch_ghsa_published", lambda _id: "not-a-date")
    jobs._apply_ghsa_published("GHSA-ABCD-1234-5678", now)
    assert record.update_record.call_args.kwargs == {"ghsa_fetched_at": now, "commit": False}

    monkeypatch.setattr(jobs.db, "session", SimpleNamespace(get=MagicMock(return_value=None)))
    monkeypatch.setattr(jobs.VulnerabilitiesController, "_fetch_ghsa_published", lambda _id: "2024-01-02")
    jobs._apply_ghsa_published("GHSA-ABCD-1234-5678", now)


def test_ghsa_refresh_handles_http_error_periodic_commit_and_cancellation(monkeypatch):
    error = urllib.error.HTTPError("url", 500, "server error", {}, None)
    monkeypatch.setattr(jobs, "_apply_ghsa_published", MagicMock(side_effect=error))
    committed = MagicMock()
    monkeypatch.setattr(jobs, "_safe_commit", committed)
    monkeypatch.setattr(jobs.time, "sleep", MagicMock())
    monkeypatch.setattr(jobs, "GHSA_COMMIT_EVERY", 1)
    jobs.run_ghsa_refresh(job_context(["GHSA-ABCD-1234-5678"]))
    assert committed.call_count == 2

    ctx = job_context(["GHSA-ABCD-1234-5678"])
    ctx.is_cancelled = lambda: True
    ctx.check_cancelled.side_effect = RuntimeError("cancelled")
    with pytest.raises(RuntimeError, match="cancelled"):
        jobs.run_ghsa_refresh(ctx)


def test_apply_and_run_euvd_refresh(monkeypatch):
    record = MagicMock(
        euvd_id=None,
        euvd_known_exploited=False,
        euvd_kev_sources=[],
        euvd_date_added=None,
    )
    monkeypatch.setattr(jobs.db, "session", SimpleNamespace(get=MagicMock(return_value=record)))
    now = datetime.datetime.now(datetime.timezone.utc)
    assert jobs._apply_euvd("CVE-2024-1", {"CVE-2024-1": "EUVD-1"}, {"CVE-2024-1": {"sources": ["kev"], "date_added": "2024-01-01"}}, now) == (True, True)
    assert record.update_record.call_args.kwargs["euvd_id"] == "EUVD-1"

    record.reset_mock()
    assert jobs._apply_euvd("CVE-2024-1", {}, {}, now) == (False, False)
    assert record.update_record.call_args.kwargs["euvd_fetched_at"] == now

    client = MagicMock()
    client.get_full_mapping.return_value = {"CVE-2024-1": "EUVD-1"}
    client.get_mapping.return_value = {}
    monkeypatch.setattr(jobs, "EUVD_DB", lambda: client)
    monkeypatch.setattr(jobs, "_apply_euvd", MagicMock(side_effect=[(True, False), (False, False)]))
    monkeypatch.setattr(jobs, "_safe_commit", MagicMock())
    ctx = job_context(["CVE-2024-1", "CVE-2024-2"])
    jobs.run_euvd_refresh(ctx)
    assert "1/2 matched" in ctx.report.call_args_list[-1].args[-1]

    client.get_full_mapping.return_value = {}
    with pytest.raises(RuntimeError, match="mapping unavailable"):
        jobs.run_euvd_refresh(job_context(["CVE-2024-1"]))


def test_euvd_helper_handles_missing_and_stale_records(monkeypatch):
    now = datetime.datetime.now(datetime.timezone.utc)
    monkeypatch.setattr(jobs.db, "session", SimpleNamespace(get=MagicMock(return_value=None)))
    assert jobs._apply_euvd("CVE-2024-0001", {}, {}, now) == (False, False)

    record = MagicMock(
        euvd_id="EUVD-1",
        euvd_known_exploited=True,
        euvd_kev_sources=["kev"],
        euvd_date_added="2024-01-01",
    )
    monkeypatch.setattr(jobs.db, "session", SimpleNamespace(get=MagicMock(return_value=record)))
    assert jobs._apply_euvd("CVE-2024-0001", {}, {}, now) == (False, False)
    assert record.euvd_id is None
    assert record.euvd_known_exploited is False


def test_euvd_refresh_counts_exploitation_and_honours_cancellation(monkeypatch):
    client = MagicMock()
    client.get_full_mapping.return_value = {"CVE-2024-0001": "EUVD-1"}
    client.get_mapping.return_value = {}
    monkeypatch.setattr(jobs, "EUVD_DB", lambda: client)
    monkeypatch.setattr(jobs, "_apply_euvd", MagicMock(return_value=(True, True)))
    committed = MagicMock()
    monkeypatch.setattr(jobs, "_safe_commit", committed)
    monkeypatch.setattr(jobs, "EUVD_COMMIT_EVERY", 1)
    ctx = job_context(["CVE-2024-0001"])
    jobs.run_euvd_refresh(ctx)
    assert "1 known exploitable" in ctx.report.call_args_list[-1].args[-1]
    assert committed.call_count == 2

    ctx = job_context(["CVE-2024-0001"])
    ctx.is_cancelled = lambda: True
    ctx.check_cancelled.side_effect = RuntimeError("cancelled")
    with pytest.raises(RuntimeError, match="cancelled"):
        jobs.run_euvd_refresh(ctx)