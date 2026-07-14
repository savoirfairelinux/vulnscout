# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Shared persistence for NVD-API CVE results.

The NVD-scan API path is driven from two places — the web route
(:mod:`src.routes.scan_triggers`) and the CLI command
(:mod:`src.bin.cmd_vuln_scan`).  Both turn a raw NVD CVE dict into a
:class:`Vulnerability` record (create-or-update) plus its CVSS metrics.  That
per-CVE logic lives here so the two callers cannot drift apart; each caller
still owns its own progress reporting and finding/observation creation.
"""

from __future__ import annotations

from ..extensions import db
from ..models.vulnerability import Vulnerability as VulnModel
from ..models.metrics import Metrics as MetricsModel
from ..models.cvss import CVSS


def persist_nvd_cve(cve_id: str, details: dict) -> VulnModel:
    """Create or update the :class:`Vulnerability` for *cve_id* and its CVSS metric.

    *details* is the dict returned by
    :func:`~src.controllers.nvd_extract.extract_cve_details`.  Only empty fields
    are filled in on an existing record, so scanner data never overwrites
    richer values already present.  The row is flushed (``commit=False``); the
    caller is responsible for committing and for creating findings/observations.

    :return: the persisted :class:`Vulnerability` model.
    """
    existing_vuln = db.session.get(VulnModel, cve_id.upper())
    if existing_vuln is None:
        existing_vuln = VulnModel.create_record(
            id=cve_id,
            description=details.get("description"),
            status=details.get("status"),
            publish_date=details.get("publish_date"),
            attack_vector=details.get("attack_vector"),
            links=details.get("links"),
            weaknesses=details.get("weaknesses"),
            nvd_last_modified=details.get("nvd_last_modified"),
        )
        existing_vuln.add_found_by("nvd")
    else:
        existing_vuln.add_found_by("nvd")
        update: dict = {}
        if not existing_vuln.description and details.get("description"):
            update["description"] = details["description"]
        if not existing_vuln.status and details.get("status"):
            update["status"] = details["status"]
        if not existing_vuln.publish_date and details.get("publish_date"):
            update["publish_date"] = details["publish_date"]
        if not existing_vuln.attack_vector and details.get("attack_vector"):
            update["attack_vector"] = details["attack_vector"]
        if not existing_vuln.links and details.get("links"):
            update["links"] = details["links"]
        if not existing_vuln.weaknesses and details.get("weaknesses"):
            update["weaknesses"] = details["weaknesses"]
        if update:
            existing_vuln.update_record(**update, commit=False)

    _persist_cvss_metric(details, existing_vuln)
    return existing_vuln


def _persist_cvss_metric(details: dict, vuln: VulnModel) -> None:
    """Persist the NVD CVSS base metric for *vuln* when one is present.

    ``Metrics.from_cvss`` dedups within the session on its own, so no external
    pre-check is needed.  Failures are swallowed so one malformed metric never
    aborts the enrichment run.
    """
    if details.get("base_score") is None:
        return
    try:
        MetricsModel.from_cvss(
            CVSS(
                version=details.get("cvss_version") or "",
                vector_string=details.get("cvss_vector") or "",
                author="nvd",
                base_score=float(details["base_score"]),
                exploitability_score=float(details.get("cvss_exploitability") or 0),
                impact_score=float(details.get("cvss_impact") or 0),
            ),
            vuln.id,
        )
    except Exception:
        pass
