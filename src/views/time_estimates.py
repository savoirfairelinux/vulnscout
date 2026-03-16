# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from datetime import datetime, timezone
from typing import Optional


class TimeEstimates:
    """
    TimeEstimates class to handle custom JSON file format and parse it.
    Support reading, parsing and writing from/to JSON format.

    Two task-key formats are recognised in ``load_from_dict``:

    * **Legacy** – the key is a vulnerability id (str).  The effort is stored on
      the in-memory :class:`~src.models.vulnerability.Vulnerability` object using
      ISO 8601 duration strings (e.g. ``"PT4H"``).

    * **DB** – the key is a finding id (UUID str).  The effort is given as plain
      integers (hours) and optionally accompanied by a ``variant_id``.  When a
      Flask application context with a live database session is available the data
      are persisted to the :class:`~src.models.time_estimate.TimeEstimate` table.
    """

    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _iso_to_hours(iso_str: Optional[str]) -> Optional[int]:
        """Convert an ISO 8601 duration string to whole hours, or return ``None``."""
        if not iso_str:
            return None
        try:
            from ..models.iso8601_duration import Iso8601Duration
            return int(Iso8601Duration(iso_str).total_seconds // 3600)
        except Exception:
            return None

    @staticmethod
    def _persist_db_estimate(
        finding_id: str,
        optimistic: int,
        likely: int,
        pessimistic: int,
        variant_id: Optional[str] = None,
    ) -> None:
        """Upsert a :class:`~src.models.time_estimate.TimeEstimate` DB row.

        Silently skips when no Flask application context / DB session is
        available so that the parser can still be used outside of a web request.
        """
        try:
            from ..models.time_estimate import TimeEstimate
            existing = TimeEstimate.get_by_finding_and_variant(
                finding_id, variant_id
            ) if variant_id else None
            if existing is None:
                TimeEstimate.create(
                    finding_id=finding_id,
                    variant_id=variant_id,
                    optimistic=optimistic,
                    likely=likely,
                    pessimistic=pessimistic,
                )
            else:
                existing.update(
                    optimistic=optimistic,
                    likely=likely,
                    pessimistic=pessimistic,
                )
        except Exception:
            # No DB context available – skip silently.
            pass

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load_from_dict(self, data: dict):
        """Parse a time-estimates JSON payload.

        The payload must contain a ``"tasks"`` mapping where each key is either:

        * a **vulnerability id** (legacy format) – values are ISO 8601 duration
          strings; the effort is applied to the matching in-memory vulnerability.
        * a **finding id** (DB format) – values are integers (hours); the record
          is persisted to the ``time_estimates`` table when a DB session is live.
          An optional ``"variant_id"`` field may be present per task entry.
        """
        if "tasks" not in data:
            return

        for (task_id, task) in data["tasks"].items():
            optimistic = task.get("optimistic")
            likely = task.get("likely")
            pessimistic = task.get("pessimistic")

            # DB format: integer hours keyed by finding_id
            if isinstance(optimistic, int) and isinstance(likely, int) and isinstance(pessimistic, int):
                variant_id = task.get("variant_id")
                self._persist_db_estimate(task_id, optimistic, likely, pessimistic, variant_id)
                continue

            # Legacy format: ISO 8601 duration strings keyed by vuln_id
            vuln = self.vulnerabilitiesCtrl.get(task_id)
            if vuln is not None:
                vuln.set_effort(optimistic, likely, pessimistic)
                self.vulnerabilitiesCtrl.add(vuln)  # will merge

                # Also persist to DB when a session is available
                hours_opt = self._iso_to_hours(optimistic)
                hours_lik = self._iso_to_hours(likely)
                hours_pes = self._iso_to_hours(pessimistic)
                if all(v is not None for v in [hours_opt, hours_lik, hours_pes]):
                    # Try to find the corresponding finding(s) and persist
                    try:
                        from ..models.finding import Finding
                        for finding in Finding.get_by_vulnerability(vuln.id):
                            self._persist_db_estimate(
                                str(finding.id), hours_opt, hours_lik, hours_pes  # type: ignore[arg-type]
                            )
                    except Exception:
                        pass

    def to_dict(self) -> dict:
        """Serialise current in-memory effort data to the legacy JSON format."""
        output = {
            "author": "Savoir-faire Linux",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 1,
            "tasks": {}
        }
        for (vuln_id, vuln) in self.vulnerabilitiesCtrl.vulnerabilities.items():
            if not (vuln.effort["optimistic"] is None
               or vuln.effort["likely"] is None
               or vuln.effort["pessimistic"] is None):

                output["tasks"][vuln_id] = {  # type: ignore
                    "optimistic": str(vuln.effort["optimistic"]),
                    "likely": str(vuln.effort["likely"]),
                    "pessimistic": str(vuln.effort["pessimistic"])
                }
        return output
