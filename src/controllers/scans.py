# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional

from ..models.scan import Scan
from ..helpers.datetime_utils import ensure_utc_iso


class ScanController:
    """
    Service layer for Scan CRUD operations.

    Handles input validation, delegates persistence to the :class:`Scan`
    model and provides dictionary serialisation for API responses.
    """

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(scan: Scan) -> dict:
        """Return a JSON-serialisable dict representation of *scan*."""
        return {
            "id": str(scan.id),
            "description": scan.description,
            "scan_type": scan.scan_type or "sbom",
            "timestamp": ensure_utc_iso(scan.timestamp),
            "variant_id": str(scan.variant_id),
        }

    @staticmethod
    def serialize_list(scans: list[Scan]) -> list[dict]:
        """Return a list of serialised scan dicts."""
        return [ScanController.serialize(s) for s in scans]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def get(scan_id: uuid.UUID | str) -> Optional[Scan]:
        """Return the scan matching *scan_id*, or ``None`` if not found."""
        if isinstance(scan_id, str):
            scan_id = uuid.UUID(scan_id)
        return Scan.get_by_id(scan_id)

    @staticmethod
    def get_all() -> list[Scan]:
        """Return all scans ordered by timestamp."""
        return Scan.get_all()

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID | str) -> list[Scan]:
        """Return all scans belonging to *variant_id*, ordered by timestamp."""
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        return Scan.get_by_variant_id(variant_id)

    @staticmethod
    def get_by_project(project_id: uuid.UUID | str) -> list[Scan]:
        """Return all scans belonging to *project_id* (across all its variants), ordered by timestamp."""
        if isinstance(project_id, str):
            project_id = uuid.UUID(project_id)
        return Scan.get_by_project(project_id)

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    @staticmethod
    def create(description: str, variant_id: uuid.UUID | str, scan_type: str = "sbom") -> Scan:
        """
        Create a new scan under *variant_id*.

        :raises ValueError: if *variant_id* is not a valid UUID string.
        """
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        return Scan.create(description, variant_id, scan_type=scan_type)

    @staticmethod
    def update(scan: Scan | uuid.UUID | str, description: str) -> Scan:
        """
        Update *scan*'s description.  *scan* may be a :class:`Scan` instance,
        a UUID object, or a UUID string.

        :raises ValueError: if the scan is not found.
        """
        if not isinstance(scan, Scan):
            _fetched = ScanController.get(scan)
            if _fetched is None:
                raise ValueError("Scan not found.")
            scan = _fetched
        return scan.update(description)

    @staticmethod
    def delete(scan: Scan | uuid.UUID | str) -> None:
        """
        Delete *scan*.  *scan* may be a :class:`Scan` instance,
        a UUID object, or a UUID string.

        :raises ValueError: if the scan is not found.
        """
        if not isinstance(scan, Scan):
            _fetched = ScanController.get(scan)
            if _fetched is None:
                raise ValueError("Scan not found.")
            scan = _fetched
        scan.delete()
