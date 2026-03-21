# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional
from ..models.finding import Finding


class FindingController:
    """
    Service layer for :class:`Finding` CRUD operations.

    Delegates persistence to the model and provides dictionary serialisation
    for API responses.
    """

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(finding: Finding) -> dict:
        """Return a JSON-serialisable dict representation of *finding*."""
        return {
            "id": str(finding.id),
            "package_id": str(finding.package_id),
            "vulnerability_id": finding.vulnerability_id,
        }

    @staticmethod
    def serialize_list(findings: list[Finding]) -> list[dict]:
        """Return a list of serialised finding dicts."""
        return [FindingController.serialize(f) for f in findings]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def get(finding_id: uuid.UUID | str) -> Optional[Finding]:
        """Return the finding matching *finding_id*, or ``None`` if not found."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        return Finding.get_by_id(finding_id)

    @staticmethod
    def get_by_package(package_id: uuid.UUID | str) -> list[Finding]:
        """Return all findings for the given package."""
        return Finding.get_by_package(package_id)

    @staticmethod
    def get_by_vulnerability(vulnerability_id: str) -> list[Finding]:
        """Return all findings for the given vulnerability id."""
        return Finding.get_by_vulnerability(vulnerability_id)

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    @staticmethod
    def create(package_id: uuid.UUID | str, vulnerability_id: str) -> Finding:
        """Create a new finding.

        :raises ValueError: if *vulnerability_id* is empty or blank.
        """
        vulnerability_id = vulnerability_id.strip()
        if not vulnerability_id:
            raise ValueError("Vulnerability id must not be empty.")
        return Finding.create(package_id, vulnerability_id)

    @staticmethod
    def get_or_create(package_id: uuid.UUID | str, vulnerability_id: str) -> Finding:
        """Return an existing finding or create a new one.

        :raises ValueError: if *vulnerability_id* is empty or blank.
        """
        vulnerability_id = vulnerability_id.strip()
        if not vulnerability_id:
            raise ValueError("Vulnerability id must not be empty.")
        return Finding.get_or_create(package_id, vulnerability_id)

    @staticmethod
    def delete(finding: Finding | uuid.UUID | str) -> None:
        """Delete *finding*.  *finding* may be a model instance or a UUID string.

        :raises ValueError: if the finding is not found.
        """
        if isinstance(finding, Finding):
            resolved = finding
        else:
            found = FindingController.get(finding)
            if found is None:
                raise ValueError("Finding not found.")
            resolved = found
        resolved.delete()
