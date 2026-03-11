# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import datetime
from typing import Optional

from ..models.vulnerability_record import VulnerabilityRecord


class VulnerabilityDBController:
    """
    Service layer for :class:`VulnerabilityRecord` CRUD operations.

    Delegates persistence to the model and provides dictionary serialisation
    for API responses.
    """

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(record: VulnerabilityRecord) -> dict:
        """Return a JSON-serialisable dict representation of *record*."""
        return {
            "id": record.id,
            "description": record.description,
            "yocto_description": record.yocto_description,
            "status": record.status,
            "publish_date": record.publish_date.isoformat() if record.publish_date else None,
            "attack_vector": record.attack_vector,
            "epss_score": float(record.epss_score) if record.epss_score is not None else None,
            "links": record.links or [],
        }

    @staticmethod
    def serialize_list(records: list[VulnerabilityRecord]) -> list[dict]:
        """Return a list of serialised vulnerability dicts."""
        return [VulnerabilityDBController.serialize(r) for r in records]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def get(vuln_id: str) -> Optional[VulnerabilityRecord]:
        """Return the record matching *vuln_id*, or ``None`` if not found."""
        return VulnerabilityRecord.get_by_id(vuln_id)

    @staticmethod
    def get_all() -> list[VulnerabilityRecord]:
        """Return all vulnerability records ordered by id."""
        return VulnerabilityRecord.get_all()

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        vuln_id: str,
        description: Optional[str] = None,
        yocto_description: Optional[str] = None,
        status: Optional[str] = None,
        publish_date: Optional[datetime.date | str] = None,
        attack_vector: Optional[str] = None,
        epss_score: Optional[float] = None,
        links: Optional[list] = None,
    ) -> VulnerabilityRecord:
        """Validate inputs and create a new :class:`VulnerabilityRecord`.

        :raises ValueError: if *vuln_id* is empty or blank.
        """
        vuln_id = vuln_id.strip()
        if not vuln_id:
            raise ValueError("Vulnerability id must not be empty.")
        if isinstance(publish_date, str) and publish_date:
            publish_date = datetime.date.fromisoformat(publish_date)
        return VulnerabilityRecord.create(
            id=vuln_id,
            description=description,
            yocto_description=yocto_description,
            status=status,
            publish_date=publish_date,
            attack_vector=attack_vector,
            epss_score=epss_score,
            links=links,
        )

    @staticmethod
    def get_or_create(vuln_id: str, **kwargs) -> VulnerabilityRecord:
        """Return an existing record by id, or create and persist a new one.

        :raises ValueError: if *vuln_id* is empty or blank.
        """
        vuln_id = vuln_id.strip()
        if not vuln_id:
            raise ValueError("Vulnerability id must not be empty.")
        return VulnerabilityRecord.get_or_create(vuln_id, **kwargs)

    @staticmethod
    def update(
        record: VulnerabilityRecord | str,
        **kwargs,
    ) -> VulnerabilityRecord:
        """Update *record* fields.  *record* may be a model instance or an id string.

        :raises ValueError: if the record is not found.
        """
        if isinstance(record, VulnerabilityRecord):
            resolved = record
        else:
            found = VulnerabilityDBController.get(record)
            if found is None:
                raise ValueError("VulnerabilityRecord not found.")
            resolved = found
        return resolved.update(**kwargs)

    @staticmethod
    def delete(record: VulnerabilityRecord | str) -> None:
        """Delete *record*.  *record* may be a model instance or an id string.

        :raises ValueError: if the record is not found.
        """
        if isinstance(record, VulnerabilityRecord):
            resolved = record
        else:
            found = VulnerabilityDBController.get(record)
            if found is None:
                raise ValueError("VulnerabilityRecord not found.")
            resolved = found
        resolved.delete()
