# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional

from ..models.metrics import Metrics
from ._base import ensure_uuid, resolve_entity, validate_non_empty


class MetricsController:
    """
    Service layer for :class:`Metrics` CRUD operations.

    Delegates persistence to the model and provides dictionary serialisation
    for API responses.
    """

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(metrics: Metrics) -> dict:
        """Return a JSON-serialisable dict representation of *metrics*."""
        return {
            "id": str(metrics.id),
            "vulnerability_id": metrics.vulnerability_id,
            "variant_id": str(metrics.variant_id) if metrics.variant_id is not None else None,
            "version": metrics.version,
            "score": float(metrics.score) if metrics.score is not None else None,
            "vector": metrics.vector,
            "author": metrics.author,
            "origin": metrics.origin,
        }

    @staticmethod
    def serialize_list(metrics_list: list[Metrics]) -> list[dict]:
        """Return a list of serialised metrics dicts."""
        return [MetricsController.serialize(m) for m in metrics_list]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def get(metrics_id: uuid.UUID | str) -> Optional[Metrics]:
        """Return the metrics record matching *metrics_id*, or ``None`` if not found."""
        return Metrics.get_by_id(ensure_uuid(metrics_id))

    @staticmethod
    def get_by_vulnerability(vulnerability_id: str) -> list[Metrics]:
        """Return all metrics for the given vulnerability id."""
        return Metrics.get_by_vulnerability(vulnerability_id)

    @staticmethod
    def get_by_vulnerability_and_variant(
        vulnerability_id: str,
        variant_id: uuid.UUID | str,
        include_unscoped: bool = True,
    ) -> list[Metrics]:
        """Return metrics for the given vulnerability and variant."""
        return Metrics.get_by_vulnerability_and_variant(vulnerability_id, variant_id, include_unscoped)

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        vulnerability_id: str,
        variant_id: uuid.UUID | str | None = None,
        version: Optional[str] = None,
        score: Optional[float] = None,
        vector: Optional[str] = None,
        author: Optional[str] = None,
        origin: Optional[str] = None,
    ) -> Metrics:
        """Create a new :class:`Metrics` record.

        :raises ValueError: if *vulnerability_id* is empty or blank.
        """
        vulnerability_id = validate_non_empty(vulnerability_id, "Vulnerability id")
        return Metrics.create(
            vulnerability_id=vulnerability_id,
            variant_id=variant_id,
            version=version,
            score=score,
            vector=vector,
            author=author,
            origin=origin,
        )

    @staticmethod
    def update(
        metrics: Metrics | uuid.UUID | str,
        version: Optional[str] = None,
        score: Optional[float] = None,
        vector: Optional[str] = None,
        author: Optional[str] = None,
        origin: Optional[str] = None,
    ) -> Metrics:
        """Update *metrics* fields.

        :raises ValueError: if the record is not found.
        """
        resolved = resolve_entity(metrics, MetricsController.get, "Metrics record")
        return resolved.update(version=version, score=score, vector=vector, author=author, origin=origin)

    @staticmethod
    def delete(metrics: Metrics | uuid.UUID | str) -> None:
        """Delete *metrics*.

        :raises ValueError: if the record is not found.
        """
        resolved = resolve_entity(metrics, MetricsController.get, "Metrics record")
        resolved.delete()
