# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional

from ..models.metrics import Metrics


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
            "version": metrics.version,
            "score": float(metrics.score) if metrics.score is not None else None,
            "vector": metrics.vector,
            "author": metrics.author,
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
        if isinstance(metrics_id, str):
            metrics_id = uuid.UUID(metrics_id)
        return Metrics.get_by_id(metrics_id)

    @staticmethod
    def get_by_vulnerability(vulnerability_id: str) -> list[Metrics]:
        """Return all metrics for the given vulnerability id."""
        return Metrics.get_by_vulnerability(vulnerability_id)

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        vulnerability_id: str,
        version: Optional[str] = None,
        score: Optional[float] = None,
        vector: Optional[str] = None,
        author: Optional[str] = None,
    ) -> Metrics:
        """Create a new :class:`Metrics` record.

        :raises ValueError: if *vulnerability_id* is empty or blank.
        """
        vulnerability_id = vulnerability_id.strip()
        if not vulnerability_id:
            raise ValueError("Vulnerability id must not be empty.")
        return Metrics.create(
            vulnerability_id=vulnerability_id,
            version=version,
            score=score,
            vector=vector,
            author=author,
        )

    @staticmethod
    def update(
        metrics: Metrics | uuid.UUID | str,
        version: Optional[str] = None,
        score: Optional[float] = None,
        vector: Optional[str] = None,
        author: Optional[str] = None,
    ) -> Metrics:
        """Update *metrics* fields.

        :raises ValueError: if the record is not found.
        """
        if isinstance(metrics, Metrics):
            resolved = metrics
        else:
            found = MetricsController.get(metrics)
            if found is None:
                raise ValueError("Metrics record not found.")
            resolved = found
        return resolved.update(version=version, score=score, vector=vector, author=author)

    @staticmethod
    def delete(metrics: Metrics | uuid.UUID | str) -> None:
        """Delete *metrics*.

        :raises ValueError: if the record is not found.
        """
        if isinstance(metrics, Metrics):
            resolved = metrics
        else:
            found = MetricsController.get(metrics)
            if found is None:
                raise ValueError("Metrics record not found.")
            resolved = found
        resolved.delete()
