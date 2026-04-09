# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional

from ..models.time_estimate import TimeEstimate


class TimeEstimateController:
    """
    Service layer for :class:`TimeEstimate` CRUD operations.

    Delegates persistence to the model and provides dictionary serialisation
    for API responses.
    """

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(estimate: TimeEstimate) -> dict:
        """Return a JSON-serialisable dict representation of *estimate*."""
        return {
            "id": str(estimate.id),
            "finding_id": str(estimate.finding_id) if estimate.finding_id else None,
            "variant_id": str(estimate.variant_id) if estimate.variant_id else None,
            "optimistic": estimate.optimistic,
            "likely": estimate.likely,
            "pessimistic": estimate.pessimistic,
        }

    @staticmethod
    def serialize_list(estimates: list[TimeEstimate]) -> list[dict]:
        """Return a list of serialised time estimate dicts."""
        return [TimeEstimateController.serialize(e) for e in estimates]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def get(estimate_id: uuid.UUID | str) -> Optional[TimeEstimate]:
        """Return the time estimate matching *estimate_id*, or ``None`` if not found."""
        if isinstance(estimate_id, str):
            estimate_id = uuid.UUID(estimate_id)
        return TimeEstimate.get_by_id(estimate_id)

    @staticmethod
    def get_by_finding(finding_id: uuid.UUID | str) -> list[TimeEstimate]:
        """Return all time estimates for the given finding."""
        return TimeEstimate.get_by_finding(finding_id)

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID | str) -> list[TimeEstimate]:
        """Return all time estimates for the given variant."""
        return TimeEstimate.get_by_variant(variant_id)

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        finding_id: Optional[uuid.UUID | str] = None,
        variant_id: Optional[uuid.UUID | str] = None,
        optimistic: Optional[int] = None,
        likely: Optional[int] = None,
        pessimistic: Optional[int] = None,
    ) -> TimeEstimate:
        """Create a new :class:`TimeEstimate`.

        :raises ValueError: if optimistic > likely or likely > pessimistic (when all provided).
        """
        if optimistic is not None and likely is not None and pessimistic is not None:
            if optimistic > likely or likely > pessimistic:
                raise ValueError(
                    "Time estimates must satisfy: optimistic <= likely <= pessimistic."
                )
        return TimeEstimate.create(
            finding_id=finding_id,
            variant_id=variant_id,
            optimistic=optimistic,
            likely=likely,
            pessimistic=pessimistic,
        )

    @staticmethod
    def update(
        estimate: TimeEstimate | uuid.UUID | str,
        optimistic: Optional[int] = None,
        likely: Optional[int] = None,
        pessimistic: Optional[int] = None,
    ) -> TimeEstimate:
        """Update *estimate* fields.

        :raises ValueError: if the estimate is not found, or ordering constraints are violated.
        """
        if isinstance(estimate, TimeEstimate):
            resolved = estimate
        else:
            found = TimeEstimateController.get(estimate)
            if found is None:
                raise ValueError("TimeEstimate not found.")
            resolved = found

        new_opt = optimistic if optimistic is not None else resolved.optimistic
        new_lik = likely if likely is not None else resolved.likely
        new_pes = pessimistic if pessimistic is not None else resolved.pessimistic
        if all(v is not None for v in [new_opt, new_lik, new_pes]):
            if new_opt > new_lik or new_lik > new_pes:
                raise ValueError(
                    "Time estimates must satisfy: optimistic <= likely <= pessimistic."
                )
        return resolved.update(optimistic=optimistic, likely=likely, pessimistic=pessimistic)

    @staticmethod
    def delete(estimate: TimeEstimate | uuid.UUID | str) -> None:
        """Delete *estimate*.

        :raises ValueError: if the estimate is not found.
        """
        if isinstance(estimate, TimeEstimate):
            resolved = estimate
        else:
            found = TimeEstimateController.get(estimate)
            if found is None:
                raise ValueError("TimeEstimate not found.")
            resolved = found
        resolved.delete()
