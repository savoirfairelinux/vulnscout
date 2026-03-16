# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional
from ..extensions import db, Base


class TimeEstimate(Base):
    """Stores three-point time estimates (optimistic / likely / pessimistic) for a finding."""

    __tablename__ = "time_estimates"

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    finding_id = db.Column(db.Uuid, db.ForeignKey("findings.id"), nullable=True)
    variant_id = db.Column(db.Uuid, db.ForeignKey("variants.id"), nullable=True)
    optimistic = db.Column(db.Integer, nullable=True)
    likely = db.Column(db.Integer, nullable=True)
    pessimistic = db.Column(db.Integer, nullable=True)

    finding = db.relationship("Finding", back_populates="time_estimate")
    variant = db.relationship("Variant", back_populates="time_estimates")

    def __repr__(self) -> str:
        return (
            f"<TimeEstimate id={self.id} finding_id={self.finding_id}"
            f" optimistic={self.optimistic} likely={self.likely} pessimistic={self.pessimistic}>"
        )

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        finding_id: Optional[uuid.UUID | str] = None,
        variant_id: Optional[uuid.UUID | str] = None,
        optimistic: Optional[int] = None,
        likely: Optional[int] = None,
        pessimistic: Optional[int] = None,
    ) -> "TimeEstimate":
        """Create a new time estimate, persist it and return it."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        estimate = TimeEstimate(
            finding_id=finding_id,
            variant_id=variant_id,
            optimistic=optimistic,
            likely=likely,
            pessimistic=pessimistic,
        )
        db.session.add(estimate)
        db.session.commit()
        return estimate

    @staticmethod
    def get_by_id(estimate_id: uuid.UUID | str) -> Optional["TimeEstimate"]:
        """Return the time estimate matching *estimate_id*, or ``None``."""
        if isinstance(estimate_id, str):
            estimate_id = uuid.UUID(estimate_id)
        return db.session.get(TimeEstimate, estimate_id)

    @staticmethod
    def get_by_finding(finding_id: uuid.UUID | str) -> list["TimeEstimate"]:
        """Return all time estimates for the given finding."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        return list(db.session.execute(
            db.select(TimeEstimate).where(TimeEstimate.finding_id == finding_id)
        ).scalars().all())

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID | str) -> list["TimeEstimate"]:
        """Return all time estimates for the given variant."""
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        return list(db.session.execute(
            db.select(TimeEstimate).where(TimeEstimate.variant_id == variant_id)
        ).scalars().all())

    @staticmethod
    def get_by_finding_and_variant(
        finding_id: uuid.UUID | str,
        variant_id: uuid.UUID | str,
    ) -> Optional["TimeEstimate"]:
        """Return a time estimate matching both *finding_id* and *variant_id*, or ``None``."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        return db.session.execute(
            db.select(TimeEstimate).where(
                TimeEstimate.finding_id == finding_id,
                TimeEstimate.variant_id == variant_id,
            )
        ).scalar_one_or_none()

    def update(
        self,
        optimistic: Optional[int] = None,
        likely: Optional[int] = None,
        pessimistic: Optional[int] = None,
    ) -> "TimeEstimate":
        """Update fields in place, persist the change and return ``self``."""
        if optimistic is not None:
            self.optimistic = optimistic
        if likely is not None:
            self.likely = likely
        if pessimistic is not None:
            self.pessimistic = pessimistic
        db.session.commit()
        return self

    def delete(self) -> None:
        """Delete this time estimate from the database."""
        db.session.delete(self)
        db.session.commit()
