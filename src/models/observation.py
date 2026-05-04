# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
import typing

from sqlalchemy.orm import Mapped, relationship

from ..extensions import db, Base

if typing.TYPE_CHECKING:
    from .scan import Scan
    from .finding import Finding


class Observation(Base):
    """Represents an observation linking a finding to a scan."""

    __tablename__ = "observations"

    id: Mapped[uuid.UUID] = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = db.Column(db.Uuid, db.ForeignKey("findings.id"), nullable=False, index=True)
    scan_id: Mapped[uuid.UUID] = db.Column(db.Uuid, db.ForeignKey("scans.id"), nullable=False, index=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="observations")
    finding: Mapped["Finding"] = relationship("Finding", back_populates="observations")

    def __repr__(self) -> str:
        return f"<Observation id={self.id} finding_id={self.finding_id} scan_id={self.scan_id}>"

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        finding_id: uuid.UUID | str,
        scan_id: uuid.UUID | str,
        commit: bool = True,
    ) -> "Observation":
        """Create a new observation, persist it and return it.

        Args:
            commit: If True (default), commit immediately. Set False for bulk operations.
        """
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        if isinstance(scan_id, str):
            scan_id = uuid.UUID(scan_id)
        observation = Observation(finding_id=finding_id, scan_id=scan_id)
        db.session.add(observation)
        if commit:
            db.session.commit()
        else:
            db.session.flush()
        return observation

    @staticmethod
    def get_by_id(observation_id: uuid.UUID | str) -> "Observation | None":
        """Return the observation matching *observation_id*, or ``None`` if not found."""
        if isinstance(observation_id, str):
            observation_id = uuid.UUID(observation_id)
        return db.session.get(Observation, observation_id)

    @staticmethod
    def get_by_scan(scan_id: uuid.UUID | str) -> list["Observation"]:
        """Return all observations for the given scan."""
        if isinstance(scan_id, str):
            scan_id = uuid.UUID(scan_id)
        return list(db.session.execute(
            db.select(Observation).where(Observation.scan_id == scan_id)
        ).scalars().all())

    @staticmethod
    def get_by_finding(finding_id: uuid.UUID | str) -> list["Observation"]:
        """Return all observations for the given finding."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        return list(db.session.execute(
            db.select(Observation).where(Observation.finding_id == finding_id)
        ).scalars().all())

    def delete(self) -> None:
        """Delete this observation from the database."""
        db.session.delete(self)
        db.session.commit()
