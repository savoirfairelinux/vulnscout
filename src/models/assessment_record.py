# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from datetime import datetime, timezone
from typing import Optional
from ..extensions import db, Base


class Assessment(Base):
    """Stores a triage assessment for a :class:`Finding` scoped to a :class:`Variant`."""

    __tablename__ = "assessments"

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    source = db.Column(db.String, nullable=True)
    status = db.Column(db.String, nullable=True)
    simplified_status = db.Column(db.String, nullable=True)
    status_notes = db.Column(db.Text, nullable=True)
    justification = db.Column(db.Text, nullable=True)
    impact_statement = db.Column(db.Text, nullable=True)
    workaround = db.Column(db.Text, nullable=True)
    workaround_timestamp = db.Column(db.String, nullable=True)
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_update = db.Column(db.String, nullable=True)
    responses = db.Column(db.JSON, nullable=True)
    finding_id = db.Column(db.Uuid, db.ForeignKey("findings.id"), nullable=True)
    variant_id = db.Column(db.Uuid, db.ForeignKey("variants.id"), nullable=True)

    # Denormalised convenience columns (duplicated from finding/package for
    # fast lookup without joins and for backward compat with the VulnAssessment DTO)
    vuln_id = db.Column(db.String, nullable=True)
    packages = db.Column(db.JSON, nullable=True)   # list of "name@version" strings

    finding = db.relationship("Finding", back_populates="assessments")
    variant = db.relationship("Variant")

    def __repr__(self) -> str:
        return (
            f"<Assessment id={self.id} status={self.status!r}"
            f" finding_id={self.finding_id} variant_id={self.variant_id}>"
        )

    # ------------------------------------------------------------------
    # Serialisation (matches VulnAssessment.to_dict() format)
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        ts = self.timestamp
        if ts is not None:
            ts = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
        return {
            "id": str(self.id),
            "vuln_id": self.vuln_id or "",
            "packages": list(self.packages or []),
            "timestamp": ts,
            "last_update": self.last_update,
            "status": self.status or "",
            "status_notes": self.status_notes or "",
            "justification": self.justification or "",
            "impact_statement": self.impact_statement or "",
            "responses": list(self.responses or []),
            "workaround": self.workaround or "",
            "workaround_timestamp": self.workaround_timestamp or "",
        }

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        status: str,
        finding_id: Optional[uuid.UUID | str] = None,
        variant_id: Optional[uuid.UUID | str] = None,
        source: Optional[str] = None,
        simplified_status: Optional[str] = None,
        status_notes: Optional[str] = None,
        justification: Optional[str] = None,
        impact_statement: Optional[str] = None,
        workaround: Optional[str] = None,
        workaround_timestamp: Optional[str] = None,
        responses: Optional[list] = None,
        vuln_id: Optional[str] = None,
        packages: Optional[list] = None,
        last_update: Optional[str] = None,
    ) -> "Assessment":
        """Create a new assessment, persist it and return it."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        assessment = Assessment(
            status=status,
            finding_id=finding_id,
            variant_id=variant_id,
            source=source,
            simplified_status=simplified_status,
            status_notes=status_notes,
            justification=justification,
            impact_statement=impact_statement,
            workaround=workaround,
            workaround_timestamp=workaround_timestamp,
            responses=responses or [],
            vuln_id=vuln_id,
            packages=packages or [],
            last_update=last_update,
        )
        db.session.add(assessment)
        db.session.commit()
        return assessment

    @staticmethod
    def get_all() -> list["Assessment"]:
        """Return all assessments."""
        return list(db.session.execute(
            db.select(Assessment).order_by(Assessment.timestamp)
        ).scalars().all())

    @staticmethod
    def from_vuln_assessment(assess, finding_id=None) -> "Assessment":
        """Create or update an ``Assessment`` DB record from a ``VulnAssessment`` DTO."""
        ts = assess.timestamp
        if ts and hasattr(ts, "isoformat"):
            ts_str = ts.isoformat()
        else:
            ts_str = str(ts) if ts else None

        existing = None
        if finding_id is not None:
            existing = db.session.execute(
                db.select(Assessment).where(Assessment.finding_id == finding_id)
            ).scalar_one_or_none()

        if existing is not None:
            # Update existing
            existing.status = assess.status or existing.status
            existing.status_notes = assess.status_notes or existing.status_notes
            existing.justification = assess.justification or existing.justification
            existing.impact_statement = assess.impact_statement or existing.impact_statement
            existing.workaround = getattr(assess, "workaround", None) or existing.workaround
            existing.workaround_timestamp = getattr(assess, "workaround_timestamp", None) or existing.workaround_timestamp
            existing.responses = list(assess.responses) if assess.responses else existing.responses
            existing.vuln_id = assess.vuln_id or existing.vuln_id
            existing.packages = list(assess.packages) if assess.packages else existing.packages
            existing.last_update = getattr(assess, "last_update", None)
            db.session.commit()
            return existing

        return Assessment.create(
            status=assess.status or "under_investigation",
            finding_id=finding_id,
            status_notes=assess.status_notes,
            justification=assess.justification,
            impact_statement=assess.impact_statement,
            workaround=getattr(assess, "workaround", None),
            workaround_timestamp=getattr(assess, "workaround_timestamp", None),
            responses=list(assess.responses) if assess.responses else [],
            vuln_id=assess.vuln_id,
            packages=list(assess.packages) if assess.packages else [],
            last_update=getattr(assess, "last_update", None),
        )

    @staticmethod
    def get_by_id(assessment_id: uuid.UUID | str) -> Optional["Assessment"]:
        """Return the assessment matching *assessment_id*, or ``None``."""
        if isinstance(assessment_id, str):
            assessment_id = uuid.UUID(assessment_id)
        return db.session.get(Assessment, assessment_id)

    @staticmethod
    def get_by_finding(finding_id: uuid.UUID | str) -> list["Assessment"]:
        """Return all assessments for the given finding."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        return list(db.session.execute(
            db.select(Assessment).where(Assessment.finding_id == finding_id)
        ).scalars().all())

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID | str) -> list["Assessment"]:
        """Return all assessments for the given variant."""
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        return list(db.session.execute(
            db.select(Assessment).where(Assessment.variant_id == variant_id)
        ).scalars().all())

    @staticmethod
    def get_by_finding_and_variant(
        finding_id: uuid.UUID | str,
        variant_id: uuid.UUID | str,
    ) -> list["Assessment"]:
        """Return assessments matching both *finding_id* and *variant_id*."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        return list(db.session.execute(
            db.select(Assessment).where(
                Assessment.finding_id == finding_id,
                Assessment.variant_id == variant_id,
            )
        ).scalars().all())

    def update(
        self,
        status: Optional[str] = None,
        source: Optional[str] = None,
        simplified_status: Optional[str] = None,
        status_notes: Optional[str] = None,
        justification: Optional[str] = None,
        impact_statement: Optional[str] = None,
        workaround: Optional[str] = None,
        workaround_timestamp: Optional[str] = None,
        responses: Optional[list] = None,
        last_update: Optional[str] = None,
    ) -> "Assessment":
        """Update fields in place, persist the change and return ``self``."""
        if status is not None:
            self.status = status
        if source is not None:
            self.source = source
        if simplified_status is not None:
            self.simplified_status = simplified_status
        if status_notes is not None:
            self.status_notes = status_notes
        if justification is not None:
            self.justification = justification
        if impact_statement is not None:
            self.impact_statement = impact_statement
        if workaround is not None:
            self.workaround = workaround
        if workaround_timestamp is not None:
            self.workaround_timestamp = workaround_timestamp
        if responses is not None:
            self.responses = responses
        if last_update is not None:
            self.last_update = last_update
        db.session.commit()
        return self

    def delete(self) -> None:
        """Delete this assessment from the database."""
        db.session.delete(self)
        db.session.commit()
