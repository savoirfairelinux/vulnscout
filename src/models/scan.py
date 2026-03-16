# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from typing import Optional
import uuid
from datetime import datetime, timezone
from ..extensions import db, Base


class Scan(Base):
    """Represents a single scan run associated with a variant."""

    __tablename__ = "scans"

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    description = db.Column(db.Text, nullable=True)
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    variant_id = db.Column(db.Uuid, db.ForeignKey("variants.id"), nullable=False)

    variant = db.relationship("Variant", back_populates="scans")
    sbom_documents = db.relationship("SBOMDocument", back_populates="scan", cascade="all, delete-orphan")
    observations = db.relationship("Observation", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan id={self.id} timestamp={self.timestamp}>"

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(description: str, variant_id: uuid.UUID) -> "Scan":
        """Create a new scan with the given *description* under *variant_id*, persist it and return it."""
        scan = Scan(description=description, variant_id=variant_id)
        db.session.add(scan)
        db.session.commit()
        return scan

    @staticmethod
    def get_by_id(scan_id: uuid.UUID) -> Optional["Scan"]:
        """Return the scan matching *scan_id*, or ``None`` if not found."""
        return db.session.get(Scan, scan_id)

    @staticmethod
    def get_all() -> list["Scan"]:
        """Return all scans ordered by timestamp."""
        return list(db.session.execute(
            db.select(Scan).order_by(Scan.timestamp)
        ).scalars().all())

    @staticmethod
    def get_by_project(project_id: uuid.UUID) -> list["Scan"]:
        """Return all scans belonging to *project_id* (across all its variants), ordered by timestamp."""
        from .variant import Variant
        return list(db.session.execute(
            db.select(Scan)
            .join(Variant, Scan.variant_id == Variant.id)
            .where(Variant.project_id == project_id)
            .order_by(Scan.timestamp)
        ).scalars().all())

    @staticmethod
    def get_by_variant_id(variant_id: uuid.UUID) -> list["Scan"]:
        """Return all scans belonging to *variant_id*, ordered by timestamp."""
        return list(db.session.execute(
            db.select(Scan).where(Scan.variant_id == variant_id).order_by(Scan.timestamp)
        ).scalars().all())

    @staticmethod
    def get_latest() -> Optional["Scan"]:
        """Return the most recently created scan, or ``None`` if no scans exist."""
        result = db.session.execute(
            db.select(Scan).order_by(Scan.timestamp.desc()).limit(1)
        ).scalars().first()
        return result

    def update(self, description: str) -> "Scan":
        """Update the scan's *description* in place, persist the change and return ``self``."""
        self.description = description
        db.session.commit()
        return self

    def delete(self) -> None:
        """Delete this scan (and its related SBOM documents via cascade) from the database."""
        db.session.delete(self)
        db.session.commit()
