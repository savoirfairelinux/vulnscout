# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import typing
import uuid
from datetime import datetime, timezone

from ..extensions import db, Base
from ..helpers.datetime_utils import ensure_utc_iso
from .variant import Variant

from sqlalchemy.orm import Mapped

if typing.TYPE_CHECKING:
    # avoid circular imports, https://stackoverflow.com/a/79601366
    from .sbom_document import SBOMDocument
    from .observation import Observation


class Scan(Base):
    """Represents a single scan run associated with a variant."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    description: Mapped[str | None] = db.Column(db.Text, nullable=True)
    scan_type: Mapped[str | None] = db.Column(db.String, nullable=True, default="sbom")  # 'sbom' or 'tool'
    scan_source: Mapped[str | None] = db.Column(db.String, nullable=True)  # 'grype', 'nvd', 'osv', or None
    timestamp: Mapped[datetime] = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    variant_id: Mapped[uuid.UUID] = db.Column(db.Uuid, db.ForeignKey("variants.id"), nullable=False, index=True)

    # Flask-SQLAlchemy has typing issues, see https://github.com/pallets-eco/flask-sqlalchemy/issues/1318
    variant: Mapped[Variant] = db.relationship(  # type: ignore
        "Variant",
        back_populates="scans"
    )
    sbom_documents: Mapped[list["SBOMDocument"]] = db.relationship(  # type: ignore
        "SBOMDocument",
        back_populates="scan",
        cascade="all, delete-orphan"
    )
    observations: Mapped[list["Observation"]] = db.relationship(  # type: ignore
        "Observation",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} timestamp={self.timestamp}>"

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "description": self.description,
            "timestamp": ensure_utc_iso(self.timestamp),
            "variant": {
                "id": str(self.variant.id),
                "name": self.variant.name,
                "project": {
                    "id": str(self.variant.project.id),
                    "name": self.variant.project.name,
                }
            }
        }

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(description: str, variant_id: uuid.UUID, scan_type: str = "sbom",
               scan_source: str | None = None) -> "Scan":
        """Create a new scan with the given *description* under *variant_id*, persist it and return it."""
        scan = Scan(description=description, variant_id=variant_id,
                    scan_type=scan_type, scan_source=scan_source)
        db.session.add(scan)
        db.session.commit()
        return scan

    @staticmethod
    def get_by_id(scan_id: uuid.UUID) -> "Scan | None":
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
    def get_latest() -> "Scan | None":
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
