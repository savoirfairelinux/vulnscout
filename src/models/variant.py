# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
import typing

from ..extensions import db, Base

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column, relationship

if typing.TYPE_CHECKING:
    from ..models import Project, Scan, Assessment, TimeEstimate, Metrics
    from .variant_context import VariantContext


class Variant(Base):
    """Represents a named variant (e.g. board configuration) belonging to a project."""

    __tablename__ = "variants"
    __table_args__ = (
        UniqueConstraint("name", "project_id", name="uq_variants_name_project"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str]
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))

    project: Mapped["Project"] = relationship(
        back_populates="variants"
    )
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="variant",
        cascade="all, delete-orphan"
    )
    assessments: Mapped[list["Assessment"]] = relationship(
        back_populates="variant",
        cascade="all, delete-orphan"
    )
    time_estimates: Mapped[list["TimeEstimate"]] = relationship(
        back_populates="variant",
        cascade="all, delete-orphan"
    )
    metrics: Mapped[list["Metrics"]] = relationship(
        back_populates="variant",
        cascade="all, delete-orphan"
    )
    context: Mapped["VariantContext | None"] = relationship(
        back_populates="variant",
        cascade="all, delete-orphan",
        uselist=False,
    )

    def __repr__(self) -> str:
        return f"<Variant id={self.id} name={self.name!r}>"

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(name: str, project_id: uuid.UUID) -> "Variant":
        """Create a new variant with the given *name* under *project_id*, persist it and return it."""
        variant = Variant(name=name, project_id=project_id)
        db.session.add(variant)
        db.session.commit()
        return variant

    @staticmethod
    def get_by_id(variant_id: uuid.UUID) -> "Variant | None":
        """Return the variant matching *variant_id*, or ``None`` if not found."""
        return db.session.get(Variant, variant_id)

    @staticmethod
    def get_all() -> list["Variant"]:
        """Return all variants ordered by name."""
        return list(db.session.execute(
            db.select(Variant).order_by(Variant.name)
        ).scalars().all())

    @staticmethod
    def get_by_project(project_id: uuid.UUID) -> list["Variant"]:
        """Return all variants belonging to *project_id*, ordered by name."""
        return list(db.session.execute(
            db.select(Variant).where(Variant.project_id == project_id).order_by(Variant.name)
        ).scalars().all())

    @staticmethod
    def get_by_name_and_project(name: str, project_id: uuid.UUID) -> "Variant | None":
        """Return an existing variant by *name* under *project_id*, or None if it does not exist."""
        return db.session.execute(
            db.select(Variant).where(Variant.name == name, Variant.project_id == project_id)
        ).scalar_one_or_none()

    @staticmethod
    def get_or_create(name: str, project_id: uuid.UUID) -> "Variant":
        """Return an existing variant by *name* under *project_id*, or create and persist a new one."""

        existing = db.session.execute(
            db.select(Variant).where(Variant.name == name, Variant.project_id == project_id)
        ).scalar_one_or_none()
        if existing is not None:
            return existing
        try:
            with db.session.begin_nested():
                variant = Variant(name=name, project_id=project_id)
                db.session.add(variant)
                db.session.flush()
            db.session.commit()
            return variant
        except IntegrityError:
            return db.session.execute(
                db.select(Variant).where(Variant.name == name, Variant.project_id == project_id)
            ).scalar_one()

    def update(self, name: str) -> "Variant":
        """Update the variant's *name* in place, persist the change and return ``self``."""
        self.name = name
        db.session.commit()
        return self

    def delete(self) -> None:
        """Delete this variant (and its scans via cascade) from the database."""
        db.session.delete(self)
        db.session.commit()
