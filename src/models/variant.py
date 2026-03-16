# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional
from sqlalchemy.exc import IntegrityError
from ..extensions import db, Base


class Variant(Base):
    """Represents a named variant (e.g. board configuration) belonging to a project."""

    __tablename__ = "variants"
    __table_args__ = (
        db.UniqueConstraint("name", "project_id", name="uq_variants_name_project"),
    )

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String, nullable=False)
    project_id = db.Column(db.Uuid, db.ForeignKey("projects.id"), nullable=False)

    project = db.relationship("Project", back_populates="variants")
    scans = db.relationship("Scan", back_populates="variant", cascade="all, delete-orphan")
    assessments = db.relationship("Assessment", back_populates="variant", cascade="all, delete-orphan")
    time_estimates = db.relationship("TimeEstimate", back_populates="variant", cascade="all, delete-orphan")

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
    def get_by_id(variant_id: uuid.UUID) -> Optional["Variant"]:
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
    def get_or_create(name: str, project_id: uuid.UUID) -> "Variant":
        """Return an existing variant by *name* under *project_id*, or create and persist a new one."""

        existing = db.session.execute(
            db.select(Variant).where(Variant.name == name, Variant.project_id == project_id)
        ).scalar_one_or_none()
        if existing is not None:
            return existing
        try:
            variant = Variant(name=name, project_id=project_id)
            db.session.add(variant)
            db.session.flush()
            db.session.commit()
            return variant
        except IntegrityError:
            db.session.rollback()
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
